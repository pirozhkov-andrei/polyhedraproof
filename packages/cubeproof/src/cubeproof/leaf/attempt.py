"""One attempt as a nonblocking state machine (specification §6.1-§6.5, §7.1, §7.2, §8.1).

The coordinator's event loop owns the :class:`~cubeproof.tools.process.Supervisor` and the
I/O service client; it calls :meth:`LeafAttempt.advance` (bounded CPU work, never a wait),
steps the supervisor, and hands every I/O result to the attempt that submitted the job
(:meth:`LeafAttempt.owns`, :meth:`LeafAttempt.deliver`). Phases:

``PREPARE``       create ``work/<node_id>-<attempt_id>.cnf`` exclusively and write CNF(F, C) in
                  chunks, hashing the bytes as written; compare with the independent digest of
                  the verified bundle (``cnf.cubecnf.CnfDigest``). The proof name must be free.
                  Stream mode: the two FIFOs are created exclusively here (``leaf.stream``), so
                  a taken name or a failed ``mkfifo`` is a failure before any route.
``UNIT``          unit propagation in time slices: a conflict gives a unit-v1 proof file
                  (route unit), a complete assignment a model (route unit), otherwise route cdcl.
                  Under a stream policy a unit route first removes the FIFOs: the unit proof is
                  a small file checked through the file protocol (specification §4.8, §6.4).
``SOLVE``         the pinned solver, **once** per attempt, with the recorded argv, CNF and proof
                  paths, AS cap, proof cap (fsize and watched) and deadline (none for an audit
                  attempt, ``unlimited_solver_time``: specification §11.2). No proofless solve.
``STREAM``        route cdcl under a stream policy instead of SOLVE ... CHECK: the coupled
                  solver -> relay -> checker run of :class:`~cubeproof.leaf.stream.StreamRun`
                  with the attempt's checker arena (the policy's first stream arena, or the one
                  the coordinator derived for a fresh attempt, ``stream_arena``), classified by
                  :func:`~cubeproof.leaf.stream.classify_stream`. Nothing is spooled or sealed;
                  the record is bound by :func:`~cubeproof.leaf.binding.bind_stream_verified` or
                  ``bind_outcome`` with the stream evidence. An arena exhaustion is recorded;
                  the fresh attempt is the coordinator's decision (``leaf.retry``). A rejection
                  is recorded with metadata-only quarantine (``stream_not_spooled``).
``SEAL``          exit 20 with a regular proof file: chmod read-only, size, I/O-service hash.
``QUEUED_CHECK``  the sealed proof waits for :meth:`LeafAttempt.start_check` (the scheduler's
                  check priority and fit, specification §8.4); solve CPU/RAM are free, the disk is
                  not.
``CHECK``         cake_lpr on the same CNF and proof with the fitted (then doubled) arena; an
                  eligible arena diagnostic returns to ``QUEUED_CHECK`` with the doubled arena:
                  only the check is repeated, the sealed proof is reused.
``MODEL``         the solver's model parsed and evaluated against CNF(F, C) in time slices.
``REHASH``        the CNF and the sealed proof hashed again by the I/O service.
``PUBLISH``       retain: a VERIFIED_UNSAT proof whose evidence the binding accepted
                  (``check_verified``) is published durably as ``proofs/<node_id>-<sha>.lrat``
                  through the single publication **before** its record (specification §6.1 step 6,
                  §7.2); quarantine: a CHECK_REJECTED proof is published as ``quarantine/...`` if
                  the quota permits. With ``publish_gate`` the coordinator first grants the copy's
                  disk (:meth:`LeafAttempt.start_publish`) or refuses it
                  (:meth:`LeafAttempt.refuse_publish`). The append follows on the next
                  :meth:`LeafAttempt.advance` after the answer, never before it.
``COMMIT``        the record built by :mod:`cubeproof.leaf.binding` appended (one append, after
                  every input, the verdict and any publication are established).
``CLEANUP``       removal of the work files this attempt created; then ``DONE``.
``ABANDONED``     no record: user cancellation before the commit, a failed or misbehaving I/O
                  service, a refused or uncertain commit (replay decides about the latter), or
                  a retained publication that did not complete (``retain_blocked``: a
                  VERIFIED_UNSAT without its reference would be a silent downgrade; the run
                  stops new work with :attr:`LeafAttempt.retain_blocked`).

The outcome is decided by the specification §6.3 table
(:func:`cubeproof.tools.process_outcome.classify`) from typed facts, with the binding failures of
this module (I/O failure, a hash that differs: ``io``/``file_changed``) as row 1, which outranks any
checker success. Routine decisions:

- A terminal outcome before any route was decided (the CNF could not be written or is not
  the expected CNF(F, C), the proof name is taken) has no solver run, so it is recorded with
  route unit (solver null, specification §4.8 attempt.solver).
- A SAT exit whose stdout exceeded the model capture (:func:`binding.model_capture_bytes`) is
  an unrecognized state: TOOL_FAILED ``protocol`` with diagnostic ``model_output: overflow``,
  never a guessed model.
- A failed hash of a file that is no longer a regular file is ``file_changed``; any other
  failed hash or file operation is ``io``.
- A checker launch refused before it started (e.g. a changed binary) is not a check that ran:
  it is not recorded in ``checks`` but the check time is the fitted one (specification §4.8).
- Quarantine of rejected proofs uses the :class:`~cubeproof.leaf.quarantine.QuarantineLedger`
  the coordinator passes (``quarantine``): the copy is reserved against the quota and
  published before the record; a quota miss or a failed copy records ``quarantined: null``
  with the reason (``quarantine_unavailable``) and the record is committed in every case. An
  attempt without a ledger (outside a coordinator) cannot account the quota and records
  ``quarantine_unavailable: not_supported``.
- A cancellation while a publication is in flight waits for its answer (the source stays
  until then) and records nothing; the copy is an orphan of the next startup (specification §7.5 row
  2).
"""

from __future__ import annotations

import dataclasses
import enum
import hashlib
import time
from collections.abc import Callable, Generator, Sequence
from dataclasses import dataclass
from typing import Any, Protocol

from cubeproof.base.errors import ConfigurationError, ContractError, CubeproofError, ToolError
from cubeproof.base.ids import new_id128
from cubeproof.cnf.cube import node_of
from cubeproof.cnf.cubecnf import CnfDigest
from cubeproof.cnf.dimacs import Formula
from cubeproof.cnf.model import ModelResult, solver_model_steps
from cubeproof.cnf.unit import UnitIndex
from cubeproof.contracts.enums import Outcome, ProofMode, Route
from cubeproof.contracts.identity import check_cube
from cubeproof.contracts.io import (
    AppendRequest,
    AppendValue,
    Area,
    Failure,
    HashRequest,
    HashValue,
    Job,
    PublishRequest,
    RemoveRequest,
    RemoveValue,
    Request,
    Result,
)
from cubeproof.contracts.policy import Policy
from cubeproof.evidence.schema import Attempt
from cubeproof.leaf import files
from cubeproof.leaf.binding import (
    AttemptIdentity,
    BindingError,
    CheckEvidence,
    FileHash,
    RelayEvidence,
    SolveEvidence,
    StreamEvidence,
    ToolPins,
    bind_outcome,
    bind_stream_verified,
    bind_verified,
    check_verified,
    checker_launch,
    fitted_check_time_ms,
    initial_arena,
    model_capture_bytes,
    solver_launch,
)
from cubeproof.leaf.quarantine import (
    NO_SPACE,
    NOT_SUPPORTED,
    Quarantined,
    QuarantineLedger,
    Unavailable,
    decide,
    quarantine_applies,
    quarantine_result,
)
from cubeproof.leaf.retain import Published, RetainBlocked, retain_request, retain_result
from cubeproof.leaf.retry import initial_stream_arena
from cubeproof.leaf.stream import (
    QUARANTINE_DIAGNOSTIC,
    Role,
    StreamDecision,
    StreamError,
    StreamFacts,
    StreamLimits,
    StreamPlan,
    StreamRun,
    StreamTools,
    classify_stream,
    relay_value,
    stream_paths,
)
from cubeproof.tools import checker as ck
from cubeproof.tools import solver as sv
from cubeproof.tools.isolation import PinnedBinary
from cubeproof.tools.process import Process, ProcessRun, Supervisor
from cubeproof.tools.process_outcome import (
    Action,
    ArenaLimits,
    CheckFacts,
    Decision,
    SolveFacts,
    classify,
)
from cubeproof.tools.process_outcome import Failure as Binding
from cubeproof.tools.unit_helper import SlicedTask, TaskState, UnitAnswer, UnitRoute, unit_task

__all__ = [
    "CheckRequest",
    "IoPort",
    "LeafAttempt",
    "LeafError",
    "LeafTools",
    "Phase",
]

#: Bounds of diagnostic text kept in a record (specification §4.8: bounded metadata only).
_TEXT = 300
_ITEMS = 64


class Phase(str, enum.Enum):
    PREPARE = "prepare"
    UNIT = "unit"
    SOLVE = "solve"
    STREAM = "stream"
    SEAL = "seal"
    QUEUED_CHECK = "queued_check"
    CHECK = "check"
    MODEL = "model"
    REHASH = "rehash"
    PUBLISH = "publish"
    COMMIT = "commit"
    CLEANUP = "cleanup"
    DONE = "done"
    ABANDONED = "abandoned"


_FINISHED = frozenset({Phase.DONE, Phase.ABANDONED})
#: Phases in which a cancellation still gives no record (specification §6.3: before the terminal
#: commit).
_CANCELLABLE = frozenset(
    {
        Phase.PREPARE,
        Phase.UNIT,
        Phase.SOLVE,
        Phase.STREAM,
        Phase.SEAL,
        Phase.QUEUED_CHECK,
        Phase.CHECK,
        Phase.MODEL,
        Phase.REHASH,
        Phase.PUBLISH,
    }
)


class LeafError(ToolError):
    """A misuse of the attempt or a result that does not belong to it (``leaf.*``)."""


class IoPort(Protocol):
    """The submitting side of the I/O service client (``tools.io_service_client.IoClient``)."""

    def submit(self, request: Request, *, attempt_id: str | None = None) -> Job: ...


@dataclass(frozen=True)
class LeafTools:
    """The pinned solver with its recorded argv, the pinned checker (specification §4.6) and, for
    the stream mode, the pinned interpreter that runs the relay script (``python``; None: no
    stream).

    The coordinator builds these from the measured machinery snapshot it recorded;
    :attr:`pins` is derived from them, so the binding's binary comparison is only as good as
    that construction (``leaf.binding`` module doc)."""

    solver: PinnedBinary
    solver_argv: tuple[str, ...]
    checker: PinnedBinary
    python: PinnedBinary | None = None
    #: The processor model of the machine (:func:`cubeproof.tools.machinery.host_cpu`), written
    #: into the diagnostics of every attempt; not a tool and not part of :attr:`pins`.
    host_cpu: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.solver, PinnedBinary) or not isinstance(self.checker, PinnedBinary):
            raise ValueError("leaf tools are pinned binaries")
        if self.python is not None and not isinstance(self.python, PinnedBinary):
            raise ValueError("the relay interpreter is a pinned binary")
        object.__setattr__(self, "solver_argv", tuple(self.solver_argv))
        sv.check_argv(self.solver_argv)

    @property
    def pins(self) -> ToolPins:
        python = None if self.python is None else self.python.sha256
        return ToolPins(
            self.solver.sha256, self.solver_argv, self.checker.sha256, python_sha256=python
        )


@dataclass(frozen=True)
class CheckRequest:
    """What the next check needs (for the scheduler's reservation, specification §8.3)."""

    heap_mib: int
    stack_mib: int
    memory_bytes: int
    time_ms: int
    proof_bytes: int


class _Purpose(str, enum.Enum):
    SEAL = "seal"
    CNF_FINAL = "cnf_final"
    PROOF_FINAL = "proof_final"
    PUBLISH = "publish"
    APPEND = "append"
    REMOVE = "remove"


_MEASUREMENTS = frozenset({_Purpose.SEAL, _Purpose.CNF_FINAL, _Purpose.PROOF_FINAL})


@dataclass(frozen=True)
class _Pending:
    job: Job
    purpose: _Purpose
    path: str | None


@dataclass(frozen=True)
class _Fixed:
    """A terminal outcome decided outside the specification §6.3 table (model, overflow, heap
    fit)."""

    outcome: Outcome
    reason: str | None
    model: ModelResult | None = None


@dataclass(frozen=True)
class _Verdict:
    """The decided outcome, before any publication; bound into the record at the commit."""

    outcome: Outcome
    reason: str | None
    model: ModelResult | None
    refusal: dict[str, Any]


def _bounded(text: str) -> str:
    return text if len(text) <= _TEXT else text[: _TEXT - 3] + "..."


def _used(run: ProcessRun) -> dict[str, int | None]:
    """Processor time and peak resident memory of one finished process (None: not known), with
    the resident size of the coordinator at the launch, below which the peak cannot be seen."""
    return {
        "cpu_ms": run.cpu_ms,
        "max_rss_kib": run.max_rss_kib,
        "launch_rss_kib": run.launch_rss_kib,
    }


def _stream_arena(policy: Policy, arena: tuple[int, int] | None) -> tuple[int, int]:
    """The checker arena of a stream attempt: the policy's first stream arena, or a derived
    one between it and the maxima (ValueError otherwise: no arena outside the ladder)."""
    first = initial_stream_arena(policy)
    if arena is None:
        return first
    if not isinstance(arena, tuple) or len(arena) != 2:
        raise ValueError(f"{arena!r} is not a (heap_mib, stack_mib) pair")
    heap, stack = arena
    if not (
        type(heap) is int
        and type(stack) is int
        and first[0] <= heap <= policy.checker_max_heap_mib
        and first[1] <= stack <= policy.checker_max_stack_mib
    ):
        raise ValueError(
            f"the stream arena {heap}/{stack} is outside {first} .. "
            f"{policy.checker_max_heap_mib}/{policy.checker_max_stack_mib}"
        )
    return heap, stack


class LeafAttempt:
    """One attempt on one node (module doc). Construct, then drive it to ``finished``."""

    def __init__(
        self,
        *,
        formula: Formula,
        digest: CnfDigest,
        cube: Sequence[int],
        policy: Policy,
        work_dir: str,
        tools: LeafTools,
        supervisor: Supervisor,
        io: IoPort,
        attempt_id: str | None = None,
        unit_index: UnitIndex | None = None,
        fits: ck.Fits | None = None,
        cnf_chunk: int = files.DEFAULT_CHUNK,
        unit_budget_ms: int | None = None,
        clock: Callable[[], int] = time.monotonic_ns,
        quarantine: QuarantineLedger | None = None,
        publish_gate: bool = False,
        stream_arena: tuple[int, int] | None = None,
        unlimited_solver_time: bool = False,
    ) -> None:
        if type(unlimited_solver_time) is not bool:
            raise ValueError("unlimited_solver_time is a bool")
        if quarantine is not None and not isinstance(quarantine, QuarantineLedger):
            raise ValueError("quarantine is a QuarantineLedger")
        if not isinstance(formula, Formula) or not isinstance(digest, CnfDigest):
            raise ValueError("an attempt needs the formula and its CnfDigest")
        same = digest.formula is formula or (
            digest.formula.sha256 == formula.sha256 and digest.formula.data == formula.data
        )
        if not same:
            raise ValueError("the digest belongs to another formula")
        if not isinstance(tools, LeafTools):
            raise ValueError("an attempt needs LeafTools")
        if type(cnf_chunk) is not int or cnf_chunk < 1:
            raise ValueError("cnf_chunk must be a positive integer")
        literals = check_cube(cube, formula.variables)
        self.formula = formula
        self.cube = literals
        self.tools = tools
        self.supervisor = supervisor
        self.io = io
        self.unit_index = unit_index
        self.arena_limits = ArenaLimits(
            max_heap_mib=policy.checker_max_heap_mib,
            max_stack_mib=policy.checker_max_stack_mib,
            fits=fits,
        )
        self.cnf_chunk = cnf_chunk
        self.unit_budget_ms = unit_budget_ms
        self.clock = clock
        # The identity is validated here, before any file exists (mode, ID, work directory).
        # The route is provisional until unit propagation decides it. An audit attempt has no
        # solver deadline (``unlimited_solver_time``, specification §11.2; refused under a stream
        # policy).
        self.identity = AttemptIdentity(
            node=node_of(formula, literals),
            attempt_id=new_id128() if attempt_id is None else attempt_id,
            policy=policy,
            route=Route.CDCL,
            work_dir=work_dir,
            cnf_sha256=digest.cnf_sha256(literals),
            unlimited_solver_time=unlimited_solver_time,
        )
        self.pins = tools.pins
        # stream mode: the relay interpreter and the checker arena, before any file
        self._stream_tools: StreamTools | None = None
        self.stream_arena: tuple[int, int] | None = None
        if policy.proof_mode is ProofMode.STREAM:
            if tools.python is None:
                raise ConfigurationError(
                    "leaf.relay_interpreter",
                    "a stream attempt needs the pinned interpreter that runs the relay",
                )
            self.stream_arena = _stream_arena(policy, stream_arena)
            self._stream_tools = StreamTools(
                tools.solver, tools.solver_argv, tools.checker, tools.python
            )
        elif stream_arena is not None:
            raise ValueError(f"a {policy.proof_mode.value} attempt takes no stream arena")
        self._stream: StreamRun | None = None
        self._stream_owned = False
        self._stream_facts: StreamFacts | None = None
        self._stream_decision: StreamDecision | None = None
        self._stream_proof: tuple[int, str] | None = None
        self.phase = Phase.PREPARE
        self.route: Route | None = None
        #: The bound record once established (before its append).
        self.record: Attempt | None = None
        #: The committed position (seq, head) after the durable append.
        self.committed: AppendValue | None = None
        #: Why the attempt ended without a record (None while running or after DONE).
        self.abandoned: str | None = None
        #: A failed cleanup after the commit (the startup reconciliation finishes it).
        self.cleanup_error: str | None = None
        self.cancelled = False
        self._failures: list[Binding] = []
        self._notes: list[str] = []
        self._secondary: tuple[str, ...] = ()
        self._extra: dict[str, Any] = {}
        self._pending: dict[int, _Pending] = {}
        self._writer: Generator[None, None, tuple[int, str]] | None = None
        self._cnf_created = False
        self._proof_created = False
        self._cnf_written: FileHash | None = None
        self._cnf_final: FileHash | None = None
        self._proof_sealed: FileHash | None = None
        self._proof_final: FileHash | None = None
        self._seal_size: int | None = None
        self._unit_task: SlicedTask[UnitAnswer] | None = None
        self._unit_proof_sha256: str | None = None
        self._model_task: SlicedTask[ModelResult] | None = None
        self._solve_process: Process | None = None
        self._solve: SolveEvidence | None = None
        self._solve_facts: SolveFacts | None = None
        self._check_process: Process | None = None
        self._checks: list[CheckEvidence] = []
        self._check_facts: list[CheckFacts] = []
        self._arena: tuple[int, int] | None = None
        self._check_launched = False
        self._fixed: _Fixed | None = None
        self._decision: Decision | None = None
        self._after_cleanup: str | None = None
        # publication: retained or quarantined copy before the record
        self.quarantine = quarantine
        self.publish_gate = bool(publish_gate)
        #: The publication this attempt asks for or runs (None: nothing to publish).
        self.publication: PublishRequest | None = None
        #: The durable copy the record references (retained or quarantined).
        self.published: Published | Quarantined | None = None
        #: Why a retained publication did not complete (the attempt then has no record).
        self.retain_blocked: RetainBlocked | None = None
        self._publish_started = False
        self._append_due = False
        self._quarantine_reserved = False
        self._unavailable: Unavailable | None = None
        self._verdict: _Verdict | None = None

    # -- identity and state -------------------------------------------------------------------

    @property
    def attempt_id(self) -> str:
        return self.identity.attempt_id

    @property
    def node_id(self) -> str:
        return self.identity.node_id

    @property
    def cnf_path(self) -> str:
        return self.identity.cnf_path

    @property
    def proof_path(self) -> str:
        return self.identity.proof_path

    @property
    def finished(self) -> bool:
        return self.phase in _FINISHED

    @property
    def wants_check(self) -> bool:
        return self.phase is Phase.QUEUED_CHECK and not self.cancelled

    @property
    def check_request(self) -> CheckRequest | None:
        """The next check's arenas, memory cap and time (None unless a check is queued)."""
        if self.phase is not Phase.QUEUED_CHECK or self._arena is None:
            return None
        assert self._proof_sealed is not None
        heap, stack = self._arena
        size = self._proof_sealed.bytes
        policy = self.identity.policy
        return CheckRequest(
            heap_mib=heap,
            stack_mib=stack,
            memory_bytes=ck.checker_memory_bytes(heap, stack, policy.checker_slack_mib),
            time_ms=fitted_check_time_ms(policy, size),
            proof_bytes=size,
        )

    @property
    def wants_publish(self) -> bool:
        """A gated publication waits for :meth:`start_publish` or :meth:`refuse_publish`."""
        return (
            self.phase is Phase.PUBLISH
            and self.publication is not None
            and not self._publish_started
            and not self.cancelled
        )

    @property
    def publish_request(self) -> PublishRequest | None:
        """The publication to reserve for (its proof size; None unless one waits)."""
        return self.publication if self.wants_publish else None

    @property
    def processes(self) -> tuple[Process, ...]:
        """Tool processes of this attempt that have not finished."""
        running = (self._solve_process, self._check_process)
        found = tuple(p for p in running if p is not None and p.run is None)
        if self._stream is not None:
            found += self._stream.processes
        return found

    def owns(self, job: Job) -> bool:
        """True if ``job`` is a pending job this attempt submitted itself."""
        pending = self._pending.get(job.job_id)
        return pending is not None and pending.job == job

    # -- the loop interface --------------------------------------------------------------------

    def advance(self, slice_ms: int = 20) -> Phase:
        """Do the bounded work that is due (at most about ``slice_ms`` of CPU); never wait."""
        if type(slice_ms) is not int or slice_ms < 1:
            raise ValueError("slice_ms must be a positive integer")
        end = self.clock() + slice_ms * 1_000_000
        while not self.finished:
            before = self.phase
            if self.cancelled and self.phase in _CANCELLABLE:
                self._cancel_step()
            else:
                self._step(slice_ms)
            if self.phase is before or self.clock() >= end:
                break
        return self.phase

    def start_check(self) -> None:
        """Launch the queued check (the scheduler reserved its memory and time)."""
        if self.phase is not Phase.QUEUED_CHECK or self.cancelled:
            raise LeafError("leaf.no_check", f"attempt {self.attempt_id} has no check queued")
        assert self._arena is not None and self._proof_sealed is not None
        heap, stack = self._arena
        launch = checker_launch(
            self.identity, self.tools.checker, heap, stack, self._proof_sealed.bytes
        )
        self._check_launched = True
        self._check_process = self.supervisor.start(launch)
        self.phase = Phase.CHECK

    def start_publish(self) -> None:
        """Submit the waiting publication (the coordinator reserved its disk, specification §7.2
        step 1)."""
        if not self.wants_publish:
            raise LeafError("leaf.no_publication", f"attempt {self.attempt_id} has none waiting")
        assert self.publication is not None
        self._publish_started = True
        self._submit(self.publication, _Purpose.PUBLISH, None)

    def refuse_publish(self, detail: str) -> None:
        """The copy's disk cannot be reserved: retain-full (no record, the run stops new work)
        or, for a quarantine copy, the rejection is recorded with null plus ``no_space``."""
        if not self.wants_publish:
            raise LeafError("leaf.no_publication", f"attempt {self.attempt_id} has none waiting")
        assert self.publication is not None
        self._publish_started = True
        if self.publication.area is Area.PROOFS:
            self._block(RetainBlocked.full(detail))
            return
        self._quarantine_failed(Unavailable(NO_SPACE, None, detail))
        self._append_due = True

    def deliver(self, job: Job, result: Result) -> None:
        """The verified result of a job this attempt submitted (LeafError otherwise)."""
        pending = self._pending.get(job.job_id)
        problem = self._delivery_problem(pending, job, result)
        if problem is not None:
            self._stop("io_mismatch")
            raise LeafError("leaf.io_mismatch", f"attempt {self.attempt_id}: {problem}")
        assert pending is not None
        del self._pending[job.job_id]
        if self.finished:
            return  # a late result of a stopped attempt: absorbed, nothing follows
        outcome = result.outcome
        if isinstance(outcome, Failure) and outcome.fatal:
            self._service_failed(f"{outcome.kind}: {outcome.rule}")
            return
        if self.cancelled and pending.purpose in _MEASUREMENTS:
            return  # cancelled before the commit: measurements no longer matter
        handler = {
            _Purpose.SEAL: self._sealed,
            _Purpose.CNF_FINAL: self._rehashed,
            _Purpose.PROOF_FINAL: self._rehashed,
            _Purpose.PUBLISH: self._published,
            _Purpose.APPEND: self._appended,
            _Purpose.REMOVE: self._removed,
        }[pending.purpose]
        handler(pending, outcome)

    def cancel(self, grace_ms: int | None = None) -> None:
        """User cancellation: no record unless the commit was already submitted (specification
        §6.3)."""
        if self.finished or self.phase not in _CANCELLABLE or self.cancelled:
            return
        self.cancelled = True
        grace = self.identity.policy.stop_grace_ms if grace_ms is None else grace_ms
        if self._stream is not None:
            self._stream.cancel(grace)  # the owner's cancellation of the coupled run
        for process in self.processes:
            self.supervisor.cancel(process, grace)
        self._close_work()

    def io_failed(self, detail: str) -> None:
        """The I/O service failed (specification §8.1: stop new work; replay decides uncertain
        commits)."""
        if not self.finished:
            self._service_failed(detail)

    # -- steps ---------------------------------------------------------------------------------

    def _step(self, slice_ms: int) -> None:
        if self.phase is Phase.PREPARE:
            self._prepare(slice_ms)
        elif self.phase is Phase.UNIT:
            self._unit(slice_ms)
        elif self.phase is Phase.SOLVE:
            self._solve_step()
        elif self.phase is Phase.STREAM:
            self._stream_step()
        elif self.phase is Phase.CHECK:
            self._check_step()
        elif self.phase is Phase.MODEL:
            self._model_step(slice_ms)
        elif self.phase is Phase.PUBLISH and self._append_due:
            self._commit()
        # SEAL, QUEUED_CHECK, REHASH, PUBLISH, COMMIT and CLEANUP otherwise wait for a result
        # or a grant.

    def _prepare(self, slice_ms: int) -> None:
        if self._writer is None:
            self._writer = files.write_cnf_steps(
                self.formula, self.cube, self.cnf_path, chunk=self.cnf_chunk
            )
        deadline = self.clock() + slice_ms * 1_000_000
        try:
            while True:
                next(self._writer)
                self._cnf_created = True
                if self.clock() >= deadline:
                    return
        except StopIteration as stop:
            size, digest = stop.value
        except OSError as error:
            self._writer = None
            self._io_failure("cnf_write", error)
            self._terminal(None)
            return
        self._writer = None
        self._cnf_written = FileHash(self.attempt_id, self.cnf_path, size, digest)
        if digest != self.identity.cnf_sha256:
            self._failure(Binding.FILE_CHANGED, "cnf:written_is_not_cnf_of_node")
        if not files.absent(self.proof_path):
            self._failure(Binding.IO, "proof:path_exists")
        if not self._failures and self._stream_tools is not None:
            self._make_fifos()
        if self._failures:
            self._terminal(None)
            return
        self.phase = Phase.UNIT

    def _make_fifos(self) -> None:
        """Stream mode: the coupled run and its two FIFOs, created exclusively (module doc)."""
        assert self._stream_tools is not None and self.stream_arena is not None
        identity = self.identity
        plan = StreamPlan.of(
            identity.policy,
            stream_paths(identity.work_dir, self.node_id, self.attempt_id),
            depth=identity.depth,
            arena=self.stream_arena,
            stdout_capture=model_capture_bytes(self.formula.variables),
        )
        run = StreamRun(self.supervisor, self._stream_tools, plan, clock=self.clock)
        try:
            run.prepare()
        except StreamError as error:  # nothing of it is left (create_fifos)
            self._failure(Binding.IO, _bounded(f"{error.rule}:{error.detail}"))
            return
        self._stream = run
        self._stream_owned = True

    def _drop_fifos(self) -> bool:
        """Remove this attempt's FIFOs (only FIFOs it created); False after an I/O failure."""
        run = self._stream
        if run is None or not self._stream_owned:
            return True
        try:
            run.cleanup()
        except (StreamError, OSError) as error:
            self._failure(Binding.IO, _bounded(f"stream:cleanup:{error}"))
            return False
        self._stream_owned = False
        return True

    def _to_cdcl(self) -> None:
        self._set_route(Route.CDCL)
        self.phase = Phase.STREAM if self._stream is not None else Phase.SOLVE

    def _unit(self, slice_ms: int) -> None:
        if self._unit_task is None:
            self._unit_task = unit_task(
                self.formula,
                self.cube,
                index=self.unit_index,
                budget_ms=self.unit_budget_ms,
                clock=self.clock,
            )
        state = self._unit_task.advance(slice_ms)
        if state is TaskState.RUNNING:
            return
        if state is TaskState.BUDGET:
            self._notes.append("unit:budget")
            self._to_cdcl()
            return
        answer = self._unit_task.result
        self._unit_task = None
        if answer.route is UnitRoute.UNDECIDED:
            self._to_cdcl()
            return
        self._set_route(Route.UNIT)
        if not self._drop_fifos():  # a unit route never streams (module doc)
            self._terminal(None)
        elif answer.route is UnitRoute.PROOF:
            self._unit_proof(answer)
        else:
            assert answer.model is not None
            self._terminal(_Fixed(answer.model.outcome, answer.model.reason, answer.model))

    def _unit_proof(self, answer: UnitAnswer) -> None:
        proof = answer.proof
        assert proof is not None
        self._unit_proof_sha256 = hashlib.sha256(proof).hexdigest()
        try:
            files.write_new_file(self.proof_path, proof)
        except OSError as error:
            self._proof_created = files.regular_file(self.proof_path)
            self._io_failure("proof_write", error)
            self._terminal(None)
            return
        self._proof_created = True
        self._seal()

    def _solve_step(self) -> None:
        if self._solve_process is None:
            launch = solver_launch(
                self.identity,
                self.tools.solver,
                self.tools.solver_argv,
                stdout_capture=model_capture_bytes(self.formula.variables),
            )
            self._solve_process = self.supervisor.start(launch)
        run = self._solve_process.run
        if run is None:
            return
        self._solve = SolveEvidence(self._solve_process.launch, run)
        self._proof_created = not files.absent(self.proof_path)
        complete = run.result.exit == sv.UNSAT_EXIT and files.regular_file(self.proof_path)
        self._solve_facts = SolveFacts(run=run, proof_complete=complete)
        decision = self._classify()
        if decision.action is Action.NO_RECORD:
            self.cancelled = True
        elif decision.action is Action.CHECK:
            self._seal()
        elif decision.action is Action.PARSE_MODEL:
            self.phase = Phase.MODEL
        else:
            self._terminal(None)

    def _stream_step(self) -> None:
        """The coupled run (module doc, STREAM): launch it once, react, classify at its end."""
        run = self._stream
        assert run is not None
        if not run.started:
            run.start()
        if not run.step():
            return
        facts = run.facts()
        self._stream_facts = facts
        self._solve = SolveEvidence(run.launches[Role.SOLVER], facts.solver)
        decision = self._classify_stream()
        if decision.action is Action.NO_RECORD:
            self.cancelled = True
        elif decision.action is Action.PARSE_MODEL:
            self.phase = Phase.MODEL
        else:
            self._terminal(None)

    def _classify_stream(self) -> StreamDecision:
        facts = self._stream_facts
        assert facts is not None
        decision = classify_stream(
            facts, StreamLimits.of(self.identity.policy), list(self._failures)
        )
        self._secondary = decision.secondary
        self._stream_proof = decision.proof
        self._stream_decision = decision if decision.action is Action.RECORD else None
        return decision

    def _stream_evidence(self) -> StreamEvidence:
        run, facts = self._stream, self._stream_facts
        assert run is not None and facts is not None
        launches = run.launches
        return StreamEvidence(
            solve=SolveEvidence(launches[Role.SOLVER], facts.solver),
            relay=RelayEvidence(launches[Role.RELAY], facts.relay),
            check=CheckEvidence(
                launches[Role.CHECKER], facts.checker, facts.heap_mib, facts.stack_mib
            ),
        )

    def _seal(self) -> None:
        try:
            self._seal_size = files.seal(self.proof_path)
        except OSError as error:
            self._io_failure("proof_seal", error, path=self.proof_path)
            self._terminal(None)
            return
        self.phase = Phase.SEAL
        self._submit(HashRequest(self.proof_path), _Purpose.SEAL, self.proof_path)

    def _sealed(self, pending: _Pending, outcome: Any) -> None:
        if self.phase is not Phase.SEAL:
            return
        if isinstance(outcome, HashValue):
            sealed = FileHash(self.attempt_id, self.proof_path, outcome.bytes, outcome.sha256)
            self._proof_sealed = sealed
            if sealed.bytes != self._seal_size:
                self._failure(Binding.FILE_CHANGED, "proof:sealed_size_differs")
            if self._unit_proof_sha256 is not None and sealed.sha256 != self._unit_proof_sha256:
                self._failure(Binding.FILE_CHANGED, "proof:not_the_unit_proof")
        else:
            self._hash_failed(pending, outcome)
        if self._failures:
            self._terminal(None)
            return
        assert self._proof_sealed is not None
        heap, stack = initial_arena(self.identity.policy, self._proof_sealed.bytes)
        if heap > self.identity.policy.checker_max_heap_mib:
            self._extra["initial_heap_mib"] = heap
            self._terminal(_Fixed(Outcome.EXHAUSTED, "check_memory"))
            return
        self._arena = (heap, stack)
        self.phase = Phase.QUEUED_CHECK

    def _check_step(self) -> None:
        process = self._check_process
        assert process is not None and self._arena is not None
        run = process.run
        if run is None:
            return
        self._check_process = None
        heap, stack = self._arena
        self._checks.append(CheckEvidence(process.launch, run, heap, stack))
        self._check_facts.append(CheckFacts(run=run, heap_mib=heap, stack_mib=stack))
        decision = self._classify()
        if decision.action is Action.NO_RECORD:
            self.cancelled = True
        elif decision.action is Action.RETRY_CHECK:
            assert decision.arena is not None
            self._arena = decision.arena
            self.phase = Phase.QUEUED_CHECK
        elif decision.action is Action.RECORD:
            self._terminal(None)
        else:  # pragma: no cover - classify never asks for a model or a first check here
            raise LeafError("leaf.internal", f"unexpected decision {decision.action}")

    def _model_step(self, slice_ms: int) -> None:
        if self._model_task is None:
            assert self._solve is not None
            stdout = self._solve.run.stdout
            if stdout is None:
                self._extra["model_output"] = "overflow"
                self._terminal(_Fixed(Outcome.TOOL_FAILED, "protocol"))
                return
            steps = solver_model_steps(stdout, self.formula, self.cube)
            self._model_task = SlicedTask(steps, clock=self.clock)
        if self._model_task.advance(slice_ms) is TaskState.RUNNING:
            return
        model = self._model_task.result
        self._model_task = None
        self._terminal(_Fixed(model.outcome, model.reason, model))

    # -- terminal: re-hash, decide, bind, commit, clean up ---------------------------------------

    def _terminal(self, fixed: _Fixed | None) -> None:
        """Every input is in; measure the files again before anything is decided."""
        self._fixed = fixed
        self.phase = Phase.REHASH
        if self._cnf_created:
            self._submit(HashRequest(self.cnf_path), _Purpose.CNF_FINAL, self.cnf_path)
        if self._proof_sealed is not None and self.phase is Phase.REHASH:
            self._submit(HashRequest(self.proof_path), _Purpose.PROOF_FINAL, self.proof_path)
        measuring = any(p.purpose in _MEASUREMENTS for p in self._pending.values())
        if self.phase is Phase.REHASH and not measuring:
            self._decide()

    def _rehashed(self, pending: _Pending, outcome: Any) -> None:
        if self.phase is not Phase.REHASH:
            return
        if isinstance(outcome, HashValue):
            assert pending.path is not None
            measured = FileHash(self.attempt_id, pending.path, outcome.bytes, outcome.sha256)
            if pending.purpose is _Purpose.CNF_FINAL:
                self._cnf_final = measured
                written = self._cnf_written
                if measured.sha256 != self.identity.cnf_sha256 or (
                    written is not None and measured.bytes != written.bytes
                ):
                    self._failure(Binding.FILE_CHANGED, "cnf:changed")
            else:
                self._proof_final = measured
                sealed = self._proof_sealed
                assert sealed is not None
                if (measured.bytes, measured.sha256) != (sealed.bytes, sealed.sha256):
                    self._failure(Binding.FILE_CHANGED, "proof:changed")
        else:
            self._hash_failed(pending, outcome)
        if not any(p.purpose in _MEASUREMENTS for p in self._pending.values()):
            self._decide()

    def _decide(self) -> None:
        """The final outcome (specification §6.3 with all binding facts), the bound record, the
        append."""
        fixed = self._fixed
        if fixed is None:
            # The table decision taken when the last run ended stands unless the re-hash
            # added a binding failure (row 1); row 1 precedes the arena row, so the
            # idle-machine fit is never asked twice and cannot turn the outcome into a retry.
            decision: Decision | StreamDecision | None
            if self._stream_facts is not None:
                decision = self._stream_decision
                if decision is None or self._failures:
                    decision = self._classify_stream()
            else:
                decision = self._decision
                if decision is None or self._failures:
                    decision = self._classify()
            if decision.action is Action.NO_RECORD:
                self._begin_cleanup("cancelled")
                return
            if decision.action is not Action.RECORD or decision.outcome is None:
                raise LeafError("leaf.internal", f"no terminal decision: {decision}")
            outcome, reason, model = decision.outcome, decision.reason, None
        elif self._failures:
            outcome, reason, model = Outcome.TOOL_FAILED, self._failures[0].value, None
        else:
            outcome, reason, model = fixed.outcome, fixed.reason, fixed.model
        if self.route is None:
            self._set_route(Route.UNIT)  # nothing ran: no solver result (module doc)
        refusal: dict[str, Any] = {}
        request: PublishRequest | None = None
        mode = self.identity.policy.proof_mode
        if outcome is Outcome.VERIFIED_UNSAT and mode is ProofMode.RETAIN:
            # The evidence is judged before anything is published (specification §6.1 step 6): a
            # refusal is TOOL_FAILED with the binding's reason and publishes nothing.
            try:
                checked = check_verified(self.identity, self.pins, **self._evidence())
            except BindingError as refused:
                outcome, reason = Outcome.TOOL_FAILED, refused.reason
                refusal = self._refusal(refused)
            else:
                request = retain_request(self.node_id, checked)
        elif quarantine_applies(mode, outcome):
            request = self._quarantine_request(mode, outcome)
        self._verdict = _Verdict(outcome, reason, model, refusal)
        if request is None:
            self._commit()
            return
        self.publication = request
        self.phase = Phase.PUBLISH
        if not self.publish_gate:
            self.start_publish()

    def _quarantine_request(self, mode: ProofMode, outcome: Outcome) -> PublishRequest | None:
        """The reserved quarantine copy of the rejected proof, or None (null plus reason)."""
        sealed = self._proof_sealed
        if self.quarantine is None or sealed is None:
            self._unavailable = Unavailable(NOT_SUPPORTED)
            return None
        decided = decide(
            self.quarantine, self.attempt_id, self.node_id, sealed, mode=mode, outcome=outcome
        )
        if isinstance(decided, Unavailable):
            self._unavailable = decided
            return None
        self._quarantine_reserved = True
        return decided

    def _published(self, pending: _Pending, outcome: Any) -> None:
        """The answer to this attempt's publication (specification §7.2 steps 2-3)."""
        del pending
        request = self.publication
        assert request is not None and self.phase is Phase.PUBLISH
        try:
            if request.area is Area.PROOFS:
                answer: Published | Quarantined | RetainBlocked | Unavailable = retain_result(
                    request, outcome
                )
            else:
                answer = quarantine_result(request, outcome)
        except ContractError as error:  # the service published another artifact
            self._stop("io_mismatch")
            raise LeafError("leaf.io_mismatch", f"attempt {self.attempt_id}: {error}") from None
        if isinstance(answer, Quarantined):
            assert self.quarantine is not None
            self.quarantine.published(self.attempt_id)
            self.published = answer
        elif isinstance(answer, Unavailable):
            self._quarantine_failed(answer)
        elif self.cancelled:
            return  # a retained copy without its record: an orphan of the next startup
        elif isinstance(answer, RetainBlocked):
            self._block(answer)
            return
        else:
            self.published = answer
        if not self.cancelled:
            self._append_due = True  # the append follows on the next advance (module doc)

    def _quarantine_failed(self, unavailable: Unavailable) -> None:
        """No durable quarantine copy: release the reservation, record null plus reason."""
        assert self.quarantine is not None and self._quarantine_reserved
        self.quarantine.failed(self.attempt_id)
        self._quarantine_reserved = False
        self._unavailable = unavailable

    def _block(self, blocked: RetainBlocked) -> None:
        """A retained publication that did not complete: no record (module doc)."""
        self.retain_blocked = blocked
        self._notes.append(blocked.note)
        self._begin_cleanup("retain_blocked")

    def _commit(self) -> None:
        """Bind the decided verdict with any published reference and append it (one append)."""
        verdict = self._verdict
        assert verdict is not None
        self._append_due = False
        self.record = self._bind(verdict)
        payload = {"type": "attempt", **self.record.to_json()}
        self.phase = Phase.COMMIT
        self._submit(AppendRequest.of(payload), _Purpose.APPEND, None)

    def _evidence(self) -> dict[str, Any]:
        return {
            "cnf_written": self._cnf_written,
            "cnf_final": self._cnf_final,
            "proof_sealed": self._proof_sealed,
            "proof_final": self._proof_final,
            "checks": list(self._checks),
            "solve": self._solve,
            "unit_proof_sha256": self._unit_proof_sha256,
        }

    @staticmethod
    def _refusal(refused: BindingError) -> dict[str, Any]:
        return {"binding": {"rule": refused.rule, "detail": _bounded(refused.detail)}}

    def _bind(self, verdict: _Verdict) -> Attempt:
        """The record through :mod:`cubeproof.leaf.binding`; a refused VERIFIED_UNSAT binding
        is recorded as TOOL_FAILED with the binding's reason (never as success)."""
        outcome, reason, refusal = verdict.outcome, verdict.reason, dict(verdict.refusal)
        if self.identity.streams and self._stream_facts is not None:
            return self._bind_stream(verdict)
        evidence = self._evidence()
        published = self.published
        if outcome is Outcome.VERIFIED_UNSAT:
            retained = published.artifact if isinstance(published, Published) else None
            try:
                return bind_verified(
                    self.identity,
                    self.pins,
                    retained=retained,
                    diagnostics=self._diagnostics(outcome),
                    **evidence,
                )
            except BindingError as refused:
                outcome, reason = Outcome.TOOL_FAILED, refused.reason
                refusal = self._refusal(refused)
        quarantined = None
        if outcome is Outcome.CHECK_REJECTED and isinstance(published, Quarantined):
            quarantined = published.artifact
        return bind_outcome(
            self.identity,
            self.pins,
            outcome=outcome,
            reason=reason,
            model=verdict.model,
            checked=self._check_launched,
            quarantined=quarantined,
            diagnostics=self._diagnostics(outcome) | refusal,
            **evidence,
        )

    def _bind_stream(self, verdict: _Verdict) -> Attempt:
        """The record of a coupled stream run (module doc, STREAM): VERIFIED_UNSAT only through
        ``bind_stream_verified``; a refusal is TOOL_FAILED with the binding's reason."""
        outcome, reason, refusal = verdict.outcome, verdict.reason, dict(verdict.refusal)
        facts = self._stream_facts
        assert facts is not None
        stream = self._stream_evidence()
        cnf: dict[str, Any] = {"cnf_written": self._cnf_written, "cnf_final": self._cnf_final}
        if outcome is Outcome.VERIFIED_UNSAT:
            try:
                return bind_stream_verified(
                    self.identity,
                    self.pins,
                    stream=stream,
                    diagnostics=self._diagnostics(outcome),
                    **cnf,
                )
            except BindingError as refused:
                outcome, reason = Outcome.TOOL_FAILED, refused.reason
                refusal = self._refusal(refused)
        return bind_outcome(
            self.identity,
            self.pins,
            outcome=outcome,
            reason=reason,
            model=verdict.model,
            stream=stream,
            relay=relay_value(facts),
            stream_proof=None if verdict.model is not None else self._stream_proof,
            diagnostics=self._diagnostics(outcome) | refusal,
            **cnf,
        )

    def _diagnostics(self, outcome: Outcome) -> dict[str, Any]:
        value: dict[str, Any] = {
            "secondary": [_bounded(s) for s in self._secondary[:_ITEMS]],
            "notes": [_bounded(s) for s in self._notes[:_ITEMS]],
        }
        value.update(self._extra)
        value["usage"] = self._usage()
        if outcome is Outcome.CHECK_REJECTED and not isinstance(self.published, Quarantined):
            if self.identity.streams:
                value.update(QUARANTINE_DIAGNOSTIC)  # metadata-only (specification §6.4)
            else:
                unavailable = self._unavailable or Unavailable(NOT_SUPPORTED)
                value.update(unavailable.diagnostics())
        return value

    def _usage(self) -> dict[str, Any]:
        """What the tools of this attempt used, for the record's diagnostics.

        ``elapsed_ms`` of a process result is wall-clock time and depends on what else the
        machine did; the processor time and the peak resident memory of each process are what
        a later reader needs to say what a leaf cost and how to size an audit. They are
        measurements beside the evidence: no rule reads them (specification §4.8, diagnostics).
        File modes: ``solver`` (a CDCL attempt) and ``checks``, one entry for each check of the
        record. Stream mode: ``solver``, ``relay`` and ``checker``, the coupled processes.
        """
        value: dict[str, Any] = {"host_cpu": self.tools.host_cpu}
        if self._stream_facts is not None:
            # a coupled run: its three processes by role (the record's ``checks`` may be empty)
            facts = self._stream_facts
            value["solver"] = _used(facts.solver)
            value["relay"] = _used(facts.relay)
            value["checker"] = _used(facts.checker)
            return value
        if self._solve_facts is not None:
            value["solver"] = _used(self._solve_facts.run)
        value["checks"] = [_used(check.run) for check in self._checks]  # as the record's checks
        return value

    def _appended(self, pending: _Pending, outcome: Any) -> None:
        del pending
        if isinstance(outcome, AppendValue):
            self.committed = outcome
            if self._quarantine_reserved:
                # the record referencing the quarantine copy is durable (reservation lifetime)
                assert self.quarantine is not None
                self.quarantine.committed(self.attempt_id)
                self._quarantine_reserved = False
            self._begin_cleanup(None)
        else:
            assert isinstance(outcome, Failure)
            self._notes.append(_bounded(f"append:{outcome.rule}"))
            self._begin_cleanup("commit_refused")

    def _begin_cleanup(self, abandon: str | None) -> None:
        self._after_cleanup = abandon
        if self._stream is not None and self._stream_owned:
            # no process of the run is alive here; only FIFOs this attempt created are removed
            try:
                self._stream.cleanup()
                self._stream_owned = False
            except (StreamError, OSError) as error:
                self.cleanup_error = self.cleanup_error or _bounded(f"stream:cleanup:{error}")
        if self._solve_process is not None and not self._proof_created:
            # The solver creates its proof file when it starts; a cancelled solve never
            # delivered a result that would have noted it. No tool runs any more here, and
            # PREPARE proved the attempt's proof name free before the launch, so whatever
            # now has that name is this attempt's disposable work (specification §6.1 step 7, §7.5
            # row 1).
            self._proof_created = not files.absent(self.proof_path)
        owned = ((self.cnf_path, self._cnf_created), (self.proof_path, self._proof_created))
        paths = tuple(path for path, created in owned if created)
        if not paths:
            self._end()
            return
        self.phase = Phase.CLEANUP
        self._submit(RemoveRequest(paths), _Purpose.REMOVE, None)

    def _removed(self, pending: _Pending, outcome: Any) -> None:
        del pending
        if not isinstance(outcome, RemoveValue):
            assert isinstance(outcome, Failure)
            self.cleanup_error = f"{outcome.kind}: {outcome.rule}"
        if not any(p.purpose is _Purpose.REMOVE for p in self._pending.values()):
            self._end()

    def _end(self) -> None:
        if self.committed is not None:
            self.phase = Phase.DONE
        else:
            self._settle()
            self.abandoned = self._after_cleanup or "cancelled"
            self.phase = Phase.ABANDONED

    def _settle(self) -> None:
        """No record follows: a quarantine reservation ends; a durable copy stays counted
        until the startup reconciliation removes it (specification §7.2 step 5)."""
        if self._quarantine_reserved:
            assert self.quarantine is not None
            self._quarantine_reserved = False
            self.quarantine.abandoned(self.attempt_id)

    # -- cancellation and failures --------------------------------------------------------------

    def _cancel_step(self) -> None:
        """A cancelled attempt: wait for its processes and for a publication in flight (its
        source stays until the answer), then remove its files."""
        if self.processes or any(p.purpose is _Purpose.PUBLISH for p in self._pending.values()):
            return
        self._close_work()
        self._begin_cleanup("cancelled")

    def _close_work(self) -> None:
        for task in (self._unit_task, self._model_task):
            if task is not None:
                task.cancel()
        self._unit_task = self._model_task = None
        if self._writer is not None:
            self._writer.close()
            self._writer = None

    def _service_failed(self, detail: str) -> None:
        """The service failed: no further I/O from this attempt (specification §8.1)."""
        if self.committed is not None:
            self.cleanup_error = self.cleanup_error or _bounded(detail)
        self._halt("io_failed")

    def _stop(self, reason: str) -> None:
        """A result that is not this attempt's: stop it without any further I/O (specification
        §8.1)."""
        self._halt(reason)

    def _halt(self, reason: str) -> None:
        """End now: cancel the tools, submit nothing more. Pending jobs stay known, so their
        late results are recognized and absorbed; replay decides an uncertain commit."""
        if self.finished:
            return
        grace = self.identity.policy.stop_grace_ms
        for process in self.processes:
            self.supervisor.cancel(process, grace)
        self._close_work()
        if self.committed is not None:
            self.phase = Phase.DONE
            return
        self._settle()
        if self.phase is Phase.COMMIT:
            self.abandoned = "commit_uncertain"
        elif self.phase is Phase.CLEANUP:
            self.abandoned = self._after_cleanup or reason
        else:
            self.abandoned = reason
        self.phase = Phase.ABANDONED

    # -- helpers ---------------------------------------------------------------------------------

    def _set_route(self, route: Route) -> None:
        self.route = route
        self.identity = dataclasses.replace(self.identity, route=route)

    def _classify(self) -> Decision:
        decision = classify(
            solve=self._solve_facts,
            checks=list(self._check_facts),
            limits=self.arena_limits,
            failures=list(self._failures),
        )
        self._secondary = decision.secondary
        self._decision = decision if decision.action is Action.RECORD else None
        return decision

    def _failure(self, failure: Binding, note: str) -> None:
        if failure not in self._failures:
            self._failures.append(failure)
        self._notes.append(note)

    def _io_failure(self, what: str, error: OSError, *, path: str | None = None) -> None:
        kind = Binding.IO
        if path is not None and not files.regular_file(path):
            kind = Binding.FILE_CHANGED
        self._failure(
            kind, _bounded(f"{what}:{error.__class__.__name__}:{error.strerror or error}")
        )

    def _hash_failed(self, pending: _Pending, outcome: Any) -> None:
        assert isinstance(outcome, Failure) and pending.path is not None
        kind = Binding.IO if files.regular_file(pending.path) else Binding.FILE_CHANGED
        self._failure(kind, _bounded(f"hash:{pending.purpose.value}:{outcome.rule}"))

    def _submit(self, request: Request, purpose: _Purpose, path: str | None) -> None:
        """Every job carries this attempt's ID (specification §8.1: identity-bound results)."""
        try:
            job = self.io.submit(request, attempt_id=self.attempt_id)
        except CubeproofError as error:
            self._service_failed(f"submit:{error.rule}")
            return
        self._pending[job.job_id] = _Pending(job, purpose, path)

    def _delivery_problem(self, pending: _Pending | None, job: Job, result: Result) -> str | None:
        if pending is None:
            return f"job {job.job_id} is not a pending job of this attempt"
        if pending.job != job:
            return f"job {job.job_id} is not the job this attempt submitted"
        if job.attempt_id != self.attempt_id:
            return f"job {job.job_id} belongs to attempt {job.attempt_id}"
        request = job.request
        if pending.path is not None and not (
            isinstance(request, HashRequest) and request.path == pending.path
        ):
            return f"job {job.job_id} does not measure {pending.path}"
        try:
            problem = result.problem(job)
        except ContractError as error:  # pragma: no cover - Result.problem does not raise
            problem = str(error)
        return problem
