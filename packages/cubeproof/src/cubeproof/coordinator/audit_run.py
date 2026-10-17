"""The audit executor: one audit journal, one target at a time (specification §7.3, §11.1, §11.2).

:class:`AuditExecutor` runs the attempts of an audit plan the command layer made
(:class:`~cubeproof.coordinator.audit_config.AuditWork`); it never selects targets and never
decides a status itself (``work.runnable`` and ``work.decide`` are the command layer's rules).
It reuses the run's pieces without the run's scheduler: the results/work layout and both locks,
the I/O service as the sole writer of the journal, the machinery and resource measurement with
the specification §8.3 proof-cap clamp, and :class:`~cubeproof.leaf.attempt.LeafAttempt` for every
attempt.

**Startup** (in this order): the results and work directories and their exclusive locks (a
second process is refused, exit 3), a check that no process of an older session still uses the
work directory, ``work = prepare(results)`` under the lock (the command layer binds the
certified inputs and regenerates the plan there), the validation and replay of an existing
audit journal (every record through the certifier's record rules and ``work.observe``; a torn
tail is repaired under the lock; a journal of another campaign or worker, or a run journal, is
refused), ``work.check_plan`` (what the journal holds must be the regenerated plan, else an
IntegrityError), removal of old work files, the measurement, the I/O service and the committed
header (purpose ``audit``) or resume before anything else.

**Effective policy.** The campaign policy with ``proof_mode`` transient (an audit keeps no
proof files: the new proof's size and hash are recorded) and ``proof_cap_bytes`` =
``config.proof_cap_bytes`` or, by default, the larger of the policy's cap and the largest
selected reference proof (specification §11.2: "the reference proof size allows an appropriate
cap"); then the specification §8.3 clamp against the measured budgets (``--memory``/``--disk``).
Every attempt runs with **no solver time limit** (``unlimited_solver_time``: ``solver_time_ms``
null).

**Plan.** Missing plan records are appended in order: ``audit_begin``, the ``audit_target``
records after those the journal holds, ``audit_ready``. No attempt is launched before
``audit_ready`` is durable.

**Targets**, in plan order, each without a committed ``audit_result``:

1. a target the session cannot run (``work.runnable`` False: a strict audit without the source
   solver) gets the placeholder attempt of :func:`~cubeproof.leaf.binding.bind_not_run`;
2. otherwise a :class:`LeafAttempt` runs (unit propagation, then the pinned solver once without
   a deadline, the admitted checker, the model check), and its record is committed;
3. a TOOL_FAILED attempt is run again while the target's tool failures do not exceed the
   policy's ``tool_retries`` (a transient failure is retried *before* the final result,
   specification §11.2);
4. ``audit_result`` with ``work.decide(target, attempt, machinery)`` refers to the target's last
   attempt.

A restart finishes what is missing: a target whose last committed attempt is final (anything
but a retryable TOOL_FAILED) gets its ``audit_result`` for that attempt without a new run; a
committed ``audit_result`` is never repeated.

**Stop.** SIGINT/SIGTERM cancels the running attempt (no record before its commit) and ends
the session after the record in flight (``interrupted``); an I/O service failure ends it
(``service_failed``). After a session without an error and with a complete plan,
``work.conclude(journal)`` is called while the lock is held (the command layer derives and
publishes the report there). Errors are raised as typed CubeproofError after an orderly shutdown.

Lifecycle points for ``config.hooks`` (crash tests kill the process there): ``startup.locked``,
``startup.replayed``, ``startup.measured``, ``snapshot.committed``, ``plan.begin``,
``plan.target``, ``plan.ready`` (each after its record is durable), ``attempt.started``,
``attempt.committed`` (the attempt record is durable, its result not yet submitted),
``result.committed``, ``shutdown``.
"""

from __future__ import annotations

import contextlib
import errno
import json
import signal
from collections import Counter
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from types import FrameType
from typing import Any

from cubeproof.base.canonical_json import document_bytes
from cubeproof.base.errors import (
    ConfigurationError,
    CubeproofError,
    InputError,
    IntegrityError,
    ToolError,
)
from cubeproof.base.ids import new_id128
from cubeproof.cnf.campaign import LoadedCampaign
from cubeproof.cnf.cube import node_of
from cubeproof.cnf.cubecnf import CnfDigest
from cubeproof.contracts.enums import Outcome, Purpose, Route
from cubeproof.contracts.identity import check_cube
from cubeproof.contracts.io import AppendRequest, AppendValue, Failure, Job, Op, Result
from cubeproof.contracts.values import Ref
from cubeproof.coordinator.audit_config import AuditConfig, AuditRun, AuditWork, Prepare
from cubeproof.coordinator.config import RunConfig, Stop
from cubeproof.coordinator.layout import WORK_LOCK_NAME, Layout, clear_work, wait_for_survivors
from cubeproof.coordinator.measure import Measured, measure
from cubeproof.coordinator.replay import peek_header, validator_of
from cubeproof.coordinator.resources import idle_fit
from cubeproof.coordinator.run import lock_descriptor
from cubeproof.coordinator.tail import JournalTail
from cubeproof.evidence.journal import JournalReader, RunLock
from cubeproof.evidence.journal.chain import ChainState
from cubeproof.evidence.journal.storage import repair_journal
from cubeproof.evidence.schema import (
    Attempt,
    AuditBegin,
    AuditReady,
    AuditResult,
    AuditTarget,
    AuditTargetRecord,
    Header,
    Machinery,
    Payload,
    Record,
    Resume,
)
from cubeproof.leaf.attempt import LeafAttempt, Phase
from cubeproof.leaf.binding import SOURCE_TOOL_UNAVAILABLE, AttemptIdentity, bind_not_run
from cubeproof.tools.io_service_client import IoClient

__all__ = ["AuditExecutor", "audit_cap", "is_retryable", "run_audit"]

_CPU_PHASES = frozenset({Phase.PREPARE, Phase.UNIT, Phase.MODEL})
_SLICE_MS = 20


def audit_cap(policy_cap: int, reference_bytes: int, configured: int | None) -> int:
    """The requested audit proof cap before the specification §8.3 clamp (module doc)."""
    if configured is not None:
        return configured
    return max(policy_cap, reference_bytes)


def is_retryable(attempt: Attempt) -> bool:
    """A TOOL_FAILED attempt that ran (a placeholder of a target that was not run is final)."""
    if attempt.outcome != Outcome.TOOL_FAILED:
        return False
    solver = attempt.solver
    return solver is None or solver.cause != SOURCE_TOOL_UNAVAILABLE


class _Interrupted(Exception):
    """A signal arrived while starting up or between records."""


@dataclass
class _TargetState:
    """What the journal holds for one planned target."""

    #: (attempt ref, attempt, machinery in force at it), in journal order
    attempts: list[tuple[Ref, Attempt, Machinery]] = field(default_factory=list)
    result: Ref | None = None

    @property
    def tool_failures(self) -> int:
        return sum(1 for _, attempt, _ in self.attempts if is_retryable(attempt))


class AuditExecutor:
    """One audit session on one results/work directory pair (module doc)."""

    def __init__(self, config: AuditConfig, prepare: Prepare) -> None:
        if not isinstance(config, AuditConfig):
            raise ValueError("an AuditExecutor needs an AuditConfig")
        self.config = config
        self.prepare = prepare
        self._signals = 0
        self._stop: Stop | None = None
        self._notes: list[str] = []
        self._counts: Counter[str] = Counter()
        self.lock: RunLock | None = None
        self.work_lock: RunLock | None = None
        self.layout: Layout | None = None
        self.work: AuditWork | None = None
        self.measured: Measured | None = None
        self.io: IoClient | None = None
        self.tail: JournalTail | None = None
        self._error: CubeproofError | None = None
        # the journal as replayed and followed
        self.journal_id: str | None = None
        self.seq = -1
        self.head: str | None = None
        self._machinery: Machinery | None = None
        self._begin: AuditBegin | None = None
        self._targets: list[AuditTarget] = []
        self._ready: AuditReady | None = None
        self._state: dict[str, _TargetState] = {}
        self._selfs: dict[int, str] = {}
        # jobs in flight
        self._own: dict[int, str] = {}
        self._acked: dict[int, AppendValue] = {}
        self._attempt: LeafAttempt | None = None
        self._retired: list[LeafAttempt] = []
        self._digests: dict[str, CnfDigest] = {}

    # -- helpers ------------------------------------------------------------------------------

    def _hook(self, name: str) -> None:
        if self.config.hooks is not None:
            self.config.hooks(name)

    @contextlib.contextmanager
    def _signal_scope(self) -> Iterator[None]:
        if not self.config.handle_signals:
            yield
            return
        previous: dict[signal.Signals, Any] = {}

        def handler(signum: int, frame: FrameType | None) -> None:
            del signum, frame
            self._signals += 1

        try:
            for number in (signal.SIGINT, signal.SIGTERM):
                previous[number] = signal.signal(number, handler)
        except ValueError:  # not the main thread: the caller owns signal handling
            for restored, old in previous.items():
                signal.signal(restored, old)
            previous.clear()
        try:
            yield
        finally:
            for restored, old in previous.items():
                signal.signal(restored, old)

    def _interruption_point(self) -> None:
        if self._signals:
            raise _Interrupted

    @property
    def _campaign(self) -> LoadedCampaign:
        assert self.work is not None
        return self.work.campaign

    # -- the whole session ----------------------------------------------------------------------

    def run(self) -> AuditRun:
        """Start up, run every target that has no result, shut down, and report."""
        # the handlers stay installed through the shutdown and the report (as in Coordinator.run)
        with self._signal_scope():
            try:
                try:
                    self._startup()
                    self._plan()
                    self._targets_loop()
                except _Interrupted:
                    self._stop = Stop.INTERRUPTED
            except CubeproofError as error:
                self._error = error
                raise
            except OSError as error:
                self._error = _classify_os_error(error)
                raise self._error from error
            finally:
                self._shutdown()
            return self._result()

    # -- startup --------------------------------------------------------------------------------

    def _startup(self) -> None:
        config = self.config
        self.layout = layout = Layout.of(config.results, config.work)
        layout.prepare()
        self.lock = RunLock.acquire(layout.lock)
        try:
            self.work_lock = RunLock.acquire(layout.work_lock)
        except ConfigurationError as error:
            if error.rule != "run.locked":
                raise
            raise ConfigurationError(
                "run.work_locked", f"{layout.work} is the work directory of another worker"
            ) from None
        self._hook("startup.locked")
        alive = wait_for_survivors(layout.work, wait_ms=config.survivor_wait_ms)
        if alive:
            raise ConfigurationError(
                "run.work_in_use", f"processes {alive} still use {layout.work}"
            )
        self.work = work = self.prepare(layout.results)
        if not isinstance(work, AuditWork):
            raise ValueError("prepare must return an AuditWork")
        self._interruption_point()
        self._replay()
        work.check_plan(self._begin, tuple(self._targets), self._ready)
        self._interruption_point()
        self._hook("startup.replayed")
        removed = clear_work(layout.work, keep=(WORK_LOCK_NAME,))
        if removed:
            self._notes.append(f"removed {removed} files left in the work directory")
        self.measured = self._measure()
        self._notes.extend(self.measured.notes)
        self._interruption_point()
        self._hook("startup.measured")
        self._begin_session()

    def _replay(self) -> None:
        """Validate and follow an existing audit journal (module doc); none: a new audit."""
        assert self.layout is not None and self.lock is not None
        path, limits = self.layout.journal, self.config.limits
        if not path.exists() or path.stat().st_size == 0:
            return
        header = peek_header(path, limits)
        if header is not None:
            owner, campaign, purpose = header
            if purpose != Purpose.AUDIT.value:
                raise ConfigurationError(
                    "audit.purpose", f"{path} is a {purpose} journal, not an audit"
                )
            if campaign != self._campaign.campaign.campaign_id:
                raise ConfigurationError(
                    "audit.campaign", f"{path} belongs to another campaign ({campaign})"
                )
            if owner != self.config.worker:
                raise ConfigurationError(
                    "audit.worker", f"{path} belongs to worker {owner}, not {self.config.worker}"
                )
        validator = validator_of(self._campaign)
        try:
            with path.open("rb") as stream:
                reader = JournalReader(stream, validator, name=path.name, limits=limits)
                for record in reader:
                    self._apply(record)
        except InputError as error:
            if error.rule == "journal.no_header":
                return  # a torn initial header: the service creates the journal again
            raise
        self.tail = JournalTail(path, reader.chain, validator, limits=limits)
        if path.stat().st_size > reader.chain.offset:
            outcome = repair_journal(
                path, validator=validator_of(self._campaign), run_lock=self.lock
            )
            if outcome is not None:
                self._notes.append(f"repaired a torn tail of {outcome.removed_bytes} bytes")
            self._sync()

    def _measure(self) -> Measured:
        assert self.work is not None and self.layout is not None
        config, campaign = self.config, self._campaign
        cap = audit_cap(
            campaign.campaign.policy.proof_cap_bytes,
            self.work.reference_bytes,
            config.proof_cap_bytes,
        )
        run_config = RunConfig(
            campaign=campaign.path,
            results=self.layout.results,
            work=self.layout.work,
            worker=config.worker,
            tools=config.tools,
            limits=config.limits,
            memory_bytes=config.memory_bytes,
            disk_bytes=config.disk_bytes,
            policy_overrides={"proof_cap_bytes": cap},
            proof_mode="transient",
            known_answer=config.known_answer,
            service_argv=config.service_argv,
            service_env=config.service_env,
            packages=config.packages,
            probes=config.probes,
            handle_signals=False,
            clock=config.clock,
        )
        return measure(
            run_config,
            campaign,
            self.layout.work,
            self.layout.results,
            frontier_nodes=len(self.work.targets),
        )

    def _begin_session(self) -> None:
        """The header (new audit) or resume, committed before anything else."""
        assert self.measured is not None
        measured = self.measured
        snapshot = {
            "machinery": measured.machinery.to_json(),
            "policy": measured.policy.to_json(),
            "resources": measured.resources.snapshot().to_json(),
        }
        if self.journal_id is None:
            header = {
                "type": "header",
                "worker": self.config.worker,
                "campaign": self._campaign.campaign.campaign_id,
                "purpose": Purpose.AUDIT.value,
                **snapshot,
            }
            self._spawn_service(header)
            self._sync()
            self._check_position()
        else:
            self._spawn_service(None)
            self._check_position()
            self._append({"type": "resume", **snapshot}, "resume")
        self._hook("snapshot.committed")

    def _spawn_service(self, header: dict[str, Any] | None) -> None:
        assert self.lock is not None and self.layout is not None
        config, layout = self.config, self.layout
        if not config.service_argv:
            raise ConfigurationError("run.service", "no I/O service command is configured")
        variables = {sha: b.formula.variables for sha, b in self._campaign.bundles.items()}
        descriptor = lock_descriptor(self.lock)
        argv = [
            *config.service_argv,
            "--results",
            str(layout.results),
            "--work",
            str(layout.work),
            "--journal",
            str(layout.journal),
            "--lock",
            str(self.lock.path),
            "--lock-fd",
            str(descriptor),
            "--campaign",
            self._campaign.campaign.campaign_id,
            "--variables",
            json.dumps(variables, sort_keys=True),
        ]
        header_path: Path | None = None
        if header is not None:
            header_path = layout.work / "header.json"
            header_path.write_bytes(document_bytes(header))
            argv += ["--header-file", str(header_path)]
        self.io = IoClient.spawn(
            argv, cwd=str(layout.results), pass_fds=(descriptor,), env=config.service_env
        )
        while self.io.hello is None and self.io.failure is None:
            self.io.poll(0.05)
            if self._signals:
                raise _Interrupted
        if self.io.failure is not None:
            raise ToolError(
                "io.service_failed", f"the I/O service did not start: {self.io.failure}"
            )
        if header_path is not None:
            with contextlib.suppress(OSError):
                header_path.unlink()
            self.tail = JournalTail(
                layout.journal,
                ChainState(name=layout.journal.name, limits=config.limits),
                validator_of(self._campaign),
                limits=config.limits,
            )

    def _check_position(self) -> None:
        """The service starts exactly at the end of the journal this session validated."""
        assert self.io is not None and self.tail is not None
        hello = self.io.hello
        if hello is None or (hello.seq, hello.head) != (self.tail.seq, self.tail.head):
            raise IntegrityError(
                "run.tail", "the journal changed between its validation and the service start"
            )

    # -- the journal ------------------------------------------------------------------------------

    def _apply(self, record: Record) -> None:
        """Fold one validated record (replayed or new) into the executor's view and hand it to
        ``work.observe`` (the command layer's audit-journal rules)."""
        assert self.work is not None
        if self.work.observe is not None:
            self.work.observe(record)
        payload = record.payload
        self.seq, self.head = record.seq, record.self_hash
        if isinstance(payload, Header):
            self.journal_id = record.self_hash
        if isinstance(payload, (Header, Resume)):
            self._machinery = payload.machinery
        elif isinstance(payload, AuditBegin):
            self._begin = payload
        elif isinstance(payload, AuditTargetRecord):
            self._targets.append(payload.target)
            self._state.setdefault(payload.target.node_id, _TargetState())
        elif isinstance(payload, AuditReady):
            self._ready = payload
        elif isinstance(payload, Attempt):
            assert self.journal_id is not None and self._machinery is not None
            state = self._state.get(payload.node_id)
            if state is not None:
                ref = Ref(self.journal_id, record.seq)
                state.attempts.append((ref, payload, self._machinery))
            self._counts["attempts"] += 1
            self._counts[f"outcome:{payload.outcome.value}"] += 1
        elif isinstance(payload, AuditResult):
            assert self.journal_id is not None
            state = self._state.setdefault(payload.target.node_id, _TargetState())
            state.result = Ref(self.journal_id, record.seq)
            self._counts["results"] += 1
            self._counts[f"status:{payload.status.value}"] += 1

    def _sync(self) -> list[Record]:
        assert self.tail is not None
        records = self.tail.poll()
        for record in records:
            self._apply(record)
            self._selfs[record.seq] = record.self_hash
        return records

    def _acknowledge(self, value: AppendValue) -> None:
        """The service's committed position must be a record the journal holds."""
        if value.seq not in self._selfs:
            self._sync()
        held = self._selfs.pop(value.seq, None)
        if held != value.head:
            raise IntegrityError(
                "run.tail",
                f"the service reported seq {value.seq} head {value.head}; the journal differs",
            )

    def _take(self, results: list[tuple[Job, Result]]) -> None:
        for job, result in results:
            outcome = result.outcome
            if isinstance(outcome, AppendValue):
                self._acknowledge(outcome)
            kind = self._own.pop(job.job_id, None)
            if kind is not None:
                if isinstance(outcome, Failure):
                    raise IntegrityError(
                        "audit.refused",
                        f"the journal refused this audit's {kind} record: "
                        f"{outcome.rule}: {outcome.detail}",
                    )
                assert isinstance(outcome, AppendValue)
                self._acked[job.job_id] = outcome
                continue
            owners = [a for a in (self._attempt, *self._retired) if a is not None and a.owns(job)]
            if not owners:
                raise ToolError("io.unknown_job", f"a result for job {job.job_id} of no task")
            if job.op is Op.APPEND and isinstance(outcome, AppendValue):
                self._hook("attempt.committed")
            owners[0].deliver(job, result)

    def _service_failure(self) -> str | None:
        assert self.io is not None
        failure = self.io.failure
        return None if failure is None else str(failure)

    def _append(
        self, payload: dict[str, Any], kind: str, *, attempt_id: str | None = None
    ) -> AppendValue:
        """Append one record of this module and wait for it to be durable and read back."""
        assert self.io is not None
        job = self.io.submit(AppendRequest.of(payload), attempt_id=attempt_id)
        self._own[job.job_id] = kind
        while job.job_id not in self._acked:
            self._take(self.io.poll(0.05))
            failure = self._service_failure()
            if failure is not None and job.job_id not in self._acked:
                raise ToolError("io.service_failed", failure)
        value = self._acked.pop(job.job_id)
        self._sync()
        return value

    @staticmethod
    def _payload(payload: Payload) -> dict[str, Any]:
        return {"type": payload.TYPE.value, **payload.to_json()}

    # -- the plan --------------------------------------------------------------------------------

    def _plan(self) -> None:
        """Append the plan records the journal does not hold yet (module doc)."""
        assert self.work is not None
        work = self.work
        if self._begin is None:
            self._append(self._payload(work.begin), "audit_begin")
            self._hook("plan.begin")
            self._interruption_point()
        targets = work.targets
        for ordinal in range(len(self._targets), len(targets)):
            record = work.plan[1 + ordinal]
            self._append(self._payload(record), "audit_target")
            self._hook("plan.target")
            self._interruption_point()
        if self._ready is None:
            self._append(self._payload(work.ready), "audit_ready")
            self._hook("plan.ready")
        # the journal holds exactly the regenerated plan now
        work.check_plan(self._begin, tuple(self._targets), self._ready)

    # -- the targets -----------------------------------------------------------------------------

    def _targets_loop(self) -> None:
        assert self.work is not None and self.measured is not None
        for target in self.work.targets:
            if self._stop is not None:
                return
            self._interruption_point()
            state = self._state.setdefault(target.node_id, _TargetState())
            if state.result is not None:
                continue
            self._finish_target(target, state)
        if self._stop is None:
            self._stop = Stop.COMPLETE

    def _final(self, state: _TargetState) -> tuple[Ref, Attempt, Machinery] | None:
        """The attempt the target's result refers to, if the journal already holds it."""
        assert self.measured is not None
        if not state.attempts:
            return None
        last = state.attempts[-1]
        retries = self.measured.policy.tool_retries
        if is_retryable(last[1]) and state.tool_failures <= retries:
            return None
        return last

    def _finish_target(self, target: AuditTarget, state: _TargetState) -> None:
        assert self.work is not None and self.measured is not None
        while (final := self._final(state)) is None:
            if self.work.runnable(target, self.measured.machinery):
                if not self._run_attempt(target):
                    return  # stopped: no record, the target stays pending
            else:
                self._not_run(target)
            self._interruption_point()
        ref, attempt, machinery = final
        status, reason = self.work.decide(target, attempt, machinery)
        result = AuditResult(target=target, attempt=ref, status=status, reason=reason)
        self._append(self._payload(result), "audit_result")
        self._hook("result.committed")

    def _identity_parts(self, target: AuditTarget) -> tuple[Any, CnfDigest, tuple[int, ...]]:
        formula = self._campaign.formula(target.node.formula_sha256)
        digest = self._digests.setdefault(formula.sha256, CnfDigest(formula))
        return formula, digest, tuple(check_cube(target.node.cube, formula.variables))

    def _not_run(self, target: AuditTarget) -> None:
        """The placeholder attempt of a target this session cannot run."""
        assert self.measured is not None and self.layout is not None
        formula, digest, cube = self._identity_parts(target)
        identity = AttemptIdentity(
            node=node_of(formula, cube),
            attempt_id=new_id128(),
            policy=self.measured.policy,
            route=Route.CDCL,
            work_dir=str(self.layout.work),
            cnf_sha256=digest.cnf_sha256(cube),
            unlimited_solver_time=True,
        )
        source = target.machinery.solver
        detail = (
            f"strict audit: the source solver {source.sha256} with argv {list(source.argv)} "
            "is not the configured one"
        )
        record = bind_not_run(identity, detail=detail)
        self._append(self._payload(record), "attempt", attempt_id=record.attempt_id)
        self._hook("attempt.committed")

    def _run_attempt(self, target: AuditTarget) -> bool:
        """One attempt of ``target`` to its end; False if it ended without a record."""
        assert self.measured is not None and self.layout is not None and self.io is not None
        measured = self.measured
        formula, digest, cube = self._identity_parts(target)
        attempt = LeafAttempt(
            formula=formula,
            digest=digest,
            cube=cube,
            policy=measured.policy,
            work_dir=str(self.layout.work),
            tools=measured.tools,
            supervisor=measured.supervisor,
            io=self.io,
            fits=idle_fit(measured.policy, measured.resources.capacity),
            clock=self.config.clock,
            unlimited_solver_time=True,
        )
        self._attempt = attempt
        self._hook("attempt.started")
        try:
            self._drive(attempt)
        finally:
            self._attempt = None
            if not attempt.finished or attempt.phase is not Phase.DONE:
                self._retired.append(attempt)
        if attempt.phase is Phase.DONE:
            assert attempt.committed is not None
            self._sync()
            if attempt.cleanup_error:
                self._notes.append(
                    f"cleanup of attempt {attempt.attempt_id}: {attempt.cleanup_error}"
                )
            return True
        reason = attempt.abandoned
        if reason == "commit_refused":
            raise IntegrityError(
                "audit.refused", f"the journal refused the record of attempt {attempt.attempt_id}"
            )
        if reason == "io_mismatch":
            raise ToolError("leaf.io_mismatch", f"attempt {attempt.attempt_id} was stopped")
        if self._stop is None:
            self._stop = Stop.INTERRUPTED if reason == "cancelled" else Stop.SERVICE
        if reason != "cancelled":
            self._notes.append(f"attempt {attempt.attempt_id} abandoned: {reason}")
        return False

    def _drive(self, attempt: LeafAttempt) -> None:
        """Advance the attempt, its processes and the I/O service until it has finished."""
        assert self.measured is not None and self.io is not None
        supervisor, io = self.measured.supervisor, self.io
        cancelled = False
        while not attempt.finished:
            if self._signals and not cancelled:
                cancelled = True
                self._stop = Stop.INTERRUPTED
                attempt.cancel()
            if self._signals >= 2:
                supervisor.stop(1)  # a second signal: no more grace
            phase = attempt.advance(_SLICE_MS)
            if attempt.wants_check:
                attempt.start_check()
            if attempt.finished:
                break
            timeout_ms = 0 if phase in _CPU_PHASES else self.config.tick_ms
            if supervisor.active:
                supervisor.step(timeout_ms)
                self._take(io.poll(0.0))
            else:
                self._take(io.poll(timeout_ms / 1000))
            failure = self._service_failure()
            if failure is not None:
                if self._stop is None:
                    self._stop = Stop.SERVICE
                    self._notes.append(f"the I/O service failed: {failure}")
                attempt.io_failed(failure)

    # -- shutdown and the result -------------------------------------------------------------------

    def _shutdown(self) -> None:
        self._hook("shutdown")
        if self._attempt is not None:
            self._attempt.cancel(grace_ms=1)
        measured = self.measured
        if measured is not None:
            try:
                measured.supervisor.shutdown(grace_ms=min(measured.policy.stop_grace_ms, 5000))
            except ToolError as error:
                self._notes.append(f"shutdown: {error}")
        if self.io is not None:
            self.io.close(timeout=30.0)
        if self.tail is not None:
            try:
                self._sync()
            except CubeproofError as error:
                if self._error is None:
                    self._error = error
            self.tail.close()
        try:
            self._conclude()
        finally:
            if self.work_lock is not None:
                self.work_lock.release()
            if self.lock is not None:
                self.lock.release()

    def _conclude(self) -> None:
        """``work.conclude`` after a session without an error and with a complete plan."""
        work, layout = self.work, self.layout
        if self._error is not None or work is None or layout is None or work.conclude is None:
            return
        if self._ready is None or self._stop is None:
            return
        work.conclude(layout.journal)

    def _result(self) -> AuditRun:
        assert self._stop is not None
        pending = sum(
            1
            for t in (self.work.targets if self.work is not None else ())
            if (s := self._state.get(t.node_id)) is None or s.result is None
        )
        return AuditRun(
            stop=self._stop,
            journal=self.journal_id,
            seq=self.seq,
            head=self.head,
            pending=pending,
            session=dict(sorted(self._counts.items())),
            notes=tuple(self._notes),
        )


_ACCESS_ERRORS = frozenset(
    {errno.EACCES, errno.EPERM, errno.ENOENT, errno.ENOTDIR, errno.EISDIR, errno.EROFS}
)


def _classify_os_error(error: OSError) -> CubeproofError:
    where = f"{error.filename}: " if error.filename else ""
    detail = f"{where}{error.strerror or error}"
    if error.errno in _ACCESS_ERRORS:
        return ConfigurationError("run.access", detail)
    return ToolError("run.io", detail)


def run_audit(config: AuditConfig, prepare: Prepare) -> AuditRun:
    """One audit session as a library call (:class:`AuditExecutor`)."""
    return AuditExecutor(config, prepare).run()
