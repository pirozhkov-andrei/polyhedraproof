"""The coupled stream run and its outcome precedence (specification §4.8, §6.2-§6.4, §8.3).

In stream mode a CDCL leaf runs three supervised processes at once: the pinned solver
writes its LRAT proof into a FIFO, the relay (:mod:`cubeproof.tools.relay`, a separate
bounded process) hashes, counts and forwards it into a second FIFO, and the pinned checker
reads the proof from there. Nothing is spooled: the work directory holds the CNF and the two
FIFOs only (specification §8.3: no proof disk reservation). A unit refutation never streams: it is a
small file checked through the file protocol even when the policy is stream
(:func:`protocol_for`; specification §4.8, §6.4).

:class:`StreamRun` drives one such run without blocking (the coordinator's loop steps the
shared :class:`~cubeproof.tools.process.Supervisor`):

- **files**: both FIFOs are created exclusively (mode 0600) at the attempt's own paths
  ``<work>/<node_id>-<attempt_id>.lrat`` (solver side) and ``.check.lrat`` (checker side);
  an existing name is never reused (``stream.path_exists``); cleanup removes only FIFOs;
- **launch order**: relay, checker, solver. The relay opens its input without blocking and
  its output with explicit readiness (the relay module doc), so no order deadlocks;
- **one paired deadline**: the solver's ``leaf_time_ms`` covers the whole coupled task
  (``check_time_ms`` does not extend it, specification §6.4); each process gets the time that
  remains of it when it is launched, so all three expire together;
- **teardown**: the supervisor terminates processes whose partner is gone, so nothing waits for
  the deadline in vain: a process that did not start ends the others; a solver that ended on
  its own other than by exit 20 ends the relay and the checker (they only ever saw a partial
  proof); a relay that ended without a complete transfer ends the solver (the checker is not
  terminated: its own diagnostic may be the primary cause; it only gets EOF); a relay that
  still runs ``term_grace_ms`` after the checker ended is ended (cake_lpr stops reading at
  the empty clause, possibly just before the solver's EOF, so the relay is not ended at once;
  a slower solver exit after an early checker success therefore counts as a broken
  transfer). A terminated process is recorded as torn
  down; its ``cancelled`` cause and its termination signal are then secondary facts, never a
  user cancellation or a crash;
- **EOF nudges**: when the solver has ended, its FIFO is opened for writing and closed once
  (without data) so that a relay that never saw a writer reaches EOF; likewise the checker's
  FIFO when the relay ended without a complete transfer, so that a checker blocked in opening
  its input gets EOF. A solver that exited without opening its proof output is therefore
  indistinguishable from one that wrote an empty proof.

:func:`classify_stream` is the specification §6.3 table with the specification §6.4 stream
precedence, from the facts of the three runs (first applicable row wins):

0. user cancellation (or a supervisor stop of a process that was not torn down) -> no record;
1. launch failure, changed binary (solver, relay interpreter or checker), I/O or file binding
   -> TOOL_FAILED ``launch``/``binary_changed``/``io``/``file_changed``;
S. a clean solver exit 10 -> parse the model. The checker could only ever have read a partial
   proof that does not end in the empty clause, so its arena, rejection or crash, and any
   relay condition, are secondary;
2. the relay reached the proof cap -> EXHAUSTED ``proof_size`` (before the EPIPE, termination
   or checker failure the cap causes);
3. the coupled deadline while the solver ran -> EXHAUSTED ``time``;
4. the coupled deadline of the checker or the relay -> EXHAUSTED ``check_time``;
U. a solver that ended **on its own** other than by exit 20 (not torn down, and not a SIGPIPE
   while the transfer was broken, which is the consequence of the relay or checker stopping
   first): its allocation failure or memory event (EXHAUSTED ``solver_memory``), crash
   (TOOL_FAILED ``crash``) or unsupported exit (TOOL_FAILED ``protocol``) is upstream of
   whatever the checker then did with the partial proof, so it precedes rows 5 and 7;
5. a pinned checker arena diagnostic without contradictory success -> EXHAUSTED
   ``check_memory``/``check_stack`` (before the relay EPIPE and the solver's end it causes); the
   fresh attempt with the derived arena is the coordinator's (:mod:`cubeproof.leaf.retry`);
6. solver allocation failure or attributable memory event -> EXHAUSTED ``solver_memory``;
7. a checker crash (before its downstream relay errors), a solver crash (a SIGPIPE caused by a
   broken transfer is not one), a relay crash -> TOOL_FAILED ``crash``; output held open, a
   solver exit other than 10/20, a relay without a valid report -> TOOL_FAILED ``protocol``;
   an incomplete transfer (EPIPE, termination, early checker exit, a relay that did not end
   cleanly) -> TOOL_FAILED ``relay``;
9. a complete proof (clean solver exit 20 and a complete transfer) and a clean checker
   rejection -> CHECK_REJECTED ``rejected`` with metadata-only quarantine
   (:data:`QUARANTINE_DIAGNOSTIC`: nothing was spooled, nothing can be recovered);
10. a complete proof and the exact checker success (``tools.checker.accepts``) -> VERIFIED_UNSAT;
11. anything else -> TOOL_FAILED ``protocol``.

Proof fields (:attr:`StreamDecision.proof`) are the relay's count and hash only for a complete
transfer of a clean exit-20 solve; partial counters live in the ``relay`` value only (specification
§4.8). The record itself is built by the leaf binding (``bind_stream_verified``, ``bind_outcome``)
from the evidence of the run; :class:`~cubeproof.leaf.attempt.LeafAttempt` drives it.
"""

from __future__ import annotations

import enum
import errno
import os
import signal
import stat
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any

from cubeproof.base.errors import ToolError
from cubeproof.base.process import Cause
from cubeproof.contracts.enums import Outcome, ProofMode, Route
from cubeproof.contracts.policy import HeapFit, Policy
from cubeproof.leaf.binding import RELAY_ARGS, RELAY_MEMORY_BYTES, RELAY_SCRIPT, attempt_paths
from cubeproof.leaf.retry import exhausted_reason, initial_stream_arena
from cubeproof.tools import checker as ck
from cubeproof.tools import relay as rl
from cubeproof.tools import solver as sv
from cubeproof.tools.isolation import PinnedBinary
from cubeproof.tools.process import Launch, Process, ProcessRun, Supervisor
from cubeproof.tools.process_outcome import Action, Failure

__all__ = [
    "MISSING_REPORT",
    "QUARANTINE_DIAGNOSTIC",
    "RELAY_ARGS",
    "RELAY_MEMORY_BYTES",
    "RELAY_SCRIPT",
    "Role",
    "StreamDecision",
    "StreamError",
    "StreamFacts",
    "StreamLimits",
    "StreamPaths",
    "StreamPlan",
    "StreamRun",
    "StreamTools",
    "checker_stream_launch",
    "classify_stream",
    "create_fifos",
    "protocol_for",
    "relay_launch",
    "relay_value",
    "remove_fifos",
    "solver_stream_launch",
    "stream_paths",
]

MIB = 1 << 20
# The relay's address-space cap, script and interpreter flags are the binding's
# (RELAY_MEMORY_BYTES, RELAY_SCRIPT, RELAY_ARGS): the launches built here are what it checks.
#: Stdout kept of the relay (its report is one short line).
_RELAY_CAPTURE = 4096
#: The ``relay.error`` of a record whose relay left no valid report.
MISSING_REPORT = "no_report"
#: Stream quarantine is metadata-only (specification §6.4).
QUARANTINE_DIAGNOSTIC = MappingProxyType({"quarantine_unavailable": "stream_not_spooled"})
_EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
_SIGPIPE = int(signal.SIGPIPE)
_NS_PER_MS = 1_000_000


class StreamError(ToolError):
    """A misuse of a stream run or a file it cannot use (``stream.*``)."""


class Role(str, enum.Enum):
    SOLVER = "solver"
    RELAY = "relay"
    CHECKER = "checker"


_ORDER = (Role.SOLVER, Role.RELAY, Role.CHECKER)


def protocol_for(policy: Policy, route: Route) -> str:
    """``"stream"`` only for a CDCL leaf under a stream policy; unit proofs and the file modes
    use the file protocol (specification §4.8: a unit proof under stream has relay null)."""
    if policy.proof_mode is ProofMode.STREAM and route is Route.CDCL:
        return "stream"
    return "file"


# -- files ---------------------------------------------------------------------------------------


@dataclass(frozen=True)
class StreamPaths:
    """The attempt's CNF and its two FIFOs (all in the private work directory)."""

    cnf: str
    solver_fifo: str
    checker_fifo: str

    @property
    def work_dir(self) -> str:
        return os.path.dirname(self.cnf)

    @property
    def fifos(self) -> tuple[str, str]:
        return self.solver_fifo, self.checker_fifo


def stream_paths(work_dir: str, node_id: str, attempt_id: str) -> StreamPaths:
    """``<work>/<node_id>-<attempt_id>.cnf``, ``.lrat`` (solver side), ``.check.lrat``."""
    cnf, proof = attempt_paths(work_dir, node_id, attempt_id)
    return StreamPaths(cnf, proof, proof.removesuffix(".lrat") + ".check.lrat")


def create_fifos(paths: StreamPaths) -> None:
    """Create both FIFOs exclusively (mode 0600); on any failure none of them is left."""
    made: list[str] = []
    try:
        for path in paths.fifos:
            try:
                os.mkfifo(path, 0o600)
            except FileExistsError:
                raise StreamError("stream.path_exists", f"{path} already exists") from None
            except OSError as error:
                raise StreamError("stream.io", f"{path}: {error}") from error
            made.append(path)
            if not stat.S_ISFIFO(os.lstat(path).st_mode):
                raise StreamError("stream.io", f"{path} is not the FIFO just created")
    except BaseException:
        for path in made:
            _unlink_fifo(path)
        raise


def _unlink_fifo(path: str) -> bool:
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return False
    if not stat.S_ISFIFO(info.st_mode):
        return False  # not ours: never removed
    os.unlink(path)
    return True


def _eof_nudge(path: str) -> bool:
    """Open a FIFO for writing and close it at once, without data: its reader (blocked in
    ``open`` or polling) gets EOF. True when done or impossible; False to try again (ENXIO:
    no reader yet)."""
    flags = os.O_WRONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        fd = os.open(path, flags)
    except OSError as error:
        return error.errno != errno.ENXIO
    try:
        if not stat.S_ISFIFO(os.fstat(fd).st_mode):
            return True  # not a FIFO (never written to): nothing to nudge
    finally:
        os.close(fd)
    return True


def remove_fifos(paths: StreamPaths) -> list[str]:
    """Remove the attempt's FIFOs (only FIFOs: any other object at those names stays)."""
    removed = []
    for path in paths.fifos:
        try:
            if _unlink_fifo(path):
                removed.append(path)
        except OSError as error:
            raise StreamError("stream.cleanup", f"{path}: {error}") from error
    return removed


# -- tools, plan and launches --------------------------------------------------------------------


@dataclass(frozen=True)
class StreamTools:
    """The pinned solver (with its recorded argv), checker and relay interpreter."""

    solver: PinnedBinary
    solver_argv: tuple[str, ...]
    checker: PinnedBinary
    python: PinnedBinary
    relay_script: str = RELAY_SCRIPT

    def __post_init__(self) -> None:
        for name in ("solver", "checker", "python"):
            if not isinstance(getattr(self, name), PinnedBinary):
                raise ValueError(f"StreamTools.{name} must be a PinnedBinary")
        object.__setattr__(self, "solver_argv", tuple(self.solver_argv))
        sv.check_argv(self.solver_argv)
        script = self.relay_script
        if not isinstance(script, str) or not script.startswith("/") or "\0" in script:
            raise ValueError("StreamTools.relay_script must be an absolute path")


def _positive(name: str, value: object) -> None:
    if type(value) is not int or value < 1:
        raise ValueError(f"StreamPlan.{name} must be a positive integer, not {value!r}")


@dataclass(frozen=True)
class StreamPlan:
    """Everything one coupled run needs: paths, arenas, the paired deadline and limits."""

    paths: StreamPaths
    heap_mib: int
    stack_mib: int
    deadline_ms: int
    proof_cap_bytes: int
    solver_memory_bytes: int
    checker_slack_mib: int
    term_grace_ms: int
    stdout_capture: int = 0

    def __post_init__(self) -> None:
        if not isinstance(self.paths, StreamPaths):
            raise ValueError("StreamPlan.paths must be StreamPaths")
        for name in (
            "heap_mib",
            "stack_mib",
            "deadline_ms",
            "proof_cap_bytes",
            "solver_memory_bytes",
            "checker_slack_mib",
            "term_grace_ms",
        ):
            _positive(name, getattr(self, name))
        if type(self.stdout_capture) is not int or self.stdout_capture < 0:
            raise ValueError("StreamPlan.stdout_capture must be a nonnegative integer")

    @classmethod
    def of(
        cls,
        policy: Policy,
        paths: StreamPaths,
        *,
        depth: int,
        arena: tuple[int, int] | None = None,
        stdout_capture: int = 0,
    ) -> StreamPlan:
        """The plan of a stream attempt at cube size ``depth``: the first stream arena, or
        the ``arena`` derived for a retry (:func:`cubeproof.leaf.retry.stream_arena`)."""
        heap, stack = initial_stream_arena(policy) if arena is None else arena
        return cls(
            paths=paths,
            heap_mib=heap,
            stack_mib=stack,
            deadline_ms=policy.leaf_time_ms_for_depth(depth),
            proof_cap_bytes=policy.proof_cap_bytes,
            solver_memory_bytes=policy.solver_memory_bytes,
            checker_slack_mib=policy.checker_slack_mib,
            term_grace_ms=policy.term_grace_ms,
            stdout_capture=stdout_capture,
        )


def solver_stream_launch(tools: StreamTools, plan: StreamPlan, deadline_ms: int) -> Launch:
    """The pinned solver with its recorded argv, writing its proof into the solver FIFO
    (no file size cap or watch: nothing is written to a file)."""
    paths = plan.paths
    return Launch(
        binary=tools.solver,
        args=sv.solver_args(tools.solver_argv, paths.cnf, paths.solver_fifo),
        cwd=paths.work_dir,
        memory_bytes=plan.solver_memory_bytes,
        deadline_ms=deadline_ms,
        term_grace_ms=plan.term_grace_ms,
        stdout_capture=plan.stdout_capture,
    )


def relay_launch(tools: StreamTools, plan: StreamPlan, deadline_ms: int) -> Launch:
    """The relay script under the pinned interpreter, capped at the relay cap (specification
    §8.3)."""
    paths = plan.paths
    return Launch(
        binary=tools.python,
        args=(
            *RELAY_ARGS,
            tools.relay_script,
            paths.solver_fifo,
            paths.checker_fifo,
            str(plan.proof_cap_bytes),
        ),
        cwd=paths.work_dir,
        memory_bytes=RELAY_MEMORY_BYTES,
        deadline_ms=deadline_ms,
        term_grace_ms=plan.term_grace_ms,
        stdout_capture=_RELAY_CAPTURE,
    )


def checker_stream_launch(tools: StreamTools, plan: StreamPlan, deadline_ms: int) -> Launch:
    """The pinned checker on the CNF and the checker FIFO with the plan's arenas."""
    paths = plan.paths
    return Launch(
        binary=tools.checker,
        args=ck.checker_args(plan.heap_mib, plan.stack_mib, paths.cnf, paths.checker_fifo),
        cwd=paths.work_dir,
        memory_bytes=ck.checker_memory_bytes(plan.heap_mib, plan.stack_mib, plan.checker_slack_mib),
        deadline_ms=deadline_ms,
        term_grace_ms=plan.term_grace_ms,
    )


_BUILDERS: dict[Role, Callable[[StreamTools, StreamPlan, int], Launch]] = {
    Role.RELAY: relay_launch,
    Role.CHECKER: checker_stream_launch,
    Role.SOLVER: solver_stream_launch,
}
#: Launch order: the relay first (it never blocks), then the checker, then the solver.
_LAUNCH_ORDER = (Role.RELAY, Role.CHECKER, Role.SOLVER)


# -- the run -------------------------------------------------------------------------------------


@dataclass(frozen=True)
class StreamFacts:
    """The finished runs of one coupled stream run and what the controller did."""

    solver: ProcessRun
    relay: ProcessRun
    checker: ProcessRun
    heap_mib: int
    stack_mib: int
    #: Roles the controller terminated because a partner had ended (module doc).
    torn_down: frozenset[Role] = field(default_factory=frozenset)
    #: The run was cancelled by its owner (a user cancellation: no record).
    cancelled: bool = False

    @property
    def report(self) -> rl.RelayReport | None:
        """The relay's report, if its complete stdout is exactly one valid report line."""
        return rl.parse_report(self.relay.stdout)

    def run_of(self, role: Role) -> ProcessRun:
        return {Role.SOLVER: self.solver, Role.RELAY: self.relay, Role.CHECKER: self.checker}[role]


class StreamRun:
    """One coupled solver -> relay -> checker run (module doc). Never blocks."""

    def __init__(
        self,
        supervisor: Supervisor,
        tools: StreamTools,
        plan: StreamPlan,
        *,
        clock: Callable[[], int] = time.monotonic_ns,
    ) -> None:
        if not isinstance(tools, StreamTools) or not isinstance(plan, StreamPlan):
            raise ValueError("a stream run needs StreamTools and a StreamPlan")
        self.supervisor = supervisor
        self.tools = tools
        self.plan = plan
        self.clock = clock
        self.prepared = False
        #: The launches as given to the supervisor (for the binding), by role.
        self.launches: dict[Role, Launch] = {}
        #: The supervised processes, by role (a refused launch is an already finished one).
        self.started: dict[Role, Process] = {}
        self._torn: set[Role] = set()
        self._cancelled = False
        #: EOF nudges by the reading role: True while due, False once given (module doc).
        self._nudges: dict[Role, bool] = {}
        self._checker_end_ns: int | None = None

    # -- state -------------------------------------------------------------------------------

    @property
    def processes(self) -> tuple[Process, ...]:
        """The processes of this run that have not finished."""
        return tuple(p for p in self.started.values() if p.run is None)

    @property
    def finished(self) -> bool:
        return len(self.started) == len(_ORDER) and not self.processes

    @property
    def cancelled(self) -> bool:
        return self._cancelled

    # -- control -----------------------------------------------------------------------------

    def prepare(self) -> None:
        """Create the two FIFOs (exclusively); idempotent once it succeeded."""
        if not self.prepared:
            create_fifos(self.plan.paths)
            self.prepared = True

    def start(self) -> None:
        """Launch relay, checker and solver under one paired deadline."""
        if self.started:
            raise StreamError("stream.started", "a stream run is started once")
        if self._cancelled:
            raise StreamError("stream.cancelled", "the run was cancelled before it started")
        self.prepare()
        begun = self.clock()
        total = self.plan.deadline_ms
        for role in _LAUNCH_ORDER:
            elapsed = max(0, (self.clock() - begun) // _NS_PER_MS)
            launch = _BUILDERS[role](self.tools, self.plan, max(1, total - elapsed))
            self.launches[role] = launch
            self.started[role] = self.supervisor.start(launch)

    def cancel(self, grace_ms: int | None = None) -> None:
        """Owner cancellation (a user stop or an unneeded attempt): no record (specification
        §6.3)."""
        self._cancelled = True
        grace = self.plan.term_grace_ms if grace_ms is None else grace_ms
        for process in self.processes:
            self.supervisor.cancel(process, grace)

    def step(self) -> bool:
        """React to processes that ended (teardown, EOF nudge); True once all have ended."""
        if len(self.started) != len(_ORDER):
            return False
        if self.finished:
            return True
        if not self._cancelled:
            self._react()
        return self.finished

    def _run(self, role: Role) -> ProcessRun | None:
        return self.started[role].run

    def _react(self) -> None:
        runs = {role: self._run(role) for role in _ORDER}
        if any(run is not None and not run.result.started for run in runs.values()):
            self._teardown(*_ORDER)
        solver, relay, checker = runs[Role.SOLVER], runs[Role.RELAY], runs[Role.CHECKER]
        if solver is not None:
            self._nudges.setdefault(Role.RELAY, True)  # the relay's input: solver gone
            result = solver.result
            on_its_own = Role.SOLVER not in self._torn and result.signal != _SIGPIPE
            if on_its_own and not (result.exit == sv.UNSAT_EXIT and result.signal is None):
                # no complete proof can come: the partners only see a partial one
                self._teardown(Role.RELAY, Role.CHECKER)
        if relay is not None:
            report = rl.parse_report(relay.stdout)
            if relay.result.exit != rl.EXIT_COMPLETE or report is None or not report.complete:
                # the transfer is broken: the solver cannot finish it; the checker is not
                # terminated (its own diagnostics may be the primary cause), it only gets EOF
                self._teardown(Role.SOLVER)
                self._nudges.setdefault(Role.CHECKER, True)  # the checker's input: relay gone
        if checker is not None and relay is None:
            # cake_lpr may stop at the empty clause just before the solver's EOF reached the
            # relay: the relay is ended only if it still runs ``term_grace_ms`` after the
            # checker ended (e.g. it waits for a checker that never opened its input)
            now = self.clock()
            if self._checker_end_ns is None:
                self._checker_end_ns = now
            if now - self._checker_end_ns >= self.plan.term_grace_ms * _NS_PER_MS:
                self._teardown(Role.RELAY)
        fifos = {
            Role.RELAY: self.plan.paths.solver_fifo,
            Role.CHECKER: self.plan.paths.checker_fifo,
        }
        for role, due in list(self._nudges.items()):
            if due and self._run(role) is None:
                self._nudges[role] = not _eof_nudge(fifos[role])

    def _teardown(self, *roles: Role) -> None:
        for role in roles:
            process = self.started[role]
            if process.run is None and not process.leader_exited():
                self._torn.add(role)
                self.supervisor.cancel(process, self.plan.term_grace_ms)

    # -- results -----------------------------------------------------------------------------

    def facts(self) -> StreamFacts:
        if not self.finished:
            raise StreamError("stream.running", "the stream run has not finished")
        runs = {role: self._run(role) for role in _ORDER}
        solver, relay, checker = runs[Role.SOLVER], runs[Role.RELAY], runs[Role.CHECKER]
        assert solver is not None and relay is not None and checker is not None
        return StreamFacts(
            solver=solver,
            relay=relay,
            checker=checker,
            heap_mib=self.plan.heap_mib,
            stack_mib=self.plan.stack_mib,
            torn_down=frozenset(self._torn),
            cancelled=self._cancelled,
        )

    def cleanup(self) -> list[str]:
        """Remove the FIFOs once no process of the run is alive (``stream.running`` before)."""
        if self.started and not self.finished:
            raise StreamError("stream.running", "processes of the stream run are alive")
        return remove_fifos(self.plan.paths)


# -- the outcome table ----------------------------------------------------------------------------


@dataclass(frozen=True)
class StreamLimits:
    """The policy values the table needs for the arena reason (specification §6.3, §6.4)."""

    max_heap_mib: int
    max_stack_mib: int
    heap_fit: HeapFit

    @classmethod
    def of(cls, policy: Policy) -> StreamLimits:
        return cls(policy.checker_max_heap_mib, policy.checker_max_stack_mib, policy.heap_fit)


@dataclass(frozen=True)
class StreamDecision:
    """What to record (or do) for one coupled run."""

    action: Action
    outcome: Outcome | None
    reason: str | None
    #: The record's ``relay`` value (specification §4.8).
    relay: dict[str, Any]
    #: ``(proof_bytes, proof_sha256)`` for a complete proof, else None (specification §4.8).
    proof: tuple[int, str] | None
    #: Raw secondary conditions (diagnostics), e.g. ``relay:error:...``, ``solver:signal:13``.
    secondary: tuple[str, ...] = ()
    #: Diagnostics the record must carry (metadata-only quarantine of a rejected stream).
    diagnostics: dict[str, Any] = field(default_factory=dict)


def _effective(facts: StreamFacts, role: Role) -> tuple[Cause, ...]:
    """The run's causes, without the cancellation of a teardown (module doc)."""
    causes = facts.run_of(role).causes
    if role in facts.torn_down:
        return tuple(c for c in causes if c is not Cause.CANCELLED)
    return causes


def _relay_clean(facts: StreamFacts) -> bool:
    result = facts.relay.result
    return (
        result.started
        and result.exit == rl.EXIT_COMPLETE
        and result.signal is None
        and not _effective(facts, Role.RELAY)
    )


def relay_value(facts: StreamFacts) -> dict[str, Any]:
    """The record's ``relay`` object: the report's fields; a missing report or a relay that
    did not end cleanly is never presented as a complete transfer."""
    report = facts.report
    if report is None:
        return {
            "bytes": 0,
            "sha256": _EMPTY_SHA256,
            "solver_eof": False,
            "all_written": False,
            "error": MISSING_REPORT,
        }
    value = report.record_value()
    if report.complete and not _relay_clean(facts):
        result = facts.relay.result
        if result.signal is not None:
            value["error"] = f"relay_signal:{result.signal}"
        elif result.exit != rl.EXIT_COMPLETE:
            value["error"] = f"relay_exit:{result.exit}"
        else:
            value["error"] = "relay_cause:" + ",".join(
                c.value for c in _effective(facts, Role.RELAY)
            )
    return value


def _observations(facts: StreamFacts, role: Role) -> list[str]:
    label = role.value
    run = facts.run_of(role)
    torn = role in facts.torn_down
    notes = [
        f"{label}:teardown" if torn and cause is Cause.CANCELLED else f"{label}:{cause.value}"
        for cause in run.causes
    ]
    result = run.result
    if not result.started:
        notes.append(f"{label}:not_started")
    if result.signal is not None:
        notes.append(f"{label}:signal:{result.signal}")
    if result.exit is not None and result.exit != 0:
        notes.append(f"{label}:exit:{result.exit}")
    if role is Role.CHECKER:
        arena = ck.exhausted_arena(result.stderr_tail)
        if arena is not None:
            notes.append(f"checker:arena:{arena.value}")
        if ck.accepts(result):
            notes.append("checker:accepted")
    if role is Role.SOLVER and sv.allocation_failure(result):
        notes.append("solver:bad_alloc")
    if role is Role.RELAY and result.started:
        report = facts.report
        if report is None:
            notes.append(f"relay:{MISSING_REPORT}")
        elif report.error is not None:
            notes.append(f"relay:error:{report.error}")
    return notes


def _solver_row(
    facts: StreamFacts, causes: tuple[Cause, ...], transferred: bool
) -> tuple[str, str, str] | None:
    """``(outcome, reason, primary)`` of a solver that ended on its own other than by a clean
    exit 20 (row U of the module doc), else None."""
    result = facts.solver.result
    if Role.SOLVER in facts.torn_down or not result.started:
        return None
    if result.signal == _SIGPIPE and not transferred:
        return None  # the relay stopped reading first: a consequence, not a cause
    if sv.allocation_failure(result) or Cause.MEMORY_EVENT in causes:
        return Outcome.EXHAUSTED.value, "solver_memory", "solver:bad_alloc"
    if result.signal is not None:
        return Outcome.TOOL_FAILED.value, "crash", f"solver:signal:{result.signal}"
    if result.exit is not None and result.exit not in (sv.SAT_EXIT, sv.UNSAT_EXIT):
        return Outcome.TOOL_FAILED.value, "protocol", f"solver:exit:{result.exit}"
    return None


def classify_stream(  # noqa: PLR0911 - one return per table row keeps the order visible
    facts: StreamFacts, limits: StreamLimits, failures: Sequence[Failure] = ()
) -> StreamDecision:
    """The decision for one finished coupled run (module doc, rows in order)."""
    for failure in failures:
        if not isinstance(failure, Failure):
            raise ValueError(f"{failure!r} is not a Failure")
    if not isinstance(facts, StreamFacts) or not isinstance(limits, StreamLimits):
        raise ValueError("classify_stream needs StreamFacts and StreamLimits")
    report = facts.report
    relay = relay_value(facts)
    notes = [n for role in _ORDER for n in _observations(facts, role)]
    notes += [f"binding:{failure.value}" for failure in failures]
    solver = facts.solver.result
    checker = facts.checker.result
    solver_causes = _effective(facts, Role.SOLVER)
    checker_causes = _effective(facts, Role.CHECKER)
    relay_causes = _effective(facts, Role.RELAY)
    transferred = report is not None and report.complete
    complete_transfer = transferred and _relay_clean(facts)
    clean_unsat = (
        solver.started
        and solver.exit == sv.UNSAT_EXIT
        and solver.signal is None
        and not solver_causes
    )
    proof = (report.bytes, report.sha256) if complete_transfer and clean_unsat and report else None

    def decision(
        action: Action,
        outcome: Outcome | None = None,
        reason: str | None = None,
        primary: str | None = None,
        diagnostics: dict[str, Any] | None = None,
        with_proof: bool = True,
    ) -> StreamDecision:
        secondary = tuple(n for n in notes if n != primary)
        return StreamDecision(
            action=action,
            outcome=outcome,
            reason=reason,
            relay=relay,
            proof=proof if with_proof else None,
            secondary=secondary,
            diagnostics=dict(diagnostics or {}),
        )

    def record(outcome: Outcome, reason: str | None, primary: str | None = None) -> StreamDecision:
        return decision(Action.RECORD, outcome, reason, primary)

    # 0. user cancellation: the owner's, or a supervisor stop of a process not torn down
    if facts.cancelled or any(
        Cause.CANCELLED in facts.run_of(role).causes and role not in facts.torn_down
        for role in _ORDER
    ):
        return decision(Action.NO_RECORD, with_proof=False)
    # 1. launch, binary, I/O and file binding (also over success)
    for role in _ORDER:
        run = facts.run_of(role)
        for cause in _effective(facts, role):
            if cause in (Cause.LAUNCH, Cause.BINARY_CHANGED):
                return record(Outcome.TOOL_FAILED, str(cause.value), f"{role.value}:{cause.value}")
        if not run.result.started:
            return record(Outcome.TOOL_FAILED, "launch", f"{role.value}:not_started")
    if failures:
        reason = str(failures[0].value)
        return record(Outcome.TOOL_FAILED, reason, f"binding:{reason}")
    # S. a clean SAT exit: the checker and the relay only saw a partial proof
    if solver.exit == sv.SAT_EXIT and solver.signal is None and not solver_causes:
        return decision(Action.PARSE_MODEL, with_proof=False)
    # 2. the proof cap (before the EPIPE, termination and checker failure it causes)
    if (
        report is not None
        and report.error == rl.ERROR_CAP
        and facts.relay.result.exit == rl.EXIT_CAP
    ):
        return record(Outcome.EXHAUSTED, "proof_size", f"relay:error:{rl.ERROR_CAP}")
    # 3./4. the paired deadline
    if Cause.DEADLINE in solver_causes:
        return record(Outcome.EXHAUSTED, "time", "solver:deadline")
    if Cause.DEADLINE in checker_causes:
        return record(Outcome.EXHAUSTED, "check_time", "checker:deadline")
    if Cause.DEADLINE in relay_causes:
        return record(Outcome.EXHAUSTED, "check_time", "relay:deadline")
    # U. a solver that ended on its own without exit 20 (not torn down, not a SIGPIPE of a
    #    broken transfer): its end is upstream of anything the checker did with the partial
    #    proof, so rows 6/7 of the solver come before the checker's rows 5/7
    upstream = _solver_row(facts, solver_causes, transferred)
    if upstream is not None:
        return record(Outcome(upstream[0]), upstream[1], upstream[2])
    # 5. checker arena exhaustion (before the relay EPIPE and the solver's end it causes)
    arena = ck.arena_diagnostic(checker)
    if arena is not None and not checker_causes:
        if ck.contradictory_success(checker):
            return record(Outcome.TOOL_FAILED, "protocol")
        step = ck.next_stream_arena(
            arena,
            facts.heap_mib,
            facts.stack_mib,
            relay_bytes=0 if report is None else report.bytes,
            fit=limits.heap_fit,
            max_heap_mib=limits.max_heap_mib,
            max_stack_mib=limits.max_stack_mib,
        )
        return record(
            Outcome.EXHAUSTED, exhausted_reason(arena, step), f"checker:arena:{arena.value}"
        )
    # 6. solver memory
    if sv.allocation_failure(solver) or Cause.MEMORY_EVENT in solver_causes:
        return record(Outcome.EXHAUSTED, "solver_memory", "solver:bad_alloc")
    # 7. crashes, protocol, transport
    if checker.signal is not None and Role.CHECKER not in facts.torn_down:
        return record(Outcome.TOOL_FAILED, "crash", f"checker:signal:{checker.signal}")
    if (
        solver.signal is not None
        and Role.SOLVER not in facts.torn_down
        and not (solver.signal == _SIGPIPE and not transferred)
    ):
        return record(Outcome.TOOL_FAILED, "crash", f"solver:signal:{solver.signal}")
    relay_result = facts.relay.result
    if relay_result.signal is not None and Role.RELAY not in facts.torn_down:
        return record(Outcome.TOOL_FAILED, "crash", f"relay:signal:{relay_result.signal}")
    if any(Cause.HELD_OPEN in _effective(facts, role) for role in _ORDER):
        return record(Outcome.TOOL_FAILED, "protocol")
    if (
        Role.SOLVER not in facts.torn_down
        and solver.exit is not None
        and solver.exit not in (sv.SAT_EXIT, sv.UNSAT_EXIT)
    ):
        return record(Outcome.TOOL_FAILED, "protocol", f"solver:exit:{solver.exit}")
    if report is None and Role.RELAY not in facts.torn_down:
        return record(Outcome.TOOL_FAILED, "protocol", f"relay:{MISSING_REPORT}")
    if not complete_transfer:
        primary = None if report is None else f"relay:error:{report.error}"
        return record(Outcome.TOOL_FAILED, "relay", primary)
    if not clean_unsat:
        return record(Outcome.TOOL_FAILED, "protocol")
    # 9./10. a complete proof
    checker_run = facts.checker
    exact = not checker_run.causes and not checker_run.stderr_truncated
    if exact and ck.clean_rejection(checker):
        return decision(
            Action.RECORD,
            Outcome.CHECK_REJECTED,
            "rejected",
            diagnostics=dict(QUARANTINE_DIAGNOSTIC),
        )
    if exact and ck.accepts(checker) and ck.exhausted_arena(checker.stderr_tail) is None:
        return record(Outcome.VERIFIED_UNSAT, None, "checker:accepted")
    # 11. anything else
    return record(Outcome.TOOL_FAILED, "protocol")
