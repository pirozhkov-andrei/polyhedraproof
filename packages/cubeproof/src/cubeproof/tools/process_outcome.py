"""The specification §6.3 outcome table for file-mode attempts (and unit proofs), from typed facts.

:func:`classify` is called after the solve and after every check. It returns what to do
next: record a terminal outcome with its reason, run the (first) check, retry the check with
larger arenas, parse the solver's model, or record nothing (user cancellation). It is pure:
it reads the typed causes the supervisor recorded, the process results, whether the proof
is complete (exit 20 and a closed, present proof file; specification §6.1) and the binding failures
the caller detected (I/O, re-hash after the check). Rows, first applicable wins:

0. explicit user cancellation before the terminal commit -> no record;
1. launch failure, missing/changed binary, I/O/hash failure, violated file binding ->
   TOOL_FAILED ``launch``/``binary_changed``/``io``/``file_changed`` (overrides success);
2. supervisor reached the proof cap, or solver SIGXFSZ -> EXHAUSTED ``proof_size``;
3. supervisor reached the solver deadline -> EXHAUSTED ``time``;
4. supervisor reached the check deadline -> EXHAUSTED ``check_time``;
5. pinned checker arena diagnostic without contradictory success -> retry the check with
   the doubled arena if within maxima/fit, else EXHAUSTED ``check_memory``/``check_stack``;
6. pinned solver allocation failure or attributable memory event -> EXHAUSTED
   ``solver_memory``;
7. unexpected signal -> TOOL_FAILED ``crash``; unsupported exit protocol, output held open
   by a descendant, contradictory arena success -> TOOL_FAILED ``protocol``;
8. solver exit 10 -> parse the model (MODEL/INVALID_MODEL are decided there, specification §4.8);
9. complete proof, clean checker rejection -> CHECK_REJECTED ``rejected``;
10. complete proof, exact checker success (``tools.checker.accepts``), no binding failure
    -> VERIFIED_UNSAT;
11. anything else -> TOOL_FAILED ``protocol``.

A signal never stands for a resource cause by itself: only SIGXFSZ of the solver (row 2) and
the pinned bad_alloc abort (row 6) do; SIGKILL/SIGSEGV/SIGTERM without a typed cause are
crashes. Every other observed condition is kept in ``secondary`` (raw diagnostics).
Stream-mode precedence (relay, specification §6.4) belongs to the stream state machine.
"""

from __future__ import annotations

import enum
import signal
from collections.abc import Sequence
from dataclasses import dataclass
from itertools import pairwise

from cubeproof.base.process import Cause
from cubeproof.contracts.enums import Outcome
from cubeproof.tools import checker as ck
from cubeproof.tools import solver as sv
from cubeproof.tools.process import ProcessRun


class Action(str, enum.Enum):
    RECORD = "record"
    CHECK = "check"
    RETRY_CHECK = "retry_check"
    PARSE_MODEL = "parse_model"
    NO_RECORD = "no_record"


class Failure(str, enum.Enum):
    """Row-1 conditions detected by the caller outside a process (values are the reasons)."""

    LAUNCH = "launch"
    BINARY_CHANGED = "binary_changed"
    IO = "io"
    FILE_CHANGED = "file_changed"


@dataclass(frozen=True)
class SolveFacts:
    run: ProcessRun
    #: Solver exit 20 with the proof file closed and present (the caller seals it).
    proof_complete: bool


@dataclass(frozen=True)
class CheckFacts:
    run: ProcessRun
    heap_mib: int
    stack_mib: int


@dataclass(frozen=True)
class ArenaLimits:
    max_heap_mib: int
    max_stack_mib: int
    fits: ck.Fits | None = None


@dataclass(frozen=True)
class Decision:
    action: Action
    outcome: Outcome | None = None
    reason: str | None = None
    #: The next ``(heap_mib, stack_mib)`` for RETRY_CHECK.
    arena: tuple[int, int] | None = None
    #: Raw secondary conditions, e.g. ``solver:deadline``, ``checker:signal:9``.
    secondary: tuple[str, ...] = ()


def _record(outcome: Outcome, reason: str | None, notes: list[str]) -> Decision:
    return Decision(Action.RECORD, outcome, reason, secondary=tuple(notes))


def _observations(label: str, run: ProcessRun) -> list[str]:
    """Raw facts of one run, for the secondary diagnostics."""
    notes = [f"{label}:{cause.value}" for cause in run.causes]
    result = run.result
    if not result.started:
        notes.append(f"{label}:not_started")
    if result.signal is not None:
        notes.append(f"{label}:signal:{result.signal}")
    if result.exit is not None and result.exit != 0:
        notes.append(f"{label}:exit:{result.exit}")
    if label == "checker":
        arena = ck.exhausted_arena(result.stderr_tail)
        if arena is not None:
            notes.append(f"checker:arena:{arena.value}")
        if ck.accepts(result):
            notes.append("checker:accepted")
    if label == "solver" and sv.allocation_failure(result):
        notes.append("solver:bad_alloc")
    return notes


def _validate_history(checks: Sequence[CheckFacts], limits: ArenaLimits) -> None:
    """Preceding checks must be the arena ladder that leads to the last one."""
    for previous, following in pairwise(checks):
        arena = ck.arena_diagnostic(previous.run.result)
        if arena is None or ck.contradictory_success(previous.run.result) or previous.run.causes:
            raise ValueError("only arena exhaustions may precede the last check")
        step = ck.next_arena(
            arena,
            previous.heap_mib,
            previous.stack_mib,
            max_heap_mib=limits.max_heap_mib,
            max_stack_mib=limits.max_stack_mib,
        )
        if step.retry != (following.heap_mib, following.stack_mib):
            raise ValueError(
                f"check arenas {following.heap_mib}/{following.stack_mib} do not follow the ladder"
            )


def _row1(
    solve: SolveFacts | None, checks: Sequence[CheckFacts], failures: Sequence[Failure]
) -> str | None:
    runs = ([solve.run] if solve is not None else []) + [c.run for c in checks]
    for run in runs:
        for cause in run.causes:
            if cause in (Cause.LAUNCH, Cause.BINARY_CHANGED):
                return str(cause.value)
        if not run.result.started:
            return Failure.LAUNCH.value
    return str(failures[0].value) if failures else None


def classify(  # noqa: PLR0911 - one return per table row keeps the order visible
    *,
    solve: SolveFacts | None,
    checks: Sequence[CheckFacts],
    limits: ArenaLimits,
    failures: Sequence[Failure] = (),
    cancelled: bool = False,
) -> Decision:
    """The next step of one attempt. ``solve`` is None for a unit proof (complete by
    construction). ``checks`` are all checker runs of the attempt in execution order."""
    for failure in failures:
        if not isinstance(failure, Failure):
            raise ValueError(f"{failure!r} is not a Failure")
    if solve is not None and solve.run.result.exit == sv.SAT_EXIT and checks:
        raise ValueError("a satisfiable solve has no checks")
    if checks and solve is not None and not solve.proof_complete:
        raise ValueError("checks need a complete proof")
    _validate_history(checks, limits)

    notes: list[str] = []
    if solve is not None:
        notes += _observations("solver", solve.run)
    for check in checks:
        notes += _observations("checker", check.run)
    notes += [f"binding:{failure.value}" for failure in failures]

    def secondary(primary: str) -> list[str]:
        return [note for note in notes if note != primary]

    all_runs = ([solve.run] if solve is not None else []) + [c.run for c in checks]
    # 0. user cancellation: nothing is recorded
    if cancelled or any(Cause.CANCELLED in run.causes for run in all_runs):
        return Decision(Action.NO_RECORD, secondary=tuple(notes))
    # 1. launch, binary, I/O, file binding
    reason = _row1(solve, checks, failures)
    if reason is not None:
        primary = next((n for n in notes if n.endswith(":" + reason)), "")
        return _record(Outcome.TOOL_FAILED, reason, secondary(primary))
    solver_result = solve.run.result if solve is not None else None
    # 2. proof cap or SIGXFSZ
    if solve is not None and (
        Cause.PROOF_CAP in solve.run.causes or solve.run.result.signal == signal.SIGXFSZ
    ):
        capped = Cause.PROOF_CAP in solve.run.causes
        primary = "solver:proof_cap" if capped else f"solver:signal:{int(signal.SIGXFSZ)}"
        return _record(Outcome.EXHAUSTED, "proof_size", secondary(primary))
    # 3. solver deadline
    if solve is not None and Cause.DEADLINE in solve.run.causes:
        return _record(Outcome.EXHAUSTED, "time", secondary("solver:deadline"))
    last = checks[-1] if checks else None
    # 4. check deadline
    if last is not None and Cause.DEADLINE in last.run.causes:
        return _record(Outcome.EXHAUSTED, "check_time", secondary("checker:deadline"))
    # 5. checker arena diagnostic
    if last is not None:
        arena = ck.arena_diagnostic(last.run.result)
        if arena is not None and not last.run.causes:
            if ck.contradictory_success(last.run.result):
                return _record(Outcome.TOOL_FAILED, "protocol", notes)
            step = ck.next_arena(
                arena,
                last.heap_mib,
                last.stack_mib,
                max_heap_mib=limits.max_heap_mib,
                max_stack_mib=limits.max_stack_mib,
                fits=limits.fits,
            )
            if step.retry is not None:
                return Decision(Action.RETRY_CHECK, arena=step.retry, secondary=tuple(notes))
            assert step.reason is not None
            return _record(Outcome.EXHAUSTED, step.reason, notes)
    # 6. solver memory
    if solve is not None and (
        sv.allocation_failure(solve.run.result) or Cause.MEMORY_EVENT in solve.run.causes
    ):
        return _record(Outcome.EXHAUSTED, "solver_memory", notes)
    # 7. crashes and unsupported protocols
    if solver_result is not None and solver_result.signal is not None:
        return _record(Outcome.TOOL_FAILED, "crash", notes)
    if any(Cause.HELD_OPEN in run.causes for run in all_runs):
        return _record(Outcome.TOOL_FAILED, "protocol", notes)
    if last is not None and last.run.result.signal is not None:
        return _record(Outcome.TOOL_FAILED, "crash", notes)
    if solver_result is not None and solver_result.exit not in (sv.SAT_EXIT, sv.UNSAT_EXIT):
        return _record(Outcome.TOOL_FAILED, "protocol", notes)
    if solve is not None and solve.run.result.exit == sv.UNSAT_EXIT and not solve.proof_complete:
        return _record(Outcome.TOOL_FAILED, "protocol", notes)
    # 8. model
    if solver_result is not None and solver_result.exit == sv.SAT_EXIT:
        return Decision(Action.PARSE_MODEL, secondary=tuple(notes))
    # the proof is complete here (unit route or exit 20 with a sealed proof)
    if last is None:
        return Decision(Action.CHECK, secondary=tuple(notes))
    result = last.run.result
    # 9. clean rejection
    if not last.run.causes and not last.run.stderr_truncated and ck.clean_rejection(result):
        return _record(Outcome.CHECK_REJECTED, "rejected", notes)
    # 10. exact success, no arena message, no binding failure (row 1 already excluded those)
    if (
        not last.run.causes
        and not last.run.stderr_truncated
        and ck.accepts(result)
        and ck.exhausted_arena(result.stderr_tail) is None
    ):
        return _record(Outcome.VERIFIED_UNSAT, None, secondary("checker:accepted"))
    # 11. anything else
    return _record(Outcome.TOOL_FAILED, "protocol", notes)
