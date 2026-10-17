"""Bounded stream arena retries, derived from committed records only (specification §6.4, §6.5,
§8.3).

A stream attempt whose checker exhausted its arena is recorded EXHAUSTED(``check_memory`` or
``check_stack``) with its raw results; unlike the file modes there is no sealed proof to
check again, so the next action is a **fresh attempt** on the same node. It is computed from
the last record alone (and the effective policy), so a live run and a replay of the journal
take the same decision:

- the record is a stream attempt on route cdcl, EXHAUSTED with an arena reason, whose last
  check is a clean pinned arena diagnostic (``tools.checker.arena_diagnostic``, no supervisor
  cause, no contradictory success);
- the next arena is ``tools.checker.next_stream_arena``: at least twice the exhausted arena
  (both for the combined diagnostic) and, for the heap, at least the specification §8.3 fit of the
  relay bytes observed in that attempt;
- it is a retry only within ``checker_max_heap_mib``/``checker_max_stack_mib`` and, when the
  caller passes the idle-machine fit, within the idle machine; otherwise the node splits.

The arena only grows (each retry at least doubles the exhausted arena and the maxima bound
it), so there is no infinite ladder. :func:`stream_arena` folds a node's committed stream
attempts into the arena of its next attempt: a tool failure between two exhaustions does not
restart the ladder at the policy's ``stream_heap_mib``.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass

from cubeproof.base.process import ProcessResult
from cubeproof.contracts.enums import Outcome, ProofMode, Route
from cubeproof.contracts.policy import Policy
from cubeproof.evidence.schema import Attempt
from cubeproof.evidence.schema.values import ProcessResult as RecordResult
from cubeproof.tools import checker as ck

__all__ = [
    "STREAM_ARENA_REASONS",
    "RetryAction",
    "arena_exhaustion",
    "arena_floor",
    "exhausted_reason",
    "initial_stream_arena",
    "next_stream_attempt",
    "raise_floor",
    "retry_judge",
    "stream_arena",
]

#: The EXHAUSTED reasons of a checker arena exhaustion (specification §6.3).
STREAM_ARENA_REASONS = frozenset({"check_memory", "check_stack"})

RetryJudge = Callable[[Attempt, Policy], bool]


@dataclass(frozen=True)
class RetryAction:
    """A fresh stream attempt on the same node with these checker arenas (MiB)."""

    heap_mib: int
    stack_mib: int


def initial_stream_arena(policy: Policy) -> tuple[int, int]:
    """The first stream check's arenas: ``stream_heap_mib`` and ``checker_stack_mib``."""
    return policy.stream_heap_mib, policy.checker_stack_mib


def exhausted_reason(arena: ck.Arena, step: ck.ArenaStep) -> str:
    """The EXHAUSTED reason of an arena diagnostic: the step's when no retry is possible,
    else the exhausted arena's (``check_stack`` for the stack, ``check_memory`` otherwise)."""
    if step.reason is not None:
        return step.reason
    return "check_stack" if arena is ck.Arena.STACK else "check_memory"


def _result(value: RecordResult) -> ProcessResult:
    """The record's checker result as the value ``tools.checker`` judges (same fields)."""
    return ProcessResult(**value.to_json())


def arena_exhaustion(attempt: Attempt) -> tuple[ck.Arena, int, int, int] | None:
    """``(arena, heap_mib, stack_mib, relay_bytes)`` of a stream record that ended in a clean
    arena exhaustion of its last check (module doc), else None."""
    if not isinstance(attempt, Attempt):
        raise ValueError("arena_exhaustion needs an Attempt record")
    if (
        attempt.proof_mode is not ProofMode.STREAM
        or attempt.route is not Route.CDCL
        or attempt.outcome is not Outcome.EXHAUSTED
        or attempt.reason not in STREAM_ARENA_REASONS
        or attempt.relay is None
        or not attempt.checks
    ):
        return None
    last = attempt.checks[-1]
    result = _result(last.result)
    arena = ck.arena_diagnostic(result)
    if arena is None or result.cause is not None or ck.contradictory_success(result):
        return None
    return arena, last.heap_mib, last.stack_mib, attempt.relay.bytes


def next_stream_attempt(
    attempt: Attempt, policy: Policy, fits: ck.Fits | None = None
) -> RetryAction | None:
    """The fresh attempt after an arena-exhausted stream record, or None (split)."""
    found = arena_exhaustion(attempt)
    if found is None:
        return None
    arena, heap, stack, relay_bytes = found
    step = ck.next_stream_arena(
        arena,
        heap,
        stack,
        relay_bytes=relay_bytes,
        fit=policy.heap_fit,
        max_heap_mib=policy.checker_max_heap_mib,
        max_stack_mib=policy.checker_max_stack_mib,
        fits=fits,
    )
    return None if step.retry is None else RetryAction(*step.retry)


def retry_judge(fits: ck.Fits | None = None) -> RetryJudge:
    """The ``ReplayState`` judge: True iff the record calls for a fresh stream attempt."""

    def judge(attempt: Attempt, policy: Policy) -> bool:
        return next_stream_attempt(attempt, policy, fits) is not None

    return judge


def arena_floor(attempt: Attempt, policy: Policy) -> tuple[int, int] | None:
    """What one committed attempt says about its node's next stream arena: the derived retry
    arena of an arena exhaustion within the maxima, else the arena its last check used; None
    for an attempt that is not a stream CDCL attempt with a check."""
    if (
        attempt.proof_mode is not ProofMode.STREAM
        or attempt.route is not Route.CDCL
        or not attempt.checks
    ):
        return None
    action = next_stream_attempt(attempt, policy)
    if action is not None:
        return action.heap_mib, action.stack_mib
    last = attempt.checks[-1]
    return last.heap_mib, last.stack_mib


def raise_floor(
    floor: tuple[int, int] | None, other: tuple[int, int] | None
) -> tuple[int, int] | None:
    """The componentwise maximum of two floors (None: no floor)."""
    if floor is None or other is None:
        return other if floor is None else floor
    return max(floor[0], other[0]), max(floor[1], other[1])


def stream_arena(attempts: Iterable[Attempt], policy: Policy) -> tuple[int, int]:
    """The arenas of a node's next stream attempt, folded over its committed attempts in
    journal order: never below the policy's first arena, never below an arena already
    used, and at least the derived retry arena of an arena exhaustion (module doc)."""
    floor: tuple[int, int] | None = initial_stream_arena(policy)
    for attempt in attempts:
        floor = raise_floor(floor, arena_floor(attempt, policy))
    assert floor is not None
    return floor
