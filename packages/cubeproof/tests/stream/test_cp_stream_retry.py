"""Deterministic stream arena retries from the last record (specification §6.4, §6.5, §8.3).

An arena-exhausted stream attempt is recorded EXHAUSTED(check_memory/check_stack) with its
raw results; the next action is computed from that record alone: a fresh attempt on the same
node with at least twice the exhausted arena (heap: at least the fit of the observed relay
bytes) if within the maxima and the idle-machine fit, otherwise a split. Records are built
as journal records (the scheduler test journal, checked by the record rules), so replay sees
exactly what it would read back.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from typing import Any

import pytest
from cp_stream_support import Journal, formula_bytes, make_policy, sha
from cp_stream_support import policy_value as policy

from cubeproof.contracts.policy import HeapFit, Policy
from cubeproof.coordinator.state import Disposition, ReplayState
from cubeproof.evidence.schema import Attempt, check_record
from cubeproof.leaf.retry import (
    RetryAction,
    initial_stream_arena,
    next_stream_attempt,
    retry_judge,
    stream_arena,
)
from cubeproof.tools import checker as ck

F = {"f": formula_bytes(8, [(1, 2), (-1, 3)])}
HEAP = (1, "CakeML heap space exhausted.\n")
STACK = (2, "CakeML stack space exhausted.\n")
BOTH = (3, "failed to allocate sufficient CakeML heap and stack space.\n")
ARENAS = {"heap": HEAP, "stack": STACK, "both": BOTH}
MIB = 1 << 20


def stream_policy(**changes: Any) -> dict[str, Any]:
    value: dict[str, Any] = policy(proof_mode="stream", **changes)
    return value


def check(kind: str, heap: int, stack: int, *, stdout: str = "") -> dict[str, Any]:
    code, message = ARENAS[kind]
    return {
        "heap_mib": heap,
        "stack_mib": stack,
        "result": {
            "started": True,
            "exit": code,
            "signal": None,
            "elapsed_ms": 10,
            "stdout_tail": stdout,
            "stderr_tail": message,
            "stdout_bytes": len(stdout),
            "stdout_truncated": False,
            "cause": None,
            "conflicts": None,
        },
    }


def relay(count: int, *, complete: bool = False) -> dict[str, Any]:
    return {
        "bytes": count,
        "sha256": sha(b"relay %d" % count),
        "solver_eof": complete,
        "all_written": complete,
        "error": None if complete else "write: EPIPE (Broken pipe)",
    }


def exhausted(
    journal: Journal,
    kind: str = "heap",
    heap: int = 1024,
    stack: int = 256,
    relay_bytes: int = 1000,
    *,
    reason: str | None = None,
    cube: Sequence[int] = (),
    **fields: Any,
) -> Attempt:
    """Append an arena-exhausted stream attempt; return the typed record."""
    if reason is None:
        reason = "check_stack" if kind == "stack" else "check_memory"
    values: dict[str, Any] = {
        "route": "cdcl",
        "checks": [check(kind, heap, stack)],
        "relay": relay(relay_bytes),
        "proof_bytes": None,
        "proof_sha256": None,
    }
    values.update(fields)
    seq = journal.failed("f", cube, "EXHAUSTED", reason, **values)
    payload = journal.records[seq].payload
    assert isinstance(payload, Attempt)
    return payload


def new_journal(**changes: Any) -> Journal:
    j = Journal(F, policy_value=stream_policy(**changes))
    j.shard([("f", ())])
    return j


def typed_policy(journal: Journal) -> Policy:
    return Policy.from_json(journal.policy_value)


# -- the next arena -----------------------------------------------------------------------------


def test_the_first_stream_arena_is_the_policy_stream_heap_and_stack() -> None:
    p = make_policy(stream_heap_mib=2048, checker_stack_mib=128)
    assert initial_stream_arena(p) == (2048, 128)


@pytest.mark.parametrize(
    ("kind", "arena", "expected"),
    [
        ("heap", (1024, 256), (2048, 256)),
        ("stack", (1024, 256), (1024, 512)),
        ("both", (1024, 256), (2048, 512)),
        ("heap", (512, 1024), (1024, 1024)),
    ],
)
def test_the_exhausted_arena_doubles(
    kind: str, arena: tuple[int, int], expected: tuple[int, int]
) -> None:
    j = new_journal()
    record = exhausted(j, kind, *arena)
    assert next_stream_attempt(record, typed_policy(j)) == RetryAction(*expected)


def test_the_heap_also_covers_the_fit_of_the_observed_relay_bytes() -> None:
    j = new_journal()
    p = typed_policy(j)
    big = 10_000_000_000
    fitted = ck.initial_heap_mib(big, p.heap_fit)
    assert fitted > 2048
    record = exhausted(j, "heap", 1024, 256, relay_bytes=big)
    assert next_stream_attempt(record, p) == RetryAction(fitted, 256)
    # the stack arena never takes the heap fit
    stacked = exhausted(j, "stack", 1024, 256, relay_bytes=big)
    assert next_stream_attempt(stacked, p) == RetryAction(1024, 512)


@pytest.mark.parametrize(
    ("kind", "arena"), [("heap", (8192, 256)), ("stack", (1024, 2048)), ("both", (1024, 2048))]
)
def test_no_retry_beyond_the_maxima(kind: str, arena: tuple[int, int]) -> None:
    j = new_journal()
    record = exhausted(j, kind, *arena)
    assert next_stream_attempt(record, typed_policy(j)) is None
    assert retry_judge()(record, typed_policy(j)) is False


def test_the_idle_machine_fit_can_refuse_a_retry() -> None:
    j = new_journal()
    record = exhausted(j, "heap", 1024, 256)
    p = typed_policy(j)
    asked: list[tuple[int, int]] = []

    def fits(heap: int, stack: int) -> bool:
        asked.append((heap, stack))
        return heap <= 1024

    assert next_stream_attempt(record, p, fits) is None
    assert asked == [(2048, 256)]
    assert retry_judge(fits)(record, p) is False
    assert retry_judge(lambda h, s: True)(record, p) is True


@pytest.mark.parametrize(
    "change",
    [
        {"proof_mode": "transient"},
        {"route": "unit", "solver": None, "relay": None},
        {"outcome": "EXHAUSTED", "reason": "time"},
        {"outcome": "TOOL_FAILED", "reason": "relay"},
        {"checks": []},
        {"last_check": "contradictory"},
        {"last_check": "signal"},
        {"last_check": "cause"},
        {"last_check": "wrong_code"},
    ],
)
def test_only_a_clean_arena_exhaustion_of_a_stream_attempt_is_retried(
    change: dict[str, Any],
) -> None:
    j = new_journal()
    fields: dict[str, Any] = {}
    reason = None
    last = check("heap", 1024, 256)
    variant = change.get("last_check")
    if variant == "contradictory":
        last = check("heap", 1024, 256, stdout="s VERIFIED UNSAT\n")
    elif variant == "signal":
        last["result"].update(exit=None, signal=9)
    elif variant == "cause":
        last["result"].update(cause="deadline")
    elif variant == "wrong_code":
        last["result"].update(exit=2)
    fields["checks"] = [last]
    for key, value in change.items():
        if key == "reason":
            reason = value
        elif key == "outcome":
            continue
        elif key != "last_check":
            fields[key] = value
    if change.get("proof_mode") == "transient":
        fields["relay"] = None
    if change.get("outcome") == "TOOL_FAILED":
        seq = j.failed("f", (), "TOOL_FAILED", "relay", route="cdcl", relay=relay(5), checks=[last])
        record = j.records[seq].payload
    else:
        record = exhausted(j, reason=reason, **fields)
    assert isinstance(record, Attempt)
    assert next_stream_attempt(record, typed_policy(j)) is None


def test_the_ladder_is_finite() -> None:
    """Repeated exhaustion of the derived arena ends at the maxima: no infinite ladder."""
    j = new_journal()
    p = typed_policy(j)
    heap, stack = initial_stream_arena(p)
    steps = 0
    while True:
        record = exhausted(j, "both", heap, stack, relay_bytes=10 * MIB)
        action = next_stream_attempt(record, p)
        if action is None:
            break
        assert action.heap_mib >= 2 * heap and action.stack_mib == 2 * stack
        heap, stack = action.heap_mib, action.stack_mib
        steps += 1
        assert steps <= 64
    assert heap <= p.checker_max_heap_mib and stack <= p.checker_max_stack_mib
    assert steps >= 1


# -- replay determinism ------------------------------------------------------------------------


def test_replay_produces_the_same_next_action() -> None:
    j = new_journal()
    record = exhausted(j, "heap", 1024, 256, relay_bytes=5 * MIB)
    p = typed_policy(j)
    first = next_stream_attempt(record, p)
    assert first is not None
    # the record as the journal reader returns it after a restart (parsed from its bytes)
    reread = check_record(json.loads(json.dumps(j.values[-1])), variables=j.counts).payload
    assert isinstance(reread, Attempt) and reread == record
    again = reread
    assert next_stream_attempt(again, p) == first
    # the fold the coordinator keeps gives the same arena on a full replay
    assert stream_arena([record], p) == (first.heap_mib, first.stack_mib)
    assert stream_arena([again], p) == stream_arena([record], p)


def test_an_eligible_retry_keeps_the_node_pending_in_replay() -> None:
    j = new_journal()
    exhausted(j, "heap", 1024, 256)
    state = ReplayState(j.view, retry_judge=retry_judge())
    state.apply_all(j.records)
    assert [n.disposition for n in state.open_nodes()] == [Disposition.PENDING]
    replayed = ReplayState(j.view, retry_judge=retry_judge())
    replayed.apply_all(j.records)
    assert replayed.digest() == state.digest()
    # beyond the maxima the same record means a split
    k = new_journal()
    exhausted(k, "heap", 8192, 256)
    state = ReplayState(k.view, retry_judge=retry_judge())
    state.apply_all(k.records)
    assert [n.disposition for n in state.open_nodes()] == [Disposition.NEEDS_SPLIT]


def test_the_arena_floor_never_drops_after_other_failures() -> None:
    """A tool failure between two exhaustions does not restart the ladder (bounded retry)."""
    j = new_journal()
    p = typed_policy(j)
    first = exhausted(j, "heap", 1024, 256)
    seq = j.failed(
        "f",
        (),
        "TOOL_FAILED",
        "relay",
        route="cdcl",
        relay=relay(5),
        checks=[check("heap", 2048, 256)],
    )
    failed = j.records[seq].payload
    assert isinstance(failed, Attempt)
    launch = j.failed("f", (), "TOOL_FAILED", "launch", route="cdcl", relay=relay(0), checks=[])
    unstarted = j.records[launch].payload
    assert isinstance(unstarted, Attempt)
    assert stream_arena([first], p) == (2048, 256)
    assert stream_arena([first, failed], p) == (2048, 256)
    assert stream_arena([first, failed, unstarted], p) == (2048, 256)
    second = exhausted(j, "heap", 2048, 256)
    assert stream_arena([first, failed, unstarted, second], p) == (4096, 256)
    assert stream_arena([], p) == initial_stream_arena(p)


def test_a_larger_policy_stream_heap_raises_the_floor() -> None:
    j = new_journal()
    record = exhausted(j, "heap", 1024, 256)
    bigger = Policy.from_json(stream_policy(stream_heap_mib=4096))
    assert stream_arena([record], bigger) == (4096, 256)


def test_the_relay_bytes_fit_uses_the_policy_heap_fit() -> None:
    j = new_journal()
    record = exhausted(j, "heap", 512, 256, relay_bytes=400 * MIB)
    p = typed_policy(j)
    fit = HeapFit(coefficient_milli=3230, exponent_milli=711, margin_milli=1500, min_mib=512)
    assert p.heap_fit == fit
    action = next_stream_attempt(record, p)
    assert action is not None
    assert action.heap_mib == max(1024, ck.initial_heap_mib(400 * MIB, fit))
