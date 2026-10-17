"""Stream arena retries in the replayed scheduling state and the stream reservation (specification
§6.4, §6.5, §7.3, §8.2, §8.3).

The replay itself (no judge passed by the caller, as the coordinator's startup replay and the
state cache build it) decides whether an arena-exhausted stream record keeps its node pending
for a fresh attempt: within the policy maxima **and** within the idle machine's memory budget
recorded in the latest header/resume. It also keeps the arena of the node's next stream attempt
(a monotone floor), so a live run and a replay of the same journal take the same next action.
Records are journal records (the scheduler test journal, checked by the record rules).
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

import pytest
from cp_stream_support import MACHINERY, RESOURCES, Journal, formula_bytes, sha
from cp_stream_support import policy_value as policy

from cubeproof.contracts.policy import Policy
from cubeproof.coordinator.resources import CHILD_OVERHEAD, RELAY_CAP, stream_need
from cubeproof.coordinator.state import Disposition, NodeFacts, ReplayState
from cubeproof.leaf.retry import initial_stream_arena
from cubeproof.tools import checker as ck

F = {"f": formula_bytes(8, [(1, 2), (-1, 3)])}
HEAP = (1, "CakeML heap space exhausted.\n")
MIB = 1 << 20
GIB = 1 << 30


def stream_policy(**changes: Any) -> dict[str, Any]:
    value: dict[str, Any] = policy(proof_mode="stream", **changes)
    return value


def check(heap: int, stack: int) -> dict[str, Any]:
    code, message = HEAP
    return {
        "heap_mib": heap,
        "stack_mib": stack,
        "result": {
            "started": True,
            "exit": code,
            "signal": None,
            "elapsed_ms": 10,
            "stdout_tail": "",
            "stderr_tail": message,
            "stdout_bytes": 0,
            "stdout_truncated": False,
            "cause": None,
            "conflicts": None,
        },
    }


def relay(count: int) -> dict[str, Any]:
    return {
        "bytes": count,
        "sha256": sha(b"relay %d" % count),
        "solver_eof": False,
        "all_written": False,
        "error": "write: EPIPE (Broken pipe)",
    }


def exhausted(j: Journal, heap: int, stack: int = 256, *, cube: Sequence[int] = ()) -> int:
    return j.failed(
        "f",
        cube,
        "EXHAUSTED",
        "check_memory",
        route="cdcl",
        checks=[check(heap, stack)],
        relay=relay(1000),
    )


def new_journal(**changes: Any) -> Journal:
    j = Journal(F, policy_value=stream_policy(**changes))
    j.shard([("f", ())])
    return j


def resume(j: Journal, *, memory_budget_bytes: int | None = None, **changes: Any) -> int:
    """A resume with another policy and/or another recorded idle-machine memory budget."""
    if changes:
        j.policy_value = stream_policy(**changes)
    resources = dict(RESOURCES)
    if memory_budget_bytes is not None:
        resources["memory_budget_bytes"] = memory_budget_bytes
    return j.append(
        {
            "type": "resume",
            "machinery": j.machinery_value,
            "policy": j.policy_value,
            "resources": resources,
        }
    )


def replay(j: Journal) -> ReplayState:
    """The replay as the coordinator builds it: no judge passed in."""
    state = ReplayState(j.view)
    state.apply_all(j.records)
    return state


def disposition(state: ReplayState) -> Disposition:
    (node,) = state.open_nodes()
    return node.disposition


def stream_memory(p: Policy, heap: int, stack: int) -> int:
    """The memory of a stream reservation (specification §8.3), transcribed: solver + checker +
    relay caps and one child overhead each."""
    checker = (heap + stack + p.checker_slack_mib) * MIB
    return p.solver_memory_bytes + checker + RELAY_CAP + 3 * CHILD_OVERHEAD


# -- the default replay judges stream arena retries ------------------------------------------------


def test_an_eligible_retry_keeps_the_node_pending_without_a_judge() -> None:
    j = new_journal()
    exhausted(j, 1024)
    state = replay(j)
    assert disposition(state) is Disposition.PENDING
    assert state.stream_arena(j.key("f")) == (2048, 256)


def test_beyond_the_maxima_the_node_needs_a_split() -> None:
    j = new_journal()
    exhausted(j, 8192)
    assert disposition(replay(j)) is Disposition.NEEDS_SPLIT


def test_a_retry_the_recorded_idle_machine_cannot_hold_splits() -> None:
    p = Policy.from_json(stream_policy())
    first = stream_memory(p, 1024, 256)
    retry = stream_memory(p, 2048, 256)
    assert first < retry
    j = new_journal()
    resume(j, memory_budget_bytes=retry - 1)
    exhausted(j, 1024)
    assert disposition(replay(j)) is Disposition.NEEDS_SPLIT
    k = new_journal()
    resume(k, memory_budget_bytes=retry)
    exhausted(k, 1024)
    assert disposition(replay(k)) is Disposition.PENDING


def test_the_judgement_uses_the_snapshot_in_force_when_the_record_was_committed() -> None:
    """A later resume does not change an earlier decision (the fold, not a re-evaluation)."""
    p = Policy.from_json(stream_policy())
    j = new_journal()
    exhausted(j, 1024)
    resume(j, memory_budget_bytes=stream_memory(p, 2048, 256) - 1)
    assert disposition(replay(j)) is Disposition.PENDING


def test_a_file_mode_record_is_never_a_stream_retry() -> None:
    j = Journal(F, policy_value=policy(proof_mode="transient"))
    j.shard([("f", ())])
    j.failed("f", (), "EXHAUSTED", "check_memory", route="cdcl", checks=[check(1024, 256)])
    assert disposition(replay(j)) is Disposition.NEEDS_SPLIT


def test_an_explicit_judge_still_overrides_the_default() -> None:
    j = new_journal()
    exhausted(j, 1024)
    state = ReplayState(j.view, retry_judge=lambda attempt, pol: False)
    state.apply_all(j.records)
    assert disposition(state) is Disposition.NEEDS_SPLIT


# -- the arena of the next stream attempt ----------------------------------------------------------


def test_a_node_without_stream_attempts_starts_at_the_policy_arena() -> None:
    j = new_journal()
    state = replay(j)
    p = Policy.from_json(j.policy_value)
    assert state.stream_arena(j.key("f")) == initial_stream_arena(p)
    assert state.stream_arena(j.key("f", (1,))) == initial_stream_arena(p)


def test_the_arena_floor_survives_tool_failures_and_grows_with_each_exhaustion() -> None:
    j = new_journal()
    key = j.key("f")
    exhausted(j, 1024)
    assert replay(j).stream_arena(key) == (2048, 256)
    j.failed(
        "f", (), "TOOL_FAILED", "relay", route="cdcl", relay=relay(5), checks=[check(2048, 256)]
    )
    state = replay(j)
    assert disposition(state) is Disposition.PENDING  # a tool failure is retried
    assert state.stream_arena(key) == (2048, 256)
    j.failed("f", (), "TOOL_FAILED", "launch", route="cdcl", relay=relay(0), checks=[])
    assert replay(j).stream_arena(key) == (2048, 256)
    exhausted(j, 2048)
    assert replay(j).stream_arena(key) == (4096, 256)


def test_the_floor_is_per_node() -> None:
    j = new_journal()
    j.split("f", (), (1,))
    exhausted(j, 1024, cube=(1,))
    state = replay(j)
    p = Policy.from_json(j.policy_value)
    assert state.stream_arena(j.key("f", (1,))) == (2048, 256)
    assert state.stream_arena(j.key("f", (-1,))) == initial_stream_arena(p)


def test_a_larger_policy_stream_heap_at_resume_raises_the_arena() -> None:
    j = new_journal()
    exhausted(j, 1024)
    resume(j, stream_heap_mib=4096)
    assert replay(j).stream_arena(j.key("f")) == (4096, 256)


def test_a_resume_that_lowers_the_maxima_below_the_floor_splits() -> None:
    """The decision was a retry at 2048 MiB; a resume with a 1024 MiB maximum cannot run it:
    the node needs a split, and the arena never exceeds the maxima in force."""
    j = new_journal()
    exhausted(j, 1024)
    assert disposition(replay(j)) is Disposition.PENDING
    resume(j, checker_max_heap_mib=1024)
    state = replay(j)
    assert disposition(state) is Disposition.NEEDS_SPLIT
    assert state.stream_arena(j.key("f")) == (1024, 256)


def test_the_state_cache_round_trip_keeps_the_stream_facts() -> None:
    j = new_journal()
    exhausted(j, 1024)
    state = replay(j)
    restored = ReplayState(j.view)
    restored.restore(state.export())
    assert restored.digest() == state.digest()
    assert restored.stream_arena(j.key("f")) == state.stream_arena(j.key("f"))
    facts = state.facts(j.key("f"))
    assert facts is not None
    assert NodeFacts.from_json(facts.to_json()) == facts
    # a later record applied to the restored state continues exactly like the fold
    exhausted(j, 2048)
    restored.apply(j.records[-1])
    assert restored.digest() == replay(j).digest()


def test_live_application_equals_replay() -> None:
    j = new_journal()
    exhausted(j, 1024)
    j.failed(
        "f", (), "TOOL_FAILED", "relay", route="cdcl", relay=relay(5), checks=[check(2048, 256)]
    )
    exhausted(j, 2048)
    live = ReplayState(j.view)
    for record in j.records:
        live.apply(record)
        assert live.digest() == replay_prefix(j, record.seq + 1).digest()


def replay_prefix(j: Journal, count: int) -> ReplayState:
    state = ReplayState(j.view)
    state.apply_all(j.prefix(count))
    return state


# -- the reservation of a stream task --------------------------------------------------------------


@pytest.mark.parametrize("arena", [None, (2048, 256), (4096, 512)])
def test_the_stream_reservation_holds_the_attempts_arena(arena: tuple[int, int] | None) -> None:
    p = Policy.from_json(stream_policy())
    heap, stack = initial_stream_arena(p) if arena is None else arena
    need = stream_need(p, 1000, "work", arena=arena)
    assert need.memory_bytes == stream_memory(p, heap, stack)
    assert need.cpu_milli == 3000
    assert dict(need.disk) == {"work": 1000 + 4 * MIB}
    assert (
        ck.checker_memory_bytes(heap, stack, p.checker_slack_mib)
        == (heap + stack + p.checker_slack_mib) * MIB
    )


def test_machinery_is_the_corpus_one() -> None:
    """Guard of this module's oracle: the journal's snapshots are the corpus header's."""
    j = new_journal()
    assert j.machinery_value == MACHINERY
    assert RESOURCES["memory_budget_bytes"] >= 4 * GIB
