"""Which nodes a handoff gives away: pending, unsplit, not running, oldest first (specification
§7.4, §8.4)."""

from __future__ import annotations

import random
from collections.abc import Collection, Sequence
from typing import Any

import pytest
from cp_handoff_support import CAMPAIGN, FORMULAS, HASH, VARIABLES, key, node
from cp_sched_support import Journal, node_id

from cubeproof.base.canonical_json import encode
from cubeproof.contracts.documents import Shard
from cubeproof.coordinator.handoff import pending_frontier, select_nodes
from cubeproof.coordinator.ownership import Ownership
from cubeproof.coordinator.state import Disposition, ReplayState

Cube = tuple[int, ...]


def fold(journal: Journal) -> tuple[ReplayState, Ownership]:
    state = ReplayState(journal.view)
    owned = Ownership(CAMPAIGN, VARIABLES)
    for record in journal.records:
        state.apply(record)
        owned.observe(record)
    return state, owned


def chosen(
    journal: Journal, count: int, running: Collection[Any] = (), cap: int = 8 * 1024 * 1024
) -> list[tuple[str, Cube]]:
    state, owned = fold(journal)
    nodes = select_nodes(
        state, owned, running=set(running), node_count=count, output_name="out", max_line_bytes=cap
    )
    return [(n.formula_sha256, n.cube) for n in nodes]


def base() -> Journal:
    j = Journal(FORMULAS)
    j.resume()
    j.shard([("a", ()), ("b", ())])
    return j


def by_id(formula: str, cubes: Sequence[Cube]) -> list[tuple[str, Cube]]:
    """Keys sorted the way the shard is: (formula_sha256, node_id)."""
    keys = [(HASH[formula], tuple(c)) for c in cubes]
    return sorted(keys, key=lambda k: (k[0], node_id(*k)))


def test_roots_without_work_are_given_in_shard_order_of_age_then_node_id() -> None:
    j = base()
    assert chosen(j, 5) == sorted([key("a"), key("b")], key=lambda k: (k[0], node_id(*k)))
    assert chosen(j, 1) == [min([key("a"), key("b")], key=lambda k: node_id(*k))]


def test_the_oldest_entries_go_first_not_the_first_in_depth_first_order() -> None:
    j = base()
    j.split("a", (), (1, 2))  # four newer entries; b is older (it came with the shard)
    state, owned = fold(j)
    entries = {k: seq for seq, _, k in pending_frontier(state, owned)}
    assert entries[key("b")] < entries[key("a", (1, 2))]
    assert chosen(j, 1) == [key("b")]
    five = chosen(j, 5)
    assert key("b") in five and len(five) == 5
    kids = [(1, 2), (1, -2), (-1, 2), (-1, -2)]
    assert chosen(j, 3) == sorted(
        [key("b"), *sorted((key("a", c) for c in kids), key=lambda k: node_id(*k))[:2]],
        key=lambda k: (k[0], node_id(*k)),
    )


def test_ties_between_siblings_are_broken_by_node_id() -> None:
    j = Journal(FORMULAS)
    j.shard([("a", ())])
    j.split("a", (), (1, 2))
    kids = [(1, 2), (1, -2), (-1, 2), (-1, -2)]
    smallest = min((key("a", c) for c in kids), key=lambda k: node_id(*k))
    assert chosen(j, 1) == [smallest]


def test_a_node_that_runs_is_never_given() -> None:
    j = base()
    j.split("a", (), (1, 2))
    running = {key("b"), key("a", (1, 2))}
    got = chosen(j, 10, running)
    assert set(got) == {key("a", (1, -2)), key("a", (-1, 2)), key("a", (-1, -2))}
    assert (
        chosen(j, 10, [key("b"), *[key("a", c) for c in [(1, 2), (1, -2), (-1, 2), (-1, -2)]]])
        == []
    )


def test_only_pending_unsplit_nodes_are_given() -> None:
    j = Journal(FORMULAS)
    j.shard([("a", ())])
    j.split("a", (), (1, 2, 3))  # eight children
    kids = [
        (1, 2, 3), (1, 2, -3), (1, -2, 3), (1, -2, -3), (-1, 2, 3), (-1, 2, -3), (-1, -2, 3),
        (-1, -2, -3),
    ]  # fmt: skip
    j.unsat("a", kids[0])  # closed
    j.model("a", kids[1])  # a model
    j.failed("a", kids[2], "EXHAUSTED", "time")  # waits for its split
    j.stop("a", kids[3], "stuck")  # stopped
    j.failed("a", kids[4], "TOOL_FAILED", "crash")  # one failure: a retry is pending
    for _ in range(5):  # more failures than tool_retries: a stop is due
        j.failed("a", kids[5], "TOOL_FAILED", "crash")
    state, _ = fold(j)
    kinds = {n.key[1]: n.disposition for n in state.open_nodes()}
    assert kinds[kids[2]] is Disposition.NEEDS_SPLIT
    assert kinds[kids[5]] is Disposition.STOP_DUE
    assert set(chosen(j, 20)) == {key("a", kids[4]), key("a", kids[6]), key("a", kids[7])}


def test_a_node_given_away_is_not_given_twice() -> None:
    j = base()
    j.split("a", (), (1, 2))
    j.handoff([("b", ()), ("a", (1, 2))], request="1", name="first")
    assert set(chosen(j, 10)) == {key("a", (1, -2)), key("a", (-1, 2)), key("a", (-1, -2))}
    j.handoff([("a", (1, -2))], request="2", name="second")
    assert set(chosen(j, 10)) == {key("a", (-1, 2)), key("a", (-1, -2))}


def test_the_result_is_a_valid_sorted_disjoint_shard_and_stable() -> None:
    j = base()
    j.split("a", (), (1, 2))
    j.split("a", (1, 2), (3,))
    picked = chosen(j, 99)
    assert picked == chosen(j, 99)
    shard = Shard(CAMPAIGN, "x", tuple(node_of(k) for k in picked))  # sorted and disjoint
    assert [n.sort_key for n in shard.nodes] == sorted(n.sort_key for n in shard.nodes)
    assert key("a", (1, 2)) not in picked  # split: its children are the frontier
    assert key("a", (1, 2, 3)) in picked


def node_of(k: tuple[str, Cube]) -> Any:
    from cubeproof.contracts.values import Node

    return Node(*k)


def test_a_count_and_a_line_size_bound_the_batch() -> None:
    j = Journal(FORMULAS)
    j.shard([("a", ())])
    j.split("a", (), (1, 2, 3))
    assert len(chosen(j, 3)) == 3 and len(chosen(j, 100)) == 8
    from cubeproof.coordinator.ownership import RECORD_OVERHEAD

    floor = RECORD_OVERHEAD + 512 + 200
    sizes = [len(chosen(j, 100, cap=floor + extra)) for extra in range(0, 1200, 100)]
    assert sizes == sorted(sizes) and sizes[0] < 8 and sizes[-1] == 8
    assert len(chosen(j, 100, cap=RECORD_OVERHEAD)) == 0  # not even one node fits


def test_the_selected_batch_fits_the_cap_it_was_chosen_for() -> None:
    j = Journal(FORMULAS)
    j.shard([("a", ())])
    j.split("a", (), (1, 2, 3))
    for cap in range(RECORD_OVERHEAD_ + 600, RECORD_OVERHEAD_ + 1500, 97):
        picked = chosen(j, 100, cap=cap)
        if not picked:
            continue
        shard = Shard(CAMPAIGN, "out", tuple(node_of(k) for k in picked))
        record = {
            "type": "handoff",
            "request": {"x": "0" * 200},
            "shard": shard.to_json(),
            "shard_sha256": shard.shard_id,
        }
        assert len(encode(record)) + 500 <= cap


RECORD_OVERHEAD_ = 4096


def test_a_non_positive_count_is_refused() -> None:
    state, owned = fold(base())
    for bad in (0, -1):
        with pytest.raises(ValueError, match="positive"):
            select_nodes(state, owned, running=set(), node_count=bad, output_name="out")


# -- the same cover as the state's own traversal -----------------------------------------------


def random_journal(rng: random.Random) -> Journal:
    j = Journal(FORMULAS)
    j.resume()
    roots = [("a", ()), ("b", ())]
    j.shard(roots)
    leaves: list[tuple[str, Cube]] = list(roots)
    for _ in range(rng.randrange(0, 14)):
        name, cube = leaves.pop(rng.randrange(len(leaves)))
        count = VARIABLES[HASH[name]]
        free = [v for v in range(1, count + 1) if v not in {abs(x) for x in cube}]
        action = rng.choice(
            ["split", "split", "unsat", "model", "exhausted", "stop", "fail", "keep"]
        )
        if action == "split" and free:
            chosen_vars = tuple(sorted(rng.sample(free, rng.randrange(1, min(3, len(free)) + 1))))
            j.split(name, cube, chosen_vars)
            for index in range(1 << len(chosen_vars)):
                signed = [v if index >> b & 1 else -v for b, v in enumerate(chosen_vars)]
                leaves.append((name, tuple(sorted([*cube, *signed], key=abs))))
            continue
        if action == "unsat":
            j.unsat(name, cube)
        elif action == "model":
            j.model(name, cube)
        elif action == "exhausted":
            j.failed(name, cube, "EXHAUSTED", "time")
        elif action == "stop":
            j.stop(name, cube, "stuck")
        elif action == "fail":
            j.failed(name, cube, "TOOL_FAILED", "crash")
        leaves.append((name, cube))
    if rng.random() < 0.5 and leaves:
        picked = [leaves[rng.randrange(len(leaves))]]
        j.handoff(picked, request="5", name="gone")
    return j


@pytest.mark.parametrize("seed", range(60))
def test_the_frontier_is_exactly_the_pending_open_nodes_of_the_state(seed: int) -> None:
    j = random_journal(random.Random(seed))
    state, owned = fold(j)
    pending = {n.key for n in state.open_nodes() if n.disposition is Disposition.PENDING}
    found = pending_frontier(state, owned)
    assert {k for _, _, k in found} == pending
    assert len(found) == len(pending)  # no node twice
    for entry, ident, k in found:
        assert ident == node_id(*k) and entry >= -1


def test_the_unused_helpers_exist() -> None:
    assert node("a").formula_sha256 == HASH["a"]


def test_a_blocked_node_is_given_only_after_it_is_reopened() -> None:
    j = Journal(FORMULAS)
    j.shard([("a", ())])
    j.split("a", (), (1,))
    j.stop("a", (1,), "tool_blocked", "tool_retries_exhausted")
    assert chosen(j, 5) == [key("a", (-1,))]
    j.reopen("a", (1,))
    assert set(chosen(j, 5)) == {key("a", (1,)), key("a", (-1,))}
    j.model("a", (-1,))
    assert chosen(j, 5) == [key("a", (1,))]  # a model is evidence, not work to hand over
    j.stop("a", (1,), "resource_blocked", "stalled")
    assert chosen(j, 5) == []
