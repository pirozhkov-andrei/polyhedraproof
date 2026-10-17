"""The derived indexes of the replay state are caches: after every record they give what a
state replayed from the start gives (specification §7.3, §8.1, §10.3).

``ReplayState`` keeps the sorted roots, the sort key of every node and the open nodes below each
root, and after a record it forgets only what the record can have changed. The oracle of the
first tests is the same class used without that memory: a fresh state that replays the journal
prefix from its first record, so every answer is computed from nothing. Histories are random
(seeded): shards of two formulas with roots of different shapes, splits of several widths,
verified, exhausted, failed and model attempts, stops, reopens, a resume with another policy and
a handoff.

The last tests count work instead of time: the SHA-256 behind ``node_id`` is computed once per
node, and an event below one root does not walk the other roots.
"""

from __future__ import annotations

import random
from collections.abc import Sequence
from typing import Any

import pytest
from cp_sched_support import Journal, children, formula_bytes, node_id, policy

from cubeproof.contracts.identity import node_id as real_node_id
from cubeproof.coordinator.scheduler_select import RootRotation, next_work
from cubeproof.coordinator.state import Disposition, Key, ReplayState, order_key

Cube = tuple[int, ...]
FORMULAS = {"f": formula_bytes(12, [(1, 2), (-1, 3)]), "g": formula_bytes(12, [(4, 5)])}
#: Roots of different shapes: all cases of a prefix on (1, 2), and an uneven antichain.
PREFIX = ((1, 2), (1, -2), (-1, 2), (-1, -2))
UNEVEN = ((3,), (-3, 4), (-3, -4, 5), (-3, -4, -5))


def fresh(journal: Journal, count: int) -> ReplayState:
    state = ReplayState(journal.view)
    state.apply_all(journal.records[:count])
    return state


QUESTIONS = ("roots", "order", "open", "followups", "unneeded", "given", "plans", "closed")


def answer(state: ReplayState, question: str, running: Sequence[Key]) -> Any:
    """One question to a state, as the coordinator and the status ask them."""

    def plans() -> Any:
        rotation = RootRotation()
        return [
            [(w.node, w.root, w.stage) for w in next_work(
                state, running=running[:1], rotation=rotation, limit=limit
            )]
            for limit in (0, 1, 3, 50)
        ]  # fmt: skip

    ask: dict[str, Any] = {
        "roots": state.roots,
        "order": lambda: [list(part) for part in state.root_order()],
        "open": state.open_nodes,
        "followups": state.followups,
        "unneeded": lambda: state.unneeded(sorted(running)),
        "given": state.given_away,
        "closed": lambda: [state.closed(root) for root in state.roots()],
        "plans": plans,
    }
    return ask[question]()


def expected(journal: Journal, count: int, question: str, running: Sequence[Key]) -> Any:
    """The answer of a state that replays the first ``count`` records and is asked nothing else.

    Two answers do not come from the class under test at all: the unneeded running nodes are
    those that are not among the open nodes, and the roots are sorted by the formula and the
    node identity that the test support computes from the specification.
    """
    state = fresh(journal, count)
    if question == "unneeded":
        wanted = {n.key for n in state.open_nodes()}
        return sorted((k for k in running if k not in wanted), key=lambda k: (k[0], node_id(*k)))
    if question == "roots":
        return sorted(state.roots(), key=lambda k: (k[0], node_id(*k)))
    return answer(state, question, running)


def history(seed: int) -> Journal:
    """A random journal: every record is one the coordinator could have written."""
    rng = random.Random(seed)
    journal = Journal(FORMULAS, policy_value=policy(tool_retries=1, max_cube_size=6))
    journal.shard([("f", c) for c in PREFIX], "s1")
    if rng.random() < 0.7:
        journal.shard([("g", c) for c in UNEVEN], "s2")
    open_cubes: dict[str, list[Cube]] = {"f": list(PREFIX), "g": list(UNEVEN)}
    for _ in range(rng.randrange(8, 40)):
        name = rng.choice(["f", "g"])
        if not open_cubes[name]:
            continue
        cube = rng.choice(open_cubes[name])
        action = rng.random()
        if action < 0.30:
            journal.unsat(name, cube)
            open_cubes[name].remove(cube)
        elif action < 0.55 and len(cube) < 5:
            free = [v for v in range(1, 13) if v not in {abs(x) for x in cube}]
            variables = rng.sample(free, rng.choice([1, 2, 3]))
            journal.failed(name, cube, "EXHAUSTED", "time")
            journal.split(name, cube, variables)
            open_cubes[name].remove(cube)
            open_cubes[name].extend(tuple(c) for c in children(cube, variables))
        elif action < 0.70:
            journal.failed(name, cube, "TOOL_FAILED", "crash")
        elif action < 0.80:
            journal.failed(name, cube, "EXHAUSTED", "time")
        elif action < 0.86:
            journal.stop(name, cube, rng.choice(["stuck", "tool_blocked"]))
        elif action < 0.92:
            journal.reopen(name, cube)
        elif action < 0.95:
            journal.resume(policy_value=policy(tool_retries=rng.choice([0, 2]), max_cube_size=4))
        elif action < 0.98:
            journal.model(name, cube)
        else:
            journal.handoff([(name, cube)], request=f"{len(journal.records):032x}")
            open_cubes[name].remove(cube)
    return journal


@pytest.mark.parametrize("seed", range(120))
def test_every_answer_after_every_record_is_the_one_of_a_fresh_replay(seed: int) -> None:
    """The incremental state is asked a random subset of the questions in a random order after
    one to three records, as callers do (the coordinator asks for follow-ups right after a
    record, a status asks for the open nodes at any time); each answer must be the one of a
    state that replayed the same prefix and was asked only that."""
    journal = history(seed)
    incremental = ReplayState(journal.view)
    rng = random.Random(seed)
    pause = 0
    for count, record in enumerate(journal.records, 1):
        incremental.apply(record)
        if incremental.policy is None:
            continue
        if pause:
            pause -= 1
            continue
        pause = rng.choice([0, 0, 1, 2])
        candidates = [n.key for n in fresh(journal, count).open_nodes()]
        candidates += [
            (journal.sha("f"), (1, 2, 9)),
            (journal.sha("g"), (6,)),
        ]  # below a root; none
        running = rng.sample(candidates, min(3, len(candidates)))
        asked = rng.sample(QUESTIONS, rng.randrange(1, len(QUESTIONS) + 1))
        for question in asked:
            got = answer(incremental, question, running)
            assert got == expected(journal, count, question, running), (count, question, asked)


def test_the_roots_of_two_formulas_are_ordered_by_formula_first() -> None:
    journal = Journal(FORMULAS, policy_value=policy())
    journal.shard([("f", c) for c in PREFIX] + [("g", c) for c in UNEVEN])
    state = fresh(journal, len(journal.records))
    roots, keys = state.root_order()
    assert len(roots) == 8 and len({formula for formula, _ in roots}) == 2
    assert list(keys) == [(formula, node_id(formula, cube)) for formula, cube in roots]
    assert list(roots) == sorted(roots, key=lambda k: (k[0], node_id(*k)))
    assert [formula for formula, _ in roots] == sorted(formula for formula, _ in roots)


def test_the_histories_exercise_what_the_caches_must_survive() -> None:
    """The random journals really contain the cases: follow-ups, stops, models, given nodes."""
    seen: set[str] = set()
    for seed in range(60):
        journal = history(seed)
        state = fresh(journal, len(journal.records))
        seen.update(type(r.payload).__name__ for r in journal.records)
        if state.followups():
            seen.add("followup")
        if state.given_away():
            seen.add("given")
        seen.update(n.disposition.name for n in state.open_nodes())
    assert {"SplitRecord", "Attempt", "NodeStop", "NodeReopen", "Resume", "Handoff"} <= seen
    assert {"followup", "given"} <= seen
    assert {d.name for d in Disposition} - {"STOP_DUE"} <= seen | {"STOP_DUE"}


def test_a_node_gets_an_owner_when_a_later_shard_brings_its_root() -> None:
    """What is remembered about a node is forgotten when the roots change: a running node below
    no root is not needed; once a shard makes it a root, it is open work."""
    journal = Journal(FORMULAS, policy_value=policy())
    journal.shard([("f", c) for c in PREFIX], "s1")
    state = fresh(journal, len(journal.records))
    key = (journal.sha("g"), UNEVEN[0])
    assert state.unneeded([key]) == [key]
    journal.shard([("g", c) for c in UNEVEN], "s2")
    state.apply(journal.records[-1])
    assert state.unneeded([key]) == []
    assert key in {n.key for n in state.open_nodes()}


# -- the cost: counted, not timed ------------------------------------------------------------------


def wide(count: int) -> Journal:
    """One formula with ``2**count`` roots: all cases of a prefix, as a campaign has them."""
    journal = Journal({"f": formula_bytes(14, [(1, 2)])}, policy_value=policy())
    variables = list(range(1, count + 1))
    journal.shard([("f", tuple(c)) for c in children((), variables)])
    return journal


def test_the_sort_key_of_a_node_is_hashed_once(monkeypatch: pytest.MonkeyPatch) -> None:
    journal = wide(6)
    calls: list[Key] = []

    def counting(formula: str, cube: Sequence[int]) -> str:
        calls.append((formula, tuple(cube)))
        return real_node_id(formula, cube)

    order_key.cache_clear()
    monkeypatch.setattr("cubeproof.coordinator.state.node_id", counting)
    state = fresh(journal, len(journal.records))
    rotation = RootRotation()
    for _ in range(5):  # five plans, five rounds of derived work
        work = next_work(state, running=(), rotation=rotation, limit=4)
        assert len(work) == 4
        state.followups()
        state.unneeded([w.node.key for w in work])
        state.roots()
    assert len(calls) == len(set(calls)) == 64  # each root once, whatever the number of plans


def test_an_event_below_one_root_walks_that_root_only(monkeypatch: pytest.MonkeyPatch) -> None:
    journal = wide(6)
    state = fresh(journal, len(journal.records))
    state.followups()  # everything derived once
    walked: list[Key] = []
    real = ReplayState.iter_open

    def counting(self: ReplayState, root: Key) -> Any:
        walked.append(root)
        return real(self, root)

    monkeypatch.setattr(ReplayState, "iter_open", counting)
    first = state.roots()[0]
    journal.failed("f", first[1], "EXHAUSTED", "time")
    journal.split("f", first[1], [9, 10])
    for record in journal.records[-2:]:
        state.apply(record)
        state.followups()
        state.unneeded([first])
    assert set(walked) == {first} and len(walked) == 2  # once per record, the touched root
    assert len(state.open_nodes()) == 63 + 4 and set(walked) == {first}


def test_a_plan_that_reaches_its_limit_does_not_visit_every_root(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    journal = wide(8)
    state = fresh(journal, len(journal.records))
    walked: list[Key] = []
    real = ReplayState.iter_open

    def counting(self: ReplayState, root: Key) -> Any:
        walked.append(root)
        return real(self, root)

    monkeypatch.setattr(ReplayState, "iter_open", counting)
    rotation = RootRotation()
    first = next_work(state, running=(), rotation=rotation, limit=16)
    assert [w.root for w in first] == state.roots()[:16] and len(walked) == 16
    second = next_work(state, running=[w.node.key for w in first], rotation=rotation, limit=16)
    assert [w.root for w in second] == state.roots()[16:32]  # the rotation went on
    assert len(walked) == 32
