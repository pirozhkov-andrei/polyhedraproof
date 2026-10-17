"""Closed coverage: exact, reduced, stable (specification §8.4, §12.3).

The oracle is an independent transcription of specification §10.2/§10.3 over the journal's plain
JSON with ``fractions.Fraction``; it shares nothing with ``ReplayState`` or the coverage module."""

from __future__ import annotations

import random
from fractions import Fraction
from typing import Any

import cp_status_support as sup
import pytest

from cubeproof.contracts.identity import node_id
from cubeproof.coordinator.state import ReplayState
from cubeproof.coordinator.status_coverage import (
    Coverage,
    CoverageBudget,
    closed_coverage,
    fraction_text,
    mean_text,
    reduce_fraction,
)

sched = sup.sched
Cube = tuple[int, ...]


def _fraction(item: Coverage) -> Fraction:
    return Fraction(item.numerator, 2**item.power)


def oracle(j: Any, name: str, root: Cube = ()) -> Fraction:
    """The closed measure of ``root`` by the definition (module doc)."""
    formula = j.hashes[name]
    verified: set[Cube] = set()
    models: set[Cube] = set()
    splits: dict[Cube, list[tuple[str, tuple[int, ...]]]] = {}
    for value in j.values:
        kind = value["type"]
        if kind == "attempt":
            cube = tuple(value["node"]["cube"])
            if value["outcome"] == "VERIFIED_UNSAT":
                verified.add(cube)
            elif value["outcome"] == "MODEL":
                models.add(cube)
        elif kind == "split":
            cube = tuple(value["node"]["cube"])
            variables = tuple(value["variables"])
            splits.setdefault(cube, []).append(
                (sched.split_id(formula, cube, variables), variables)
            )

    def closed(cube: Cube) -> bool:
        if cube in verified:
            return True
        return any(
            all(closed(child) for child in sched.children(cube, variables))
            for _, variables in splits.get(cube, [])
        )

    def measure(cube: Cube) -> Fraction:
        if closed(cube):
            return Fraction(1, 2 ** (len(cube) - len(root)))
        if cube in models or cube not in splits:
            return Fraction(0)
        _, variables = min(splits[cube])
        return sum((measure(child) for child in sched.children(cube, variables)), Fraction(0))

    return measure(root)


def _cover(j: Any) -> list[Coverage]:
    state, _ = sup.folded(j)
    return closed_coverage(state)


def _journal(variables: int = 6) -> Any:
    j = sched.Journal({"a": sched.formula_bytes(variables)})
    j.shard([("a", ())])
    return j


def _reduced(item: Coverage) -> bool:
    if item.power == 0:
        return item.numerator in (0, 1)
    return item.numerator % 2 == 1 and item.numerator <= 2**item.power


# -- small cases -----------------------------------------------------------------------------------


def test_no_evidence_is_zero_and_a_closed_root_is_one() -> None:
    j = _journal()
    (empty,) = _cover(j)
    assert (empty.numerator, empty.power) == (0, 0) and not empty.closed
    j.unsat("a", ())
    (full,) = _cover(j)
    assert (full.numerator, full.power) == (1, 0) and full.closed


def test_two_of_four_children_are_one_half() -> None:
    j = _journal()
    j.split("a", (), (1, 2))
    j.unsat("a", (-1, -2))
    j.unsat("a", (1, -2))
    j.model("a", (-1, 2))
    j.failed("a", (1, 2), "EXHAUSTED", "time")
    (item,) = _cover(j)
    assert (item.numerator, item.power) == (1, 1)
    assert (
        item.to_json()["closed_numerator"] == "1" and item.to_json()["denominator_power_two"] == 1
    )


def test_a_model_counts_nothing_and_an_unsplit_open_node_counts_nothing() -> None:
    j = _journal()
    j.split("a", (), (1,))
    j.unsat("a", (-1,))
    j.model("a", (1,))
    (item,) = _cover(j)
    assert _fraction(item) == Fraction(1, 2)


def test_uneven_depths_reduce_to_lowest_terms() -> None:
    j = _journal()
    j.split("a", (), (1,))
    j.unsat("a", (-1,))  # 1/2
    j.split("a", (1,), (2, 3))
    j.unsat("a", (1, -2, -3))  # 1/8
    j.unsat("a", (1, 2, -3))  # 1/8
    (item,) = _cover(j)
    assert (item.numerator, item.power) == (3, 2)  # 3/4, not 6/8
    assert _reduced(item)


def test_the_smallest_split_id_is_followed_but_any_closed_split_closes_a_node() -> None:
    j = _journal()
    j.split("a", (), (1,))
    j.split("a", (), (2,))
    _, high = sorted([(1,), (2,)], key=lambda w: sched.split_id(j.sha("a"), (), w))
    # evidence only below the split that does NOT have the smallest id: the node is closed all the
    # same, because closure (specification §10.2) is by any split, only the open traversal uses the
    # smallest
    for child in sched.children((), high):
        j.unsat("a", child)
    (item,) = _cover(j)
    assert item.closed


def test_a_node_with_a_model_counts_nothing_even_below_a_split() -> None:
    """The traversal is the certifier's (specification §10.3): a model node is reported and not
    entered, so closed evidence below it is not counted until the model is resolved (documented
    limit)."""
    j = _journal()
    j.model("a", ())
    j.split("a", (), (1,))
    j.unsat("a", (-1,))
    (item,) = _cover(j)
    assert (item.numerator, item.power) == (0, 0)
    assert oracle(j, "a") == 0


def test_the_open_traversal_uses_the_smallest_split_id() -> None:
    j = _journal()
    j.split("a", (), (1,))
    j.split("a", (), (2,))
    low, high = sorted([(1,), (2,)], key=lambda w: sched.split_id(j.sha("a"), (), w))
    j.unsat("a", sched.children((), low)[0])  # half of the smallest split
    j.unsat("a", sched.children((), high)[0])  # half of the other: ignored for an open node
    (item,) = _cover(j)
    assert _fraction(item) == Fraction(1, 2) == oracle(j, "a")


def test_several_roots_are_listed_in_order_and_each_relative_to_itself() -> None:
    j = sched.Journal({"a": sched.formula_bytes(6), "b": sched.formula_bytes(7)})
    j.shard([("a", (1,)), ("a", (-1,)), ("b", ())])
    j.split("a", (1,), (2,))
    j.unsat("a", (1, -2))
    j.unsat("b", ())
    items = _cover(j)
    state, _ = sup.folded(j)
    assert [i.root for i in items] == state.roots()
    by_root = {i.root: _fraction(i) for i in items}
    assert by_root[j.key("a", (1,))] == Fraction(1, 2)
    assert by_root[j.key("a", (-1,))] == 0
    assert by_root[j.key("b", ())] == 1
    keys = [(i.root[0], node_id(*i.root)) for i in items]
    assert keys == sorted(keys)


def test_given_away_nodes_are_not_counted_as_closed_coverage() -> None:
    j = _journal()
    j.split("a", (), (1,))
    j.unsat("a", (-1,))
    j.handoff([("a", (1,))])
    (item,) = _cover(j)
    assert _fraction(item) == Fraction(1, 2)


def test_a_closed_node_that_was_given_away_is_not_this_workers_coverage() -> None:
    j = _journal()
    j.split("a", (), (1,))
    j.unsat("a", (-1,))  # 1/2
    j.split("a", (1,), (2,))
    j.unsat("a", (1, -2))  # would be 1/4 ...
    j.handoff([("a", (1, -2))])  # ... but it belongs to another worker now
    (item,) = _cover(j)
    assert _fraction(item) == Fraction(1, 2)


def test_a_root_given_away_is_not_listed() -> None:
    j = _journal()
    j.handoff([("a", ())])
    assert _cover(j) == []


def test_coverage_never_exceeds_one_and_is_monotone_while_records_arrive() -> None:
    j = _journal(8)
    j.split("a", (), (1, 2))
    j.split("a", (-1, -2), (3,))
    for cube in [(-1, -2, -3), (1, 2), (1, -2), (-1, 2), (-1, -2, 3)]:
        j.unsat("a", cube)
    state = ReplayState(j.view)
    previous = Fraction(0)
    for record in j.records:
        state.apply(record)
        roots = closed_coverage(state)
        value = _fraction(roots[0]) if roots else Fraction(0)
        assert previous <= value <= 1
        previous = value
    assert previous == 1


def test_a_numerator_beyond_64_bits_is_exact_and_a_decimal_string() -> None:
    depth = 100
    j = sched.Journal({"a": sched.formula_bytes(depth + 2)})
    j.shard([("a", ())])
    cube: list[int] = []
    for level in range(1, depth + 1):
        j.split("a", tuple(cube), (level,))
        j.unsat("a", (*cube, -level))
        cube.append(level)
    (item,) = _cover(j)
    assert (item.numerator, item.power) == (2**depth - 1, depth)
    assert item.numerator > 2**64
    wire = item.to_json()
    assert wire["closed_numerator"] == str(2**depth - 1) and isinstance(
        wire["closed_numerator"], str
    )
    assert _reduced(item) and _fraction(item) == oracle(j, "a")


# -- stability: the oracle, order independence, restore --------------------------------------------


def _random_ops(rng: random.Random, variables: int) -> list[tuple[str, Cube, tuple[int, ...]]]:
    ops: list[tuple[str, Cube, tuple[int, ...]]] = []
    frontier: list[Cube] = [()]
    for _ in range(rng.randrange(4, 40)):
        if not frontier:
            break
        cube = frontier.pop(rng.randrange(len(frontier)))
        used = {abs(x) for x in cube}
        free = [v for v in range(1, variables + 1) if v not in used]
        action = rng.random()
        if action < 0.45 and len(free) >= 1:
            width = rng.choice([1, 1, 2]) if len(free) >= 2 else 1
            chosen = tuple(sorted(rng.sample(free, width)))
            ops.append(("split", cube, chosen))
            frontier.extend(sched.children(cube, chosen))
            if rng.random() < 0.2:  # a second, alternative split of the same node
                other = tuple(sorted(rng.sample(free, 1)))
                if other != chosen:
                    ops.append(("split", cube, other))
        elif action < 0.8:
            ops.append(("unsat", cube, ()))
        elif action < 0.9:
            ops.append(("model", cube, ()))
        else:
            ops.append(("exhausted", cube, ()))
    return ops


def _play(ops: list[tuple[str, Cube, tuple[int, ...]]], variables: int) -> Any:
    j = _journal(variables)
    for kind, cube, chosen in ops:
        if kind == "split":
            j.split("a", cube, chosen)
        elif kind == "unsat":
            j.unsat("a", cube)
        elif kind == "model":
            j.model("a", cube)
        else:
            j.failed("a", cube, "EXHAUSTED", "time")
    return j


@pytest.mark.parametrize("seed", range(12))
def test_coverage_equals_the_oracle_in_every_order_of_the_same_evidence(seed: int) -> None:
    rng = random.Random(seed)
    variables = rng.randrange(3, 8)
    ops = _random_ops(rng, variables)
    expected: Fraction | None = None
    for _ in range(4):
        shuffled = list(ops)
        rng.shuffle(shuffled)
        j = _play(shuffled, variables)
        (item,) = _cover(j)
        assert _reduced(item)
        value = _fraction(item)
        assert 0 <= value <= 1
        assert value == oracle(j, "a")
        if expected is not None:
            assert value == expected  # independent of the order in which records arrived
        expected = value


def test_coverage_is_the_same_after_a_cache_restore_and_a_second_computation() -> None:
    rng = random.Random(7)
    ops = _random_ops(rng, 6)
    j = _play(ops, 6)
    state, _ = sup.folded(j)
    first = closed_coverage(state)
    assert closed_coverage(state) == first  # repeatable
    restored = ReplayState(j.view)
    restored.restore(state.export())
    assert closed_coverage(restored) == first


def test_the_budget_stops_a_large_traversal_with_a_signal_not_a_wrong_value() -> None:
    j = _journal(8)
    j.split("a", (), (1, 2, 3))
    for cube in sched.children((), (1, 2, 3))[:7]:
        j.unsat("a", cube)
    state, _ = sup.folded(j)
    # root + 8 children are visited: nine visits are exactly enough
    assert _fraction(closed_coverage(state, max_visits=9)[0]) == Fraction(7, 8)
    with pytest.raises(CoverageBudget) as caught:
        closed_coverage(state, max_visits=8)
    assert caught.value.visited == 8


# -- the arithmetic helpers ------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("numerator", "power", "expected"),
    [
        (0, 5, (0, 0)),
        (4, 2, (1, 0)),
        (6, 3, (3, 2)),
        (3, 2, (3, 2)),
        (1, 0, (1, 0)),
        (8, 0, (8, 0)),
    ],
)
def test_reduce_fraction(numerator: int, power: int, expected: tuple[int, int]) -> None:
    assert reduce_fraction(numerator, power) == expected


def test_decimal_text_rounds_down_exactly() -> None:
    assert fraction_text(1, 1) == "0.5000"
    assert fraction_text(1, 3) == "0.1250"
    assert fraction_text(1, 0) == "1.0000"
    assert fraction_text(2**100 - 1, 100) == "0.9999"  # not rounded up to 1.0000
    assert mean_text([]) == "0.0000"
    assert mean_text([(1, 0), (0, 0), (1, 1)]) == "0.5000"
    assert mean_text([(1, 0), (1, 0), (0, 0)]) == "0.6666"
