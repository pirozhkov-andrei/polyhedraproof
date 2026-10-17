"""Closure of the evidence graph over wide splits (specification §10.2).

A split of ``k`` variables has ``2**k`` children, and its node is closed only if every one of
them is. The campaign of the 59 formulas consists of such splits: twelve variables at the root
(4096 children) and four below. A closure that looked at the first children only would be right
for one and two variables and wrong for these, so the cases here have splits of three, four and
twelve variables with exactly one child left open, at the first, the last and inner positions,
and random graphs with splits of up to six variables.

The oracle is written here again and shares nothing with the certifier: its own enumeration of
the children (bit ``j`` of the child index gives the sign of the ``j``-th variable), and a plain
recursion for "closed". For a closed node the selected leaves must be a partition: pairwise
incompatible, and every total assignment below the node lies in exactly one leaf.
"""

from __future__ import annotations

import itertools
import random

import pytest

from cubeproof.evidence.certify.closure import EvidenceGraph, Leaf

Cube = tuple[int, ...]
F = "ab" * 32
JOURNAL = "cd" * 32


def children_of(cube: Cube, variables: list[int]) -> list[Cube]:
    found = []
    for index in range(2 ** len(variables)):
        literals = list(cube)
        literals += [v if (index >> j) & 1 else -v for j, v in enumerate(variables)]
        found.append(tuple(sorted(literals, key=abs)))
    return found


def graph_of(splits: dict[Cube, list[list[int]]], verified: set[Cube]) -> EvidenceGraph:
    graph = EvidenceGraph()
    for cube, lists in splits.items():
        for variables in lists:
            graph.add_split((F, cube), variables)
    for seq, cube in enumerate(sorted(verified)):
        graph.add_verified((F, cube), Leaf(JOURNAL, seq, "0" * 64, "1" * 64, "cdcl"))
    return graph


def naive(
    cube: Cube, splits: dict[Cube, list[list[int]]], verified: set[Cube], memo: dict[Cube, bool]
) -> bool:
    if cube not in memo:
        memo[cube] = cube in verified or any(
            all(naive(child, splits, verified, memo) for child in children_of(cube, variables))
            for variables in splits.get(cube, [])
        )
    return memo[cube]


def positions(count: int) -> list[int]:
    """The first and last child, the ones around the fourth, and one in the middle."""
    return sorted({0, 3, 4, 5, count // 2, count - 2, count - 1} & set(range(count)))


@pytest.mark.parametrize("width", [3, 4, 12])
def test_one_open_child_of_a_wide_split_keeps_the_node_open(width: int) -> None:
    variables = list(range(1, width + 1))
    children = children_of((), variables)
    assert len(set(children)) == 2**width
    for position in positions(len(children)):
        verified = set(children) - {children[position]}
        graph = graph_of({(): [variables]}, verified)
        assert not graph.closed((F, ())), (width, position)
        assert not graph.closed((F, children[position]))
        # the same when every child was asked, and remembered, before the parent
        asked = graph_of({(): [variables]}, verified)
        assert [asked.closed((F, child)) for child in children].count(False) == 1
        assert not asked.closed((F, ()))
        assert [key for key, _, _ in graph.frontier((F, ()))] == [(F, children[position])]
    full = graph_of({(): [variables]}, set(children))
    assert full.closed((F, ()))
    leaves, splits = full.select((F, ()))
    assert splits == 1 and sorted(key[1] for key, _ in leaves) == sorted(children)


@pytest.mark.parametrize("width", [3, 4])
def test_a_wide_split_is_closed_through_a_child_that_is_split_again(width: int) -> None:
    """The last child is not verified itself; it is closed by a split of two further variables,
    and stays open while one grandchild is."""
    variables = list(range(1, width + 1))
    children = children_of((), variables)
    last = children[-1]
    below = [width + 1, width + 2]
    grandchildren = children_of(last, below)
    splits = {(): [variables], last: [below]}
    verified = set(children[:-1]) | set(grandchildren)
    assert graph_of(splits, verified).closed((F, ()))
    for missing in grandchildren:
        assert not graph_of(splits, verified - {missing}).closed((F, ()))


def history(rng: random.Random) -> tuple[int, dict[Cube, list[list[int]]], set[Cube], list[Cube]]:
    """A random graph: up to six split nodes, each with one or two splits of one to six
    variables; then most children verified, and some left open anywhere in the child order."""
    total = rng.randint(3, 8)
    splits: dict[Cube, list[list[int]]] = {}
    nodes: list[Cube] = [()]
    frontier: list[Cube] = [()]
    for _ in range(rng.randint(1, 6)):
        if not frontier:
            break
        cube = frontier.pop(rng.randrange(len(frontier)))
        free = [v for v in range(1, total + 1) if v not in {abs(x) for x in cube}]
        if not free:
            continue
        for _ in range(rng.randint(1, 2)):
            variables = rng.sample(free, rng.randint(1, min(len(free), 6)))
            splits.setdefault(cube, []).append(variables)
            children = children_of(cube, variables)
            nodes.extend(children)
            frontier.extend(rng.sample(children, min(len(children), 3)))
    verified: set[Cube] = set()
    mode = rng.random()
    for cube, lists in splits.items():
        for variables in lists:
            children = children_of(cube, variables)
            if mode < 0.4:
                skipped: set[int] = set()
            elif mode < 0.8:
                skipped = {rng.randrange(len(children))}
            else:
                skipped = set(rng.sample(range(len(children)), rng.randint(0, len(children))))
            verified.update(child for i, child in enumerate(children) if i not in skipped)
    for cube in sorted(verified):
        if cube in splits and rng.random() < 0.7:
            verified.discard(cube)  # the closure has to go through the split
    return total, splits, verified, list(dict.fromkeys(nodes))


@pytest.mark.parametrize("seed", range(150))
def test_closure_and_selection_on_random_graphs_with_wide_splits(seed: int) -> None:
    total, splits, verified, nodes = history(random.Random(seed))
    graph = graph_of(splits, verified)
    memo: dict[Cube, bool] = {}
    for cube in nodes:
        expected = naive(cube, splits, verified, memo)
        assert graph.closed((F, cube)) is expected, (seed, cube)
        if not expected:
            continue
        leaves, _ = graph.select((F, cube))
        cubes = [set(key[1]) for key, _ in leaves]
        for a, b in itertools.combinations(cubes, 2):
            assert any(-literal in b for literal in a), (seed, cube, "two leaves overlap")
        free = [v for v in range(1, total + 1) if v not in {abs(x) for x in cube}]
        for bits in itertools.product((False, True), repeat=len(free)):
            assignment = set(cube) | {v if bit else -v for v, bit in zip(free, bits, strict=True)}
            assert sum(leaf <= assignment for leaf in cubes) == 1, (seed, cube)


def test_the_random_graphs_contain_the_cases_that_matter() -> None:
    """Open nodes whose wide split has exactly one open child beyond the fourth, and closed
    nodes with a wide split: the random test is not vacuous for them."""
    one_open_late = closed_wide = 0
    for seed in range(150):
        _, splits, verified, _ = history(random.Random(seed))
        memo: dict[Cube, bool] = {}
        for cube, lists in splits.items():
            for variables in lists:
                if len(variables) < 3:
                    continue
                state = [naive(c, splits, verified, memo) for c in children_of(cube, variables)]
                closed_wide += all(state)
                one_open_late += state.count(False) == 1 and all(state[:4])
    assert one_open_late >= 10 and closed_wide >= 10, (one_open_late, closed_wide)
