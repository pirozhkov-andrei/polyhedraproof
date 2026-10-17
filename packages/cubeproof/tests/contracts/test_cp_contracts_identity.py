"""Cube canonicality, node and split identities and sign children (specification §3.2)."""

from __future__ import annotations

import hashlib
import itertools
import json
import random
from typing import Any

import cp_corpus
import pytest

from cubeproof.base.errors import ContractError
from cubeproof.contracts.identity import (
    canonical_cube,
    check_cube,
    check_split,
    compatible,
    cube_problem,
    incompatible,
    node_id,
    pairwise_incompatible,
    split_children,
    split_id,
    split_problem,
)
from cubeproof.contracts.primitives import K_MAX
from cubeproof.contracts.values import JsonObject, Node, Split, Splitter

CNF = cp_corpus.vectors("cnf")
FORMULAS = {f["name"]: f for f in CNF["formulas"]}


def _plain_node_id(formula_sha256: str, cube: list[int]) -> str:
    text = "node\0" + formula_sha256 + "\0" + " ".join(str(x) for x in cube)
    return hashlib.sha256(text.encode("ascii")).hexdigest()


def _plain_split_id(node: str, variables: list[int]) -> str:
    data = json.dumps({"node_id": node, "variables": variables}, separators=(",", ":"))
    return hashlib.sha256(data.encode("ascii")).hexdigest()


@pytest.mark.parametrize("case", CNF["cubes"], ids=lambda c: f"{c['cube']}/{c['variables']}")
def test_cube_vectors(case: dict[str, Any]) -> None:
    assert cube_problem(case["cube"], case["variables"]) == case["expect"]
    if case["expect"] is None:
        assert check_cube(case["cube"], case["variables"]) == tuple(case["cube"])
    else:
        with pytest.raises(ContractError) as info:
            check_cube(case["cube"], case["variables"])
        assert info.value.rule == case["expect"]


@pytest.mark.parametrize("case", CNF["nodes"], ids=lambda c: f"{c['formula']}{c['cube']}")
def test_node_vectors(case: dict[str, Any]) -> None:
    assert node_id(case["formula_sha256"], case["cube"]) == case["node_id"]
    assert node_id(case["formula_sha256"], tuple(case["cube"])) == case["node_id"]
    node = Node(case["formula_sha256"], tuple(case["cube"]))
    assert node.node_id == case["node_id"]
    assert node.sort_key == (case["formula_sha256"], case["node_id"])


@pytest.mark.parametrize("case", CNF["splits"], ids=lambda c: c["split_id"][:12])
def test_split_vectors(case: dict[str, Any]) -> None:
    formula = FORMULAS[case["formula"]]
    assert node_id(formula["sha256"], case["cube"]) == case["node_id"]
    assert split_id(case["node_id"], case["variables"]) == case["split_id"]
    assert _plain_split_id(case["node_id"], case["variables"]) == case["split_id"]
    children = split_children(case["cube"], case["variables"])
    assert [list(c) for c in children] == [c["cube"] for c in case["children"]]
    assert [c["index"] for c in case["children"]] == list(range(len(children)))
    for child, expected in zip(children, case["children"]):
        assert node_id(formula["sha256"], child) == expected["node_id"]
    split = Split(
        Node(formula["sha256"], tuple(case["cube"])),
        tuple(case["variables"]),
        Splitter("static", JsonObject.from_json({})),
    )
    assert split.split_id == case["split_id"]
    assert [c.node_id for c in split.children()] == [c["node_id"] for c in case["children"]]


@pytest.mark.parametrize(
    "case", CNF["split_problems"], ids=lambda c: f"{c['split'][:4]}/{c['cube']}/{c['expect']}"
)
def test_split_problem_vectors(case: dict[str, Any]) -> None:
    assert split_problem(case["split"], case["cube"], case["variables"]) == case["expect"]
    if case["expect"] is None:
        check_split(case["split"], case["cube"], case["variables"])
    else:
        with pytest.raises(ContractError) as info:
            check_split(case["split"], case["cube"], case["variables"])
        assert info.value.rule == case["expect"]


def test_split_problems_are_reported_in_the_listed_order() -> None:
    # Too long and repeated and out of range: too_long comes first.
    assert split_problem([5] * 21, [1], 3) == "split.too_long"
    # Repeated and out of range and in cube: repeated first.
    assert split_problem([1, 1, 9], [1], 3) == "split.repeated"
    # Out of range and in cube: out_of_range first.
    assert split_problem([9, 1], [1], 3) == "split.out_of_range"
    assert split_problem(list(range(1, K_MAX + 1)), [], K_MAX) is None
    assert split_problem(list(range(1, K_MAX + 2)), [], K_MAX + 1) == "split.too_long"


def test_split_refuses_values_that_are_not_positive_integers() -> None:
    bads: tuple[list[Any], ...] = ([0], [-1], [True], ["1"])
    for bad in bads:
        with pytest.raises(ContractError) as info:
            check_split(bad, [], 3)
        assert info.value.rule == "schema"


def test_node_id_refuses_noncanonical_cubes() -> None:
    for bad in ([2, 1], [1, 1], [1, -1], [0], [True]):
        with pytest.raises(ContractError):
            node_id("0" * 64, bad)


def test_node_id_refuses_a_bad_formula_hash() -> None:
    with pytest.raises(ContractError):
        node_id("A" * 64, [])


def test_canonical_cube_is_a_construction_helper() -> None:
    assert canonical_cube([3, -1, 2]) == (-1, 2, 3)
    assert canonical_cube([]) == ()
    for bad in ([1, -1], [2, 2], [0], [True], [1.0]):
        with pytest.raises(ContractError):
            canonical_cube(bad)  # type: ignore[arg-type]


def test_compatibility() -> None:
    assert incompatible([1, 2], [-2, 3])
    assert not incompatible([1, 2], [2, 3])
    assert not incompatible([], [1])
    assert compatible([1], [1, 2])
    assert not compatible([-1], [1, 2])


def test_children_are_a_disjoint_cover_of_the_parent() -> None:
    rng = random.Random(1030)
    for _ in range(300):
        count = rng.randint(1, 9)
        variables = list(range(1, count + 1))
        cube_vars = rng.sample(variables, rng.randint(0, count - 1))
        cube = sorted((v if rng.random() < 0.5 else -v for v in cube_vars), key=abs)
        free = [v for v in variables if v not in cube_vars]
        width = rng.randint(1, min(len(free), 5))
        w = rng.sample(free, width)
        assert split_problem(w, cube, count) is None
        children = split_children(cube, w)
        assert len(children) == 2**width
        for index, child in enumerate(children):
            assert check_cube(child, count) == child
            assert set(cube) <= set(child)
            for j, var in enumerate(w):
                assert (var if (index >> j) & 1 else -var) in child
        for a, b in itertools.combinations(children, 2):
            assert incompatible(a, b)
        # Every total assignment that extends the cube lies in exactly one child.
        for bits in itertools.product((False, True), repeat=count):
            literals = {v if bits[v - 1] else -v for v in variables}
            if not set(cube) <= literals:
                continue
            assert sum(set(child) <= literals for child in children) == 1


def _plain_pairwise_incompatible(cubes: list[list[int]]) -> bool:
    return all(
        any(-x in b for x in a) for a, b in itertools.combinations([set(c) for c in cubes], 2)
    )


def _random_cubes(rng: random.Random) -> list[list[int]]:
    count = rng.randint(1, 6)
    cubes = []
    for _ in range(rng.randint(0, 12)):
        chosen = rng.sample(range(1, count + 1), rng.randint(0, count))
        cubes.append(sorted((v if rng.random() < 0.5 else -v for v in chosen), key=abs))
    return cubes


def test_pairwise_incompatible_agrees_with_the_plain_pairwise_check() -> None:
    rng = random.Random(1032)
    verdicts = set()
    for _ in range(3000):
        cubes = _random_cubes(rng)
        expected = _plain_pairwise_incompatible(cubes)
        verdicts.add(expected)
        assert pairwise_incompatible(cubes) == expected, cubes
    assert verdicts == {True, False}


def test_pairwise_incompatible_on_split_trees_and_near_misses() -> None:
    rng = random.Random(1033)
    for _ in range(200):
        # The leaves of a random split tree are a disjoint cover: always incompatible.
        leaves: list[tuple[int, ...]] = [()]
        free = list(range(1, 13))
        rng.shuffle(free)
        for _ in range(rng.randint(1, 4)):
            index = rng.randrange(len(leaves))
            used = {abs(x) for x in leaves[index]}
            width = rng.randint(1, 2)
            variables = [v for v in free if v not in used][:width]
            leaves[index : index + 1] = list(split_children(leaves[index], variables))
        cubes = [list(c) for c in leaves]
        rng.shuffle(cubes)
        assert pairwise_incompatible(cubes)
        if len(cubes) > 1:
            # Dropping one literal of one leaf (a coarser cube) creates an overlap with a
            # sibling unless the leaf had no literal left to drop.
            victim = rng.randrange(len(cubes))
            if cubes[victim]:
                broken = [*cubes]
                broken[victim] = cubes[victim][:-1]
                assert pairwise_incompatible(broken) == _plain_pairwise_incompatible(broken)
            # A duplicate leaf always overlaps itself.
            assert not pairwise_incompatible([*cubes, cubes[0]])
    assert pairwise_incompatible([])
    assert pairwise_incompatible([[1]])
    assert pairwise_incompatible([[]])
    assert not pairwise_incompatible([[], [1]])
    assert not pairwise_incompatible([[1], [2]])


def test_pairwise_incompatible_both_paths_agree_with_the_plain_check(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The refinement hands over to the plain check when its work bound is exceeded. Record
    # which path decided, so that both paths and both verdicts are known to be exercised.
    from cubeproof.contracts import identity

    plain = identity._pairwise
    fallback: list[bool] = []

    def recording(sets: Any) -> bool:
        fallback.append(True)
        return plain(sets)

    monkeypatch.setattr(identity, "_pairwise", recording)
    seen: set[tuple[bool, bool]] = set()
    rng = random.Random(1034)
    for _ in range(3000):
        cubes = _random_cubes(rng)
        fallback.clear()
        result = identity.pairwise_incompatible(cubes)
        assert result == _plain_pairwise_incompatible(cubes), cubes
        seen.add((bool(fallback), result))
    assert seen == {(False, False), (False, True), (True, False), (True, True)}


def test_random_node_ids_match_the_plain_definition() -> None:
    rng = random.Random(1031)
    for _ in range(500):
        formula = hashlib.sha256(str(rng.random()).encode()).hexdigest()
        variables = rng.sample(range(1, 10**6), rng.randint(0, 30))
        cube = sorted((v if rng.random() < 0.5 else -v for v in variables), key=abs)
        assert node_id(formula, cube) == _plain_node_id(formula, cube)


def test_split_value_validates_against_its_parent() -> None:
    node = Node("0" * 64, (1,))
    splitter = Splitter("static", JsonObject.from_json({}))
    with pytest.raises(ContractError) as info:
        Split(node, (1,), splitter)
    assert info.value.rule == "split.in_cube"
    with pytest.raises(ContractError) as empty:
        Split(node, (), splitter)
    assert empty.value.rule == "split.empty"
    assert Split(node, (3, 2), splitter).to_json() == {
        "node": {"formula_sha256": "0" * 64, "cube": [1]},
        "variables": [3, 2],
        "splitter": {"name": "static", "info": {}},
    }
