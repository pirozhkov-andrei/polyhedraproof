"""Static splits: ordered W, prefixes, case indexing, frozen prefix documents (specification
§9.2)."""

from __future__ import annotations

import random

import pytest

from cubeproof.base.errors import ConfigurationError, ContractError
from cubeproof.contracts.documents import Prefixes
from cubeproof.contracts.identity import split_children, split_id
from cubeproof.contracts.values import JsonObject, Node, Split, Splitter
from cubeproof.split.static import (
    STATIC_NAME,
    child_cube,
    child_index,
    frozen_split,
    static_choice,
    static_split,
    static_splitter,
)

FORMULA = "ab" * 32


def case_units(variables: list[int], depth: int, index: int) -> list[int]:
    """The units of case ``index``, written out independently (bit j is the polarity of W[j])."""
    return [variables[j] if (index >> j) & 1 else -variables[j] for j in range(depth)]


def test_a_prefix_of_the_supplied_order_is_the_split() -> None:
    order = [7, 3, 9, 1]
    assert static_split(10, (), order, 3) == (7, 3, 9)
    assert static_split(10, (), order, None) == (7, 3, 9, 1)
    assert static_split(10, (), order, 4) == (7, 3, 9, 1)
    assert static_split(10, (2, -5), order, 1) == (7,)


def test_prefix_zero_means_no_root_split_not_a_zero_variable_split() -> None:
    assert static_split(10, (), [7, 3], 0) is None
    assert static_choice(10, (), [7, 3], 0) is None
    assert static_split(10, (), [], None) is None


def test_the_prefix_must_fit_the_order() -> None:
    for prefix in (-1, 3, True, 1.5):
        with pytest.raises(ConfigurationError):
            static_split(10, (), [7, 3], prefix)  # type: ignore[arg-type]


def test_the_order_itself_is_validated() -> None:
    for order in ([3, 3], [0], [-1], [True], [1.5]):
        with pytest.raises(ConfigurationError):
            static_split(10, (), order, None)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("cube", "order", "rule"),
    [
        ((), [11], "split.out_of_range"),
        ((7,), [7, 3], "split.in_cube"),
        ((-3,), [7, 3], "split.in_cube"),
        ((), list(range(1, 22)), "split.too_long"),
    ],
)
def test_the_split_is_validated_against_the_parent_cube(
    cube: tuple[int, ...], order: list[int], rule: str
) -> None:
    with pytest.raises(ContractError) as error:
        static_split(30 if rule == "split.too_long" else 10, cube, order, None)
    assert error.value.rule == rule


def test_a_noncanonical_or_out_of_range_cube_is_refused() -> None:
    with pytest.raises(ContractError):
        static_split(10, (3, 2), [5], 1)
    with pytest.raises(ContractError):
        static_split(10, (11,), [5], 1)


def test_static_choice_is_a_chosen_split_choice() -> None:
    choice = static_choice(10, (), [7, 3, 9], 2)
    assert choice is not None
    assert choice.status == "chosen" and choice.variables == (7, 3)
    assert choice.info_dict() == {"algorithm": "static", "order": 3, "prefix": 2}


def test_case_indexing_matches_the_contract_children() -> None:
    order = [5, 2, 8, 4]
    for depth in range(1, 5):
        w = order[:depth]
        children = split_children((), w)
        for index in range(1 << depth):
            expected = tuple(sorted(case_units(order, depth, index), key=abs))
            assert child_cube((), w, index) == expected == children[index]
            assert child_index((), w, expected) == index


def test_case_indexing_under_a_parent_cube() -> None:
    rng = random.Random(8)
    for _ in range(40):
        variables = list(range(1, 25))
        rng.shuffle(variables)
        parent_vars = variables[: rng.randint(0, 4)]
        parent = tuple(sorted((rng.choice([-1, 1]) * v for v in parent_vars), key=abs))
        w = variables[4 : 4 + rng.randint(1, 8)]
        children = split_children(parent, w)
        index = rng.randrange(1 << len(w))
        child = child_cube(parent, w, index)
        assert child == children[index]
        assert child_index(parent, w, child) == index
        assert set(parent) <= set(child) and len(child) == len(parent) + len(w)


def test_child_cube_and_index_validate() -> None:
    with pytest.raises(ConfigurationError):
        child_cube((), [1, 2], 4)
    with pytest.raises(ConfigurationError):
        child_cube((), [1, 2], -1)
    with pytest.raises(ContractError):
        child_cube((1,), [1], 0)  # W overlaps the cube
    with pytest.raises(ContractError):
        child_index((), [1, 2], (1,))  # not a child: variable 2 missing
    with pytest.raises(ContractError):
        child_index((), [1, 2], (1, 2, 3))  # an extra literal
    with pytest.raises(ContractError):
        child_index((5,), [1], (-1,))  # the parent literal is missing


def test_the_recorded_splitter_carries_the_order_and_provenance() -> None:
    splitter = static_splitter([7, 3, 9], 2, source="x.json")
    assert splitter.name == STATIC_NAME
    assert splitter.info.to_json() == {"order": [7, 3, 9], "prefix": 2, "source": "x.json"}
    assert static_splitter([4]).info.to_json()["prefix"] == 1


def test_a_frozen_prefix_document_gives_the_split_of_a_node() -> None:
    node = Node(FORMULA, ())
    other = Node(FORMULA, (1,))
    split = Split(node, (4, 2, 9), Splitter("proof-prefix-v1", JsonObject.from_json({"seed": 5})))
    document = Prefixes((split,)).to_json()
    prefixes = Prefixes.from_json(document, variables={FORMULA: 12})
    assert frozen_split(prefixes, node) == split
    assert frozen_split(prefixes, other) is None
    assert split.split_id == split_id(node.node_id, (4, 2, 9))
    bad = dict(document)
    bad["splits"] = [{**document["splits"][0], "variables": [4, 4]}]
    with pytest.raises(ContractError):
        Prefixes.from_json(bad, variables={FORMULA: 12})
