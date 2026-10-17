"""Shard, handoff request, roots, prefixes and weights documents (specification §4.5, §12.1)."""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from typing import Any

import cp_corpus
import pytest

from cubeproof.base.canonical_json import encode, parse_document
from cubeproof.base.errors import ContractError
from cubeproof.contracts.documents import HandoffRequest, Prefixes, Roots, Shard, Weights
from cubeproof.contracts.values import Node

ALL3 = "83ef822c62746022fb52b0d52f6050c2f8a699e171512c9eb61356bda5d553d4"


def _variables(context: dict[str, Any], value: Any) -> dict[str, int] | None:
    """The fixtures give one V for every node; the API takes V per formula."""
    if "variables" not in context:
        return None
    nodes = value.get("nodes") or value.get("roots") or []
    return {n["formula_sha256"]: context["variables"] for n in nodes}


PARSERS: dict[str, Callable[[Any, dict[str, Any]], Any]] = {
    "shard": lambda v, c: Shard.from_json(v, variables=_variables(c, v)),
    "handoff-request": lambda v, c: HandoffRequest.from_json(v),
    "roots": lambda v, c: Roots.from_json(v, variables=_variables(c, v)),
    "prefixes": lambda v, c: Prefixes.from_json(v, variables=c.get("formulas")),
    "weights": lambda v, c: Weights.from_json(v, planned=c.get("planned")),
}


def _entries() -> list[dict[str, Any]]:
    return [e for kind in PARSERS for e in cp_corpus.documents(kind)]


@pytest.mark.parametrize("entry", _entries(), ids=lambda e: e["id"])
def test_document_fixtures(entry: dict[str, Any]) -> None:
    data = cp_corpus.fixture_bytes(entry)
    value = parse_document(data)
    context = entry.get("context", {})
    kind, expected = cp_corpus.expectation(entry)
    parse = PARSERS[entry["type"]]
    if kind == "valid":
        document = parse(value, context)
        assert document.to_json() == value
        assert encode(document.to_json()) + b"\n" == data
        return
    with pytest.raises(ContractError) as info:
        parse(value, context)
    assert info.value.rule == ("schema" if kind == "schema" else expected)
    if kind == "schema":
        assert info.value.location == expected


def test_shard_identity_and_nodes() -> None:
    entry = next(e for e in cp_corpus.documents("shard") if e["id"] == "shard-valid")
    data = cp_corpus.fixture_bytes(entry)
    shard = Shard.from_json(parse_document(data))
    assert shard.shard_id == hashlib.sha256(data[:-1]).hexdigest()
    keys = [n.sort_key for n in shard.nodes]
    assert keys == sorted(keys)


def test_shard_constructor_refuses_an_empty_node_list() -> None:
    # Shards built directly (not through from_json, whose schema needs one node) follow
    # the same rule shard.nodes.
    assert Shard("0" * 64, "s", (Node(ALL3, ()),)).nodes
    with pytest.raises(ContractError) as info:
        Shard("0" * 64, "s", ())
    assert info.value.rule == "shard.nodes"


def test_shard_range_is_checked_only_where_v_is_known() -> None:
    value = {
        "format": "cubeproof-shard-1",
        "campaign": "0" * 64,
        "name": "s",
        "nodes": [{"formula_sha256": ALL3, "cube": [7]}],
    }
    assert Shard.from_json(value).nodes[0].cube == (7,)
    with pytest.raises(ContractError) as info:
        Shard.from_json(value, variables={ALL3: 3})
    assert info.value.rule == "cube.range"
    with pytest.raises(ContractError) as missing:
        Shard.from_json(value, variables={})
    assert missing.value.rule == "record.formula"


def test_nodes_of_different_formulas_never_conflict() -> None:
    other = "1" * 64  # sorts before ALL3
    nodes = [{"formula_sha256": other, "cube": [1]}, {"formula_sha256": ALL3, "cube": [1]}]
    roots = Roots.from_json({"format": "cubeproof-roots-1", "roots": nodes})
    assert len(roots.roots) == 2
    # The empty cube is compatible with every cube of its formula, in either order.
    clash = [{"formula_sha256": ALL3, "cube": []}, {"formula_sha256": ALL3, "cube": [1]}]
    for ordered in (clash, clash[::-1]):
        with pytest.raises(ContractError) as info:
            Roots.from_json({"format": "cubeproof-roots-1", "roots": ordered})
        assert info.value.rule == "roots.nodes"
    with pytest.raises(ContractError) as info:
        Roots.from_json({"format": "cubeproof-roots-1", "roots": clash})
    assert info.value.rule == "roots.nodes"


def test_handoff_request_round_trip() -> None:
    value = {
        "format": "cubeproof-handoff-request-1",
        "campaign": "0" * 64,
        "request_id": "a" * 32,
        "node_count": 3,
        "output_name": "out-1",
    }
    request = HandoffRequest.from_json(value)
    assert request.to_json() == value
    assert (request.node_count, request.output_name) == (3, "out-1")


def test_prefix_splits_need_a_known_formula_for_range() -> None:
    value = {
        "format": "cubeproof-prefixes-1",
        "splits": [
            {
                "node": {"formula_sha256": ALL3, "cube": []},
                "variables": [4],
                "splitter": {"name": "static", "info": {}},
            }
        ],
    }
    assert len(Prefixes.from_json(value).splits) == 1
    with pytest.raises(ContractError) as info:
        Prefixes.from_json(value, variables={ALL3: 3})
    assert info.value.rule == "split.out_of_range"


def test_weights_cost_lookup() -> None:
    node = "a" * 64
    weights = Weights.from_json(
        {"format": "cubeproof-weights-1", "campaign": "0" * 64, "costs": {node: 5}},
        planned=[node, "b" * 64],
    )
    assert weights.cost(node) == 5
    assert weights.cost("b" * 64) == 1
