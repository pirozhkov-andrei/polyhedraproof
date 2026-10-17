"""The helper documents ``cubeproof-look-request-1`` and ``cubeproof-look-result-1`` (specification
§9.3)."""

from __future__ import annotations

import copy
import json
from typing import Any

import pytest
from cp_split_support import make_formula

from cubeproof.base.canonical_json import document_bytes, encode, parse_document
from cubeproof.base.errors import ToolError
from cubeproof.contracts.identity import node_id
from cubeproof.split.choice import Budget
from cubeproof.split.lookahead import lookahead
from cubeproof.split.protocol import (
    INFO_KEYS,
    REQUEST_FORMAT,
    RESULT_FORMAT,
    STOPS,
    parse_result,
    request_document,
    result_document,
)

FORMULA = make_formula(6, [[-1, 2], [-2, 3], [-2, 4], [4, 5, 6]])
CUBE = (-5,)
K = 3
LIMIT = 500


def good() -> tuple[bytes, dict[str, Any], str]:
    choice = lookahead(FORMULA, CUBE, K, None, Budget(LIMIT))
    node = node_id(FORMULA.sha256, CUBE)
    document = result_document(node, choice)
    return document, parse_document(document), node


def check(data: bytes, node: str, **overrides: Any) -> Any:
    arguments: dict[str, Any] = {
        "node": node,
        "variables": FORMULA.variables,
        "cube": CUBE,
        "k": K,
        "pool": None,
        "probe_limit": LIMIT,
        "wall_ms": None,
    }
    arguments.update(overrides)
    return parse_result(data, **arguments)


def test_the_request_is_a_canonical_document_with_exactly_the_specified_fields() -> None:
    data = request_document(
        formula_path="/data/f/formula.cnf",
        formula_sha256=FORMULA.sha256,
        variables=6,
        cube=(-5,),
        k=3,
        pool=[1, 2, 4],
        probe_limit=100,
        wall_ms=None,
    )
    assert data.endswith(b"\n") and not data.endswith(b"\n\n")
    value = parse_document(data)  # canonical: J(x) + one LF
    assert value == {
        "format": REQUEST_FORMAT,
        "formula_path": "/data/f/formula.cnf",
        "formula_sha256": FORMULA.sha256,
        "cube": [-5],
        "k": 3,
        "pool": [1, 2, 4],
        "probe_limit": 100,
        "wall_ms": None,
    }


def test_the_request_pool_and_wall_budget_may_be_null_or_set() -> None:
    base: dict[str, Any] = {
        "formula_path": "/f",
        "formula_sha256": FORMULA.sha256,
        "variables": 6,
        "cube": (),
        "k": 1,
        "pool": None,
        "probe_limit": 1,
        "wall_ms": 7,
    }
    value = parse_document(request_document(**base))
    assert value["pool"] is None and value["wall_ms"] == 7


@pytest.mark.parametrize(
    "change",
    [
        {"formula_path": "relative/formula.cnf"},
        {"formula_path": "/a\0b"},
        {"formula_sha256": "xy"},
        {"k": 0},
        {"k": 21},
        {"probe_limit": 0},
        {"probe_limit": None},
        {"wall_ms": 0},
        {"pool": [3, 2]},
        {"pool": [7]},
        {"cube": (2, 1)},
        {"cube": (7,)},
    ],
)
def test_the_request_is_validated_before_it_is_written(change: dict[str, Any]) -> None:
    base: dict[str, Any] = {
        "formula_path": "/f",
        "formula_sha256": FORMULA.sha256,
        "variables": 6,
        "cube": (),
        "k": 1,
        "pool": None,
        "probe_limit": 1,
        "wall_ms": None,
    }
    base.update(change)
    with pytest.raises(Exception) as error:
        request_document(**base)
    assert not isinstance(error.value, AssertionError)


def test_a_non_ascii_path_round_trips_as_utf8_j() -> None:
    data = request_document(
        formula_path="/data/été/formula.cnf",
        formula_sha256=FORMULA.sha256,
        variables=6,
        cube=(),
        k=1,
        pool=None,
        probe_limit=1,
        wall_ms=None,
    )
    assert "/data/été/formula.cnf".encode() in data
    assert parse_document(data)["formula_path"] == "/data/été/formula.cnf"


def test_a_valid_result_is_accepted_and_equals_the_reference_choice() -> None:
    data, value, node = good()
    assert value["format"] == RESULT_FORMAT and value["node_id"] == node
    assert set(value["info"]) == INFO_KEYS
    accepted = check(data, node)
    assert accepted == lookahead(FORMULA, CUBE, K, None, Budget(LIMIT))
    assert result_document(node, accepted) == data  # canonical: re-encoding is the same bytes


def test_every_status_with_its_own_stop_is_accepted() -> None:
    node = node_id(FORMULA.sha256, CUBE)
    for limit, k in ((LIMIT, K), (3, K), (1, K), (LIMIT, 1)):
        choice = lookahead(FORMULA, CUBE, k, None, Budget(limit))
        data = result_document(node, choice)
        assert check(data, node, k=k, probe_limit=limit) == choice
    empty = lookahead(FORMULA, CUBE, 2, [], Budget(LIMIT))
    assert empty.status == "no_eligible"
    assert check(result_document(node, empty), node, k=2, pool=[]) == empty
    conflicting = make_formula(2, [[1], [-1]])
    failed = lookahead(conflicting, (), 1, None, Budget(5))
    failed_node = node_id(conflicting.sha256, ())
    assert failed.status == "failed"
    assert (
        check(
            result_document(failed_node, failed),
            failed_node,
            variables=2,
            cube=(),
            k=1,
            probe_limit=5,
        )
        == failed
    )


def mutate(change: Any) -> bytes:
    _, value, _node = good()
    changed = copy.deepcopy(value)
    change(changed)
    return document_bytes(changed)


@pytest.mark.parametrize(
    "change",
    [
        lambda v: v.pop("info"),
        lambda v: v.update(extra=1),
        lambda v: v.update(format="cubeproof-look-result-2"),
        lambda v: v.update(status="done"),
        lambda v: v.update(status="no_eligible"),
        lambda v: v.update(variables=[1, 1]),
        lambda v: v.update(variables=[0]),
        lambda v: v.update(variables=[7]),
        lambda v: v.update(variables=[5]),  # assigned by the cube
        lambda v: v.update(variables=[5, 1, 2]),  # k variables, one of them in the cube
        lambda v: v.update(variables=["1"]),
        lambda v: v.update(variables=[1, 2, 3, 4]),  # more than k
        lambda v: v["info"].pop("probes"),
        lambda v: v["info"].update(extra=1),
        lambda v: v["info"].update(algorithm="lookahead-v2"),
        lambda v: v["info"].update(probes=LIMIT + 1),
        lambda v: v["info"].update(probes=-1),
        lambda v: v["info"].update(probes=True),
        lambda v: v["info"].update(candidates=7),
        lambda v: v["info"].update(parent_assigned=7),
        lambda v: v["info"].update(rounds=1),
        lambda v: v["info"].update(scores=[1]),
        lambda v: v["info"].update(scores=["a", "b", "c"]),
        lambda v: v["info"].update(scores=[-1, 0, 0]),
        lambda v: v["info"].update(stop="wall_ms"),  # no wall budget was given
        lambda v: v["info"].update(stop="parent_conflict"),
        lambda v: v["info"].update(stop="zzz"),
        lambda v: v["info"].update(stop="candidates"),  # status chosen with k variables: stop k
    ],
)
def test_an_invalid_result_is_refused(change: Any) -> None:
    node = node_id(FORMULA.sha256, CUBE)
    data = mutate(change)
    with pytest.raises(ToolError) as error:
        check(data, node)
    assert error.value.rule == "split.helper_protocol"


def test_the_node_identity_must_be_the_callers() -> None:
    data, _, node = good()
    other = node_id(FORMULA.sha256, (-4,))
    assert other != node
    with pytest.raises(ToolError, match="node identity"):
        check(data, other)


def test_variables_must_lie_in_the_pool() -> None:
    data, value, node = good()
    outside = [v for v in range(1, 7) if v not in value["variables"] and v != 5]
    pool = [outside[0]]
    with pytest.raises(ToolError, match="pool"):
        check(data, node, pool=pool)


def test_non_canonical_or_non_document_output_is_refused() -> None:
    data, value, node = good()
    spaced = json.dumps(value, sort_keys=True, indent=1).encode() + b"\n"
    for bad in (
        data.rstrip(b"\n"),  # no LF
        data + b"\n",  # two LFs
        spaced,
        b"",
        b"not json\n",
        b"\xef\xbb\xbf" + data,
        data.replace(b'"probes":', b'"probes":0.0,"x":'),
        b"[]\n",
        encode({"a": 1}) + b"\n",
        data + data,  # two documents
    ):
        with pytest.raises(ToolError):
            check(bad, node)


def test_stops_and_statuses_are_the_documented_vocabulary() -> None:
    assert {"k", "candidates", "probe_limit", "wall_ms", "parent_conflict"} == STOPS


def test_the_result_encoder_validates_the_node() -> None:
    choice = lookahead(FORMULA, CUBE, K, None, Budget(LIMIT))
    with pytest.raises(ValueError):
        result_document("not-a-hash", choice)
