"""neighbourly.interpret, model side: the golden model description and model interpretation.

Specification §13.2. The golden (``golden_model_map1.json``) is the
``describe_model`` of map 1 (S,H,A,B,I, gauge face 1) on the pinned assignment
``SHA256("k12-s00-model-1:v")[0] & 1``. Its digest is pinned here; the full document is
compared in the checkout. On other maps, gauges and assignments the SHA-256 of the
documents is pinned.
"""

from __future__ import annotations

import hashlib
import json
from fractions import Fraction
from functools import cache
from pathlib import Path
from typing import Any

import pytest

from neighbourly import corpus12
from neighbourly.data import read_bytes
from neighbourly.encoding import Encoder
from neighbourly.exact import oracle_from_planes
from neighbourly.interpret import (
    InterpretError,
    VerifiedFormula,
    describe_model,
    formula_bundle,
    interpret_model,
    verify_bundle,
)
from neighbourly.maps import CombinatorialMap

GOLDEN_MODEL = Path(__file__).resolve().parent / "golden_model_map1.json"
#: ``description_sha256`` = J(describe_model(map 1, S,H,A,B,I, gauge 1, pinned values)).
MODEL_DESCRIPTION_SHA256 = "4689bfd8bba3d87b8a36f8b38b7b5d900f8f4f2f8d0670534afd2f1e7dc41dfc"
#: ``assignment_sha256`` and ``assignment_ones`` of the pinned assignment.
ASSIGNMENT_SHA256 = "998d7508d8c65b232305b9a5d64de8a09d1c3656af6b619883a460825c7f1ef6"
ASSIGNMENT_ONES = 2626
#: An opaque constant: the assignment derived from it and the digests of the golden model pin it.
MODEL_SEED = "k12-s00-model-1"
#: SHA-256 of J(describe_model) on (map, gauge face, seed of the assignment).
DESCRIPTIONS_GOLDEN = {
    (2, 3, "a"): "1cdf953f70f59e8557bec4c0ccd38791d3b1a9d53747fd59ed907a75564faff6",
    (59, 1, "b"): "64cde15697a082cbb5c6a99e9377213cb7f9b761b3c0c139f015e0929ce310b7",
}


def J(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def model_value(variable: int) -> int:
    return hashlib.sha256(f"{MODEL_SEED}:{variable}".encode("ascii")).digest()[0] & 1


@cache
def map1() -> VerifiedFormula:
    produced = formula_bundle(corpus12.load_map(1), map_name="topology_01")
    return verify_bundle(produced.files.manifest, corpus12.load_map(1))


def pinned(variables: int) -> dict[int, int]:
    return {v: model_value(v) for v in range(1, variables + 1)}


def test_the_pinned_assignment_is_the_golden_assignment() -> None:
    values = pinned(map1().variables)
    assert sum(values.values()) == ASSIGNMENT_ONES
    # J of the values in variable order
    assert sha(J([values[v] for v in range(1, map1().variables + 1)])) == ASSIGNMENT_SHA256


def test_the_golden_model_description() -> None:
    description = describe_model(map1().variable_map, pinned(map1().variables))
    assert sha(J(description)) == MODEL_DESCRIPTION_SHA256
    assert list(description) == ["chirotope", "line_orders", "face_orientation_s"]
    assert len(description["chirotope"]) == 715
    assert len(description["line_orders"]) == 66 + 12
    assert description["line_orders"]["L0,1 cut at 2"] == [3, 5, 12, 6, 7, 4, 9, 8, 11, 10]


def test_transitive_order_bits_give_their_order() -> None:
    """When the bits of a line are a total order, the description is that order."""
    variable_map = map1().variable_map
    values = pinned(map1().variables)
    expected: dict[str, list[int]] = {}
    rows = [(f"L{i},{j}", row, (i, j)) for (i, j), row in variable_map.line_orders.items()]
    rows += [(f"L0,{b} cut at {c}", row, (b, c)) for (b, c), row in variable_map.cut_orders.items()]
    for number, (name, row, skip) in enumerate(rows):
        others = [x for x in variable_map.faces if x not in skip]
        order = sorted(others, key=lambda x: hashlib.sha256(f"{number}:{x}".encode()).digest())
        for (a, b), variable in row.items():
            values[variable] = int(order.index(a) < order.index(b))
        expected[name] = order
    assert describe_model(variable_map, values)["line_orders"] == expected


def test_the_golden_document_is_matched_in_full() -> None:
    golden = json.loads(GOLDEN_MODEL.read_text(encoding="utf-8"))
    assert golden["format"] == "neighbourly-golden-model-1"
    assert MODEL_SEED in golden["assignment"]
    assert golden["assignment_sha256"] == ASSIGNMENT_SHA256
    assert golden["description_sha256"] == MODEL_DESCRIPTION_SHA256
    assert (golden["map"], golden["layers"], golden["gauge_face"]) == (1, "S,H,A,B,I", 1)
    assert golden["formula_sha256"] == map1().formula_sha256
    assert golden["assignment_ones"] == ASSIGNMENT_ONES
    assert describe_model(map1().variable_map, pinned(map1().variables)) == golden["description"]


def test_the_description_is_the_frozen_description_on_other_maps_and_assignments() -> None:
    """The description document, by its frozen digest."""
    for (map_id, gauge, seed), expected in DESCRIPTIONS_GOLDEN.items():
        cmap = corpus12.load_map(map_id)
        verified = verify_bundle(formula_bundle(cmap, "S,H,A,B,I", gauge).files.manifest, cmap)
        values = {
            v: hashlib.sha256(f"{seed}:{v}".encode()).digest()[0] & 1
            for v in range(1, verified.variables + 1)
        }
        assert sha(J(describe_model(verified.variable_map, values))) == expected


@pytest.mark.parametrize(
    "change",
    [
        lambda values: values.pop(1),
        lambda values: values.update({0: 1}),
        lambda values: values.update({10**6: 0}),
        lambda values: values.update({1: 2}),
        lambda values: values.update({1: True}),
    ],
)
def test_an_incomplete_or_non_boolean_assignment_is_refused(change: Any) -> None:
    values = pinned(map1().variables)
    change(values)
    with pytest.raises(InterpretError):
        describe_model(map1().variable_map, values)
    with pytest.raises(InterpretError):
        interpret_model(map1(), values)


def test_the_pinned_assignment_violates_the_formula_and_says_so() -> None:
    result = interpret_model(map1(), pinned(map1().variables))
    assert not result.satisfies
    assert set(result.violated) <= {"S", "H", "A", "B", "I", "gauge"}
    assert sum(result.violated.values()) > 0
    summary = result.summary()
    assert summary["satisfies_formula"] is False
    assert "not a geometric realization" in summary["note"]
    assert sha(J(summary["description"])) == MODEL_DESCRIPTION_SHA256


def realized(name: str) -> tuple[CombinatorialMap, list[list[Fraction]]]:
    files = {
        "tetrahedron": ("tetrahedron", "tetrahedron.txt", "planes.json"),
        "szilassi": ("szilassi", "csaszar_n7.txt", "szilassi.json"),
    }
    folder, matrix, planes = files[name]
    cmap = CombinatorialMap.from_text(read_bytes("fixtures", folder, matrix).decode("utf-8"))
    rows = json.loads(read_bytes("fixtures", folder, planes))["planes"]
    return cmap, [[Fraction(x) for x in row] for row in rows]


def test_a_realization_is_interpreted_as_a_satisfying_model_with_its_reflex_corners() -> None:
    """Szilassi's planes (n = 7, not moved into gauge): every clause holds, reflex as measured."""
    cmap, planes = realized("szilassi")
    document = json.loads(read_bytes("fixtures", "szilassi", "szilassi.json"))
    orientation = {int(k): v for k, v in document["verification"]["orientation"].items()}
    oracle = oracle_from_planes(planes).with_orientations(orientation)
    truth = Encoder(cmap, oracle=oracle).build("S,H,A,B,I", None)
    verified = verify_bundle(formula_bundle(cmap, "S,H,A,B,I", None).files.manifest, cmap)
    result = interpret_model(verified, dict(truth.formula.values))
    assert result.satisfies and dict(result.violated) == {}
    reflex = {int(k): v for k, v in document["verification"]["reflex"].items()}
    assert dict(result.reflex_corners) == reflex
    assert result.description["face_orientation_s"] == {str(f): orientation[f] for f in cmap.faces}


def test_flipping_one_orientation_bit_of_a_realization_violates_layer_i() -> None:
    cmap, planes = realized("szilassi")
    document = json.loads(read_bytes("fixtures", "szilassi", "szilassi.json"))
    orientation = {int(k): v for k, v in document["verification"]["orientation"].items()}
    truth = Encoder(cmap, oracle=oracle_from_planes(planes).with_orientations(orientation))
    truth.build("S,H,A,B,I", None)
    verified = verify_bundle(formula_bundle(cmap, "S,H,A,B,I", None).files.manifest, cmap)
    values = dict(truth.formula.values)
    values[verified.variable_map.orientation_bits[1]] ^= 1
    result = interpret_model(verified, values)
    assert set(result.violated) == {"I"}
