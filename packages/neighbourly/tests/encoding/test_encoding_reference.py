"""neighbourly.encoding against a second, separately written encoder.

The reference (``nb_reference_encoder``) is compared with :mod:`neighbourly.encoding`
directly. It has its own map reader, its own link walks, its own truth-table CNF and its own
gauge rank decision, but the production encoder's numbering and chaining conventions, so
that clauses can be compared literally.  It checks the encoder against a second
implementation, not against the article, and cannot catch an error in a shared convention.

Comparing the two clause multisets is the strongest check on the encoder that does not
involve a solver -- and ``test_the_comparison_detects_missing_and_changed_constraints``
shows that the comparison would notice if a constraint went missing or changed sign.  The
last test evaluates the reference on the realized fixtures with its own exact geometry.
"""

from __future__ import annotations

import json
from collections import Counter
from fractions import Fraction
from itertools import combinations, permutations

import pytest
from nb_reference_encoder import (
    MapSpec,
    ReferenceEncoder,
    clause_bag,
    geometry_witness,
    literal_value,
)

from neighbourly import corpus12
from neighbourly.data import read_bytes
from neighbourly.encoding import DEFAULT_LAYERS, Encoder
from neighbourly.exact import oracle_from_planes
from neighbourly.maps import CombinatorialMap

LAYERS = ("S", "H", "A", "B", "I", "gauge")
FIXTURES = {
    "tetrahedron": ("tetrahedron", "tetrahedron.txt", "planes.json"),
    "szilassi": ("szilassi", "csaszar_n7.txt", "szilassi.json"),
}


def fixture_text(name: str) -> str:
    folder, matrix, _ = FIXTURES[name]
    return read_bytes("fixtures", folder, matrix).decode("utf-8")


def fixture_planes(name: str) -> list[list[Fraction]]:
    folder, _, planes = FIXTURES[name]
    rows = json.loads(read_bytes("fixtures", folder, planes))["planes"]
    return [[Fraction(x) for x in row] for row in rows]


def compare(spec: MapSpec, production: CombinatorialMap) -> tuple[ReferenceEncoder, Encoder]:
    reference = ReferenceEncoder(spec).build()
    actual = Encoder(production).build("SHABI", gauge_face=1)
    assert actual.variables == reference.cnf.nvars
    assert dict(actual.brackets) == reference.brackets
    assert dict(actual.face_orientation_bits) == reference.orientation
    assert actual.gauge_targets(1) == reference.gauge
    assert len(actual.clauses) == len(actual.formula.tags)
    assert clause_bag(actual.clauses) == clause_bag(reference.cnf.clauses)
    for layer in LAYERS:
        expected = [
            clause
            for clause, name in zip(reference.cnf.clauses, reference.cnf.layers, strict=True)
            if name == layer
        ]
        produced = [
            clause
            for clause, (name, _) in zip(actual.clauses, actual.formula.tags, strict=True)
            if name == layer
        ]
        assert clause_bag(produced) == clause_bag(expected), layer
    n = spec.n
    assert len(reference.corners) == n * (n - 1)
    assert len(reference.on_boundary) == n * (n - 1) * (n - 4) // 2
    assert len(reference.orientation) == n
    assert len(reference.rays) == n
    for face, (g, z0, z1, terms) in reference.rays.items():
        assert g == spec.cycles[face][0]
        assert (z0, z1) == spec.end_pair(face, g)
        assert len(terms) == n - 4
    vertex_clauses = [
        (clause, tag)
        for clause, (layer, tag) in zip(actual.clauses, actual.formula.tags, strict=True)
        if layer == "I" and tag.startswith("I:")
    ]
    assert len(vertex_clauses) == 3 * len(spec.triples)
    assert Counter(tag for _, tag in vertex_clauses) == Counter(
        {"I:" + ",".join(map(str, triple)): 3 for triple in spec.triples}
    )
    for face in spec.faces:
        assert tuple(production.link_cycle(face)) == spec.cycles[face]
        for a, b in zip(spec.cycles[face], spec.cycles[face][1:] + spec.cycles[face][:1]):
            assert actual.corner_literal(face, a, b) == reference.corner(face, a, b)
            assert actual.corner_literal(face, b, a) == reference.corner(face, a, b)
    return reference, actual


def test_small_maps_agree_clause_for_clause() -> None:
    compare(
        MapSpec(4, combinations(range(1, 5), 3)),
        CombinatorialMap(4, combinations(range(1, 5), 3)),
    )
    text = fixture_text("szilassi")
    compare(MapSpec.from_text(text), CombinatorialMap.from_text(text, "csaszar_n7.txt"))


@pytest.mark.slow
def test_all_shipped_maps_agree_clause_for_clause() -> None:
    compared = 0
    for map_id in corpus12.map_ids():
        text = corpus12.matrix_bytes(map_id).decode("utf-8")
        spec = MapSpec.from_text(text)
        assert spec.n == 12
        assert len(spec.triples) == 44
        compare(spec, CombinatorialMap.from_text(text, corpus12.matrix_name(map_id)))
        compared += 1
    assert compared == 59


def test_signed_brackets_and_orders_agree() -> None:
    spec = MapSpec(4, combinations(range(1, 5), 3))
    reference = ReferenceEncoder(spec).build(gauge_face=None)
    actual = Encoder(CombinatorialMap(4, spec.triples)).build("SHABI", gauge_face=None)
    for ordered in permutations(range(5), 4):
        assert actual.bracket_literal(*ordered) == reference.bracket(*ordered)
    for i, j, k, l in permutations(range(1, 5), 4):
        assert actual.order_literal(i, j, k, l) == reference.order(i, j, k, l)


def test_every_gauge_basis_spans_all_sign_patterns() -> None:
    spec = MapSpec.from_text(corpus12.matrix_bytes(1).decode("utf-8"))
    actual = Encoder(CombinatorialMap(12, spec.triples))
    for face in spec.faces:
        reference = ReferenceEncoder(spec)
        reference.add_gauge(face)
        assert actual.gauge_targets(face) == reference.gauge
        assert len(reference.gauge) == 13
        patterns = {
            tuple(
                (mask & 1) ^ (sum((mask >> i) & 1 for i in subset if i) % 2)
                for subset in reference.gauge
            )
            for mask in range(1 << 13)
        }
        assert len(patterns) == 1 << 13


def test_the_comparison_detects_missing_and_changed_constraints() -> None:
    """All three mutations leave a syntactically valid DIMACS file behind."""
    spec = MapSpec.from_text(fixture_text("szilassi"))
    expected = clause_bag(ReferenceEncoder(spec).build().cnf.clauses)
    actual = Encoder(CombinatorialMap(7, spec.triples)).build("SHABI", gauge_face=1)
    assert clause_bag(actual.clauses) == expected
    for prefix in ("orientation:", "turn:", "I:"):
        index = next(i for i, (_, tag) in enumerate(actual.formula.tags) if tag.startswith(prefix))
        dropped = list(actual.clauses)
        dropped.pop(index)
        assert clause_bag(dropped) != expected
        flipped = list(actual.clauses)
        flipped[index] = (-flipped[index][0], *flipped[index][1:])
        assert clause_bag(flipped) != expected
    without_orientation = [
        clause
        for clause, (_, tag) in zip(actual.clauses, actual.formula.tags, strict=True)
        if not tag.startswith("orientation:")
    ]
    assert clause_bag(without_orientation) != expected


@pytest.mark.parametrize("name", ["tetrahedron", "szilassi"])
def test_the_reference_witness_of_a_realization_is_the_ground_truth(name: str) -> None:
    """The reference, valued by its own exact geometry, satisfies its clauses, and gives
    every variable the value neighbourly's ground-truth mode gives it.

    The two witnesses share no geometry code: the reference uses Leibniz determinants,
    Gaussian elimination and polygon areas; neighbourly uses the bracket signs of
    :func:`neighbourly.exact.oracle_from_planes`.  The orientation bits ``s_f`` given to
    neighbourly are the reference's measured ones, so the comparison covers every other
    variable; for the Szilassi surface they are also compared with the fixture's recorded
    verification (made by ``nb_exact_geometry``, see ``tests/exact``).
    """
    text, planes = fixture_text(name), fixture_planes(name)
    spec = MapSpec.from_text(text)
    reference = ReferenceEncoder(spec).build(gauge_face=None)
    values, reflex = geometry_witness(reference, planes)
    violated = [
        clause
        for clause in reference.cnf.clauses
        if not any(literal_value(lit, values) for lit in clause)
    ]
    assert violated == []
    for (face, pair), bit in reflex.items():
        assert literal_value(reference.corner(face, *pair), values) == bit
    orientation = {face: values[variable] for face, variable in reference.orientation.items()}
    if name == "szilassi":
        recorded = json.loads(read_bytes("fixtures", "szilassi", "szilassi.json"))
        assert {str(face): bit for face, bit in orientation.items()} == recorded["verification"][
            "orientation"
        ]
    oracle = oracle_from_planes(planes).with_orientations(orientation)
    cmap = CombinatorialMap.from_text(text, name)
    actual = Encoder(cmap, oracle=oracle).build(DEFAULT_LAYERS, gauge_face=None)
    assert not actual.formula.violations
    assert dict(actual.formula.values) == values
