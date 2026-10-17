"""neighbourly.encoding: layer selection, the encoder's domain and its own identities.

Layer selection, the encoder's domain and the structural identity checks (gauge, corner
symmetry, cyclic adjacency, Layer I shape, order bits against exact affine orders). The
n-scope tests follow specification §13.2: the encoder entry accepts integer n >= 4 with n mod
12 in {0, 3, 4, 7} and orientable maps only.
"""

from __future__ import annotations

import itertools
import json
import random
from fractions import Fraction
from typing import Any

import pytest

from neighbourly import corpus12
from neighbourly.cnf import CnfError
from neighbourly.data import read_bytes
from neighbourly.encoding import (
    DEFAULT_LAYERS,
    ENCODABLE_RESIDUES,
    POOLS,
    Encoder,
    EncodingError,
    build_encoder,
    check_encodable,
    gauge_targets,
    normalize_layers,
)
from neighbourly.encoding.common import permutation_parity
from neighbourly.encoding.formula import clause_tags, describe_sizes
from neighbourly.encoding.layers import LAYER_DESCRIPTIONS, LAYERS
from neighbourly.exact import homogeneous_planes, oracle_from_planes
from neighbourly.geometry import line_coordinate
from neighbourly.maps import CombinatorialMap

TETRAHEDRON = CombinatorialMap(4, itertools.combinations(range(1, 5), 3))
PROJECTIVE_PLANE = CombinatorialMap(
    6,
    [
        (1, 2, 3),
        (1, 3, 4),
        (1, 4, 5),
        (1, 5, 6),
        (1, 2, 6),
        (2, 3, 5),
        (3, 4, 6),
        (2, 4, 5),
        (3, 5, 6),
        (2, 4, 6),
    ],
)


def csaszar() -> CombinatorialMap:
    text = read_bytes("fixtures", "szilassi", "csaszar_n7.txt").decode("utf-8")
    return CombinatorialMap.from_text(text)


# -- layer selection ----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("given", "expected"),
    [
        ("SHABI", DEFAULT_LAYERS),
        ("s,h,a,b,i", DEFAULT_LAYERS),
        ("i, a", DEFAULT_LAYERS),  # I needs S, H and B; A is asked for
        ("I", "S,H,B,I"),
        ("B", "S,H,B"),
        ("H", "S,H"),
        ("  A ", "S,A"),
        ("S", "S"),
    ],
)
def test_layer_selection_is_canonical_and_closed(given: str, expected: str) -> None:
    assert normalize_layers(given) == expected


@pytest.mark.parametrize("given", ["", "E", "X,Y", "shabix", " , ", 5, None])
def test_unknown_or_empty_selections_are_refused(given: Any) -> None:
    with pytest.raises(EncodingError):
        normalize_layers(given)


def test_every_layer_is_described_in_emission_order() -> None:
    assert LAYERS == "SHABI"
    assert "".join(LAYER_DESCRIPTIONS) == LAYERS
    assert not any("12" in text or "twelve" in text for text in LAYER_DESCRIPTIONS.values())


def test_encoding_errors_are_cnf_errors_and_value_errors() -> None:
    assert issubclass(EncodingError, CnfError)
    assert issubclass(EncodingError, ValueError)


# -- the domain (specification §13.2) -----------------------------------------------------------


def test_the_residues_are_those_of_orientable_neighbourly_maps() -> None:
    """chi = n(7-n)/6 must be an even integer: exactly n mod 12 in {0, 3, 4, 7}."""
    derived = {r for r in range(12) if all((n * (7 - n)) % 12 == 0 for n in range(r + 12, 400, 12))}
    assert derived == set(ENCODABLE_RESIDUES) == {0, 3, 4, 7}


@pytest.mark.parametrize(
    ("cmap", "n"),
    [(TETRAHEDRON, 4), (None, 7), (None, 12)],
)
def test_the_encoder_accepts_n_4_7_and_12(cmap: CombinatorialMap | None, n: int) -> None:
    if cmap is None:
        cmap = csaszar() if n == 7 else corpus12.load_map(1)
    assert check_encodable(cmap) is cmap
    encoder = build_encoder(cmap)
    assert encoder.n == n
    assert encoder.selection == "S,H,A,B,I+gauge@1"


def test_a_non_orientable_map_with_a_bad_residue_is_refused_before_anything_is_emitted() -> None:
    assert PROJECTIVE_PLANE.n % 12 == 6 and not PROJECTIVE_PLANE.is_orientable()
    with pytest.raises(EncodingError, match="n mod 12"):
        Encoder(PROJECTIVE_PLANE)
    with pytest.raises(EncodingError, match="n mod 12"):
        check_encodable(PROJECTIVE_PLANE)


def test_a_non_orientable_map_with_a_good_residue_is_refused(monkeypatch: Any) -> None:
    """No small non-orientable map with n mod 12 in {0,3,4,7} is at hand; the query is
    replaced, so this tests that the entry asks it."""
    cmap = CombinatorialMap(4, itertools.combinations(range(1, 5), 3))
    monkeypatch.setattr(CombinatorialMap, "is_orientable", lambda self: False)
    with pytest.raises(EncodingError, match="not orientable"):
        Encoder(cmap)


@pytest.mark.parametrize("value", [None, "map", 12, TETRAHEDRON.triples])
def test_only_a_combinatorial_map_is_encoded(value: Any) -> None:
    with pytest.raises(EncodingError, match="CombinatorialMap"):
        Encoder(value)


# -- the encoder's interface --------------------------------------------------------------------


def test_an_encoder_builds_once() -> None:
    encoder = Encoder(TETRAHEDRON)
    encoder.build()
    with pytest.raises(EncodingError):
        encoder.build()


@pytest.mark.parametrize("face", [0, 5, -1, True, "1", 1.0])
def test_the_gauge_face_must_name_a_face(face: Any) -> None:
    with pytest.raises(EncodingError):
        Encoder(TETRAHEDRON).build(gauge_face=face)
    with pytest.raises(EncodingError):
        Encoder(TETRAHEDRON).gauge_targets(face)


def test_brackets_and_orders_are_signed_consistently() -> None:
    encoder = Encoder(TETRAHEDRON).build("S,H,A,B,I", gauge_face=None)
    for ordered in itertools.permutations(range(5), 4):
        literal = encoder.bracket_literal(*ordered)
        assert abs(literal) == encoder.brackets[tuple(sorted(ordered))]
        # Swapping two elements flips the sign.
        swapped = (ordered[1], ordered[0], *ordered[2:])
        assert encoder.bracket_literal(*swapped) == -literal
    for i, j, k, l in itertools.permutations(range(1, 5), 4):
        assert encoder.order_literal(i, j, k, l) == -encoder.order_literal(i, j, l, k)
        assert encoder.order_literal(i, j, k, l) == -encoder.order_literal(j, i, k, l)
    with pytest.raises(EncodingError):
        encoder.bracket_literal(0, 1, 1, 2)
    with pytest.raises(EncodingError):
        encoder.bracket_literal(0, 1, 2)
    with pytest.raises(EncodingError):
        encoder.order_literal(1, 2, 2, 3)
    with pytest.raises(EncodingError):
        encoder.between_pair(1, 2, 3, 3, 4)


def test_permutation_parity() -> None:
    assert permutation_parity([0, 1, 2, 3]) == 0
    assert permutation_parity([1, 0, 2, 3]) == 1
    assert permutation_parity([3, 2, 1, 0]) == 0
    assert permutation_parity([2, 0, 1]) == 0


def test_corner_literals_are_symmetric_in_their_two_neighbours() -> None:
    encoder = Encoder(corpus12.load_map(1)).build()
    for face in encoder.map.faces:
        cycle = encoder.map.link_cycle(face)
        for a, b in zip(cycle, cycle[1:] + cycle[:1]):
            assert encoder.corner_literal(face, a, b) == encoder.corner_literal(face, b, a)
    with pytest.raises(EncodingError):
        encoder.corner_literal(1, 2, 2)


def test_public_views_are_read_only() -> None:
    encoder = Encoder(TETRAHEDRON).build()
    views: list[Any] = [
        encoder.brackets,
        encoder.line_orders,
        encoder.cut_orders,
        encoder.boundary_bits,
        encoder.corner_bits,
        encoder.face_orientation_bits,
    ]
    for view in views:
        with pytest.raises(TypeError):
            view[next(iter(view), (1,))] = 1


def test_pools_are_disjoint_and_named() -> None:
    encoder = Encoder(TETRAHEDRON).build()
    assert POOLS == ("order", "brackets")
    assert not encoder.pool("order") & encoder.pool("brackets")
    assert encoder.pool("brackets") == set(range(1, 6))  # C(5,4) brackets come first
    with pytest.raises(EncodingError):
        encoder.pool("nonsense")


def test_sizes_and_tags_are_reported_per_layer() -> None:
    encoder = build_encoder(TETRAHEDRON)
    rows = describe_sizes(encoder)
    assert [name for name, *_ in rows] == ["brackets", "S", "H", "A", "B", "I", "gauge"]
    assert sum(clauses for _, clauses, _, _ in rows) == len(encoder.clauses)
    assert sum(variables for _, _, variables, _ in rows) == encoder.variables
    assert len(clause_tags(encoder, "gauge:")) == 5


# -- identities (structural part) ------------------------------------------------------------------


def test_the_gauge_is_one_representative_of_each_reorientation_orbit() -> None:
    """(paper: lem:gaugegroup, cor:gauge), exhaustively over all 2^(n+1) group elements."""
    for n, face in ((12, 1), (12, 7), (7, 3), (4, None)):
        targets = gauge_targets(n, face)
        assert len(targets) == n + 1
        if face is not None:
            assert sum(face in subset for subset in targets) == n
        patterns = set()
        for element in range(1 << (n + 1)):  # bit 0 mirrors, bit i reorients plane i
            pattern = 0
            for position, subset in enumerate(targets):
                flip = element & 1
                for plane in subset:
                    if plane >= 1:
                        flip ^= (element >> plane) & 1
                pattern |= flip << position
            patterns.add(pattern)
        assert len(patterns) == 1 << (n + 1)


def test_the_gauge_of_the_encoder_is_the_pure_function() -> None:
    encoder = Encoder(corpus12.load_map(1))
    for face in (None, *range(1, 13)):
        assert encoder.gauge_targets(face) == gauge_targets(12, face)


def test_layer_b_constrains_exactly_the_non_adjacent_pairs() -> None:
    """(paper: lem:adjacency): consecutive edges of a face meet at real vertices."""
    cmap = corpus12.load_map(1)
    encoder = build_encoder(cmap)
    constrained = set(clause_tags(encoder, "B:"))
    expected = set()
    for face in cmap.faces:
        successor = cmap.link_successor(face)
        for a, b in itertools.combinations([x for x in cmap.faces if x != face], 2):
            adjacent = successor.get(a) == b or successor.get(b) == a
            assert adjacent == cmap.is_real(face, a, b)
            if not adjacent:
                expected.add(f"B:{face}|{a},{b}")
    assert constrained == expected


@pytest.mark.parametrize("which", ["tetrahedron", "csaszar", "map1"])
def test_layer_i_has_three_clauses_per_vertex_and_one_bit_per_corner(which: str) -> None:
    cmap = {"tetrahedron": TETRAHEDRON, "csaszar": csaszar(), "map1": corpus12.load_map(1)}[which]
    encoder = build_encoder(cmap)
    vertex_tags = clause_tags(encoder, "I:")
    corner_tags = set(clause_tags(encoder, "turn:"))
    assert len(vertex_tags) == 3 * len(cmap.triples)
    assert len(set(vertex_tags)) == len(cmap.triples)
    assert len(corner_tags) == cmap.n * (cmap.n - 1) == len(encoder.corner_bits)
    assert len(encoder.face_orientation_bits) == cmap.n
    assert len(set(clause_tags(encoder, "orientation:"))) >= cmap.n


def test_order_bits_are_the_affine_order_on_every_real_line() -> None:
    """(paper: thm:order) against orders solved for exactly, not against the same XOR."""
    generator = random.Random(20260903)
    cmap = corpus12.load_map(2)
    while True:
        planes = [[Fraction(generator.randint(-9, 9)) for _ in range(4)] for _ in range(12)]
        oracle = oracle_from_planes(planes)
        if oracle.in_general_position:
            break
    rows = homogeneous_planes(planes)
    encoder = Encoder(cmap, oracle=oracle).build("S", gauge_face=None)
    checked = 0
    for (i, j), row in encoder.line_orders.items():
        for k, l in row:
            geometric = int(line_coordinate(rows, i, j, k) < line_coordinate(rows, i, j, l))
            assert encoder.formula.literal_value(encoder.order_literal(i, j, k, l)) == geometric
            checked += 1
    assert checked == 66 * 45


def test_ground_truth_mode_sees_the_bracket_values() -> None:
    planes = json.loads(read_bytes("fixtures", "tetrahedron", "planes.json"))["planes"]
    oracle = oracle_from_planes([[Fraction(x) for x in plane] for plane in planes])
    encoder = Encoder(TETRAHEDRON, oracle=oracle)
    for subset, variable in encoder.brackets.items():
        assert encoder.formula.values[variable] == oracle(subset)
