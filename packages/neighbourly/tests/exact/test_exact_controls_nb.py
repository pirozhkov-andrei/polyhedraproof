"""The clauses of neighbourly.encoding against explicit rational configurations.

Three different things are checked, and the distinction matters:

    S, H, A     hold for ANY planes in general position, so random rational planes test
                them and zero violations is the requirement.
    the PREDICATES under B and I (`onb` and the turn bit) are pure functions of the planes
                and are testable on random planes even though their CLAUSES are not.
    B and I     hold for REALIZATIONS (paper: lem:B, lem:I), so they are tested against
                configurations that are realized: the tetrahedron (n = 4) and a Szilassi
                surface (n = 7), with an independent exact geometry implementation
                (``nb_exact_geometry``) deciding what the truth is.

These are finite controls: they can expose a wrong clause on these configurations; they do
not prove the layers for every n.
"""

from __future__ import annotations

import json
import random
from collections.abc import Iterator
from fractions import Fraction
from typing import Any

import pytest
from nb_exact_geometry import inspect_embedding

from neighbourly import corpus12
from neighbourly.data import read_bytes
from neighbourly.encoding import DEFAULT_LAYERS, Encoder
from neighbourly.exact import (
    GeometryError,
    PlaneOracle,
    homogeneous_planes,
    oracle_from_planes,
)
from neighbourly.geometry import affine_point, line_coordinate
from neighbourly.maps import CombinatorialMap

N_FACES = 12


def fixture(name: str) -> tuple[CombinatorialMap, list[list[Fraction]]]:
    """A packaged realized configuration: its map and its planes."""
    if name == "tetrahedron":
        text = read_bytes("fixtures", "tetrahedron", "tetrahedron.txt").decode("utf-8")
        planes = json.loads(read_bytes("fixtures", "tetrahedron", "planes.json"))["planes"]
        cmap = CombinatorialMap.from_text(text, "tetrahedron.txt")
    else:
        text = read_bytes("fixtures", "szilassi", "csaszar_n7.txt").decode("utf-8")
        planes = json.loads(read_bytes("fixtures", "szilassi", "szilassi.json"))["planes"]
        cmap = CombinatorialMap.from_text(text, "csaszar_n7.txt")
    return cmap, [[Fraction(x) for x in plane] for plane in planes]


def flat_orientations(oracle: PlaneOracle, cmap: CombinatorialMap) -> PlaneOracle:
    """`s_f = 0` on every face, for controls that read a bit `s_f` cannot change.

    Random planes are not an embedding of the map, so there is no `s_f` to measure
    (paper: lem:sf).  The two controls below read the boundary bits and the turn
    identity, and both are the same whatever `s_f` is fixed to; Layer I's clauses, which
    are not, are not asserted on random planes anywhere.
    """
    return oracle.with_orientations(dict.fromkeys(cmap.faces, 0))


def random_configurations(
    n: int, count: int, seed: int
) -> Iterator[tuple[list[list[Fraction]], PlaneOracle]]:
    """General-position plane families, drawn until there are `count` of them."""
    generator = random.Random(seed)
    produced = 0
    while produced < count:
        planes = [[Fraction(generator.randint(-40, 40)) for _ in range(4)] for _ in range(n)]
        oracle = oracle_from_planes(planes)
        if not oracle.in_general_position:
            continue
        produced += 1
        yield planes, oracle


def test_the_packaged_fixtures_are_realized_by_the_independent_geometry() -> None:
    """The fixtures carry their own verification record; it is recomputed here."""
    _cmap, planes = fixture("szilassi")
    recorded = json.loads(read_bytes("fixtures", "szilassi", "szilassi.json"))["verification"]
    measured = inspect_embedding(planes, _cmap)
    assert {str(k): v for k, v in measured["orientation"].items()} == recorded["orientation"]
    assert {str(k): v for k, v in measured["reflex"].items()} == recorded["reflex"]
    assert measured["triangle_pairs"] == recorded["triangle_pairs"]
    assert measured["vertices"] == recorded["vertices"]
    cmap, planes = fixture("tetrahedron")
    assert inspect_embedding(planes, cmap)["vertices"] == 4


def test_unconditional_layers_hold_on_random_planes() -> None:
    cmap = corpus12.load_map(1)
    for _planes, oracle in random_configurations(N_FACES, 3, seed=20260903):
        # S, H and A build no corner, so no orientation bit s_f is ever asked for.
        encoder = Encoder(cmap, oracle=oracle)
        encoder.build("S,H,A", gauge_face=None)
        assert not encoder.formula.violations
        assert len(encoder.formula.values) == encoder.variables


def test_the_boundary_predicate_is_the_exact_interior_point_test() -> None:
    cmap = corpus12.load_map(1)
    wrong = total = 0
    for planes, oracle in random_configurations(N_FACES, 2, seed=7):
        rows = homogeneous_planes(planes)
        encoder = Encoder(cmap, oracle=flat_orientations(oracle, cmap))
        encoder.build(DEFAULT_LAYERS, gauge_face=None)
        values = encoder.formula.values
        for (a, b, u), variable in encoder.boundary_bits.items():
            z0, z1 = cmap.end_pair(a, b)
            here, first, second = (
                line_coordinate(rows, a, b, u),
                line_coordinate(rows, a, b, z0),
                line_coordinate(rows, a, b, z1),
            )
            inside = 1 if min(first, second) < here < max(first, second) else 0
            total += 1
            wrong += values[variable] != inside
    assert total > 1000
    assert wrong == 0


def test_the_turn_bit_is_the_sign_of_the_measured_turn_at_every_corner() -> None:
    """The turn identity (paper: lem:turn) in its sharpest form: the constant 1.

    `turn XOR [measured turn is negative]` is 1 at every corner (the `turn:` variable is
    the complement of the corner bit, paper: lem:sf).
    """
    cmap = corpus12.load_map(1)
    constants: set[int] = set()
    corners = 0
    for planes, oracle in random_configurations(N_FACES, 2, seed=7):
        rows = homogeneous_planes(planes)
        encoder = Encoder(cmap, oracle=flat_orientations(oracle, cmap))
        encoder.build(DEFAULT_LAYERS, gauge_face=None)
        for face in cmap.faces:
            cycle = cmap.link_cycle(face)
            for position in range(len(cycle)):
                a, b = cycle[position], cycle[(position + 1) % len(cycle)]
                x, y = cmap.far_end(face, a, b), cmap.far_end(face, b, a)
                previous = affine_point(rows, face, a, x)
                corner = affine_point(rows, face, a, b)
                following = affine_point(rows, face, b, y)
                incoming = [corner[k] - previous[k] for k in range(3)]
                outgoing = [following[k] - corner[k] for k in range(3)]
                cross = [
                    incoming[1] * outgoing[2] - incoming[2] * outgoing[1],
                    incoming[2] * outgoing[0] - incoming[0] * outgoing[2],
                    incoming[0] * outgoing[1] - incoming[1] * outgoing[0],
                ]
                turn = sum(cross[k] * rows[face][k] for k in range(3))
                assert turn != 0, "general position should have excluded a straight corner"
                literal = encoder.corner_literal(face, a, b)
                encoded = 1 - encoder.formula.literal_value(literal)
                constants.add(encoded ^ (1 if turn < 0 else 0))
                corners += 1
    assert corners > 200
    assert constants == {1}


def test_ground_truth_without_the_orientation_bits_is_refused_at_the_first_corner() -> None:
    """No silent default for `s_f`: a wrong one would make Layer I true by construction."""
    cmap, planes = fixture("tetrahedron")
    oracle = oracle_from_planes(planes)
    with pytest.raises(GeometryError, match="orientation bit s_f"):
        Encoder(cmap, oracle=oracle).build(DEFAULT_LAYERS, gauge_face=None)


@pytest.mark.parametrize("name", ["tetrahedron", "szilassi"])
def test_every_clause_holds_on_a_realized_configuration(name: str) -> None:
    """Positive controls: a false exclusion would show up here as a violated clause."""
    cmap, planes = fixture(name)
    oracle = oracle_from_planes(planes)
    assert oracle.in_general_position
    geometry = inspect_embedding(planes, cmap)
    orientation = geometry["orientation"]
    encoder = Encoder(cmap, oracle=oracle.with_orientations(orientation))
    encoder.build(DEFAULT_LAYERS, gauge_face=None)
    assert not encoder.formula.violations
    assert len(encoder.formula.values) == encoder.variables
    for face in cmap.faces:
        cycle = cmap.link_cycle(face)
        measured = sum(
            encoder.formula.literal_value(
                encoder.corner_literal(face, cycle[i], cycle[(i + 1) % len(cycle)])
            )
            for i in range(len(cycle))
        )
        assert measured == geometry["reflex"][face]


def test_a_wrong_orientation_bit_is_caught_by_layer_i() -> None:
    """Negative control: flipping one measured `s_f` must violate a Layer I clause."""
    cmap, planes = fixture("szilassi")
    oracle = oracle_from_planes(planes)
    orientation: dict[int, Any] = dict(inspect_embedding(planes, cmap)["orientation"])
    orientation[1] ^= 1
    encoder = Encoder(cmap, oracle=oracle.with_orientations(orientation))
    encoder.build(DEFAULT_LAYERS, gauge_face=None)
    assert set(encoder.formula.violations) == {"I"}


@pytest.mark.parametrize("name", ["tetrahedron", "szilassi"])
def test_the_gauge_keeps_a_representative_of_a_realized_configuration(name: str) -> None:
    """Every gauge face must admit an actual reorientation of a real polyhedron."""
    cmap, planes = fixture(name)
    oracle = oracle_from_planes(planes)
    encoder = Encoder(cmap).build(DEFAULT_LAYERS, gauge_face=None)
    for face in cmap.faces:
        for group_element in range(1 << (cmap.n + 1)):
            if all(
                oracle(subset)
                ^ (group_element & 1)
                ^ (sum((group_element >> x) & 1 for x in subset if x) & 1)
                == 0
                for subset in encoder.gauge_targets(face)
            ):
                break
        else:
            pytest.fail(f"gauge {face} has no geometric representative")
        transformed = [
            [
                -x if ((k == 0 and group_element & 1) ^ bool((group_element >> (i + 1)) & 1)) else x
                for k, x in enumerate(plane)
            ]
            for i, plane in enumerate(planes)
        ]
        moved = oracle_from_planes(transformed)
        assert moved.in_general_position
        orientation = inspect_embedding(transformed, cmap)["orientation"]
        other = Encoder(cmap, oracle=moved.with_orientations(orientation))
        other.build(DEFAULT_LAYERS, gauge_face=face)
        assert not other.formula.violations
