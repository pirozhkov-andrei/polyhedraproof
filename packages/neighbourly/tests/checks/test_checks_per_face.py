"""neighbourly.checks.per_face: fixed-seed per-face controls on n = 12, 15, 16 and n = 4, 7.

The controls compare the encoder's ground-truth face predicates with exact plane and polygon
operations that share no code with the encoder (``neighbourly.checks.rational``). Random
planes test the predicates and Layer B's crossing semantics; the realized n = 4 tetrahedron
and n = 7 Szilassi configurations test every clause. The negative controls below show that
each comparison can fail. Finite controls: they prove nothing for other configurations.
"""

from __future__ import annotations

import ast
import importlib.util
import inspect
import json
import random
from fractions import Fraction
from functools import cache
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from neighbourly import corpus12
from neighbourly.checks import ChecksError, per_face, per_face_check, random_planes, rational
from neighbourly.data import read_bytes
from neighbourly.encoding import PLANE_AT_INFINITY, Encoder
from neighbourly.exact import oracle_from_planes
from neighbourly.maps import CombinatorialMap

#: The fixed seeds of the per-face controls.
SEEDS = (20261006, 7)
EXACT_HELPER = Path(__file__).resolve().parents[1] / "exact" / "nb_exact_geometry.py"


def load(n: int) -> CombinatorialMap:
    if n == 12:
        return corpus12.load_map(1)
    text = read_bytes("fixtures", f"n{n}", f"n{n}.txt").decode("utf-8")
    return CombinatorialMap.from_text(text, f"n{n}.txt")


def realized(name: str) -> tuple[CombinatorialMap, list[list[Fraction]], dict[str, Any]]:
    folder, matrix, planes = {
        "tetrahedron": ("tetrahedron", "tetrahedron.txt", "planes.json"),
        "szilassi": ("szilassi", "csaszar_n7.txt", "szilassi.json"),
    }[name]
    cmap = CombinatorialMap.from_text(read_bytes("fixtures", folder, matrix).decode("utf-8"))
    document = json.loads(read_bytes("fixtures", folder, planes))
    return cmap, [[Fraction(x) for x in row] for row in document["planes"]], document


@cache
def exact_helper() -> ModuleType:
    """The independent control geometry (tests/exact), loaded by path."""
    spec = importlib.util.spec_from_file_location("nb_exact_geometry_controls", EXACT_HELPER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# -- positive controls ------------------------------------------------------------------------


@pytest.mark.parametrize("seed", SEEDS)
@pytest.mark.parametrize("n", [12, 15, 16])
def test_per_face_controls_on_random_planes(n: int, seed: int) -> None:
    cmap = load(n)
    result = per_face_check(cmap, random_planes(n, seed))
    assert result.passed, result.problems
    summary = result.summary()
    assert summary["boundary_compared"] == n * (n - 1) * (n - 4)
    assert summary["corners_compared"] == n * (n - 1)
    assert summary["crossing_pairs"] == n * (n - 1) * (n - 4) // 2
    assert summary["wrong"] == 0
    # random planes are no realization: Layer B is violated exactly at the crossings, and
    # those exist, so the crossing comparison is not vacuous
    assert summary["crossings"] == result.violations["B"] > 0
    assert not set(result.violations) & {"S", "H", "A"}
    assert [report.face for report in result.faces] == list(cmap.faces)


def test_more_shipped_maps_on_the_fixed_seed() -> None:
    for map_id in (2, 30, 59):
        result = per_face_check(corpus12.load_map(map_id), random_planes(12, SEEDS[0]))
        assert result.passed, (map_id, result.problems)


def test_random_planes_redraws_degenerate_families() -> None:
    """Seed 2 with coefficients in -3..3 gives ten degenerate six-plane families first."""
    planes = random_planes(6, 2, bound=3)
    assert oracle_from_planes(planes).in_general_position
    generator = random.Random(2)
    first = [[Fraction(generator.randint(-3, 3)) for _ in range(4)] for _ in range(6)]
    assert not oracle_from_planes(first).in_general_position


def test_random_planes_are_fixed_by_the_seed_and_in_general_position() -> None:
    first = random_planes(16, SEEDS[0])
    assert first == random_planes(16, SEEDS[0]) != random_planes(16, SEEDS[1])
    assert oracle_from_planes(first).in_general_position
    assert all(-40 <= x <= 40 and x.denominator == 1 for plane in first for x in plane)


@pytest.mark.parametrize("name", ["tetrahedron", "szilassi"])
def test_per_face_controls_on_realized_configurations(name: str) -> None:
    cmap, planes, document = realized(name)
    result = per_face_check(cmap, planes, realized=True)
    assert result.passed, result.problems
    assert dict(result.violations) == {}
    assert all(report.simple for report in result.faces)
    geometry = exact_helper().inspect_embedding(planes, cmap)
    assert {r.face: r.orientation for r in result.faces} == geometry["orientation"]
    assert {r.face: r.reflex_corners for r in result.faces} == geometry["reflex"]
    if "verification" in document:
        recorded = document["verification"]
        assert {str(r.face): r.orientation for r in result.faces} == recorded["orientation"]
        assert {str(r.face): r.reflex_corners for r in result.faces} == recorded["reflex"]


# -- negative controls: every comparison can fail ---------------------------------------------


class _Corner(Encoder):
    """The corner bit with its bracket term written `X_{0,f,b,a}` (a sign convention error)."""

    def corner_literal(self, face: int, a: int, b: int) -> int:
        successor = self.map.link_successor(face)
        if successor.get(a) != b:
            a, b = b, a
        key = (face, a, b)
        if key in self._corner_bits:
            return self._corner_bits[key]
        if face not in self._orientation_bits:
            self._orientation_bits[face] = self._orientation_variable(face)
        turn = self.formula.define_xor(
            [
                self.order_literal(face, a, self.map.far_end(face, a, b), b),
                self.order_literal(face, b, a, self.map.far_end(face, b, a)),
                self.bracket_literal(PLANE_AT_INFINITY, face, b, a),
                self._orientation_bits[face],
            ],
            f"turn:{face};{a},{b}",
        )
        self._corner_bits[key] = -turn
        return -turn


class _Between(Encoder):
    """`Between` with the second term complemented: OnB becomes its complement."""

    def between_pair(self, i: int, j: int, m: int, k: int, l: int) -> tuple[int, int]:
        first, second = super().between_pair(i, j, m, k, l)
        return first, -second


class _LayerB(Encoder):
    """Layer B forbidding the wrong pattern (one literal of every clause flipped)."""

    def layer_B(self) -> None:
        formula = self.formula
        formula.begin_layer("B")
        for f in self.map.faces:
            others = [x for x in self.map.faces if x != f]
            for i, a in enumerate(others):
                for b in others[i + 1 :]:
                    if not self.map.is_real(f, a, b):
                        formula.add_clause(
                            (-self.boundary_bit(f, a, b), self.boundary_bit(f, b, a)),
                            f"B:{f}|{a},{b}",
                        )


class _LayerH(Encoder):
    """An extra Layer H clause that real planes violate."""

    def layer_H(self) -> None:
        super().layer_H()
        kl = self.order_literal(1, 2, 3, 4)
        self.formula.add_clause((kl,), "H:extra")
        self.formula.add_clause((-kl,), "H:extra")


@pytest.mark.parametrize(
    ("encoder", "message"),
    [
        (_Corner, "corner bits disagree"),
        (_Between, "boundary bits disagree"),
        (_LayerB, "Layer B crossings disagree"),
        (_LayerH, "layers that hold for any planes"),
    ],
)
def test_a_wrong_encoder_is_caught_on_random_planes(
    monkeypatch: Any, encoder: type[Encoder], message: str
) -> None:
    monkeypatch.setattr(per_face, "Encoder", encoder)
    result = per_face_check(load(12), random_planes(12, SEEDS[0]))
    assert not result.passed
    assert any(message in problem for problem in result.problems), result.problems


def test_a_wrong_orientation_bit_is_caught_on_a_realization(monkeypatch: Any) -> None:
    measured = per_face._Faces.orientation

    def flipped(self: Any, face: int) -> int:
        return int(measured(self, face)) ^ (face == 1)

    monkeypatch.setattr(per_face._Faces, "orientation", flipped)
    cmap, planes, _ = realized("szilassi")
    result = per_face_check(cmap, planes, realized=True)
    assert any("a realization violates clauses" in p for p in result.problems)
    assert result.violations.get("I", 0) > 0


def test_two_reflex_corners_at_a_vertex_are_reported(monkeypatch: Any) -> None:
    """If the measured geometry made every corner reflex, lem:onereflex would be violated."""

    measured = per_face._Faces.turn_negative

    def reflex_on(faces: set[int]) -> Any:
        def turn_negative(self: Any, face: int, a: int, b: int) -> int:
            if face in faces:
                return 1 ^ int(self.orientation(face))
            return int(measured(self, face, a, b))

        return turn_negative

    cmap, planes, _ = realized("szilassi")
    monkeypatch.setattr(per_face._Faces, "turn_negative", reflex_on(set(cmap.faces)))
    result = per_face_check(cmap, planes, realized=True)
    vertex = [p for p in result.problems if "more than one reflex corner" in p]
    assert len(vertex) == len(cmap.triples)
    # exactly two reflex corners: faces 1 and 2 forced, face 3 left as measured
    monkeypatch.setattr(per_face._Faces, "turn_negative", reflex_on({1, 2}))
    result = per_face_check(cmap, planes, realized=True)
    vertex = [p for p in result.problems if "more than one reflex corner" in p]
    both = [t for t in sorted(cmap.triples) if {1, 2} <= set(t)]
    assert both and all(f"vertex {t} has" in " ".join(vertex) for t in both)


def test_random_planes_claimed_as_a_realization_are_reported() -> None:
    """Non-simple faces are reported; a satisfied clause set alone would prove nothing."""
    cmap, _, _ = realized("szilassi")
    result = per_face_check(cmap, random_planes(7, SEEDS[0]), realized=True)
    assert not result.passed
    assert any("is not a simple polygon" in p for p in result.problems), result.problems


def test_degenerate_or_malformed_input_is_refused() -> None:
    cmap = load(12)
    planes = random_planes(12, SEEDS[0])
    with pytest.raises(ChecksError, match="12 planes"):
        per_face_check(cmap, planes[:-1])
    flat = [list(p) for p in planes]
    flat[1] = list(flat[0])  # two equal planes: zero brackets
    with pytest.raises(ChecksError, match="general position"):
        per_face_check(cmap, flat)
    with pytest.raises(ChecksError, match="CombinatorialMap"):
        per_face_check("map 1", planes)  # type: ignore[arg-type]
    with pytest.raises(ChecksError):
        random_planes(3, 1)


def test_nothing_compared_is_a_failure() -> None:
    result = per_face_check(load(12), random_planes(12, SEEDS[0]), layers="S,H,A")
    assert any("nothing was compared" in p for p in result.problems)


# -- independence ---------------------------------------------------------------------------


def test_the_controls_do_not_reuse_the_predicates_under_test() -> None:
    """rational imports only the standard library; per_face takes from neighbourly only the
    encoder and oracle under test, the map, and the layer selection."""
    for module, allowed in (
        (rational, set()),
        (
            per_face,
            {
                "neighbourly.checks.rational",
                "neighbourly.encoding",
                "neighbourly.exact",
                "neighbourly.maps",
            },
        ),
    ):
        tree = ast.parse(inspect.getsource(module))
        imported = {
            node.module
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom)
            and node.module
            and node.module.startswith("neighbourly")
        }
        assert imported <= allowed, imported
    source = inspect.getsource(per_face)
    for name in ("line_coordinate", "affine_point", "bracket(", "order_literal", "between_pair"):
        assert name not in source.split('"""', 2)[2], name
    exact_names = {"oracle_from_planes"}
    tree = ast.parse(source)
    used = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module == "neighbourly.exact"
        for alias in node.names
    }
    assert used == exact_names


def test_the_rational_helpers_on_known_values() -> None:
    q = Fraction
    point = rational.meet(
        (q(1), q(0), q(0), q(-1)), (q(0), q(1), q(0), q(-2)), (q(0), q(0), q(1), q(-3))
    )
    assert point == (q(1), q(2), q(3))
    assert rational.det3((q(1), q(0), q(0)), (q(0), q(1), q(0)), (q(0), q(0), q(1))) == 1
    with pytest.raises(ValueError):
        rational.meet((q(1), q(0), q(0), q(0)), (q(2), q(0), q(0), q(1)), (q(0), q(0), q(1), q(0)))
    square = [(q(0), q(0)), (q(2), q(2)), (q(0), q(2)), (q(2), q(0))]
    assert rational.segments_cross(*square)
    assert not rational.segments_cross((q(0), q(0)), (q(1), q(0)), (q(0), q(1)), (q(1), q(1)))
    with pytest.raises(ValueError):
        rational.segments_cross((q(0), q(0)), (q(2), q(0)), (q(1), q(0)), (q(1), q(1)))
    triangle = [(q(0), q(0), q(0)), (q(1), q(0), q(0)), (q(0), q(1), q(0))]
    assert rational.signed_area_normal(triangle) == (q(0), q(0), q(1))
    assert rational.project(triangle, (q(0), q(0), q(-5))) == [
        (q(0), q(0)),
        (q(1), q(0)),
        (q(0), q(1)),
    ]
