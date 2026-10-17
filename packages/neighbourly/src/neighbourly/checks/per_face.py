"""Per-face controls: the encoder's face predicates against exact plane and polygon geometry.

For a family of `n` rational planes (one per face) and a map on `n` faces, the encoder is
built in ground-truth mode, so every variable gets the value this configuration gives it.
Then each face `f` is examined with the independent operations of
:mod:`neighbourly.checks.rational`, never with the encoder's literals, brackets or
betweenness bits:

    boundary    `OnB(i,j;u)` (paper: def:onb) for the edges of `f`: `P_iju` is strictly
                inside `E(i,j)` iff `(P - E_0) . (P - E_1) < 0` for the edge's end points
    corners     the corner bit at every corner of `f` (paper: lem:turn, lem:sf) equals
                `[turn < 0] xor s_f`, with `turn = ((c - p) x (q - c)) . n_f` along the
                link-cycle traversal
    crossings   two non-adjacent edges of `f` cross (segment test in the plane of `f`)
                exactly when Layer B's clause for that pair is violated (paper: lem:B)

On RANDOM planes (``realized=False``) the faces are generally not simple polygons, so the
orientation bits are fixed to 0 (the comparisons above hold for any fixed `s_f`), S, H and
A must hold (they hold for every configuration in general position) and B must be violated
exactly at the crossings; Layer I is not asserted. On a REALIZED configuration
(``realized=True``) `s_f` is measured from the polygon's own vector area, every polygon must
be simple, no clause of any layer may be violated, and no vertex may have two reflex corners
(paper: lem:onereflex).

These are finite controls on the configurations given; they can expose a wrong predicate or
clause there and prove nothing for other configurations or other `n`.
"""

from __future__ import annotations

import random
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from fractions import Fraction
from types import MappingProxyType
from typing import Any

from neighbourly.checks.rational import (
    Point,
    cross,
    dot,
    meet,
    project,
    segments_cross,
    signed_area_normal,
    sub,
)
from neighbourly.encoding import DEFAULT_LAYERS, Encoder, layer_letters
from neighbourly.exact import oracle_from_planes
from neighbourly.maps import CombinatorialMap, sorted_triple

__all__ = ["ChecksError", "FaceReport", "PerFaceResult", "per_face_check", "random_planes"]

#: Coefficient bound of :func:`random_planes` (coefficients are drawn from -40..40).
RANDOM_BOUND = 40


class ChecksError(ValueError):
    """Input a control cannot judge: wrong sizes, or degenerate geometry."""


def random_planes(n: int, seed: int, bound: int = RANDOM_BOUND) -> list[list[Fraction]]:
    """The first family of `n` integer planes in general position drawn from `seed`.

    Coefficients are uniform in `-bound..bound` (``random.Random(seed).randint``); families
    with a vanishing 4x4 bracket (the plane at infinity included) are skipped.
    """
    if type(n) is not int or n < 4:
        raise ChecksError("n must be an integer of at least 4")
    generator = random.Random(seed)
    while True:
        planes = [[Fraction(generator.randint(-bound, bound)) for _ in range(4)] for _ in range(n)]
        if oracle_from_planes(planes).in_general_position:
            return planes


@dataclass(frozen=True)
class FaceReport:
    """What the controls compared on one face, and how often the encoder disagreed."""

    face: int
    boundary_compared: int
    boundary_wrong: int
    corners_compared: int
    corners_wrong: int
    crossing_pairs: int
    crossings: int
    crossings_wrong: int
    orientation: int
    reflex_corners: int

    @property
    def simple(self) -> bool:
        """No two non-adjacent edges of the face cross."""
        return self.crossings == 0

    @property
    def wrong(self) -> int:
        return self.boundary_wrong + self.corners_wrong + self.crossings_wrong


@dataclass(frozen=True)
class PerFaceResult:
    """The per-face controls of one configuration."""

    n: int
    realized: bool
    faces: tuple[FaceReport, ...]
    violations: Mapping[str, int]
    problems: tuple[str, ...]

    @property
    def passed(self) -> bool:
        return not self.problems

    def summary(self) -> dict[str, Any]:
        """JSON-ready totals and the problems."""
        return {
            "n": self.n,
            "realized": self.realized,
            "passed": self.passed,
            "boundary_compared": sum(r.boundary_compared for r in self.faces),
            "corners_compared": sum(r.corners_compared for r in self.faces),
            "crossing_pairs": sum(r.crossing_pairs for r in self.faces),
            "crossings": sum(r.crossings for r in self.faces),
            "wrong": sum(r.wrong for r in self.faces),
            "violations": dict(self.violations),
            "problems": list(self.problems),
        }


class _Faces:
    """Exact points and polygons of one plane family, computed on demand."""

    def __init__(self, cmap: CombinatorialMap, planes: Sequence[Sequence[Fraction]]) -> None:
        self.map = cmap
        self.planes = planes
        self._points: dict[tuple[int, int, int], Point] = {}

    def normal(self, face: int) -> Sequence[Fraction]:
        return self.planes[face - 1][:3]

    def point(self, a: int, b: int, c: int) -> Point:
        key = sorted_triple((a, b, c))
        if key not in self._points:
            try:
                self._points[key] = meet(*(self.planes[x - 1] for x in key))
            except ValueError:
                raise ChecksError(f"planes {key} have no single common point") from None
        return self._points[key]

    def edge(self, face: int, other: int) -> tuple[Point, Point]:
        z0, z1 = self.map.end_pair(face, other)
        return self.point(face, other, z0), self.point(face, other, z1)

    def inside(self, a: int, b: int, u: int) -> int:
        """`P_abu` strictly inside the edge `E(a,b)` (the three points are collinear)."""
        first, second = self.edge(a, b)
        here = self.point(a, b, u)
        product = dot(sub(here, first), sub(here, second))
        if product == 0:
            raise ChecksError(f"P_{a},{b},{u} coincides with an end of E({a},{b})")
        return 1 if product < 0 else 0

    def polygon(self, face: int) -> list[Point]:
        """The vertices of `face` in link-cycle order."""
        cycle = self.map.link_cycle(face)
        return [self.point(face, cycle[k], cycle[(k + 1) % len(cycle)]) for k in range(len(cycle))]

    def turn_negative(self, face: int, a: int, b: int) -> int:
        """`[((c - p) x (q - c)) . n_f < 0]` at the corner `P_fab`, `a -> b` in link order."""
        previous = self.point(face, a, self.map.far_end(face, a, b))
        corner = self.point(face, a, b)
        following = self.point(face, b, self.map.far_end(face, b, a))
        turn = dot(cross(sub(corner, previous), sub(following, corner)), self.normal(face))
        if turn == 0:
            raise ChecksError(f"straight corner of face {face} at P_{face},{a},{b}")
        return 1 if turn < 0 else 0

    def crosses(self, face: int, a: int, b: int) -> bool:
        """Do the edges `E(face,a)` and `E(face,b)` cross inside both (in the plane of `face`)?"""
        p, q = self.edge(face, a)
        r, s = self.edge(face, b)
        flat = project([p, q, r, s], self.normal(face))
        try:
            return segments_cross(*flat)
        except ValueError:
            raise ChecksError(f"face {face}: edges to {a} and {b} touch") from None

    def orientation(self, face: int) -> int:
        """Measured `s_f`: the link traversal runs against `n_f` (paper: lem:sf)."""
        area = dot(signed_area_normal(self.polygon(face)), self.normal(face))
        if area == 0:
            raise ChecksError(f"face {face} has zero signed area")
        return 1 if area < 0 else 0


def _planes(cmap: CombinatorialMap, planes: Sequence[Sequence[Any]]) -> list[list[Fraction]]:
    if not isinstance(cmap, CombinatorialMap):
        raise ChecksError(f"the controls need a CombinatorialMap, not {type(cmap).__name__}")
    if len(planes) != cmap.n or any(len(plane) != 4 for plane in planes):
        raise ChecksError(f"need {cmap.n} planes of four coefficients")
    return [[Fraction(x) for x in plane] for plane in planes]


def per_face_check(
    cmap: CombinatorialMap,
    planes: Sequence[Sequence[Any]],
    *,
    realized: bool = False,
    layers: str = DEFAULT_LAYERS,
) -> PerFaceResult:
    """Run the per-face controls of the module documentation on one configuration."""
    exact = _planes(cmap, planes)
    oracle = oracle_from_planes(exact)
    if not oracle.in_general_position:
        zero = len(oracle.degenerate)
        raise ChecksError(f"the planes are not in general position: {zero} zero brackets")
    faces = _Faces(cmap, exact)
    problems: list[str] = []
    orientation = dict.fromkeys(cmap.faces, 0)
    if realized:
        for f in cmap.faces:
            if any(faces.crosses(f, a, b) for a, b in _pairs(cmap, f)):
                problems.append(f"not a realization: face {f} is not a simple polygon")
            else:
                orientation[f] = faces.orientation(f)
    encoder = Encoder(cmap, oracle=oracle.with_orientations(orientation))
    encoder.build(layers, gauge_face=None)
    values = encoder.formula
    violated = {layer: len(tags) for layer, tags in sorted(encoder.formula.violations.items())}
    b_violations = set(encoder.formula.violations.get("B", ()))
    with_b = "B" in layer_letters(layers)

    reports = []
    reflex_at: dict[tuple[int, int, int], int] = {}
    for f in cmap.faces:
        boundary = boundary_wrong = 0
        for (a, b, u), variable in encoder.boundary_bits.items():
            if f not in (a, b):
                continue
            boundary += 1
            boundary_wrong += values.values[variable] != faces.inside(a, b, u)
        corners = corners_wrong = reflex = 0
        for (face, a, b), literal in encoder.corner_bits.items():
            if face != f:
                continue
            expected = faces.turn_negative(f, a, b) ^ orientation[f]
            corners += 1
            corners_wrong += values.literal_value(literal) != expected
            reflex += expected
            reflex_at[(f, a, b)] = expected
        pairs = crossings = crossings_wrong = 0
        if with_b:
            for a, b in _pairs(cmap, f):
                pairs += 1
                crosses = faces.crosses(f, a, b)
                crossings += crosses
                crossings_wrong += crosses != (f"B:{f}|{a},{b}" in b_violations)
        reports.append(
            FaceReport(
                face=f,
                boundary_compared=boundary,
                boundary_wrong=boundary_wrong,
                corners_compared=corners,
                corners_wrong=corners_wrong,
                crossing_pairs=pairs,
                crossings=crossings,
                crossings_wrong=crossings_wrong,
                orientation=orientation[f],
                reflex_corners=reflex,
            )
        )
        for what, wrong in (
            ("boundary bits", boundary_wrong),
            ("corner bits", corners_wrong),
            ("Layer B crossings", crossings_wrong),
        ):
            if wrong:
                problems.append(f"face {f}: {wrong} {what} disagree with the exact geometry")

    unconditional = {layer: count for layer, count in violated.items() if layer in ("S", "H", "A")}
    if unconditional:
        problems.append(f"layers that hold for any planes are violated: {unconditional}")
    if realized:
        if violated:
            problems.append(f"a realization violates clauses: {violated}")
        for triple in sorted(cmap.triples):
            f, g, h = triple
            corners_here = (
                _corner(cmap, reflex_at, f, g, h),
                _corner(cmap, reflex_at, g, f, h),
                _corner(cmap, reflex_at, h, f, g),
            )
            if None not in corners_here and sum(c or 0 for c in corners_here) > 1:
                problems.append(f"vertex {triple} has more than one reflex corner")
    if not any(report.boundary_compared or report.corners_compared for report in reports):
        problems.append("nothing was compared (no Layer B or I variables)")
    return PerFaceResult(
        n=cmap.n,
        realized=realized,
        faces=tuple(reports),
        violations=MappingProxyType(violated),
        problems=tuple(problems),
    )


def _pairs(cmap: CombinatorialMap, face: int) -> list[tuple[int, int]]:
    """The non-adjacent edge pairs `(a, b)`, `a < b`, of `face` (Layer B's pairs)."""
    others = [x for x in cmap.faces if x != face]
    return [
        (a, b)
        for i, a in enumerate(others)
        for b in others[i + 1 :]
        if not cmap.is_real(face, a, b)
    ]


def _corner(
    cmap: CombinatorialMap, reflex_at: Mapping[tuple[int, int, int], int], f: int, a: int, b: int
) -> int | None:
    """The measured reflexness of the corner of `f` between `a` and `b` (either order)."""
    successor = cmap.link_successor(f)
    if successor.get(a) != b:
        a, b = b, a
    return reflex_at.get((f, a, b))
