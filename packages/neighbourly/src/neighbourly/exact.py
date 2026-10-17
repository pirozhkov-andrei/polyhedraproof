"""Exact rational determinants and the bracket oracle of an explicit plane family.

Everything here is exact: `Fraction` throughout, no floating point anywhere, because
these values are the ground truth the encoder's identities are checked against. Nothing
here depends on the number of planes; the element `0` is the plane at infinity
`q_0 = (0,0,0,1)` that :func:`homogeneous_planes` puts in front of the given planes.
"""

from __future__ import annotations

import itertools
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, replace
from fractions import Fraction

__all__ = [
    "GeometryError",
    "Matrix",
    "Plane",
    "PlaneOracle",
    "bracket",
    "determinant",
    "homogeneous_planes",
    "oracle_from_planes",
]

Matrix = Sequence[Sequence[Fraction]]
#: A plane `(a, b, c, d)` standing for `a x + b y + c z + d = 0`.
Plane = Sequence[Fraction]


class GeometryError(ValueError):
    """Exact geometric input that is degenerate or incomplete for the question asked."""


def determinant(matrix: Matrix) -> Fraction:
    """Exact determinant by Gaussian elimination over the rationals."""
    rows = [list(row) for row in matrix]
    size = len(rows)
    if any(len(row) != size for row in rows):
        raise GeometryError("determinant needs a square matrix")
    result = Fraction(1)
    for column in range(size):
        pivot = next((r for r in range(column, size) if rows[r][column] != 0), None)
        if pivot is None:
            return Fraction(0)
        if pivot != column:
            rows[column], rows[pivot] = rows[pivot], rows[column]
            result = -result
        result *= rows[column][column]
        inverse = Fraction(1) / rows[column][column]
        for r in range(column + 1, size):
            factor = rows[r][column] * inverse
            if factor:
                for c in range(column, size):
                    rows[r][c] -= factor * rows[column][c]
    return result


def homogeneous_planes(planes: Sequence[Plane]) -> list[list[Fraction]]:
    """The planes as exact rows, with the plane at infinity `q_0 = (0,0,0,1)` in front."""
    return [[Fraction(0), Fraction(0), Fraction(0), Fraction(1)]] + [
        [Fraction(x) for x in plane] for plane in planes
    ]


def bracket(rows: Sequence[Sequence[Fraction]], elements: Sequence[int]) -> Fraction:
    """`[S]` -- the 4x4 determinant of the rows named by `elements`."""
    return determinant([rows[i] for i in elements])


@dataclass(frozen=True)
class PlaneOracle:
    """Ground truth for one explicit plane family: `oracle(S) == 1` iff `chi(S) < 0`.

    Callable, so it can be handed straight to `Encoder(cmap, oracle=...)`, which then
    evaluates every variable and clause it emits against this configuration.

    The planes fix every bracket but not the per-face orientation bit `s_f`
    (paper: lem:sf), which also depends on the direction the combinatorial map traverses
    the face's boundary.  `with_orientations` attaches the bits measured on the
    embedding; an encoder that reaches a corner without them is told what is missing
    rather than shown a default that would make Layer I true by construction.
    """

    signs: dict[tuple[int, ...], int]
    degenerate: tuple[tuple[int, ...], ...] = field(default=())
    orientations: Mapping[int, int] | None = None

    def __call__(self, elements: Sequence[int]) -> int:
        return self.signs[tuple(elements)]

    def orientation(self, face: int) -> int:
        """`s_f` of one embedding of one map, as `with_orientations` was given it."""
        if self.orientations is None or face not in self.orientations:
            raise GeometryError(
                f"this ground truth carries no orientation bit s_f for face {face} "
                "(paper: lem:sf); attach the measured bits with .with_orientations(...)"
            )
        return self.orientations[face] & 1

    def with_orientations(self, orientations: Mapping[int, int]) -> PlaneOracle:
        """The same brackets, now also carrying one embedding's orientation bits."""
        return replace(self, orientations=dict(orientations))

    @property
    def in_general_position(self) -> bool:
        return not self.degenerate


def oracle_from_planes(planes: Sequence[Plane]) -> PlaneOracle:
    """Sign bits of every 4-subset of `[q_0, *planes]`, plus the degenerate subsets."""
    rows = homogeneous_planes(planes)
    signs: dict[tuple[int, ...], int] = {}
    degenerate: list[tuple[int, ...]] = []
    for subset in itertools.combinations(range(len(rows)), 4):
        value = bracket(rows, subset)
        if value == 0:
            degenerate.append(subset)
        signs[subset] = 1 if value < 0 else 0
    return PlaneOracle(signs=signs, degenerate=tuple(degenerate))
