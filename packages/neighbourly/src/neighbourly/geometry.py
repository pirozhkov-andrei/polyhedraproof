"""Exact affine geometry of a plane family: intersection points and order along a line.

These functions exist so that the encoder's identities can be checked against the
actual geometry rather than against a rearrangement of themselves, which would be a
tautology dressed as a test. Rows are homogeneous planes as built by
:func:`neighbourly.exact.homogeneous_planes`.
"""

from __future__ import annotations

from collections.abc import Sequence
from fractions import Fraction

from neighbourly.exact import GeometryError, determinant

__all__ = ["affine_point", "line_coordinate"]


def affine_point(rows: Sequence[Sequence[Fraction]], i: int, j: int, k: int) -> list[Fraction]:
    """The point where planes `i`, `j`, `k` meet, exactly, by Cramer's rule."""
    coefficients = [rows[i][:3], rows[j][:3], rows[k][:3]]
    constants = [-rows[i][3], -rows[j][3], -rows[k][3]]
    denominator = determinant(coefficients)
    if denominator == 0:
        raise GeometryError(f"planes {i}, {j}, {k} do not meet in a single point")
    out: list[Fraction] = []
    for column in range(3):
        matrix = [list(row) for row in coefficients]
        for row in range(3):
            matrix[row][column] = constants[row]
        out.append(determinant(matrix) / denominator)
    return out


def line_coordinate(rows: Sequence[Sequence[Fraction]], i: int, j: int, k: int) -> Fraction:
    """Where `P_ijk` sits along the line `L_ij`, in the direction `n_i x n_j`."""
    a, b = rows[i][:3], rows[j][:3]
    direction = [
        a[1] * b[2] - a[2] * b[1],
        a[2] * b[0] - a[0] * b[2],
        a[0] * b[1] - a[1] * b[0],
    ]
    point = affine_point(rows, i, j, k)
    return sum((point[m] * direction[m] for m in range(3)), Fraction(0))
