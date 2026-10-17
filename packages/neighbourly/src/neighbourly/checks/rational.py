"""Exact plane and polygon operations for the per-face controls, written for them alone.

Nothing here calls :mod:`neighbourly.exact`, :mod:`neighbourly.geometry` or the encoder:
the per-face controls compare the encoder's ground-truth values (which are computed from
4x4 bracket signs) with answers obtained here from 3x3 Cramer solutions, dot and cross
products and 2D orientation tests. Sharing code with the thing under test would turn the
control into a restatement of it.
"""

from __future__ import annotations

from collections.abc import Sequence
from fractions import Fraction

__all__ = [
    "Point",
    "Vector",
    "cross",
    "det3",
    "dot",
    "meet",
    "orient2",
    "project",
    "segments_cross",
    "sign",
    "signed_area_normal",
    "sub",
]

Vector = tuple[Fraction, Fraction, Fraction]
Point = tuple[Fraction, Fraction, Fraction]


def sub(a: Sequence[Fraction], b: Sequence[Fraction]) -> Vector:
    return (a[0] - b[0], a[1] - b[1], a[2] - b[2])


def dot(a: Sequence[Fraction], b: Sequence[Fraction]) -> Fraction:
    return a[0] * b[0] + a[1] * b[1] + a[2] * b[2]


def cross(a: Sequence[Fraction], b: Sequence[Fraction]) -> Vector:
    return (
        a[1] * b[2] - a[2] * b[1],
        a[2] * b[0] - a[0] * b[2],
        a[0] * b[1] - a[1] * b[0],
    )


def det3(a: Sequence[Fraction], b: Sequence[Fraction], c: Sequence[Fraction]) -> Fraction:
    """`a . (b x c)`: the determinant of the rows `a`, `b`, `c`."""
    return dot(a, cross(b, c))


def sign(value: Fraction) -> int:
    return (value > 0) - (value < 0)


def meet(p: Sequence[Fraction], q: Sequence[Fraction], r: Sequence[Fraction]) -> Point:
    """The common point of the planes `p`, `q`, `r`, each `(a, b, c, d)`: `a x + b y + c z + d = 0`.

    Solved as `x = -(d_p (q x r) + d_q (r x p) + d_r (p x q)) / (p . (q x r))` on the normals.
    """
    np, nq, nr = p[:3], q[:3], r[:3]
    denominator = det3(np, nq, nr)
    if denominator == 0:
        raise ValueError("three planes without a single common point")
    qr, rp, pq = cross(nq, nr), cross(nr, np), cross(np, nq)
    return (
        -(p[3] * qr[0] + q[3] * rp[0] + r[3] * pq[0]) / denominator,
        -(p[3] * qr[1] + q[3] * rp[1] + r[3] * pq[1]) / denominator,
        -(p[3] * qr[2] + q[3] * rp[2] + r[3] * pq[2]) / denominator,
    )


def project(points: Sequence[Point], normal: Sequence[Fraction]) -> list[tuple[Fraction, Fraction]]:
    """Points of one plane in 2D, dropping the coordinate of the largest normal component.

    The projection is injective on the plane; it reverses the orientation when that
    component is negative, which the callers account for with the sign of it.
    """
    drop = max(range(3), key=lambda k: abs(normal[k]))
    keep = [k for k in range(3) if k != drop]
    return [(point[keep[0]], point[keep[1]]) for point in points]


def orient2(a: Sequence[Fraction], b: Sequence[Fraction], c: Sequence[Fraction]) -> Fraction:
    """Twice the signed area of the 2D triangle `a, b, c`."""
    return (b[0] - a[0]) * (c[1] - a[1]) - (b[1] - a[1]) * (c[0] - a[0])


def segments_cross(
    a: Sequence[Fraction], b: Sequence[Fraction], c: Sequence[Fraction], d: Sequence[Fraction]
) -> bool:
    """Do the 2D segments `ab` and `cd` cross at a point interior to both?

    Touching or collinear configurations are degenerate here and raise ``ValueError``.
    """
    x, y = orient2(a, b, c), orient2(a, b, d)
    z, w = orient2(c, d, a), orient2(c, d, b)
    if not (x and y and z and w):
        raise ValueError("degenerate segment pair: an endpoint lies on the other line")
    return (x > 0) != (y > 0) and (z > 0) != (w > 0)


def signed_area_normal(points: Sequence[Point]) -> Vector:
    """`sum p_i x p_(i+1)`: twice the vector area of the closed polygon `points`."""
    total: list[Fraction] = [Fraction(0), Fraction(0), Fraction(0)]
    for index, point in enumerate(points):
        following = points[(index + 1) % len(points)]
        term = cross(point, following)
        for k in range(3):
            total[k] += term[k]
    return (total[0], total[1], total[2])
