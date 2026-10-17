"""Independent rational geometry for the positive controls (realized configurations).

No SAT literals, encoder determinants, or encoded betweenness predicates are used.
It shares no code with neighbourly.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from fractions import Fraction as Q
from itertools import combinations
from typing import Any, Protocol

Number = Q | int
Vector = Sequence[Number]
Point = tuple[Q, ...]
Point2 = tuple[Q, ...]


class MapLike(Protocol):
    """What the controls need of a combinatorial map."""

    @property
    def faces(self) -> tuple[int, ...]: ...

    @property
    def triples(self) -> frozenset[tuple[int, int, int]]: ...

    def link_cycle(self, face: int) -> list[int]: ...

    def end_pair(self, i: int, j: int) -> tuple[int, int]: ...


def sub(a: Vector, b: Vector) -> tuple[Q, ...]:
    return tuple(Q(x) - y for x, y in zip(a, b))


def dot(a: Vector, b: Vector) -> Q:
    return sum((Q(x) * y for x, y in zip(a, b)), Q(0))


def cross(a: Vector, b: Vector) -> tuple[Q, Q, Q]:
    return (
        Q(a[1]) * b[2] - Q(a[2]) * b[1],
        Q(a[2]) * b[0] - Q(a[0]) * b[2],
        Q(a[0]) * b[1] - Q(a[1]) * b[0],
    )


def meet(a: Vector, b: Vector, c: Vector) -> Point:
    det = dot(a[:3], cross(b[:3], c[:3]))
    if not det:
        raise ValueError("dependent vertex normals")
    vectors = (cross(b[:3], c[:3]), cross(c[:3], a[:3]), cross(a[:3], b[:3]))
    return tuple(
        -sum((Q(p[3]) * v[k] for p, v in zip((a, b, c), vectors)), Q(0)) / det for k in range(3)
    )


def orient(a: Sequence[Q], b: Sequence[Q], c: Sequence[Q]) -> Q:
    return (b[0] - a[0]) * (c[1] - a[1]) - (b[1] - a[1]) * (c[0] - a[0])


def on_segment(a: Sequence[Q], b: Sequence[Q], p: Sequence[Q]) -> bool:
    return orient(a, b, p) == 0 and all(min(x, y) <= z <= max(x, y) for x, y, z in zip(a, b, p))


def segments_meet(a: Point2, b: Point2, c: Point2, d: Point2) -> bool:
    x, y, z, w = orient(a, b, c), orient(a, b, d), orient(c, d, a), orient(c, d, b)
    return (x * y < 0 and z * w < 0) or any(
        (on_segment(a, b, c), on_segment(a, b, d), on_segment(c, d, a), on_segment(c, d, b))
    )


def triangulate(points: list[Point], normal: Vector) -> tuple[list[tuple[Point, ...]], int]:
    """Check polygon simplicity, then triangulate its closed region by ear clipping."""
    drop = max(range(3), key=lambda k: abs(Q(normal[k])))
    projected = [tuple(x for k, x in enumerate(p) if k != drop) for p in points]
    m = len(points)
    if len(set(points)) != m:
        raise ValueError("repeated polygon vertex")
    for i, j in combinations(range(m), 2):
        if (i - j) % m in (1, m - 1):
            continue
        if segments_meet(
            projected[i], projected[(i + 1) % m], projected[j], projected[(j + 1) % m]
        ):
            raise ValueError("self-intersecting polygon")
    turns = [orient(projected[i - 1], projected[i], projected[(i + 1) % m]) for i in range(m)]
    if not all(turns):
        raise ValueError("straight polygon corner")
    area = sum(
        (
            projected[i][0] * projected[(i + 1) % m][1]
            - projected[(i + 1) % m][0] * projected[i][1]
            for i in range(m)
        ),
        Q(0),
    )
    if not area:
        raise ValueError("zero polygon area")
    sign = 1 if area > 0 else -1
    remaining = list(range(m))
    out: list[tuple[Point, ...]] = []
    while len(remaining) > 3:
        for k, b in enumerate(remaining):
            a, c = remaining[k - 1], remaining[(k + 1) % len(remaining)]
            if sign * orient(projected[a], projected[b], projected[c]) <= 0:
                continue
            if any(
                all(
                    sign * orient(projected[u], projected[v], projected[x]) >= 0
                    for u, v in ((a, b), (b, c), (c, a))
                )
                for x in remaining
                if x not in (a, b, c)
            ):
                continue
            out.append(tuple(points[i] for i in (a, b, c)))
            remaining.pop(k)
            break
        else:
            raise ValueError("ear triangulation failed")
    out.append(tuple(points[i] for i in remaining))
    return out, sum(t * sign < 0 for t in turns)


def plane_slice(triangle: tuple[Point, ...], q: Vector, axis: int) -> tuple[Q, Q] | None:
    """Coordinate interval cut out of a triangle by a noncoplanar plane."""
    values = [dot(q[:3], p) + q[3] for p in triangle]
    points = [p for p, s in zip(triangle, values) if s == 0]
    for i, j in combinations(range(3), 2):
        if values[i] * values[j] < 0:
            t = values[i] / (values[i] - values[j])
            points.append(tuple(x + t * (y - x) for x, y in zip(triangle[i], triangle[j])))
    if not points:
        return None
    return min(p[axis] for p in points), max(p[axis] for p in points)


def inspect_embedding(planes: Sequence[Sequence[Any]], cmap: MapLike) -> dict[str, Any]:
    """Verify each polygon and all face-pair intersections exactly.

    Faces are triangulated independently of their SAT encoding. Each triangle
    pair is intersected along the two supporting planes' line; the intersection
    must be contained in the prescribed shared edge.
    """
    q = {i + 1: tuple(map(Q, p)) for i, p in enumerate(planes)}
    vertices = {t: meet(*(q[f] for f in t)) for t in cmap.triples}
    if len(set(vertices.values())) != len(vertices):
        raise ValueError("distinct abstract vertices coincide")
    triangles: dict[int, list[tuple[Point, ...]]] = {}
    orientation: dict[int, int] = {}
    reflex: dict[int, int] = {}
    for f in cmap.faces:
        cyc = cmap.link_cycle(f)
        pts = [vertices[_sorted3((f, cyc[k], cyc[(k + 1) % len(cyc)]))] for k in range(len(cyc))]
        triangles[f], reflex[f] = triangulate(pts, q[f][:3])
        area_normal = tuple(
            sum((cross(pts[i], pts[(i + 1) % len(pts)])[k] for i in range(len(pts))), Q(0))
            for k in range(3)
        )
        orientation[f] = int(dot(area_normal, q[f][:3]) < 0)
    checks = 0
    for f, g in combinations(cmap.faces, 2):
        direction = cross(q[f][:3], q[g][:3])
        if not any(direction):
            raise ValueError("parallel face planes")
        axis = max(range(3), key=lambda k: abs(direction[k]))
        ends = sorted(vertices[_sorted3((f, g, h))][axis] for h in cmap.end_pair(f, g))
        for a in triangles[f]:
            sa = plane_slice(a, q[g], axis)
            if sa is None:
                continue
            for b in triangles[g]:
                sb = plane_slice(b, q[f], axis)
                if sb is None:
                    continue
                checks += 1
                lo, hi = max(sa[0], sb[0]), min(sa[1], sb[1])
                if lo <= hi and not ends[0] <= lo <= hi <= ends[1]:
                    raise ValueError(f"faces {f}, {g} meet outside their common edge")
    result: Mapping[str, Any] = {
        "orientation": orientation,
        "reflex": reflex,
        "triangle_pairs": checks,
        "vertices": len(vertices),
    }
    return dict(result)


def _sorted3(faces: Sequence[int]) -> tuple[int, int, int]:
    a, b, c = sorted(faces)
    return (a, b, c)
