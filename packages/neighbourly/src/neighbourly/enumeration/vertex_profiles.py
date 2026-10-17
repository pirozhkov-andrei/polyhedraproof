"""At most one reflex corner (paper: lem:onereflex), by enumeration (paper: rem:octants).

What a vertex of an embedded polyhedron can look like locally.

Three planes in general position cut a neighbourhood of their common point into 8
octants (the sign vectors of the three linear forms) and 12 quadrants (a plane with the
signs of the other two forms fixed).  A local solid is a set `S` of octants; the surface
is the set of quadrants separating `S` from its complement.  For `S` to be the local
picture of an embedded polyhedron whose vertex carries exactly the three faces:

  * every ray carries 0 or 2 boundary quadrants -- the boundary is a surface, not a book;
  * the boundary is one closed curve, not two;
  * each plane carries one connected sector, bounded by ONE ray of each of the two lines
    in it.  A sector bounded by two rays of the SAME line is a half-plane, which would
    mean the two edges at the vertex are opposite rays of one line: impossible, and it is
    exactly the case that has to be excluded by hand.

The corner is reflex when its sector is three quadrants rather than one.  The answer is
that only `(1,1,1)` and `(1,1,3)` occur, so a vertex has at most one reflex corner --
which is (paper: lem:onereflex), the statement the vertex clauses of Layer I encode
(paper: lem:I).
"""

from __future__ import annotations

import itertools
from collections import Counter

__all__ = [
    "ADMISSIBLE_PROFILES",
    "OCTANTS",
    "QUADRANTS",
    "RAYS",
    "admissible_profiles",
    "at_most_one_reflex_corner",
    "profile",
]

Octant = tuple[int, int, int]
Quadrant = tuple[int, int, int]  # (plane, sign, sign) of the other two forms
Ray = tuple[int, int, int]  # (plane, plane, sign) of the remaining form

OCTANTS: list[Octant] = [(a, b, c) for a in (0, 1) for b in (0, 1) for c in (0, 1)]
QUADRANTS: list[Quadrant] = [(i, a, b) for i in range(3) for a in (0, 1) for b in (0, 1)]
RAYS: list[Ray] = [(i, j, c) for i, j in itertools.combinations(range(3), 2) for c in (0, 1)]

#: The only local pictures an embedded polyhedron's trivalent vertex can have.
ADMISSIBLE_PROFILES = {(1, 1, 1), (1, 1, 3)}


def _others(plane: int) -> list[int]:
    return [x for x in range(3) if x != plane]


def _sides(quadrant: Quadrant) -> tuple[Octant, Octant]:
    """The two octants a quadrant separates."""
    plane, a, b = quadrant
    j, k = _others(plane)
    low, high = [0, 0, 0], [0, 0, 0]
    low[j], low[k] = a, b
    high[j], high[k] = a, b
    low[plane], high[plane] = 0, 1
    return (low[0], low[1], low[2]), (high[0], high[1], high[2])


def _ray_quadrants(ray: Ray) -> list[Quadrant]:
    """The four quadrants meeting one ray."""
    i, j, c = ray
    k = next(x for x in range(3) if x not in (i, j))
    out: list[Quadrant] = []
    for plane, other in ((i, j), (j, i)):
        for sign in (0, 1):
            signs = [0, 0, 0]
            signs[other], signs[k] = sign, c
            first, second = _others(plane)
            out.append((plane, signs[first], signs[second]))
    return out


def profile(octants: list[Octant]) -> tuple[int, ...] | None:
    """The quadrant counts of the three corners, or `None` if `S` is not admissible."""
    solid = set(octants)
    boundary = {q for q in QUADRANTS if (_sides(q)[0] in solid) != (_sides(q)[1] in solid)}
    if not boundary or len({q[0] for q in boundary}) != 3:
        return None
    for ray in RAYS:
        if len([q for q in _ray_quadrants(ray) if q in boundary]) not in (0, 2):
            return None
    adjacency: dict[Quadrant, set[Quadrant]] = {q: set() for q in boundary}
    for ray in RAYS:
        touching = [q for q in _ray_quadrants(ray) if q in boundary]
        if len(touching) == 2:
            adjacency[touching[0]].add(touching[1])
            adjacency[touching[1]].add(touching[0])
    seen: set[Quadrant] = set()
    stack = [next(iter(boundary))]
    while stack:
        current = stack.pop()
        if current in seen:
            continue
        seen.add(current)
        stack.extend(adjacency[current] - seen)
    if seen != boundary:
        return None
    for plane in range(3):
        ends = [
            ray
            for ray in RAYS
            if plane in ray[:2]
            and len([q for q in _ray_quadrants(ray) if q in boundary and q[0] == plane]) == 1
        ]
        if len(ends) != 2 or {next(iter(set(ray[:2]) - {plane})) for ray in ends} != set(
            _others(plane)
        ):
            return None
    return tuple(sorted(Counter(q[0] for q in boundary).values()))


def admissible_profiles() -> Counter[tuple[int, ...]]:
    """All 256 octant sets enumerated; the admissible ones counted by profile.

    The result is 16 sets with profile `(1,1,1)` and 48 with `(1,1,3)`; inadmissible sets
    are not counted.
    """
    seen: Counter[tuple[int, ...]] = Counter()
    for mask in range(1 << len(OCTANTS)):
        found = profile([OCTANTS[t] for t in range(8) if (mask >> t) & 1])
        if found:
            seen[found] += 1
    return seen


def at_most_one_reflex_corner() -> bool:
    """No admissible vertex has two reflex corners (paper: lem:onereflex, rem:octants)."""
    profiles = admissible_profiles()
    return set(profiles) == ADMISSIBLE_PROFILES and all(
        sum(1 for count in found if count == 3) <= 1 for found in profiles
    )
