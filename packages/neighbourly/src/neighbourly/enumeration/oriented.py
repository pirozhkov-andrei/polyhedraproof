"""Orientable neighbourly maps on `n` faces, enumerated and grouped into classes.

THE FORMULATION (paper: lem:oriented).  Dualizing, a neighbourly map on `n` faces is a
triangulation of a closed surface with `n` vertices in which every pair is an edge, and
only the orientable ones embed in `R^3`.  An ORIENTABLE such triangulation is exactly a
set of oriented triples covering every ORDERED pair `(a,b)`, `a != b`, exactly once,
whose every vertex link -- the permutation `b -> c` given by the triangles `(v,b,c)` --
is a single `(n-1)`-cycle.  Orientability is then automatic instead of being tested
afterwards, which is what makes the search finish.

Fixing the link of vertex 0 to be `1 -> 2 -> ... -> n-1 -> 1` costs nothing: every
isomorphism class has such a representative, and the count of representatives is
`2n(n-1)/|Aut|` per class (paper: lem:framing), which the run checks per class.  That
is a consistency check, not an independent guarantee against correlated enumeration and
canonicalization errors.

The search is generic: it accepts any integer `n >= 4` and returns an empty list when no
orientable map exists (for example `n = 10`, where the search runs and finds none).  A count
reproduced for some `n` is a computation for that `n`, not a statement about others.  The
twelve-face census and its comparison with the shipped matrices are
:mod:`neighbourly.corpus12`; this module reads no data.
"""

from __future__ import annotations

import itertools
import time
from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from functools import cache
from typing import Any

from neighbourly.maps import CombinatorialMap, MapError, Triple, sorted_triple

__all__ = [
    "SMALL_REFERENCE_COUNTS",
    "EnumerationResult",
    "SearchStatistics",
    "canonical",
    "canonical_map",
    "classes_of",
    "enumerate_classes",
    "enumerate_oriented",
    "link_cycle",
]

#: `(labelled maps, classes)` this search finds for small `n`; they are
#: regression references for those `n` only (`n = 10`: none exists).
SMALL_REFERENCE_COUNTS: Mapping[int, tuple[int, int]] = {4: (1, 1), 7: (2, 1), 10: (0, 0)}


def _check_n(n: object) -> int:
    if type(n) is not int or n < 4:
        raise MapError("n must be an integer of at least 4")
    return n


# -- the search -----------------------------------------------------------------------------


@dataclass
class SearchStatistics:
    """How much a search did: `nodes` counts the calls of the recursive step (0 when `3`
    does not divide `n(n-1)` and nothing is searched)."""

    nodes: int = 0


def enumerate_oriented(
    n: int, statistics: SearchStatistics | None = None
) -> list[tuple[Triple, ...]]:
    """Every orientable neighbourly map on `n` vertices with `link(0) = (1,...,n-1)`.

    No residue rule is applied: whenever `3` divides `n(n-1)` the search runs, so an empty
    answer (as for `n = 10`) is its result, not an assumption.
    """
    _check_n(n)
    if n * (n - 1) % 3:
        return []
    full = (1 << n) - 1
    outgoing = [0] * n  # outgoing[a]: bitmask of b with the ordered pair (a,b) used
    incoming = [0] * n  # incoming[a]: bitmask of c with the ordered pair (c,a) used
    successor = [[-1] * n for _ in range(n)]
    predecessor = [[-1] * n for _ in range(n)]
    degree = [0] * n
    needed = n * (n - 1) // 3
    placed: list[Triple] = []
    found: list[tuple[Triple, ...]] = []

    def link_ok(v: int, a: int, b: int) -> bool:
        if a == b or successor[v][a] != -1 or predecessor[v][b] != -1:
            return False
        if degree[v] < n - 2:  # a link cycle may close only on the last triangle
            x = b
            while x != -1:
                if x == a:
                    return False
                x = successor[v][x]
        return True

    def place(a: int, b: int, c: int) -> bool:
        rotations = ((a, b, c), (b, c, a), (c, a, b))
        for position, (v, p, q) in enumerate(rotations):
            if not link_ok(v, p, q):
                for v2, p2, q2 in rotations[:position]:
                    successor[v2][p2] = -1
                    predecessor[v2][q2] = -1
                    degree[v2] -= 1
                return False
            successor[v][p] = q
            predecessor[v][q] = p
            degree[v] += 1
        outgoing[a] |= 1 << b
        outgoing[b] |= 1 << c
        outgoing[c] |= 1 << a
        incoming[b] |= 1 << a
        incoming[c] |= 1 << b
        incoming[a] |= 1 << c
        placed.append((a, b, c))
        return True

    def unplace(a: int, b: int, c: int) -> None:
        placed.pop()
        outgoing[a] &= ~(1 << b)
        outgoing[b] &= ~(1 << c)
        outgoing[c] &= ~(1 << a)
        incoming[b] &= ~(1 << a)
        incoming[c] &= ~(1 << b)
        incoming[a] &= ~(1 << c)
        for v, p, q in ((c, a, b), (b, c, a), (a, b, c)):
            successor[v][p] = -1
            predecessor[v][q] = -1
            degree[v] -= 1

    def search() -> None:
        if statistics is not None:
            statistics.nodes += 1
        if len(placed) == needed:
            found.append(tuple(sorted(sorted_triple(t) for t in placed)))
            return
        best = n + 1
        best_a = best_b = -1
        best_mask = 0
        for a in range(n):
            free = full & ~outgoing[a] & ~(1 << a)
            while free:
                b = (free & -free).bit_length() - 1
                free &= free - 1
                mask = full & ~outgoing[b] & ~incoming[a] & ~(1 << a) & ~(1 << b)
                options = mask.bit_count()
                if options < best:
                    best, best_a, best_b, best_mask = options, a, b, mask
                    if options == 0:
                        return
        if best_a < 0:
            return
        while best_mask:
            c = (best_mask & -best_mask).bit_length() - 1
            best_mask &= best_mask - 1
            if place(best_a, best_b, c):
                search()
                unplace(best_a, best_b, c)

    for i in range(1, n - 1):
        if not place(0, i, i + 1):
            return []
    if not place(0, n - 1, 1):
        return []
    search()
    return found


# -- isomorphism ----------------------------------------------------------------------------


def link_cycle(triples: list[Triple], vertex: int, n: int) -> list[int]:
    """The neighbours of `vertex` in cyclic order, on a zero-based triple list."""
    neighbours: dict[int, list[int]] = {u: [] for u in range(n) if u != vertex}
    for triple in triples:
        if vertex not in triple:
            continue
        a, b = (x for x in triple if x != vertex)
        neighbours[a].append(b)
        neighbours[b].append(a)
    start = min(neighbours)
    cycle = [start, neighbours[start][0]]
    while len(cycle) < n - 1:
        cycle.append(next(x for x in neighbours[cycle[-1]] if x != cycle[-2]))
    return cycle


@cache
def _triple_bits(n: int) -> tuple[list[list[list[int]]], list[tuple[Triple, int]]]:
    """A bit per unordered triple, ordered so that a larger integer is lexicographically earlier."""
    triples: list[Triple] = list(itertools.combinations(range(n), 3))
    lookup = [[[0] * n for _ in range(n)] for _ in range(n)]
    entries: list[tuple[Triple, int]] = []
    for rank, triple in enumerate(triples):
        bit = 1 << (len(triples) - rank - 1)
        entries.append((triple, bit))
        for a, b, c in itertools.permutations(triple):
            lookup[a][b][c] = bit
    return lookup, entries


def canonical(triples: list[Triple], n: int) -> tuple[tuple[Triple, ...], int]:
    """The lexicographically least normalized link framing, and `|Aut|`.

    An isomorphism is pinned by the image of one vertex and the rotation or reflection it
    induces on that vertex's link, so `2n(n-1)` framings exhaust the possibilities -- 264
    for twelve.  The number of framings that reproduce the least image IS the order of
    the automorphism group.
    """
    lookup, entries = _triple_bits(n)
    best = -1
    automorphisms = 0
    for vertex in range(n):
        cycle = link_cycle(triples, vertex, n)
        length = len(cycle)
        for rotation in range(length):
            for direction in (1, -1):
                relabel = [0] * n
                for offset in range(length):
                    relabel[cycle[(rotation + direction * offset) % length]] = offset + 1
                image = 0
                for a, b, c in triples:
                    image |= lookup[relabel[a]][relabel[b]][relabel[c]]
                if image > best:
                    best, automorphisms = image, 1
                elif image == best:
                    automorphisms += 1
    return tuple(triple for triple, bit in entries if best & bit), automorphisms


def canonical_map(cmap: CombinatorialMap) -> tuple[Triple, ...]:
    """The canonical form of a map with faces `1..n` (as zero-based triples)."""
    form, _ = canonical([(a - 1, b - 1, c - 1) for a, b, c in sorted(cmap.triples)], cmap.n)
    return form


def classes_of(
    maps: Iterable[tuple[str, CombinatorialMap]], n: int
) -> dict[tuple[Triple, ...], str]:
    """The canonical form of every named map with `n` faces; others are skipped.

    Two isomorphic maps are an error: a reference list must name each class once.
    """
    classes: dict[tuple[Triple, ...], str] = {}
    for name, cmap in maps:
        if cmap.n != n:
            continue
        form = canonical_map(cmap)
        if form in classes:
            raise MapError(f"{name} is isomorphic to {classes[form]}")
        classes[form] = name
    return classes


# -- the result -----------------------------------------------------------------------------


@dataclass
class EnumerationResult:
    """What one run of the enumeration found, and whether it agrees with a reference."""

    n: int
    labelled: int
    classes: dict[tuple[Triple, ...], tuple[int, int]]
    orbit_count: int
    seconds: float
    reference_compared: bool
    reference_matches: bool | None
    expected: tuple[int, int] | None
    orbit_identity_holds: bool
    problems: list[str] = field(default_factory=list)
    #: Recursive steps of the search (diagnostic; not part of :meth:`summary`).
    search_nodes: int = 0

    @property
    def class_count(self) -> int:
        return len(self.classes)

    @property
    def automorphism_histogram(self) -> dict[int, int]:
        return dict(sorted(Counter(order for _, order in self.classes.values()).items()))

    @property
    def passed(self) -> bool:
        return not self.problems

    def summary(self) -> dict[str, Any]:
        """The result as JSON-ready data (classes in canonical order)."""
        return {
            "n": self.n,
            "passed": self.passed,
            "compared_corpus": self.reference_compared,
            "labelled_count": self.labelled,
            "class_count": self.class_count,
            "orbit_count": self.orbit_count,
            "arithmetic": "exact integers",
            "problems": self.problems,
            "classes": [
                {
                    "triples": [list(t) for t in form],
                    "multiplicity": count,
                    "automorphisms": order,
                }
                for form, (count, order) in sorted(self.classes.items())
            ],
        }


def enumerate_classes(
    n: int,
    expected: tuple[int, int] | None = None,
    reference: Mapping[tuple[Triple, ...], str] | None = None,
) -> EnumerationResult:
    """Run the search, group into isomorphism classes, and check what can be checked.

    Always checked: the orbit identity. With `expected`, the `(labelled, classes)` counts;
    with `reference` (canonical forms, as :func:`classes_of` returns them), that the classes
    found are exactly the reference's and that the reference is not empty.
    """
    _check_n(n)
    started = time.time()
    statistics = SearchStatistics()
    labelled = enumerate_oriented(n, statistics)
    classes: dict[tuple[Triple, ...], tuple[int, int]] = {}
    for solution in labelled:
        form, automorphisms = canonical(list(solution), n)
        count, _ = classes.get(form, (0, automorphisms))
        classes[form] = (count + 1, automorphisms)
    framings = 2 * n * (n - 1)
    orbit_count = sum(framings // order for _, order in classes.values())
    problems: list[str] = []
    orbit_identity = orbit_count == len(labelled) and all(
        framings % order == 0 and count == framings // order for count, order in classes.values()
    )
    if not orbit_identity:
        problems.append("the orbit identity sum 2n(n-1)/|Aut| does not reproduce the count")
    if expected is not None and (len(labelled), len(classes)) != expected:
        problems.append(
            f"expected {expected} labelled maps and classes, got {(len(labelled), len(classes))}"
        )
    reference_matches: bool | None = None
    if reference is not None:
        reference_matches = bool(reference) and set(reference) == set(classes)
        if not reference_matches:
            problems.append(
                f"the reference holds {len(reference)} maps with n = {n}; "
                f"the search found {len(classes)} classes and they do not agree"
            )
    return EnumerationResult(
        n=n,
        labelled=len(labelled),
        classes=classes,
        orbit_count=orbit_count,
        seconds=round(time.time() - started, 3),
        reference_compared=reference is not None,
        reference_matches=reference_matches,
        expected=expected,
        orbit_identity_holds=orbit_identity,
        problems=problems,
        search_nodes=statistics.nodes,
    )
