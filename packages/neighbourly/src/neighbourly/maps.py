"""Neighbourly combinatorial maps and their deterministic boundary cycles (paper: def:map).

A neighbourly map on ``n`` faces is given by its real vertices, each a set of three faces.
:class:`CombinatorialMap` validates the structural domain of such a map for any integer
``n >= 4``: ``3`` divides ``n(n-1)``, there are ``n(n-1)/3`` distinct vertices, every pair
of faces has exactly two distinct end faces, and every face link is a single
``(n-1)``-cycle. Orientability is a query (:meth:`CombinatorialMap.is_orientable`), not a
condition of the type: the encoder entry point decides which maps it accepts.

The cycle and end-pair conventions are fixed: the formula bytes depend on them.
"""

from __future__ import annotations

import itertools
from collections.abc import Iterable, Sequence
from pathlib import Path

#: Three faces in increasing order.
Triple = tuple[int, int, int]

__all__ = ["CombinatorialMap", "MapError", "Triple", "sorted_triple"]


class MapError(ValueError):
    """The input is not a neighbourly map, or a query names something the map lacks."""


def sorted_triple(faces: Iterable[int]) -> Triple:
    """The three faces in increasing order, as a triple of fixed width."""
    a, b, c = sorted(faces)
    return (a, b, c)


def _sorted_pair(faces: Iterable[int]) -> tuple[int, int]:
    """The two faces in increasing order, as a pair of fixed width."""
    a, b = sorted(faces)
    return (a, b)


class CombinatorialMap:
    """A neighbourly map on `n` faces, given by its real vertices.

    Faces are numbered `1..n`; `0` is reserved for the plane at infinity in the encoder.
    `end_pair(i, j)` is the pair `{k, l}` such that `{i,j,k}` and `{i,j,l}` are real
    vertices: the two endpoints of the edge `E(i,j)`.  A triple that is not a real vertex
    is *virtual* -- the three planes still meet at a point, but that point is not a vertex
    of the surface.
    """

    __slots__ = ("_ends", "_link_cycles", "faces", "n", "triples")

    def __init__(self, n: int, triples: Iterable[Sequence[int]]) -> None:
        if type(n) is not int or n < 4:
            raise MapError("n must be an integer of at least 4")
        rows = [tuple(t) for t in triples]
        for row in rows:
            if len(row) != 3 or any(type(x) is not int for x in row) or len(set(row)) != 3:
                raise MapError(f"a vertex must contain three distinct integer faces: {row}")
        self.n = n
        self.faces: tuple[int, ...] = tuple(range(1, n + 1))
        self.triples: frozenset[Triple] = frozenset(sorted_triple(row) for row in rows)
        if len(self.triples) != len(rows):
            raise MapError("duplicate vertex triples")
        self._validate()
        self._ends: dict[tuple[int, int], tuple[int, int]] = {
            pair: _sorted_pair(thirds) for pair, thirds in self._pair_thirds().items()
        }
        self._link_cycles: dict[int, list[int]] = {}

    # -- construction -------------------------------------------------------------------

    @classmethod
    def from_matrix(cls, matrix: Sequence[Sequence[int]]) -> CombinatorialMap:
        """Build from a vertex-by-face incidence matrix of zeros and ones."""
        if not matrix:
            raise MapError("empty incidence matrix")
        n = len(matrix[0])
        triples: list[Triple] = []
        for r, row in enumerate(matrix):
            if len(row) != n:
                raise MapError(f"row {r}: expected {n} entries, got {len(row)}")
            if any(x not in (0, 1) for x in row):
                raise MapError(f"row {r}: entries must be 0 or 1")
            ones = [i + 1 for i, x in enumerate(row) if x]
            if len(ones) != 3:
                raise MapError(f"row {r}: expected exactly three 1s, got {len(ones)}")
            triples.append((ones[0], ones[1], ones[2]))
        return cls(n, triples)

    @classmethod
    def from_text(cls, text: str, source: str = "<text>") -> CombinatorialMap:
        """Read an incidence matrix; `#` starts a comment, commas count as spaces."""
        rows: list[list[int]] = []
        for number, raw in enumerate(text.splitlines(), 1):
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            try:
                rows.append([int(token) for token in line.replace(",", " ").split()])
            except ValueError as exc:
                raise MapError(f"{source}:{number}: expected integers, got {raw!r}") from exc
        return cls.from_matrix(rows)

    @classmethod
    def from_file(cls, path: str | Path) -> CombinatorialMap:
        """:meth:`from_text` on a UTF-8 file."""
        return cls.from_text(Path(path).read_text(encoding="utf-8"), str(path))

    # -- validation ---------------------------------------------------------------------

    def _pair_thirds(self) -> dict[tuple[int, int], list[int]]:
        """For every face pair, the third faces of the real vertices containing it."""
        thirds: dict[tuple[int, int], list[int]] = {}
        for triple in self.triples:
            for pair in itertools.combinations(triple, 2):
                thirds.setdefault(pair, []).append(next(x for x in triple if x not in pair))
        return thirds

    def _validate(self) -> None:
        """A closed surface every one of whose face links is a single `(n-1)`-cycle."""
        self._validate_counts()
        thirds = self._pair_thirds()
        expected_pairs = self.n * (self.n - 1) // 2
        if len(thirds) != expected_pairs:
            raise MapError(
                f"{len(thirds)} face pairs occur, expected {expected_pairs}: "
                "the map is not neighbourly"
            )
        for pair, ends in thirds.items():
            if len(ends) != 2 or ends[0] == ends[1]:
                raise MapError(f"pair {pair} has ends {ends}; expected exactly two distinct")
        for face in self.faces:
            self._validate_link(face)

    def _validate_counts(self) -> None:
        n = self.n
        if n * (n - 1) % 3:
            raise MapError(f"n = {n} admits no neighbourly map: 3 does not divide n(n-1)")
        expected_vertices = n * (n - 1) // 3
        if len(self.triples) != expected_vertices:
            raise MapError(f"expected {expected_vertices} real vertices, got {len(self.triples)}")
        for triple in self.triples:
            if any(not 1 <= x <= n for x in triple):
                raise MapError(f"face index out of range in {triple}")

    def _validate_link(self, face: int) -> None:
        """The other faces around one face must form a single cycle."""
        neighbours: dict[int, set[int]] = {u: set() for u in self.faces if u != face}
        containing = [t for t in self.triples if face in t]
        if len(containing) != self.n - 1:
            raise MapError(f"face {face}: {len(containing)} vertices, expected {self.n - 1}")
        for triple in containing:
            a, b = (x for x in triple if x != face)
            neighbours[a].add(b)
            neighbours[b].add(a)
        if any(len(v) != 2 for v in neighbours.values()):
            raise MapError(f"face {face}: link is not 2-regular")
        start = next(iter(neighbours))
        seen: set[int] = set()
        stack = [start]
        while stack:
            current = stack.pop()
            if current in seen:
                continue
            seen.add(current)
            stack.extend(neighbours[current] - seen)
        if len(seen) != self.n - 1:
            raise MapError(f"face {face}: link is not a single {self.n - 1}-cycle")

    def is_orientable(self) -> bool:
        """A closed non-orientable surface does not embed in R^3, so this is a free filter."""
        triples = sorted(self.triples)

        def directed(triple: Triple, sign: int) -> list[tuple[int, int]]:
            a, b, c = triple
            return [(a, b), (b, c), (c, a)] if sign > 0 else [(c, b), (b, a), (a, c)]

        incident: dict[tuple[int, int], list[int]] = {}
        for index, triple in enumerate(triples):
            for edge in itertools.combinations(triple, 2):
                incident.setdefault(edge, []).append(index)
        sign = {0: 1}
        stack = [0]
        while stack:
            index = stack.pop()
            oriented = set(directed(triples[index], sign[index]))
            for edge in itertools.combinations(triples[index], 2):
                a, b = edge
                here = (a, b) if (a, b) in oriented else (b, a)
                want = (here[1], here[0])
                for other in incident[edge]:
                    if other == index:
                        continue
                    other_sign = 1 if want in directed(triples[other], 1) else -1
                    if other in sign:
                        if sign[other] != other_sign:
                            return False
                    else:
                        sign[other] = other_sign
                        stack.append(other)
        return len(sign) == len(triples)

    @property
    def euler_characteristic(self) -> int:
        """`V - E + F` of the surface: `n(n-1)/3 - n(n-1)/2 + n`."""
        return len(self.triples) - self.n * (self.n - 1) // 2 + self.n

    # -- queries ------------------------------------------------------------------------

    def is_real(self, a: int, b: int, c: int) -> bool:
        """Is `{a,b,c}` a real vertex of the surface?"""
        return tuple(sorted((a, b, c))) in self.triples

    def link_cycle(self, face: int) -> list[int]:
        """The other faces in the cyclic order they occur around `face`.

        The starting point and direction are pinned to the smallest neighbour and its
        smallest neighbour, so the cycle never depends on set iteration order and the
        formula stays byte-identical between runs and machines.
        """
        cached = self._link_cycles.get(face)
        if cached is not None:
            return list(cached)
        neighbours: dict[int, list[int]] = {u: [] for u in self.faces if u != face}
        for triple in self.triples:
            if face not in triple:
                continue
            a, b = (x for x in triple if x != face)
            neighbours[a].append(b)
            neighbours[b].append(a)
        start = min(neighbours)
        cycle = [start, min(neighbours[start])]
        while len(cycle) < self.n - 1:
            cycle.append(next(x for x in neighbours[cycle[-1]] if x != cycle[-2]))
        self._link_cycles[face] = cycle
        return list(cycle)

    def link_successor(self, face: int) -> dict[int, int]:
        """`a -> b` for faces consecutive in the link cycle of `face`."""
        cycle = self.link_cycle(face)
        return {cycle[i]: cycle[(i + 1) % len(cycle)] for i in range(len(cycle))}

    def end_pair(self, i: int, j: int) -> tuple[int, int]:
        """The two faces whose vertices with `i, j` bound the edge `E(i,j)`."""
        try:
            return self._ends[(min(i, j), max(i, j))]
        except KeyError:
            raise MapError(f"faces {i} and {j} share no edge") from None

    def far_end(self, face: int, other: int, near: int) -> int:
        """The face `x` with `Ends(face, other) = {near, x}`.

        `P_{face,other,x}` is the endpoint of `E(face,other)` not shared with `E(face,near)`.
        """
        a, b = self.end_pair(face, other)
        if near == a:
            return b
        if near == b:
            return a
        raise MapError(f"{near} is not an end of E({face},{other})")
