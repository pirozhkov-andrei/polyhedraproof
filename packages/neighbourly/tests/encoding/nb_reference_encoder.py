"""A second encoder of the formula: layers S, H, A, B, I and the gauge (standard library only).

Maps are read by :meth:`MapSpec.from_text`, so that the packaged matrices can be read.  It
imports nothing from ``neighbourly``.

Provenance.  It was written separately from the production encoder; it is not a referee's
check of the mathematics.  What it encodes corresponds to S (paper: thm:order), H and A
(paper: lem:cutorder, thm:chirotope), B (paper: def:onb, lem:B), I (paper: lem:turn, lem:sf,
lem:onereflex, lem:parity, lem:I) and the gauge (paper: lem:gaugegroup, cor:gauge).

What is separate and what is shared.  Its implementation is its own: map reader, link
walks, truth-table CNF builder and gauge rank test.  Its conventions are deliberately the
production encoder's -- the order in which variables are allocated, the chaining of long
XORs into three-input links, the start and direction of each link cycle, `z1` as the
larger end in the orientation equation, the cut point `r_b`, and the order in which gauge
candidates are tried -- so that the two clause multisets can be compared literally.  Only
clause order is not shared: XOR clauses are derived by enumerating variable assignments.
The comparison therefore checks the production encoder against a second implementation;
it cannot catch an error in a shared convention or in the theory both follow, and it
does not prove the geometric lemmas or the 59-map classification.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from fractions import Fraction
from itertools import combinations, permutations, product

Subset = tuple[int, ...]
Clause = tuple[int, ...]


def literal_value(literal: int, values: Mapping[int, int]) -> int:
    return int(bool(values[abs(literal)]) != (literal < 0))


def clause_bag(clauses: Iterable[Sequence[int]]) -> Counter[Clause]:
    """Preserve duplicate-clause multiplicity; ignore only literal/row ordering."""
    return Counter(tuple(sorted(set(row))) for row in clauses)


class MapSpec:
    """Read the incidence relation and derive ends and boundary walks separately.

    The walk start and direction deliberately follow `CombinatorialMap.link_cycle` (least
    label first, then the lexicographically least walk), so that literals line up.
    """

    def __init__(self, n: int, vertices: Iterable[Iterable[int]]) -> None:
        self.n = n
        self.faces = tuple(range(1, n + 1))
        rows = [frozenset(row) for row in vertices]
        if n < 4 or len(set(rows)) != len(rows):
            raise ValueError("bad size or repeated vertex")
        if any(len(row) != 3 or not row <= set(self.faces) for row in rows):
            raise ValueError("vertex must have three distinct face labels")
        self.triples: frozenset[Subset] = frozenset(tuple(sorted(row)) for row in rows)
        self.ends: dict[tuple[int, int], tuple[int, int]] = {}
        for i, j in combinations(self.faces, 2):
            ends = tuple(k for k in self.faces if frozenset((i, j, k)) in rows and k not in (i, j))
            if len(ends) != 2:
                raise ValueError("every pair must have exactly two ends")
            self.ends[i, j] = (ends[0], ends[1])
        self.cycles: dict[int, tuple[int, ...]] = {}
        for f in self.faces:
            rest = [a for a in self.faces if a != f]
            neighbors = {a: [b for b in rest if b != a and self.real(f, a, b)] for a in rest}
            if any(len(adj) != 2 for adj in neighbors.values()):
                raise ValueError("link must have degree two")
            # Two possible walks start at the least label; take lexicographically least.
            walks = []
            for second in neighbors[rest[0]]:
                walk = [rest[0], second]
                while True:
                    (following,) = [x for x in neighbors[walk[-1]] if x != walk[-2]]
                    if following == walk[0]:
                        break
                    if following in walk:
                        raise ValueError("link walk repeats")
                    walk.append(following)
                if len(walk) != n - 1:
                    raise ValueError("disconnected link")
                walks.append(tuple(walk))
            self.cycles[f] = min(walks)

    @classmethod
    def from_text(cls, text: str) -> MapSpec:
        """An incidence matrix (one row per vertex, one 0/1 column per face)."""
        matrix = []
        for raw in text.splitlines():
            line = raw.partition("#")[0].replace(",", " ").strip()
            if line:
                matrix.append([int(x) for x in line.split()])
        if not matrix or any(len(row) != len(matrix[0]) for row in matrix):
            raise ValueError("empty or ragged incidence matrix")
        if any(x not in (0, 1) for row in matrix for x in row):
            raise ValueError("incidence entries must be Boolean")
        return cls(len(matrix[0]), [[i + 1 for i, x in enumerate(row) if x] for row in matrix])

    def real(self, *triple: int) -> bool:
        return tuple(sorted(triple)) in self.triples

    def end_pair(self, a: int, b: int) -> tuple[int, int]:
        return self.ends[min(a, b), max(a, b)]

    def far(self, a: int, b: int, near: int) -> int:
        ends = self.end_pair(a, b)
        if near not in ends:
            raise ValueError("not an endpoint")
        return next(v for v in ends if v != near)

    def link_cycle(self, face: int) -> list[int]:
        return list(self.cycles[face])


class TruthCNF:
    """Truth-table CNF builder, written separately from the production CNF builder.

    It chains long XORs the same way (three inputs per link variable, link placed first) so
    that clauses match literally, and keeps a defining evaluation program.
    """

    def __init__(self) -> None:
        self.nvars = 0
        self.clauses: list[Clause] = []
        self.program: list[tuple[int, str, tuple[int, ...]]] = []
        self.layer = "brackets"
        self.layers: list[str] = []

    def variable(self) -> int:
        self.nvars += 1
        return self.nvars

    def clause(self, *literals: int) -> None:
        row = set(literals)
        if not any(-v in row for v in row):
            self.clauses.append(tuple(sorted(row)))
            self.layers.append(self.layer)

    def small_parity(self, literals: Sequence[int], rhs: int) -> None:
        # Enumerate assignments to distinct VARIABLES, then test the signed law.
        variables = sorted(set(map(abs, literals)))
        for bits in product((0, 1), repeat=len(variables)):
            values = dict(zip(variables, bits))
            if sum(literal_value(lit, values) for lit in literals) % 2 != rhs:
                self.clause(*(v if bit == 0 else -v for v, bit in zip(variables, bits)))

    def parity(self, literals: Iterable[int], rhs: int = 0) -> None:
        pending = tuple(literals)
        while len(pending) > 4:
            segment, pending = pending[:3], pending[3:]
            link = self.variable()
            self.program.append((link, "xor", segment))
            self.small_parity((*segment, link), 0)
            pending = (link, *pending)
        self.small_parity(pending, rhs)

    def xor(self, literals: Iterable[int]) -> int:
        inputs = tuple(literals)
        if len(inputs) == 1:
            return inputs[0]
        output = self.variable()
        self.program.append((output, "xor", inputs))
        self.parity((*inputs, output))
        return output

    def conjunction(self, a: int, b: int) -> int:
        output = self.variable()
        self.program.append((output, "and", (a, b)))
        # y -> a, y -> b, and (a and b) -> y.
        self.clause(a, -output)
        self.clause(b, -output)
        self.clause(-a, -b, output)
        return output

    def evaluate(self, initial: Mapping[int, int]) -> dict[int, int]:
        values = dict(initial)
        for output, kind, inputs in self.program:
            bits = [literal_value(lit, values) for lit in inputs]
            values[output] = sum(bits) % 2 if kind == "xor" else int(all(bits))
        if set(values) != set(range(1, self.nvars + 1)):
            raise ValueError("incomplete witness")
        return values


class ReferenceEncoder:
    def __init__(self, spec: MapSpec) -> None:
        self.map = spec
        self.cnf = TruthCNF()
        self.brackets: dict[Subset, int] = {
            s: self.cnf.variable() for s in combinations(range(spec.n + 1), 4)
        }
        self.orders: dict[tuple[Subset, Subset], int] = {}
        self.cuts: dict[tuple[int, int], dict[tuple[int, int], int]] = {}
        self.on_boundary: dict[Subset, int] = {}
        self.orientation: dict[int, int] = {}
        self.corners: dict[tuple[int, Subset], int] = {}
        self.rays: dict[int, tuple[int, int, int, tuple[int, ...]]] = {}
        self.gauge: list[Subset] = []

    def bracket(self, *ordered: int) -> int:
        # Sorting by adjacent swaps fixes the alternating sign, independently of the
        # production permutation_parity.
        data = list(ordered)
        sign = 1
        for end in range(len(data), 1, -1):
            for i in range(end - 1):
                if data[i] > data[i + 1]:
                    data[i], data[i + 1] = data[i + 1], data[i]
                    sign = -sign
        return sign * self.brackets[tuple(data)]

    def order(self, i: int, j: int, k: int, l: int) -> int:
        return (-1 if (i > j) != (k > l) else 1) * self.orders[
            tuple(sorted((i, j))), tuple(sorted((k, l)))
        ]

    def onb(self, f: int, w: int, u: int) -> int:
        key = (*sorted((f, w)), u)
        if key not in self.on_boundary:
            a, b, _ = key
            z0, z1 = self.map.end_pair(a, b)
            self.on_boundary[key] = self.cnf.xor((self.order(a, b, u, z0), self.order(a, b, u, z1)))
        return self.on_boundary[key]

    def corner(self, f: int, a: int, b: int) -> int:
        return self.corners[f, tuple(sorted((a, b)))]

    def build(self, gauge_face: int | None = 1) -> ReferenceEncoder:
        m, c = self.map, self.cnf
        c.layer = "S"
        for i, j in combinations(m.faces, 2):
            for k, l in combinations([x for x in m.faces if x not in (i, j)], 2):
                self.orders[(i, j), (k, l)] = c.xor(
                    (self.bracket(0, i, j, k), self.bracket(0, i, j, l), self.bracket(i, j, k, l))
                )
        c.layer = "H"
        for i, j in combinations(m.faces, 2):
            for k, l, t in combinations([x for x in m.faces if x not in (i, j)], 3):
                a, b, d = (self.order(i, j, k, l), self.order(i, j, l, t), self.order(i, j, k, t))
                c.clause(-a, -b, d)
                c.clause(a, b, -d)
        c.layer = "A"
        for f in m.faces:
            anchor, *others = [x for x in m.faces if x != f]
            row = {}
            for a, b in combinations(others, 2):
                row[a, b] = c.xor(
                    (
                        self.bracket(0, f, a, b),
                        self.bracket(0, f, anchor, a),
                        self.bracket(0, f, anchor, b),
                    )
                )
            self.cuts[f, anchor] = row
            for a, b, d in combinations(others, 3):
                c.clause(-row[a, b], -row[b, d], row[a, d])
                c.clause(row[a, b], row[b, d], -row[a, d])
        c.layer = "B"
        for f in m.faces:
            for a, b in combinations([x for x in m.faces if x != f], 2):
                if not m.real(f, a, b):
                    c.clause(-self.onb(f, a, b), -self.onb(f, b, a))
        c.layer = "I"
        for f in m.faces:
            self.orientation[f] = c.variable()
            cycle = m.cycles[f]
            for a, b in zip(cycle, cycle[1:] + cycle[:1]):
                raw = c.xor(
                    (
                        self.order(f, a, m.far(f, a, b), b),
                        self.order(f, b, a, m.far(f, b, a)),
                        self.bracket(0, f, a, b),
                        self.orientation[f],
                    )
                )
                self.corners[f, tuple(sorted((a, b)))] = -raw
        for vertex in sorted(m.triples):
            corners = [self.corner(f, *[x for x in vertex if x != f]) for f in vertex]
            for a, b in combinations(corners, 2):
                c.clause(-a, -b)
        for f in m.faces:
            g = m.cycles[f][0]
            z0, z1 = m.end_pair(f, g)
            terms = []
            for v in m.faces:
                if v not in (f, g, z0, z1):
                    beyond = c.xor((self.order(f, g, z1, z0), self.order(f, g, z1, v)))
                    terms.append(c.conjunction(self.onb(f, v, g), beyond))
            self.rays[f] = (g, z0, z1, tuple(terms))
            c.parity((*terms, self.corner(f, g, z1)))
        if gauge_face is not None:
            self.add_gauge(gauge_face)
        return self

    def add_gauge(self, face: int) -> None:
        # Separate rank decision: enumerate the linear span (at most 2**13). The candidate order
        # -- brackets through the face first, then lexicographic -- deliberately matches
        # the production gauge_targets.
        self.cnf.layer = "gauge"
        candidates = sorted(self.brackets, key=lambda s: (face not in s, s))
        span = {0}
        for s in candidates:
            functional = 1 + sum(2**i for i in s if i)
            if functional not in span:
                span |= {v ^ functional for v in span}
                self.gauge.append(s)
                self.cnf.clause(-self.brackets[s])
                if len(self.gauge) == self.map.n + 1:
                    return
        raise ValueError("gauge has deficient rank")


def determinant(matrix: Sequence[Sequence[Fraction]]) -> Fraction:
    """Leibniz formula, used by `geometry_witness`."""
    total = Fraction(0)
    for perm in permutations(range(len(matrix))):
        term = Fraction(1)
        for i, j in enumerate(perm):
            term *= matrix[i][j]
        inversions = sum(
            perm[i] > perm[j] for i in range(len(perm)) for j in range(i + 1, len(perm))
        )
        total += (-1 if inversions % 2 else 1) * term
    return total


def geometry_witness(
    reference: ReferenceEncoder, planes: Sequence[Sequence[Fraction | int | str]]
) -> tuple[dict[int, int], dict[tuple[int, Subset], int]]:
    """Bracket signs and face orientation from exact intersections and area vectors.

    No encoded order/betweenness formula is used to compute the initial witness.
    Returns per-corner cross-product reflexness as an orthogonal comparison.
    """
    q = [(Fraction(0), Fraction(0), Fraction(0), Fraction(1))] + [
        tuple(Fraction(x) for x in row) for row in planes
    ]
    values: dict[int, int] = {}
    for s, variable in reference.brackets.items():
        d = determinant([q[i] for i in s])
        if not d:
            raise ValueError("fixture is not in general position")
        values[variable] = int(d < 0)

    def point(s: Sequence[int]) -> tuple[Fraction, ...]:
        # Independent rational Gaussian elimination, no production Cramer helper.
        matrix = [[*q[i][:3], -q[i][3]] for i in s]
        for k in range(3):
            pivot = next(i for i in range(k, 3) if matrix[i][k])
            matrix[k], matrix[pivot] = matrix[pivot], matrix[k]
            divisor = matrix[k][k]
            matrix[k] = [x / divisor for x in matrix[k]]
            for i in range(3):
                if i != k:
                    factor = matrix[i][k]
                    matrix[i] = [x - factor * y for x, y in zip(matrix[i], matrix[k])]
        return tuple(matrix[i][3] for i in range(3))

    def cross(a: Sequence[Fraction], b: Sequence[Fraction]) -> tuple[Fraction, ...]:
        return tuple(
            a[(k + 1) % 3] * b[(k + 2) % 3] - a[(k + 2) % 3] * b[(k + 1) % 3] for k in range(3)
        )

    def dot(a: Sequence[Fraction], b: Sequence[Fraction]) -> Fraction:
        return sum((x * y for x, y in zip(a, b)), Fraction(0))

    reflex: dict[tuple[int, Subset], int] = {}
    for f, cycle in reference.map.cycles.items():
        pairs = list(zip(cycle, cycle[1:] + cycle[:1]))
        polygon = [point((f, a, b)) for a, b in pairs]
        area = sum(
            (dot(cross(p, r), q[f][:3]) for p, r in zip(polygon, polygon[1:] + polygon[:1])),
            Fraction(0),
        )
        if not area:
            raise ValueError("zero oriented polygon area")
        values[reference.orientation[f]] = int(area < 0)
        for i, (a, b) in enumerate(pairs):
            incoming = tuple(x - y for x, y in zip(polygon[i], polygon[i - 1]))
            outgoing = tuple(x - y for x, y in zip(polygon[(i + 1) % len(polygon)], polygon[i]))
            turn = dot(cross(incoming, outgoing), q[f][:3])
            if not turn:
                raise ValueError("straight corner")
            reflex[f, tuple(sorted((a, b)))] = int(turn * area < 0)
    return reference.cnf.evaluate(values), reflex
