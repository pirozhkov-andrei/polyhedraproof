"""The identities the encoder rests on, checked rather than argued, for any encodable map.

The self-test identity checks are generic: the map is a parameter, and the corpus
check itself stays with :mod:`neighbourly.corpus12` (it is specific to `n = 12`). Each
identity is compared against exact arithmetic or exhausted, never against a rearrangement
of itself:

- the order bits (paper: thm:order) against affine orders solved for exactly, on random
  quadruples of a random rational plane family;
- the cut-order lemma (paper: lem:cutorder, rem:counts) on every tournament with 4, 5 and 6
  elements, by cyclic triangles here and by out-degrees in
  :mod:`neighbourly.enumeration.tournaments`;
- the gauge (paper: cor:gauge) over the whole reorientation group, `2^(n+1)` elements;
- the corner bits do not depend on the order the two neighbours are named in
  (paper: lem:sf, rem:order-matters);
- Layer B constrains exactly the non-adjacent edge pairs (paper: lem:adjacency);
- Layer I has three clauses at every vertex and one bit per corner (paper: lem:I);
- the octant table (paper: lem:onereflex, rem:octants).

They are the facts that can be wrong while every formula stays well formed and every solver
keeps answering. They are finite checks for the map and seed given.
"""

from __future__ import annotations

import itertools
import random
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from fractions import Fraction

from neighbourly.encoding import PLANE_AT_INFINITY, Encoder, build_encoder
from neighbourly.enumeration.tournaments import census
from neighbourly.enumeration.vertex_profiles import admissible_profiles, at_most_one_reflex_corner
from neighbourly.exact import bracket, homogeneous_planes, oracle_from_planes
from neighbourly.geometry import line_coordinate
from neighbourly.maps import CombinatorialMap

__all__ = [
    "SAMPLES",
    "SEED",
    "Check",
    "adjacency_check",
    "corner_symmetry_check",
    "cut_order_check",
    "gauge_check",
    "identity_checks",
    "layer_i_check",
    "octant_check",
    "order_bits_check",
    "selftest_planes",
]

#: Fixed so that a failure is reproducible and a passing run means the same each time.
SEED = 20260903
#: Random quadruples of the order-bit check.
SAMPLES = 200


@dataclass(frozen=True)
class Check:
    """One named thing that either holds or does not (a self-test line)."""

    name: str
    passed: bool
    detail: str = ""

    def __str__(self) -> str:
        mark = "OK" if self.passed else "**"
        return f"  [{mark:>4}] {self.name}{'  ' + self.detail if self.detail else ''}"


def selftest_planes(n: int, seed: int = SEED) -> list[list[Fraction]]:
    """The self-test plane family: `n` planes, coefficients in -9..9, not redrawn."""
    generator = random.Random(seed)
    return [[Fraction(generator.randint(-9, 9)) for _ in range(4)] for _ in range(n)]


def identity_checks(
    cmap: CombinatorialMap,
    seed: int = SEED,
    planes: Sequence[Sequence[Fraction]] | None = None,
) -> list[Check]:
    """Every identity check for `cmap`, in a fixed order (without the corpus check).

    The order bits are checked on `planes` (`n` planes), by default the self-test family
    :func:`selftest_planes`; that family is not redrawn, so for some `n` it is degenerate
    (for example `n = 16` with the default seed), and then only the general-position check is
    returned, failed. Pass
    :func:`~neighbourly.checks.per_face.random_planes` for a family that is redrawn until it
    is in general position.
    """
    checks: list[Check] = []
    if planes is None:
        planes = selftest_planes(cmap.n, seed)
    if len(planes) != cmap.n:
        raise ValueError(f"need {cmap.n} planes, got {len(planes)}")
    oracle = oracle_from_planes(planes)
    checks.append(
        Check(
            "random planes are in general position",
            oracle.in_general_position,
            f"{len(oracle.degenerate)} degenerate 4-subsets",
        )
    )
    if not oracle.in_general_position:
        return checks
    checks.append(order_bits_check(homogeneous_planes(planes), seed))
    checks.append(cut_order_check())
    encoder = build_encoder(cmap)
    checks.extend(
        [
            gauge_check(encoder),
            corner_symmetry_check(encoder),
            adjacency_check(cmap),
            layer_i_check(encoder),
            octant_check(),
        ]
    )
    return checks


def order_bits_check(
    rows: Sequence[Sequence[Fraction]], seed: int = SEED, samples: int = SAMPLES
) -> Check:
    """The order bit is the XOR of three brackets (paper: thm:order).

    Compared against the ACTUAL affine order of the two points along the line, found by
    solving for them. `rows` are homogeneous planes with the plane at infinity first.
    """
    n = len(rows) - 1
    generator = random.Random(seed)
    wrong = 0
    for _ in range(samples):
        i, j, k, l = generator.sample(range(1, n + 1), 4)
        formula = (
            (1 if bracket(rows, (PLANE_AT_INFINITY, i, j, k)) < 0 else 0)
            ^ (1 if bracket(rows, (PLANE_AT_INFINITY, i, j, l)) < 0 else 0)
            ^ (1 if bracket(rows, (i, j, k, l)) < 0 else 0)
        )
        geometric = 1 if line_coordinate(rows, i, j, k) < line_coordinate(rows, i, j, l) else 0
        wrong += formula != geometric
    return Check(
        "order bits (paper: thm:order): X_0ijk xor X_0ijl xor X_ijkl is the order on L_ij",
        wrong == 0,
        f"{samples} random quadruples, {wrong} disagreements",
    )


def cut_order_check(sizes: Iterable[int] = (4, 5, 6)) -> Check:
    """Rank-2 Grassmann-Plucker holds iff the cut order is transitive (paper: lem:cutorder)."""

    def gp_holds(chi: dict[tuple[int, int], int], elements: Sequence[int]) -> bool:
        c, d, e, f = elements
        first = chi[(c, d)] ^ chi[(e, f)]
        second = 1 ^ chi[(c, e)] ^ chi[(d, f)]
        third = chi[(c, f)] ^ chi[(d, e)]
        return not (first == second == third)

    sizes = tuple(sizes)
    mismatches = 0
    for m in sizes:
        pairs = list(itertools.combinations(range(m), 2))
        for bits in range(1 << len(pairs)):
            chi: dict[tuple[int, int], int] = {}
            for position, (x, y) in enumerate(pairs):
                value = (bits >> position) & 1
                chi[(x, y)], chi[(y, x)] = value, value ^ 1
            gp = all(gp_holds(chi, subset) for subset in itertools.combinations(range(m), 4))
            cut = {
                (x, y): chi[(x, y)] ^ (chi[(0, x)] if x else 0) ^ (chi[(0, y)] if y else 0)
                for x in range(m)
                for y in range(m)
                if x != y
            }
            transitive = all(
                not (cut[(x, y)] and cut[(y, z)] and not cut[(x, z)])
                for x, y, z in itertools.permutations(range(m), 3)
            )
            mismatches += gp != transitive
    counted = [census(m) for m in sizes]
    return Check(
        "cut order (paper: lem:cutorder, rem:counts): rank-2 GP iff the cut order is "
        "transitive, n = 4,5,6, with (n-1)! 2^(n-1) and n! tournaments",
        mismatches == 0 and all(result.passed for result in counted),
        f"{mismatches} mismatches; "
        + ", ".join(f"{r.satisfying_gp}/{r.transitive}" for r in counted),
    )


def gauge_check(encoder: Encoder, face: int = 1) -> Check:
    """The reorientation group acts simply transitively on the pinned sign patterns.

    Exhaustive over the `2^(n+1)` group elements (bit 0 mirrors, bit `i` reorients plane
    `i`): independence of the `n+1` GF(2) functionals is what makes the gauge discard no
    orbit (paper: lem:gaugegroup, cor:gauge).
    """
    n = encoder.n
    targets = encoder.gauge_targets(face)
    patterns = set()
    for element in range(1 << (n + 1)):
        pattern = 0
        for position, subset in enumerate(targets):
            flip = element & 1
            for member in subset:
                if member >= 1:
                    flip ^= (element >> member) & 1
            pattern |= flip << position
        patterns.add(pattern)
    return Check(
        "gauge (paper: cor:gauge): one representative of each reorientation orbit",
        len(patterns) == 1 << (n + 1) == 1 << len(targets),
        f"{len(patterns):,} sign patterns on {len(targets)} pinned brackets",
    )


def corner_symmetry_check(encoder: Encoder) -> Check:
    """A corner bit does not depend on the order its two neighbours are named in.

    The formula behind it is ANTI-symmetric, so this is where an innocuous-looking call
    would silently return the complement (paper: lem:sf, rem:order-matters).
    """
    cmap = encoder.map
    swapped = 0
    for face in cmap.faces:
        cycle = cmap.link_cycle(face)
        for position in range(len(cycle)):
            a, b = cycle[position], cycle[(position + 1) % len(cycle)]
            swapped += encoder.corner_literal(face, a, b) != encoder.corner_literal(face, b, a)
    return Check(
        "corner bits (paper: lem:sf): independent of the order the neighbours are named",
        swapped == 0,
        f"{(cmap.n - 1) * cmap.n} corners, {swapped} disagreements",
    )


def adjacency_check(cmap: CombinatorialMap) -> Check:
    """Consecutive edges of a face meet at real vertices, and only they (paper: lem:adjacency)."""
    mismatches = 0
    for face in cmap.faces:
        successor = cmap.link_successor(face)
        for a in cmap.faces:
            if a == face:
                continue
            for b in cmap.faces:
                if b in (face, a):
                    continue
                adjacent = successor.get(a) == b or successor.get(b) == a
                mismatches += adjacent != cmap.is_real(face, a, b)
    return Check(
        "cyclic adjacency (paper: lem:adjacency): consecutive edges meet at real vertices",
        mismatches == 0,
        f"{mismatches} mismatches",
    )


def layer_i_check(encoder: Encoder) -> Check:
    """Layer I speaks about every vertex and only about vertices (paper: lem:I)."""
    cmap = encoder.map
    vertex_tags = [tag for _layer, tag in encoder.formula.tags if tag.startswith("I:")]
    corner_tags = {tag for _layer, tag in encoder.formula.tags if tag.startswith("turn:")}
    return Check(
        "Layer I (paper: lem:I): three clauses at every vertex, one bit per corner",
        len(vertex_tags) == 3 * len(cmap.triples)
        and len(set(vertex_tags)) == len(cmap.triples)
        and len(corner_tags) == cmap.n * (cmap.n - 1),
        f"{len(vertex_tags)} clauses over {len(set(vertex_tags))} vertices, "
        f"{len(corner_tags)} corner bits",
    )


def octant_check() -> Check:
    """At most one reflex corner at a vertex, by the octant table (paper: rem:octants)."""
    return Check(
        "at most one reflex corner at a vertex (paper: lem:onereflex, rem:octants)",
        at_most_one_reflex_corner(),
        f"admissible profiles {dict(admissible_profiles())}",
    )
