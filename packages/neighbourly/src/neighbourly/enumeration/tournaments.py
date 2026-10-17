"""Tournaments, the rank-2 Grassmann-Pluecker condition and the cut order.

A tournament on `{0, ..., m-1}` is a sign `chi(x, y)` for every ordered pair with
`chi(y, x) = 1 - chi(x, y)`.  It satisfies (GP) when every 4-subset satisfies the rank-2
Grassmann-Pluecker relation, and its *cut order* at `0` reorients every other element
by `chi(0, .)` (paper: lem:cutorder).  The lemma says: (GP) on every 4-subset if and only
if the cut order is a strict total order.  `census(m)` checks that on every tournament
with `m` elements and counts the two classes the article's remark compares
(paper: rem:counts): `(m-1)! 2^(m-1)` satisfy (GP), and `m!` are transitive.

A tournament is transitive exactly when its out-degrees are `0, 1, ..., m-1`, which is
how both orders are tested here -- a different test from the triangle check the
self-test uses, so the two computations share nothing but the definitions.

The census is exhaustive for the `m` it is run on; it is evidence for the lemma at those `m`,
not a proof of it.
"""

from __future__ import annotations

import itertools
from dataclasses import dataclass
from math import factorial

__all__ = ["Census", "census"]


@dataclass(frozen=True)
class Census:
    m: int
    tournaments: int
    satisfying_gp: int
    transitive: int
    #: Tournaments for which "(GP) everywhere" and "cut order transitive" disagree.
    mismatches: int

    @property
    def expected_gp(self) -> int:
        return factorial(self.m - 1) * (1 << (self.m - 1))

    @property
    def expected_transitive(self) -> int:
        return factorial(self.m)

    @property
    def passed(self) -> bool:
        return (
            self.mismatches == 0
            and self.satisfying_gp == self.expected_gp
            and self.transitive == self.expected_transitive
        )


def census(m: int) -> Census:
    """Every tournament on `m >= 4` elements: the lemma, and the two counts."""
    if m < 4:
        raise ValueError("the census needs at least four elements")
    pairs = list(itertools.combinations(range(m), 2))
    position = {pair: bit for bit, pair in enumerate(pairs)}

    def sign(bits: int, x: int, y: int) -> int:
        """chi(x, y) for x != y, read from the bit of the unordered pair."""
        if x < y:
            return (bits >> position[(x, y)]) & 1
        return 1 ^ ((bits >> position[(y, x)]) & 1)

    quadruples = [
        (
            position[(c, d)],
            position[(e, f)],
            position[(c, e)],
            position[(d, f)],
            position[(c, f)],
            position[(d, e)],
        )
        for c, d, e, f in itertools.combinations(range(m), 4)
    ]
    others = range(1, m)
    targets = list(range(m))
    gp_count = transitive_count = mismatches = 0
    for bits in range(1 << len(pairs)):
        gp = True
        for cd, ef, ce, df, cf, de in quadruples:
            first = ((bits >> cd) ^ (bits >> ef)) & 1
            second = 1 ^ (((bits >> ce) ^ (bits >> df)) & 1)
            third = ((bits >> cf) ^ (bits >> de)) & 1
            if first == second == third:
                gp = False
                break
        # The tournament itself: transitive iff its out-degrees are 0..m-1.
        degrees = [0] * m
        for x, y in pairs:
            if sign(bits, x, y):
                degrees[x] += 1
            else:
                degrees[y] += 1
        transitive_count += sorted(degrees) == targets
        # The cut order at 0 on the other m-1 elements.
        cut = [0] * m
        for x, y in itertools.combinations(others, 2):
            if sign(bits, x, y) ^ sign(bits, 0, x) ^ sign(bits, 0, y):
                cut[x] += 1
            else:
                cut[y] += 1
        linear = sorted(cut[1:]) == targets[: m - 1]
        gp_count += gp
        mismatches += gp != linear
    return Census(
        m=m,
        tournaments=1 << len(pairs),
        satisfying_gp=gp_count,
        transitive=transitive_count,
        mismatches=mismatches,
    )
