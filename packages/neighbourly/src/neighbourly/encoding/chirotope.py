"""Layers S, H and A: the bracket bits are a uniform rank-4 chirotope (paper: thm:chirotope).

    S   order-bit definitions        o^{ij}_{kl} = X_{0ijk} xor X_{0ijl} xor X_{ijkl}
    H   transitivity, real lines     each of the C(n,2) line orders is a strict total order
    A   transitivity at infinity     the n circular orders, each cut at one point

The `n+1` planes give C(n+1,2) projective lines, each carrying `n-1` marked points -- its
intersections with the other planes.  A chirotope gives each line a CIRCULAR order of those
points; cutting each circle at one point leaves a linear order on the others.  Layers S, H
and A are exactly *C(n+1,2) linear orders, each defined from three brackets by one XOR and
constrained by ternary transitivity*, and that is precisely the statement "the C(n+1,4)
bracket bits are a uniform rank-4 chirotope on n+1 elements" (paper: thm:chirotope).  On
the C(n,2) real lines the cut point is the line's own point at infinity, which is why Layer
S's definition contains a `0` (paper: rem:cut).  On the `n` lines at infinity element 0 is
already one of the two defining planes, so another cut point is chosen; that is Layer A.
(For n = 12: 78 lines, 66 real, 715 brackets.)

:class:`ChirotopeLayers` holds the bracket and order primitives and the three layer
methods of :class:`neighbourly.encoding.formula.Encoder`, which owns the state and the
emission order.
"""

from __future__ import annotations

import itertools

from neighbourly.encoding.common import (
    PLANE_AT_INFINITY,
    Bracket,
    EncodingBuilder,
    EncodingError,
    Oracle,
    permutation_parity,
)
from neighbourly.maps import CombinatorialMap

__all__ = ["ChirotopeLayers"]


class ChirotopeLayers:
    """Brackets, order literals and the layers S, H, A (state set by the Encoder)."""

    map: CombinatorialMap
    n: int
    elements: tuple[int, ...]
    oracle: Oracle | None
    formula: EncodingBuilder
    _brackets: dict[Bracket, int]
    _line_orders: dict[tuple[int, int], dict[tuple[int, int], int]]
    _cut_orders: dict[tuple[int, int], dict[tuple[int, int], int]]

    # -- primitives ---------------------------------------------------------------------

    def bracket_literal(self, *elements: int) -> int:
        """The literal whose truth value is `[chi(elements) < 0]`, for an ordered tuple."""
        if len(elements) != 4 or len(set(elements)) != 4:
            raise EncodingError(f"need four distinct elements, got {elements}")
        variable = self._brackets[tuple(sorted(elements))]
        return -variable if permutation_parity(elements) else variable

    def order_literal(self, i: int, j: int, k: int, l: int) -> int:
        """The literal whose truth value is `Order(i,j,k,l) = [P_ijk < P_ijl]`."""
        if len({i, j, k, l}) != 4:
            raise EncodingError(f"Order needs four distinct faces, got {(i, j, k, l)}")
        sign = 1
        if i > j:
            i, j, sign = j, i, -sign
        if k > l:
            k, l, sign = l, k, -sign
        return sign * self._line_orders[(i, j)][(k, l)]

    def between_pair(self, i: int, j: int, m: int, k: int, l: int) -> tuple[int, int]:
        """`Between(i,j; m; k,l)` is the XOR of the two returned literals."""
        if len({i, j, m, k, l}) != 5:
            raise EncodingError(f"Between needs five distinct faces, got {(i, j, m, k, l)}")
        return self.order_literal(i, j, m, k), self.order_literal(i, j, m, l)

    # -- Layer S: the order bits ---------------------------------------------------------

    def layer_S(self) -> None:
        """`o^{ij}_{kl} = X_{0ijk} xor X_{0ijl} xor X_{ijkl}`  (paper: thm:order).

        On the line `L_ij` the points `P_ijk` for the other `n-2` faces are ordered, and
        this is that order.  It is a definition, not a condition: no model is excluded.
        The `0` in it is the cut point -- the line's own point at infinity -- and seeing
        that is what makes Layer A possible (paper: rem:cut).
        """
        formula = self.formula
        formula.begin_layer("S")
        witness = formula.witness
        for i, j in itertools.combinations(self.map.faces, 2):
            row: dict[tuple[int, int], int] = {}
            rest = [x for x in self.map.faces if x not in (i, j)]
            for k, l in itertools.combinations(rest, 2):
                terms = (
                    self.bracket_literal(PLANE_AT_INFINITY, i, j, k),
                    self.bracket_literal(PLANE_AT_INFINITY, i, j, l),
                    self.bracket_literal(i, j, k, l),
                )
                if witness is None:
                    variable = formula.new_variable()
                else:
                    value = 0
                    for term in terms:
                        value ^= formula.literal_value(term)
                    variable = formula.new_variable(value)
                row[(k, l)] = variable
                formula.assert_xor([variable, *terms], 0, f"S:{i},{j};{k},{l}")
                formula.bump()
            self._line_orders[(i, j)] = row

    # -- Layer H: transitivity on the real lines -----------------------------------------

    def layer_H(self) -> None:
        """Each of the C(n,2) real line orders is a strict total order.

        On a realized line the parameters are real numbers, so this is immediate.  It is
        also the whole of the Grassmann-Plucker content at the real pairs: the two clauses
        of one triple `k, l, m`, expanded onto the six brackets they involve, forbid exactly
        the sign patterns that the three-term Grassmann-Plucker condition on `{0,k,l,m}` in
        the contraction at `{i,j}` forbids, and by (paper: lem:cutorder) that gives the
        condition on every 4-subset.  So S, H and A together say "the brackets are a
        uniform rank-4 chirotope" (paper: thm:chirotope), and the relational form
        (411,840 clauses for n = 12) is not needed.
        """
        formula = self.formula
        formula.begin_layer("H")
        for i, j in itertools.combinations(self.map.faces, 2):
            rest = [x for x in self.map.faces if x not in (i, j)]
            for k, l, m in itertools.combinations(rest, 3):
                kl = self.order_literal(i, j, k, l)
                lm = self.order_literal(i, j, l, m)
                km = self.order_literal(i, j, k, m)
                tag = f"H:{i},{j};{k},{l},{m}"
                formula.add_clause((-kl, -lm, km), tag)
                formula.add_clause((kl, lm, -km), tag)
                formula.bump()

    # -- Layer A: the cut order on the lines at infinity ---------------------------------

    def layer_A(self) -> None:
        """The same statement for the `n` lines `L_{0b}`, which needs one extra idea.

        A bracket through infinity is `[0,b,x,y] = -det(n_b, n_x, n_y)` (paper: lem:cofactor),
        so the brackets containing 0 are the chirotope of the face NORMALS.  Contracting
        at a face `b` leaves `n-1` vectors in a plane -- a CIRCULAR sequence, not a
        linear order.  Of the tournaments on `m` elements `(m-1)! 2^(m-1)` satisfy
        Grassmann-Plucker and only `m!` are transitive (a factor of 93 at `m = 11`), so
        handing the contraction to Layer H would delete realizations (paper: rem:counts).

        A circle becomes a line once it is cut.  Reorienting `x` negates `n_x` and flips
        `chi(x,z)` for every `z`; reorienting every element into the half-plane bounded
        by the line through `n_r` puts them all in a closed half-plane, which is acyclic,
        which for uniform rank 2 is a linear order.  The reorientation is read off, not
        searched for:

            d(x,y)  =  chi(x,y) xor chi(r,x) xor chi(r,y)

        and `chi` satisfies the rank-2 Grassmann-Plucker condition on every 4-subset if
        and only if `d` is transitive (paper: lem:cutorder); the census of
        :mod:`neighbourly.enumeration.tournaments` checks this exhaustively on small sizes.
        """
        formula = self.formula
        formula.begin_layer("A")
        for b in self.map.faces:
            rest = [x for x in self.map.faces if x != b]
            cut, others = rest[0], rest[1:]
            row: dict[tuple[int, int], int] = {}
            for x, y in itertools.combinations(others, 2):
                row[(x, y)] = formula.define_xor(
                    [
                        self.bracket_literal(PLANE_AT_INFINITY, b, x, y),
                        self.bracket_literal(PLANE_AT_INFINITY, b, cut, x),
                        self.bracket_literal(PLANE_AT_INFINITY, b, cut, y),
                    ],
                    f"A:{b},{cut};{x},{y}",
                )
                formula.bump()
            self._cut_orders[(b, cut)] = row

            def cut_literal(u: int, v: int, row: dict[tuple[int, int], int] = row) -> int:
                return row[(u, v)] if u < v else -row[(v, u)]

            for x, y, z in itertools.combinations(others, 3):
                xy, yz, xz = cut_literal(x, y), cut_literal(y, z), cut_literal(x, z)
                tag = f"A:{b},{cut};{x},{y},{z}"
                formula.add_clause((-xy, -yz, xz), tag)
                formula.add_clause((xy, yz, -xz), tag)
                formula.bump()
