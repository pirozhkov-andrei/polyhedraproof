"""Layers B and I: the faces are simple polygons, oriented, with at most one reflex corner.

    B   face-boundary simplicity     no two non-adjacent edges of a face cross
    I   face orientation and corners the crossing-parity identity (paper: lem:parity), and
                                     at most one reflex corner at every vertex
                                     (paper: lem:onereflex)

B and I are the geometry: the face polygons are simple (paper: lem:B), every face carries
the orientation its crossing parity forces, and no vertex has two reflex corners
(paper: lem:I).  Like every layer they are necessary conditions only.

The auxiliary variables of these layers are allocated lazily, the first time a boundary
bit or a corner is reached, so the order of the calls below is part of the formula's
identity.  :class:`FaceLayers` holds those methods of
:class:`neighbourly.encoding.formula.Encoder`.
"""

from __future__ import annotations

import itertools

from neighbourly.encoding.chirotope import ChirotopeLayers
from neighbourly.encoding.common import PLANE_AT_INFINITY, EncodingError

__all__ = ["FaceLayers"]


class FaceLayers(ChirotopeLayers):
    """Boundary bits, corner bits, orientation bits and the layers B, I."""

    _boundary_bits: dict[tuple[int, int, int], int]
    _corner_bits: dict[tuple[int, int, int], int]
    _orientation_bits: dict[int, int]

    # -- primitives ---------------------------------------------------------------------

    def _orientation_variable(self, face: int) -> int:
        """`s_f`, the one variable the brackets do not determine (paper: lem:sf)."""
        if self.oracle is None:
            return self.formula.new_variable()
        return self.formula.new_variable(int(self.oracle.orientation(face)) & 1)

    # -- Layer B: the face boundary is simple --------------------------------------------

    def boundary_bit(self, face: int, other: int, point: int) -> int:
        """`OnB(face,other;point)` (paper: def:onb): `P_{face,other,point}` is inside the edge.

        The predicate is a statement about the edge `E(face,other)` and the point
        `P_{face,other,point}` (paper: lem:onb), so it is symmetric in its first two
        arguments; canonicalising on the unordered pair halves the variable count to
        `C(n,2) (n-4)` (528 for `n = 12`).
        """
        a, b = (face, other) if face < other else (other, face)
        key = (a, b, point)
        if key not in self._boundary_bits:
            z0, z1 = self.map.end_pair(a, b)
            pair = self.between_pair(a, b, point, z0, z1)
            self._boundary_bits[key] = self.formula.define_xor(list(pair), f"OnB:{a},{b};{point}")
        return self._boundary_bits[key]

    def layer_B(self) -> None:
        """No two non-adjacent edges of a face cross inside both of them.

        For a face `f` and two boundary edges `E(f,a)`, `E(f,b)` that are not cyclically
        adjacent at `f`, the crossing point `P_fab` is not interior to both at once;
        otherwise the boundary polygon of `F^f` is not simple.  Every general-position
        realization therefore satisfies this layer (paper: lem:B); like every layer, it
        is a necessary condition only.
        """
        formula = self.formula
        formula.begin_layer("B")
        for f in self.map.faces:
            others = [x for x in self.map.faces if x != f]
            for a, b in itertools.combinations(others, 2):
                if self.map.is_real(f, a, b):
                    continue
                formula.add_clause(
                    (-self.boundary_bit(f, a, b), -self.boundary_bit(f, b, a)),
                    f"B:{f}|{a},{b}",
                )
                formula.bump()

    # -- Layer I: face orientation and reflex corners -------------------------------------

    def corner_literal(self, face: int, a: int, b: int) -> int:
        """ "The corner of `face` at the vertex `P_{face,a,b}` is reflex" (paper: lem:sf).

            refl(f; a,b) = Order(f,a,x,b) xor Order(f,b,a,y) xor X_{0,f,a,b} xor 1 xor s_f

        with `x = far_end(f,a,b)`, `y = far_end(f,b,a)`.  The first three terms XOR 1 are
        the negative-turn bit; `s_f` is the orientation bit of the face, one bit per face
        and not one per corner.

        (paper: lem:turn) proves that those three terms XOR 1 indicate negativity of the
        turn `(u_in x u_out) . n_f` at that corner, where `u_in` and `u_out` are the
        incoming and outgoing edge directions of the link-cycle traversal -- an identity,
        not an approximation.  The corner bit adds `s_f` (paper: lem:sf) to record whether
        that traversal runs positively or negatively around `n_f`; the orientation part of
        Layer I fixes `s_f` by the crossing-parity identity (paper: lem:parity).  The
        variable this method defines, tagged `turn:`, is the complement of the corner bit.

        THE ARGUMENT ORDER MATTERS, AND IS CANONICALISED HERE.  Swapping `a` and `b`
        negates all three terms, so the formula is ANTI-symmetric, while the predicate it
        names -- "this corner is reflex" -- is symmetric.  The two are reconciled by
        always writing the pair in the direction of the link cycle, which is what the
        first lines below do (paper: rem:order-matters).  It is done here so that no caller
        can get it wrong: reach a corner bit in the other order and you would get the
        complement of the intended bit, the formula would still be well-formed, nothing
        would fail, and the theorem would be wrong.
        """
        successor = self.map.link_successor(face)
        if successor.get(a) != b:
            a, b = b, a
        if successor.get(a) != b:
            raise EncodingError(f"{a} and {b} are not consecutive in the link of {face}")
        key = (face, a, b)
        if key in self._corner_bits:
            return self._corner_bits[key]
        if face not in self._orientation_bits:
            self._orientation_bits[face] = self._orientation_variable(face)
        turn = self.formula.define_xor(
            [
                self.order_literal(face, a, self.map.far_end(face, a, b), b),
                self.order_literal(face, b, a, self.map.far_end(face, b, a)),
                self.bracket_literal(PLANE_AT_INFINITY, face, a, b),
                self._orientation_bits[face],
            ],
            f"turn:{face};{a},{b}",
        )
        self._corner_bits[key] = -turn  # the trailing XOR 1
        return -turn

    def vertex_corners(self, f: int, g: int, h: int) -> list[int]:
        """The three corner literals of the vertex `{f,g,h}`."""
        return [
            self.corner_literal(f, g, h),
            self.corner_literal(g, f, h),
            self.corner_literal(h, f, g),
        ]

    def layer_I(self) -> None:
        """At most one reflex corner at every vertex, on top of the fixed orientations.

        Every general-position realization satisfies this layer (paper: lem:I).  The vertex
        clauses encode (paper: lem:onereflex), proved directly in the article.  A second,
        independent route: at a vertex three planes meet, the solid is locally a union of
        octants, and enumerating the admissible octant sets leaves only two boundary
        profiles, `(1,1,1)` with no reflex corner and `(1,1,3)` with exactly one, never two;
        :mod:`neighbourly.enumeration.vertex_profiles` runs that enumeration over all 256
        octant sets (paper: rem:octants).
        """
        formula = self.formula
        formula.begin_layer("I")
        for f in self.map.faces:  # define every corner bit first
            cycle = self.map.link_cycle(f)
            for index in range(len(cycle)):
                self.corner_literal(f, cycle[index], cycle[(index + 1) % len(cycle)])
        for triple in sorted(self.map.triples):
            f, g, h = triple
            literals = self.vertex_corners(f, g, h)
            for p, q in itertools.combinations(literals, 2):
                formula.add_clause((-p, -q), f"I:{f},{g},{h}")
            formula.bump()
        self._constrain_face_orientations()

    def _constrain_face_orientations(self) -> None:
        """Fix each face orientation by one crossing-parity equation (paper: lem:parity).

        For the first face `g` of the link of `f`, with `(z0, z1)` the sorted pair
        `Ends(f,g)`, assert

            refl(f; g, z1) = XOR_v (OnB(f,v;g) AND Between(f,g;z1;z0,v))

        over the faces `v` other than `f, g, z0, z1`.  The lemma holds for either end of
        `E(f,g)`; taking `z1` to be the larger label is a fixed convention and part of the
        formula's identity (stated with Layer I in paper: sec:geometric).  The corner bit is
        normalized to link-cycle order by `corner_literal`.
        """
        formula = self.formula
        formula.begin_layer("I")
        for f in self.map.faces:
            g = self.map.link_cycle(f)[0]
            z0, z1 = self.map.end_pair(f, g)
            tag = f"orientation:{f};{g};{z0},{z1}"
            edge = self.order_literal(f, g, z1, z0)
            products = []
            for v in self.map.faces:
                if v in (f, g, z0, z1):
                    continue
                between = formula.define_xor(
                    (edge, self.order_literal(f, g, z1, v)), tag + f":between:{v}"
                )
                products.append(
                    formula.define_and(self.boundary_bit(f, v, g), between, tag + f":and:{v}")
                )
            formula.assert_xor((*products, self.corner_literal(f, g, z1)), 0, tag + ":parity")
            formula.bump()
