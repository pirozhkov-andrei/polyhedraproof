"""ref_paper.py -- an independent semantic reference for the encoding of the article.

WHAT THIS IS
    A library written from the text of paper/faces12-en.tex (sections 3, 5-9 and the appendix
    "Numerical data") ONLY, before the project's encoder (neighbourly.encoding*) and its tests
    were opened.  It shares no code and no numbering conventions with the project.  Exact
    arithmetic (fractions.Fraction).

    It provides
      * NMap      -- a neighbourly map T (labels 1..n): Ends, links, corners, relabelling;
      * Arr       -- an arrangement of n planes (covectors) plus the plane at infinity 0:
                     brackets, bracket bits X_S, triple points P_ijk, group action (covector sign
                     flips and a mirror image), affine / projective images;
      * geometric predicates computed DIRECTLY from points and vectors (order of points on a line,
        point inside a segment, sign of a turn, reflex corner of a simple polygon by the shoelace
        rule, ray crossings, traversal orientation, angular cut order of normals);
      * the same predicates computed by THE PAPER'S FORMULAS from the bits X_S (PaperX);
      * check_realization -- an independent exact test of (R1)-(R4) and (G) of the paper
        (simple faces, faces meet exactly in the common edge);
      * paper_constraints -- the list of substantive (non-definitional) constraints of layers
        H, A, B, I written from the paper, as semantic records.

HOW TO RUN
    This file is a library.  Its self-test checks the paper's dictionary (thm:order, lem:onb,
    lem:turn, lem:parity, the cut order d^b) against direct geometry on random plane arrangements
    and on a tetrahedron:

        python3 tests/reference/ref_paper.py

    The drivers ref_*_check.py import it.
"""

from __future__ import annotations

import random
from fractions import Fraction as Fr
from itertools import combinations

# --------------------------------------------------------------------------------------------
# small exact linear algebra
# --------------------------------------------------------------------------------------------


def det3(a, b, c):
    return (
        a[0] * (b[1] * c[2] - b[2] * c[1])
        - a[1] * (b[0] * c[2] - b[2] * c[0])
        + a[2] * (b[0] * c[1] - b[1] * c[0])
    )


def det4(r):
    a, b, c, d = r
    # expansion along the last column
    m = lambda x, y, z: det3(x[:3], y[:3], z[:3])  # noqa: E731
    return -a[3] * m(b, c, d) + b[3] * m(a, c, d) - c[3] * m(a, b, d) + d[3] * m(a, b, c)


def cross(a, b):
    return (a[1] * b[2] - a[2] * b[1], a[2] * b[0] - a[0] * b[2], a[0] * b[1] - a[1] * b[0])


def dot(a, b):
    return a[0] * b[0] + a[1] * b[1] + a[2] * b[2]


def sub(a, b):
    return (a[0] - b[0], a[1] - b[1], a[2] - b[2])


def add(a, b):
    return (a[0] + b[0], a[1] + b[1], a[2] + b[2])


def scale(t, a):
    return (t * a[0], t * a[1], t * a[2])


def perm_parity(seq):
    """Parity (0/1) of the permutation sorting seq (distinct entries)."""
    seq = list(seq)
    p = 0
    for i in range(len(seq)):
        for j in range(i + 1, len(seq)):
            if seq[i] > seq[j]:
                p ^= 1
    return p


# --------------------------------------------------------------------------------------------
# neighbourly maps (def:map)
# --------------------------------------------------------------------------------------------


class NMap:
    """Neighbourly map on labels 1..n given by its real vertices (3-subsets)."""

    def __init__(self, n, triples):
        self.n = n
        self.T = frozenset(frozenset(t) for t in triples)
        assert all(len(t) == 3 and all(1 <= x <= n for x in t) for t in self.T)
        assert len(self.T) * 3 == n * (n - 1), "wrong number of triples"
        self.labels = list(range(1, n + 1))
        # (M1)
        self._ends = {}
        for i, j in combinations(self.labels, 2):
            e = sorted(next(iter(t - {i, j})) for t in self.T if i in t and j in t)
            assert len(e) == 2, f"(M1) fails at {(i, j)}"
            self._ends[(i, j)] = tuple(e)
        # (M2)
        self._link = {}
        for f in self.labels:
            others = [u for u in self.labels if u != f]
            nb = {
                u: [w for w in others if w != u and frozenset((f, u, w)) in self.T] for u in others
            }
            assert all(len(v) == 2 for v in nb.values()), f"(M2) fails at {f}"
            start = min(others)
            cyc = [start, min(nb[start])]
            while True:
                a, b = cyc[-2], cyc[-1]
                c = nb[b][0] if nb[b][0] != a else nb[b][1]
                if c == start:
                    break
                cyc.append(c)
            assert len(cyc) == n - 1, f"(M2) fails at {f}: link is not one cycle"
            self._link[f] = tuple(cyc)

    def ends(self, i, j):
        return self._ends[(i, j) if i < j else (j, i)]

    def other_end(self, i, j, z):
        e = self.ends(i, j)
        assert z in e
        return e[0] if e[1] == z else e[1]

    def link(self, f, reverse=False):
        """Link cycle of f as a tuple (my own start/direction; reverse=True flips direction)."""
        c = self._link[f]
        return tuple(reversed(c)) if reverse else c

    def adjacent_in_link(self, f, a, b):
        return frozenset((f, a, b)) in self.T

    def corners(self, f, reverse=False):
        """Corners (x, a, b, y): consecutive link faces x->a->b->y in the traversal direction."""
        c = self.link(f, reverse)
        m = len(c)
        return [(c[(k - 1) % m], c[k], c[(k + 1) % m], c[(k + 2) % m]) for k in range(m)]

    def relabel(self, perm):
        """perm: dict old->new.  Returns the relabelled map."""
        return NMap(self.n, [[perm[x] for x in t] for t in self.T])

    def is_orientable(self):
        """Orientability per def:map (cyclic orientations covering every ordered pair once)."""
        start = next(iter(self.T))
        a, b, c = sorted(start)
        orient = {start: (a, b, c)}
        stack = [start]
        while stack:
            t = stack.pop()
            o = orient[t]
            for k in range(3):
                u, v = (
                    o[k],
                    o[(k + 1) % 3],
                )  # ordered pair (u,v) used by t; neighbour must use (v,u)
                for z in self.ends(u, v):
                    t2 = frozenset((u, v, z))
                    if t2 == t:
                        continue
                    want = (v, u, z)
                    if t2 in orient:
                        o2 = orient[t2]
                        rots = {(o2[0], o2[1], o2[2]), (o2[1], o2[2], o2[0]), (o2[2], o2[0], o2[1])}
                        if want not in rots:
                            return False
                    else:
                        orient[t2] = want
                        stack.append(t2)
        return len(orient) == len(self.T)


def tetra_map():
    return NMap(4, combinations(range(1, 5), 3))


# --------------------------------------------------------------------------------------------
# plane arrangements
# --------------------------------------------------------------------------------------------


class Arr:
    """Planes q_1..q_n (covectors (a,b,c,d): ax+by+cz+d=0) and q_0=(0,0,0,1)."""

    def __init__(self, planes):
        self.q = {0: (Fr(0), Fr(0), Fr(0), Fr(1))}
        for k, v in planes.items():
            assert k >= 1
            self.q[k] = tuple(Fr(x) for x in v)
        self.n = len(planes)
        assert sorted(planes) == list(range(1, self.n + 1))
        self._P = {}
        self._X = None

    def nrm(self, i):
        return self.q[i][:3]

    def bracket(self, *labels):
        return det4([self.q[s] for s in labels])

    def general_position(self):
        return all(self.bracket(*S) != 0 for S in combinations(range(self.n + 1), 4))

    def allX(self):
        """X_S = [bracket(S) < 0] for S sorted increasing (paper, sec. 5)."""
        if self._X is None:
            X = {}
            for S in combinations(range(self.n + 1), 4):
                v = self.bracket(*S)
                if v == 0:
                    raise ValueError(f"bracket {S} vanishes: not in general position")
                X[S] = 1 if v < 0 else 0
            self._X = X
        return self._X

    def P(self, i, j, k):
        key = tuple(sorted((i, j, k)))
        p = self._P.get(key)
        if p is None:
            a, b, c = (self.q[s] for s in key)
            D = det3(a[:3], b[:3], c[:3])
            if D == 0:
                raise ValueError(f"planes {key} do not meet in a point")
            r = (-a[3], -b[3], -c[3])
            col = lambda m: (a[m], b[m], c[m])  # noqa: E731
            x = det3(r, col(1), col(2)) / D
            y = det3(col(0), r, col(2)) / D
            z = det3(col(0), col(1), r) / D
            p = (x, y, z)
            for s in key:  # sanity: the point is on all three planes
                assert dot(self.q[s][:3], p) + self.q[s][3] == 0
            self._P[key] = p
        return p

    # ---- the two operations of lem:gaugegroup, done geometrically
    def flip(self, i):
        pl = {k: v for k, v in self.q.items() if k}
        pl[i] = tuple(-x for x in pl[i])
        return Arr(pl)

    def mirror(self):
        """Image under the reflection x -> (-x1, x2, x3)."""
        return Arr({k: (-v[0], v[1], v[2], v[3]) for k, v in self.q.items() if k})

    def apply_group(self, gamma, eps):
        """eps: dict label->0/1.  Geometric action of (gamma, eps) in G."""
        pl = {k: (tuple(-x for x in v) if eps.get(k, 0) else v) for k, v in self.q.items() if k}
        a = Arr(pl)
        return a.mirror() if gamma else a

    def relabel(self, perm):
        return Arr({perm[k]: v for k, v in self.q.items() if k})

    def transform(self, M):
        """Image under the projective map p -> M p (homogeneous columns): q -> q M^{-1}.

        M is a 4x4 matrix (rows).  Covectors are only defined up to a non-zero scalar, so we use
        q * adj(M) (adjugate), which is q M^{-1} times det M.  The plane at infinity stays the
        formal covector (0,0,0,1) of the new chart: this is a genuinely different arrangement
        unless M is affine.
        """
        adj = adjugate4(M)
        pl = {}
        for k, v in self.q.items():
            if k:
                pl[k] = tuple(sum(v[r] * adj[r][c] for r in range(4)) for c in range(4))
        return Arr(pl)


def adjugate4(M):
    M = [[Fr(x) for x in row] for row in M]
    adj = [[Fr(0)] * 4 for _ in range(4)]
    for i in range(4):
        for j in range(4):
            minor = [[M[r][c] for c in range(4) if c != j] for r in range(4) if r != i]
            adj[j][i] = (-1) ** (i + j) * det3(*minor)
    return adj


def apply_point(M, p):
    v = [sum(Fr(M[r][c]) * ([*list(p), Fr(1)])[c] for c in range(4)) for r in range(4)]
    assert v[3] != 0
    return (v[0] / v[3], v[1] / v[3], v[2] / v[3])


def random_arrangement(n, rng, R=9):
    """Random integer planes in general position (hyp:G)."""
    while True:
        a = Arr({i: tuple(rng.randint(-R, R) for _ in range(4)) for i in range(1, n + 1)})
        if all(any(a.nrm(i)) for i in range(1, n + 1)) and a.general_position():
            return a


# --------------------------------------------------------------------------------------------
# predicates computed DIRECTLY from geometry (no bracket signs are used below)
# --------------------------------------------------------------------------------------------


def ord_geom(arr, i, j, k, l):
    """1 iff P_ijk precedes P_ijl along L_ij directed by n_i x n_j (sec. 5.2)."""
    d = cross(arr.nrm(i), arr.nrm(j))
    t = dot(sub(arr.P(i, j, l), arr.P(i, j, k)), d)
    assert t != 0
    return 1 if t > 0 else 0


def onb_geom(M, arr, i, j, u):
    """1 iff P_iju lies strictly between the endpoints of E(i,j) (lem:onb)."""
    z0, z1 = M.ends(i, j)
    d = cross(arr.nrm(i), arr.nrm(j))
    t0, t1, tu = (dot(arr.P(i, j, z), d) for z in (z0, z1, u))
    assert tu not in (t0, t1) and t0 != t1
    return 1 if min(t0, t1) < tu < max(t0, t1) else 0


def turn_geom(M, arr, f, a, b):
    """[w(f;a,b) < 0], corner at P_fab reached along E(f,a) and left along E(f,b) (sec. 5.4)."""
    assert M.adjacent_in_link(f, a, b)
    x = M.other_end(f, a, b)
    y = M.other_end(f, b, a)
    v = arr.P(f, a, b)
    w = dot(cross(sub(v, arr.P(f, a, x)), sub(arr.P(f, b, y), v)), arr.nrm(f))
    assert w != 0
    return 1 if w < 0 else 0


def Bv_geom(M, arr, f, g, z1, v):
    """1 iff P_fgv lies on the open ray from V=P_fgz1 pointing away from E(f,g) (lem:parity)."""
    z0 = M.other_end(f, g, z1)
    V = arr.P(f, g, z1)
    away = sub(V, arr.P(f, g, z0))
    t = dot(sub(arr.P(f, g, v), V), away)
    assert t != 0
    return 1 if t > 0 else 0


def crossing_parity_geom(M, arr, f, g, z1):
    """Parity of the number of edges E(f,v), v not in {f,g,z0,z1}, crossed by that ray."""
    z0 = M.other_end(f, g, z1)
    par = 0
    for v in M.labels:
        if v in (f, g, z0, z1):
            continue
        par ^= Bv_geom(M, arr, f, g, z1, v) & onb_geom(M, arr, f, v, g)
    return par


def face_polygon(M, arr, f, reverse=False):
    """Vertex sequence (P_{f,u,succ u}) of the boundary polygon of face f (def:realization)."""
    return [arr.P(f, a, b) for (_x, a, b, _y) in M.corners(f, reverse)]


def _proj2(arr, f):
    nf = arr.nrm(f)
    drop = max(range(3), key=lambda c: abs(nf[c]))
    keep = [c for c in range(3) if c != drop]
    return lambda p: (p[keep[0]], p[keep[1]])


def _cross2(a, b):
    return a[0] * b[1] - a[1] * b[0]


def reflex_geom(M, arr, f, a, b):
    """1 iff the interior angle of the (simple) polygon of f at P_fab exceeds pi.

    Shoelace rule in a coordinate projection of the plane h_f: the corner is reflex iff the turn
    there has the sign opposite to the signed area.  Uses neither n_f's orientation nor brackets.
    Independent of the traversal direction.
    """
    pr = _proj2(arr, f)
    cs = M.corners(f)
    poly = [pr(arr.P(f, c[1], c[2])) for c in cs]
    m = len(poly)
    area2 = sum(_cross2(poly[k], poly[(k + 1) % m]) for k in range(m))
    assert area2 != 0
    idx = next(k for k, c in enumerate(cs) if {c[1], c[2]} == {a, b})
    p0, p1, p2 = poly[(idx - 1) % m], poly[idx], poly[(idx + 1) % m]
    t = _cross2((p1[0] - p0[0], p1[1] - p0[1]), (p2[0] - p1[0], p2[1] - p1[1]))
    assert t != 0
    return 1 if (t > 0) != (area2 > 0) else 0


def traversal_bit_geom(M, arr, f, reverse=False):
    """s_f of lem:sf: 0 iff the polygon, traversed in the given link direction, runs positively in
    the plane h_f oriented by n_f (signed area w.r.t. n_f positive)."""
    poly = face_polygon(M, arr, f, reverse)
    m = len(poly)
    acc = (Fr(0), Fr(0), Fr(0))
    for k in range(m):
        acc = add(acc, cross(poly[k], poly[(k + 1) % m]))
    s = dot(acc, arr.nrm(f))
    assert s != 0
    return 0 if s > 0 else 1


def d_geom(arr, b, r, x, y):
    """Cut order of the normals modulo n_b with cut point r (layer A), computed by slopes.

    Write n_x = alpha_x n_r + beta_x e + (multiple of n_b) with det(n_b, n_r, e) > 0.  The class
    of +-n_x in the plane R^3/n_b has slope alpha_x/beta_x w.r.t. the cut direction n_r; d(x,y)=1
    iff slope(x) > slope(y), i.e. the representative of x in the open half-plane to the left of
    n_r comes before that of y counterclockwise.  (Derivation from chi(x,y)=X_{0bxy}=
    [det(n_b,n_x,n_y)>0] and d = chi' after reorienting so that chi'(r,.)=1, lem:cutorder.)
    """
    nb, nr = arr.nrm(b), arr.nrm(r)
    e = cross(nb, nr)  # det(nb, nr, nb x nr) = |nb x nr|^2 > 0
    D = det3(nb, nr, e)
    assert D > 0

    def slope(u):
        nu = arr.nrm(u)
        alpha = det3(nb, nu, e) / D
        beta = det3(nb, nr, nu) / D
        assert beta != 0
        return alpha / beta

    sx, sy = slope(x), slope(y)
    assert sx != sy
    return 1 if sx > sy else 0


# --------------------------------------------------------------------------------------------
# the same predicates by the paper's formulas from the bits X_S
# --------------------------------------------------------------------------------------------


class PaperX:
    """Evaluates the paper's dictionary on an assignment X: sorted 4-subset of {0..n} -> 0/1."""

    def __init__(self, M, X):
        self.M = M
        self.Xs = X

    def X(self, *t):
        """Bit of an ordered tuple: X_sigma(S) = X_S xor par(sigma)."""
        return self.Xs[tuple(sorted(t))] ^ perm_parity(t)

    def ord(self, i, j, k, l):  # thm:order
        return self.X(0, i, j, k) ^ self.X(0, i, j, l) ^ self.X(i, j, k, l)

    def onb(self, i, j, u):  # def:onb
        z0, z1 = self.M.ends(i, j)
        return self.ord(i, j, z0, u) ^ self.ord(i, j, z1, u)

    def turn(self, f, a, b):  # lem:turn, (a,b) in traversal order
        x = self.M.other_end(f, a, b)
        y = self.M.other_end(f, b, a)
        return 1 ^ self.ord(f, a, x, b) ^ self.ord(f, b, a, y) ^ self.X(0, f, a, b)

    def Bv(self, f, g, z1, v):  # lem:parity
        z0 = self.M.other_end(f, g, z1)
        return self.ord(f, g, z1, z0) ^ self.ord(f, g, z1, v)

    def Cv(self, f, g, v):
        return self.onb(f, v, g)

    def crossing_parity(self, f, g, z1):
        z0 = self.M.other_end(f, g, z1)
        par = 0
        for v in self.M.labels:
            if v not in (f, g, z0, z1):
                par ^= self.Cv(f, g, v) & self.Bv(f, g, z1, v)
        return par

    def d(self, b, r, x, y):  # layer A
        return self.X(0, b, x, y) ^ self.X(0, b, r, x) ^ self.X(0, b, r, y)

    def refl_invariant(self, f, a, b, g, z1):
        """refl(f;a,b) as forced by the orientation equation pinned at the corner (g,z1):
        turn(f;a,b) xor turn(f; corner at P_fgz1) xor crossing parity -- with both turns taken in
        the same traversal direction, so the value does not depend on that direction."""
        cs = self.M.corners(f)
        (c1,) = [c for c in cs if {c[1], c[2]} == {a, b}]
        (c2,) = [c for c in cs if {c[1], c[2]} == {g, z1}]
        return (
            self.turn(f, c1[1], c1[2]) ^ self.turn(f, c2[1], c2[2]) ^ self.crossing_parity(f, g, z1)
        )


def refl_invariant_geom(M, arr, f, a, b, g, z1):
    """Geometric counterpart of PaperX.refl_invariant, defined for ANY planes in general position
    (no simplicity needed): [w(corner)<0] xor [w(pin corner)<0] xor (ray crossing parity)."""
    cs = M.corners(f)
    (c1,) = [c for c in cs if {c[1], c[2]} == {a, b}]
    (c2,) = [c for c in cs if {c[1], c[2]} == {g, z1}]
    return (
        turn_geom(M, arr, f, c1[1], c1[2])
        ^ turn_geom(M, arr, f, c2[1], c2[2])
        ^ crossing_parity_geom(M, arr, f, g, z1)
    )


# --------------------------------------------------------------------------------------------
# independent exact test of def:realization (R1)-(R4)
# --------------------------------------------------------------------------------------------


def _on_segment2(p, a, b):
    if _cross2((b[0] - a[0], b[1] - a[1]), (p[0] - a[0], p[1] - a[1])) != 0:
        return False
    return (min(a[0], b[0]) <= p[0] <= max(a[0], b[0])) and (
        min(a[1], b[1]) <= p[1] <= max(a[1], b[1])
    )


def _segments_meet2(a, b, c, d):
    """Closed segments ab and cd have a common point (exact)."""

    def sgn(v):
        return (v > 0) - (v < 0)

    o1 = sgn(_cross2((b[0] - a[0], b[1] - a[1]), (c[0] - a[0], c[1] - a[1])))
    o2 = sgn(_cross2((b[0] - a[0], b[1] - a[1]), (d[0] - a[0], d[1] - a[1])))
    o3 = sgn(_cross2((d[0] - c[0], d[1] - c[1]), (a[0] - c[0], a[1] - c[1])))
    o4 = sgn(_cross2((d[0] - c[0], d[1] - c[1]), (b[0] - c[0], b[1] - c[1])))
    if o1 != o2 and o3 != o4:
        return True
    return (
        _on_segment2(c, a, b)
        or _on_segment2(d, a, b)
        or _on_segment2(a, c, d)
        or _on_segment2(b, c, d)
    )


def polygon_is_simple2(poly):
    m = len(poly)
    if len(set(poly)) != m:
        return False
    for k in range(m):
        a, b = poly[k], poly[(k + 1) % m]
        for l in range(k + 1, m):
            c, d = poly[l], poly[(l + 1) % m]
            if l == k + 1 or (k == 0 and l == m - 1):
                # consecutive edges: must meet only in the shared vertex
                shared = b if l == k + 1 else a
                other1 = a if l == k + 1 else b
                other2 = d if l == k + 1 else c
                if _on_segment2(other1, c, d) or _on_segment2(other2, a, b):
                    return False
                assert shared in (c, d)
            elif _segments_meet2(a, b, c, d):
                return False
    return True


def point_in_closed_polygon2(p, poly):
    m = len(poly)
    for k in range(m):
        if _on_segment2(p, poly[k], poly[(k + 1) % m]):
            return True
    inside = False
    for k in range(m):
        a, b = poly[k], poly[(k + 1) % m]
        if (a[1] > p[1]) != (b[1] > p[1]):
            # x-coordinate of the edge at height p.y
            xint = a[0] + (p[1] - a[1]) * (b[0] - a[0]) / (b[1] - a[1])
            if xint > p[0]:
                inside = not inside
    return inside


def check_realization(M, arr, need_G=True):
    """Exact test of (R1)-(R4) [and (G)].  Returns (ok, reason)."""
    # (R4) planes pairwise distinct; pairs must intersect in a line
    for i, j in combinations(M.labels, 2):
        if cross(arr.nrm(i), arr.nrm(j)) == (0, 0, 0):
            return False, f"planes {i},{j} parallel or equal"
    # (R1)
    pts = {}
    for t in M.T:
        try:
            pts[t] = arr.P(*t)
        except ValueError as e:
            return False, str(e)
    if len(set(pts.values())) != len(pts):
        return False, "(R1) vertices not distinct"
    if need_G and not arr.general_position():
        return False, "(G) fails"
    # (R2)
    polys3 = {f: face_polygon(M, arr, f) for f in M.labels}
    polys2 = {}
    for f in M.labels:
        pr = _proj2(arr, f)
        polys2[f] = [pr(p) for p in polys3[f]]
        if not polygon_is_simple2(polys2[f]):
            return False, f"(R2) face {f} is not a simple polygon"
    # (R3): F^i cap F^j == E(i,j).  Both faces lie in distinct planes, so the intersection lies on
    # L_ij.  Collect every parameter at which membership in either face can change, then test
    # those points and the midpoints of the gaps between them.
    for i, j in combinations(M.labels, 2):
        d = cross(arr.nrm(i), arr.nrm(j))
        z0, z1 = M.ends(i, j)
        A, B = arr.P(i, j, z0), arr.P(i, j, z1)
        dd = dot(d, d)
        par = lambda p: dot(sub(p, A), d) / dd  # noqa: E731
        pt = lambda t: add(A, scale(t, d))  # noqa: E731
        tA, tB = par(A), par(B)
        lo, hi = min(tA, tB), max(tA, tB)
        crit = {tA, tB}
        for f in (i, j):
            poly = polys3[f]
            m = len(poly)
            g = j if f == i else i
            hg = lambda p: dot(arr.nrm(g), p) + arr.q[g][3]  # noqa: E731
            for k in range(m):
                p, q = poly[k], poly[(k + 1) % m]
                hp, hq = hg(p), hg(q)
                if hp == 0:
                    crit.add(par(p))
                if hq == 0:
                    crit.add(par(q))
                if (hp > 0 and hq < 0) or (hp < 0 and hq > 0):
                    s = hp / (hp - hq)
                    crit.add(par(add(p, scale(s, sub(q, p)))))
        cl = sorted(crit)
        tests = list(cl)
        tests += [(cl[k] + cl[k + 1]) / 2 for k in range(len(cl) - 1)]
        tests += [cl[0] - 1, cl[-1] + 1]
        pri, prj = _proj2(arr, i), _proj2(arr, j)
        for t in tests:
            p = pt(t)
            both = point_in_closed_polygon2(pri(p), polys2[i]) and point_in_closed_polygon2(
                prj(p), polys2[j]
            )
            if both != (lo <= t <= hi):
                return False, f"(R3) fails for faces {i},{j} at parameter {t}"
    return True, "ok"


# --------------------------------------------------------------------------------------------
# the substantive constraints of the paper (H, A, B, I) as semantic records
# --------------------------------------------------------------------------------------------


def paper_constraints(M):
    """Substantive (non-definitional) constraints, written from sections 6-7 of the paper.

    Returned as a dict of lists:
      'H'      : (i, j, k, l, m)   i<j, k<l<m others: Ord(i,j;.,.) has no directed 3-cycle on k,l,m
      'A'      : (b, r_b, x, y, z) x<y<z others:     d^b has no directed 3-cycle on x,y,z
      'B'      : (f, a, b)         a<b, {f,a,b} not in T: not(OnB(f,a;b) and OnB(f,b;a))
      'Ivert'  : (f, g, h)         each {f,g,h} in T, as the three unordered pairs of corner bits
                                   {refl(f;g,h), refl(g;f,h)}, ... : not both
      'Iorient': f                 refl(f;g,z1) = XOR_v C_v & B_v  (g, z1 are the implementation's
                                   choice; any g in link(f) and any z1 in Ends(f,g) is sound)
    """
    L = M.labels
    out = {"H": [], "A": [], "B": [], "Ivert": [], "Iorient": []}
    for i, j in combinations(L, 2):
        rest = [u for u in L if u not in (i, j)]
        for k, l, m in combinations(rest, 3):
            out["H"].append((i, j, k, l, m))
    for b in L:
        r = min(u for u in L if u != b)
        rest = [u for u in L if u not in (b, r)]
        for x, y, z in combinations(rest, 3):
            out["A"].append((b, r, x, y, z))
    for f in L:
        rest = [u for u in L if u != f]
        for a, b in combinations(rest, 2):
            if frozenset((f, a, b)) not in M.T:
                out["B"].append((f, a, b))
    for t in sorted(tuple(sorted(t)) for t in M.T):
        out["Ivert"].append(t)
    out["Iorient"] = list(L)
    return out


def paper_counts(n):
    """Clause/variable counts per layer that the text of the paper implies (sec. 6-9, app. B)."""
    pairs = n * (n - 1) // 2
    m = n - 2
    V = n * (n - 1) // 3
    c2 = lambda k: k * (k - 1) // 2  # noqa: E731
    c3 = lambda k: k * (k - 1) * (k - 2) // 6  # noqa: E731
    onb = pairs * (n - 4) * 1  # u not in {i,j,z0,z1}
    return {
        "X_vars": (n + 1) * n * (n - 1) * (n - 2) // 24,
        "S_vars": pairs * c2(m),
        "S_clauses": 8 * pairs * c2(m),
        "H_clauses": 2 * pairs * c3(m),
        "A_vars": n * c2(n - 2),
        "A_clauses": 8 * n * c2(n - 2) + 2 * n * c3(n - 2),
        "B_vars": onb,
        "B_clauses": 4 * onb + (n * (c2(n - 1) - (n - 1))),
        "I_vertex_clauses": 3 * V,
        "corners": 3 * V,
        "orient_terms_per_face": n - 4,
    }


# --------------------------------------------------------------------------------------------
# self-test: the paper's dictionary against direct geometry
# --------------------------------------------------------------------------------------------


def random_map_like(n, rng):
    """For dictionary tests on random planes we need *some* neighbourly map to supply Ends/links.
    n=4: the tetrahedron; n=7: the 7-vertex torus (Z_7 difference construction)."""
    if n == 4:
        return tetra_map()
    if n == 7:
        tr = []
        for i in range(7):
            tr.append([i + 1, (i + 1) % 7 + 1, (i + 3) % 7 + 1])
            tr.append([i + 1, (i + 2) % 7 + 1, (i + 3) % 7 + 1])
        M = NMap(7, tr)
        perm = list(range(1, 8))
        rng.shuffle(perm)
        return M.relabel({k + 1: perm[k] for k in range(7)})
    raise ValueError


def selftest_dictionary(n, trials, seed):
    rng = random.Random(seed)
    stats = {"ord": 0, "onb": 0, "turn": 0, "Bv": 0, "d": 0, "group": 0}
    for _ in range(trials):
        M = random_map_like(n, rng)
        arr = random_arrangement(n, rng)
        PX = PaperX(M, arr.allX())
        L = M.labels
        for i in L:
            for j in L:
                if i == j:
                    continue
                rest = [u for u in L if u not in (i, j)]
                for k in rest:
                    for l in rest:
                        if k != l:
                            assert PX.ord(i, j, k, l) == ord_geom(arr, i, j, k, l), (
                                "ord",
                                i,
                                j,
                                k,
                                l,
                            )
                            stats["ord"] += 1
                z = M.ends(i, j)
                for u in rest:
                    if u not in z:
                        assert PX.onb(i, j, u) == onb_geom(M, arr, i, j, u)
                        stats["onb"] += 1
        for f in L:
            for rev in (False, True):
                for _x, a, b, _y in M.corners(f, rev):
                    assert PX.turn(f, a, b) == turn_geom(M, arr, f, a, b)
                    stats["turn"] += 1
            for g in L:
                if g == f:
                    continue
                for z1 in M.ends(f, g):
                    z0 = M.other_end(f, g, z1)
                    for v in L:
                        if v not in (f, g, z0, z1):
                            assert PX.Bv(f, g, z1, v) == Bv_geom(M, arr, f, g, z1, v)
                            stats["Bv"] += 1
        for b in L:
            for r in L:
                if r == b:
                    continue
                rest = [u for u in L if u not in (b, r)]
                for x in rest:
                    for y in rest:
                        if x != y:
                            assert PX.d(b, r, x, y) == d_geom(arr, b, r, x, y), ("d", b, r, x, y)
                            stats["d"] += 1
        # lem:gaugegroup: geometric action == the stated action on bits
        gamma = rng.randint(0, 1)
        eps = {i: rng.randint(0, 1) for i in L}
        X2 = arr.apply_group(gamma, eps).allX()
        for S, v in arr.allX().items():
            assert X2[S] == v ^ gamma ^ (sum(eps[i] for i in S if i >= 1) & 1)
            stats["group"] += 1
    return stats


if __name__ == "__main__":
    import time

    t0 = time.time()
    print("n=4 :", selftest_dictionary(4, 300, 1))
    print("n=7 :", selftest_dictionary(7, 60, 2))
    # tetrahedron: a real realization; all corners convex; realization test accepts it
    M = tetra_map()
    arr = Arr({1: (1, 0, 0, 0), 2: (0, 1, 0, 0), 3: (0, 0, 1, 0), 4: (1, 1, 1, -1)})
    ok, why = check_realization(M, arr, need_G=False)
    assert ok, why
    for f in M.labels:
        for _x, a, b, _y in M.corners(f):
            assert reflex_geom(M, arr, f, a, b) == 0
    print("tetrahedron ok; paper counts n=12:", paper_counts(12))
    print("selftest passed in %.1fs" % (time.time() - t0))
