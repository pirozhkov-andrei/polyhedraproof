"""ref_realizations.py -- genuine realizations for n=4 and n=7, built from the literature (not from the
project) and verified independently; generators of perturbed / relabelled / mirrored / affine /
projective images.

SOURCE OF THE n=7 COORDINATES
    Szilassi polyhedron, vertex list and face cycles of the Python script on the Wikimedia Commons
    page "File:Szilassi polyhedron.stl" by CMG Lee (2018), which is Szilassi's original
    coordinate set scaled by 20.  (Wikimedia Commons, Szilassi_polyhedron.stl.)

WHAT IS CHECKED HERE (self-test)
    * the 7 faces are planar hexagons, every vertex lies on exactly 3 faces, the triples form a
      neighbourly map (M1),(M2) which is orientable, the link order reproduces the given faces;
    * exact (R1)-(R4): faces are simple polygons and any two faces meet exactly in their common
      edge (ref_paper.check_realization) -- for the original and for every generated image;
    * lem:onereflex and lem:parity on these realizations by direct geometry.

RUN
    python3 tests/reference/ref_realizations.py
"""

from __future__ import annotations

import random
import sys
from fractions import Fraction as Fr
from itertools import combinations
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ref_paper as R

SZ_VERTS = [
    (-240, 0, 240),
    (240, 0, 240),
    (0, -252, -240),
    (0, 252, -240),
    (40, -100, -160),
    (-40, 100, -160),
    (-75, -75, -60),
    (75, 75, -60),
    (90, -50, 40),
    (-90, 50, 40),
    (-140, 0, 40),
    (140, 0, 40),
    (-140, -50, 40),
    (140, 50, 40),
]
# face cycles as on the Commons page; the last two faces are given there as two quadrilaterals
# each, glued here along their common diagonal (5,10) resp. (4,11)
SZ_FACES = [
    (11, 13, 9, 10, 12, 8),
    (6, 4, 2, 10, 9, 7),
    (7, 5, 3, 11, 8, 6),
    (9, 13, 1, 0, 5, 7),
    (8, 12, 0, 1, 4, 6),
    (5, 3, 2, 10, 12, 0),  # (5,10,2,3) + (0,12,10,5)
    (4, 2, 3, 11, 13, 1),
]  # (4,11,3,2) + (1,13,11,4)


def plane_through(pts):
    p0, p1, p2 = pts[0], pts[1], pts[2]
    nrm = R.cross(R.sub(p1, p0), R.sub(p2, p0))
    assert nrm != (0, 0, 0)
    d = -R.dot(nrm, p0)
    return (Fr(nrm[0]), Fr(nrm[1]), Fr(nrm[2]), Fr(d))


def szilassi():
    """Returns (NMap, Arr) with faces labelled 1..7 in the order of SZ_FACES."""
    V = [tuple(Fr(c) for c in v) for v in SZ_VERTS]
    planes = {}
    for fi, cyc in enumerate(SZ_FACES, start=1):
        # three non-collinear vertices of the cycle
        for a, b, c in combinations(cyc, 3):
            if R.cross(R.sub(V[b], V[a]), R.sub(V[c], V[a])) != (0, 0, 0):
                planes[fi] = plane_through([V[a], V[b], V[c]])
                break
        q = planes[fi]
        on = [k for k in range(14) if R.dot(q[:3], V[k]) + q[3] == 0]
        assert sorted(on) == sorted(cyc), (fi, on, cyc)  # planar; exactly its own six vertices
    triples = []
    for k in range(14):
        fs = [fi for fi, cyc in enumerate(SZ_FACES, start=1) if k in cyc]
        assert len(fs) == 3, (k, fs)
        triples.append(fs)
    M = R.NMap(7, triples)
    assert M.is_orientable()
    arr = R.Arr(planes)
    # vertices are the triple points; the polygon of def:realization is the given face cycle
    for k in range(14):
        fs = [fi for fi, cyc in enumerate(SZ_FACES, start=1) if k in cyc]
        assert arr.P(*fs) == V[k]
    for fi, cyc in enumerate(SZ_FACES, start=1):
        poly = R.face_polygon(M, arr, fi)
        idx = [V.index(p) for p in poly]
        m = len(cyc)
        rots = [tuple(cyc[(s + d * t) % m] for t in range(m)) for s in range(m) for d in (1, -1)]
        assert tuple(idx) in rots, (fi, idx, cyc)
    return M, arr


def tetrahedron():
    M = R.tetra_map()
    arr = R.Arr({1: (1, 0, 0, 0), 2: (0, 1, 0, 0), 3: (0, 0, 1, 0), 4: (1, 1, 1, -1)})
    return M, arr


def vertices(M, arr):
    return [arr.P(*t) for t in M.T]


def perturb(M, arr, rng, scale_den=2000, tries=200):
    """Small random rational perturbation of the covectors that is still a realization, in
    general position (verified exactly)."""
    for _ in range(tries):
        pl = {}
        for k, q in arr.q.items():
            if k == 0:
                continue
            size = max(abs(x) for x in q)
            pl[k] = tuple(x + size * Fr(rng.randint(-50, 50), 50 * scale_den) for x in q)
        a2 = R.Arr(pl)
        try:
            ok, _why = R.check_realization(M, a2, need_G=True)
        except (ValueError, AssertionError):
            ok = False
        if ok:
            return a2
    raise RuntimeError("no valid perturbation found")


def random_affine(rng):
    while True:
        A = [[Fr(rng.randint(-5, 5)) for _ in range(3)] for _ in range(3)]
        if R.det3(*A) != 0:
            break
    b = [Fr(rng.randint(-7, 7)) for _ in range(3)]
    return [A[0] + [b[0]], A[1] + [b[1]], A[2] + [b[2]], [Fr(0), Fr(0), Fr(0), Fr(1)]]


def random_projective(M, arr, rng):
    """4x4 matrix whose 'vanishing plane' (last row) is strictly positive on all vertices, so the
    plane sent to infinity misses the convex hull of the polyhedron."""
    verts = vertices(M, arr)
    while True:
        rows = [[Fr(rng.randint(-5, 5)) for _ in range(4)] for _ in range(4)]
        # make the last row a genuinely non-affine plane, far enough from the polyhedron
        c = [Fr(rng.randint(-3, 3)) for _ in range(3)]
        if c == [0, 0, 0]:
            continue
        m = min(R.dot(c, v) for v in verts)
        rows[3] = [*c, -m + Fr(rng.randint(1, 40), rng.randint(1, 4))]
        if R.det4(rows) != 0:
            return rows


def image(M, arr, Mx):
    """Image arrangement under the projective/affine map Mx; verified to carry vertices to the
    triple points of the image planes."""
    a2 = arr.transform(Mx)
    for t in M.T:
        assert a2.P(*t) == R.apply_point(Mx, arr.P(*t))
    return a2


def check_lemmas_on_realization(M, arr):
    """lem:onereflex and lem:parity by direct geometry (for all g and both z1)."""
    for t in M.T:
        f, g, h = sorted(t)
        s = (
            R.reflex_geom(M, arr, f, g, h)
            + R.reflex_geom(M, arr, g, f, h)
            + R.reflex_geom(M, arr, h, f, g)
        )
        assert s <= 1, ("lem:onereflex", t)
    for f in M.labels:
        for g in M.labels:
            if g == f:
                continue
            for z1 in M.ends(f, g):
                assert R.reflex_geom(M, arr, f, g, z1) == R.crossing_parity_geom(
                    M, arr, f, g, z1
                ), ("lem:parity", f, g, z1)
        # lem:sf: reflex == [w<0] xor s_f, in either traversal direction
        for rev in (False, True):
            s = R.traversal_bit_geom(M, arr, f, rev)
            for _x, a, b, _y in M.corners(f, rev):
                assert R.reflex_geom(M, arr, f, a, b) == R.turn_geom(M, arr, f, a, b) ^ s


if __name__ == "__main__":
    rng = random.Random(7)
    M, arr = szilassi()
    ok, why = R.check_realization(M, arr, need_G=False)
    print("Szilassi (Commons/CMG Lee coordinates): realization (R1)-(R4):", ok, why)
    assert ok
    print("  in general position as given:", arr.general_position())
    nreflex = sum(
        R.reflex_geom(M, arr, f, a, b) for f in M.labels for (_x, a, b, _y) in M.corners(f)
    )
    print("  reflex corners (of 42):", nreflex)
    print("  real vertices:", sorted(tuple(sorted(t)) for t in M.T))
    cnt = 0
    for _ in range(20):
        a2 = perturb(M, arr, rng)
        check_lemmas_on_realization(M, a2)
        a3 = image(M, a2, random_affine(rng))
        assert R.check_realization(M, a3)[0]
        check_lemmas_on_realization(M, a3)
        a4 = image(M, a2, random_projective(M, a2, rng))
        ok4, why4 = R.check_realization(M, a4, need_G=False)
        assert ok4, why4
        if a4.general_position():
            check_lemmas_on_realization(M, a4)
            cnt += 1
    print("  20 perturbations + affine images ok; projective images in general position:", cnt)
    Mt, at = tetrahedron()
    assert R.check_realization(Mt, at)[0]
    check_lemmas_on_realization(Mt, at)
    print("tetrahedron ok")
