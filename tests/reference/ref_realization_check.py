"""ref_realization_check.py -- the encoder on GENUINE realizations (n = 4 and n = 7), every relabelling.

Realizations (each one verified by the independent exact test ref_paper.check_realization:
simple faces, two faces meet exactly in their common edge, general position):
  n = 7  Szilassi polyhedron from the literature (Wikimedia Commons / CMG Lee coordinates, see
         ref_realizations.py), small random rational perturbations of its planes, their mirror images,
         random affine images, random projective images whose vanishing plane misses the
         polyhedron, random covector sign changes; and, separately, the project's own fixture
         planes (data/fixtures/szilassi) with the project's map -- checked by the same test;
  n = 4  the coordinate tetrahedron and random tetrahedra (any 4 planes in general position).

For every relabelling sigma of the faces (all 5040 for n = 7, all 24 for n = 4) the project's
encoder is run on the relabelled map sigma(T) -- 120 distinct labelled maps for n = 7 -- with
several gauge faces, and for realizations of sigma(T) (the relabelled planes):
  * exactly one of the 2^(n+1) elements of the reorientation group zeroes the pinned brackets
    (brute force over the whole group); it is applied GEOMETRICALLY and the bits recomputed;
  * unit propagation from the bracket bits over the WHOLE formula gives a total assignment with
    no conflict, and EVERY clause is satisfied;
  * every named variable equals its geometric meaning computed directly: o, d, OnB, and the
    corner bit == "the interior angle of the simple polygon exceeds pi" (shoelace rule),
    s_f == traversal bit;
  * the formula built for sigma(T) passes the exact comparison with the paper (ref_adapter.analyse);
  * for the formula without gauge: every one of the 2^(n+1) group images (bit action) of the
    geometric assignment is again a model.

A second stage (--walk-only STEPS) walks randomly inside the realization space of the 7-face map
(each step verified exactly), which crosses walls where non-vertex brackets change sign, and runs
the same checks on one realization per distinct bracket-sign vector found.

RUN
    python3 tests/reference/ref_realization_check.py [--quick] [--seed 3]
    Exit code 0 iff no problem.
"""

from __future__ import annotations

import argparse
import json
import random
import sys
import time
from collections import Counter
from fractions import Fraction as Fr
from itertools import permutations
from math import lcm
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ref_adapter as A
import ref_paper as R
import ref_realizations as RL

PROBLEMS = []
STATS = Counter()
_CF = {}


def integerize(arr):
    pl = {}
    for k, q in arr.q.items():
        if k:
            m = lcm(*[x.denominator for x in q])
            pl[k] = tuple(x * m for x in q)
    return R.Arr(pl)


def formula(n, M, gauge_face):
    key = (tuple(sorted(tuple(sorted(t)) for t in M.T)), gauge_face)
    if key not in _CF:
        cf = A.CodeFormula(n, M.T, gauge_face=gauge_face)
        pr, info = A.analyse(cf, check_group=True)
        for p in pr:
            PROBLEMS.append(f"n={n} map {key[0][:3]}.. gauge {gauge_face}: exact analysis: {p}")
        info.pop("polys", None)
        for note in info.get("notes", []):
            if not STATS["notes"]:
                print("NOTE:", note)
            STATS["notes"] += 1
        _CF[key] = (cf, A.Evaluator(cf), info)
        STATS[f"n{n}_formulas_built"] += 1
    return _CF[key]


def check_one(n, M, arr, gauge_face, tag, group_orbit=False):
    """M, arr: a verified realization (labels already final)."""
    cf, ev, _info = formula(n, M, gauge_face)
    X0 = arr.allX()
    if gauge_face is not None:
        sols = A.gauge_element(cf, X0)
        if sols is None or len(sols) != 1:
            PROBLEMS.append(
                f"{tag}: {0 if not sols else len(sols)} group elements move the realization into gauge"
            )
            return
        gamma, eps = sols[0]
        arr = arr.apply_group(gamma, eps)
        X = arr.allX()
    else:
        X = X0
    val, conflict = ev.propagate(X)
    if conflict is not None:
        PROBLEMS.append(
            f"{tag}: CONFLICT on a genuine realization at clause {cf.clauses[conflict]} "
            f"(tag {cf.enc.formula.tags[conflict]})"
        )
        return
    if len(val) != cf.nvars:
        PROBLEMS.append(f"{tag}: {cf.nvars - len(val)} variables undetermined")
        return
    viol = ev.violated(val)
    if viol:
        PROBLEMS.append(
            f"{tag}: {len(viol)} clauses VIOLATED on a genuine realization, e.g. "
            f"{[(cf.clauses[i], cf.enc.formula.tags[i]) for i in viol[:3]]}"
        )
        return
    STATS[f"n{n}_realizations_satisfying_all_clauses"] += 1
    STATS[f"n{n}_clauses_checked"] += len(cf.clauses)
    # meanings
    for (i, j, k, l), v in cf.o.items():
        if val[v] != R.ord_geom(arr, i, j, k, l):
            PROBLEMS.append(f"{tag}: o{(i, j, k, l)} != geometry")
            break
    for (b, r, x, y), v in cf.d.items():
        if val[v] != R.d_geom(arr, b, r, x, y):
            PROBLEMS.append(f"{tag}: d{(b, r, x, y)} != geometry")
            break
    for (i, j, u), v in cf.onb.items():
        if val[v] != R.onb_geom(M, arr, i, j, u):
            PROBLEMS.append(f"{tag}: OnB{(i, j, u)} != geometry")
            break
    nref = 0
    for (f, a, b), lit in cf.corner.items():
        got = val[abs(lit)] ^ (1 if lit < 0 else 0)
        nref += got
        if got != R.reflex_geom(M, arr, f, a, b):
            PROBLEMS.append(
                f"{tag}: corner bit {(f, a, b)} != true reflexness of the polygon corner"
            )
            break
    STATS[f"n{n}_reflex_corners_seen"] += nref
    for f in M.labels:
        sv = val[cf.s[f]]
        if sv not in (
            R.traversal_bit_geom(M, arr, f, False),
            R.traversal_bit_geom(M, arr, f, True),
        ):
            PROBLEMS.append(f"{tag}: s_{f} is not a traversal bit")
    if group_orbit and gauge_face is None:
        for g in range(1 << (n + 1)):
            gamma = g & 1
            Xg = {S: v ^ gamma ^ (sum((g >> i) & 1 for i in S if i >= 1) & 1) for S, v in X.items()}
            vg, conflict = ev.propagate(Xg)
            if conflict is not None or len(vg) != cf.nvars or ev.violated(vg):
                PROBLEMS.append(
                    f"{tag}: group element {g:b} maps a model of the ungauged formula to a non-model"
                )
                break
            STATS[f"n{n}_group_images_checked"] += 1


def pool_n7(rng, npert):
    M, arr = RL.szilassi()
    assert R.check_realization(M, arr, need_G=False)[0]
    pool = []
    for k in range(npert):
        a = integerize(RL.perturb(M, arr, rng))
        variants = [("perturbed", a)]
        variants.append(("mirror", a.mirror()))
        variants.append(("affine", integerize(RL.image(M, a, RL.random_affine(rng)))))
        for _ in range(100):
            p = integerize(RL.image(M, a, RL.random_projective(M, a, rng)))
            if p.general_position():
                variants.append(("projective", p))
                break
        signs = {i: rng.randint(0, 1) for i in M.labels}
        variants.append(("signflip", a.apply_group(0, signs)))
        for name, v in variants:
            ok, why = R.check_realization(M, v, need_G=True)
            assert ok, (name, why)
            RL.check_lemmas_on_realization(M, v)
            pool.append((f"szilassi-lit/{name}#{k}", v))
            STATS["n7_pool_" + name] += 1
    return M, pool


def project_fixture_n7():
    """The project's fixture: its map and its planes, verified by MY realization test."""
    import neighbourly.data as nd

    doc = json.loads(nd.read_bytes("fixtures", "szilassi", "szilassi.json"))
    text = nd.read_bytes("fixtures", "szilassi", "csaszar_n7.txt").decode()
    rows = [
        [int(x) for x in line.split()]
        for line in text.splitlines()
        if line.strip() and not line.startswith("#")
    ]
    triples = [[i + 1 for i, x in enumerate(r) if x] for r in rows]
    M = R.NMap(7, triples)
    out = []
    for key in ("published_planes", "planes"):
        arr = R.Arr({i + 1: tuple(Fr(x) for x in pl) for i, pl in enumerate(doc[key])})
        ok, why = R.check_realization(M, arr, need_G=(key == "planes"))
        out.append((key, ok, why, arr))
    return M, out


def walk_stage(steps, rng, t0):
    """Random walk inside the realization space of the 7-face torus map, started at the Szilassi
    polyhedron: every step is a small perturbation of the planes accepted only if the result is
    still a realization (exact test).  The walk crosses walls where non-vertex brackets change
    sign, so it yields realizations with DIFFERENT chirotopes.  One realization per distinct
    bracket-sign vector is kept and checked in many labellings."""
    Mlit, arr = RL.szilassi()
    Mp, _fx = project_fixture_n7()
    perms = list(permutations(range(1, 8)))
    to_project = [
        dict(zip(range(1, 8), p))
        for p in perms
        if Mlit.relabel(dict(zip(range(1, 8), p))).T == Mp.T
    ]
    cur = arr
    seen = {}
    for _step in range(steps):
        pl = {}
        for k, q in cur.q.items():
            if k:
                size = max(abs(x) for x in q)
                pl[k] = tuple(
                    Fr(round((x + size * Fr(rng.randint(-50, 50), 50 * 1500)) * 10**6), 10**6)
                    for x in q
                )
        a2 = R.Arr(pl)
        try:
            good, _why = R.check_realization(Mlit, a2, need_G=False)
        except (ValueError, AssertionError):
            good = False
        if not good:
            continue
        cur = a2
        if a2.general_position():
            X = a2.allX()
            key = tuple(X[S] for S in sorted(X))
            if key not in seen:
                seen[key] = integerize(a2)
    print(
        f"walk: {steps} steps, {len(seen)} realizations with pairwise distinct bracket-sign vectors "
        f"[{time.time() - t0:.0f}s]",
        flush=True,
    )
    for wi, a2 in enumerate(seen.values()):
        RL.check_lemmas_on_realization(Mlit, a2)
        for p in to_project:
            check_one(7, Mp, a2.relabel(p), 1, f"n=7 walk#{wi} project-map via {p}")
        for _ in range(12):
            perm = rng.sample(range(1, 8), 7)
            p = dict(zip(range(1, 8), perm))
            gf = rng.choice([1, 2, 3, 4, 5, 6, 7, None])
            check_one(
                7,
                Mlit.relabel(p),
                a2.relabel(p),
                gf,
                f"n=7 walk#{wi} perm {perm} gauge {gf}",
                group_orbit=True,
            )
        STATS["n7_walk_realizations"] += 1


def run(tets: int, npert: int, perm_step: int, seed: int) -> list[str]:
    """The stages n = 4 and n = 7 with the given sizes; the problems found (also in PROBLEMS).

    ``tets`` random tetrahedra besides the regular one, each in all 24 labellings; ``npert``
    perturbations of the Szilassi polyhedron, each with its mirror, affine, projective and
    sign-flipped images; every ``perm_step``-th of the 5040 labellings of seven faces.
    """
    PROBLEMS.clear()
    STATS.clear()
    rng = random.Random(seed)
    t0 = time.time()
    # ------------------------------------------------------------------ n = 4
    M4 = R.tetra_map()
    tets = [RL.tetrahedron()[1]] + [R.random_arrangement(4, rng) for _ in range(tets)]
    for t, arr in enumerate(tets):
        ok, why = R.check_realization(M4, arr)
        assert ok, why
        for perm in permutations(range(1, 5)):
            p = {k + 1: perm[k] for k in range(4)}
            arr2 = arr.relabel(p)
            gf = [1, 2, 3, 4, None][(t + sum(perm[:2])) % 5]
            check_one(
                4,
                M4.relabel(p),
                arr2,
                gf,
                f"n=4 tetra#{t} perm {perm} gauge {gf}",
                group_orbit=True,
            )
    print(f"n=4 done [{time.time() - t0:.0f}s]", dict(STATS), "problems", len(PROBLEMS), flush=True)

    # ------------------------------------------------------------------ n = 7
    Mp, fx = project_fixture_n7()
    for key, ok, why, _arr in fx:
        print(
            f"project fixture szilassi.json[{key}] with csaszar_n7.txt: independent realization test: {ok} ({why})"
        )
        if not ok:
            PROBLEMS.append(f"project fixture {key} is not a realization: {why}")
    Mlit, pool = pool_n7(rng, npert)
    print(f"n=7 pool of verified realizations: {len(pool)} [{time.time() - t0:.0f}s]", flush=True)
    labelled = set()
    to_project = []
    perms = list(permutations(range(1, 8)))
    perms = perms[::perm_step]
    for pi, perm in enumerate(perms):
        p = {k + 1: perm[k] for k in range(7)}
        Mrel = Mlit.relabel(p)
        labelled.add(Mrel.T)
        if Mrel.T == Mp.T:
            to_project.append(p)
        picks = [pool[(pi * 2) % len(pool)], pool[(pi * 2 + 1 + pi // len(pool)) % len(pool)]]
        gfs = [1, [2, 3, 4, 5, 6, 7, None][pi % 7]]
        for (name, arr), gf in zip(picks, gfs):
            check_one(
                7,
                Mrel,
                arr.relabel(p),
                gf,
                f"n=7 {name} perm {perm} gauge {gf}",
                group_orbit=(pi % 3 == 0),
            )
        if pi % 500 == 0:
            print(
                f"  perm {pi}/{len(perms)} problems {len(PROBLEMS)} [{time.time() - t0:.0f}s]",
                flush=True,
            )
    print(
        f"n=7: {len(perms)} relabellings, {len(labelled)} distinct labelled maps; "
        f"{len(to_project)} relabellings carry the literature polyhedron onto the project's map"
    )
    # every pool realization, in every labelling that gives the PROJECT's map, default gauge 1
    for p in to_project:
        for name, arr in pool:
            check_one(7, Mp, arr.relabel(p), 1, f"n=7 project-map {name} via {p}")
            STATS["n7_project_map_labelled_realizations"] += 1
    # the project's own fixture planes
    for key, ok, _why, arr in fx:
        if ok and arr.general_position():
            for gf in (1, 2, 3, 4, 5, 6, 7, None):
                check_one(7, Mp, arr, gf, f"n=7 project fixture {key} gauge {gf}", group_orbit=True)
                STATS["n7_project_fixture_checked"] += 1
    return list(PROBLEMS)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true")
    ap.add_argument("--seed", type=int, default=3)
    ap.add_argument(
        "--walk-only",
        type=int,
        default=0,
        metavar="STEPS",
        help="run only the random-walk stage with this many steps",
    )
    a = ap.parse_args()
    t0 = time.time()
    print("project code:", A.PROJECT_FILE)
    if a.walk_only:
        walk_stage(a.walk_only, random.Random(a.seed), t0)
    elif a.quick:
        run(40, 2, 37, a.seed)
    else:
        run(400, 8, 1, a.seed)
    print("STATS", dict(STATS))
    for p in PROBLEMS[:40]:
        print("PROBLEM:", p)
    kinds = Counter()
    for p in PROBLEMS:
        kinds[
            "exact-analysis"
            if "exact analysis" in p
            else "clause-violated-on-genuine-realization"
            if ("VIOLATED" in p or "CONFLICT" in p)
            else "gauge-loses-realization"
            if "group elements move" in p
            else "meaning-differs-from-geometry"
            if "!=" in p
            else "other"
        ] += 1
    print("PROBLEM KINDS:", dict(kinds))
    print(f"TOTAL PROBLEMS: {len(PROBLEMS)}   wall {time.time() - t0:.0f}s")
    sys.exit(1 if PROBLEMS else 0)


if __name__ == "__main__":
    main()
