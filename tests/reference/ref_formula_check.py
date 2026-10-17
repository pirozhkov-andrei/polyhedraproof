"""ref_formula_check.py -- the real n=12 formulas against the paper, without the code's conventions.

For every selected map of the 59 (default: all):
  (0) the encoder's DIMACS bytes have the SHA-256 of the packaged golden fixture, so what is
      analysed here IS the campaign formula;
  (1) EXACT: ref_adapter.analyse -- substantive clauses == the paper's H, A, B, I-vertex, gauge
      sets; everything else is a pure list of definitions; the ANF of every named variable equals
      the paper's formula; gauge rank n+1; G-invariance;
  (2) NUMERIC, on random arrangements of 12 planes in general position (three distributions):
      bracket bits from exact determinants -> gauge element (unique) -> applied GEOMETRICALLY
      (covector sign flips, mirror image) -> bits recomputed -> unit propagation on the formula
      (B and I-vertex clauses excluded from propagation: random planes are not polyhedra) ->
      every variable compared with the predicate computed DIRECTLY from geometry
      (ref_paper.ord_geom, d_geom, onb_geom, refl_invariant_geom), every clause of S, H, A, the
      definitions and the gauge checked; every B clause is violated iff the two segments
      really cross (independent 2D segment test).

RUN
    python3 tests/reference/ref_formula_check.py [--maps 1-59] [--arr 12]
        [--procs 2] [--seed 1]
Exit code 0 iff no problem was found.
"""

from __future__ import annotations

import argparse
import random
import sys
import time
from collections import Counter
from fractions import Fraction as Fr
from itertools import combinations
from multiprocessing import Pool
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ref_adapter as A
import ref_paper as R

from neighbourly import corpus12


def arrangement(n, rng, kind):
    while True:
        if kind == 0:
            pl = {i: tuple(rng.randint(-9, 9) for _ in range(4)) for i in range(1, n + 1)}
        elif kind == 1:
            pl = {i: tuple(rng.randint(-40, 40) for _ in range(4)) for i in range(1, n + 1)}
        else:  # planes all at distance about 1 from the origin (a convex polytope's planes)
            pl = {}
            for i in range(1, n + 1):
                v = [rng.randint(-20, 20) for _ in range(3)]
                if v == [0, 0, 0]:
                    v = [1, 2, 3]
                norm2 = sum(x * x for x in v)
                # d with |d| ~ |v| * (1 + small): use a rational approximation of sqrt
                root = Fr(int(norm2**0.5 * 1000), 1000)
                pl[i] = (v[0], v[1], v[2], -root * Fr(rng.randint(90, 130), 100))
        a = R.Arr(pl)
        if all(any(a.nrm(i)) for i in range(1, n + 1)) and a.general_position():
            return a


def numeric(cf, info, pred, rng, kind, dirs):
    M, n = cf.M, cf.n
    problems = []
    arr0 = arrangement(n, rng, kind)
    X0 = arr0.allX()
    sols = A.gauge_element(cf, X0)
    if sols is None or len(sols) != 1:
        return [f"gauge: group element not unique/absent: {sols}"], {}
    gamma, eps = sols[0]
    arr = arr0.apply_group(gamma, eps)
    X = arr.allX()
    if any(X[tuple(S)] for S in cf.gauge):
        problems.append(
            "gauge: geometric action of the group element does not zero the pinned brackets"
        )
    index = {}
    for idx, c in enumerate(cf.clauses):
        index.setdefault(frozenset(c), idx)
    skip = frozenset(index[c] for kind_ in ("B", "Ivert") for c in pred[kind_])
    ev = numeric.ev
    val, conflict = ev.propagate(X, skip)
    if conflict is not None:
        problems.append(f"conflict in S/H/A/definitions/gauge at clause {cf.clauses[conflict]}")
        return problems, {}
    if len(val) != cf.nvars:
        problems.append(f"unit propagation leaves {cf.nvars - len(val)} variables undetermined")
        return problems, {}
    viol = set(ev.violated(val))
    bad = viol - skip
    if bad:
        problems.append(
            f"{len(bad)} violated clauses outside B/I-vertex, e.g. {[cf.clauses[i] for i in sorted(bad)[:3]]}"
        )
    stats = Counter()
    for (i, j, k, l), v in cf.o.items():
        stats["o"] += 1
        if val[v] != R.ord_geom(arr, i, j, k, l):
            problems.append(f"o{(i, j, k, l)} != geometry")
            break
    for (b, r, x, y), v in cf.d.items():
        stats["d"] += 1
        if val[v] != R.d_geom(arr, b, r, x, y):
            problems.append(f"d{(b, r, x, y)} != geometry")
            break
    onbg = {}
    for (i, j, u), v in cf.onb.items():
        stats["onb"] += 1
        onbg[(i, j, u)] = g = R.onb_geom(M, arr, i, j, u)
        if val[v] != g:
            problems.append(f"OnB{(i, j, u)} != geometry")
            break
    for f in M.labels:
        g, z1 = info["pins"][f]
        par = R.crossing_parity_geom(M, arr, f, g, z1)
        tpin = {}
        for rev in (False, True):
            (c2,) = [c for c in M.corners(f, rev) if {c[1], c[2]} == {g, z1}]
            tpin[rev] = R.turn_geom(M, arr, f, c2[1], c2[2])
        for (ff, a, b), lit in cf.corner.items():
            if ff != f:
                continue
            (c1,) = [c for c in M.corners(f) if {c[1], c[2]} == {a, b}]
            expect = R.turn_geom(M, arr, f, c1[1], c1[2]) ^ tpin[False] ^ par
            got = val[abs(lit)] ^ (1 if lit < 0 else 0)
            stats["refl"] += 1
            if got != expect:
                problems.append(f"corner bit {(f, a, b)} != geometry")
                break
        # s_f: turn(pin corner) xor parity in the code's (fixed) traversal direction
        sv = val[cf.s[f]]
        match = {rev for rev in (False, True) if sv == tpin[rev] ^ par}
        dirs.setdefault(f, {False, True})
        dirs[f] &= match
        stats["s"] += 1
        if not dirs[f]:
            problems.append(f"s_{f} is not the traversal bit of a fixed direction")
    # B clauses: violated iff the two edges really cross (independent segment test)
    for c in pred["B"]:
        idx = index[c]
        stats["B"] += 1
    for f in M.labels:
        pr = R._proj2(arr, f)
        seg = {}
        for a in M.labels:
            if a != f:
                z0, z1 = M.ends(f, a)
                seg[a] = (pr(arr.P(f, a, z0)), pr(arr.P(f, a, z1)))
        for a, b in combinations([u for u in M.labels if u != f], 2):
            if M.adjacent_in_link(f, a, b):
                continue
            cross = R._segments_meet2(*seg[a], *seg[b])
            cl = frozenset((-cf.onb[(min(f, a), max(f, a), b)], -cf.onb[(min(f, b), max(f, b), a)]))
            if (index[cl] in viol) != cross:
                problems.append(
                    f"B clause for face {f}, edges {a},{b}: violated={index[cl] in viol}, crossing={cross}"
                )
            stats["Bx"] += cross
    stats["viol_B_Ivert"] = len(viol & skip)
    return problems, stats


def work(args):
    map_id, narr, seed = args
    t0 = time.time()
    cmap = corpus12.load_map(map_id)
    cf = A.CodeFormula(12, cmap.triples)
    golden = corpus12.formula_hashes()[map_id]
    sha = cf.dimacs_sha256()
    problems, info = A.analyse(cf)
    problems = [f"map {map_id}: {p}" for p in problems]
    sha_ok = (
        sha == golden.sha256 and cf.nvars == golden.variables and len(cf.clauses) == golden.clauses
    )
    stats = Counter()
    if not problems and narr:
        pred, _ = A.predicted_substantive(cf)
        numeric.ev = A.Evaluator(cf)
        rng = random.Random(seed * 1000 + map_id)
        dirs = {}
        for t in range(narr):
            pr, st = numeric(cf, info, pred, rng, t % 3, dirs)
            problems += [f"map {map_id} arrangement {t}: {p}" for p in pr]
            stats.update(st)
            stats["arrangements"] += 1
    info.pop("polys", None)
    return map_id, sha_ok, sha, problems, info, dict(stats), time.time() - t0


def parse_maps(text):
    out = []
    for part in text.split(","):
        a, _, b = part.partition("-")
        out += list(range(int(a), int(b or a) + 1))
    return out


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--maps", default="1-59")
    ap.add_argument("--arr", type=int, default=12)
    ap.add_argument("--procs", type=int, default=2)
    ap.add_argument("--seed", type=int, default=1)
    a = ap.parse_args()
    print("project code:", A.PROJECT_FILE)
    jobs = [(m, a.arr, a.seed) for m in parse_maps(a.maps)]
    total = Counter()
    nprob = 0
    shabad = []
    t0 = time.time()
    with Pool(a.procs) as pool:
        for map_id, sha_ok, sha, problems, info, stats, dt in pool.imap(work, jobs):
            total.update(stats)
            nprob += len(problems)
            if not sha_ok:
                shabad.append(map_id)
            print(
                f"map {map_id:2d}: sha256 {'== golden' if sha_ok else '!= GOLDEN'} {sha[:16]} vars {info['vars']} "
                f"clauses {info['clauses']} H {info.get('pred_H')} A {info.get('pred_A')} B {info.get('pred_B')} "
                f"Ivert {info.get('pred_Ivert')} defs {info['definitional_clauses']} deg {info['max_degree']} "
                f"gauge rank {info.get('gauge_rank')} paper-pin {info['pin_is_paper_choice']} "
                f"G-inv {info.get('group_invariance_checked', False)} problems {len(problems)} [{dt:.0f}s]",
                flush=True,
            )
            for p in problems[:20]:
                print("   PROBLEM:", p, flush=True)
            for note in info.get("notes", []):
                print("   NOTE:", note, flush=True)
    print("totals of numeric comparisons:", dict(total))
    print(f"maps with hash != golden: {shabad}")
    print(f"TOTAL PROBLEMS: {nprob}   wall {time.time() - t0:.0f}s")
    sys.exit(1 if nprob or shabad else 0)
