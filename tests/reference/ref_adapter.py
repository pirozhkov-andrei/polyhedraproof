"""ref_adapter.py -- bridge between the project's encoder and the independent reference ref_paper.

WHAT IT DOES
    * imports the project's encoder;
    * takes from the project ONLY: the clause list, the variable count and the *names* of the
      meaningful variables (X_S, o, d, OnB, corner literal, s_f).  Clause tags are not used;
    * `analyse(...)` then proves, exactly and for ALL assignments of the bracket bits:
        1. the clauses split into (a) the substantive clauses predicted from the paper by
           ref_paper.paper_constraints -- H, A, B, I-vertex, gauge -- as an exact set comparison,
           and (b) a remainder that is a pure, acyclic list of gate definitions: every remaining
           clause is consumed by a group that defines one fresh variable as a total function of
           already defined ones (truth-table test, so nothing about the encoder's XOR splitting
           or Tseitin conventions is assumed).  Any clause that is in neither class is reported:
           it is a candidate strengthening;
        2. the algebraic normal form (polynomial over F_2 in the 715 bracket bits) of every
           named variable, obtained from those gate definitions, equals the ANF of the paper's
           formula for the predicate the name claims (thm:order, layer A, def:onb, lem:turn +
           lem:sf + lem:parity), computed by ref_paper.PaperX on symbolic bits;
        3. the n+1 gauge brackets have independent functionals (own Gaussian elimination);
        4. the formula without the gauge is invariant under the reorientation group G
           (symbolically on the ANFs, generator by generator).
    * `Evaluator` computes all variable values from bracket bits by plain unit propagation on the
      full clause list (own implementation) and checks every clause.

USED BY  ref_formula_check.py, ref_realization_check.py
"""

from __future__ import annotations

import sys
from collections import Counter, defaultdict
from itertools import combinations, product
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import ref_paper as R

import neighbourly
from neighbourly.encoding import build_encoder
from neighbourly.maps import CombinatorialMap

PROJECT_FILE = neighbourly.__file__


# --------------------------------------------------------------------------------------------
# polynomials over F_2 (algebraic normal form)
# --------------------------------------------------------------------------------------------

_EMPTY = frozenset()


class P:
    """Polynomial over F_2: a frozenset of monomials, a monomial = frozenset of variable ids."""

    __slots__ = ("m",)

    def __init__(self, m):
        self.m = m

    @staticmethod
    def const(c):
        return P(frozenset([_EMPTY])) if c & 1 else P(frozenset())

    @staticmethod
    def var(v):
        return P(frozenset([frozenset([v])]))

    def __xor__(self, o):
        if isinstance(o, int):
            o = P.const(o)
        return P(self.m ^ o.m)

    __rxor__ = __xor__

    def __and__(self, o):
        if isinstance(o, int):
            o = P.const(o)
        acc = set()
        for a in self.m:
            for b in o.m:
                acc ^= {a | b}
        return P(frozenset(acc))

    __rand__ = __and__

    def __eq__(self, o):
        return isinstance(o, P) and self.m == o.m

    def __hash__(self):
        return hash(self.m)

    def degree(self):
        return max((len(x) for x in self.m), default=0)

    def substitute_flip(self, flipped):
        """Polynomial after x -> x+1 for every variable id in `flipped`."""
        acc = set()
        for mono in self.m:
            fl = [v for v in mono if v in flipped]
            keep = frozenset(v for v in mono if v not in flipped)
            # prod (x+1) over fl = sum over subsets
            for r in range(len(fl) + 1):
                for sub in combinations(fl, r):
                    acc ^= {keep | frozenset(sub)}
        return P(frozenset(acc))

    def evaluate(self, val):
        s = 0
        for mono in self.m:
            if all(val[v] for v in mono):
                s ^= 1
        return s


# --------------------------------------------------------------------------------------------
# the project's formula, reduced to clauses + names
# --------------------------------------------------------------------------------------------


class CodeFormula:
    def __init__(self, n, triples, gauge_face=1, layers="S,H,A,B,I"):
        self.n = n
        self.triples = sorted(tuple(sorted(t)) for t in triples)
        cmap = CombinatorialMap(n, self.triples)
        enc = build_encoder(cmap, layers, gauge_face)
        self.enc = enc
        self.gauge_face = gauge_face
        self.clauses = [tuple(c) for c in enc.clauses]
        self.nvars = enc.variables
        # names (claims about meaning, verified in analyse)
        self.X = dict(enc.brackets)  # sorted 4-subset -> var
        self.o = {
            (i, j, k, l): v for (i, j), row in enc.line_orders.items() for (k, l), v in row.items()
        }
        self.d = {
            (b, c, x, y): v for (b, c), row in enc.cut_orders.items() for (x, y), v in row.items()
        }
        self.onb = dict(enc.boundary_bits)  # (i,j,u), i<j -> var
        self.corner = dict(enc.corner_bits)  # (f,a,b) -> literal of refl
        self.s = dict(enc.face_orientation_bits)  # f -> var
        self.gauge = list(enc.gauge_targets(gauge_face)) if gauge_face is not None else []
        self.M = R.NMap(n, self.triples)

    def dimacs_sha256(self):
        import hashlib

        body = "".join(" ".join(map(str, c)) + " 0\n" for c in self.clauses)
        return hashlib.sha256(
            (f"p cnf {self.nvars} {len(self.clauses)}\n" + body).encode()
        ).hexdigest()


# --------------------------------------------------------------------------------------------
# substantive clauses predicted from the paper, in the code's variable ids
# --------------------------------------------------------------------------------------------


def code_cut_points(cf):
    """Cut point used by the code for each face b, if it is a single face != b; else the paper's.
    lem:cutorder holds for ANY cut point, so a different one is a deviation from the paper's
    text (r_b = smallest face != b) but not a strengthening."""
    cuts = {}
    for b in cf.M.labels:
        cs = {k[1] for k in cf.d if k[0] == b}
        paper = min(u for u in cf.M.labels if u != b)
        cuts[b] = next(iter(cs)) if len(cs) == 1 and next(iter(cs)) != b else paper
    return cuts


def a_triples(cf, cuts):
    for b in cf.M.labels:
        r = cuts[b]
        rest = [u for u in cf.M.labels if u not in (b, r)]
        for x, y, z in combinations(rest, 3):
            yield (b, r, x, y, z)


def predicted_substantive(cf):
    """Returns dict kind -> list of frozenset(literals), from ref_paper.paper_constraints."""
    pc = R.paper_constraints(cf.M)
    out = defaultdict(list)
    missing_names = []

    def name(table, key):
        if key not in table:
            missing_names.append(key)
            return None
        return table[key]

    for i, j, k, l, m in pc["H"]:
        a, b, c = name(cf.o, (i, j, k, l)), name(cf.o, (i, j, l, m)), name(cf.o, (i, j, k, m))
        if None in (a, b, c):
            continue
        out["H"].append(frozenset((-a, -b, c)))
        out["H"].append(frozenset((a, b, -c)))
    cuts = code_cut_points(cf)
    for b_, r, x, y, z in a_triples(cf, cuts):
        a, b, c = name(cf.d, (b_, r, x, y)), name(cf.d, (b_, r, y, z)), name(cf.d, (b_, r, x, z))
        if None in (a, b, c):
            continue
        out["A"].append(frozenset((-a, -b, c)))
        out["A"].append(frozenset((a, b, -c)))
    for f, a, b in pc["B"]:
        u = name(cf.onb, (min(f, a), max(f, a), b))
        v = name(cf.onb, (min(f, b), max(f, b), a))
        if None in (u, v):
            continue
        out["B"].append(frozenset((-u, -v)))

    def corner(f, a, b):
        if (f, a, b) in cf.corner:
            return cf.corner[(f, a, b)]
        if (f, b, a) in cf.corner:
            return cf.corner[(f, b, a)]
        missing_names.append(("corner", f, a, b))
        return None

    for f, g, h in pc["Ivert"]:
        lits = [corner(f, g, h), corner(g, f, h), corner(h, f, g)]
        if None in lits:
            continue
        for p, q in combinations(lits, 2):
            out["Ivert"].append(frozenset((-p, -q)))
    for S in cf.gauge:
        out["gauge"].append(frozenset((-cf.X[tuple(S)],)))
    return out, missing_names


# --------------------------------------------------------------------------------------------
# gate extraction on the remaining clauses
# --------------------------------------------------------------------------------------------


def extract_definitions(nvars, clauses, inputs):
    """clauses: list of tuples.  inputs: iterable of variable ids that are free.
    Returns (defs, order, leftovers, undefined) where defs[y] = (input_vars, truth_table dict)
    and leftovers = indices of clauses consumed by no definition."""
    occ = defaultdict(list)
    for idx, c in enumerate(clauses):
        for lit in c:
            occ[abs(lit)].append(idx)
    defined = set(inputs)
    undef_count = [sum(1 for lit in c if abs(lit) not in defined) for c in clauses]
    used = [False] * len(clauses)
    defs = {}
    order = []
    problems = []
    cand = set()
    for idx, c in enumerate(clauses):
        if undef_count[idx] == 1:
            cand.add(next(abs(lit) for lit in c if abs(lit) not in defined))
    while cand:
        y = min(cand)
        cand.discard(y)
        if y in defined:
            continue
        group = [idx for idx in occ[y] if not used[idx] and undef_count[idx] == 1]
        ins = sorted({abs(lit) for idx in group for lit in clauses[idx]} - {y})
        if len(ins) > 10:
            problems.append(("too-wide", y, len(ins)))
            continue
        table = {}
        status = "ok"
        for bits in product((0, 1), repeat=len(ins)):
            val = dict(zip(ins, bits))
            ok = []
            for yv in (0, 1):
                val[y] = yv
                ok.append(
                    all(any((val[abs(l)] == 1) == (l > 0) for l in clauses[idx]) for idx in group)
                )
            if ok == [True, True]:
                status = "under"
                break
            if ok == [False, False]:
                status = "over"
                break
            table[bits] = 0 if ok[0] else 1
        if status == "under":
            continue  # wait for more clauses to become eligible
        if status == "over":
            problems.append(("constrains-inputs", y, [clauses[idx] for idx in group]))
            continue
        defs[y] = (ins, table)
        order.append(y)
        defined.add(y)
        for idx in group:
            used[idx] = True
        for idx in occ[y]:
            undef_count[idx] -= 1
            if undef_count[idx] == 1 and not used[idx]:
                cand.add(next(abs(lit) for lit in clauses[idx] if abs(lit) not in defined))
    leftovers = [idx for idx in range(len(clauses)) if not used[idx]]
    undefined = [v for v in range(1, nvars + 1) if v not in defined]
    return defs, order, leftovers, undefined, problems


def anf_of_table(ins, table, polys):
    """ANF of the function given by a truth table over `ins`, composed with polys[ins]."""
    k = len(ins)
    # Moebius transform
    coeff = {}
    for bits in product((0, 1), repeat=k):
        coeff[bits] = table[bits]
    for pos in range(k):
        for bits in product((0, 1), repeat=k):
            if bits[pos]:
                lower = (*bits[:pos], 0, *bits[pos + 1 :])
                coeff[bits] ^= coeff[lower]
    acc = P.const(0)
    for bits, c in coeff.items():
        if c:
            term = P.const(1)
            for pos in range(k):
                if bits[pos]:
                    term = term & polys[ins[pos]]
            acc = acc ^ term
    return acc


# --------------------------------------------------------------------------------------------
# the exact analysis
# --------------------------------------------------------------------------------------------


def gf2_rank(vectors):
    basis = []
    for v in vectors:
        for b in basis:
            v = min(v, v ^ b)
        if v:
            basis.append(v)
    return len(basis)


def analyse(cf, check_group=True, verbose=False):
    """Returns (problems: list[str], info: dict)."""
    problems = []
    info = {}
    M, n = cf.M, cf.n
    # ---- names: completeness of the claimed tables
    allS = list(combinations(range(n + 1), 4))
    if sorted(cf.X) != allS:
        problems.append("bracket variables are not exactly the 4-subsets of 0..n")
    if len(set(cf.X.values())) != len(allS):
        problems.append("bracket variables not distinct")
    # ---- 1a. substantive clauses: exact set comparison
    pred, missing = predicted_substantive(cf)
    if missing:
        problems.append(
            f"{len(missing)} predicates of the paper have no named variable, e.g. {missing[:3]}"
        )
    bag = Counter(frozenset(c) for c in cf.clauses)
    dups = {c: k for c, k in bag.items() if k > 1}
    info["duplicate_clauses"] = len(dups)
    info["clauses"] = len(cf.clauses)
    info["vars"] = cf.nvars
    for kind, cls in pred.items():
        miss = 0
        for c in cls:
            if bag.get(c, 0) > 0:
                bag[c] -= 1
            else:
                miss += 1
        info[f"pred_{kind}"] = len(cls)
        if miss:
            # weaker than the paper: not a soundness problem, but a discrepancy
            problems.append(
                f"WEAKER: {miss} of {len(cls)} predicted {kind} clauses are absent from the code formula"
            )
    rest = [tuple(c) for c, k in bag.items() for _ in range(k)]
    info["definitional_clauses"] = len(rest)
    # ---- 1b. the remainder must be a pure list of definitions over the bracket bits
    defs, order, leftovers, undefined, eprob = extract_definitions(cf.nvars, rest, cf.X.values())
    for p in eprob:
        problems.append(f"STRONGER? gate extraction: {p[0]} at variable {p[1]}: {str(p[2])[:300]}")
    if leftovers:
        ex = [sorted(rest[i], key=abs) for i in leftovers[:6]]
        problems.append(
            f"STRONGER? {len(leftovers)} clauses are neither predicted substantive clauses nor "
            f"part of a definition, e.g. {ex}"
        )
    if undefined:
        problems.append(
            f"{len(undefined)} variables are not defined by the definitional clauses, e.g. {undefined[:8]}"
        )
    info["defined_aux"] = len(defs)
    # ---- 2. ANF of every variable
    polys = {v: P.var(v) for v in cf.X.values()}
    for y in order:
        ins, table = defs[y]
        polys[y] = anf_of_table(ins, table, polys)
    info["max_degree"] = max((p.degree() for p in polys.values()), default=0)
    PX = R.PaperX(M, {S: P.var(v) for S, v in cf.X.items()})

    def lit_poly(lit):
        p = polys.get(abs(lit))
        if p is None:
            return None
        return p ^ 1 if lit < 0 else p

    bad = Counter()
    # order bits
    exp_o = set()
    for i, j in combinations(M.labels, 2):
        rest_ = [u for u in M.labels if u not in (i, j)]
        for k, l in combinations(rest_, 2):
            exp_o.add((i, j, k, l))
    if set(cf.o) != exp_o:
        problems.append(
            f"order variable index set differs from the paper: extra {sorted(set(cf.o) - exp_o)[:3]} "
            f"missing {sorted(exp_o - set(cf.o))[:3]}"
        )
    for key, v in cf.o.items():
        if polys.get(v) != PX.ord(*key):
            bad["o"] += 1
    # cut order bits
    exp_d = set()
    cuts = code_cut_points(cf)
    notes = info.setdefault("notes", [])
    if any(cuts[b] != min(u for u in M.labels if u != b) for b in M.labels):
        notes.append(
            "DIFFERS FROM THE PAPER (sound by lem:cutorder): layer A cut points are "
            f"{cuts}, the paper takes the smallest face != b"
        )
    for b in M.labels:
        r = cuts[b]
        rest_ = [u for u in M.labels if u not in (b, r)]
        for x, y in combinations(rest_, 2):
            exp_d.add((b, r, x, y))
    if set(cf.d) != exp_d:
        problems.append(
            f"cut-order variable index set differs from the paper (r_b = smallest face != b): "
            f"extra {sorted(set(cf.d) - exp_d)[:3]} missing {sorted(exp_d - set(cf.d))[:3]}"
        )
    for key, v in cf.d.items():
        if polys.get(v) != PX.d(*key):
            bad["d"] += 1
    # OnB
    for (i, j, u), v in cf.onb.items():
        if u in M.ends(i, j) or u in (i, j) or not i < j:
            problems.append(f"OnB variable with illegal index {(i, j, u)}")
            continue
        if polys.get(v) != PX.onb(i, j, u):
            bad["onb"] += 1
    # corner bits: determine the pin (g, z1) per face from the paper's family of choices
    pins = {}
    for f in M.labels:
        keys = [k for k in cf.corner if k[0] == f]
        if len(keys) != n - 1 or {frozenset(k[1:]) for k in keys} != {
            frozenset((c[1], c[2])) for c in M.corners(f)
        }:
            problems.append(f"face {f}: corner bits are not exactly the n-1 corners of the link")
            continue
        matches = []
        for g in M.labels:
            if g == f:
                continue
            for z1 in M.ends(f, g):
                if all(
                    lit_poly(cf.corner[k]) == PX.refl_invariant(f, k[1], k[2], g, z1) for k in keys
                ):
                    matches.append((g, z1))
        g0 = min(u for u in M.labels if u != f)
        paper_pin = (g0, max(M.ends(f, g0)))
        found = paper_pin if paper_pin in matches else (matches[0] if matches else None)
        if found is None:
            bad["refl"] += 1
            problems.append(
                f"STRONGER? face {f}: corner bits equal the paper's refl(f;.,.) for NO admissible "
                f"pinning corner (g, z1): wrong turn formula, wrong pair order or wrong orientation equation"
            )
        else:
            pins[f] = found
            # s_f itself: must be turn(pin) xor parity in one of the two traversal directions
            g, z1 = found
            sp = polys.get(cf.s.get(f))
            cands = []
            for rev in (False, True):
                (c2,) = [c for c in M.corners(f, rev) if {c[1], c[2]} == {g, z1}]
                cands.append(PX.turn(f, c2[1], c2[2]) ^ PX.crossing_parity(f, g, z1))
            if sp not in cands:
                bad["s"] += 1
    for k, c in bad.items():
        if k != "refl":
            problems.append(
                f"STRONGER? {c} variables named {k} do not equal the paper's formula (ANF mismatch)"
            )
    info["pins"] = pins
    info["pin_is_paper_choice"] = all(
        pins.get(f)
        == (min(u for u in M.labels if u != f), max(M.ends(f, min(u for u in M.labels if u != f))))
        for f in M.labels
    )
    # ---- 3. gauge
    if cf.gauge_face is not None:
        vecs = [1 | sum(1 << e for e in S if e >= 1) for S in cf.gauge]
        rk = gf2_rank(vecs)
        info["gauge_rank"] = rk
        info["gauge"] = [tuple(S) for S in cf.gauge]
        if len(cf.gauge) != n + 1 or rk != n + 1:
            problems.append(
                f"STRONGER: gauge pins {len(cf.gauge)} brackets of rank {rk}; need {n + 1} independent"
            )
    xvars = set(cf.X.values())
    units = [c for c in cf.clauses if len(c) == 1 and abs(c[0]) in xvars]
    if sorted(units) != sorted((-cf.X[tuple(S)],) for S in cf.gauge):
        problems.append(
            f"STRONGER? unit clauses on bracket bits are not exactly the gauge clauses: {units[:20]}"
        )
    # ---- 4. invariance under G of everything except the gauge (symbolic, generators)
    if check_group and not problems:
        gens = [("gamma", None)] + [("eps", i) for i in M.labels]
        for kind, i in gens:
            flipped = {v for S, v in cf.X.items() if kind == "gamma" or i in S}
            for (a, b, k, l), v in cf.o.items():
                exp = polys[v] ^ (1 if (kind == "gamma" or i in (a, b)) else 0)
                if polys[v].substitute_flip(flipped) != exp:
                    problems.append(
                        f"G-action: o{(a, b, k, l)} does not transform as expected under {kind}{i}"
                    )
                    break
            for (b, r, x, y), v in cf.d.items():
                exp = polys[v] ^ (1 if (kind == "gamma" or i == b) else 0)
                if polys[v].substitute_flip(flipped) != exp:
                    problems.append(
                        f"G-action: d{(b, r, x, y)} does not transform as expected under {kind}{i}"
                    )
                    break
            for key, v in cf.onb.items():
                if polys[v].substitute_flip(flipped) != polys[v]:
                    problems.append(f"G-action: OnB{key} is not invariant under {kind}{i}")
                    break
            for key, lit in cf.corner.items():
                if polys[abs(lit)].substitute_flip(flipped) != polys[abs(lit)]:
                    problems.append(f"G-action: corner bit {key} is not invariant under {kind}{i}")
                    break
        info["group_invariance_checked"] = True
    info["polys"] = polys
    return problems, info


# --------------------------------------------------------------------------------------------
# numeric evaluation by unit propagation (own implementation)
# --------------------------------------------------------------------------------------------


class Evaluator:
    """Unit propagation on the FULL clause list starting from the bracket bits."""

    def __init__(self, cf):
        self.cf = cf
        self.occ = defaultdict(list)
        for idx, c in enumerate(cf.clauses):
            for lit in c:
                self.occ[abs(lit)].append(idx)

    def propagate(self, Xbits, skip=frozenset()):
        """Xbits: dict sorted 4-subset -> 0/1.  skip: clause indices not used for propagation.
        Returns (values dict, conflict clause index or None)."""
        cf = self.cf
        val = {}
        queue = []
        for S, v in cf.X.items():
            val[v] = Xbits[S]
            queue.append(v)
        for idx, c in enumerate(cf.clauses):  # unit clauses on non-bracket variables (n = 4)
            if len(c) == 1 and idx not in skip and abs(c[0]) not in val:
                val[abs(c[0])] = 1 if c[0] > 0 else 0
                queue.append(abs(c[0]))
        while queue:
            v = queue.pop()
            for idx in self.occ[v]:
                if idx in skip:
                    continue
                c = cf.clauses[idx]
                unassigned = None
                sat = False
                cnt = 0
                for lit in c:
                    x = val.get(abs(lit))
                    if x is None:
                        unassigned = lit
                        cnt += 1
                    elif (x == 1) == (lit > 0):
                        sat = True
                        break
                if sat:
                    continue
                if cnt == 0:
                    return val, idx
                if cnt == 1:
                    val[abs(unassigned)] = 1 if unassigned > 0 else 0
                    queue.append(abs(unassigned))
        return val, None

    def violated(self, val):
        out = []
        for idx, c in enumerate(self.cf.clauses):
            if not any(val.get(abs(lit)) == (1 if lit > 0 else 0) for lit in c):
                out.append(idx)
        return out


def gauge_element(cf, Xbits):
    """All (gamma, eps) in G whose action (lem:gaugegroup, on bits) zeroes the pinned brackets.
    Brute force over the whole group for n <= 7, linear algebra otherwise."""
    n = cf.n
    sols = []
    if n <= 7:
        for g in range(1 << (n + 1)):
            gamma = g & 1
            eps = {i: (g >> i) & 1 for i in range(1, n + 1)}
            if all(
                (Xbits[tuple(S)] ^ gamma ^ (sum(eps[i] for i in S if i >= 1) & 1)) == 0
                for S in cf.gauge
            ):
                sols.append((gamma, eps))
        return sols
    # Gauss-Jordan elimination: unknown vector g (bit0 gamma, bit i eps_i), phi_S(g) = X_S
    rows = [[(1 | sum(1 << e for e in S if e >= 1)), Xbits[tuple(S)]] for S in cf.gauge]
    rank = 0
    pivcols = []
    for col in range(n + 1):
        p = next((r for r in range(rank, len(rows)) if rows[r][0] >> col & 1), None)
        if p is None:
            continue
        rows[rank], rows[p] = rows[p], rows[rank]
        for r in range(len(rows)):
            if r != rank and rows[r][0] >> col & 1:
                rows[r][0] ^= rows[rank][0]
                rows[r][1] ^= rows[rank][1]
        pivcols.append(col)
        rank += 1
    if any(m == 0 and rhs for m, rhs in rows):
        return []
    if rank != n + 1:
        return None  # solution not unique
    g = 0
    for r, col in enumerate(pivcols):
        assert rows[r][0] == 1 << col
        g |= rows[r][1] << col
    return [(g & 1, {i: (g >> i) & 1 for i in range(1, n + 1)})]
