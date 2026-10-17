"""Shared helpers of the split tests.

- random formulas, cubes and pools;
- ``oracle_lookahead``: lookahead-v1 written literally from specification §9.3 with from-scratch
  unit propagation of ``cubeproof.cnf.unit`` (an implementation independent of the counter engine of
  ``split.lookahead`` and of the C helper), with its own sampling by sorting;
- the fake partition solver used by the proof-prefix tests, in-process and as a script.
"""

from __future__ import annotations

import hashlib
import importlib.util
import inspect
import os
import random
import stat
import sys
from collections.abc import Sequence
from pathlib import Path
from types import ModuleType
from typing import Any

from cubeproof.cnf.dimacs import Formula, canonical_dimacs, parse_dimacs
from cubeproof.cnf.unit import build_index, propagate
from cubeproof.contracts.identity import canonical_cube, node_id

NATIVE = Path(__file__).resolve().parents[2] / "native"
#: ``tests/`` of the repository, for the shared ``image`` package (pinned tool location).
SHARED_TESTS = Path(__file__).resolve().parents[4] / "tests"
if str(SHARED_TESTS) not in sys.path:
    sys.path.insert(0, str(SHARED_TESTS))


def load_build_module() -> ModuleType:
    """``native/build.py`` as a module (it is not part of an installed package)."""
    spec = importlib.util.spec_from_file_location("cubeproof_look_build", NATIVE / "build.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def make_formula(variables: int, clauses: Sequence[Sequence[int]]) -> Formula:
    return parse_dimacs(canonical_dimacs(variables, clauses))


def random_formula(
    rng: random.Random,
    *,
    min_variables: int = 9,
    max_variables: int = 16,
    low: float = 0.5,
    high: float = 1.6,
) -> Formula:
    """A small random CNF with unit, binary, duplicate-literal and tautological clauses."""
    variables = rng.randint(min_variables, max_variables)
    count = rng.randint(int(variables * low), int(variables * high))
    clauses = []
    for _ in range(count):
        width = rng.choice([1, 2, 2, 3, 3, 3, 3, 4, 5, 6])
        clauses.append([rng.choice([-1, 1]) * rng.randint(1, variables) for _ in range(width)])
    return make_formula(variables, clauses)


def random_cube(rng: random.Random, formula: Formula, most: int = 3) -> tuple[int, ...]:
    chosen = rng.sample(range(1, formula.variables + 1), rng.randint(0, most))
    return tuple(sorted((rng.choice([-1, 1]) * v for v in chosen), key=abs))


def random_pool(rng: random.Random, formula: Formula) -> list[int] | None:
    if rng.random() >= 0.4:
        return None
    return sorted(rng.sample(range(1, formula.variables + 1), rng.randint(0, formula.variables)))


# -- the literal oracle ------------------------------------------------------------------------


def oracle_sample(node: str, round_number: int, width: int) -> list[int]:
    indices = range(1 << width)
    if len(indices) <= 16:
        return list(indices)
    prefix = f"{node}\0{round_number}\0"
    keyed = sorted(
        indices, key=lambda t: (hashlib.sha256(f"{prefix}{t}".encode("ascii")).digest(), t)
    )
    return keyed[:16]


def oracle_lookahead(
    formula: Formula,
    cube: Sequence[int],
    k: int,
    pool: Sequence[int] | None,
    probe_limit: int,
) -> dict[str, Any]:
    """lookahead-v1 by the letter of specification §9.3 (probe accounting: see the module
    docstring)."""
    index = build_index(formula)
    count = formula.variables
    node = node_id(formula.sha256, cube)

    def up(literals: Sequence[int]) -> Any:
        return propagate(index, canonical_cube(literals))

    used = 1
    parent = up(cube)
    if parent.conflict:
        return {
            "variables": [],
            "status": "failed",
            "scores": [],
            "probes": used,
            "stop": "parent_conflict",
            "candidates": 0,
            "parent_assigned": 0,
        }
    parent_assigned = parent.assigned()
    members = range(1, count + 1) if pool is None else pool
    candidates = [v for v in members if v not in parent_assigned]
    chosen: list[int] = []
    scores: list[int] = []
    stop = ""
    while len(chosen) < k:
        remaining = [v for v in candidates if v not in chosen]
        if not remaining:
            stop = "candidates"
            break
        round_number = len(chosen) + 1
        children = []
        for t in oracle_sample(node, round_number, len(chosen)):
            if chosen:
                if used >= probe_limit:
                    stop = "probe_limit"
                    break
                used += 1
            literals = [*cube, *(w if (t >> j) & 1 else -w for j, w in enumerate(chosen))]
            children.append((literals, up(literals)))
        if stop:
            break
        best: tuple[int, int] | None = None
        for v in remaining:
            live = [(c, p) for c, p in children if not p.conflict and v not in p.assigned()]
            if used + 2 * len(live) > probe_limit:
                stop = "probe_limit"
                break
            used += 2 * len(live)
            total = 0
            for literals, base in live:
                gains = []
                for literal in (v, -v):
                    probe = up([*literals, literal])
                    gains.append(
                        count + 1 if probe.conflict else len(probe.trail) - len(base.trail) - 1
                    )
                total += (gains[0] + 1) * (gains[1] + 1)
            if best is None or total > best[1]:
                best = (v, total)
        if best is not None:
            chosen.append(best[0])
            scores.append(best[1])
        if stop:
            break
    stop = stop or "k"
    if chosen:
        status = "chosen"
    else:
        status = "no_eligible" if stop == "candidates" else "budget"
    return {
        "variables": chosen,
        "status": status,
        "scores": scores,
        "probes": used,
        "stop": stop,
        "candidates": len(candidates),
        "parent_assigned": len(parent_assigned),
    }


def summary(choice: Any) -> dict[str, Any]:
    """The fields ``oracle_lookahead`` reports, from a SplitChoice."""
    info = choice.info_dict()
    return {
        "variables": list(choice.variables),
        "status": choice.status,
        "scores": info["scores"],
        "probes": info["probes"],
        "stop": info["stop"],
        "candidates": info["candidates"],
        "parent_assigned": info["parent_assigned"],
    }


# -- the fake partition solver -----------------------------------------------------------------


def fake_lrat(cnf: bytes, mode: str = "random", lines: int = 40) -> bytes:
    """A deterministic LRAT-looking text for ``cnf`` (a function of its bytes only).

    ``random``: additions with 1-4 literals and some deletions; ``flat``: one literal per
    addition, every variable equally often, in a rotation that depends on the input, so the
    counts tie and only the counting order decides.
    """
    header = cnf.split(b"\n", 1)[0].split()
    variables = int(header[2])
    rng = random.Random(int.from_bytes(hashlib.sha256(cnf).digest()[:8], "big"))
    out = []
    clause_id = int(header[3]) + 1
    if mode == "flat":
        offset = rng.randrange(variables)
        for i in range(variables):
            literal = (offset + i) % variables + 1
            out.append(f"{clause_id + i} {literal} 0 1 0")
        return ("\n".join(out) + "\n").encode()
    for i in range(lines):
        if rng.random() < 0.2:
            out.append(f"{clause_id + i} d 1 2 0")
            continue
        literals = [
            rng.choice([-1, 1]) * rng.randint(1, variables) for _ in range(rng.randint(1, 4))
        ]
        hints = " ".join(str(rng.randint(1, 5)) for _ in range(rng.randint(0, 3)))
        out.append(f"{clause_id + i} {' '.join(map(str, literals))} 0 {hints} 0".replace("  ", " "))
    out.append("")
    return "\n".join(out).encode()


FAKE_SOLVER_SOURCE = """#!{python}
import hashlib, os, random, sys
{function}
args = sys.argv[1:]
cnf, lrat = args[-2], args[-1]
data = open(cnf, "rb").read()
log = {log!r}
n = len(os.listdir(log))
with open(os.path.join(log, "%04d.cnf" % n), "wb") as stream:
    stream.write(data)
with open(os.path.join(log, "%04d.argv" % n), "w") as stream:
    stream.write("\\n".join(args[:-2]))
with open(lrat, "wb") as stream:
    stream.write(fake_lrat(data, {mode!r}))
sys.exit(20)
"""


def write_fake_solver(path: Path, log: Path, mode: str = "random") -> Path:
    """An executable script that logs its input and argv and writes ``fake_lrat``."""
    log.mkdir(parents=True, exist_ok=True)
    source = FAKE_SOLVER_SOURCE.format(
        python=sys.executable, function=inspect.getsource(fake_lrat), log=str(log), mode=mode
    )
    path.write_text(source)
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return path


def read_log(log: Path) -> tuple[list[bytes], list[str]]:
    names = sorted(os.listdir(log))
    cnfs = [(log / n).read_bytes() for n in names if n.endswith(".cnf")]
    argvs = [(log / n).read_text() for n in names if n.endswith(".argv")]
    return cnfs, argvs
