"""Fake pinned tools of the lifecycle tests: a solver and a checker as real executables.

``cp_life_tools.install`` copies this file twice (as ``cadical`` and as ``cake_lpr``) behind an
interpreter line; the tool reads ``<its own path>.json`` for its behaviour, so a test changes
what the tool does between runs without changing the pinned hash of the binary file. The tools
are test doubles of the same kind as the fakes of ``tests/fakes``: the solver brute-forces tiny
formulas (a model, or a valid LRAT decision-tree proof of unsatisfiability) and the checker is
the independent test validator ``fakes.lrat_check``. No production result rests on them.

Configuration keys (all optional): ``tests`` (the directory that holds ``fakes``), ``sleep``
(seconds before answering), and for the solver ``max_free`` (the solver runs out of memory, as
CaDiCaL does, when more variables than this are not fixed by unit clauses of the CNF) and
``crash_if_free_le`` (it dies of SIGSEGV when at most this many are free) and ``ignore_term``
(only KILL ends it, ``ready``: a file it creates once it ignores TERM) and ``proof_at_start``
(like CaDiCaL, it creates its proof file as soon as it starts, long before it has an answer, so
a solve that is cancelled leaves that file behind unless its attempt removes it); for the checker
``reject`` (it reports a normal unsuccessful check), ``arena`` (it always runs out of its
heap) and ``crash``.
"""

from __future__ import annotations

import json
import os
import signal
import sys
import time
from collections.abc import Sequence
from pathlib import Path
from typing import Any


def _config() -> dict[str, Any]:
    path = Path(str(Path(__file__).resolve()) + ".json")
    if not path.exists():
        return {}
    loaded: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    return loaded


CONFIG = _config()
if CONFIG.get("tests"):
    sys.path.insert(0, str(CONFIG["tests"]))

from fakes import cnf_model, lrat_check  # noqa: E402

BAD_ALLOC = (
    "terminate called after throwing an instance of 'std::bad_alloc'\n  what():  std::bad_alloc\n"
)
REJECTION = "c Checking failed at line: 0. Reason: pivot must be non-zero\n"
HEAP_EXHAUSTED = "CakeML heap space exhausted.\n"


def _free(cnf: cnf_model.Cnf) -> int:
    fixed = {abs(clause[0]) for clause in cnf.clauses if len(clause) == 1}
    return int(cnf.variables) - len(fixed)


def solver(args: Sequence[str]) -> int:
    if list(args) == ["--version"]:
        sys.stdout.write("cadical-fake 1.0\n")
        return 0
    if CONFIG.get("ignore_term"):
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
    if CONFIG.get("proof_at_start"):  # as CaDiCaL: the proof file exists from the start
        Path(args[-1]).write_bytes(b"")
    if CONFIG.get("ready"):  # a test waits for this file before it signals the run
        Path(str(CONFIG["ready"])).write_text("ready", encoding="utf-8")
    cnf_path, proof_path = args[-2], args[-1]
    cnf = cnf_model.parse_dimacs(Path(cnf_path).read_bytes())
    free = _free(cnf)
    time.sleep(float(CONFIG.get("sleep", 0)))
    limit = CONFIG.get("max_free")
    if limit is not None and free > int(limit):
        sys.stderr.write(BAD_ALLOC)
        sys.stderr.flush()
        os.kill(os.getpid(), signal.SIGABRT)
    crash = CONFIG.get("crash_if_free_le")
    if crash is not None and free <= int(crash):
        os.kill(os.getpid(), signal.SIGSEGV)
    model = cnf_model.brute_force_model(cnf)
    if model is not None:
        literals = [v if model[v] else -v for v in range(1, cnf.variables + 1)]
        sys.stdout.buffer.write(cnf_model.model_lines(literals))
        sys.stdout.flush()
        return 10
    steps = lrat_check.decision_tree_proof(cnf)
    Path(proof_path).write_bytes(lrat_check.encode_text(steps))
    sys.stdout.write("s UNSATISFIABLE\n")
    return 20


def checker(args: Sequence[str]) -> int:
    time.sleep(float(CONFIG.get("sleep", 0)))
    if CONFIG.get("crash"):
        os.kill(os.getpid(), signal.SIGSEGV)
    if CONFIG.get("arena"):
        sys.stderr.write(HEAP_EXHAUSTED)
        return 1
    if CONFIG.get("reject"):
        sys.stderr.write(REJECTION)
        return 0
    return int(lrat_check.main(list(args)))


def main(argv: Sequence[str]) -> int:
    role = Path(argv[0]).name
    code: int = solver(argv[1:]) if role == "cadical" else checker(argv[1:])
    sys.stdout.flush()
    return code


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
