"""Fake pinned tools of the audit tests: a solver and a checker as real executables.

``cp_audit_world.install`` copies this file twice (as ``cadical`` and as ``cake_lpr``) behind an
interpreter line; the tool reads ``<its own path>.json`` for its behaviour, so a test changes what
the tool does between the source run and the audit without changing the pinned hash. The solver
brute-forces tiny formulas (a model, or a valid LRAT decision-tree proof) and the checker is the
independent test validator ``fakes.lrat_check``, as in the lifecycle tests. No production result
rests on them.

Configuration keys (all optional): ``tests`` (the directory that holds ``fakes``); for the solver
``max_free`` (out of memory when more variables than this are free, so the run splits),
``variant`` (a comment line before the proof: a different but valid proof), ``lie`` (exit 20 with
a bogus proof even when the CNF has a model), ``crash`` (SIGSEGV), ``fail_first`` (a counter file:
SIGSEGV while it holds fewer than ``fail_count`` lines, one line added per run), ``sleep``
(seconds before solving) and ``ready`` (a file it creates when it starts solving, so a test can
signal the audit while a target runs); for the checker ``accept`` (success without reading the
proof), ``reject`` and ``tamper`` (``"proof"`` or ``"cnf"``: it appends a line to that input
after a successful check).
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

from fakes.cnf_model import Cnf, brute_force_model, model_lines, parse_dimacs  # noqa: E402
from fakes.lrat_check import SUCCESS, decision_tree_proof, encode_text  # noqa: E402
from fakes.lrat_check import main as lrat_main  # noqa: E402

BAD_ALLOC = (
    "terminate called after throwing an instance of 'std::bad_alloc'\n  what():  std::bad_alloc\n"
)
REJECTION = "c Checking failed at line: 0. Reason: pivot must be non-zero\n"


def _free(cnf: Cnf) -> int:
    fixed = {abs(clause[0]) for clause in cnf.clauses if len(clause) == 1}
    return int(cnf.variables) - len(fixed)


def _fail_first() -> bool:
    counter = CONFIG.get("fail_first")
    if counter is None:
        return False
    path = Path(str(counter))
    runs = path.read_text(encoding="utf-8").count("\n") if path.exists() else 0
    with path.open("a", encoding="utf-8") as stream:
        stream.write("run\n")
    return runs < int(CONFIG.get("fail_count", 1))


def solver(args: Sequence[str]) -> int:
    if list(args) == ["--version"]:
        sys.stdout.write("cadical-fake 1.0\n")
        return 0
    cnf_path, proof_path = args[-2], args[-1]
    if CONFIG.get("ready"):  # a test waits for this file before it signals the audit
        Path(str(CONFIG["ready"])).write_text("ready", encoding="utf-8")
    time.sleep(float(CONFIG.get("sleep", 0)))
    cnf = parse_dimacs(Path(cnf_path).read_bytes())
    limit = CONFIG.get("max_free")
    if limit is not None and _free(cnf) > int(limit):
        sys.stderr.write(BAD_ALLOC)
        sys.stderr.flush()
        os.kill(os.getpid(), signal.SIGABRT)
    if CONFIG.get("crash") or _fail_first():
        os.kill(os.getpid(), signal.SIGSEGV)
    if CONFIG.get("lie"):
        Path(proof_path).write_bytes(b"c no proof\n")
        sys.stdout.write("s UNSATISFIABLE\n")
        return 20
    model = brute_force_model(cnf)
    if model is not None:
        literals = [v if model[v] else -v for v in range(1, cnf.variables + 1)]
        sys.stdout.buffer.write(model_lines(literals))
        sys.stdout.flush()
        return 10
    proof = encode_text(decision_tree_proof(cnf))
    if CONFIG.get("variant"):
        proof = b"c an equivalent proof with other bytes\n" + proof
    Path(proof_path).write_bytes(proof)
    sys.stdout.write("s UNSATISFIABLE\n")
    return 20


def checker(args: Sequence[str]) -> int:
    if CONFIG.get("accept"):
        sys.stdout.buffer.write(SUCCESS)
        return 0
    if CONFIG.get("reject"):
        sys.stderr.write(REJECTION)
        return 0
    code = int(lrat_main(list(args)))
    tamper = CONFIG.get("tamper")
    if tamper is not None:  # a buggy checker: it changes its input after accepting it
        path = Path(args[-1] if tamper == "proof" else args[-2])
        with path.open("ab") as stream:
            stream.write(b"c changed by the checker\n")
    return code


def main(argv: Sequence[str]) -> int:
    # Python ignores SIGXFSZ; a C solver dies of it at the file size cap (the proof cap)
    signal.signal(signal.SIGXFSZ, signal.SIG_DFL)
    role = Path(argv[0]).name
    code: int = solver(argv[1:]) if role == "cadical" else checker(argv[1:])
    sys.stdout.flush()
    return code


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
