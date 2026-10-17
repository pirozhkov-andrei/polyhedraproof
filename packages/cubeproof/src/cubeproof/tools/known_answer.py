"""A known-answer control of the checker before a session starts work.

The campaign names the checker by the hash of its binary, and ``run`` uses no other file
(specification §4.6). The hash says which bytes run; it does not say that they behave as a
checker here: a binary can be the wrong program, or the right one on a machine where it does
not work. Before a session writes its header or resume record, the checker is therefore asked
four small questions whose answers are known: one refutation it must accept and three it must
reject. Only then may its answer close a leaf.

The inputs are fixed bytes, written into a fresh directory below the session's work directory,
and the checker is launched through the path of a leaf check: the same supervisor and
isolation, the argument form of :func:`cubeproof.tools.checker.checker_args` (with small fixed
arenas instead of the policy's), and :func:`cubeproof.tools.checker.accepts` as the one judge
of success. A checker that accepts what it must reject, rejects what it must
accept, or cannot be run, stops the session with a tool error before any record is written.

The control shows that the program distinguishes these four cases on this machine. It is not
a proof that the program is a correct checker; that is the theorem about the pinned cake_lpr
(docs/TRUST.md).
"""

from __future__ import annotations

import os
import tempfile
from dataclasses import dataclass
from typing import Final

from cubeproof.base.errors import ToolError
from cubeproof.tools.checker import accepts, checker_args, checker_memory_bytes, clean_rejection
from cubeproof.tools.isolation import PinnedBinary
from cubeproof.tools.process import Launch, Supervisor

__all__ = ["CASES", "KnownAnswer", "check_checker"]

_HEAP_MIB: Final = 256
_STACK_MIB: Final = 64
_SLACK_MIB: Final = 256
_TIMEOUT_MS: Final = 60_000

#: ``x`` and ``not x``: unsatisfiable, refuted by one resolution step.
_UNSAT: Final = b"p cnf 1 2\n1 0\n-1 0\n"
#: ``x or y`` and ``not x or y``: satisfiable (``y``), so no refutation exists.
_SAT: Final = b"p cnf 2 2\n1 2 0\n-1 2 0\n"
#: LRAT: clause 3 is the empty clause, by unit propagation on clauses 1 and 2.
_PROOF: Final = b"3 0 1 2 0\n"


@dataclass(frozen=True)
class KnownAnswer:
    """One question: a CNF, a proof, and whether a checker must accept the pair."""

    name: str
    cnf: bytes
    proof: bytes
    accept: bool


#: The four questions. The first is a correct refutation. The others must be rejected: the same
#: proof for a satisfiable formula, a derivation whose hints do not give the conflict, and a
#: proof that derives nothing.
CASES: Final = (
    KnownAnswer("a refutation of x and not x", _UNSAT, _PROOF, True),
    KnownAnswer("that proof for a satisfiable formula", _SAT, _PROOF, False),
    KnownAnswer("an empty clause without its conflict", _UNSAT, b"3 0 1 0\n", False),
    KnownAnswer("an empty proof", _UNSAT, b"", False),
)


def _ask(supervisor: Supervisor, checker: PinnedBinary, directory: str, case: KnownAnswer) -> str:
    """Run one question; the empty string if the answer is the known one, else what happened."""
    cnf, proof = os.path.join(directory, "known.cnf"), os.path.join(directory, "known.lrat")
    for path, data in ((cnf, case.cnf), (proof, case.proof)):
        with open(path, "wb") as stream:
            stream.write(data)
    process = supervisor.start(
        Launch(
            binary=checker,
            args=checker_args(_HEAP_MIB, _STACK_MIB, cnf, proof),
            cwd=directory,
            memory_bytes=checker_memory_bytes(_HEAP_MIB, _STACK_MIB, _SLACK_MIB),
            file_bytes=1 << 20,
            deadline_ms=_TIMEOUT_MS,
            term_grace_ms=1000,
        )
    )
    while process.run is None:
        supervisor.step(100)
    run = process.run
    result = run.result
    seen = (
        f"exit {result.exit}, signal {result.signal}, causes {[c.value for c in run.causes]}, "
        f"stdout {result.stdout_tail[:80]!r}, stderr {result.stderr_tail[:200]!r}"
    )
    if run.causes:
        return f"could not be asked ({seen})"
    if case.accept:
        return "" if accepts(result) else f"was not accepted ({seen})"
    if accepts(result):
        return "was ACCEPTED"
    return "" if clean_rejection(result) else f"was not rejected cleanly ({seen})"


def check_checker(supervisor: Supervisor, checker: PinnedBinary, work: str) -> None:
    """Ask the checker the known questions (module doc); ToolError unless every answer is right.

    ``work`` is an existing directory; the inputs are written into a fresh directory below it,
    which is removed afterwards.
    """
    with tempfile.TemporaryDirectory(prefix="known-answer-", dir=work) as directory:
        for case in CASES:
            problem = _ask(supervisor, checker, directory, case)
            if problem:
                raise ToolError(
                    "tool.known_answer",
                    f"the checker {checker.path} ({checker.sha256}) failed its known-answer "
                    f"control: {case.name} {problem}. It is not used: no record was written",
                )
