"""Admission, success fields and the regenerated-formula rules of attempts (specification §10.1,
§4.8, §6).

- :func:`admission_reason`: an attempt is admitted when the checker hash of its snapshot (the
  latest header/resume before it in its journal) is in ``admit.checker_sha256`` and, when
  ``admit.solvers`` is a list, the snapshot solver's ``{sha256, argv}`` is in it; also for
  route unit, whose solver is not executed. Otherwise the reason is ``checker_not_admitted``
  (checked first) or ``solver_not_admitted``. Source hashes and limits are provenance only.
- :func:`success_problem`: the success fields of an **admitted** VERIFIED_UNSAT, in the order
  success.proof, success.checks, success.checker_output, success.solver, success.relay. The
  certifier validates them itself; it does not trust the binding that wrote the record.
- :class:`AttemptRules`: the certifier's hooks into the journal reader
  (:class:`~cubeproof.evidence.schema.ExtraRules`), run in the reference order for every
  attempt, admitted or not: the success fields (admitted VERIFIED_UNSAT only), then, after
  the reader's policy and attempt-ID rules, ``attempt.cnf_sha256`` against CNF(F, C)
  regenerated from the verified bundle and ``attempt.model_false`` for a MODEL whose
  assignment does not satisfy every clause and cube unit. It also remembers whether the
  assignment of a MODEL/INVALID_MODEL attempt really satisfies CNF(F, C) (specification §10.4).
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from cubeproof.cnf.cubecnf import CnfDigest
from cubeproof.cnf.dimacs import Formula
from cubeproof.cnf.model import assignment_violation
from cubeproof.contracts.campaign import Admit
from cubeproof.contracts.enums import Outcome
from cubeproof.contracts.primitives import SUCCESS_LINE
from cubeproof.evidence.schema import Attempt, Header, Machinery, Record, Resume

CHECKER_NOT_ADMITTED = "checker_not_admitted"
SOLVER_NOT_ADMITTED = "solver_not_admitted"
_SUCCESS_BYTES = len(SUCCESS_LINE.encode("ascii"))


def admission_reason(admit: Admit, machinery: Machinery) -> str | None:
    """None when the snapshot machinery is admitted, otherwise the not_admitted reason."""
    if not admit.admits_checker(machinery.checker.sha256):
        return CHECKER_NOT_ADMITTED
    if not admit.admits_solver(machinery.solver.sha256, machinery.solver.argv):
        return SOLVER_NOT_ADMITTED
    return None


def _exact_success(result: Mapping[str, Any]) -> bool:
    return (
        result["exit"] == 0
        and result["signal"] is None
        and result["stdout_bytes"] == _SUCCESS_BYTES
        and result["stdout_truncated"] is False
        and result["stdout_tail"] == SUCCESS_LINE
    )


def success_problem(attempt: Mapping[str, Any]) -> str | None:
    """The first success rule an admitted VERIFIED_UNSAT attempt (JSON payload) violates."""
    proof_bytes, proof_sha256 = attempt["proof_bytes"], attempt["proof_sha256"]
    if proof_bytes is None or proof_sha256 is None:
        return "success.proof"
    checks = attempt["checks"]
    if not checks:
        return "success.checks"
    if not _exact_success(checks[-1]["result"]):
        return "success.checker_output"
    cdcl = attempt["route"] == "cdcl"
    solver = attempt["solver"]
    if cdcl and (
        solver is None
        or solver["started"] is not True
        or solver["exit"] != 20
        or solver["signal"] is not None
    ):
        return "success.solver"
    if cdcl and attempt["proof_mode"] == "stream":
        relay = attempt["relay"]
        if relay is None or not (
            relay["solver_eof"] is True
            and relay["all_written"] is True
            and relay["error"] is None
            and relay["bytes"] == proof_bytes
            and relay["sha256"] == proof_sha256
        ):
            return "success.relay"
    return None


class AttemptRules:
    """The certifier's :class:`~cubeproof.evidence.schema.ExtraRules` (see module doc)."""

    def __init__(self, admit: Admit, formulas: Mapping[str, Formula]) -> None:
        self._admit = admit
        self._formulas = dict(formulas)
        self._digests = {sha: CnfDigest(formula) for sha, formula in self._formulas.items()}
        self._model: tuple[str, bool] | None = None

    def attempt_record(self, record: Record, snapshot: Header | Resume) -> str | None:
        attempt = record.payload
        assert isinstance(attempt, Attempt)
        if attempt.outcome != Outcome.VERIFIED_UNSAT:
            return None
        if admission_reason(self._admit, snapshot.machinery) is not None:
            return None
        return success_problem(attempt.to_json())

    def attempt_context(self, record: Record, snapshot: Header | Resume) -> str | None:
        del snapshot
        attempt = record.payload
        assert isinstance(attempt, Attempt)
        node = attempt.node
        if self._digests[node.formula_sha256].cnf_sha256(node.cube) != attempt.cnf_sha256:
            return "attempt.cnf_sha256"
        if attempt.outcome == Outcome.MODEL and not self.model_satisfies(record):
            return "attempt.model_false"
        return None

    def model_satisfies(self, record: Record) -> bool:
        """Whether the attempt's complete assignment satisfies every clause and cube unit.

        False for an attempt without assignment (a parse error has no model, specification §10.4).
        """
        known = self._model
        if known is not None and known[0] == record.self_hash:
            return known[1]
        attempt = record.payload
        assert isinstance(attempt, Attempt)
        valid = attempt.assignment is not None and (
            assignment_violation(
                self._formulas[attempt.node.formula_sha256], attempt.node.cube, attempt.assignment
            )
            is None
        )
        self._model = (record.self_hash, valid)
        return valid
