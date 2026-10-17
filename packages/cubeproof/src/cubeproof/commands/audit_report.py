"""The audit report ``cubeproof-audit-report-1`` and the audit exit code (specification §11.2,
§12.2).

:func:`build_report` derives the report from the regenerated plan and the audit journal; it
trusts neither. The journal's plan must be the regenerated plan (``audit.plan_changed``), and
every committed ``audit_result`` must have exactly the status and reason that
:mod:`.audit_compare` computes from its referenced attempt and the machinery in force at that
attempt (``audit.result_status``): a journal cannot claim a match its attempt does not show.

Report fields, exactly: ``format``, ``campaign``, ``certificate_sha256``, ``targets_sha256``,
``comparison``, ``population``, ``selected``, ``seed``, ``counts`` (every audit_result status,
also those with count 0), ``results`` (``{target, record, status, reason}`` in target order;
``record`` is the Ref of the audit_result, which names its attempt) and ``pending`` (node IDs of
targets without a committed result, in target order).

Exit code (most severe first, 4 > 5 > 1 > 0): MISMATCH or an integrity FAILED -> 4; a tool
FAILED -> 5; OPEN, NOT_COMPARABLE, REPROVED_UNSAT, a pending target, an empty selection or a
``reprove`` comparison -> at least 1; 0 only when every selected target of a strict audit is
HASH_MATCHED and at least one target was selected. A sample never reads as full verification:
``population`` and ``selected`` are both reported.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from cubeproof.base.canonical_json import document_bytes
from cubeproof.base.errors import ContractError, IntegrityError
from cubeproof.commands.audit_compare import (
    Classified,
    classify_attempt,
    classify_unavailable,
    exit_class,
    strict_runnable,
)
from cubeproof.commands.audit_journal import AuditJournal, CommittedResult
from cubeproof.commands.audit_plan import AuditPlan, check_plan_prefix
from cubeproof.contracts import fields as f
from cubeproof.contracts.campaign import Admit
from cubeproof.contracts.enums import AuditComparison, AuditStatus, ExitCode, Outcome
from cubeproof.contracts.primitives import is_hash
from cubeproof.contracts.values import Ref
from cubeproof.evidence.schema import Attempt, AuditTarget, Machinery

__all__ = [
    "REPORT_FORMAT",
    "STATUSES",
    "AuditReport",
    "build_report",
    "check_report",
    "classify_result",
    "expected_result",
    "runnable",
]

REPORT_FORMAT = "cubeproof-audit-report-1"
STATUSES: tuple[str, ...] = tuple(s.value for s in AuditStatus)
_FIELDS = (
    "format",
    "campaign",
    "certificate_sha256",
    "targets_sha256",
    "comparison",
    "population",
    "selected",
    "seed",
    "counts",
    "results",
    "pending",
)
_SEVERITY = {
    int(ExitCode.SUCCESS): 0,
    int(ExitCode.OPEN): 1,
    int(ExitCode.TOOL): 2,
    int(ExitCode.INTEGRITY): 3,
}


@dataclass(frozen=True)
class AuditReport:
    """A report document and the exit code of the audit command."""

    document: dict[str, Any]
    exit_code: int

    @property
    def data(self) -> bytes:
        """The report file: J(report) plus LF."""
        return document_bytes(self.document)

    @property
    def strict_success(self) -> bool:
        return self.exit_code == int(ExitCode.SUCCESS)


def expected_result(
    comparison: AuditComparison, committed: CommittedResult, admit: Admit
) -> Classified:
    """The status and reason the comparison rules give for a committed result.

    A strict audit never runs a CDCL target without its source solver: such a target is
    NOT_COMPARABLE whatever its placeholder attempt says, unless that attempt is a valid
    model (an inconsistency is never hidden behind NOT_COMPARABLE).
    """
    return classify_result(
        comparison, committed.result.target, committed.attempt, committed.machinery, admit
    )


def runnable(comparison: AuditComparison, target: AuditTarget, machinery: Machinery) -> bool:
    """Whether an audit session with ``machinery`` runs ``target``: a reprove audit always;
    a strict audit unit targets always and CDCL targets only with the source solver and argv."""
    if AuditComparison(comparison) == AuditComparison.REPROVE:
        return True
    return strict_runnable(target, machinery.solver.sha256, machinery.solver.argv)


def classify_result(
    comparison: AuditComparison,
    target: AuditTarget,
    attempt: Attempt,
    machinery: Machinery,
    admit: Admit,
) -> Classified:
    """The status and reason of ``target``'s audit_result from its attempt and the machinery in
    force at that attempt (what the executor commits and the report recomputes)."""
    if not runnable(comparison, target, machinery) and attempt.outcome != Outcome.MODEL:
        return classify_unavailable(target, machinery)
    return classify_attempt(target, attempt, machinery, admit)


def _severest(codes: list[int]) -> int:
    return max(codes, key=lambda code: _SEVERITY[code]) if codes else int(ExitCode.OPEN)


def build_report(plan: AuditPlan, journal: AuditJournal, *, admit: Admit) -> AuditReport:
    """The report of a complete audit plan and its committed results (module doc)."""
    if journal.ready is None:
        raise IntegrityError("audit.plan_order", "the audit journal has no complete plan")
    check_plan_prefix(plan, journal.begin, journal.targets, journal.ready)
    by_node = {r.result.target.node_id: r for r in journal.results}
    results: list[dict[str, Any]] = []
    pending: list[str] = []
    codes: list[int] = []
    for target in plan.targets:
        committed = by_node.get(target.node_id)
        if committed is None:
            pending.append(target.node_id)
            codes.append(int(ExitCode.OPEN))
            continue
        claimed = Classified(committed.result.status, committed.result.reason)
        expected = expected_result(plan.comparison, committed, admit)
        if claimed != expected:
            raise IntegrityError(
                "audit.result_status",
                f"audit_result at seq {committed.record.seq} claims {claimed.status.value} "
                f"({claimed.reason!r}); its attempt gives {expected.status.value} "
                f"({expected.reason!r})",
            )
        results.append(_entry(target, committed.record, expected))
        codes.append(exit_class(expected.status, expected.reason))
    if not plan.targets or plan.comparison == AuditComparison.REPROVE:
        codes.append(int(ExitCode.OPEN))
    counts = dict.fromkeys(STATUSES, 0)
    for entry in results:
        counts[entry["status"]] += 1
    document = {
        "format": REPORT_FORMAT,
        "campaign": plan.campaign,
        "certificate_sha256": plan.certificate_sha256,
        "targets_sha256": plan.targets_sha256,
        "comparison": AuditComparison(plan.comparison).value,
        "population": plan.population,
        "selected": plan.target_count,
        "seed": plan.seed,
        "counts": counts,
        "results": results,
        "pending": pending,
    }
    check_report(document)
    return AuditReport(document, _severest(codes))


def _entry(target: AuditTarget, record: Ref, result: Classified) -> dict[str, Any]:
    return {
        "target": target.to_json(),
        "record": record.to_json(),
        "status": result.status.value,
        "reason": result.reason,
    }


# -- reading a report ------------------------------------------------------------------------------


def _hash(value: Any, at: str) -> str:
    return f.matching(value, at, is_hash, "Hash")


def _result(value: Any, at: str) -> str:
    f.obj(value, at, ("target", "record", "status", "reason"))
    AuditTarget.from_json(value["target"], f.member(at, "target"))
    Ref.from_json(value["record"], f.member(at, "record"))
    f.string(value["reason"], f.member(at, "reason"))
    return f.choice(value["status"], f.member(at, "status"), STATUSES)


def check_report(value: Any) -> None:
    """The schema of an audit report and its rules ``audit_report.counts`` and
    ``audit_report.selected`` (ContractError naming the rule; ``schema`` with a location)."""
    f.obj(value, "$", _FIELDS)
    f.const(value["format"], "$.format", REPORT_FORMAT)
    for name in ("campaign", "certificate_sha256", "targets_sha256", "seed"):
        _hash(value[name], f.member("$", name))
    f.choice(value["comparison"], "$.comparison", tuple(c.value for c in AuditComparison))
    population = f.nonnegative(value["population"], "$.population")
    selected = f.nonnegative(value["selected"], "$.selected")
    counts: Mapping[str, Any] = f.obj(value["counts"], "$.counts", STATUSES)
    for status in STATUSES:
        f.nonnegative(counts[status], f.member("$.counts", status))
    statuses = f.items(value["results"], "$.results", _result)
    pending = f.items(value["pending"], "$.pending", _hash)
    tally = dict.fromkeys(STATUSES, 0)
    for status in statuses:
        tally[status] += 1
    if tally != dict(counts):
        raise ContractError("audit_report.counts", "counts differ from the results")
    if selected != len(statuses) + len(pending) or selected > population:
        raise ContractError(
            "audit_report.selected", "selected is not results + pending, or exceeds population"
        )
