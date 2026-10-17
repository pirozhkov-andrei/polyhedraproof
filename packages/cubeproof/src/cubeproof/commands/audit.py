"""``audit``: recompute audit of certified leaves (specification §11.1, §11.2, §12.1, §12.2).

The command layer owns every decision about *what* is audited and *what a result means*; the
executor (:mod:`cubeproof.coordinator.audit_run`) only runs attempts and commits records:

1. inputs: ``--campaign --certificate --journals`` or ``--evidence`` (exclusive alternatives;
   the manifest names its certificate). No input journal or certificate may lie in the
   results directory;
2. under the results directory's lock (``prepare``) the certificate is bound to snapshots of its
   exact journal prefixes in ``<results>/certified/`` and re-certified
   (:mod:`.audit_inputs`), and the plan is regenerated from them (:mod:`.audit_plan`): the same
   inputs and selection always give the same plan, which the executor compares with what the
   journal already holds;
3. the executor runs every planned target; whether a target can run in a strict audit
   (:func:`.audit_report.runnable`) and the status of each result
   (:func:`.audit_report.classify_result`) are the rules of this layer;
4. after a session that ended without an error and with a complete plan, the report is derived
   from the regenerated plan and a fresh validated read of the audit journal
   (:func:`.audit_report.build_report`, which recomputes every committed status) and published
   atomically as ``<results>/audit-report.json`` (replaced by a later session).

Exit code: the report's (4 > 5 > 1 > 0; 0 only when every selected target of a strict audit is
HASH_MATCHED), at least 5 after an I/O service failure, 130 after a deliberate interruption
unless the report already shows an integrity failure (4); 1 when no report exists (the plan was
not complete).
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from cubeproof.base.errors import ConfigurationError, InputError, IntegrityError
from cubeproof.cnf.campaign import LoadedCampaign, load_campaign
from cubeproof.commands.audit_inputs import bind_certified_inputs, read_certificate
from cubeproof.commands.audit_journal import AuditScan, read_audit_journal
from cubeproof.commands.audit_plan import AuditPlan, Selection, check_plan_prefix, make_plan
from cubeproof.commands.audit_report import AuditReport, build_report, classify_result, runnable
from cubeproof.commands.inputs import resolve_inputs
from cubeproof.commands.run import SERVICE_COMMAND
from cubeproof.commands.verify_retained import publish_replacing
from cubeproof.contracts.enums import AuditStatus, ExitCode
from cubeproof.coordinator.audit_config import AuditConfig, AuditRun, AuditWork
from cubeproof.coordinator.audit_run import run_audit
from cubeproof.coordinator.config import Stop
from cubeproof.evidence.schema import Attempt, AuditTarget, Machinery

__all__ = [
    "REPORT_NAME",
    "SNAPSHOT_DIRECTORY",
    "AuditOutcome",
    "AuditRequest",
    "audit_command",
    "outcome_exit_code",
]

REPORT_NAME = "audit-report.json"
#: The preserved certified inputs: one snapshot per certified journal prefix (specification §11.1).
SNAPSHOT_DIRECTORY = "certified"

_SEVERITY = {
    int(ExitCode.SUCCESS): 0,
    int(ExitCode.OPEN): 1,
    int(ExitCode.TOOL): 2,
    int(ExitCode.INTEGRITY): 3,
}


@dataclass(frozen=True)
class AuditRequest:
    """``audit``: the execution environment, the selection and the certified inputs (explicit
    campaign, certificate and journals, or an evidence manifest)."""

    config: AuditConfig
    selection: Selection
    campaign: Path | None = None
    certificate: Path | None = None
    journals: tuple[Path, ...] = ()
    evidence: Path | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.config, AuditConfig) or not isinstance(self.selection, Selection):
            raise ConfigurationError("usage", "an audit needs an AuditConfig and a Selection")
        object.__setattr__(self, "journals", tuple(Path(j) for j in self.journals))


@dataclass(frozen=True)
class AuditOutcome:
    """How ``audit`` ended: the session, the report (None if the plan was not complete), its
    file and the exit code of specification §12.2."""

    run: AuditRun
    report: AuditReport | None
    path: Path | None
    exit_code: int
    notes: tuple[str, ...] = field(default=())

    def to_json(self) -> dict[str, Any]:
        summary: dict[str, Any] | None = None
        if self.report is not None:
            document = self.report.document
            summary = {
                name: document[name]
                for name in ("comparison", "population", "selected", "seed", "counts")
            }
            summary["pending"] = len(document["pending"])
            summary["strict_success"] = self.report.strict_success
        return {
            "exit_code": self.exit_code,
            "reason": self.run.stop.value,
            "journal": self.run.journal,
            "seq": self.run.seq,
            "head": self.run.head,
            "pending": self.run.pending,
            "session": dict(self.run.session),
            "report": None if self.path is None else str(self.path),
            "summary": summary,
            "notes": [*self.run.notes, *self.notes],
        }


def _inputs(request: AuditRequest) -> tuple[Path, Path, tuple[Path, ...]]:
    """``(campaign, certificate, journals)`` from explicit paths or the evidence manifest."""
    if request.evidence is not None:
        if request.campaign is not None or request.certificate is not None or request.journals:
            raise ConfigurationError(
                "usage",
                "--evidence is the exclusive alternative to --campaign/--certificate/--journals",
            )
        found = resolve_inputs(
            campaign=None, journals=(), evidence=request.evidence, limits=request.config.limits
        )
        if found.certificate is None:
            raise ConfigurationError("usage", "the evidence manifest names no certificate")
        return found.campaign, found.certificate, found.journals
    if request.campaign is None or request.certificate is None or not request.journals:
        raise ConfigurationError(
            "usage", "--campaign, --certificate and --journals are required without --evidence"
        )
    return Path(request.campaign), Path(request.certificate), request.journals


def _inside(inner: Path, outer: Path) -> bool:
    return inner == outer or outer in inner.parents


def _check_results(results: Path, inputs: tuple[Path, ...]) -> None:
    resolved = Path(results).resolve()
    for path in inputs:
        if _inside(Path(path).resolve(), resolved):
            raise ConfigurationError(
                "audit.results", f"input {path} lies in the audit's results directory"
            )


def _severest(codes: list[int]) -> int:
    return max(codes, key=lambda code: _SEVERITY[code])


def outcome_exit_code(run: AuditRun, report: AuditReport | None) -> int:
    """The exit code of an audit session (module doc)."""
    reported = int(ExitCode.OPEN) if report is None else report.exit_code
    if run.stop is Stop.INTERRUPTED:
        return reported if reported == int(ExitCode.INTEGRITY) else int(ExitCode.INTERRUPTED)
    codes = [reported]
    if run.stop is Stop.SERVICE:
        codes.append(int(ExitCode.TOOL))
    return _severest(codes)


@dataclass
class _Session:
    """What ``prepare`` and ``conclude`` share within one command."""

    plan: AuditPlan | None = None
    campaign: LoadedCampaign | None = None
    report: AuditReport | None = None
    path: Path | None = None
    copies_ignored: tuple[str, ...] = ()


def audit_command(request: AuditRequest) -> AuditOutcome:
    """Run ``audit`` (module doc); the report is published before returning.

    Errors before any target runs: ConfigurationError (usage, directories, locks), InputError
    and IntegrityError (certified inputs, a changed plan), ToolError (tools, I/O service),
    ResourceError (the preflight of specification §8.3).
    """
    campaign, certificate, journals = _inputs(request)
    config = request.config
    _check_results(config.results, (campaign, certificate, *journals))
    # preflight: unusable inputs are refused before any directory is created (the binding
    # itself runs again under the results directory's lock)
    preflight = load_campaign(campaign, limits=config.limits)
    claim = read_certificate(certificate, limits=config.limits)
    if claim.campaign != preflight.campaign.campaign_id:
        raise IntegrityError(
            "audit.certificate", f"the certificate is of campaign {claim.campaign}"
        )
    for journal in journals:
        if not Path(journal).is_file():
            raise InputError("input.file", f"{journal} is not a journal file")
    if not config.service_argv:
        config = replace(config, service_argv=SERVICE_COMMAND)
    selection, limits = request.selection, config.limits
    session = _Session()

    def prepare(results: Path) -> AuditWork:
        bound = bind_certified_inputs(
            campaign, journals, certificate, results / SNAPSHOT_DIRECTORY, limits=limits
        )
        plan = make_plan(bound, selection, limits=limits)
        loaded = bound.campaign
        admit = loaded.campaign.admit
        session.plan, session.campaign = plan, loaded
        session.copies_ignored = bound.copies_ignored
        scan = AuditScan()

        def can_run(target: AuditTarget, machinery: Machinery) -> bool:
            return runnable(plan.comparison, target, machinery)

        def decide(
            target: AuditTarget, attempt: Attempt, machinery: Machinery
        ) -> tuple[AuditStatus, str]:
            found = classify_result(plan.comparison, target, attempt, machinery, admit)
            return found.status, found.reason

        def conclude(journal: Path) -> None:
            read = read_audit_journal(journal, loaded, complete=True, limits=limits)
            report = build_report(plan, read, admit=admit)
            path = results / REPORT_NAME
            publish_replacing(path, report.data)
            session.report, session.path = report, path

        return AuditWork(
            campaign=loaded,
            plan=plan.payloads(),
            runnable=can_run,
            decide=decide,
            check_plan=lambda begin, targets, ready: check_plan_prefix(plan, begin, targets, ready),
            observe=scan.add,
            conclude=conclude,
            reference_bytes=plan.reference_bytes,
        )

    run = run_audit(config, prepare)
    notes: tuple[str, ...] = tuple(
        f"{path}: not used, another copy of the same journal was" for path in session.copies_ignored
    )
    if session.report is not None and session.report.document["comparison"] == "reprove":
        notes += ("a reprove audit is an independent reproof, not a historical hash match",)
    return AuditOutcome(
        run=run,
        report=session.report,
        path=session.path,
        exit_code=outcome_exit_code(run, session.report),
        notes=notes,
    )
