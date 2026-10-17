"""The Python API (specification §12.1): typed values in, result documents out.

It mirrors the commands one to one. It never reads the environment, prints or exits: every input
is an argument (a frozen request value or a path), every result a value with ``to_json()`` (plain
JSON types) and, where the command has one, an ``exit_code`` (specification §12.2); a failure is a
typed :class:`~cubeproof.base.errors.CubeproofError` and :func:`exit_code_of` maps it to the exit
code the command line would use. The log of a run goes to a sink the caller passes
(:class:`RunOptions`); the API itself writes nowhere but the files the command is about.

====================  ==============================================================
``bundle import``     :func:`bundle_import`
``campaign create``   :func:`campaign_create` (a :class:`CampaignRequest`)
``shard``             :func:`shard` (a :class:`ShardRequest`)
``run``               :func:`run` (a :class:`RunConfig` and :class:`RunOptions`)
``handoff``           :func:`handoff` (a :class:`HandoffCommand`)
``status``            :func:`status`
``certify``           :func:`certify`, :func:`certify_evidence`
``evidence package``  :func:`package` (a :class:`PackageRequest`)
``journal``           :func:`journal_verify`, :func:`journal_repair`
``audit``             :func:`audit` (an :class:`AuditRequest`: :class:`AuditConfig`,
                      :class:`Selection` and the certified inputs)
``verify-retained``   :func:`verify_retained` (a :class:`VerifyRequest`)
====================  ==============================================================
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import replace
from pathlib import Path
from typing import Any

from cubeproof.base.canonical_json import parse_document
from cubeproof.base.settings import DEFAULT_LIMITS
from cubeproof.commands import (
    AuditOutcome,
    AuditRequest,
    BundleImport,
    CampaignRequest,
    HandoffCommand,
    HandoffOutcome,
    JournalReport,
    PackageRequest,
    PackageResult,
    RepairReport,
    RootSplitSpec,
    RunOptions,
    Selection,
    ShardRequest,
    ShardResult,
    StatusReport,
    VerifyRequest,
    VerifyResult,
    certify_command,
    create_campaign,
    handoff_command,
    status_command,
)
from cubeproof.commands import audit_command as _audit_command
from cubeproof.commands import bundle_import as _bundle_import
from cubeproof.commands import certify_evidence as _certify_evidence
from cubeproof.commands import journal_repair as _journal_repair
from cubeproof.commands import journal_verify as _journal_verify
from cubeproof.commands import package_evidence as _package_evidence
from cubeproof.commands import run_command as _run_command
from cubeproof.commands import shard_command as _shard_command
from cubeproof.commands import verify_retained_command as _verify_retained_command
from cubeproof.coordinator.audit_config import AuditConfig, AuditRun
from cubeproof.coordinator.config import RunConfig, RunResult, Stop, exit_code_of
from cubeproof.evidence.certify.run import exit_code as verdict_exit_code

__all__ = [
    "AuditConfig",
    "AuditOutcome",
    "AuditRequest",
    "AuditRun",
    "BundleImport",
    "CampaignRequest",
    "HandoffCommand",
    "HandoffOutcome",
    "JournalReport",
    "PackageRequest",
    "PackageResult",
    "RepairReport",
    "RootSplitSpec",
    "RunConfig",
    "RunOptions",
    "RunResult",
    "Selection",
    "ShardRequest",
    "ShardResult",
    "StatusReport",
    "Stop",
    "VerifyRequest",
    "VerifyResult",
    "audit",
    "bundle_import",
    "campaign_create",
    "certify",
    "certify_evidence",
    "exit_code_of",
    "handoff",
    "journal_repair",
    "journal_verify",
    "package",
    "run",
    "shard",
    "status",
    "verdict_exit_code",
    "verify_retained",
]


def bundle_import(source: Path, target: Path) -> BundleImport:
    """``bundle import``: the new bundle directory ``target`` from external DIMACS ``source``."""
    return _bundle_import(source, target)


def campaign_create(request: CampaignRequest) -> dict[str, Any]:
    """``campaign create``: the campaign document that was published."""
    return create_campaign(request).to_json()


def shard(request: ShardRequest) -> ShardResult:
    """``shard``: plan and write the shard files (default, weighted or from a frontier)."""
    return _shard_command(request)


def run(config: RunConfig, options: RunOptions = RunOptions()) -> RunResult:  # noqa: B008
    """``run``: one worker until nothing is left to do or a stop (``RunResult.exit_code``)."""
    return _run_command(config, options)


def handoff(command: HandoffCommand) -> HandoffOutcome:
    """``handoff``: write (or find) the request and report its state."""
    return handoff_command(command)


def status(results: Path) -> StatusReport:
    """``status``: the validated ``status.json`` of a results directory."""
    return status_command(results)


def _certificate_value(document: bytes) -> dict[str, Any]:
    """The value of a certificate document the certifier wrote: a certificate has no document
    size limit (specification §4.1), the other reader limits apply."""
    limits = replace(
        DEFAULT_LIMITS, document_bytes=max(DEFAULT_LIMITS.document_bytes, len(document))
    )
    value: dict[str, Any] = parse_document(document, limits=limits)
    return value


def certify(campaign: Path, journals: Sequence[Path], output: Path | None = None) -> dict[str, Any]:
    """``certify``: the certificate document (its verdict is ``certificate["verdict"]``;
    :func:`verdict_exit_code` maps it to the command's exit code)."""
    result = certify_command(campaign, journals, output)
    document: dict[str, Any] = _certificate_value(result.document)
    return document


def certify_evidence(manifest: Path, output: Path | None = None) -> dict[str, Any]:
    """``certify --evidence``: the certificate of a verified evidence directory, which must equal
    the packaged one."""
    result = _certify_evidence(manifest, output)
    document: dict[str, Any] = _certificate_value(result.document)
    return document


def package(request: PackageRequest) -> PackageResult:
    """``evidence package``: certify and publish a portable evidence directory."""
    return _package_evidence(request)


def journal_verify(journal: Path, campaign: Path) -> JournalReport:
    """``journal verify``: validate every complete record of a journal of the campaign."""
    return _journal_verify(journal, campaign)


def journal_repair(journal: Path, campaign: Path) -> RepairReport:
    """``journal repair``: remove a torn tail under the results directory's run lock."""
    return _journal_repair(journal, campaign)


def audit(request: AuditRequest) -> AuditOutcome:
    """``audit``: bind the certificate to its journal prefixes, plan, run the selected targets
    and publish the report (``AuditOutcome.exit_code``; the report document is
    ``AuditOutcome.report.document``)."""
    return _audit_command(request)


def verify_retained(request: VerifyRequest) -> VerifyResult:
    """``verify-retained``: check every committed retained proof of the journals and publish
    the report (``VerifyResult.document``, ``VerifyResult.exit_code``)."""
    return _verify_retained_command(request)
