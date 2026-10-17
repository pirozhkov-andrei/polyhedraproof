"""Command entry points (specification §12.1): typed values in, typed results out; no printing, no
exit.

``bundle import``, ``campaign create`` (with ``--roots`` and ``--root-split``), ``shard``
(default, weighted and from a certificate's frontier), ``run`` (with the handoff desk, the status
monitor and the export), ``handoff``, ``status``, ``certify`` (explicit files or an evidence
manifest), ``evidence package``, ``journal verify|repair`` and the hidden I/O service command
the run starts, ``audit`` (certified-input binding, seeded selection, the plan, the comparison
rules and the report; the audit executor runs the attempts) and ``verify-retained``. All use the
same boundary rules: the CLI reads the environment and the command line and reports; the API
returns result documents; the commands in between do neither. There is exactly one scheduler,
the coordinator's: no command decides what a run executes next.
"""

from __future__ import annotations

from cubeproof.commands.audit import AuditOutcome, AuditRequest, audit_command
from cubeproof.commands.audit_plan import Selection, parse_seed, percent_count
from cubeproof.commands.bundle import BundleImport, bundle_import
from cubeproof.commands.campaign import (
    CampaignRequest,
    certify_command,
    create_campaign,
    publish_file,
    read_json_file,
)
from cubeproof.commands.certify import certify_evidence
from cubeproof.commands.evidence import Evidence, EvidenceManifest, load_evidence
from cubeproof.commands.handoff import (
    HandoffCommand,
    HandoffOutcome,
    HandoffState,
    handoff_command,
)
from cubeproof.commands.inputs import ResolvedInputs, parse_input, resolve_inputs
from cubeproof.commands.journal import (
    JournalReport,
    RepairReport,
    journal_repair,
    journal_verify,
)
from cubeproof.commands.package import PackageRequest, PackageResult, package_evidence
from cubeproof.commands.rootsplit import RootSplitSpec
from cubeproof.commands.run import (
    SERVICE_COMMAND,
    RunOptions,
    parse_policy_overrides,
    parse_size,
    run_command,
    service_command,
)
from cubeproof.commands.shard import ShardRequest, ShardResult, read_shard_file, shard_command
from cubeproof.commands.status import StatusReport, status_command
from cubeproof.commands.verify_retained import VerifyRequest, VerifyResult
from cubeproof.commands.verify_retained import verify_retained as verify_retained_command

__all__ = [
    "SERVICE_COMMAND",
    "AuditOutcome",
    "AuditRequest",
    "BundleImport",
    "CampaignRequest",
    "Evidence",
    "EvidenceManifest",
    "HandoffCommand",
    "HandoffOutcome",
    "HandoffState",
    "JournalReport",
    "PackageRequest",
    "PackageResult",
    "RepairReport",
    "ResolvedInputs",
    "RootSplitSpec",
    "RunOptions",
    "Selection",
    "ShardRequest",
    "ShardResult",
    "StatusReport",
    "VerifyRequest",
    "VerifyResult",
    "audit_command",
    "bundle_import",
    "certify_command",
    "certify_evidence",
    "create_campaign",
    "handoff_command",
    "journal_repair",
    "journal_verify",
    "load_evidence",
    "package_evidence",
    "parse_input",
    "parse_policy_overrides",
    "parse_seed",
    "parse_size",
    "percent_count",
    "publish_file",
    "read_json_file",
    "read_shard_file",
    "resolve_inputs",
    "run_command",
    "service_command",
    "shard_command",
    "status_command",
    "verify_retained_command",
]
