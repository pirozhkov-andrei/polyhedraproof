"""The command handlers: the only place that prints (specification §12.1, §12.2).

A handler receives the parsed arguments, enforces the rules over several arguments (exclusive
alternatives, required combinations: usage errors, exit code 3), builds the typed request of the
command layer, calls it and reports: result documents on standard output, notes and the run log on
standard error. It returns the exit code of specification §12.2; errors raised below are reported by
:func:`cubeproof.cli.main`.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

from cubeproof.base.errors import ConfigurationError
from cubeproof.base.settings import ToolPaths
from cubeproof.commands import (
    AuditRequest,
    CampaignRequest,
    HandoffCommand,
    PackageRequest,
    RootSplitSpec,
    RunOptions,
    Selection,
    ShardRequest,
    VerifyRequest,
    audit_command,
    bundle_import,
    certify_command,
    certify_evidence,
    create_campaign,
    handoff_command,
    journal_repair,
    journal_verify,
    package_evidence,
    parse_input,
    parse_policy_overrides,
    parse_size,
    resolve_inputs,
    run_command,
    service_command,
    shard_command,
    status_command,
    verify_retained_command,
)
from cubeproof.contracts.campaign import Admit
from cubeproof.contracts.documents import Roots
from cubeproof.contracts.enums import AuditComparison
from cubeproof.contracts.policy import Policy
from cubeproof.coordinator.audit_config import AuditConfig
from cubeproof.coordinator.config import RunConfig
from cubeproof.coordinator.events import stream_sink

__all__ = ["HANDLERS", "Handler", "report_note"]

Handler = Callable[[argparse.Namespace], int]


def say(text: str) -> None:
    sys.stdout.write(text + "\n")
    sys.stdout.flush()


def report_note(text: str) -> None:
    """A note on standard error."""
    sys.stderr.write(text + "\n")
    sys.stderr.flush()


def _say_json(document: dict[str, Any]) -> None:
    say(json.dumps(document, sort_keys=True, separators=(",", ":")))


def _local(text: str | None) -> str | None:
    """A tool path as the absolute local path the tool layer requires (specification §4.1)."""
    return None if text is None else str(Path(text).absolute())


def _usage(detail: str) -> ConfigurationError:
    return ConfigurationError("usage", detail)


# -- bundle, campaign --------------------------------------------------------------------------


def bundle_import_command(args: argparse.Namespace) -> int:
    result = bundle_import(args.input, args.output)
    _say_json(result.to_json())
    return result.exit_code


def campaign_create_command(args: argparse.Namespace) -> int:
    try:
        argv = json.loads(args.solver_argv)
    except ValueError:
        raise _usage("--solver-argv is not a JSON list") from None
    if not isinstance(argv, list) or not all(isinstance(x, str) for x in argv):
        raise _usage("--solver-argv is not a JSON list of strings")
    root_split = RootSplitSpec.parse(args.root_split)
    solver, checker = _local(args.solver), _local(args.checker)
    assert solver is not None and checker is not None
    request = CampaignRequest(
        bundles=args.bundle,
        policy=parse_input(args.policy, Policy.from_json),
        admit=parse_input(args.admit, lambda value: Admit.from_json(value, "$")),
        solver=solver,
        solver_argv=argv,
        checker=checker,
        output=args.output,
        author=args.author,
        roots=None if args.roots is None else parse_input(args.roots, Roots.from_json),
        root_split=root_split,
    )
    campaign = create_campaign(request)
    say(f"campaign {campaign.campaign_id} written to {args.output}")
    return 0


# -- shard, run, handoff, status -----------------------------------------------------------------


def shard_plan_command(args: argparse.Namespace) -> int:
    if args.evidence is not None:
        if args.campaign is not None or args.from_open is not None or args.journals:
            raise _usage(
                "--evidence is the exclusive alternative to --campaign/--from-open/--journals"
            )
        inputs = resolve_inputs(campaign=None, journals=(), evidence=args.evidence)
        request = ShardRequest(
            campaign=inputs.campaign,
            machines=args.machines,
            output=args.output,
            weights=args.weights,
            from_open=inputs.certificate,
            journals=inputs.journals,
            scope=args.scope or "campaign",
            formulas=tuple(args.formula or ()),
        )
    else:
        if args.campaign is None:
            raise _usage("one of --campaign or --evidence is required")
        if args.from_open is None and (args.journals or args.scope is not None):
            raise _usage("--journals and --scope belong to --from-open")
        if args.from_open is not None and not args.journals:
            raise _usage("--from-open needs --journals")
        request = ShardRequest(
            campaign=args.campaign,
            machines=args.machines,
            output=args.output,
            weights=args.weights,
            from_open=args.from_open,
            journals=tuple(args.journals or ()),
            scope=args.scope or "campaign",
            formulas=tuple(args.formula or ()),
        )
    _say_json(shard_command(request).to_json())
    return 0


def run_worker_command(args: argparse.Namespace) -> int:
    if args.verbose and args.quiet:
        raise _usage("-v and -q exclude each other")
    inputs = resolve_inputs(
        campaign=args.campaign, journals=(), evidence=args.evidence, need_journals=False
    )
    config = RunConfig(
        campaign=inputs.campaign,
        results=args.results,
        work=args.work,
        worker=args.worker,
        tools=ToolPaths(
            solver=_local(args.solver), checker=_local(args.checker), helper=_local(args.helper)
        ),
        jobs=args.jobs,
        memory_bytes=None if args.memory is None else parse_size(args.memory),
        disk_bytes=None if args.disk is None else parse_size(args.disk),
        max_seconds=None if args.max_hours is None else args.max_hours * 3600,
        policy_overrides=parse_policy_overrides(args.policy_override),
        proof_mode=args.proof_mode,
        reopen_blocked=args.reopen_blocked,
        campaign_policy=args.campaign_policy,
        accept_code_change=args.accept_code_change,
        known_answer=not args.no_known_answer,
        cache=not args.no_cache,
    )
    options = RunOptions(
        inbox=args.inbox,
        outbox=args.outbox,
        shard=args.shard,
        export=args.export,
        log_sink=stream_sink(sys.stderr),
        log_level="debug" if args.verbose else "warn" if args.quiet else "info",
    )
    result = run_command(config, options)
    for note in result.notes:
        report_note(f"cubeproof: {note}")
    _say_json(result.to_json())
    return result.exit_code


def handoff_request_command(args: argparse.Namespace) -> int:
    outcome = handoff_command(
        HandoffCommand(args.results, args.nodes, args.output_name, wait_ms=args.wait_ms)
    )
    _say_json(outcome.to_json())
    return outcome.exit_code


def status_show_command(args: argparse.Namespace) -> int:
    report = status_command(args.results)
    if args.json:
        if report.stale:
            report_note("cubeproof: the status is stale; the worker may have died")
        _say_json(report.document)
    else:
        say(report.text.rstrip("\n"))
    return 0


# -- certify, evidence, journal ------------------------------------------------------------------


def certify_verdict_command(args: argparse.Namespace) -> int:
    if args.evidence is not None:
        if args.campaign is not None or args.journals:
            raise _usage("--evidence is the exclusive alternative to --campaign/--journals")
        result = certify_evidence(args.evidence, args.output)
    else:
        inputs = resolve_inputs(campaign=args.campaign, journals=args.journals or (), evidence=None)
        result = certify_command(inputs.campaign, inputs.journals, args.output)
    for duplicate in result.duplicates:
        report_note(f"cubeproof: {duplicate.path} is a copy of a journal already used")
    say(f"{result.verdict.value} {args.output if args.output is not None else ''}".rstrip())
    return result.exit_code


def evidence_package_command(args: argparse.Namespace) -> int:
    result = package_evidence(PackageRequest(args.campaign, tuple(args.journals), args.output))
    for path in result.duplicates:
        report_note(f"cubeproof: {path} is a copy of a journal already used")
    _say_json(result.to_json())
    return result.exit_code


def journal_verify_command(args: argparse.Namespace) -> int:
    report = journal_verify(args.journal, args.campaign)
    if report.torn_tail_bytes:
        report_note(
            f"cubeproof: {report.torn_tail_bytes} bytes after the last complete record "
            "(a torn tail; journal repair removes it)"
        )
    _say_json(report.to_json())
    return report.exit_code


def journal_repair_command(args: argparse.Namespace) -> int:
    report = journal_repair(args.journal, args.campaign)
    _say_json(report.to_json())
    return report.exit_code


# -- audit, verify-retained ------------------------------------------------------------------------


def audit_recompute_command(args: argparse.Namespace) -> int:
    if (args.sample is None) == (not args.all):
        raise _usage("exactly one of --sample N and --all is required")
    if args.evidence is not None:
        if args.campaign is not None or args.certificate is not None or args.journals:
            raise _usage(
                "--evidence is the exclusive alternative to --campaign/--certificate/--journals"
            )
    elif args.campaign is None or args.certificate is None or not args.journals:
        raise _usage("--campaign, --certificate and --journals are required without --evidence")
    selection = Selection(
        None if args.all else args.sample, args.seed, AuditComparison(args.comparison)
    )
    config = AuditConfig(
        results=args.results,
        work=args.work,
        worker=args.worker,
        tools=ToolPaths(
            solver=_local(args.solver), checker=_local(args.checker), helper=_local(args.helper)
        ),
        memory_bytes=None if args.memory is None else parse_size(args.memory),
        disk_bytes=None if args.disk is None else parse_size(args.disk),
        proof_cap_bytes=None if args.proof_cap is None else parse_size(args.proof_cap),
        known_answer=not args.no_known_answer,
    )
    outcome = audit_command(
        AuditRequest(
            config,
            selection,
            campaign=args.campaign,
            certificate=args.certificate,
            journals=tuple(args.journals or ()),
            evidence=args.evidence,
        )
    )
    document = outcome.to_json()
    for note in document["notes"]:
        report_note(f"cubeproof: {note}")
    _say_json(document)
    return outcome.exit_code


def verify_retained_check_command(args: argparse.Namespace) -> int:
    checker = _local(args.checker)
    assert checker is not None
    request = VerifyRequest(
        proofs_root=args.proofs_root,
        results=args.results,
        work=args.work,
        worker=args.worker,
        checker=checker,
        campaign=args.campaign,
        journals=tuple(args.journals or ()),
        evidence=args.evidence,
        memory_bytes=None if args.memory is None else parse_size(args.memory),
    )
    result = verify_retained_command(request)
    _say_json(result.to_json())
    return result.exit_code


# -- not available / internal ----------------------------------------------------------------------


def unavailable_command(args: argparse.Namespace) -> int:
    name = (
        args.command if getattr(args, "action", None) is None else f"{args.command} {args.action}"
    )
    raise ConfigurationError("command.unavailable", f"{name} is not available in this build")


def io_service_command(args: argparse.Namespace) -> int:
    return service_command(
        results=args.results,
        work=args.work,
        journal=args.journal,
        lock=args.lock,
        lock_fd=args.lock_fd,
        campaign=args.campaign,
        variables=args.variables,
        header_file=args.header_file,
    )


#: The handler of every command of :data:`cubeproof.cli.spec.COMMANDS`, by its words.
HANDLERS: dict[tuple[str, ...], Handler] = {
    ("bundle", "import"): bundle_import_command,
    ("campaign", "create"): campaign_create_command,
    ("shard",): shard_plan_command,
    ("run",): run_worker_command,
    ("handoff",): handoff_request_command,
    ("status",): status_show_command,
    ("certify",): certify_verdict_command,
    ("evidence", "package"): evidence_package_command,
    ("journal", "verify"): journal_verify_command,
    ("journal", "repair"): journal_repair_command,
    ("audit",): audit_recompute_command,
    ("verify-retained",): verify_retained_check_command,
    ("io-service",): io_service_command,
}
