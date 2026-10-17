"""Measuring the machinery and the resources, and the effective policy (specification §4.3, §4.6,
§8.2, §8.3).

Startup step 5 of specification §7.3: before anything is committed or launched the run

1. resolves the **effective policy**: the campaign's policy, then ``--policy-override KEY=JSON``
   (a dotted key reaches into ``split``, ``heap_fit`` and ``leaf_time_ms``), then the proof mode
   (``transient``, ``retain`` or ``stream``), then the proof-cap clamp of specification §8.3 against
   the measured idle machine; a stream task the idle machine cannot hold (solver, checker and
   relay: 3000 milli-CPU and their memory) fails preflight (specification §8.2);
2. pins the configured solver and checker to the **campaign's hashes** (a missing, unusable or
   different binary is a ToolError before any record exists: no synthetic attempts) and probes
   the isolation wrappers, the solver version and the optional splitter helper; in stream mode
   also the interpreter that runs the relay (:func:`relay_interpreter`; not a machinery field:
   the relay script's bytes are in the source manifest);
3. hashes the installed sources and assembles the machinery snapshot;
4. measures the resources and derives the ledgers.

Everything is returned in one :class:`Measured` value; the caller commits the header/resume.
"""

from __future__ import annotations

import sys
from collections.abc import Mapping
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from cubeproof.base.canonical_json import encode
from cubeproof.base.errors import ConfigurationError, ContractError
from cubeproof.base.settings import ToolPaths
from cubeproof.cnf.campaign import LoadedCampaign
from cubeproof.contracts.enums import ProofMode
from cubeproof.contracts.policy import Policy
from cubeproof.coordinator.config import RunConfig
from cubeproof.coordinator.resources import (
    IO_SERVICE_RESIDENT,
    ResourceConfig,
    Resources,
    SystemProbes,
    cnf_size_bound,
    preflight,
)
from cubeproof.coordinator.scheduler_select import leaf_tools
from cubeproof.evidence.schema import Machinery
from cubeproof.leaf.attempt import LeafTools
from cubeproof.split.helper import Helper, discover_helper
from cubeproof.split.lookahead import ALGORITHM
from cubeproof.tools.isolation import Isolation, PinnedBinary
from cubeproof.tools.known_answer import check_checker
from cubeproof.tools.machinery import (
    package_root,
    runtime_info,
    snapshot,
    solver_version,
    source_manifest,
)
from cubeproof.tools.process import Supervisor

__all__ = [
    "Measured",
    "apply_overrides",
    "check_policy_continuity",
    "measure",
    "relay_interpreter",
    "resolve_policy",
]


def apply_overrides(base: Policy, overrides: Mapping[str, Any], proof_mode: str | None) -> Policy:
    """``base`` with the JSON values of ``overrides`` (dotted keys) and the proof mode."""
    value = base.to_json()
    for key, new in overrides.items():
        target = value
        parts = key.split(".")
        for part in parts[:-1]:
            nested = target.get(part)
            if not isinstance(nested, dict):
                raise ConfigurationError("run.policy_override", f"{key!r} is not a policy field")
            target = nested
        depth_time = parts[:-1] == ["leaf_time_ms"]  # a new depth key is a policy value
        if parts[-1] not in target and not depth_time:
            raise ConfigurationError("run.policy_override", f"{key!r} is not a policy field")
        target[parts[-1]] = new
    if proof_mode is not None:
        value["proof_mode"] = proof_mode
    try:
        return Policy.from_json(value)
    except ContractError as error:
        raise ConfigurationError(
            "run.policy_override", f"the effective policy is invalid: {error.rule}: {error.detail}"
        ) from None


def resolve_policy(loaded: LoadedCampaign, config: RunConfig) -> Policy:
    """The policy before the proof-cap clamp (module doc, step 1)."""
    return apply_overrides(loaded.campaign.policy, config.policy_overrides, config.proof_mode)


#: The one policy field that the machine may change without the command line: the startup
#: clamp lowers the proof cap to what fits (specification §8.3).
_CLAMPED = "proof_cap_bytes"


def check_policy_continuity(previous: Policy | None, config: RunConfig, requested: Policy) -> None:
    """Refuse a session whose policy differs from the one before it without being told so.

    A policy is the campaign's with the options of one command line (``--proof-mode``,
    ``--policy-override``); nothing is remembered between sessions. A worker restarted without
    an option it was started with would silently go back to the campaign's value: a run meant
    to retain its proofs would record leaves without them, which cannot be repaired afterwards.
    So a value that differs from the policy the last header or resume recorded must be named
    on this command line, by its dotted key (``split.vars``) or a key above it, with the old
    value or a new one, or the caller must say that the campaign's policy is wanted
    (``campaign_policy``). The proof cap is exempt: the machine clamps it.
    """
    if previous is None or config.campaign_policy:
        return
    before, now = _leaves(previous.to_json()), _leaves(requested.to_json())
    named = set(config.policy_overrides)
    if config.proof_mode is not None:
        named.add("proof_mode")
    absent = object()
    silent = sorted(
        path
        for path in before.keys() | now.keys()
        if before.get(path, absent) != now.get(path, absent)
        and path != _CLAMPED
        and not any(path == key or path.startswith(key + ".") for key in named)
    )
    if not silent:
        return

    def shown(values: Mapping[str, Any]) -> str:
        return ", ".join(
            f"{path}={encode(values[path]).decode()}" if path in values else f"{path} unset"
            for path in silent
        )

    raise ConfigurationError(
        "run.policy_changed",
        f"the session before this one ran with {shown(before)}; this command line gives "
        f"{shown(now)}. Repeat the options of that session (--proof-mode MODE, "
        "--policy-override KEY=JSON_VALUE with these keys and values), or pass "
        "--campaign-policy to return to the campaign's policy on purpose",
    )


def check_code_continuity(
    previous: Machinery | None, config: RunConfig, now: Machinery
) -> str | None:
    """Refuse a session whose cubeproof sources differ from the session before, unless told.

    A worker restarted on another release, or on a rebuilt image, would otherwise continue its
    journal with other code without a word. Records stay judged by the machinery of their own
    header or resume, but a campaign that mixes code versions should be one on purpose: a strict
    audit of a ``unit`` leaf compares ``cubeproof_sha256``, and the claim names the writers. With
    ``accept_code_change`` the session goes on and the returned note says so.
    """
    if previous is None or previous.cubeproof_sha256 == now.cubeproof_sha256:
        return None
    change = f"cubeproof_sha256 {previous.cubeproof_sha256} -> {now.cubeproof_sha256}"
    if config.accept_code_change:
        return f"the cubeproof sources differ from the session before ({change}); accepted"
    raise ConfigurationError(
        "run.code_changed",
        f"the session before this one ran other cubeproof sources ({change}). Run the release "
        "the journal was started with, or pass --accept-code-change to continue with this one "
        "on purpose",
    )


def _leaves(value: Mapping[str, Any], prefix: str = "") -> dict[str, Any]:
    """The policy as dotted paths to its scalar values, the keys ``--policy-override`` takes
    (``split.vars``, ``leaf_time_ms.12``)."""
    found: dict[str, Any] = {}
    for key, item in value.items():
        path = f"{prefix}{key}"
        if isinstance(item, Mapping):
            found.update(_leaves(item, path + "."))
        else:
            found[path] = item
    return found


def relay_interpreter() -> PinnedBinary:
    """The interpreter that runs the stream relay script (``leaf.stream``): this process's own,
    resolved and hashed like a tool binary (the supervisor re-hashes it before each launch).
    The relay script itself is part of the measured source manifest."""
    executable = sys.executable
    if not executable:
        raise ConfigurationError(
            "run.relay_interpreter", "the interpreter of this process is unknown"
        )
    return PinnedBinary.measure(executable)


def _tool_paths(tools: ToolPaths) -> tuple[str, str]:
    if tools.solver is None or tools.checker is None:
        raise ConfigurationError("run.tools", "the solver and the checker paths are required")
    return tools.solver, tools.checker


#: The note of a session whose checker was not asked its known-answer questions.
SKIPPED_CONTROL = "the known-answer control of the checker was skipped (--no-known-answer)"


def _control_note(config: RunConfig) -> tuple[str, ...]:
    return () if config.known_answer else (SKIPPED_CONTROL,)


@dataclass
class Measured:
    """The measured machinery, resources and effective policy of one session."""

    isolation: Isolation
    supervisor: Supervisor
    solver: PinnedBinary
    checker: PinnedBinary
    helper: Helper | None
    helper_note: str | None
    machinery: Machinery
    tools: LeafTools
    resources: Resources
    policy: Policy
    notes: tuple[str, ...]


def measure(
    config: RunConfig, loaded: LoadedCampaign, work: Path, results: Path, *, frontier_nodes: int
) -> Measured:
    """Measure everything a header/resume records (module doc)."""
    campaign = loaded.campaign
    policy = resolve_policy(loaded, config)
    solver_path, checker_path = _tool_paths(config.tools)
    isolation = Isolation.probe()
    solver = PinnedBinary.pinned(solver_path, campaign.tools.solver.sha256)
    checker = PinnedBinary.pinned(checker_path, campaign.tools.checker_sha256)
    supervisor = Supervisor(isolation, clock=config.clock)
    try:
        if config.known_answer:
            # before anything is recorded: a checker that fails its control closes no leaf
            check_checker(supervisor, checker, str(work))
        version = solver_version(supervisor, solver, str(work))
        discovery = discover_helper(config.tools.helper, supervisor, str(work))
        manifest = source_manifest(config.packages or {"cubeproof": package_root("cubeproof")})
        helper = discovery.helper
        document = snapshot(
            solver=solver,
            solver_argv=campaign.tools.solver.argv,
            solver_version=version,
            checker=checker,
            helper=None if helper is None else (helper.binary.sha256, ALGORITHM),
            manifest=manifest,
            runtime=runtime_info(image_digest=None),
        )
        machinery = Machinery.from_json(document)
        resources = Resources(
            config.probes or SystemProbes(),
            ResourceConfig(
                cpu_milli=None if config.jobs is None else config.jobs * 1000,
                memory_bytes=config.memory_bytes,
                disk_bytes=config.disk_bytes,
                helper_resident_bytes=IO_SERVICE_RESIDENT,
                frontier_nodes=frontier_nodes,
            ),
            {"work": str(work), "results": str(results)},
        )
        cnf_bytes = max(
            cnf_size_bound(bundle.formula, min(policy.max_cube_size, bundle.formula.variables))
            for bundle in loaded.bundles.values()
        )
        effective, _clamp, notes = preflight(
            policy, resources.capacity, cnf_bytes=cnf_bytes, group=resources.group_of("work")
        )
        tools = leaf_tools(machinery)
        if effective.proof_mode is ProofMode.STREAM:
            tools = replace(tools, python=relay_interpreter())
    except BaseException:
        supervisor.shutdown(grace_ms=1000)
        raise
    return Measured(
        isolation=isolation,
        supervisor=supervisor,
        solver=solver,
        checker=checker,
        helper=helper,
        helper_note=discovery.problem,
        machinery=machinery,
        tools=tools,
        resources=resources,
        policy=effective,
        notes=notes + resources.capacity.notes + _control_note(config),
    )
