"""Test-only helpers of the audit executor tests: a certified source run and audits of it.

A *source* is a real run of the coordinator (lifecycle helpers of ``tests/lifecycle``) with the
fake tools of :mod:`cp_audit_tool`, its journal and the certificate ``certify`` computed from it.
:func:`audit_config` and :func:`request` build the audit of a copy of that evidence with the same
tool installation (so the strict profile is the source's), in its own results and work
directories. :func:`spawn_audit` runs an audit in a child process (``cp_audit_runner.py``) with
signal handling on, which kills itself with SIGKILL (or signals itself, or kills its I/O service)
at the n-th occurrence of a lifecycle hook.

Nothing here is imported by runtime code.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
LIFECYCLE = HERE.parent / "lifecycle"
for _path in (HERE, LIFECYCLE):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

import cp_life_tools as t  # noqa: E402

from cubeproof import api  # noqa: E402
from cubeproof.base.settings import ToolPaths  # noqa: E402
from cubeproof.commands import SERVICE_COMMAND  # noqa: E402
from cubeproof.commands.audit import AuditRequest  # noqa: E402
from cubeproof.commands.audit_plan import Selection  # noqa: E402
from cubeproof.contracts.enums import AuditComparison  # noqa: E402
from cubeproof.contracts.policy import Policy  # noqa: E402
from cubeproof.coordinator.audit_config import AuditConfig  # noqa: E402

TOOL_SOURCE = HERE / "cp_audit_tool.py"
RUNNER = HERE / "cp_audit_runner.py"


def configure(tool: Path, **settings: Any) -> None:
    """Set the behaviour of an installed fake tool (its binary hash does not change)."""
    values = {"tests": str(t.TESTS), **settings}
    Path(str(tool) + ".json").write_text(json.dumps(values), encoding="utf-8")


def install(directory: Path, **solver: Any) -> t.Tools:
    """The audit fake solver ``cadical`` and checker ``cake_lpr`` below ``directory``."""
    directory.mkdir(parents=True, exist_ok=True)
    body = TOOL_SOURCE.read_text(encoding="utf-8")
    found: dict[str, Path] = {}
    for name in ("cadical", "cake_lpr"):
        path = directory / name
        path.write_text(f"#!{sys.executable} -I\n{body}", encoding="utf-8")
        path.chmod(0o755)
        found[name] = path
    configure(found["cadical"], **solver)
    configure(found["cake_lpr"])
    return t.Tools(found["cadical"], found["cake_lpr"])


@dataclass(frozen=True)
class Source:
    """A certified run: campaign, journal, certificate and the tools it ran with."""

    root: Path
    campaign: Path
    journal: Path
    certificate: Path
    tools: t.Tools
    verdict: str


def make_source(
    root: Path,
    formulas: Mapping[str, bytes],
    *,
    solver: Mapping[str, Any] | None = None,
    checker: Mapping[str, Any] | None = None,
    policy: Policy | None = None,
    exit_code: int = 0,
) -> Source:
    """Run the coordinator on ``formulas`` with the audit fake tools and certify the journal."""
    tools = install(root / "tools", **(solver or {}))
    if checker:
        configure(tools.checker, **checker)
    campaign = t.campaign(root, formulas, tools, policy or t.split_policy())
    result = api.run(t.config(root, campaign, tools))
    t.wait_clean(root / "results", root / "work")
    assert result.exit_code == exit_code, result.to_json()
    journal = root / "results" / "journal.jsonl"
    certificate = root / "certificate.json"
    document = api.certify(campaign, [journal], certificate)
    return Source(root, campaign, journal, certificate, tools, document["verdict"])


def copy_source(source: Source, target: Path) -> Source:
    """A copy of the source evidence (campaign directory, journal, certificate) below ``target``;
    the tools stay shared."""
    target.mkdir(parents=True, exist_ok=True)
    shutil.copytree(source.root / "bundles", target / "bundles")
    shutil.copyfile(source.campaign, target / source.campaign.name)
    journal = target / "evidence" / "journal.jsonl"
    journal.parent.mkdir()
    shutil.copyfile(source.journal, journal)
    certificate = target / "certificate.json"
    shutil.copyfile(source.certificate, certificate)
    return Source(
        target,
        target / source.campaign.name,
        journal,
        certificate,
        source.tools,
        source.verdict,
    )


def audit_config(root: Path, installed: t.Tools, **changes: Any) -> AuditConfig:
    """An audit with results and work below ``root`` and the given tool installation."""
    values: dict[str, Any] = {
        "results": root / "audit",
        "work": root / "audit-work",
        "worker": "auditor",
        "tools": ToolPaths(solver=str(installed.solver), checker=str(installed.checker)),
        "service_argv": SERVICE_COMMAND,
        "service_env": t.service_env(),
        "probes": t.FixedProbes(),
        "handle_signals": False,
        "survivor_wait_ms": 2000,
        "tick_ms": 5,
        "known_answer": False,  # scripted tools, as in cp_life_tools.config
    }
    values.update(changes)
    return AuditConfig(**values)


def request(
    source: Source,
    root: Path,
    *,
    sample: int | None = None,
    seed: str | None = None,
    comparison: str = "strict",
    **changes: Any,
) -> AuditRequest:
    """An audit of ``source`` (explicit campaign, certificate and journal)."""
    return AuditRequest(
        config=audit_config(root, source.tools, **changes),
        selection=Selection(sample, seed, AuditComparison(comparison)),
        campaign=source.campaign,
        certificate=source.certificate,
        journals=(source.journal,),
    )


def journal_records(results: Path) -> list[dict[str, Any]]:
    """The complete lines of the journal in ``results`` as JSON values."""
    found: list[dict[str, Any]] = t.journal_records(results)
    return found


def spawn_audit(
    source: Source,
    root: Path,
    crash: tuple[str, int] | None,
    *,
    action: str = "SIGKILL",
    **options: Any,
) -> subprocess.Popen[bytes]:
    """Run an audit of ``source`` in a child process that performs ``action`` at ``crash``
    (``cp_audit_runner``: SIGKILL by default, another signal or ``kill_io_service``)."""
    spec = {
        "campaign": str(source.campaign),
        "certificate": str(source.certificate),
        "journals": [str(source.journal)],
        "solver": str(source.tools.solver),
        "checker": str(source.tools.checker),
        "results": str(root / "audit"),
        "work": str(root / "audit-work"),
        "crash": None if crash is None else {"point": crash[0], "n": crash[1], "action": action},
        **options,
    }
    path = root / f"audit-spec-{os.urandom(4).hex()}.json"
    path.write_text(json.dumps(spec), encoding="utf-8")
    return subprocess.Popen(
        [sys.executable, str(RUNNER), str(path)],
        env=t.service_env(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
