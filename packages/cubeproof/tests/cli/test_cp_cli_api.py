"""Specification §12.1, §2.3: the API mirrors the commands, returns documents of exact JSON types,
and neither reads the environment, prints nor exits; commands contain no second scheduler; clean
child processes leave nothing behind.
"""

from __future__ import annotations

import ast
import inspect
import json
import os
import subprocess
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import cp_cli_support as c
import pytest

from cubeproof import api
from cubeproof.commands import (
    HandoffCommand,
    PackageRequest,
    RunOptions,
    ShardRequest,
    monitored,
)
from cubeproof.coordinator.run import Coordinator
from cubeproof.coordinator.status_format import validate_status

SRC = c.SRC / "cubeproof"
COMMANDS = SRC / "commands"

#: command -> API function (specification §12.1: the Python API mirrors the commands)
MIRROR = {
    ("bundle", "import"): "bundle_import",
    ("campaign", "create"): "campaign_create",
    ("shard",): "shard",
    ("run",): "run",
    ("handoff",): "handoff",
    ("status",): "status",
    ("certify",): "certify",
    ("evidence", "package"): "package",
    ("journal", "verify"): "journal_verify",
    ("journal", "repair"): "journal_repair",
    ("audit",): "audit",
    ("verify-retained",): "verify_retained",
}


def assert_json_types(value: Any, where: str = "$", floats: tuple[str, ...] = ()) -> None:
    """Only dict (string keys), list, str, int, bool and None; floats only where listed."""
    if value is None or isinstance(value, (bool, str)):
        return
    if isinstance(value, int):
        return
    if isinstance(value, float):
        assert any(where.endswith(f) or f in where for f in floats), f"{where}: float {value}"
        return
    if isinstance(value, dict):
        for key, item in value.items():
            assert isinstance(key, str), f"{where}: key {key!r}"
            assert_json_types(item, f"{where}.{key}", floats)
        return
    assert type(value) is list, f"{where}: {type(value).__name__}"
    for index, item in enumerate(value):
        assert_json_types(item, f"{where}[{index}]", floats)


def test_every_available_command_has_an_api_function() -> None:
    from cubeproof.cli import spec

    available = {cmd.words for cmd in spec.COMMANDS if cmd.available and not cmd.hidden}
    assert available == set(MIRROR)
    for name in MIRROR.values():
        assert callable(getattr(api, name)) and name in api.__all__
    assert api.exit_code_of is not None and api.verdict_exit_code is not None


def test_the_api_runs_the_whole_chain_and_returns_documents_of_exact_types(tmp_path: Path) -> None:
    source = tmp_path / "in.cnf"
    source.write_bytes(b"p cnf 3 8\n" + b"".join(
        f"{a} {b} {cc} 0\n".encode() for a in (1, -1) for b in (2, -2) for cc in (3, -3)
    ))  # fmt: skip
    imported = api.bundle_import(source, tmp_path / "bundles" / "f")
    assert imported.exit_code == 0
    assert_json_types(imported.to_json())
    tools = c.t.install(tmp_path / "tools", solver={"max_free": 3})
    shop = c.Shop(tmp_path, tools)
    from cubeproof.base.canonical_json import parse_document
    from cubeproof.commands import CampaignRequest
    from cubeproof.contracts.campaign import Admit
    from cubeproof.contracts.policy import Policy

    request = CampaignRequest(
        bundles=[tmp_path / "bundles" / "f"],
        policy=Policy.from_json(parse_document(shop.write_policy().read_bytes())),
        admit=Admit.from_json(parse_document(shop.write_admit().read_bytes()), "$"),
        solver=str(tools.solver),
        solver_argv=["--lrat"],
        checker=str(tools.checker),
        output=shop.campaign,
        author="api",
    )
    campaign = api.campaign_create(request)
    assert_json_types(campaign)
    assert campaign["author"] == "api" and campaign["root_splits"] == []
    config = c.t.config(tmp_path, shop.campaign, tools)
    result = api.run(config)
    assert result.exit_code == 0
    assert_json_types(result.to_json(), floats=("ticks",))
    status = api.status(shop.results)
    assert_json_types(status.document)
    assert validate_status(status.document) == status.document
    certificate = api.certify(shop.campaign, [shop.journal], tmp_path / "certificate.json")
    assert_json_types(certificate)
    assert certificate["verdict"] == "PROVED" and api.verdict_exit_code(certificate["verdict"]) == 0
    plan = api.shard(ShardRequest(shop.campaign, 2, tmp_path / "plan"))
    assert_json_types(plan.to_json())
    package = api.package(PackageRequest(shop.campaign, [shop.journal], tmp_path / "package"))
    assert_json_types(package.to_json())
    assert api.certify_evidence(Path(package.manifest)) == certificate
    verified = api.journal_verify(shop.journal, shop.campaign)
    assert_json_types(verified.to_json())
    repaired = api.journal_repair(shop.journal, shop.campaign)
    assert_json_types(repaired.to_json())
    # a worker with a desk: the handoff request is a document of exact types as well
    desk = c.t.config(tmp_path / "desk", shop.campaign, tools, worker="w2")
    served = api.run(desk, RunOptions(inbox=tmp_path / "inbox", outbox=tmp_path / "outbox"))
    assert_json_types(served.to_json(), floats=("ticks",))
    handed = api.handoff(HandoffCommand(tmp_path / "desk" / "results", 1, "o"))
    assert_json_types(handed.to_json())
    assert (handed.state.value, handed.exit_code) == ("pending", 0)


def test_the_api_reads_no_environment_prints_nothing_and_never_exits(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    shop = c.made(tmp_path / "origin", {"f": c.SHALLOW}, solver={"max_free": 3})
    assert api.run(c.t.config(shop.root, shop.campaign, shop.tools)).exit_code == 0

    class NoEnvironment(dict):  # type: ignore[type-arg]
        def __getitem__(self, key: str) -> str:
            raise AssertionError(f"the environment was read: {key}")

        def get(self, key: str, default: Any = None) -> Any:
            raise AssertionError(f"the environment was read: {key}")

        def __contains__(self, key: object) -> bool:
            raise AssertionError(f"the environment was read: {key}")

        def __iter__(self) -> Any:
            raise AssertionError("the environment was read")

        def copy(self) -> Any:
            raise AssertionError("the environment was read")

    monkeypatch.setattr(os, "environ", NoEnvironment())
    monkeypatch.setattr(
        os, "getenv", lambda *a, **k: (_ for _ in ()).throw(AssertionError("getenv"))
    )
    capsys.readouterr()
    other = tmp_path / "source.cnf"
    other.write_bytes(b"p cnf 2 1\n1 2 0\n")
    api.bundle_import(other, tmp_path / "imported")
    api.shard(ShardRequest(shop.campaign, 2, tmp_path / "plan"))
    api.certify(shop.campaign, [shop.journal])
    api.package(PackageRequest(shop.campaign, [shop.journal], tmp_path / "package"))
    api.certify_evidence(tmp_path / "package" / "evidence.json")
    api.journal_verify(shop.journal, shop.campaign)
    api.journal_repair(shop.journal, shop.campaign)
    api.status(shop.results)
    captured = capsys.readouterr()
    assert (captured.out, captured.err) == ("", "")


def test_a_failure_is_a_typed_error_with_an_exit_code_never_an_exit(tmp_path: Path) -> None:
    from cubeproof.base.errors import ConfigurationError, CubeproofError

    with pytest.raises(CubeproofError) as info:
        api.certify(tmp_path / "nope.json", [tmp_path / "j"])
    assert api.exit_code_of(info.value) == 3
    with pytest.raises(ConfigurationError):
        api.shard(ShardRequest(tmp_path / "c.json", 0, tmp_path / "o"))
    with pytest.raises(CubeproofError) as other:
        api.bundle_import(tmp_path / "nope.cnf", tmp_path / "b")
    assert api.exit_code_of(other.value) == 3


def test_an_api_run_with_a_log_sink_and_an_export(tmp_path: Path) -> None:
    shop = c.made(tmp_path, {"f": c.SHALLOW}, solver={"max_free": 3})
    lines: list[str] = []
    options = RunOptions(export=tmp_path / "export", log_sink=lines.append)
    result = api.run(c.t.config(tmp_path, shop.campaign, shop.tools), options)
    assert result.exit_code == 0
    assert any("progress" in line for line in lines) and any("export.ok" in line for line in lines)
    assert (tmp_path / "export" / "export.json").exists()
    assert (shop.results / "status.json").exists()
    with pytest.raises(Exception, match="log level"):
        RunOptions(log_level="loud")


# -- the commands contain no second scheduler -----------------------------------------------------


def imports_of(path: Path) -> set[str]:
    found: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            found.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            found.add(node.module)
            found.update(f"{node.module}.{a.name}" for a in node.names)
    return found


def test_no_command_imports_a_scheduler_or_decides_what_runs() -> None:
    forbidden = (
        "cubeproof.coordinator.scheduler",
        "cubeproof.coordinator.scheduler_select",
        "cubeproof.coordinator.scheduler_loop",
        "cubeproof.coordinator.ledger",
        "cubeproof.coordinator.resources",
        "cubeproof.leaf",
        "cubeproof.split.lookahead",
    )
    files = [*sorted(COMMANDS.glob("*.py")), *sorted((SRC / "cli").glob("*.py")), SRC / "api.py"]
    for path in files:
        imports = imports_of(path)
        for name in forbidden:
            assert not any(i == name or i.startswith(name + ".") for i in imports), (
                path.name,
                name,
            )


def test_the_monitor_wiring_overrides_only_the_points_it_needs() -> None:
    allowed = {
        "__init__",
        "_before_replay",
        "_begin_session",
        "_on_record",
        "_observe",
        "_final_sync_and_cache",
    }
    for cls in (
        monitored._MonitorMixin,
        monitored.MonitoredCoordinator,
        monitored.MonitoredDeskCoordinator,
    ):
        overridden = {
            name
            for name, member in vars(cls).items()
            if inspect.isfunction(member) and hasattr(Coordinator, name)
        }
        assert overridden <= allowed, (cls.__name__, overridden - allowed)
        assert "_plan" not in vars(cls) and "_loop" not in vars(cls) and "_advance" not in vars(cls)


# -- clean child processes ------------------------------------------------------------------------


def test_python_dash_m_cubeproof_works_from_a_bare_environment(tmp_path: Path) -> None:
    shop = c.made(tmp_path, {"f": c.SHALLOW}, solver={"max_free": 3})
    done = subprocess.run(
        [sys.executable, "-m", "cubeproof", *shop.run_args("--jobs", "2")],
        env={"PYTHONPATH": str(c.SRC)},  # no PATH, no HOME, no locale
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert done.returncode == 0, done.stderr
    assert json.loads(done.stdout.strip().splitlines()[-1])["reason"] == "complete"
    c.t.wait_clean(shop.results, tmp_path / "work-w1")  # no process of the run survives it
    assert c.t.lock_is_free(shop.results)
    assert [p.name for p in (tmp_path / "work-w1").iterdir()] == [".run.lock"]


def test_the_command_line_and_the_in_process_main_agree(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    source = tmp_path / "in.cnf"
    source.write_bytes(b"p cnf 2 2\n1 2 0\n-1 -2 0\n")
    child = c.command("bundle", "import", str(source), "-o", str(tmp_path / "one"))
    local = c.cli_main(["bundle", "import", str(source), "-o", str(tmp_path / "two")], capsys)
    assert child.code == local.code == 0
    one, two = c.last_json(child.out), c.last_json(local.out)
    for key in ("formula_sha256", "variables", "clauses", "source_sha256"):
        assert one[key] == two[key]
    assert (tmp_path / "one" / "formula.cnf").read_bytes() == (
        tmp_path / "two" / "formula.cnf"
    ).read_bytes()


def test_only_audit_takes_a_certificate_and_it_refuses_one_its_journals_do_not_reproduce(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A certificate is read only together with the journals it must be recomputed from:
    ``shard --from-open`` and ``audit``, whose certificate is bound to its exact
    journal prefixes and recomputed before any target is chosen."""
    from cubeproof.base.canonical_json import document_bytes
    from cubeproof.cli import spec

    takers = {
        command.name
        for command in spec.COMMANDS
        if command.available and any("--certificate" in a.flags for a in command.args)
    }
    assert takers == {"audit"}
    for name in ("shard", "audit"):
        assert any(a.flags == ("--journals",) for a in spec.find(name).args), name
    assert any(a.flags == ("--from-open",) for a in spec.find("shard").args)
    shop = c.made(tmp_path / "origin", {"f": c.SHALLOW}, solver={"max_free": 3})
    assert api.run(c.t.config(shop.root, shop.campaign, shop.tools)).exit_code == 0
    certificate = tmp_path / "certificate.json"
    document = api.certify(shop.campaign, [shop.journal], certificate)

    def audit(cert: Path, results: str) -> c.Done:
        return c.cli_main(
            [
                "audit", "--campaign", str(shop.campaign), "--certificate", str(cert),
                "--journals", str(shop.journal), "--all",
                "--results", str(tmp_path / results), "--work", str(tmp_path / f"{results}-work"),
                "--worker", "auditor",
                "--solver", str(shop.tools.solver), "--checker", str(shop.tools.checker),
            ],
            capsys,
        )  # fmt: skip

    done = audit(certificate, "audit")
    assert done.code == 0, done.err
    assert c.last_json(done.out)["summary"]["strict_success"] is True
    document["used_attempts"] = document["used_attempts"][1:]
    tampered = c.write(tmp_path / "tampered.json", document)
    assert tampered.read_bytes() == document_bytes(document)
    done = audit(tampered, "tampered")
    assert done.code == 4 and "[audit.certificate]" in done.err, done.err
    assert done.out == ""
    assert not (tmp_path / "tampered" / "journal.jsonl").exists()


def test_audit_and_verify_retained_return_documents_of_exact_types(tmp_path: Path) -> None:
    from cubeproof.base.settings import ToolPaths
    from cubeproof.contracts.enums import AuditComparison

    shop = c.made(tmp_path / "origin", {"f": c.SHALLOW}, solver={"max_free": 3})
    config = c.t.config(shop.root, shop.campaign, shop.tools, proof_mode="retain")
    assert api.run(config).exit_code == 0
    certificate = tmp_path / "certificate.json"
    api.certify(shop.campaign, [shop.journal], certificate)
    audit_config = api.AuditConfig(
        results=tmp_path / "audit",
        work=tmp_path / "audit-work",
        worker="auditor",
        tools=ToolPaths(solver=str(shop.tools.solver), checker=str(shop.tools.checker)),
        service_env=c.t.service_env(),
        probes=c.t.FixedProbes(),
        handle_signals=False,
    )
    selection = api.Selection(1, "0" * 64, AuditComparison.STRICT)
    outcome = api.audit(
        api.AuditRequest(
            audit_config,
            selection,
            campaign=shop.campaign,
            certificate=certificate,
            journals=(shop.journal,),
        )
    )
    assert outcome.exit_code == 0 and outcome.report is not None
    assert_json_types(outcome.to_json())
    assert_json_types(outcome.report.document)
    assert outcome.report.document["selected"] == 1
    verified = api.verify_retained(
        api.VerifyRequest(
            proofs_root=shop.results,
            results=tmp_path / "verify",
            work=tmp_path / "verify-work",
            worker="verifier",
            checker=str(shop.tools.checker),
            campaign=shop.campaign,
            journals=(shop.journal,),
        )
    )
    assert verified.exit_code == 0 and verified.document["verified"] > 0
    assert_json_types(verified.to_json())
    assert_json_types(verified.document)


def hash_of(mapping: Mapping[str, Any]) -> str:
    return json.dumps(mapping, sort_keys=True)
