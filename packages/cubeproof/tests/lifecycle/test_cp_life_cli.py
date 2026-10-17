"""Specification §12.1, §12.2: the command line and API of a run: exit codes and messages.

The command line is exercised both in-process (``cubeproof.cli.main``: exit codes and messages)
and as ``python -m cubeproof`` in child processes (the real entry point, the arguments the
coordinator passes to its I/O service, and the exit status of the process).
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import cp_life_tools as t
import pytest

from cubeproof import api, cli
from cubeproof.base.canonical_json import document_bytes, parse_document
from cubeproof.base.errors import ConfigurationError
from cubeproof.cnf.bundle import publish_bundle
from cubeproof.commands import parse_policy_overrides, parse_size
from cubeproof.contracts.campaign import Admit
from cubeproof.tools.isolation import PinnedBinary


def command(*args: str, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "cubeproof", *args],
        env=t.service_env(),
        capture_output=True,
        text=True,
        cwd=cwd,
        timeout=180,
        check=False,
    )


def prepare(root: Path, formula: bytes, *, solver: dict[str, int] | None = None) -> dict[str, str]:
    """Bundle, policy and admit files and the arguments of ``campaign create`` and ``run``."""
    tools = t.install(root / "tools", solver=solver or {"max_free": 3})
    publish_bundle(
        root / "bundles" / "f",
        formula,
        pools={},
        producer={"name": "cli-test", "version": "1", "parameters": {}},
    )
    (root / "policy.json").write_bytes(document_bytes(t.split_policy().to_json()))
    checker = PinnedBinary.measure(str(tools.checker)).sha256
    admit = Admit.from_json({"checker_sha256": [checker], "solvers": None}, "$")
    (root / "admit.json").write_bytes(document_bytes(admit.to_json()))
    return {"solver": str(tools.solver), "checker": str(tools.checker)}


def create_args(root: Path, tools: dict[str, str]) -> list[str]:
    return [
        "campaign",
        "create",
        "--bundle",
        str(root / "bundles" / "f"),
        "--policy",
        str(root / "policy.json"),
        "--admit",
        str(root / "admit.json"),
        "--solver",
        tools["solver"],
        "--solver-argv",
        '["--lrat"]',
        "--checker",
        tools["checker"],
        "-o",
        str(root / "campaign.json"),
    ]


def run_args(root: Path, tools: dict[str, str], *more: str) -> list[str]:
    return [
        "run",
        "--campaign",
        str(root / "campaign.json"),
        "--results",
        str(root / "results"),
        "--work",
        str(root / "work"),
        "--worker",
        "w1",
        "--solver",
        tools["solver"],
        "--checker",
        tools["checker"],
        *more,
    ]


def test_create_run_and_certify_as_commands(tmp_path: Path) -> None:
    tools = prepare(tmp_path, t.unsat(8, core=5))
    created = command(*create_args(tmp_path, tools))
    assert created.returncode == 0, created.stderr
    assert (tmp_path / "campaign.json").exists()
    ran = command(*run_args(tmp_path, tools, "--jobs", "2"))
    assert ran.returncode == 0, ran.stderr
    document = json.loads(ran.stdout.strip().splitlines()[-1])
    assert document["exit_code"] == 0 and document["reason"] == "complete"
    assert document["open"] == {} and document["session"]["outcome:VERIFIED_UNSAT"] == 16
    out = tmp_path / "certificate.json"
    journal = tmp_path / "results" / "journal.jsonl"
    certified = command(
        "certify", "--campaign", str(tmp_path / "campaign.json"), "--journals", str(journal),
        "-o", str(out),
    )  # fmt: skip
    assert certified.returncode == 0, certified.stderr
    assert certified.stdout.startswith("PROVED")
    assert parse_document(out.read_bytes())["verdict"] == "PROVED"
    # a certificate is never silently replaced
    again = command(
        "certify", "--campaign", str(tmp_path / "campaign.json"), "--journals", str(journal),
        "-o", str(out),
    )  # fmt: skip
    assert again.returncode == 3 and "campaign.exists" in again.stderr
    # the same directories again: a resume that has nothing to do
    resumed = command(*run_args(tmp_path, tools))
    assert resumed.returncode == 0
    assert json.loads(resumed.stdout)["session"] == {"resume": 1}


def test_a_model_exits_two_in_run_and_in_certify(tmp_path: Path) -> None:
    tools = prepare(tmp_path, t.sat(5), solver={})
    assert command(*create_args(tmp_path, tools)).returncode == 0
    ran = command(*run_args(tmp_path, tools))
    assert ran.returncode == 2, ran.stderr
    journal = tmp_path / "results" / "journal.jsonl"
    certified = command(
        "certify", "--campaign", str(tmp_path / "campaign.json"), "--journals", str(journal)
    )
    assert certified.returncode == 2 and certified.stdout.startswith("MODEL_FOUND")


@pytest.mark.parametrize(
    "arguments",
    [
        [],
        ["frobnicate"],
        ["run"],
        ["campaign"],
        ["campaign", "create"],
        ["certify", "--campaign", "x"],
    ],
)
def test_usage_errors_exit_three(arguments: list[str]) -> None:
    result = command(*arguments)
    assert result.returncode == 3
    assert "cubeproof: error [usage]" in result.stderr


def test_the_errors_of_the_layers_below_are_reported_with_their_rule_and_exit_code(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    tools = prepare(tmp_path, t.unsat(5))
    assert cli.main(create_args(tmp_path, tools)) == 0
    capsys.readouterr()
    code = cli.main(run_args(tmp_path, tools, "--policy-override", "no_such=1"))
    assert code == 3
    assert "cubeproof: error [run.policy_override]" in capsys.readouterr().err
    assert cli.main(run_args(tmp_path, tools, "--memory", "12x")) == 3
    assert cli.main(run_args(tmp_path, tools, "--proof-mode", "nope")) == 3
    # a stream task on fewer slots than solver + relay + checker: preflight, exit 1 (specification
    # §8.2)
    stream = run_args(tmp_path, tools, "--proof-mode", "stream", "--jobs", "2")
    assert cli.main(stream) == 1
    assert "cubeproof: error [resources.preflight]" in capsys.readouterr().err
    # a campaign file that is not there
    missing = run_args(tmp_path, tools)
    missing[missing.index("--campaign") + 1] = str(tmp_path / "nope.json")
    assert cli.main(missing) == 3
    assert "campaign.file" in capsys.readouterr().err
    # a tool that is not the pinned one
    other = tmp_path / "other"
    other.write_text("#!/bin/sh\nexit 0\n")
    other.chmod(0o755)
    changed = run_args(tmp_path, {**tools, "checker": str(other)})
    assert cli.main(changed) == 5
    assert "tool.hash_mismatch" in capsys.readouterr().err
    assert not (tmp_path / "results" / "journal.jsonl").exists()


def retained_files(root: Path) -> dict[str, bytes]:
    proofs = root / "results" / "proofs"
    return {p.name: p.read_bytes() for p in proofs.iterdir() if p.is_file()}


def test_a_retain_run_and_its_damaged_artifacts_through_the_command_line(tmp_path: Path) -> None:
    """Specification §7.2, §12.2: ``cubeproof run --proof-mode retain`` publishes every verified
    proof under its checked hash; a later run (in any mode) validates every committed reference
    first: a missing or corrupt retained proof stops it with exit 4 before anything is removed or
    appended, never a silent conversion to transient."""
    tools = prepare(tmp_path, t.unsat(5))
    assert command(*create_args(tmp_path, tools)).returncode == 0
    ran = command(*run_args(tmp_path, tools, "--proof-mode", "retain"))
    assert ran.returncode == 0, ran.stderr
    verified = [a for a in t.attempts(tmp_path / "results") if a["outcome"] == "VERIFIED_UNSAT"]
    files = retained_files(tmp_path)
    assert verified and sorted(files) == sorted(
        a["retained"]["path"].split("/", 1)[1] for a in verified
    )
    for record in verified:
        data = files[record["retained"]["path"].split("/", 1)[1]]
        assert hashlib.sha256(data).hexdigest() == record["proof_sha256"]
        assert len(data) == record["proof_bytes"]
    journal = tmp_path / "results" / "journal.jsonl"
    before = journal.read_bytes()
    orphan = tmp_path / "results" / "proofs" / ("ab" * 32 + "-" + "cd" * 32 + ".lrat")
    orphan.write_bytes(b"not referenced\n")
    victim = tmp_path / "results" / "proofs" / sorted(files)[0]
    original = victim.read_bytes()
    victim.chmod(0o644)
    victim.unlink()
    for mode in (("--proof-mode", "retain"), ()):
        failed = command(*run_args(tmp_path, tools, *mode))
        assert failed.returncode == 4, failed.stderr
        assert "artifact.missing" in failed.stderr
    victim.write_bytes(bytes([original[0] ^ 1]) + original[1:])  # same size, other bytes
    failed = command(*run_args(tmp_path, tools))
    assert failed.returncode == 4 and "artifact.corrupt" in failed.stderr
    assert journal.read_bytes() == before  # nothing appended, not even a resume
    assert orphan.exists()  # nothing removed while a reference is broken
    victim.write_bytes(original)
    resumed = command(*run_args(tmp_path, tools, "--proof-mode", "retain"))
    assert resumed.returncode == 0, resumed.stderr
    assert not orphan.exists()  # the orphan goes once every reference is intact
    assert retained_files(tmp_path) == files


def test_the_hidden_service_command_refuses_bad_arguments(tmp_path: Path) -> None:
    result = command(
        "io-service", "--results", str(tmp_path), "--work", str(tmp_path / "w"), "--journal",
        str(tmp_path / "j"), "--lock", str(tmp_path / "l"), "--lock-fd", "99",
        "--campaign", "0" * 64, "--variables", "not json",
    )  # fmt: skip
    assert result.returncode == 3 and "io.service_args" in result.stderr
    assert result.stdout == ""  # standard output carries only the job protocol


def test_the_api_mirrors_the_commands(tmp_path: Path) -> None:
    w = t.make_world(tmp_path, {"f": t.unsat(5)}, solver={"max_free": 3})
    result = api.run(w.config())
    assert result.exit_code == 0 and result.to_json()["reason"] == "complete"
    certificate = api.certify(w.campaign, [w.journal()], tmp_path / "cert.json")
    assert certificate["verdict"] == "PROVED"
    assert parse_document((tmp_path / "cert.json").read_bytes()) == certificate
    assert api.exit_code_of(ConfigurationError("x")) == 3


def test_sizes_and_policy_overrides_parse() -> None:
    assert parse_size("512") == 512
    assert parse_size("64MiB") == 64 << 20
    assert parse_size("2G") == 2 << 30
    assert parse_size("1gb") == 1 << 30
    assert parse_size(" 3KiB ") == 3 << 10
    for bad in ("", "0", "-1", "1.5G", "G", "12x", "1 2", "3 KiB"):
        with pytest.raises(ConfigurationError):
            parse_size(bad)
    assert parse_policy_overrides(["split.vars=3", 'proof_mode="transient"', "a=null"]) == {
        "split.vars": 3,
        "proof_mode": "transient",
        "a": None,
    }
    for bad in ("novalue", "=1", "k=not json", "k={"):
        with pytest.raises(ConfigurationError):
            parse_policy_overrides([bad])
