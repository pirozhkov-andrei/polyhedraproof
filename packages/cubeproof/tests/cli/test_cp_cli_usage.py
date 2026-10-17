"""Specification §12.1, §12.2: invalid option combinations are usage errors (exit 3) before any
work.

Each case is one of the rules of the command table: exclusive alternatives, required
combinations, malformed values. The checks run in this process (the same parser, handlers and
exit mapping as ``python -m cubeproof``); none of them may create a file.
"""

from __future__ import annotations

import shlex
from pathlib import Path

import cp_cli_support as c
import pytest

import cubeproof

RUN = "run --results r --work w --worker w1 --solver s --checker k"
CREATE = "campaign create --bundle b --policy p --admit a --solver s --checker k -o campaign.json"
SHARD = "shard --machines 2 -o out"
HANDOFF = "handoff --results r --nodes 1 --output-name o"
AUDIT = "audit --results r --work w --worker a --solver s --checker k"
AUDIT_INPUTS = "--campaign c --certificate x --journals j"
VERIFY = "verify-retained --proofs-root p --results r --work w --worker v --checker k"

USAGE_CASES: dict[str, tuple[str, str]] = {
    "no command": ("", "usage"),
    "unknown command": ("frobnicate", "usage"),
    "unknown action": ("campaign frobnicate", "usage"),
    "missing action": ("journal", "usage"),
    "abbreviated option": ("status --res x", "usage"),
    "unknown option": ("status --results x --nope", "usage"),
    "run without anything": ("run", "usage"),
    "run without worker": ("run --campaign c --results r --work w --solver s --checker k", "usage"),
    "run, neither campaign nor evidence": (RUN, "usage"),
    "run, campaign and evidence": (f"{RUN} --campaign c --evidence e", "usage"),
    "run, verbose and quiet": (f"{RUN} --campaign c -v -q", "usage"),
    "run, a jobs count that is not a number": (f"{RUN} --campaign c --jobs many", "usage"),
    "run, a proof mode that is not one": (f"{RUN} --campaign c --proof-mode nope", "usage"),
    "shard, no campaign": (SHARD, "usage"),
    "shard, evidence and campaign": (f"{SHARD} --evidence e --campaign c", "usage"),
    "shard, evidence and journals": (f"{SHARD} --evidence e --journals j", "usage"),
    "shard, evidence and from-open": (f"{SHARD} --evidence e --from-open x", "usage"),
    "shard, from-open without journals": (f"{SHARD} --campaign c --from-open x", "usage"),
    "shard, journals without from-open": (f"{SHARD} --campaign c --journals j", "usage"),
    "shard, scope without from-open": (f"{SHARD} --campaign c --scope formulas", "usage"),
    "shard, explicit campaign scope without from-open": (
        f"{SHARD} --campaign c --scope campaign",
        "usage",
    ),
    "shard, an unknown scope": (
        f"{SHARD} --campaign c --from-open x --journals j --scope all",
        "usage",
    ),
    "shard, zero machines": ("shard --campaign c --machines 0 -o out", "shard.machines"),
    "shard, machines that is not a number": ("shard --campaign c --machines two -o o", "usage"),
    "certify, nothing": ("certify", "usage"),
    "certify, campaign without journals": ("certify --campaign c", "usage"),
    "certify, journals without campaign": ("certify --journals j", "usage"),
    "certify, evidence and campaign": ("certify --evidence e --campaign c", "usage"),
    "certify, evidence and journals": ("certify --evidence e --journals j", "usage"),
    "campaign create, nothing": ("campaign create", "usage"),
    "campaign create, a solver argv that is not json": (f"{CREATE} --solver-argv --lrat", "usage"),
    "campaign create, a solver argv of numbers": (f"{CREATE} --solver-argv '[1]'", "usage"),
    "campaign create, a root split that is nothing": (
        (f"{CREATE} --solver-argv '[]' --root-split frob"),
        "campaign.root_split",
    ),
    "handoff, zero nodes": ("handoff --results r --nodes 0 --output-name o", "handoff.nodes"),
    "handoff, a bad output name": (
        "handoff --results r --nodes 1 --output-name 'A b'",
        "handoff.output_name",
    ),
    "handoff, a negative wait": (f"{HANDOFF} --wait-ms -1", "handoff.wait_ms"),
    "journal verify, no campaign": ("journal verify j", "usage"),
    "journal repair, no journal": ("journal repair --campaign c", "usage"),
    "bundle import, no output": ("bundle import in.cnf", "usage"),
    "evidence package, no journals": ("evidence package --campaign c -o o", "usage"),
    "audit, no results": ("audit --all", "usage"),
    "audit, no solver": ("audit --results r --work w --worker a --checker k --all", "usage"),
    "audit, sample and all": (f"{AUDIT} {AUDIT_INPUTS} --sample 1 --all", "usage"),
    "audit, neither sample nor all": (f"{AUDIT} {AUDIT_INPUTS}", "usage"),
    "audit, a zero sample": (f"{AUDIT} {AUDIT_INPUTS} --sample 0", "usage"),
    "audit, a sample that is not a number": (f"{AUDIT} {AUDIT_INPUTS} --sample few", "usage"),
    "audit, a seed that is not 64 hex digits": (f"{AUDIT} {AUDIT_INPUTS} --all --seed ab", "usage"),
    "audit, an unknown comparison": (f"{AUDIT} {AUDIT_INPUTS} --all --comparison loose", "usage"),
    "audit, nothing to audit": (f"{AUDIT} --all", "usage"),
    "audit, evidence and campaign": (f"{AUDIT} --all --evidence e --campaign c", "usage"),
    "audit, evidence and certificate": (f"{AUDIT} --all --evidence e --certificate x", "usage"),
    "audit, evidence and journals": (f"{AUDIT} --all --evidence e --journals j", "usage"),
    "audit, campaign without certificate": (f"{AUDIT} --all --campaign c --journals j", "usage"),
    "audit, certificate without journals": (f"{AUDIT} --all --campaign c --certificate x", "usage"),
    "audit, a bad worker name": (
        f"{AUDIT} {AUDIT_INPUTS} --all --worker 'A b'",
        "audit.worker",
    ),
    "audit, a size that is not one": (f"{AUDIT} {AUDIT_INPUTS} --all --memory lots", "run.size"),
    "audit, a proof cap that is not one": (
        f"{AUDIT} {AUDIT_INPUTS} --all --proof-cap 0",
        "run.size",
    ),
    "verify-retained, no worker": ("verify-retained --results r", "usage"),
    "verify-retained, no checker": (
        "verify-retained --proofs-root p --results r --work w --worker v --campaign c",
        "usage",
    ),
    "verify-retained, neither campaign nor evidence": (VERIFY, "usage"),
    "verify-retained, evidence and campaign": (f"{VERIFY} --evidence e --campaign c", "usage"),
    "verify-retained, campaign without journals": (f"{VERIFY} --campaign c", "usage"),
    "verify-retained, a bad worker name": (
        f"{VERIFY} --campaign c --journals j --worker 'A b'",
        "usage",
    ),
}


@pytest.mark.parametrize("name", sorted(USAGE_CASES))
def test_an_invalid_combination_is_a_usage_error(
    name: str, tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    line, rule = USAGE_CASES[name]
    done = c.cli_main(shlex.split(line), capsys)
    assert done.code == 3, (done.out, done.err)
    assert f"cubeproof: error [{rule}]" in done.err, done.err
    assert done.out == ""
    assert list(tmp_path.iterdir()) == []  # nothing created before the failure


@pytest.mark.parametrize(
    "line",
    [
        f"{AUDIT} {AUDIT_INPUTS} --all",
        f"{AUDIT} --evidence e --sample 3 --seed {'0' * 64} --comparison reprove",
        f"{VERIFY} --campaign c --journals j",
        f"{VERIFY} --evidence e --memory 64MiB",
    ],
)
def test_audit_and_verify_retained_are_available_and_reach_their_inputs(
    line: str,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A valid command line is not refused as unavailable or as usage: it reaches the inputs
    (here missing files: an input error, exit 3) and has created nothing before that."""
    monkeypatch.chdir(tmp_path)
    done = c.cli_main(shlex.split(line), capsys)
    assert done.code == 3, (done.out, done.err)
    assert "command.unavailable" not in done.err and "error [usage]" not in done.err, done.err
    assert done.out == ""
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize(
    "words",
    [[], ["run"], ["campaign", "create"], ["journal", "repair"], ["audit"], ["verify-retained"]],
)
def test_help_exits_zero_and_prints_the_usage(
    words: list[str], capsys: pytest.CaptureFixture[str]
) -> None:
    done = c.cli_main([*words, "-h"], capsys)
    assert done.code == 0
    assert done.out.startswith("usage: cubeproof")
    assert done.err == ""


def test_the_top_level_help_lists_the_commands_and_hides_the_service(
    capsys: pytest.CaptureFixture[str],
) -> None:
    done = c.cli_main(["-h"], capsys)
    names = "bundle campaign shard run handoff status certify evidence journal audit"
    names += " verify-retained"
    for name in names.split():
        assert name in done.out
    assert "io-service" not in done.out
    assert "internal" not in done.out


def test_version_prints_the_program_and_its_version_and_exits_zero(
    capsys: pytest.CaptureFixture[str],
) -> None:
    done = c.cli_main(["--version"], capsys)
    assert (done.code, done.out, done.err) == (0, f"cubeproof {cubeproof.__version__}\n", "")
    child = c.command("--version")  # ``python -m cubeproof --version``
    assert (child.code, child.out, child.err) == (0, f"cubeproof {cubeproof.__version__}\n", "")
    assert "--version" in c.cli_main(["-h"], capsys).out
    # an option of the program, not of a command
    assert c.cli_main(["status", "--version"], capsys).code == 3


def test_the_hidden_service_command_refuses_bad_arguments_and_prints_nothing_else(
    tmp_path: Path,
) -> None:
    done = c.command(
        *["io-service", "--results", str(tmp_path), "--work", str(tmp_path / "w")],
        *["--journal", str(tmp_path / "j"), "--lock", str(tmp_path / "l"), "--lock-fd", "99"],
        *["--campaign", "0" * 64, "--variables", "not json"],
    )
    assert done.code == 3 and "io.service_args" in done.err
    assert done.out == ""
