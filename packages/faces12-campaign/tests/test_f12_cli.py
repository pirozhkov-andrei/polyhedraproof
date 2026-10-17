"""The command line: usage, delegation to cubeproof, exit codes, a clean child process."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
from f12_support import REPO, World, make_world

from faces12_campaign import cli, commands
from neighbourly import corpus12

SRC = [
    REPO / "packages" / name / "src" for name in ("cubeproof", "neighbourly", "faces12-campaign")
]


def child(*args: str) -> subprocess.CompletedProcess[str]:
    """``python -m faces12_campaign ARGS`` with a minimal environment."""
    env = {"PYTHONPATH": os.pathsep.join(str(s) for s in SRC), "PATH": "/usr/bin:/bin"}
    return subprocess.run(
        [sys.executable, "-m", "faces12_campaign", *args],
        env=env, capture_output=True, text=True, timeout=300, check=False,
    )  # fmt: skip


def last_json(text: str) -> Any:
    return json.loads(text.strip().splitlines()[-1])


def test_help_version_and_usage_errors(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["--help"]) == 0
    assert "claim" in capsys.readouterr().out
    assert cli.main(["--version"]) == 0
    assert cli.main([]) == 3
    assert cli.main(["prove-everything"]) == 3
    assert cli.main(["formulas", "--chec"]) == 3  # no abbreviations
    assert cli.main(["formulas"]) == 3
    assert cli.main(["formulas", "--check", "--maps", "0"]) == 3
    assert cli.main(["campaign"]) == 3
    assert cli.main(["selftest", "--maps", "x"]) == 3


def test_the_cubeproof_commands_are_handed_over(capsys: pytest.CaptureFixture[str]) -> None:
    for name in cli.DELEGATED:
        assert cli.main([name, "--help"]) == 0
        assert f"usage: cubeproof {name}" in capsys.readouterr().out
    assert cli.main(["status", "--results", "/nonexistent/results"]) != 0
    assert "cubeproof: error" in capsys.readouterr().err


@pytest.fixture(scope="module")
def world(tmp_path_factory: pytest.TempPathFactory) -> World:
    found = make_world(tmp_path_factory.mktemp("cli"), [1, 2])
    found.init(prefix=0)
    return found


def test_certify_is_cubeproof_certify(world: World, capsys: pytest.CaptureFixture[str]) -> None:
    journal = world.proved_journal()
    out = world.root / "certificate.json"
    args = [
        "certify",
        "--campaign",
        str(world.campaign),
        "--journals",
        str(journal),
        "-o",
        str(out),
    ]
    assert cli.main(args) == 0
    assert json.loads(out.read_text())["verdict"] == "PROVED"
    capsys.readouterr()
    partial = world.proved_journal(["map01"], worker="w2")
    assert cli.main(["certify", "--campaign", str(world.campaign), "--journals", str(partial)]) == 1


def test_formulas_and_campaign_init_from_the_command_line(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    world = make_world(tmp_path, [1])
    capsys.readouterr()
    assert cli.main(["formulas", "-o", str(world.bundles), "--maps", "1"]) == 0
    assert last_json(capsys.readouterr().out)["formulas"][0]["status"] == "present"
    assert cli.main(["formulas", "-o", str(world.bundles), "--maps", "1", "--check"]) == 0
    capsys.readouterr()
    base = [
        "campaign", "init", "--formulas", str(world.bundles), "--maps", "1",
        "--solver", str(world.tools.solver), "--checker", str(world.tools.checker),
        "--author", "cli test", "--unpinned-checker",
    ]  # fmt: skip
    output = tmp_path / "campaign.json"
    assert cli.main([*base, "--solver-argv", "--lrat", "-o", str(output)]) == 3
    # the stand-in checker of these tests is not the release cake_lpr: refused without the flag
    capsys.readouterr()
    pinned = [a for a in base if a != "--unpinned-checker"]
    refused = cli.main([*pinned, "--solver-argv", '["--lrat"]', "-o", str(output), "--prefix", "0"])
    assert refused == 3 and "[campaign.checker]" in capsys.readouterr().err
    assert not output.exists()
    assert cli.main([*base, "--solver-argv", '["--lrat"]', "-o", str(output), "--prefix", "0"]) == 0
    result = last_json(capsys.readouterr().out)
    assert result["root_split"] == "none" and result["root_splits"] == 0
    assert result["formulas"] == [
        {"key": "map01", "formula_sha256": corpus12.formula_hashes()[1].sha256}
    ]
    assert cli.main([*base, "--solver-argv", '["--lrat"]', "-o", str(output), "--prefix", "0"]) == 3
    assert "campaign.exists" in capsys.readouterr().err


def test_selftest_and_maps(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli.main(["selftest"]) == 0
    assert "checks hold" in capsys.readouterr().out
    monkeypatch.setattr(commands, "census", lambda: (True, {"format": "faces12-enumeration-1"}))
    out = tmp_path / "maps.json"
    assert cli.main(["maps", "-o", str(out)]) == 0
    assert json.loads(out.read_text()) == {"format": "faces12-enumeration-1"}
    monkeypatch.setattr(commands, "census", lambda: (False, {"format": "faces12-enumeration-1"}))
    assert cli.main(["maps"]) == 4


def test_a_clean_child_process(tmp_path: Path) -> None:
    done = child("formulas", "--check", "--maps", "2")
    assert done.returncode == 0, done.stderr
    assert last_json(done.stdout)["formulas"][0]["formula_sha256"] == (
        corpus12.formula_hashes()[2].sha256
    )
    assert child("status", "--help").returncode == 0
    assert child("claim").returncode == 3


def test_errors_are_typed_and_exits_are_mapped(tmp_path: Path, capsys: Any) -> None:
    assert cli.main(["formulas", "-o", str(tmp_path / "none"), "--check", "--maps", "1"]) == 3
    assert "formulas.directory" in capsys.readouterr().err
    (tmp_path / "empty").mkdir()
    assert cli.main(["formulas", "-o", str(tmp_path / "empty"), "--check", "--maps", "1"]) == 4
    assert "formulas.bundle" in capsys.readouterr().err
    assert cli.main(["campaign", "prefixes", "--campaign", str(tmp_path / "x"), "-o", "y"]) == 3
