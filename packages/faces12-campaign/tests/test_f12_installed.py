"""The installed application outside the checkout (slow).

The three wheels are built from copies of the packages, installed with ``--no-index`` into a
fresh virtual environment, and the command line runs in a directory outside the checkout:
``selftest``, ``formulas`` (write and check maps 1 and 2), ``campaign init`` with prefix 0 and
``release provenance``. Every module comes from the environment, none from the checkout.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

PACKAGE = Path(__file__).resolve().parents[1]
REPO = PACKAGE.parents[1]
SCRUB = ("PYTHONPATH", "PYTHONHOME", "VIRTUAL_ENV", "PIP_CONSTRAINT")


def clean_env() -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if k not in SCRUB}
    env["PIP_DISABLE_PIP_VERSION_CHECK"] = "1"
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return env


def run(command: list[str | Path], cwd: Path, expect: int = 0) -> str:
    result = subprocess.run(
        [str(c) for c in command], cwd=cwd, env=clean_env(), capture_output=True, text=True,
        check=False, timeout=900,
    )  # fmt: skip
    if result.returncode != expect:
        shown = " ".join(map(str, command))
        raise AssertionError(f"{shown} -> {result.returncode}\n{result.stdout}\n{result.stderr}")
    return result.stdout


def new_venv(path: Path) -> Path:
    run([sys.executable, "-m", "venv", path], cwd=path.parent)
    scripts = path / ("Scripts" if os.name == "nt" else "bin")
    return scripts / ("python.exe" if os.name == "nt" else "python")


@pytest.mark.slow
def test_the_installed_application_runs_outside_the_checkout(tmp_path: Path) -> None:
    assert REPO not in tmp_path.parents
    builder = new_venv(tmp_path / "build-env")
    constraints = REPO / "constraints" / "dev.txt"
    run([builder, "-m", "pip", "install", "-q", "-c", constraints, "setuptools", "build"], tmp_path)
    dist = tmp_path / "dist"
    ignore = shutil.ignore_patterns("build", "*.egg-info", "__pycache__", ".pytest_cache")
    for name in ("cubeproof", "neighbourly", "faces12-campaign"):
        source = tmp_path / "src" / name
        shutil.copytree(REPO / "packages" / name, source, ignore=ignore)
        run(
            [builder, "-m", "build", "--wheel", "--no-isolation", "--outdir", dist, source],
            tmp_path,
        )
    python = new_venv(tmp_path / "venv")
    run(
        [python, "-m", "pip", "install", "--no-index", "--find-links", dist, "faces12-campaign"],
        tmp_path,
    )

    work = tmp_path / "work"
    work.mkdir()
    app: list[str | Path] = [python, "-m", "faces12_campaign"]
    assert "checks hold" in run([*app, "selftest"], work)
    formulas = work / "formulas"
    run([*app, "formulas", "-o", formulas, "--maps", "1,2"], work)
    checked = json.loads(run([*app, "formulas", "-o", formulas, "--check", "--maps", "1,2"], work))
    assert [e["status"] for e in checked["formulas"]] == ["verified", "verified"]
    for name in ("cadical", "cake_lpr"):
        tool = work / name
        tool.write_text(f"#!/bin/sh\n# {name}\nexit 1\n")
        tool.chmod(0o755)
    init: list[str | Path] = [
        *app, "campaign", "init", "--formulas", formulas, "--maps", "1,2", "--prefix", "0",
        "--solver", work / "cadical", "--solver-argv", '["--lrat"]', "--checker",
        work / "cake_lpr", "--author", "installed test", "--unpinned-checker",
        "-o", work / "campaign.json",
    ]  # fmt: skip
    made = json.loads(run(init, work))
    assert [f["key"] for f in made["formulas"]] == ["map01", "map02"]
    provenance = json.loads(run([*app, "release", "provenance"], work))
    assert set(provenance["packages"]) == {"cubeproof", "neighbourly", "faces12-campaign"}
    where = run([python, "-c", "import faces12_campaign, cubeproof, neighbourly as n; "
                 "print(faces12_campaign.__file__); print(cubeproof.__file__); print(n.__file__)"],
                work)  # fmt: skip
    prefix = (tmp_path / "venv").resolve()
    for line in where.split():
        location = Path(line).resolve()
        assert prefix in location.parents and REPO not in location.parents, location
