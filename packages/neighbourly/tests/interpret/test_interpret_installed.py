"""Installed-data round trip of the n = 15/16 fixtures, interpretation and checks (slow).

The wheel is built from a copy of
``packages/neighbourly`` outside the checkout, installed alone with ``--no-index`` into a
fresh virtual environment, and a script run outside the checkout: reads the stored n = 15/16
maps through ``importlib.resources``, checks them against their recorded hashes, produces and
publishes each map's bundle, reads it back with a map loaded independently from the installed
data, compares the formula hash with the recorded one, runs the fixed-seed per-face controls,
and reproduces the golden model description of map 1.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

PACKAGE = Path(__file__).resolve().parents[2]
REPO = PACKAGE.parents[1]
SCRUB = ("PYTHONPATH", "PYTHONHOME", "VIRTUAL_ENV", "PIP_CONSTRAINT")
MODEL_DESCRIPTION_SHA256 = "4689bfd8bba3d87b8a36f8b38b7b5d900f8f4f2f8d0670534afd2f1e7dc41dfc"

CHECK = """
import hashlib, json, sys, tempfile
from pathlib import Path
import neighbourly
from neighbourly import corpus12
from neighbourly.checks import per_face_check, random_planes
from neighbourly.cnf import publish_bundle
from neighbourly.data import read_bytes, resource
from neighbourly.interpret import describe_model, formula_bundle, read_bundle
from neighbourly.maps import CombinatorialMap

def J(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()

found = {"prefix": sys.prefix, "files": [neighbourly.__file__], "sizes": {}}
with tempfile.TemporaryDirectory() as work:
    for n in (15, 16):
        raw = read_bytes("fixtures", f"n{n}", f"n{n}.txt")
        doc = json.loads(read_bytes("fixtures", f"n{n}", f"n{n}.json"))
        found["files"].append(str(resource("fixtures", f"n{n}", f"n{n}.txt")))
        cmap = CombinatorialMap.from_text(raw.decode("utf-8"))
        target = publish_bundle(Path(work) / f"n{n}", formula_bundle(cmap, map_name=f"n{n}").files)
        trusted = CombinatorialMap.from_text(read_bytes("fixtures", f"n{n}", f"n{n}.txt").decode())
        verified = read_bundle(target, trusted)
        found["sizes"][str(n)] = {
            "matrix": hashlib.sha256(raw).hexdigest() == doc["matrix_sha256"],
            "formula": verified.formula_sha256 == doc["base_formula"]["sha256"],
            "variables": verified.variables == doc["base_formula"]["variables"],
            "per_face": per_face_check(cmap, random_planes(n, 20261006)).passed,
        }
    produced = formula_bundle(corpus12.load_map(1))
    target = publish_bundle(Path(work) / "map1", produced.files)
    verified = read_bundle(target, corpus12.load_map(1))
    values = {
        v: hashlib.sha256(f"k12-s00-model-1:{v}".encode("ascii")).digest()[0] & 1
        for v in range(1, verified.variables + 1)
    }
    found["model"] = hashlib.sha256(J(describe_model(verified.variable_map, values))).hexdigest()
    found["map1"] = verified.formula_sha256 == corpus12.formula_hashes()[1].sha256
print(json.dumps(found))
"""


def clean_env() -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if k not in SCRUB}
    env["PIP_DISABLE_PIP_VERSION_CHECK"] = "1"
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return env


def run(command: list[str | Path], cwd: Path) -> str:
    result = subprocess.run(
        [str(c) for c in command],
        cwd=cwd,
        env=clean_env(),
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        shown = " ".join(map(str, command))
        raise AssertionError(f"{shown} -> {result.returncode}\n{result.stdout}\n{result.stderr}")
    return result.stdout


def new_venv(path: Path) -> Path:
    run([sys.executable, "-m", "venv", path], cwd=path.parent)
    scripts = path / ("Scripts" if os.name == "nt" else "bin")
    return scripts / ("python.exe" if os.name == "nt" else "python")


@pytest.mark.slow
def test_the_installed_wheel_round_trips_fixtures_bundles_and_models(tmp_path: Path) -> None:
    assert REPO not in tmp_path.parents
    builder = new_venv(tmp_path / "build-env")
    constraints = REPO / "constraints" / "dev.txt"
    run([builder, "-m", "pip", "install", "-q", "-c", constraints, "setuptools", "build"], tmp_path)
    source = tmp_path / "src" / "neighbourly"
    ignore = shutil.ignore_patterns("build", "*.egg-info", "__pycache__", ".pytest_cache")
    shutil.copytree(PACKAGE, source, ignore=ignore)
    dist = tmp_path / "dist"
    run([builder, "-m", "build", "--wheel", "--no-isolation", "--outdir", dist, source], tmp_path)
    (wheel,) = sorted(dist.glob("neighbourly-*.whl"))

    python = new_venv(tmp_path / "venv")
    run([python, "-m", "pip", "install", "--no-index", wheel], tmp_path)
    work = tmp_path / "work"
    work.mkdir()
    found = json.loads(run([python, "-c", CHECK], work))
    prefix = Path(found["prefix"]).resolve()
    for file in found["files"]:
        location = Path(file).resolve()
        assert prefix in location.parents and REPO not in location.parents, location
    assert found["sizes"] == {
        str(n): {"matrix": True, "formula": True, "variables": True, "per_face": True}
        for n in (15, 16)
    }
    assert found["map1"] is True
    assert found["model"] == MODEL_DESCRIPTION_SHA256
