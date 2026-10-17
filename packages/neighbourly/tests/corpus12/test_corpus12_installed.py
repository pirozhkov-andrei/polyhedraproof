"""The installed neighbourly wheel reads all its data through importlib.resources (slow).

The wheel and the sdist are built from a copy of ``packages/neighbourly`` outside the
checkout; the wheel built from the sdist is installed alone with ``--no-index`` into a fresh
virtual environment, and a script run from a directory outside the checkout loads every
packaged file through the installed package: the 59 matrices against ``SHA256SUMS``, the
corpus checks, the hash fixture, map 1's base formula, the fixtures and ``provenance.json``.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest

PACKAGE = Path(__file__).resolve().parents[2]
REPO = PACKAGE.parents[1]
SCRUB = ("PYTHONPATH", "PYTHONHOME", "VIRTUAL_ENV", "PIP_CONSTRAINT")

CHECK = """
import hashlib, json, sys
import neighbourly, neighbourly.data as data
from neighbourly import corpus12
from neighbourly.maps import CombinatorialMap

sums = corpus12.matrix_sums()
loaded = 0
for map_id in corpus12.map_ids():
    cmap = corpus12.load_map(map_id)
    assert cmap.n == 12 and cmap.is_orientable()
    name = corpus12.matrix_name(map_id)
    assert hashlib.sha256(corpus12.matrix_bytes(map_id)).hexdigest() == sums[name]
    loaded += 1
provenance = json.loads(data.read_bytes("provenance.json"))
for entry in provenance["files"]:
    raw = data.read_bytes(*entry["path"].split("/"))
    assert hashlib.sha256(raw).hexdigest() == entry["sha256"], entry["path"]
for parts in (
    ("fixtures", "tetrahedron", "tetrahedron.txt"),
    ("fixtures", "szilassi", "csaszar_n7.txt"),
):
    CombinatorialMap.from_text(data.read_bytes(*parts).decode("utf-8"))
base = corpus12.base_formula(1)
print(json.dumps({
    "prefix": sys.prefix,
    "files": [neighbourly.__file__, str(data.resource("n12", "matrices", "topology_01.txt"))],
    "loaded": loaded,
    "provenance": len(provenance["files"]),
    "matrix_problems": corpus12.matrix_problems(),
    "corpus_problems": corpus12.corpus_problems(),
    "hashes": len(corpus12.formula_hashes()),
    "map1": [base.variables, base.clauses, base.sha256],
    "map1_fixture": corpus12.formula_hashes()[1].sha256,
}))
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


def packaged_files() -> set[str]:
    """Every data file under the source package, as wheel member names."""
    source = PACKAGE / "src" / "neighbourly" / "data"
    return {
        "neighbourly/data/" + path.relative_to(source).as_posix()
        for path in source.rglob("*")
        if path.is_file() and "__pycache__" not in path.parts
    }


@pytest.mark.slow
def test_the_installed_wheel_reads_every_packaged_file(tmp_path: Path) -> None:
    assert REPO not in tmp_path.parents
    builder = new_venv(tmp_path / "build-env")
    constraints = REPO / "constraints" / "dev.txt"
    run([builder, "-m", "pip", "install", "-q", "-c", constraints, "setuptools", "build"], tmp_path)
    source = tmp_path / "src" / "neighbourly"
    ignore = shutil.ignore_patterns("build", "*.egg-info", "__pycache__", ".pytest_cache")
    shutil.copytree(PACKAGE, source, ignore=ignore)
    dist = tmp_path / "dist"
    run([builder, "-m", "build", "--no-isolation", "--outdir", dist, source], tmp_path)
    (wheel,) = sorted(dist.glob("neighbourly-*.whl"))
    (sdist,) = sorted(dist.glob("neighbourly-*.tar.gz"))

    expected = packaged_files()
    # 59 matrices, sums, hashes, 4 fixture files (n = 4, 7), provenance, init; 4 files
    # of the n = 15, 16 fixtures
    assert len(expected) == 71
    with zipfile.ZipFile(wheel) as archive:
        assert expected <= set(archive.namelist())
    with tarfile.open(sdist) as archive:
        members = {m.name.split("/", 1)[1] for m in archive.getmembers() if "/" in m.name}
    assert {f"src/{name}" for name in expected} <= members

    python = new_venv(tmp_path / "venv")
    run([python, "-m", "pip", "install", "--no-index", wheel], tmp_path)
    work = tmp_path / "work"
    work.mkdir()
    found = json.loads(run([python, "-c", CHECK], work))
    prefix = Path(found["prefix"]).resolve()
    for file in found["files"]:
        location = Path(file).resolve()
        assert prefix in location.parents and REPO not in location.parents, location
    assert found["loaded"] == 59
    assert found["provenance"] == 69
    assert found["matrix_problems"] == found["corpus_problems"] == []
    assert found["hashes"] == 59
    assert found["map1"][2] == found["map1_fixture"]
    assert found["map1"][:2] == [5257, 52177]
