"""``scripts/bump_version.py`` on a copy of the release leaves no hash-pinned file stale.

The script rewrites the version wherever a listed file names it, among them the image tag of
``docs/SPECIFICATION.md``, whose hash the contract corpus records; it then regenerates the
corpus (CONTRIBUTING, "Generated and hash-pinned files").
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from release_view import build_view

ROOT = Path(__file__).resolve().parents[2]


def run(view: Path, *command: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, *command], cwd=view, capture_output=True, text=True, check=False
    )


def test_a_version_bump_leaves_the_contract_corpus_current(tmp_path: Path) -> None:
    view = tmp_path / "view"
    build_view(ROOT, view)
    bumped = run(view, "scripts/bump_version.py", "9.8.7")
    assert bumped.returncode == 0, bumped.stdout + bumped.stderr
    assert 'version = "9.8.7"' in (view / "packages/cubeproof/pyproject.toml").read_text()
    checked = run(view, "tools/spec_vectors/generate.py", "--check")
    assert checked.returncode == 0, checked.stdout + checked.stderr
