"""The cubeproof skeleton: release version, typing marker and import isolation."""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

import cubeproof

PACKAGE_DIR = Path(__file__).resolve().parents[1]


def _pyproject_version() -> str:
    text = (PACKAGE_DIR / "pyproject.toml").read_text(encoding="utf-8")
    match = re.search(r'^version = "([^"]+)"$', text, re.MULTILINE)
    assert match is not None
    return match.group(1)


def _modules_loaded_by(statement: str) -> set[str]:
    """Top-level modules loaded by a fresh interpreter (no site) running ``statement``."""
    source_root = Path(cubeproof.__file__).resolve().parents[1]
    code = f"import sys\n{statement}\nprint('\\n'.join(sorted(sys.modules)))"
    env = {**os.environ, "PYTHONPATH": str(source_root)}
    out = subprocess.run(
        [sys.executable, "-S", "-c", code], capture_output=True, text=True, check=True, env=env
    ).stdout
    return {name.split(".")[0] for name in out.split()} - {"__main__"}


def test_the_version_is_the_release_version() -> None:
    assert cubeproof.__version__ == _pyproject_version()


def test_the_package_is_typed() -> None:
    assert (Path(cubeproof.__file__).parent / "py.typed").is_file()


def test_importing_loads_only_the_standard_library() -> None:
    allowed = set(sys.stdlib_module_names) | set(sys.builtin_module_names) | {"cubeproof"}
    assert _modules_loaded_by("import cubeproof") - allowed == set()
