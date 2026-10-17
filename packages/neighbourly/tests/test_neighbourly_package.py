"""The neighbourly package: release version, typing marker and the neighbourly.cnf boundary."""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

import neighbourly
import neighbourly.cnf

PACKAGE_DIR = Path(__file__).resolve().parents[1]


def _pyproject_version() -> str:
    text = (PACKAGE_DIR / "pyproject.toml").read_text(encoding="utf-8")
    match = re.search(r'^version = "([^"]+)"$', text, re.MULTILINE)
    assert match is not None
    return match.group(1)


def _modules_loaded_by(statement: str) -> set[str]:
    """Modules loaded by a fresh interpreter (no site) running ``statement``."""
    source_root = Path(neighbourly.__file__).resolve().parents[1]
    code = f"import sys\n{statement}\nprint('\\n'.join(sorted(sys.modules)))"
    env = {**os.environ, "PYTHONPATH": str(source_root)}
    out = subprocess.run(
        [sys.executable, "-S", "-c", code], capture_output=True, text=True, check=True, env=env
    ).stdout
    return set(out.split()) - {"__main__"}


def test_the_version_is_the_release_version() -> None:
    assert neighbourly.__version__ == _pyproject_version()


def test_the_package_is_typed() -> None:
    assert (Path(neighbourly.__file__).parent / "py.typed").is_file()


def test_cnf_is_a_subpackage() -> None:
    assert neighbourly.cnf.__name__ == "neighbourly.cnf"
    assert Path(neighbourly.cnf.__file__).name == "__init__.py"


def test_importing_loads_only_the_standard_library() -> None:
    allowed = set(sys.stdlib_module_names) | set(sys.builtin_module_names) | {"neighbourly"}
    tops = {name.split(".")[0] for name in _modules_loaded_by("import neighbourly")}
    assert tops - allowed == set()


def test_importing_cnf_loads_no_other_neighbourly_module() -> None:
    loaded = _modules_loaded_by("import neighbourly.cnf")
    ours = {name for name in loaded if name.split(".")[0] == "neighbourly"}
    assert ours <= {"neighbourly"} | {n for n in ours if n.startswith("neighbourly.cnf")}
