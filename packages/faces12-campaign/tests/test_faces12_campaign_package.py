"""The faces12-campaign package: release version, declared dependencies, typing marker."""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

import cubeproof
import faces12_campaign
import neighbourly

PACKAGE_DIR = Path(__file__).resolve().parents[1]


def _pyproject_text() -> str:
    return (PACKAGE_DIR / "pyproject.toml").read_text(encoding="utf-8")


def _pyproject_version() -> str:
    match = re.search(r'^version = "([^"]+)"$', _pyproject_text(), re.MULTILINE)
    assert match is not None
    return match.group(1)


def test_the_version_is_the_release_version() -> None:
    assert faces12_campaign.__version__ == _pyproject_version()


def test_the_libraries_are_pinned_to_the_same_release() -> None:
    version = faces12_campaign.__version__
    assert cubeproof.__version__ == neighbourly.__version__ == version
    text = _pyproject_text()
    for library in ("cubeproof", "neighbourly"):
        assert f'"{library}=={version}"' in text


def test_the_package_is_typed() -> None:
    assert (Path(faces12_campaign.__file__).parent / "py.typed").is_file()


def test_importing_loads_only_the_standard_library_and_the_libraries() -> None:
    roots = {
        str(Path(str(module.__file__)).resolve().parents[1])
        for module in (cubeproof, neighbourly, faces12_campaign)
    }
    code = "import sys\nimport faces12_campaign\nprint('\\n'.join(sorted(sys.modules)))"
    env = {**os.environ, "PYTHONPATH": os.pathsep.join(sorted(roots))}
    out = subprocess.run(
        [sys.executable, "-S", "-c", code], capture_output=True, text=True, check=True, env=env
    ).stdout
    tops = {name.split(".")[0] for name in out.split()} - {"__main__"}
    allowed = set(sys.stdlib_module_names) | set(sys.builtin_module_names)
    allowed |= {"faces12_campaign", "cubeproof", "neighbourly"}
    assert tops - allowed == set()
