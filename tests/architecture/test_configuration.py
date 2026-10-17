"""Packaging, tool and test configuration (specification §14).

Three distributions with one release version and exactly their declared dependencies; a root
meta-package that requires exactly the three of the release; pinned development tools; strict
typing for the packages; opt-in slow/image tiers; the standard make targets.
"""

from __future__ import annotations

import ast
import importlib.util
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from archcheck import import_name, load_pyproject, requirement_name

ROOT = Path(__file__).resolve().parents[2]
PACKAGES = {
    "cubeproof": ROOT / "packages" / "cubeproof",
    "neighbourly": ROOT / "packages" / "neighbourly",
    "faces12-campaign": ROOT / "packages" / "faces12-campaign",
}
DEPENDS = {"cubeproof": [], "neighbourly": [], "faces12-campaign": ["cubeproof", "neighbourly"]}
DEV_TOOLS = {"pytest", "pytest-xdist", "coverage", "ruff", "mypy", "build", "setuptools"}
STANDARD_TARGETS = (
    "install-dev",
    "test-fast",
    "test-all",
    "lint",
    "test-architecture",
    "test-installed",
    "test-release-view",
)
OPT_IN_MARKERS = ("slow", "image")


def project(path: Path) -> dict[str, Any]:
    data = load_pyproject(path / "pyproject.toml")
    section = data["project"]
    assert isinstance(section, dict)
    return section


def release_version() -> str:
    return str(project(PACKAGES["cubeproof"])["version"])


def init_version(package_dir: Path, top: str) -> str:
    tree = ast.parse((package_dir / "src" / top / "__init__.py").read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id == "__version__" for t in node.targets
        ):
            return str(ast.literal_eval(node.value))
    raise AssertionError(f"{top} has no __version__")


def normalize(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def test_exactly_three_packages_exist() -> None:
    found = sorted(p.parent.name for p in (ROOT / "packages").glob("*/pyproject.toml"))
    assert found == sorted(PACKAGES)


@pytest.mark.parametrize("name", sorted(PACKAGES))
def test_one_release_version(name: str) -> None:
    meta = project(PACKAGES[name])
    assert meta["name"] == name
    assert meta["version"] == release_version()
    assert init_version(PACKAGES[name], import_name(name)) == release_version()


@pytest.mark.parametrize("name", sorted(PACKAGES))
def test_declared_dependencies_are_exactly_the_own_packages_of_the_release(name: str) -> None:
    dependencies = project(PACKAGES[name]).get("dependencies", [])
    assert sorted(requirement_name(d) for d in dependencies) == DEPENDS[name]
    for requirement in dependencies:
        assert requirement == f"{requirement_name(requirement)}=={release_version()}"


#: Package data besides the typing marker (the n = 12 corpus, fixtures, provenance).
PACKAGE_DATA: dict[str, list[str]] = {
    "neighbourly": [
        "data/provenance.json",
        "data/n12/*.json",
        "data/n12/matrices/*.txt",
        "data/n12/matrices/SHA256SUMS",
        "data/fixtures/*/*.txt",
        "data/fixtures/*/*.json",
    ],
}


@pytest.mark.parametrize("name", sorted(PACKAGES))
def test_package_metadata_and_files(name: str) -> None:
    directory = PACKAGES[name]
    data = load_pyproject(directory / "pyproject.toml")
    meta = project(directory)
    top = import_name(name)
    assert data["build-system"] == {
        "requires": ["setuptools>=77.0.3"],
        "build-backend": "setuptools.build_meta",
    }
    assert meta["requires-python"] == ">=3.10"
    assert meta["license"] == "MIT"
    assert meta["license-files"] == ["LICENSE"]
    assert meta["readme"] == "README.md"
    assert "optional-dependencies" not in meta, "development tools belong to the root"
    assert (directory / "LICENSE").read_bytes() == (ROOT / "LICENSE").read_bytes()
    readme = (directory / "README.md").read_text(encoding="utf-8")
    assert readme.startswith(f"# {name}\n")
    tool = data["tool"]
    assert isinstance(tool, dict)
    assert tool["setuptools"]["packages"]["find"] == {"where": ["src"]}
    assert tool["setuptools"]["package-data"] == {top: ["py.typed", *PACKAGE_DATA.get(name, [])]}
    assert (directory / "src" / top / "py.typed").is_file()
    assert (directory / "tests").is_dir()
    packages = sorted(
        p.name
        for p in (directory / "src").iterdir()
        if p.is_dir() and not p.name.endswith(".egg-info") and p.name != "__pycache__"
    )
    assert packages == [top], "one import package per distribution"


def test_neighbourly_cnf_is_a_subpackage() -> None:
    assert (PACKAGES["neighbourly"] / "src" / "neighbourly" / "cnf" / "__init__.py").is_file()


def test_the_root_distribution_is_the_meta_package_of_the_release() -> None:
    """Specification §2.2: no code, and exactly the three distributions at the release version."""
    meta = project(ROOT)
    assert meta["name"] == "polyhedraproof"
    assert meta["version"] == release_version()
    assert "scripts" not in meta and "entry-points" not in meta
    data = load_pyproject(ROOT / "pyproject.toml")
    tool = data["tool"]
    assert isinstance(tool, dict)
    assert tool["setuptools"] == {"packages": []}
    dependencies = meta["dependencies"]
    assert sorted(normalize(requirement_name(r)) for r in dependencies) == sorted(PACKAGES)
    for requirement in dependencies:
        assert requirement == f"{requirement_name(requirement)}=={release_version()}"
    assert not (ROOT / "src").exists(), "the root holds no code"
    assert not (ROOT / "setup.py").exists()


def _constraints() -> dict[str, str]:
    pins: dict[str, str] = {}
    for raw in (ROOT / "constraints" / "dev.txt").read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        match = re.fullmatch(
            r'([A-Za-z0-9_.-]+)==([A-Za-z0-9_.+!-]+)( ; python_version < "3\.\d+")?', line
        )
        assert match, f"not an exact pin: {raw!r}"
        name = normalize(match.group(1))
        assert name not in pins or match.group(3), f"duplicate pin {name}"
        pins.setdefault(name, match.group(2))
    return pins


def test_development_tools_are_pinned_and_not_runtime_dependencies() -> None:
    pins = _constraints()
    dev = project(ROOT)["optional-dependencies"]["dev"]
    names = {normalize(requirement_name(r)) for r in dev}
    assert names >= DEV_TOOLS
    assert names <= set(pins), f"unpinned development tools: {sorted(names - set(pins))}"
    for directory in [ROOT, *PACKAGES.values()]:
        for requirement in project(directory).get("dependencies", []):
            assert normalize(requirement_name(requirement)) not in pins


def test_pytest_markers_and_paths() -> None:
    data = load_pyproject(ROOT / "pyproject.toml")
    ini = data["tool"]["pytest"]["ini_options"]  # type: ignore[index]
    markers = {m.split(":")[0].strip() for m in ini["markers"]}
    assert {"slow", "image", "serial", "release_view"} == markers
    assert "--strict-markers" in ini["addopts"]
    paths = set(ini["pythonpath"])
    assert paths == {"tools/checks", *(f"packages/{n}/src" for n in PACKAGES)}


def _make_dry_run(target: str) -> str:
    make = shutil.which("make")
    if make is None:
        pytest.skip("make is not installed")
    result = subprocess.run(
        [make, "-n", "-C", str(ROOT), target, "PYTHON=python3"],
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout


def test_the_standard_targets_exist() -> None:
    text = (ROOT / "Makefile").read_text(encoding="utf-8")
    for target in STANDARD_TARGETS:
        assert re.search(rf"^{re.escape(target)}:", text, re.MULTILINE), target


def test_lint_is_strict_for_every_package() -> None:
    commands = _make_dry_run("lint")
    mypy = [line for line in commands.splitlines() if "mypy" in line and "--strict" in line]
    assert mypy
    for name in PACKAGES:
        assert any(f"packages/{name}/src" in line for line in mypy), name
    assert "ruff check" in commands
    assert "ruff format --check" in commands


def test_the_fast_suite_excludes_the_opt_in_tiers() -> None:
    commands = _make_dry_run("test-fast")
    assert '-m "not slow and not image and not serial"' in commands
    assert '-m "not slow and not image and serial"' in commands
    for name in PACKAGES:
        assert f"packages/{name}/tests" in commands
    # tests/architecture run in `make test-architecture`, not twice (its nested release-view
    # test re-runs every package fast suite); a standard target must still run them.
    assert "tests/architecture" not in commands
    assert "tests/architecture" in _make_dry_run("test-architecture")


def test_the_fast_suite_runs_in_workers_and_the_serial_tests_alone() -> None:
    """A parallel pass without the serial tests, then a pass of only them, no workers."""
    text = (ROOT / "Makefile").read_text(encoding="utf-8")
    assert "-n $(WORKERS)" in text
    commands = _make_dry_run("test-fast").splitlines()
    parallel = [c for c in commands if "and not serial" in c]
    serial = [c for c in commands if c.rstrip().endswith("no:cacheprovider") and 'and serial"' in c]
    assert len(parallel) == 1 and len(serial) == 1
    assert " -n " not in serial[0]
    for name in PACKAGES:
        assert f"packages/{name}/tests" in parallel[0] and f"packages/{name}/tests" in serial[0]


def test_the_release_view_test_has_its_own_target() -> None:
    """test-architecture leaves the release-view re-run to test-release-view."""
    assert '-m "not release_view"' in _make_dry_run("test-architecture")
    assert "-m release_view" in _make_dry_run("test-release-view")
    release_list_tests = ROOT / "tests" / "architecture" / "test_release_list.py"
    marked = "@pytest.mark.release_view\ndef test_the_source_release_runs_its_own_fast_suites"
    assert marked in release_list_tests.read_text(encoding="utf-8")


def test_every_serial_entry_names_an_existing_test() -> None:
    """A stale entry would silently move a timing-sensitive test back into the workers."""
    for prefix in _root_conftest().SERIAL:
        path, _, name = prefix.partition("::")
        assert (ROOT / path).is_file(), prefix
        if name:
            text = (ROOT / path).read_text(encoding="utf-8")
            assert f"def {name}(" in text, prefix


def test_lint_checks_the_claims_documents() -> None:
    """`make lint` runs the claims ledger check."""
    commands = _make_dry_run("lint")
    assert "tools/checks/claims_docs.py --check" in commands
    assert "-m faces12 " not in commands and "release docs" not in commands


def test_install_dev_uses_the_constraints_and_installs_everything_editable() -> None:
    commands = _make_dry_run("install-dev")
    assert "constraints/dev.txt" in commands
    for name in PACKAGES:
        assert f"-e packages/{name}" in commands
    assert '-e ".[dev]"' in commands or "-e .[dev]" in commands


def test_test_basenames_are_unique() -> None:
    """Pytest's default import mode needs unique basenames across test directories."""
    roots = [ROOT / "tests", *(p / "tests" for p in PACKAGES.values())]
    seen: dict[str, Path] = {}
    for root in roots:
        for path in sorted(root.rglob("*.py")):
            if path.name in ("__init__.py", "conftest.py") or "__pycache__" in path.parts:
                continue
            assert path.name not in seen, f"{path} and {seen[path.name]}"
            seen[path.name] = path


def _root_conftest() -> Any:
    spec = importlib.util.spec_from_file_location("root_conftest", ROOT / "conftest.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_opt_in_rule() -> None:
    rule = _root_conftest().opt_in_skip
    assert rule({"slow"}, set(), "packages/cubeproof/tests/test_x.py")
    assert rule({"slow"}, {"slow"}, "packages/cubeproof/tests/test_x.py") is None
    assert rule({"image", "slow"}, {"slow"}, "tests/release/test_x.py")
    assert rule({"image"}, {"slow"}, "tests/image/test_x.py")
    assert rule({"image"}, {"image"}, "tests/image/test_x.py") is None
    assert rule(set(), set(), "tests/architecture/test_x.py") is None
    # no directory keeps a policy of its own
    assert rule({"slow"}, set(), "tests/unit/test_x.py")
    assert rule({"slow"}, set(), "tests/integration/test_x.py")


def test_a_plain_invocation_skips_the_opt_in_tiers(tmp_path: Path) -> None:
    shutil.copy(ROOT / "conftest.py", tmp_path / "conftest.py")
    markers = "\n".join(f'    "{m}: test marker",' for m in OPT_IN_MARKERS)
    (tmp_path / "pyproject.toml").write_text(
        f'[tool.pytest.ini_options]\naddopts = "-p no:cacheprovider --strict-markers"\n'
        f"markers = [\n{markers}\n]\n",
        encoding="utf-8",
    )
    tests = tmp_path / "suite"
    tests.mkdir()
    body = "import pytest\n\n"
    for marker in OPT_IN_MARKERS:
        body += f"@pytest.mark.{marker}\ndef test_{marker}() -> None:\n    pass\n\n"
    body += "def test_plain() -> None:\n    pass\n"
    (tests / "test_tiers.py").write_text(body, encoding="utf-8")

    def run(*options: str) -> str:
        result = subprocess.run(
            [sys.executable, "-m", "pytest", "-q", str(tests), *options],
            cwd=tmp_path,
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        return result.stdout.strip().splitlines()[-1]

    assert run().startswith("1 passed, 2 skipped")
    assert run("--run-slow").startswith("2 passed, 1 skipped")
    assert run("--run-slow", "--run-image").startswith("3 passed")
