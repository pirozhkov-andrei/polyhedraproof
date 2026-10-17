"""Installed artifacts in clean environments outside the checkout (specification §14).

    make test-installed        # python3 -m pytest tests/release --run-slow

A build environment is created from ``constraints/dev.txt`` (network, or pip's own
configuration such as ``PIP_FIND_LINKS``/``PIP_NO_INDEX`` for an offline wheelhouse). Each
package is copied out of the checkout and built twice: an sdist followed by a wheel built
*from that sdist*, and a wheel straight from the source tree; both wheels must agree. The
root distribution ``polyhedraproof``, the meta-package of the release (specification §2.2),
is built from the release view. Every installation happens in a fresh virtual environment
with ``--no-index`` from the built files only, and every check runs from a temporary
directory with no ``PYTHONPATH``, so nothing can be imported from the checkout.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tarfile
import zipfile
from dataclasses import dataclass
from email.parser import Parser
from pathlib import Path

import pytest

from release_view import build_view

pytestmark = pytest.mark.slow

ROOT = Path(__file__).resolve().parents[2]
PACKAGES = ("cubeproof", "neighbourly", "faces12-campaign")
DEPENDS = {"cubeproof": [], "neighbourly": [], "faces12-campaign": ["cubeproof", "neighbourly"]}
#: The root distribution: the meta-package requiring the three exact versions of the release.
META = "polyhedraproof"
SCRUB = ("PYTHONPATH", "PYTHONHOME", "VIRTUAL_ENV", "PIP_CONSTRAINT")


def release_version() -> str:
    text = (ROOT / "packages" / "cubeproof" / "pyproject.toml").read_text(encoding="utf-8")
    for line in text.splitlines():
        if line.startswith("version = "):
            return line.split('"')[1]
    raise AssertionError("no version")


def module_name(distribution: str) -> str:
    return distribution.replace("-", "_")


def clean_env() -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if k not in SCRUB}
    env["PIP_DISABLE_PIP_VERSION_CHECK"] = "1"
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return env


def run(
    command: list[str | Path], cwd: Path, check: bool = True
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        [str(c) for c in command],
        cwd=cwd,
        env=clean_env(),
        capture_output=True,
        text=True,
        check=False,
    )
    if check and result.returncode != 0:
        shown = " ".join(map(str, command))
        raise AssertionError(f"{shown} -> {result.returncode}\n{result.stdout}\n{result.stderr}")
    return result


def new_venv(path: Path) -> Path:
    run([sys.executable, "-m", "venv", path], cwd=path.parent)
    scripts = path / ("Scripts" if os.name == "nt" else "bin")
    return scripts / ("python.exe" if os.name == "nt" else "python")


@dataclass(frozen=True)
class Artifacts:
    base: Path
    dist: Path
    direct: Path

    def wheel(self, distribution: str, where: Path | None = None) -> Path:
        found = sorted((where or self.dist).glob(f"{module_name(distribution)}-*.whl"))
        assert len(found) == 1, found
        return found[0]

    def sdist(self, distribution: str) -> Path:
        found = sorted(self.dist.glob(f"{module_name(distribution)}-*.tar.gz"))
        assert len(found) == 1, found
        return found[0]


@pytest.fixture(scope="session")
def artifacts(tmp_path_factory: pytest.TempPathFactory) -> Artifacts:
    base = tmp_path_factory.mktemp("installed")
    assert ROOT not in base.parents
    builder = new_venv(base / "build-env")
    constraints = ROOT / "constraints" / "dev.txt"
    run([builder, "-m", "pip", "install", "-q", "-c", constraints, "setuptools", "build"], cwd=base)
    dist, direct = base / "dist", base / "direct"
    ignore = shutil.ignore_patterns("build", "*.egg-info", "__pycache__", ".pytest_cache")
    for name in PACKAGES:
        source = base / "src" / name
        shutil.copytree(ROOT / "packages" / name, source, ignore=ignore)
        run([builder, "-m", "build", "--no-isolation", "--outdir", dist, source], cwd=base)
        run(
            [builder, "-m", "build", "--no-isolation", "--wheel", "--outdir", direct, source],
            cwd=base,
        )
    meta = base / "src" / META
    meta.mkdir()
    build_view(ROOT, meta)
    run([builder, "-m", "build", "--no-isolation", "--outdir", dist, meta], cwd=base)
    return Artifacts(base, dist, direct)


def wheel_members(path: Path) -> dict[str, str]:
    with zipfile.ZipFile(path) as archive:
        return {
            info.filename: hashlib.sha256(archive.read(info)).hexdigest()
            for info in archive.infolist()
            if not info.filename.endswith(".dist-info/RECORD")
        }


def wheel_metadata(path: Path) -> tuple[dict[str, str], list[str]]:
    with zipfile.ZipFile(path) as archive:
        name = next(n for n in archive.namelist() if n.endswith(".dist-info/METADATA"))
        message = Parser().parsestr(archive.read(name).decode("utf-8"))
    return dict(message.items()), message.get_all("Requires-Dist") or []


@pytest.mark.parametrize("name", PACKAGES)
def test_the_wheel_built_from_the_sdist_equals_the_wheel_built_from_the_tree(
    artifacts: Artifacts, name: str
) -> None:
    from_sdist = wheel_members(artifacts.wheel(name))
    from_tree = wheel_members(artifacts.wheel(name, artifacts.direct))
    assert from_sdist == from_tree


@pytest.mark.parametrize("name", PACKAGES)
def test_the_sdist_contains_the_package_and_its_metadata(artifacts: Artifacts, name: str) -> None:
    with tarfile.open(artifacts.sdist(name)) as archive:
        members = {m.name.split("/", 1)[1] for m in archive.getmembers() if "/" in m.name}
    top = module_name(name)
    for required in (
        "pyproject.toml",
        "README.md",
        "LICENSE",
        f"src/{top}/__init__.py",
        f"src/{top}/py.typed",
    ):
        assert required in members, required


@pytest.mark.parametrize("name", PACKAGES)
def test_the_wheel_contains_one_typed_package_and_exact_metadata(
    artifacts: Artifacts, name: str
) -> None:
    wheel = artifacts.wheel(name)
    top = module_name(name)
    members = wheel_members(wheel)
    tops = {m.split("/")[0] for m in members}
    assert tops == {top, f"{top}-{release_version()}.dist-info"}
    assert f"{top}/py.typed" in members
    assert f"{top}-{release_version()}.dist-info/licenses/LICENSE" in members
    headers, requires = wheel_metadata(wheel)
    assert headers["Version"] == release_version()
    assert headers["Requires-Python"] == ">=3.10"
    assert sorted(requires) == [f"{d}=={release_version()}" for d in DEPENDS[name]]


CHECK = """
import importlib, importlib.metadata as md, json, sys
names = sys.argv[1:]
result = {"prefix": sys.prefix, "modules": {}, "distributions": sorted(
    d.metadata["Name"].lower() for d in md.distributions())}
for name in names:
    module = importlib.import_module(name)
    version = getattr(module, "__version__", None)
    result["modules"][name] = {"file": module.__file__, "version": version}
print(json.dumps(result))
"""


@dataclass(frozen=True)
class Inspection:
    prefix: Path
    files: dict[str, Path]
    versions: dict[str, str | None]
    distributions: set[str]

    def assert_outside_the_checkout(self) -> None:
        for name, location in self.files.items():
            assert self.prefix in location.parents, (name, location)
            assert ROOT not in location.parents, (name, location)


def inspect(python: Path, cwd: Path, *modules: str) -> Inspection:
    data = json.loads(run([python, "-c", CHECK, *modules], cwd=cwd).stdout)
    return Inspection(
        prefix=Path(data["prefix"]).resolve(),
        files={k: Path(v["file"]).resolve() for k, v in data["modules"].items()},
        versions={k: v["version"] for k, v in data["modules"].items()},
        distributions=set(data["distributions"]) - {"pip", "setuptools"},
    )


def install(artifacts: Artifacts, env_name: str, *requirements: str) -> Path:
    python = new_venv(artifacts.base / env_name)
    run(
        [
            python,
            "-m",
            "pip",
            "install",
            "-q",
            "--no-index",
            "--find-links",
            artifacts.dist,
            *requirements,
        ],
        cwd=artifacts.base,
    )
    return python


@pytest.mark.parametrize("name", ["cubeproof", "neighbourly"])
def test_a_library_installs_alone_with_no_dependency(artifacts: Artifacts, name: str) -> None:
    python = install(artifacts, f"venv-{name}", name)
    work = artifacts.base / f"work-{name}"
    work.mkdir()
    modules = [name, "neighbourly.cnf"] if name == "neighbourly" else [name]
    found = inspect(python, work, *modules)
    found.assert_outside_the_checkout()
    assert found.distributions == {name}
    assert found.versions[name] == release_version()
    for other in (p for p in PACKAGES if p != name):
        missing = run([python, "-c", f"import {module_name(other)}"], cwd=work, check=False)
        assert missing.returncode != 0, other


def test_the_application_pulls_exactly_its_declared_dependencies(artifacts: Artifacts) -> None:
    python = install(artifacts, "venv-app", "faces12-campaign")
    work = artifacts.base / "work-app"
    work.mkdir()
    found = inspect(python, work, "faces12_campaign", "cubeproof", "neighbourly")
    found.assert_outside_the_checkout()
    assert found.distributions == {"faces12-campaign", "cubeproof", "neighbourly"}
    assert set(found.versions.values()) == {release_version()}


def test_the_application_refuses_to_install_without_its_dependencies(artifacts: Artifacts) -> None:
    alone = artifacts.base / "only-app"
    alone.mkdir()
    shutil.copy(artifacts.wheel("faces12-campaign"), alone)
    python = new_venv(artifacts.base / "venv-app-alone")
    result = run(
        [python, "-m", "pip", "install", "--no-index", "--find-links", alone, "faces12-campaign"],
        cwd=artifacts.base,
        check=False,
    )
    assert result.returncode != 0
    assert (
        "cubeproof" in result.stdout + result.stderr
        or "neighbourly" in result.stdout + result.stderr
    )


def test_the_meta_package_holds_no_code_and_requires_the_three_exact_versions(
    artifacts: Artifacts,
) -> None:
    wheel = artifacts.wheel(META)
    members = wheel_members(wheel)
    assert {m.split("/")[0] for m in members} == {f"{META}-{release_version()}.dist-info"}
    assert f"{META}-{release_version()}.dist-info/licenses/LICENSE" in members
    headers, requires = wheel_metadata(wheel)
    assert (headers["Name"], headers["Version"]) == (META, release_version())
    assert headers["Requires-Python"] == ">=3.10"
    runtime = [r for r in requires if "extra ==" not in r]  # not the development extra
    assert sorted(runtime) == sorted(f"{d}=={release_version()}" for d in PACKAGES)
    assert all('extra == "dev"' in r for r in requires if r not in runtime)
    with tarfile.open(artifacts.sdist(META)) as archive:
        names = {m.name.split("/", 1)[1] for m in archive.getmembers() if "/" in m.name}
    assert {"pyproject.toml", "README.md", "LICENSE"} <= names
    assert not any(name.startswith(("src/", "packages/")) for name in names), sorted(names)


def test_the_meta_package_installs_the_three_packages_of_the_release(
    artifacts: Artifacts,
) -> None:
    python = install(artifacts, "venv-all", META)
    work = artifacts.base / "work-all"
    work.mkdir()
    found = inspect(python, work, "faces12_campaign", "cubeproof", "neighbourly")
    found.assert_outside_the_checkout()
    assert found.distributions == {META, *PACKAGES}
    assert set(found.versions.values()) == {release_version()}
    assert run([python, "-c", "import faces12"], cwd=work, check=False).returncode != 0
    assert "selftest" in run([python, "-m", "faces12_campaign", "--help"], cwd=work).stdout


def test_the_meta_package_refuses_to_install_without_the_packages(artifacts: Artifacts) -> None:
    alone = artifacts.base / "only-meta"
    alone.mkdir()
    shutil.copy(artifacts.wheel(META), alone)
    python = new_venv(artifacts.base / "venv-meta-alone")
    result = run(
        [python, "-m", "pip", "install", "--no-index", "--find-links", alone, META],
        cwd=artifacts.base,
        check=False,
    )
    assert result.returncode != 0
    assert any(name in result.stdout + result.stderr for name in PACKAGES)
