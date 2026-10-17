"""The test image and the release image build the tools of one manifest.

Runs anywhere (no ``image`` marker): it reads files only. A change of a pin in one place and
not in the other fails here, so the tool inputs cannot drift casually.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

from image.pinned import ROOT, pinned_tools

DOCKER = ROOT / "docker"
TEST_DOCKERFILE = DOCKER / "test" / "Dockerfile"
RELEASE_DOCKERFILE = DOCKER / "release" / "Dockerfile"
MANIFEST: dict[str, Any] = pinned_tools.load_manifest(pinned_tools.MANIFEST)
HEX40 = re.compile(r"[0-9a-f]{40}")
HEX64 = re.compile(r"[0-9a-f]{64}")


def logical_lines(path: Path) -> list[str]:
    """Dockerfile/shell lines with backslash continuations joined, runs of whitespace collapsed
    to one space and comments dropped."""
    text = path.read_text(encoding="utf-8").replace("\\\n", " ")
    lines = text.splitlines()
    return [" ".join(line.split()) for line in lines if not line.lstrip().startswith("#")]


def stages(path: Path) -> list[tuple[str, list[str]]]:
    """``(FROM argument, lines)`` of every build stage."""
    out: list[tuple[str, list[str]]] = []
    for line in logical_lines(path):
        if line.startswith("FROM "):
            out.append((line.removeprefix("FROM ").strip(), []))
        elif out:
            out[-1][1].append(line)
    return out


def apt_packages(lines: list[str]) -> list[str]:
    """The packages of the ``apt-get install`` commands among `lines`, sorted."""
    packages: list[str] = []
    for line in lines:
        for match in re.finditer(r"apt-get install -y --no-install-recommends (.*?)(?:&&|$)", line):
            packages += match.group(1).split()
    return sorted(packages)


def env_values(lines: list[str]) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in lines:
        if line.startswith("ENV "):
            values.update(re.findall(r"(\w+)=(\S+)", line))
    return values


def test_the_manifest_is_complete_and_well_formed() -> None:
    assert MANIFEST["platform"] == "linux/amd64"
    assert re.fullmatch(r"debian@sha256:[0-9a-f]{64}", MANIFEST["base_image"])
    assert re.fullmatch(r"\d{8}T\d{6}Z", MANIFEST["apt_snapshot"])
    assert set(MANIFEST["apt_packages"]) == {"tools", "test"}
    assert set(MANIFEST["build_environment"]) == {"SOURCE_DATE_EPOCH", "TZ", "LC_ALL"}
    cadical = MANIFEST["tools"]["cadical"]
    cake = MANIFEST["tools"]["cake_lpr"]
    assert set(MANIFEST["tools"]) == {"cadical", "cake_lpr"}
    assert HEX40.fullmatch(cadical["commit"]) and HEX40.fullmatch(cake["commit"])
    assert set(cake["sources"]) == {"basis_ffi.c", "cake_lpr.S"}
    assert all(HEX64.fullmatch(value) for value in cake["sources"].values())
    assert cake["heap_mb"] > 0 and cake["stack_mb"] > 0
    assert (ROOT / cadical["normalize"]).is_file()
    assert (ROOT / MANIFEST["python_constraints"]).is_file()


def test_the_release_image_builds_the_tools_of_the_manifest() -> None:
    """The release image compiles its tools with the same script, manifest and inputs."""
    found = stages(RELEASE_DOCKERFILE)
    base = MANIFEST["base_image"]
    assert [name for name, _ in found] == [
        f"{base} AS tools",
        "tools AS helper",
        f"{base} AS artifacts",
        f"{base} AS release",
    ]
    release = RELEASE_DOCKERFILE.read_text(encoding="utf-8")
    assert set(re.findall(r"SOURCE_DATE_EPOCH=(\d+)", release)) == {
        MANIFEST["build_environment"]["SOURCE_DATE_EPOCH"]
    }
    tools = found[0][1]
    assert apt_packages(tools) == sorted(MANIFEST["apt_packages"]["tools"])
    assert env_values(tools).items() >= MANIFEST["build_environment"].items()
    # the tools stage is, line for line, the tools stage of the test image
    assert tools == stages(TEST_DOCKERFILE)[0][1]
    joined = " ".join(tools)
    assert "COPY docker/test/pinned_tools.py docker/test/tools.json /build/docker/test/" in joined
    assert "pinned_tools.py build --root /build --prefix /opt/polyhedraproof-test" in joined
    # no other stage fetches or compiles a solver or checker: the binaries come from `tools`
    later = " ".join(line for _, lines in found[1:] for line in lines)
    assert "git clone" not in later and "pinned_tools.py" not in later
    assert "COPY --from=helper /opt/polyhedraproof-test/bin/ /opt/faces12/bin/" in later

    # the builder compiles cake_lpr from exactly the two checksummed sources
    builder = (DOCKER / "test" / "pinned_tools.py").read_text(encoding="utf-8")
    for token in ('"gcc"', '"-O2"', '"-std=c99"', '"basis_ffi.c"', '"cake_lpr.S"'):
        assert token in builder, token
    assert 'observed != dict(pin["sources"])' in builder

    sources = (DOCKER / "debian.sources").read_text(encoding="utf-8")
    snapshots = re.findall(r"^URIs: \S+/(\d{8}T\d{6}Z)/$", sources, re.M)
    assert snapshots and set(snapshots) == {MANIFEST["apt_snapshot"]}


def test_the_test_image_is_built_from_the_pinned_base_only() -> None:
    """No stage starts from the release image or any other image."""
    found = stages(TEST_DOCKERFILE)
    assert [name for name, _ in found] == [
        f"{MANIFEST['base_image']} AS tools",
        f"{MANIFEST['base_image']} AS test",
    ]
    copies = [line for _, lines in found for line in lines if line.startswith("COPY ")]
    sources = {token for line in copies for token in line.split()[1:-1]}
    assert sources == {
        "--from=tools",
        "/opt/polyhedraproof-test",
        "docker/debian.sources",
        "docker/normalize_cadical_build.py",
        "docker/test/pinned_tools.py",
        "docker/test/tools.json",
        MANIFEST["python_constraints"],
    }, "the image must not bake in the checkout or the release image's files"


def test_the_test_dockerfile_follows_the_manifest() -> None:
    (_, tools), (_, test) = stages(TEST_DOCKERFILE)
    assert apt_packages(tools) == sorted(MANIFEST["apt_packages"]["tools"])
    assert apt_packages(test) == sorted(MANIFEST["apt_packages"]["test"])
    assert env_values(tools).items() >= MANIFEST["build_environment"].items()
    assert "util-linux" in MANIFEST["apt_packages"]["test"]  # prlimit, setpriv (specification §6.2)
    joined = " ".join(test)
    python_tools = " ".join(MANIFEST["python_tools"])
    assert joined.count(f"-c /opt/polyhedraproof-test/share/{MANIFEST['python_constraints']}") == 2
    assert joined.count(python_tools) == 2  # downloaded, then installed offline
    assert "pinned_tools.py verify --prefix /opt/polyhedraproof-test" in joined
    environment = env_values(test)
    assert environment["POLYHEDRAPROOF_TEST_TOOLS"] == "/opt/polyhedraproof-test"
    assert environment["PIP_NO_INDEX"] == "1"


def test_the_python_tools_are_exactly_pinned() -> None:
    constraints = (ROOT / MANIFEST["python_constraints"]).read_text(encoding="utf-8")
    pins = dict(re.findall(r"^([A-Za-z0-9_.-]+)==(\S+)", constraints, re.M))
    lowered = {name.lower() for name in pins}
    assert {name.lower() for name in MANIFEST["python_tools"]} <= lowered


@pytest.mark.skipif(shutil.which("bash") is None, reason="needs bash")
@pytest.mark.parametrize("script", sorted((DOCKER / "test").glob("*.sh")), ids=lambda p: p.name)
def test_the_shell_scripts_parse(script: Path) -> None:
    result = subprocess.run(["bash", "-n", str(script)], capture_output=True, check=False)
    assert result.returncode == 0, result.stderr.decode()


def test_the_wrappers_run_tests_without_network_and_with_an_init() -> None:
    for name in ("run.sh", "validate.sh"):
        lines = logical_lines(DOCKER / "test" / name)
        runs = [line for line in lines if "docker run" in line]
        assert runs, name
        assert all("--network none" in line for line in runs), name
    run = " ".join(logical_lines(DOCKER / "test" / "run.sh"))
    assert "--init" in run and ":/src:ro" in run
    # the cross-device tests need /dev/shm above the 2 GiB disk reserve
    assert '--shm-size "$shm"' in run and "shm=${TEST_SHM_SIZE:-4g}" in run
