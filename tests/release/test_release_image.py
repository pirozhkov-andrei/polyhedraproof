"""The installed release image: its Dockerfile, artifact builder and entry point.

The fast tests read ``docker/release/Dockerfile`` and exercise the pure parts of
``docker/release/release_artifacts.py`` and ``docker/release/release_entrypoint.py`` (loaded
from their files: they are image scripts, not package modules), and run the two validation
scripts ``docker/release/validate.sh`` and ``docker/test/validate.sh`` with recording programs
in place of ``docker`` and ``python3`` (no image is built). The tests marked ``image``
run a built release image; they need Docker and ``POLYHEDRAPROOF_RELEASE_IMAGE`` naming the image
(``docker/release/validate.sh`` sets it for the image it has just built)::

    POLYHEDRAPROOF_RELEASE_IMAGE=faces12-campaign:1.0.0 \\
        python3 -m pytest tests/release --run-slow --run-image
"""

from __future__ import annotations

import dataclasses
import importlib.util
import io
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
RELEASE = ROOT / "docker" / "release"
DOCKERFILE = RELEASE / "Dockerfile"
TEST_DOCKERFILE = ROOT / "docker" / "test" / "Dockerfile"
IMAGE_VARIABLE = "POLYHEDRAPROOF_RELEASE_IMAGE"


def load(name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(f"a11_{name}", RELEASE / f"{name}.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # dataclasses resolve their module by name
    spec.loader.exec_module(module)
    return module


entry = load("release_entrypoint")
artifacts = load("release_artifacts")


# -- the Dockerfile ------------------------------------------------------------------------------


def instructions(path: Path) -> list[str]:
    """The instructions of a Dockerfile, continuation lines joined, comments dropped."""
    joined: list[str] = []
    current = ""
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.endswith("\\"):
            current += line[:-1].strip() + " "
            continue
        joined.append(re.sub(r"\s+", " ", current + line))
        current = ""
    assert not current, f"{path}: dangling continuation"
    return joined


def stages(path: Path) -> dict[str, list[str]]:
    """Instructions by stage name (``FROM ... AS name``), the FROM line included."""
    result: dict[str, list[str]] = {}
    name = ""
    for line in instructions(path):
        if line.startswith("FROM "):
            match = re.fullmatch(r"FROM (\S+) AS (\S+)", line)
            assert match, line
            name = match.group(2)
            result[name] = []
        result[name].append(line)
    return result


def test_the_tools_stage_is_the_tools_stage_of_the_test_image() -> None:
    """The release binaries are the binaries the image tests use (same pins, same steps)."""
    assert stages(DOCKERFILE)["tools"] == stages(TEST_DOCKERFILE)["tools"]


def test_every_stage_starts_from_the_pinned_base_or_an_earlier_stage() -> None:
    pinned = stages(TEST_DOCKERFILE)["tools"][0].split()[1]
    assert re.fullmatch(r"debian@sha256:[0-9a-f]{64}", pinned)
    seen: list[str] = []
    for name, lines in stages(DOCKERFILE).items():
        base = lines[0].split()[1]
        assert base == pinned or base in seen, (name, base)
        seen.append(name)
    assert seen == ["tools", "helper", "artifacts", "release"]


def test_the_release_stage_installs_built_wheels_only() -> None:
    release = stages(DOCKERFILE)["release"]
    copies = [line for line in release if line.startswith("COPY ")]
    from_context = [line for line in copies if "--from=" not in line]
    # the build context contributes the apt sources and the entry point, never the packages
    assert [line.split()[1] for line in from_context] == [
        "docker/debian.sources",
        "docker/release/release_entrypoint.py",
    ]
    install = next(line for line in release if "pip install" in line)
    assert "--no-index" in install
    assert "--find-links /opt/faces12/artifacts/wheels" in install
    assert "-r /opt/faces12/artifacts/requirements.txt" in install
    assert "-e " not in install
    text = DOCKERFILE.read_text(encoding="utf-8")
    assert "PYTHONPATH" not in "\n".join(instructions(DOCKERFILE)), "no PYTHONPATH in the image"
    assert "COPY . /src" in "\n".join(stages(DOCKERFILE)["artifacts"])
    assert "checked-hash" in text  # reproducible .pyc files


def test_the_release_stage_runs_as_a_non_root_user_with_an_isolated_entry_point() -> None:
    release = stages(DOCKERFILE)["release"]
    users = [line for line in release if line.startswith("USER ")]
    assert users == ["USER faces12"]
    entrypoint = next(line for line in release if line.startswith("ENTRYPOINT "))
    words = json.loads(entrypoint.split(" ", 1)[1])
    assert words == ["/opt/faces12/venv/bin/python", "-I", "/opt/faces12/entrypoint.py"]
    setup = next(line for line in release if "useradd" in line)
    assert "--uid 1000" in setup
    assert "chown faces12:faces12 /work/results /work/scratch" in setup


def test_the_artifact_builder_matches_the_release_packages() -> None:
    assert artifacts.PACKAGES == ("cubeproof", "neighbourly", "faces12-campaign")
    versions = {artifacts.package_version(ROOT, name) for name in artifacts.PACKAGES}
    assert len(versions) == 1
    assert set(entry.DISTRIBUTIONS) == set(artifacts.PACKAGES)


def test_the_artifact_builder_refuses_an_output_inside_the_source(tmp_path: Path) -> None:
    source = tmp_path / "src"
    source.mkdir()
    with pytest.raises(artifacts.ArtifactError, match="outside the source tree"):
        artifacts.build_all(source, source / "out", Path(sys.executable), "x")
    out = tmp_path / "out"
    out.mkdir()
    (out / "old.whl").write_bytes(b"")
    with pytest.raises(artifacts.ArtifactError, match="not empty"):
        artifacts.build_all(source, out, Path(sys.executable), "x")


def test_the_artifact_environment_cannot_import_from_a_checkout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PYTHONPATH", "/checkout/src")
    monkeypatch.setenv("PYTHONHOME", "/x")
    monkeypatch.setenv("PIP_CONSTRAINT", "/x")
    env = artifacts.clean_env()
    assert not {"PYTHONPATH", "PYTHONHOME", "PIP_CONSTRAINT"} & set(env)


def test_the_artifact_manifest_separates_reproduced_and_informational_hashes(
    tmp_path: Path,
) -> None:
    for kind, name in (("wheels", "a.whl"), ("sdists", "a.tar.gz"), ("source", "s.tar.gz")):
        (tmp_path / kind).mkdir()
        (tmp_path / kind / name).write_bytes(kind.encode())
    document = artifacts.manifest(tmp_path, "1.0.0", ["build==1"], "3.11")
    assert document["format"] == "faces12-release-artifacts-1"
    assert document["reproducible"] == ["wheels", "source"]
    assert document["informational"] == ["sdists"]
    assert set(document["wheels"]) == {"a.whl"}
    assert document["requirements"] == [
        "cubeproof==1.0.0",
        "neighbourly==1.0.0",
        "faces12-campaign==1.0.0",
    ]


# -- the entry point: dispatch and explicit tools ------------------------------------------------


def test_every_built_in_mode_has_a_handler() -> None:
    assert set(entry.MODES) == {*entry.BUILTIN, "help"}


def help_commands(text: str) -> list[str]:
    """The first words of the indented one-line entries under 'Commands of the image:'."""
    section = text.split("Commands of the image:\n", 1)[1].split("\n\n", 1)[0]
    return [line.split()[0] for line in section.splitlines()]


def test_help_is_plain_text_with_one_line_for_every_user_mode(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert entry.main(["help"]) == 0
    text = capsys.readouterr().out
    assert entry.main([]) == 0
    assert capsys.readouterr().out == text
    assert text == entry.usage() + "\n" and not text.endswith("\n\n")
    # every mode a user may call, once, in the order of the dispatch table; not the build's
    user_modes = [mode for mode in entry.MODES if mode != "record"]
    assert help_commands(text) == user_modes
    assert "record " not in text and "records written" not in text
    for program in entry.PROGRAMS:
        assert re.search(rf"^  {re.escape(program)} ARGUMENTS ", text, re.MULTILINE), program
    for path in entry.TOOL_PATHS.values():
        assert str(path) in text
    assert f"default {entry.EXAMPLE_HOLES})" in text
    assert f"default {entry.EXAMPLE_LEAF_MS})" in text
    # plain text for a terminal: no markup, nothing about the implementation
    assert "`" not in text and "*" not in text and "\t" not in text
    for internal in (
        "docstring",
        "Standard library",
        "PYTHONPATH",
        "python -m",
        "-I",
        "Dockerfile",
    ):
        assert internal not in text, internal
    assert text.isascii()
    assert all(len(line) <= 96 and line == line.rstrip() for line in text.splitlines())
    assert text.startswith("The release image of faces12-campaign")


def test_the_module_docstring_is_not_the_help() -> None:
    assert entry.__doc__ is not None and "Notes for developers" in entry.__doc__
    assert entry.__doc__.strip() != entry.usage()


def test_modes_programs_and_the_default_program() -> None:
    assert entry.resolve([]) == ("help", [])
    assert entry.resolve(["help"]) == ("help", [])
    assert entry.resolve(["selfcheck"]) == ("selfcheck", [])
    assert entry.resolve(["init-volumes", "1000:1000"]) == ("init-volumes", ["1000:1000"])
    mode, command = entry.resolve(["cubeproof", "status", "--results", "/r"])
    assert mode == "exec"
    assert command[:4] == [sys.executable, "-I", "-m", "cubeproof"]
    assert command[4:] == ["status", "--results", "/r"]
    mode, command = entry.resolve(["maps"])
    assert command[:4] == [sys.executable, "-I", "-m", "faces12_campaign"]


def test_the_selfcheck_compares_the_tools_with_the_pins_of_the_application(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``release_pin_problems`` on the host, where the image's tool paths hold other files:
    binaries that are not the pinned ones, missing binaries, and an installation whose pins
    cannot be read are each a failed check with a reason, never a traceback."""
    from faces12_campaign import pins  # the oracle, not through the entrypoint

    paths = {name: tmp_path / name for name in ("solver", "checker", "helper")}
    monkeypatch.setattr(entry, "TOOL_PATHS", paths)
    assert len(entry.release_pin_problems()) == 2  # both missing
    assert all("missing" in problem for problem in entry.release_pin_problems())
    for path in paths.values():
        path.write_bytes(b"not a tool\n")
    problems = entry.release_pin_problems()
    assert len(problems) == 2
    assert any(pins.RELEASE_CHECKER_SHA256 in problem for problem in problems)
    assert any(pins.RELEASE_SOLVER_SHA256 in problem for problem in problems)

    def broken(name: str) -> object:
        raise ImportError(f"cannot import {name}")

    monkeypatch.setattr(entry.importlib, "import_module", broken)
    (problem,) = entry.release_pin_problems()
    assert "faces12_campaign.pins cannot be read" in problem and "ImportError" in problem


def test_the_run_command_gets_the_three_explicit_tools() -> None:
    words = entry.with_tools("faces12-campaign", ["run", "--campaign", "/io/c.json"])
    assert words == [
        "run",
        "--solver", "/opt/faces12/bin/cadical",
        "--checker", "/opt/faces12/bin/cake_lpr",
        "--helper", "/opt/faces12/bin/cubeproof-look",
        "--campaign", "/io/c.json",
    ]  # fmt: skip


def test_given_tools_are_not_replaced_or_duplicated() -> None:
    words = entry.with_tools(
        "cubeproof", ["run", "--solver=/x/cadical", "--checker", "/x/cake", "--worker", "w"]
    )
    assert words.count("--checker") == 1
    assert not any(w == "--solver" for w in words)
    assert words[1:3] == ["--helper", "/opt/faces12/bin/cubeproof-look"]


def test_solver_argv_is_not_the_solver_and_words_after_double_dash_are_not_options() -> None:
    assert not entry.given(["--solver-argv", "[]"], "--solver")
    assert entry.given(["--solver=/a"], "--solver")
    assert not entry.given(["--", "--solver", "/a"], "--solver")
    words = entry.with_tools("faces12-campaign", ["campaign", "init", "--solver-argv", "[]"])
    assert words[:6] == [
        "campaign", "init",
        "--solver", "/opt/faces12/bin/cadical",
        "--checker", "/opt/faces12/bin/cake_lpr",
    ]  # fmt: skip


@pytest.mark.parametrize(
    ("program", "words", "tools"),
    [
        ("faces12-campaign", ["audit"], ["--solver", "--checker", "--helper"]),
        ("cubeproof", ["verify-retained"], ["--checker"]),
        ("cubeproof", ["campaign", "create"], ["--solver", "--checker"]),
        ("faces12-campaign", ["status", "--results", "/r"], []),
        ("faces12-campaign", ["formulas", "--check"], []),
    ],
)
def test_only_the_commands_that_run_tools_get_them(
    program: str, words: list[str], tools: list[str]
) -> None:
    result = entry.with_tools(program, words)
    assert [w for w in result if w.startswith("--") and w not in words] == tools


# -- the entry point: volumes --------------------------------------------------------------------


def test_the_volume_owner_is_a_non_root_uid_gid() -> None:
    assert entry.parse_owner("1000:1001") == (1000, 1001)
    for bad in ("0:0", "0:1000", "00:1000", "1000", "a:b", "1000:1000:1", "-1:2"):
        with pytest.raises(entry.UsageError):
            entry.parse_owner(bad)


def test_init_volumes_changes_only_empty_volumes_with_another_owner(tmp_path: Path) -> None:
    uid, gid = os.getuid(), os.getgid()
    mine = tmp_path / "mine"
    mine.mkdir()
    assert entry.plan_volume(mine, uid, gid).action == "keep"
    other = uid + 1
    assert entry.plan_volume(mine, other, gid).action == "chown"
    (mine / "journal.jsonl").write_bytes(b"{}\n")
    refused = entry.plan_volume(mine, other, gid)
    assert refused.action == "refuse"
    assert "never re-owned" in refused.detail
    assert entry.plan_volume(tmp_path / "missing", other, gid).action == "refuse"
    (tmp_path / "file").write_bytes(b"")
    assert entry.plan_volume(tmp_path / "file", other, gid).action == "refuse"


def test_init_volumes_changes_nothing_when_one_volume_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    empty, full = tmp_path / "results", tmp_path / "scratch"
    empty.mkdir()
    full.mkdir()
    (full / "x").write_bytes(b"x")
    calls: list[Any] = []
    monkeypatch.setattr(entry.os, "chown", lambda *a: calls.append(a))
    owner = f"{os.getuid() + 1}:{os.getgid()}"
    assert entry.init_volumes([owner], volumes=(empty, full)) == 3
    assert calls == []
    assert "refuse" in capsys.readouterr().out
    shutil.rmtree(full)
    full.mkdir()
    monkeypatch.setattr(entry.os, "chmod", lambda *a: calls.append(("chmod", *a)))
    assert entry.init_volumes([owner], volumes=(empty, full)) == 0
    assert [c[0] for c in calls if c[0] != "chmod"] == [empty, full]


def test_capacity_groups_mounts_that_share_one_disk() -> None:
    mounts = [
        {"path": "/work/results", "device": 1, "total_bytes": 100},
        {"path": "/work/scratch", "device": 2, "total_bytes": 100},
        {"path": "/", "device": 3, "total_bytes": 100},
        {"path": "/other", "device": 4, "total_bytes": 7},
    ]
    assert entry.shared_groups(mounts) == [["/work/results", "/work/scratch", "/"]]
    mounts[1]["total_bytes"] = 50
    mounts[2]["device"] = 2
    # joined transitively: results~/ by size, /~scratch by device
    assert entry.shared_groups(mounts) == [["/work/results", "/work/scratch", "/"]]
    assert entry.shared_groups(mounts[3:]) == []


def test_the_capacity_report_of_real_directories(tmp_path: Path) -> None:
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    report = entry.capacity_report([tmp_path / "a", tmp_path / "b"])
    assert report["shared"] == [[str(tmp_path / "a"), str(tmp_path / "b")]]
    assert all(m["free_bytes"] <= m["total_bytes"] for m in report["mounts"])
    assert "--disk" in report["note"]


# -- the entry point: backup and restore ---------------------------------------------------------


def make_results(path: Path) -> None:
    (path / "journals").mkdir(parents=True)
    (path / "journals" / "journal.1.jsonl").write_bytes(b'{"seq":0}\n{"seq":1}\n')
    (path / "status.json").write_bytes(b"{}\n")


def tree(path: Path) -> dict[str, bytes]:
    return {
        p.relative_to(path).as_posix(): p.read_bytes()
        for p in sorted(path.rglob("*"))
        if p.is_file()
    }


def test_a_backup_restores_byte_for_byte_into_an_empty_volume(tmp_path: Path) -> None:
    results, backups, restored = tmp_path / "results", tmp_path / "b", tmp_path / "restored"
    make_results(results)
    backups.mkdir()
    restored.mkdir()
    assert entry.backup_results([str(backups), "w1.tar"], results=results) == 0
    assert sorted(p.name for p in backups.iterdir()) == ["w1.tar", "w1.tar.sha256"]
    assert entry.restore_results([str(backups / "w1.tar")], results=restored) == 0
    assert tree(restored) == tree(results)


def test_a_backup_never_replaces_a_file_and_refuses_unsafe_names(tmp_path: Path) -> None:
    results = tmp_path / "results"
    make_results(results)
    assert entry.backup_results([str(tmp_path), "w.tar"], results=results) == 0
    for name in ("w.tar", "../w.tar", ".hidden", "a b.tar", ""):
        with pytest.raises(entry.UsageError):
            entry.backup_results([str(tmp_path), name], results=results)


def test_restore_refuses_a_volume_with_files_and_a_wrong_checksum(tmp_path: Path) -> None:
    results, target = tmp_path / "results", tmp_path / "target"
    make_results(results)
    target.mkdir()
    assert entry.backup_results([str(tmp_path), "w.tar"], results=results) == 0
    (target / "keep").write_bytes(b"live")
    with pytest.raises(entry.UsageError, match="not empty"):
        entry.restore_results([str(tmp_path / "w.tar")], results=target)
    assert tree(target) == {"keep": b"live"}
    (target / "keep").unlink()
    with open(tmp_path / "w.tar", "ab") as stream:
        stream.write(b"\0")
    assert entry.restore_results([str(tmp_path / "w.tar")], results=target) == 4
    assert tree(target) == {}
    (tmp_path / "w.tar.sha256").unlink()
    with pytest.raises(entry.UsageError, match="checksum"):
        entry.restore_results([str(tmp_path / "w.tar")], results=target)


def member(name: str, kind: bytes = tarfile.REGTYPE) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.type = kind
    return info


def test_restore_admits_only_plain_files_below_results() -> None:
    good = [member("results", tarfile.DIRTYPE), member("results/journals/j.jsonl")]
    assert entry.restore_problems(good) == []
    for bad in (
        member("results/../etc/passwd"),
        member("/results/x"),
        member("other/x"),
        member("results//x"),
        member("results/link", tarfile.SYMTYPE),
        member("results/dev", tarfile.CHRTYPE),
    ):
        assert entry.restore_problems([bad]), bad.name


def test_restore_refuses_a_hostile_archive_before_writing(tmp_path: Path) -> None:
    archive = tmp_path / "bad.tar"
    with tarfile.open(archive, "w") as stream:
        data = b"x"
        info = tarfile.TarInfo("results/ok")
        info.size = len(data)
        stream.addfile(info, io.BytesIO(data))
        link = tarfile.TarInfo("results/escape")
        link.type = tarfile.SYMTYPE
        link.linkname = "/etc"
        stream.addfile(link)
    (tmp_path / "bad.tar.sha256").write_text(entry.checksum_line(archive), encoding="utf-8")
    target = tmp_path / "target"
    target.mkdir()
    assert entry.restore_results([str(archive)], results=target) == 4
    assert tree(target) == {}


# -- the entry point: the example campaign -------------------------------------------------------


def test_the_example_options() -> None:
    assert entry.parse_example(["/io"]) == (Path("/io"), 10, 1000)
    assert entry.parse_example(["/io", "--holes", "6", "--leaf-ms", "500"]) == (
        Path("/io"),
        6,
        500,
    )
    for bad in ([], ["--holes", "3"], ["/io", "--holes", "1"], ["/io", "--leaf-ms", "5"],
                ["/io", "--holes"], ["/io", "--jobs", "2"]):  # fmt: skip
        with pytest.raises(entry.UsageError):
            entry.parse_example(bad)


def test_the_example_formula_is_the_pigeonhole_principle() -> None:
    text = entry.pigeonhole(3).decode()
    lines = text.splitlines()
    assert lines[0] == "p cnf 12 22"  # 4 pigeons x 3 holes; 4 + 3 * C(4, 2) clauses
    assert len(lines) == 23
    assert all(line.endswith(" 0") for line in lines[1:])


def test_the_example_policy_is_a_valid_transient_policy() -> None:
    from cubeproof.base.canonical_json import document_bytes, parse_document
    from cubeproof.contracts.policy import Policy

    document = entry.example_policy(1000)
    policy = Policy.from_json(parse_document(document_bytes(document)))
    assert policy.proof_mode == "transient"
    assert policy.leaf_time_ms == {"default": 1000}


# -- the validation scripts: tags of a run, cleanup, the steps -----------------------------------
#
# docker/release/validate.sh and docker/test/validate.sh run here complete, with programs
# named ``docker`` and ``python3`` in front of PATH that record their calls and keep the tags
# as files. No image is built and no container runs.

VALIDATORS = {"release": "faces12-release-validate", "test": "polyhedraproof-test-validate"}
STUB_DOCKER = r"""
import json, os, shutil, sys
from pathlib import Path

state = Path(os.environ["STUB_STATE"])
tags = state / "tags"
tags.mkdir(parents=True, exist_ok=True)
words = sys.argv[1:]
with open(state / "calls.log", "a", encoding="utf-8") as log:
    log.write(json.dumps(words) + "\n")


def file_of(tag):
    return tags / tag.replace(":", "@").replace("/", "%")


def count(name):
    path = state / name
    value = int(path.read_text()) + 1 if path.exists() else 1
    path.write_text(str(value))
    return value


if words[0] == "build":
    number = count("builds")
    if os.environ.get("STUB_FAIL_BUILD") == str(number):
        sys.exit(1)
    tag = words[words.index("-t") + 1]
    file_of(tag).write_text(f"sha256:{number}:{tag}")  # the "image ID": build and first tag
elif words[:2] == ["image", "inspect"]:
    target = file_of(words[-1])
    if not target.exists():
        sys.exit(1)
    if "--format" in words:
        print(target.read_text())
elif words[:2] == ["image", "rm"]:
    target = file_of(words[-1])
    if not target.exists():
        sys.exit(1)
    target.unlink()
elif words[0] == "tag":
    shutil.copy(file_of(words[1]), file_of(words[2]))
elif words[0] == "create":
    (state / "container").write_text(file_of(words[1]).read_text())
    print("container-" + str(count("containers")))
elif words[0] == "cp":
    source, target = words[1].split(":", 1)[1], Path(words[2])
    build = (state / "container").read_text().split(":")[1]
    fixture = Path(os.environ["STUB_FIXTURE"])
    if source.endswith("/provenance"):
        shutil.copytree(fixture / "provenance", target)
        varied = target / "release-provenance.json"
        if varied.exists():
            document = json.loads(varied.read_text())
            document["recorded_utc"] = f"2026-01-01T00:00:0{build}.000Z"
            if os.environ.get("STUB_HOST_SPECIFIC"):
                document["platform"] = f"host-of-build-{build}"
            varied.write_text(json.dumps(document))
    elif target.is_dir():
        shutil.copy(fixture / Path(source).name, target)
    else:
        shutil.copy(fixture / Path(source).name, target)
elif words[0] == "run":
    sys.exit(int(os.environ.get("STUB_RUN_STATUS", "0")))
elif words[0] == "rm":
    pass
else:
    sys.exit(f"stub docker: unexpected {words}")
"""
STUB_PYTHON = r"""
import json, os, subprocess, sys
from pathlib import Path

words = sys.argv[1:]
if words[:1] == ["-"]:  # the script's own inline program
    sys.exit(subprocess.run([sys.executable, *words], check=False).returncode)
with open(Path(os.environ["STUB_STATE"]) / "calls.log", "a", encoding="utf-8") as log:
    image = os.environ.get("POLYHEDRAPROOF_RELEASE_IMAGE")
    log.write(json.dumps(["python3", *words, {"image": image}]) + "\n")
kind = "CLUSTER" if any("cluster_installed.py" in word for word in words) else "PYTEST"
sys.exit(int(os.environ.get(f"STUB_{kind}_STATUS", "0")))
"""


@dataclasses.dataclass
class Validation:
    """One run of a validation script against the recording programs."""

    code: int
    out: str
    err: str
    summary: str
    calls: list[list[Any]]
    tags: dict[str, str]

    def built(self) -> list[str]:
        return [call[call.index("-t") + 1] for call in self.calls if call[0] == "build"]


class Validator:
    def __init__(self, kind: str, base: Path) -> None:
        self.kind, self.base = kind, base
        self.state = base / "state"
        self.out = base / "release validation"  # a directory name that no tag may contain
        bin_dir = base / "bin"
        bin_dir.mkdir(parents=True)
        for name, text in (("docker", STUB_DOCKER), ("python3", STUB_PYTHON)):
            program = bin_dir / name
            program.write_text(f"#!{sys.executable}\n{text}", encoding="utf-8")
            program.chmod(0o755)
        fixture = base / "fixture"
        provenance = fixture / "provenance"
        provenance.mkdir(parents=True)
        digest = "ab" * 32
        documents: dict[str, Any] = {
            "tools.json": {"tools": {"cadical": {"sha256": digest}}},
            "artifacts.json": {"reproducible": ["wheels"], "wheels": {"a.whl": digest}},
            "formulas.json": {"formulas": [{"key": "m01", "formula_sha256": digest}]},
            "installed.json": {"cubeproof": {"a.py": digest}},
            "release-provenance.json": {"platform": "linux-x86_64", "recorded_utc": "x"},
        }
        for name, document in documents.items():
            (provenance / name).write_text(json.dumps(document), encoding="utf-8")
        for name in ("tools-stage-packages.txt", "wheelhouse.sha256", "environment.json"):
            (provenance / name).write_text("same\n", encoding="utf-8")
        (fixture / "cubeproof-look.provenance.json").write_text(
            json.dumps({"binary_sha256": digest}), encoding="utf-8"
        )
        (fixture / "SHA256SUMS").write_text(f"{digest}  cadical.tar.gz\n", encoding="utf-8")
        self.env = {
            "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
            "STUB_STATE": str(self.state),
            "STUB_FIXTURE": str(fixture),
            "HOME": str(base),
        }

    def run(self, *arguments: str, out: Path | None = None, **env: str) -> Validation:
        log = self.state / "calls.log"
        for name in ("calls.log", "builds", "containers"):  # what one run counts
            (self.state / name).unlink(missing_ok=True)
        target = self.out if out is None else out
        done = subprocess.run(
            ["bash", str(ROOT / "docker" / self.kind / "validate.sh"), str(target), *arguments],
            env={**self.env, **env},
            capture_output=True,
            text=True,
            check=False,
            timeout=120,
        )
        summary = target / "summary.txt"
        calls = log.read_text(encoding="utf-8").splitlines() if log.exists() else []
        tags = self.state / "tags"
        return Validation(
            done.returncode,
            done.stdout,
            done.stderr,
            summary.read_text(encoding="utf-8") if summary.exists() else "",
            [json.loads(line) for line in calls],
            {p.name.replace("@", ":"): p.read_text() for p in sorted(tags.iterdir())}
            if tags.is_dir()
            else {},
        )


needs_bash = pytest.mark.skipif(
    shutil.which("bash") is None or platform.machine() != "x86_64",
    reason="the validation scripts are bash scripts for x86-64",
)


@needs_bash
@pytest.mark.parametrize("kind", sorted(VALIDATORS))
def test_a_validation_names_its_two_builds_for_the_run_and_removes_them(
    kind: str, tmp_path: Path
) -> None:
    validator = Validator(kind, tmp_path)
    first = validator.run()
    assert first.code == 0, first.out + first.err
    second = validator.run()
    assert second.code == 0, second.out + second.err
    repository = VALIDATORS[kind]
    built = first.built() + second.built()
    assert len(set(built)) == 4, built  # the second run retags nothing of the first
    for run in (first, second):
        one, two = run.built()
        assert re.fullmatch(rf"{repository}:[A-Za-z0-9_][A-Za-z0-9_.-]*-1", one), one
        assert two == one[:-1] + "2"
        assert "release-validation" in one  # the name of OUTPUT_DIR, made safe for a tag
        assert f"removed intermediate tag {one}\n" in run.summary
        assert f"removed intermediate tag {two}\n" in run.summary
        assert run.summary in run.out
        assert f"run {one.split(':')[1][:-2]}: {one} {two}\n" in run.summary
    # nothing of the intermediate repository is left; the validated image keeps its own tag
    assert not [tag for tag in second.tags if tag.startswith(repository)], second.tags
    if kind == "release":
        # the version the script reads: that of packages/cubeproof in this checkout, whether
        # or not the distribution is installed (the test image runs the sources uninstalled)
        project = (ROOT / "packages" / "cubeproof" / "pyproject.toml").read_text(encoding="utf-8")
        (version,) = re.findall(r'^version = "([^"]+)"$', project, re.MULTILINE)
        for run in (first, second):  # the first build of each run, under the release tag
            assert run.tags == {f"faces12-campaign:{version}": f"sha256:1:{run.built()[0]}"}
    else:
        assert second.tags == {}


@needs_bash
@pytest.mark.parametrize("kind", sorted(VALIDATORS))
def test_a_validation_keeps_its_builds_on_request_and_never_takes_an_existing_tag(
    kind: str, tmp_path: Path
) -> None:
    validator = Validator(kind, tmp_path)
    repository = VALIDATORS[kind]
    kept = validator.run(VALIDATE_RUN_ID="rc.1_a", VALIDATE_KEEP_IMAGES="1")
    assert kept.code == 0, kept.out + kept.err
    assert kept.built() == [f"{repository}:rc.1_a-1", f"{repository}:rc.1_a-2"]
    assert {tag for tag in kept.tags if tag.startswith(repository)} == set(kept.built())
    assert "kept intermediate tags" in kept.summary and "removed" not in kept.summary
    assert not [call for call in kept.calls if call[:2] == ["image", "rm"]]
    # the same run ID again: refused before anything is built, and the kept images stay
    again = validator.run(VALIDATE_RUN_ID="rc.1_a")
    assert again.code == 2 and "exists" in again.err
    assert again.built() == [] and again.tags == kept.tags
    for bad in (".x", "-x", "a b", "a:b", "a/b", "x" * 101):
        refused = validator.run(VALIDATE_RUN_ID=bad)
        assert refused.code == 2 and "run ID" in refused.err, bad
        assert refused.calls == [] and refused.tags == kept.tags


@needs_bash
@pytest.mark.parametrize("kind", sorted(VALIDATORS))
def test_a_failed_validation_removes_its_builds_and_keeps_its_exit_status(
    kind: str, tmp_path: Path
) -> None:
    validator = Validator(kind, tmp_path)
    failed = validator.run(STUB_RUN_STATUS="1")  # selfcheck, or the comparison and the tests
    assert failed.code == 1 and "FAILED" in failed.summary
    assert failed.tags == {} and len(failed.built()) == 2
    assert failed.summary.count("removed intermediate tag") == 2
    broken = validator.run(STUB_FAIL_BUILD="2")  # the second build fails: the first is removed
    assert broken.code != 0 and broken.tags == {}
    assert broken.summary.count("removed intermediate tag") == 1
    assert "validation did not finish" in broken.summary


@needs_bash
def test_the_release_validation_runs_the_image_tests_and_then_the_two_worker_run(
    tmp_path: Path,
) -> None:
    validator = Validator("release", tmp_path)
    done = validator.run("faces12-campaign:candidate")
    assert done.code == 0, done.out + done.err
    first = done.built()[0]
    python = [call for call in done.calls if call[0] == "python3"]
    assert [call[1:-1] for call in python] == [
        ["-m", "pytest", "-p", "no:cacheprovider", "tests/release/test_release_image.py",
         "tests/release/test_wrappers.py", "--run-slow", "--run-image", "-v", "-rs"],
        ["tests/endtoend/cluster/cluster_installed.py", first,
         str(validator.out.resolve() / "cluster-installed")],
    ]  # fmt: skip
    assert python[0][-1] == {"image": first}
    assert (ROOT / "tests" / "endtoend" / "cluster" / "cluster_installed.py").is_file()
    assert [call for call in done.calls if call[0] == "run"] == [
        ["run", "--rm", "--init", "--network", "none", first, "selfcheck"]
    ]
    assert "installed two-worker run: passed\n" in done.summary
    assert "  cluster.log\n" in done.summary
    assert done.tags == {"faces12-campaign:candidate": f"sha256:1:{first}"}
    assert f"tagged faces12-campaign:candidate: sha256:1:{first}\n" in done.summary

    skipped = validator.run("faces12-campaign:unchecked", VALIDATE_SKIP_CLUSTER="1")
    assert skipped.code == 0, skipped.out + skipped.err
    assert len([call for call in skipped.calls if call[0] == "python3"]) == 1
    assert "installed two-worker run: SKIPPED (VALIDATE_SKIP_CLUSTER=1)\n" in skipped.summary
    assert "cluster.log" not in skipped.summary
    assert "faces12-campaign:unchecked" not in skipped.tags
    assert "\ntagged" not in skipped.summary
    assert (
        "not tagged faces12-campaign:unchecked: the installed two-worker run was skipped\n"
        in skipped.summary
    )

    failed = validator.run("faces12-campaign:other", STUB_CLUSTER_STATUS="1")
    assert failed.code == 1
    assert "installed two-worker run: FAILED (cluster.log, cluster-installed/)\n" in failed.summary
    assert "release image test tier: passed\n" in failed.summary
    assert "faces12-campaign:other" not in failed.tags and "tagged" not in failed.summary

    tests_failed = validator.run("faces12-campaign:other", STUB_PYTEST_STATUS="1")
    assert tests_failed.code == 1 and "faces12-campaign:other" not in tests_failed.tags
    assert "release image test tier: FAILED (tests.log)\n" in tests_failed.summary


@needs_bash
def test_the_release_validation_compares_the_provenance_without_its_time(tmp_path: Path) -> None:
    validator = Validator("release", tmp_path)
    done = validator.run()
    assert done.code == 0, done.out + done.err
    recorded = [
        json.loads((validator.out / f"provenance-{n}" / "release-provenance.json").read_text())
        for n in (1, 2)
    ]
    assert recorded[0]["recorded_utc"] != recorded[1]["recorded_utc"]
    lines = (validator.out / "reproduced-1.sha256").read_text(encoding="utf-8").splitlines()
    assert [line.split()[0] for line in lines] == sorted(
        ["tool/cadical", "helper/cubeproof-look", "tool-source/cadical.tar.gz", "wheels/a.whl",
         "formula/m01", "installed.json", "release-provenance.json"]
    )  # fmt: skip
    assert (validator.out / "compare.diff").read_text(encoding="utf-8") == ""
    assert "reproduced hashes: identical across the two builds\n" in done.summary
    # a record of the host that built the image would differ between two hosts: it is caught
    differs = validator.run(STUB_HOST_SPECIFIC="1")
    assert differs.code == 1
    assert "reproduced hashes: DIFFER between the two builds (compare.diff)\n" in differs.summary
    diff = (validator.out / "compare.diff").read_text(encoding="utf-8")
    assert set(re.findall(r"^[<>] (\S+) ", diff, re.MULTILINE)) == {"release-provenance.json"}


# -- the built image -----------------------------------------------------------------------------


def release_image() -> str:
    image = os.environ.get(IMAGE_VARIABLE, "")
    if not image:
        pytest.skip(f"set {IMAGE_VARIABLE} to a built release image (docker/release/validate.sh)")
    assert shutil.which("docker"), f"{IMAGE_VARIABLE} is set but docker is not on PATH"
    return image


def docker_run(image: str, *words: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", "run", "--rm", "--init", "--network", "none", image, *words],
        capture_output=True,
        text=True,
        check=False,
        timeout=600,
    )


@pytest.mark.slow
@pytest.mark.image
def test_the_image_passes_its_selfcheck() -> None:
    result = docker_run(release_image(), "selfcheck")
    assert result.returncode == 0, result.stdout + result.stderr
    assert "FAIL" not in result.stdout
    assert re.search(r"(\d+) of \1 checks hold", result.stdout), result.stdout


@pytest.mark.slow
@pytest.mark.image
def test_the_image_prints_its_help() -> None:
    for words in (["help"], []):
        result = docker_run(release_image(), *words)
        assert result.returncode == 0, result.stderr
        assert result.stdout == entry.usage() + "\n"
        assert result.stderr == ""


@pytest.mark.slow
@pytest.mark.image
def test_the_image_records_its_provenance() -> None:
    result = docker_run(release_image(), "provenance")
    assert result.returncode == 0, result.stderr
    document = json.loads(result.stdout)
    for name in (
        "artifacts.json",
        "formulas.json",
        "installed.json",
        "release-provenance.json",
        "tools.json",
        "image-packages.txt",
        "requirements.txt",
        "cubeproof-look.provenance.json",
    ):
        assert name in document, name
    assert document["artifacts.json"]["reproducible"] == ["wheels", "source"]
    assert len(document["formulas.json"]["formulas"]) == 59
    assert set(document["installed.json"]) == set(entry.DISTRIBUTIONS)
    # the build environment, not the host that built the image: no kernel release
    release = document["release-provenance.json"]
    assert release["platform"] == "linux-x86_64"
    assert release["libc"].startswith("glibc ")
    assert "machine" not in release
    kernel = subprocess.run(["uname", "-r"], capture_output=True, text=True, check=True).stdout
    assert kernel.strip() and kernel.strip() not in json.dumps(release)


@pytest.mark.slow
@pytest.mark.image
def test_the_image_imports_only_installed_code_and_refuses_root_volume_owners() -> None:
    image = release_image()
    found = subprocess.run(
        ["docker", "run", "--rm", "--network", "none", "-e", "PYTHONPATH=/work", "-w", "/work",
         "--entrypoint", "/opt/faces12/venv/bin/python", image, "-c",
         "import cubeproof, faces12_campaign, neighbourly, sys; "
         "print(cubeproof.__file__, faces12_campaign.__file__, neighbourly.__file__)"],
        capture_output=True, text=True, check=True, timeout=120,
    ).stdout.split()  # fmt: skip
    assert all(path.startswith("/opt/faces12/venv/lib/") for path in found), found
    refused = docker_run(image, "init-volumes", "1000:1000")
    assert refused.returncode == 3 and "runs as root" in refused.stderr
    as_root = subprocess.run(
        ["docker", "run", "--rm", "--network", "none", "--user", "0:0", image,
         "init-volumes", "0:0"],
        capture_output=True, text=True, check=False, timeout=120,
    )  # fmt: skip
    assert as_root.returncode == 3 and "UID 0 is refused" in as_root.stderr
