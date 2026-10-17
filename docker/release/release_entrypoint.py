"""The entry point of the release image (specification §14).

    docker run --rm --init --network none IMAGE [MODE | COMMAND] [ARGS...]

The modes and what a user needs to know about them are ``HELP`` below, the text the mode
``help`` prints (also without arguments). It is plain text for a terminal: keep markup and
notes about the build out of it, and keep one line per mode.

Notes for developers:

* The tools are configured explicitly, never searched: ``INJECT`` names the commands that get
  ``--solver``, ``--checker`` and ``--helper`` with the paths of ``TOOL_PATHS`` unless the
  arguments already name them.
* Every Python process starts isolated (``-I``), so neither ``PYTHONPATH`` nor the working
  directory can put other code in front of the installed packages.
* The mode ``record`` is used only by the image build (``docker/release/Dockerfile``) and is
  not listed in the help: it writes the records that a second build must reproduce.
* Standard library only, except ``example-campaign``, which imports the installed
  ``cubeproof`` when it runs, and ``selfcheck``, which reads the pinned tool hashes of the
  installed ``faces12_campaign.pins`` inside one check (so that a broken installation still
  reaches ``selfcheck`` and ``provenance``, and fails that check without ending the others).
"""

from __future__ import annotations

import hashlib
import importlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, replace
from importlib import metadata
from pathlib import Path
from typing import Any, NoReturn

PREFIX = Path("/opt/faces12")
PROVENANCE = PREFIX / "provenance"
TOOL_PATHS: Mapping[str, Path] = {
    "solver": PREFIX / "bin" / "cadical",
    "checker": PREFIX / "bin" / "cake_lpr",
    "helper": PREFIX / "bin" / "cubeproof-look",
}
HELPER_RECORD = PREFIX / "bin" / "cubeproof-look.provenance.json"
HELPER_VERSION = "cubeproof-look 1 lookahead-v1"
VOLUMES = (Path("/work/results"), Path("/work/scratch"))
#: The three distributions of the release (specification §2.1) and their import names.
DISTRIBUTIONS: Mapping[str, str] = {
    "cubeproof": "cubeproof",
    "neighbourly": "neighbourly",
    "faces12-campaign": "faces12_campaign",
}
PROGRAMS: Mapping[str, str] = {"cubeproof": "cubeproof", "faces12-campaign": "faces12_campaign"}
#: Which tools each command needs, by program and command words.
INJECT: Mapping[tuple[str, tuple[str, ...]], tuple[str, ...]] = {
    ("faces12-campaign", ("run",)): ("solver", "checker", "helper"),
    ("faces12-campaign", ("audit",)): ("solver", "checker", "helper"),
    ("faces12-campaign", ("campaign", "init")): ("solver", "checker"),
    ("cubeproof", ("run",)): ("solver", "checker", "helper"),
    ("cubeproof", ("audit",)): ("solver", "checker", "helper"),
    ("cubeproof", ("campaign", "create")): ("solver", "checker"),
    ("cubeproof", ("verify-retained",)): ("checker",),
}
CHECKER_SUCCESS = b"s VERIFIED UNSAT\n"
SOLVER_ARGV = ("-q", "--lrat")
BUILTIN = (
    "selfcheck",
    "provenance",
    "init-volumes",
    "capacity",
    "backup-results",
    "restore-results",
    "example-campaign",
    "record",
    "shell",
)


#: What ``help`` prints: plain text, one line per mode. A test compares it with ``MODES``.
HELP = """\
The release image of faces12-campaign: the three packages installed, with the pinned
CaDiCaL, cake_lpr and lookahead helper.

Usage:
  docker run --rm --init --network none IMAGE [COMMAND] [ARGUMENTS...]

Commands of the image:
  help                        print this text (also without a command)
  selfcheck                   check the installed tools, the packages and the volumes
  provenance                  print the build records of the image as one JSON document
  init-volumes UID:GID        as root, once: give the empty results and work volumes to UID:GID
  capacity                    print size and free space of the volumes and the container layer
  backup-results DIR NAME     archive /work/results as DIR/NAME with DIR/NAME.sha256
  restore-results ARCHIVE     fill the empty /work/results from ARCHIVE and ARCHIVE.sha256
  example-campaign DIR        write a small example campaign into the empty directory DIR
  shell                       start bash

Programs:
  cubeproof ARGUMENTS         the cubeproof command line; "cubeproof -h" lists its commands
  faces12-campaign ARGUMENTS  the faces12-campaign command line
  ARGUMENTS                   anything else is given to faces12-campaign: "run ...", "--help"

The commands that run the solver, the checker or the lookahead helper are given
  --solver /opt/faces12/bin/cadical --checker /opt/faces12/bin/cake_lpr
  --helper /opt/faces12/bin/cubeproof-look
unless the arguments name them. Nothing is looked up on PATH.

init-volumes changes a volume only while it is empty. example-campaign accepts
--holes N (2 to 14, default 10) and --leaf-ms MS (at least 100, default 1000); its
campaign is a pigeonhole formula for trying the wrapper, not a campaign of the article.

Exit status: that of the program. Of a command of the image: 0 success, 3 a usage error
or a refusal, 4 a failed check, 5 an input or output failure.

The procedures are in docs/RUNNING.md, docs/RELEASE.md and docs/AUDITING.md of the source.
"""


class UsageError(Exception):
    """A mode was called with arguments it does not accept."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def given(words: Sequence[str], option: str) -> bool:
    """Whether ``option`` (e.g. ``--solver``) appears as an option of ``words``.

    ``--solver-argv`` is not ``--solver``; ``--solver=PATH`` is. Words after ``--`` are not
    options.
    """
    for word in words:
        if word == "--":
            return False
        if word == option or word.startswith(option + "="):
            return True
    return False


def with_tools(
    program: str, words: Sequence[str], tools: Mapping[str, Path] = TOOL_PATHS
) -> list[str]:
    """``words`` with the explicit tool options the command needs, right after its name."""
    for (name, command), needed in INJECT.items():
        if name != program or tuple(words[: len(command)]) != command:
            continue
        added: list[str] = []
        for tool in needed:
            if not given(words, f"--{tool}"):
                added += [f"--{tool}", str(tools[tool])]
        return [*command, *added, *words[len(command) :]]
    return list(words)


def python_command(program: str, words: Sequence[str]) -> list[str]:
    """The isolated interpreter command of one program."""
    return [sys.executable, "-I", "-m", PROGRAMS[program], *with_tools(program, words)]


def resolve(argv: Sequence[str]) -> tuple[str, list[str]]:
    """``(mode, arguments)``: a built-in mode, or ``exec`` with the command to run."""
    if not argv or argv[0] == "help":
        return "help", []
    first, rest = argv[0], list(argv[1:])
    if first in BUILTIN:
        return first, rest
    if first in PROGRAMS:
        return "exec", python_command(first, rest)
    return "exec", python_command("faces12-campaign", list(argv))


# -- volumes -------------------------------------------------------------------------------------


def parse_owner(text: str) -> tuple[int, int]:
    parts = text.split(":")
    if len(parts) != 2 or not all(p.isdigit() for p in parts):
        raise UsageError(f"expected UID:GID, got {text!r}")
    uid, gid = int(parts[0]), int(parts[1])
    if uid == 0:
        raise UsageError("the volumes are given to a non-root user; UID 0 is refused")
    return uid, gid


@dataclass(frozen=True)
class VolumeAction:
    path: Path
    action: str  # "keep" | "chown" | "refuse"
    detail: str


def plan_volume(path: Path, uid: int, gid: int) -> VolumeAction:
    """What ``init-volumes`` does with one mount point: ownership changes only while empty."""
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return VolumeAction(path, "refuse", "does not exist (is the volume mounted?)")
    if not stat.S_ISDIR(info.st_mode):
        return VolumeAction(path, "refuse", "is not a directory")
    if (info.st_uid, info.st_gid) == (uid, gid):
        return VolumeAction(path, "keep", f"already owned by {uid}:{gid}")
    if any(os.scandir(path)):
        return VolumeAction(
            path,
            "refuse",
            f"holds files and is owned by {info.st_uid}:{info.st_gid}, not {uid}:{gid}; "
            "existing results are never re-owned (run the worker as their owner)",
        )
    return VolumeAction(path, "chown", f"empty; owner {info.st_uid}:{info.st_gid} -> {uid}:{gid}")


def init_volumes(arguments: Sequence[str], volumes: Sequence[Path] = VOLUMES) -> int:
    if len(arguments) != 1:
        raise UsageError("init-volumes UID:GID")
    uid, gid = parse_owner(arguments[0])
    actions = [plan_volume(path, uid, gid) for path in volumes]
    for action in actions:
        print(f"{action.path}: {action.action}: {action.detail}")
    if any(a.action == "refuse" for a in actions):
        return 3
    for action in actions:
        if action.action == "chown":
            os.chown(action.path, uid, gid)
            os.chmod(action.path, 0o750)
    return 0


# -- records -------------------------------------------------------------------------------------


def installed_files() -> dict[str, dict[str, str]]:
    """SHA-256 of every installed file of the three distributions, by distribution and path."""
    result: dict[str, dict[str, str]] = {}
    for name in DISTRIBUTIONS:
        distribution = metadata.distribution(name)
        files: dict[str, str] = {}
        for entry in distribution.files or []:
            if "__pycache__" in entry.parts or entry.suffix == ".pyc":
                continue
            located = Path(str(distribution.locate_file(entry)))
            files[entry.as_posix()] = sha256_file(located)
        result[name] = dict(sorted(files.items()))
    return result


def module_locations(env: Mapping[str, str] | None = None, cwd: str | None = None) -> Any:
    """Where an isolated interpreter imports the three packages from."""
    code = (
        "import importlib, json, sys\n"
        f"names = {sorted(DISTRIBUTIONS.values())!r}\n"
        "print(json.dumps({'prefix': sys.prefix, 'files': "
        "{n: importlib.import_module(n).__file__ for n in names}}))\n"
    )
    result = subprocess.run(
        [sys.executable, "-I", "-c", code],
        capture_output=True,
        text=True,
        check=True,
        env=None if env is None else dict(env),
        cwd=cwd,
    )
    return json.loads(result.stdout)


def last_json_line(text: str) -> Any:
    lines = [line for line in text.splitlines() if line.strip()]
    if not lines:
        raise ValueError("no output")
    return json.loads(lines[-1])


def application(arguments: Sequence[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        python_command("faces12-campaign", arguments), capture_output=True, text=True, check=False
    )


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def binary_problems() -> list[str]:
    """Differences between the tool binaries and their build records."""
    problems: list[str] = []
    record = json.loads((PROVENANCE / "tools.json").read_text(encoding="utf-8"))
    for name, path in (("cadical", TOOL_PATHS["solver"]), ("cake_lpr", TOOL_PATHS["checker"])):
        expected = record["tools"][name]["sha256"]
        if not path.is_file() or sha256_file(path) != expected:
            problems.append(f"{path}: not the binary recorded in tools.json")
    helper = TOOL_PATHS["helper"]
    build = json.loads(HELPER_RECORD.read_text(encoding="utf-8"))
    if build.get("format") != "cubeproof-look-build-1":
        problems.append(f"{HELPER_RECORD}: not a cubeproof-look-build-1 record")
    if not helper.is_file() or sha256_file(helper) != build.get("binary_sha256"):
        problems.append(f"{helper}: not the binary its build record describes")
    return problems


def release_pin_problems() -> list[str]:
    """Differences between the tool binaries and the hashes the application pins.

    ``faces12_campaign.pins`` records the cake_lpr and CaDiCaL of the release; ``campaign init``
    and the claim gate compare a campaign with them. A build that produces other bytes is not
    this release's tools, whatever its own build record says.
    """
    try:
        pins = importlib.import_module("faces12_campaign.pins")
        expected = {"checker": pins.RELEASE_CHECKER_SHA256, "solver": pins.RELEASE_SOLVER_SHA256}
    except Exception as error:  # a broken installation is a failed check, not a traceback
        return [f"faces12_campaign.pins cannot be read: {type(error).__name__}: {error}"]
    problems = []
    for name, sha in expected.items():
        path = TOOL_PATHS[name]
        found = sha256_file(path) if path.is_file() else "missing"
        if found != sha:
            problems.append(f"{path}: {found}, the release pins {sha}")
    return problems


def record(arguments: Sequence[str]) -> int:
    """Build time: write the records a second build must reproduce (validate.sh compares)."""
    if arguments:
        raise UsageError("record takes no arguments")
    problems = binary_problems()
    if problems:
        print("\n".join(problems), file=sys.stderr)
        return 4
    formulas = application(["formulas", "--check"])
    if formulas.returncode != 0:
        sys.stderr.write(formulas.stdout + formulas.stderr)
        return 4
    write_json(PROVENANCE / "formulas.json", last_json_line(formulas.stdout))
    write_json(PROVENANCE / "installed.json", installed_files())
    provenance = application(
        [
            "release", "provenance",
            "--solver", str(TOOL_PATHS["solver"]),
            "--checker", str(TOOL_PATHS["checker"]),
        ]
    )  # fmt: skip
    if provenance.returncode != 0:
        sys.stderr.write(provenance.stdout + provenance.stderr)
        return 4
    write_json(PROVENANCE / "release-provenance.json", last_json_line(provenance.stdout))
    print(f"records written to {PROVENANCE}")
    return 0


def provenance(arguments: Sequence[str]) -> int:
    if arguments:
        raise UsageError("provenance takes no arguments")
    document: dict[str, Any] = {}
    for path in sorted(PROVENANCE.iterdir()):
        text = path.read_text(encoding="utf-8")
        document[path.name] = json.loads(text) if path.suffix == ".json" else text.splitlines()
    document[HELPER_RECORD.name] = json.loads(HELPER_RECORD.read_text(encoding="utf-8"))
    print(json.dumps(document, indent=2, sort_keys=True))
    return 0


# -- selfcheck -----------------------------------------------------------------------------------


def pigeonhole(holes: int) -> bytes:
    """DIMACS of ``holes + 1`` pigeons in ``holes`` holes (unsatisfiable)."""

    def var(pigeon: int, hole: int) -> int:
        return pigeon * holes + hole + 1

    pigeons = holes + 1
    clauses = [[var(p, h) for h in range(holes)] for p in range(pigeons)]
    for h in range(holes):
        for p in range(pigeons):
            for q in range(p + 1, pigeons):
                clauses.append([-var(p, h), -var(q, h)])
    lines = [f"p cnf {pigeons * holes} {len(clauses)}"]
    lines += [" ".join(map(str, clause)) + " 0" for clause in clauses]
    return ("\n".join(lines) + "\n").encode()


def tiny_proof(work: Path) -> str | None:
    """Solve and check a small unsatisfiable formula; None if both tools agree it is UNSAT."""
    formula = work / "php.cnf"
    proof = work / "php.lrat"
    formula.write_bytes(pigeonhole(4))
    solver = subprocess.run(
        [str(TOOL_PATHS["solver"]), *SOLVER_ARGV, str(formula), str(proof)],
        capture_output=True,
        timeout=120,
        check=False,
    )
    if solver.returncode != 20:
        return f"cadical exited {solver.returncode}, not 20"
    checker = subprocess.run(
        [str(TOOL_PATHS["checker"]), str(formula), str(proof)],
        capture_output=True,
        timeout=120,
        check=False,
    )
    if checker.returncode != 0 or checker.stdout != CHECKER_SUCCESS:
        return f"cake_lpr exited {checker.returncode} with {checker.stdout[:80]!r}"
    return None


def selfcheck_results() -> list[tuple[str, bool, str]]:
    checks: list[tuple[str, bool, str]] = []

    def check(name: str, ok: bool, detail: str = "") -> None:
        checks.append((name, ok, detail))

    check("runs as a non-root user", os.geteuid() != 0, f"uid {os.geteuid()}")
    check("PYTHONPATH is not set", "PYTHONPATH" not in os.environ, os.environ.get("PYTHONPATH", ""))
    problems = binary_problems()
    check("tools and helper match their build records", not problems, "; ".join(problems))
    foreign = release_pin_problems()
    check(
        "cake_lpr and cadical are the binaries this release pins", not foreign, "; ".join(foreign)
    )
    version = subprocess.run(
        [str(TOOL_PATHS["helper"]), "--version"], capture_output=True, text=True, check=False
    )
    check(
        "the helper reports its protocol", version.stdout.strip() == HELPER_VERSION, version.stdout
    )
    recorded = json.loads((PROVENANCE / "installed.json").read_text(encoding="utf-8"))
    check("installed files match the recorded hashes", installed_files() == recorded)
    polluted = {**os.environ, "PYTHONPATH": "/work:/io:/tmp"}
    found = module_locations(polluted, cwd=tempfile.gettempdir())
    prefix = Path(found["prefix"]).resolve()
    outside = [n for n, f in found["files"].items() if prefix not in Path(f).resolve().parents]
    check("packages import from the installation only", not outside, ", ".join(outside))
    selftest = application(["selftest"])
    check("faces12-campaign selftest", selftest.returncode == 0, selftest.stdout[-400:])
    with tempfile.TemporaryDirectory(prefix="selfcheck-") as name:
        failure = tiny_proof(Path(name))
    check("cadical and cake_lpr refute a pigeonhole formula", failure is None, failure or "")
    for volume in VOLUMES:
        usable = volume.is_dir() and os.access(volume, os.W_OK | os.X_OK)
        check(f"{volume} is writable by this user", usable, "run init-volumes first")
    return checks


def selfcheck(arguments: Sequence[str]) -> int:
    if arguments:
        raise UsageError("selfcheck takes no arguments")
    checks = selfcheck_results()
    for name, ok, detail in checks:
        shown = f" ({detail.strip()[:200]})" if detail.strip() and not ok else ""
        print(f"{'ok  ' if ok else 'FAIL'} {name}{shown}")
    failed = sum(1 for _, ok, _ in checks if not ok)
    print(f"{len(checks) - failed} of {len(checks)} checks hold")
    return 4 if failed else 0


# -- capacity ------------------------------------------------------------------------------------


def mount_capacity(path: Path) -> dict[str, Any]:
    """Size and free space of the filesystem holding ``path`` (as this user sees it)."""
    info = os.stat(path)
    fs = os.statvfs(path)
    return {
        "path": str(path),
        "device": info.st_dev,
        "total_bytes": fs.f_blocks * fs.f_frsize,
        "free_bytes": fs.f_bavail * fs.f_frsize,
    }


def shared_groups(mounts: Sequence[Mapping[str, Any]]) -> list[list[str]]:
    """Mount paths joined transitively by an equal device or an equal total size.

    Each group has at least two paths; groups and their paths keep the order of ``mounts``.
    """
    group_of = list(range(len(mounts)))

    def find(index: int) -> int:
        while group_of[index] != index:
            index = group_of[index]
        return index

    for i, first in enumerate(mounts):
        for j in range(i + 1, len(mounts)):
            second = mounts[j]
            if first["device"] == second["device"] or first["total_bytes"] == second["total_bytes"]:
                group_of[find(j)] = find(i)
    groups: dict[int, list[str]] = {}
    for index, mount in enumerate(mounts):
        groups.setdefault(find(index), []).append(str(mount["path"]))
    return [paths for paths in groups.values() if len(paths) > 1]


def capacity_report(paths: Sequence[Path]) -> dict[str, Any]:
    """The mounts, and groups of mounts that are one filesystem or report the same figures.

    Equal devices are certainly one filesystem. Different devices with the same total size
    usually still share one disk (Docker's named volumes and the container layer live in the
    same data root unless configured otherwise), so they are grouped as well: budgets must
    count them once, not once per mount (specification §14).
    """
    mounts = [mount_capacity(path) for path in paths]
    return {
        "mounts": mounts,
        "shared": shared_groups(mounts),
        "note": (
            "mounts listed together in 'shared' draw on one capacity: give --disk for all of "
            "them together, and keep room for the container layer and the image"
        ),
    }


def capacity(arguments: Sequence[str]) -> int:
    if arguments:
        raise UsageError("capacity takes no arguments")
    present = [path for path in (*VOLUMES, Path("/")) if path.is_dir()]
    print(json.dumps(capacity_report(present), indent=2, sort_keys=True))
    return 0


# -- backup and restore of the results volume ----------------------------------------------------

ARCHIVE_ROOT = "results"
SAFE_NAME = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-"


def checksum_line(path: Path) -> str:
    return f"{sha256_file(path)}  {path.name}\n"


def backup_results(arguments: Sequence[str], results: Path = VOLUMES[0]) -> int:
    """``backup-results DIR NAME``: ``DIR/NAME`` (tar of the results) and ``DIR/NAME.sha256``.

    Run it on a stopped worker (the wrapper refuses a running one). Existing files are never
    replaced; the archive is written under a temporary name and renamed when complete.
    """
    if len(arguments) != 2:
        raise UsageError("backup-results DIR NAME")
    directory, name = Path(arguments[0]), arguments[1]
    if not name or name.startswith(".") or any(c not in SAFE_NAME for c in name):
        raise UsageError(f"backup-results: unsafe archive name {name!r}")
    target, digest = directory / name, directory / (name + ".sha256")
    if target.exists() or digest.exists():
        raise UsageError(f"{target} or its .sha256 exists; nothing is replaced")
    partial = directory / (name + ".partial")
    with tarfile.open(partial, "x", format=tarfile.PAX_FORMAT) as archive:
        archive.add(results, arcname=ARCHIVE_ROOT, recursive=True)
    with open(partial, "rb+") as stream:
        os.fsync(stream.fileno())
    os.rename(partial, target)
    digest.write_text(checksum_line(target), encoding="utf-8")
    print(checksum_line(target), end="")
    return 0


def restore_problems(members: Sequence[Any]) -> list[str]:
    """Why an archive may not be restored: only ``results/...`` regular files and directories."""
    problems: list[str] = []
    for member in members:
        parts = member.name.split("/")
        if parts[0] != ARCHIVE_ROOT or any(p in ("", ".", "..") for p in parts):
            problems.append(f"{member.name!r}: not a plain path below {ARCHIVE_ROOT}/")
        elif not (member.isfile() or member.isdir()):
            problems.append(f"{member.name!r}: only regular files and directories are restored")
    return problems


def restore_results(arguments: Sequence[str], results: Path = VOLUMES[0]) -> int:
    """``restore-results ARCHIVE``: fill the EMPTY results directory from a verified backup."""
    if len(arguments) != 1:
        raise UsageError("restore-results ARCHIVE")
    archive_path = Path(arguments[0])
    digest = archive_path.with_name(archive_path.name + ".sha256")
    if not digest.is_file():
        raise UsageError(f"{digest} is missing: a backup is restored only with its checksum")
    if digest.read_text(encoding="utf-8") != checksum_line(archive_path):
        print(f"error: {archive_path} does not match {digest}", file=sys.stderr)
        return 4
    if any(results.iterdir()):
        raise UsageError(f"{results} is not empty; a backup is restored only into an empty volume")
    with tarfile.open(archive_path, "r") as archive:
        members = archive.getmembers()
        problems = restore_problems(members)
        if problems:
            print("\n".join(problems), file=sys.stderr)
            return 4
        for member in sorted(members, key=lambda m: m.name):
            relative = member.name.split("/", 1)[1] if "/" in member.name else ""
            path = results / relative if relative else results
            if member.isdir():
                path.mkdir(parents=True, exist_ok=True)
                continue
            path.parent.mkdir(parents=True, exist_ok=True)
            source = archive.extractfile(member)
            if source is None:
                raise UsageError(f"{member.name}: cannot be read")
            with source, open(path, "xb") as sink:
                shutil.copyfileobj(source, sink)
                sink.flush()
                os.fsync(sink.fileno())
            os.chmod(path, member.mode & 0o755)
            os.utime(path, (member.mtime, member.mtime))
    print(f"restored {len(members)} entries from {archive_path.name} into {results}")
    return 0


# -- example campaign ----------------------------------------------------------------------------

EXAMPLE_HOLES = 10
EXAMPLE_LEAF_MS = 1_000
MIB = 1 << 20
GIB = 1 << 30


def example_policy(leaf_ms: int) -> dict[str, Any]:
    """The transient default policy with real-tool limits for a tiny formula."""
    from cubeproof.contracts.policy import default_policy  # noqa: PLC0415 - see the docstring

    base = default_policy("transient")
    policy = replace(
        base,
        leaf_time_ms={"default": leaf_ms},
        proof_cap_bytes=256 * MIB,
        solver_memory_bytes=1 * GIB,
        checker_stack_mib=256,
        checker_max_stack_mib=2048,
        checker_slack_mib=256,
        checker_time_base_ms=120_000,
        term_grace_ms=2_000,
        stop_grace_ms=5_000,
        split=replace(base.split, vars=2, wall_ms=60_000),
    )
    document: dict[str, Any] = policy.to_json()
    return document


def parse_example(arguments: Sequence[str]) -> tuple[Path, int, int]:
    words = list(arguments)
    if not words or words[0].startswith("-"):
        raise UsageError("example-campaign DIR [--holes N] [--leaf-ms MS]")
    target = Path(words.pop(0))
    values = {"--holes": EXAMPLE_HOLES, "--leaf-ms": EXAMPLE_LEAF_MS}
    while words:
        option = words.pop(0)
        if option not in values or not words or not words[0].isdigit():
            raise UsageError(f"example-campaign: unexpected {option!r}")
        values[option] = int(words.pop(0))
    if not 2 <= values["--holes"] <= 14 or values["--leaf-ms"] < 100:
        raise UsageError("example-campaign: --holes 2..14 and --leaf-ms >= 100")
    return target, values["--holes"], values["--leaf-ms"]


def example_campaign(arguments: Sequence[str]) -> int:
    """Write ``DIR/campaign.json`` with one pigeonhole bundle and the image's tools admitted."""
    from cubeproof.base.canonical_json import document_bytes  # noqa: PLC0415 - see the docstring

    target, holes, leaf_ms = parse_example(arguments)
    if target.exists() and (not target.is_dir() or any(target.iterdir())):
        raise UsageError(f"{target} exists and is not an empty directory")
    inputs = target / "inputs"
    inputs.mkdir(parents=True)
    formula = inputs / f"php{holes}.cnf"
    formula.write_bytes(pigeonhole(holes))
    policy = inputs / "policy.json"
    admit = inputs / "admit.json"
    # cubeproof reads canonical documents only: J(x) and one LF (specification §4.1)
    policy.write_bytes(document_bytes(example_policy(leaf_ms)))
    admit.write_bytes(
        document_bytes(
            {
                "checker_sha256": [sha256_file(TOOL_PATHS["checker"])],
                "solvers": [
                    {"sha256": sha256_file(TOOL_PATHS["solver"]), "argv": list(SOLVER_ARGV)}
                ],
            }
        )
    )
    bundle = target / "bundles" / f"php{holes}"
    steps = [
        ["bundle", "import", str(formula), "-o", str(bundle)],
        [
            "campaign", "create", "--bundle", str(bundle),
            "--policy", str(policy), "--admit", str(admit),
            "--solver-argv", json.dumps(list(SOLVER_ARGV)),
            "--author", "faces12-campaign example", "-o", str(target / "campaign.json"),
        ],
    ]  # fmt: skip
    for words in steps:
        done = subprocess.run(
            python_command("cubeproof", words), capture_output=True, text=True, check=False
        )
        if done.returncode != 0:
            sys.stderr.write(done.stdout + done.stderr)
            return done.returncode or 1
    print(f"example campaign: {target / 'campaign.json'} (pigeonhole {holes}, leaf {leaf_ms} ms)")
    return 0


# -- main ----------------------------------------------------------------------------------------


def usage() -> str:
    """The text of ``help``."""
    return HELP.rstrip("\n")


def exec_command(command: Sequence[str]) -> NoReturn:
    os.execv(command[0], list(command))


def help_mode(arguments: Sequence[str]) -> int:
    print(usage())
    return 0


def init_volumes_as_root(arguments: Sequence[str]) -> int:
    if os.geteuid() != 0:
        raise UsageError("init-volumes runs as root (docker run --user 0:0 ...)")
    return init_volumes(arguments)


def shell(arguments: Sequence[str]) -> int:
    exec_command(["/bin/bash", *arguments])


MODES: Mapping[str, Callable[[Sequence[str]], int]] = {
    "help": help_mode,
    "selfcheck": selfcheck,
    "provenance": provenance,
    "init-volumes": init_volumes_as_root,
    "capacity": capacity,
    "backup-results": backup_results,
    "restore-results": restore_results,
    "example-campaign": example_campaign,
    "record": record,
    "shell": shell,
}


def main(argv: Sequence[str] | None = None) -> int:
    """Exit codes: those of the command; 3 a usage error; 5 an I/O failure of a mode."""
    words = list(sys.argv[1:] if argv is None else argv)
    mode, arguments = resolve(words)
    if mode == "exec":
        exec_command(arguments)
    try:
        return MODES[mode](arguments)
    except UsageError as error:
        print(f"error: {error}", file=sys.stderr)
        return 3
    except OSError as error:
        print(f"error: {error}", file=sys.stderr)
        return 5


if __name__ == "__main__":
    sys.exit(main())
