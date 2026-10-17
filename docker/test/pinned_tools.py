"""Build the pinned tools of the development/test image and record its provenance.

    python3 docker/test/pinned_tools.py build --prefix DIR --work DIR [--jobs N]
    python3 docker/test/pinned_tools.py environment --output FILE
    python3 docker/test/pinned_tools.py verify --prefix DIR
    python3 docker/test/pinned_tools.py compare DIR_A DIR_B

``build`` clones CaDiCaL and cake_lpr at the commits pinned in ``docker/test/tools.json``,
verifies the cake_lpr source checksums before compiling, builds both with the manifest's build
environment (``SOURCE_DATE_EPOCH``, ``TZ``, ``LC_ALL``), runs cake_lpr's own example (exact
success line required), installs ``DIR/bin/{cadical,cake_lpr}`` and writes
``DIR/provenance/tools.json``: commits, versions, source and binary SHA-256, compilers.

``environment`` records the interpreter, platform, libc, installed Python distributions,
Debian packages and util-linux tools in a JSON file (no timestamps).

``verify`` re-hashes ``DIR/bin/*`` against ``DIR/provenance/tools.json`` and exits 1 on any
difference: the binaries a test run uses are the ones the build recorded.

``compare`` compares the provenance files of two builds (``tools.json`` and, when present in
either, ``environment.json``) and exits 1 on any difference: two clean builds of the image
must produce identical tool binaries and identical package sets (specification §14). Image
metadata and timestamps are not compared; they are not recorded.

Standard library only; runs on the build stage's system Python and on any Linux host with
git, make, gcc/g++ and network access to the two repositories.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
from collections.abc import Mapping, Sequence
from importlib import metadata
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = Path(__file__).resolve().with_name("tools.json")
MANIFEST_FORMAT = "polyhedraproof-test-tools-1"
PROVENANCE_FORMAT = "polyhedraproof-test-provenance-1"
ENVIRONMENT_FORMAT = "polyhedraproof-test-environment-1"
CHECKER_SUCCESS = b"s VERIFIED UNSAT\n"
BINARIES = ("cadical", "cake_lpr")


class BuildError(Exception):
    """A pinned input did not match or a build step failed."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def load_manifest(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.get("format") != MANIFEST_FORMAT:
        raise BuildError(f"{path}: not a {MANIFEST_FORMAT} manifest")
    return data


def build_environment(manifest: Mapping[str, Any]) -> dict[str, str]:
    """The process environment of every build step: inherited, plus the pinned variables."""
    env = dict(os.environ)
    env.update({str(k): str(v) for k, v in manifest.get("build_environment", {}).items()})
    return env


def run(
    command: Sequence[str | Path],
    cwd: Path | None = None,
    env: Mapping[str, str] | None = None,
    echo: bool = True,
) -> str:
    """Run a build command, fail loudly; return its stdout (echoed with its tail if `echo`)."""
    shown = " ".join(str(c) for c in command)
    if echo:
        print(f"+ {shown}", flush=True)
    result = subprocess.run(
        [str(c) for c in command],
        cwd=cwd,
        env=None if env is None else dict(env),
        capture_output=True,
        text=True,
        check=False,
    )
    if echo or result.returncode != 0:
        sys.stdout.write(result.stdout[-4000:])
        sys.stderr.write(result.stderr[-4000:])
    if result.returncode != 0:
        raise BuildError(f"{shown}: exit {result.returncode}")
    return result.stdout


def first_line(command: Sequence[str]) -> str | None:
    """First output line of a version query, or None when the program is absent."""
    if shutil.which(command[0]) is None:
        return None
    result = subprocess.run(list(command), capture_output=True, text=True, check=False)
    text = (result.stdout or result.stderr).strip()
    return text.splitlines()[0] if text else ""


def checkout(repository: str, commit: str, destination: Path, partial: bool) -> str:
    """Clone (or reuse) a repository at exactly `commit`, with a clean tree."""
    if not destination.exists():
        clone = ["git", "clone"] + (["--filter=blob:none"] if partial else [])
        run([*clone, repository, destination])
    run(["git", "-C", destination, "checkout", "--force", "--detach", commit])
    run(["git", "-C", destination, "clean", "-xdfq"])
    head = run(["git", "-C", destination, "rev-parse", "HEAD"]).strip()
    if head != commit:
        raise BuildError(f"{repository}: HEAD is {head}, expected {commit}")
    return head


def install_file(source: Path, target: Path, mode: int) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, target)
    target.chmod(mode)


def build_cadical(
    pin: Mapping[str, Any],
    work: Path,
    prefix: Path,
    jobs: int,
    root: Path,
    env: Mapping[str, str],
) -> dict[str, Any]:
    source = work / "cadical"
    commit = checkout(pin["repository"], pin["commit"], source, partial=False)
    run([sys.executable, root / pin["normalize"]], cwd=source, env=env)
    run(["./configure"], cwd=source, env=env)
    run(["make", f"-j{jobs}"], cwd=source, env=env)
    binary = prefix / "bin" / "cadical"
    install_file(source / "build" / "cadical", binary, 0o755)
    install_file(source / pin["license"], prefix / "licenses" / "cadical-LICENSE", 0o644)
    version = run([binary, "--version"]).strip()
    if version != pin["version"]:
        raise BuildError(f"cadical --version is {version!r}, manifest says {pin['version']!r}")
    return {
        "binary": "bin/cadical",
        "sha256": sha256_file(binary),
        "commit": commit,
        "version": version,
        "license_sha256": sha256_file(prefix / "licenses" / "cadical-LICENSE"),
    }


def build_cake_lpr(
    pin: Mapping[str, Any], work: Path, prefix: Path, env: Mapping[str, str]
) -> dict[str, Any]:
    source = work / "cake_lpr"
    commit = checkout(pin["repository"], pin["commit"], source, partial=True)
    observed = {name: sha256_file(source / name) for name in sorted(pin["sources"])}
    if observed != dict(pin["sources"]):
        raise BuildError(f"cake_lpr source checksum mismatch: {observed} != {pin['sources']}")
    run(
        [
            "gcc",
            "-O2",
            "-std=c99",
            "basis_ffi.c",
            "cake_lpr.S",
            "-o",
            "cake_lpr",
            f"-DCML_HEAP_SIZE={int(pin['heap_mb'])}",
            f"-DCML_STACK_SIZE={int(pin['stack_mb'])}",
        ],
        cwd=source,
        env=env,
    )
    smoke = subprocess.run(
        ["./cake_lpr", "example.cnf", "example.lpr"], cwd=source, capture_output=True, check=False
    )
    if smoke.returncode != 0 or smoke.stdout != CHECKER_SUCCESS:
        raise BuildError(f"cake_lpr smoke check failed: {smoke.returncode} {smoke.stdout!r}")
    binary = prefix / "bin" / "cake_lpr"
    install_file(source / "cake_lpr", binary, 0o755)
    install_file(source / pin["license"], prefix / "licenses" / "cake_lpr-LICENSE", 0o644)
    return {
        "binary": "bin/cake_lpr",
        "sha256": sha256_file(binary),
        "commit": commit,
        "sources": observed,
        "heap_mb": int(pin["heap_mb"]),
        "stack_mb": int(pin["stack_mb"]),
        "smoke": "example.cnf example.lpr: exit 0, s VERIFIED UNSAT",
        "license_sha256": sha256_file(prefix / "licenses" / "cake_lpr-LICENSE"),
    }


def build(manifest_path: Path, prefix: Path, work: Path, jobs: int, root: Path) -> Path:
    manifest = load_manifest(manifest_path)
    env = build_environment(manifest)
    prefix = prefix.resolve()
    work = work.resolve()
    work.mkdir(parents=True, exist_ok=True)
    tools = {
        "cadical": build_cadical(manifest["tools"]["cadical"], work, prefix, jobs, root, env),
        "cake_lpr": build_cake_lpr(manifest["tools"]["cake_lpr"], work, prefix, env),
    }
    record = {
        "format": PROVENANCE_FORMAT,
        "manifest_sha256": sha256_file(manifest_path),
        "manifest": manifest,
        "tools": tools,
        "build": {
            "machine": platform.machine(),
            "cc": first_line(["gcc", "--version"]),
            "cxx": first_line(["g++", "--version"]),
        },
    }
    output = prefix / "provenance" / "tools.json"
    write_json(output, record)
    print(json.dumps(tools, indent=2, sort_keys=True))
    return output


def verify(prefix: Path) -> list[str]:
    """Differences between the installed binaries and the recorded provenance."""
    record = json.loads((prefix / "provenance" / "tools.json").read_text(encoding="utf-8"))
    if record.get("format") != PROVENANCE_FORMAT:
        return [f"{prefix}/provenance/tools.json: not a {PROVENANCE_FORMAT} record"]
    problems = []
    for name in BINARIES:
        entry = record.get("tools", {}).get(name)
        if not isinstance(entry, dict):
            problems.append(f"{name}: not recorded")
            continue
        binary = prefix / entry["binary"]
        if not binary.is_file():
            problems.append(f"{name}: {binary} is missing")
        elif sha256_file(binary) != entry["sha256"]:
            problems.append(f"{name}: {binary} sha256 differs from the recorded build")
    return problems


def debian_packages() -> list[str] | None:
    if shutil.which("dpkg-query") is None:
        return None
    text = run(["dpkg-query", "-W", "-f=${Package}=${Version}\n"], echo=False)
    return sorted(line for line in text.splitlines() if line)


def environment() -> dict[str, Any]:
    distributions = sorted(
        {f"{d.metadata['Name']}=={d.version}" for d in metadata.distributions()},
        key=str.lower,
    )
    libc, libc_version = platform.libc_ver()
    return {
        "format": ENVIRONMENT_FORMAT,
        "python": {
            "implementation": platform.python_implementation(),
            "version": platform.python_version(),
            "executable": sys.executable,
        },
        "platform": {
            "system": platform.system(),
            "machine": platform.machine(),
            "libc": f"{libc} {libc_version}".strip(),
        },
        "distributions": distributions,
        "debian_packages": debian_packages(),
        "utilities": {
            name: first_line([name, "--version"]) for name in ("prlimit", "setpriv", "make")
        },
    }


def write_json(path: Path, data: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def flatten(value: Any, prefix: str = "") -> dict[str, Any]:
    """JSON value -> {dotted path: leaf}, so that differences can be listed by key."""
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for key in sorted(value):
            out.update(flatten(value[key], f"{prefix}.{key}" if prefix else str(key)))
        return out or {prefix: {}}
    if isinstance(value, list):
        out = {}
        for index, item in enumerate(value):
            out.update(flatten(item, f"{prefix}[{index}]"))
        return out or {prefix: []}
    return {prefix: value}


def compare(first: Path, second: Path) -> list[str]:
    """Differences between the provenance directories of two builds (empty: identical)."""
    problems: list[str] = []
    for name in ("tools.json", "environment.json"):
        a, b = first / name, second / name
        if not a.exists() and not b.exists() and name == "environment.json":
            continue
        if not a.exists() or not b.exists():
            problems.append(f"{name}: missing in {a.parent if not a.exists() else b.parent}")
            continue
        left = flatten(json.loads(a.read_text(encoding="utf-8")))
        right = flatten(json.loads(b.read_text(encoding="utf-8")))
        for key in sorted(set(left) | set(right)):
            shown_a = left.get(key, "<absent>")
            shown_b = right.get(key, "<absent>")
            if shown_a != shown_b:
                problems.append(f"{name}: {key}: {shown_a!r} != {shown_b!r}")
    return problems


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n\n")[0])
    commands = parser.add_subparsers(dest="command", required=True)
    build_parser = commands.add_parser("build", help="build the pinned tools")
    build_parser.add_argument("--manifest", type=Path, default=MANIFEST)
    build_parser.add_argument("--root", type=Path, default=ROOT)
    build_parser.add_argument("--prefix", type=Path, required=True)
    build_parser.add_argument("--work", type=Path, required=True)
    build_parser.add_argument("--jobs", type=int, default=4)
    environment_parser = commands.add_parser("environment", help="record the environment")
    environment_parser.add_argument("--output", type=Path, required=True)
    verify_parser = commands.add_parser("verify", help="re-hash the installed binaries")
    verify_parser.add_argument("--prefix", type=Path, required=True)
    compare_parser = commands.add_parser("compare", help="compare two provenance directories")
    compare_parser.add_argument("first", type=Path)
    compare_parser.add_argument("second", type=Path)
    args = parser.parse_args(argv)

    try:
        if args.command == "build":
            build(args.manifest, args.prefix, args.work, args.jobs, args.root)
            return 0
        if args.command == "environment":
            write_json(args.output, environment())
            return 0
        if args.command == "verify":
            problems = verify(args.prefix)
            label = "binaries"
        else:
            problems = compare(args.first, args.second)
            label = "provenance"
    except (BuildError, OSError, KeyError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    for problem in problems:
        print(problem)
    print(f"{label}: identical" if not problems else f"{label}: {len(problems)} differences")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
