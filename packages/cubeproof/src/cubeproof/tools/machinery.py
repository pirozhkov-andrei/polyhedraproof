"""The measured machinery of a header/resume record (specification §4.6; writer.machinery).

``snapshot`` assembles the Machinery JSON object from measured values: the pinned solver
(resolved path, SHA-256 of the actual regular file, ``--version`` output, checked argv), the
pinned checker, the optional splitter helper, the runtime and the source manifest.

Source manifest: every regular file of the given installed package directories, as
``<package>/<relative path>`` (RelPath), sorted by that string, excluding bytecode
(``__pycache__``, ``*.pyc``, ``*.pyo``). Symlinks and other non-regular entries are refused:
the manifest must identify actual files. ``packages_sha256`` = SHA256(J(manifest)),
``cubeproof_sha256`` = SHA256(J(entries whose first component is ``cubeproof``)).
Sources must not change during a run: :func:`verify_manifest` re-measures them.
"""

from __future__ import annotations

import importlib.util
import os
import platform
import stat
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from cubeproof.base.canonical_json import json_sha256
from cubeproof.base.errors import ToolError
from cubeproof.contracts.primitives import is_hash, is_name, is_relpath
from cubeproof.tools.isolation import PinnedBinary, file_sha256
from cubeproof.tools.process import Supervisor
from cubeproof.tools.solver import check_argv, probe_version

UNIT_ALGORITHM = "unit-v1"
_EXCLUDED_DIRS = frozenset({"__pycache__"})
_EXCLUDED_SUFFIXES = (".pyc", ".pyo")

ManifestEntry = dict[str, str]


def package_root(name: str) -> Path:
    """The directory of an importable (installed or source) package."""
    spec = importlib.util.find_spec(name)
    if spec is None or not spec.submodule_search_locations:
        raise ToolError("machinery.package", f"package {name!r} is not importable")
    locations = list(spec.submodule_search_locations)
    if len(locations) != 1:
        raise ToolError("machinery.package", f"package {name!r} has locations {locations}")
    return Path(locations[0])


def _unlistable(error: OSError) -> None:
    # os.walk skips unreadable directories silently; the manifest must not.
    raise ToolError("machinery.source", f"cannot list {error.filename}: {error.strerror}")


def _walk(name: str, root: Path) -> list[ManifestEntry]:
    entries: list[ManifestEntry] = []
    for directory, subdirs, files in os.walk(root, onerror=_unlistable, followlinks=False):
        subdirs[:] = sorted(d for d in subdirs if d not in _EXCLUDED_DIRS)
        base = Path(directory)
        for entry in (*subdirs, *files):
            if (base / entry).is_symlink():
                raise ToolError("machinery.source", f"{base / entry} is a symbolic link")
        for file in sorted(files):
            if file.endswith(_EXCLUDED_SUFFIXES):
                continue
            path = base / file
            if not stat.S_ISREG(os.lstat(path).st_mode):
                raise ToolError("machinery.source", f"{path} is not a regular file")
            relative = "/".join((name, *path.relative_to(root).parts))
            if not is_relpath(relative):
                raise ToolError("machinery.source", f"{relative!r} is not a RelPath")
            digest = file_sha256(str(path))
            if digest is None:
                raise ToolError("machinery.source", f"{path} cannot be read")
            entries.append({"path": relative, "sha256": digest})
    return entries


def source_manifest(packages: Mapping[str, Path]) -> tuple[ManifestEntry, ...]:
    """The sorted manifest of the package directories ``{package name: directory}``."""
    entries: list[ManifestEntry] = []
    for name, root in packages.items():
        if not is_name(name.replace("_", "-")) or "/" in name or name.startswith("."):
            raise ToolError("machinery.package", f"{name!r} is not a package name")
        if not Path(root).is_dir():
            raise ToolError("machinery.package", f"{root} is not a directory")
        entries += _walk(name, Path(root))
    entries.sort(key=lambda entry: entry["path"])
    paths = [entry["path"] for entry in entries]
    if len(set(paths)) != len(paths):
        raise ToolError("machinery.source", "two packages provide the same path")
    return tuple(entries)


def manifest_digests(manifest: Sequence[ManifestEntry]) -> tuple[str, str]:
    """``(packages_sha256, cubeproof_sha256)`` of a manifest."""
    own = [e for e in manifest if e["path"].split("/", 1)[0] == "cubeproof"]
    return json_sha256([dict(e) for e in manifest]), json_sha256([dict(e) for e in own])


def verify_manifest(manifest: Sequence[ManifestEntry], packages: Mapping[str, Path]) -> None:
    """ToolError ``source_changed`` unless the sources are still exactly the manifest."""
    current = source_manifest(packages)
    if list(current) != [dict(e) for e in manifest]:
        raise ToolError("source_changed", "installed sources differ from the measured manifest")


def runtime_info(*, image_digest: str | None) -> dict[str, Any]:
    """Python implementation and version, libc, platform, the release image digest or None."""
    libc_name, libc_version = platform.libc_ver()
    libc = f"{libc_name} {libc_version}".strip() or "unknown"
    return {
        "python": f"{platform.python_implementation()} {platform.python_version()}",
        "libc": libc,
        "platform": f"{platform.system()}-{platform.machine()}".lower(),
        "image_digest": image_digest,
    }


def host_cpu(cpuinfo: str = "/proc/cpuinfo") -> str:
    """The processor model of this machine as ``/proc/cpuinfo`` names it; "" if unknown.

    Recorded with every attempt (diagnostics): a proof that does not reproduce on another
    machine has to be compared with the processor that wrote it, and the journal has no other
    place that names the machine. ASCII, at most 120 characters.
    """
    try:
        with open(cpuinfo, encoding="ascii", errors="replace") as stream:
            for line in stream:
                name, _, value = line.partition(":")
                if name.strip() in ("model name", "Processor", "cpu model"):
                    printable = "".join(c for c in value if 32 <= ord(c) < 127)
                    return " ".join(printable.split())[:120].rstrip()
    except OSError:
        return ""
    return ""


def solver_version(supervisor: Supervisor, binary: PinnedBinary, cwd: str) -> str:
    """The pinned solver's ``--version`` output (first line), run isolated."""
    return probe_version(supervisor, binary, cwd)


def snapshot(
    *,
    solver: PinnedBinary,
    solver_argv: Sequence[str],
    solver_version: str,
    checker: PinnedBinary,
    helper: tuple[str, str] | None,
    manifest: Sequence[ManifestEntry],
    runtime: Mapping[str, Any],
) -> dict[str, Any]:
    """The Machinery JSON object (specification §4.6) of measured values."""
    check_argv(solver_argv)
    if helper is not None and (not is_hash(helper[0]) or not helper[1]):
        raise ValueError("helper must be (sha256, algorithm)")
    packages_sha256, cubeproof_sha256 = manifest_digests(manifest)
    return {
        "solver": {
            "path": solver.path,
            "sha256": solver.sha256,
            "version": solver_version,
            "argv": list(solver_argv),
        },
        "checker": {"path": checker.path, "sha256": checker.sha256},
        "helper": None if helper is None else {"sha256": helper[0], "algorithm": helper[1]},
        "runtime": dict(runtime),
        "source_manifest": [dict(e) for e in manifest],
        "packages_sha256": packages_sha256,
        "cubeproof_sha256": cubeproof_sha256,
        "unit_algorithm": UNIT_ALGORITHM,
    }
