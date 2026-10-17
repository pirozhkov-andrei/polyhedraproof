"""What this installation consists of, by hash (``release provenance``).

Provenance is recorded, not certified: these numbers let somebody else notice that they are
running something else. The document lists the three packages of the release (version and a
digest of their installed files), the Python runtime, the operating system with the machine
architecture, the C library, the solver and checker binaries **given explicitly** (no search
through PATH), and, for a source checkout, the SHA-256 of every file ``RELEASE_FILES.txt``
lists. The release image writes it at build time.

Nothing of the host that happens to run the interpreter is recorded: no kernel release, host
name or user. Two builds of the same image therefore record the same document, except for
``recorded_utc``.
"""

from __future__ import annotations

import hashlib
import platform
import sys
from pathlib import Path
from types import ModuleType
from typing import Any, Final

import cubeproof
import faces12_campaign
import neighbourly
from cubeproof.base.errors import ConfigurationError
from cubeproof.contracts.primitives import format_utc
from faces12_campaign.release.bundle import release_payloads

__all__ = ["FORMAT_PROVENANCE", "package_digest", "provenance_document"]

FORMAT_PROVENANCE: Final = "faces12-provenance-1"
_CHUNK: Final = 1 << 20


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(_CHUNK):
            digest.update(chunk)
    return digest.hexdigest()


def package_digest(module: ModuleType) -> dict[str, Any]:
    """Version, file count and one SHA-256 over ``path NUL sha256 LF`` of every file of an
    imported package (caches excluded)."""
    location = getattr(module, "__file__", None)
    if location is None:
        raise ConfigurationError("release.package", f"{module.__name__} has no files")
    base = Path(location).resolve().parent
    files = sorted(p for p in base.rglob("*") if p.is_file() and "__pycache__" not in p.parts)
    digest = hashlib.sha256()
    for path in files:
        digest.update(f"{path.relative_to(base).as_posix()}\0{_file_sha256(path)}\n".encode())
    return {
        "version": str(getattr(module, "__version__", "")),
        "files": len(files),
        "sha256": digest.hexdigest(),
    }


def _binary(path: Path) -> dict[str, str]:
    real = Path(path)
    if not real.is_file():
        raise ConfigurationError("release.binary", f"{real} is not a file")
    return {"path": str(real.resolve()), "sha256": _file_sha256(real.resolve())}


def _libc() -> str:
    """The C library the interpreter is linked against, e.g. ``glibc 2.36``, or ``unknown``."""
    name, version = platform.libc_ver()
    return f"{name} {version}".strip() or "unknown"


def provenance_document(
    *,
    recorded_ms: int,
    root: Path | None = None,
    solver: Path | None = None,
    checker: Path | None = None,
) -> dict[str, Any]:
    """The provenance document (module doc); ``recorded_ms`` is the time of recording."""
    binaries = {}
    if solver is not None:
        binaries["solver"] = _binary(solver)
    if checker is not None:
        binaries["checker"] = _binary(checker)
    source = None if root is None else release_payloads(Path(root))
    return {
        "format": FORMAT_PROVENANCE,
        "recorded_utc": format_utc(recorded_ms),
        "packages": {
            "cubeproof": package_digest(cubeproof),
            "neighbourly": package_digest(neighbourly),
            "faces12-campaign": package_digest(faces12_campaign),
        },
        "python": sys.version,
        "implementation": platform.python_implementation(),
        "platform": f"{platform.system()}-{platform.machine()}".lower(),
        "libc": _libc(),
        "binaries": binaries,
        "source_sha256": None
        if source is None
        else {name: hashlib.sha256(data).hexdigest() for name, data in sorted(source.items())},
    }
