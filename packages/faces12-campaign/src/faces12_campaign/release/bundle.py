"""A deterministic source archive built from an explicit allowlist (the release bundle).

What goes into the archive is ``RELEASE_FILES.txt`` of the given source root, never a
directory walk, so a stray file in a working copy cannot end up in a published package; the
archive is byte-reproducible (fixed order, modes, owners and times; gzip without a name or
time), so two people can compare its SHA-256 instead of trusting a download. The manifest
format is ``faces12-source-bundle-1``; the source root is an argument.
"""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import os
import tarfile
import tempfile
from pathlib import Path
from typing import Any, Final

from cubeproof.base.errors import ConfigurationError, InputError, IntegrityError
from faces12_campaign import __version__

__all__ = [
    "FORMAT_SOURCE_BUNDLE",
    "LISTING",
    "MANIFEST_NAME",
    "build_bundle",
    "release_payloads",
    "source_manifest",
    "verify_bundle",
]

FORMAT_SOURCE_BUNDLE: Final = "faces12-source-bundle-1"
MANIFEST_NAME: Final = "SOURCE_MANIFEST.json"
LISTING: Final = "RELEASE_FILES.txt"


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def release_payloads(root: Path) -> dict[str, bytes]:
    """Every file ``RELEASE_FILES.txt`` lists, by its POSIX path, read without following links."""
    base = Path(root)
    listing = base / LISTING
    if not listing.is_file():
        raise InputError("release.listing", f"{base} has no {LISTING}")
    names = listing.read_text(encoding="utf-8").splitlines()
    if len(names) != len(set(names)) or LISTING not in names:
        raise InputError("release.listing", f"{LISTING} lists a file twice or omits itself")
    resolved_root = base.resolve()
    payloads: dict[str, bytes] = {}
    for name in sorted(names):
        path = base / name
        if (
            not name
            or Path(name).is_absolute()
            or ".." in Path(name).parts
            or not path.resolve().is_relative_to(resolved_root)
        ):
            raise InputError("release.path", f"invalid release path: {name!r}")
        if path.is_symlink():
            raise InputError("release.path", f"release input must be a regular file: {name}")
        if not path.is_file():
            raise InputError("release.missing", f"release input is missing: {name}")
        payloads[path.relative_to(base).as_posix()] = path.read_bytes()
    return payloads


def source_manifest(payloads: dict[str, bytes], author: str = "") -> dict[str, Any]:
    """The manifest stored in the archive: format, version, author and every file's SHA-256."""
    return {
        "format": FORMAT_SOURCE_BUNDLE,
        "version": __version__,
        "author": author,
        "source_sha256": {name: _sha256(data) for name, data in payloads.items()},
    }


def _sync_directory(path: Path) -> None:
    if os.name == "nt":
        return
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def build_bundle(root: Path, destination: Path, author: str = "") -> str:
    """Write the archive ``destination`` and return its SHA-256.

    Exclusive creation: a previously cited source package is never replaced.
    """
    payloads = release_payloads(root)
    manifest = json.dumps(source_manifest(payloads, author), sort_keys=True, indent=1) + "\n"
    payloads[MANIFEST_NAME] = manifest.encode("utf-8")
    prefix = f"polyhedraproof-{__version__}"
    target = Path(destination)
    if target.exists() or target.is_symlink():
        raise ConfigurationError("release.exists", f"{target} already exists")
    target.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".bundle-", dir=target.parent) as staging:
        staged = Path(staging) / "archive.tar.gz"
        with (
            staged.open("xb") as output,
            gzip.GzipFile(filename="", mode="wb", fileobj=output, mtime=0) as compressed,
            tarfile.open(fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT) as archive,
        ):
            for name, data in sorted(payloads.items()):
                info = tarfile.TarInfo(f"{prefix}/{name}")
                info.size = len(data)
                info.mtime = 0
                info.mode = 0o644
                info.uid = info.gid = 0
                info.uname = info.gname = ""
                archive.addfile(info, io.BytesIO(data))
        with staged.open("r+b") as stream:
            os.fsync(stream.fileno())
        try:
            os.link(staged, target)
        except FileExistsError:
            raise ConfigurationError("release.exists", f"{target} already exists") from None
        _sync_directory(target.parent)
    return _sha256(target.read_bytes())


def verify_bundle(directory: Path) -> int:
    """Check an unpacked archive against its own manifest; the number of listed files."""
    base = Path(directory)
    try:
        document = json.loads((base / MANIFEST_NAME).read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise IntegrityError("release.manifest", f"{base / MANIFEST_NAME}: {error}") from None
    if not isinstance(document, dict) or document.get("format") != FORMAT_SOURCE_BUNDLE:
        raise IntegrityError("release.manifest", "unsupported source bundle manifest")
    listed = document.get("source_sha256")
    if not isinstance(listed, dict):
        raise IntegrityError("release.manifest", "the manifest has no source_sha256 object")
    actual: set[str] = set()
    for path in base.rglob("*"):
        if path.is_symlink():
            raise IntegrityError("release.symlink", f"the bundle contains a symbolic link: {path}")
        if path.is_file():
            actual.add(path.relative_to(base).as_posix())
    if actual != set(listed) | {MANIFEST_NAME}:
        raise IntegrityError("release.files", "the bundle contains missing or unlisted files")
    resolved = base.resolve()
    for name, expected in listed.items():
        path = base / name
        if not path.resolve().is_relative_to(resolved):
            raise IntegrityError("release.path", f"manifest path escapes the bundle: {name}")
        if _sha256(path.read_bytes()) != expected:
            raise IntegrityError("release.checksum", f"bundle checksum mismatch: {name}")
    return len(listed)
