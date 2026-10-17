"""``evidence package``: publish a portable evidence directory (specification §4.9, §12.1).

The command certifies the given campaign and journals, then builds ``DIR`` in a staging directory
next to it and renames it into place only when it is complete. The order is the dependency order:

1. the **immutable dependencies**: ``campaign.json`` (the campaign file's bytes), the two files of
   each bundle the campaign names (``<bundle>/manifest.json`` and ``<bundle>/formula.cnf``, at the
   campaign's own relative paths) and one snapshot per journal the certificate used,
   ``journals/<worker>.jsonl``: exactly the certified complete records, so a torn tail or records
   appended after certification are not carried. Files are fsynced and made read-only;
2. the **certificate**, recomputed from the *copied* campaign and journals (never trusted from an
   earlier run). It must equal the certificate of the original inputs except for the torn tail
   the snapshots drop; anything else is an integrity error and nothing is published;
3. the **manifest** ``evidence.json`` listing every file with its size and hash, last.

Optional side files and retained proofs travel separately (specification §4.9). The package is read
back with :func:`cubeproof.commands.evidence.load_evidence`, which verifies every listed hash.
"""

from __future__ import annotations

import copy
import os
import shutil
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cubeproof.base.canonical_json import document_bytes
from cubeproof.base.errors import ConfigurationError, IntegrityError
from cubeproof.base.ids import new_id128
from cubeproof.base.paths import open_contained
from cubeproof.base.settings import DEFAULT_LIMITS, ReaderLimits
from cubeproof.cnf.campaign import load_campaign
from cubeproof.commands.evidence import (
    CAMPAIGN_NAME,
    CERTIFICATE_NAME,
    JOURNAL_DIR,
    MANIFEST_NAME,
    BundleArtifacts,
    EvidenceManifest,
    artifact_of,
)
from cubeproof.contracts.enums import Verdict
from cubeproof.evidence.certify.run import CertifyLimits, certify_campaign

__all__ = ["PackageRequest", "PackageResult", "package_evidence"]

_CHUNK = 1 << 20


@dataclass(frozen=True)
class PackageRequest:
    """The inputs of ``evidence package`` as values."""

    campaign: Path
    journals: Sequence[Path]
    output: Path
    limits: ReaderLimits = DEFAULT_LIMITS


@dataclass(frozen=True)
class PackageResult:
    """What was published; the verdict is the certificate's (the package is written for any)."""

    output: str
    manifest: str
    #: SHA-256 of the file ``evidence.json`` as written (what ``sha256sum`` prints)
    manifest_sha256: str
    #: SHA-256 of the file ``certificate.json`` as written, the value the manifest lists. It is
    #: not the ``certificate_sha256`` of an audit, which is the document hash
    #: SHA256(J(certificate)), without the final LF (specification §4.1, §11.2).
    certificate_file_sha256: str
    campaign: str
    verdict: Verdict
    bundles: int
    journals: int
    #: input journal files that were copies of a journal already used (not packaged)
    duplicates: tuple[str, ...]

    @property
    def exit_code(self) -> int:
        """Packaging succeeded: 0 (the verdict is in the document; ``certify`` maps it)."""
        return 0

    def to_json(self) -> dict[str, Any]:
        return {
            "output": self.output,
            "manifest": self.manifest,
            "manifest_sha256": self.manifest_sha256,
            "certificate_file_sha256": self.certificate_file_sha256,
            "campaign": self.campaign,
            "verdict": self.verdict.value,
            "bundles": self.bundles,
            "journals": self.journals,
            "duplicates": list(self.duplicates),
        }


def _sync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _create(path: Path) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    return os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o444)


def _write_bytes(path: Path, data: bytes) -> None:
    descriptor = _create(path)
    try:
        view = memoryview(data)
        while view:
            view = view[os.write(descriptor, view) :]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _copy_prefix(source: Path, target: Path, count: int) -> None:
    """The first ``count`` bytes of ``source`` into a fresh read-only ``target``."""
    descriptor = _create(target)
    try:
        remaining = count
        with source.open("rb") as stream:
            while remaining:
                chunk = stream.read(min(_CHUNK, remaining))
                if not chunk:
                    raise IntegrityError(
                        "evidence.package", f"{source} is shorter than its certified {count} bytes"
                    )
                view = memoryview(chunk)
                while view:
                    view = view[os.write(descriptor, view) :]
                remaining -= len(chunk)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _read_contained(root: Path, relative: str) -> bytes:
    with open_contained(root, relative) as stream:
        return stream.read()


def _same_but_torn_tail(original: dict[str, Any], rebuilt: dict[str, Any]) -> bool:
    """The rebuilt certificate equals the original with each torn tail dropped."""
    expected = copy.deepcopy(original)
    for entry in expected["journals"]:
        entry["torn_tail_bytes"] = 0
    return bool(expected == rebuilt)


def package_evidence(request: PackageRequest) -> PackageResult:
    """Certify and publish the evidence directory (module doc); the inputs are only read."""
    output = Path(request.output).resolve()
    if os.path.lexists(output):
        raise ConfigurationError("evidence.exists", f"{output} already exists")
    limits = CertifyLimits(reader=request.limits)
    loaded = load_campaign(Path(request.campaign), limits=request.limits)
    first = certify_campaign(loaded, [Path(j) for j in request.journals], limits=limits)
    certificate = first.certificate
    certified = {entry["id"]: entry for entry in certificate["journals"]}
    campaign_root = Path(request.campaign).resolve().parent
    staging = output.parent / f".{output.name}.staging-{new_id128()}"
    output.parent.mkdir(parents=True, exist_ok=True)
    staging.mkdir()
    try:
        _write_bytes(staging / CAMPAIGN_NAME, Path(request.campaign).read_bytes())
        bundle_dirs = sorted(entry.bundle for entry in loaded.campaign.formulas)
        for relative in bundle_dirs:
            for name in ("manifest.json", "formula.cnf"):
                _write_bytes(
                    staging / relative / name, _read_contained(campaign_root, f"{relative}/{name}")
                )
        used = [item for item in first.inputs if item.used]
        for item in used:
            entry = certified[item.id]
            _copy_prefix(
                Path(item.path), staging / JOURNAL_DIR / f"{entry['worker']}.jsonl", entry["bytes"]
            )
        # the certificate comes from the copies: what the package says is what it holds
        copies = sorted((staging / JOURNAL_DIR).glob("*.jsonl")) if used else []
        rebuilt = certify_campaign(
            load_campaign(staging / CAMPAIGN_NAME, limits=request.limits),
            copies,
            limits=limits,
        )
        if not _same_but_torn_tail(certificate, rebuilt.certificate):
            raise IntegrityError(
                "evidence.package",
                "the certificate of the copied evidence differs from the certificate of the inputs",
            )
        _write_bytes(staging / CERTIFICATE_NAME, rebuilt.document)
        manifest = EvidenceManifest(
            artifact_of(staging, CAMPAIGN_NAME),
            tuple(
                BundleArtifacts(
                    artifact_of(staging, f"{relative}/manifest.json"),
                    artifact_of(staging, f"{relative}/formula.cnf"),
                )
                for relative in bundle_dirs
            ),
            tuple(
                artifact_of(staging, f"{JOURNAL_DIR}/{path.name}")
                for path in sorted(copies, key=lambda p: p.name)
            ),
            artifact_of(staging, CERTIFICATE_NAME),
        )
        manifest_bytes = document_bytes(manifest.to_json())
        _write_bytes(staging / MANIFEST_NAME, manifest_bytes)
        for directory in sorted(
            {p.parent for p in staging.rglob("*") if p.is_file()}, reverse=True
        ):
            _sync_directory(directory)
        _sync_directory(staging)
        if os.path.lexists(output):
            raise ConfigurationError("evidence.exists", f"{output} already exists")
        os.rename(staging, output)
        _sync_directory(output.parent)
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    return PackageResult(
        output=str(output),
        manifest=str(output / MANIFEST_NAME),
        manifest_sha256=artifact_of(output, MANIFEST_NAME).sha256,
        certificate_file_sha256=manifest.certificate.sha256,
        campaign=loaded.campaign.campaign_id,
        verdict=rebuilt.verdict,
        bundles=len(bundle_dirs),
        journals=len(copies),
        duplicates=tuple(item.path for item in first.inputs if not item.used),
    )
