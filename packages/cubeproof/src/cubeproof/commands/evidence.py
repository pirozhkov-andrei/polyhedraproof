"""The portable evidence manifest ``cubeproof-evidence-1`` and its verified reading (specification
§4.9, §12.1).

A portable evidence directory holds the campaign, the bundles it names, journal snapshots and a
certificate, described by a manifest (``evidence.json``)::

    {format:"cubeproof-evidence-1", campaign:Artifact,
     bundles:[{manifest:Artifact, formula:Artifact}], journals:[Artifact], certificate:Artifact}

Arrays are sorted by path, every path is a RelPath inside the directory (the manifest's own
directory). :func:`load_evidence` is the only way a command accepts such a directory: it checks
the manifest (schema, order, containment without symlinks), then the size and SHA-256 of **every**
listed file, then that the listed bundles are exactly the bundles the campaign names. Nothing is
searched for and nothing unlisted is read. A malformed manifest is an input error; a missing,
resized or altered file is an integrity error (the directory is not what the manifest says).

The certificate in a manifest is a claim, not an authority: consuming commands recompute it from
the journals and compare (see :mod:`cubeproof.commands.package` and ``certify --evidence``).
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from dataclasses import dataclass
from itertools import pairwise
from pathlib import Path
from typing import Any

from cubeproof.base.canonical_json import parse_document
from cubeproof.base.errors import (
    ContractError,
    CubeproofError,
    InputError,
    IntegrityError,
    contextualize,
)
from cubeproof.base.paths import open_contained, read_at_most
from cubeproof.base.settings import DEFAULT_LIMITS, ReaderLimits
from cubeproof.contracts import fields as f
from cubeproof.contracts.campaign import Campaign
from cubeproof.contracts.values import Artifact

__all__ = [
    "CAMPAIGN_NAME",
    "CERTIFICATE_NAME",
    "EVIDENCE_FORMAT",
    "JOURNAL_DIR",
    "MANIFEST_NAME",
    "BundleArtifacts",
    "Evidence",
    "EvidenceManifest",
    "artifact_of",
    "file_digest",
    "load_evidence",
]

EVIDENCE_FORMAT = "cubeproof-evidence-1"
MANIFEST_NAME = "evidence.json"
CAMPAIGN_NAME = "campaign.json"
CERTIFICATE_NAME = "certificate.json"
JOURNAL_DIR = "journals"
_CHUNK = 1 << 20


@dataclass(frozen=True)
class BundleArtifacts:
    """The two files of a bundle the evidence needs: its manifest and ``formula.cnf``."""

    manifest: Artifact
    formula: Artifact

    @classmethod
    def from_json(cls, value: Any, at: str) -> BundleArtifacts:
        f.obj(value, at, ("manifest", "formula"))
        return cls(
            Artifact.from_json(value["manifest"], f.member(at, "manifest")),
            Artifact.from_json(value["formula"], f.member(at, "formula")),
        )

    def to_json(self) -> dict[str, Any]:
        return {"manifest": self.manifest.to_json(), "formula": self.formula.to_json()}


def _strictly_sorted(paths: Sequence[str]) -> bool:
    return all(a < b for a, b in pairwise(paths))


@dataclass(frozen=True)
class EvidenceManifest:
    """The manifest document; arrays sorted by path (``evidence.order``)."""

    campaign: Artifact
    bundles: tuple[BundleArtifacts, ...]
    journals: tuple[Artifact, ...]
    certificate: Artifact

    @classmethod
    def from_json(cls, value: Any, at: str = "$") -> EvidenceManifest:
        f.obj(value, at, ("format", "campaign", "bundles", "journals", "certificate"))
        m = f.member
        f.const(value["format"], m(at, "format"), EVIDENCE_FORMAT)
        campaign = Artifact.from_json(value["campaign"], m(at, "campaign"))
        bundles = tuple(f.items(value["bundles"], m(at, "bundles"), BundleArtifacts.from_json))
        journals = tuple(f.items(value["journals"], m(at, "journals"), Artifact.from_json))
        certificate = Artifact.from_json(value["certificate"], m(at, "certificate"))
        if not _strictly_sorted([b.manifest.path for b in bundles]) or not _strictly_sorted(
            [j.path for j in journals]
        ):
            raise ContractError("evidence.order", "bundles and journals are not sorted by path")
        return cls(campaign, bundles, journals, certificate)

    def to_json(self) -> dict[str, Any]:
        return {
            "format": EVIDENCE_FORMAT,
            "campaign": self.campaign.to_json(),
            "bundles": [b.to_json() for b in self.bundles],
            "journals": [j.to_json() for j in self.journals],
            "certificate": self.certificate.to_json(),
        }

    def artifacts(self) -> tuple[Artifact, ...]:
        """Every file the manifest lists, in manifest order."""
        found: list[Artifact] = [self.campaign]
        for bundle in self.bundles:
            found.extend((bundle.manifest, bundle.formula))
        found.extend(self.journals)
        found.append(self.certificate)
        return tuple(found)


@dataclass(frozen=True)
class Evidence:
    """A verified evidence directory: absolute paths of its files."""

    manifest_path: Path
    root: Path
    manifest: EvidenceManifest
    campaign: Path
    journals: tuple[Path, ...]
    certificate: Path


def file_digest(path: Path) -> tuple[str, int]:
    """SHA-256 and size of a regular file, read in chunks."""
    digest = hashlib.sha256()
    size = 0
    with Path(path).open("rb") as stream:
        while True:
            chunk = stream.read(_CHUNK)
            if not chunk:
                return digest.hexdigest(), size
            digest.update(chunk)
            size += len(chunk)


def artifact_of(root: Path, relative: str) -> Artifact:
    """The descriptor (path, hash, size) of ``root/relative``."""
    sha, size = file_digest(root / relative)
    return Artifact(relative, sha, size)


def _verify(root: Path, artifact: Artifact) -> Path:
    """The listed file, after its containment, size and hash are verified (integrity errors)."""
    digest = hashlib.sha256()
    size = 0
    try:
        with open_contained(root, artifact.path) as stream:
            while True:
                chunk = stream.read(_CHUNK)
                if not chunk:
                    break
                digest.update(chunk)
                size += len(chunk)
    except FileNotFoundError:
        raise IntegrityError("evidence.missing", f"{artifact.path} is listed but absent") from None
    except ContractError as error:
        raise IntegrityError("evidence.containment", f"{artifact.path}: {error.detail}") from None
    except OSError as error:
        raise IntegrityError(
            "evidence.unreadable", f"{artifact.path}: {error.strerror or error}"
        ) from None
    if size != artifact.bytes or digest.hexdigest() != artifact.sha256:
        raise IntegrityError(
            "evidence.artifact", f"{artifact.path}: size or SHA-256 differs from the manifest"
        )
    return root / artifact.path


def _campaign_bundles(path: Path, limits: ReaderLimits) -> list[str]:
    try:
        with path.open("rb") as stream:
            data = read_at_most(stream, limits.document_bytes + 2)
        campaign = Campaign.from_json(parse_document(data, limits=limits))
    except CubeproofError as error:
        raise contextualize(error, InputError) from None
    return sorted(entry.bundle for entry in campaign.formulas)


def load_evidence(manifest_path: Path, *, limits: ReaderLimits = DEFAULT_LIMITS) -> Evidence:
    """Read and verify the evidence directory of ``manifest_path`` (module doc)."""
    path = Path(manifest_path)
    try:
        with path.open("rb") as stream:
            data = read_at_most(stream, limits.document_bytes + 2)
    except OSError as error:
        raise InputError("evidence.file", f"{path}: {error.strerror or error}") from None
    try:
        manifest = EvidenceManifest.from_json(parse_document(data, limits=limits))
    except CubeproofError as error:
        converted = contextualize(error, InputError)
        if type(converted) is InputError:
            raise InputError(
                converted.rule, f"{path}: {converted.detail}", location=converted.location
            ) from None
        raise converted from None
    listed = [a.path for a in manifest.artifacts()]
    if len(set(listed)) != len(listed):
        raise InputError("evidence.duplicate", f"{path}: a file is listed twice")
    root = path.resolve().parent
    verified = {a.path: _verify(root, a) for a in manifest.artifacts()}
    bundles = sorted(b.manifest.path.removesuffix("/manifest.json") for b in manifest.bundles)
    wrong = [
        b
        for b in manifest.bundles
        if not b.manifest.path.endswith("/manifest.json")
        or b.formula.path != b.manifest.path.removesuffix("manifest.json") + "formula.cnf"
    ]
    if wrong:
        raise InputError(
            "evidence.bundles",
            f"{path}: bundle files must be <dir>/manifest.json and <dir>/formula.cnf "
            "of one directory",
        )
    expected = _campaign_bundles(verified[manifest.campaign.path], limits)
    if bundles != expected:
        raise IntegrityError(
            "evidence.bundles", f"{path}: the listed bundles are not the bundles of the campaign"
        )
    return Evidence(
        path,
        root,
        manifest,
        verified[manifest.campaign.path],
        tuple(verified[j.path] for j in manifest.journals),
        verified[manifest.certificate.path],
    )
