"""``certify``: campaign, bundles and explicit journal files -> certificate (specification §10,
§12.1).

Order (requirements conventions): the campaign document and its bundles (input errors), then
every journal file completely (specification §7.1 order and every record rule), then copies and
workers (journal.fork, journal.worker), then closure, selection, frontier and verdict. Any error is
a :class:`~cubeproof.base.errors.CubeproofError` (input, integrity or resource; the command
reports it and exits 4 without a certificate). A reader or graph limit, or running out of
memory, is a resource error, never a partial or open result. Input order has no effect.

This library neither prints nor exits; :func:`exit_code` maps a verdict to the command's
exit code (PROVED 0, OPEN 1, MODEL_FOUND 2, INCONSISTENT 4 with a certificate).
"""

from __future__ import annotations

import os
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cubeproof.base.canonical_json import document_bytes
from cubeproof.base.errors import ResourceError
from cubeproof.base.settings import DEFAULT_LIMITS, ReaderLimits
from cubeproof.cnf.campaign import LoadedCampaign, load_campaign
from cubeproof.contracts.enums import ExitCode, Verdict
from cubeproof.evidence.certify.admission import AttemptRules
from cubeproof.evidence.certify.document import build_certificate
from cubeproof.evidence.certify.inputs import read_all, select_copies

_EXIT = {
    Verdict.PROVED: ExitCode.SUCCESS,
    Verdict.OPEN: ExitCode.OPEN,
    Verdict.MODEL_FOUND: ExitCode.MODEL,
    Verdict.INCONSISTENT: ExitCode.INTEGRITY,
}


def exit_code(verdict: Verdict) -> int:
    """The certify exit code of a verdict (specification §12.2)."""
    return int(_EXIT[Verdict(verdict)])


@dataclass(frozen=True)
class CertifyLimits:
    """Reader limits (specification §4.1) and an optional bound on evaluated evidence graph
    nodes."""

    reader: ReaderLimits = DEFAULT_LIMITS
    max_nodes: int | None = None


@dataclass(frozen=True)
class JournalInput:
    """One journal file given to certify, for the command report (duplicates, specification
    §10.1)."""

    path: str
    sha256: str
    id: str
    worker: str
    records: int
    torn_tail_bytes: int
    used: bool


@dataclass(frozen=True)
class CertifyResult:
    """A certificate, its verdict and exit code, and the journal inputs."""

    certificate: dict[str, Any]
    inputs: tuple[JournalInput, ...]

    @property
    def verdict(self) -> Verdict:
        return Verdict(self.certificate["verdict"])

    @property
    def exit_code(self) -> int:
        return exit_code(self.verdict)

    @property
    def document(self) -> bytes:
        """The certificate file: J(certificate) followed by one LF."""
        return document_bytes(self.certificate)

    @property
    def duplicates(self) -> tuple[JournalInput, ...]:
        """Inputs not used because another copy of the same journal was used."""
        return tuple(i for i in self.inputs if not i.used)


def certify_campaign(
    campaign: LoadedCampaign,
    journals: Sequence[str | os.PathLike[str]],
    *,
    limits: CertifyLimits = CertifyLimits(),  # noqa: B008 - immutable value
) -> CertifyResult:
    """Certify journals against a loaded, validated campaign (see module doc)."""
    formulas = {sha: bundle.formula for sha, bundle in campaign.bundles.items()}
    rules = AttemptRules(campaign.campaign.admit, formulas)
    try:
        evidence = read_all([Path(p) for p in journals], campaign, rules, limits.reader)
        copies = select_copies(evidence)
        certificate = build_certificate(campaign, copies, max_nodes=limits.max_nodes)
    except MemoryError:
        raise ResourceError("certify.memory", "out of memory while certifying") from None
    used = {id(copy.evidence) for copy in copies}
    inputs = tuple(
        JournalInput(
            path=item.path,
            sha256=item.sha256,
            id=item.summary.id,
            worker=item.summary.worker,
            records=item.summary.records,
            torn_tail_bytes=item.summary.torn_tail_bytes,
            used=id(item) in used,
        )
        for item in evidence
    )
    return CertifyResult(certificate, inputs)


def certify(
    campaign: str | os.PathLike[str],
    journals: Sequence[str | os.PathLike[str]],
    *,
    limits: CertifyLimits = CertifyLimits(),  # noqa: B008 - immutable value
) -> CertifyResult:
    """``cubeproof certify --campaign FILE --journals JOURNAL...`` as a library call."""
    try:
        loaded = load_campaign(Path(campaign), limits=limits.reader)
    except MemoryError:
        raise ResourceError("certify.memory", "out of memory while reading the campaign") from None
    return certify_campaign(loaded, journals, limits=limits)
