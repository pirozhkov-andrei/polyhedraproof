"""Audit input binding: a certificate bound to the exact journal prefixes it certified
(specification §11.1).

``audit`` receives a certificate and the campaign and journals it was computed from (explicit
paths or an evidence manifest). The certificate is a **claim**: nothing it says is used before
the evidence has reproduced it.

1. The certificate file is read as a canonical document; only the fields needed for binding are
   read here (``format``, ``campaign``, ``journals``). Its document hash is
   ``certificate_sha256`` (specification §4.1: J without the final LF).
2. Every journal entry ``{id, records, head, bytes}`` of the certificate is an anchor: the input
   journals with that header ID are tried in path order, and the first ``bytes`` bytes of one of
   them are copied into a read-only **snapshot** ``<snapshots>/<id>.jsonl``. The snapshot is then
   read completely with the certifier's record rules and must end exactly with record
   ``records - 1`` whose ``self`` is ``head`` at byte offset ``bytes`` (``read_snapshot``).
   Records appended to an input after certification are therefore never incorporated, and a
   different head or a shorter journal is an integrity error.
3. The certifier is run again on the snapshots and the result must equal the supplied
   certificate except the torn-tail sizes, which a snapshot by construction does not have. A
   tampered ``used_attempts`` list, a changed verdict or any other edited field is an integrity
   error (``audit.certificate``), before any target is chosen.

Every input journal must belong to the certificate (``audit.journals``); a journal the
certificate does not name would be evidence the audit silently ignores. Existing snapshots
(restart of an audit) are re-validated against the same anchors, never trusted, and never
replaced. The snapshots are the *preserved certified inputs* from which a restart regenerates
the plan (specification §11.1).
"""

from __future__ import annotations

import contextlib
import copy
import os
from collections.abc import Sequence
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from cubeproof.base.canonical_json import json_sha256, parse_document, parse_line
from cubeproof.base.errors import CubeproofError, InputError, IntegrityError, contextualize
from cubeproof.base.ids import new_id128
from cubeproof.base.paths import open_regular_file, read_at_most
from cubeproof.base.settings import DEFAULT_LIMITS, ReaderLimits
from cubeproof.cnf.campaign import LoadedCampaign, load_campaign
from cubeproof.contracts.primitives import INT_MAX, is_hash
from cubeproof.evidence.certify.admission import AttemptRules
from cubeproof.evidence.certify.inputs import context_of
from cubeproof.evidence.certify.run import CertifyLimits, CertifyResult, certify_campaign
from cubeproof.evidence.journal import Anchor, JournalReader
from cubeproof.evidence.schema import RecordSequence

__all__ = [
    "CERTIFICATE_FORMAT",
    "BoundInputs",
    "CertificateClaim",
    "CertifiedJournal",
    "bind_certified_inputs",
    "read_certificate",
    "validator_of",
]

CERTIFICATE_FORMAT = "cubeproof-certificate-1"
_CHUNK = 1 << 20
_SNAPSHOT_SUFFIX = ".jsonl"
_TEMPORARY = ".tmp-"


@dataclass(frozen=True)
class CertifiedJournal:
    """One journal entry of a certificate: the anchor of its certified prefix."""

    id: str
    worker: str
    records: int
    head: str
    bytes: int
    torn_tail_bytes: int

    @property
    def anchor(self) -> Anchor:
        return Anchor(self.id, self.records - 1, self.head, self.bytes)


@dataclass(frozen=True)
class CertificateClaim:
    """A certificate as read from its file: the document, its hash and its journal anchors."""

    path: str
    document: dict[str, Any]
    sha256: str
    campaign: str
    journals: tuple[CertifiedJournal, ...]


@dataclass(frozen=True)
class BoundInputs:
    """A certificate whose every field the snapshots of its journal prefixes reproduce."""

    campaign: LoadedCampaign
    certificate: CertificateClaim
    #: one read-only snapshot per certified journal, in journal-ID order
    snapshots: tuple[Path, ...]
    #: the certify result of the snapshots (equal to the claim but for torn tails)
    recertified: CertifyResult
    #: input files that were not used because another copy of the same journal was
    copies_ignored: tuple[str, ...]


def _claim_error(path: Path, detail: str) -> InputError:
    return InputError("audit.certificate_file", f"{path}: {detail}")


def _entry(path: Path, value: Any, index: int) -> CertifiedJournal:
    where = f"journals[{index}]"
    fields = ("id", "worker", "records", "head", "bytes", "torn_tail_bytes")
    if type(value) is not dict or set(value) != set(fields):
        raise _claim_error(path, f"{where} is not a certificate journal entry")
    ident, worker, head = value["id"], value["worker"], value["head"]
    if not (is_hash(ident) and is_hash(head) and type(worker) is str):
        raise _claim_error(path, f"{where} has a malformed id, worker or head")
    for name, low in (("records", 1), ("bytes", 1), ("torn_tail_bytes", 0)):
        number = value[name]
        if type(number) is not int or not low <= number <= INT_MAX:
            raise _claim_error(path, f"{where}.{name} is not an integer >= {low}")
    return CertifiedJournal(
        ident, worker, value["records"], head, value["bytes"], value["torn_tail_bytes"]
    )


def read_certificate(path: Path, *, limits: ReaderLimits = DEFAULT_LIMITS) -> CertificateClaim:
    """The certificate file as a claim (InputError ``audit.certificate_file`` if unusable).

    Only the binding fields are checked here; every other field is compared with the
    recomputed certificate by :func:`bind_certified_inputs`. A certificate has no document size
    limit (specification §4.1: the 64 MiB limit is for campaign and shard documents): a regular
    file is read whole, and the other reader limits apply.
    """
    path = Path(path)
    try:
        with open_regular_file(path) as stream:
            data = stream.read()
    except OSError as error:
        raise _claim_error(path, error.strerror or str(error)) from None
    try:
        document = parse_document(
            data, limits=replace(limits, document_bytes=max(limits.document_bytes, len(data)))
        )
    except CubeproofError as error:
        raise _claim_error(path, f"{error.rule}: {error.detail}") from None
    if type(document) is not dict or document.get("format") != CERTIFICATE_FORMAT:
        raise _claim_error(path, f"not a {CERTIFICATE_FORMAT} document")
    campaign, journals = document.get("campaign"), document.get("journals")
    if not is_hash(campaign) or type(journals) is not list:
        raise _claim_error(path, "campaign or journals missing")
    entries = tuple(_entry(path, value, index) for index, value in enumerate(journals))
    if len({e.id for e in entries}) != len(entries):
        raise _claim_error(path, "a journal ID occurs twice")
    return CertificateClaim(str(path), document, json_sha256(document), str(campaign), entries)


def validator_of(campaign: LoadedCampaign) -> RecordSequence:
    """The certifier's record validator for a journal of ``campaign`` (every record rule)."""
    formulas = {sha: bundle.formula for sha, bundle in campaign.bundles.items()}
    return RecordSequence(
        context=context_of(campaign), extra=AttemptRules(campaign.campaign.admit, formulas)
    )


def _header_id(path: Path, limits: ReaderLimits) -> str:
    """``self`` of the first line of a journal file (validated later, with the whole prefix)."""
    try:
        with path.open("rb") as stream:
            head = read_at_most(stream, limits.line_bytes + 1)
    except OSError as error:
        raise InputError("journal.file", f"{path}: {error.strerror or error}") from None
    end = head.find(b"\n")
    if end < 0:
        raise IntegrityError("audit.journals", f"{path}: no complete header line")
    try:
        value = parse_line(head[:end], limits=limits)
    except CubeproofError as error:
        raise contextualize(error, IntegrityError) from None
    ident = value.get("self") if type(value) is dict else None
    if not is_hash(ident) or value.get("seq") != 0:
        raise IntegrityError("audit.journals", f"{path}: the first line is not a header")
    return str(ident)


def _sync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _copy_prefix(source: Path, target: Path, count: int) -> None:
    """The first ``count`` bytes of ``source`` into a new read-only ``target`` (no replace)."""
    temporary = target.with_name(f"{target.name}{_TEMPORARY}{new_id128()}")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o444)
    try:
        try:
            remaining = count
            with source.open("rb") as stream:
                while remaining:
                    chunk = stream.read(min(_CHUNK, remaining))
                    if not chunk:
                        raise IntegrityError(
                            "journal.anchor",
                            f"{source} is shorter than its certified {count} bytes",
                        )
                    view = memoryview(chunk)
                    while view:
                        view = view[os.write(descriptor, view) :]
                    remaining -= len(chunk)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.link(temporary, target)  # never replaces a snapshot that appeared meanwhile
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(temporary)
    _sync_directory(target.parent)


def _validated(
    path: Path, entry: CertifiedJournal, campaign: LoadedCampaign, limits: ReaderLimits
) -> None:
    """``path`` holds exactly the certified prefix of ``entry`` (IntegrityError otherwise)."""
    size = path.stat().st_size
    if size != entry.bytes:
        raise IntegrityError(
            "journal.anchor", f"{path}: {size} bytes, the certificate names {entry.bytes}"
        )
    with path.open("rb") as stream:
        reader = JournalReader(
            stream, validator_of(campaign), name=path.name, limits=limits, anchor=entry.anchor
        )
        for _ in reader:  # streamed: a long journal is never held in memory
            pass
    summary = reader.summary
    if summary.torn_tail_bytes or summary.records != entry.records:
        raise IntegrityError("journal.anchor", f"{path}: the prefix does not end at the anchor")
    if summary.worker != entry.worker:
        raise IntegrityError("journal.anchor", f"{path}: the worker differs from the certificate's")


def _clear_temporaries(directory: Path) -> None:
    for leftover in directory.glob(f"*{_SNAPSHOT_SUFFIX}{_TEMPORARY}*"):
        with contextlib.suppress(FileNotFoundError):
            leftover.unlink()


def _snapshot(
    entry: CertifiedJournal,
    candidates: Sequence[Path],
    directory: Path,
    campaign: LoadedCampaign,
    limits: ReaderLimits,
) -> tuple[Path, Path | None]:
    """The validated snapshot of ``entry`` and the input it was copied from (None: kept)."""
    target = directory / f"{entry.id}{_SNAPSHOT_SUFFIX}"
    if os.path.lexists(target):
        try:
            _validated(target, entry, campaign, limits)
        except CubeproofError as error:
            raise IntegrityError(
                "audit.snapshot", f"{target} is not the certified prefix: {error}"
            ) from None
        return target, None
    if not candidates:
        raise IntegrityError(
            "audit.journals", f"no input journal has the certified header ID {entry.id}"
        )
    first: CubeproofError | None = None
    for source in candidates:
        try:
            _copy_prefix(source, target, entry.bytes)
            _validated(target, entry, campaign, limits)
        except CubeproofError as error:
            with contextlib.suppress(FileNotFoundError):
                os.chmod(target, 0o644)
                target.unlink()
            first = first or contextualize(error, IntegrityError)
            continue
        return target, source
    assert first is not None
    raise first


def _comparable(certificate: dict[str, Any]) -> dict[str, Any]:
    """The certificate with each torn tail set to 0 (a snapshot has none)."""
    value = copy.deepcopy(certificate)
    for entry in value.get("journals", []):
        if type(entry) is dict:
            entry["torn_tail_bytes"] = 0
    return value


def _first_difference(claimed: dict[str, Any], rebuilt: dict[str, Any]) -> str:
    for name in sorted(set(claimed) | set(rebuilt)):
        if claimed.get(name) != rebuilt.get(name):
            return name
    return "(none)"  # pragma: no cover - only called when they differ


def bind_certified_inputs(
    campaign: Path,
    journals: Sequence[Path],
    certificate: Path,
    snapshots: Path,
    *,
    limits: ReaderLimits = DEFAULT_LIMITS,
) -> BoundInputs:
    """Bind ``certificate`` to snapshots of its exact journal prefixes and re-certify them.

    ``snapshots`` is created if needed; existing snapshots are re-validated (module doc).
    Errors: InputError for unusable files (campaign, certificate, unreadable journal),
    IntegrityError for any disagreement between the certificate and the evidence.
    """
    loaded = load_campaign(Path(campaign), limits=limits)
    claim = read_certificate(Path(certificate), limits=limits)
    if claim.campaign != loaded.campaign.campaign_id:
        raise IntegrityError(
            "audit.certificate", f"the certificate is of campaign {claim.campaign}"
        )
    by_id: dict[str, list[Path]] = {}
    for path in sorted({Path(p) for p in journals}, key=os.fspath):
        by_id.setdefault(_header_id(path, limits), []).append(path)
    certified = {entry.id for entry in claim.journals}
    unknown = sorted(os.fspath(p) for i, ps in by_id.items() if i not in certified for p in ps)
    if unknown:
        raise IntegrityError(
            "audit.journals", f"journals not named by the certificate: {', '.join(unknown)}"
        )
    directory = Path(snapshots)
    directory.mkdir(parents=True, exist_ok=True)
    _clear_temporaries(directory)
    paths: list[Path] = []
    used: set[Path] = set()
    for entry in sorted(claim.journals, key=lambda e: e.id):
        target, source = _snapshot(entry, by_id.get(entry.id, []), directory, loaded, limits)
        paths.append(target)
        if source is not None:
            used.add(source)
    rebuilt = certify_campaign(loaded, paths, limits=CertifyLimits(reader=limits))
    if rebuilt.certificate != _comparable(claim.document):
        field = _first_difference(_comparable(claim.document), rebuilt.certificate)
        raise IntegrityError(
            "audit.certificate",
            f"the certified journal prefixes do not reproduce the certificate (field {field})",
        )
    ignored = tuple(os.fspath(p) for ps in by_id.values() for p in ps if p not in used)
    return BoundInputs(loaded, claim, tuple(paths), rebuilt, tuple(sorted(ignored)))
