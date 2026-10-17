"""Certify inputs: validated journals, their evidence, copies, forks and workers (specification
§10.1).

Every journal file is read completely by the journal reader with the campaign's
:class:`~cubeproof.evidence.schema.JournalContext` and the certifier's
:class:`~.admission.AttemptRules` (specification §7.1 order; every record rule, admitted or not).
While a file is read, the evidence the certificate needs is extracted from each accepted record
(:class:`JournalEvidence`); a file with any error contributes nothing.

When several files fail, the reported error does not depend on the input order: unreadable
files first (by path), then the failing file with the smallest SHA-256 of its bytes.

Files with the same header ID are copies of one journal: every copy must be a prefix of the
longest (``journal.fork`` otherwise); the longest is used once, with the smallest torn tail
among the copies of that length. One worker Name with two header IDs is
``journal.worker``. Groups are checked in header-ID order, fork before worker.
"""

from __future__ import annotations

import hashlib
import os
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, BinaryIO

from cubeproof.base.errors import CubeproofError, InputError, IntegrityError
from cubeproof.base.settings import ReaderLimits
from cubeproof.cnf.campaign import LoadedCampaign
from cubeproof.contracts.enums import Outcome
from cubeproof.contracts.identity import split_problem
from cubeproof.evidence.certify.admission import AttemptRules, admission_reason
from cubeproof.evidence.journal import JournalReader, JournalSummary
from cubeproof.evidence.schema import (
    Attempt,
    Header,
    JournalContext,
    NodeReopen,
    NodeStop,
    Record,
    RecordSequence,
    Resume,
    SplitRecord,
)

Cube = tuple[int, ...]
Key = tuple[str, Cube]
_DIGEST_BYTES = 32


@dataclass(frozen=True)
class AttemptFacts:
    """What the certificate needs of one attempt (Ref seq within its journal)."""

    seq: int
    key: Key
    outcome: Outcome
    not_admitted: str | None
    snapshot_seq: int
    cnf_sha256: str
    proof_sha256: str | None
    route: str
    assignment: str | None
    model_error: str | None
    valid_model: bool


@dataclass(frozen=True)
class LabelFacts:
    seq: int
    key: Key
    state: str | None  # None: node_reopen
    reason: str


@dataclass
class JournalEvidence:
    """One validated journal file and the evidence extracted from its records."""

    path: str
    sha256: str
    summary: JournalSummary
    selfs: bytes
    machinery: dict[int, dict[str, Any]] = field(default_factory=dict)
    splits: list[tuple[int, Key, tuple[int, ...]]] = field(default_factory=list)
    malformed: list[tuple[int, str]] = field(default_factory=list)
    attempts: list[AttemptFacts] = field(default_factory=list)
    labels: list[LabelFacts] = field(default_factory=list)

    def self_at(self, seq: int) -> bytes:
        return self.selfs[seq * _DIGEST_BYTES : (seq + 1) * _DIGEST_BYTES]


@dataclass(frozen=True)
class Copy:
    """A selected journal and the torn tail it reports."""

    evidence: JournalEvidence
    torn_tail_bytes: int


class _Hashing:
    """A byte source that hashes everything read through it."""

    def __init__(self, stream: BinaryIO) -> None:
        self._stream = stream
        self.digest = hashlib.sha256()

    def read(self, size: int = -1, /) -> bytes:
        data = self._stream.read(size)
        self.digest.update(data)
        return data

    def drain(self) -> None:
        while self.read(1 << 20):
            pass


class _Extractor:
    """Evidence of the records the reader accepted, in seq order."""

    def __init__(self, campaign: LoadedCampaign, rules: AttemptRules) -> None:
        self._campaign = campaign
        self._rules = rules
        self.selfs = bytearray()
        self.snapshot: Header | Resume | None = None
        self.snapshot_seq = 0
        self.machinery: dict[int, dict[str, Any]] = {}
        self.splits: list[tuple[int, Key, tuple[int, ...]]] = []
        self.malformed: list[tuple[int, str]] = []
        self.attempts: list[AttemptFacts] = []
        self.labels: list[LabelFacts] = []

    def add(self, record: Record) -> None:
        self.selfs += bytes.fromhex(record.self_hash)
        payload = record.payload
        if isinstance(payload, (Header, Resume)):
            self.snapshot, self.snapshot_seq = payload, record.seq
            self.machinery[record.seq] = payload.machinery.to_json()
        elif isinstance(payload, SplitRecord):
            node = payload.node
            count = self._campaign.formula(node.formula_sha256).variables
            problem = split_problem(payload.variables, node.cube, count)
            if problem is None:
                self.splits.append(
                    (record.seq, (node.formula_sha256, node.cube), payload.variables)
                )
            else:
                self.malformed.append((record.seq, problem.removeprefix("split.")))
        elif isinstance(payload, Attempt):
            self.attempts.append(self._attempt(record, payload))
        elif isinstance(payload, (NodeStop, NodeReopen)):
            state = payload.state.value if isinstance(payload, NodeStop) else None
            node = payload.node
            key = (node.formula_sha256, node.cube)
            self.labels.append(LabelFacts(record.seq, key, state, payload.reason))

    def _attempt(self, record: Record, attempt: Attempt) -> AttemptFacts:
        snapshot = self.snapshot
        assert snapshot is not None  # the header precedes every attempt
        modelled = attempt.outcome in (Outcome.MODEL, Outcome.INVALID_MODEL)
        return AttemptFacts(
            seq=record.seq,
            key=(attempt.node.formula_sha256, attempt.node.cube),
            outcome=attempt.outcome,
            not_admitted=admission_reason(self._campaign.campaign.admit, snapshot.machinery),
            snapshot_seq=self.snapshot_seq,
            cnf_sha256=attempt.cnf_sha256,
            proof_sha256=attempt.proof_sha256,
            route=attempt.route.value,
            assignment=attempt.assignment,
            model_error=None if attempt.model_error is None else attempt.model_error.value,
            valid_model=modelled and self._rules.model_satisfies(record),
        )


def context_of(campaign: LoadedCampaign) -> JournalContext:
    variables = {sha: bundle.formula.variables for sha, bundle in campaign.bundles.items()}
    return JournalContext(campaign.campaign.campaign_id, variables)


@dataclass(frozen=True)
class _Failure:
    """A file that failed: its error and its place in the input-order-free error choice."""

    order: tuple[int, str]
    error: CubeproofError


def _unreadable(path: Path, exc: OSError) -> _Failure:
    error = InputError("journal.file", f"{path}: {exc.strerror or exc}")
    return _Failure((0, os.fspath(path)), error)


def _read(
    path: Path, campaign: LoadedCampaign, rules: AttemptRules, limits: ReaderLimits
) -> JournalEvidence | _Failure:
    """Validate one journal file completely and extract its evidence."""
    sequence = RecordSequence(context=context_of(campaign), extra=rules)
    extractor = _Extractor(campaign, rules)
    failure: CubeproofError | None = None
    try:
        with path.open("rb") as stream:
            source = _Hashing(stream)
            reader = JournalReader(source, sequence, name=path.name, limits=limits)
            try:
                for record in reader:
                    extractor.add(record)
            except CubeproofError as error:
                failure = error
            source.drain()
    except OSError as exc:
        return _unreadable(path, exc)
    if failure is not None:
        return _Failure((1, source.digest.hexdigest()), failure)
    return JournalEvidence(
        path=os.fspath(path),
        sha256=source.digest.hexdigest(),
        summary=reader.summary,
        selfs=bytes(extractor.selfs),
        machinery=extractor.machinery,
        splits=extractor.splits,
        malformed=extractor.malformed,
        attempts=extractor.attempts,
        labels=extractor.labels,
    )


def read_all(
    paths: Sequence[Path], campaign: LoadedCampaign, rules: AttemptRules, limits: ReaderLimits
) -> list[JournalEvidence]:
    """Every file's evidence, or the error chosen independently of the input order."""
    found: list[JournalEvidence] = []
    failures: list[_Failure] = []
    for path in paths:
        result = _read(Path(path), campaign, rules, limits)
        if isinstance(result, _Failure):
            failures.append(result)
        else:
            found.append(result)
    if failures:
        raise min(failures, key=lambda failure: failure.order).error
    return found


def select_copies(journals: Sequence[JournalEvidence]) -> list[Copy]:
    """One copy per header ID, sorted by ID; journal.fork, then journal.worker (module doc)."""
    groups: dict[str, list[JournalEvidence]] = {}
    for journal in journals:
        groups.setdefault(journal.summary.id, []).append(journal)
    workers: dict[str, str] = {}
    chosen: list[Copy] = []
    for ident in sorted(groups):
        group = groups[ident]
        records = max(j.summary.records for j in group)
        longest = [j for j in group if j.summary.records == records]
        for other in group:
            last = other.summary.records - 1
            if other.self_at(last) != longest[0].self_at(last):
                raise IntegrityError(
                    "journal.fork", f"{other.path} diverges from {longest[0].path}"
                )
        worker = longest[0].summary.worker
        if workers.setdefault(worker, ident) != ident:
            raise IntegrityError("journal.worker", f"worker {worker} has two header IDs")
        best = min(longest, key=lambda j: (j.summary.torn_tail_bytes, j.path))
        chosen.append(Copy(best, best.summary.torn_tail_bytes))
    return chosen
