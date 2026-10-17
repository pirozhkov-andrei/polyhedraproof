"""The audit plan and results inside one audit-purpose journal (specification §4.7, §11.1, §11.2).

:class:`AuditScan` checks the records of an audit journal in order (records that passed the
journal reader and the certifier's record rules) and keeps what the report needs. Header,
resume and repair records are ignored for the plan rules; the rules are those of the
requirements matrix, in this order:

- ``audit.plan_order``: the journal starts with ``audit_begin``, then ``audit_target`` records
  with ordinals ``0..n-1`` in order, then ``audit_ready``; afterwards only ``attempt`` and
  ``audit_result`` records;
- ``audit.targets_hash``: ``audit_begin`` and ``audit_ready`` carry ``target_count = n`` and
  ``targets_sha256`` = SHA256 of the concatenated ``J(target) + LF``; a plan never holds more
  than ``target_count`` targets;
- ``audit.result_unique``: at most one ``audit_result`` per target;
- ``audit.result_ref``: an ``audit_result`` names a planned target and refers to an earlier
  ``attempt`` of the same journal, for the target's node.

A journal may end inside its plan (a crash while writing it): :meth:`AuditScan.finish` with
``complete=False`` accepts that, so that a restart can regenerate the plan and finish it;
``complete=True`` (a report) requires ``audit_ready``. Every violation is an IntegrityError.
For each result the referenced attempt and the machinery snapshot in force at it are kept, so
that the result's status can be recomputed (:mod:`.audit_report`).
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from cubeproof.base.errors import IntegrityError
from cubeproof.base.settings import DEFAULT_LIMITS, ReaderLimits
from cubeproof.cnf.campaign import LoadedCampaign
from cubeproof.commands.audit_inputs import validator_of
from cubeproof.commands.audit_plan import target_bytes, targets_sha256
from cubeproof.contracts.enums import Purpose
from cubeproof.contracts.values import Ref
from cubeproof.evidence.journal import JournalReader
from cubeproof.evidence.schema import (
    Attempt,
    AuditBegin,
    AuditReady,
    AuditResult,
    AuditTarget,
    AuditTargetRecord,
    Header,
    Machinery,
    Record,
    Repair,
    Resume,
)

__all__ = ["AuditJournal", "AuditScan", "CommittedResult", "read_audit_journal"]


@dataclass(frozen=True)
class CommittedResult:
    """One committed audit_result, its referenced attempt and that attempt's snapshot."""

    record: Ref
    result: AuditResult
    attempt: Attempt
    machinery: Machinery


@dataclass(frozen=True)
class AuditJournal:
    """What an audit journal holds: its identity, plan and committed results."""

    id: str
    worker: str
    records: int
    head: str
    torn_tail_bytes: int
    begin: AuditBegin | None
    targets: tuple[AuditTarget, ...]
    ready: AuditReady | None
    #: in journal order
    results: tuple[CommittedResult, ...]
    attempts: int

    def result_of(self, target: AuditTarget) -> CommittedResult | None:
        wanted = target_bytes(target)
        return next((r for r in self.results if target_bytes(r.result.target) == wanted), None)


def _order(detail: str) -> IntegrityError:
    return IntegrityError("audit.plan_order", detail)


class AuditScan:
    """Incremental audit-plan rules over the records of one journal (module doc)."""

    def __init__(self) -> None:
        self.header: Header | None = None
        self.journal_id: str | None = None
        self.machinery: Machinery | None = None
        self.begin: AuditBegin | None = None
        self.targets: list[AuditTarget] = []
        self.ready: AuditReady | None = None
        self.results: list[CommittedResult] = []
        self._planned: set[bytes] = set()
        self._seen: set[bytes] = set()
        #: attempt seq -> (attempt, snapshot machinery)
        self._attempts: dict[int, tuple[Attempt, Machinery]] = {}

    def add(self, record: Record) -> None:
        """Check and keep one record (IntegrityError on the first violated rule)."""
        payload = record.payload
        if isinstance(payload, Header):
            if payload.purpose != Purpose.AUDIT:
                raise IntegrityError("audit.purpose", f"a {payload.purpose.value} journal")
            self.header, self.journal_id = payload, record.self_hash
        if isinstance(payload, (Header, Resume)):
            self.machinery = payload.machinery
            return
        if isinstance(payload, Repair):
            return
        if self.begin is None:
            if not isinstance(payload, AuditBegin):
                raise _order(f"{payload.TYPE.value} at seq {record.seq} before audit_begin")
            self.begin = payload
            return
        if self.ready is None:
            self._plan(record)
            return
        if isinstance(payload, Attempt):
            assert self.machinery is not None
            self._attempts[record.seq] = (payload, self.machinery)
        elif isinstance(payload, AuditResult):
            self._result(record, payload)
        else:
            raise _order(f"{payload.TYPE.value} at seq {record.seq} after audit_ready")

    def _plan(self, record: Record) -> None:
        payload, begin = record.payload, self.begin
        assert begin is not None
        if isinstance(payload, AuditTargetRecord):
            if payload.ordinal != len(self.targets):
                raise _order(
                    f"audit_target ordinal {payload.ordinal}, expected {len(self.targets)}"
                )
            if len(self.targets) >= begin.target_count:
                raise IntegrityError("audit.targets_hash", "more targets than target_count")
            self.targets.append(payload.target)
            self._planned.add(target_bytes(payload.target))
            return
        if not isinstance(payload, AuditReady):
            raise _order(f"{payload.TYPE.value} at seq {record.seq} before audit_ready")
        digest = targets_sha256(self.targets)
        count = len(self.targets)
        if not (
            begin.target_count == payload.target_count == count
            and begin.targets_sha256 == payload.targets_sha256 == digest
        ):
            raise IntegrityError("audit.targets_hash", "the plan's count or targets hash differs")
        self.ready = payload

    def _result(self, record: Record, result: AuditResult) -> None:
        target = target_bytes(result.target)
        if target in self._seen:
            raise IntegrityError("audit.result_unique", f"a second result at seq {record.seq}")
        self._seen.add(target)
        ref = result.attempt
        found = self._attempts.get(ref.seq) if ref.journal == self.journal_id else None
        if target not in self._planned or found is None or ref.seq >= record.seq:
            raise IntegrityError(
                "audit.result_ref", f"audit_result at seq {record.seq} names no earlier attempt"
            )
        attempt, machinery = found
        if attempt.node_id != result.target.node_id:
            raise IntegrityError(
                "audit.result_ref", f"audit_result at seq {record.seq} names another node's attempt"
            )
        assert self.journal_id is not None
        self.results.append(
            CommittedResult(Ref(self.journal_id, record.seq), result, attempt, machinery)
        )

    def finish(
        self, *, complete: bool, worker: str, records: int, head: str, torn_tail_bytes: int = 0
    ) -> AuditJournal:
        """The scanned journal; ``complete`` requires a ready plan (``audit.plan_order``)."""
        if complete and self.ready is None:
            raise _order("the journal has no complete plan (audit_ready is missing)")
        assert self.journal_id is not None
        return AuditJournal(
            id=self.journal_id,
            worker=worker,
            records=records,
            head=head,
            torn_tail_bytes=torn_tail_bytes,
            begin=self.begin,
            targets=tuple(self.targets),
            ready=self.ready,
            results=tuple(self.results),
            attempts=len(self._attempts),
        )


def read_audit_journal(
    path: Path,
    campaign: LoadedCampaign,
    *,
    complete: bool = True,
    limits: ReaderLimits = DEFAULT_LIMITS,
) -> AuditJournal:
    """Read an audit journal file with every record rule and the audit plan rules."""
    path = Path(path)
    scan = AuditScan()
    with path.open("rb") as stream:
        reader = JournalReader(stream, validator_of(campaign), name=path.name, limits=limits)
        for record in reader:
            scan.add(record)
    summary = reader.summary
    return scan.finish(
        complete=complete,
        worker=summary.worker,
        records=summary.records,
        head=summary.head,
        torn_tail_bytes=summary.torn_tail_bytes,
    )
