"""Reading a journal: bounded complete lines, validation, torn tail, anchors (specification §7.1,
§10.1).

A line is J(record) + LF. Only a nonempty suffix **without** a terminating LF after the
complete lines is a torn tail: it is not parsed, only measured (length and SHA-256). Every
complete line is validated, also the last one; a complete invalid line is an error, never a
torn tail.

Order (requirements convention 10): every complete line's chain (reader limit, canonical
bytes, schema, self, seq, prev, journal.header, journal.campaign) is checked before a record
rule error is reported. The reader yields records while they pass every rule; at the first
record rule violation it stops yielding, continues the chain checks to the end of the file
and then raises the record rule violation (unless a chain error came first). Memory is bounded
by the line limit plus one read chunk: a line is never held beyond the limit.

``self`` detects accidental edits of a complete line; it is not a signature. Removing complete
records from the end, or replacing them by other validly chained records, leaves a valid
journal. Only a trusted external :class:`Anchor` (journal ID, seq, head and byte offset of a
committed record) detects that.
"""

from __future__ import annotations

import hashlib
import os
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO, Generic, Protocol

from cubeproof.base.errors import (
    ConfigurationError,
    CubeproofError,
    InputError,
    IntegrityError,
    ResourceError,
)
from cubeproof.base.settings import DEFAULT_LIMITS, ReaderLimits
from cubeproof.contracts.primitives import INT_MAX, is_hash
from cubeproof.evidence.journal.chain import ChainState, R, RecordValidator, located

#: Bytes requested per read; memory is at most the line limit plus this.
CHUNK_BYTES = 1 << 20


class ByteSource(Protocol):
    def read(self, size: int = -1, /) -> bytes | None: ...


@dataclass(frozen=True)
class Anchor:
    """A committed position: journal ID, seq and self of a record, and its end offset."""

    journal: str
    seq: int
    head: str
    offset: int

    def __post_init__(self) -> None:
        if not (
            is_hash(self.journal)
            and is_hash(self.head)
            and type(self.seq) is int
            and 0 <= self.seq <= INT_MAX
            and type(self.offset) is int
            and 0 < self.offset <= INT_MAX
        ):
            raise ConfigurationError("journal.anchor_value", f"invalid anchor {self!r}")


@dataclass(frozen=True)
class JournalSummary:
    """A validated journal: ID, worker, purpose, complete records/bytes, head, torn tail."""

    id: str
    worker: str
    purpose: str
    records: int
    bytes: int
    head: str
    torn_tail_bytes: int
    torn_tail_sha256: str | None

    @property
    def anchor(self) -> Anchor:
        """The anchor of the last complete record."""
        return Anchor(self.id, self.records - 1, self.head, self.bytes)


@dataclass(frozen=True)
class JournalContents(Generic[R]):
    """A whole validated journal: its records, summary, chain and the validator's state."""

    records: tuple[R, ...]
    summary: JournalSummary
    chain: ChainState
    validator: RecordValidator[R]


class _Lines:
    """Complete lines (without LF) of a byte source, never holding more than the limit."""

    def __init__(self, source: ByteSource, limit: int, where: Callable[[], str]) -> None:
        self._source = source
        self._limit = limit
        self._where = where
        self.torn_bytes = 0
        self.torn_sha256: str | None = None

    def _too_long(self) -> ResourceError:
        return ResourceError(
            "limit.line", f"a line longer than {self._limit} bytes", location=self._where()
        )

    def __iter__(self) -> Iterator[bytes]:
        buffer = bytearray()
        scanned = 0
        overlong: Any = None
        overlong_bytes = 0
        while True:
            chunk = self._source.read(CHUNK_BYTES)
            if chunk is None:
                raise OSError("the journal stream returned no data (non-blocking source)")
            if not chunk:
                break
            if overlong is not None:
                if b"\n" in chunk:
                    raise self._too_long()
                overlong.update(chunk)
                overlong_bytes += len(chunk)
                continue
            buffer += chunk
            begin = 0
            while True:
                position = buffer.find(b"\n", max(begin, scanned))
                if position < 0:
                    break
                if position - begin > self._limit:
                    raise self._too_long()
                line = bytes(buffer[begin:position])
                begin = position + 1
                yield line
            del buffer[:begin]
            scanned = len(buffer)
            if len(buffer) > self._limit:
                # Longer than any acceptable line: either it is completed later (limit.line)
                # or it is a torn tail, which is only measured.
                overlong = hashlib.sha256(buffer)
                overlong_bytes = len(buffer)
                buffer = bytearray()
                scanned = 0
        if overlong is not None:
            self.torn_bytes, self.torn_sha256 = overlong_bytes, overlong.hexdigest()
        elif buffer:
            self.torn_bytes, self.torn_sha256 = len(buffer), hashlib.sha256(buffer).hexdigest()


class _Limited:
    """The first ``end`` bytes of a source."""

    def __init__(self, source: ByteSource, end: int) -> None:
        self._source = source
        self._left = end

    def read(self, size: int = -1, /) -> bytes | None:
        if self._left <= 0:
            return b""
        want = self._left if size < 0 else min(size, self._left)
        data = self._source.read(want)
        if data:
            self._left -= len(data)
        return data


class JournalReader(Generic[R]):
    """Iterate the validated records of one journal stream (see module doc).

    ``validator`` checks record schema and rules (``cubeproof.evidence.schema.RecordSequence``)
    and is left holding the journal's committed identifiers. After complete iteration,
    :attr:`summary` describes the journal. ``anchor`` requires the journal to contain that
    committed record at that offset (IntegrityError journal.anchor).
    """

    def __init__(
        self,
        stream: ByteSource,
        validator: RecordValidator[R],
        *,
        name: str = "journal",
        limits: ReaderLimits = DEFAULT_LIMITS,
        anchor: Anchor | None = None,
    ) -> None:
        self.chain = ChainState(name=name, limits=limits)
        self.validator = validator
        self._anchor = anchor
        self._summary: JournalSummary | None = None
        self._lines = _Lines(stream, limits.line_bytes, self.chain.location)

    @property
    def summary(self) -> JournalSummary:
        if self._summary is None:
            raise RuntimeError("the journal has not been read completely")
        return self._summary

    def _anchor_error(self, detail: str) -> IntegrityError:
        return IntegrityError("journal.anchor", detail, location=self.chain.name)

    def _check_anchor(self) -> None:
        anchor, chain = self._anchor, self.chain
        if anchor is None or chain.records - 1 != anchor.seq:
            return
        if (chain.journal_id, chain.head, chain.offset) != (
            anchor.journal,
            anchor.head,
            anchor.offset,
        ):
            raise self._anchor_error(f"record {anchor.seq} differs from the anchor")

    def __iter__(self) -> Iterator[R]:
        chain, validator = self.chain, self.validator
        deferred: CubeproofError | None = None
        for line in self._lines:
            value = chain.check(line, validator)
            chain.advance(value, line)
            self._check_anchor()
            if deferred is not None:
                continue
            try:
                record = validator.check_rules(value)
            except CubeproofError as error:
                deferred = located(error, chain.location(chain.records - 1))
                continue
            validator.commit(record)
            yield record
        if chain.records == 0:
            raise InputError("journal.no_header", "no complete line", location=chain.name)
        anchor = self._anchor
        if anchor is not None and chain.records <= anchor.seq:
            raise self._anchor_error(
                f"{chain.records} complete records, the anchor names seq {anchor.seq}"
            )
        if deferred is not None:
            raise deferred
        if chain.head is None or chain.journal_id is None:  # pragma: no cover
            raise IntegrityError("journal.header", "no header", location=chain.name)
        self._summary = JournalSummary(
            id=chain.journal_id,
            worker=chain.worker or "",
            purpose=chain.purpose or "",
            records=chain.records,
            bytes=chain.offset,
            head=chain.head,
            torn_tail_bytes=self._lines.torn_bytes,
            torn_tail_sha256=self._lines.torn_sha256,
        )


def drain(reader: JournalReader[R]) -> JournalContents[R]:
    """Read every record of ``reader`` into memory (small journals, tests, snapshots)."""
    records = tuple(reader)
    return JournalContents(records, reader.summary, reader.chain, reader.validator)


def read_journal(
    source: str | os.PathLike[str] | BinaryIO | ByteSource,
    validator: RecordValidator[R],
    *,
    name: str | None = None,
    limits: ReaderLimits = DEFAULT_LIMITS,
    anchor: Anchor | None = None,
) -> JournalContents[R]:
    """Read and validate a whole journal file or stream (see :class:`JournalReader`)."""
    if isinstance(source, (str, os.PathLike)):
        path = Path(source)
        with path.open("rb") as stream:
            reader = JournalReader(
                stream, validator, name=name or path.name, limits=limits, anchor=anchor
            )
            return drain(reader)
    return drain(
        JournalReader(source, validator, name=name or "journal", limits=limits, anchor=anchor)
    )


def read_snapshot(
    path: str | os.PathLike[str],
    anchor: Anchor,
    validator: RecordValidator[R],
    *,
    limits: ReaderLimits = DEFAULT_LIMITS,
) -> JournalContents[R]:
    """Exactly the anchored prefix ``[0, anchor.offset)`` of a (possibly live) journal.

    Append-only writers never change committed bytes, so the prefix is read without a lock
    (specification §7.5 export). It must end with the anchored record, without a torn tail.
    """
    path = Path(path)
    with path.open("rb") as stream:
        reader = JournalReader(
            _Limited(stream, anchor.offset), validator, name=path.name, limits=limits, anchor=anchor
        )
        contents = drain(reader)
    summary = contents.summary
    if summary.torn_tail_bytes or summary.records != anchor.seq + 1:
        raise IntegrityError(
            "journal.anchor", "the prefix does not end at the anchor", location=path.name
        )
    return contents
