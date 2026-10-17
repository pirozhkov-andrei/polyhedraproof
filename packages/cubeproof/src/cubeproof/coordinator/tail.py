"""Following the journal the I/O service writes (specification §7.1, §8.1).

The service is the sole writer; the coordinator needs the **committed records** (their `utc` is
chosen by the service) to keep its scheduling state equal to the journal. :class:`JournalTail`
reads the complete lines after the last one it has seen and validates each exactly as the
journal reader does (canonical bytes, schema, self, seq, prev, then the record rules of the
shared :class:`~cubeproof.evidence.schema.RecordSequence`, with the certifier's attempt rules).
So the live state is a fold of independently validated records, and the position the service
reports for a commit is checked against what the file holds (the caller compares
``(seq, head)``).

A suffix without LF is a write in progress (the service holds the journal lock while it writes
and the coordinator takes none): it is kept until its LF arrives and never parsed. Nothing is
ever truncated or repaired here; repair is startup's, under the run lock, before the service
starts.
"""

from __future__ import annotations

import os
from pathlib import Path

from cubeproof.base.errors import CubeproofError, ResourceError
from cubeproof.base.settings import DEFAULT_LIMITS, ReaderLimits
from cubeproof.evidence.journal.chain import ChainState, located
from cubeproof.evidence.schema import Record, RecordSequence

__all__ = ["JournalTail"]

_CHUNK = 1 << 20


class JournalTail:
    """The validated records appended to a journal after the position of ``chain``."""

    def __init__(
        self,
        path: str | os.PathLike[str],
        chain: ChainState,
        validator: RecordSequence,
        *,
        limits: ReaderLimits = DEFAULT_LIMITS,
    ) -> None:
        self.path = Path(path)
        self.chain = chain
        self.validator = validator
        self._limits = limits
        self._buffer = bytearray()
        self._fd: int | None = None

    @property
    def seq(self) -> int:
        """The seq of the last validated record (-1 before the header)."""
        return self.chain.records - 1

    @property
    def head(self) -> str | None:
        return self.chain.head

    def _descriptor(self) -> int | None:
        if self._fd is None:
            try:
                self._fd = os.open(self.path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
            except FileNotFoundError:
                return None
        return self._fd

    def poll(self) -> list[Record]:
        """Every complete line appended since the last call, validated and committed to the
        shared validator; the records in order. IntegrityError (or another CubeproofError, with
        the line location) at the first defect; the tail is then unusable."""
        descriptor = self._descriptor()
        if descriptor is None:
            return []
        records: list[Record] = []
        while True:
            offset = self.chain.offset + len(self._buffer)
            data = os.pread(descriptor, _CHUNK, offset)
            if not data:
                break
            self._buffer += data
            records.extend(self._lines())
        return records

    def _lines(self) -> list[Record]:
        records: list[Record] = []
        begin = 0
        limit = self._limits.line_bytes
        chain, validator = self.chain, self.validator
        while True:
            end = self._buffer.find(b"\n", begin)
            if end < 0:
                break
            if end - begin > limit:
                raise ResourceError(
                    "limit.line", f"a line longer than {limit} bytes", location=chain.location()
                )
            line = bytes(self._buffer[begin:end])
            begin = end + 1
            value = chain.check(line, validator)
            chain.advance(value, line)
            try:
                record = validator.check_rules(value)
            except CubeproofError as error:
                raise located(error, chain.location(chain.records - 1)) from None
            validator.commit(record)
            records.append(record)
        del self._buffer[:begin]
        if len(self._buffer) > limit:
            raise ResourceError(
                "limit.line", f"a line longer than {limit} bytes", location=chain.location()
            )
        return records

    def close(self) -> None:
        fd, self._fd = self._fd, None
        if fd is not None:
            os.close(fd)
