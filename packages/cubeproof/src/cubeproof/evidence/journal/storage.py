"""Durable journal storage: append, locks, torn-tail repair, anchors (specification §7.1, §7.3,
§7.5).

Protocol (specification §7.1):

- One writer owns a worker journal; it holds the run lock (:class:`RunLock`, nonblocking
  exclusive ``results/run.lock``), which every writer constructor requires.
- :meth:`JournalWriter.append` builds the record (seq, prev, self) and validates its line
  exactly as a reader would (chain and the validator's rules) before any byte is written;
  then it takes the exclusive flock of the journal, validates the tail on disk (size and last
  line), writes the line with :func:`write_all` on an ``O_APPEND`` descriptor (short writes
  completed, EINTR retried), fsyncs, and only then returns the record (the acknowledgement).
  Every successful creation (new file, reused empty file, torn initial header) also syncs
  the directory before it returns.
- Any write, fsync or lock failure marks the writer failed: it never appends again (no second
  version, nothing after uncertain bytes). Recovery re-reads the disk: a complete committed
  line is recognized (``RecordSequence.committed_attempt``/``committed_request``) and the
  same attempt or request is refused, so it is never committed twice.
- A torn tail (nonempty suffix without LF after a valid prefix) is repaired under the lock:
  its length and hash are kept, it is truncated, the file is synced and a ``repair`` record
  is appended. A complete invalid line anywhere, including the last one, is an integrity
  error that no repair touches; it needs a backup.
- An empty file or one holding only a torn initial header is initialized by
  :meth:`JournalWriter.create` (under the run lock, before any work): the new header is
  written first, then a ``repair`` record with the removed bytes' length and hash. Nothing is
  inferred from the damaged header.
- After :meth:`JournalWriter.open` the first appended record must be a ``resume``; headers
  are written only by ``create`` and repairs only by recovery.
- :func:`capture_anchor` takes a shared flock briefly to read a committed position; the
  prefix is then copied and validated outside the lock (:func:`read_snapshot`).

System calls go through :class:`SysCalls` so that tests can inject faults. Journal writing
needs POSIX ``flock``/``fsync`` (Linux, specification §14); without ``fcntl`` the reader still works
and the writer refuses with ConfigurationError.
"""

from __future__ import annotations

import errno
import hashlib
import os
import time
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from types import TracebackType
from typing import Any, Generic

from cubeproof.base.canonical_json import encode, parse_line
from cubeproof.base.errors import (
    ConfigurationError,
    ContractError,
    CubeproofError,
    InputError,
    IntegrityError,
    ResourceError,
    ToolError,
)
from cubeproof.base.hashing import ZERO_HASH
from cubeproof.base.settings import DEFAULT_LIMITS, ReaderLimits
from cubeproof.contracts.primitives import format_utc
from cubeproof.evidence.journal.chain import (
    HEADER,
    JOURNAL_FORMAT,
    REPAIR,
    RESUME,
    ChainState,
    R,
    RecordValidator,
    envelope_ok,
    located,
)
from cubeproof.evidence.journal.reader import Anchor, JournalReader, JournalSummary

try:
    import fcntl
except ImportError:  # pragma: no cover - a system without fcntl can read journals, not lock them
    fcntl = None  # type: ignore[assignment]

LOCK_SH = 1
LOCK_EX = 2
LOCK_NB = 4
LOCK_UN = 8
if fcntl is not None:
    LOCK_SH, LOCK_EX, LOCK_NB, LOCK_UN = fcntl.LOCK_SH, fcntl.LOCK_EX, fcntl.LOCK_NB, fcntl.LOCK_UN

_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
_SCAN = 1 << 16


class JournalWriteError(ToolError):
    """The journal could not be written durably (I/O failure; exit 5 at the CLI, specification
    §12.2).

    Rules: ``journal.write``, ``journal.fsync``, ``journal.lock`` (the failing call; the
    OSError is the cause), ``journal.failed`` (a writer after such a failure),
    ``journal.closed``.
    """


class SysCalls:
    """The system calls of journal storage; replaced in tests to inject faults."""

    def open(self, path: str, flags: int, mode: int = 0o644) -> int:
        return os.open(path, flags | _CLOEXEC, mode)

    def close(self, fd: int) -> None:
        os.close(fd)

    def write(self, fd: int, data: memoryview) -> int:
        return os.write(fd, data)

    def fsync(self, fd: int) -> None:
        os.fsync(fd)

    def flock(self, fd: int, operation: int) -> None:
        if fcntl is None:  # pragma: no cover - a system without fcntl
            raise ConfigurationError("journal.platform", "journal locks need POSIX flock")
        fcntl.flock(fd, operation)

    def ftruncate(self, fd: int, length: int) -> None:
        os.ftruncate(fd, length)

    def size(self, fd: int) -> int:
        return os.fstat(fd).st_size

    def pread(self, fd: int, count: int, offset: int) -> bytes:
        return os.pread(fd, count, offset)


OS_CALLS = SysCalls()


def write_all(calls: SysCalls, fd: int, data: bytes) -> None:
    """Write every byte of ``data``: complete short writes, retry EINTR, refuse no progress."""
    view = memoryview(data)
    while view.nbytes:
        try:
            count = calls.write(fd, view)
        except InterruptedError:
            continue
        if type(count) is not int or count <= 0:
            raise OSError(errno.EIO, f"write accepted {count!r} bytes")
        if count > view.nbytes:
            raise OSError(errno.EIO, f"write reported {count} of {view.nbytes} bytes")
        view = view[count:]


def _now() -> str:
    return format_utc(time.time_ns() // 1_000_000)


class RunLock:
    """The nonblocking exclusive lock of a results directory (``results/run.lock``, specification
    §7.3)."""

    def __init__(self, path: Path, fd: int, calls: SysCalls) -> None:
        self.path = path
        self._fd: int | None = fd
        self._calls = calls

    @classmethod
    def acquire(cls, path: str | os.PathLike[str], *, calls: SysCalls = OS_CALLS) -> RunLock:
        """Take the lock or fail at once (ConfigurationError ``run.locked``: a live owner)."""
        path = Path(path)
        fd = calls.open(str(path), os.O_RDWR | os.O_CREAT, 0o644)
        try:
            calls.flock(fd, LOCK_EX | LOCK_NB)
        except BlockingIOError:
            calls.close(fd)
            raise ConfigurationError("run.locked", f"{path} is held by a live process") from None
        except BaseException:
            calls.close(fd)
            raise
        return cls(path, fd, calls)

    @property
    def held(self) -> bool:
        return self._fd is not None

    def release(self) -> None:
        fd, self._fd = self._fd, None
        if fd is not None:
            self._calls.close(fd)

    def __enter__(self) -> RunLock:
        return self

    def __exit__(self, *exc: object) -> None:
        self.release()


def _require(run_lock: RunLock) -> None:
    if not isinstance(run_lock, RunLock) or not run_lock.held:
        raise ConfigurationError("run.lock", "the run lock must be held to write a journal")


class _FdSource:
    """Sequential reads of a descriptor through ``pread`` (the writer's own descriptor)."""

    def __init__(self, calls: SysCalls, fd: int) -> None:
        self._calls = calls
        self._fd = fd
        self._offset = 0

    def read(self, size: int = -1, /) -> bytes:
        data = self._calls.pread(self._fd, _SCAN if size < 0 else size, self._offset)
        self._offset += len(data)
        return data


@dataclass(frozen=True)
class RepairOutcome:
    """A removed torn tail and the repair record (the validator's record) documenting it."""

    removed_bytes: int
    removed_sha256: str
    record: Any


def _contains_lf(calls: SysCalls, fd: int, size: int) -> tuple[bool, str]:
    """Whether ``fd`` holds an LF, and the SHA-256 of all its bytes."""
    digest = hashlib.sha256()
    offset = 0
    found = False
    while offset < size:
        data = calls.pread(fd, min(_SCAN, size - offset), offset)
        if not data:
            break
        found = found or b"\n" in data
        digest.update(data)
        offset += len(data)
    return found, digest.hexdigest()


class JournalWriter(Generic[R]):
    """The single writer of one journal file (see module doc). Use :meth:`create`/:meth:`open`.

    ``validator`` (``cubeproof.evidence.schema.RecordSequence``) checks every record exactly
    as the journal reader does and keeps the journal's committed identifiers.
    """

    def __init__(
        self,
        path: Path,
        fd: int,
        chain: ChainState,
        validator: RecordValidator[R],
        calls: SysCalls,
        *,
        session: bool,
    ) -> None:
        self.path = path
        self._fd = fd
        self._calls = calls
        self.chain = chain
        self.validator = validator
        self.failed = False
        self.repaired: RepairOutcome | None = None
        self._session = session
        self._closed = False

    # -- construction --------------------------------------------------------------------------

    @classmethod
    def create(
        cls,
        path: str | os.PathLike[str],
        header: Any,
        *,
        validator: RecordValidator[R],
        run_lock: RunLock,
        utc: str | None = None,
        limits: ReaderLimits = DEFAULT_LIMITS,
        calls: SysCalls = OS_CALLS,
    ) -> JournalWriter[R]:
        """Start a journal with ``header`` (new file, empty file or a torn initial header).

        The header is validated before the file is touched. An existing file with a complete
        line is refused (ConfigurationError ``journal.exists``; use :meth:`open`).
        """
        _require(run_lock)
        path = Path(path)
        payload = validator.payload_json(header)
        if payload.get("type") != HEADER:
            raise ContractError("journal.session", "a journal starts with a header")
        chain = ChainState(name=path.name, limits=limits)
        prepared = _prepare(chain, validator, payload, utc)
        created = True
        try:
            fd = calls.open(str(path), os.O_RDWR | os.O_APPEND | os.O_CREAT | os.O_EXCL, 0o644)
        except FileExistsError:
            created = False
            fd = calls.open(str(path), os.O_RDWR | os.O_APPEND)
        writer = cls(path, fd, chain, validator, calls, session=True)
        try:
            writer._lock()
            try:
                removed: tuple[int, str] | None = None
                if not created:
                    size = writer._io("journal.write", calls.size, fd)
                    has_line, digest = writer._io("journal.write", _contains_lf, calls, fd, size)
                    if has_line:
                        raise ConfigurationError("journal.exists", f"{path} already has records")
                    if size:
                        removed = (size, digest)
                        writer._io("journal.write", calls.ftruncate, fd, 0)
                        writer._io("journal.fsync", calls.fsync, fd)
                writer._write(prepared, check_tail=False)
                # Also for a reused empty file or torn header: an earlier run may have died
                # before its directory sync, so the entry may not be durable yet (specification
                # §7.1).
                writer._sync_directory()
                if removed is not None:
                    writer.repaired = writer._repair(*removed, utc=utc)
            finally:
                writer._unlock()
        except BaseException:
            writer.close()
            raise
        return writer

    @classmethod
    def open(
        cls,
        path: str | os.PathLike[str],
        *,
        validator: RecordValidator[R],
        run_lock: RunLock,
        utc: str | None = None,
        limits: ReaderLimits = DEFAULT_LIMITS,
        calls: SysCalls = OS_CALLS,
    ) -> JournalWriter[R]:
        """Continue an existing journal: validate it whole, repair a torn tail.

        Raises the reader's errors (a complete invalid line is never repaired) and InputError
        ``journal.no_header`` for a file without a complete line (use :meth:`create`).
        The containing directory is synced before it returns. The next appended record must
        be a resume.
        """
        _require(run_lock)
        return cls._recover(Path(path), validator, utc, limits, calls)

    @classmethod
    def _recover(
        cls,
        path: Path,
        validator: RecordValidator[R],
        utc: str | None,
        limits: ReaderLimits,
        calls: SysCalls,
    ) -> JournalWriter[R]:
        fd = calls.open(str(path), os.O_RDWR | os.O_APPEND)
        writer = cls(path, fd, ChainState(name=path.name), validator, calls, session=False)
        try:
            writer._lock()
            try:
                size = writer._io("journal.write", calls.size, fd)
                reader = JournalReader(
                    _FdSource(calls, fd), validator, name=path.name, limits=limits
                )
                for _ in reader:
                    pass
                summary = reader.summary
                writer.chain = reader.chain
                if summary.torn_tail_bytes:
                    if writer._io("journal.write", calls.size, fd) != size:
                        raise IntegrityError("journal.tail", "the file changed during recovery")
                    digest = summary.torn_tail_sha256
                    assert digest is not None
                    writer._io("journal.write", calls.ftruncate, fd, summary.bytes)
                    writer._io("journal.fsync", calls.fsync, fd)
                    writer.repaired = writer._repair(summary.torn_tail_bytes, digest, utc=utc)
                # As in create: the run that made the file may have died before its directory
                # sync, so the entry may not be durable yet; sync it before anything this
                # writer appends is acknowledged (specification §7.1).
                writer._sync_directory()
            finally:
                writer._unlock()
        except BaseException:
            writer.close()
            raise
        return writer

    # -- appending -----------------------------------------------------------------------------

    def append(self, payload: Any, *, utc: str | None = None) -> R:
        """Commit ``payload`` as the next record; return it only after it is durable."""
        self._usable()
        value = self.validator.payload_json(payload)
        kind = value.get("type")
        if kind in (HEADER, REPAIR):
            raise ContractError("journal.session", f"a {kind} record is not appended by callers")
        if not self._session and kind != RESUME:
            raise ContractError("journal.session", "a resume precedes new activity")
        prepared = _prepare(self.chain, self.validator, value, utc)
        self._lock()
        try:
            self._write(prepared, check_tail=True)
        finally:
            self._unlock()
        if kind == RESUME:
            self._session = True
        return prepared.record

    def _usable(self) -> None:
        if self._closed:
            raise JournalWriteError("journal.closed", f"{self.path} writer is closed")
        if self.failed:
            raise JournalWriteError("journal.failed", f"{self.path}: an earlier write failed")

    def _io(self, rule: str, call: Any, *args: Any) -> Any:
        try:
            return call(*args)
        except OSError as exc:
            self.failed = True
            raise JournalWriteError(rule, f"{self.path}: {exc}") from exc

    def _lock(self) -> None:
        self._io("journal.lock", self._calls.flock, self._fd, LOCK_EX)

    def _unlock(self) -> None:
        self._io("journal.lock", self._calls.flock, self._fd, LOCK_UN)

    def _check_tail(self) -> None:
        """The file still ends exactly with the last line this writer validated or wrote."""
        chain = self.chain
        expected = b"" if chain.last_line is None else chain.last_line + b"\n"
        size = self._io("journal.write", self._calls.size, self._fd)
        tail = b""
        if size == chain.offset and expected:
            start = chain.offset - len(expected)
            tail = self._io("journal.write", self._calls.pread, self._fd, len(expected), start)
        if size != chain.offset or tail != expected:
            self.failed = True
            raise IntegrityError(
                "journal.tail", f"{self.path} changed outside this writer", location=chain.name
            )

    def _write(self, prepared: _Prepared[R], *, check_tail: bool) -> None:
        """Under the lock: tail check, write_all, fsync, then the in-memory commit."""
        if check_tail:
            self._check_tail()
        self._io("journal.write", write_all, self._calls, self._fd, prepared.line + b"\n")
        self._io("journal.fsync", self._calls.fsync, self._fd)
        self.chain.advance(prepared.value, prepared.line)
        self.validator.commit(prepared.record)

    def _repair(self, removed: int, digest: str, *, utc: str | None) -> RepairOutcome:
        payload = {"type": REPAIR, "removed_bytes": removed, "removed_sha256": digest}
        prepared = _prepare(self.chain, self.validator, payload, utc)
        self._write(prepared, check_tail=False)
        return RepairOutcome(removed, digest, prepared.record)

    def _sync_directory(self) -> None:
        calls = self._calls
        directory = self._io(
            "journal.fsync", calls.open, str(self.path.parent), os.O_RDONLY | _DIRECTORY
        )
        try:
            self._io("journal.fsync", calls.fsync, directory)
        finally:
            calls.close(directory)

    # -- state ---------------------------------------------------------------------------------

    @property
    def summary(self) -> JournalSummary:
        chain = self.chain
        assert chain.head is not None and chain.journal_id is not None
        return JournalSummary(
            id=chain.journal_id,
            worker=chain.worker or "",
            purpose=chain.purpose or "",
            records=chain.records,
            bytes=chain.offset,
            head=chain.head,
            torn_tail_bytes=0,
            torn_tail_sha256=None,
        )

    def fileno(self) -> int:
        return self._fd

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            self._calls.close(self._fd)

    def __enter__(self) -> JournalWriter[R]:
        return self

    def __exit__(
        self,
        kind: type[BaseException] | None,
        error: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()


@dataclass(frozen=True)
class _Prepared(Generic[R]):
    value: dict[str, Any]
    line: bytes
    record: R


def _prepare(
    chain: ChainState, validator: RecordValidator[R], payload: Mapping[str, Any], utc: str | None
) -> _Prepared[R]:
    """The next line of ``chain`` for a payload value, checked exactly as a reader checks it."""
    value: dict[str, Any] = dict(payload)
    value.update(
        format=JOURNAL_FORMAT,
        seq=chain.records,
        prev=chain.head if chain.head is not None else ZERO_HASH,
        utc=utc or _now(),
    )
    value.pop("self", None)
    try:
        # J of the unsigned record first: a value J cannot encode (e.g. a lone surrogate in
        # a payload string) is a typed contract error, not a codec exception while hashing.
        value["self"] = hashlib.sha256(encode(value)).hexdigest()
        line = encode(value)
    except CubeproofError as error:
        raise located(error, chain.location()) from None
    checked = chain.check(line, validator)
    try:
        record = validator.check_rules(checked)
    except CubeproofError as error:
        raise located(error, chain.location()) from None
    return _Prepared(checked, line, record)


def repair_journal(
    path: str | os.PathLike[str],
    *,
    validator: RecordValidator[Any],
    run_lock: RunLock,
    utc: str | None = None,
    limits: ReaderLimits = DEFAULT_LIMITS,
    calls: SysCalls = OS_CALLS,
) -> RepairOutcome | None:
    """``journal repair``: remove only a torn tail, recording it; None if there is none.

    Requires the containing results' run lock (a live coordinator refuses it). A file
    without a complete line is InputError journal.no_header (a torn initial header needs a
    new header from its owner, :meth:`JournalWriter.create`); any invalid complete line is
    the reader's error and the file is left unchanged for restoration from a backup.
    """
    _require(run_lock)
    writer = JournalWriter._recover(Path(path), validator, utc, limits, calls)
    try:
        return writer.repaired
    finally:
        writer.close()


def _record_at(calls: SysCalls, fd: int, start: int, end: int, limits: ReaderLimits) -> Any:
    if end - start > limits.line_bytes:
        raise ResourceError("limit.line", f"a line longer than {limits.line_bytes} bytes")
    try:
        value = parse_line(calls.pread(fd, end - start, start), limits=limits)
    except CubeproofError as error:
        raise located(error, f"{start}") from None
    if not envelope_ok(value):
        raise IntegrityError("schema", "not a journal record", location=f"{start}")
    return value


def capture_anchor(
    path: str | os.PathLike[str],
    *,
    limits: ReaderLimits = DEFAULT_LIMITS,
    calls: SysCalls = OS_CALLS,
) -> Anchor:
    """The committed position of a journal, read under a brief shared lock (specification §7.5).

    Reads only the first and the last complete line; a torn tail is ignored. The anchor is
    not trusted by itself: :func:`read_snapshot` validates the copied prefix against it.
    """
    path = Path(path)
    fd = calls.open(str(path), os.O_RDONLY)
    try:
        calls.flock(fd, LOCK_SH)
        try:
            size = calls.size(fd)
            end = _last_lf(calls, fd, size) + 1
            if end == 0:
                raise InputError("journal.no_header", "no complete line", location=path.name)
            start = _last_lf(calls, fd, end - 1, floor=max(0, end - 2 - limits.line_bytes)) + 1
            last = _record_at(calls, fd, start, end - 1, limits)
            first = last
            if start > 0:
                first = _record_at(calls, fd, 0, _first_lf(calls, fd, end, limits), limits)
        finally:
            calls.flock(fd, LOCK_UN)
    finally:
        calls.close(fd)
    return Anchor(first["self"], last["seq"], last["self"], end)


def _last_lf(calls: SysCalls, fd: int, before: int, floor: int = 0) -> int:
    """Offset of the last LF in ``[floor, before)``, or ``floor - 1`` if there is none."""
    position = before
    while position > floor:
        start = max(floor, position - _SCAN)
        data = calls.pread(fd, position - start, start)
        index = data.rfind(b"\n")
        if index >= 0:
            return start + index
        position = start
    return floor - 1


def _first_lf(calls: SysCalls, fd: int, end: int, limits: ReaderLimits) -> int:
    position = 0
    stop = min(end, limits.line_bytes + 1)
    while position < stop:
        data = calls.pread(fd, min(_SCAN, stop - position), position)
        index = data.find(b"\n")
        if index >= 0:
            return position + index
        position += len(data)
    raise ResourceError("limit.line", f"a line longer than {limits.line_bytes} bytes")
