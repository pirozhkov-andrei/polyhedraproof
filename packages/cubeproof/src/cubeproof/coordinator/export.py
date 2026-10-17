"""Prefix exports of the live journal: a backup with a published lag, not replication (specification
§7.5).

One export directory belongs to one journal and holds

``export.json``          the **descriptor**, written last and replaced atomically: format, journal
                         ID, ``seq``, ``head`` and byte ``offset`` of the exported prefix, the
                         name of the data file, its generation, how it was produced and when;
``journal.<g>.jsonl``    the data file of generation ``g``: the exported prefix is the first
                         ``offset`` bytes, nothing else is published. Bytes after ``offset`` are an
                         unfinished copy and are cut off by the next export.

One export (:func:`export_once`):

1. capture the committed ``(journal, seq, head, offset)`` under a brief shared lock
   (:func:`~cubeproof.evidence.journal.capture_anchor`: two lines are read, nothing is copied);
2. copy the immutable prefix ``[start, offset)`` **outside the lock** (append-only writers never
   change it) in bounded chunks, checking the hash chain (self, seq, prev) of every line;
3. check that the copied chain ends exactly at the captured anchor, fsync the data file (and the
   directory when the file is new);
4. publish the descriptor last (temporary file, fsync, atomic rename, directory fsync).

*Incremental* copy appends to the published data file when the previous exported prefix matches the
source (the last exported record is byte-identical in the source and is the descriptor's head);
*full* copy writes a new generation when there is no valid descriptor or the exported file is
damaged, and removes the old generation only after the new descriptor is published. A crash or
error at any point leaves the previous descriptor and its prefix intact: no unfinished prefix is
ever published. A source that does not contain the exported prefix (another journal, a shorter or a
forked history) is an integrity error and nothing is replaced: the export is a backup, and a backup
is never overwritten by something that is not its continuation.

The export is the journal as of the capture. Everything committed afterwards is unexported until
the next export (default every 60 s and at a clean stop): the recovery point objective is that
lag, which status publishes. It is neither a synchronous replica nor a zero-loss backup, and the
hash chain does not authenticate the writer (specification §7.1).

Before a run resumes (specification §7.3 step 2) the journal and the export directory are
compared (:func:`compare_export`), because the first record the run appends decides whether the
two stay one history:

* the export holds the journal's prefix (the usual lag) or exactly the journal: nothing to do;
* the export holds **more** than the journal and the journal file is byte for byte a prefix of
  the exported one (a results directory restored from a backup older than the export):
  :func:`restore_from_export` appends the missing exported bytes to the journal under the run
  lock, so the run resumes from the exported position instead of forking the published history;
* anything else (another journal, no journal, a different continuation, an export that claims
  more than the journal but cannot be verified) is an error before any record is written. The
  operator decides which history continues; nothing is replaced."""

from __future__ import annotations

import contextlib
import json
import os
import re
import stat
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any, TypeVar

from cubeproof.base.canonical_json import document_bytes, parse_document
from cubeproof.base.errors import (
    ConfigurationError,
    ContractError,
    CubeproofError,
    IntegrityError,
    ResourceError,
    ToolError,
)
from cubeproof.base.hashing import ZERO_HASH
from cubeproof.base.ids import new_id128
from cubeproof.base.settings import DEFAULT_LIMITS, ReaderLimits
from cubeproof.contracts.primitives import INT_MAX, format_utc, is_hash, is_utc
from cubeproof.evidence.journal import (
    CHUNK_BYTES,
    OS_CALLS,
    Anchor,
    JournalReader,
    RecordValidator,
    RunLock,
    SysCalls,
    capture_anchor,
    envelope_ok,
    unsigned_sha256,
)
from cubeproof.evidence.journal import write_all as journal_write_all
from cubeproof.evidence.journal.storage import LOCK_EX, LOCK_UN
from cubeproof.tools.atomic import (
    OS_FILE_CALLS,
    FileCalls,
    fsync,
    fsync_directory,
    os_failure,
    read_chunk,
    remove_quietly,
    write_all,
)

__all__ = [
    "DESCRIPTOR_NAME",
    "EXPORT_FORMAT",
    "ExportCancelled",
    "ExportDescriptor",
    "ExportResult",
    "ExportStanding",
    "JournalRestoreError",
    "compare_export",
    "export_once",
    "exported_records",
    "read_descriptor",
    "restore_from_export",
    "verify_export",
]

R = TypeVar("R")

EXPORT_FORMAT = "cubeproof-export-1"
DESCRIPTOR_NAME = "export.json"
_DATA_FILE = re.compile(r"journal\.([1-9][0-9]{0,17})\.jsonl")
_TEMPORARY = re.compile(r"\.export\.json\.[0-9a-f]{32}\.tmp")
_MODES = ("full", "incremental", "unchanged")
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_FIELDS = (
    "format",
    "journal",
    "seq",
    "head",
    "offset",
    "file",
    "generation",
    "mode",
    "captured_utc",
    "utc",
)


class ExportCancelled(ToolError):
    """The export was cancelled (shutdown or timeout); the published export is unchanged."""


@dataclass(frozen=True)
class ExportDescriptor:
    """What is published: the exported prefix ``[0, offset)`` of ``file`` ends at ``seq``/``head``.

    ``captured_utc`` is when the source position was captured (everything committed up to it is in
    the prefix); ``utc`` is when the descriptor was published; ``mode`` how the data was produced
    by the latest export (``full``, ``incremental`` or ``unchanged``: nothing new to copy).
    """

    journal: str
    seq: int
    head: str
    offset: int
    file: str
    generation: int
    mode: str
    captured_utc: str
    utc: str

    def to_json(self) -> dict[str, Any]:
        return {
            "format": EXPORT_FORMAT,
            "journal": self.journal,
            "seq": self.seq,
            "head": self.head,
            "offset": self.offset,
            "file": self.file,
            "generation": self.generation,
            "mode": self.mode,
            "captured_utc": self.captured_utc,
            "utc": self.utc,
        }

    @classmethod
    def from_json(cls, value: Any) -> ExportDescriptor:
        """Strict reader: exactly the fields, types and ranges of the descriptor."""
        if type(value) is not dict or set(value) != set(_FIELDS):
            raise ContractError("export.descriptor", "not exactly the descriptor fields")
        match = _DATA_FILE.fullmatch(value["file"]) if type(value["file"]) is str else None
        ok = (
            value["format"] == EXPORT_FORMAT
            and is_hash(value["journal"])
            and is_hash(value["head"])
            and _count(value["seq"], 0)
            and _count(value["offset"], 1)
            and match is not None
            and _count(value["generation"], 1)
            and int(match.group(1)) == value["generation"]
            and value["mode"] in _MODES
            and is_utc(value["captured_utc"])
            and is_utc(value["utc"])
        )
        if not ok:
            raise ContractError("export.descriptor", "a field is out of its contract")
        return cls(
            value["journal"],
            value["seq"],
            value["head"],
            value["offset"],
            value["file"],
            value["generation"],
            value["mode"],
            value["captured_utc"],
            value["utc"],
        )


def _count(value: object, minimum: int) -> bool:
    return type(value) is int and minimum <= value <= INT_MAX


@dataclass(frozen=True)
class ExportResult:
    """One successful export: the published descriptor and how it came about."""

    descriptor: ExportDescriptor
    #: ``full``, ``incremental`` or ``unchanged``
    mode: str
    #: Why a full copy was needed although a descriptor existed (None otherwise).
    reason: str | None
    bytes_copied: int
    elapsed_ms: int


def read_descriptor(
    directory: str | os.PathLike[str], *, calls: FileCalls = OS_FILE_CALLS
) -> ExportDescriptor | None:
    """The published descriptor, None if there is none; a damaged one is a ContractError."""
    path = os.path.join(os.fspath(directory), DESCRIPTOR_NAME)
    try:
        fd = calls.open(path, os.O_RDONLY | _NOFOLLOW)
    except FileNotFoundError:
        return None
    except OSError as error:
        raise ContractError("export.descriptor", f"{path}: {error}") from error
    try:
        data = read_chunk(calls, fd, 1 << 16, 0)
    except OSError as error:
        raise ContractError("export.descriptor", f"{path}: {error}") from error
    finally:
        calls.close(fd)
    try:
        return ExportDescriptor.from_json(parse_document(data))
    except CubeproofError as error:
        raise ContractError("export.descriptor", f"{path}: {error.rule}") from None


class _Chain:
    """Chain-only validation of the lines being copied (self, seq, prev, header position).

    The writer validated every record against the full schema and rules when it committed it; the
    export checks what makes the copy a faithful prefix: every line is a record whose ``self`` is
    the hash of the others, ``seq`` is contiguous, ``prev`` is the previous ``self`` and only the
    first line is a header. It resumes from a published ``(seq, head, offset)`` for incremental
    copies.
    """

    def __init__(
        self,
        limits: ReaderLimits,
        *,
        journal: str | None = None,
        records: int = 0,
        head: str | None = None,
        offset: int = 0,
    ) -> None:
        self.limits = limits
        self.journal = journal
        self.records = records
        self.head = head
        self.offset = offset
        self._carry = bytearray()

    def feed(self, data: bytes) -> None:
        buffer = self._carry
        buffer += data
        begin = 0
        while True:
            end = buffer.find(b"\n", begin)
            if end < 0:
                break
            if end - begin > self.limits.line_bytes:
                raise self._too_long()
            self._line(bytes(buffer[begin:end]))
            begin = end + 1
        del buffer[:begin]
        if len(buffer) > self.limits.line_bytes:
            raise self._too_long()

    def finish(self) -> None:
        if self._carry:
            raise IntegrityError(
                "export.chain", f"{len(self._carry)} bytes after the last complete line"
            )

    def _too_long(self) -> ResourceError:
        return ResourceError("limit.line", f"a line longer than {self.limits.line_bytes} bytes")

    def _line(self, line: bytes) -> None:
        where = f"record {self.records}"
        try:
            value = json.loads(line)
        except ValueError:
            raise IntegrityError("export.chain", "a line is not JSON", location=where) from None
        if not envelope_ok(value):
            raise IntegrityError("export.chain", "not a journal record", location=where)
        try:
            computed = unsigned_sha256(value)
        except (TypeError, ValueError):
            raise IntegrityError("export.chain", "not hashable", location=where) from None
        if computed != value["self"]:
            raise IntegrityError("journal.self", "self does not match", location=where)
        if value["seq"] != self.records:
            raise IntegrityError("journal.seq", f"seq {value['seq']}", location=where)
        expected = self.head if self.head is not None else ZERO_HASH
        if value["prev"] != expected:
            raise IntegrityError("journal.prev", "prev is not the previous self", location=where)
        if (self.records == 0) != (value["type"] == "header"):
            raise IntegrityError("journal.header", "seq 0 is the only header", location=where)
        if self.records == 0:
            self.journal = value["self"]
        self.records += 1
        self.offset += len(line) + 1
        self.head = value["self"]


def _clock_ms() -> int:
    return int(time.monotonic() * 1000)


def _last_line(calls: FileCalls, fd: int, end: int, limit: int) -> bytes | None:
    """The complete last line (without LF) of ``[0, end)``, None if it is not one."""
    want = min(end, limit + 2)
    data = read_chunk(calls, fd, want, end - want)
    if len(data) != want or data[-1:] != b"\n":
        return None
    body = data[:-1]
    index = body.rfind(b"\n")
    if index < 0:
        return body if want == end else None
    return body[index + 1 :]


def _record_of(line: bytes) -> dict[str, Any] | None:
    try:
        value = json.loads(line)
        if not envelope_ok(value) or unsigned_sha256(value) != value["self"]:
            return None
    except (ValueError, TypeError):
        return None
    result: dict[str, Any] = value
    return result


def _open(calls: FileCalls, path: str, flags: int, mode: int = 0o644) -> int:
    try:
        return calls.open(path, flags | _NOFOLLOW, mode)
    except FileNotFoundError:
        raise
    except OSError as error:
        raise os_failure("export.io", error, path) from error


def _regular(calls: FileCalls, fd: int, path: str) -> int:
    try:
        info = calls.fstat(fd)
    except OSError as error:
        raise os_failure("export.io", error, path) from error
    if not stat.S_ISREG(info.st_mode):
        raise ConfigurationError("export.layout", f"{path} is not a regular file")
    return info.st_size


def _check_prior(
    calls: FileCalls,
    directory: str,
    source_fd: int,
    descriptor: ExportDescriptor,
    limits: ReaderLimits,
) -> str | None:
    """None if the exported prefix can be extended; a reason if a full copy is needed.

    An exported file that is missing, short or damaged is local damage (full copy from the
    source); a source that does not contain the exported prefix is an IntegrityError.
    """
    path = os.path.join(directory, descriptor.file)
    try:
        fd = _open(calls, path, os.O_RDONLY)
    except FileNotFoundError:
        return "file_missing"
    try:
        size = _regular(calls, fd, path)
        if size < descriptor.offset:
            return "file_short"
        line = _last_line(calls, fd, descriptor.offset, limits.line_bytes)
    finally:
        calls.close(fd)
    record = None if line is None else _record_of(line)
    if (
        line is None
        or record is None
        or record["self"] != descriptor.head
        or record["seq"] != descriptor.seq
    ):
        return "file_damaged"
    held = read_chunk(calls, source_fd, len(line) + 1, descriptor.offset - len(line) - 1)
    if held != line + b"\n":
        raise IntegrityError(
            "export.diverged",
            f"the journal does not contain the exported record {descriptor.seq}",
        )
    return None


def _clean(calls: FileCalls, directory: str, keep: str) -> None:
    """Remove unfinished leftovers: generations the descriptor does not name, temporary files.

    Run after a descriptor was published (best effort): until then, the files of an older or
    damaged export are all that exists and are not touched."""
    try:
        names = calls.listdir(directory)
    except OSError:
        return
    for name in names:
        stale = _TEMPORARY.fullmatch(name) or (_DATA_FILE.fullmatch(name) and name != keep)
        if stale:
            remove_quietly(calls, os.path.join(directory, name))


def _publish(calls: FileCalls, directory: str, descriptor: ExportDescriptor) -> None:
    final = os.path.join(directory, DESCRIPTOR_NAME)
    temporary = os.path.join(directory, f".{DESCRIPTOR_NAME}.{new_id128()}.tmp")
    fd = _open(calls, temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    try:
        try:
            write_all(calls, fd, document_bytes(descriptor.to_json()))
        except OSError as error:
            raise os_failure("export.io", error, temporary) from error
        fsync(calls, fd, temporary)
    except BaseException as error:
        calls.close(fd)
        if isinstance(error, Exception):
            remove_quietly(calls, temporary)
        raise
    calls.close(fd)
    try:
        try:
            calls.rename(temporary, final)
        except OSError as error:
            raise os_failure("export.io", error, final) from error
        fsync_directory(calls, directory)
    except Exception:
        remove_quietly(calls, temporary)
        raise


def _capture(source: Path, journal_calls: SysCalls, limits: ReaderLimits) -> Anchor:
    try:
        return capture_anchor(source, limits=limits, calls=journal_calls)
    except OSError as error:
        raise os_failure("export.source", error, str(source)) from error


def export_once(
    source: str | os.PathLike[str],
    directory: str | os.PathLike[str],
    *,
    calls: FileCalls = OS_FILE_CALLS,
    journal_calls: SysCalls = OS_CALLS,
    limits: ReaderLimits = DEFAULT_LIMITS,
    chunk_bytes: int = CHUNK_BYTES,
    wall_ms: Callable[[], int] | None = None,
    progress: Callable[[int, int], None] | None = None,
    cancel: Callable[[], bool] | None = None,
    hook: Callable[[str], None] | None = None,
) -> ExportResult:
    """Export the committed prefix of the journal at ``source`` into ``directory`` (module doc).

    ``progress(done, total)`` reports bytes of the prefix handled so far; ``cancel()`` is asked
    between chunks and raises :class:`ExportCancelled`; ``hook(name)`` is a test seam called at the
    named points (``captured``, ``copied``, ``synced``, ``descriptor``, ``published``). Errors:
    :class:`~cubeproof.base.errors.IntegrityError` (the source does not extend the export, or the
    copied chain is wrong), ToolError/ResourceError (I/O, no space, fsync),
    ConfigurationError (the export directory belongs to another journal or is not a directory).
    Whatever happens, the published descriptor and its prefix are unchanged until the last step.
    """
    started = _clock_ms()
    now = wall_ms or (lambda: int(time.time() * 1000))
    source_path, target = Path(os.fspath(source)), os.fspath(directory)
    if chunk_bytes < 1:
        raise ConfigurationError("export.chunk", "the chunk size must be positive")

    def mark(name: str) -> None:
        if hook is not None:
            hook(name)

    def check_cancel() -> None:
        if cancel is not None and cancel():
            raise ExportCancelled("export.cancelled", "the export was cancelled")

    _ensure_directory(calls, target)
    try:
        previous = read_descriptor(target, calls=calls)
        invalid = False
    except ContractError:
        previous, invalid = None, True

    anchor = _capture(source_path, journal_calls, limits)
    captured = format_utc(now())
    mark("captured")
    if previous is not None and previous.journal != anchor.journal:
        raise ConfigurationError("export.foreign", "the export directory holds another journal")
    if previous is not None:
        if anchor.seq < previous.seq or anchor.offset < previous.offset:
            raise IntegrityError(
                "export.regressed",
                f"the journal ends at record {anchor.seq}, the export already holds {previous.seq}",
            )
        if anchor.seq == previous.seq and (anchor.head, anchor.offset) != (
            previous.head,
            previous.offset,
        ):
            raise IntegrityError(
                "export.diverged", f"record {previous.seq} of the journal is not the exported one"
            )
    try:
        source_fd = _open(calls, str(source_path), os.O_RDONLY)
    except FileNotFoundError:
        raise ToolError("export.source", f"{source_path} does not exist") from None
    try:
        reason: str | None = "descriptor_invalid" if invalid else None
        if previous is None:
            reason = reason or "no_descriptor"
        else:
            reason = _check_prior(calls, target, source_fd, previous, limits)
        if previous is not None and reason is None and anchor.seq == previous.seq:
            descriptor = ExportDescriptor(
                anchor.journal,
                anchor.seq,
                anchor.head,
                anchor.offset,
                previous.file,
                previous.generation,
                "unchanged",
                captured,
                format_utc(now()),
            )
            mark("descriptor")
            _publish(calls, target, descriptor)
            mark("published")
            _clean(calls, target, descriptor.file)
            return ExportResult(descriptor, "unchanged", None, 0, _clock_ms() - started)
        if previous is not None and reason is None:
            descriptor, copied = _extend(
                calls,
                target,
                source_fd,
                previous,
                anchor,
                captured,
                limits,
                chunk_bytes,
                progress,
                check_cancel,
                mark,
                now,
            )
            mode = "incremental"
        else:
            descriptor, copied = _rebuild(
                calls,
                target,
                source_fd,
                previous,
                anchor,
                captured,
                limits,
                chunk_bytes,
                progress,
                check_cancel,
                mark,
                now,
            )
            mode = "full"
    finally:
        calls.close(source_fd)
    _clean(calls, target, descriptor.file)
    return ExportResult(
        descriptor, mode, reason if mode == "full" else None, copied, _clock_ms() - started
    )


def _ensure_directory(calls: FileCalls, path: str) -> None:
    try:
        mode = calls.lstat(path).st_mode
    except FileNotFoundError:
        try:
            with contextlib.suppress(FileExistsError):
                calls.mkdir(path, 0o755)
            fsync_directory(calls, os.path.dirname(os.path.abspath(path)))
        except OSError as error:
            raise os_failure("export.io", error, path) from error
        return
    except OSError as error:
        raise os_failure("export.io", error, path) from error
    if not stat.S_ISDIR(mode):
        raise ConfigurationError("export.layout", f"{path} is not a directory")


def _copy(
    calls: FileCalls,
    source_fd: int,
    destination_fd: int,
    start: int,
    end: int,
    chain: _Chain,
    chunk_bytes: int,
    progress: Callable[[int, int], None] | None,
    check_cancel: Callable[[], None],
    destination: str,
) -> int:
    """Copy ``[start, end)`` of the source, chain-checking each chunk before it is written."""
    position = start
    if progress is not None:
        progress(0, end - start)
    while position < end:
        check_cancel()
        want = min(chunk_bytes, end - position)
        try:
            data = read_chunk(calls, source_fd, want, position)
        except OSError as error:
            raise os_failure("export.source", error, "the journal") from error
        if len(data) != want:
            raise IntegrityError("export.source_short", "the journal ends before the anchor")
        chain.feed(data)
        try:
            write_all(calls, destination_fd, data)
        except OSError as error:
            raise os_failure("export.io", error, destination) from error
        position += want
        if progress is not None:
            progress(position - start, end - start)
    chain.finish()
    return end - start


def _verify_end(chain: _Chain, anchor: Anchor) -> None:
    if (chain.journal, chain.records - 1, chain.head, chain.offset) != (
        anchor.journal,
        anchor.seq,
        anchor.head,
        anchor.offset,
    ):
        raise IntegrityError("export.chain", "the copied chain does not end at the captured anchor")


def _extend(
    calls: FileCalls,
    directory: str,
    source_fd: int,
    previous: ExportDescriptor,
    anchor: Anchor,
    captured: str,
    limits: ReaderLimits,
    chunk_bytes: int,
    progress: Callable[[int, int], None] | None,
    check_cancel: Callable[[], None],
    mark: Callable[[str], None],
    now: Callable[[], int],
) -> tuple[ExportDescriptor, int]:
    path = os.path.join(directory, previous.file)
    # Cut off an unfinished copy of an earlier attempt: only [0, offset) is published.
    try:
        os.truncate(path, previous.offset)
    except OSError as error:
        raise os_failure("export.io", error, path) from error
    fd = _open(calls, path, os.O_WRONLY | os.O_APPEND)
    chain = _Chain(
        limits,
        journal=previous.journal,
        records=previous.seq + 1,
        head=previous.head,
        offset=previous.offset,
    )
    try:
        copied = _copy(
            calls,
            source_fd,
            fd,
            previous.offset,
            anchor.offset,
            chain,
            chunk_bytes,
            progress,
            check_cancel,
            path,
        )
        mark("copied")
        _verify_end(chain, anchor)
        fsync(calls, fd, path)
    finally:
        calls.close(fd)
    mark("synced")
    descriptor = ExportDescriptor(
        anchor.journal,
        anchor.seq,
        anchor.head,
        anchor.offset,
        previous.file,
        previous.generation,
        "incremental",
        captured,
        format_utc(now()),
    )
    mark("descriptor")
    _publish(calls, directory, descriptor)
    mark("published")
    return descriptor, copied


def _rebuild(
    calls: FileCalls,
    directory: str,
    source_fd: int,
    previous: ExportDescriptor | None,
    anchor: Anchor,
    captured: str,
    limits: ReaderLimits,
    chunk_bytes: int,
    progress: Callable[[int, int], None] | None,
    check_cancel: Callable[[], None],
    mark: Callable[[str], None],
    now: Callable[[], int],
) -> tuple[ExportDescriptor, int]:
    generation = previous.generation + 1 if previous is not None else 1
    name = f"journal.{generation}.jsonl"
    path = os.path.join(directory, name)
    remove_quietly(calls, path)
    fd = _open(calls, path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    chain = _Chain(limits)
    try:
        try:
            copied = _copy(
                calls,
                source_fd,
                fd,
                0,
                anchor.offset,
                chain,
                chunk_bytes,
                progress,
                check_cancel,
                path,
            )
            mark("copied")
            _verify_end(chain, anchor)
            fsync(calls, fd, path)
        finally:
            calls.close(fd)
        fsync_directory(calls, directory)
    except Exception:
        remove_quietly(calls, path)
        raise
    mark("synced")
    descriptor = ExportDescriptor(
        anchor.journal,
        anchor.seq,
        anchor.head,
        anchor.offset,
        name,
        generation,
        "full",
        captured,
        format_utc(now()),
    )
    mark("descriptor")
    try:
        _publish(calls, directory, descriptor)
    except Exception:
        remove_quietly(calls, path)
        raise
    mark("published")
    return descriptor, copied


def verify_export(
    directory: str | os.PathLike[str],
    *,
    calls: FileCalls = OS_FILE_CALLS,
    limits: ReaderLimits = DEFAULT_LIMITS,
    chunk_bytes: int = CHUNK_BYTES,
) -> ExportDescriptor:
    """Check the published prefix of an export directory against its descriptor.

    Streams the first ``offset`` bytes of the named data file through the chain check and requires
    the chain to end exactly at the descriptor's ``(journal, seq, head, offset)``. Bytes after
    ``offset`` are ignored (an unfinished copy is not published). Raises IntegrityError when the
    prefix is incomplete or wrong, InputError when there is no descriptor.
    """
    root = os.fspath(directory)
    try:
        descriptor = read_descriptor(root, calls=calls)
    except ContractError as error:
        raise IntegrityError(error.rule, error.detail) from None
    if descriptor is None:
        raise ContractError("export.absent", f"{root} holds no export descriptor")
    path = os.path.join(root, descriptor.file)
    try:
        fd = calls.open(path, os.O_RDONLY | _NOFOLLOW)
    except OSError as error:
        raise IntegrityError("export.prefix", f"{descriptor.file}: {error.strerror}") from error
    try:
        chain = _Chain(limits)
        position = 0
        while position < descriptor.offset:
            want = min(chunk_bytes, descriptor.offset - position)
            data = read_chunk(calls, fd, want, position)
            if len(data) != want:
                raise IntegrityError("export.prefix", "the data file is shorter than the offset")
            chain.feed(data)
            position += want
        chain.finish()
    finally:
        calls.close(fd)
    if (chain.journal, chain.records - 1, chain.head, chain.offset) != (
        descriptor.journal,
        descriptor.seq,
        descriptor.head,
        descriptor.offset,
    ):
        raise IntegrityError("export.prefix", "the prefix does not end at the descriptor's head")
    return descriptor


# -- the journal and its export before a run resumes -----------------------------------------------

_KEEP = "keep the export directory: it is a backup"


@dataclass(frozen=True)
class ExportStanding:
    """How a journal stands to the export directory given for it (:func:`compare_export`).

    ``relation`` is ``absent`` (nothing is published there), ``unreadable`` (the descriptor is
    damaged: nothing is published, the next export is a full copy), ``behind`` (the export is
    a proper prefix of the journal: the usual lag), ``level`` (both end at the same record),
    ``ahead`` (the journal file is byte for byte a proper prefix of the exported one) or
    ``unknown`` (the journal's end or the exported file could not be read; the replay or the
    next export reports why). ``journal_bytes`` is the size of the journal file: its complete
    lines (``journal.offset``) and an unterminated suffix, if any.
    """

    relation: str
    descriptor: ExportDescriptor | None = None
    journal: Anchor | None = None
    journal_bytes: int = 0
    detail: str = ""


def _journal_end(
    path: Path, journal_calls: SysCalls, limits: ReaderLimits
) -> tuple[Anchor | None, int, str]:
    """``(anchor, size, problem)`` of the journal file; no anchor without a complete header."""
    anchor, size, problem = None, 0, ""
    try:
        size = os.stat(path).st_size
        if size:
            anchor = capture_anchor(path, limits=limits, calls=journal_calls)
    except FileNotFoundError:
        size = 0
    except OSError as error:
        raise os_failure("export.source", error, str(path)) from error
    except CubeproofError as error:
        # an empty file or a torn initial header is no journal yet (specification §7.1); any
        # other unreadable end is diagnosed precisely by the replay
        problem = "" if error.rule == "journal.no_header" else error.rule
    return anchor, size, problem


def _short(value: str) -> str:
    return value[:12]


def _regressed(descriptor: ExportDescriptor, anchor: Anchor, why: str) -> IntegrityError:
    return IntegrityError(
        "export.regressed",
        f"the journal ends at record {anchor.seq}, the export already holds {descriptor.seq}, "
        f"and the missing records cannot be restored from it: {why}. Nothing was changed. To "
        f"continue from this journal, move the export directory aside and start again ({_KEEP} "
        "of the longer history; only one of the two can be certified); otherwise restore a newer "
        "backup of the results",
    )


def _diverged(descriptor: ExportDescriptor, target: str, where: str) -> IntegrityError:
    return IntegrityError(
        "export.diverged",
        f"the journal and the export in {target} are different continuations of journal "
        f"{_short(descriptor.journal)} ({where}). Nothing was changed. Only one of the two "
        f"can be certified: to continue from this journal, move the export directory aside and "
        f"start again ({_KEEP} of the other history)",
    )


def _require_prefix(
    calls: FileCalls,
    source: Path,
    target: str,
    descriptor: ExportDescriptor,
    anchor: Anchor,
    size: int,
    chunk_bytes: int,
) -> None:
    """The journal file (``size`` bytes) must be a byte prefix of the exported prefix."""
    path = os.path.join(target, descriptor.file)
    try:
        exported = _open(calls, path, os.O_RDONLY)
    except FileNotFoundError:
        raise _regressed(
            descriptor, anchor, f"the data file {descriptor.file} is missing"
        ) from None
    try:
        if _regular(calls, exported, path) < descriptor.offset:
            raise _regressed(descriptor, anchor, f"the data file {descriptor.file} is incomplete")
        if size >= descriptor.offset:
            raise _diverged(
                descriptor, target, "the journal has fewer records but is not the shorter file"
            )
        try:
            journal = _open(calls, str(source), os.O_RDONLY)
        except FileNotFoundError:
            raise ToolError("export.source", f"{source} does not exist") from None
        try:
            position = 0
            while position < size:
                want = min(chunk_bytes, size - position)
                ours = read_chunk(calls, journal, want, position)
                theirs = read_chunk(calls, exported, want, position)
                if len(ours) != want:
                    raise IntegrityError("export.source_short", "the journal became shorter")
                if ours != theirs:
                    first = position + next(
                        (i for i in range(len(theirs)) if ours[i] != theirs[i]), len(theirs)
                    )
                    if first >= anchor.offset:
                        raise _regressed(
                            descriptor,
                            anchor,
                            "the journal ends in a partial line that is not the beginning of "
                            f"the exported record {anchor.seq + 1}",
                        )
                    raise _diverged(
                        descriptor,
                        target,
                        f"the files differ at byte {first}, before the journal's record "
                        f"{anchor.seq}: a different history or a damaged journal",
                    )
                position += want
        finally:
            calls.close(journal)
    except OSError as error:
        raise os_failure("export.io", error, path) from error
    finally:
        calls.close(exported)


def compare_export(
    source: str | os.PathLike[str],
    directory: str | os.PathLike[str],
    *,
    calls: FileCalls = OS_FILE_CALLS,
    journal_calls: SysCalls = OS_CALLS,
    limits: ReaderLimits = DEFAULT_LIMITS,
    chunk_bytes: int = CHUNK_BYTES,
) -> ExportStanding:
    """Compare the journal at ``source`` with the export in ``directory``; change nothing.

    Called under the run lock before the journal is replayed, repaired or appended to (module
    doc). Returns the :class:`ExportStanding`; raises, before a run can fork a published history,

    * ConfigurationError ``export.layout``: ``directory`` or its parent is not a directory;
    * ConfigurationError ``export.foreign``: the export is of another journal, or it is
      published and there is no journal (a new journal can never continue it);
    * IntegrityError ``export.diverged``: journal and export are different continuations of
      one journal;
    * IntegrityError ``export.regressed``: the export holds more records than the journal, and
      its data cannot supply them (missing or short file, or the journal's unterminated suffix
      is not the beginning of the next exported record).
    """
    source_path, target = Path(os.fspath(source)), os.fspath(directory)
    descriptor, detail = _published(calls, target)
    if descriptor is None:
        return ExportStanding("unreadable" if detail else "absent", detail=detail)
    anchor, size, problem = _journal_end(source_path, journal_calls, limits)
    if problem:
        return ExportStanding("unknown", descriptor, None, size, problem)
    held = f"journal {_short(descriptor.journal)} through record {descriptor.seq}"
    if anchor is None:
        raise ConfigurationError(
            "export.foreign",
            f"{target} holds the export of {held}, and {source_path} holds no journal. A new "
            "journal cannot continue it. If the results were lost, restore a backup of them and "
            "start again (the run takes the newer records from the export), or plan the open "
            "work of the exported journal into a new worker; a new journal needs its own, empty "
            f"--export directory ({_KEEP})",
        )
    if descriptor.journal != anchor.journal:
        raise ConfigurationError(
            "export.foreign",
            f"{target} holds the export of {held}; this worker's journal is "
            f"{_short(anchor.journal)}. Give the run its own --export directory ({_KEEP} of the "
            "other journal)",
        )
    relation, detail = "ahead", ""
    if descriptor.seq > anchor.seq:
        _require_prefix(calls, source_path, target, descriptor, anchor, size, chunk_bytes)
    elif descriptor.seq == anchor.seq:
        if (descriptor.head, descriptor.offset) != (anchor.head, anchor.offset):
            raise _diverged(descriptor, target, f"record {anchor.seq} differs")
        relation = "level"
    else:
        relation, detail = _behind(calls, source_path, target, descriptor, limits)
    return ExportStanding(relation, descriptor, anchor, size, detail)


def _published(calls: FileCalls, target: str) -> tuple[ExportDescriptor | None, str]:
    """``(descriptor, "")``, ``(None, "")`` when nothing is published in ``target`` or
    ``(None, why)`` when its descriptor is unreadable; ConfigurationError ``export.layout``."""
    try:
        mode = calls.lstat(target).st_mode
    except FileNotFoundError:
        parent = os.path.dirname(os.path.abspath(target))
        if not os.path.isdir(parent):
            raise ConfigurationError(
                "export.layout", f"{parent}, the parent of the export directory, does not exist"
            ) from None
        return None, ""
    except OSError as error:
        raise os_failure("export.io", error, target) from error
    if not stat.S_ISDIR(mode):
        raise ConfigurationError("export.layout", f"{target} is not a directory")
    try:
        return read_descriptor(target, calls=calls), ""
    except ContractError as error:
        return None, error.detail or error.rule


def _behind(
    calls: FileCalls, source: Path, target: str, descriptor: ExportDescriptor, limits: ReaderLimits
) -> tuple[str, str]:
    """``("behind", "")`` when the journal contains the last exported record (or the exported
    file is locally damaged: the next export is a full copy); ``("unknown", why)`` when that
    cannot be read now; IntegrityError ``export.diverged`` when the journal holds another one."""
    try:
        source_fd = _open(calls, str(source), os.O_RDONLY)
    except (FileNotFoundError, ToolError, ResourceError) as error:
        return "unknown", str(error)
    try:
        _check_prior(calls, target, source_fd, descriptor, limits)
    except IntegrityError:
        raise _diverged(
            descriptor, target, f"the journal does not contain the exported record {descriptor.seq}"
        ) from None
    except (ToolError, ResourceError, OSError) as error:
        return "unknown", str(error)
    finally:
        calls.close(source_fd)
    return "behind", ""


class _Prefix:
    """The first ``end`` bytes of a binary stream (the published prefix of a data file)."""

    def __init__(self, stream: Any, end: int) -> None:
        self._stream = stream
        self._left = end

    def read(self, size: int = -1, /) -> bytes:
        if self._left <= 0:
            return b""
        want = self._left if size < 0 else min(size, self._left)
        data: bytes = self._stream.read(want) or b""
        self._left -= len(data)
        return data


def exported_records(
    directory: str | os.PathLike[str],
    descriptor: ExportDescriptor,
    validator: RecordValidator[R],
    *,
    limits: ReaderLimits = DEFAULT_LIMITS,
) -> Iterator[R]:
    """The records of the published prefix, validated like a journal (schema, rules, chain).

    The prefix must end exactly at the descriptor's ``(journal, seq, head, offset)``; a reader
    error or IntegrityError ``journal.anchor`` otherwise (raised when the iteration ends)."""
    anchor = Anchor(descriptor.journal, descriptor.seq, descriptor.head, descriptor.offset)
    path = Path(os.fspath(directory), descriptor.file)
    with path.open("rb") as stream:
        reader = JournalReader(
            _Prefix(stream, descriptor.offset),
            validator,
            name=f"export/{descriptor.file}",
            limits=limits,
            anchor=anchor,
        )
        yield from reader
        summary = reader.summary
    if summary.torn_tail_bytes or summary.records != descriptor.seq + 1:
        raise IntegrityError(
            "journal.anchor",
            "the exported prefix does not end at its descriptor",
            location=path.name,
        )


class JournalRestoreError(ToolError):
    """The journal could not be completed from its export durably (``journal.restore``): an I/O
    failure while appending; the journal is still a prefix of the export."""


def restore_from_export(
    source: str | os.PathLike[str],
    directory: str | os.PathLike[str],
    standing: ExportStanding,
    *,
    run_lock: RunLock,
    inspect: Callable[[ExportDescriptor, Anchor], None] | None = None,
    calls: FileCalls = OS_FILE_CALLS,
    journal_calls: SysCalls = OS_CALLS,
    limits: ReaderLimits = DEFAULT_LIMITS,
    chunk_bytes: int = CHUNK_BYTES,
) -> int:
    """Append to the journal the exported records it lacks; return how many (module doc).

    ``standing`` is an ``ahead`` result of :func:`compare_export` for the same files, taken under
    the same held ``run_lock`` (no writer exists). ``inspect(descriptor, journal_anchor)`` is
    called before anything is written and refuses the restoration by raising: the caller
    validates the exported records against the campaign and checks that what the new records
    reference exists. Whatever it raises is reported as IntegrityError ``export.regressed``.

    The bytes ``[journal size, exported offset)`` are then chain-checked from the journal's head
    to the descriptor's head, appended in whole validated lines under the journal's exclusive
    lock and fsynced. The journal is afterwards byte for byte the exported prefix. A crash on the
    way leaves a journal that is still a byte prefix of the export: the next start completes it.
    """
    descriptor, anchor = standing.descriptor, standing.journal
    if standing.relation != "ahead" or descriptor is None or anchor is None:
        raise ValueError("only an export that is ahead of its journal is restored from")
    if not isinstance(run_lock, RunLock) or not run_lock.held:
        raise ConfigurationError("run.lock", "the run lock must be held to write a journal")
    if chunk_bytes < 1:
        raise ConfigurationError("export.chunk", "the chunk size must be positive")
    source_path, target = Path(os.fspath(source)), os.fspath(directory)
    path = os.path.join(target, descriptor.file)
    end = Anchor(descriptor.journal, descriptor.seq, descriptor.head, descriptor.offset)

    def chain() -> _Chain:
        return _Chain(
            limits,
            journal=anchor.journal,
            records=anchor.seq + 1,
            head=anchor.head,
            offset=anchor.offset,
        )

    def chunks(fd: int) -> Iterator[tuple[int, bytes]]:
        position = anchor.offset
        while position < descriptor.offset:
            want = min(chunk_bytes, descriptor.offset - position)
            try:
                data = read_chunk(calls, fd, want, position)
            except OSError as error:
                raise os_failure("export.io", error, path) from error
            if len(data) != want:
                raise IntegrityError("export.prefix", "the data file is shorter than the offset")
            yield position, data
            position += want

    try:
        if inspect is not None:
            inspect(descriptor, anchor)
        try:
            exported = _open(calls, path, os.O_RDONLY)
        except FileNotFoundError:
            raise IntegrityError("export.prefix", f"{descriptor.file} is missing") from None
        try:
            # 1. the whole tail is a chain from the journal's head to the descriptor's head
            checked = chain()
            for _, data in chunks(exported):
                checked.feed(data)
            checked.finish()
            _verify_end(checked, end)
            # 2. append it, in whole lines that were checked again
            _append_tail(journal_calls, source_path, standing, chain(), chunks(exported), end)
        finally:
            calls.close(exported)
    except CubeproofError as error:
        if isinstance(error, (ToolError, ResourceError)):
            raise
        why = f"{error.rule}: {error.detail}"
        if error.location:
            why += f" ({error.location})"
        raise _regressed(descriptor, anchor, why) from error
    return descriptor.seq - anchor.seq


def _append_tail(
    journal_calls: SysCalls,
    source: Path,
    standing: ExportStanding,
    checked: _Chain,
    chunks: Iterator[tuple[int, bytes]],
    end: Anchor,
) -> None:
    try:
        fd = journal_calls.open(str(source), os.O_WRONLY | os.O_APPEND)
    except OSError as error:
        raise JournalRestoreError("journal.restore", f"{source}: {error}") from error
    try:
        try:
            journal_calls.flock(fd, LOCK_EX)
            try:
                if journal_calls.size(fd) != standing.journal_bytes:
                    raise IntegrityError(
                        "run.tail", "the journal changed while it was compared with its export"
                    )
                written = standing.journal_bytes
                pending = bytearray()
                for position, data in chunks:
                    checked.feed(data)
                    pending += data[max(0, written - position) :]
                    ready = checked.offset - written
                    if ready > 0:
                        journal_write_all(journal_calls, fd, bytes(pending[:ready]))
                        del pending[:ready]
                        written += ready
                checked.finish()
                _verify_end(checked, end)
                journal_calls.fsync(fd)
            finally:
                journal_calls.flock(fd, LOCK_UN)
        except OSError as error:
            raise JournalRestoreError("journal.restore", f"{source}: {error}") from error
    finally:
        journal_calls.close(fd)
