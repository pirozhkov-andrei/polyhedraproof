"""The inbox: shard and handoff-request files published by other users (specification §7.4, §7.5).

An inbox is a directory that receives, by atomic publication (written under a dot-prefixed or
``.tmp`` name, then renamed), two kinds of canonical documents:

* ``cubeproof-shard-1`` files: work offered to this worker;
* ``cubeproof-handoff-request-1`` files: requests that this worker give work away.

:func:`scan` reads and classifies the regular files (names starting with ``.`` or ending in
``.tmp``/``.part`` are in-transit files and ignored; links and directories are never followed).
A file is re-read only when its size, modification time or inode changes.

* ``SHARD``/``REQUEST``: a canonical document of that format, valid on its own (nodes sorted and
  pairwise incompatible, formulas and ranges of the campaign);
* ``INVALID``: canonical JSON that is no valid shard or request: **rejected** (moved to
  ``rejected/`` with a ``.reason.txt`` diagnostic);
* ``UNREADABLE``: not canonical JSON, too large, not a regular file. It may be a copy still in
  progress, so it **stays** where it is and is reported until it changes.

Files leave the inbox into three sibling directories, never deleted: ``accepted/`` (a shard whose
record is committed), ``processed/`` (a request whose handoff is committed and whose output is
durable) and ``rejected/``. :func:`move_into` is repeatable at every step: it links the file into
the target (``link`` never replaces; equal bytes already there are the earlier half of the same
move), syncs the target directory, unlinks the source, syncs its directory. A crash leaves the
file in the inbox, in both places, or only in the target; a rerun finishes the move.
"""

from __future__ import annotations

import contextlib
import enum
import hashlib
import stat
from collections.abc import Mapping
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from cubeproof.base.canonical_json import parse_document
from cubeproof.base.errors import ContractError, IntegrityError, ResourceError
from cubeproof.base.settings import DEFAULT_LIMITS, ReaderLimits
from cubeproof.contracts.documents import HandoffRequest, Shard
from cubeproof.coordinator.outbox import ensure_tree, exists
from cubeproof.tools.atomic import (
    OS_FILE_CALLS,
    FileCalls,
    atomic_write,
    fsync_directory,
    link_no_replace,
    open_regular,
    read_chunk,
)

__all__ = [
    "ACCEPTED",
    "PROCESSED",
    "REJECTED",
    "InboxFile",
    "Kind",
    "move_into",
    "read_file",
    "scan",
    "write_reason",
]

ACCEPTED, REJECTED, PROCESSED = "accepted", "rejected", "processed"
SHARD_FORMAT = "cubeproof-shard-1"
REQUEST_FORMAT = "cubeproof-handoff-request-1"
_IN_TRANSIT = (".tmp", ".part")


class Kind(str, enum.Enum):
    SHARD = "shard"
    REQUEST = "request"
    INVALID = "invalid"
    UNREADABLE = "unreadable"


@dataclass(frozen=True)
class InboxFile:
    """One classified file of the inbox (see the module doc for the kinds)."""

    name: str
    path: Path
    signature: tuple[int, int, int]
    kind: Kind
    sha256: str = ""
    shard: Shard | None = None
    request: HandoffRequest | None = None
    rule: str = ""
    detail: str = ""

    @property
    def problem(self) -> str:
        return f"{self.rule}: {self.detail}" if self.detail else self.rule


def _bad(item: InboxFile, kind: Kind, error: ContractError | ResourceError) -> InboxFile:
    return replace(item, kind=kind, rule=error.rule, detail=error.detail)


def _classify(item: InboxFile, data: bytes, limits: ReaderLimits, variables: Any) -> InboxFile:
    """The kind of the file whose bytes are ``data`` (see the module doc)."""
    try:
        value = parse_document(data, limits=limits)
    except (ContractError, ResourceError) as error:
        return _bad(item, Kind.UNREADABLE, error)
    kind = value.get("format") if isinstance(value, dict) else None
    try:
        if kind == SHARD_FORMAT:
            return replace(item, kind=Kind.SHARD, shard=Shard.from_json(value, variables=variables))
        if kind == REQUEST_FORMAT:
            return replace(item, kind=Kind.REQUEST, request=HandoffRequest.from_json(value))
    except (ContractError, ResourceError) as error:
        return _bad(item, Kind.INVALID, error)
    return replace(
        item,
        kind=Kind.INVALID,
        rule="inbox.format",
        detail="a canonical document that is neither a shard nor a handoff request",
    )


def read_file(
    path: Path,
    signature: tuple[int, int, int],
    *,
    limits: ReaderLimits = DEFAULT_LIMITS,
    variables: Mapping[str, int] | None = None,
    calls: FileCalls = OS_FILE_CALLS,
) -> InboxFile:
    """Read and classify one regular file. FileNotFoundError if it vanished meanwhile."""
    item = InboxFile(path.name, path, signature, Kind.UNREADABLE)
    try:
        fd, size = open_regular(calls, str(path))
    except ContractError as error:
        return _bad(item, Kind.UNREADABLE, error)
    try:
        if size > limits.document_bytes + 2:
            detail = f"{size} bytes, limit {limits.document_bytes}"
            return _bad(item, Kind.UNREADABLE, ResourceError("limit.document", detail))
        data = read_chunk(calls, fd, size + 1, 0)
    finally:
        calls.close(fd)
    return _classify(
        replace(item, sha256=hashlib.sha256(data).hexdigest()), data, limits, variables
    )


def scan(
    directory: Path,
    known: dict[str, InboxFile],
    *,
    limits: ReaderLimits = DEFAULT_LIMITS,
    variables: Mapping[str, int] | None = None,
    calls: FileCalls = OS_FILE_CALLS,
) -> list[InboxFile]:
    """The classified regular files of ``directory`` sorted by name; ``known`` caches by
    signature and is updated (files that disappeared are dropped)."""
    try:
        names = sorted(calls.listdir(str(directory)))
    except FileNotFoundError:
        known.clear()
        return []
    found: list[InboxFile] = []
    for name in names:
        if name.startswith(".") or name.endswith(_IN_TRANSIT):
            continue
        path = directory / name
        try:
            info = calls.lstat(str(path))
        except FileNotFoundError:
            continue
        if stat.S_ISDIR(info.st_mode):
            continue
        signature = (info.st_size, info.st_mtime_ns, info.st_ino)
        cached = known.get(name)
        if cached is not None and cached.signature == signature:
            found.append(cached)
            continue
        try:
            item = read_file(path, signature, limits=limits, variables=variables, calls=calls)
        except FileNotFoundError:
            continue
        known[name] = item
        found.append(item)
    for gone in set(known) - {f.name for f in found}:
        del known[gone]
    return found


def _hash_of(path: Path, calls: FileCalls) -> str | None:
    try:
        fd, size = open_regular(calls, str(path))
    except (FileNotFoundError, ContractError):
        return None
    try:
        return hashlib.sha256(read_chunk(calls, fd, size + 1, 0)).hexdigest()
    finally:
        calls.close(fd)


def move_into(path: Path, directory: Path, sha256: str, calls: FileCalls = OS_FILE_CALLS) -> Path:
    """Move the file ``path`` (whose bytes hash to ``sha256``) into ``directory``; the new path.

    Repeatable: see the module doc. A file whose bytes are no longer ``sha256`` (replaced after it
    was read) is not moved: IntegrityError ``inbox.changed``, the next scan reads it again. If
    the name is taken by a file with other bytes, the name ``<name>.<sha256[:16]>`` is used; if
    that is taken by other bytes too, IntegrityError ``inbox.move``."""
    current = _hash_of(path, calls)
    if current is not None and current != sha256:
        raise IntegrityError("inbox.changed", f"{path} changed after it was read; not moved")
    ensure_tree(directory, calls)
    target = directory / path.name
    for candidate in (directory / path.name, directory / f"{path.name}.{sha256[:16]}"):
        target = candidate
        try:
            if link_no_replace(calls, str(path), str(target)):
                break
        except FileNotFoundError:
            pass  # the source is gone: an earlier, interrupted call may have finished the move
        if _hash_of(target, calls) == sha256:
            break
    else:
        if not exists(str(path), calls):
            raise FileNotFoundError(str(path))
        raise IntegrityError("inbox.move", f"{target} holds other bytes than {path.name}")
    fsync_directory(calls, str(directory))
    with contextlib.suppress(FileNotFoundError):  # the rename fallback already moved it
        calls.unlink(str(path))
    fsync_directory(calls, str(path.parent))
    return target


def write_reason(
    directory: Path, name: str, rule: str, detail: str, calls: FileCalls = OS_FILE_CALLS
) -> None:
    """``<directory>/<name>.reason.txt`` with the diagnostic, unless it exists already (a rerun
    after a crash between the diagnostic and the move keeps the first one)."""
    ensure_tree(directory, calls)
    target = directory / f"{name}.reason.txt"
    if exists(str(target), calls):
        return
    text = f"{rule}: {detail}\n" if detail else f"{rule}\n"
    atomic_write(str(target), text.encode("utf-8"), calls=calls)
