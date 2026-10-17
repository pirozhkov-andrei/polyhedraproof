"""The handoff outbox: ``outbox/<output_name>.json``, published once, byte for byte (specification
§7.4).

A completed handoff record embeds the complete shard, so the output is a function of the
record: ``J(shard)`` plus one LF, the ``cubeproof-shard-1`` document a receiver accepts through
``run --shard`` or its inbox. :func:`publish_output` writes it atomically and durably
(temporary file in the same directory, fsync, link without replacement, directory fsync;
``tools.atomic.atomic_write``); an existing file with equal bytes is a no-op (replay after a
crash publishes the **same** bytes) and a file with other bytes is never overwritten
(IntegrityError ``artifact.conflict``: the output name is taken by something else and the
handoff stays visibly unpublished). A handoff of zero nodes has no output file: its response is
derived from the record (:class:`HandoffResponse`), not an invalid empty shard.

The outbox belongs to one giver. ``output_name`` is a Name (no separator, no dot), so the file
stays inside the configured directory by construction.
"""

from __future__ import annotations

import enum
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cubeproof.base.canonical_json import document_bytes
from cubeproof.base.errors import ContractError, IntegrityError
from cubeproof.contracts.primitives import is_name
from cubeproof.coordinator.ownership import Given
from cubeproof.tools.atomic import (
    OS_FILE_CALLS,
    FileCalls,
    atomic_write,
    ensure_directory,
    same_bytes,
)

__all__ = [
    "HandoffResponse",
    "OutputState",
    "clean_staging",
    "ensure_tree",
    "exists",
    "output_bytes",
    "output_file",
    "output_state",
    "publish_output",
    "response_of",
]

_STAGING = re.compile(r"\..+\.[0-9a-f]{32}\.tmp")


def ensure_tree(directory: Path, calls: FileCalls = OS_FILE_CALLS) -> None:
    """``directory`` and its missing ancestors as real directories, each entry synced."""
    missing: list[Path] = []
    current = directory
    while True:
        try:
            mode = calls.lstat(str(current)).st_mode
        except FileNotFoundError:
            missing.append(current)
            if current.parent == current:
                break
            current = current.parent
            continue
        if not stat.S_ISDIR(mode):
            raise ContractError("io.layout", f"{current} is not a directory (or is a symlink)")
        break
    for path in reversed(missing):
        ensure_directory(calls, str(path))


def output_file(outbox: Path, output_name: str) -> Path:
    """``outbox/<output_name>.json``; only a Name is accepted, so it stays inside ``outbox``."""
    if not is_name(output_name):
        raise ContractError("schema", f"{output_name!r} is not an output Name")
    return outbox / f"{output_name}.json"


def output_bytes(given: Given) -> bytes | None:
    """The bytes the handoff publishes, or None for a handoff of zero nodes."""
    return None if given.shard is None else document_bytes(given.shard.to_json())


class OutputState(str, enum.Enum):
    NOTHING = "nothing"  # zero nodes: there is no file to publish
    MISSING = "missing"
    PUBLISHED = "published"  # the file holds exactly the record's bytes
    CONFLICT = "conflict"  # something else is at that name


def output_state(outbox: Path, given: Given, calls: FileCalls = OS_FILE_CALLS) -> OutputState:
    data = output_bytes(given)
    if data is None:
        return OutputState.NOTHING
    path = str(output_file(outbox, given.request.output_name))
    try:
        calls.lstat(path)
    except FileNotFoundError:
        return OutputState.MISSING
    try:  # a link, directory or device at the name is no regular file: ContractError
        return OutputState.PUBLISHED if same_bytes(calls, path, data) else OutputState.CONFLICT
    except ContractError:
        return OutputState.CONFLICT


def publish_output(outbox: Path, given: Given, calls: FileCalls = OS_FILE_CALLS) -> bool:
    """Publish the output of a committed handoff; True if written now, False if already there
    (or if there is nothing to publish). IntegrityError ``artifact.conflict`` if the name holds
    other bytes. The directory is created if needed."""
    data = output_bytes(given)
    if data is None:
        return False
    ensure_tree(outbox, calls)
    try:
        return atomic_write(str(output_file(outbox, given.request.output_name)), data, calls=calls)
    except IntegrityError:
        raise
    except ContractError as error:  # not a regular file at that name
        raise IntegrityError("artifact.conflict", error.detail) from None


def clean_staging(directory: Path, calls: FileCalls = OS_FILE_CALLS) -> int:
    """Remove the temporary files of interrupted publications in ``directory``; the count.

    Only the dot-prefixed ``.<name>.<id128>.tmp`` files of ``atomic_write`` are removed, and only
    by the owner of the directory at startup (run lock held)."""
    try:
        names = calls.listdir(str(directory))
    except FileNotFoundError:
        return 0
    removed = 0
    for name in sorted(names):
        if _STAGING.fullmatch(name) is None:
            continue
        path = str(directory / name)
        try:
            if not stat.S_ISREG(calls.lstat(path).st_mode):
                continue
            calls.unlink(path)
            removed += 1
        except FileNotFoundError:
            continue
    return removed


@dataclass(frozen=True)
class HandoffResponse:
    """The completion response derived from a committed handoff.

    ``nodes`` is the size of the shard given away; zero available nodes is the **empty
    completion** (``shard_sha256`` and ``output`` null): the request is answered, nothing was
    transferred, nothing was published.
    """

    request_id: str
    output_name: str
    seq: int
    nodes: int
    shard_sha256: str | None
    output: str | None

    @property
    def empty(self) -> bool:
        return self.nodes == 0

    def to_json(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "output_name": self.output_name,
            "seq": self.seq,
            "nodes": self.nodes,
            "shard_sha256": self.shard_sha256,
            "output": self.output,
        }


def response_of(given: Given) -> HandoffResponse:
    """The response of a committed handoff (a pure function of the record)."""
    shard = given.shard
    return HandoffResponse(
        request_id=given.request.request_id,
        output_name=given.request.output_name,
        seq=given.seq,
        nodes=0 if shard is None else len(shard.nodes),
        shard_sha256=given.shard_sha256,
        output=None if shard is None else f"{given.request.output_name}.json",
    )


def exists(path: str, calls: FileCalls = OS_FILE_CALLS) -> bool:
    """Whether anything is at ``path`` (a link is not followed)."""
    try:
        calls.lstat(path)
    except FileNotFoundError:
        return False
    return True
