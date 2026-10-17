"""Test-only helpers of the status tests: journals, folded states, fault injection, the oracles.

Three kinds of journals are used:

- *plain chains* (:func:`make_chain`): canonical lines whose ``self``/``seq``/``prev`` are right and
  whose payload is padding, for export tests that need many bytes quickly (the export checks the
  hash chain, the writer has validated records);
- *real journals* written by the ``JournalWriter`` (:class:`LiveJournal`): header from the
  contract corpus, ``node_stop`` records appended under the real file lock, for the tests that
  run an export concurrently with a writer;
- *scheduling journals* (``cp_sched_support.Journal``, the scheduler helper): attempts, splits
  and shards folded into a ``ReplayState`` for status and coverage.

The contract corpus and schemas are the expected values; ``tests/contracts`` provides the
independent schema validator and the reference reader of the requirements. Nothing here is
imported by runtime code.
"""

from __future__ import annotations

import errno
import hashlib
import json
import os
import stat
import sys
import threading
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[4]
TESTS = REPO / "packages" / "cubeproof" / "tests"
CONTRACT_TESTS = REPO / "tests" / "contracts"
CORPUS = CONTRACT_TESTS / "corpus"
SCHEMAS = REPO / "schemas" / "cubeproof" / "v1"
for _path in (TESTS / "scheduler", CONTRACT_TESTS):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

import contract_reader  # noqa: E402
import contract_schema  # noqa: E402
import cp_sched_support as sched  # noqa: E402

from cubeproof.base.canonical_json import encode  # noqa: E402
from cubeproof.base.hashing import ZERO_HASH  # noqa: E402
from cubeproof.contracts.enums import Lifecycle, StopState  # noqa: E402
from cubeproof.contracts.values import Node  # noqa: E402
from cubeproof.coordinator.state import ReplayState  # noqa: E402
from cubeproof.coordinator.status import StatusTracker, build_status  # noqa: E402
from cubeproof.evidence import journal  # noqa: E402
from cubeproof.evidence.journal import JournalWriter, RunLock  # noqa: E402
from cubeproof.evidence.schema import (  # noqa: E402
    NodeStop,
    Record,
    RecordSequence,
    ResourceSnapshot,
)
from cubeproof.tools.atomic import FileCalls  # noqa: E402

__all__ = [
    "REPO",
    "Crash",
    "FaultCalls",
    "LiveJournal",
    "append_lines",
    "build",
    "chain_of",
    "contract_reader",
    "folded",
    "make_chain",
    "relink",
    "resign",
    "resources",
    "sched",
    "schema_store",
    "sha",
    "status_documents",
    "write_lines",
]


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def schema_store() -> Any:
    return contract_schema.SchemaStore(SCHEMAS)


def status_documents() -> list[dict[str, Any]]:
    data = json.loads((CORPUS / "documents.json").read_bytes())
    return [e for e in data["documents"] if e["type"] == "status"]


def resources() -> ResourceSnapshot:
    snapshot: ResourceSnapshot = ResourceSnapshot.from_json(sched.RESOURCES)
    return snapshot


# -- plain chains ---------------------------------------------------------------------------------


def make_chain(
    count: int, *, seed: str = "a", pad: int = 0, start: int = 0, prev: str | None = None
) -> list[bytes]:
    """``count`` canonical journal lines (with LF) starting at seq ``start``.

    Line 0 is the header (the journal ID is its ``self``, which depends on ``seed``); a later
    start needs the ``prev`` hash of the line before it (see :func:`chain_of`).
    """
    lines: list[bytes] = []
    previous = ZERO_HASH if start == 0 else prev
    assert previous is not None
    for seq in range(start, start + count):
        record: dict[str, Any] = {
            "format": "cubeproof-journal-1",
            "prev": previous,
            "seq": seq,
            "type": "header" if seq == 0 else "repair",
            "utc": "2026-10-01T00:00:00.000Z",
            "seed": seed,
            "pad": "x" * pad,
        }
        record["self"] = sha(encode({k: v for k, v in record.items() if k != "self"}))
        lines.append(encode(record) + b"\n")
        previous = record["self"]
    return lines


def resign(line: bytes, **changes: Any) -> bytes:
    """``line`` with fields changed and ``self`` recomputed (a well-formed but wrong record)."""
    record: dict[str, Any] = json.loads(line)
    record.update(changes)
    record.pop("self")
    record["self"] = sha(encode(record))
    return encode(record) + b"\n"


def relink(lines: Sequence[bytes], start: int) -> list[bytes]:
    """``lines`` with ``prev`` and ``self`` of every line from ``start`` on recomputed, so that a
    change made at ``start`` leaves a chain that is consistent except for that change."""
    result = list(lines)
    for index in range(start, len(result)):
        previous = json.loads(result[index - 1])["self"] if index else "0" * 64
        result[index] = resign(result[index], prev=previous)
    return result


def chain_of(lines: Sequence[bytes]) -> str:
    """The ``self`` of the last line of ``lines``."""
    value: dict[str, Any] = json.loads(lines[-1])
    return str(value["self"])


def write_lines(path: Path, lines: Sequence[bytes]) -> None:
    path.write_bytes(b"".join(lines))


def append_lines(path: Path, lines: Sequence[bytes]) -> None:
    with path.open("ab") as stream:
        stream.write(b"".join(lines))


# -- real journals --------------------------------------------------------------------------------


class LiveJournal:
    """A journal written by the real ``JournalWriter`` (header from the contract corpus)."""

    def __init__(self, path: Path, lock_path: Path) -> None:
        self.path = path
        self.lock = RunLock.acquire(lock_path)
        corpus = journal.read_journal(
            CORPUS / "journals" / "base" / "w1.jsonl", RecordSequence(context=None)
        )
        header = corpus.records[0].payload
        self.writer: JournalWriter[Record] = JournalWriter.create(
            path,
            header,
            validator=RecordSequence(context=None),
            run_lock=self.lock,
            utc=corpus.records[0].utc,
        )
        self.formula = sha(b"live")
        self.count = 0

    def append(self, reason: str | None = None) -> Record:
        self.count += 1
        payload = NodeStop(
            node=Node(self.formula, ()),
            state=StopState.STUCK,
            reason=reason or f"stop {self.count}",
            policy_sha256=sha(b"policy"),
        )
        return self.writer.append(payload, utc="2026-10-01T00:00:01.000Z")

    def close(self) -> None:
        self.writer.close()
        self.lock.release()


# -- folded states ---------------------------------------------------------------------------------


def folded(j: Any) -> tuple[ReplayState, StatusTracker]:
    """The ``ReplayState`` and ``StatusTracker`` after every record of the helper journal."""
    state = ReplayState(j.view)
    tracker = StatusTracker()
    for record in j.records:
        state.apply(record)
        tracker.observe(record)
    return state, tracker


def build(
    state: ReplayState,
    tracker: StatusTracker,
    *,
    lifecycle: Lifecycle = Lifecycle.RUNNING,
    wall_ms: int = 1_790_000_000_000,
    now_ms: int = 100_000,
    **changes: Any,
) -> dict[str, Any]:
    """A status document with fixed clocks and the test resources (overrides as keywords)."""
    arguments: dict[str, Any] = {
        "resources": resources(),
        "reservations": [],
        "active": [],
    }
    arguments.update(changes)
    return build_status(
        state=state,
        lifecycle=lifecycle,
        wall_ms=wall_ms,
        now_ms=now_ms,
        tracker=tracker,
        **arguments,
    )


# -- faults ----------------------------------------------------------------------------------------


class Crash(BaseException):
    """Raised by a hook or a call to end the "process" at that point (not an Exception)."""


def _os_error(code: int) -> OSError:
    return OSError(code, os.strerror(code))


class FaultCalls(FileCalls):
    """``FileCalls`` with scripted faults and a gate.

    ``write_hook(path_name, n)`` is called before the ``n``-th write (1-based, counted per file
    name pattern ``only``) and may raise or block; ``fail_fsync`` / ``fail_rename`` raise OSError
    for paths whose name contains the given text. ``paths`` maps fds to names so the hook can see
    them."""

    def __init__(
        self,
        *,
        only: str = "journal.",
        write_hook: Callable[[int], None] | None = None,
        fail_fsync_on: str | None = None,
        fail_rename_to: str | None = None,
        fail_open_of: str | None = None,
        fail_directory_fsync: bool = False,
        errno_code: int = errno.ENOSPC,
    ) -> None:
        self.only = only
        self.write_hook = write_hook
        self.fail_fsync_on = fail_fsync_on
        self.fail_rename_to = fail_rename_to
        self.fail_open_of = fail_open_of
        self.fail_directory_fsync = fail_directory_fsync
        self.errno_code = errno_code
        self.paths: dict[int, str] = {}
        self.writes = 0
        self.rename_calls: list[tuple[str, str]] = []
        self._lock = threading.Lock()

    def open(self, path: str, flags: int, mode: int = 0o600) -> int:
        if self.fail_open_of is not None and self.fail_open_of in os.path.basename(path):
            raise _os_error(self.errno_code)
        fd = super().open(path, flags, mode)
        with self._lock:
            self.paths[fd] = os.path.basename(path)
        return fd

    def write(self, fd: int, data: memoryview) -> int:
        name = self.paths.get(fd, "")
        if self.only in name:
            with self._lock:
                self.writes += 1
                number = self.writes
            if self.write_hook is not None:
                self.write_hook(number)
        return super().write(fd, data)

    def fsync(self, fd: int) -> None:
        name = self.paths.get(fd, "")
        if self.fail_fsync_on is not None and self.fail_fsync_on in name:
            raise _os_error(errno.EIO)
        if self.fail_directory_fsync and stat.S_ISDIR(os.fstat(fd).st_mode):
            raise _os_error(errno.EIO)
        super().fsync(fd)

    def rename(self, source: str, target: str) -> None:
        self.rename_calls.append((os.path.basename(source), os.path.basename(target)))
        if self.fail_rename_to is not None and self.fail_rename_to in os.path.basename(target):
            raise _os_error(self.errno_code)
        super().rename(source, target)
