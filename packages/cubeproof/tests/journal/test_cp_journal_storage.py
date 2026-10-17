"""Durable append, locks, recovery and snapshots (specification §7.1, §7.3, §7.5).

System calls go through an injectable :class:`SysCalls`; the tests record them in order and
inject short writes, EINTR, write and fsync failures and simulated process death. They show
which calls are requested in which order; whether a filesystem honours fsync is outside what
a test can observe.
"""

from __future__ import annotations

import errno
import fcntl
import hashlib
import io
import os
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import cp_journal_support as sup
import pytest
from cp_journal_support import read_journal

from cubeproof.base.errors import (
    ConfigurationError,
    ContractError,
    CubeproofError,
    InputError,
    IntegrityError,
)
from cubeproof.contracts.enums import RecordType
from cubeproof.contracts.primitives import is_utc
from cubeproof.evidence.journal import (
    OS_CALLS,
    JournalWriteError,
    JournalWriter,
    RepairOutcome,
    RunLock,
    SysCalls,
    capture_anchor,
    write_all,
)
from cubeproof.evidence.journal import reader as journal_reader
from cubeproof.evidence.schema import (
    Attempt,
    Header,
    JournalContext,
    Record,
    Repair,
    Resume,
)

ALL3 = "campaigns/all3/campaign.json"
UTC = "2026-10-02T00:00:00.000Z"


def _records(relative: str) -> list[Record]:
    return list(read_journal(sup.CORPUS / relative).records)


@pytest.fixture
def run_lock(tmp_path: Path) -> Iterator[RunLock]:
    lock = RunLock.acquire(tmp_path / "run.lock")
    try:
        yield lock
    finally:
        lock.release()


def _resume(header: Header) -> Resume:
    return Resume(machinery=header.machinery, policy=header.policy, resources=header.resources)


def _state(writer: JournalWriter[Record]) -> tuple[Any, ...]:
    """The writer's public in-memory state (what it acknowledges as committed)."""
    chain = writer.chain
    return (chain.records, chain.head, chain.offset, chain.last_line, writer.summary)


def _unacknowledged(writer: JournalWriter[Record], before: tuple[Any, ...], record: Record) -> None:
    """A failed append left no trace in the writer's state (acknowledgement after durability)."""
    assert _state(writer) == before
    payload = record.payload
    assert isinstance(payload, Attempt)
    assert sup.sequence_of(writer).committed_attempt(payload.attempt_id) is None


def _write(
    path: Path,
    records: list[Record],
    run_lock: RunLock,
    calls: SysCalls = OS_CALLS,
    **options: Any,
) -> JournalWriter[Record]:
    header = records[0].payload
    assert isinstance(header, Header)
    writer = sup.create(path, header, run_lock=run_lock, utc=records[0].utc, calls=calls, **options)
    for record in records[1:]:
        writer.append(record.payload, utc=record.utc)
    return writer


class Armed:
    """A fault that fires only after ``arm()``: ``allow`` more calls pass, then ``action``."""

    def __init__(self, action: Callable[..., Any], allow: int = 0) -> None:
        self.action = action
        self.allow = allow
        self.armed = False
        self.passed = 0

    def arm(self) -> None:
        self.armed = True

    def __call__(self, number: int, *args: Any) -> Any:
        if not self.armed:
            return None
        if self.passed < self.allow:
            self.passed += 1
            return None
        return self.action(*args)


def _raise(code: int) -> Callable[..., Any]:
    def action(*args: Any) -> Any:
        raise OSError(code, os.strerror(code))

    return action


# -- round trip and protocol -----------------------------------------------------------------------


@pytest.mark.parametrize(
    "relative", ["journals/base/w1.jsonl", "journals/catalogue/w1.jsonl", "journals/modes/w1.jsonl"]
)
def test_writer_reproduces_corpus_journals(
    tmp_path: Path, run_lock: RunLock, relative: str
) -> None:
    records = _records(relative)
    path = tmp_path / "journal.jsonl"
    with _write(path, records, run_lock) as writer:
        assert writer.summary.records == len(records)
        assert writer.summary.anchor == read_journal(path).summary.anchor
    assert path.read_bytes() == sup.corpus_bytes(relative)


def test_append_returns_the_committed_record(tmp_path: Path, run_lock: RunLock) -> None:
    records = _records("journals/base/w1.jsonl")
    path = tmp_path / "journal.jsonl"
    header = records[0].payload
    assert isinstance(header, Header)
    with sup.create(path, header, run_lock=run_lock, utc=records[0].utc) as writer:
        for expected in records[1:]:
            assert writer.append(expected.payload, utc=expected.utc) == expected
        assert writer.chain.head == records[-1].self_hash
        record = writer.append(_resume(header))
        assert is_utc(record.utc)
        assert record.seq == len(records)


def test_create_writes_syncs_and_syncs_the_directory_before_returning(
    tmp_path: Path, run_lock: RunLock
) -> None:
    records = _records("journals/base/w1.jsonl")
    calls = sup.TraceCalls()
    path = tmp_path / "journal.jsonl"
    header = records[0].payload
    assert isinstance(header, Header)
    writer = sup.create(path, header, run_lock=run_lock, utc=records[0].utc, calls=calls)
    log = calls.log
    opened = [e for e in log if e[0] == "open"]
    file_fd = next(e[3] for e in opened if e[1] == str(path))
    flags = next(e[2] for e in opened if e[1] == str(path))
    assert flags & os.O_CREAT and flags & os.O_EXCL and flags & os.O_APPEND
    dir_fd = next(e[3] for e in opened if e[1] == str(tmp_path))
    names = [(e[0], e[1] if len(e) > 1 else None) for e in log]
    first_write = names.index(("write", file_fd))
    file_sync = names.index(("fsync", file_fd))
    dir_sync = names.index(("fsync", dir_fd))
    assert first_write < file_sync < dir_sync
    assert sum(e[2] for e in log if e[0] == "write" and e[1] == file_fd) == len(records[0].line) + 1
    assert _create_events(calls, path) == [
        ("flock", fcntl.LOCK_EX),
        ("write", "file"),
        ("fsync", "file"),
        ("fsync", "directory"),
        ("flock", fcntl.LOCK_UN),
    ]
    writer.close()


def test_append_holds_the_exclusive_lock_around_write_and_fsync(
    tmp_path: Path, run_lock: RunLock
) -> None:
    records = _records("journals/base/w1.jsonl")
    calls = sup.TraceCalls()
    path = tmp_path / "journal.jsonl"
    with _write(path, records[:2], run_lock, calls) as writer:
        start = len(calls.log)
        writer.append(records[2].payload, utc=records[2].utc)
        log = calls.log[start:]
    names = [e[0] for e in log]
    lock = next(i for i, e in enumerate(log) if e[0] == "flock" and e[2] == fcntl.LOCK_EX)
    unlock = next(i for i, e in enumerate(log) if e[0] == "flock" and e[2] == fcntl.LOCK_UN)
    writes = [i for i, n in enumerate(names) if n == "write"]
    sync = names.index("fsync")
    assert lock < min(writes) <= max(writes) < sync < unlock


def test_short_writes_and_eintr_are_completed(tmp_path: Path, run_lock: RunLock) -> None:
    records = _records("journals/base/w1.jsonl")
    calls = sup.TraceCalls(write_limit=7, faults={"write": sup.interrupt(5)})
    path = tmp_path / "journal.jsonl"
    _write(path, records, run_lock, calls).close()
    assert path.read_bytes() == sup.corpus_bytes("journals/base/w1.jsonl")
    assert max(e[2] for e in calls.log if e[0] == "write") <= 7


def test_write_all() -> None:
    read, write = os.pipe()
    try:
        calls = sup.TraceCalls(write_limit=3, faults={"write": sup.interrupt(2)})
        write_all(calls, write, b"0123456789")
        assert os.read(read, 100) == b"0123456789"
        for replaced in (0, 11):
            calls = sup.TraceCalls(faults={"write": lambda n, *a, r=replaced: r})
            with pytest.raises(OSError):
                write_all(calls, write, b"0123456789")
    finally:
        os.close(read)
        os.close(write)


# -- failures --------------------------------------------------------------------------------------


def test_zero_progress_write_fails_and_poisons(tmp_path: Path, run_lock: RunLock) -> None:
    records = _records("journals/base/w1.jsonl")
    fault = Armed(lambda *a: 0)
    calls = sup.TraceCalls(faults={"write": fault})
    path = tmp_path / "journal.jsonl"
    writer = _write(path, records[:2], run_lock, calls)
    state = _state(writer)
    fault.arm()
    with pytest.raises(JournalWriteError) as info:
        writer.append(records[2].payload, utc=records[2].utc)
    assert info.value.rule == "journal.write"
    assert writer.failed
    _unacknowledged(writer, state, records[2])
    before = len(calls.log)
    with pytest.raises(JournalWriteError) as info:
        writer.append(records[2].payload, utc=records[2].utc)
    assert info.value.rule == "journal.failed"
    assert "write" not in [e[0] for e in calls.log[before:]]
    writer.close()


def test_write_error_after_partial_bytes_is_repaired_on_the_next_open(
    tmp_path: Path, run_lock: RunLock
) -> None:
    records = _records("journals/base/w1.jsonl")
    fault = Armed(_raise(errno.ENOSPC), allow=2)
    calls = sup.TraceCalls(write_limit=50, faults={"write": fault})
    path = tmp_path / "journal.jsonl"
    writer = _write(path, records[:2], run_lock, calls)
    committed = path.read_bytes()
    state = _state(writer)
    fault.arm()
    with pytest.raises(JournalWriteError) as info:
        writer.append(records[2].payload, utc=records[2].utc)
    assert info.value.rule == "journal.write"
    assert isinstance(info.value.__cause__, OSError)
    _unacknowledged(writer, state, records[2])
    writer.close()
    damaged = path.read_bytes()
    assert damaged[: len(committed)] == committed
    assert len(damaged) == len(committed) + 100  # two partial writes of 50 bytes
    with sup.open_writer(path, run_lock=run_lock, utc=UTC) as reopened:
        repaired = reopened.repaired
        assert isinstance(repaired, RepairOutcome)
        assert repaired.removed_bytes == 100
        assert repaired.removed_sha256 == hashlib.sha256(damaged[len(committed) :]).hexdigest()
        assert repaired.record.type is RecordType.REPAIR
        payload = records[2].payload
        assert isinstance(payload, Attempt)
        assert sup.sequence_of(reopened).committed_attempt(payload.attempt_id) is None
        header = records[0].payload
        assert isinstance(header, Header)
        reopened.append(_resume(header), utc=UTC)
        reopened.append(payload, utc=UTC)
    contents = read_journal(path)
    assert contents.summary.torn_tail_bytes == 0
    assert [r.type for r in contents.records][2:] == [
        RecordType.REPAIR,
        RecordType.RESUME,
        RecordType.ATTEMPT,
    ]
    assert path.read_bytes()[: len(committed)] == committed


def test_fsync_failure_poisons_and_the_record_is_recognized_on_replay(
    tmp_path: Path, run_lock: RunLock
) -> None:
    records = _records("journals/base/w1.jsonl")
    fault = Armed(_raise(errno.EIO))
    calls = sup.TraceCalls(faults={"fsync": fault})
    path = tmp_path / "journal.jsonl"
    writer = _write(path, records[:2], run_lock, calls)
    state = _state(writer)
    fault.arm()
    with pytest.raises(JournalWriteError) as info:
        writer.append(records[2].payload, utc=records[2].utc)
    assert info.value.rule == "journal.fsync"
    assert writer.failed
    # The bytes may be on disk, but nothing was acknowledged: the state is the old one.
    _unacknowledged(writer, state, records[2])
    with pytest.raises(JournalWriteError):
        writer.append(records[3].payload, utc=records[3].utc)
    writer.close()
    # Recovery re-reads the disk: the bytes reached the file, so the record is committed.
    payload = records[2].payload
    assert isinstance(payload, Attempt)
    with sup.open_writer(path, run_lock=run_lock, utc=UTC) as reopened:
        assert reopened.repaired is None
        assert sup.sequence_of(reopened).committed_attempt(payload.attempt_id) == 2
        header = records[0].payload
        assert isinstance(header, Header)
        reopened.append(_resume(header), utc=UTC)
        size = path.stat().st_size
        with pytest.raises(IntegrityError) as refused:
            reopened.append(payload, utc=UTC)
        assert refused.value.rule == "attempt.attempt_id"
        assert path.stat().st_size == size
        assert not reopened.failed


def test_lost_acknowledgement_after_durability(tmp_path: Path, run_lock: RunLock) -> None:
    records = _records("journals/frontier/w1.jsonl")
    handoff_at = next(i for i, r in enumerate(records) if r.type is RecordType.HANDOFF)

    def crash(*args: Any) -> Any:
        if args[1] == fcntl.LOCK_UN:
            raise sup.Crash()
        return None

    fault = Armed(crash)
    calls = sup.TraceCalls(faults={"flock": fault})
    path = tmp_path / "journal.jsonl"
    writer = _write(path, records[:handoff_at], run_lock, calls)
    fault.arm()
    with pytest.raises(sup.Crash):
        writer.append(records[handoff_at].payload, utc=records[handoff_at].utc)
    os.close(writer.fileno())  # the process died: its descriptor is gone
    handoff = records[handoff_at].to_json()
    with sup.open_writer(path, run_lock=run_lock, utc=UTC) as reopened:
        request_id = handoff["request"]["request_id"]
        assert sup.sequence_of(reopened).committed_request(request_id) == handoff_at
        header = records[0].payload
        assert isinstance(header, Header)
        reopened.append(_resume(header), utc=UTC)
        with pytest.raises(IntegrityError) as refused:
            reopened.append(records[handoff_at].payload, utc=UTC)
        assert refused.value.rule == "handoff.request_unique"


def test_invalid_records_are_refused_before_any_byte_is_written(
    tmp_path: Path, run_lock: RunLock
) -> None:
    records = _records("journals/base/w1.jsonl")
    path = tmp_path / "journal.jsonl"
    with _write(path, records[:3], run_lock) as writer:
        size = path.stat().st_size
        attempt = records[3].payload
        assert isinstance(attempt, Attempt)
        fields = {n: getattr(attempt, n) for n in attempt.__dataclass_fields__}
        wrong = Attempt(**{**fields, "policy_sha256": "e" * 64})
        with pytest.raises(IntegrityError) as info:
            writer.append(wrong, utc=records[3].utc)
        assert info.value.rule == "attempt.policy_sha256"
        duplicate = records[2].payload
        with pytest.raises(IntegrityError) as info:
            writer.append(duplicate, utc=records[3].utc)
        assert info.value.rule == "attempt.attempt_id"
        with pytest.raises(ContractError) as calendar:
            writer.append(records[3].payload, utc="2026-02-30T00:00:00.000Z")
        assert calendar.value.rule == "utc.calendar"
        assert path.stat().st_size == size
        assert not writer.failed
        writer.append(records[3].payload, utc=records[3].utc)


def test_campaign_context_is_enforced_on_write(tmp_path: Path, run_lock: RunLock) -> None:
    records = _records("journals/base/w1.jsonl")
    header = records[0].payload
    assert isinstance(header, Header)
    other = JournalContext("e" * 64, {})
    with pytest.raises(InputError) as info:
        sup.create(tmp_path / "j.jsonl", header, run_lock=run_lock, context=other)
    assert info.value.rule == "journal.campaign"
    assert not (tmp_path / "j.jsonl").exists()


# -- session order ---------------------------------------------------------------------------------


def test_a_reopened_journal_needs_a_resume_before_new_activity(
    tmp_path: Path, run_lock: RunLock
) -> None:
    records = _records("journals/base/w1.jsonl")
    path = tmp_path / "journal.jsonl"
    _write(path, records[:3], run_lock).close()
    header = records[0].payload
    assert isinstance(header, Header)
    with sup.open_writer(path, run_lock=run_lock) as writer:
        for payload in (
            records[3].payload,
            header,
            Repair(removed_bytes=1, removed_sha256="a" * 64),
        ):
            with pytest.raises(ContractError) as info:
                writer.append(payload, utc=UTC)
            assert info.value.rule == "journal.session"
        writer.append(_resume(header), utc=UTC)
        writer.append(records[3].payload, utc=UTC)
        with pytest.raises(ContractError) as info:
            writer.append(header, utc=UTC)
        assert info.value.rule == "journal.session"


def test_create_refuses_an_existing_journal(tmp_path: Path, run_lock: RunLock) -> None:
    records = _records("journals/base/w1.jsonl")
    path = tmp_path / "journal.jsonl"
    _write(path, records, run_lock).close()
    before = path.read_bytes()
    header = records[0].payload
    assert isinstance(header, Header)
    with pytest.raises(ConfigurationError) as info:
        sup.create(path, header, run_lock=run_lock, utc=UTC)
    assert info.value.rule == "journal.exists"
    assert path.read_bytes() == before


def test_open_refuses_a_file_without_a_complete_line(tmp_path: Path, run_lock: RunLock) -> None:
    path = tmp_path / "journal.jsonl"
    for data in (b"", b'{"format":"cubeproof-jo'):
        path.write_bytes(data)
        with pytest.raises(InputError) as info:
            sup.open_writer(path, run_lock=run_lock, utc=UTC)
        assert info.value.rule == "journal.no_header"
        assert path.read_bytes() == data


def _create_events(calls: sup.TraceCalls, path: Path) -> list[tuple[str, Any]]:
    """Journal-file and directory events of a traced writer (flock by operation)."""
    log = calls.log
    file_fd = next(e[3] for e in log if e[0] == "open" and e[1] == str(path))
    dir_fd = next((e[3] for e in log if e[0] == "open" and e[1] == str(path.parent)), None)
    events: list[tuple[str, Any]] = []
    for entry in log:
        name = entry[0]
        if name == "flock" and entry[1] == file_fd:
            events.append(("flock", entry[2]))
        elif name in ("write", "fsync", "ftruncate"):
            target = {file_fd: "file", dir_fd: "directory"}.get(entry[1], "other")
            events.append((name, target))
    return events


def test_create_initializes_an_empty_file_and_a_torn_initial_header(
    tmp_path: Path, run_lock: RunLock
) -> None:
    records = _records("journals/base/w1.jsonl")
    header = records[0].payload
    assert isinstance(header, Header)
    path = tmp_path / "empty.jsonl"
    path.write_bytes(b"")
    calls = sup.TraceCalls()
    with sup.create(path, header, run_lock=run_lock, utc=records[0].utc, calls=calls) as writer:
        assert writer.repaired is None
        # Specification §7.1: the directory is synced on creation, also when an existing empty file
        # is initialized (it may never have been synced), and before create returns.
        assert _create_events(calls, path) == [
            ("flock", fcntl.LOCK_EX),
            ("write", "file"),
            ("fsync", "file"),
            ("fsync", "directory"),
            ("flock", fcntl.LOCK_UN),
        ]
    assert path.read_bytes() == records[0].line + b"\n"
    torn = b'{"campaign":"0000","format":"cubeproof-j'
    path = tmp_path / "torn.jsonl"
    path.write_bytes(torn)
    calls = sup.TraceCalls()
    with sup.create(path, header, run_lock=run_lock, utc=records[0].utc, calls=calls) as writer:
        # Under the lock: truncate, sync the truncation, header, sync, directory, repair, sync.
        assert _create_events(calls, path) == [
            ("flock", fcntl.LOCK_EX),
            ("ftruncate", "file"),
            ("fsync", "file"),
            ("write", "file"),
            ("fsync", "file"),
            ("fsync", "directory"),
            ("write", "file"),
            ("fsync", "file"),
            ("flock", fcntl.LOCK_UN),
        ]
        repaired = writer.repaired
        assert repaired is not None
        assert repaired.removed_bytes == len(torn)
        assert repaired.removed_sha256 == hashlib.sha256(torn).hexdigest()
        assert repaired.record.seq == 1
        writer.append(records[1].payload, utc=records[1].utc)
    contents = read_journal(path)
    assert [r.type for r in contents.records] == [
        RecordType.HEADER,
        RecordType.REPAIR,
        RecordType.SPLIT,
    ]
    assert contents.records[0] == records[0]


def test_a_failing_size_call_in_create_is_a_write_failure(
    tmp_path: Path, run_lock: RunLock
) -> None:
    records = _records("journals/base/w1.jsonl")
    header = records[0].payload
    assert isinstance(header, Header)
    path = tmp_path / "empty.jsonl"
    path.write_bytes(b"")
    calls = sup.TraceCalls(faults={"size": sup.fail_with(errno.EIO)})
    with pytest.raises(JournalWriteError) as info:
        sup.create(path, header, run_lock=run_lock, utc=records[0].utc, calls=calls)
    assert info.value.rule == "journal.write"
    assert "write" not in calls.names()
    assert path.read_bytes() == b""


def test_open_after_a_crash_before_the_directory_sync_syncs_the_directory(
    tmp_path: Path, run_lock: RunLock
) -> None:
    # Run 1 dies after the header fsync and before its directory sync; nothing was
    # acknowledged. Run 2 continues the file with open (create refuses a complete header):
    # the directory entry may still not be durable, so open syncs the directory before it
    # returns, i.e. before anything is acknowledged (specification §7.1).
    records = _records("journals/base/w1.jsonl")
    header = records[0].payload
    assert isinstance(header, Header)
    path = tmp_path / "journal.jsonl"

    def die(number: int, *args: Any) -> Any:
        if number == 2:  # the file is synced first, then its directory
            raise sup.Crash()
        return None

    with pytest.raises(sup.Crash):
        sup.create(
            path,
            header,
            run_lock=run_lock,
            utc=records[0].utc,
            calls=sup.TraceCalls(faults={"fsync": die}),
        )
    assert path.read_bytes() == records[0].line + b"\n"
    with pytest.raises(ConfigurationError):
        sup.create(path, header, run_lock=run_lock, utc=records[0].utc)
    calls = sup.TraceCalls()
    with sup.open_writer(path, run_lock=run_lock, utc=UTC, calls=calls) as writer:
        assert writer.repaired is None
        writer.append(_resume(header), utc=UTC)
    assert _create_events(calls, path) == [
        ("flock", fcntl.LOCK_EX),
        ("fsync", "directory"),
        ("flock", fcntl.LOCK_UN),
        ("flock", fcntl.LOCK_EX),
        ("write", "file"),
        ("fsync", "file"),
        ("flock", fcntl.LOCK_UN),
    ]


@pytest.mark.parametrize("how", ["open", "repair"])
@pytest.mark.parametrize("torn", [b"", b'{"format":"cubeproof-journal-1","seq":5'])
def test_recovery_syncs_the_directory_before_returning(
    tmp_path: Path, run_lock: RunLock, how: str, torn: bytes
) -> None:
    data = sup.corpus_bytes("journals/base/w1.jsonl")
    path = tmp_path / "journal.jsonl"
    path.write_bytes(data + torn)
    calls = sup.TraceCalls()
    if how == "open":
        with sup.open_writer(path, run_lock=run_lock, utc=UTC, calls=calls):
            pass
    else:
        sup.repair(path, run_lock=run_lock, utc=UTC, calls=calls)
    repair = [("ftruncate", "file"), ("fsync", "file"), ("write", "file"), ("fsync", "file")]
    assert _create_events(calls, path) == [
        ("flock", fcntl.LOCK_EX),
        *(repair if torn else []),
        ("fsync", "directory"),
        ("flock", fcntl.LOCK_UN),
    ]


def test_a_failed_directory_sync_fails_open(tmp_path: Path, run_lock: RunLock) -> None:
    data = sup.corpus_bytes("journals/base/w1.jsonl")
    path = tmp_path / "journal.jsonl"
    path.write_bytes(data)
    calls = sup.TraceCalls(faults={"fsync": sup.fail_with(errno.EIO)})
    with pytest.raises(JournalWriteError) as info:
        sup.open_writer(path, run_lock=run_lock, utc=UTC, calls=calls)
    assert info.value.rule == "journal.fsync"
    assert path.read_bytes() == data
    assert ("close", next(e[3] for e in calls.log if e[0] == "open")) in calls.log


# -- tail validation ------------------------------------------------------------------------------


@pytest.mark.parametrize("change", ["append", "truncate", "replace"])
def test_the_tail_is_validated_before_each_append(
    tmp_path: Path, run_lock: RunLock, change: str
) -> None:
    records = _records("journals/base/w1.jsonl")
    path = tmp_path / "journal.jsonl"
    writer = _write(path, records[:3], run_lock)
    data = path.read_bytes()
    if change == "append":
        path.write_bytes(data + b"{}\n")
    elif change == "truncate":
        path.write_bytes(data[: data.rindex(b"\n", 0, len(data) - 1) + 1])
    else:
        last = data.rindex(b"\n", 0, len(data) - 1) + 1
        path.write_bytes(data[:last] + data[last:].replace(b"2026", b"2027", 1))
    changed = path.read_bytes()
    with pytest.raises(IntegrityError) as info:
        writer.append(records[3].payload, utc=records[3].utc)
    assert info.value.rule == "journal.tail"
    assert writer.failed
    assert path.read_bytes() == changed
    writer.close()


# -- repair ----------------------------------------------------------------------------------------


def test_open_repairs_a_torn_tail_under_the_lock(tmp_path: Path, run_lock: RunLock) -> None:
    data = sup.corpus_bytes("journals/base/w1.jsonl")
    path = tmp_path / "journal.jsonl"
    torn = b'{"format":"cubeproof-journal-1","seq":5'
    path.write_bytes(data + torn)
    calls = sup.TraceCalls()
    with sup.open_writer(path, run_lock=run_lock, utc=UTC, calls=calls) as writer:
        repaired = writer.repaired
        assert repaired is not None
        assert (repaired.removed_bytes, repaired.removed_sha256) == (
            len(torn),
            hashlib.sha256(torn).hexdigest(),
        )
        assert repaired.record.seq == 5
    log = calls.log
    names = [e[0] for e in log]
    lock = next(i for i, e in enumerate(log) if e[0] == "flock" and e[2] == fcntl.LOCK_EX)
    truncate = names.index("ftruncate")
    assert log[truncate][2] == len(data)
    sync_after_truncate = names.index("fsync", truncate)
    write = names.index("write", truncate)
    sync_after_write = names.index("fsync", write)
    unlock = next(
        i for i, e in enumerate(log) if e[0] == "flock" and e[2] == fcntl.LOCK_UN and i > lock
    )
    assert lock < truncate < sync_after_truncate < write < sync_after_write <= unlock
    result = path.read_bytes()
    assert result.startswith(data)
    assert result == data + repaired.record.line + b"\n"


def test_recovery_refuses_a_file_that_grew_while_it_was_read(
    tmp_path: Path, run_lock: RunLock
) -> None:
    # A writer ignoring both locks appends after the scan: the measured tail is not the tail.
    data = sup.corpus_bytes("journals/base/w1.jsonl") + b'{"torn'
    path = tmp_path / "journal.jsonl"
    path.write_bytes(data)

    def grow(number: int, *args: Any) -> Any:
        if number == 2:  # the re-check before truncation
            with path.open("ab") as stream:
                stream.write(b"x")
        return None

    calls = sup.TraceCalls(faults={"size": grow})
    with pytest.raises(IntegrityError) as info:
        sup.repair(path, run_lock=run_lock, utc=UTC, calls=calls)
    assert info.value.rule == "journal.tail"
    assert "ftruncate" not in calls.names()
    assert path.read_bytes() == data + b"x"


def test_a_failing_size_call_in_recovery_is_a_write_failure(
    tmp_path: Path, run_lock: RunLock
) -> None:
    data = sup.corpus_bytes("journals/base/w1.jsonl")
    path = tmp_path / "journal.jsonl"
    path.write_bytes(data)
    calls = sup.TraceCalls(faults={"size": sup.fail_with(errno.EIO)})
    with pytest.raises(JournalWriteError) as info:
        sup.open_writer(path, run_lock=run_lock, utc=UTC, calls=calls)
    assert info.value.rule == "journal.write"
    assert path.read_bytes() == data


def test_open_and_repair_find_an_lf_on_a_chunk_boundary(
    tmp_path: Path, run_lock: RunLock, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A complete last line whose LF arrives as the first byte of a read is not a torn tail:
    # treating it as one would truncate a committed record (specification §7.1).
    data = sup.corpus_bytes("journals/base/w1.jsonl")
    lfs = [i for i, byte in enumerate(data) if byte == 0x0A]
    path = tmp_path / "journal.jsonl"
    torn = b'{"x'
    for size in sorted(set(lfs) | {lf + 1 for lf in lfs}):
        monkeypatch.setattr(journal_reader, "CHUNK_BYTES", size)
        path.write_bytes(data)
        with sup.open_writer(path, run_lock=run_lock, utc=UTC) as writer:
            assert writer.repaired is None, size
            assert writer.chain.records == len(lfs)
        assert path.read_bytes() == data
        assert sup.repair(path, run_lock=run_lock, utc=UTC) is None
        assert path.read_bytes() == data
        path.write_bytes(data + torn)
        outcome = sup.repair(path, run_lock=run_lock, utc=UTC)
        assert outcome is not None
        assert outcome.removed_bytes == len(torn), size
        assert path.read_bytes() == data + outcome.record.line + b"\n"


@pytest.mark.parametrize(
    "relative",
    [
        "journals/pilot_root/w1.jsonl",
        pytest.param("journals/base/w1.jsonl", marks=pytest.mark.slow),
    ],
)
def test_every_torn_tail_length_is_repaired(
    tmp_path: Path, run_lock: RunLock, relative: str
) -> None:
    data = sup.corpus_bytes(relative)
    ends = [i + 1 for i, byte in enumerate(data) if byte == 0x0A]
    calls = sup.TraceCalls(sync=False)
    path = tmp_path / "journal.jsonl"
    for length in range(ends[0] + 1, len(data) + 1):
        complete = max(e for e in ends if e <= length)
        prefix = data[:length]
        path.write_bytes(prefix)
        outcome = sup.repair(path, run_lock=run_lock, utc=UTC, calls=calls)
        repaired = path.read_bytes()
        if length == complete:
            assert outcome is None
            assert repaired == prefix
            continue
        assert outcome is not None
        assert outcome.removed_bytes == length - complete
        assert outcome.removed_sha256 == hashlib.sha256(prefix[complete:]).hexdigest()
        assert repaired == prefix[:complete] + outcome.record.line + b"\n"
        summary = read_journal(path).summary
        assert summary.records == ends.index(complete) + 2
        assert summary.torn_tail_bytes == 0


@pytest.mark.parametrize(
    "damage",
    [b"garbage\n", b"{}\n", b'{"format":"cubeproof-journal-1"}\n', b"\xff\n"],
)
def test_a_complete_corrupt_last_line_is_never_truncated(
    tmp_path: Path, run_lock: RunLock, damage: bytes
) -> None:
    data = sup.corpus_bytes("journals/base/w1.jsonl") + damage
    path = tmp_path / "journal.jsonl"
    path.write_bytes(data)
    with pytest.raises(IntegrityError):
        sup.open_writer(path, run_lock=run_lock, utc=UTC)
    assert path.read_bytes() == data
    with pytest.raises(IntegrityError):
        sup.repair(path, run_lock=run_lock, utc=UTC)
    assert path.read_bytes() == data
    # Also with a torn tail after the corrupt complete line.
    path.write_bytes(data + b'{"x"')
    with pytest.raises(IntegrityError):
        sup.repair(path, run_lock=run_lock, utc=UTC)
    assert path.read_bytes() == data + b'{"x"'


def test_middle_corruption_is_never_repaired(tmp_path: Path, run_lock: RunLock) -> None:
    data = bytearray(sup.corpus_bytes("journals/base/w1.jsonl"))
    data[3000] ^= 0x01
    path = tmp_path / "journal.jsonl"
    path.write_bytes(bytes(data) + b"torn")
    with pytest.raises(IntegrityError):
        sup.repair(path, run_lock=run_lock, utc=UTC)
    assert path.read_bytes() == bytes(data) + b"torn"


def test_standalone_repair_needs_a_header_and_the_run_lock(
    tmp_path: Path, run_lock: RunLock
) -> None:
    path = tmp_path / "journal.jsonl"
    path.write_bytes(b'{"format":"cubeproof-journal-1"')
    with pytest.raises(InputError) as info:
        sup.repair(path, run_lock=run_lock, utc=UTC)
    assert info.value.rule == "journal.no_header"
    assert path.read_bytes() == b'{"format":"cubeproof-journal-1"'
    released = RunLock.acquire(tmp_path / "other.lock")
    released.release()
    data = sup.corpus_bytes("journals/base/w1.jsonl") + b"torn"
    path.write_bytes(data)
    with pytest.raises(ConfigurationError) as locked:
        sup.repair(path, run_lock=released, utc=UTC)
    assert locked.value.rule == "run.lock"
    assert path.read_bytes() == data


def test_run_lock_is_exclusive_and_nonblocking(tmp_path: Path) -> None:
    path = tmp_path / "run.lock"
    first = RunLock.acquire(path)
    try:
        assert first.held
        with pytest.raises(ConfigurationError) as info:
            RunLock.acquire(path)
        assert info.value.rule == "run.locked"
        # Another open file description of the same process conflicts as well.
        fd = os.open(path, os.O_RDWR)
        try:
            with pytest.raises(BlockingIOError):
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally:
            os.close(fd)
    finally:
        first.release()
    assert not first.held
    with RunLock.acquire(path) as second:
        assert second.held


def test_writers_require_a_held_run_lock(tmp_path: Path) -> None:
    records = _records("journals/base/w1.jsonl")
    header = records[0].payload
    assert isinstance(header, Header)
    lock = RunLock.acquire(tmp_path / "run.lock")
    lock.release()
    with pytest.raises(ConfigurationError) as info:
        sup.create(tmp_path / "j.jsonl", header, run_lock=lock, utc=UTC)
    assert info.value.rule == "run.lock"
    assert not (tmp_path / "j.jsonl").exists()


def test_a_closed_writer_refuses_appends(tmp_path: Path, run_lock: RunLock) -> None:
    records = _records("journals/base/w1.jsonl")
    writer = _write(tmp_path / "j.jsonl", records[:2], run_lock)
    writer.close()
    writer.close()
    with pytest.raises(JournalWriteError) as info:
        writer.append(records[2].payload, utc=UTC)
    assert info.value.rule == "journal.closed"


# -- snapshots for export --------------------------------------------------------------------------


def test_capture_anchor_takes_a_shared_lock_and_ignores_a_torn_tail(
    tmp_path: Path, run_lock: RunLock
) -> None:
    records = _records("journals/base/w1.jsonl")
    path = tmp_path / "journal.jsonl"
    writer = _write(path, records[:3], run_lock)
    with path.open("ab") as stream:
        stream.write(b'{"torn')
    calls = sup.TraceCalls()
    anchor = capture_anchor(path, calls=calls)
    locks = [e[2] for e in calls.log if e[0] == "flock"]
    assert locks == [fcntl.LOCK_SH, fcntl.LOCK_UN]
    assert anchor.journal == records[0].self_hash
    assert (anchor.seq, anchor.head) == (2, records[2].self_hash)
    assert anchor.offset == sum(len(r.line) + 1 for r in records[:3])
    writer.close()


def test_read_snapshot_validates_exactly_the_anchored_prefix(
    tmp_path: Path, run_lock: RunLock
) -> None:
    records = _records("journals/base/w1.jsonl")
    path = tmp_path / "journal.jsonl"
    writer = _write(path, records[:3], run_lock)
    anchor = capture_anchor(path)
    writer.append(records[3].payload, utc=records[3].utc)
    writer.append(records[4].payload, utc=records[4].utc)
    snapshot = sup.snapshot(path, anchor)
    assert [r.seq for r in snapshot.records] == [0, 1, 2]
    assert snapshot.summary.anchor == anchor
    writer.close()
    data = path.read_bytes()
    path.write_bytes(data[: anchor.offset - 1])
    with pytest.raises(IntegrityError) as info:
        sup.snapshot(path, anchor)
    assert info.value.rule == "journal.anchor"
    forged = sup.chain([*[r.to_json() for r in records[:2]], {**records[2].to_json(), "utc": UTC}])
    path.write_bytes(forged)
    with pytest.raises(CubeproofError) as error:
        sup.snapshot(path, anchor)
    assert error.value.rule == "journal.anchor"


def test_reader_of_a_live_journal_sees_only_committed_lines(
    tmp_path: Path, run_lock: RunLock
) -> None:
    records = _records("journals/base/w1.jsonl")
    path = tmp_path / "journal.jsonl"
    fault = Armed(_raise(errno.ENOSPC), allow=1)
    calls = sup.TraceCalls(write_limit=64, faults={"write": fault})
    writer = _write(path, records[:3], run_lock, calls)
    fault.arm()
    with pytest.raises(JournalWriteError):
        writer.append(records[3].payload, utc=records[3].utc)
    summary = read_journal(io.BytesIO(path.read_bytes())).summary
    assert summary.records == 3
    assert summary.torn_tail_bytes == 64
    writer.close()
