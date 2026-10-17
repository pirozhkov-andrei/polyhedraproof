"""Prefix exports: incremental and full copies, crash points, no incomplete published prefix,
a large export concurrent with appends, no lock held through the copy (specification §7.5)."""

from __future__ import annotations

import errno
import fcntl
import itertools
import json
import os
import threading
import time
from pathlib import Path
from typing import Any

import cp_status_support as sup
import pytest

from cubeproof.base.canonical_json import document_bytes
from cubeproof.base.errors import (
    ConfigurationError,
    ContractError,
    IntegrityError,
    ResourceError,
    ToolError,
)
from cubeproof.coordinator.export import (
    DESCRIPTOR_NAME,
    EXPORT_FORMAT,
    ExportCancelled,
    ExportDescriptor,
    JournalRestoreError,
    compare_export,
    export_once,
    read_descriptor,
    restore_from_export,
    verify_export,
)
from cubeproof.evidence.journal import RunLock, SysCalls, capture_anchor
from cubeproof.tools.atomic import DurabilityError


class Clock:
    """A settable wall clock in milliseconds."""

    def __init__(self, start: int = 1_790_000_000_000) -> None:
        self.now = start

    def __call__(self) -> int:
        self.now += 1
        return self.now


@pytest.fixture
def source(tmp_path: Path) -> Path:
    path = tmp_path / "journal.jsonl"
    sup.write_lines(path, sup.make_chain(20))
    return path


@pytest.fixture
def target(tmp_path: Path) -> str:
    return str(tmp_path / "export")


def _data(target: str, descriptor: ExportDescriptor) -> bytes:
    return Path(target, descriptor.file).read_bytes()[: descriptor.offset]


def _extend(path: Path, count: int, *, seed: str = "a") -> None:
    existing = path.read_bytes().splitlines(keepends=True)
    start = len(existing)
    sup.append_lines(
        path, sup.make_chain(count, seed=seed, start=start, prev=sup.chain_of(existing))
    )


def _listing(target: str) -> list[str]:
    return sorted(os.listdir(target))


# -- the descriptor and the first export -----------------------------------------------------------


def test_the_first_export_is_a_full_copy_with_a_descriptor(source: Path, target: str) -> None:
    anchor = capture_anchor(source)
    result = export_once(source, target, wall_ms=Clock())
    descriptor = result.descriptor
    assert (result.mode, result.reason) == ("full", "no_descriptor")
    assert (descriptor.journal, descriptor.seq, descriptor.head, descriptor.offset) == (
        anchor.journal,
        anchor.seq,
        anchor.head,
        anchor.offset,
    )
    assert descriptor.file == "journal.1.jsonl" and descriptor.generation == 1
    assert _data(target, descriptor) == source.read_bytes()
    assert result.bytes_copied == anchor.offset
    assert _listing(target) == [DESCRIPTOR_NAME, "journal.1.jsonl"]
    assert read_descriptor(target) == descriptor
    assert verify_export(target) == descriptor


def test_the_descriptor_is_canonical_and_complete(source: Path, target: str) -> None:
    export_once(source, target, wall_ms=Clock())
    raw = Path(target, DESCRIPTOR_NAME).read_bytes()
    assert raw.endswith(b"\n") and b"\n" not in raw[:-1]
    value = ExportDescriptor.from_json(json.loads(raw))
    assert value.to_json()["format"] == EXPORT_FORMAT
    assert set(value.to_json()) == {
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
    }


@pytest.mark.parametrize(
    "change",
    [
        {"format": "cubeproof-export-2"},
        {"journal": "0" * 63},
        {"seq": -1},
        {"seq": True},
        {"offset": 0},
        {"file": "../journal.1.jsonl"},
        {"file": "journal.2.jsonl"},
        {"generation": 0},
        {"mode": "partial"},
        {"captured_utc": "2026-02-30T00:00:00.000Z"},
        {"utc": "2026-10-01"},
        {"extra": 1},
    ],
)
def test_a_damaged_descriptor_is_rejected(
    source: Path, target: str, change: dict[str, Any]
) -> None:
    descriptor = export_once(source, target, wall_ms=Clock()).descriptor
    value = {**descriptor.to_json(), **change}
    with pytest.raises(ContractError):
        ExportDescriptor.from_json(value)


def test_a_missing_field_of_the_descriptor_is_rejected(source: Path, target: str) -> None:
    value = export_once(source, target, wall_ms=Clock()).descriptor.to_json()
    del value["head"]
    with pytest.raises(ContractError):
        ExportDescriptor.from_json(value)


# -- incremental, unchanged and full ---------------------------------------------------------------


def test_a_later_export_appends_only_the_new_records(source: Path, target: str) -> None:
    clock = Clock()
    first = export_once(source, target, wall_ms=clock).descriptor
    inode = os.stat(Path(target, first.file)).st_ino
    before = source.stat().st_size
    _extend(source, 7)
    result = export_once(source, target, wall_ms=clock)
    descriptor = result.descriptor
    assert result.mode == "incremental" and result.reason is None
    assert result.bytes_copied == source.stat().st_size - before
    assert descriptor.seq == 26 and descriptor.generation == first.generation
    assert descriptor.offset == source.stat().st_size and descriptor.mode == "incremental"
    assert os.stat(Path(target, first.file)).st_ino == inode  # appended in place
    assert _data(target, descriptor) == source.read_bytes()
    assert verify_export(target) == descriptor
    assert _listing(target) == [DESCRIPTOR_NAME, "journal.1.jsonl"]


def test_nothing_new_refreshes_the_descriptor_without_copying(source: Path, target: str) -> None:
    clock = Clock()
    first = export_once(source, target, wall_ms=clock).descriptor
    clock.now += 60_000
    result = export_once(source, target, wall_ms=clock)
    assert (result.mode, result.bytes_copied) == ("unchanged", 0)
    again = result.descriptor
    assert (again.head, again.seq, again.offset, again.file) == (
        first.head,
        first.seq,
        first.offset,
        first.file,
    )
    assert again.captured_utc > first.captured_utc and again.utc > first.utc
    assert verify_export(target) == again


def test_incremental_exports_chain_for_many_rounds(source: Path, target: str) -> None:
    clock = Clock()
    for round_number in range(8):
        _extend(source, 3 + round_number)
        result = export_once(source, target, wall_ms=clock, chunk_bytes=1000)
        assert result.mode in ("full", "incremental")
        assert _data(target, result.descriptor) == source.read_bytes()
    assert verify_export(target).seq == len(source.read_bytes().splitlines()) - 1


def test_a_torn_tail_of_the_source_is_not_exported(source: Path, target: str) -> None:
    clock = Clock()
    complete = source.read_bytes()
    with source.open("ab") as stream:
        stream.write(b'{"seq":20,"torn":')
    result = export_once(source, target, wall_ms=clock)
    assert result.descriptor.offset == len(complete)
    assert _data(target, result.descriptor) == complete
    # the writer repairs it and appends: the export continues from the same prefix
    source.write_bytes(complete)
    _extend(source, 2)
    later = export_once(source, target, wall_ms=clock)
    assert later.mode == "incremental" and later.descriptor.seq == 21


@pytest.mark.parametrize(
    ("damage", "reason"),
    [
        ("delete", "file_missing"),
        ("truncate", "file_short"),
        ("corrupt_last_line", "file_damaged"),
        ("other_valid_last_line", "file_damaged"),
        ("garbage_descriptor", "descriptor_invalid"),
    ],
)
def test_damage_to_the_export_is_repaired_by_a_full_copy(
    source: Path, target: str, damage: str, reason: str
) -> None:
    clock = Clock()
    first = export_once(source, target, wall_ms=clock).descriptor
    data = Path(target, first.file)
    if damage == "delete":
        data.unlink()
    elif damage == "truncate":
        os.truncate(data, first.offset - 5)
    elif damage == "corrupt_last_line":
        raw = bytearray(data.read_bytes())
        raw[first.offset - 20] ^= 1
        data.write_bytes(bytes(raw))
    elif damage == "other_valid_last_line":  # a well-formed record of the same size, not the head
        lines = data.read_bytes().splitlines(keepends=True)
        lines[-1] = sup.resign(lines[-1], utc="2026-10-01T00:00:01.000Z")
        data.write_bytes(b"".join(lines))
    else:
        Path(target, DESCRIPTOR_NAME).write_bytes(b"{not json")
    _extend(source, 4)
    result = export_once(source, target, wall_ms=clock)
    assert result.mode == "full" and result.reason == reason
    assert result.descriptor.generation == (1 if damage == "garbage_descriptor" else 2)
    assert _data(target, result.descriptor) == source.read_bytes()
    assert verify_export(target) == result.descriptor
    assert len([n for n in _listing(target) if n.startswith("journal.")]) == 1


def test_a_full_copy_leaves_the_old_generation_until_its_descriptor_is_published(
    source: Path, target: str
) -> None:
    clock = Clock()
    first = export_once(source, target, wall_ms=clock).descriptor
    os.truncate(Path(target, first.file), first.offset - 5)
    seen: list[list[str]] = []

    def hook(name: str) -> None:
        if name == "descriptor":
            seen.append(_listing(target))
            assert read_descriptor(target) == first  # still the old one

    result = export_once(source, target, wall_ms=clock, hook=hook)
    assert result.mode == "full"
    assert seen == [[DESCRIPTOR_NAME, "journal.1.jsonl", "journal.2.jsonl"]]
    assert _listing(target) == [DESCRIPTOR_NAME, "journal.2.jsonl"]


def test_stale_leftovers_are_removed_after_a_success(source: Path, target: str) -> None:
    clock = Clock()
    export_once(source, target, wall_ms=clock)
    Path(target, "journal.7.jsonl").write_bytes(b"unfinished")
    Path(target, f".{DESCRIPTOR_NAME}.{'0' * 32}.tmp").write_bytes(b"{")
    Path(target, "notes.txt").write_bytes(b"mine")
    _extend(source, 1)
    export_once(source, target, wall_ms=clock)
    assert _listing(target) == [DESCRIPTOR_NAME, "journal.1.jsonl", "notes.txt"]


# -- a source that does not extend the export ------------------------------------------------------


def test_another_journal_is_never_exported_over_a_backup(source: Path, target: str) -> None:
    clock = Clock()
    first = export_once(source, target, wall_ms=clock).descriptor
    sup.write_lines(source, sup.make_chain(30, seed="other"))
    with pytest.raises(ConfigurationError) as caught:
        export_once(source, target, wall_ms=clock)
    assert caught.value.rule == "export.foreign"
    assert read_descriptor(target) == first and verify_export(target) == first


def test_a_shorter_journal_is_not_exported_over_a_longer_backup(source: Path, target: str) -> None:
    clock = Clock()
    first = export_once(source, target, wall_ms=clock).descriptor
    sup.write_lines(source, sup.make_chain(10))
    with pytest.raises(IntegrityError) as caught:
        export_once(source, target, wall_ms=clock)
    assert caught.value.rule == "export.regressed"
    assert verify_export(target) == first


def test_a_forked_history_is_refused_and_the_backup_stays(source: Path, target: str) -> None:
    clock = Clock()
    first = export_once(source, target, wall_ms=clock).descriptor
    # same header (same journal ID), different continuation from seq 1 on
    lines = source.read_bytes().splitlines(keepends=True)
    forked = lines[:1] + sup.make_chain(
        25, seed="fork", start=1, prev=sup.chain_of(lines[:1]), pad=3
    )
    sup.write_lines(source, forked)
    with pytest.raises(IntegrityError) as caught:
        export_once(source, target, wall_ms=clock)
    assert caught.value.rule == "export.diverged"
    assert verify_export(target) == first
    assert _data(target, first) == b"".join(lines)


@pytest.mark.parametrize("damaged", [False, True])
def test_a_fork_at_the_same_seq_is_refused(source: Path, target: str, damaged: bool) -> None:
    """Also when the exported file is gone: a damaged export is rebuilt from the journal it came
    from, never from a different history."""
    clock = Clock()
    first = export_once(source, target, wall_ms=clock).descriptor
    if damaged:
        Path(target, first.file).unlink()
    lines = source.read_bytes().splitlines(keepends=True)
    forked = lines[:19] + sup.make_chain(1, seed="fork", start=19, prev=sup.chain_of(lines[:19]))
    sup.write_lines(source, forked)
    with pytest.raises(IntegrityError) as caught:
        export_once(source, target, wall_ms=clock)
    assert caught.value.rule == "export.diverged"
    assert read_descriptor(target) == first
    if not damaged:
        assert verify_export(target) == first


@pytest.mark.parametrize("what", ["self", "seq", "prev", "not_json", "second_header"])
def test_a_broken_chain_in_the_source_is_never_published(
    source: Path, target: str, what: str
) -> None:
    lines = source.read_bytes().splitlines(keepends=True)
    index = 12
    if what == "self":
        lines[index] = lines[index].replace(b'"pad":""', b'"pad":"y"')
    elif what == "seq":  # a consistent chain from here on, only the seq is wrong
        lines[index] = sup.resign(lines[index], seq=99)
        lines = sup.relink(lines, index + 1)
    elif what == "prev":  # the line after a wrong prev is consistent with it
        lines[index] = sup.resign(lines[index], prev="f" * 64)
        lines = sup.relink(lines, index + 1)
    elif what == "not_json":
        lines[index] = b"this is not json\n"
    else:  # only the header position is wrong
        lines[index] = sup.resign(lines[index], type="header")
        lines = sup.relink(lines, index + 1)
    sup.write_lines(source, lines)
    with pytest.raises((IntegrityError, ContractError)):
        export_once(source, target, wall_ms=Clock())
    assert read_descriptor(target) is None
    assert [n for n in _listing(target) if n.startswith("journal.")] == []


def test_a_source_that_ends_before_the_anchor_is_an_integrity_error(
    source: Path, target: str
) -> None:
    class Late(SysCalls):
        """The anchor is captured, then the file shrinks (a restored backup) before the copy."""

        def flock(self, fd: int, operation: int) -> None:
            super().flock(fd, operation)
            if operation == fcntl.LOCK_UN:
                os.truncate(source, 100)

    with pytest.raises(IntegrityError) as caught:
        export_once(source, target, wall_ms=Clock(), journal_calls=Late())
    assert caught.value.rule == "export.source_short"
    assert read_descriptor(target) is None


@pytest.mark.parametrize("situation", ["first", "incremental"])
def test_a_source_replaced_between_capture_and_copy_is_never_published(
    source: Path, target: str, situation: str
) -> None:
    """The copied chain must end at the captured anchor, whatever the file holds when it is read."""
    clock = Clock()
    previous = None
    if situation == "incremental":
        previous = export_once(source, target, wall_ms=clock).descriptor
        _extend(source, 10)
    original = source.read_bytes().splitlines(keepends=True)
    if previous is None:  # another journal whose lines have the same lengths
        replacement = sup.make_chain(len(original), seed="b", pad=0)
    else:  # the same history up to the export, a different continuation of the same lengths
        keep = original[: previous.seq + 1]
        replacement = keep + sup.make_chain(
            len(original) - len(keep), seed="b", start=len(keep), prev=sup.chain_of(keep)
        )
    assert [len(x) for x in replacement] == [len(x) for x in original]

    class Swap(SysCalls):
        def flock(self, fd: int, operation: int) -> None:
            super().flock(fd, operation)
            if operation == fcntl.LOCK_UN:
                sup.write_lines(source, replacement)

    with pytest.raises(IntegrityError) as caught:
        export_once(source, target, wall_ms=clock, journal_calls=Swap())
    assert caught.value.rule in ("export.chain", "export.diverged")
    assert read_descriptor(target) == previous
    if previous is not None:
        assert verify_export(target) == previous


def test_missing_source_and_bad_directory_are_typed_errors(tmp_path: Path, source: Path) -> None:
    with pytest.raises(ToolError):
        export_once(tmp_path / "absent.jsonl", str(tmp_path / "e1"), wall_ms=Clock())
    blocked = tmp_path / "file"
    blocked.write_bytes(b"x")
    with pytest.raises(ConfigurationError) as caught:
        export_once(source, str(blocked), wall_ms=Clock())
    assert caught.value.rule == "export.layout"
    with pytest.raises(ConfigurationError):
        export_once(source, str(tmp_path / "e2"), wall_ms=Clock(), chunk_bytes=0)


# -- interruption and retry ------------------------------------------------------------------------

POINTS = ("captured", "copied", "synced", "descriptor", "published")


@pytest.mark.parametrize("point", POINTS)
@pytest.mark.parametrize("situation", ["first", "incremental", "full_fallback"])
def test_a_crash_at_any_point_publishes_nothing_incomplete(
    source: Path, target: str, point: str, situation: str
) -> None:
    clock = Clock()
    previous = None
    if situation != "first":
        previous = export_once(source, target, wall_ms=clock).descriptor
        if situation == "full_fallback":
            os.truncate(Path(target, previous.file), previous.offset - 3)
        _extend(source, 6)

    def hook(name: str) -> None:
        if name == point:
            raise sup.Crash

    with pytest.raises(sup.Crash):
        export_once(source, target, wall_ms=clock, hook=hook, chunk_bytes=700)
    published = read_descriptor(target)
    if point == "published":
        assert published is not None and published.seq == (25 if previous else 19)
        assert verify_export(target) == published
    elif previous is None:
        assert published is None
    elif situation == "full_fallback":
        assert published == previous  # the damaged old export is still what is published
    else:
        assert published == previous
        assert verify_export(target) == previous  # bytes after the offset are not published
    # the retry completes and publishes the whole current prefix
    result = export_once(source, target, wall_ms=clock)
    assert _data(target, result.descriptor) == source.read_bytes()
    assert verify_export(target) == result.descriptor
    assert [n for n in _listing(target) if n.startswith(".")] == []
    assert len([n for n in _listing(target) if n.startswith("journal.")]) == 1


def test_an_unfinished_incremental_copy_leaves_bytes_that_are_not_published(
    source: Path, target: str
) -> None:
    clock = Clock()
    previous = export_once(source, target, wall_ms=clock).descriptor
    _extend(source, 30)

    def stop_after_two_chunks(number: int) -> None:
        if number == 3:
            raise sup.Crash

    calls = sup.FaultCalls(write_hook=stop_after_two_chunks)
    with pytest.raises(sup.Crash):
        export_once(source, target, calls=calls, wall_ms=clock, chunk_bytes=500)
    on_disk = Path(target, previous.file).stat().st_size
    assert on_disk > previous.offset  # an unpublished tail exists ...
    assert read_descriptor(target) == previous
    assert verify_export(target) == previous  # ... and is ignored
    result = export_once(source, target, wall_ms=clock)
    assert result.mode == "incremental"
    assert result.descriptor.offset == source.stat().st_size
    assert Path(target, previous.file).stat().st_size == source.stat().st_size


@pytest.mark.parametrize("stage", ["write", "fsync", "descriptor_fsync", "descriptor_rename"])
def test_io_failures_leave_the_published_export_untouched_and_retry_works(
    source: Path, target: str, stage: str
) -> None:
    clock = Clock()
    previous = export_once(source, target, wall_ms=clock).descriptor
    _extend(source, 12)
    if stage == "write":
        calls = sup.FaultCalls(
            write_hook=lambda n: (_ for _ in ()).throw(OSError(errno.ENOSPC, "full"))
        )
        expected: type[Exception] = ResourceError
    elif stage == "fsync":
        calls = sup.FaultCalls(fail_fsync_on="journal.")
        expected = DurabilityError
    elif stage == "descriptor_fsync":
        calls = sup.FaultCalls(fail_fsync_on=DESCRIPTOR_NAME)
        expected = DurabilityError
    else:
        calls = sup.FaultCalls(fail_rename_to=DESCRIPTOR_NAME, errno_code=errno.EIO)
        expected = ToolError
    with pytest.raises(expected):
        export_once(source, target, calls=calls, wall_ms=clock)
    assert read_descriptor(target) == previous
    assert verify_export(target) == previous
    assert [n for n in _listing(target) if n.endswith(".tmp")] == []
    result = export_once(source, target, wall_ms=clock)
    assert verify_export(target) == result.descriptor
    assert result.descriptor.seq == 31


def test_a_failed_fsync_of_the_first_copy_publishes_nothing(source: Path, target: str) -> None:
    calls = sup.FaultCalls(fail_fsync_on="journal.")
    with pytest.raises(DurabilityError):
        export_once(source, target, calls=calls, wall_ms=Clock())
    assert read_descriptor(target) is None
    assert [n for n in _listing(target) if n.startswith("journal.")] == []  # no unsynced data left
    result = export_once(source, target, wall_ms=Clock())
    assert verify_export(target) == result.descriptor


@pytest.mark.parametrize("situation", ["first", "first_in_existing_directory", "incremental"])
def test_a_failed_directory_sync_is_an_error_and_what_is_visible_stays_valid(
    source: Path, target: str, situation: str
) -> None:
    """The directory entry of a new file or of the descriptor may not be durable: that is reported
    as a failure and the next export checks and completes it; nothing visible is ever invalid."""
    clock = Clock()
    if situation == "incremental":
        export_once(source, target, wall_ms=clock)
        _extend(source, 5)
    elif situation == "first_in_existing_directory":
        os.mkdir(target)
    calls = sup.FaultCalls(fail_directory_fsync=True)
    with pytest.raises(DurabilityError):
        export_once(source, target, calls=calls, wall_ms=clock)
    visible = read_descriptor(target)
    if situation == "first_in_existing_directory":
        assert visible is None  # the new data file's entry was not durable: nothing was published
    if visible is not None:
        assert verify_export(target) == visible
    result = export_once(source, target, wall_ms=clock)
    assert verify_export(target) == result.descriptor
    assert result.descriptor.seq == source.read_bytes().count(b"\n") - 1


def test_a_failed_full_copy_removes_its_unfinished_generation(source: Path, target: str) -> None:
    calls = sup.FaultCalls(
        write_hook=lambda n: (_ for _ in ()).throw(OSError(errno.ENOSPC, "full"))
    )
    with pytest.raises(ResourceError) as caught:
        export_once(source, target, calls=calls, wall_ms=Clock())
    assert caught.value.rule == "io.no_space"
    assert [n for n in _listing(target) if n.startswith("journal.")] == []
    assert read_descriptor(target) is None


def test_cancellation_between_chunks_publishes_nothing(source: Path, target: str) -> None:
    clock = Clock()
    previous = export_once(source, target, wall_ms=clock).descriptor
    _extend(source, 40)
    calls_made = itertools.count()
    with pytest.raises(ExportCancelled):
        export_once(
            source,
            target,
            wall_ms=clock,
            chunk_bytes=300,
            cancel=lambda: next(calls_made) >= 3,
        )
    assert verify_export(target) == previous


def test_progress_reports_bytes_of_the_captured_prefix(source: Path, target: str) -> None:
    seen: list[tuple[int, int]] = []
    result = export_once(
        source, target, wall_ms=Clock(), chunk_bytes=400, progress=lambda d, t: seen.append((d, t))
    )
    assert seen[0] == (0, result.descriptor.offset)
    assert seen[-1] == (result.descriptor.offset, result.descriptor.offset)
    assert [d for d, _ in seen] == sorted(d for d, _ in seen)
    assert all(t == result.descriptor.offset for _, t in seen)


# -- the chain check of the copy ----------------------------------------------------------------


def _chain(limit: int = 1 << 20) -> Any:
    from cubeproof.base.settings import ReaderLimits
    from cubeproof.coordinator.export import _Chain

    return _Chain(ReaderLimits(line_bytes=limit))


def test_the_chain_check_accepts_lines_in_any_chunking_and_ends_on_a_line() -> None:
    data = b"".join(sup.make_chain(30, pad=50))
    for size in (1, 7, 100, len(data)):
        chain = _chain()
        for start in range(0, len(data), size):
            chain.feed(data[start : start + size])
        chain.finish()
        assert (chain.records, chain.offset) == (30, len(data))
        assert chain.head == sup.chain_of(sup.make_chain(30, pad=50))


def test_the_chain_check_refuses_bytes_after_the_last_line_and_overlong_lines() -> None:
    data = b"".join(sup.make_chain(3))
    chain = _chain()
    chain.feed(data[:-1])  # the last LF is missing: the last line is incomplete
    assert chain.records == 2
    with pytest.raises(IntegrityError) as caught:
        chain.finish()
    assert caught.value.rule == "export.chain"
    small = _chain(limit=100)
    with pytest.raises(ResourceError) as long:
        small.feed(b"x" * 101)
    assert long.value.rule == "limit.line"
    with pytest.raises(ResourceError):
        _chain(limit=100).feed(b"x" * 101 + b"\n")


def test_the_chain_check_continues_from_a_published_position() -> None:
    from cubeproof.base.settings import ReaderLimits
    from cubeproof.coordinator.export import _Chain

    lines = sup.make_chain(10)
    head = sup.chain_of(lines[:6])
    resumed = _Chain(
        ReaderLimits(),
        journal=json.loads(lines[0])["self"],
        records=6,
        head=head,
        offset=len(b"".join(lines[:6])),
    )
    resumed.feed(b"".join(lines[6:]))
    resumed.finish()
    assert (resumed.records, resumed.head, resumed.offset) == (
        10,
        sup.chain_of(lines),
        len(b"".join(lines)),
    )
    wrong = _Chain(ReaderLimits(), journal="0" * 64, records=6, head="f" * 64, offset=1)
    with pytest.raises(IntegrityError):
        wrong.feed(b"".join(lines[6:]))


# -- verify_export ---------------------------------------------------------------------------------


def test_verify_export_detects_damage_inside_the_published_prefix(
    source: Path, target: str
) -> None:
    descriptor = export_once(source, target, wall_ms=Clock()).descriptor
    path = Path(target, descriptor.file)
    original = path.read_bytes()
    for position in (5, descriptor.offset // 2, descriptor.offset - 10):
        damaged = bytearray(original)
        damaged[position] ^= 1
        path.write_bytes(bytes(damaged))
        with pytest.raises((IntegrityError, ResourceError)):
            verify_export(target)
    path.write_bytes(original[: descriptor.offset - 1])
    with pytest.raises(IntegrityError):
        verify_export(target)
    path.write_bytes(original + b"unpublished tail")
    assert verify_export(target) == descriptor  # a tail after the offset is not published
    path.unlink()
    with pytest.raises(IntegrityError):
        verify_export(target)


def test_verify_export_requires_the_prefix_to_end_on_a_line(source: Path, target: str) -> None:
    descriptor = export_once(source, target, wall_ms=Clock()).descriptor
    cut = {**descriptor.to_json(), "offset": descriptor.offset - 1}  # inside the last line
    Path(target, DESCRIPTOR_NAME).write_bytes(document_bytes(cut))
    with pytest.raises(IntegrityError) as caught:
        verify_export(target)
    assert caught.value.rule == "export.chain"


def test_verify_export_without_a_descriptor_or_with_a_bad_one(tmp_path: Path, source: Path) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()
    with pytest.raises(ContractError) as caught:
        verify_export(empty)
    assert caught.value.rule == "export.absent"
    (empty / DESCRIPTOR_NAME).write_bytes(b"[]\n")
    with pytest.raises(IntegrityError):
        verify_export(empty)


# -- concurrency -----------------------------------------------------------------------------------


def test_no_lock_is_held_while_the_copy_runs(tmp_path: Path) -> None:
    """With the copy blocked inside a write, the journal's lock is free for the writer."""
    live = sup.LiveJournal(tmp_path / "journal.jsonl", tmp_path / "run.lock")
    try:
        for _ in range(200):
            live.append()
        blocked, release = threading.Event(), threading.Event()

        def gate(number: int) -> None:
            if number == 1:
                blocked.set()
                assert release.wait(30)

        calls = sup.FaultCalls(write_hook=gate)
        target = str(tmp_path / "export")
        outcome: list[Any] = []
        worker = threading.Thread(
            target=lambda: outcome.append(
                export_once(live.path, target, calls=calls, wall_ms=Clock())
            )
        )
        worker.start()
        assert blocked.wait(30)
        # the exporter sits inside its copy: neither shared nor exclusive lock is held
        probe = os.open(live.path, os.O_RDWR)
        try:
            fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
            fcntl.flock(probe, fcntl.LOCK_UN)
        finally:
            os.close(probe)
        started = time.monotonic()
        live.append("while the export is blocked")
        assert time.monotonic() - started < 1.0
        release.set()
        worker.join(30)
        result = outcome[0]
        assert result.descriptor.seq == 200  # the position captured before the extra append
        assert verify_export(target) == result.descriptor
        again = export_once(live.path, target, wall_ms=Clock())
        assert again.mode == "incremental" and again.descriptor.seq == 201
    finally:
        live.close()


def test_the_shared_lock_covers_only_two_lines_of_a_large_journal(tmp_path: Path) -> None:
    """The capture reads the first and the last line: bytes read under the lock do not depend on
    the size of the journal."""
    path = tmp_path / "journal.jsonl"
    sup.write_lines(path, sup.make_chain(20_000, pad=1000))
    assert path.stat().st_size > 20_000_000

    class Counting(SysCalls):
        def __init__(self) -> None:
            self.locked = False
            self.bytes_under_lock = 0
            self.reads_under_lock = 0

        def flock(self, fd: int, operation: int) -> None:
            super().flock(fd, operation)
            self.locked = operation != fcntl.LOCK_UN

        def pread(self, fd: int, count: int, offset: int) -> bytes:
            data = super().pread(fd, count, offset)
            if self.locked:
                self.bytes_under_lock += len(data)
                self.reads_under_lock += 1
            return data

    calls = Counting()
    export_once(path, str(tmp_path / "export"), journal_calls=calls, wall_ms=Clock())
    assert calls.reads_under_lock > 0
    assert calls.bytes_under_lock < 512 * 1024
    assert calls.reads_under_lock < 20


@pytest.mark.parametrize(
    "megabytes", [8, pytest.param(64, marks=pytest.mark.slow)], ids=["8MiB", "64MiB"]
)
def test_a_large_export_concurrent_with_appends_is_a_consistent_prefix(
    tmp_path: Path, megabytes: int
) -> None:
    """A large journal exported while a writer keeps appending under the real lock.

    The export must be exactly the prefix captured at its start (never a mix), the writer's appends
    must not wait for the copy, and a reader that polls the descriptor must always find a valid
    prefix."""
    live = sup.LiveJournal(tmp_path / "journal.jsonl", tmp_path / "run.lock")
    try:
        # grow the real journal with long reasons, through the real writer
        reason = "r" * 1_000_000
        while live.path.stat().st_size < megabytes * 1024 * 1024:
            live.append(reason)
        size_at_start = live.path.stat().st_size
        target = str(tmp_path / "export")
        stop = threading.Event()
        append_waits: list[float] = []
        failures: list[str] = []
        checks = [0]

        def writer() -> None:
            while not stop.is_set():
                started = time.monotonic()
                live.append("concurrent")
                append_waits.append(time.monotonic() - started)
                time.sleep(0.002)

        def reader() -> None:
            while not stop.is_set():
                try:
                    descriptor = read_descriptor(target)
                    if descriptor is None:
                        continue
                    verify_export(target)
                    checks[0] += 1
                except Exception as error:  # recorded, asserted below
                    failures.append(repr(error))
                time.sleep(0.05)

        threads = [threading.Thread(target=writer), threading.Thread(target=reader)]
        for thread in threads:
            thread.start()
        try:
            clock = Clock()
            first = export_once(live.path, target, wall_ms=clock)
            assert first.mode == "full" and first.descriptor.offset >= size_at_start
            # more appends happened during the copy; the next exports take only the delta
            for _ in range(4):
                second = export_once(live.path, target, wall_ms=clock)
                assert second.mode in ("incremental", "unchanged")
                time.sleep(0.05)
            deadline = time.monotonic() + 60
            while checks[0] < 3 and time.monotonic() < deadline:
                time.sleep(0.01)
        finally:
            stop.set()
            for thread in threads:
                thread.join(30)
        assert failures == []
        assert checks[0] >= 3  # a reader polling the descriptor always found a valid prefix
        assert second.bytes_copied < megabytes * 1024 * 1024 // 4
        descriptor = verify_export(target)
        assert (
            Path(target, descriptor.file).read_bytes()[: descriptor.offset]
            == live.path.read_bytes()[: descriptor.offset]
        )
        assert max(append_waits) < 1.0  # a writer never waits for the copy
    finally:
        live.close()


# -- the journal and its export before a run resumes (specification §7.3 step 2) -------------------


@pytest.fixture
def lock(tmp_path: Path) -> Any:
    held = RunLock.acquire(tmp_path / "run.lock")
    yield held
    held.release()


def _lose_and_restore(source: Path, target: str, kept: int) -> tuple[bytes, ExportDescriptor]:
    """Export the whole journal, then leave only its first ``kept`` lines in the results (an
    older backup restored): ``(the exported bytes, the published descriptor)``."""
    descriptor = export_once(source, target, wall_ms=Clock()).descriptor
    exported = source.read_bytes()
    sup.write_lines(source, exported.splitlines(keepends=True)[:kept])
    return exported, descriptor


def test_no_export_directory_or_an_empty_one_is_absent(source: Path, target: str) -> None:
    assert compare_export(source, target).relation == "absent"
    os.mkdir(target)
    assert compare_export(source, target).relation == "absent"
    assert _listing(target) == [] and len(source.read_bytes().splitlines()) == 20


def test_a_new_worker_with_an_empty_export_directory_is_absent(tmp_path: Path, target: str) -> None:
    os.mkdir(target)
    assert compare_export(tmp_path / "journal.jsonl", target).relation == "absent"
    (tmp_path / "journal.jsonl").write_bytes(b"")
    assert compare_export(tmp_path / "journal.jsonl", target).relation == "absent"


def test_an_export_path_that_cannot_be_a_directory_is_refused_at_once(
    tmp_path: Path, source: Path
) -> None:
    (tmp_path / "file").write_bytes(b"x")
    with pytest.raises(ConfigurationError) as caught:
        compare_export(source, tmp_path / "file")
    assert caught.value.rule == "export.layout"
    with pytest.raises(ConfigurationError) as caught:
        compare_export(source, tmp_path / "missing" / "export")
    assert caught.value.rule == "export.layout"


def test_an_export_that_lags_or_equals_the_journal_needs_nothing(source: Path, target: str) -> None:
    descriptor = export_once(source, target, wall_ms=Clock()).descriptor
    level = compare_export(source, target)  # the export is ahead by zero records
    assert (level.relation, level.descriptor) == ("level", descriptor)
    assert level.journal == capture_anchor(source) and level.journal_bytes == descriptor.offset
    _extend(source, 5)
    behind = compare_export(source, target)
    assert behind.relation == "behind" and behind.journal == capture_anchor(source)
    assert read_descriptor(target) == descriptor and verify_export(target) == descriptor
    with pytest.raises(ValueError, match="ahead"):
        restore_from_export(source, target, behind, run_lock=RunLock.acquire(source.with_name("l")))


def test_a_lagging_export_whose_file_is_damaged_is_local_damage_not_a_fork(
    source: Path, target: str
) -> None:
    descriptor = export_once(source, target, wall_ms=Clock()).descriptor
    _extend(source, 5)
    Path(target, descriptor.file).unlink()
    assert compare_export(source, target).relation == "behind"
    assert export_once(source, target, wall_ms=Clock()).reason == "file_missing"


@pytest.mark.parametrize("kept", [1, 7, 19])
def test_a_journal_that_is_a_prefix_of_its_export_is_completed_from_it(
    source: Path, target: str, lock: RunLock, kept: int
) -> None:
    exported, descriptor = _lose_and_restore(source, target, kept)
    standing = compare_export(source, target)
    assert (standing.relation, standing.descriptor) == ("ahead", descriptor)
    assert standing.journal is not None and standing.journal.seq == kept - 1
    assert source.read_bytes() == b"".join(exported.splitlines(keepends=True)[:kept])  # read only
    seen: list[tuple[int, int]] = []
    restored = restore_from_export(
        source,
        target,
        standing,
        run_lock=lock,
        inspect=lambda d, a: seen.append((d.seq, a.seq)),
        chunk_bytes=37,
    )
    assert restored == 20 - kept and seen == [(19, kept - 1)]
    assert source.read_bytes() == exported
    # the export is untouched and the journal continues it: the next export is incremental
    assert read_descriptor(target) == descriptor and verify_export(target) == descriptor
    assert compare_export(source, target).relation == "level"
    _extend(source, 3)
    assert export_once(source, target, wall_ms=Clock()).mode == "incremental"
    assert _data(target, verify_export(target)) == source.read_bytes()


def test_the_unterminated_suffix_of_an_interrupted_restoration_is_completed(
    source: Path, target: str, lock: RunLock
) -> None:
    """A crash while the tail was appended leaves complete lines and part of the next one: all
    of it bytes of the export, so the next start appends the rest and removes nothing."""
    exported, _ = _lose_and_restore(source, target, 20)
    lines = exported.splitlines(keepends=True)
    source.write_bytes(b"".join(lines[:9]) + lines[9][:17])
    standing = compare_export(source, target)
    assert standing.relation == "ahead" and standing.journal is not None
    assert (standing.journal.seq, standing.journal_bytes) == (8, len(source.read_bytes()))
    assert restore_from_export(source, target, standing, run_lock=lock, chunk_bytes=5) == 11
    assert source.read_bytes() == exported


def test_a_failure_while_appending_leaves_a_prefix_that_the_next_start_completes(
    source: Path, target: str, lock: RunLock
) -> None:
    exported, _ = _lose_and_restore(source, target, 4)

    class Failing(SysCalls):
        writes = 0

        def write(self, fd: int, data: memoryview) -> int:
            Failing.writes += 1
            if Failing.writes == 3:
                raise OSError(errno.EIO, "injected")
            return super().write(fd, data[: max(1, len(data) // 2)])  # short writes on the way

    standing = compare_export(source, target)
    with pytest.raises(JournalRestoreError) as caught:
        restore_from_export(
            source, target, standing, run_lock=lock, journal_calls=Failing(), chunk_bytes=64
        )
    assert caught.value.rule == "journal.restore"
    partial = source.read_bytes()
    assert exported.startswith(partial) and len(partial) < len(exported)
    again = compare_export(source, target)
    assert again.relation == "ahead"
    restore_from_export(source, target, again, run_lock=lock)
    assert source.read_bytes() == exported


def test_an_fsync_failure_of_the_restoration_is_an_error(
    source: Path, target: str, lock: RunLock
) -> None:
    exported, _ = _lose_and_restore(source, target, 4)

    class NoSync(SysCalls):
        def fsync(self, fd: int) -> None:
            raise OSError(errno.EIO, "injected")

    with pytest.raises(JournalRestoreError):
        restore_from_export(
            source, target, compare_export(source, target), run_lock=lock, journal_calls=NoSync()
        )
    assert exported.startswith(source.read_bytes())


def test_restoring_needs_the_held_run_lock(source: Path, target: str, tmp_path: Path) -> None:
    _lose_and_restore(source, target, 4)
    before = source.read_bytes()
    released = RunLock.acquire(tmp_path / "other.lock")
    released.release()
    with pytest.raises(ConfigurationError) as caught:
        restore_from_export(source, target, compare_export(source, target), run_lock=released)
    assert caught.value.rule == "run.lock" and source.read_bytes() == before


def test_the_inspection_can_refuse_and_nothing_is_written(
    source: Path, target: str, lock: RunLock
) -> None:
    _, descriptor = _lose_and_restore(source, target, 4)
    before = source.read_bytes()

    def refuse(d: ExportDescriptor, a: Any) -> None:
        raise IntegrityError("artifact.missing", "a proof is not there")

    with pytest.raises(IntegrityError) as caught:
        restore_from_export(
            source, target, compare_export(source, target), run_lock=lock, inspect=refuse
        )
    assert caught.value.rule == "export.regressed"
    assert "artifact.missing: a proof is not there" in caught.value.detail
    assert "record 3" in caught.value.detail and "holds 19" in caught.value.detail
    assert source.read_bytes() == before and verify_export(target) == descriptor


def test_a_journal_changed_after_the_comparison_is_not_appended_to(
    source: Path, target: str, lock: RunLock
) -> None:
    exported, _ = _lose_and_restore(source, target, 4)
    standing = compare_export(source, target)
    sup.append_lines(source, exported.splitlines(keepends=True)[4:5])
    before = source.read_bytes()
    with pytest.raises(IntegrityError) as caught:
        restore_from_export(source, target, standing, run_lock=lock)
    assert caught.value.rule == "export.regressed" and "run.tail" in caught.value.detail
    assert source.read_bytes() == before


@pytest.mark.parametrize("damage", ["missing", "short", "garbage", "relinked"])
def test_an_export_that_is_ahead_but_cannot_supply_the_records_is_refused(
    source: Path, target: str, lock: RunLock, damage: str
) -> None:
    """The export claims more records than the journal has, and its data file is missing, cut,
    damaged after the journal's end, or a well-formed chain that does not reach the descriptor's
    head: the run must not start (it would fork what the descriptor publishes) and nothing is
    written anywhere."""
    exported, descriptor = _lose_and_restore(source, target, 6)
    data = Path(target, descriptor.file)
    lines = exported.splitlines(keepends=True)
    if damage == "missing":
        data.unlink()
    elif damage == "short":
        data.write_bytes(exported[:-10])
    elif damage == "garbage":
        data.write_bytes(b"".join(lines[:10]) + b"x" * len(lines[10]) + b"".join(lines[11:]))
    else:
        # same lengths, a well-formed chain, another head than the descriptor's
        changed = sup.relink([*lines[:10], sup.resign(lines[10], seed="b"), *lines[11:]], 11)
        data.write_bytes(b"".join(changed))
        assert len(data.read_bytes()) == len(exported)
    before, held = source.read_bytes(), data.read_bytes() if data.exists() else None
    with pytest.raises(IntegrityError) as caught:
        standing = compare_export(source, target)
        restore_from_export(source, target, standing, run_lock=lock)
    assert caught.value.rule == "export.regressed", caught.value
    assert "ends at record 5, the export already holds 19" in caught.value.detail
    assert "move the export directory aside" in caught.value.detail
    assert source.read_bytes() == before and read_descriptor(target) == descriptor
    assert (data.read_bytes() if data.exists() else None) == held


def test_a_restored_journal_that_already_went_on_is_a_fork_and_is_refused(
    source: Path, target: str
) -> None:
    """The walkthrough's state after a run that ignored the failing export: the restored journal
    has its own records after the backup point, the export the older continuation."""
    exported, descriptor = _lose_and_restore(source, target, 6)
    lines = exported.splitlines(keepends=True)[:6]
    for extra in (3, 14, 30):  # shorter than, as long as and longer than the exported history
        forked = lines + sup.make_chain(extra, seed="fork", start=6, prev=sup.chain_of(lines))
        sup.write_lines(source, forked)
        with pytest.raises(IntegrityError) as caught:
            compare_export(source, target)
        assert caught.value.rule == "export.diverged", extra
        assert "move the export directory aside" in caught.value.detail
        assert source.read_bytes() == b"".join(forked) and verify_export(target) == descriptor


def test_a_partial_last_line_that_is_not_the_next_exported_record_is_refused(
    source: Path, target: str
) -> None:
    _, descriptor = _lose_and_restore(source, target, 6)
    with source.open("ab") as stream:
        stream.write(b'{"format":"cubeproof-journal-1","other')
    before = source.read_bytes()
    with pytest.raises(IntegrityError) as caught:
        compare_export(source, target)
    assert caught.value.rule == "export.regressed" and "partial line" in caught.value.detail
    assert source.read_bytes() == before and verify_export(target) == descriptor


def test_the_export_of_another_journal_or_of_no_journal_is_refused(
    tmp_path: Path, source: Path, target: str
) -> None:
    descriptor = export_once(source, target, wall_ms=Clock()).descriptor
    sup.write_lines(source, sup.make_chain(30, seed="other"))
    with pytest.raises(ConfigurationError) as caught:
        compare_export(source, target)
    assert caught.value.rule == "export.foreign" and "its own --export" in caught.value.detail
    for empty in (True, False):  # an empty journal file, no journal file: a new worker
        source.write_bytes(b"") if empty else source.unlink()
        with pytest.raises(ConfigurationError) as caught:
            compare_export(source, target)
        assert caught.value.rule == "export.foreign" and "holds no journal" in caught.value.detail
    assert verify_export(target) == descriptor


def test_a_damaged_descriptor_publishes_nothing_and_does_not_stop_a_run(
    source: Path, target: str
) -> None:
    export_once(source, target, wall_ms=Clock())
    Path(target, DESCRIPTOR_NAME).write_bytes(b'{"format":"cubeproof-export-1"')
    standing = compare_export(source, target)
    assert standing.relation == "unreadable" and standing.descriptor is None
    result = export_once(source, target, wall_ms=Clock())
    assert (result.mode, result.reason) == ("full", "descriptor_invalid")


def test_a_journal_whose_end_is_unreadable_is_left_to_the_replay(source: Path, target: str) -> None:
    export_once(source, target, wall_ms=Clock())
    with source.open("ab") as stream:
        stream.write(b"not a record\n")
    standing = compare_export(source, target)
    assert standing.relation == "unknown" and standing.detail
