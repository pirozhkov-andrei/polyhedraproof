"""Atomic file helpers (specification §7.1, §7.2, §7.4): write_all, directory sync, no-overwrite
publication by link (with a rename fallback), atomic small documents, chunked hashing.

System calls go through an injectable :class:`FileCalls`; the tests record them in order and
inject short writes, EINTR, ENOSPC, failing fsync and simulated process death. They show which
calls are made in which order; whether a file system honours fsync cannot be observed here.
"""

from __future__ import annotations

import errno
import os
from pathlib import Path

import cp_io_support as sup
import pytest
from cp_io_support import Crash, FaultCalls

from cubeproof.base.errors import ContractError, IntegrityError, ResourceError, ToolError
from cubeproof.tools.atomic import (
    OS_FILE_CALLS,
    DurabilityError,
    atomic_write,
    drive,
    ensure_directory,
    fsync_directory,
    hash_steps,
    link_no_replace,
    open_regular,
    write_all,
)

# -- write_all -------------------------------------------------------------------------------------


def test_write_all_completes_short_writes(tmp_path: Path) -> None:
    calls = FaultCalls(write_limit=3)
    fd = calls.open(str(tmp_path / "f"), os.O_WRONLY | os.O_CREAT, 0o600)
    try:
        write_all(calls, fd, b"0123456789")
    finally:
        calls.close(fd)
    assert (tmp_path / "f").read_bytes() == b"0123456789"
    assert [e[2] for e in calls.events("write")] == [3, 3, 3, 1]


def test_write_all_retries_eintr(tmp_path: Path) -> None:
    calls = FaultCalls(faults={"write": sup.interrupt(2)})
    fd = calls.open(str(tmp_path / "f"), os.O_WRONLY | os.O_CREAT, 0o600)
    try:
        write_all(calls, fd, b"abc")
    finally:
        calls.close(fd)
    assert (tmp_path / "f").read_bytes() == b"abc"


@pytest.mark.parametrize("bad", [0, -1, 99])
def test_write_all_refuses_no_progress_and_impossible_counts(tmp_path: Path, bad: int) -> None:
    def fault(number: int, *args: object) -> int:
        if number > 100:  # a loop that accepts no progress would never end
            raise AssertionError("write_all retried a write without progress")
        return bad

    calls = FaultCalls(faults={"write": fault})
    fd = calls.open(str(tmp_path / "f"), os.O_WRONLY | os.O_CREAT, 0o600)
    try:
        with pytest.raises(OSError):
            write_all(calls, fd, b"abc")
    finally:
        calls.close(fd)
    assert calls.counts["write"] == 1


# -- directories -----------------------------------------------------------------------------------


def test_fsync_directory_syncs_the_directory(tmp_path: Path) -> None:
    calls = FaultCalls()
    fsync_directory(calls, str(tmp_path))
    assert calls.events("fsync") == [("fsync", str(tmp_path))]
    assert calls.events("close") == [("close", str(tmp_path))]


def test_a_failed_directory_sync_is_a_durability_error(tmp_path: Path) -> None:
    calls = FaultCalls(faults={"fsync": sup.fail_with(errno.EIO)})
    with pytest.raises(DurabilityError) as caught:
        fsync_directory(calls, str(tmp_path))
    assert caught.value.rule == "io.fsync"
    assert isinstance(caught.value, ToolError)
    assert calls.events("close") == [("close", str(tmp_path))]


def test_ensure_directory_creates_and_syncs_the_parent(tmp_path: Path) -> None:
    calls = FaultCalls()
    assert ensure_directory(calls, str(tmp_path / "proofs")) is True
    assert (tmp_path / "proofs").is_dir()
    assert calls.names().index("mkdir") < calls.names().index("fsync")
    assert ("fsync", str(tmp_path)) in calls.log
    calls = FaultCalls()
    assert ensure_directory(calls, str(tmp_path / "proofs")) is False
    assert calls.events("mkdir", "fsync") == []


def test_ensure_directory_refuses_symlinks_and_files(tmp_path: Path) -> None:
    (tmp_path / "real").mkdir()
    (tmp_path / "link").symlink_to(tmp_path / "real")
    (tmp_path / "file").write_bytes(b"")
    for name in ("link", "file"):
        with pytest.raises(ContractError) as caught:
            ensure_directory(OS_FILE_CALLS, str(tmp_path / name))
        assert caught.value.rule == "io.layout"


# -- opening ---------------------------------------------------------------------------------------


def test_open_regular_refuses_symlinks_and_special_files(tmp_path: Path) -> None:
    sup.write_file(tmp_path / "f", b"abc")
    (tmp_path / "l").symlink_to(tmp_path / "f")
    os.mkfifo(tmp_path / "p")
    fd, size = open_regular(OS_FILE_CALLS, str(tmp_path / "f"))
    os.close(fd)
    assert size == 3
    for name in ("l", "p"):
        with pytest.raises(ContractError) as caught:
            open_regular(OS_FILE_CALLS, str(tmp_path / name))
        assert caught.value.rule == "io.not_regular"
    with pytest.raises(FileNotFoundError):
        open_regular(OS_FILE_CALLS, str(tmp_path / "missing"))


# -- chunked hashing -------------------------------------------------------------------------------


@pytest.mark.parametrize("size", [0, 1, 4095, 4096, 4097, 3 * 4096])
def test_hash_steps_reads_in_bounded_chunks(tmp_path: Path, size: int) -> None:
    data = sup.proof_bytes(size)
    sup.write_file(tmp_path / "f", data)
    calls = FaultCalls()
    fd, _ = open_regular(calls, str(tmp_path / "f"))
    steps = 0
    generator = hash_steps(calls, fd, chunk_bytes=4096)
    try:
        while True:
            next(generator)
            steps += 1
    except StopIteration as stop:
        assert stop.value == (size, sup.sha(data))
    finally:
        calls.close(fd)
    assert all(e[2] <= 4096 for e in calls.events("pread"))
    assert steps >= size // 4096


def test_hash_steps_handles_short_reads(tmp_path: Path) -> None:
    data = sup.proof_bytes(10_000)
    sup.write_file(tmp_path / "f", data)
    real = os.pread
    calls = FaultCalls(
        faults={"pread": lambda n, fd, count, offset: real(fd, min(7, count), offset)}
    )
    fd, _ = open_regular(calls, str(tmp_path / "f"))
    try:
        assert drive(hash_steps(calls, fd, chunk_bytes=4096)) == (len(data), sup.sha(data))
    finally:
        calls.close(fd)


# -- no-overwrite publication ----------------------------------------------------------------------


def test_link_no_replace_publishes_and_never_overwrites(tmp_path: Path) -> None:
    sup.write_file(tmp_path / "a", b"new")
    assert link_no_replace(OS_FILE_CALLS, str(tmp_path / "a"), str(tmp_path / "b")) is True
    assert (tmp_path / "b").read_bytes() == b"new"
    sup.write_file(tmp_path / "c", b"other")
    assert link_no_replace(OS_FILE_CALLS, str(tmp_path / "c"), str(tmp_path / "b")) is False
    assert (tmp_path / "b").read_bytes() == b"new"


@pytest.mark.parametrize("code", [errno.EPERM, errno.EOPNOTSUPP, errno.ENOSYS])
def test_link_no_replace_falls_back_to_rename_without_hard_links(tmp_path: Path, code: int) -> None:
    calls = FaultCalls(faults={"link": sup.fail_with(code)})
    sup.write_file(tmp_path / "a", b"new")
    assert link_no_replace(calls, str(tmp_path / "a"), str(tmp_path / "b")) is True
    assert (tmp_path / "b").read_bytes() == b"new"
    assert not (tmp_path / "a").exists()
    sup.write_file(tmp_path / "c", b"other")
    calls = FaultCalls(faults={"link": sup.fail_with(code)})
    assert link_no_replace(calls, str(tmp_path / "c"), str(tmp_path / "b")) is False
    assert (tmp_path / "b").read_bytes() == b"new"
    assert calls.events("rename") == []


def test_link_no_replace_propagates_other_errors(tmp_path: Path) -> None:
    calls = FaultCalls(faults={"link": sup.fail_with(errno.EIO)})
    sup.write_file(tmp_path / "a", b"new")
    with pytest.raises(OSError):
        link_no_replace(calls, str(tmp_path / "a"), str(tmp_path / "b"))
    assert not (tmp_path / "b").exists()


# -- atomic documents ------------------------------------------------------------------------------


def test_atomic_write_order_is_write_fsync_publish_fsync_directory(tmp_path: Path) -> None:
    calls = FaultCalls()
    target = tmp_path / "outbox" / "r.json"
    target.parent.mkdir()
    assert atomic_write(str(target), b"{}\n", calls=calls) is True
    assert target.read_bytes() == b"{}\n"
    names = [n for n in calls.names() if n in ("write", "fsync", "link", "rename", "unlink")]
    assert names[0] == "write"
    fsyncs = calls.events("fsync")
    assert fsyncs[-1] == ("fsync", str(target.parent))
    publish = next(i for i, n in enumerate(calls.names()) if n in ("link", "rename"))
    first_fsync = calls.names().index("fsync")
    assert first_fsync < publish  # the file is durable before it gets its name
    assert sorted(p.name for p in target.parent.iterdir()) == ["r.json"]


def test_atomic_write_is_idempotent_for_equal_bytes_and_refuses_unequal(tmp_path: Path) -> None:
    target = tmp_path / "r.json"
    assert atomic_write(str(target), b"same") is True
    calls = FaultCalls()
    assert atomic_write(str(target), b"same", calls=calls) is False
    assert calls.events("write", "link", "rename") == []
    with pytest.raises(IntegrityError) as caught:
        atomic_write(str(target), b"different")
    assert caught.value.rule == "artifact.conflict"
    assert target.read_bytes() == b"same"
    assert sorted(p.name for p in tmp_path.iterdir()) == ["r.json"]


def test_atomic_write_never_leaves_partial_bytes_at_the_name(tmp_path: Path) -> None:
    data = b"x" * 10_000
    crashed = 0
    for point in range(1, 20):
        directory = tmp_path / str(point)
        directory.mkdir()
        target = directory / "doc"
        calls = FaultCalls(crash_at=point, write_limit=4096)
        try:
            atomic_write(str(target), data, calls=calls)
        except Crash:
            crashed += 1
        if target.exists():
            assert target.read_bytes() == data
        # A rerun after the crash (orphan temporary files aside) publishes the same bytes.
        atomic_write(str(target), data)
        assert target.read_bytes() == data
    assert crashed >= 7  # open, three writes, fsync, publish, directory fsync, ...


def test_atomic_write_full_disk_leaves_nothing(tmp_path: Path) -> None:
    calls = FaultCalls(faults={"write": sup.fail_with(errno.ENOSPC, after=1)}, write_limit=10)
    with pytest.raises(ResourceError) as caught:
        atomic_write(str(tmp_path / "doc"), b"y" * 100, calls=calls)
    assert caught.value.rule == "io.no_space"
    assert list(tmp_path.iterdir()) == []


def test_atomic_write_failed_fsync_is_a_durability_error_and_leaves_nothing(
    tmp_path: Path,
) -> None:
    calls = FaultCalls(faults={"fsync": sup.fail_with(errno.EIO)})
    with pytest.raises(DurabilityError):
        atomic_write(str(tmp_path / "doc"), b"z", calls=calls)
    assert list(tmp_path.iterdir()) == []
