"""The read/write/fsync/rename fault adapters inject exactly the configured faults."""

from __future__ import annotations

import errno
import os
from pathlib import Path

import pytest

from fakes.fault_ops import Fault, FaultyOS, SimulatedCrash, patched


def append_record(ops: object, path: Path, data: bytes) -> None:
    """A tiny durable append, the way journal code would write it."""
    real: FaultyOS = ops  # type: ignore[assignment]
    fd = real.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
    try:
        view = memoryview(data)
        while view:
            view = view[real.write(fd, view) :]
        real.fsync(fd)
    finally:
        real.close(fd)


def test_without_faults_everything_is_forwarded_and_logged(tmp_path: Path) -> None:
    ops = FaultyOS()
    target = tmp_path / "journal"
    append_record(ops, target, b"one\n")
    assert target.read_bytes() == b"one\n"
    assert [c.op for c in ops.calls] == ["open", "write", "fsync", "close"]
    assert ops.outcomes() == ["ok"] * 4
    assert ops.calls[1].path == str(target)
    assert ops.calls[1].size == 4
    assert ops.O_RDONLY == os.O_RDONLY  # everything else is the real module


@pytest.mark.parametrize("code", [errno.EIO, errno.ENOSPC, errno.EDQUOT])
def test_an_fsync_error(tmp_path: Path, code: int) -> None:
    ops = FaultyOS([Fault("fsync", errno=code)])
    with pytest.raises(OSError) as caught:
        append_record(ops, tmp_path / "j", b"x\n")
    assert caught.value.errno == code
    assert ops.outcomes("fsync") == ["error"]
    assert ops.outcomes("close") == ["ok"]


def test_short_writes_are_retried_by_correct_code(tmp_path: Path) -> None:
    ops = FaultyOS([Fault("write", "short", nth=1, times=3, keep=2)])
    append_record(ops, tmp_path / "j", b"abcdefgh\n")
    assert (tmp_path / "j").read_bytes() == b"abcdefgh\n"
    assert ops.outcomes("write") == ["short", "short", "short", "ok"]


def test_a_zero_byte_write(tmp_path: Path) -> None:
    ops = FaultyOS([Fault("write", "short", keep=0)])
    fd = ops.open(tmp_path / "j", os.O_WRONLY | os.O_CREAT, 0o644)
    assert ops.write(fd, b"abc") == 0
    assert ops.write(fd, b"abc") == 3
    ops.close(fd)


def test_a_short_read(tmp_path: Path) -> None:
    (tmp_path / "j").write_bytes(b"0123456789")
    ops = FaultyOS([Fault("read", "short", keep=3)])
    fd = ops.open(tmp_path / "j", os.O_RDONLY)
    assert ops.read(fd, 100) == b"012"
    assert ops.read(fd, 100) == b"3456789"
    ops.close(fd)


def test_eintr_is_raised_once(tmp_path: Path) -> None:
    ops = FaultyOS([Fault("write", "eintr")])
    fd = ops.open(tmp_path / "j", os.O_WRONLY | os.O_CREAT, 0o644)
    with pytest.raises(InterruptedError):
        ops.write(fd, b"abc")
    assert ops.write(fd, b"abc") == 3
    ops.close(fd)


def test_a_torn_write_leaves_a_partial_record_and_crashes(tmp_path: Path) -> None:
    target = tmp_path / "j"
    ops = FaultyOS([Fault("write", "torn", nth=2, keep=3)])
    append_record(ops, target, b"first\n")
    with pytest.raises(SimulatedCrash):
        append_record(ops, target, b"second\n")
    assert target.read_bytes() == b"first\nsec"


def test_a_crash_is_not_an_ordinary_exception(tmp_path: Path) -> None:
    ops = FaultyOS([Fault("fsync", "crash_before")])
    swallowed = False
    with pytest.raises(SimulatedCrash):
        try:
            append_record(ops, tmp_path / "j", b"x\n")
        except Exception:
            swallowed = True
    assert not swallowed


def test_rename_crash_before_and_after(tmp_path: Path) -> None:
    for effect, moved in (("crash_before", False), ("crash_after", True)):
        source = tmp_path / f"{effect}.tmp"
        target = tmp_path / f"{effect}.final"
        source.write_bytes(b"data")
        ops = FaultyOS([Fault("rename", effect), Fault("replace", effect)])
        with pytest.raises(SimulatedCrash):
            ops.rename(source, target)
        assert target.exists() is moved
        assert source.exists() is not moved


def test_replace_error_matches_the_destination_path(tmp_path: Path) -> None:
    ops = FaultyOS([Fault("replace", path="*/artifacts/*", errno=errno.EXDEV)])
    (tmp_path / "artifacts").mkdir()
    (tmp_path / "a").write_bytes(b"1")
    (tmp_path / "b").write_bytes(b"2")
    ops.replace(tmp_path / "a", tmp_path / "moved")
    with pytest.raises(OSError) as caught:
        ops.replace(tmp_path / "b", tmp_path / "artifacts" / "b")
    assert caught.value.errno == errno.EXDEV
    assert ops.outcomes("replace") == ["ok", "error"]


def test_nth_and_times_count_matching_calls_only(tmp_path: Path) -> None:
    ops = FaultyOS([Fault("write", nth=2, times=2, path="*/b")])
    fds = {name: ops.open(tmp_path / name, os.O_WRONLY | os.O_CREAT, 0o644) for name in "ab"}
    outcomes = []
    for name in "abababab":
        try:
            ops.write(fds[name], b"x")
            outcomes.append(f"{name}:ok")
        except OSError:
            outcomes.append(f"{name}:error")
    for fd in fds.values():
        ops.close(fd)
    assert outcomes == ["a:ok", "b:ok", "a:ok", "b:error", "a:ok", "b:error", "a:ok", "b:ok"]


def _write_outcomes(ops: FaultyOS, fd: int, count: int) -> list[str]:
    outcomes = []
    for _ in range(count):
        try:
            written = ops.write(fd, b"abc")
            outcomes.append("ok" if written == 3 else f"short:{written}")
        except InterruptedError:
            outcomes.append("eintr")
        except OSError as error:
            outcomes.append(errno.errorcode[error.errno or 0])
    return outcomes


def test_two_faults_on_one_operation_count_the_same_calls(tmp_path: Path) -> None:
    # "first write short, the retry fails with EIO": nth refers to the calls of the code
    # under test, not to the calls left over by an earlier fault.
    ops = FaultyOS([Fault("write", "short", nth=1, keep=1), Fault("write", "error", nth=2)])
    fd = ops.open(tmp_path / "j", os.O_WRONLY | os.O_CREAT, 0o644)
    assert _write_outcomes(ops, fd, 3) == ["short:1", "EIO", "ok"]
    ops.close(fd)
    assert ops.outcomes("write") == ["short", "error", "ok"]


def test_when_two_faults_are_due_the_first_listed_fires(tmp_path: Path) -> None:
    ops = FaultyOS(
        [
            Fault("write", "eintr", nth=1, times=2),
            Fault("write", "error", nth=2, errno=errno.ENOSPC),
            Fault("write", "error", nth=3, errno=errno.EIO),
        ]
    )
    fd = ops.open(tmp_path / "j", os.O_WRONLY | os.O_CREAT, 0o644)
    # Call 2 is due for the EINTR and the ENOSPC fault: EINTR wins, ENOSPC has used it up.
    assert _write_outcomes(ops, fd, 4) == ["eintr", "eintr", "EIO", "ok"]
    ops.close(fd)


def test_rename_faults_match_the_source_or_the_destination(tmp_path: Path) -> None:
    ops = FaultyOS([Fault("rename", path="*.tmp", nth=2), Fault("replace", path="*/final")])
    for name in ("a.tmp", "b.tmp", "c.tmp", "d"):
        (tmp_path / name).write_bytes(b"x")
    ops.rename(tmp_path / "a.tmp", tmp_path / "a")
    with pytest.raises(OSError):
        ops.rename(tmp_path / "b.tmp", tmp_path / "b")  # second call whose source matches
    ops.rename(tmp_path / "c.tmp", tmp_path / "c")
    with pytest.raises(OSError):
        ops.replace(tmp_path / "d", tmp_path / "final")  # destination matches
    assert ops.outcomes() == ["ok", "error", "ok", "error"]
    assert ops.calls[1].source == str(tmp_path / "b.tmp")
    assert ops.calls[1].path == str(tmp_path / "b")
    assert (tmp_path / "b.tmp").exists()
    assert not (tmp_path / "final").exists()


def test_times_zero_fires_forever(tmp_path: Path) -> None:
    ops = FaultyOS([Fault("fdatasync", times=0, nth=2)])
    fd = ops.open(tmp_path / "j", os.O_WRONLY | os.O_CREAT, 0o644)
    ops.fdatasync(fd)
    for _ in range(5):
        with pytest.raises(OSError):
            ops.fdatasync(fd)
    ops.close(fd)


def test_descriptors_not_opened_through_the_adapter_resolve_by_proc(tmp_path: Path) -> None:
    fd = os.open(tmp_path / "outside", os.O_WRONLY | os.O_CREAT, 0o644)
    try:
        ops = FaultyOS([Fault("write", path="*/outside")])
        with pytest.raises(OSError):
            ops.write(fd, b"x")
        assert ops.calls[0].path == str(tmp_path / "outside")
    finally:
        os.close(fd)


def test_open_and_close_faults(tmp_path: Path) -> None:
    ops = FaultyOS([Fault("open", errno=errno.EMFILE), Fault("close", errno=errno.EIO)])
    with pytest.raises(OSError) as caught:
        ops.open(tmp_path / "j", os.O_WRONLY | os.O_CREAT, 0o644)
    assert caught.value.errno == errno.EMFILE
    fd = ops.open(tmp_path / "j", os.O_WRONLY | os.O_CREAT, 0o644)
    with pytest.raises(OSError):
        ops.close(fd)
    os.close(fd)  # the injected error did not close it


def test_patched_installs_over_the_os_module_and_restores_it(tmp_path: Path) -> None:
    original = os.fsync
    with patched([Fault("fsync", errno=errno.EIO)]) as ops:
        assert os.fsync is not original
        fd = os.open(tmp_path / "j", os.O_WRONLY | os.O_CREAT, 0o644)
        os.write(fd, b"x")
        with pytest.raises(OSError):
            os.fsync(fd)
        os.close(fd)
    assert os.fsync is original
    assert [c.op for c in ops.calls] == ["open", "write", "fsync", "close"]


def test_patched_restores_after_a_crash(tmp_path: Path) -> None:
    original = os.write
    with pytest.raises(SimulatedCrash), patched([Fault("write", "crash_after")]):
        fd = os.open(tmp_path / "j", os.O_WRONLY | os.O_CREAT, 0o644)
        try:
            os.write(fd, b"x")
        finally:
            os.close(fd)
    assert os.write is original
    assert (tmp_path / "j").read_bytes() == b"x"


@pytest.mark.parametrize(
    "kwargs",
    [
        {"op": "chmod"},
        {"op": "write", "effect": "explode"},
        {"op": "fsync", "effect": "short"},
        {"op": "write", "nth": 0},
        {"op": "write", "times": -1},
        {"op": "write", "keep": -1},
    ],
)
def test_bad_faults_are_rejected(kwargs: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        Fault(**kwargs)  # type: ignore[arg-type]
