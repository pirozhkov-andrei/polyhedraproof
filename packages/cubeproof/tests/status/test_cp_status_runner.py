"""The export runner: the loop never waits for a disk, slow I/O is visible, failures are
retried (specification §7.5, §8.1)."""

from __future__ import annotations

import errno
import threading
import time
from pathlib import Path
from typing import Any

import cp_status_support as sup
import pytest

from cubeproof.contracts.primitives import parse_utc
from cubeproof.coordinator.export import read_descriptor, verify_export
from cubeproof.coordinator.export_runner import ExportRunner

WALL0 = 1_790_000_000_000


class Clocks:
    def __init__(self) -> None:
        self.mono = 5_000
        self.wall = WALL0

    def advance(self, ms: int) -> None:
        self.mono += ms
        self.wall += ms

    def now(self) -> int:
        return self.mono

    def wall_ms(self) -> int:
        return self.wall


class Gate:
    """Blocks the n-th data write of an export until released (a slow or hung disk)."""

    def __init__(self, at: int = 1) -> None:
        self.at = at
        self.reached = threading.Event()
        self.release = threading.Event()

    def __call__(self, number: int) -> None:
        if number == self.at:
            self.reached.set()
            assert self.release.wait(30)


def _wait(condition: Any, what: str, seconds: float = 20.0) -> None:
    deadline = time.monotonic() + seconds
    while not condition():
        assert time.monotonic() < deadline, what
        time.sleep(0.002)


@pytest.fixture
def source(tmp_path: Path) -> Path:
    path = tmp_path / "journal.jsonl"
    sup.write_lines(path, sup.make_chain(40, pad=200))
    return path


def _grow(path: Path, count: int) -> None:
    lines = path.read_bytes().splitlines(keepends=True)
    sup.append_lines(
        path, sup.make_chain(count, pad=200, start=len(lines), prev=sup.chain_of(lines))
    )


class Events:
    def __init__(self) -> None:
        self.items: list[tuple[str, str, dict[str, Any]]] = []

    def __call__(self, level: str, kind: str, fields: dict[str, Any]) -> None:
        self.items.append((level, kind, fields))

    def kinds(self) -> list[str]:
        return [kind for _, kind, _ in self.items]


def _runner(
    source: Path, tmp_path: Path, clocks: Clocks, events: Events | None = None, **options: Any
) -> ExportRunner:
    return ExportRunner(
        source,
        tmp_path / "export",
        monotonic_ms=clocks.now,
        wall_ms=clocks.wall_ms,
        on_event=events,
        **options,
    )


def _finish(runner: ExportRunner, clocks: Clocks) -> Any:
    """Wait for the running export and collect its outcome."""
    _wait(lambda: not runner.running(), "the export did not end")
    outcome = runner.poll(clocks.mono)
    assert outcome is not None
    return outcome


def test_the_first_poll_starts_an_export_and_a_later_one_collects_it(
    source: Path, tmp_path: Path
) -> None:
    clocks, events = Clocks(), Events()
    runner = _runner(source, tmp_path, clocks, events, chunk_bytes=4096)
    assert runner.info() is None and runner.last is None
    assert runner.poll(clocks.mono) is None  # started, not collected
    outcome = _finish(runner, clocks)
    assert outcome.ok and outcome.result is not None and outcome.result.mode == "full"
    info = runner.info(outcome.result.descriptor.head)
    assert info is not None
    assert (info.head, info.seq, info.lag_ms) == (outcome.result.descriptor.head, 39, 0)
    assert runner.counters()["export_ok"] == 1 and runner.counters()["export_full"] == 1
    assert events.kinds() == ["export.ok"]
    assert verify_export(tmp_path / "export").head == info.head


def test_the_loop_is_not_blocked_by_a_disk_that_hangs(source: Path, tmp_path: Path) -> None:
    clocks, events = Clocks(), Events()
    gate = Gate()
    runner = _runner(
        source,
        tmp_path,
        clocks,
        events,
        slow_ms=10_000,
        calls=sup.FaultCalls(write_hook=gate),
    )
    runner.poll(clocks.mono)
    assert gate.reached.wait(20)
    # the "process loop": thousands of polls and timer reads while the write hangs
    longest = 0.0
    started = time.monotonic()
    for _ in range(2000):
        before = time.monotonic()
        assert runner.poll(clocks.mono) is None
        runner.details(clocks.mono)
        longest = max(longest, time.monotonic() - before)
    assert longest < 0.05 and time.monotonic() - started < 2.0
    details = runner.details(clocks.mono)
    assert details["state"] == "running" and details["slow"] is False
    assert details["bytes_total"] > 0 and details["bytes_done"] == 0
    gate.release.set()
    assert _finish(runner, clocks).ok


def test_an_export_that_runs_too_long_is_reported_once_as_slow(
    source: Path, tmp_path: Path
) -> None:
    clocks, events = Clocks(), Events()
    gate = Gate(at=2)
    runner = _runner(
        source,
        tmp_path,
        clocks,
        events,
        slow_ms=30_000,
        chunk_bytes=2048,
        calls=sup.FaultCalls(write_hook=gate),
    )
    runner.poll(clocks.mono)
    assert gate.reached.wait(20)
    details = runner.details(clocks.mono)
    assert details["bytes_done"] > 0 and details["bytes_done"] < details["bytes_total"]
    clocks.advance(29_999)
    runner.poll(clocks.mono)
    assert "export.slow" not in events.kinds()
    clocks.advance(1)
    runner.poll(clocks.mono)
    clocks.advance(10_000)
    runner.poll(clocks.mono)
    slow = [fields for _, kind, fields in events.items if kind == "export.slow"]
    assert len(slow) == 1 and slow[0]["running_ms"] == 30_000 and slow[0]["bytes_done"] > 0
    assert runner.details(clocks.mono)["slow"] is True
    gate.release.set()
    _finish(runner, clocks)
    assert runner.details(clocks.mono)["state"] == "idle"


def test_exports_start_at_most_once_per_interval(source: Path, tmp_path: Path) -> None:
    clocks = Clocks()
    runner = _runner(source, tmp_path, clocks, interval_ms=60_000)
    runner.poll(clocks.mono)
    _finish(runner, clocks)
    _grow(source, 3)
    clocks.advance(59_999)
    assert runner.poll(clocks.mono) is None and not runner.running()
    assert runner.counters()["export_runs"] == 1
    clocks.advance(1)
    runner.poll(clocks.mono)
    outcome = _finish(runner, clocks)
    assert outcome.result is not None and outcome.result.mode == "incremental"
    assert runner.counters()["export_runs"] == 2 and runner.counters()["export_incremental"] == 1


def test_the_lag_is_the_time_since_the_capture_and_zero_when_nothing_is_unexported(
    source: Path, tmp_path: Path
) -> None:
    class Ticking(Clocks):
        """Every reading of the wall clock is 7 ms later: the capture precedes the publication."""

        def wall_ms(self) -> int:
            self.wall += 7
            return self.wall

    clocks = Ticking()
    runner = _runner(source, tmp_path, clocks)
    runner.poll(clocks.mono)
    outcome = _finish(runner, clocks)
    assert outcome.result is not None
    descriptor = outcome.result.descriptor
    assert parse_utc(descriptor.utc) > parse_utc(descriptor.captured_utc)
    head = descriptor.head
    clocks.advance(45_000)
    idle = runner.info(head)
    assert idle is not None and idle.lag_ms == 0  # the journal has not advanced
    behind = runner.info("f" * 64)
    assert behind is not None and behind.head == head and behind.utc == descriptor.utc
    # measured from the capture of the exported position, not from its publication
    assert behind.lag_ms == clocks.wall - parse_utc(descriptor.captured_utc)


def test_a_failure_is_counted_reported_and_retried_and_the_old_export_stays(
    source: Path, tmp_path: Path
) -> None:
    clocks, events = Clocks(), Events()
    runner = _runner(source, tmp_path, clocks, events, interval_ms=1_000)
    runner.poll(clocks.mono)
    first = _finish(runner, clocks)
    assert first.result is not None
    _grow(source, 5)
    runner._calls = sup.FaultCalls(
        write_hook=lambda n: (_ for _ in ()).throw(OSError(errno.ENOSPC, "full"))
    )
    for expected in (1, 2):
        clocks.advance(1_000)
        runner.poll(clocks.mono)
        failed = _finish(runner, clocks)
        assert not failed.ok and failed.error is not None and failed.error.rule == "io.no_space"
        assert runner.details(clocks.mono)["consecutive_failures"] == expected
    assert runner.last == first.result.descriptor  # the published export is unchanged
    assert verify_export(tmp_path / "export") == first.result.descriptor
    assert "io.no_space" in runner.details(clocks.mono)["last_error"]
    assert [k for k in events.kinds() if k == "export.failed"] == ["export.failed"] * 2
    # the disk recovers: the next export succeeds incrementally and the error is cleared
    runner._calls = sup.FaultCalls()
    clocks.advance(1_000)
    runner.poll(clocks.mono)
    ok = _finish(runner, clocks)
    assert ok.ok and ok.result is not None and ok.result.mode == "incremental"
    details = runner.details(clocks.mono)
    assert details["consecutive_failures"] == 0 and "last_error" not in details
    assert runner.counters()["export_failed"] == 2 and runner.counters()["export_ok"] == 2


def test_an_unexpected_exception_in_the_worker_is_a_failure_not_a_crash(
    source: Path, tmp_path: Path
) -> None:
    clocks, events = Clocks(), Events()

    def boom(name: str) -> None:
        raise RuntimeError("bug in a hook")

    runner = _runner(source, tmp_path, clocks, events, hook=boom)
    runner.poll(clocks.mono)
    outcome = _finish(runner, clocks)
    assert outcome.error is not None and outcome.error.rule == "export.unexpected"
    assert "RuntimeError" in outcome.error.detail


def test_an_integrity_problem_of_the_source_is_an_error_level_event(
    source: Path, tmp_path: Path
) -> None:
    clocks, events = Clocks(), Events()
    runner = _runner(source, tmp_path, clocks, events)
    runner.poll(clocks.mono)
    _finish(runner, clocks)
    lines = source.read_bytes().splitlines(keepends=True)
    sup.write_lines(source, lines[:10])
    clocks.advance(60_000)
    runner.poll(clocks.mono)
    outcome = _finish(runner, clocks)
    assert outcome.error is not None and outcome.error.rule == "export.regressed"
    assert events.items[-1][0] == "error" and events.items[-1][1] == "export.failed"


def test_finish_exports_the_final_position_after_waiting_for_a_running_export(
    source: Path, tmp_path: Path
) -> None:
    clocks = Clocks()
    gate = Gate()
    runner = _runner(source, tmp_path, clocks, calls=sup.FaultCalls(write_hook=gate))
    runner.poll(clocks.mono)
    assert gate.reached.wait(20)
    _grow(source, 6)
    threading.Timer(0.2, gate.release.set).start()
    outcome = runner.finish(timeout_ms=20_000)
    assert outcome.ok and outcome.result is not None
    assert outcome.result.descriptor.seq == 45  # the records committed after the first capture
    assert verify_export(tmp_path / "export") == outcome.result.descriptor
    assert not runner.running()


def test_finish_gives_up_and_cancels_when_the_disk_hangs(source: Path, tmp_path: Path) -> None:
    clocks = Clocks()
    release = threading.Event()

    def hang(number: int) -> None:
        release.wait(0.4)

    runner = _runner(
        source, tmp_path, clocks, chunk_bytes=1024, calls=sup.FaultCalls(write_hook=hang)
    )
    started = time.monotonic()
    outcome = runner.finish(timeout_ms=100)
    release.set()
    assert not outcome.ok and outcome.error is not None
    assert outcome.error.rule == "export.cancelled"
    assert time.monotonic() - started < 10
    assert read_descriptor(tmp_path / "export") is None  # nothing unfinished was published
    assert not runner.running()
    # the cancelled thread has ended: nothing can publish later
    assert not [t for t in threading.enumerate() if t.name == "cubeproof-export" and t.is_alive()]


def test_a_finished_job_is_collected_once(source: Path, tmp_path: Path) -> None:
    clocks = Clocks()
    runner = _runner(source, tmp_path, clocks)
    runner.poll(clocks.mono)
    job = runner._job
    assert job is not None
    _finish(runner, clocks)
    assert runner.counters()["export_ok"] == 1
    assert runner._collect(job) is None  # a second collection changes nothing
    assert runner.counters()["export_ok"] == 1


def test_close_cancels_a_running_export(source: Path, tmp_path: Path) -> None:
    clocks = Clocks()
    gate = Gate()
    runner = _runner(
        source, tmp_path, clocks, chunk_bytes=1024, calls=sup.FaultCalls(write_hook=gate)
    )
    runner.poll(clocks.mono)
    assert gate.reached.wait(20)
    threading.Timer(0.1, gate.release.set).start()
    runner.close()
    assert not runner.running()
    assert read_descriptor(tmp_path / "export") is None


def test_an_unreadable_descriptor_at_startup_is_reported_and_the_export_rebuilt(
    source: Path, tmp_path: Path
) -> None:
    clocks, events = Clocks(), Events()
    (tmp_path / "export").mkdir()
    (tmp_path / "export" / "export.json").write_bytes(b"{")
    runner = _runner(source, tmp_path, clocks, events)
    assert runner.last is None and events.kinds() == ["export.descriptor_unreadable"]
    runner.poll(clocks.mono)
    outcome = _finish(runner, clocks)
    assert outcome.result is not None and outcome.result.reason == "descriptor_invalid"
    assert verify_export(tmp_path / "export") == outcome.result.descriptor


def test_a_restart_picks_up_the_published_export(source: Path, tmp_path: Path) -> None:
    clocks = Clocks()
    first = _runner(source, tmp_path, clocks)
    first.poll(clocks.mono)
    outcome = _finish(first, clocks)
    assert outcome.result is not None
    restarted = _runner(source, tmp_path, clocks)
    assert restarted.last == outcome.result.descriptor
    info = restarted.info("f" * 64)
    assert info is not None and info.head == outcome.result.descriptor.head


def test_bad_settings_are_refused(source: Path, tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        ExportRunner(source, tmp_path / "e", interval_ms=0)
    with pytest.raises(ValueError):
        ExportRunner(source, tmp_path / "e", slow_ms=0)


def test_a_large_copy_does_not_stall_the_timers_of_the_process(tmp_path: Path) -> None:
    """An export of 20 MiB runs in its thread while this thread keeps a 2 ms timer: the longest gap
    of the timer stays small (the copy releases the GIL in I/O and is chunked)."""
    path = tmp_path / "journal.jsonl"
    sup.write_lines(path, sup.make_chain(20_000, pad=1000))
    clocks = Clocks()
    runner = _runner(path, tmp_path, clocks)
    runner.poll(clocks.mono)
    gaps: list[float] = []
    last = time.monotonic()
    deadline = last + 60
    while runner.running() and time.monotonic() < deadline:
        time.sleep(0.002)
        now = time.monotonic()
        gaps.append(now - last)
        last = now
    outcome = _finish(runner, clocks)
    assert outcome.ok and outcome.result is not None and outcome.result.bytes_copied > 20_000_000
    assert len(gaps) > 20
    assert max(gaps) < 0.5, max(gaps)
