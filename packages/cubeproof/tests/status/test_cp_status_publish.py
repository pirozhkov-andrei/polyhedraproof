"""Status files, the human log, the status command and the run monitor (specification §8.4,
§12.3)."""

from __future__ import annotations

import errno
import json
import os
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import cp_status_support as sup
import pytest

from cubeproof.base.errors import ConfigurationError, InputError
from cubeproof.commands.status import status_command
from cubeproof.contracts.enums import Lifecycle
from cubeproof.contracts.primitives import format_utc, parse_utc
from cubeproof.coordinator import status_monitor
from cubeproof.coordinator.events import (
    EventLog,
    format_event,
    progress_fields,
    stream_sink,
)
from cubeproof.coordinator.export import verify_export
from cubeproof.coordinator.status import ExportInfo
from cubeproof.coordinator.status_coverage import CoverageBudget, closed_coverage
from cubeproof.coordinator.status_format import render_status, status_bytes, validate_status
from cubeproof.coordinator.status_monitor import MonitorConfig, RunMonitor, StatusSources
from cubeproof.coordinator.status_publish import JSON_NAME, TEXT_NAME, StatusPublisher

sched = sup.sched
WALL0 = 1_790_000_000_000


class Clocks:
    """Manual monotonic and wall clocks (milliseconds)."""

    def __init__(self) -> None:
        self.mono = 1_000
        self.wall = WALL0

    def advance(self, ms: int) -> None:
        self.mono += ms
        self.wall += ms

    def now(self) -> int:
        return self.mono

    def wall_ms(self) -> int:
        return self.wall


def _journal(extra: int = 0) -> Any:
    j = sched.Journal({"a": sched.formula_bytes(8)})
    j.shard([("a", ())])
    j.split("a", (), (1, 2))
    j.unsat("a", (-1, -2))
    for index in range(extra):
        j.failed("a", (1, 2), "TOOL_FAILED", "launch" if index % 2 else "crash")
    return j


def _write_journal(path: Path, j: Any) -> None:
    sup.write_lines(path, [sched.j(v) + b"\n" for v in j.values])


@pytest.fixture
def results(tmp_path: Path) -> Path:
    path = tmp_path / "results"
    path.mkdir()
    return path


def _doc(**changes: Any) -> dict[str, Any]:
    state, tracker = sup.folded(_journal())
    return sup.build(state, tracker, coverage=closed_coverage(state), **changes)


# -- the publisher ---------------------------------------------------------------------------------


def test_both_files_are_written_atomically_and_hold_the_same_snapshot(results: Path) -> None:
    clocks = Clocks()
    publisher = StatusPublisher(results, monotonic_ms=clocks.now)
    doc = _doc()
    outcome = publisher.publish(doc)
    assert outcome.written and outcome.error is None
    raw = (results / JSON_NAME).read_bytes()
    assert raw == status_bytes(doc) and validate_status(json.loads(raw)) == doc
    assert (results / TEXT_NAME).read_text() == render_status(doc)
    assert sorted(os.listdir(results)) == [JSON_NAME, TEXT_NAME]


def test_at_most_one_snapshot_per_interval_unless_forced(results: Path) -> None:
    clocks = Clocks()
    publisher = StatusPublisher(results, interval_ms=10_000, monotonic_ms=clocks.now)
    assert publisher.due() and publisher.publish(_doc()).written
    clocks.advance(9_999)
    assert not publisher.due() and not publisher.publish(_doc()).written
    assert publisher.publish(_doc(), force=True).written
    clocks.advance(9_999)
    assert not publisher.due()  # the forced write restarted the interval
    clocks.advance(1)
    assert publisher.due() and publisher.publish(_doc()).written
    assert publisher.writes == 3


def test_an_invalid_document_is_a_programming_error_not_a_file(results: Path) -> None:
    publisher = StatusPublisher(results)
    broken = _doc()
    broken["lifecycle"] = "paused"
    with pytest.raises(Exception, match="lifecycle"):
        publisher.publish(broken)
    assert os.listdir(results) == []


@pytest.mark.parametrize("fault", ["open", "rename", "disk_full"])
def test_a_failed_write_keeps_the_previous_status_and_never_raises(
    results: Path, fault: str
) -> None:
    clocks = Clocks()
    publisher = StatusPublisher(results, monotonic_ms=clocks.now)
    first = _doc()
    publisher.publish(first)
    before = (results / JSON_NAME).read_bytes()
    if fault == "open":
        calls = sup.FaultCalls(fail_open_of="status.json", errno_code=errno.EACCES)
    elif fault == "rename":
        calls = sup.FaultCalls(fail_rename_to="status.json", errno_code=errno.EIO)
    else:
        calls = sup.FaultCalls(
            only="status", write_hook=lambda n: (_ for _ in ()).throw(OSError(errno.ENOSPC, "full"))
        )
    failing = StatusPublisher(results, monotonic_ms=clocks.now, calls=calls)
    outcome = failing.publish(_doc(lifecycle=Lifecycle.DRAINING))
    assert not outcome.written and outcome.error is not None
    assert failing.failures == 1 and failing.last_error is not None
    assert (results / JSON_NAME).read_bytes() == before
    assert [n for n in os.listdir(results) if n.endswith(".tmp")] == []
    # the next attempt, with a working disk, succeeds and clears the error
    clocks.advance(20_000)
    failing._calls = sup.FaultCalls()
    assert failing.publish(_doc(lifecycle=Lifecycle.DRAINING)).written
    assert failing.last_error is None


def test_a_crash_while_writing_leaves_the_previous_status_intact(results: Path) -> None:
    publisher = StatusPublisher(results)
    publisher.publish(_doc())
    before = (results / JSON_NAME).read_bytes()

    def die(number: int) -> None:
        raise sup.Crash

    crashing = StatusPublisher(results, calls=sup.FaultCalls(only="status", write_hook=die))
    with pytest.raises(sup.Crash):
        crashing.publish(_doc(lifecycle=Lifecycle.STOPPED), force=True)
    assert (results / JSON_NAME).read_bytes() == before
    assert validate_status(json.loads(before))


def test_slow_writes_are_counted_and_reported(results: Path) -> None:
    clocks = Clocks()

    def slow(number: int) -> None:
        clocks.advance(2_500)

    publisher = StatusPublisher(
        results,
        slow_ms=1_000,
        monotonic_ms=clocks.now,
        calls=sup.FaultCalls(only="status", write_hook=slow),
    )
    outcome = publisher.publish(_doc())
    assert outcome.written and outcome.ms >= 2_500
    details = publisher.details()
    assert details["slow_writes"] == 1 and details["last_ms"] >= 2_500 and details["writes"] == 1


# -- the human log ---------------------------------------------------------------------------------


def test_an_event_is_one_sorted_line_with_single_token_values() -> None:
    line = format_event(WALL0, "warn", "export.failed", {"b": 2, "a": "x y", "c": "ok"})
    assert line == f'{format_utc(WALL0)} WARN export.failed a="x y" b=2 c=ok'


def test_hostile_values_cannot_forge_or_split_log_lines() -> None:
    line = format_event(
        WALL0, "info", "k", {"detail": "a\nERROR forged\r\x00 x=1", "n": "é" + chr(0x2028)}
    )
    assert "\n" not in line and "\r" not in line and "\x00" not in line and chr(0x2028) not in line
    assert line.startswith(f"{format_utc(WALL0)} INFO k detail=")
    long = format_event(WALL0, "info", "k", {"d": "z" * 10_000})
    assert len(long) < 400
    with pytest.raises(ValueError):
        format_event(WALL0, "trace", "k", {})


def test_repeated_events_with_a_dedupe_key_are_quiet_and_counted() -> None:
    clocks = Clocks()
    lines: list[str] = []
    log = EventLog(lines.append, wall_ms=clocks.wall_ms, quiet_ms=60_000)
    assert log.event("warn", "export.failed", {"rule": "io"}, dedupe="export")
    for _ in range(5):
        clocks.advance(5_000)
        assert not log.event("warn", "export.failed", {"rule": "io"}, dedupe="export")
    assert log.event("warn", "other", {}, dedupe="other")  # another key is independent
    assert log.event("info", "plain")  # no key: always logged
    clocks.advance(40_000)
    assert log.event("warn", "export.failed", {"rule": "io"}, dedupe="export")
    assert len(lines) == 4 and "repeated=5" in lines[-1]
    clocks.advance(61_000)
    assert log.event("warn", "export.failed", {"rule": "io"}, dedupe="export")
    assert "repeated" not in lines[-1]


def test_min_level_filters_events() -> None:
    clocks = Clocks()
    for level, expected in (
        ("debug", ["DEBUG", "INFO", "WARN", "ERROR"]),
        ("info", ["INFO", "WARN", "ERROR"]),
        ("warn", ["WARN", "ERROR"]),
        ("error", ["ERROR"]),
    ):
        lines: list[str] = []
        log = EventLog(lines.append, wall_ms=clocks.wall_ms, min_level=level)
        results = [log.event(name.lower(), "k") for name in ("debug", "info", "warn", "error")]
        assert [line.split(" ")[1] for line in lines] == expected
        assert results == [name in expected for name in ("DEBUG", "INFO", "WARN", "ERROR")]
    with pytest.raises(ValueError):
        EventLog(lambda line: None, min_level="trace")
    quiet: list[str] = []
    assert not EventLog(quiet.append, min_level="warn").progress(_doc(), 0) and quiet == []


def test_the_stream_sink_writes_flushes_and_survives_a_closed_stream() -> None:
    import io

    class Counting(io.StringIO):
        flushes = 0

        def flush(self) -> None:
            self.flushes += 1
            super().flush()

    stream = Counting()
    sink = stream_sink(stream)
    sink("one")
    sink("two")
    assert stream.getvalue() == "one\ntwo\n" and stream.flushes == 2
    stream.close()
    sink("three")  # a closed log stream (a broken pipe) never stops a run


def test_a_failing_sink_is_counted_and_never_raised() -> None:
    def broken(line: str) -> None:
        raise OSError("no space")

    log = EventLog(broken, wall_ms=lambda: WALL0)
    assert log.event("warn", "k") and log.progress(_doc(), 0)
    assert log.sink_failures == 2


def test_progress_is_logged_at_most_once_a_minute_and_shows_the_state() -> None:
    clocks = Clocks()
    lines: list[str] = []
    log = EventLog(lines.append, wall_ms=clocks.wall_ms, progress_interval_ms=60_000)
    doc = _doc(export=ExportInfo("e" * 64, 3, "2026-10-01T00:00:00.000Z", 12_000))
    stamps = [0, 10_000, 59_999, 60_000, 61_000, 119_999, 120_000]
    logged = [log.progress(doc, clocks.mono + t) for t in stamps]
    assert logged == [True, False, False, True, False, False, True]
    assert len(lines) == 3 and all(" progress " in line for line in lines)
    fields = progress_fields(doc)
    assert fields["seq"] == doc["seq"] and fields["export_lag"] == "12.0 s"
    assert fields["eta"] == "n/a" and fields["closed_roots"] == "0/1"
    assert "needs_split:" in fields["nodes"] or "closed:" in fields["nodes"]
    assert 'export_lag="12.0 s"' in lines[0]


# -- the status command ----------------------------------------------------------------------------


def test_the_command_reads_validates_and_renders_the_published_status(results: Path) -> None:
    clocks = Clocks()
    doc = _doc()
    StatusPublisher(results, monotonic_ms=clocks.now).publish(doc)
    report = status_command(results, now_ms=WALL0 + 5_000)
    assert report.document == doc and report.text == render_status(doc)
    assert not report.stale and report.age_ms >= 0


def test_a_status_that_stopped_updating_is_reported_stale_unless_the_worker_stopped(
    results: Path,
) -> None:
    clocks = Clocks()
    publisher = StatusPublisher(results, monotonic_ms=clocks.now)
    doc = _doc()
    publisher.publish(doc)
    written = parse_utc(doc["utc"])
    fresh = status_command(results, now_ms=written + 29_000)
    edge = status_command(results, now_ms=written + 30_000)
    stale = status_command(results, now_ms=written + 31_000)
    assert not fresh.stale and not edge.stale and stale.stale and stale.age_ms == 31_000
    assert status_command(results, now_ms=written - 5_000).age_ms == 0  # a clock behind
    assert stale.text.startswith("WARNING: the last status is 31.0 s old")
    publisher.publish(_doc(lifecycle=Lifecycle.STOPPED), force=True)
    assert not status_command(results, now_ms=written + 3_600_000).stale


def test_the_command_refuses_missing_or_invalid_status_files(results: Path, tmp_path: Path) -> None:
    with pytest.raises(InputError) as caught:
        status_command(results)
    assert caught.value.rule == "status.absent"
    (results / JSON_NAME).write_bytes(b"{not json\n")
    with pytest.raises(InputError) as bad:
        status_command(results)
    assert bad.value.rule == "status.invalid"
    doc = _doc()
    (results / JSON_NAME).write_bytes(status_bytes(doc)[:-1])  # not canonical: no LF
    with pytest.raises(InputError):
        status_command(results)
    (results / JSON_NAME).write_bytes(
        json.dumps({**doc, "newer_field": 1}, sort_keys=True, separators=(",", ":")).encode()
        + b"\n"
    )
    with pytest.raises(InputError) as unknown:
        status_command(results)
    assert "schema" in unknown.value.detail
    (results / JSON_NAME).unlink()
    (results / JSON_NAME).mkdir()
    with pytest.raises(InputError) as directory:
        status_command(results)
    assert directory.value.rule == "status.unreadable"


# -- the run monitor -------------------------------------------------------------------------------


def _wait(condition: Callable[[], bool], what: str, seconds: float = 20.0) -> None:
    deadline = time.monotonic() + seconds
    while not condition():
        assert time.monotonic() < deadline, what
        time.sleep(0.005)


class World:
    """A monitor over a journal file that grows, with manual clocks and a collected log."""

    def __init__(self, tmp_path: Path, *, export: bool = True, **config: Any) -> None:
        self.clocks = Clocks()
        tmp_path.mkdir(parents=True, exist_ok=True)
        self.results = tmp_path / "results"
        self.results.mkdir()
        self.journal_path = tmp_path / "journal.jsonl"
        self.export_dir = tmp_path / "export"
        self.lines: list[str] = []
        self.j = _journal()
        _write_journal(self.journal_path, self.j)
        self.state, tracker_unused = sup.folded(self.j)
        del tracker_unused
        self.monitor = RunMonitor(
            results=self.results,
            journal=self.journal_path,
            export=self.export_dir if export else None,
            log=EventLog(self.lines.append, wall_ms=self.clocks.wall_ms),
            config=MonitorConfig(**config),
            monotonic_ms=self.clocks.now,
            wall_ms=self.clocks.wall_ms,
        )
        for record in self.j.records:
            self.monitor.observe(record)
        self.calls = 0

    def grow(self, count: int = 1) -> None:
        """More committed records: into the journal file, the state and the monitor."""
        for index in range(count):
            self.j.failed("a", (1, 2), "TOOL_FAILED", "crash" if index % 2 else "launch")
        _write_journal(self.journal_path, self.j)
        for record in self.j.records[self.state.seq + 1 :]:
            self.state.apply(record)
            self.monitor.observe(record)

    def sources(self, lifecycle: Lifecycle = Lifecycle.RUNNING) -> StatusSources:
        self.calls += 1
        return StatusSources(self.state, lifecycle, sup.resources())

    def tick(self, **kwargs: Any) -> Any:
        return self.monitor.tick(self.sources, **kwargs)

    def status(self) -> dict[str, Any]:
        return validate_status(json.loads((self.results / JSON_NAME).read_bytes()))

    def settle(self) -> None:
        runner = self.monitor.runner
        assert runner is not None
        _wait(lambda: not runner.running(), "the export did not finish")
        runner.poll(self.clocks.mono)


def test_tick_publishes_when_due_and_reads_the_sources_only_then(tmp_path: Path) -> None:
    world = World(tmp_path, export=False)
    assert world.tick() is not None and world.calls == 1
    first = world.status()
    world.clocks.advance(9_999)
    assert world.tick() is None and world.calls == 1  # nothing is even looked at
    world.clocks.advance(1)
    assert world.tick() is not None and world.calls == 2
    assert world.tick(force=True) is not None and world.calls == 3  # a lifecycle change
    assert world.status()["seq"] == first["seq"]


def test_the_published_status_reflects_the_run(tmp_path: Path) -> None:
    world = World(tmp_path, export=False)
    world.tick()
    doc = world.status()
    assert doc["lifecycle"] == "running" and doc["seq"] == world.state.seq
    assert doc["head"] == world.state.head and doc["worker"] == "w1"
    assert doc["counters"]["status_writes"] == 0  # the first write is not counted before it exists
    assert doc["info"]["status_write"]["interval_ms"] == 10_000
    world.clocks.advance(10_000)
    world.tick()
    assert world.status()["counters"]["status_writes"] == 1
    assert (world.results / TEXT_NAME).read_text() == render_status(world.status())
    report = status_command(world.results, now_ms=world.clocks.wall)
    assert report.document == world.status() and not report.stale


def test_coverage_is_recomputed_only_when_the_state_changed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    world = World(tmp_path, export=False)
    calls: list[int] = []

    def counting(state: Any, **kwargs: Any) -> Any:
        calls.append(state.seq)
        return closed_coverage(state, **kwargs)

    monkeypatch.setattr(status_monitor, "closed_coverage", counting)
    for _ in range(3):
        world.tick(force=True)
    assert calls == [world.state.seq]
    world.grow()
    world.tick(force=True)
    world.tick(force=True)
    assert calls == [world.state.seq - 1, world.state.seq]


def test_when_the_coverage_budget_runs_out_the_previous_value_is_kept_and_marked_stale(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    world = World(tmp_path, export=False)
    world.tick(force=True)
    good = world.status()["coverage"]
    seq_before = world.state.seq

    def exhausted(state: Any, **kwargs: Any) -> Any:
        raise CoverageBudget(123)

    monkeypatch.setattr(status_monitor, "closed_coverage", exhausted)
    world.grow()
    world.tick(force=True)
    doc = world.status()
    assert doc["coverage"] == good
    assert doc["info"]["coverage"]["stale"] is True
    assert doc["info"]["coverage"]["computed_seq"] == seq_before
    assert any("status.coverage_budget" in line for line in world.lines)
    # with no previous value at all the coverage is absent and says so
    fresh = World(tmp_path / "second", export=False)
    fresh.tick(force=True)
    assert fresh.status()["info"]["coverage"] == {"available": False}


def test_exports_run_in_the_background_and_the_status_shows_the_last_one_and_its_lag(
    tmp_path: Path,
) -> None:
    world = World(tmp_path)
    world.tick()  # starts the first export, publishes a status without one
    assert world.status()["export"] is None
    world.settle()
    world.clocks.advance(10_000)
    world.tick()
    exported = world.status()["export"]
    assert exported is not None
    assert exported["head"] == world.state.head and exported["seq"] == world.state.seq
    assert exported["lag_ms"] == 0  # nothing committed since the export
    assert world.status()["info"]["export"]["state"] == "idle"
    assert world.status()["counters"]["export_ok"] == 1
    # records are committed; the export is stale by the time since its capture
    world.grow(3)
    world.clocks.advance(25_000)
    world.tick(force=True)
    stale = world.status()["export"]
    assert stale is not None and stale["head"] != world.state.head
    assert stale["seq"] == world.state.seq - 3
    assert stale["lag_ms"] == 35_000
    # the next interval exports the new records incrementally
    world.clocks.advance(40_000)
    world.tick()
    world.settle()
    world.clocks.advance(10_000)
    world.tick()
    caught_up = world.status()["export"]
    assert caught_up is not None and caught_up["head"] == world.state.head
    assert world.status()["counters"]["export_incremental"] == 1
    assert verify_export(world.export_dir).head == world.state.head


def test_exports_that_found_nothing_new_are_counted_but_not_logged(tmp_path: Path) -> None:
    world = World(tmp_path)
    world.tick()
    world.settle()
    for _ in range(3):  # three intervals without a new record
        world.clocks.advance(60_001)
        world.tick()
        world.settle()
    world.tick(force=True)
    counters = world.status()["counters"]
    assert counters["export_full"] == 1 and counters["export_unchanged"] == 3
    assert len([line for line in world.lines if " export.ok " in line]) == 1  # the first, full one


def test_the_clean_stop_exports_the_final_position_and_publishes_stopped(tmp_path: Path) -> None:
    world = World(tmp_path)
    world.tick()
    world.settle()
    world.grow(5)
    outcome = world.monitor.finish(lambda: world.sources(Lifecycle.STOPPED))
    assert outcome.written
    doc = world.status()
    assert doc["lifecycle"] == "stopped" and doc["export"]["head"] == world.state.head
    assert doc["export"]["lag_ms"] == 0
    assert verify_export(world.export_dir).seq == world.state.seq


def test_a_failing_export_is_visible_logged_once_a_minute_and_never_stops_the_run(
    tmp_path: Path,
) -> None:
    world = World(tmp_path, export_interval_ms=1_000)
    (tmp_path / "export").write_bytes(b"a file where the export directory should be")
    for _ in range(12):
        world.clocks.advance(2_000)
        world.tick(force=True)
        world.settle()
    doc = world.status()
    assert doc["export"] is None
    assert doc["counters"]["export_failed"] >= 10 and doc["counters"].get("export_ok", 0) == 0
    assert "export.layout" in doc["info"]["export"]["last_error"]
    assert doc["info"]["export"]["consecutive_failures"] >= 10
    failures = [line for line in world.lines if " export.failed " in line]
    assert 1 <= len(failures) <= 2  # 24 s of failures, one line per quiet minute
    assert doc["lifecycle"] == "running"


def test_further_facts_of_the_coordinator_reach_info_under_their_own_names(
    tmp_path: Path,
) -> None:
    world = World(tmp_path, export=False)
    budgets = {"requested": {"cpu": 8000}, "effective": {"cpu": 6000}, "proof_queue_bytes": 5}
    world.monitor.tick(
        lambda: StatusSources(
            world.state, Lifecycle.RUNNING, sup.resources(), info={"budgets": budgets}
        )
    )
    assert world.status()["info"]["budgets"] == budgets
    with pytest.raises(ConfigurationError):
        world.monitor.tick(
            lambda: StatusSources(
                world.state, Lifecycle.RUNNING, sup.resources(), info={"coverage": {}}
            ),
            force=True,
        )


def test_a_failing_status_write_is_logged_and_does_not_raise(tmp_path: Path) -> None:
    world = World(tmp_path, export=False)
    world.tick()
    before = (world.results / JSON_NAME).read_bytes()
    world.monitor.publisher._calls = sup.FaultCalls(
        fail_open_of="status.txt", errno_code=errno.EROFS
    )
    world.clocks.advance(10_000)
    outcome = world.tick()
    assert outcome is not None and outcome.error is not None
    assert (world.results / JSON_NAME).read_bytes() == before
    assert any("status.write_failed" in line for line in world.lines)
    assert world.monitor.publisher.failures == 1


def test_progress_lines_come_once_a_minute_through_the_monitor(tmp_path: Path) -> None:
    world = World(tmp_path, export=False)
    for _ in range(13):
        world.tick(force=True)
        world.clocks.advance(10_000)
    progress = [line for line in world.lines if " progress " in line]
    assert len(progress) == 3  # at 0 s, 60 s and 120 s


def test_the_monitor_refuses_records_out_of_order(tmp_path: Path) -> None:
    world = World(tmp_path, export=False)
    with pytest.raises(ConfigurationError):
        world.monitor.observe(world.j.records[3])
