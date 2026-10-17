"""The relay process alone (specification §6.4, §8.3): hashing transport between two FIFOs.

The relay is ``cubeproof/tools/relay.py`` run as a child process (``python -I -S``) exactly as
the stream leaf launches it, between two FIFOs whose other ends are test threads. Oracles are
plain: the bytes the "checker" thread received, ``hashlib`` of the bytes the "solver" thread
wrote, and the relay's own one-line report on stdout.
"""

from __future__ import annotations

import dataclasses
import json
import os
import resource
import subprocess
import sys
import time
from collections.abc import Iterator
from pathlib import Path

import pytest
from cp_stream_support import RELAY_SCRIPT, RelayHarness, sha

from cubeproof.tools import relay as rl

pytestmark = pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux FIFOs")

MIB = 1 << 20


def report_of(harness: RelayHarness) -> rl.RelayReport:
    report = rl.parse_report(harness.stdout)
    assert report is not None, (harness.stdout, harness.stderr)
    return report


def payload(size: int) -> bytes:
    """Deterministic, non-repeating-looking proof-like bytes."""
    line = b"".join(f"{i} {i + 1} 0 {i} 0\n".encode() for i in range(1, 2000))
    return (line * (size // len(line) + 1))[:size]


@pytest.fixture
def harness(tmp_path: Path) -> Iterator[RelayHarness]:
    value = RelayHarness(tmp_path / "relay")
    yield value
    value.kill()


# -- complete transfers ---------------------------------------------------------------------


@pytest.mark.parametrize("size", [0, 1, 17, (1 << 16) + 3, 5 * MIB + 11])
def test_a_complete_transfer_is_hashed_counted_and_written(
    harness: RelayHarness, size: int
) -> None:
    data = payload(size)
    harness.start(64 * MIB)
    harness.writer(data)
    harness.reader()
    assert harness.finish() == rl.EXIT_COMPLETE
    report = report_of(harness)
    assert bytes(harness.received) == data
    assert (report.bytes, report.sha256) == (size, sha(data))
    assert (report.solver_eof, report.all_written, report.error) == (True, True, None)
    assert report.complete
    assert report.record_value() == {
        "bytes": size,
        "sha256": sha(data),
        "solver_eof": True,
        "all_written": True,
        "error": None,
    }


@pytest.mark.parametrize("buffer", ["4096", str(1 << 20)])
def test_partial_writes_to_a_slow_reader_lose_no_byte(harness: RelayHarness, buffer: str) -> None:
    """The checker reads in small, slow bites: the pipe fills, writes are partial (a 64 KiB
    write into a pipe with less room writes what fits) or refused (EAGAIN), and the relay
    must resume exactly where it stopped. A buffer of 4 KiB gives many short rounds."""
    data = payload(3 * MIB + 5)
    harness.start(64 * MIB, buffer)
    harness.writer(data, chunk=(1 << 16) + 7)
    harness.reader(chunk=1000, pause=0.0)
    assert harness.finish() == rl.EXIT_COMPLETE
    assert bytes(harness.received) == data
    report = report_of(harness)
    assert (report.bytes, report.sha256, report.complete) == (len(data), sha(data), True)


@pytest.mark.parametrize(
    ("writer_delay", "reader_delay"), [(0.0, 0.0), (0.4, 0.0), (0.0, 0.4), (0.3, 0.6), (0.6, 0.3)]
)
def test_no_start_order_deadlock(
    harness: RelayHarness, writer_delay: float, reader_delay: float
) -> None:
    """Either side may open its FIFO first, late or never before the other (specification §6.4)."""
    data = payload(200_000)
    harness.start(64 * MIB)
    harness.writer(data, delay=writer_delay)
    harness.reader(delay=reader_delay)
    assert harness.finish(timeout=30) == rl.EXIT_COMPLETE
    assert bytes(harness.received) == data
    assert report_of(harness).complete


def test_exactly_the_cap_is_still_a_complete_transfer(harness: RelayHarness) -> None:
    data = payload(100_000)
    harness.start(len(data))
    harness.writer(data)
    harness.reader()
    assert harness.finish() == rl.EXIT_COMPLETE
    assert report_of(harness).complete


# -- cap and transport errors ---------------------------------------------------------------


def test_one_byte_over_the_cap_stops_the_transfer(harness: RelayHarness) -> None:
    cap = 300_000
    data = payload(4 * MIB)
    harness.start(cap)
    harness.writer(data)
    harness.reader()
    assert harness.finish() == rl.EXIT_CAP
    report = report_of(harness)
    assert report.error == rl.ERROR_CAP
    assert not report.complete
    assert not report.solver_eof and not report.all_written
    # the counters cover only bytes accepted within the cap, and they are exactly those bytes
    assert report.bytes <= cap
    assert report.sha256 == sha(data[: report.bytes])
    assert bytes(harness.received) == data[: len(harness.received)]
    assert len(harness.received) <= report.bytes
    # the solver side was cut off (it would die of SIGPIPE)
    assert isinstance(harness.writer_error, BrokenPipeError)


def test_a_checker_that_stops_reading_gives_epipe_and_stops_the_solver(
    harness: RelayHarness,
) -> None:
    data = payload(6 * MIB)
    harness.start(64 * MIB)
    harness.writer(data)
    harness.reader(limit=1000)
    assert harness.finish() == rl.EXIT_TRANSPORT
    report = report_of(harness)
    assert report.error is not None and "EPIPE" in report.error
    assert not report.all_written and not report.complete
    assert report.sha256 == sha(data[: report.bytes])
    assert isinstance(harness.writer_error, BrokenPipeError)


def _silent_solver(harness: RelayHarness, seconds: float, then: bytes) -> None:
    def solver() -> None:
        fd = os.open(harness.source, os.O_WRONLY)
        try:
            time.sleep(seconds)  # silent (searching), then a few more proof bytes
            if then:
                os.write(fd, then)
        finally:
            os.close(fd)

    harness._spawn(solver)


def test_a_checker_closing_early_fails_when_a_byte_cannot_be_written(
    harness: RelayHarness,
) -> None:
    """The checker closed its end while the solver was silent; the next proof byte from the
    solver cannot be written: EPIPE, at that byte (not at the solver's EOF)."""
    harness.start(64 * MIB)
    harness.reader(limit=0)
    _silent_solver(harness, 0.5, b"5 1 0 1 2 0\n")
    assert harness.finish() == rl.EXIT_TRANSPORT
    report = report_of(harness)
    assert "EPIPE" in str(report.error)
    assert (report.bytes, report.written, report.all_written) == (12, 0, False)


def test_a_checker_that_stopped_after_the_last_byte_does_not_break_the_transfer(
    harness: RelayHarness,
) -> None:
    """cake_lpr stops reading at the empty clause, before the solver's EOF: if nothing more
    comes, every byte was written and the transfer is complete (specification §6.4)."""
    data = payload(5000)
    harness.start(64 * MIB)
    harness.reader(limit=len(data))

    def solver() -> None:
        fd = os.open(harness.source, os.O_WRONLY)
        try:
            os.write(fd, data)
            time.sleep(0.8)  # the checker reads everything and closes meanwhile
        finally:
            os.close(fd)

    harness._spawn(solver)
    assert harness.finish() == rl.EXIT_COMPLETE
    report = report_of(harness)
    assert report.complete and report.written == len(data)
    assert bytes(harness.received) == data


def test_no_eof_before_a_writer_ever_opened(harness: RelayHarness) -> None:
    """A FIFO without a writer reads as EOF; the relay must not take that for solver EOF."""
    harness.start(64 * MIB)
    harness.reader()
    time.sleep(0.5)
    assert harness.process is not None and harness.process.poll() is None
    harness.terminate()
    assert harness.finish() == rl.EXIT_TERMINATED
    report = report_of(harness)
    assert report.error == rl.ERROR_TERMINATED
    assert (report.bytes, report.solver_eof, report.all_written) == (0, False, False)


def test_termination_mid_transfer_reports_the_partial_counts(harness: RelayHarness) -> None:
    data = payload(2 * MIB)
    harness.start(64 * MIB)
    harness.writer(data, chunk=4096, pause=0.002)
    harness.reader()
    time.sleep(0.3)
    harness.terminate()
    assert harness.finish() == rl.EXIT_TERMINATED
    report = report_of(harness)
    assert report.error == rl.ERROR_TERMINATED and not report.complete
    assert 0 < report.bytes < len(data)
    assert report.sha256 == sha(data[: report.bytes])


def test_termination_after_completion_keeps_the_complete_report(harness: RelayHarness) -> None:
    """A teardown signal that arrives after the transfer completed does not spoil it."""
    data = payload(1000)
    harness.start(64 * MIB, str(1 << 20), "--linger-ms", "1500")
    harness.writer(data)
    harness.reader()
    time.sleep(0.8)
    harness.terminate()
    assert harness.finish() == rl.EXIT_COMPLETE
    assert report_of(harness).complete


@pytest.mark.parametrize("which", ["source", "sink"])
def test_endpoints_must_be_fifos(tmp_path: Path, which: str) -> None:
    root = tmp_path / "plain"
    root.mkdir()
    fifo = root / "fifo"
    os.mkfifo(fifo, 0o600)
    regular = root / "regular"
    regular.write_bytes(b"")
    link = root / "link"
    link.symlink_to(fifo)
    for bad in (regular, link, root / "missing"):
        args = [str(bad), str(fifo)] if which == "source" else [str(fifo), str(bad)]
        done = subprocess.run(
            [sys.executable, "-I", "-S", str(RELAY_SCRIPT), *args, "1000"],
            capture_output=True,
            timeout=30,
            check=False,
        )
        assert done.returncode == rl.EXIT_USAGE, (bad, done)
        report = rl.parse_report(done.stdout)
        assert report is not None and report.error is not None and not report.complete


@pytest.mark.parametrize(
    "argv", [[], ["a"], ["/a", "/b"], ["/a", "/b", "0"], ["/a", "/b", "x"], ["a", "/b", "5"]]
)
def test_bad_arguments_are_a_usage_error(argv: list[str]) -> None:
    done = subprocess.run(
        [sys.executable, "-I", "-S", str(RELAY_SCRIPT), *argv],
        capture_output=True,
        timeout=30,
        check=False,
    )
    assert done.returncode == rl.EXIT_USAGE


# -- bounded resources ------------------------------------------------------------------------


def test_the_relay_runs_in_bounded_memory(harness: RelayHarness) -> None:
    """64 MiB through a relay whose address space is capped at the specification §8.3 relay cap."""

    def cap_memory() -> None:
        limit = 128 * MIB
        resource.setrlimit(resource.RLIMIT_AS, (limit, limit))

    data = payload(64 * MIB)
    harness.process = subprocess.Popen(
        [
            sys.executable,
            "-I",
            "-S",
            str(RELAY_SCRIPT),
            str(harness.source),
            str(harness.sink),
            str(128 * MIB),
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={"LC_ALL": "C"},
        start_new_session=True,
        preexec_fn=cap_memory,  # noqa: PLW1509 - a test child, no threads in it yet
    )
    harness.writer(data, chunk=1 << 20)
    harness.reader(chunk=1 << 20)
    assert harness.finish(timeout=120) == rl.EXIT_COMPLETE
    assert report_of(harness).sha256 == sha(data)
    assert bytes(harness.received) == data


def test_a_stalled_checker_stalls_the_solver(harness: RelayHarness) -> None:
    """The relay holds at most its buffer: while the checker reads nothing, the solver can
    write only the buffer plus the two pipes' capacity (backpressure, not memory growth)."""
    data = payload(8 * MIB)
    buffer = 64 * 1024
    harness.start(64 * MIB, str(buffer))
    harness.writer(data, chunk=4096)
    harness.reader(delay=1.5)
    time.sleep(1.0)
    pipes = 2 * (1 << 20)  # generous bound for two FIFO pipe buffers (default 64 KiB each)
    assert harness.written <= buffer + pipes + 4096
    assert harness.finish() == rl.EXIT_COMPLETE
    assert bytes(harness.received) == data


# -- the report -----------------------------------------------------------------------------


def test_the_report_round_trips_and_malformed_reports_are_refused() -> None:
    report = rl.RelayReport(
        bytes=3, sha256=sha(b"abc"), solver_eof=True, all_written=True, error=None, written=3
    )
    line = report.to_line()
    assert line.endswith(b"\n") and line.count(b"\n") == 1
    assert rl.parse_report(line) == report
    assert rl.parse_report(b"noise\n" + line) is None  # exactly one line
    value = json.loads(line)
    for broken in (
        {**value, "format": "other"},
        {**value, "bytes": -1},
        {**value, "bytes": True},
        {**value, "sha256": "x"},
        {**value, "solver_eof": 1},
        {**value, "error": 5},
        {**value, "written": 4},
        {k: v for k, v in value.items() if k != "written"},
        {**value, "extra": 1},
    ):
        assert rl.parse_report(json.dumps(broken).encode() + b"\n") is None, broken
    assert rl.parse_report(None) is None
    assert rl.parse_report(b"") is None
    assert rl.parse_report(line[:-1]) is None  # no newline: possibly cut
    # an incomplete report is never complete, whatever its counters say
    assert not dataclasses.replace(report, error="x").complete
    assert not dataclasses.replace(report, solver_eof=False).complete
    assert not dataclasses.replace(report, all_written=False).complete
    assert not dataclasses.replace(report, written=2).complete


def test_the_relay_script_imports_nothing_but_the_standard_library() -> None:
    """It runs as ``python -I -S`` (no site-packages): the package is not importable there."""
    text = RELAY_SCRIPT.read_text(encoding="utf-8")
    assert "import cubeproof" not in text and "from cubeproof" not in text
    done = subprocess.run(
        [sys.executable, "-I", "-S", "-c", f"import runpy; runpy.run_path({str(RELAY_SCRIPT)!r})"],
        capture_output=True,
        timeout=30,
        check=False,
    )
    assert done.returncode == 0, done.stderr
