"""Periodic prefix exports without blocking the coordinator's loop (specification §7.5, §8.1).

:class:`ExportRunner` owns the schedule of :func:`~cubeproof.coordinator.export.export_once`: one
export at a time, at most one started per ``interval_ms`` (default 60 s), plus a final one at a
clean stop (:meth:`ExportRunner.finish`). The copy runs in a background thread, so the loop only
calls the nonblocking :meth:`poll` and its timers never wait for a slow disk. Slow I/O is visible
instead: the thread publishes how many bytes of how many it has handled, :meth:`details` reports
the running export with its elapsed time, and an export that runs longer than ``slow_ms`` raises
one warning event. A failure never stops the run (the export is a backup, the journal is the
evidence): it is counted, kept as the last error with its time and retried at the next interval;
the previously published export stays valid.

The lag of the last export is the time since its source position was captured (0 when the journal
has not advanced since): every record committed after that is not in the backup. It is published
as such; a periodic export is a backup with that possible lag, never synchronous replication."""

from __future__ import annotations

import os
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from cubeproof.base.errors import ContractError, CubeproofError, ToolError
from cubeproof.base.settings import DEFAULT_LIMITS, ReaderLimits
from cubeproof.contracts.primitives import parse_utc
from cubeproof.coordinator.export import (
    ExportCancelled,
    ExportDescriptor,
    ExportResult,
    export_once,
    read_descriptor,
)
from cubeproof.coordinator.status import ExportInfo
from cubeproof.evidence.journal import CHUNK_BYTES, OS_CALLS, SysCalls
from cubeproof.tools.atomic import OS_FILE_CALLS, FileCalls

__all__ = ["ExportOutcome", "ExportRunner"]

#: ``on_event(level, kind, fields)``: level is ``info``, ``warn`` or ``error``.
EventSink = Callable[[str, str, dict[str, Any]], None]


def _monotonic_ms() -> int:
    return int(time.monotonic() * 1000)


def _wall_ms() -> int:
    return int(time.time() * 1000)


@dataclass(frozen=True)
class ExportOutcome:
    """The end of one export attempt: its result or the error that stopped it."""

    result: ExportResult | None
    error: CubeproofError | None
    started_ms: int
    ended_ms: int

    @property
    def ok(self) -> bool:
        return self.result is not None


class _Job:
    """One running export: its thread, progress and (when done) outcome."""

    def __init__(self, started_ms: int) -> None:
        self.started_ms = started_ms
        self.done_bytes = 0
        self.total_bytes = 0
        self.cancel = threading.Event()
        self.slow_reported = False
        self.thread: threading.Thread | None = None
        self.result: ExportResult | None = None
        self.error: CubeproofError | None = None
        self.ended_ms = started_ms


class ExportRunner:
    """Schedule and supervise prefix exports of one journal (module doc)."""

    def __init__(
        self,
        source: str | os.PathLike[str],
        directory: str | os.PathLike[str],
        *,
        interval_ms: int = 60_000,
        slow_ms: int = 30_000,
        calls: FileCalls = OS_FILE_CALLS,
        journal_calls: SysCalls = OS_CALLS,
        limits: ReaderLimits = DEFAULT_LIMITS,
        chunk_bytes: int = CHUNK_BYTES,
        monotonic_ms: Callable[[], int] = _monotonic_ms,
        wall_ms: Callable[[], int] = _wall_ms,
        on_event: EventSink | None = None,
        hook: Callable[[str], None] | None = None,
    ) -> None:
        if interval_ms < 1 or slow_ms < 1:
            raise ValueError("interval_ms and slow_ms must be positive")
        self.source = os.fspath(source)
        self.directory = os.fspath(directory)
        self.interval_ms = interval_ms
        self.slow_ms = slow_ms
        self._calls = calls
        self._journal_calls = journal_calls
        self._limits = limits
        self._chunk = chunk_bytes
        self._now = monotonic_ms
        self._wall = wall_ms
        self._emit = on_event
        self._hook = hook
        self._job: _Job | None = None
        self._last_start: int | None = None
        self._counts: dict[str, int] = {
            "export_runs": 0,
            "export_ok": 0,
            "export_failed": 0,
            "export_full": 0,
            "export_incremental": 0,
            "export_unchanged": 0,
            "export_bytes": 0,
        }
        self._failures = 0
        self._last_error: tuple[str, int] | None = None
        self.last: ExportDescriptor | None = None
        try:
            self.last = read_descriptor(self.directory, calls=calls)
        except ContractError:
            self._event("warn", "export.descriptor_unreadable", {"directory": self.directory})

    # -- scheduling ---------------------------------------------------------------------------

    def poll(self, now_ms: int | None = None) -> ExportOutcome | None:
        """Nonblocking: collect a finished export, or start one that is due. Returns the outcome of
        an export that finished since the last call (otherwise None)."""
        now = self._now() if now_ms is None else now_ms
        job = self._job
        if job is not None:
            thread = job.thread
            assert thread is not None
            if thread.is_alive():
                if not job.slow_reported and now - job.started_ms >= self.slow_ms:
                    job.slow_reported = True
                    self._event("warn", "export.slow", self._progress_fields(job, now))
                return None
            return self._collect(job)
        if self._last_start is None or now - self._last_start >= self.interval_ms:
            self._start(now)
        return None

    def running(self) -> bool:
        job = self._job
        return job is not None and job.thread is not None and job.thread.is_alive()

    def finish(self, *, timeout_ms: int = 30_000) -> ExportOutcome:
        """The clean-stop export: wait for a running one, then export the final position.

        Blocks at most about ``timeout_ms``; an export that does not finish in time is cancelled and
        reported as failed (its unfinished copy is never published). Never raises.
        """
        deadline = self._now() + timeout_ms
        job = self._job
        if job is not None:
            self._join(job, deadline)
            self._collect(job)
        job = self._start(self._now())
        self._join(job, deadline)
        outcome = self._collect(job)
        assert outcome is not None
        return outcome

    def close(self) -> None:
        """Cancel a running export and wait briefly for its thread (no final export)."""
        job = self._job
        if job is not None and job.thread is not None:
            job.cancel.set()
            job.thread.join(5.0)

    # -- the worker thread ----------------------------------------------------------------------

    def _start(self, now: int) -> _Job:
        job = _Job(now)
        self._job = job
        self._last_start = now
        self._counts["export_runs"] += 1

        def progress(done: int, total: int) -> None:
            job.done_bytes, job.total_bytes = done, total

        def work() -> None:
            try:
                job.result = export_once(
                    self.source,
                    self.directory,
                    calls=self._calls,
                    journal_calls=self._journal_calls,
                    limits=self._limits,
                    chunk_bytes=self._chunk,
                    wall_ms=self._wall,
                    progress=progress,
                    cancel=job.cancel.is_set,
                    hook=self._hook,
                )
            except CubeproofError as error:
                job.error = error
            except Exception as error:
                job.error = ToolError("export.unexpected", f"{type(error).__name__}: {error}")
            finally:
                job.ended_ms = self._now()

        thread = threading.Thread(target=work, name="cubeproof-export", daemon=True)
        job.thread = thread
        thread.start()
        return job

    def _join(self, job: _Job, deadline: int) -> None:
        thread = job.thread
        assert thread is not None
        thread.join(max(0.0, (deadline - self._now()) / 1000))
        if thread.is_alive():
            job.cancel.set()
            thread.join(5.0)

    def _collect(self, job: _Job) -> ExportOutcome | None:
        if self._job is not job:
            return None
        self._job = None
        result, error = job.result, job.error
        if result is None and error is None:  # the thread ended without a result (cancelled hard)
            error = ExportCancelled("export.cancelled", "the export did not finish")
        outcome = ExportOutcome(result, error, job.started_ms, job.ended_ms)
        elapsed = max(0, job.ended_ms - job.started_ms)
        if result is not None:
            self.last = result.descriptor
            self._failures = 0
            self._last_error = None
            self._counts["export_ok"] += 1
            self._counts[f"export_{result.mode}"] += 1
            self._counts["export_bytes"] += result.bytes_copied
            self._event(
                "info",
                "export.ok",
                {
                    "mode": result.mode,
                    "seq": result.descriptor.seq,
                    "head": result.descriptor.head[:12],
                    "offset": result.descriptor.offset,
                    "copied": result.bytes_copied,
                    "ms": elapsed,
                    **({"reason": result.reason} if result.reason else {}),
                },
            )
        else:
            assert error is not None
            self._failures += 1
            self._last_error = (f"{error.rule}: {error.detail}"[:200], self._wall())
            self._counts["export_failed"] += 1
            self._event(
                "error" if error.kind in ("integrity", "reject") else "warn",
                "export.failed",
                {"rule": error.rule, "detail": error.detail[:200], "failures": self._failures},
            )
        return outcome

    # -- what status shows ------------------------------------------------------------------------

    def info(self, head: str | None = None) -> ExportInfo | None:
        """The last successful export for ``status.json`` (None before the first one).

        ``head`` is the journal's current head: when it equals the exported head nothing is
        unexported and the lag is 0; otherwise the lag is the time since the capture."""
        last = self.last
        if last is None:
            return None
        lag = 0
        if head != last.head:
            lag = max(0, self._wall() - parse_utc(last.captured_utc))
        return ExportInfo(last.head, last.seq, last.utc, lag)

    def details(self, now_ms: int | None = None) -> dict[str, Any]:
        """Bounded facts for ``info.export``: schedule, a running export, the last error."""
        now = self._now() if now_ms is None else now_ms
        found: dict[str, Any] = {
            "interval_ms": self.interval_ms,
            "consecutive_failures": self._failures,
        }
        last = self.last
        if last is not None:
            found.update(last_mode=last.mode, offset=last.offset, file=last.file)
        job = self._job
        if job is not None and job.thread is not None and job.thread.is_alive():
            found.update(
                state="running",
                running_ms=max(0, now - job.started_ms),
                bytes_done=job.done_bytes,
                bytes_total=job.total_bytes,
                slow=job.slow_reported,
            )
        else:
            found["state"] = "idle"
        if self._last_error is not None:
            found.update(last_error=self._last_error[0])
        return found

    def counters(self) -> dict[str, int]:
        return dict(self._counts)

    def _progress_fields(self, job: _Job, now: int) -> dict[str, Any]:
        return {
            "running_ms": max(0, now - job.started_ms),
            "bytes_done": job.done_bytes,
            "bytes_total": job.total_bytes,
        }

    def _event(self, level: str, kind: str, fields: dict[str, Any]) -> None:
        if self._emit is not None:
            self._emit(level, kind, fields)
