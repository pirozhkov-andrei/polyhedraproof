"""The run's monitor: status files, periodic exports and the human log behind one object
(specification §8.4).

The coordinator creates one :class:`RunMonitor`, feeds it every committed record
(:meth:`~RunMonitor.observe`, once, in order: at startup replay and for each record the I/O
service acknowledges), calls :meth:`~RunMonitor.tick` from its loop and :meth:`~RunMonitor.finish`
at a clean stop. ``tick`` never blocks: the export copy runs in a thread (see
:mod:`.export_runner`), a status is built only when its interval has passed and then from the
already folded state (the ``sources`` callable is not even called otherwise), the closed coverage
is recomputed only when the state changed and within a visit budget (when the budget is exhausted
the previous value is kept and ``info.coverage`` says ``stale``), and a status write is one small
rename.

Nothing here is evidence. A monitor that fails (disk full for ``status.json``, a failing export) is
reported through counters, ``info`` and the log and never stops the run.
"""

from __future__ import annotations

import os
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from cubeproof.contracts.enums import Lifecycle
from cubeproof.coordinator.events import EventLog
from cubeproof.coordinator.export_runner import ExportOutcome, ExportRunner
from cubeproof.coordinator.ledger import Reservation
from cubeproof.coordinator.state import ReplayState
from cubeproof.coordinator.status import (
    ActiveTask,
    EtaEstimator,
    StatusTracker,
    build_status,
)
from cubeproof.coordinator.status_coverage import Coverage, CoverageBudget, closed_coverage
from cubeproof.coordinator.status_publish import PublishOutcome, StatusPublisher
from cubeproof.evidence.schema import Record, ResourceSnapshot
from cubeproof.tools.atomic import OS_FILE_CALLS, FileCalls

__all__ = ["MonitorConfig", "RunMonitor", "StatusSources"]


@dataclass(frozen=True)
class MonitorConfig:
    """Intervals and bounds (specification §7.5: export every 60 s; specification §8.4: status at
    most every 10 s, human progress each minute)."""

    status_interval_ms: int = 10_000
    export_interval_ms: int = 60_000
    export_slow_ms: int = 30_000
    export_stop_timeout_ms: int = 60_000
    progress_interval_ms: int = 60_000
    coverage_visits: int = 100_000


@dataclass(frozen=True)
class StatusSources:
    """What the coordinator hands over when a status is due (read at that moment only)."""

    state: ReplayState
    lifecycle: Lifecycle
    resources: ResourceSnapshot
    reservations: Sequence[Reservation] = ()
    active: Sequence[ActiveTask] = ()
    stalls: Sequence[str] = ()
    counters: Mapping[str, int] = field(default_factory=dict)
    #: Further bounded facts for ``info`` (requested/effective budgets, observed usage, proof queue
    #: bytes, ...): JSON values under names the monitor does not use itself.
    info: Mapping[str, Any] = field(default_factory=dict)


def _monotonic_ms() -> int:
    return int(time.monotonic() * 1000)


def _wall_ms() -> int:
    return int(time.time() * 1000)


class RunMonitor:
    """Status publication, exports and log lines of one worker (module doc)."""

    def __init__(
        self,
        *,
        results: str | os.PathLike[str],
        journal: str | os.PathLike[str],
        export: str | os.PathLike[str] | None = None,
        log: EventLog | None = None,
        config: MonitorConfig = MonitorConfig(),  # noqa: B008 - a frozen value
        calls: FileCalls = OS_FILE_CALLS,
        monotonic_ms: Callable[[], int] = _monotonic_ms,
        wall_ms: Callable[[], int] = _wall_ms,
        eta: EtaEstimator | None = None,
    ) -> None:
        self.config = config
        self.log = log
        self.tracker = StatusTracker()
        self.eta = eta or EtaEstimator()
        self._now = monotonic_ms
        self._wall = wall_ms
        self.publisher = StatusPublisher(
            results,
            interval_ms=config.status_interval_ms,
            calls=calls,
            monotonic_ms=monotonic_ms,
        )
        self.runner: ExportRunner | None = None
        if export is not None:
            self.runner = ExportRunner(
                journal,
                export,
                interval_ms=config.export_interval_ms,
                slow_ms=config.export_slow_ms,
                calls=calls,
                monotonic_ms=monotonic_ms,
                wall_ms=wall_ms,
                on_event=self._runner_event,
            )
        #: the outcome of the clean-stop export (None before :meth:`finish` or without an export)
        self.final_export: ExportOutcome | None = None
        self._coverage: tuple[int, list[Coverage]] | None = None
        self.last_document: dict[str, Any] | None = None

    # -- records -------------------------------------------------------------------------------

    def observe(self, record: Record) -> None:
        """Count one committed record (call once per record, in order)."""
        self.tracker.observe(record)

    # -- the loop --------------------------------------------------------------------------------

    def tick(
        self, sources: Callable[[], StatusSources], *, force: bool = False
    ) -> PublishOutcome | None:
        """Collect/start exports and publish a status when due (or ``force``, for a lifecycle
        change). Nonblocking; returns the publication outcome when one was attempted."""
        now = self._now()
        if self.runner is not None:
            self.runner.poll(now)
        if not force and not self.publisher.due(now):
            return None
        return self._publish(sources(), now)

    def finish(self, sources: Callable[[], StatusSources]) -> PublishOutcome:
        """The clean-stop export (bounded wait), then the final status (forced)."""
        runner = self.runner
        if runner is not None:
            self.final_export = runner.finish(timeout_ms=self.config.export_stop_timeout_ms)
        return self._publish(sources(), self._now())

    # -- internals ---------------------------------------------------------------------------------

    def _coverage_for(self, state: ReplayState) -> tuple[list[Coverage] | None, int | None]:
        cached = self._coverage
        if cached is not None and cached[0] == state.seq:
            return cached[1], cached[0]
        try:
            fresh = closed_coverage(state, max_visits=self.config.coverage_visits)
        except CoverageBudget as error:
            self._event("warn", "status.coverage_budget", {"visits": error.visited}, "coverage")
            return (cached[1], cached[0]) if cached is not None else (None, None)
        self._coverage = (state.seq, fresh)
        return fresh, state.seq

    def _eta(self, state: ReplayState, now: int) -> int | None:
        counts = state.counts()
        pending = sum(n for (s, _), n in counts.items() if s == "pending")
        waiting = sum(n for (s, _), n in counts.items() if s in ("needs_split", "stop_due"))
        self.eta.observe(
            now,
            closed_leaves=sum(state.verified_by_depth().values()),
            pending=pending,
            needs_split=waiting,
            splits=self.tracker.counters().get("type_split", 0),
        )
        return self.eta.estimate()

    def _publish(self, src: StatusSources, now: int) -> PublishOutcome:
        state = src.state
        coverage, coverage_seq = self._coverage_for(state)
        counters = dict(src.counters)
        info: dict[str, Any] = {**src.info, "status_write": self.publisher.details()}
        export = None
        if self.runner is not None:
            export = self.runner.info(state.head)
            counters.update(self.runner.counters())
            info["export"] = self.runner.details(now)
        counters["status_writes"] = self.publisher.writes
        counters["status_write_failures"] = self.publisher.failures
        doc = build_status(
            state=state,
            lifecycle=src.lifecycle,
            wall_ms=self._wall(),
            now_ms=now,
            resources=src.resources,
            reservations=src.reservations,
            active=src.active,
            tracker=self.tracker,
            counters=counters,
            export=export,
            coverage=coverage,
            coverage_seq=coverage_seq,
            eta_ms=self._eta(state, now),
            stalls=src.stalls,
            info=info,
        )
        outcome = self.publisher.publish(doc, now, force=True)
        self.last_document = doc
        if outcome.error is not None:
            error = outcome.error
            self._event("warn", "status.write_failed", {"rule": error.rule}, "status.write")
        if self.log is not None:
            self.log.progress(doc, now)
        return outcome

    def _runner_event(self, level: str, kind: str, fields: dict[str, Any]) -> None:
        if kind == "export.ok" and fields.get("mode") == "unchanged":
            return
        key = f"{kind}:{fields.get('rule', '')}" if level != "info" else None
        self._event(level, kind, fields, key)

    def _event(self, level: str, kind: str, fields: Mapping[str, Any], dedupe: str | None) -> None:
        if self.log is not None:
            self.log.event(level, kind, fields, dedupe=dedupe)
