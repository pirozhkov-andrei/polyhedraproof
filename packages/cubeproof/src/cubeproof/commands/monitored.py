"""A run that publishes its status and exports its journal (specification §7.5, §8.4, §12.3).

The coordinator knows nothing about the monitor (``status.json``/``status.txt``, the periodic
prefix export, the human progress log). This module is the wiring, as small subclasses of the
coordinators that only override the points the monitor needs and always call the base
implementation first:

* ``_before_replay``: under the run lock and before the journal is validated, repaired or
  appended to, the journal is compared with the export directory
  (:func:`~cubeproof.coordinator.export.compare_export`). An export that holds more of this
  journal than the results directory (a backup older than the export was restored) is the more
  recent backup: its records are validated like the journal's, what they reference must exist,
  and the missing ones are appended to the journal before the replay, so the run resumes from
  the exported position and the published history is never forked. Another journal, a
  different continuation or an export that cannot supply the records ends the run here, before
  any record is written (exit 3 or 4, specification §12.2);
* ``_begin_session``: before the I/O service starts (the journal is then stable under the run
  lock) the monitor is created and every record the replay already validated is fed to its
  tracker, so the status counters, models and anomalies cover the whole journal. A new worker has
  no records yet; the header and resume then arrive through ``_on_record`` like every record;
* ``_on_record``: every committed record is observed once, in order;
* ``_observe`` (once per tick): ``RunMonitor.tick`` with the sources of the moment (collected only
  when a status is due), a forced status when the lifecycle changes to ``draining``;
* ``_final_sync_and_cache``: after the last synchronisation and before the lock is released, the
  clean-stop export (bounded wait) and the final status with lifecycle ``stopped``.

Nothing the monitor does is evidence and, once the run has started, nothing it does may stop
it: a monitor failure is reported once as a note of the run result and the monitor is switched
off; an export that fails is retried, and a clean-stop export that failed is a note of the run
result. The exit code describes the journal (specification §12.2), not its copies. The cost of the
tracker's catch-up is a second validated pass over an existing journal at startup; a run without
prior records pays nothing.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from cubeproof.base.errors import ConfigurationError, CubeproofError
from cubeproof.commands.shard import read_shard_file
from cubeproof.contracts.enums import Lifecycle
from cubeproof.coordinator.config import RunConfig
from cubeproof.coordinator.events import EventLog
from cubeproof.coordinator.export import compare_export, restore_from_export
from cubeproof.coordinator.handoff_run import DeskCoordinator
from cubeproof.coordinator.replay import Replayed, validator_of
from cubeproof.coordinator.run import Coordinator, check_exported_tail
from cubeproof.coordinator.state import Key
from cubeproof.coordinator.status import ActiveTask
from cubeproof.coordinator.status_monitor import RunMonitor, StatusSources
from cubeproof.evidence.journal import JournalReader
from cubeproof.evidence.schema import Record

__all__ = ["MonitoredCoordinator", "MonitoredDeskCoordinator", "Monitoring"]

_STALL_PREFIX = "stalled:"


def _monotonic_ms() -> int:
    return int(time.monotonic() * 1000)


class Monitoring:
    """What a run needs to monitor itself: the export directory and the log sink/level."""

    def __init__(
        self,
        export: Path | None = None,
        sink: Callable[[str], None] | None = None,
        level: str = "info",
    ) -> None:
        self.export = None if export is None else Path(export).resolve()
        self.sink = sink
        self.level = level


class _MonitorMixin(Coordinator):
    """The monitor overrides (module doc); mixed into the two accepted coordinators."""

    _monitoring: Monitoring
    _monitor: RunMonitor | None
    _started: dict[str, int]
    _lifecycle: Lifecycle | None
    _restored: dict[str, Any] | None

    def _init_monitor(self, monitoring: Monitoring) -> None:
        self._monitoring = monitoring
        self._monitor = None
        self._started = {}
        self._lifecycle = None
        self._restored = None

    # -- the journal and its export, before the replay (module doc) ----------------------------

    def _before_replay(self) -> None:
        super()._before_replay()
        export = self._monitoring.export
        if export is None:
            return
        assert self.lock is not None
        journal, limits = self.layout.journal, self.config.limits
        standing = compare_export(journal, export, limits=limits)
        if standing.relation == "unreadable":
            self._notes.append(
                f"the export descriptor in {export} is unreadable: the next export is a full copy"
            )
        if standing.relation != "ahead":
            return
        descriptor, anchor = standing.descriptor, standing.journal
        assert descriptor is not None and anchor is not None
        count = restore_from_export(
            journal,
            export,
            standing,
            run_lock=self.lock,
            inspect=lambda d, a: check_exported_tail(
                export, d, a, loaded=self.loaded, results=self.layout.results, limits=limits
            ),
            limits=limits,
        )
        self._restored = {"records": count, "first": anchor.seq + 1, "last": descriptor.seq}
        self._notes.append(
            f"restored the records {anchor.seq + 1} to {descriptor.seq} of the journal from the "
            f"export in {export}: the journal was a prefix of the exported one"
        )

    # -- the monitor ---------------------------------------------------------------------------

    def _make_monitor(self) -> RunMonitor:
        monitoring = self._monitoring
        log = (
            None
            if monitoring.sink is None
            else EventLog(monitoring.sink, min_level=monitoring.level)
        )
        return RunMonitor(
            results=self.layout.results,
            journal=self.layout.journal,
            export=monitoring.export,
            log=log,
            monotonic_ms=_monotonic_ms,
        )

    def _guard(self, work: Callable[[], Any]) -> None:
        """Run a monitor step; a failure ends monitoring with a note (module doc)."""
        if self._monitor is None:
            return
        try:
            work()
        except (CubeproofError, OSError) as error:
            self._notes.append(f"the status monitor stopped: {error}")
            self._monitor = None

    def _catch_up(self, monitor: RunMonitor) -> None:
        """Feed the tracker every record the replay validated (the journal is stable here)."""
        with self.layout.journal.open("rb") as stream:
            reader = JournalReader(
                stream,
                validator_of(self.loaded),
                name=self.layout.journal.name,
                limits=self.config.limits,
            )
            for record in reader:
                monitor.observe(record)

    def _begin_session(self, replayed: Replayed) -> None:
        self._monitor = self._make_monitor()
        log = self._monitor.log
        if self._restored is not None and log is not None:
            log.event("warn", "journal.restored", {**self._restored, "source": "export"})
        if replayed.header is not None:
            monitor = self._monitor
            self._guard(lambda: self._catch_up(monitor))
        super()._begin_session(replayed)

    def _on_record(self, record: Record) -> None:
        super()._on_record(record)
        monitor = self._monitor
        if monitor is not None:
            self._guard(lambda: monitor.observe(record))

    # -- the loop --------------------------------------------------------------------------------

    def _active_tasks(self) -> list[ActiveTask]:
        now = _monotonic_ms()
        found: dict[str, tuple[Key | None, str]] = {}
        for task_id, attempt in self._attempts.items():
            found[task_id] = (attempt.key, attempt.attempt.phase.value)
        for task_id, split in self._splits.items():
            found[task_id] = (split.key, "split")
        self._started = {t: self._started.get(t, now) for t in found}
        return [
            ActiveTask(task_id, key, stage, self._started[task_id])
            for task_id, (key, stage) in sorted(found.items())
        ]

    def _extra_counters(self) -> dict[str, int]:
        return {}

    def _sources(self, lifecycle: Lifecycle) -> StatusSources:
        assert self.state is not None
        info: dict[str, Any] = {"resources": self.resources.status()}
        stalls = [
            n[len(_STALL_PREFIX) :].strip() for n in self._notes if n.startswith(_STALL_PREFIX)
        ]
        return StatusSources(
            state=self.state,
            lifecycle=lifecycle,
            resources=self.resources.snapshot(),
            reservations=self.book.reservations(),
            active=self._active_tasks(),
            stalls=stalls,
            counters=self._extra_counters(),
            info=info,
        )

    def _observe(self) -> None:
        super()._observe()
        monitor = self._monitor
        if monitor is None or self.state is None or self.state.policy is None:
            return
        lifecycle = Lifecycle.DRAINING if self._drained else Lifecycle.RUNNING
        force = lifecycle is not self._lifecycle and self._lifecycle is not None
        self._lifecycle = lifecycle
        self._guard(lambda: monitor.tick(lambda: self._sources(lifecycle), force=force))

    def _final_sync_and_cache(self) -> None:
        super()._final_sync_and_cache()
        monitor = self._monitor
        if monitor is None or self.state is None or self.state.policy is None:
            return
        self._guard(lambda: monitor.finish(lambda: self._sources(Lifecycle.STOPPED)))
        failed = monitor.final_export
        if failed is not None and failed.error is not None:
            last = monitor.runner.last if monitor.runner is not None else None
            held = "holds nothing" if last is None else f"ends at record {last.seq}"
            self._notes.append(
                f"the final export failed ({failed.error.rule}: {failed.error.detail[:200]}): "
                f"the export directory {held}, the journal ends at record {self.state.seq}"
            )


class MonitoredCoordinator(_MonitorMixin):
    """The coordinator with the monitor (a run without a handoff desk)."""

    def __init__(self, config: RunConfig, monitoring: Monitoring) -> None:
        super().__init__(config)
        self._init_monitor(monitoring)


class MonitoredDeskCoordinator(_MonitorMixin, DeskCoordinator):
    """The desk coordinator with the monitor (``--inbox``, ``--outbox`` or ``--shard``).

    A ``--shard`` file is read once the campaign is loaded (its nodes are checked against the
    campaign's formulas) and before the I/O service starts or anything is written: a bad file is
    an input error (exit 3) with the journal untouched.
    """

    def __init__(
        self,
        config: RunConfig,
        monitoring: Monitoring,
        *,
        inbox: Path | None = None,
        outbox: Path | None = None,
        shard_file: Path | None = None,
    ) -> None:
        super().__init__(config, inbox=inbox, outbox=outbox)
        self._init_monitor(monitoring)
        self._shard_file = shard_file

    def _begin_session(self, replayed: Replayed) -> None:
        if self._shard_file is not None:
            variables = {sha: b.formula.variables for sha, b in self.loaded.bundles.items()}
            shard = read_shard_file(
                self._shard_file, variables=variables, limits=self.config.limits
            )
            if shard.campaign != self.campaign_id:
                raise ConfigurationError(
                    "shard.campaign",
                    f"{self._shard_file} is a shard of campaign {shard.campaign}, "
                    f"not of {self.campaign_id}",
                )
            self._cli_shard = shard
        super()._begin_session(replayed)

    def _extra_counters(self) -> dict[str, int]:
        return {f"desk_{name}": value for name, value in self.desk.summary().items()}
