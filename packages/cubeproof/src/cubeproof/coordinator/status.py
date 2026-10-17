"""The status snapshot of a run: bounded, derived, never evidence (specification §8.4, §12.3).

:func:`build_status` turns the pieces the coordinator already has (the folded
:class:`~cubeproof.coordinator.state.ReplayState`, the resource ledgers, the active tasks, the
export state) into the ``cubeproof-status-1`` document. Everything in it is bounded by constants,
not by the size of the run:

- ``models`` and ``anomalies`` list at most 100 Refs (the earliest, so the list is stable while it
  grows) and the full totals are counters; no model assignment is ever copied;
- ``reservations``, ``active`` and ``coverage`` are cut at :data:`ROW_LIMIT` rows, ``info.stalls``
  at :data:`STALL_LIMIT`; a cut is announced in ``info.truncated`` with the number left out;
- ``node_counts`` is one row per ``(state, depth)``, so it grows with the depth limit, not with the
  frontier;
- ``counters`` is a fixed set of names.

The document is built from state only: the same state, inputs and clock give the same bytes.
Coverage is the exact closed measure of :mod:`.status_coverage`. An ETA is a rough estimate that
is **omitted** (null) unless the frontier and the rates are stable (:class:`EtaEstimator`): while
branching goes on a remaining-work figure would be a guess presented as a number."""

from __future__ import annotations

from collections import deque
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from cubeproof.base.errors import ConfigurationError
from cubeproof.contracts.enums import Lifecycle, Outcome
from cubeproof.contracts.identity import node_id
from cubeproof.contracts.primitives import format_utc
from cubeproof.coordinator.ledger import Reservation
from cubeproof.coordinator.state import Key, ReplayState
from cubeproof.coordinator.status_coverage import Coverage
from cubeproof.coordinator.status_format import MODEL_LIMIT, STATUS_FORMAT
from cubeproof.evidence.schema import Attempt, Record, ResourceSnapshot

__all__ = [
    "ROW_LIMIT",
    "STALL_LIMIT",
    "ActiveTask",
    "EtaEstimator",
    "ExportInfo",
    "StatusTracker",
    "build_status",
    "utc_of",
]

#: Rows kept of the lists whose length depends on the run (reservations, active tasks, coverage).
ROW_LIMIT = 1000
#: Stall reasons kept in ``info.stalls`` (each cut to :data:`TEXT_LIMIT` characters).
STALL_LIMIT = 20
TEXT_LIMIT = 300


def utc_of(wall_ms: int) -> str:
    """The UTC string of a wall-clock reading in milliseconds since the Unix epoch."""
    return format_utc(wall_ms)


@dataclass(frozen=True)
class ActiveTask:
    """One running task: its identity, the node it works on (None for machine tasks), its stage and
    when it started on the caller's monotonic clock (milliseconds)."""

    task_id: str
    node: Key | None
    stage: str
    started_ms: int


@dataclass(frozen=True)
class ExportInfo:
    """The last successful export as the status shows it (``lag_ms`` is computed by the caller)."""

    head: str
    seq: int
    utc: str
    lag_ms: int

    def to_json(self) -> dict[str, Any]:
        return {"head": self.head, "seq": self.seq, "utc": self.utc, "lag_ms": self.lag_ms}


class StatusTracker:
    """What the status needs of the records that the state does not keep: counters and Refs.

    Feed every committed record once, in order (the coordinator's startup replay and every record
    the I/O service acknowledges). Memory is bounded: at most ``MODEL_LIMIT`` sequence numbers per
    list and a handful of counters, however long the journal is.
    """

    def __init__(self) -> None:
        self.models: list[int] = []
        self.anomalies: list[int] = []
        self._counts: dict[str, int] = {}
        self.last_seq = -1

    def observe(self, record: Record) -> None:
        if record.seq != self.last_seq + 1:
            raise ConfigurationError(
                "status.order", f"record {record.seq} observed after {self.last_seq}"
            )
        self.last_seq = record.seq
        self._add("records")
        self._add(f"type_{record.type.value}")
        payload = record.payload
        if not isinstance(payload, Attempt):
            return
        self._add("attempts")
        outcome = payload.outcome
        self._add(f"outcome_{outcome.value.lower()}")
        if outcome is Outcome.MODEL:
            self._add("models")
            if len(self.models) < MODEL_LIMIT:
                self.models.append(record.seq)
        elif outcome in (Outcome.INVALID_MODEL, Outcome.CHECK_REJECTED):
            self._add("anomalies")
            if len(self.anomalies) < MODEL_LIMIT:
                self.anomalies.append(record.seq)

    def _add(self, name: str) -> None:
        self._counts[name] = self._counts.get(name, 0) + 1

    def counters(self) -> dict[str, int]:
        """The counters seen so far; ``models`` and ``anomalies`` are always present."""
        found = dict(self._counts)
        found.setdefault("models", 0)
        found.setdefault("anomalies", 0)
        return dict(sorted(found.items()))


class EtaEstimator:
    """A remaining-time estimate that exists only while it can mean something (specification §8.4).

    ``observe`` is called with the closed-leaf count, the pending frontier size, the number of
    nodes that still need a split and the number of splits ever recorded. The estimate is
    available only if

    - no node waits for a split and no split was recorded during the whole window (the shape of the
      frontier is stable: pending leaves are the work left),
    - the window holds at least ``min_samples`` samples spanning at least ``min_span_ms``,
    - leaves closed at a steady rate: the rates of the two halves of the window are both positive
      and differ by at most the factor ``ratio``.

    Otherwise it returns None. The value is ``pending / rate`` in milliseconds; it assumes every
    pending node closes at the observed rate, which is optimistic when later nodes are harder.
    """

    def __init__(
        self,
        *,
        window_ms: int = 600_000,
        min_samples: int = 6,
        min_span_ms: int = 60_000,
        ratio: float = 2.0,
        max_samples: int = 512,
    ) -> None:
        self.window_ms = window_ms
        self.min_samples = min_samples
        self.min_span_ms = min_span_ms
        self.ratio = ratio
        self._samples: deque[tuple[int, int, int, int, int]] = deque(maxlen=max_samples)

    def observe(
        self, now_ms: int, *, closed_leaves: int, pending: int, needs_split: int, splits: int
    ) -> None:
        if self._samples and now_ms < self._samples[-1][0]:
            self._samples.clear()  # the clock went backwards: start over
        self._samples.append((now_ms, closed_leaves, pending, needs_split, splits))
        while len(self._samples) > 1 and now_ms - self._samples[0][0] > self.window_ms:
            self._samples.popleft()

    def estimate(self) -> int | None:
        samples = self._samples
        if len(samples) < self.min_samples:
            return None
        first, last = samples[0], samples[-1]
        span = last[0] - first[0]
        if span < self.min_span_ms or last[2] <= 0:
            return None
        if any(s[3] for s in samples) or any(s[4] != last[4] for s in samples):
            return None
        middle = first[0] + span // 2
        pivot = next(s for s in samples if s[0] >= middle)
        early = (pivot[1] - first[1]) / max(1, pivot[0] - first[0])
        late = (last[1] - pivot[1]) / max(1, last[0] - pivot[0])
        if early <= 0 or late <= 0 or max(early, late) / min(early, late) > self.ratio:
            return None
        rate = (last[1] - first[1]) / span
        return int(last[2] / rate)


def _text(value: str) -> str:
    return value if len(value) <= TEXT_LIMIT else value[: TEXT_LIMIT - 3] + "..."


def build_status(
    *,
    state: ReplayState,
    lifecycle: Lifecycle,
    wall_ms: int,
    now_ms: int,
    resources: ResourceSnapshot,
    reservations: Sequence[Reservation],
    active: Sequence[ActiveTask],
    tracker: StatusTracker,
    counters: Mapping[str, int] | None = None,
    export: ExportInfo | None = None,
    coverage: Sequence[Coverage] | None = None,
    coverage_seq: int | None = None,
    eta_ms: int | None = None,
    stalls: Sequence[str] = (),
    info: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """The status document of ``state`` (module doc); validate with ``validate_status``.

    ``wall_ms`` is the wall clock (the document's ``utc``), ``now_ms`` the caller's monotonic clock
    in which ``ActiveTask.started_ms`` is measured. ``coverage=None`` omits coverage and says so in
    ``info.coverage``; a ``coverage_seq`` older than the state's marks it ``stale`` there.
    ``counters`` are merged under the tracker's (extra names must not clash).
    """
    policy, journal, head, worker = state.policy, state.journal_id, state.head, state.worker
    if policy is None or journal is None or head is None or worker is None:
        raise ConfigurationError("status.state", "the state has not applied a header yet")
    truncated: dict[str, int] = {}

    def bounded(name: str, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        if len(rows) > ROW_LIMIT:
            truncated[name] = len(rows) - ROW_LIMIT
        return rows[:ROW_LIMIT]

    rows = sorted(reservations, key=lambda r: r.task_id)
    reserved = bounded(
        "reservations",
        [
            {
                "task_id": r.task_id,
                "stage": r.stage,
                "cpu_milli": r.need.cpu_milli,
                "memory_bytes": r.need.memory_bytes,
                "disk": [{"id": g, "bytes": b} for g, b in r.need.disk],
            }
            for r in rows
        ],
    )
    shown = sorted(active, key=lambda a: a.task_id)
    tasks = bounded(
        "active",
        [
            {
                "task_id": a.task_id,
                "node_id": None if a.node is None else node_id(*a.node),
                "stage": a.stage,
                "elapsed_ms": max(0, now_ms - a.started_ms),
            }
            for a in shown
        ],
    )
    oldest = max((max(0, now_ms - a.started_ms) for a in active), default=0)

    frontier: dict[tuple[str, int], int] = dict(state.counts())
    for depth, count in state.verified_by_depth().items():
        frontier[("closed", depth)] = count
    node_counts = [{"state": s, "depth": d, "count": c} for (s, d), c in sorted(frontier.items())]

    merged = tracker.counters()
    merged["not_admitted"] = len(state.not_admitted)
    merged["malformed_splits"] = len(state.malformed)
    merged["given_away"] = len(state.given_away())
    for name, number in (counters or {}).items():
        if name in merged:
            raise ConfigurationError("status.counter", f"counter {name!r} is defined twice")
        merged[name] = number

    notes: dict[str, Any] = {}
    if coverage is None:
        notes["coverage"] = {"available": False}
        listed: list[dict[str, Any]] = []
    else:
        listed = bounded("coverage", [c.to_json() for c in coverage])
        computed = state.seq if coverage_seq is None else coverage_seq
        notes["coverage"] = {
            "available": True,
            "roots": len(coverage),
            "closed_roots": sum(1 for c in coverage if c.closed),
            "computed_seq": computed,
            "stale": computed != state.seq,
        }
    if len(tracker.models) < merged["models"]:
        truncated["models"] = merged["models"] - len(tracker.models)
    if len(tracker.anomalies) < merged["anomalies"]:
        truncated["anomalies"] = merged["anomalies"] - len(tracker.anomalies)
    if stalls:
        cut = [_text(s) for s in stalls]
        notes["stalls"] = cut[:STALL_LIMIT]
        if len(cut) > STALL_LIMIT:
            truncated["stalls"] = len(cut) - STALL_LIMIT
    notes["session"] = {
        "anomalies": state.session.anomalies,
        "machine_failures": state.session.machine_failures,
    }
    if truncated:
        notes["truncated"] = dict(sorted(truncated.items()))
    for name, extra in (info or {}).items():
        if name in notes:
            raise ConfigurationError("status.info", f"info {name!r} is defined twice")
        notes[name] = extra

    return {
        "format": STATUS_FORMAT,
        "campaign": state.view.campaign_id,
        "journal": journal,
        "head": head,
        "policy_sha256": policy.sha256,
        "worker": worker,
        "seq": state.seq,
        "utc": utc_of(wall_ms),
        "lifecycle": lifecycle.value,
        "resources": resources.to_json(),
        "reservations": reserved,
        "node_counts": node_counts,
        "active": tasks,
        "oldest_elapsed_ms": oldest,
        "counters": dict(sorted(merged.items())),
        "export": None if export is None else export.to_json(),
        "models": [{"journal": journal, "seq": seq} for seq in tracker.models],
        "anomalies": [{"journal": journal, "seq": seq} for seq in tracker.anomalies],
        "coverage": listed,
        "eta_ms": eta_ms,
        "info": notes,
    }
