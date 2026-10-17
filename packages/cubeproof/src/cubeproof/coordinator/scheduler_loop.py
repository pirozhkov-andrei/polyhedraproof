"""Bounded ticks: fair slicing of the sliceable work and the tick-latency statistics.

Specification §8.1. The single-threaded loop must stay responsive: unit propagation, model
evaluation and CNF writing are generator-driven slices (``tools.unit_helper.SlicedTask``,
``LeafAttempt.advance``), hashing, copying and journal appends run in the I/O service
process, and the splitter helper is a supervised child. What is left for the loop is to give
every sliceable task a share of each tick **without** letting the sum of the shares grow with
the number of tasks: :class:`SliceRotor` advances the tasks round-robin until the tick's
budget is spent and remembers where it stopped, so that every task is served in turn even
if one tick cannot serve them all.

:class:`TickStats` keeps the durations of the last ticks for the acceptance profile (specification
§8.1: ordinary-operation tick latency p99 <= 100 ms and observed maximum <= 1 s). It measures; it
neither throttles nor excuses a stall: an operating-system stall is reported separately by
the caller and a delay never authorizes a skipped check or an early record.
"""

from __future__ import annotations

import time
from collections import deque
from collections.abc import Callable, Sequence
from typing import Protocol

__all__ = ["TICK_MAX_MS", "TICK_P99_MS", "SliceRotor", "Sliced", "TickStats"]

#: The acceptance bounds of specification §8.1 for ordinary operation.
TICK_P99_MS = 100
TICK_MAX_MS = 1000
_NS_PER_MS = 1_000_000


class Sliced(Protocol):
    """A task that does bounded work per call (``LeafAttempt``)."""

    @property
    def finished(self) -> bool: ...

    def advance(self, slice_ms: int = ...) -> object: ...


class SliceRotor:
    """Round-robin slicing with a per-tick budget (module doc)."""

    def __init__(self, *, clock: Callable[[], int] = time.monotonic_ns) -> None:
        self._clock = clock
        self._cursor = 0

    def run(self, tasks: Sequence[Sliced], *, budget_ms: int, slice_ms: int = 5) -> int:
        """Advance unfinished tasks round-robin for about ``budget_ms``; returns the slices run.

        At least one slice runs per call when there is a task to advance (so a tiny budget
        cannot starve the work), and the call returns once the budget is spent: it overshoots
        by at most one slice of one task. The next call continues with the task after the last
        one served.
        """
        if type(budget_ms) is not int or budget_ms < 0 or type(slice_ms) is not int or slice_ms < 1:
            raise ValueError("budget_ms must be nonnegative and slice_ms positive")
        count = len(tasks)
        if count == 0:
            self._cursor = 0
            return 0
        start = self._clock()
        slices = 0
        index = self._cursor % count
        idle = 0
        while idle < count:
            task = tasks[index]
            index = (index + 1) % count
            if task.finished:
                idle += 1
                continue
            idle = 0
            task.advance(slice_ms)
            slices += 1
            self._cursor = index
            if self._clock() - start >= budget_ms * _NS_PER_MS:
                break
        return slices


class TickStats:
    """Durations of the last ``keep`` ticks and the statistics the acceptance profile needs."""

    def __init__(self, keep: int = 10_000) -> None:
        if type(keep) is not int or keep < 1:
            raise ValueError("keep must be a positive integer")
        self._ticks: deque[int] = deque(maxlen=keep)
        self.count = 0
        self.maximum_ns = 0

    def record(self, duration_ns: int) -> None:
        if type(duration_ns) is not int or duration_ns < 0:
            raise ValueError("a tick duration is a nonnegative number of nanoseconds")
        self._ticks.append(duration_ns)
        self.count += 1
        self.maximum_ns = max(self.maximum_ns, duration_ns)

    def percentile_ms(self, percent: float) -> float:
        """Nearest-rank percentile of the kept ticks, in milliseconds (0 when none)."""
        if not 0 < percent <= 100:
            raise ValueError("percent must be in (0, 100]")
        if not self._ticks:
            return 0.0
        ordered = sorted(self._ticks)
        rank = -(-len(ordered) * percent // 100)  # ceil(n * p / 100) without float error
        return ordered[max(1, int(rank)) - 1] / _NS_PER_MS

    @property
    def maximum_ms(self) -> float:
        return self.maximum_ns / _NS_PER_MS

    def within_bounds(
        self, *, p99_ms: float = TICK_P99_MS, maximum_ms: float = TICK_MAX_MS
    ) -> bool:
        """The specification §8.1 acceptance bounds: p99 and the observed maximum."""
        return self.percentile_ms(99) <= p99_ms and self.maximum_ms <= maximum_ms

    def report(self) -> dict[str, float | int]:
        return {
            "ticks": self.count,
            "p50_ms": self.percentile_ms(50),
            "p99_ms": self.percentile_ms(99),
            "max_ms": self.maximum_ms,
        }
