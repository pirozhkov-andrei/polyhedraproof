"""Per-formula propagation indexes, built in slices and shared by every task (specification §8.1).

Unit propagation (leaf attempts) and the lookahead reference (splits) need an index of the
whole formula. Building it for a large formula must not block the event loop (tick latency,
specification §8.1), and building it once per task would multiply the memory, so
:class:`SlicedCache` builds each index with the step generators of ``cnf.unit`` and
``split.lookahead`` in time slices and keeps it for the run. :meth:`SlicedCache.get` advances a
pending build by one slice and returns the finished index, or None while it is still being built:
the caller simply does not start work that needs it yet.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Generator
from typing import Generic, TypeVar

from cubeproof.cnf.dimacs import Formula
from cubeproof.cnf.unit import UnitIndex, build_index_steps
from cubeproof.split.lookahead import Engine, build_engine_steps
from cubeproof.tools.unit_helper import SlicedTask, TaskState

__all__ = ["EngineCache", "IndexCache", "SlicedCache"]

_T = TypeVar("_T")


class SlicedCache(Generic[_T]):
    """One value per formula hash, each built by a step generator in slices."""

    def __init__(
        self,
        make: Callable[[Formula], Generator[None, None, _T]],
        *,
        slice_ms: int = 5,
        clock: Callable[[], int] = time.monotonic_ns,
    ) -> None:
        self._make = make
        self._slice_ms = slice_ms
        self._clock = clock
        self._done: dict[str, _T] = {}
        self._building: dict[str, SlicedTask[_T]] = {}

    def get(self, formula: Formula) -> _T | None:
        """The finished value for ``formula``, or None after advancing its build by a slice."""
        found = self._done.get(formula.sha256)
        if found is not None:
            return found
        task = self._building.get(formula.sha256)
        if task is None:
            task = self._building[formula.sha256] = SlicedTask(
                self._make(formula), clock=self._clock
            )
        state = task.advance(self._slice_ms)
        if state is TaskState.RUNNING:
            return None
        del self._building[formula.sha256]
        value = task.result
        self._done[formula.sha256] = value
        return value

    @property
    def pending(self) -> bool:
        """True while some build is in progress (the loop must not sleep through it)."""
        return bool(self._building)

    def drop(self) -> None:
        for task in self._building.values():
            task.cancel()
        self._building.clear()
        self._done.clear()


class IndexCache(SlicedCache[UnitIndex]):
    """The :class:`~cubeproof.cnf.unit.UnitIndex` of each formula."""

    def __init__(self, *, slice_ms: int = 5, clock: Callable[[], int] = time.monotonic_ns) -> None:
        super().__init__(build_index_steps, slice_ms=slice_ms, clock=clock)


class EngineCache(SlicedCache[Engine]):
    """The lookahead reference :class:`~cubeproof.split.lookahead.Engine` of each formula."""

    def __init__(self, *, slice_ms: int = 5, clock: Callable[[], int] = time.monotonic_ns) -> None:
        super().__init__(build_engine_steps, slice_ms=slice_ms, clock=clock)
