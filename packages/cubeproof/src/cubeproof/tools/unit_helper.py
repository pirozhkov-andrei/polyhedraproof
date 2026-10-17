"""Bounded helper adapter: unit propagation and model evaluation in time slices (specification §8.1,
§9.1).

Arbitrary-CNF propagation must not block the coordinator's event loop (specification §8.1). The pure
work of :mod:`cubeproof.cnf.unit` and :mod:`cubeproof.cnf.model` is written as generators
that yield after a bounded amount of work; :class:`SlicedTask` drives such a generator for
at most one time slice per call on a monotonic clock, so the loop can drain children, run
timers and handle cancellation in between. A task may carry a budget (active time and/or
steps); when it is used up the task ends in state ``budget``, which the caller treats as a
resource condition (specification §9.1: block the node, never the protocol), not as a result.

:func:`unit_steps` is the unit route of one node (specification §6.1 stage 2, 9.1):

- conflict -> route ``proof``: the unit-v1 LRAT bytes, to be written as the attempt's proof
  file and checked by the pinned checker; this is a proof *candidate*, never a verdict;
- every variable assigned without conflict -> route ``model``: the complete assignment
  evaluated against every clause and cube unit (:func:`cubeproof.cnf.model.propagated_model`),
  recorded through the ordinary model path (route unit, solver null);
- otherwise -> route ``undecided``: the propagation (e.g. the assigned variables a splitter
  excludes, specification §9.1); the node needs the CDCL route or a split.

Reserving CPU for an active helper (1000 milli-CPU, specification §8.2) is the scheduler's business;
this module only bounds how long one call may run.
"""

from __future__ import annotations

import enum
import time
from collections.abc import Callable, Generator, Sequence
from dataclasses import dataclass
from typing import Generic, TypeVar, cast

from cubeproof.cnf.dimacs import Formula
from cubeproof.cnf.model import ModelResult, propagated_model_steps
from cubeproof.cnf.unit import (
    DEFAULT_CHUNK,
    Propagation,
    UnitIndex,
    build_index_steps,
    propagate_steps,
    unit_proof,
)

_T = TypeVar("_T")

#: Default length of one slice: well below the 100 ms tick latency target of specification §8.1.
DEFAULT_SLICE_MS = 20


class TaskState(str, enum.Enum):
    RUNNING = "running"
    DONE = "done"
    BUDGET = "budget"
    FAILED = "failed"


class SlicedTask(Generic[_T]):
    """Drive a step generator in bounded slices.

    ``budget_ms`` bounds the total active time spent inside :meth:`advance`, ``max_steps``
    the number of generator steps (deterministic, for tests and reproducible bounds); either
    may be None. ``clock`` returns monotonic nanoseconds.
    """

    def __init__(
        self,
        steps: Generator[None, None, _T],
        *,
        budget_ms: int | None = None,
        max_steps: int | None = None,
        clock: Callable[[], int] = time.monotonic_ns,
    ) -> None:
        for name, value in (("budget_ms", budget_ms), ("max_steps", max_steps)):
            if value is not None and (type(value) is not int or value < 1):
                raise ValueError(f"{name} must be a positive integer or None")
        self._steps = steps
        self._budget_ns = None if budget_ms is None else budget_ms * 1_000_000
        self._max_steps = max_steps
        self._clock = clock
        self._state = TaskState.RUNNING
        self._result: _T | None = None
        self._error: BaseException | None = None
        self.active_ns = 0
        self.steps = 0

    @property
    def state(self) -> TaskState:
        return self._state

    @property
    def result(self) -> _T:
        """The value of a finished task; ``RuntimeError`` in any other state."""
        if self._state is not TaskState.DONE:
            raise RuntimeError(f"the task is {self._state.value}, not done")
        return cast(_T, self._result)

    @property
    def error(self) -> BaseException | None:
        return self._error

    def _over_budget(self) -> bool:
        if self._max_steps is not None and self.steps >= self._max_steps:
            return True
        return self._budget_ns is not None and self.active_ns >= self._budget_ns

    def advance(self, slice_ms: int = DEFAULT_SLICE_MS) -> TaskState:
        """Run steps until the task ends or ``slice_ms`` elapsed; return the new state.

        A step raising an exception ends the task in state ``failed`` and re-raises.
        """
        if type(slice_ms) is not int or slice_ms < 1:
            raise ValueError("slice_ms must be a positive integer")
        if self._state is not TaskState.RUNNING:
            return self._state
        start = self._clock()
        end = start + slice_ms * 1_000_000
        now = start
        try:
            while True:
                if self._over_budget():
                    self._state = TaskState.BUDGET
                    self._steps.close()
                    break
                try:
                    next(self._steps)
                except StopIteration as stop:
                    self._result = stop.value
                    self._state = TaskState.DONE
                    break
                finally:
                    previous, now = now, self._clock()
                    self.active_ns += now - previous
                    self.steps += 1
                if now >= end:
                    break
        except BaseException as error:
            self._state = TaskState.FAILED
            self._error = error
            raise
        return self._state

    def cancel(self) -> None:
        """Stop a running task; it ends in state ``budget`` without a result."""
        if self._state is TaskState.RUNNING:
            self._steps.close()
            self._state = TaskState.BUDGET


class UnitRoute(str, enum.Enum):
    PROOF = "proof"
    MODEL = "model"
    UNDECIDED = "undecided"


@dataclass(frozen=True)
class UnitAnswer:
    """What unit propagation offers for one node (module docstring)."""

    route: UnitRoute
    propagation: Propagation
    proof: bytes | None = None
    model: ModelResult | None = None

    def __post_init__(self) -> None:
        if (self.route is UnitRoute.PROOF) != (self.proof is not None):
            raise ValueError("a proof exactly for route proof")
        if (self.route is UnitRoute.MODEL) != (self.model is not None):
            raise ValueError("a model result exactly for route model")
        if (self.route is UnitRoute.PROOF) != self.propagation.conflict:
            raise ValueError("route proof exactly for a conflict")
        if (self.route is UnitRoute.MODEL) != self.propagation.complete:
            raise ValueError("route model exactly for a complete propagation")


def unit_steps(
    formula: Formula,
    cube: Sequence[int],
    *,
    index: UnitIndex | None = None,
    chunk: int = DEFAULT_CHUNK,
) -> Generator[None, None, UnitAnswer]:
    """The unit route of node (F, C) as a step generator (module docstring).

    ``index`` may be a prebuilt :class:`UnitIndex` of ``formula`` (shared by many nodes);
    otherwise it is built inside the same bounded steps.
    """
    if index is None:
        index = yield from build_index_steps(formula, chunk=chunk)
    elif index.formula_sha256 != formula.sha256:
        raise ValueError("the index belongs to another formula")
    propagation = yield from propagate_steps(index, cube, chunk=chunk)
    if propagation.conflict:
        return UnitAnswer(UnitRoute.PROOF, propagation, proof=unit_proof(index, propagation))
    if propagation.complete:
        model = yield from propagated_model_steps(formula, propagation, chunk=chunk)
        return UnitAnswer(UnitRoute.MODEL, propagation, model=model)
    return UnitAnswer(UnitRoute.UNDECIDED, propagation)


def unit_task(
    formula: Formula,
    cube: Sequence[int],
    *,
    index: UnitIndex | None = None,
    budget_ms: int | None = None,
    max_steps: int | None = None,
    chunk: int = DEFAULT_CHUNK,
    clock: Callable[[], int] = time.monotonic_ns,
) -> SlicedTask[UnitAnswer]:
    """A :class:`SlicedTask` running :func:`unit_steps`."""
    return SlicedTask(
        unit_steps(formula, cube, index=index, chunk=chunk),
        budget_ms=budget_ms,
        max_steps=max_steps,
        clock=clock,
    )
