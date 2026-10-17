"""One splitter run as a nonblocking task (specification §8.1, §9.1, §9.3).

:class:`SplitTask` asks ``lookahead-v1`` for the variables of a node that needs a split and
never blocks the event loop:

- with a native helper (``machinery.helper``): one supervised helper process; its failure of any
  kind (timeout, crash, bad exit, invalid output) is answered by the **lowest eligible
  variables** under the validated parent propagation, recorded in the choice info (specification
  §9.1);
- without one: the Python reference as a step generator, in time slices, on the formula's
  shared engine (built in slices by :class:`~cubeproof.coordinator.indexes.EngineCache`).

The task ends with a :class:`~cubeproof.split.choice.SplitChoice`; the coordinator turns it
into an action with :func:`~cubeproof.coordinator.scheduler_select.decide_split`. Computing the
lowest-eligible fallback builds the formula's unit index in one call (the one place where a
splitter step is not sliced; it only happens after a helper failure).
"""

from __future__ import annotations

import time
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

from cubeproof.base.errors import ToolError
from cubeproof.cnf.bundle import Bundle
from cubeproof.coordinator.indexes import EngineCache
from cubeproof.split.choice import Budget, SplitChoice, check_pool
from cubeproof.split.helper import (
    DEFAULT_MEMORY_BYTES,
    Helper,
    HelperJob,
    HelperRequest,
    LookaheadSplitter,
    start_helper,
)
from cubeproof.split.lookahead import lookahead_steps
from cubeproof.tools.process import Supervisor
from cubeproof.tools.unit_helper import SlicedTask, TaskState

__all__ = ["SplitTask"]


def _tagged(choice: SplitChoice, implementation: str, **more: Any) -> SplitChoice:
    info = choice.info_dict()
    info["implementation"] = implementation
    info.update(more)
    return SplitChoice.make(choice.variables, choice.status, info)


class SplitTask:
    """The choice of split variables for one node (module doc)."""

    def __init__(
        self,
        *,
        bundle: Bundle,
        cube: Sequence[int],
        k: int,
        pool: Sequence[int] | None,
        budget: Budget,
        engines: EngineCache,
        supervisor: Supervisor,
        helper: Helper | None,
        work: Path,
        clock: Callable[[], int] = time.monotonic_ns,
        helper_memory_bytes: int = DEFAULT_MEMORY_BYTES,
    ) -> None:
        self.bundle = bundle
        self.cube = tuple(cube)
        self.k = k
        self.pool = check_pool(pool, bundle.formula.variables)
        self.budget = budget
        self._engines = engines
        self._supervisor = supervisor
        self._helper = helper
        self._work = work
        self._clock = clock
        self._memory = helper_memory_bytes
        self._job: HelperJob | None = None
        self._steps: SlicedTask[SplitChoice] | None = None
        self._splitter = LookaheadSplitter(
            helper=helper,
            supervisor=supervisor if helper is not None else None,
            workdir=work if helper is not None else None,
        )
        self.choice: SplitChoice | None = None
        self.cancelled = False

    @property
    def finished(self) -> bool:
        return self.choice is not None or self.cancelled

    @property
    def processes(self) -> int:
        """1 while a helper process runs."""
        return 1 if self._job is not None and not self._job.finished else 0

    def advance(self, slice_ms: int = 5) -> TaskState:
        """Do the bounded work that is due; the choice is set when the task finishes."""
        if self.finished:
            return TaskState.DONE
        if self._helper is not None:
            self._advance_helper()
        else:
            self._advance_reference(slice_ms)
        return TaskState.DONE if self.finished else TaskState.RUNNING

    def _advance_helper(self) -> None:
        helper = self._helper
        assert helper is not None
        formula = self.bundle.formula
        if self._job is None:
            request = HelperRequest(
                formula_path=str((Path(self.bundle.directory) / "formula.cnf").resolve()),
                formula_sha256=formula.sha256,
                variables=formula.variables,
                cube=self.cube,
                k=self.k,
                pool=self.pool,
                probe_limit=self.budget.probe_limit,
                wall_ms=self.budget.wall_ms,
            )
            self._job = start_helper(
                self._supervisor, helper, request, self._work, memory_bytes=self._memory
            )
            return
        if not self._job.finished:
            return
        try:
            choice = self._job.result()
        except ToolError as error:
            fallback = self._splitter.fallback(self.bundle, self.cube, self.k, self.pool, error)
            self.choice = fallback
            return
        self.choice = _tagged(choice, "helper", helper=helper.record())

    def _advance_reference(self, slice_ms: int) -> None:
        formula = self.bundle.formula
        if self._steps is None:
            engine = self._engines.get(formula)
            if engine is None:
                return
            self._steps = SlicedTask(
                lookahead_steps(
                    formula,
                    self.cube,
                    self.k,
                    self.pool,
                    self.budget,
                    engine=engine,
                    clock=self._clock,
                ),
                clock=self._clock,
            )
        if self._steps.advance(slice_ms) is TaskState.RUNNING:
            return
        self.choice = _tagged(self._steps.result, "python-reference")

    def cancel(self, grace_ms: int) -> None:
        """Abandon the run: stop the helper, drop the generator. No choice follows."""
        if self.finished:
            return
        self.cancelled = True
        if self._job is not None and not self._job.finished:
            self._supervisor.cancel(self._job.process, grace_ms)
        if self._steps is not None:
            self._steps.cancel()
