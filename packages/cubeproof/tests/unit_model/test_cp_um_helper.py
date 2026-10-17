"""The bounded helper adapter: slices, budgets and the unit route (specification §8.1, §9.1)."""

from __future__ import annotations

import gc
import time
from collections.abc import Generator

import pytest
from cp_um_support import formula, oracle_accepts

from cubeproof.cnf import unit as up
from cubeproof.cnf.model import propagated_model
from cubeproof.contracts.enums import ModelError
from cubeproof.tools import unit_helper as uh


class FakeClock:
    """Monotonic nanoseconds advancing by ``tick_ms`` on every reading."""

    def __init__(self, tick_ms: int) -> None:
        self.now = 0
        self.tick = tick_ms * 1_000_000
        self.readings = 0

    def __call__(self) -> int:
        self.now += self.tick
        self.readings += 1
        return self.now


def counter(steps: int, log: list[str]) -> Generator[None, None, int]:
    try:
        for _ in range(steps):
            yield
        return steps
    finally:
        log.append("closed")


def test_a_slice_ends_after_its_time_and_the_task_resumes() -> None:
    log: list[str] = []
    clock = FakeClock(1)
    task = uh.SlicedTask(counter(10, log), clock=clock)
    assert task.advance(3) is uh.TaskState.RUNNING
    assert task.steps == 3
    assert task.advance(3) is uh.TaskState.RUNNING
    assert task.steps == 6
    while task.advance(3) is uh.TaskState.RUNNING:
        pass
    assert task.state is uh.TaskState.DONE and task.result == 10
    assert task.steps == 11  # ten yields and the final return
    assert task.active_ns == 11 * 1_000_000
    assert task.advance(3) is uh.TaskState.DONE  # finished tasks stay finished
    assert log == ["closed"]


def test_an_active_time_budget_ends_the_task_without_a_result() -> None:
    log: list[str] = []
    task = uh.SlicedTask(counter(1000, log), budget_ms=5, clock=FakeClock(1))
    states = [task.advance(2) for _ in range(5)]
    assert states[-1] is uh.TaskState.BUDGET
    assert task.steps == 5 and log == ["closed"]
    with pytest.raises(RuntimeError, match="budget"):
        _ = task.result


def test_a_step_budget_is_deterministic() -> None:
    log: list[str] = []
    task = uh.SlicedTask(counter(1000, log), max_steps=7, clock=FakeClock(0))
    # a clock that never advances: the slice never ends, only the step budget does
    assert task.advance(1) is uh.TaskState.BUDGET
    assert task.steps == 7 and log == ["closed"]


def test_a_failing_step_fails_the_task_and_reraises() -> None:
    def broken() -> Generator[None, None, int]:
        yield
        raise MemoryError("synthetic")

    task = uh.SlicedTask(broken(), clock=FakeClock(0))
    with pytest.raises(MemoryError):
        task.advance(1)
    assert task.state is uh.TaskState.FAILED
    assert isinstance(task.error, MemoryError)
    assert task.advance(1) is uh.TaskState.FAILED
    with pytest.raises(RuntimeError):
        _ = task.result


def test_cancel_closes_the_generator() -> None:
    log: list[str] = []
    task = uh.SlicedTask(counter(100, log), clock=FakeClock(1))
    task.advance(2)
    task.cancel()
    assert task.state is uh.TaskState.BUDGET and log == ["closed"]


def test_arguments_are_validated() -> None:
    for kwargs in ({"budget_ms": 0}, {"max_steps": -1}, {"budget_ms": 1.5}, {"max_steps": True}):
        with pytest.raises(ValueError):
            uh.SlicedTask(counter(1, []), **kwargs)
    task = uh.SlicedTask(counter(1, []))
    for bad in (0, -5, 2.0):
        with pytest.raises(ValueError):
            task.advance(bad)  # type: ignore[arg-type]


def run(task: uh.SlicedTask[uh.UnitAnswer]) -> uh.UnitAnswer:
    while task.advance(5) is uh.TaskState.RUNNING:
        pass
    return task.result


def test_unit_route_proof() -> None:
    f = formula(3, [(1, 2), (-1, 3), (-2, -3)])
    answer = run(uh.unit_task(f, (1, 2), chunk=1))
    assert answer.route is uh.UnitRoute.PROOF and answer.model is None
    assert answer.proof == b"6 0 4 5 2 3 0\n"
    assert answer.proof is not None and oracle_accepts(f, (1, 2), answer.proof)


def test_unit_route_model() -> None:
    f = formula(3, [(1, 2), (-1, 3), (-2, -3)])
    answer = run(uh.unit_task(f, (-3,)))
    assert answer.route is uh.UnitRoute.MODEL and answer.proof is None
    assert answer.model is not None
    assert (answer.model.assignment, answer.model.model_error) == ("Ag==", None)
    empty = run(uh.unit_task(formula(0, []), ()))
    assert empty.route is uh.UnitRoute.MODEL
    assert empty.model is not None and empty.model.assignment == ""


def test_unit_route_undecided_with_a_shared_index() -> None:
    f = formula(4, [(-1, 2), (3, 4)])
    index = up.build_index(f)
    answer = run(uh.unit_task(f, (1,), index=index))
    assert answer.route is uh.UnitRoute.UNDECIDED
    assert (answer.proof, answer.model) == (None, None)
    assert answer.propagation.assigned() == frozenset({1, 2})
    with pytest.raises(ValueError, match="another formula"):
        run(uh.unit_task(formula(4, [(1,)]), (), index=index))


def test_unit_answer_invariants() -> None:
    f = formula(1, [(1,)])
    sat = up.propagate(up.build_index(f), ())
    conflict = up.propagate(up.build_index(f), (-1,))
    partial = up.propagate(up.build_index(formula(2, [(1,)])), ())
    model = uh.unit_steps(f, ())
    good = up.drive(model)
    assert good.model is not None and good.model.model_error is None
    for args in [
        (uh.UnitRoute.PROOF, sat, b"x", None),
        (uh.UnitRoute.PROOF, conflict, None, None),
        (uh.UnitRoute.MODEL, sat, None, None),
        (uh.UnitRoute.MODEL, partial, None, good.model),
        (uh.UnitRoute.UNDECIDED, sat, None, None),
        (uh.UnitRoute.UNDECIDED, conflict, None, None),
        (uh.UnitRoute.UNDECIDED, partial, b"x", None),
    ]:
        with pytest.raises(ValueError):
            uh.UnitAnswer(*args)


def test_a_violated_propagated_model_is_still_reported() -> None:
    """The model route never assumes success: evaluation decides (specification §4.8, §9.1)."""
    f = formula(1, [(1,)])
    forged = up.Propagation(f.sha256, 1, 1, (), (-1,), (1,), None)
    answer = uh.UnitAnswer(
        uh.UnitRoute.MODEL,
        forged,
        model=propagated_model(f, forged),
    )
    assert answer.model is not None and answer.model.model_error is ModelError.VIOLATED


def test_large_propagation_never_monopolizes_the_loop() -> None:
    """Specification §8.1: ordinary tick latency p99 <= 100 ms, maximum <= 1 s, here for one long
    chain of 200 000 implications (index build, propagation and model evaluation in slices).

    The limits apply to the work one slice does, so every ``advance`` is measured in CPU
    time of the calling thread (``time.thread_time``; the steps run synchronously in this
    thread). OS scheduling delays on a shared host are excluded from them. A loose
    wall-clock bound (maximum <= 5 s per slice, well above ordinary scheduling delays) still
    fails a slice that blocks the loop without using CPU.

    The objects that exist before the measurement are frozen (``gc.freeze``) and unfrozen
    afterwards. These are the test runner's heap (collected items, earlier tests) and
    the input formula. Full collections then do not traverse them, so their cost is not
    charged to a slice; in a large pytest process it reached 0.1 s per collection. Every
    object the slices allocate is still tracked, collected and counted in slice CPU time."""
    n = 200_000
    f = formula(n, [(-i, i + 1) for i in range(1, n)])
    gc.collect()
    gc.freeze()
    try:
        task = uh.unit_task(f, (1,))
        cpu: list[float] = []
        wall_max = 0.0
        while True:
            wall_start = time.perf_counter()
            cpu_start = time.thread_time()
            state = task.advance(20)
            cpu.append(time.thread_time() - cpu_start)
            wall_max = max(wall_max, time.perf_counter() - wall_start)
            if state is not uh.TaskState.RUNNING:
                break
    finally:
        gc.unfreeze()
    assert state is uh.TaskState.DONE
    answer = task.result
    assert answer.route is uh.UnitRoute.MODEL
    assert answer.model is not None and answer.model.model_error is None
    cpu.sort()
    p99 = cpu[int(0.99 * (len(cpu) - 1))]
    assert len(cpu) > 10
    assert p99 <= 0.100, (p99, cpu[-5:])
    assert cpu[-1] <= 1.0, cpu[-5:]
    assert wall_max <= 5.0, (wall_max, cpu[-5:])
