"""Bounded ticks: fair slicing and tick-latency statistics (specification §8.1)."""

from __future__ import annotations

import pytest

from cubeproof.coordinator.scheduler_loop import SliceRotor, TickStats


class Clock:
    def __init__(self) -> None:
        self.now = 0

    def __call__(self) -> int:
        return self.now


class Task:
    """A sliceable task that costs ``cost_ms`` of fake time per slice."""

    def __init__(self, clock: Clock, cost_ms: int = 5, slices: int | None = None) -> None:
        self.clock, self.cost_ms, self.left = clock, cost_ms, slices
        self.served = 0

    @property
    def finished(self) -> bool:
        return self.left is not None and self.left <= 0

    def advance(self, slice_ms: int = 20) -> object:
        self.served += 1
        self.clock.now += self.cost_ms * 1_000_000
        if self.left is not None:
            self.left -= 1
        return None


def test_a_tick_runs_slices_until_its_budget_is_spent() -> None:
    clock = Clock()
    tasks = [Task(clock) for _ in range(10)]
    rotor = SliceRotor(clock=clock)
    assert rotor.run(tasks, budget_ms=20, slice_ms=5) == 4
    assert clock.now == 20 * 1_000_000
    assert sum(t.served for t in tasks) == 4


def test_the_overshoot_is_at_most_one_slice() -> None:
    clock = Clock()
    tasks = [Task(clock, cost_ms=7)]
    assert SliceRotor(clock=clock).run(tasks, budget_ms=10, slice_ms=5) == 2
    assert clock.now == 14 * 1_000_000


def test_every_task_is_served_in_turn_across_ticks() -> None:
    clock = Clock()
    tasks = [Task(clock) for _ in range(10)]
    rotor = SliceRotor(clock=clock)
    for _ in range(10):
        rotor.run(tasks, budget_ms=20)
    assert [t.served for t in tasks] == [4] * 10  # 40 slices over 10 tasks


def test_a_tiny_budget_still_serves_one_task_and_rotates() -> None:
    clock = Clock()
    tasks = [Task(clock) for _ in range(3)]
    rotor = SliceRotor(clock=clock)
    for _ in range(6):
        assert rotor.run(tasks, budget_ms=0) == 1
    assert [t.served for t in tasks] == [2, 2, 2]


def test_finished_tasks_are_skipped_and_all_finished_ends_the_tick() -> None:
    clock = Clock()
    tasks = [Task(clock, slices=0), Task(clock), Task(clock, slices=0)]
    rotor = SliceRotor(clock=clock)
    assert rotor.run(tasks, budget_ms=10) == 2
    assert [t.served for t in tasks] == [0, 2, 0]
    assert rotor.run([Task(clock, slices=0)], budget_ms=10) == 0
    assert rotor.run([], budget_ms=10) == 0


def test_a_cursor_past_a_shrunk_task_list_wraps() -> None:
    clock = Clock()
    many = [Task(clock) for _ in range(8)]
    rotor = SliceRotor(clock=clock)
    rotor.run(many, budget_ms=30)
    assert rotor.run(many[:2], budget_ms=10) == 2


def test_invalid_budgets_are_refused() -> None:
    rotor = SliceRotor()
    for budget, slice_ms in ((-1, 5), (5, 0), (True, 5)):
        with pytest.raises(ValueError):
            rotor.run([], budget_ms=budget, slice_ms=slice_ms)


def test_tick_statistics_use_the_nearest_rank_percentile() -> None:
    stats = TickStats()
    for ms in range(1, 101):
        stats.record(ms * 1_000_000)
    assert stats.percentile_ms(50) == 50.0
    assert stats.percentile_ms(99) == 99.0
    assert stats.percentile_ms(100) == 100.0
    assert stats.maximum_ms == 100.0
    assert stats.report() == {"ticks": 100, "p50_ms": 50.0, "p99_ms": 99.0, "max_ms": 100.0}


def test_the_percentile_is_the_nearest_rank_for_a_count_that_is_not_a_multiple_of_100() -> None:
    stats = TickStats()
    for ms in range(1, 11):
        stats.record(ms * 1_000_000)
    assert stats.percentile_ms(99) == 10.0  # ceil(9.9) = 10, not 9
    assert stats.percentile_ms(50) == 5.0
    assert stats.percentile_ms(51) == 6.0


def test_the_bounds_are_inclusive() -> None:
    stats = TickStats()
    for _ in range(100):
        stats.record(100 * 1_000_000)
    stats.record(1000 * 1_000_000)
    assert stats.percentile_ms(99) == 100.0 and stats.maximum_ms == 1000.0
    assert stats.within_bounds()
    assert not stats.within_bounds(p99_ms=99.9)
    assert not stats.within_bounds(maximum_ms=999.9)


def test_the_acceptance_bounds_of_the_specification() -> None:
    stats = TickStats()
    for _ in range(989):
        stats.record(10 * 1_000_000)
    for _ in range(11):
        stats.record(900 * 1_000_000)
    # more than 1 % of the ticks are slow: the p99 sits on the slow value
    assert stats.percentile_ms(99) == 900.0 and not stats.within_bounds()
    good = TickStats()
    for _ in range(990):
        good.record(10 * 1_000_000)
    for _ in range(10):
        good.record(900 * 1_000_000)
    assert good.percentile_ms(99) == 10.0 and good.within_bounds()
    stalled = TickStats()
    for _ in range(3000):
        stalled.record(10 * 1_000_000)
    stalled.record(1001 * 1_000_000)  # one stall above a second fails the maximum only
    assert stalled.percentile_ms(99) == 10.0 and not stalled.within_bounds()
    assert stalled.within_bounds(maximum_ms=2000)


def test_statistics_keep_a_bounded_window_but_remember_the_maximum() -> None:
    stats = TickStats(keep=10)
    stats.record(5_000_000_000)
    for _ in range(50):
        stats.record(1_000_000)
    assert stats.count == 51 and stats.maximum_ms == 5000.0
    assert stats.percentile_ms(99) == 1.0  # the stall left the window
    assert TickStats().percentile_ms(99) == 0.0
    with pytest.raises(ValueError):
        TickStats().record(-1)
    with pytest.raises(ValueError):
        TickStats().percentile_ms(0)
