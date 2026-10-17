"""Launch priorities, check draining, impossible tasks, stalls and liveness (specification §8.4)."""

from __future__ import annotations

import random
from collections.abc import Iterator

import pytest

from cubeproof.coordinator.ledger import CPU, MEMORY, Measure, Need, ResourceBook, disk
from cubeproof.coordinator.scheduler import (
    Candidate,
    Scheduler,
    SchedulerError,
    Stage,
)

G = "work"
H1 = "11" * 32
H2 = "22" * 32


def book(cpu: int = 4000, memory: int = 1000, work: int = 1000) -> ResourceBook:
    return ResourceBook({CPU: cpu, MEMORY: memory, disk(G): work})


def need(cpu: int = 1000, memory: int = 100, work: int = 0) -> Need:
    return Need(cpu, memory, ((G, work),) if work else ())


def cand(
    task: str,
    stage: Stage,
    seq: int,
    n: Need | None = None,
    *,
    node: tuple[int, ...] | None = None,
    holds: bool = False,
) -> Candidate:
    key = None if node is None else (H1, node)
    return Candidate(task, stage, key, n or need(), seq, holds)


class Clock:
    def __init__(self) -> None:
        self.now = 0

    def __call__(self) -> int:
        return self.now

    def advance_ms(self, ms: int) -> None:
        self.now += ms * 1_000_000


def ids(plan) -> list[str]:  # type: ignore[no-untyped-def]
    return [launch.candidate.task_id for launch in plan.launches]


# -- priorities -------------------------------------------------------------------------------


def test_checks_before_splits_before_solves() -> None:
    b = book(cpu=2000)  # room for two tasks
    s = Scheduler(b)
    plan = s.plan(
        checks=[cand("c", Stage.CHECK, 1)],
        splits=[cand("p", Stage.SPLIT, 1)],
        solves=[cand("s", Stage.SOLVE, 1)],
    )
    assert ids(plan) == ["c", "p"]
    assert plan.reserved_check is None and plan.stall is None and not plan.impossible
    assert b.outstanding(CPU) == 2000  # launching is reserving


def test_within_a_stage_the_oldest_comes_first() -> None:
    b = book(cpu=3000)
    plan = Scheduler(b).plan(
        checks=[cand("old", Stage.CHECK, 1), cand("new", Stage.CHECK, 2)],
        solves=[cand("s1", Stage.SOLVE, 1), cand("s2", Stage.SOLVE, 2)],
    )
    assert ids(plan) == ["old", "new", "s1"]


def test_every_launch_takes_a_reservation_of_its_stage() -> None:
    b = book()
    plan = Scheduler(b).plan(solves=[cand("s", Stage.SOLVE, 1, need(1000, 300, 50))])
    (launch,) = plan.launches
    assert launch.reservation.stage == "solve"
    assert b.get("s") == launch.reservation
    assert b.outstanding(MEMORY) == 300 and b.outstanding(disk(G)) == 50


def test_a_task_that_does_not_fit_now_waits_and_a_later_one_that_fits_goes() -> None:
    b = book(memory=500)
    plan = Scheduler(b).plan(
        solves=[
            cand("big", Stage.SOLVE, 1, need(1000, 450)),
            cand("big2", Stage.SOLVE, 2, need(1000, 450)),
            cand("small", Stage.SOLVE, 3, need(1000, 40)),
        ]
    )
    assert ids(plan) == ["big", "small"]
    assert any("big2" in reason and "waits" in reason for reason in plan.reasons)


def test_measured_headroom_limits_launches() -> None:
    b = book()
    plan = Scheduler(b).plan(
        solves=[
            cand("s1", Stage.SOLVE, 1, need(1000, 400)),
            cand("s2", Stage.SOLVE, 2, need(1000, 400)),
        ],
        measures={MEMORY: Measure(600, 0)},
    )
    assert ids(plan) == ["s1"]  # 600 of headroom minus 400 not yet resident leaves 200 < 400


# -- check draining ------------------------------------------------------------------------------


def test_the_oldest_check_that_fits_idle_but_not_now_blocks_new_solves_and_splits() -> None:
    b = book(memory=1000)
    b.reserve("running", "solve", need(1000, 700))
    s = Scheduler(b)
    plan = s.plan(
        checks=[cand("c0", Stage.CHECK, 1, need(1000, 600))],
        splits=[cand("p", Stage.SPLIT, 1, need(1000, 10))],
        solves=[cand("s", Stage.SOLVE, 1, need(1000, 10))],
        active=1,
    )
    assert plan.launches == () and not plan.impossible
    assert plan.reserved_check is not None and plan.reserved_check.task_id == "c0"
    assert plan.stall is None
    assert any("draining for check c0" in reason for reason in plan.reasons)
    b.release("running")  # the running task finishes: the reserved check goes first
    plan = s.plan(
        checks=[cand("c0", Stage.CHECK, 1, need(1000, 600))],
        solves=[cand("s", Stage.SOLVE, 1, need(1000, 10))],
    )
    assert ids(plan) == ["c0", "s"]
    assert plan.reserved_check is None


def test_a_younger_check_may_not_delay_the_reserved_check() -> None:
    b = book(memory=1000)
    b.reserve("running", "solve", need(1000, 700))
    plan = Scheduler(b).plan(
        checks=[
            cand("c0", Stage.CHECK, 1, need(1000, 600)),
            cand("c1", Stage.CHECK, 2, need(1000, 100)),
        ],
        active=1,
    )
    assert plan.launches == ()  # c1 fits (300 free) but would take memory c0 is waiting for
    assert plan.reserved_check is not None and plan.reserved_check.task_id == "c0"


def test_a_younger_check_that_leaves_the_reserved_checks_dimensions_intact_may_start() -> None:
    """c0 waits for memory only; c1 touches cpu and disk, never memory."""
    b = book(cpu=4000, memory=1000)
    b.reserve("running", "solve", need(1000, 700))
    plan = Scheduler(b).plan(
        checks=[
            cand("c0", Stage.CHECK, 1, need(1000, 600)),
            cand("c1", Stage.CHECK, 2, Need(1000, 0, ((G, 5),))),
        ],
        active=1,
    )
    assert ids(plan) == ["c1"]
    assert plan.reserved_check is not None and plan.reserved_check.task_id == "c0"


def test_a_younger_check_may_start_while_the_reserved_one_still_has_its_room() -> None:
    """The reserved check misses cpu (3 of 4 busy, needs 2000); a memory-only young check
    leaves the cpu it waits for alone."""
    b = book(cpu=4000, memory=1000)
    for index in range(3):
        b.reserve(f"r{index}", "solve", need(1000, 10))
    plan = Scheduler(b).plan(
        checks=[
            cand("c0", Stage.CHECK, 1, Need(2000, 10)),
            cand("c1", Stage.CHECK, 2, Need(0, 100)),
            cand("c2", Stage.CHECK, 3, Need(1000, 100)),
        ],
        active=3,
    )
    assert ids(plan) == ["c1"]  # c2 would take the cpu that c0 needs


def test_a_queued_check_holding_its_disk_asks_only_for_cpu_and_memory() -> None:
    b = book(work=100)
    b.reserve("c", "sealed", Need(0, 0, ((G, 100),)))
    full = Need(1000, 200, ((G, 100),))
    plan = Scheduler(b).plan(checks=[cand("c", Stage.CHECK, 1, full, holds=True)])
    (launch,) = plan.launches
    assert launch.reservation.stage == "check" and launch.reservation.need == full
    assert (b.outstanding(CPU), b.outstanding(MEMORY), b.outstanding(disk(G))) == (1000, 200, 100)
    b.check()


def test_a_waiting_check_does_not_hold_back_the_others_when_it_misses_only_a_bound() -> None:
    b = book(memory=100)
    b.reserve("c0", "sealed", Need(0, 0, ((G, 10),)))
    plan = Scheduler(b).plan(
        checks=[cand("c0", Stage.CHECK, 1, Need(1000, 90, ((G, 10),)), holds=True)],
    )
    assert ids(plan) == ["c0"]


# -- impossible tasks ---------------------------------------------------------------------------


def test_a_task_that_cannot_fit_an_idle_machine_is_reported_at_once() -> None:
    b = book(memory=1000)
    plan = Scheduler(b).plan(
        checks=[cand("c", Stage.CHECK, 1, need(1000, 1001))],
        splits=[cand("p", Stage.SPLIT, 1, need(1000, 2000))],
        solves=[cand("s", Stage.SOLVE, 1, need(5000, 1)), cand("ok", Stage.SOLVE, 2)],
    )
    rules = {i.candidate.task_id: i.rule for i in plan.impossible}
    assert rules == {"c": "check_exhausted", "p": "resource_blocked", "s": "resource_blocked"}
    assert all(i.shortfall.reason == "exceeds the capacity" for i in plan.impossible)
    assert ids(plan) == ["ok"]  # an impossible check does not drain the machine
    assert plan.reserved_check is None


def test_impossible_is_judged_against_the_initial_ceiling_not_a_lowered_total() -> None:
    b = book(memory=1000)
    b.set_total(MEMORY, 100)
    plan = Scheduler(b).plan(solves=[cand("s", Stage.SOLVE, 1, need(1000, 500))])
    assert not plan.impossible and plan.launches == ()


# -- stalls --------------------------------------------------------------------------------------


def test_nothing_running_and_nothing_launchable_stalls_after_the_patience() -> None:
    b = book(memory=1000)
    b.set_total(MEMORY, 50)  # pressure lowered the budget; nothing runs that could free it
    clock = Clock()
    s = Scheduler(b, clock=clock, stall_patience_ms=30_000)
    queue = [cand("s", Stage.SOLVE, 1, need(1000, 500), node=(1,))]
    plan = s.plan(solves=queue)
    assert plan.stall is None  # patience
    clock.advance_ms(29_999)
    assert s.plan(solves=queue).stall is None
    clock.advance_ms(1)
    stall = s.plan(solves=queue).stall
    assert stall is not None
    assert stall.nodes == ((H1, (1,)),)
    assert stall.waited_ms == 30_000
    assert stall.capacities[MEMORY] == {"total": 50, "ceiling": 1000, "outstanding": 0}
    assert any("memory" in line and "s" in line for line in stall.requirements)


def test_running_work_prevents_a_stall_and_resets_the_patience() -> None:
    b = book(memory=1000)
    b.reserve("running", "solve", need(1000, 900))
    clock = Clock()
    s = Scheduler(b, clock=clock, stall_patience_ms=10)
    queue = [cand("s", Stage.SOLVE, 1, need(1000, 500))]
    for _ in range(3):
        clock.advance_ms(100)
        assert s.plan(solves=queue, active=1).stall is None
    b.release("running")
    plan = s.plan(solves=queue)
    assert ids(plan) == ["s"] and plan.stall is None


def test_a_plan_that_starts_something_is_never_a_stall() -> None:
    b = book(memory=1000)
    s = Scheduler(b, stall_patience_ms=0)
    plan = s.plan(
        solves=[
            cand("fits", Stage.SOLVE, 1, need(1000, 900)),
            cand("waits", Stage.SOLVE, 2, need(1000, 900)),
        ]
    )
    assert ids(plan) == ["fits"] and plan.stall is None  # "waits" has a running task to wait for


def test_an_empty_queue_is_not_a_stall() -> None:
    clock = Clock()
    s = Scheduler(book(), clock=clock, stall_patience_ms=0)
    assert s.plan().stall is None
    clock.advance_ms(10**6)
    assert s.plan().stall is None


def test_a_zero_patience_stalls_immediately() -> None:
    b = book(memory=1000)
    b.set_total(MEMORY, 0)
    s = Scheduler(b, stall_patience_ms=0)
    assert s.plan(solves=[cand("s", Stage.SOLVE, 1, need(1000, 1), node=())]).stall is not None


def test_a_blocked_reserved_check_with_nothing_running_stalls_too() -> None:
    b = book(memory=1000)
    b.set_total(MEMORY, 10)
    s = Scheduler(b, stall_patience_ms=0)
    plan = s.plan(checks=[cand("c", Stage.CHECK, 1, need(1000, 100), node=(2,))])
    assert plan.reserved_check is not None
    assert plan.stall is not None and plan.stall.nodes == ((H1, (2,)),)


def test_halting_starts_nothing_and_never_stalls() -> None:
    clock = Clock()
    b = book()
    s = Scheduler(b, clock=clock, stall_patience_ms=0)
    plan = s.plan(
        solves=[cand("s", Stage.SOLVE, 1)], checks=[cand("c", Stage.CHECK, 1)], halted=True
    )
    assert plan.halted and plan.launches == () and plan.stall is None
    assert b.reservations() == ()


# -- bounded ticks and input discipline ----------------------------------------------------------


def counting(count: int, stage: Stage, seen: list[int]) -> Iterator[Candidate]:
    for index in range(count):
        seen.append(index)
        yield cand(f"{stage.value}{index}", stage, index, node=(index + 1,))


def test_a_tick_examines_a_bounded_number_of_candidates() -> None:
    seen: list[int] = []
    s = Scheduler(book(cpu=10**9, memory=10**9, work=10**9), max_examined=32, max_launches=1000)
    plan = s.plan(solves=counting(10**9, Stage.SOLVE, seen))
    assert len(plan.launches) == 32 and len(seen) == 32


def test_a_tick_starts_at_most_max_launches_tasks_and_does_not_mistake_that_for_a_stall() -> None:
    seen: list[int] = []
    s = Scheduler(book(cpu=10**9, memory=10**9, work=10**9), max_launches=3, stall_patience_ms=0)
    plan = s.plan(solves=counting(100, Stage.SOLVE, seen))
    assert len(plan.launches) == 3 and plan.stall is None
    assert len(seen) <= 4


def test_checks_are_examined_before_the_launch_cap_stops_solves() -> None:
    s = Scheduler(book(cpu=10**6, memory=10**6, work=10**6), max_launches=2)
    plan = s.plan(
        checks=[cand("c1", Stage.CHECK, 1), cand("c2", Stage.CHECK, 2)],
        solves=[cand("s", Stage.SOLVE, 1)],
    )
    assert ids(plan) == ["c1", "c2"]


@pytest.mark.parametrize("stage", [Stage.CHECK, Stage.SPLIT])
def test_a_queue_that_is_not_oldest_first_is_refused(stage: Stage) -> None:
    queue = [cand("a", stage, 5), cand("b", stage, 2)]
    with pytest.raises(SchedulerError) as unordered:
        if stage is Stage.CHECK:
            Scheduler(book()).plan(checks=queue)
        else:
            Scheduler(book()).plan(splits=queue)
    assert unordered.value.rule == "scheduler.order"


def test_a_candidate_in_the_wrong_queue_is_refused() -> None:
    with pytest.raises(SchedulerError) as wrong:
        Scheduler(book()).plan(checks=[cand("s", Stage.SOLVE, 1)])
    assert wrong.value.rule == "scheduler.stage"


def test_invalid_configuration_is_refused() -> None:
    for options in ({"max_launches": 0}, {"max_examined": 0}, {"stall_patience_ms": -1}):
        with pytest.raises(SchedulerError):
            Scheduler(book(), **options)  # type: ignore[arg-type]


# -- liveness ------------------------------------------------------------------------------------


def simulate(seed: int) -> dict[str, int]:
    """A discrete simulation: solves produce sealed proofs that wait for checks. A reserved
    check is never overtaken in a dimension it needs, and the whole workload ends."""
    counts = {"drained": 0, "passed": 0, "ticks": 0}
    rng = random.Random(seed)
    b = book(cpu=4000, memory=1000, work=800)
    s = Scheduler(b, stall_patience_ms=10**9, max_launches=3)
    pending_solves = [
        cand(
            f"s{i}",
            Stage.SOLVE,
            i,
            need(1000, rng.choice([100, 300, 600]), rng.choice([20, 60, 90])),
            node=(i + 1,),
        )
        for i in range(rng.randint(5, 14))
    ]
    checks: list[Candidate] = []
    running: dict[str, tuple[int, str, Candidate]] = {}
    seq = 100
    finished_checks = 0
    total_solves = len(pending_solves)
    for step in range(5000):
        for task_id, (due, kind, candidate) in list(running.items()):
            if due > step:
                continue
            del running[task_id]
            if kind == "solve":
                sealed = Need(0, 0, ((G, rng.choice([10, 30, 80])),))
                b.restage(task_id, "sealed", sealed)
                seq += 1
                full = Need(1000, rng.choice([150, 400, 700]), sealed.disk)
                checks.append(Candidate(task_id, Stage.CHECK, candidate.node, full, seq, True))
            else:
                b.release(task_id)
                finished_checks += 1
        checks.sort(key=lambda c: c.order)
        plan = s.plan(checks=checks, solves=pending_solves, active=len(running), measures=None)
        b.check()
        assert not plan.impossible and plan.stall is None, (seed, step)
        for dimension in (CPU, MEMORY, disk(G)):
            assert b.outstanding(dimension) <= b.ledger(dimension).total
        started = {launch.candidate.task_id: launch for launch in plan.launches}
        if plan.reserved_check is not None:
            blocked = plan.reserved_check
            counts["drained"] += 1
            counts["passed"] += len(plan.launches)
            # while a check is reserved nothing but checks starts ...
            assert all(launch.candidate.stage is Stage.CHECK for launch in plan.launches)
            held = b.get(blocked.task_id)
            old = {} if held is None else held.need.amounts()
            wanted = {d: a - old.get(d, 0) for d, a in blocked.need.amounts().items()}
            assert any(a > b.available(d) for d, a in wanted.items()), (seed, step)
            # ... and a younger check never took what the reserved check still needs
            for launch in plan.launches:
                if launch.candidate.order > blocked.order:
                    for dimension in launch.candidate.need.amounts():
                        assert b.available(dimension) >= wanted.get(dimension, 0), (
                            seed,
                            step,
                            dimension,
                        )
        checks = [c for c in checks if c.task_id not in started]
        pending_solves = [c for c in pending_solves if c.task_id not in started]
        for task_id, launch in started.items():
            kind = "solve" if launch.candidate.stage is Stage.SOLVE else "check"
            running[task_id] = (step + rng.randint(1, 6), kind, launch.candidate)
        if finished_checks == total_solves:
            break
        counts["ticks"] = step
    assert finished_checks == total_solves, (seed, finished_checks, total_solves)
    assert b.reservations() == ()
    assert all(b.outstanding(d) == 0 for d in b.dimensions)
    return counts


@pytest.mark.parametrize("seed", range(30))
def test_every_queued_task_eventually_runs_and_no_reservation_is_double_counted(seed: int) -> None:
    assert simulate(seed)["ticks"] < 4000


def test_the_simulations_really_drain_and_let_unharmful_checks_pass() -> None:
    totals = {"drained": 0, "passed": 0, "ticks": 0}
    for seed in range(30):
        for name, value in simulate(seed).items():
            totals[name] += value
    assert totals["drained"] >= 20 and totals["passed"] >= 5, totals


def test_a_candidate_that_claims_a_reservation_it_does_not_hold_is_refused() -> None:
    with pytest.raises(SchedulerError) as claim:
        Scheduler(book()).plan(checks=[cand("c", Stage.CHECK, 1, holds=True)])
    assert claim.value.rule == "scheduler.holds"


def test_a_candidate_that_already_holds_a_reservation_cannot_be_started_again() -> None:
    from cubeproof.coordinator.ledger import LedgerError

    b = book()
    b.reserve("c", "sealed", Need(0, 0, ((G, 10),)))
    with pytest.raises(LedgerError) as duplicate:
        Scheduler(b).plan(checks=[cand("c", Stage.CHECK, 1, need(1000, 10, 10))])
    assert duplicate.value.rule == "ledger.duplicate"
