"""Budget invariants on fake cgroups v1/v2, shared storage, impossible tasks, pressure.

The whole chain is exercised on fake kernel trees that the tests change while work runs:
``SystemProbes`` -> ``Resources`` (capacity, remeasurement, pressure) -> ``ResourceBook`` ->
``Scheduler``. Reservations are accounting for admission: the tests assert that a budget is
never treated as a promise of memory the kernel reports as taken (specification §1.4, §8.2).
"""

from __future__ import annotations

import time
from collections.abc import Iterator, Mapping
from pathlib import Path

import pytest

from cubeproof.base.resources import Roots, StorageProbe, mount_of
from cubeproof.contracts.enums import ProofMode
from cubeproof.contracts.policy import default_policy
from cubeproof.coordinator.ledger import CPU, MEMORY, Need, disk
from cubeproof.coordinator.resources import (
    DISK_RESERVE,
    SYSTEM_RESERVE,
    PressureLevel,
    ResourceConfig,
    Resources,
    SystemProbes,
    check_need,
    solve_need,
)
from cubeproof.coordinator.scheduler import Candidate, Scheduler, Stage

GIB = 1 << 30
MIB = 1 << 20
POLICY = default_policy(ProofMode.TRANSIENT)


class Clock:
    def __init__(self) -> None:
        self.now = 10**9

    def __call__(self) -> int:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += int(seconds * 1e9)


class Host:
    """A fake host: kernel files under ``tmp_path`` that tests change (cgroup v1 or v2)."""

    def __init__(self, tmp: Path, version: int, *, memory_gib: int = 16, cpus: int = 4) -> None:
        self.tmp, self.version = tmp, version
        self.mountinfo = (
            "22 1 8:1 / /data rw - ext4 /dev/sda1 rw\n23 1 8:2 / /scratch rw - ext4 /dev/sdb1 rw\n"
        )
        self.free = {"/data": 200 * GIB, "/scratch": 100 * GIB, "/overlay": 150 * GIB}
        self.write("proc/self/mountinfo", self.mountinfo)
        self.write("proc/self/status", "VmRSS: 102400 kB\n")
        self.set_available(60)
        if version == 2:
            self.write("cg/cgroup.controllers", "cpu memory\n")
            self.write("proc/self/cgroup", "0::/job\n")
        else:
            self.write("proc/self/cgroup", "4:memory:/job\n3:cpu,cpuacct:/job\n")
        self.set_quota(cpus)
        self.set_memory(limit=memory_gib * GIB, current=1 * GIB)
        self.set_pressure(0.0, 0.0)

    def write(self, name: str, text: str) -> None:
        path = self.tmp / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)

    def set_available(self, gib: int) -> None:
        self.write(
            "proc/meminfo",
            f"MemTotal: {64 * GIB // 1024} kB\nMemAvailable: {gib * GIB // 1024} kB\n",
        )

    def set_quota(self, cpus: int) -> None:
        if self.version == 2:
            self.write("cg/job/cpu.max", f"{cpus * 100000} 100000\n")
        else:
            self.write("cg/cpu,cpuacct/job/cpu.cfs_quota_us", f"{cpus * 100000}\n")
            self.write("cg/cpu,cpuacct/job/cpu.cfs_period_us", "100000\n")

    def set_memory(self, *, limit: int, current: int, oom_kills: int = 0) -> None:
        if self.version == 2:
            self.write("cg/job/memory.max", str(limit))
            self.write("cg/job/memory.current", str(current))
            self.write("cg/job/memory.events", f"oom_kill {oom_kills}\n")
        else:
            self.write("cg/memory/job/memory.limit_in_bytes", str(limit))
            self.write("cg/memory/job/memory.usage_in_bytes", str(current))
            self.write("cg/memory/job/memory.oom_control", f"oom_kill {oom_kills}\n")

    def set_pressure(self, some: float, full: float) -> None:
        tail = "avg60=0.00 avg300=0.00 total=0"
        text = f"some avg10={some:.2f} {tail}\nfull avg10={full:.2f} {tail}\n"
        self.write("cg/job/memory.pressure" if self.version == 2 else "proc/pressure/memory", text)

    def roots(self) -> Roots:
        return Roots(str(self.tmp / "cg"), str(self.tmp / "proc"))

    def probes(self) -> SystemProbes:
        def storage(path: str) -> StorageProbe:
            return StorageProbe(path, 1, self.free[path], 500 * GIB, mount_of(path, self.mountinfo))

        return SystemProbes(
            roots=self.roots(),
            cpu_count=lambda: 64,
            affinity=lambda: None,
            storage_probe=storage,
        )

    def resources(
        self, clock: Clock, paths: Mapping[str, str] | None = None, **config: int
    ) -> Resources:
        return Resources(
            self.probes(),
            ResourceConfig(helper_resident_bytes=0, **config),
            paths or {"work": "/data", "results": "/scratch"},
            clock=clock,
        )


def candidate(
    task: str, stage: Stage, seq: int, need: Need, node: tuple[int, ...] = ()
) -> Candidate:
    return Candidate(task, stage, ("aa" * 32, node), need, seq)


@pytest.mark.parametrize("version", [1, 2])
def test_cgroup_v1_and_v2_give_the_same_capacity(tmp_path: Path, version: int) -> None:
    host = Host(tmp_path, version, memory_gib=16, cpus=4)
    r = host.resources(Clock())
    assert r.capacity.cpu_milli == 4000
    # 16 GiB limit, 1 GiB used: 15 GiB headroom (host reports 60 GiB available)
    assert r.capacity.observed[MEMORY] == 15 * GIB - SYSTEM_RESERVE - 100 * MIB
    assert r.capacity.storage.groups() == ("dev:/dev/sda1", "dev:/dev/sdb1")
    assert r.capacity.disk_budget_bytes == {
        "dev:/dev/sda1": 200 * GIB - DISK_RESERVE,
        "dev:/dev/sdb1": 100 * GIB - DISK_RESERVE,
    }


@pytest.mark.parametrize("version", [1, 2])
def test_shared_storage_is_one_budget_for_every_path_on_it(tmp_path: Path, version: int) -> None:
    host = Host(tmp_path, version)
    host.mountinfo += "40 1 0:50 / /overlay rw - overlay overlay rw\n"
    r = host.resources(Clock(), {"work": "/data", "results": "/scratch", "proofs": "/overlay"})
    assert r.capacity.storage.groups() == ("shared",)
    work, results, proofs = (r.group_of(x) for x in ("work", "results", "proofs"))
    assert work == results == proofs == "shared"
    assert r.capacity.disk_budget_bytes["shared"] == 100 * GIB - DISK_RESERVE  # the smallest
    r.book.reserve("solve", "solve", Need(0, 0, ((work, 60 * GIB),)))
    assert not r.book.fits(Need(0, 0, ((proofs, 40 * GIB),)))  # the same budget, not another one
    assert r.book.fits(Need(0, 0, ((proofs, 38 * GIB),)))


@pytest.mark.parametrize("version", [1, 2])
def test_no_task_fitting_is_decided_at_once_and_never_waited_for(
    tmp_path: Path, version: int
) -> None:
    host = Host(tmp_path, version, memory_gib=3, cpus=1)
    r = host.resources(Clock())
    group = r.group_of("work")
    scheduler = Scheduler(r.book, stall_patience_ms=10**9)
    big = Need(1000, 4 * GIB, ((group, 10 * GIB),))  # more RAM than this machine has
    wide = Need(2000, 10 * MIB)  # more cpu than it has
    huge_disk = Need(1000, 10 * MIB, ((group, 10**13),))
    plan = scheduler.plan(
        checks=[candidate("c", Stage.CHECK, 1, big)],
        splits=[candidate("p", Stage.SPLIT, 1, wide)],
        solves=[candidate("s1", Stage.SOLVE, 1, huge_disk), candidate("s2", Stage.SOLVE, 2, big)],
    )
    assert {i.candidate.task_id for i in plan.impossible} == {"c", "p", "s1", "s2"}
    assert plan.launches == () and plan.stall is None and plan.reserved_check is None
    shortfalls = {i.candidate.task_id: i.shortfall.dimension for i in plan.impossible}
    assert shortfalls == {"c": MEMORY, "p": CPU, "s1": disk(group), "s2": MEMORY}
    assert r.book.reservations() == ()  # nothing was reserved for work that can never run


@pytest.mark.parametrize("version", [1, 2])
def test_pressure_mid_check_stops_new_admissions_but_not_the_running_check(
    tmp_path: Path, version: int
) -> None:
    host = Host(tmp_path, version, memory_gib=16)
    clock = Clock()
    r = host.resources(clock)
    group = r.group_of("work")
    scheduler = Scheduler(r.book, clock=clock, stall_patience_ms=60_000)
    check = check_need(POLICY, 2048, 256, 700 * MIB, 20 * MIB, group)
    plan = scheduler.plan(checks=[candidate("check", Stage.CHECK, 1, check, (1,))])
    assert [l.candidate.task_id for l in plan.launches] == ["check"]

    host.set_pressure(40.0, 12.0)
    clock.advance(11)
    report = r.remeasure(children_rss=2 * GIB)
    assert report is not None and report.level is PressureLevel.HIGH and report.lowered
    assert r.book.get("check") is not None  # the check keeps running with its reservation
    solve = solve_need(POLICY, 20 * MIB, group)
    plan = scheduler.plan(
        solves=[candidate("solve", Stage.SOLVE, 1, solve, (2,))],
        measures=r.measures(),
        active=1,
    )
    assert plan.launches == () and plan.stall is None  # waits: a running task will free memory
    assert any("memory" in reason for reason in plan.reasons)

    r.book.release("check")  # the check ends; pressure goes away
    host.set_pressure(0.5, 0.0)
    for _ in range(6):
        clock.advance(11)
        r.remeasure()
    plan = scheduler.plan(
        solves=[candidate("solve", Stage.SOLVE, 1, solve, (2,))], measures=r.measures()
    )
    assert [l.candidate.task_id for l in plan.launches] == ["solve"]
    assert r.book.ledger(MEMORY).total <= r.book.ledger(MEMORY).ceiling


@pytest.mark.parametrize("version", [1, 2])
def test_pressure_that_never_ends_with_nothing_running_stalls_instead_of_spinning(
    tmp_path: Path, version: int
) -> None:
    host = Host(tmp_path, version)
    clock = Clock()
    r = host.resources(clock)
    group = r.group_of("work")
    scheduler = Scheduler(r.book, clock=clock, stall_patience_ms=20_000)
    solve = solve_need(POLICY, 20 * MIB, group)
    # something ran and was lowered, then ended; pressure stays: the total stays at zero
    r.book.reserve("old", "solve", Need(0, 1 * GIB))
    host.set_pressure(90.0, 40.0)
    clock.advance(11)
    r.remeasure()
    r.book.release("old")
    queue = [candidate("solve", Stage.SOLVE, 1, solve, (7,))]
    assert scheduler.plan(solves=queue, measures=r.measures()).stall is None
    clock.advance(21)
    stall = scheduler.plan(solves=queue, measures=r.measures()).stall
    assert stall is not None and stall.nodes == (("aa" * 32, (7,)),)
    assert stall.capacities[MEMORY]["total"] < stall.capacities[MEMORY]["ceiling"]
    assert "memory" in " ".join(stall.requirements)


@pytest.mark.parametrize("version", [1, 2])
def test_a_lower_budget_while_work_runs_refuses_new_work_and_revokes_nothing(
    tmp_path: Path, version: int
) -> None:
    host = Host(tmp_path, version, memory_gib=16)
    clock = Clock()
    r = host.resources(clock)
    group = r.group_of("work")
    scheduler = Scheduler(r.book, clock=clock)
    solve = solve_need(POLICY, 20 * MIB, group)  # ~1.1 GiB of memory
    plan = scheduler.plan(
        solves=[candidate(f"s{i}", Stage.SOLVE, i, solve, (i + 1,)) for i in range(4)],
        measures=r.measures(),
    )
    assert len(plan.launches) == 4
    held = r.book.outstanding(MEMORY)

    # an operator lowers the cgroup limit under the running solves, and the cpu quota
    host.set_memory(limit=4 * GIB, current=3 * GIB)
    host.set_quota(2)
    clock.advance(11)
    report = r.remeasure(children_rss=3 * GIB)
    assert report is not None and report.cpu_total == 2000
    assert r.book.outstanding(MEMORY) == held and r.book.outstanding(CPU) == 4000
    assert len(r.book.reservations()) == 4  # not revoked
    plan = scheduler.plan(
        solves=[candidate("more", Stage.SOLVE, 9, solve, (9,))], measures=r.measures(), active=4
    )
    assert plan.launches == ()
    assert r.book.deficits().get(CPU) == 2000

    for task in ("s0", "s1", "s2", "s3"):
        r.book.release(task)
    host.set_memory(limit=16 * GIB, current=1 * GIB)
    host.set_quota(4)
    clock.advance(11)
    r.remeasure(children_rss=0)
    clock.advance(11)
    plan = scheduler.plan(
        solves=[candidate("more", Stage.SOLVE, 9, solve, (9,))], measures=r.measures()
    )
    assert [l.candidate.task_id for l in plan.launches] == ["more"]
    assert r.book.ledger(CPU).total == 4000  # restored, never above the initial ceiling


@pytest.mark.parametrize("version", [1, 2])
def test_a_budget_is_not_a_promise_of_physical_memory(tmp_path: Path, version: int) -> None:
    """The budget says 8 GiB; the kernel reports only 2 GiB left because other programs took
    the rest. The ledger refuses what the measured headroom cannot back."""
    host = Host(tmp_path, version, memory_gib=12)
    clock = Clock()
    r = host.resources(clock)
    assert r.book.ledger(MEMORY).total > 8 * GIB
    host.set_memory(limit=12 * GIB, current=10 * GIB)  # someone else uses 9 GiB
    clock.advance(11)
    r.remeasure()
    usable = r.measures()[MEMORY].headroom
    assert usable == 2 * GIB - SYSTEM_RESERVE
    assert r.book.fits(Need(0, usable), r.measures())
    assert not r.book.fits(Need(0, usable + 1), r.measures())
    # without remeasurement the budget alone would have admitted it: that is the false guarantee
    assert r.book.fits(Need(0, usable + 1), None)


def test_remeasurement_does_not_double_count_what_the_children_already_use(tmp_path: Path) -> None:
    """Other programs use 6 GiB of a 16 GiB limit and our task a reserves 6 GiB.

    Resident (U = R): the kernel reports 12 GiB used, 3 GiB usable after the 1 GiB reserve, and
    all 3 GiB are new capacity; subtracting the reservation again would leave nothing. Not yet
    resident (U = 0): 6 GiB used, 9 GiB usable, of which the reservation still claims 6."""
    host = Host(tmp_path, 2, memory_gib=16)
    clock = Clock()
    r = host.resources(clock)
    r.book.reserve("a", "solve", Need(1000, 6 * GIB))
    host.set_memory(limit=16 * GIB, current=12 * GIB)
    clock.advance(11)
    r.remeasure(children_rss=6 * GIB)
    assert r.measures()[MEMORY].headroom == 16 * GIB - 12 * GIB - SYSTEM_RESERVE == 3 * GIB
    assert r.book.fits(Need(0, 3 * GIB), r.measures())
    assert not r.book.fits(Need(0, 3 * GIB + 1), r.measures())
    host.set_memory(limit=16 * GIB, current=6 * GIB)
    clock.advance(11)
    r.remeasure(children_rss=0)
    assert r.measures()[MEMORY].headroom == 9 * GIB
    assert r.book.fits(Need(0, 3 * GIB), r.measures())
    assert not r.book.fits(Need(0, 3 * GIB + 1), r.measures())
    # an unmeasured U is zero: the same conservative answer
    r.remeasure(children_rss=None, force=True)
    assert not r.book.fits(Need(0, 3 * GIB + 1), r.measures())


def test_a_tick_stays_cheap_with_a_huge_frontier(tmp_path: Path) -> None:
    """Event-loop responsiveness (specification §8.1) at the unit level: planning examines a bounded
    number of candidates however long the queue is, and a remeasurement reads a few files."""
    host = Host(tmp_path, 2)
    clock = Clock()
    r = host.resources(clock)
    group = r.group_of("work")
    scheduler = Scheduler(r.book)
    solve = solve_need(POLICY, 20 * MIB, group)

    def endless() -> Iterator[Candidate]:
        index = 0
        while True:
            index += 1
            yield candidate(f"s{index}", Stage.SOLVE, index, solve, (index,))

    started = time.monotonic()
    for _ in range(50):
        scheduler.plan(solves=endless(), measures=r.measures())
        for reservation in r.book.reservations():
            r.book.release(reservation.task_id)
    plan_time = (time.monotonic() - started) / 50
    started = time.monotonic()
    for _ in range(50):
        r.remeasure(force=True)
    measure_time = (time.monotonic() - started) / 50
    assert plan_time < 0.05 and measure_time < 0.05, (plan_time, measure_time)


@pytest.mark.parametrize("version", [1, 2])
def test_a_filling_disk_refuses_new_solves_and_leaves_the_running_ones(
    tmp_path: Path, version: int
) -> None:
    host = Host(tmp_path, version)
    clock = Clock()
    r = host.resources(clock)
    group = r.group_of("work")
    scheduler = Scheduler(r.book, clock=clock)
    solve = solve_need(POLICY, 20 * MIB, group)  # about 4 GiB of disk (the proof cap)
    first = scheduler.plan(
        solves=[candidate("s0", Stage.SOLVE, 0, solve, (1,))], measures=r.measures()
    )
    assert len(first.launches) == 1
    # another program fills the disk down to 5 GiB free: 3 GiB usable after the 2 GiB reserve,
    # and the running solve's 4 GiB are not yet written (U = 0), so nothing new fits
    host.free["/data"] = 5 * GIB
    clock.advance(11)
    r.remeasure(disk_used={group: 0})
    plan = scheduler.plan(
        solves=[candidate("s1", Stage.SOLVE, 1, solve, (2,))], measures=r.measures(), active=1
    )
    assert plan.launches == () and r.book.get("s0") is not None
    # once the first solve ends and frees its reservation, 3 GiB are still too little for 4 GiB
    r.book.release("s0")
    clock.advance(11)
    r.remeasure()
    assert (
        scheduler.plan(
            solves=[candidate("s1", Stage.SOLVE, 1, solve, (2,))], measures=r.measures()
        ).launches
        == ()
    )
    host.free["/data"] = 100 * GIB
    clock.advance(11)
    r.remeasure()
    assert (
        len(
            scheduler.plan(
                solves=[candidate("s1", Stage.SOLVE, 1, solve, (2,))], measures=r.measures()
            ).launches
        )
        == 1
    )
