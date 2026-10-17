"""Capacity, reservation sizes, the proof-cap clamp and pressure handling (specification §8.2,
§8.3)."""

from __future__ import annotations

import functools
import random
from dataclasses import dataclass, field, replace
from pathlib import Path

import pytest
from cp_sched_support import formula_bytes

from cubeproof.base.errors import ConfigurationError, ResourceError
from cubeproof.base.resources import (
    CpuProbe,
    MemoryProbe,
    Pressure,
    Roots,
    StorageGroups,
    StorageProbe,
    mount_of,
)
from cubeproof.cnf.cubecnf import cube_cnf_bytes
from cubeproof.cnf.dimacs import parse_dimacs
from cubeproof.contracts.enums import ProofMode
from cubeproof.contracts.policy import Policy, default_policy
from cubeproof.coordinator.ledger import CPU, MEMORY, Need, disk
from cubeproof.coordinator.resources import (
    CHILD_OVERHEAD,
    DISK_RESERVE,
    LOG_ALLOWANCE,
    MIN_PROOF_CAP,
    SYSTEM_RESERVE,
    Capacity,
    PressureLevel,
    PressurePolicy,
    ResourceConfig,
    Resources,
    SystemProbes,
    check_need,
    clamp_proof_cap,
    cnf_size_bound,
    cnf_size_bytes,
    derive_capacity,
    helper_need,
    idle_fit,
    io_service_need,
    preflight,
    proof_prefix_need,
    sealed_need,
    solve_need,
    stream_need,
)
from cubeproof.evidence.schema import ResourceSnapshot
from cubeproof.tools import checker as ck

MIB = 1 << 20
GIB = 1 << 30
G = "dev:/dev/sda1"
POLICY = default_policy(ProofMode.TRANSIENT)


def memory_probe(
    headroom: int | None,
    *,
    pressure: Pressure | None = None,
    oom: int | None = 0,
) -> MemoryProbe:
    return MemoryProbe("cgroup-v2", None, None, None, None, headroom, oom, pressure)


def groups(*, free: int = 100 * GIB, group: str = G) -> StorageGroups:
    return StorageGroups(
        {"/work": group, "/results": group}, {group: ("/results", "/work")}, {group: free}
    )


def capacity(
    *, cpu: int = 8000, memory: int = 32 * GIB, work: int = 200 * GIB, group: str = G
) -> Capacity:
    return Capacity(
        cpu_milli=cpu,
        memory_budget_bytes=memory,
        disk_budget_bytes={group: work},
        storage=groups(group=group),
        requested={},
        observed={},
    )


# -- reservation sizes (specification §8.3 table) -------------------------------------------------


def test_solve_reserves_the_solver_cap_overhead_and_the_full_disk_need() -> None:
    need = solve_need(POLICY, 5 * MIB, G)
    assert need.cpu_milli == 1000
    assert need.memory_bytes == POLICY.solver_memory_bytes + CHILD_OVERHEAD
    assert need.disk == ((G, POLICY.proof_cap_bytes + 5 * MIB + LOG_ALLOWANCE),)


def test_a_sealed_proof_holds_only_its_disk() -> None:
    need = sealed_need(7 * MIB, 5 * MIB, G)
    assert (need.cpu_milli, need.memory_bytes) == (0, 0)
    assert need.disk == ((G, 12 * MIB + LOG_ALLOWANCE),)


def test_a_check_reserves_heap_stack_slack_and_overhead_and_keeps_the_disk() -> None:
    need = check_need(POLICY, 1024, 256, 7 * MIB, 5 * MIB, G)
    assert need.memory_bytes == (1024 + 256 + POLICY.checker_slack_mib) * MIB + CHILD_OVERHEAD
    assert need.cpu_milli == 1000
    # the check's disk is exactly the sealed stage's disk: restaging adds only cpu and memory
    assert need.disk == sealed_need(7 * MIB, 5 * MIB, G).disk


def test_a_stream_reserves_three_processes_and_no_proof_disk() -> None:
    stream = default_policy(ProofMode.STREAM)
    need = stream_need(stream, 5 * MIB, G)
    checker = (stream.stream_heap_mib + stream.checker_stack_mib + stream.checker_slack_mib) * MIB
    assert need.cpu_milli == 3000
    assert (
        need.memory_bytes == stream.solver_memory_bytes + checker + 128 * MIB + 3 * CHILD_OVERHEAD
    )
    assert need.disk == ((G, 5 * MIB + LOG_ALLOWANCE),)


def test_helpers_reserve_their_cap_plus_overhead_while_active() -> None:
    need = helper_need(G)
    assert (need.cpu_milli, need.memory_bytes) == (1000, 256 * MIB + CHILD_OVERHEAD)
    assert need.disk == ((G, 1 * MIB),)
    assert helper_need(G, cap=512 * MIB).memory_bytes == 512 * MIB + CHILD_OVERHEAD


def test_proof_prefix_reserves_the_solver_cap_and_256_mib_of_scratch() -> None:
    need = proof_prefix_need(POLICY, 5 * MIB, G)
    assert need.memory_bytes == POLICY.solver_memory_bytes + CHILD_OVERHEAD
    assert need.disk == ((G, 256 * MIB + 5 * MIB + LOG_ALLOWANCE),)


def test_the_io_service_counts_its_resident_cost_buffers_and_temporary_copies() -> None:
    need = io_service_need({G: 40 * MIB}, resident=100 * MIB)
    assert need.memory_bytes == 100 * MIB + 32 * MIB
    assert need.disk == ((G, 40 * MIB),)


@pytest.mark.parametrize("cube", [(), (3,), (-1, 2, -30)])
def test_the_cnf_size_is_the_actual_size(cube: tuple[int, ...]) -> None:
    formula = parse_dimacs(formula_bytes(40, [(1, 2), (-1, 3), (4, -5, 6)]))
    assert cnf_size_bytes(formula, cube) == len(cube_cnf_bytes(formula, cube))


def test_the_cnf_bound_covers_every_cube_of_the_depth() -> None:
    formula = parse_dimacs(formula_bytes(40, [(1, 2), (-1, 3)]))
    rng = random.Random(1)
    for depth in range(0, 8):
        bound = cnf_size_bound(formula, depth)
        for _ in range(30):
            variables = sorted(rng.sample(range(1, 41), depth))
            cube = tuple(v if rng.random() < 0.5 else -v for v in variables)
            assert cnf_size_bytes(formula, cube) <= bound
    assert cnf_size_bound(formula, 0) == cnf_size_bytes(formula, ())


# -- capacity ---------------------------------------------------------------------------------


def test_memory_budget_is_headroom_minus_reserve_coordinator_and_helpers() -> None:
    config = ResourceConfig(frontier_nodes=1000, helper_resident_bytes=100 * MIB)
    cap = derive_capacity(
        config,
        CpuProbe(8000, {}),
        memory_probe(20 * GIB),
        200 * MIB,
        groups(free=50 * GIB),
    )
    fixed = SYSTEM_RESERVE + 200 * MIB + 1000 * 2048 + 100 * MIB
    assert cap.memory_budget_bytes == 20 * GIB - fixed
    assert cap.disk_budget_bytes == {G: 50 * GIB - DISK_RESERVE}
    assert cap.cpu_milli == 8000


def test_the_coordinator_allowance_has_a_floor() -> None:
    cap = derive_capacity(
        ResourceConfig(helper_resident_bytes=0),
        CpuProbe(1000, {}),
        memory_probe(10 * GIB),
        None,
        groups(),
    )
    assert cap.memory_budget_bytes == 10 * GIB - SYSTEM_RESERVE - 64 * MIB


def test_a_request_lowers_a_ceiling_and_never_raises_it() -> None:
    probes = (CpuProbe(4000, {}), memory_probe(10 * GIB), 0, groups(free=30 * GIB))
    low = derive_capacity(
        ResourceConfig(cpu_milli=2000, memory_bytes=3 * GIB, disk_bytes=5 * GIB), *probes
    )
    assert (low.cpu_milli, low.memory_budget_bytes, low.disk_budget_bytes[G]) == (
        2000,
        3 * GIB,
        5 * GIB,
    )
    assert low.requested == {CPU: 2000, MEMORY: 3 * GIB, disk(G): 5 * GIB}
    high = derive_capacity(
        ResourceConfig(cpu_milli=64000, memory_bytes=1000 * GIB, disk_bytes=1000 * GIB), *probes
    )
    assert high.cpu_milli == 4000
    assert high.memory_budget_bytes == high.observed[MEMORY] < 10 * GIB
    assert high.disk_budget_bytes[G] == 30 * GIB - DISK_RESERVE
    assert any("clamped" in note for note in high.notes)


def test_unmeasurable_memory_needs_an_explicit_budget() -> None:
    probes = (CpuProbe(4000, {}), memory_probe(None), None, groups())
    with pytest.raises(ResourceError) as unmeasured:
        derive_capacity(ResourceConfig(), *probes)
    assert unmeasured.value.rule == "resources.memory_unmeasured"
    cap = derive_capacity(ResourceConfig(memory_bytes=2 * GIB), *probes)
    assert cap.memory_budget_bytes == 2 * GIB
    assert any("unmeasured" in note for note in cap.notes)


def test_a_full_machine_has_a_zero_budget_not_a_negative_one() -> None:
    cap = derive_capacity(
        ResourceConfig(), CpuProbe(1000, {}), memory_probe(GIB // 2), 0, groups(free=GIB)
    )
    assert cap.memory_budget_bytes == 0
    assert cap.disk_budget_bytes[G] == 0


def test_every_storage_group_gets_its_own_disk_budget() -> None:
    storage = StorageGroups(
        {"/a": "dev:a", "/b": "dev:b"},
        {"dev:a": ("/a",), "dev:b": ("/b",)},
        {"dev:a": 10 * GIB, "dev:b": 20 * GIB},
    )
    cap = derive_capacity(
        ResourceConfig(disk_bytes=15 * GIB), CpuProbe(1000, {}), memory_probe(8 * GIB), 0, storage
    )
    assert cap.disk_budget_bytes == {"dev:a": 10 * GIB - DISK_RESERVE, "dev:b": 15 * GIB}
    assert set(cap.budgets()) == {CPU, MEMORY, disk("dev:a"), disk("dev:b")}


def test_invalid_budgets_are_configuration_errors() -> None:
    for bad in (0, -1, True):
        with pytest.raises(ConfigurationError):
            ResourceConfig(memory_bytes=bad)
    with pytest.raises(ConfigurationError):
        ResourceConfig(system_reserve=-1)


# -- proof cap clamp (specification §8.3) ---------------------------------------------------------


@functools.cache
def heap_of(size: int) -> int:
    return ck.initial_heap_mib(size, POLICY.heap_fit)


def largest_fitting_cap(policy: Policy, cap: Capacity, cnf: int) -> int:
    """Brute-force oracle on whole MiB: the largest cap whose three conditions hold."""
    best = 0
    for mib in range(1, policy.proof_cap_bytes // MIB + 1):
        size = mib * MIB
        heap = heap_of(size)
        memory = ck.checker_memory_bytes(heap, policy.checker_stack_mib, policy.checker_slack_mib)
        if (
            heap <= policy.checker_max_heap_mib
            and memory + CHILD_OVERHEAD <= cap.memory_budget_bytes
            and size + cnf + LOG_ALLOWANCE <= cap.disk_budget_bytes[G]
        ):
            best = size
    return best


def small_policy(cap_mib: int, **changes):  # type: ignore[no-untyped-def]
    heap = changes.get("checker_max_heap_mib", POLICY.checker_max_heap_mib)
    return replace(
        POLICY,
        proof_cap_bytes=cap_mib * MIB,
        stream_heap_mib=min(POLICY.stream_heap_mib, heap),
        **changes,
    )


def test_a_cap_that_fits_is_unchanged() -> None:
    result = clamp_proof_cap(POLICY, capacity(), cnf_bytes=10 * MIB, group=G)
    assert (result.proof_cap_bytes, result.limited_by) == (POLICY.proof_cap_bytes, None)


def test_the_cap_is_clamped_by_the_maximum_heap() -> None:
    # 4 GiB of proof predicts a heap above 512 MiB: the cap must drop to the largest MiB whose
    # predicted initial heap still fits
    policy = small_policy(4000, checker_max_heap_mib=512)
    cap = capacity()
    result = clamp_proof_cap(policy, cap, cnf_bytes=MIB, group=G)
    assert result.limited_by == "heap"
    assert result.proof_cap_bytes == largest_fitting_cap(policy, cap, MIB)
    assert ck.initial_heap_mib(result.proof_cap_bytes, policy.heap_fit) <= 512
    assert ck.initial_heap_mib(result.proof_cap_bytes + MIB, policy.heap_fit) > 512


def test_the_cap_is_clamped_by_the_idle_machines_ram() -> None:
    policy = small_policy(4000)
    cap = capacity(memory=2 * GIB)
    result = clamp_proof_cap(policy, cap, cnf_bytes=MIB, group=G)
    assert result.limited_by == "memory"
    assert result.proof_cap_bytes == largest_fitting_cap(policy, cap, MIB)
    heap = ck.initial_heap_mib(result.proof_cap_bytes, policy.heap_fit)
    memory = ck.checker_memory_bytes(heap, policy.checker_stack_mib, policy.checker_slack_mib)
    assert memory + CHILD_OVERHEAD <= 2 * GIB


def test_the_cap_is_clamped_by_one_solves_disk_reservation() -> None:
    policy = small_policy(4000)
    cap = capacity(work=900 * MIB)
    result = clamp_proof_cap(policy, cap, cnf_bytes=100 * MIB, group=G)
    assert result.limited_by == "disk"
    assert result.proof_cap_bytes == 796 * MIB  # 900 - 100 (CNF) - 4 (logs)
    assert result.proof_cap_bytes == largest_fitting_cap(policy, cap, 100 * MIB)
    assert result.proof_cap_bytes + 100 * MIB + LOG_ALLOWANCE <= 900 * MIB


def test_the_clamp_matches_the_brute_force_oracle_for_random_machines() -> None:
    rng = random.Random(7)
    for _ in range(25):
        policy = small_policy(
            rng.choice([300, 1200, 4000]), checker_max_heap_mib=rng.choice([512, 1024, 8192])
        )
        cap = capacity(memory=rng.randint(1, 6) * GIB, work=rng.randint(200, 6000) * MIB)
        cnf = rng.randint(1, 50) * MIB
        expected = largest_fitting_cap(policy, cap, cnf)
        if expected == 0:
            with pytest.raises(ResourceError):
                clamp_proof_cap(policy, cap, cnf_bytes=cnf, group=G)
            continue
        got = clamp_proof_cap(policy, cap, cnf_bytes=cnf, group=G).proof_cap_bytes
        assert got == expected


def test_the_cap_is_never_lowered_below_one_mib_and_fails_instead() -> None:
    cap = capacity(work=3 * MIB)  # 1 MiB + CNF + logs cannot fit
    with pytest.raises(ResourceError) as failed:
        clamp_proof_cap(POLICY, cap, cnf_bytes=MIB, group=G)
    assert failed.value.rule == "resources.proof_cap"
    assert str(MIN_PROOF_CAP) in str(failed.value) and "disk" in str(failed.value)
    # a smaller cap would fit (512 KiB) but the cap is never lowered below 1 MiB automatically
    almost = capacity(work=MIB // 2 + MIB + LOG_ALLOWANCE)
    assert clamp_proof_cap(
        replace(POLICY, proof_cap_bytes=MIB // 2), almost, cnf_bytes=MIB, group=G
    )
    with pytest.raises(ResourceError):
        clamp_proof_cap(POLICY, almost, cnf_bytes=MIB, group=G)
    barely = capacity(work=MIB + MIB + LOG_ALLOWANCE)
    assert clamp_proof_cap(POLICY, barely, cnf_bytes=MIB, group=G).proof_cap_bytes == MIN_PROOF_CAP


def test_a_configured_cap_below_one_mib_is_kept_if_it_fits() -> None:
    policy = replace(POLICY, proof_cap_bytes=1000)
    assert clamp_proof_cap(policy, capacity(), cnf_bytes=MIB, group=G).proof_cap_bytes == 1000


def test_arena_retries_are_checked_against_the_idle_machine() -> None:
    fits = idle_fit(POLICY, capacity(memory=4 * GIB))
    assert fits(1024, 256)
    assert fits(2048, 256)
    assert not fits(4096, 256)  # 4096 + 256 + 256 MiB + overhead > 4 GiB
    bound = 4 * GIB - CHILD_OVERHEAD - POLICY.checker_slack_mib * MIB - 256 * MIB
    assert fits(bound // MIB, 256) and not fits(bound // MIB + 1, 256)


def test_preflight_gives_the_effective_policy_to_persist() -> None:
    policy = small_policy(4000, checker_max_heap_mib=512)
    effective, clamp, notes = preflight(policy, capacity(), cnf_bytes=MIB, group=G)
    assert effective.proof_cap_bytes == clamp.proof_cap_bytes < policy.proof_cap_bytes
    assert effective.sha256 != policy.sha256
    assert "lowered" in notes[0]
    same, _, quiet = preflight(POLICY, capacity(), cnf_bytes=MIB, group=G)
    assert same == POLICY and quiet == ()


def test_an_idle_machine_impossible_stream_task_is_rejected_not_waited_for() -> None:
    stream = default_policy(ProofMode.STREAM)
    with pytest.raises(ResourceError) as impossible:
        preflight(stream, capacity(cpu=2000), cnf_bytes=MIB, group=G)
    assert impossible.value.rule == "resources.preflight"
    assert "stream" in str(impossible.value) and "cpu" in str(impossible.value)
    effective, _, _ = preflight(stream, capacity(cpu=3000), cnf_bytes=MIB, group=G)
    assert effective.proof_mode is ProofMode.STREAM


def test_a_solver_that_cannot_fit_the_idle_machine_fails_preflight() -> None:
    greedy = replace(POLICY, solver_memory_bytes=2 * GIB)
    with pytest.raises(ResourceError) as impossible:
        preflight(greedy, capacity(memory=2 * GIB), cnf_bytes=MIB, group=G)
    assert impossible.value.rule == "resources.preflight"
    assert "solve" in str(impossible.value) and "memory" in str(impossible.value)


# -- Resources: probes, pressure and the snapshot ------------------------------------------------


@dataclass
class Scripted:
    """Probes whose values the test changes between remeasurements."""

    cpu_milli: int = 4000
    headroom: int | None = 20 * GIB
    pressure: Pressure | None = None
    oom: int | None = 0
    rss_value: int | None = 100 * MIB
    free: dict[str, int] = field(default_factory=lambda: {G: 100 * GIB})
    calls: list[str] = field(default_factory=list)

    def cpu(self) -> CpuProbe:
        return CpuProbe(self.cpu_milli, {})

    def memory(self) -> MemoryProbe:
        self.calls.append("memory")
        return memory_probe(self.headroom, pressure=self.pressure, oom=self.oom)

    def rss(self) -> int | None:
        return self.rss_value

    def storage(self, paths):  # type: ignore[no-untyped-def]
        members = {g: tuple(sorted(paths)) for g in self.free}
        return StorageGroups({p: next(iter(self.free)) for p in paths}, members, dict(self.free))


class Clock:
    def __init__(self) -> None:
        self.now = 1_000_000_000

    def __call__(self) -> int:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += int(seconds * 1e9)


def resources(probes: Scripted, clock: Clock, **options):  # type: ignore[no-untyped-def]
    return Resources(
        probes,
        ResourceConfig(helper_resident_bytes=0),
        {"work": "/work", "results": "/results"},
        clock=clock,
        **options,
    )


def test_the_first_measurement_is_taken_at_construction_and_the_next_is_due_in_ten_seconds() -> (
    None
):
    probes, clock = Scripted(), Clock()
    r = resources(probes, clock)
    assert r.measures()[MEMORY].headroom == 20 * GIB - SYSTEM_RESERVE
    assert not r.due()
    assert r.remeasure() is None
    clock.advance(9.9)
    assert r.remeasure() is None
    clock.advance(0.2)
    assert r.due() and r.remeasure() is not None
    assert not r.due()
    assert r.remeasure(force=True) is not None


def test_oom_kills_before_the_run_are_not_new_pressure() -> None:
    probes, clock = Scripted(oom=9), Clock()
    r = resources(probes, clock)
    r.book.reserve("t", "solve", Need(1000, 4 * GIB))
    report = r.remeasure(force=True)
    assert report is not None and report.level is PressureLevel.CALM


def test_h_and_u_of_the_remeasurement() -> None:
    probes, clock = Scripted(headroom=20 * GIB, free={G: 50 * GIB}), Clock()
    r = resources(probes, clock)
    r.remeasure(children_rss=3 * GIB, disk_used={G: 7 * GIB}, force=True)
    measures = r.measures()
    assert measures[MEMORY].headroom == 20 * GIB - SYSTEM_RESERVE
    assert measures[MEMORY].used == 3 * GIB
    assert measures[disk(G)].headroom == 50 * GIB - DISK_RESERVE
    assert measures[disk(G)].used == 7 * GIB


def test_unmeasured_used_is_none_and_missing_headroom_leaves_the_budget_only() -> None:
    probes, clock = Scripted(headroom=None), Clock()
    r = Resources(
        probes,
        ResourceConfig(memory_bytes=4 * GIB, helper_resident_bytes=0),
        {"work": "/work"},
        clock=clock,
    )
    r.remeasure()
    assert MEMORY not in r.measures()
    assert r.measures()[disk(G)].used is None


def test_no_double_count_between_reservations_and_the_measured_headroom() -> None:
    """With 6 GiB reserved and fully resident, headroom shrinks by 6 GiB and the rest of the
    budget is still admitted; reserved-but-untouched memory is not."""
    probes, clock = Scripted(headroom=16 * GIB), Clock()
    r = resources(probes, clock)
    budget = r.book.ledger(MEMORY).total
    r.book.reserve("t1", "solve", Need(1000, 6 * GIB))
    probes.headroom = 16 * GIB - 6 * GIB  # t1 really uses its 6 GiB
    r.remeasure(children_rss=6 * GIB)
    assert r.book.fits(Need(0, budget - 6 * GIB), r.measures())
    assert not r.book.fits(Need(0, budget - 6 * GIB + 1), r.measures())
    # the same free memory while t1 has not touched its reservation: only the unreserved part
    probes.headroom = 16 * GIB - 1 * GIB
    r.remeasure(children_rss=1 * GIB, force=True)
    assert r.book.fits(Need(0, 9 * GIB - SYSTEM_RESERVE), r.measures())
    assert not r.book.fits(Need(0, 9 * GIB), r.measures())


def test_pressure_mid_check_lowers_the_total_and_never_revokes_running_work() -> None:
    probes, clock = Scripted(), Clock()
    r = resources(probes, clock)
    ceiling = r.book.ledger(MEMORY).ceiling
    r.book.reserve("check", "check", Need(1000, 8 * GIB))
    probes.pressure = Pressure(35.0, 8.0)
    report = r.remeasure(force=True)
    assert report is not None and report.level is PressureLevel.HIGH and report.lowered
    assert r.book.ledger(MEMORY).total == 6 * GIB  # 75 % of the outstanding 8 GiB
    assert r.book.outstanding(MEMORY) == 8 * GIB  # the running check keeps its reservation
    assert r.book.get("check") is not None
    assert not r.book.fits(Need(0, 1), r.measures())  # no new memory work while it is lowered
    assert r.book.ledger(MEMORY).ceiling == ceiling


def test_the_total_is_restored_stepwise_after_calm_remeasurements_never_above_the_ceiling() -> None:
    probes, clock = Scripted(), Clock()
    r = resources(probes, clock, pressure=PressurePolicy(calm_ticks=2, restore_percent=50))
    ledger = r.book.ledger(MEMORY)
    r.book.reserve("t", "solve", Need(1000, 4 * GIB))
    probes.pressure = Pressure(50.0, None)
    r.remeasure(force=True)
    lowered = ledger.total
    assert lowered == 3 * GIB < ledger.ceiling
    probes.pressure = Pressure(1.0, 0.0)
    totals = []
    for _ in range(12):
        report = r.remeasure(force=True)
        assert report is not None
        totals.append(ledger.total)
    assert totals[0] == lowered  # a single calm tick does not restore
    assert totals == sorted(totals) and totals[-1] == ledger.ceiling
    assert max(totals) <= ledger.ceiling


def test_moderate_pressure_does_not_lower_but_restores_like_calm() -> None:
    probes, clock = Scripted(), Clock()
    r = resources(probes, clock, pressure=PressurePolicy(calm_ticks=2, restore_percent=10))
    ledger = r.book.ledger(MEMORY)
    r.book.reserve("t", "solve", Need(1000, 4 * GIB))
    probes.pressure = Pressure(40.0, None)
    r.remeasure(force=True)
    lowered = ledger.total
    probes.pressure = Pressure(10.0, 2.0)  # between the calm and the high thresholds
    first = r.remeasure(force=True)
    assert first is not None and first.level is PressureLevel.MODERATE
    assert ledger.total == lowered and not first.restored  # one quiet tick is not enough
    second = r.remeasure(force=True)
    assert second is not None and second.restored and ledger.total > lowered
    # and a HIGH tick in between restarts the count
    probes.pressure = Pressure(40.0, None)
    r.remeasure(force=True)
    probes.pressure = Pressure(0.0, 0.0)
    before = ledger.total
    r.remeasure(force=True)
    assert ledger.total == before


def test_a_new_oom_kill_is_high_pressure() -> None:
    probes, clock = Scripted(oom=3), Clock()
    r = resources(probes, clock)
    r.book.reserve("t", "solve", Need(1000, 4 * GIB))
    first = r.remeasure(force=True)
    assert first is not None and first.level is PressureLevel.CALM
    probes.oom = 4
    second = r.remeasure(force=True)
    assert second is not None and second.level is PressureLevel.HIGH and second.lowered


def test_an_oom_kill_between_construction_and_the_first_remeasurement_is_new() -> None:
    probes, clock = Scripted(oom=3), Clock()
    r = resources(probes, clock)
    r.book.reserve("t", "solve", Need(1000, 4 * GIB))
    probes.oom = 4
    report = r.remeasure(force=True)
    assert report is not None and report.level is PressureLevel.HIGH


def test_no_headroom_left_is_high_pressure() -> None:
    probes, clock = Scripted(), Clock()
    r = resources(probes, clock)
    r.book.reserve("t", "solve", Need(1000, GIB))
    probes.headroom = SYSTEM_RESERVE
    report = r.remeasure(force=True)
    assert report is not None and report.level is PressureLevel.HIGH


def test_a_lowered_cpu_quota_lowers_the_cpu_total_and_a_restored_one_raises_it_again() -> None:
    probes, clock = Scripted(cpu_milli=4000), Clock()
    r = resources(probes, clock)
    r.book.reserve("t1", "solve", Need(3000, 0))
    probes.cpu_milli = 2000
    report = r.remeasure(force=True)
    assert report is not None and report.cpu_total == 2000
    assert r.book.outstanding(CPU) == 3000  # existing work is not revoked
    assert not r.book.fits(Need(1000, 0))
    probes.cpu_milli = 64000
    r.remeasure(force=True)
    assert r.book.ledger(CPU).total == 4000  # never above the initial ceiling


def test_group_of_a_path_role_and_unknown_roles() -> None:
    r = resources(Scripted(), Clock())
    assert r.group_of("work") == G == r.group_of("results")
    with pytest.raises(ConfigurationError):
        r.group_of("elsewhere")
    with pytest.raises(ConfigurationError):
        Resources(Scripted(), ResourceConfig(), {}, clock=Clock())


def test_the_snapshot_is_a_valid_resource_snapshot() -> None:
    r = resources(Scripted(free={G: 50 * GIB}), Clock())
    snapshot = r.snapshot()
    assert isinstance(snapshot, ResourceSnapshot)
    assert snapshot.cpu_milli == 4000
    assert snapshot.memory_budget_bytes == r.book.ledger(MEMORY).total
    (fs,) = snapshot.filesystems
    assert (fs.id, fs.paths, fs.free_bytes) == (G, ("/results", "/work"), 50 * GIB)
    assert fs.budget_bytes == 50 * GIB - DISK_RESERVE
    assert snapshot.coordinator_rss_bytes == 100 * MIB
    assert r.snapshot(rss=5).coordinator_rss_bytes == 5
    assert ResourceSnapshot.from_json(snapshot.to_json()) == snapshot


def test_status_shows_requested_effective_and_per_stage_reservations() -> None:
    r = Resources(
        Scripted(),
        ResourceConfig(memory_bytes=2 * GIB, helper_resident_bytes=0),
        {"work": "/work"},
        clock=Clock(),
    )
    r.book.reserve("t1", "solve", Need(1000, GIB))
    status = r.status()
    assert status["requested"] == {MEMORY: 2 * GIB}
    assert status["total"][MEMORY] == 2 * GIB  # type: ignore[index]
    assert status["outstanding"][MEMORY] == GIB  # type: ignore[index]
    assert status["stages"] == {"solve": {CPU: 1000, MEMORY: GIB}}
    assert status["coordinator_rss_bytes"] == 100 * MIB  # the coordinator's overhead is reported
    assert status["measures"][MEMORY] == [20 * GIB - SYSTEM_RESERVE, None]  # type: ignore[index]


# -- end to end on fake kernel trees -------------------------------------------------------------


def test_system_probes_on_fake_cgroup_v2_and_a_shared_overlay_disk(tmp_path: Path) -> None:
    cg, proc = tmp_path / "cg", tmp_path / "proc"
    for name, text in {
        "cg/cgroup.controllers": "cpu memory",
        "cg/job/cpu.max": "400000 100000",
        "cg/job/memory.max": str(10 * GIB),
        "cg/job/memory.current": str(2 * GIB),
        "proc/self/cgroup": "0::/job",
        "proc/self/status": "VmRSS: 204800 kB\n",
        "proc/meminfo": f"MemTotal: {64 * GIB // 1024} kB\nMemAvailable: {40 * GIB // 1024} kB\n",
        "proc/self/mountinfo": "40 1 0:50 / /w rw - overlay overlay rw\n"
        "41 1 8:1 / /r rw - ext4 /dev/sda1 rw\n",
    }.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)

    def fake_storage(path: str) -> StorageProbe:
        return StorageProbe(
            path,
            1,
            90 * GIB if path == "/w" else 60 * GIB,
            100 * GIB,
            mount_of(path, (proc / "self/mountinfo").read_text()),
        )

    probes = SystemProbes(
        roots=Roots(str(cg), str(proc)),
        cpu_count=lambda: 64,
        affinity=lambda: None,
        storage_probe=fake_storage,
    )
    r = Resources(
        probes,
        ResourceConfig(helper_resident_bytes=0),
        {"work": "/w", "results": "/r"},
        clock=Clock(),
    )
    assert r.capacity.cpu_milli == 4000
    # one overlay path makes both paths one group with the smaller free space
    assert r.capacity.storage.groups() == ("shared",)
    assert r.group_of("work") == r.group_of("results") == "shared"
    assert r.capacity.disk_budget_bytes == {"shared": 60 * GIB - DISK_RESERVE}
    assert r.capacity.memory_budget_bytes == 8 * GIB - SYSTEM_RESERVE - 200 * MIB
    assert any("independence not established" in note for note in r.capacity.notes)
    # one reservation on either path competes for the same budget
    work = r.group_of("work")
    r.book.reserve("a", "solve", Need(0, 0, ((work, 50 * GIB),)))
    assert not r.book.fits(Need(0, 0, ((r.group_of("results"), 9 * GIB),)))
    assert isinstance(r.snapshot(), ResourceSnapshot)
