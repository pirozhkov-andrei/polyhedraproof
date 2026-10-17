"""Root fairness, depth-first order, split decisions and the tools of a snapshot (specification
§8.4, §9.1)."""

from __future__ import annotations

import hashlib
import os
import stat
import time
from dataclasses import replace
from pathlib import Path

import pytest
from cp_sched_support import Journal, children, formula_bytes, machinery, node_id, policy

from cubeproof.base.errors import ContractError, ToolError
from cubeproof.cnf.dimacs import parse_dimacs
from cubeproof.contracts.enums import StopState
from cubeproof.contracts.policy import default_policy
from cubeproof.coordinator.ledger import ResourceBook, disk
from cubeproof.coordinator.resources import check_need, sealed_need
from cubeproof.coordinator.scheduler import Scheduler, Stage
from cubeproof.coordinator.scheduler_select import (
    RootRotation,
    SplitAction,
    check_candidate,
    decide_split,
    leaf_tools,
    next_work,
    split_k,
)
from cubeproof.coordinator.state import Disposition, ReplayState
from cubeproof.evidence.schema import Machinery
from cubeproof.leaf.attempt import CheckRequest
from cubeproof.split.choice import (
    BUDGET,
    CHOSEN,
    FAILED,
    NO_ELIGIBLE,
    SplitChoice,
    lowest_eligible_choice,
)

F = {"f": formula_bytes(8, [(1, 2), (-1, 3)])}
Q4 = ((1, 2), (1, -2), (-1, 2), (-1, -2))


def state_of(j: Journal) -> ReplayState:
    state = ReplayState(j.view)
    state.apply_all(j.records)
    return state


def cubes(work) -> list[tuple[int, ...]]:  # type: ignore[no-untyped-def]
    return [w.node.key[1] for w in work]


def order(j: Journal, roots) -> list[tuple[int, ...]]:  # type: ignore[no-untyped-def]
    return sorted(roots, key=lambda c: node_id(j.sha("f"), c))


# -- next_work -----------------------------------------------------------------------------------


def test_a_single_root_is_walked_depth_first_smallest_child_first() -> None:
    j = Journal(F)
    j.shard([("f", ())])
    j.split("f", (), (1, 2))
    j.split("f", (-1, -2), (3,))
    work = next_work(state_of(j), running=(), rotation=RootRotation(), limit=10)
    assert cubes(work) == [(-1, -2, -3), (-1, -2, 3), (1, -2), (-1, 2), (1, 2)]
    assert {w.stage for w in work} == {Stage.SOLVE}
    assert all(w.root == j.key("f") for w in work)


def test_running_nodes_are_skipped_and_the_next_ones_follow() -> None:
    j = Journal(F)
    j.shard([("f", ())])
    j.split("f", (), (1, 2))
    running = {j.key("f", (-1, -2)), j.key("f", (-1, 2))}
    work = next_work(state_of(j), running=running, rotation=RootRotation(), limit=10)
    assert cubes(work) == [(1, -2), (1, 2)]


def test_only_pending_and_needs_split_nodes_are_work() -> None:
    j = Journal(F)
    j.shard([("f", ())])
    j.split("f", (), (1, 2))
    j.model("f", (-1, -2))
    j.stop("f", (1, -2), "stuck")
    j.failed("f", (-1, 2), "EXHAUSTED", "time")
    work = next_work(state_of(j), running=(), rotation=RootRotation(), limit=10)
    assert [(w.node.key[1], w.stage) for w in work] == [
        ((-1, 2), Stage.SPLIT),
        ((1, 2), Stage.SOLVE),
    ]
    assert work[0].node.disposition is Disposition.NEEDS_SPLIT


def test_a_node_waiting_for_its_stop_follow_up_is_not_scheduled() -> None:
    j = Journal(F, policy_value=policy(tool_retries=0))
    j.shard([("f", ())])
    j.failed("f", (), "TOOL_FAILED", "crash")
    state = state_of(j)
    assert state.followups()
    assert next_work(state, running=(), rotation=RootRotation(), limit=5) == []


def test_roots_are_served_round_robin() -> None:
    j = Journal(F)
    j.shard([("f", c) for c in Q4])
    for root in Q4:
        j.split("f", root, (3, 4))
    state = state_of(j)
    rotation = RootRotation()
    roots = order(j, Q4)
    work = next_work(state, running=(), rotation=rotation, limit=8)
    assert [w.root[1] for w in work] == roots * 2
    # the nodes of each root appear in its own depth-first order
    for root in Q4:
        mine = [w.node.key[1] for w in work if w.root[1] == root]
        assert mine == children(root, (3, 4))[:2]


def test_the_rotation_continues_after_the_last_served_root() -> None:
    j = Journal(F)
    j.shard([("f", c) for c in Q4])
    for root in Q4:
        j.split("f", root, (3, 4))
    state = state_of(j)
    rotation = RootRotation()
    roots = order(j, Q4)
    served: list[tuple[int, ...]] = []
    running: set[tuple[str, tuple[int, ...]]] = set()
    for _ in range(8):
        (work,) = next_work(state, running=running, rotation=rotation, limit=1)
        served.append(work.root[1])
        running.add(work.node.key)
    assert served == roots * 2


def test_a_root_without_work_is_skipped_without_stalling_the_others() -> None:
    j = Journal(F)
    j.shard([("f", c) for c in Q4])
    j.unsat("f", Q4[0])
    j.unsat("f", Q4[1])
    j.split("f", Q4[2], (3,))
    work = next_work(state_of(j), running=(), rotation=RootRotation(), limit=6)
    assert sorted(w.root[1] for w in work) == sorted([Q4[2], Q4[2], Q4[3]])


def test_a_halted_session_has_no_new_work() -> None:
    j = Journal(F, policy_value=policy(anomaly_limit=1))
    j.shard([("f", ())])
    j.failed("f", (), "CHECK_REJECTED", "rejected")
    state = state_of(j)
    assert state.anomaly_halt
    assert next_work(state, running=(), rotation=RootRotation(), limit=5) == []
    m = Journal(F, policy_value=policy(machine_failure_limit=2))
    m.shard([("f", ())])
    m.failed("f", (), "TOOL_FAILED", "crash")
    m.failed("f", (), "TOOL_FAILED", "crash")
    assert next_work(state_of(m), running=(), rotation=RootRotation(), limit=5) == []


def test_the_limit_bounds_the_walk_of_a_huge_frontier() -> None:
    """A split of 20 variables has a million children; picking three must not enumerate them."""
    big = {"f": formula_bytes(30, [(1, 2)])}
    j = Journal(big)
    j.shard([("f", ())])
    j.split("f", (), tuple(range(1, 21)))
    state = state_of(j)
    started = time.monotonic()
    work = next_work(state, running=(), rotation=RootRotation(), limit=3)
    assert time.monotonic() - started < 2.0
    negatives = tuple(-v for v in range(1, 21))
    assert cubes(work) == [
        negatives,
        (1, *negatives[1:]),
        (-1, 2, *negatives[2:]),
    ]


def test_negative_limits_are_refused() -> None:
    j = Journal(F)
    j.shard([("f", ())])
    with pytest.raises(ValueError):
        next_work(state_of(j), running=(), rotation=RootRotation(), limit=-1)


# -- split decisions -----------------------------------------------------------------------------


def choice(variables, status, **info) -> SplitChoice:  # type: ignore[no-untyped-def]
    return SplitChoice.make(variables, status, info)


def decide(c: SplitChoice, **options):  # type: ignore[no-untyped-def]
    base = {"variables": 8, "cube": (1,), "pool": None, "k": 3}
    return decide_split(c, **{**base, **options})


def test_a_valid_chosen_split_is_recorded() -> None:
    d = decide(choice((3, 2), CHOSEN, algorithm="lookahead-v1"))
    assert (d.action, d.variables) == (SplitAction.SPLIT, (3, 2))


@pytest.mark.parametrize(
    ("variables", "options", "rule"),
    [
        ((1,), {}, "split.in_cube"),
        ((9,), {}, "split.out_of_range"),
        ((2, 3, 4, 5), {}, "split.too_long"),
        ((2, 7), {"pool": (2, 3)}, "split.pool"),
    ],
)
def test_an_invalid_choice_goes_to_the_fallback(variables, options, rule) -> None:  # type: ignore[no-untyped-def]
    c = choice(variables, CHOSEN)
    d = decide(c, **options)
    assert d.action is SplitAction.FALLBACK and d.reason == f"invalid_choice:{rule}"
    with pytest.raises(ContractError):
        decide(c, fallback=True, **options)


def test_a_complete_conflict_free_assignment_takes_the_model_path() -> None:
    d = decide(choice((), NO_ELIGIBLE, parent_assigned=8))
    assert (d.action, d.reason) == (SplitAction.SOLVE, "complete_assignment")


def test_an_empty_restricted_pool_is_stuck() -> None:
    d = decide(choice((), NO_ELIGIBLE, parent_assigned=5), pool=(1, 2))
    assert (d.action, d.stop_state, d.reason) == (
        SplitAction.STOP,
        StopState.STUCK,
        "no_eligible_pool",
    )
    unrestricted = decide(choice((), NO_ELIGIBLE, parent_assigned=5))
    assert unrestricted.reason == "no_eligible"


def test_a_parent_conflict_schedules_the_checked_unit_route_never_an_empty_split() -> None:
    d = decide(choice((), FAILED, stop="parent_conflict"))
    assert (d.action, d.reason) == (SplitAction.SOLVE, "parent_conflict")
    assert (
        decide(choice((), FAILED, stop="parent_conflict"), fallback=True).action
        is SplitAction.SOLVE
    )


@pytest.mark.parametrize("status", [BUDGET, FAILED])
def test_a_helper_that_ran_out_of_budget_or_failed_gets_the_fallback(status: str) -> None:
    d = decide(choice((), status, algorithm="lookahead-v1"))
    assert (d.action, d.reason) == (SplitAction.FALLBACK, status)


def test_a_parent_propagation_that_does_not_fit_blocks_the_node_not_the_protocol() -> None:
    d = decide(choice((), BUDGET, algorithm="lowest-eligible", stop="resources"))
    assert (d.action, d.stop_state, d.reason) == (
        SplitAction.STOP,
        StopState.RESOURCE_BLOCKED,
        "split_resources",
    )
    assert decide(choice((), BUDGET), fallback=True).stop_state is StopState.RESOURCE_BLOCKED


def test_the_decisions_on_the_real_fallback() -> None:
    formula = parse_dimacs(formula_bytes(4, [(1,), (-1, 2), (3, 4)]))
    ok = lowest_eligible_choice(formula, (), 2, None, reason="helper_timeout")
    d = decide_split(ok, variables=4, cube=(), pool=None, k=2, fallback=True)
    assert (d.action, d.variables) == (SplitAction.SPLIT, (3, 4))
    conflict = parse_dimacs(formula_bytes(2, [(1,), (-1,)]))
    bad = lowest_eligible_choice(conflict, (), 1, None, reason="helper_timeout")
    assert decide_split(bad, variables=2, cube=(), pool=None, k=1).action is SplitAction.SOLVE
    full = parse_dimacs(formula_bytes(2, [(1,), (2,)]))
    done = lowest_eligible_choice(full, (), 1, None, reason="helper_timeout")
    assert done.status == NO_ELIGIBLE
    assert decide_split(done, variables=2, cube=(), pool=None, k=1).action is SplitAction.SOLVE


def test_k_is_clamped_to_the_depth_and_the_unassigned_variables() -> None:
    p = default_policy("transient")
    assert split_k(p, (), 100) == 4
    assert split_k(p, tuple(range(1, 59)), 100) == 2  # 60 - 58 depth left
    assert split_k(p, tuple(range(1, 60)), 100) == 1
    assert split_k(p, tuple(range(1, 61)), 100) == 0  # at the depth limit: record STUCK
    assert split_k(p, (1, 2, 3), 5) == 2  # two unassigned variables
    assert split_k(replace(p, max_cube_size=0), (), 100) == 0
    assert split_k(p, (1, 2), 2) == 0


# -- the pinned tools of a snapshot --------------------------------------------------------------


def executable(path: Path, text: str) -> str:
    path.write_text(text)
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return hashlib.sha256(path.read_bytes()).hexdigest()


def snapshot(tmp_path: Path, *, solver_hash: str | None = None) -> Machinery:
    solver_sha = executable(tmp_path / "cadical", "#!/bin/sh\necho solver\n")
    checker_sha = executable(tmp_path / "cake_lpr", "#!/bin/sh\necho checker\n")
    value = machinery()
    value["solver"].update(path=str(tmp_path / "cadical"), sha256=solver_hash or solver_sha)
    value["checker"].update(path=str(tmp_path / "cake_lpr"), sha256=checker_sha)
    machinery_value: Machinery = Machinery.from_json(value)
    return machinery_value


def test_the_tools_of_a_snapshot_are_verified_against_its_hashes(tmp_path: Path) -> None:
    snap = snapshot(tmp_path)
    tools = leaf_tools(snap)
    assert tools.solver.sha256 == snap.solver.sha256
    assert tools.checker.sha256 == snap.checker.sha256
    assert tools.solver_argv == tuple(snap.solver.argv)
    assert tools.pins.solver_sha256 == snap.solver.sha256


def test_a_binary_that_is_not_the_measured_one_is_refused(tmp_path: Path) -> None:
    snap = snapshot(tmp_path, solver_hash="ab" * 32)
    with pytest.raises(ToolError) as mismatch:
        leaf_tools(snap)
    assert mismatch.value.rule == "tool.hash_mismatch"


def test_a_missing_binary_is_refused(tmp_path: Path) -> None:
    snap = snapshot(tmp_path)
    os.remove(tmp_path / "cake_lpr")
    with pytest.raises(ToolError):
        leaf_tools(snap)


# -- a queued check as a candidate ---------------------------------------------------------------


def test_a_queued_check_is_a_restage_of_the_sealed_proofs_disk() -> None:
    p = default_policy("transient")
    request = CheckRequest(
        heap_mib=1024,
        stack_mib=256,
        memory_bytes=ck_memory(1024, 256, p.checker_slack_mib),
        time_ms=600000,
        proof_bytes=7 << 20,
    )
    candidate = check_candidate(
        request, task_id="a" * 32, node=("11" * 32, (3,)), cnf_bytes=5 << 20, group="g", seq=4
    )
    assert candidate.holds and candidate.stage is Stage.CHECK and candidate.seq == 4
    assert candidate.need == check_need(p, 1024, 256, 7 << 20, 5 << 20, "g")
    book = ResourceBook({"cpu": 4000, "memory": 8 << 30, disk("g"): 1 << 30})
    book.reserve("a" * 32, "sealed", sealed_need(7 << 20, 5 << 20, "g"))
    plan = Scheduler(book).plan(checks=[candidate])
    (launch,) = plan.launches
    assert launch.reservation.need == candidate.need
    assert book.outstanding(disk("g")) == candidate.need.amounts()[disk("g")]  # not doubled


def ck_memory(heap: int, stack: int, slack: int) -> int:
    return (heap + stack + slack) << 20
