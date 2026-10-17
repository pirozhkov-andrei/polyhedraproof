"""Replay of one journal into scheduling state (specification §6.5, §7.3, §7.4, §10.2-§10.3)."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

import pytest
from cp_sched_support import (
    CHECKER,
    OTHER_HASH,
    Journal,
    checked,
    children,
    formula_bytes,
    policy,
    split_id,
)

from cubeproof.base.errors import IntegrityError
from cubeproof.contracts.campaign import Admit, AdmittedSolver
from cubeproof.contracts.enums import StopState
from cubeproof.coordinator.state import (
    CampaignView,
    Disposition,
    ReplayState,
    iter_children,
)

F = {"f": formula_bytes(8, [(1, 2), (-1, 3)])}
Cube = tuple[int, ...]
#: Pairwise incompatible roots (a shard must be disjoint, specification §4.5).
R3 = ((1,), (-1, 2), (-1, -2))
Q4 = ((1, 2), (1, -2), (-1, 2), (-1, -2))


def replay(journal: Journal, view: CampaignView | None = None) -> ReplayState:
    state = ReplayState(view or journal.view)
    state.apply_all(journal.records)
    return state


def journal(*, roots: Sequence[Cube] = ((),), **options: Any) -> Journal:
    j = Journal(F, **options)
    j.shard([("f", r) for r in roots])
    return j


def keys(state: ReplayState) -> list[tuple[int, ...]]:
    return [n.key[1] for n in state.open_nodes()]


def dispositions(state: ReplayState) -> dict[tuple[int, ...], Disposition]:
    return {n.key[1]: n.disposition for n in state.open_nodes()}


# -- the fold ---------------------------------------------------------------------------------


def test_a_root_without_attempts_is_pending() -> None:
    state = replay(journal())
    assert dispositions(state) == {(): Disposition.PENDING}
    assert state.roots() == [(Journal(F).hashes["f"], ())]


def test_records_must_come_in_order_and_start_with_the_header() -> None:
    j = journal()
    state = ReplayState(j.view)
    with pytest.raises(IntegrityError) as first:
        state.apply(j.records[1])
    assert first.value.rule == "state.seq"
    state.apply(j.records[0])
    with pytest.raises(IntegrityError) as again:
        state.apply(j.records[0])
    assert again.value.rule == "state.seq"
    other = Journal(F, campaign="ff" * 32)
    with pytest.raises(IntegrityError) as foreign:
        ReplayState(j.view).apply(other.records[0])
    assert foreign.value.rule == "state.campaign"


def test_the_chain_must_be_unbroken() -> None:
    j = journal()
    j.split("f", (), (1,))
    j2 = Journal(F)
    j2.shard([("f", ())], name="other")
    j2.failed("f", (), "EXHAUSTED", "time")
    state = ReplayState(j.view)
    state.apply_all(j.records[:2])
    # a record of another chain at seq 2
    with pytest.raises(IntegrityError) as broken:
        state.apply(j2.records[2])
    assert broken.value.rule == "state.chain"


def test_a_verified_attempt_closes_the_root() -> None:
    j = journal()
    j.unsat("f", ())
    state = replay(j)
    assert state.open_nodes() == []
    assert state.closed(j.key("f"))
    assert state.verified_by_depth() == {0: 1}


def test_a_split_closes_only_when_every_child_is_closed() -> None:
    j = journal()
    j.split("f", (), (1, 2))
    for cube in children((), (1, 2))[:3]:
        j.unsat("f", cube)
    state = replay(j)
    assert not state.closed(j.key("f"))
    assert keys(state) == [children((), (1, 2))[3]]
    j.unsat("f", children((), (1, 2))[3])
    state = replay(j)
    assert state.closed(j.key("f"))
    assert state.open_nodes() == []


def test_an_open_answer_is_not_remembered_when_new_evidence_closes_the_node() -> None:
    """Live use: the node was asked about (open) before its last child was verified."""
    j = journal()
    j.split("f", (), (1,))
    j.unsat("f", (-1,))
    state = replay(j)
    assert not state.closed(j.key("f"))  # remembered as open ...
    assert keys(state) == [(1,)]
    j.unsat("f", (1,))
    state.apply(j.records[-1])
    assert state.closed(j.key("f"))  # ... until a record arrives
    assert state.open_nodes() == []


def test_the_open_frontier_is_depth_first_in_child_index_order() -> None:
    j = journal()
    j.split("f", (), (1, 2))
    state = replay(j)
    assert keys(state) == [(-1, -2), (1, -2), (-1, 2), (1, 2)]
    j.split("f", (-1, -2), (3,))
    state = replay(j)
    assert keys(state) == [(-1, -2, -3), (-1, -2, 3), (1, -2), (-1, 2), (1, 2)]


def test_iter_children_equals_the_contract_children() -> None:
    from cubeproof.contracts.identity import split_children

    for cube, w in [((), (3, 1)), ((2,), (5, 4, 1)), ((-3, 4), (1, 7))]:
        assert tuple(iter_children(cube, w)) == split_children(cube, w)


def test_the_smallest_split_id_is_traversed() -> None:
    j = journal()
    j.split("f", (), (1,))
    j.split("f", (), (2,))
    h = j.sha("f")
    smaller = min([(1,), (2,)], key=lambda w: split_id(h, (), w))
    state = replay(j)
    assert keys(state) == children((), smaller)
    # the larger alternative closing does not close the root while the smaller is open
    larger = max([(1,), (2,)], key=lambda w: split_id(h, (), w))
    for cube in children((), larger):
        j.unsat("f", cube)
    state = replay(j)
    assert state.closed(j.key("f"))
    assert state.open_nodes() == []


def test_a_malformed_split_is_ignored_and_listed() -> None:
    j = journal(roots=((2,),))
    j.split("f", (2,), (2,))  # variable in the cube
    j.split("f", (2,), (9,))  # out of range for V=8
    state = replay(j)
    assert [m[1] for m in state.malformed] == ["in_cube", "out_of_range"]
    assert keys(state) == [(2,)]


def test_a_campaign_root_split_expands_the_root() -> None:
    j = journal()
    view = CampaignView(j.view.campaign_id, j.view.admit, j.view.variables, ((j.key("f"), (3, 4)),))
    state = replay(j, view)
    assert keys(state) == children((), (3, 4))


def test_a_root_split_outside_an_accepted_root_is_not_scheduled() -> None:
    j = journal(roots=((5,),))
    view = CampaignView(j.view.campaign_id, j.view.admit, j.view.variables, ((j.key("f"), (3, 4)),))
    state = replay(j, view)
    assert keys(state) == [(5,)]


def test_a_model_is_emitted_and_never_split_or_retried() -> None:
    j = journal()
    j.model("f", ())
    state = replay(j)
    assert dispositions(state) == {(): Disposition.MODEL}
    assert state.followups() == []


# -- admission is section 10's -------------------------------------------------------------------


def test_a_verified_attempt_by_a_nonadmitted_checker_does_not_close() -> None:
    j = journal()
    j.resume(checker=OTHER_HASH)
    j.unsat("f", ())
    state = replay(j)
    assert dispositions(state) == {(): Disposition.PENDING}
    assert state.not_admitted == [(3, "checker_not_admitted")]
    assert not state.closed(j.key("f"))


def test_admission_follows_the_snapshot_of_each_attempt() -> None:
    j = journal(roots=((1,), (-1,)))
    j.resume(checker=OTHER_HASH)
    j.unsat("f", (1,))
    j.resume(checker=CHECKER)
    j.unsat("f", (-1,))
    state = replay(j)
    assert keys(state) == [(1,)]
    assert [r for _, r in state.not_admitted] == ["checker_not_admitted"]


def test_a_nonadmitted_leaf_below_a_split_does_not_close_the_parent() -> None:
    j = journal()
    j.split("f", (), (1,))
    j.unsat("f", (-1,))
    j.resume(checker=OTHER_HASH)
    j.unsat("f", (1,))
    state = replay(j)
    assert not state.closed(j.key("f"))
    assert keys(state) == [(1,)]


def test_a_solver_that_the_campaign_does_not_list_is_not_admitted() -> None:
    j = journal()
    j.unsat("f", ())
    view = CampaignView(
        j.view.campaign_id,
        Admit((CHECKER,), (AdmittedSolver(OTHER_HASH, ("--lrat",)),)),
        j.view.variables,
    )
    state = replay(j, view)
    assert state.not_admitted == [(2, "solver_not_admitted")]
    assert dispositions(state) == {(): Disposition.PENDING}


def test_inconsistent_success_fields_never_close_an_admitted_leaf() -> None:
    j = journal(roots=R3)
    bad_tail = checked(0, "s VERIFIED UNSAT\n")
    bad_tail["result"]["stdout_tail"] = "s SOMETHING ELSE\n"
    j.unsat("f", (1,), checks=[bad_tail])
    j.unsat("f", (-1, 2), proof_sha256=None, proof_bytes=None)
    state = replay(j)
    assert dispositions(state) == {
        (1,): Disposition.PENDING,
        (-1, 2): Disposition.PENDING,
        (-1, -2): Disposition.PENDING,
    }
    assert sorted(r for _, r in state.not_admitted) == ["success.checker_output", "success.proof"]


# -- counters, stops and follow-ups --------------------------------------------------------------


def exhausted(j: Journal, cube: Cube = (), reason: str = "time") -> int:
    return j.failed("f", cube, "EXHAUSTED", reason)


def test_exhausted_needs_a_split() -> None:
    j = journal()
    exhausted(j)
    assert dispositions(replay(j)) == {(): Disposition.NEEDS_SPLIT}


@pytest.mark.parametrize("outcome", ["INVALID_MODEL", "CHECK_REJECTED"])
def test_anomalies_need_a_split_and_are_counted(outcome: str) -> None:
    j = journal()
    if outcome == "CHECK_REJECTED":
        j.failed("f", (), "CHECK_REJECTED", "rejected")
    else:
        j.model("f", (), outcome=outcome)
    state = replay(j)
    assert dispositions(state) == {(): Disposition.NEEDS_SPLIT}
    assert state.session.anomalies == 1


def test_the_anomaly_limit_halts_new_work_and_a_resume_resets_the_session() -> None:
    j = journal(roots=Q4, policy_value=policy(anomaly_limit=2))
    j.failed("f", (1, 2), "CHECK_REJECTED", "rejected")
    assert not replay(j).anomaly_halt
    j.failed("f", (1, -2), "CHECK_REJECTED", "rejected")
    state = replay(j)
    assert state.anomaly_halt
    j.resume()
    state = replay(j)
    assert not state.anomaly_halt
    assert state.session.anomalies == 0
    # the nodes are still waiting for their split
    assert dispositions(state)[(1, 2)] is Disposition.NEEDS_SPLIT


def test_tool_failures_retry_up_to_tool_retries_then_a_tool_block_is_due() -> None:
    j = journal(policy_value=policy(tool_retries=2))
    for _ in range(2):
        j.failed("f", (), "TOOL_FAILED", "crash")
        assert dispositions(replay(j)) == {(): Disposition.PENDING}
    j.failed("f", (), "TOOL_FAILED", "crash")
    state = replay(j)
    (due,) = state.followups()
    assert (due.state, due.reason) == (StopState.TOOL_BLOCKED, "tool_retries_exhausted")
    assert dispositions(state) == {(): Disposition.STOP_DUE}
    # the follow-up is committed once and then gone
    j.stop("f", (), "tool_blocked", "tool_retries_exhausted")
    state = replay(j)
    assert state.followups() == []
    assert dispositions(state) == {(): Disposition.STOPPED}


def test_tool_retries_zero_blocks_after_the_first_failure() -> None:
    j = journal(policy_value=policy(tool_retries=0))
    j.failed("f", (), "TOOL_FAILED", "launch")
    assert replay(j).followups()[0].state is StopState.TOOL_BLOCKED


def test_the_node_counter_persists_across_resume_and_resets_on_success_or_reopen() -> None:
    j = journal(policy_value=policy(tool_retries=2))
    j.failed("f", (), "TOOL_FAILED", "crash")
    j.resume()
    j.failed("f", (), "TOOL_FAILED", "crash")
    j.resume()
    j.failed("f", (), "TOOL_FAILED", "crash")
    assert replay(j).followups()  # three consecutive failures across two resumes
    k = journal(policy_value=policy(tool_retries=2))
    k.failed("f", (), "TOOL_FAILED", "crash")
    k.failed("f", (), "TOOL_FAILED", "crash")
    k.failed("f", (), "EXHAUSTED", "time")  # another outcome resets the counter
    k.failed("f", (), "TOOL_FAILED", "crash")
    assert replay(k).followups() == []
    r = journal(policy_value=policy(tool_retries=0))
    r.failed("f", (), "TOOL_FAILED", "crash")
    r.stop("f", (), "tool_blocked", "x")
    r.reopen("f", ())
    state = replay(r)
    assert dispositions(state) == {(): Disposition.PENDING}  # counter reset by the reopen


def test_the_machine_counter_is_consecutive_in_commit_order_and_per_session() -> None:
    a, b, c = R3
    j = journal(roots=R3, policy_value=policy(machine_failure_limit=3))
    j.failed("f", a, "TOOL_FAILED", "crash")
    j.failed("f", b, "TOOL_FAILED", "crash")
    assert not replay(j).machine_halt
    j.failed("f", c, "EXHAUSTED", "time")  # any other attempt resets
    j.failed("f", a, "TOOL_FAILED", "crash")
    j.failed("f", b, "TOOL_FAILED", "crash")
    assert not replay(j).machine_halt
    j.failed("f", a, "TOOL_FAILED", "crash")
    assert replay(j).machine_halt
    j.resume()
    assert not replay(j).machine_halt


def test_a_stop_survives_a_new_policy_and_only_a_reopen_clears_it() -> None:
    j = journal()
    j.failed("f", (), "TOOL_FAILED", "crash")
    j.stop("f", (), "tool_blocked", "tool_retries_exhausted")
    j.resume(policy_value=policy(tool_retries=99, max_cube_size=61))
    state = replay(j)
    (node,) = state.open_nodes()
    assert (node.disposition, node.stop_state) == (Disposition.STOPPED, StopState.TOOL_BLOCKED)
    j.reopen("f", ())
    assert dispositions(replay(j)) == {(): Disposition.PENDING}


def test_a_stuck_node_at_the_depth_limit_gets_its_stop_due() -> None:
    j = journal(roots=((1, 2),), policy_value=policy(max_cube_size=2))
    j.failed("f", (1, 2), "EXHAUSTED", "time")
    (due,) = replay(j).followups()
    assert (due.state, due.reason) == (StopState.STUCK, "max_depth")
    # a policy raising the limit re-evaluates a node that was never stopped
    j.resume(policy_value=policy(max_cube_size=3))
    state = replay(j)
    assert state.followups() == []
    assert dispositions(state) == {(1, 2): Disposition.NEEDS_SPLIT}


def test_a_node_with_every_variable_assigned_cannot_be_split() -> None:
    cube = (1, 2, 3, 4, 5, 6, 7, 8)
    j = journal(roots=(cube,))
    j.failed("f", cube, "EXHAUSTED", "time")
    (due,) = replay(j).followups()
    assert (due.state, due.reason) == (StopState.STUCK, "no_eligible")


def test_a_stream_arena_retry_keeps_the_node_pending() -> None:
    j = journal(policy_value=policy(proof_mode="stream"))
    relay = {
        "bytes": 0,
        "sha256": "ab" * 32,
        "solver_eof": False,
        "all_written": False,
        "error": None,
    }
    j.failed("f", (), "EXHAUSTED", "check_memory", relay=relay)
    state = ReplayState(j.view, retry_judge=lambda attempt, pol: attempt.reason == "check_memory")
    state.apply_all(j.records)
    assert dispositions(state) == {(): Disposition.PENDING}
    # without an explicit judge the replay derives the retry from the record itself
    # (tests/stream/test_cp_stream_state.py); a record without the exhausted check it names
    # gives no arena to derive from, so the node needs a split
    assert dispositions(replay(j)) == {(): Disposition.NEEDS_SPLIT}


# -- regions -------------------------------------------------------------------------------------


def test_given_away_nodes_are_not_scheduled_and_never_close_locally() -> None:
    j = journal()
    j.split("f", (), (1,))
    j.handoff([("f", (1,))])
    state = replay(j)
    assert keys(state) == [(-1,)]
    assert state.given_away() == [j.key("f", (1,))]
    j.unsat("f", (-1,))
    state = replay(j)
    assert state.open_nodes() == []
    assert not state.closed(j.key("f"))  # the given half is not closed here


def test_a_given_root_leaves_no_work() -> None:
    j = journal(roots=((1,), (-1,)))
    j.handoff([("f", (-1,))])
    state = replay(j)
    assert keys(state) == [(1,)]
    assert state.roots() == [j.key("f", (1,))]


def test_an_empty_handoff_gives_nothing_away() -> None:
    j = journal()
    j.handoff([])
    assert state_open(j) == [()]


def state_open(j: Journal) -> list[tuple[int, ...]]:
    return keys(replay(j))


def test_nodes_outside_the_accepted_roots_are_never_open() -> None:
    j = journal(roots=((1,),))
    j.failed("f", (-1,), "EXHAUSTED", "time")
    assert state_open(j) == [(1,)]


def test_a_second_shard_adds_roots_and_an_identical_one_changes_nothing() -> None:
    j = journal(roots=((1,),))
    j.shard([("f", (-1,))], name="s2")
    assert sorted(keys(replay(j))) == [(-1,), (1,)]
    again = journal(roots=((1,),))
    again.shard([("f", (1,))], name="s1")
    assert state_open(again) == [(1,)]


def test_overlapping_roots_are_an_integrity_error_when_checked() -> None:
    j = journal(roots=((1,),))
    j.shard([("f", (1, 2))], name="s2")
    with pytest.raises(IntegrityError) as overlap:
        replay(j).check_antichain()
    assert overlap.value.rule == "state.roots"
    ok = journal(roots=((1,), (-1,)))
    replay(ok).check_antichain()


def test_unneeded_running_nodes_are_those_below_a_closed_node() -> None:
    j = journal()
    j.split("f", (), (1,))
    running = [j.key("f", (1,)), j.key("f", (-1,))]
    assert replay(j).unneeded(running) == []
    j.unsat("f", ())  # the root is closed by an admitted leaf: the children are not needed
    assert replay(j).unneeded(running) == sorted(running, key=lambda k: (k[0], _id(k)))


def _id(key: tuple[str, Cube]) -> str:
    from cp_sched_support import node_id

    return node_id(*key)


def test_a_deep_split_chain_needs_no_recursion() -> None:
    f = {"f": formula_bytes(1800, [(1,)])}
    j = Journal(f)
    j.shard([("f", ())])
    cube: tuple[int, ...] = ()
    for variable in range(1, 1501):
        j.split("f", cube, (variable,))
        cube = (*cube, -variable)
    j.unsat("f", cube)
    state = replay(j)
    assert not state.closed(j.key("f"))
    assert len(state.open_nodes()) == 1500  # the positive child of every split
    # closing every positive child closes the chain bottom-up without recursion
    cube = ()
    for variable in range(1, 1501):
        j.unsat("f", (*cube, variable))
        cube = (*cube, -variable)
    assert replay(j).closed(j.key("f"))


def test_the_campaign_view_of_a_loaded_campaign() -> None:
    from cp_sched_support import CORPUS

    from cubeproof.cnf.campaign import load_campaign

    loaded = load_campaign(CORPUS / "campaigns" / "all3" / "campaign.json")
    view = CampaignView.of(loaded)
    assert view.campaign_id == loaded.campaign.campaign_id
    assert view.admit == loaded.campaign.admit
    (entry,) = loaded.campaign.formulas
    assert view.variables == {entry.formula_sha256: loaded.formula(entry.formula_sha256).variables}
    (split,) = loaded.campaign.root_splits
    assert view.root_splits == (((split.node.formula_sha256, split.node.cube), split.variables),)
    j = Journal({"f": loaded.formula(entry.formula_sha256).data}, campaign=view.campaign_id)
    j.shard([("f", root.cube) for root in loaded.campaign.roots])
    state = ReplayState(view)
    state.apply_all(j.records)
    assert keys(state) == list(children(split.node.cube, split.variables))


@pytest.mark.parametrize("kind", ["EXHAUSTED", "TOOL_FAILED", "MODEL", "VERIFIED_UNSAT"])
def test_only_invalid_models_and_rejected_proofs_are_anomalies(kind: str) -> None:
    j = journal(roots=R3, policy_value=policy(anomaly_limit=1))
    a, b, _ = R3
    if kind == "EXHAUSTED":
        j.failed("f", a, "EXHAUSTED", "time")
    elif kind == "TOOL_FAILED":
        j.failed("f", a, "TOOL_FAILED", "crash")
    elif kind == "MODEL":
        j.model("f", a)
    else:
        j.unsat("f", a)
    state = replay(j)
    assert state.session.anomalies == 0 and not state.anomaly_halt
    j.failed("f", b, "CHECK_REJECTED", "rejected")
    assert replay(j).anomaly_halt


def test_the_effective_policy_is_the_latest_header_or_resume_snapshot() -> None:
    from cp_sched_support import j as plain
    from cp_sched_support import sha

    j = journal(policy_value=policy(tool_retries=1))
    first = sha(plain(policy(tool_retries=1)))
    state = replay(j)
    assert state.policy is not None and state.policy.tool_retries == 1
    assert state.policy.sha256 == first and state.epochs == [(0, first)]
    j.resume(policy_value=policy(tool_retries=5))
    state = replay(j)
    assert state.policy.tool_retries == 5  # type: ignore[union-attr]
    assert state.epochs == [(0, first), (2, sha(plain(policy(tool_retries=5))))]
    assert state.snapshot_seq == 2 and state.machinery is not None


def test_the_status_counts_by_state_and_depth() -> None:
    j = journal(roots=Q4)
    j.model("f", Q4[0])
    j.failed("f", Q4[1], "EXHAUSTED", "time")
    j.stop("f", Q4[2], "stuck")
    j.unsat("f", Q4[3])
    state = replay(j)
    assert state.counts() == {("model", 2): 1, ("needs_split", 2): 1, ("stuck", 2): 1}
    assert state.verified_by_depth() == {2: 1}
    j.failed("f", Q4[1], "TOOL_FAILED", "crash")
    assert replay(j).counts()[("pending", 2)] == 1
