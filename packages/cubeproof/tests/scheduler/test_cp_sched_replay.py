"""Random journals: live state equals replayed state, and closure/frontier equal section 10.

``random_journal`` writes plausible evidence (splits, every outcome, stops, reopens, resumes
that change the policy or the checker, handoffs) while tracking its own naive facts; the live
state is fed record by record with queries in between (so every cache is exercised), the
replay gets the whole prefix at once, and their digests must agree after every record. The
certifier's :class:`~cubeproof.evidence.certify.closure.EvidenceGraph` is the oracle for
closure and for the open frontier (single journal, no given-away nodes).
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field

import pytest
from cp_sched_support import CHECKER, OTHER_HASH, Journal, formula_bytes, node_id, policy

from cubeproof.contracts.identity import split_id
from cubeproof.coordinator.state import Disposition, ReplayState
from cubeproof.evidence.certify.closure import EvidenceGraph, Leaf

V = 6
F = {"f": formula_bytes(V, [(1, 2, 3), (-1, 4), (-2, 5), (-3, 6)])}
SEEDS = range(60)


@dataclass
class Scenario:
    journal: Journal
    roots: list[tuple[int, ...]]
    graph_splits: list[tuple[tuple[int, ...], tuple[int, ...]]] = field(default_factory=list)
    verified: list[tuple[tuple[int, ...], int]] = field(default_factory=list)
    models: set[tuple[int, ...]] = field(default_factory=set)
    labels: list[tuple[tuple[int, ...], int, str | None, str]] = field(default_factory=list)
    handed: bool = False


def random_journal(seed: int, *, handoffs: bool = False) -> Scenario:
    rng = random.Random(seed)
    j = Journal(
        F,
        policy_value=policy(
            tool_retries=rng.randint(0, 2),
            max_cube_size=rng.randint(2, 5),
            anomaly_limit=rng.randint(1, 4),
            machine_failure_limit=rng.randint(2, 3),
        ),
    )
    roots: list[tuple[int, ...]] = rng.choice([[()], [(1,), (-1,)], [(1, 2), (-1,), (1, -2)]])
    j.shard([("f", r) for r in roots])
    scenario = Scenario(j, roots)
    known: list[tuple[int, ...]] = list(roots)
    admitted = True
    for _ in range(rng.randint(8, 45)):
        cube = rng.choice(known)
        action = rng.choices(
            [
                "split",
                "unsat",
                "model",
                "invalid",
                "exhausted",
                "tool",
                "reject",
                "stop",
                "reopen",
                "resume",
                "handoff",
                "badsplit",
                "sweep",
            ],
            [14, 9, 3, 3, 9, 22, 4, 4, 3, 5, 2 if handoffs else 0, 2, 5],
        )[0]
        free = [v for v in range(1, V + 1) if v not in {abs(x) for x in cube}]
        if action == "split" and free:
            w = tuple(rng.sample(free, rng.randint(1, min(2, len(free)))))
            j.split("f", cube, w)
            scenario.graph_splits.append((cube, w))
            for index in range(1 << len(w)):
                signed = [v if index >> b & 1 else -v for b, v in enumerate(w)]
                known.append(tuple(sorted([*cube, *signed], key=abs)))
        elif action == "sweep" and scenario.graph_splits:
            # verify every child of one split: the split (and maybe its ancestors) closes
            split_cube, w = rng.choice(scenario.graph_splits)
            for index in range(1 << len(w)):
                signed = [v if index >> b & 1 else -v for b, v in enumerate(w)]
                child = tuple(sorted([*split_cube, *signed], key=abs))
                seq = j.unsat("f", child)
                if admitted:
                    scenario.verified.append((child, seq))
        elif action == "badsplit" and cube:
            j.split("f", cube, (abs(cube[0]),))  # a variable of the cube: ignored by every reader
        elif action == "unsat":
            seq = j.unsat("f", cube)
            if admitted:
                scenario.verified.append((cube, seq))
        elif action == "model":
            j.model("f", cube)
            scenario.models.add(cube)
        elif action == "invalid":
            j.model("f", cube, outcome="INVALID_MODEL")
        elif action == "exhausted":
            j.failed("f", cube, "EXHAUSTED", rng.choice(["time", "proof_size", "check_memory"]))
        elif action == "tool":
            j.failed("f", cube, "TOOL_FAILED", rng.choice(["crash", "io", "launch"]))
        elif action == "reject":
            j.failed("f", cube, "CHECK_REJECTED", "rejected")
        elif action == "stop":
            state = rng.choice(["stuck", "tool_blocked", "resource_blocked"])
            seq = j.stop("f", cube, state, f"why{rng.randint(0, 3)}")
            scenario.labels.append((cube, seq, state, j.values[seq]["reason"]))
        elif action == "reopen":
            seq = j.reopen("f", cube)
            scenario.labels.append((cube, seq, None, "reopen"))
        elif action == "resume":
            admitted = rng.random() < 0.7
            j.resume(
                policy_value=policy(
                    tool_retries=rng.randint(0, 3),
                    max_cube_size=rng.randint(2, 6),
                    anomaly_limit=rng.randint(1, 4),
                    machine_failure_limit=rng.randint(2, 5),
                ),
                checker=CHECKER if admitted else OTHER_HASH,
            )
        elif action == "handoff":
            leaf = rng.choice(known)
            j.handoff([("f", leaf)], request=f"{len(j.values):x}")
            scenario.handed = True
    return scenario


def oracle(scenario: Scenario) -> EvidenceGraph:
    graph = EvidenceGraph()
    h = scenario.journal.sha("f")
    for cube, w in scenario.graph_splits:
        graph.add_split((h, cube), w)
    for cube, seq in scenario.verified:
        record = scenario.journal.values[seq]
        graph.add_verified(
            (h, cube),
            Leaf("j", seq, record["cnf_sha256"], record["proof_sha256"], record["route"]),
        )
    for cube in scenario.models:
        graph.add_model((h, cube))
    for cube, seq, state, reason in scenario.labels:
        graph.add_label((h, cube), "j", seq, state, reason)
    return graph


def label(node) -> tuple[str, str | None]:  # type: ignore[no-untyped-def]
    if node.disposition is Disposition.MODEL:
        return ("model", None)
    if node.disposition is Disposition.STOPPED:
        return (node.stop_state.value, node.reason)
    return ("pending", None)


@pytest.mark.parametrize("seed", SEEDS)
def test_closure_and_frontier_equal_the_certifiers(seed: int) -> None:
    scenario = random_journal(seed)
    j = scenario.journal
    graph = oracle(scenario)
    state = ReplayState(j.view)
    state.apply_all(j.records)
    h = j.sha("f")
    for root in scenario.roots:
        assert state.closed((h, root)) == graph.closed((h, root)), root
        expected = [(k[1], s, r) for k, s, r in graph.frontier((h, root))]
        found = [(n.key[1], *label(n)) for n in state.iter_open((h, root))]
        assert found == expected, root
    for cube in {c for c, _ in scenario.graph_splits}:
        assert state.closed((h, cube)) == graph.closed((h, cube)), cube


@pytest.mark.parametrize("seed", SEEDS)
def test_live_state_equals_replayed_state_after_every_record(seed: int) -> None:
    scenario = random_journal(seed, handoffs=True)
    j = scenario.journal
    rng = random.Random(seed + 1000)
    live = ReplayState(j.view)
    h = j.sha("f")
    for count, record in enumerate(j.records, start=1):
        live.apply(record)
        if rng.random() < 0.7:
            live.open_nodes()
        if rng.random() < 0.4:
            live.closed((h, rng.choice(scenario.roots)))
        if rng.random() < 0.3:
            live.followups()
        fresh = ReplayState(j.view)
        fresh.apply_all(j.records[:count])
        assert live.digest() == fresh.digest(), (seed, count)
        # closure answers for every node that has a split (and the roots), not only the roots
        asked = {(h, cube) for cube, _ in scenario.graph_splits} | {(h, r) for r in scenario.roots}
        for key in sorted(asked):
            assert live.closed(key) == fresh.closed(key), (seed, count, key)
    assert live.digest_sha256() == fresh.digest_sha256()


@pytest.mark.parametrize("seed", range(20))
def test_the_open_frontier_is_an_antichain_in_depth_first_order(seed: int) -> None:
    scenario = random_journal(seed)
    state = ReplayState(scenario.journal.view)
    state.apply_all(scenario.journal.records)
    for root in scenario.roots:
        nodes = [n.key[1] for n in state.iter_open((scenario.journal.sha("f"), root))]
        for a in nodes:
            assert not any(a != b and set(b) <= set(a) for b in nodes), (a, nodes)
    everything = [n.key for n in state.open_nodes()]
    assert len(everything) == len(set(everything))


def test_the_split_ids_used_by_the_oracle_are_the_contract_ids() -> None:
    j = Journal(F)
    h = j.sha("f")
    from cp_sched_support import split_id as plain

    assert plain(h, (1,), (2, 3)) == split_id(node_id(h, (1,)), (2, 3))


def test_the_random_journals_cover_the_interesting_cases() -> None:
    """The seeds are not vacuous: every disposition and every counter path occurs."""
    seen: dict[str, int] = {}

    def count(name: str, condition: bool) -> None:
        seen[name] = seen.get(name, 0) + int(condition)

    for seed in SEEDS:
        scenario = random_journal(seed, handoffs=True)
        state = ReplayState(scenario.journal.view)
        state.apply_all(scenario.journal.records)
        kinds = {n.disposition for n in state.open_nodes()}
        for kind in Disposition:
            count(kind.value, kind in kinds)
        h = scenario.journal.sha("f")
        count("closed root", any(state.closed((h, r)) for r in scenario.roots))
        count("open root", any(not state.closed((h, r)) for r in scenario.roots))
        count("deep split", len(scenario.graph_splits) >= 3)
        count("not admitted", bool(state.not_admitted))
        count("malformed", bool(state.malformed))
        count("given away", bool(state.given_away()))
        count("anomaly halt", state.anomaly_halt)
        count("machine halt", state.machine_halt)
        count("several epochs", len(state.epochs) >= 3)
        count("followups", bool(state.followups()))
    assert all(value >= 4 for value in seen.values()), seen
    assert len(seen) == 15
