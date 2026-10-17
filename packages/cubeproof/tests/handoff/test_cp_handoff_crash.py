"""A crash at every append, move and publish point of acceptance and handoff (specification §7.4,
§7.5).

A scenario is run once without a crash (the crash-free run: its gate counts every point at which the
process may die: each mutating file call of the desk and both sides of each journal append). Then
it is run again for every point ``n``: the process dies at point ``n``, a second process starts from
the files alone and settles, and the result must be the crash-free one: the same shard and handoff
records, the same inbox and outbox files, and the invariants of ``check_invariants`` (no shard or
request committed twice, the giver excluded for good, an output equal to its record byte for byte,
no staging file, nothing lost). A crash of the recovery process itself is covered for a sample of
points (every point in the slow tier).
"""

from __future__ import annotations

import itertools
import os
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from cp_handoff_support import (
    Crash,
    Gate,
    World,
    check_invariants,
    drop_request,
    drop_shard,
    publish,
    request_of,
    shard_of,
    tree,
)
from test_cp_handoff_desk import seeded, split_payload, summary

from cubeproof.base.canonical_json import document_bytes

Drops = Callable[[World], None]


def shard_drops(world: World) -> None:
    first = shard_of([("a", (1,)), ("a", (-1, 2))], name="first")
    drop_shard(world.inbox, first, "1.json")
    drop_shard(world.inbox, first, "2.json")  # the same shard under another name
    drop_shard(world.inbox, shard_of([("a", (1, 2)), ("b", ())], name="clash"), "3.json")
    publish(world.inbox / "4.json", document_bytes({"format": "something-else"}))
    drop_shard(world.inbox, shard_of([("b", ())], name="second"), "5.json")


def handoff_drops(world: World) -> None:
    drop_request(world.inbox, request_of("out1", 2, "1"), "r1.request.json")
    drop_request(world.inbox, request_of("out1", 2, "1"), "r1b.request.json")  # a repeat
    drop_request(world.inbox, request_of("out2", 2, "2"), "r2.request.json")
    drop_request(world.inbox, request_of("out3", 9, "2"), "r3.request.json")  # id 2, other content
    drop_request(world.inbox, request_of("out4", 10, "4"), "r4.request.json")  # the rest
    drop_request(world.inbox, request_of("out5", 3, "5"), "r5.request.json")  # nothing is left


def mixed_drops(world: World) -> None:
    drop_shard(world.inbox, shard_of([("a", (-1,))], name="more"), "m.json")  # fresh work
    drop_shard(world.inbox, shard_of([("a", (1, -2, 3))], name="inside"), "n.json")  # a clash
    handoff_drops(world)


def run_once(world: World, gate: Gate, *, drops: Drops, prepared: bool) -> bool:
    """One worker process; True if it died at the gate's point."""
    drops(world)
    session = world.session(gate=gate)
    try:
        session.start()
        session.settle()
    except Crash:
        session.close()
        return True
    session.close()
    return False


def recover(world: World, gate: Gate | None = None) -> bool:
    session = world.session(gate=gate or Gate())
    try:
        session.start()
        session.settle()
    except Crash:
        session.close()
        return True
    session.close()
    return False


def prepare_handoff(world: World) -> None:
    _, session = seeded(world.root)
    session.close()


def prepare_mixed(world: World) -> None:
    """Roots a(1) and b, a(1) split on variable 2: pending a(1,2), a(1,-2) and b."""
    session = world.session().start()
    session.desk.offer(shard_of([("a", (1,)), ("b", ())], name="initial"))
    session.pump()
    session.append_now(split_payload("a", (1,), (2,)))
    session.close()


def outcome(world: World) -> dict[str, Any]:
    return {
        "records": summary(world),
        "inbox": tree(world.inbox),
        "outbox": tree(world.outbox) if world.outbox.exists() else {},
    }


class Scenario:
    def __init__(self, name: str, drops: Drops, prepare: Callable[[World], None] | None) -> None:
        self.name = name
        self.drops = drops
        self.prepare = prepare

    def world(self, root: Path) -> World:
        world = World(root)
        if self.prepare is not None:
            self.prepare(world)
        return world


SCENARIOS = [
    Scenario("shards", shard_drops, None),
    Scenario("handoff", handoff_drops, prepare_handoff),
    Scenario("mixed", mixed_drops, prepare_mixed),
]
_CRASH_FREE: dict[str, tuple[dict[str, Any], int, list[str]]] = {}
_RUNS = itertools.count()


def crash_free(scenario: Scenario, root: Path) -> tuple[dict[str, Any], int, list[str]]:
    if scenario.name not in _CRASH_FREE:
        world = scenario.world(root / f"base-{scenario.name}")
        gate = Gate()
        assert run_once(world, gate, drops=scenario.drops, prepared=True) is False
        check_invariants(world)
        _CRASH_FREE[scenario.name] = (outcome(world), gate.count, list(gate.log))
    return _CRASH_FREE[scenario.name]


@pytest.fixture(scope="module")
def base_root(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return tmp_path_factory.mktemp("crash")


@pytest.mark.parametrize("scenario", SCENARIOS, ids=lambda s: s.name)
def test_the_crash_free_run_reaches_the_expected_result(
    scenario: Scenario, base_root: Path
) -> None:
    expected, points, log = crash_free(scenario, base_root)
    kinds = {entry.split(" ")[0] for entry in log}
    assert {"append", "appended", "open", "write", "fsync", "link", "unlink"} <= kinds
    assert points >= 20
    records = expected["records"]
    if scenario.name == "shards":
        assert [k for k, _ in records] == ["shard", "shard"]
        assert sorted(n for n in expected["inbox"] if n.startswith("accepted/")) == [
            "accepted/1.json",
            "accepted/2.json",
            "accepted/5.json",
        ]
        assert sorted(n for n in expected["inbox"] if n.startswith("rejected/")) == [
            "rejected/3.json",
            "rejected/3.json.reason.txt",
            "rejected/4.json",
            "rejected/4.json.reason.txt",
        ]
    if scenario.name == "handoff":
        assert [k for k, _ in records] == ["shard", "handoff", "handoff", "handoff", "handoff"]
        assert sorted(expected["outbox"]) == ["out1.json", "out2.json", "out4.json"]
        assert sorted(n for n in expected["inbox"] if n.startswith("rejected/")) == [
            "rejected/r3.request.json",
            "rejected/r3.request.json.reason.txt",
        ]
        assert len([n for n in expected["inbox"] if n.startswith("processed/")]) == 5


def crash_at(scenario: Scenario, root: Path, point: int, *, nested: int | None = None) -> None:
    expected, _, _ = crash_free(scenario, root)
    world = scenario.world(root / f"{scenario.name}-{point}-{nested}-{next(_RUNS)}")
    died = run_once(world, Gate(point), drops=scenario.drops, prepared=True)
    assert died, f"point {point} was not reached"
    if nested is not None and recover(world, Gate(nested)):
        pass  # the recovery died too: a third process finishes
    assert recover(world) is False
    check_invariants(world)
    assert outcome(world) == expected, f"crash at point {point}"


def points(scenario: Scenario, root: Path, *, sample: bool) -> list[int]:
    _, total, log = crash_free(scenario, root)
    everything = list(range(1, total + 1))
    if not sample:
        return everything
    chosen = {1, total}
    seen: set[str] = set()
    for index, entry in enumerate(log, 1):
        label = entry.split(" ")[0]
        if label not in seen or index % 12 == 0:
            seen.add(label)
            chosen.add(index)
    return sorted(chosen)


@pytest.mark.parametrize("scenario", SCENARIOS, ids=lambda s: s.name)
def test_a_crash_at_a_representative_point_leaves_the_crash_free_result(
    scenario: Scenario, base_root: Path
) -> None:
    for point in points(scenario, base_root, sample=True):
        crash_at(scenario, base_root, point)


@pytest.mark.parametrize("scenario", SCENARIOS, ids=lambda s: s.name)
def test_a_crash_of_the_recovery_too_leaves_the_crash_free_result(
    scenario: Scenario, base_root: Path
) -> None:
    for point in points(scenario, base_root, sample=True)[::5]:
        for nested in (1, 3, 8):
            crash_at(scenario, base_root, point, nested=nested)


@pytest.mark.slow
@pytest.mark.parametrize("scenario", SCENARIOS, ids=lambda s: s.name)
def test_a_crash_at_every_point_leaves_the_crash_free_result(
    scenario: Scenario, base_root: Path
) -> None:
    for point in points(scenario, base_root, sample=False):
        crash_at(scenario, base_root, point)


@pytest.mark.slow
@pytest.mark.parametrize("scenario", SCENARIOS, ids=lambda s: s.name)
def test_a_crash_at_every_point_of_the_recovery_too(scenario: Scenario, base_root: Path) -> None:
    for point in points(scenario, base_root, sample=True):
        for nested in range(1, 40):
            crash_at(scenario, base_root, point, nested=nested)


def test_a_committed_handoff_is_published_with_the_same_bytes_after_a_crash(
    tmp_path: Path,
) -> None:
    """The one case of the crash table that matters most: committed, output missing."""
    world, session = seeded(tmp_path)
    drop_request(world.inbox, request_of("gift", 3))
    session.tick()  # the record is committed, the output is not there
    (handoff,) = world.payloads("handoff")
    assert not (world.outbox / "gift.json").exists()
    given = {(n.formula_sha256, n.cube) for n in handoff.shard.nodes}
    session.close()  # the process dies here
    # meanwhile the journal moved on: other work is committed, as another record could be
    again = world.session().start()
    assert set(again.state.given_away()) == given  # the giver stays excluded at once
    assert not given & {n.key for n in again.state.open_nodes()}
    assert (world.outbox / "gift.json").read_bytes() == document_bytes(handoff.shard.to_json())
    again.settle()
    assert len(world.payloads("handoff")) == 1  # never a second node set
    assert os.listdir(world.inbox / "processed") == ["gift.request.json"]
    check_invariants(world)
