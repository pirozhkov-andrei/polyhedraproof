"""The desk at work: shard acceptance, handoff service, repeated and conflicting requests."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

import pytest
from cp_handoff_support import (
    CAMPAIGN,
    VARIABLES,
    Session,
    World,
    check_invariants,
    drop_request,
    drop_shard,
    key,
    node,
    publish,
    request_of,
    shard_of,
)
from cp_sched_support import node_id

from cubeproof.base.canonical_json import document_bytes
from cubeproof.base.errors import ConfigurationError
from cubeproof.contracts.documents import Shard
from cubeproof.coordinator.handoff import Ports, read_ports, write_ports
from cubeproof.coordinator.ownership import Verdict

KIDS = [(1, 2), (1, -2), (-1, 2), (-1, -2)]


def split_payload(name: str, cube: tuple[int, ...], variables: tuple[int, ...]) -> dict[str, Any]:
    return {
        "type": "split",
        "node": node(name, cube).to_json(),
        "variables": list(variables),
        "splitter": {"name": "lookahead-v1", "info": {}},
    }


def seeded(tmp_path: Path, **options: Any) -> tuple[World, Session]:
    """A worker that owns roots a and b, with a split into four children (five pending nodes);
    the session is running (header committed) and the desk has not scanned yet."""
    world = World(tmp_path)
    session = world.session(**options).start()
    shard = shard_of([("a", ()), ("b", ())], name="initial")
    assert session.desk.offer(shard).verdict is Verdict.ACCEPT
    session.pump()
    session.append_now(split_payload("a", (), (1, 2)))
    return world, session


def summary(world: World) -> list[tuple[str, str]]:
    out = []
    for record in world.records():
        payload: Any = record.payload
        kind = payload.TYPE.value
        if kind == "shard":
            out.append((kind, payload.shard_sha256))
        elif kind == "handoff":
            out.append((kind, f"{payload.request.request_id}:{payload.shard_sha256}"))
    return out


# -- shards ------------------------------------------------------------------------------------


def test_a_shard_in_the_inbox_is_committed_before_its_nodes_exist_and_then_moved(
    tmp_path: Path,
) -> None:
    world = World(tmp_path)
    session = world.session().start()
    shard = shard_of([("a", (1,)), ("a", (-1,))], name="gift")
    path = drop_shard(world.inbox, shard)
    assert session.state.roots() == []
    session.desk.tick(session.state, set())  # judged, submitted; not observed yet
    assert [p.shard_sha256 for p in world.payloads("shard")] == [shard.shard_id]
    assert session.state.roots() == []  # the scheduling state only knows what it has read back
    assert path.exists()  # the file moves after the record, not before
    session.settle()
    assert not path.exists() and (world.inbox / "accepted" / "gift.json").exists()
    assert session.state.roots() == sorted(
        [key("a", (1,)), key("a", (-1,))], key=lambda k: (k[0], node_id(*k))
    )
    assert session.hooks.count("shard.committed") == 1
    check_invariants(world)


def test_an_identical_shard_under_another_name_is_a_no_op(tmp_path: Path) -> None:
    world = World(tmp_path)
    session = world.session().start()
    shard = shard_of([("a", (1,)), ("a", (-1,))], name="gift")
    drop_shard(world.inbox, shard, "first.json")
    session.settle()
    drop_shard(world.inbox, shard, "second.json")
    session.settle()
    assert len(world.payloads("shard")) == 1
    assert world.inbox_names("accepted") == ["first.json", "second.json"]
    assert session.desk.counters["duplicates"] == 1
    check_invariants(world)


def test_a_shard_overlapping_accepted_work_is_rejected_whole_with_a_diagnostic(
    tmp_path: Path,
) -> None:
    world = World(tmp_path)
    session = world.session().start()
    drop_shard(world.inbox, shard_of([("a", (1,))], name="first"), "1.json")
    session.settle()
    mixed = shard_of([("a", (-1,)), ("a", (1, 2))], name="mixed")  # one fresh, one inside "first"
    drop_shard(world.inbox, mixed, "2.json")
    session.settle()
    assert [p.shard.name for p in world.payloads("shard")] == ["first"]  # not partially accepted
    assert world.inbox_names("rejected") == ["2.json", "2.json.reason.txt"]
    reason = (world.inbox / "rejected" / "2.json.reason.txt").read_text()
    assert reason.startswith("shard.overlap: ") and "accepted node" in reason
    assert key("a", (-1,)) not in session.state.roots()
    check_invariants(world)


def test_invalid_files_are_rejected_and_unreadable_ones_wait_until_complete(
    tmp_path: Path,
) -> None:
    world = World(tmp_path)
    session = world.session().start()
    publish(world.inbox / "other.json", document_bytes({"format": "something-else"}))
    shard = shard_of([("a", (1,)), ("a", (-1,))], name="late")
    data = document_bytes(shard.to_json())
    (world.inbox / "copy.json").write_bytes(data[:30])  # a copy in progress
    session.settle()
    assert world.inbox_names("rejected") == ["other.json", "other.json.reason.txt"]
    assert world.inbox_names() == ["copy.json"]
    assert list(session.desk.problems) == ["copy.json"]
    assert session.state.roots() == []
    (world.inbox / "copy.json").write_bytes(data)
    session.settle()
    assert world.inbox_names() == [] and session.desk.problems == {}
    assert [p.shard.name for p in world.payloads("shard")] == ["late"]


def test_a_cli_shard_is_judged_like_an_inbox_shard(tmp_path: Path) -> None:
    world = World(tmp_path)
    session = world.session().start()
    shard = shard_of([("a", ()), ("b", ())], name="initial")
    assert session.desk.offer(shard).verdict is Verdict.ACCEPT
    assert session.desk.busy
    with pytest.raises(ConfigurationError, match="still being committed"):
        session.desk.offer(shard_of([("a", (1,))]))
    session.pump()
    assert not session.desk._active and len(world.payloads("shard")) == 1
    assert session.desk.offer(shard).verdict is Verdict.DUPLICATE
    overlapping = session.desk.offer(shard_of([("a", (1,))], name="x"))
    assert overlapping.verdict is Verdict.REJECT and overlapping.rule == "shard.overlap"
    assert session.desk.counters["duplicates"] == 1 and session.desk.counters["rejected"] == 1
    assert len(world.payloads("shard")) == 1


def test_files_are_handled_in_bounded_batches(tmp_path: Path) -> None:
    world = World(tmp_path)
    session = world.session(files_per_scan=2).start()
    for index, cube in enumerate([(1,), (-1, 2), (-1, -2)]):
        drop_shard(world.inbox, shard_of([("a", cube)], name=f"s{index}"))
    session.tick()
    assert len(world.payloads("shard")) == 1  # at most one append per tick
    session.settle()
    assert len(world.payloads("shard")) == 3 and world.inbox_names() == []


def test_the_inbox_is_scanned_at_most_once_per_interval(tmp_path: Path) -> None:
    world = World(tmp_path)
    session = world.session(scan_interval_ns=10**9).start()
    session.tick()  # the first scan
    drop_shard(world.inbox, shard_of([("a", ())], name="s"))
    for _ in range(5):  # the clock of the test session moves by a few ns per tick
        session.tick()
    assert world.payloads("shard") == [] and world.inbox_names() == ["s.json"]
    session._time += 10**9  # the interval has passed
    session.settle()
    assert len(world.payloads("shard")) == 1


def test_the_desk_is_busy_until_the_first_scan_has_run(tmp_path: Path) -> None:
    world = World(tmp_path)
    session = world.session().start()
    assert session.desk.busy  # requests already waiting must be served before the run ends
    session.tick()
    assert not session.desk.busy


def test_a_desk_without_inbox_or_outbox_does_nothing(tmp_path: Path) -> None:
    world = World(tmp_path)
    session = world.session(inbox=False, outbox=False).start()
    session.settle()
    assert not session.desk.busy and not (world.results / "ports.json").exists()
    assert world.records()[-1].type.value == "header"


# -- handoff -----------------------------------------------------------------------------------


def expected_oldest(count: int) -> list[Any]:
    """b is older than the four children of the split of a; ties by node_id."""
    kids = sorted((key("a", c) for c in KIDS), key=lambda k: node_id(*k))
    return sorted([key("b"), *kids][:count], key=lambda k: (k[0], node_id(*k)))


def test_a_request_is_served_with_the_oldest_pending_nodes(tmp_path: Path) -> None:
    world, session = seeded(tmp_path)
    request = request_of("gift", 3)
    drop_request(world.inbox, request)
    session.settle()
    (handoff,) = world.payloads("handoff")
    assert handoff.request == request and handoff.shard is not None
    assert [(n.formula_sha256, n.cube) for n in handoff.shard.nodes] == expected_oldest(3)
    assert handoff.shard.name == "gift" and handoff.shard.campaign == CAMPAIGN
    output = world.outbox / "gift.json"
    assert output.read_bytes() == document_bytes(handoff.shard.to_json())
    assert Shard.from_json(__import__("json").loads(output.read_text())).shard_id == (
        handoff.shard_sha256
    )
    assert world.inbox_names("processed") == ["gift.request.json"] and world.inbox_names() == []
    assert set(session.state.given_away()) == set(expected_oldest(3))
    assert not set(session.state.given_away()) & {n.key for n in session.state.open_nodes()}
    assert session.hooks.index("handoff.committed") < session.hooks.index("outbox.published")
    check_invariants(world)


def test_fewer_nodes_than_requested_are_given_when_fewer_are_available(tmp_path: Path) -> None:
    world, session = seeded(tmp_path)
    drop_request(world.inbox, request_of("all", 50))
    session.settle()
    (handoff,) = world.payloads("handoff")
    assert handoff.shard is not None and len(handoff.shard.nodes) == 5
    assert session.state.open_nodes() == []
    check_invariants(world)


def test_zero_available_nodes_is_an_empty_completion_not_an_empty_shard(tmp_path: Path) -> None:
    world, session = seeded(tmp_path)
    drop_request(world.inbox, request_of("first", 50), "a.request.json")
    session.settle()
    drop_request(world.inbox, request_of("second", 5, "2"), "b.request.json")
    session.settle()
    first, second = world.payloads("handoff")
    assert second.shard is None and second.shard_sha256 is None
    assert not (world.outbox / "second.json").exists()
    assert sorted(world.inbox_names("processed")) == ["a.request.json", "b.request.json"]
    from cubeproof.coordinator.outbox import response_of

    given = session.ownership.prior("2".rjust(32, "0"))
    assert given is not None
    response = response_of(given)
    assert response.empty and response.output is None and response.shard_sha256 is None
    assert response.to_json()["nodes"] == 0
    assert first.shard is not None
    check_invariants(world)


def test_a_repeated_request_returns_the_prior_result(tmp_path: Path) -> None:
    world, session = seeded(tmp_path)
    request = request_of("gift", 2)
    drop_request(world.inbox, request)
    session.settle()
    before = summary(world)
    output = (world.outbox / "gift.json").read_bytes()
    drop_request(world.inbox, request, "again.request.json")  # the same bytes, another name
    session.settle()
    assert summary(world) == before
    assert world.inbox_names("processed") == ["again.request.json", "gift.request.json"]
    assert (world.outbox / "gift.json").read_bytes() == output
    # a lost output is recreated from the record
    (world.outbox / "gift.json").unlink()
    drop_request(world.inbox, request, "third.request.json")
    session.settle()
    assert (world.outbox / "gift.json").read_bytes() == output and summary(world) == before


def test_a_request_id_with_other_content_is_rejected(tmp_path: Path) -> None:
    world, session = seeded(tmp_path)
    drop_request(world.inbox, request_of("gift", 2))
    session.settle()
    before = summary(world)
    changed = request_of("other", 4)  # same id, other count and name
    drop_request(world.inbox, changed, "changed.request.json")
    session.settle()
    assert summary(world) == before
    assert world.inbox_names("rejected") == [
        "changed.request.json",
        "changed.request.json.reason.txt",
    ]
    assert (
        "request_conflict"
        in (world.inbox / "rejected" / "changed.request.json.reason.txt").read_text()
    )


def test_an_output_name_that_belongs_to_another_request_is_rejected(tmp_path: Path) -> None:
    world, session = seeded(tmp_path)
    drop_request(world.inbox, request_of("gift", 2, "1"))
    session.settle()
    drop_request(world.inbox, request_of("gift", 2, "2"), "second.request.json")
    session.settle()
    assert len(world.payloads("handoff")) == 1
    assert (
        "handoff.output_name"
        in (world.inbox / "rejected" / "second.request.json.reason.txt").read_text()
    )


def test_a_request_of_another_campaign_is_rejected(tmp_path: Path) -> None:
    world, session = seeded(tmp_path)
    foreign = request_of("gift", 2).to_json()
    foreign["campaign"] = "ab" * 32
    publish(world.inbox / "x.request.json", document_bytes(foreign))
    session.settle()
    assert world.payloads("handoff") == []
    assert (
        "request.campaign" in (world.inbox / "rejected" / "x.request.json.reason.txt").read_text()
    )


def test_a_file_in_the_way_leaves_the_request_pending_and_visible(tmp_path: Path) -> None:
    world, session = seeded(tmp_path)
    world.outbox.mkdir(exist_ok=True)
    (world.outbox / "gift.json").write_bytes(b"somebody else's file\n")
    drop_request(world.inbox, request_of("gift", 2))
    session.settle()
    assert world.payloads("handoff") == []  # nothing was given away
    assert world.inbox_names() == ["gift.request.json"]
    assert "handoff.output_exists" in session.desk.problems["gift.request.json"]
    assert (world.outbox / "gift.json").read_bytes() == b"somebody else's file\n"
    (world.outbox / "gift.json").unlink()
    session.settle()
    assert len(world.payloads("handoff")) == 1 and session.desk.problems == {}
    check_invariants(world)


def test_a_file_that_appears_after_the_commit_is_never_overwritten(tmp_path: Path) -> None:
    world, session = seeded(tmp_path)
    drop_request(world.inbox, request_of("gift", 2))
    session.tick()  # the handoff record is committed; the output is not published yet
    assert len(world.payloads("handoff")) == 1 and not (world.outbox / "gift.json").exists()
    (world.outbox / "gift.json").write_bytes(b"late stranger\n")
    session.settle()
    assert (world.outbox / "gift.json").read_bytes() == b"late stranger\n"
    problem = session.desk.problems[next(iter(session.desk.problems))]
    assert problem.startswith("artifact.conflict")
    assert world.inbox_names() == ["gift.request.json"]  # not processed: no durable output
    assert not session.desk.busy  # a blocked output does not keep the run alive
    assert set(session.state.given_away())  # the giver stays excluded
    (world.outbox / "gift.json").unlink()
    session.settle()
    assert (world.outbox / "gift.json").exists() and world.inbox_names("processed")
    check_invariants(world)


def test_nodes_that_run_are_never_given_and_chosen_nodes_are_reserved(tmp_path: Path) -> None:
    world, session = seeded(tmp_path)
    session.running = {key("b"), key("a", (1, 2))}
    drop_request(world.inbox, request_of("gift", 10))
    held: list[dict[str, Any]] = []
    session.desk._append = held.append  # the commit is slow: nothing is written yet
    session.tick()
    (payload,) = held
    chosen = {(n["formula_sha256"], tuple(n["cube"])) for n in payload["shard"]["nodes"]}
    assert chosen == {key("a", (1, -2)), key("a", (-1, 2)), key("a", (-1, -2))}
    assert session.desk.reserved == chosen and session.desk.busy
    session.tick()
    assert len(held) == 1  # one record at a time
    session.desk._append = session.append
    assert session.port is not None
    session.port.append(payload)
    session.pump()
    assert session.desk.reserved == frozenset()
    assert set(session.state.given_away()) == chosen


def test_a_request_without_an_outbox_uses_the_default_one(tmp_path: Path) -> None:
    world, session = seeded(tmp_path, outbox=False)
    drop_request(world.inbox, request_of("gift", 2))
    session.settle()
    assert (world.results / "outbox" / "gift.json").exists()
    ports = read_ports(world.results)
    assert ports.outbox == str(world.results / "outbox") and ports.inbox == str(world.inbox)


def test_a_worker_with_an_outbox_but_no_inbox_republishes_outputs_only(tmp_path: Path) -> None:
    world, session = seeded(tmp_path)
    drop_request(world.inbox, request_of("gift", 2))
    session.settle()
    session.close()
    (world.outbox / "gift.json").unlink()
    again = world.session(inbox=False).start()
    assert (world.outbox / "gift.json").exists()  # at startup, before the resume and any tick
    again.settle()
    assert read_ports(world.results).inbox is None


# -- ports -------------------------------------------------------------------------------------


def test_the_ports_file_is_replaced_when_the_configuration_changes(tmp_path: Path) -> None:
    ports = Ports(CAMPAIGN, "/x/in", "/x/out")
    assert write_ports(tmp_path, ports) is True
    assert write_ports(tmp_path, ports) is False
    assert read_ports(tmp_path) == ports
    other = Ports(CAMPAIGN, None, "/y/out")
    assert write_ports(tmp_path, other) is True and read_ports(tmp_path) == other
    assert sorted(p.name for p in tmp_path.iterdir()) == ["ports.json"]


@pytest.mark.parametrize(
    "text",
    [b"", b"{}\n", b'{"format":"cubeproof-ports-1"}\n', b"not json"],
)
def test_a_damaged_ports_file_is_a_configuration_error(tmp_path: Path, text: bytes) -> None:
    (tmp_path / "ports.json").write_bytes(text)
    with pytest.raises(ConfigurationError):
        read_ports(tmp_path)
    with pytest.raises(ConfigurationError, match=r"no ports\.json"):
        read_ports(tmp_path / "missing")


def test_the_giver_of_a_second_request_never_repeats_the_first_nodes(tmp_path: Path) -> None:
    world, session = seeded(tmp_path)
    drop_request(world.inbox, request_of("one", 2, "1"), "1.request.json")
    session.settle()
    drop_request(world.inbox, request_of("two", 2, "2"), "2.request.json")
    session.settle()
    first, second = world.payloads("handoff")
    ones = {n.node_id for n in first.shard.nodes}
    twos = {n.node_id for n in second.shard.nodes}
    assert ones and twos and not ones & twos
    assert len(ones | twos) == 4
    check_invariants(world)


def test_moves_are_made_in_bounded_batches_too(tmp_path: Path) -> None:
    world = World(tmp_path)
    session = world.session(files_per_scan=2).start()
    shard = shard_of([("a", (1,)), ("a", (-1,))], name="gift")
    drop_shard(world.inbox, shard, "0.json")
    session.settle()
    for index in range(1, 6):
        drop_shard(world.inbox, shard, f"copy{index}.json")
    session.tick()
    assert len(world.inbox_names("accepted")) == 1 + 2  # the first, and two copies
    session.settle()
    assert len(world.inbox_names("accepted")) == 6 and world.inbox_names() == []
    assert len(world.payloads("shard")) == 1


def test_an_output_is_published_from_the_record_alone(tmp_path: Path) -> None:
    """The request file may be gone (moved, deleted): the committed record is enough."""
    world, session = seeded(tmp_path)
    drop_request(world.inbox, request_of("gift", 2))
    session.tick()  # committed, not published
    assert len(world.payloads("handoff")) == 1 and not (world.outbox / "gift.json").exists()
    (world.inbox / "gift.request.json").unlink()
    session.tick()
    (handoff,) = world.payloads("handoff")
    assert (world.outbox / "gift.json").read_bytes() == document_bytes(handoff.shard.to_json())
    session.settle()
    assert world.inbox_names() == [] and world.inbox_names("processed") == []


def test_a_restart_republishes_before_anything_else_and_needs_no_request_file(
    tmp_path: Path,
) -> None:
    world, session = seeded(tmp_path)
    drop_request(world.inbox, request_of("gift", 2))
    session.tick()
    (handoff,) = world.payloads("handoff")
    session.close()
    (world.inbox / "gift.request.json").unlink()
    again = world.session()
    again.desk.start()  # the first thing a restarted worker does, before its resume
    assert (world.outbox / "gift.json").read_bytes() == document_bytes(handoff.shard.to_json())
    again.close()


def test_a_file_that_cannot_be_filed_stays_with_a_visible_problem(tmp_path: Path) -> None:
    world = World(tmp_path)
    session = world.session().start()
    shard = shard_of([("a", (1,)), ("a", (-1,))], name="gift")
    drop_shard(world.inbox, shard, "s.json")
    session.settle()
    code = hashlib.sha256((world.inbox / "accepted" / "s.json").read_bytes()).hexdigest()
    drop_shard(world.inbox, shard, "s.json")  # the same shard again, under the name taken ...
    (world.inbox / "accepted" / "s.json").write_bytes(b"older\n")  # ... by other bytes, and so is
    (world.inbox / "accepted" / f"s.json.{code[:16]}").write_bytes(b"older still\n")  # the suffix
    session.settle()
    assert world.inbox_names() == ["s.json"]
    assert session.desk.problems["s.json"].startswith("inbox.move: ")
    assert len(world.payloads("shard")) == 1


def test_a_shard_replaced_between_the_scan_and_the_move_is_judged_on_its_own(
    tmp_path: Path,
) -> None:
    world = World(tmp_path)
    session = world.session().start()
    session.settle()
    first = shard_of([("a", (1,)), ("a", (-1,))], name="first")
    path = drop_shard(world.inbox, first, "s.json")
    session.settle()  # accepted and moved
    again = drop_shard(world.inbox, first, "s.json")  # a duplicate is waiting to be filed ...
    session.desk._next_scan = 10**18  # (the desk does not look at the inbox ...)
    from cubeproof.coordinator.inbox import scan

    (seen,) = scan(world.inbox, session.desk._known, variables=VARIABLES)
    drop_shard(world.inbox, shard_of([("b", ())], name="other"), "s.json")  # ... replaced by news
    session.desk._file(seen, "accepted")
    assert again.exists() and path.exists() and "s.json" in session.desk.problems
    assert session.desk.problems["s.json"].startswith("inbox.changed")
    session.desk._next_scan = 0
    session.settle()
    assert [p.shard.name for p in world.payloads("shard")] == ["first", "other"]


@pytest.mark.parametrize("kind", ["directory", "link"])
def test_a_directory_or_a_link_at_the_output_name_is_a_conflict_and_is_not_followed(
    tmp_path: Path, kind: str
) -> None:
    from cubeproof.coordinator.outbox import OutputState, output_state, publish_output

    world, session = seeded(tmp_path)
    drop_request(world.inbox, request_of("gift", 2))
    session.tick()  # committed
    given = session.ownership.prior("1".rjust(32, "0"))
    assert given is not None and given.shard is not None
    world.outbox.mkdir(exist_ok=True)
    target = world.outbox / "gift.json"
    if kind == "directory":
        target.mkdir()
    else:
        elsewhere = tmp_path / "elsewhere"
        elsewhere.write_bytes(document_bytes(given.shard.to_json()))  # even the right bytes
        target.symlink_to(elsewhere)
    assert output_state(world.outbox, given) is OutputState.CONFLICT
    with pytest.raises(Exception, match=r"holds other bytes|artifact\.conflict"):
        publish_output(world.outbox, given)
    session.settle()
    assert "artifact.conflict" in next(iter(session.desk.problems.values()))
    assert target.is_dir() if kind == "directory" else target.is_symlink()
