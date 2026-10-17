"""``handoff``: the immutable request, a stable ID, pending/completed and the derived responses."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest
from cp_handoff_support import CAMPAIGN, Session, World, drop_request, request_of
from test_cp_handoff_desk import seeded

from cubeproof.base.canonical_json import document_bytes
from cubeproof.base.errors import ConfigurationError, InputError, IntegrityError
from cubeproof.commands.handoff import (
    HandoffCommand,
    HandoffOutcome,
    HandoffState,
    handoff_command,
    request_file_name,
)
from cubeproof.contracts.documents import HandoffRequest
from cubeproof.coordinator.handoff import Ports, write_ports


class Clock:
    """A clock that only moves when the command sleeps; ``on_sleep`` lets a worker act."""

    def __init__(self, on_sleep: Any = None) -> None:
        self.now = 0.0
        self.sleeps: list[float] = []
        self.on_sleep = on_sleep

    def __call__(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds
        if self.on_sleep is not None:
            self.on_sleep()


def run_command(
    world: World, nodes: int = 2, name: str = "gift", wait_ms: int = 0, **options: Any
) -> tuple[HandoffOutcome, Clock]:
    clock = options.pop("clock", None) or Clock()
    command = HandoffCommand(
        world.results, nodes, name, wait_ms=wait_ms, poll_ms=options.pop("poll_ms", 50), **options
    )
    return handoff_command(command, sleep=clock.sleep, clock=clock), clock


def configured(tmp_path: Path) -> World:
    """A results directory configured with an inbox and an outbox, no worker running."""
    world = World(tmp_path)
    world.results.mkdir()
    write_ports(world.results, Ports(CAMPAIGN, str(world.inbox), str(world.outbox)))
    return world


def test_the_request_is_an_immutable_file_in_the_inbox(tmp_path: Path) -> None:
    world = configured(tmp_path)
    outcome, _ = run_command(world, 3, "gift", request_id="ab" * 16)
    path = world.inbox / "gift.request.json"
    request = HandoffRequest(CAMPAIGN, "ab" * 16, 3, "gift")
    assert path.read_bytes() == document_bytes(request.to_json())
    assert outcome.request == request and outcome.request_file == request_file_name("gift")
    assert not os.access(path, os.W_OK) or os.stat(path).st_mode & 0o222 == 0
    assert outcome.state is HandoffState.PENDING and outcome.exit_code == 0
    assert outcome.response is None and outcome.output is None
    assert [p.name for p in world.inbox.iterdir()] == ["gift.request.json"]


def test_a_repeated_command_keeps_the_request_id(tmp_path: Path) -> None:
    world = configured(tmp_path)
    first, _ = run_command(world, 3, "gift")
    second, _ = run_command(world, 3, "gift")
    assert first.request == second.request
    assert [p.name for p in world.inbox.iterdir()] == ["gift.request.json"]
    # also after the worker has processed it
    (world.inbox / "processed").mkdir()
    os.replace(world.inbox / "gift.request.json", world.inbox / "processed" / "gift.request.json")
    third, _ = run_command(world, 3, "gift")
    assert third.request == first.request
    assert not (world.inbox / "gift.request.json").exists()


def test_a_taken_output_name_with_another_count_is_refused(tmp_path: Path) -> None:
    world = configured(tmp_path)
    run_command(world, 3, "gift")
    with pytest.raises(ConfigurationError) as caught:
        run_command(world, 5, "gift")
    assert caught.value.rule == "handoff.name_taken" and "another --output-name" in str(
        caught.value
    )


def test_two_names_make_two_requests(tmp_path: Path) -> None:
    world = configured(tmp_path)
    one, _ = run_command(world, 1, "one")
    two, _ = run_command(world, 1, "two")
    assert one.request.request_id != two.request.request_id
    assert sorted(p.name for p in world.inbox.iterdir()) == ["one.request.json", "two.request.json"]


def test_waiting_for_a_worker_that_is_not_running_times_out_without_a_false_acknowledgement(
    tmp_path: Path,
) -> None:
    world = configured(tmp_path)
    outcome, clock = run_command(world, 2, "gift", wait_ms=300, poll_ms=100)
    assert outcome.state is HandoffState.PENDING and outcome.waited
    assert outcome.exit_code == 1  # specification §12.2: a pending handoff timeout is exit 1
    assert sum(clock.sleeps) == pytest.approx(0.3) and outcome.output is None
    assert (world.inbox / "gift.request.json").exists()  # the request stays durable
    assert not world.outbox.exists()
    document = outcome.to_json()
    assert document["state"] == "pending" and document["response"] is None
    assert document["exit_code"] == 1 and json.dumps(document)


def test_a_command_waits_while_a_worker_serves_the_request(tmp_path: Path) -> None:
    world, session = seeded(tmp_path)
    clock = Clock(on_sleep=session.tick)
    outcome, _ = run_command(world, 3, "gift", wait_ms=5000, poll_ms=10, clock=clock)
    assert outcome.state is HandoffState.COMPLETED and outcome.exit_code == 0 and outcome.waited
    assert outcome.output == str(world.outbox / "gift.json")
    assert outcome.response is not None and outcome.response.nodes == 3
    (handoff,) = world.payloads("handoff")
    assert outcome.response.shard_sha256 == handoff.shard_sha256
    assert outcome.response.to_json()["output"] == "gift.json"
    assert "delivery is not tracked" in outcome.detail
    assert len(clock.sleeps) <= 4


def test_a_request_is_served_at_the_next_run_of_a_stopped_worker(tmp_path: Path) -> None:
    world, session = seeded(tmp_path)
    session.settle()
    session.close()  # the worker is stopped
    outcome, _ = run_command(world, 2, "gift")
    assert outcome.state is HandoffState.PENDING
    again = world.session().start()  # its next run
    again.settle()
    done, _ = run_command(world, 2, "gift")
    assert done.state is HandoffState.COMPLETED and done.request == outcome.request


def test_zero_available_nodes_is_completed_with_an_empty_response(tmp_path: Path) -> None:
    world, session = seeded(tmp_path)
    drop_request(world.inbox, request_of("everything", 50), "x.request.json")
    session.settle()
    outcome, _ = run_command(world, 4, "none")
    session.settle()
    done, clock = run_command(world, 4, "none", wait_ms=500)
    assert clock.sleeps == []  # completed at once
    assert done.state is HandoffState.COMPLETED and done.exit_code == 0
    assert done.response is not None and done.response.empty and done.output is None
    assert done.response.to_json()["shard_sha256"] is None
    assert "no node was available" in done.detail
    assert outcome.state is HandoffState.PENDING
    assert not (world.outbox / "none.json").exists()


def test_a_committed_handoff_whose_output_is_missing_is_publishing_not_completed(
    tmp_path: Path,
) -> None:
    world, session = seeded(tmp_path)
    run_command(world, 2, "gift")
    session.tick()  # the handoff is committed; the output is published by the next step only
    assert len(world.payloads("handoff")) == 1 and not (world.outbox / "gift.json").exists()
    outcome, _ = run_command(world, 2, "gift")
    assert outcome.state is HandoffState.PUBLISHING and outcome.exit_code == 1
    assert outcome.response is not None and outcome.output is None
    session.settle()
    assert run_command(world, 2, "gift")[0].state is HandoffState.COMPLETED


def test_an_output_with_other_bytes_is_blocked_and_never_overwritten(tmp_path: Path) -> None:
    world, session = seeded(tmp_path)
    run_command(world, 2, "gift")
    session.tick()
    world.outbox.mkdir(exist_ok=True)
    (world.outbox / "gift.json").write_bytes(b"stranger\n")
    session.settle()
    outcome, clock = run_command(world, 2, "gift", wait_ms=500)
    assert outcome.state is HandoffState.BLOCKED and outcome.exit_code == 1
    assert "other bytes" in outcome.detail and outcome.output is None
    assert clock.sleeps == []  # a blocked output does not change by waiting
    assert (world.outbox / "gift.json").read_bytes() == b"stranger\n"


def test_a_rejected_request_reports_the_reason(tmp_path: Path) -> None:
    world, session = seeded(tmp_path)
    run_command(world, 2, "gift")
    inbox = world.inbox
    (inbox / "rejected").mkdir()
    os.replace(inbox / "gift.request.json", inbox / "rejected" / "gift.request.json")
    (inbox / "rejected" / "gift.request.json.reason.txt").write_text("handoff.output_name: taken\n")
    outcome, _ = run_command(world, 2, "gift")
    assert outcome.state is HandoffState.REJECTED and outcome.exit_code == 3
    assert outcome.detail == "handoff.output_name: taken"
    assert session.state.roots()  # the worker is untouched


def test_without_configuration_or_inbox_the_command_says_what_to_do(tmp_path: Path) -> None:
    with pytest.raises(ConfigurationError, match="--inbox"):
        run_command(World(tmp_path / "none"), 1, "x")
    world = World(tmp_path / "noinbox")
    world.results.mkdir(parents=True)
    write_ports(world.results, Ports(CAMPAIGN, None, str(world.outbox)))
    with pytest.raises(ConfigurationError, match="no inbox"):
        run_command(world, 1, "x")


@pytest.mark.parametrize(
    ("nodes", "name", "rule"),
    [(0, "x", "handoff.nodes"), (-3, "x", "handoff.nodes"), (1, "X/..", "handoff.output_name")],
)
def test_the_arguments_are_checked_before_anything_is_written(
    tmp_path: Path, nodes: int, name: str, rule: str
) -> None:
    world = configured(tmp_path)
    with pytest.raises(ConfigurationError) as caught:
        run_command(world, nodes, name)
    assert caught.value.rule == rule and not world.inbox.exists()


def test_a_journal_of_another_campaign_is_an_integrity_error(tmp_path: Path) -> None:
    world = configured(tmp_path)
    write_ports(world.results, Ports("cd" * 32, str(world.inbox), str(world.outbox)))
    session = World(tmp_path / "other").session().start()
    session.close()
    (world.results / "journal.jsonl").write_bytes(
        (tmp_path / "other" / "results" / "journal.jsonl").read_bytes()
    )
    with pytest.raises(IntegrityError):
        run_command(world, 1, "x")


def test_a_request_file_that_is_not_a_request_is_an_input_error(tmp_path: Path) -> None:
    world = configured(tmp_path)
    world.inbox.mkdir()
    (world.inbox / "gift.request.json").write_bytes(b"garbage")
    with pytest.raises(InputError) as caught:
        run_command(world, 1, "gift")
    assert caught.value.rule == "handoff.request_file"


def test_the_command_reads_a_journal_that_is_being_created(tmp_path: Path) -> None:
    world = configured(tmp_path)
    world.results.joinpath("journal.jsonl").write_bytes(b'{"format":"cubeproof-jour')
    outcome, _ = run_command(world, 1, "gift")
    assert outcome.state is HandoffState.PENDING


def test_the_session_helper_is_the_one_that_wrote_the_ports(tmp_path: Path) -> None:
    world, session = seeded(tmp_path)
    assert isinstance(session, Session)
    run_command(world, 1, "gift")
    assert (world.results / "ports.json").exists()


def test_a_journal_that_committed_the_request_id_with_other_content_is_an_integrity_error(
    tmp_path: Path,
) -> None:
    world, session = seeded(tmp_path)
    drop_request(world.inbox, request_of("gift", 2, "7"), "gift.request.json")
    session.settle()  # committed for two nodes under id 7
    (world.inbox / "processed" / "gift.request.json").unlink()
    drop_request(world.inbox, request_of("gift", 3, "7"), "gift.request.json")  # a stale twin
    with pytest.raises(IntegrityError) as caught:
        run_command(world, 3, "gift")
    assert caught.value.rule == "handoff.request_conflict"


@pytest.mark.parametrize("twin_count", [3, 5])
def test_a_request_written_by_a_racing_twin_is_adopted_or_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, twin_count: int
) -> None:
    """Two commands for one output name at once: the file that won is the request."""
    from cubeproof.commands import handoff as module

    world = configured(tmp_path)
    twin = request_of("gift", twin_count, "9")

    def lost_the_race(path: str, data: bytes, **options: Any) -> bool:
        Path(path).write_bytes(document_bytes(twin.to_json()))  # the twin published first
        raise IntegrityError("artifact.conflict", f"{path} holds other bytes")

    monkeypatch.setattr(module, "atomic_write", lost_the_race)
    if twin_count == 3:
        outcome, _ = run_command(world, 3, "gift")
        assert outcome.request == twin  # one request, the twin's ID
    else:
        with pytest.raises(ConfigurationError) as caught:
            run_command(world, 3, "gift")
        assert caught.value.rule == "handoff.name_taken"
