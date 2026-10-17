"""Two workers exchange work through files, with the real coordinator and fake tools
(specification §7.4, §7.5).

The coordinator is wired to the desk by ``cp_handoff_wiring.DeskCoordinator`` (a subclass,
see its module doc). Every test runs real child processes (the I/O service, the fake solver and
checker) on tiny formulas and judges the journals with the real certifier.
"""

from __future__ import annotations

import shutil
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

TESTS = Path(__file__).resolve().parents[1]
if str(TESTS / "lifecycle") not in sys.path:
    sys.path.insert(0, str(TESTS / "lifecycle"))

import cp_life_tools as t  # noqa: E402

from cubeproof.base.canonical_json import document_bytes  # noqa: E402
from cubeproof.base.errors import ConfigurationError  # noqa: E402
from cubeproof.cnf.campaign import load_campaign  # noqa: E402
from cubeproof.commands.handoff import HandoffCommand, HandoffState, handoff_command  # noqa: E402
from cubeproof.contracts.documents import Shard  # noqa: E402
from cubeproof.contracts.values import Node  # noqa: E402
from cubeproof.coordinator.config import RunResult, exit_code_of  # noqa: E402
from cubeproof.coordinator.handoff import Ports, read_ports, write_ports  # noqa: E402
from cubeproof.coordinator.handoff_run import DeskCoordinator, run_with_desk  # noqa: E402
from cubeproof.evidence.certify.run import certify  # noqa: E402

SPLITTING = {"max_free": 3}
FORMULAS = {"a": t.unsat(5), "b": t.unsat(4)}


class Crash(BaseException):
    """The simulated death of the coordinator process at a named point."""


def crash_at(point: str, n: int = 1) -> Callable[[str], None]:
    seen = {"count": 0}

    def hook(name: str) -> None:
        if name == point:
            seen["count"] += 1
            if seen["count"] == n:
                raise Crash(point)

    return hook


class Pair:
    """A giver and a receiver of one campaign, each with its own directories and inbox/outbox."""

    def __init__(self, root: Path) -> None:
        self.giver = t.make_world(root / "giver", FORMULAS, solver=SPLITTING)
        self.receiver = t.World(root / "receiver", self.giver.campaign, self.giver.tools)
        self.campaign_id = load_campaign(self.giver.campaign).campaign.campaign_id
        for world in (self.giver, self.receiver):
            world.results.mkdir(parents=True)

    def inbox(self, world: t.World) -> Path:
        return Path(world.root) / "inbox"

    def outbox(self, world: t.World) -> Path:
        return Path(world.root) / "outbox"

    def configure(self, world: t.World) -> None:
        write_ports(
            world.results,
            Ports(self.campaign_id, str(self.inbox(world)), str(self.outbox(world))),
        )

    def run(
        self, world: t.World, name: str, *, shard: Shard | None = None, **options: Any
    ) -> RunResult:
        config = world.config(worker=name, **options)
        return DeskCoordinator(
            config,
            inbox=self.inbox(world),
            outbox=self.outbox(world),
            shard=shard,
            scan_interval_ns=0,
        ).run()

    def request(self, nodes: int = 1, name: str = "gift", wait_ms: int = 0) -> Any:
        return handoff_command(HandoffCommand(self.giver.results, nodes, name, wait_ms=wait_ms))

    def deliver(self, name: str = "gift", as_name: str | None = None) -> Path:
        self.inbox(self.receiver).mkdir(parents=True, exist_ok=True)
        target = self.inbox(self.receiver) / (as_name or f"{name}.json")
        shutil.copyfile(self.outbox(self.giver) / f"{name}.json", target)
        return target

    def verdict(self, *worlds: t.World) -> dict[str, Any]:
        result = certify(self.giver.campaign, [w.journal() for w in worlds])
        return result.certificate

    def given(self) -> set[tuple[str, tuple[int, ...]]]:
        found: set[tuple[str, tuple[int, ...]]] = set()
        for record in t.journal_records(self.giver.results):
            if record["type"] == "handoff" and record["shard"] is not None:
                found |= {(n["formula_sha256"], tuple(n["cube"])) for n in record["shard"]["nodes"]}
        return found


@pytest.fixture
def pair(tmp_path: Path) -> Pair:
    return Pair(tmp_path)


def nodes_of_journal(
    world: t.World, kinds: tuple[str, ...]
) -> list[tuple[int, tuple[str, tuple[int, ...]]]]:
    found = []
    for record in t.journal_records(world.results):
        if record["type"] in kinds:
            found.append(
                (record["seq"], (record["node"]["formula_sha256"], tuple(record["node"]["cube"])))
            )
    return found


def test_work_given_away_is_proved_by_another_worker(pair: Pair) -> None:
    pair.configure(pair.giver)
    first = pair.request(1)
    assert first.state is HandoffState.PENDING  # the worker is not running: a durable request
    result = pair.run(pair.giver, "w1")
    assert result.exit_code == 0 and result.given_away == 1
    done = pair.request(1, wait_ms=0)
    assert done.state is HandoffState.COMPLETED and done.response is not None
    assert done.response.nodes == 1 and done.request == first.request
    # the giver proved the rest by itself and never touched what it gave away
    given = pair.given()
    assert len(given) == 1
    assert not given & {
        k for _, k in nodes_of_journal(pair.giver, ("attempt", "split", "node_stop"))
    }
    # alone, the giver's evidence is open: the missing delivery stays visible
    alone = pair.verdict(pair.giver)
    assert alone["verdict"] == "OPEN"
    assert {(e["node"]["formula_sha256"], tuple(e["node"]["cube"])) for e in alone["open"]} == given
    # the receiver proves the delivered shard
    pair.deliver()
    taken = pair.run(pair.receiver, "w2")
    assert taken.exit_code == 0 and taken.given_away == 0
    assert pair.verdict(pair.receiver)["verdict"] == "OPEN"  # only its part
    union = pair.verdict(pair.giver, pair.receiver)
    assert union["verdict"] == "PROVED" and union["open"] == []
    assert sorted(p.name for p in (pair.inbox(pair.receiver) / "accepted").iterdir()) == [
        "gift.json"
    ]


def test_a_delayed_or_missing_delivery_keeps_the_coverage_open(pair: Pair) -> None:
    pair.configure(pair.giver)
    pair.request(1)
    pair.run(pair.giver, "w1")
    shard_file = pair.outbox(pair.giver) / "gift.json"
    assert shard_file.exists()
    assert pair.verdict(pair.giver)["verdict"] == "OPEN"
    # a retransmission is possible at any time from the original outbox, with the same bytes
    first = shard_file.read_bytes()
    again = pair.run(pair.giver, "w1")  # restart of the giver: nothing changes
    assert again.exit_code == 0 and shard_file.read_bytes() == first
    pair.deliver()
    assert pair.run(pair.receiver, "w2").exit_code == 0
    pair.deliver(as_name="again.json")  # delivered twice
    assert pair.run(pair.receiver, "w2").exit_code == 0
    assert len([r for r in t.journal_records(pair.receiver.results) if r["type"] == "shard"]) == 1
    assert sorted(p.name for p in (pair.inbox(pair.receiver) / "accepted").iterdir()) == [
        "again.json",
        "gift.json",
    ]
    assert pair.verdict(pair.giver, pair.receiver)["verdict"] == "PROVED"


def test_the_giver_never_takes_back_what_it_gave_away(pair: Pair) -> None:
    pair.configure(pair.giver)
    pair.request(1)
    pair.run(pair.giver, "w1")
    returned = pair.inbox(pair.giver) / "returned.json"
    shutil.copyfile(pair.outbox(pair.giver) / "gift.json", returned)
    result = pair.run(pair.giver, "w1")
    assert result.exit_code == 0 and result.given_away == 1
    reason = pair.inbox(pair.giver) / "rejected" / "returned.json.reason.txt"
    assert reason.read_text().startswith("shard.overlap: ") and "given-away" in reason.read_text()
    shards = [r for r in t.journal_records(pair.giver.results) if r["type"] == "shard"]
    assert len(shards) == 1  # only the first one


def test_zero_available_work_is_an_answer_not_an_empty_shard(pair: Pair) -> None:
    pair.configure(pair.giver)
    pair.request(5, name="all")
    pair.run(pair.giver, "w1")  # gives away both roots: nothing is left to run
    pair.request(2, name="more")
    result = pair.run(pair.giver, "w1")
    assert result.exit_code == 0 and result.given_away == 2
    answer = pair.request(2, name="more")
    assert answer.state is HandoffState.COMPLETED and answer.response is not None
    assert answer.response.empty and answer.output is None
    assert not (pair.outbox(pair.giver) / "more.json").exists()
    handoffs = [r for r in t.journal_records(pair.giver.results) if r["type"] == "handoff"]
    assert [h["shard"] is None for h in handoffs] == [False, True]


def test_the_giver_dies_after_the_commit_and_publishes_the_same_shard_after_restart(
    pair: Pair,
) -> None:
    pair.configure(pair.giver)
    pair.request(1)
    with pytest.raises(Crash):
        pair.run(pair.giver, "w1", hooks=crash_at("handoff.committed"))
    committed = [r for r in t.journal_records(pair.giver.results) if r["type"] == "handoff"]
    assert len(committed) == 1 and not (pair.outbox(pair.giver) / "gift.json").exists()
    t.wait_clean(pair.giver.results, pair.giver.work)
    result = pair.run(pair.giver, "w1")
    assert result.exit_code == 0 and result.given_away == 1
    assert (pair.outbox(pair.giver) / "gift.json").read_bytes() == document_bytes(
        committed[0]["shard"]
    )
    assert len([r for r in t.journal_records(pair.giver.results) if r["type"] == "handoff"]) == 1
    pair.deliver()
    assert pair.run(pair.receiver, "w2").exit_code == 0
    assert pair.verdict(pair.giver, pair.receiver)["verdict"] == "PROVED"


def test_the_receiver_dies_after_the_commit_and_finishes_the_move_after_restart(
    pair: Pair,
) -> None:
    pair.configure(pair.giver)
    pair.request(1)
    pair.run(pair.giver, "w1")
    target = pair.deliver()
    with pytest.raises(Crash):
        pair.run(pair.receiver, "w2", hooks=crash_at("shard.committed"))
    assert target.exists()  # the move was not made
    assert len([r for r in t.journal_records(pair.receiver.results) if r["type"] == "shard"]) == 1
    t.wait_clean(pair.receiver.results, pair.receiver.work)
    assert pair.run(pair.receiver, "w2").exit_code == 0
    assert not target.exists()
    assert (pair.inbox(pair.receiver) / "accepted" / "gift.json").exists()
    assert len([r for r in t.journal_records(pair.receiver.results) if r["type"] == "shard"]) == 1
    assert pair.verdict(pair.giver, pair.receiver)["verdict"] == "PROVED"


@pytest.mark.parametrize(
    "point",
    ["handoff.submitted", "handoff.committed", "outbox.published", "inbox.processed"],
)
def test_the_giver_dies_at_each_step_of_a_handoff(pair: Pair, point: str) -> None:
    pair.configure(pair.giver)
    pair.request(1)
    with pytest.raises(Crash):
        pair.run(pair.giver, "w1", hooks=crash_at(point))
    t.wait_clean(pair.giver.results, pair.giver.work)
    result = pair.run(pair.giver, "w1")
    assert result.exit_code == 0 and result.given_away == 1
    assert len([r for r in t.journal_records(pair.giver.results) if r["type"] == "handoff"]) == 1
    assert pair.request(1).state is HandoffState.COMPLETED
    pair.deliver()
    assert pair.run(pair.receiver, "w2").exit_code == 0
    assert pair.verdict(pair.giver, pair.receiver)["verdict"] == "PROVED"
    assert [p.name for p in (pair.inbox(pair.giver) / "processed").iterdir()] == [
        "gift.request.json"
    ]


def test_the_certifier_does_not_need_the_ports_or_the_outbox(pair: Pair) -> None:
    pair.configure(pair.giver)
    pair.request(1)
    pair.run(pair.giver, "w1")
    pair.deliver()
    pair.run(pair.receiver, "w2")
    shutil.rmtree(pair.outbox(pair.giver))
    (pair.giver.results / "ports.json").unlink()
    assert pair.verdict(pair.giver, pair.receiver)["verdict"] == "PROVED"
    assert load_campaign(pair.giver.campaign).campaign.campaign_id == pair.campaign_id


def root_shard(pair: Pair, *names: str, label: str = "cli") -> Shard:
    loaded = load_campaign(pair.giver.campaign)
    keys = {f.key: f.formula_sha256 for f in loaded.campaign.formulas}
    return Shard(
        pair.campaign_id,
        label,
        tuple(sorted((Node(keys[n], ()) for n in names), key=lambda n: n.sort_key)),
    )


def shard_records(world: t.World) -> list[dict[str, Any]]:
    return [r for r in t.journal_records(world.results) if r["type"] == "shard"]


def test_a_command_line_shard_is_the_first_shard_and_a_later_run_finds_it_again(
    pair: Pair,
) -> None:
    only_a = root_shard(pair, "a")
    first = pair.run(pair.giver, "w1", shard=only_a)
    assert first.exit_code == 0 and first.session.get("desk.accepted") == 1
    assert [r["shard"]["name"] for r in shard_records(pair.giver)] == ["cli"]
    assert pair.verdict(pair.giver)["verdict"] == "OPEN"  # b was never owned
    again = pair.run(pair.giver, "w1", shard=only_a)  # identical: harmless
    assert again.exit_code == 0 and len(shard_records(pair.giver)) == 1
    assert again.session.get("desk.duplicates") == 1
    # a different, disjoint shard is accepted by a later run (specification §7.4: validated like
    # any other)
    other = root_shard(pair, "b", label="more")
    third = pair.run(pair.giver, "w1", shard=other)
    assert third.exit_code == 0 and len(shard_records(pair.giver)) == 2
    assert pair.verdict(pair.giver)["verdict"] == "PROVED"


def test_a_command_line_shard_that_overlaps_this_worker_is_a_configuration_error(
    pair: Pair,
) -> None:
    pair.run(pair.giver, "w1", shard=root_shard(pair, "a"))
    clash = root_shard(pair, "a", "b", label="clash")
    with pytest.raises(ConfigurationError) as caught:
        pair.run(pair.giver, "w1", shard=clash)
    assert caught.value.rule == "shard.overlap" and exit_code_of(caught.value) == 3
    assert len(shard_records(pair.giver)) == 1  # nothing was partially accepted


def test_the_run_reports_the_desk_and_its_visible_problems(pair: Pair) -> None:
    pair.configure(pair.giver)
    pair.outbox(pair.giver).mkdir(parents=True)
    (pair.outbox(pair.giver) / "gift.json").write_bytes(b"in the way\n")
    pair.request(1)
    result = pair.run(pair.giver, "w1")
    assert result.exit_code == 0 and result.given_away == 0
    assert any("handoff.output_exists" in note for note in result.notes)
    assert (pair.inbox(pair.giver) / "gift.request.json").exists()  # still pending, visible
    (pair.outbox(pair.giver) / "gift.json").unlink()
    done = pair.run(pair.giver, "w1")  # all work is proved by now: the answer is "nothing left"
    assert done.given_away == 0 and done.session["desk.empty_handoffs"] == 1
    assert not [n for n in done.notes if n.startswith("handoff ")]
    assert not (pair.outbox(pair.giver) / "gift.json").exists()


def test_work_whose_delivery_never_happened_is_reclaimed_by_a_new_worker_from_open(
    pair: Pair, tmp_path: Path
) -> None:
    """Specification §7.4: handed-off work is reclaimed by a new worker and results directory
    after planning from open coverage; ownership never reverts implicitly."""
    from cubeproof.commands import certify_command
    from cubeproof.commands.shard import ShardRequest, read_shard_file, shard_command

    pair.configure(pair.giver)
    pair.request(1)
    pair.run(pair.giver, "w1")  # gave one root away; the file is never delivered
    given = pair.given()
    assert len(given) == 1
    certificate = tmp_path / "open.json"
    result = certify_command(pair.giver.campaign, [pair.giver.journal()], certificate)
    assert result.certificate["verdict"] == "OPEN"
    plan = shard_command(
        ShardRequest(
            pair.giver.campaign,
            1,
            tmp_path / "plan",
            from_open=certificate,
            journals=[pair.giver.journal()],
        )
    )
    assert plan.nodes == 1 and plan.source == "open"
    third = t.World(tmp_path / "third", pair.giver.campaign, pair.giver.tools)
    loaded = load_campaign(pair.giver.campaign)
    variables = {sha: b.formula.variables for sha, b in loaded.bundles.items()}
    shard = read_shard_file(Path(plan.shards[0].path), variables=variables)
    assert {(n.formula_sha256, n.cube) for n in shard.nodes} == given
    run = run_with_desk(third.config(worker="w3"), shard=shard)
    assert run.exit_code == 0
    union = certify(pair.giver.campaign, [pair.giver.journal(), third.journal()])
    assert union.certificate["verdict"] == "PROVED"
    # the giver still owns nothing of it: its own history is unchanged by the reclaim
    assert pair.given() == given


def test_a_restart_republishes_before_it_commits_its_resume(pair: Pair) -> None:
    """Specification §7.3: step 4 (republish missing handoff outputs) precedes step 5 (resume)."""
    pair.configure(pair.giver)
    pair.request(1)
    with pytest.raises(Crash):
        pair.run(pair.giver, "w1", hooks=crash_at("handoff.committed"))
    t.wait_clean(pair.giver.results, pair.giver.work)
    seen: list[str] = []
    result = pair.run(pair.giver, "w1", hooks=seen.append)
    assert result.exit_code == 0
    assert "outbox.published" in seen and "snapshot.submitted" in seen
    assert seen.index("outbox.published") < seen.index("snapshot.submitted")


def test_the_run_tells_the_handoff_command_where_its_inbox_and_outbox_are(pair: Pair) -> None:
    """No ports file is prepared: the run writes it, and the command finds the worker by it."""
    assert not (pair.giver.results / "ports.json").exists()
    pair.run(pair.giver, "w1")
    ports = read_ports(pair.giver.results)
    assert (ports.campaign, ports.inbox, ports.outbox) == (
        pair.campaign_id,
        str(pair.inbox(pair.giver)),
        str(pair.outbox(pair.giver)),
    )
    answer = pair.request(1)
    assert answer.state is HandoffState.PENDING
    assert (pair.inbox(pair.giver) / "gift.request.json").exists()
    served = pair.run(pair.giver, "w1")
    assert served.session["desk.empty_handoffs"] == 1  # everything was proved already
    assert pair.request(1).state is HandoffState.COMPLETED
