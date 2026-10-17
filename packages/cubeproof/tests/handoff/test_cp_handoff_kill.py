"""The crash table of specification §7.5 with a real SIGKILL: the giver and the receiver die at
each step.

Each worker runs in its own process (``cp_handoff_runner.py``) and kills itself at the named point
of its lifecycle, exactly as a power failure of the process would: no cleanup, the OS closes the
descriptors and releases the locks, the I/O service notices the closed pipe. A second process then
starts from the files alone. The journals are judged by the real certifier.
"""

from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

TESTS = Path(__file__).resolve().parents[1]
if str(TESTS / "lifecycle") not in sys.path:
    sys.path.insert(0, str(TESTS / "lifecycle"))

import cp_life_tools as t  # noqa: E402

from cubeproof.base.canonical_json import document_bytes  # noqa: E402
from cubeproof.cnf.campaign import load_campaign  # noqa: E402
from cubeproof.commands.handoff import HandoffCommand, HandoffState, handoff_command  # noqa: E402
from cubeproof.coordinator.handoff import Ports, write_ports  # noqa: E402
from cubeproof.evidence.certify.run import certify  # noqa: E402

RUNNER = Path(__file__).resolve().parent / "cp_handoff_runner.py"
FORMULAS = {"a": t.unsat(5), "b": t.unsat(4)}


class Pair:
    def __init__(self, root: Path) -> None:
        self.giver = t.make_world(root / "giver", FORMULAS, solver={"max_free": 3})
        self.receiver = t.World(root / "receiver", self.giver.campaign, self.giver.tools)
        self.campaign_id = load_campaign(self.giver.campaign).campaign.campaign_id
        for world in (self.giver, self.receiver):
            world.results.mkdir(parents=True)
        write_ports(
            self.giver.results,
            Ports(self.campaign_id, str(self.inbox(self.giver)), str(self.outbox(self.giver))),
        )

    @staticmethod
    def inbox(world: t.World) -> Path:
        return Path(world.root) / "inbox"

    @staticmethod
    def outbox(world: t.World) -> Path:
        return Path(world.root) / "outbox"

    def run(
        self, world: t.World, name: str, crash: str | None = None
    ) -> subprocess.CompletedProcess[bytes]:
        spec: dict[str, Any] = {
            "campaign": str(world.campaign),
            "results": str(world.results),
            "work": str(world.work),
            "solver": str(world.tools.solver),
            "checker": str(world.tools.checker),
            "worker": name,
            "inbox": str(self.inbox(world)),
            "outbox": str(self.outbox(world)),
            "crash": None if crash is None else {"point": crash, "n": 1},
        }
        path = Path(world.root) / f"spec-{name}-{crash}.json"
        path.write_text(json.dumps(spec), encoding="utf-8")
        completed = subprocess.run(
            [sys.executable, str(RUNNER), str(path)],
            env=t.service_env(),
            capture_output=True,
            check=False,
            timeout=180,
            start_new_session=True,
        )
        t.wait_clean(world.results, world.work)
        return completed

    def deliver(self) -> Path:
        self.inbox(self.receiver).mkdir(parents=True, exist_ok=True)
        target = self.inbox(self.receiver) / "gift.json"
        shutil.copyfile(self.outbox(self.giver) / "gift.json", target)
        return target

    def journal(self, world: t.World, kind: str) -> list[dict[str, Any]]:
        return [r for r in t.journal_records(world.results) if r["type"] == kind]


@pytest.fixture
def pair(tmp_path: Path) -> Pair:
    return Pair(tmp_path)


def killed(completed: subprocess.CompletedProcess[bytes]) -> bool:
    return completed.returncode == -signal.SIGKILL


@pytest.mark.parametrize(
    "point",
    [
        "handoff.submitted",
        "handoff.committed",
        "outbox.published",
        "inbox.processed",
    ],
)
def test_the_giver_is_killed_at_each_step_of_a_handoff(pair: Pair, point: str) -> None:
    request = handoff_command(HandoffCommand(pair.giver.results, 1, "gift"))
    assert request.state is HandoffState.PENDING
    first = pair.run(pair.giver, "w1", crash=point)
    assert killed(first), first.stderr.decode()[-400:]
    committed = pair.journal(pair.giver, "handoff")
    assert len(committed) <= 1
    second = pair.run(pair.giver, "w1")
    assert second.returncode == 0, second.stdout.decode() + second.stderr.decode()
    handoffs = pair.journal(pair.giver, "handoff")
    assert len(handoffs) == 1 and handoffs[0]["shard"] is not None  # one node set, once
    assert (pair.outbox(pair.giver) / "gift.json").read_bytes() == document_bytes(
        handoffs[0]["shard"]
    )
    assert handoff_command(HandoffCommand(pair.giver.results, 1, "gift")).state is (
        HandoffState.COMPLETED
    )
    pair.deliver()
    assert pair.run(pair.receiver, "w2").returncode == 0
    journals = [pair.giver.journal(), pair.receiver.journal()]
    assert certify(pair.giver.campaign, journals).certificate["verdict"] == "PROVED"
    given = {(n["formula_sha256"], tuple(n["cube"])) for n in handoffs[0]["shard"]["nodes"]}
    used = {
        (r["node"]["formula_sha256"], tuple(r["node"]["cube"]))
        for r in t.journal_records(pair.giver.results)
        if r["type"] in ("attempt", "split", "node_stop")
    }
    assert not given & used  # no running given-away subtree, at any point of the giver's history


@pytest.mark.parametrize(
    "point",
    [
        "shard.submitted",
        "shard.committed",
        "inbox.accepted",
    ],
)
def test_the_receiver_is_killed_at_each_step_of_an_acceptance(pair: Pair, point: str) -> None:
    handoff_command(HandoffCommand(pair.giver.results, 1, "gift"))
    assert pair.run(pair.giver, "w1").returncode == 0
    target = pair.deliver()
    first = pair.run(pair.receiver, "w2", crash=point)
    assert killed(first), first.stderr.decode()[-400:]
    second = pair.run(pair.receiver, "w2")
    assert second.returncode == 0, second.stdout.decode() + second.stderr.decode()
    assert len(pair.journal(pair.receiver, "shard")) == 1  # no duplicate acceptance
    assert not target.exists()
    assert (pair.inbox(pair.receiver) / "accepted" / "gift.json").exists()
    journals = [pair.giver.journal(), pair.receiver.journal()]
    assert certify(pair.giver.campaign, journals).certificate["verdict"] == "PROVED"


def test_a_killed_worker_leaves_no_staging_file_after_the_next_start(pair: Pair) -> None:
    handoff_command(HandoffCommand(pair.giver.results, 1, "gift"))
    assert killed(pair.run(pair.giver, "w1", crash="handoff.committed"))
    assert pair.run(pair.giver, "w1").returncode == 0
    names = sorted(p.name for p in pair.outbox(pair.giver).iterdir())
    assert names == ["gift.json"]
    assert os.listdir(pair.inbox(pair.giver) / "processed") == ["gift.request.json"]
