"""Test-only helpers of the handoff tests: a world of real files, sessions, crashes, oracles.

A :class:`World` is a campaign of two small formulas with a results directory, an inbox and an
outbox below one temporary directory. A :class:`Session` is one "process" of a worker: it replays
the journal file into a :class:`ReplayState` and an :class:`Ownership`, takes the run lock, opens
the **real** journal writer (a resume after a restart, a header the first time) behind the
same ``WriterPort`` the I/O service uses, and drives a :class:`HandoffDesk` the way the
coordinator does (read the committed records back from the file, apply them, observe them, tick).

Crashes are injected at the points the desk can die at, counted by one :class:`Gate`: every
mutating file call of the desk (``CrashCalls``) and the two sides of every journal append. A
crash raises :class:`Crash` (a BaseException, nothing catches it on the way), the session is
abandoned without any further work (locks and descriptors closed, as the OS does), and the next
session starts from the files alone.

Records are never built by the code under test in the oracles: the expected shard documents and
node IDs come from ``cp_sched_support`` (transcribed from specification §3.2/§4.1).
"""

from __future__ import annotations

import os
import sys
from collections.abc import Callable, Collection, Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[4]
TESTS = REPO / "packages" / "cubeproof" / "tests"
for _path in (TESTS / "scheduler",):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

import cp_sched_support as sched  # noqa: E402

from cubeproof.base.canonical_json import document_bytes  # noqa: E402
from cubeproof.contracts.campaign import Admit  # noqa: E402
from cubeproof.contracts.documents import HandoffRequest, Shard  # noqa: E402
from cubeproof.contracts.values import Node  # noqa: E402
from cubeproof.coordinator.handoff import DeskConfig, HandoffDesk  # noqa: E402
from cubeproof.coordinator.ownership import Ownership  # noqa: E402
from cubeproof.coordinator.service import WriterPort, payload_value  # noqa: E402
from cubeproof.coordinator.state import CampaignView, ReplayState, key_of  # noqa: E402
from cubeproof.evidence.journal import JournalWriter, RunLock  # noqa: E402
from cubeproof.evidence.schema import (  # noqa: E402
    JournalContext,
    Record,
    RecordSequence,
    parse_record,
)
from cubeproof.tools.atomic import FileCalls  # noqa: E402

Cube = tuple[int, ...]
Key = tuple[str, Cube]
CAMPAIGN = sched.CAMPAIGN_ID
FORMULAS = {
    "a": sched.formula_bytes(6, [(1, 2), (-1, 3), (4, 5, 6)]),
    "b": sched.formula_bytes(4, [(1, 2), (3, 4)]),
}
HASH = {name: sched.sha(data) for name, data in FORMULAS.items()}
VARIABLES = {HASH["a"]: 6, HASH["b"]: 4}


def node(name: str, cube: Sequence[int] = ()) -> Node:
    return Node(HASH[name], tuple(cube))


def key(name: str, cube: Sequence[int] = ()) -> Key:
    return (HASH[name], tuple(cube))


def sorted_nodes(nodes: Iterable[Node]) -> tuple[Node, ...]:
    return tuple(sorted(nodes, key=lambda n: n.sort_key))


def shard_of(nodes: Iterable[tuple[str, Sequence[int]]], name: str = "s1") -> Shard:
    return Shard(CAMPAIGN, name, sorted_nodes(node(f, c) for f, c in nodes))


def request_of(output: str, count: int, request_id: str = "1") -> HandoffRequest:
    return HandoffRequest(CAMPAIGN, request_id.rjust(32, "0"), count, output)


def publish(path: Path, data: bytes) -> Path:
    """Atomic publication as a sender would do it (dot-prefixed temporary name, then rename)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name("." + path.name + ".sending")
    temporary.write_bytes(data)
    os.replace(temporary, path)
    return path


def drop_shard(inbox: Path, shard: Shard, file_name: str | None = None) -> Path:
    return publish(inbox / (file_name or f"{shard.name}.json"), document_bytes(shard.to_json()))


def drop_request(inbox: Path, request: HandoffRequest, file_name: str | None = None) -> Path:
    name = file_name or f"{request.output_name}.request.json"
    return publish(inbox / name, document_bytes(request.to_json()))


# -- crashes -----------------------------------------------------------------------------------


class Crash(BaseException):
    """The simulated death of the process (nothing on the way catches a BaseException)."""


class Gate:
    """Counts crash points; raises :class:`Crash` at number ``at`` (never if ``at`` is None)."""

    def __init__(self, at: int | None = None) -> None:
        self.at = at
        self.count = 0
        self.fired: str | None = None
        self.log: list[str] = []

    def __call__(self, what: str) -> None:
        self.count += 1
        self.log.append(what)
        if self.at is not None and self.count == self.at:
            self.fired = what
            raise Crash(what)


class CrashCalls(FileCalls):
    """The desk's file calls with a crash point before every call that changes the disk."""

    def __init__(self, gate: Gate) -> None:
        self.gate = gate

    def open(self, path: str, flags: int, mode: int = 0o600) -> int:
        if flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT):
            self.gate(f"open {os.path.basename(path)}")
        return super().open(path, flags, mode)

    def write(self, fd: int, data: memoryview) -> int:
        self.gate("write")
        return super().write(fd, data)

    def fsync(self, fd: int) -> None:
        self.gate("fsync")
        super().fsync(fd)

    def link(self, source: str, target: str) -> None:
        self.gate(f"link {os.path.basename(target)}")
        super().link(source, target)

    def rename(self, source: str, target: str) -> None:
        self.gate(f"rename {os.path.basename(target)}")
        super().rename(source, target)

    def unlink(self, path: str) -> None:
        self.gate(f"unlink {os.path.basename(path)}")
        super().unlink(path)

    def mkdir(self, path: str, mode: int = 0o755) -> None:
        self.gate(f"mkdir {os.path.basename(path)}")
        super().mkdir(path, mode)


# -- the world ---------------------------------------------------------------------------------


def header_payload(worker: str) -> dict[str, Any]:
    return {
        "type": "header",
        "worker": worker,
        "campaign": CAMPAIGN,
        "purpose": "run",
        "machinery": sched.machinery(),
        "policy": sched.policy(),
        "resources": sched.RESOURCES,
    }


def resume_payload() -> dict[str, Any]:
    return {
        "type": "resume",
        "machinery": sched.machinery(),
        "policy": sched.policy(),
        "resources": sched.RESOURCES,
    }


@dataclass
class World:
    """Directories of one worker plus the helpers to look at them."""

    root: Path
    worker: str = "w1"
    outbox_name: str = "outbox"
    sessions: int = 0

    @property
    def results(self) -> Path:
        return self.root / "results"

    @property
    def journal(self) -> Path:
        return self.results / "journal.jsonl"

    @property
    def inbox(self) -> Path:
        return self.root / "inbox"

    @property
    def outbox(self) -> Path:
        return self.root / self.outbox_name

    def records(self) -> list[Record]:
        """The complete committed records of the journal file."""
        if not self.journal.exists():
            return []
        data = self.journal.read_bytes()
        lines = data[: data.rfind(b"\n") + 1].split(b"\n")[:-1]
        return [parse_record(line, variables=VARIABLES) for line in lines]

    def payloads(self, kind: str) -> list[Any]:
        return [r.payload for r in self.records() if r.type.value == kind]

    def names(self, directory: Path) -> list[str]:
        if not directory.exists():
            return []
        return sorted(p.name for p in directory.iterdir())

    def inbox_names(self, folder: str = "") -> list[str]:
        directory = self.inbox / folder if folder else self.inbox
        return [n for n in self.names(directory) if (directory / n).is_file()]

    def view(self) -> CampaignView:
        return CampaignView(CAMPAIGN, Admit((sched.CHECKER,), None), dict(VARIABLES))

    def state_of_file(self) -> ReplayState:
        state = ReplayState(self.view())
        state.apply_all(self.records())
        return state

    def ownership_of_file(self) -> Ownership:
        return Ownership.from_journal(self.journal, campaign=CAMPAIGN, variables=VARIABLES)

    def session(
        self,
        *,
        gate: Gate | None = None,
        inbox: bool = True,
        outbox: bool = True,
        **config: Any,
    ) -> Session:
        self.sessions += 1
        return Session(self, gate or Gate(), inbox=inbox, outbox=outbox, config=config)

    def seed(self, build: Callable[[Session], None]) -> None:
        """Run ``build`` in a session, then close it (a prepared worker)."""
        session = self.session()
        build(session)
        session.close()


class Session:
    """One process of a worker (module doc)."""

    def __init__(
        self,
        world: World,
        gate: Gate,
        *,
        inbox: bool,
        outbox: bool,
        config: dict[str, Any],
    ) -> None:
        self.world = world
        self.gate = gate
        self.hooks: list[str] = []
        self.ticks = 0
        self.running: set[Key] = set()
        self.appended = 0
        world.results.mkdir(parents=True, exist_ok=True)
        self.state = world.state_of_file()
        self._offset = world.journal.stat().st_size if world.journal.exists() else 0
        data = world.journal.read_bytes() if world.journal.exists() else b""
        self._offset = data.rfind(b"\n") + 1
        self.ownership = (
            world.ownership_of_file() if world.journal.exists() else Ownership(CAMPAIGN, VARIABLES)
        )
        self._time = 0
        values: dict[str, Any] = {
            "campaign": CAMPAIGN,
            "variables": VARIABLES,
            "results": world.results,
            "inbox": world.inbox if inbox else None,
            "outbox": world.outbox if outbox else None,
            "scan_interval_ns": 0,
            "calls": CrashCalls(gate),
            "clock": self._clock,
            "hook": self.hooks.append,
        }
        values.update(config)
        self.desk = HandoffDesk(DeskConfig(**values), self.ownership, self.append)
        self.lock = RunLock.acquire(world.results / "run.lock")
        self.writer: JournalWriter[Record] | None = None
        self.port: WriterPort | None = None
        self.started = False

    def _clock(self) -> int:
        self._time += 1
        return self._time

    # -- lifecycle -----------------------------------------------------------------------------

    def start(self) -> Session:
        """Specification §7.3: the desk's startup before the resume, then the header/resume."""
        self.desk.start()
        self.gate("start.done")
        validator = RecordSequence(context=JournalContext(CAMPAIGN, VARIABLES))
        if self.world.journal.exists() and self.world.journal.stat().st_size:
            self.writer = JournalWriter.open(
                self.world.journal, validator=validator, run_lock=self.lock
            )
            self.port = WriterPort(self.writer)
            self.port.append(resume_payload())
        else:
            self.writer = JournalWriter.create(
                self.world.journal,
                payload_value(header_payload(self.world.worker)),
                validator=validator,
                run_lock=self.lock,
            )
            self.port = WriterPort(self.writer)
        self.started = True
        self.pump()
        return self

    def close(self) -> None:
        """Orderly end or the effect of a crash on the OS resources: descriptors and lock go."""
        if self.writer is not None:
            self.writer.close()
            self.writer = None
        self.lock.release()

    # -- the journal ---------------------------------------------------------------------------

    def append(self, payload: dict[str, Any]) -> None:
        """What the coordinator hands the desk: commit a payload (the I/O service's job)."""
        assert self.port is not None, "start() first"
        self.gate("append")
        self.port.append(payload)
        self.appended += 1
        self.gate("appended")

    def append_now(self, payload: dict[str, Any]) -> Record:
        """Commit a payload outside the desk (a split, a stop, an attempt of the worker)."""
        assert self.port is not None
        self.port.append(payload)
        return self.pump()[-1]

    def pump(self) -> list[Record]:
        """Read the records committed since the last call, apply them, let the desk observe them."""
        data = self.world.journal.read_bytes()
        end = data.rfind(b"\n") + 1
        found = []
        for line in data[self._offset : end].split(b"\n")[:-1]:
            record = parse_record(line, variables=VARIABLES)
            self.state.apply(record)
            self.desk.observe(record)
            found.append(record)
        self._offset = end
        return found

    def tick(self) -> None:
        self.ticks += 1
        self.pump()
        self.desk.tick(self.state, self.running | self.desk.reserved)
        self.pump()

    def settle(self, limit: int = 60) -> int:
        """Tick until the desk is idle and nothing changed for two ticks; the ticks used."""
        calm = 0
        for used in range(1, limit + 1):
            before = self.signature()
            self.tick()
            if not self.desk.busy and self.signature() == before:
                calm += 1
                if calm >= 2:
                    return used
            else:
                calm = 0
        raise AssertionError("the desk did not settle: " + repr(self.desk.problems))

    def signature(self) -> tuple[Any, ...]:
        w = self.world
        return (
            w.journal.stat().st_size if w.journal.exists() else 0,
            tuple(sorted(str(p.relative_to(w.root)) for p in w.root.rglob("*") if p.is_file())),
        )


# -- invariants after any crash and recovery ---------------------------------------------------


def owned_open(state: ReplayState) -> set[Key]:
    return {n.key for n in state.open_nodes()}


def check_invariants(world: World) -> None:
    """What must hold of the files of a worker that has settled, whatever crashed on the way."""
    records = world.records()
    # the chain is valid and every record is fresh: parse_record checked self, rules, schema
    shard_ids = [p.shard_sha256 for p in world.payloads("shard")]
    assert len(shard_ids) == len(set(shard_ids)), "a shard was accepted twice"
    request_ids = [p.request.request_id for p in world.payloads("handoff")]
    assert len(request_ids) == len(set(request_ids)), "a request was handed off twice"
    outputs = [p.request.output_name for p in world.payloads("handoff")]
    assert len(outputs) == len(set(outputs)), "an output name was used twice"
    state = world.state_of_file()
    ownership = world.ownership_of_file()
    given = set(state.given_away())
    assert {
        (n.formula_sha256, n.cube) for g in ownership.handoffs.values() for n in g.nodes
    } == given
    assert not given & owned_open(state), "a given-away node is still open work"
    assert not given & set(state.roots())
    # given-away nodes never get a record after the handoff that gave them away
    gave: dict[Key, int] = {}
    for record in records:
        payload: Any = record.payload
        if payload.TYPE.value == "handoff" and payload.shard is not None:
            gave.update({(n.formula_sha256, n.cube): record.seq for n in payload.shard.nodes})
        elif payload.TYPE.value in ("attempt", "split", "node_stop", "node_reopen"):
            at = key_of(payload.node)
            assert at not in gave, f"{at} used after it was given away (seq {record.seq})"
    # outputs: exactly the committed shard, byte for byte; no staging file left
    for p in world.payloads("handoff"):
        path = world.outbox / f"{p.request.output_name}.json"
        if p.shard is None:
            assert not path.exists(), "an empty handoff published a file"
        else:
            assert path.read_bytes() == document_bytes(p.shard.to_json())
    if world.outbox.exists():
        assert not [n for n in world.names(world.outbox) if n.endswith(".tmp")]
    # inbox: no recorded shard / handled request stays in the inbox proper
    for name in world.inbox_names():
        assert not name.endswith(".tmp")


def tree(root: Path) -> dict[str, str]:
    """Relative file name -> sha256 for every regular file below ``root`` (state comparisons)."""
    import hashlib

    found = {}
    for path in sorted(root.rglob("*")):
        if path.is_file():
            found[str(path.relative_to(root))] = hashlib.sha256(path.read_bytes()).hexdigest()
    return found


@dataclass
class Plan:
    """A scenario: what exists on disk before the worker starts, and what is dropped later."""

    prepare: Callable[[World], None] = lambda world: None
    steps: list[Callable[[World, Session], None]] = field(default_factory=list)


def idle_collection() -> Collection[Key]:
    return frozenset()
