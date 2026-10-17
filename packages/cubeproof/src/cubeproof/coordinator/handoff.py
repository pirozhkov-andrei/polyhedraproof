"""Shard acceptance and durable handoff of one running worker (specification §4.5, §7.3 step 4,
§7.4, §7.5).

:class:`HandoffDesk` is the coordinator's part of the offline exchange. It owns no process and
no thread: the coordinator feeds it every committed record (:meth:`~HandoffDesk.observe`), calls
:meth:`~HandoffDesk.start` once at the place of specification §7.3 step 4 (after the journal is
replayed, before the resume), and :meth:`~HandoffDesk.tick` once per loop iteration after the
committed records are applied. A tick never blocks for long: it re-reads the inbox at most every
``scan_interval_ns``, submits **at most one** journal append (the commit itself is the I/O
service's job; the desk learns about it from ``observe``) and does a bounded amount of file work.

**Acceptance** (specification §7.4). A shard offered by the command line or found in the inbox is
judged by :meth:`Ownership.judge`: a duplicate (same hash) is a no-op, an overlap with an accepted
or given away region is rejected whole with a diagnostic (``rejected/<name>.reason.txt``), the rest
is committed as a ``shard`` record. Only after that record is observed does the scheduling state
contain the nodes, so nothing of the shard runs before its record is durable. The inbox file moves
to ``accepted/`` **derived from the journal**, not from a memory of the move: whenever the file is
still in the inbox and its shard hash is recorded, the move is finished (crash: "shard committed,
inbox move missing").

**Handoff** (specification §7.4). A request file is served in four steps, each repeatable:

1. choose the nodes (:func:`select_nodes`): pending, unsplit, not running, not reserved, oldest
   first (the journal position at which the entry appeared, ties by node_id), at most
   ``node_count``, as many as fit into one journal line;
2. commit one ``handoff`` record with the request and the complete shard (or ``shard: null`` if
   nothing is available). From this record on the nodes are given away for good: the replay state
   never schedules them again, and the desk rejects any later shard that meets them;
3. publish ``outbox/<output_name>.json`` (the embedded shard, atomically; equal bytes already there
   are a no-op). The bytes are a function of the record, so a crash between 2 and 3 publishes the
   same shard after restart and never chooses a second node set;
4. move the request file to ``processed/``, only after the output is durable.

Between the choice and the commit the chosen nodes are :attr:`~HandoffDesk.reserved`: the caller
must not start anything on them (it adds them to the nodes it considers running). A request whose
id is already committed returns the prior result (the output is republished if missing); the same
id with other content is rejected; another request for a taken output name is rejected; an output
name whose file exists but is not ours leaves the request **pending** with a visible problem.

The desk reads and writes only the inbox, the outbox and ``results/ports.json`` (where ``handoff``
finds them); the journal is written through the ``append`` callable the coordinator supplies.
"""

from __future__ import annotations

import os
import time
from collections import Counter
from collections.abc import Callable, Collection, Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cubeproof.base.canonical_json import document_bytes, encode, parse_document
from cubeproof.base.errors import ConfigurationError, ContractError, IntegrityError, ResourceError
from cubeproof.base.settings import DEFAULT_LIMITS, ReaderLimits
from cubeproof.contracts.documents import HandoffRequest, Shard
from cubeproof.contracts.identity import node_id
from cubeproof.contracts.primitives import is_hash
from cubeproof.contracts.values import Node
from cubeproof.coordinator.inbox import (
    ACCEPTED,
    PROCESSED,
    REJECTED,
    InboxFile,
    Kind,
    move_into,
    scan,
    write_reason,
)
from cubeproof.coordinator.outbox import (
    OutputState,
    clean_staging,
    ensure_tree,
    exists,
    output_file,
    output_state,
    publish_output,
)
from cubeproof.coordinator.ownership import (
    RECORD_OVERHEAD,
    Given,
    Judgement,
    Ownership,
    Verdict,
)
from cubeproof.coordinator.state import Disposition, ReplayState, iter_children
from cubeproof.evidence.schema import Handoff, Record, ShardRecord
from cubeproof.tools.atomic import (
    OS_FILE_CALLS,
    FileCalls,
    fsync,
    fsync_directory,
    write_all,
)

__all__ = [
    "DeskConfig",
    "HandoffDesk",
    "Ports",
    "pending_frontier",
    "read_ports",
    "select_nodes",
    "write_ports",
]

Cube = tuple[int, ...]
Key = tuple[str, Cube]
PORTS_NAME = "ports.json"
PORTS_FORMAT = "cubeproof-ports-1"


# -- which nodes can be given away -------------------------------------------------------------


def pending_frontier(state: ReplayState, ownership: Ownership) -> list[tuple[int, str, Key]]:
    """``(entry seq, node_id, key)`` of every pending, unsplit frontier node of the owned region.

    The nodes are the ones the state calls pending (:meth:`ReplayState.open_nodes`: not closed,
    not given away, not a model, not stopped, not waiting for a split). The traversal only adds
    where each one came from, following specification §10.3 (closed subtrees are not entered, models
    are not descended, the smallest split_id is followed, children in index order):
    the journal position at which its entry appeared, i.e. the shard record for a root, the split
    record for a child (-1 for a campaign split that is not in the journal).
    """
    pending = {n.key for n in state.open_nodes() if n.disposition is Disposition.PENDING}
    if not pending:
        return []
    found: list[tuple[int, str, Key]] = []
    for root in state.roots():
        frames: list[tuple[int, Iterator[Cube]]] = [(ownership.root_seq(root), iter((root[1],)))]
        while frames:
            seq, source = frames[-1]
            cube = next(source, None)
            if cube is None:
                frames.pop()
                continue
            key = (root[0], cube)
            if state.closed(key):
                continue  # nothing below a closed node is work (and a closed subtree can be huge)
            facts = state.facts(key)
            if facts is not None and facts.model:
                continue
            if facts is not None and facts.splits:
                ident = min(facts.splits)
                frames.append(
                    (ownership.split_seq(key, ident), iter_children(cube, facts.splits[ident]))
                )
                continue
            if key in pending:
                found.append((seq, node_id(*key), key))
    return found


def select_nodes(
    state: ReplayState,
    ownership: Ownership,
    *,
    running: Collection[Key],
    node_count: int,
    output_name: str,
    max_line_bytes: int = DEFAULT_LIMITS.line_bytes,
) -> list[Node]:
    """Up to ``node_count`` nodes to give away, sorted ``(formula_sha256, node_id)`` for the shard.

    A candidate is pending and unsplit (a leaf of the specification §10.3 frontier the state calls
    pending: not stopped, not a model, not waiting for a split or a stop), and is **not running**:
    nothing in ``running`` is ever chosen, so no live attempt, split or stop belongs to a given-away
    node. Candidates are taken oldest first, ties by node_id, while the shard and the record that
    will carry it fit into ``max_line_bytes``. A request that cannot get one node gets none.
    """
    if type(node_count) is not int or node_count < 1:
        raise ValueError("node_count must be a positive integer")
    blocked = set(running)
    ranked = sorted(
        (item for item in pending_frontier(state, ownership) if item[2] not in blocked),
        key=lambda item: (item[0], item[1]),
    )
    chosen: list[Node] = []
    size = len(encode({"format": "x" * 20, "campaign": "0" * 64, "name": output_name, "nodes": []}))
    size += RECORD_OVERHEAD + 512  # envelope and request
    for _, _, key in ranked:
        if len(chosen) >= node_count:
            break
        node = Node(key[0], key[1])
        size += len(encode(node.to_json())) + 1
        if size > max_line_bytes:
            break
        chosen.append(node)
    return sorted(chosen, key=lambda n: n.sort_key)


# -- where the exchange happens (results/ports.json) -------------------------------------------


@dataclass(frozen=True)
class Ports:
    """The inbox and outbox a results directory is configured with, as the ``handoff`` command
    finds them (``results/ports.json``, written by the run; derived configuration, not evidence)."""

    campaign: str
    inbox: str | None
    outbox: str | None

    def to_json(self) -> dict[str, Any]:
        return {
            "format": PORTS_FORMAT,
            "campaign": self.campaign,
            "inbox": self.inbox,
            "outbox": self.outbox,
        }


def write_ports(results: Path, ports: Ports, calls: FileCalls = OS_FILE_CALLS) -> bool:
    """Make ``ports`` the configuration of ``results``; True if the file changed.

    Replaced atomically (the previous run's configuration may differ): temporary file, fsync,
    rename, directory fsync."""
    data = document_bytes(ports.to_json())
    target = results / PORTS_NAME
    try:
        if target.read_bytes() == data:
            return False
    except FileNotFoundError:
        pass
    temporary = results / f".{PORTS_NAME}.tmp"
    fd = calls.open(str(temporary), _WRITE_NEW, 0o644)
    try:
        write_all(calls, fd, data)
        fsync(calls, fd, str(temporary))
    finally:
        calls.close(fd)
    calls.rename(str(temporary), str(target))
    fsync_directory(calls, str(results))
    return True


def read_ports(results: Path, limits: ReaderLimits = DEFAULT_LIMITS) -> Ports:
    """The configuration written by the run. ConfigurationError if there is none."""
    path = results / PORTS_NAME
    try:
        data = path.read_bytes()
    except FileNotFoundError:
        raise ConfigurationError(
            "handoff.ports",
            f"{results} has no {PORTS_NAME}: run the worker once with --inbox (and --outbox)",
        ) from None
    try:
        value = parse_document(data, limits=limits)
        if (
            not isinstance(value, dict)
            or set(value) != {"format", "campaign", "inbox", "outbox"}
            or value["format"] != PORTS_FORMAT
            or not is_hash(value["campaign"])
            or any(
                value[k] is not None and not isinstance(value[k], str) for k in ("inbox", "outbox")
            )
        ):
            raise ContractError("schema", "not a ports document")
    except (ContractError, ResourceError) as error:
        raise ConfigurationError("handoff.ports", f"{path}: {error}") from None
    return Ports(value["campaign"], value["inbox"], value["outbox"])


_WRITE_NEW = os.O_WRONLY | os.O_CREAT | os.O_TRUNC


# -- the desk ----------------------------------------------------------------------------------


@dataclass(frozen=True)
class DeskConfig:
    """What the desk needs from the run (built by the coordinator)."""

    campaign: str
    variables: Mapping[str, int]
    results: Path
    inbox: Path | None = None
    outbox: Path | None = None
    limits: ReaderLimits = DEFAULT_LIMITS
    scan_interval_ns: int = 250_000_000
    files_per_scan: int = 64
    calls: FileCalls = OS_FILE_CALLS
    clock: Callable[[], int] = time.monotonic_ns
    hook: Callable[[str], None] | None = None

    @property
    def enabled(self) -> bool:
        return self.inbox is not None or self.outbox is not None


@dataclass(frozen=True)
class _Active:
    kind: str  # "shard" | "handoff"
    key: str  # shard id | request id


class HandoffDesk:
    """Shard acceptance, handoff service and their cleanup (module doc)."""

    def __init__(
        self,
        config: DeskConfig,
        ownership: Ownership,
        append: Callable[[dict[str, Any]], None],
    ) -> None:
        self.config = config
        self.ownership = ownership
        self._append = append
        self._active: _Active | None = None
        self._reserved: frozenset[Key] = frozenset()
        self._known: dict[str, InboxFile] = {}
        self._unpublished: set[str] = set()
        self._next_scan = 0
        self._scanned = False
        self._cleanup_due = False
        self._acts = 0
        self._origin: dict[str, str] = {}
        self._file_problems: dict[str, str] = {}
        self._output_problems: dict[str, str] = {}
        self.counters: Counter[str] = Counter()

    # -- views ---------------------------------------------------------------------------------

    @property
    def reserved(self) -> frozenset[Key]:
        """Nodes chosen for a handoff not yet committed: nothing may start on them."""
        return self._reserved

    @property
    def busy(self) -> bool:
        """Work is in flight or owed: a record is being committed, a first inbox scan has not
        happened, an output is unpublished or a finished move is waiting for the next scan."""
        if self._active is not None:
            return True
        if not self.config.enabled:
            return False
        if self.config.inbox is not None and (not self._scanned or self._cleanup_due):
            return True
        return any(r not in self._output_problems for r in self._unpublished)

    @property
    def problems(self) -> dict[str, str]:
        """Visible problems: files that wait (unreadable, name taken) and unpublished outputs."""
        return {**self._file_problems, **self._output_problems}

    def summary(self) -> dict[str, int]:
        return {
            **dict(sorted(self.counters.items())),
            "unpublished": len(self._unpublished),
            "problems": len(self.problems),
        }

    def _hook(self, name: str) -> None:
        if self.config.hook is not None:
            self.config.hook(name)

    def inbox_offers(self) -> bool:
        """Whether the inbox holds a shard document now: at first use without ``--shard`` such a
        shard, not an invented all-roots shard, is the worker's first (specification §7.4, §12.1);
        otherwise the all-roots shard would be accepted first and the delivered one rejected as an
        overlap."""
        config = self.config
        if config.inbox is None:
            return False
        items = scan(
            config.inbox,
            self._known,
            limits=config.limits,
            variables=config.variables,
            calls=config.calls,
        )
        return any(item.kind is Kind.SHARD for item in items)

    # -- startup (specification §7.3 step 4) -------------------------------------------------------

    def start(self) -> None:
        """Republish missing outputs from the records, finish the moves of accepted inbox files,
        remove interrupted temporary files and write ``ports.json``. Submits nothing."""
        config = self.config
        if not config.enabled:
            return
        outbox = self._outbox_dir()
        if outbox is not None:
            ensure_tree(outbox, config.calls)
            clean_staging(outbox, config.calls)
        self._unpublished = {r for r, g in self.ownership.handoffs.items() if g.shard is not None}
        self._publish_missing(retry_problems=True)
        if config.inbox is not None:
            ensure_tree(config.inbox, config.calls)
            clean_staging(config.inbox / REJECTED, config.calls)
            self._work_inbox(None, (), submit=False)
        write_ports(
            config.results,
            Ports(
                config.campaign,
                None if config.inbox is None else str(config.inbox),
                None if outbox is None else str(outbox),
            ),
            config.calls,
        )

    # -- records -------------------------------------------------------------------------------

    def observe(self, record: Record) -> None:
        """Every committed record, in order, from the coordinator's synchronisation."""
        self.ownership.observe(record)
        payload = record.payload
        if isinstance(payload, ShardRecord):
            if self._active == _Active("shard", payload.shard_sha256):
                self._active = None
            self._cleanup_due = True
            self._next_scan = 0
            self.counters["accepted"] += 1
            self._hook("shard.committed")
        elif isinstance(payload, Handoff):
            if self._active == _Active("handoff", payload.request.request_id):
                self._active = None
                self._reserved = frozenset()
            if payload.shard is not None:
                self._unpublished.add(payload.request.request_id)
            self._cleanup_due = True
            self._next_scan = 0
            self.counters["handoffs" if payload.shard is not None else "empty_handoffs"] += 1
            self._hook("handoff.committed")

    # -- the loop ------------------------------------------------------------------------------

    def offer(self, shard: Shard) -> Judgement:
        """A shard from the command line or the coordinator itself (specification §7.4, §12.1):
        judged like an inbox shard; an acceptable one is submitted as a ``shard`` record. The caller
        waits for its record (``observe``) before it schedules. Not allowed while a record is in
        flight."""
        if self._active is not None:
            raise ConfigurationError(
                "handoff.busy", "a record of the desk is still being committed"
            )
        judgement = self.ownership.judge(shard, max_line_bytes=self.config.limits.line_bytes)
        if judgement.verdict is Verdict.ACCEPT:
            self._submit_shard(shard)
        elif judgement.verdict is Verdict.DUPLICATE:
            self.counters["duplicates"] += 1
        else:
            self.counters["rejected"] += 1
        return judgement

    def tick(self, state: ReplayState, running: Collection[Key]) -> None:
        """One loop iteration after the committed records are applied to ``state``."""
        if not self.config.enabled:
            return
        now = self.config.clock()
        due = now >= self._next_scan
        self._publish_missing(retry_problems=due)
        if self.config.inbox is None or not due:
            return
        self._next_scan = now + self.config.scan_interval_ns
        self._work_inbox(state, running, submit=True)

    # -- inbox ---------------------------------------------------------------------------------

    def _work_inbox(
        self, state: ReplayState | None, running: Collection[Key], *, submit: bool
    ) -> None:
        config = self.config
        assert config.inbox is not None
        items = scan(
            config.inbox,
            self._known,
            limits=config.limits,
            variables=config.variables,
            calls=config.calls,
        )
        self._file_problems = {}
        start = self._acts
        for item in items:
            if self._acts - start >= config.files_per_scan:
                self._next_scan = 0  # bounded work per tick: the next tick continues
                return
            self._handle(item, state, running, submit=submit)
        self._cleanup_due = False
        if submit:
            self._scanned = True

    def _handle(
        self, item: InboxFile, state: ReplayState | None, running: Collection[Key], *, submit: bool
    ) -> None:
        if item.kind is Kind.UNREADABLE:
            self._file_problems[item.name] = item.problem
        elif item.kind is Kind.INVALID:
            self._reject(item, item.rule, item.detail)
        elif item.kind is Kind.SHARD:
            self._handle_shard(item, submit=submit)
        else:
            self._handle_request(item, state, running, submit=submit)

    def _handle_shard(self, item: InboxFile, *, submit: bool) -> None:
        shard = item.shard
        assert shard is not None
        if self.ownership.knows_shard(shard.shard_id):
            # the file whose shard this session committed is accepted, any other is a duplicate
            fresh = self._origin.pop(shard.shard_id, None) == item.name
            self.counters["accepted_files" if fresh else "duplicates"] += 1
            self._file(item, ACCEPTED)
            return
        judgement = self.ownership.judge(shard, max_line_bytes=self.config.limits.line_bytes)
        if judgement.verdict is Verdict.REJECT:
            self._reject(item, judgement.rule or "shard", judgement.detail)
        elif submit and self._active is None:
            self._origin[shard.shard_id] = item.name
            self._submit_shard(shard)

    def _handle_request(
        self, item: InboxFile, state: ReplayState | None, running: Collection[Key], *, submit: bool
    ) -> None:
        request = item.request
        assert request is not None
        if request.campaign != self.config.campaign:
            self._reject(item, "request.campaign", "the request is of another campaign")
            return
        prior = self.ownership.prior(request.request_id)
        if prior is not None:
            if prior.request != request:
                self._reject(
                    item,
                    "handoff.request_conflict",
                    f"request {request.request_id} was committed with other content "
                    "(repeated request IDs must have identical bytes)",
                )
            else:
                self._complete(item, prior)
            return
        holder = self.ownership.output_owner(request.output_name)
        if holder is not None:
            self._reject(
                item,
                "handoff.output_name",
                f"output name {request.output_name!r} belongs to request "
                f"{holder.request.request_id}",
            )
            return
        if not submit or self._active is not None or state is None:
            return
        outbox = self._outbox_dir()
        if outbox is None:
            self._file_problems[item.name] = "handoff.no_outbox: this worker has no outbox"
            return
        target = output_file(outbox, request.output_name)
        if exists(str(target), self.config.calls):
            self._file_problems[item.name] = (
                f"handoff.output_exists: {target} exists and is no committed handoff's output"
            )
            return
        nodes = select_nodes(
            state,
            self.ownership,
            running={*running, *self._reserved},
            node_count=request.node_count,
            output_name=request.output_name,
            max_line_bytes=self.config.limits.line_bytes,
        )
        self._submit_handoff(request, nodes)

    def _outbox_dir(self) -> Path | None:
        if self.config.outbox is not None:
            return self.config.outbox
        return None if self.config.inbox is None else self.config.results / "outbox"

    # -- submissions ---------------------------------------------------------------------------

    def _submit_shard(self, shard: Shard) -> None:
        payload = {"type": "shard", "shard": shard.to_json(), "shard_sha256": shard.shard_id}
        self._acts += 1
        self._active = _Active("shard", shard.shard_id)
        self._hook("shard.submitted")
        try:
            self._append(payload)
        except BaseException:
            self._active = None
            raise

    def _submit_handoff(self, request: HandoffRequest, nodes: list[Node]) -> None:
        shard = Shard(self.config.campaign, request.output_name, tuple(nodes)) if nodes else None
        payload = {
            "type": "handoff",
            "request": request.to_json(),
            "shard": None if shard is None else shard.to_json(),
            "shard_sha256": None if shard is None else shard.shard_id,
        }
        self._acts += 1
        self._active = _Active("handoff", request.request_id)
        self._reserved = frozenset((n.formula_sha256, n.cube) for n in nodes)
        self._hook("handoff.submitted")
        try:
            self._append(payload)
        except BaseException:
            self._active = None
            self._reserved = frozenset()
            raise

    # -- outputs and files ---------------------------------------------------------------------

    def _publish_missing(self, *, retry_problems: bool) -> None:
        outbox = self._outbox_dir()
        for request_id in sorted(self._unpublished):
            if request_id in self._output_problems and not retry_problems:
                continue
            given = self.ownership.handoffs[request_id]
            if outbox is None:
                self._output_problems[request_id] = "handoff.no_outbox: this worker has no outbox"
                continue
            self._publish_one(outbox, given)

    def _publish_one(self, outbox: Path, given: Given) -> bool:
        """Ensure the output of a committed handoff is durable; whether it is."""
        request_id = given.request.request_id
        state = output_state(outbox, given, self.config.calls)
        if state is OutputState.MISSING:
            try:
                publish_output(outbox, given, self.config.calls)
            except IntegrityError as error:
                self._output_problems[request_id] = f"{error.rule}: {error.detail}"
                return False
            self.counters["published"] += 1
            self._hook("outbox.published")
        elif state is OutputState.CONFLICT:
            path = output_file(outbox, given.request.output_name)
            self._output_problems[request_id] = (
                f"artifact.conflict: {path} holds other bytes than the committed handoff"
            )
            return False
        self._unpublished.discard(request_id)
        self._output_problems.pop(request_id, None)
        return True

    def _complete(self, item: InboxFile, given: Given) -> None:
        """A request whose handoff is committed: the output durable, then the request processed."""
        if given.shard is not None:
            outbox = self._outbox_dir()
            if outbox is None or not self._publish_one(outbox, given):
                return
        self._file(item, PROCESSED)

    def _file(self, item: InboxFile, folder: str) -> None:
        assert self.config.inbox is not None
        try:
            move_into(item.path, self.config.inbox / folder, item.sha256, self.config.calls)
        except IntegrityError as error:  # both names in the folder hold other bytes
            self._file_problems[item.name] = f"{error.rule}: {error.detail}"
            return
        self._acts += 1
        self._known.pop(item.name, None)
        self._hook(f"inbox.{folder}")

    def _reject(self, item: InboxFile, rule: str, detail: str) -> None:
        assert self.config.inbox is not None
        directory = self.config.inbox / REJECTED
        write_reason(directory, item.name, rule, detail, self.config.calls)
        self.counters["rejected"] += 1
        self._file(item, REJECTED)
