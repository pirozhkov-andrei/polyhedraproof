"""Deterministic replay of one worker's journal into scheduling state (specification §6.5, §7.3,
§7.4, §10).

:class:`ReplayState` is a pure fold over validated journal records (the journal reader's output,
in seq order). The same ``apply`` serves the live coordinator (one record after its durable
commit) and startup replay (the whole journal), so live state equals replayed state by
construction; ``digest()`` is the canonical comparison value. Nothing here does I/O, reads
the clock or consults a cache: a state cache is only an optimisation that must reproduce this
fold (specification §7.3) and neither certifier may read it.

What the fold keeps, per record type:

- ``header``/``resume``: the **effective policy** and machinery snapshot, an epoch counter
  and the session counters (anomalies since the latest header/resume, specification §6.5;
  consecutive TOOL_FAILED outcomes of the machine). Both session counters restart at every
  header/resume: the machine counter is "consecutive in journal commit order" and a restart
  after an exit-5 stop must be able to run again (the per-node counter, in
  contrast, persists across resume until a non-TOOL_FAILED result or ``node_reopen``).
- ``shard``/``handoff``: the accepted roots and the given-away nodes (specification §7.4). A node is
  scheduled only below an accepted root and outside given-away regions.
- ``split``: well-formed splits by split_id; a split with a W problem (specification §10.1) is
  ignored and listed. Campaign root splits are the same kind of evidence and are loaded first.
- ``attempt``: per node the latest outcome, the attempt count and the consecutive
  TOOL_FAILED count; an admitted VERIFIED_UNSAT closes the node, a MODEL marks it a model.
  **Admission is §10's** (:func:`~cubeproof.evidence.certify.admission.admission_reason` of
  the attempt's own snapshot machinery and ``success_problem``): a record that the
  certifier would list as not admitted, or whose success fields are inconsistent, never
  closes a node for scheduling, whatever the outcome field says.
  Stream arena retries (specification §6.4): an arena-exhausted stream record keeps its node pending
  for a fresh attempt iff ``leaf.retry`` derives one from the record within the policy maxima
  and the memory budget of the snapshot in force (judged once, when the record is applied);
  the node's arena floor (:meth:`ReplayState.stream_arena`) is folded from its own attempts.
- ``node_stop``/``node_reopen``: the latest event per node; a reopen also clears the
  per-node TOOL_FAILED counter. A new policy never clears a stop.

Open nodes (:meth:`ReplayState.iter_open`) follow specification §10.3 exactly (skip closed, emit
models, traverse the smallest split_id's children, emit a node without splits) so the scheduled
frontier is the certifier's ``open`` list restricted to the owned region; it is an antichain
and its order is depth-first with children in index order. The disposition of an emitted
node is derived (specification §6.5): ``model``; ``stopped`` (latest stop); ``stop_due`` (a stop
that the rules imply but the journal lacks: tool retries exhausted, split depth limit or no variable
left); ``needs_split`` (latest outcome EXHAUSTED, INVALID_MODEL or CHECK_REJECTED); otherwise
``pending``. ``followups()`` lists the missing ``node_stop`` events; once committed they
disappear, so a crash before the event re-issues it exactly once.

Closure is evaluated lazily with an explicit stack and memoized: true results are permanent
(closure is monotone in the evidence), false results are dropped whenever evidence changes.
Cost is linear in the visited part of the tree for each query after a change; a state cache
and incremental frontier maintenance are optimisations, not needed for correctness.
"""

from __future__ import annotations

import enum
import functools
from collections.abc import Callable, Generator, Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from cubeproof.base.canonical_json import json_sha256
from cubeproof.base.errors import IntegrityError
from cubeproof.cnf.campaign import LoadedCampaign
from cubeproof.contracts.campaign import Admit
from cubeproof.contracts.enums import Outcome, ProofMode, StopState
from cubeproof.contracts.identity import (
    node_id,
    pairwise_incompatible,
    split_id,
    split_problem,
)
from cubeproof.contracts.policy import Policy
from cubeproof.contracts.values import Node
from cubeproof.coordinator.resources import stream_need
from cubeproof.evidence.certify.admission import admission_reason, success_problem
from cubeproof.evidence.schema import (
    Attempt,
    Handoff,
    Header,
    Machinery,
    NodeReopen,
    NodeStop,
    Record,
    Resume,
    ShardRecord,
    SplitRecord,
)
from cubeproof.leaf.retry import (
    arena_floor,
    initial_stream_arena,
    next_stream_attempt,
    raise_floor,
)

__all__ = [
    "CampaignView",
    "Disposition",
    "Followup",
    "NodeFacts",
    "OpenNode",
    "ReplayState",
    "Session",
    "iter_children",
    "key_of",
    "order_key",
]

Cube = tuple[int, ...]
Key = tuple[str, Cube]

#: Stop reasons of the follow-ups the replay derives (specification §6.5: "STUCK is recorded for max
#: depth or genuinely empty eligibility"; tool blocks "persist node_stop(tool_blocked)").
REASON_TOOL_RETRIES = "tool_retries_exhausted"
REASON_MAX_DEPTH = "max_depth"
REASON_NO_VARIABLE = "no_eligible"


def key_of(node: Node) -> Key:
    return (node.formula_sha256, node.cube)


def iter_children(cube: Sequence[int], variables: Sequence[int]) -> Iterator[Cube]:
    """The ``2^len(W)`` sign children of a well-formed split in child-index order, lazily
    (bit j of the index selects ``+W[j]``; the same cubes as ``identity.split_children``)."""
    for index in range(1 << len(variables)):
        signed = [v if (index >> j) & 1 else -v for j, v in enumerate(variables)]
        yield tuple(sorted((*cube, *signed), key=abs))


@dataclass(frozen=True)
class CampaignView:
    """What replay needs of the campaign: its ID, admission, V per formula and root splits."""

    campaign_id: str
    admit: Admit
    variables: Mapping[str, int]
    root_splits: tuple[tuple[Key, tuple[int, ...]], ...] = ()

    @classmethod
    def of(cls, loaded: LoadedCampaign) -> CampaignView:
        campaign = loaded.campaign
        return cls(
            campaign_id=campaign.campaign_id,
            admit=campaign.admit,
            variables={sha: b.formula.variables for sha, b in loaded.bundles.items()},
            root_splits=tuple((key_of(s.node), s.variables) for s in campaign.root_splits),
        )


class Disposition(str, enum.Enum):
    """What the scheduler must do with an open node (module doc)."""

    PENDING = "pending"
    NEEDS_SPLIT = "needs_split"
    STOP_DUE = "stop_due"
    STOPPED = "stopped"
    MODEL = "model"


@dataclass(frozen=True, order=True)
class OpenNode:
    """An emitted open node: its key, disposition and, for a stop, state and reason."""

    key: Key
    disposition: Disposition
    stop_state: StopState | None = None
    reason: str | None = None


@functools.cache
def order_key(key: Key) -> tuple[str, str]:
    """The sort key ``(formula_sha256, node_id)`` of a node.

    Every ordered list of nodes uses it (roots, follow-ups, given-away nodes). A node's key
    never changes, and the scheduler asks for the keys of the same roots at every event, so the
    SHA-256 behind ``node_id`` is computed once for each node, not once for each question.
    """
    return (key[0], node_id(*key))


@dataclass(frozen=True)
class _RootOpen:
    """The open nodes below one owned root, as last computed (see ``ReplayState._root_open``)."""

    nodes: tuple[OpenNode, ...]
    keys: frozenset[Key]
    due: tuple[OpenNode, ...]


@dataclass(frozen=True)
class Followup:
    """A ``node_stop`` the rules imply and the journal lacks (to be committed first)."""

    key: Key
    state: StopState
    reason: str
    policy_sha256: str


@dataclass
class Session:
    """Counters since the latest header/resume (specification §6.5)."""

    anomalies: int = 0
    machine_failures: int = 0


@dataclass
class NodeFacts:
    """Everything the journal says about one node (own attempts, stops, splits)."""

    splits: dict[str, tuple[int, ...]] = field(default_factory=dict)
    verified_seq: int | None = None
    model: bool = False
    attempts: int = 0
    last_outcome: Outcome | None = None
    last_reason: str | None = None
    last_retry: bool = False
    consecutive_failures: int = 0
    stop: tuple[StopState, str, int] | None = None
    unadmitted: int = 0
    #: The floor of the node's next stream arena from its own attempts (``leaf.retry``).
    stream_floor: tuple[int, int] | None = None

    def to_json(self) -> dict[str, Any]:
        return {
            "splits": {sid: list(w) for sid, w in sorted(self.splits.items())},
            "verified_seq": self.verified_seq,
            "model": self.model,
            "attempts": self.attempts,
            "last_outcome": None if self.last_outcome is None else self.last_outcome.value,
            "last_reason": self.last_reason,
            "last_retry": self.last_retry,
            "consecutive_failures": self.consecutive_failures,
            "stop": None
            if self.stop is None
            else {"state": self.stop[0].value, "reason": self.stop[1], "seq": self.stop[2]},
            "unadmitted": self.unadmitted,
            "stream_floor": None if self.stream_floor is None else list(self.stream_floor),
        }

    @classmethod
    def from_json(cls, value: Mapping[str, Any]) -> NodeFacts:
        """The inverse of :meth:`to_json` (the state cache); any defect raises."""
        stop = value["stop"]
        outcome = value["last_outcome"]
        floor = value["stream_floor"]
        facts = cls(
            splits={str(s): tuple(int(v) for v in w) for s, w in value["splits"].items()},
            verified_seq=None if value["verified_seq"] is None else int(value["verified_seq"]),
            model=_flag(value["model"]),
            attempts=int(value["attempts"]),
            last_outcome=None if outcome is None else Outcome(outcome),
            last_reason=None if value["last_reason"] is None else str(value["last_reason"]),
            last_retry=_flag(value["last_retry"]),
            consecutive_failures=int(value["consecutive_failures"]),
            stop=None
            if stop is None
            else (StopState(stop["state"]), str(stop["reason"]), int(stop["seq"])),
            unadmitted=int(value["unadmitted"]),
            stream_floor=None if floor is None else (int(floor[0]), int(floor[1])),
        )
        if facts.to_json() != dict(value):
            raise ValueError("node facts are not canonical")
        return facts


def _flag(value: Any) -> bool:
    if type(value) is not bool:
        raise ValueError(f"{value!r} is not a boolean")
    return value


#: ``(attempt, policy) -> True`` marks an EXHAUSTED stream attempt as an eligible arena retry
#: (specification §6.4): the node stays pending instead of needing a split. Default
#: (:meth:`ReplayState.stream_retry`): derived from the record itself (``leaf.retry``), within
#: the policy maxima and the idle machine's memory budget of the latest header/resume.
RetryJudge = Callable[[Attempt, Policy], bool]


class ReplayState:
    """The fold of one journal (module doc). Feed records in seq order with :meth:`apply`."""

    def __init__(self, view: CampaignView, *, retry_judge: RetryJudge | None = None) -> None:
        self.view = view
        self._retry = retry_judge
        self.journal_id: str | None = None
        self.worker: str | None = None
        self.seq = -1
        self.head: str | None = None
        self.policy: Policy | None = None
        self.machinery: Machinery | None = None
        #: The idle machine's memory budget recorded in the latest header/resume (specification
        #: §4.7, §8.2).
        self.memory_budget: int | None = None
        self.snapshot_seq = -1
        self.epochs: list[tuple[int, str]] = []
        self.session = Session()
        self.malformed: list[tuple[int, str]] = []
        self.not_admitted: list[tuple[int, str]] = []
        self._nodes: dict[Key, NodeFacts] = {}
        self._roots: set[Key] = set()
        self._given: set[Key] = set()
        self._shards: set[str] = set()
        self._requests: set[str] = set()
        self._true: set[Key] = set()
        self._false: set[Key] = set()
        #: Derived indexes over the roots; see "open nodes" below. All of them are caches of
        #: what the records imply and are dropped whenever a record may have changed them.
        self._sorted_roots: tuple[list[Key], list[tuple[str, str]]] | None = None
        self._owners: dict[str, dict[frozenset[int], set[Cube]]] | None = None
        self._owner_of: dict[Key, Key | None] = {}
        self._open_list: list[OpenNode] | None = None
        self._open_by_root: dict[Key, _RootOpen] = {}
        self._due_roots: set[Key] = set()
        self._all_built = False
        self._stale: set[Key] = set()
        for key, variables in view.root_splits:
            self._add_split(key, variables, source=-1)

    # -- the fold --------------------------------------------------------------------------

    def apply(self, record: Record) -> None:
        """Apply the next record; a record out of order or a foreign journal is an
        :class:`IntegrityError` (the reader already validated its content)."""
        if record.seq != self.seq + 1:
            raise IntegrityError("state.seq", f"record {record.seq} after {self.seq}")
        payload = record.payload
        if record.seq == 0:
            if not isinstance(payload, Header):
                raise IntegrityError("state.header", "a journal starts with its header")
            if payload.campaign != self.view.campaign_id:
                raise IntegrityError("state.campaign", "the journal belongs to another campaign")
            self.journal_id, self.worker = record.self_hash, payload.worker
        elif self.head is not None and record.prev != self.head:
            raise IntegrityError("state.chain", f"record {record.seq} does not follow the head")
        elif isinstance(payload, Header):
            raise IntegrityError("state.header", "a second header")
        self.seq, self.head = record.seq, record.self_hash
        self._false.clear()  # a record can close what was open; closure is re-derived on demand
        if isinstance(payload, (Header, Resume)):
            self._snapshot(record.seq, payload)
            self._changed()  # the policy and the memory budget decide dispositions everywhere
        elif isinstance(payload, ShardRecord):
            self._shards.add(payload.shard_sha256)
            self._roots.update(key_of(n) for n in payload.shard.nodes)
            self._changed()
        elif isinstance(payload, Handoff):
            self._requests.add(payload.request.request_id)
            if payload.shard is not None:
                self._given.update(key_of(n) for n in payload.shard.nodes)
                self._changed()
        elif isinstance(payload, SplitRecord):
            self._split_record(record.seq, payload)
            self._touched(key_of(payload.node))
        elif isinstance(payload, Attempt):
            self._attempt(record.seq, payload)
            self._touched(key_of(payload.node))
        elif isinstance(payload, NodeStop):
            facts = self._facts(key_of(payload.node))
            facts.stop = (payload.state, payload.reason, record.seq)
            self._touched(key_of(payload.node))
        elif isinstance(payload, NodeReopen):
            facts = self._facts(key_of(payload.node))
            facts.stop = None
            facts.consecutive_failures = 0
            self._touched(key_of(payload.node))
        # repair and audit_* records change no scheduling state.

    def apply_all(self, records: Sequence[Record]) -> None:
        for record in records:
            self.apply(record)

    def _changed(self) -> None:
        """Forget everything derived: the roots, their order, and the open nodes below each."""
        self._false.clear()
        self._sorted_roots = None
        self._owners = None
        self._owner_of.clear()
        self._open_list = None
        self._open_by_root.clear()
        self._due_roots.clear()
        self._all_built = False
        self._stale.clear()

    def _touched(self, key: Key) -> None:
        """A record changed the facts of ``key``: forget the open nodes of the root above it.

        The open nodes below a root depend on the facts of the nodes below that root, on what
        was given away below it, and on the policy; the roots are pairwise disjoint
        (specification §7.4), so a record about one node concerns one root. A node below no
        owned root (it cannot be scheduled here) forgets everything, the safe answer.
        """
        if not self._all_built and not self._open_by_root:
            return  # nothing is derived yet (a replay): there is nothing to forget
        owner = self._owner(key)
        if owner is None:
            self._changed()
            return
        self._open_list = None
        self._open_by_root.pop(owner, None)
        self._due_roots.discard(owner)
        self._stale.add(owner)

    def _owner(self, key: Key) -> Key | None:
        """The owned root whose cube is contained in the cube of ``key``, if there is one.

        The roots of a formula are grouped by their sets of variables (a proof-prefix split
        gives one group for all its cases); within a group the root above ``key`` is the
        restriction of the cube to those variables. An open frontier taken as a shard has about
        one group for each root, so the answer for a node is kept until the roots change.
        """
        if key in self._owner_of:
            return self._owner_of[key]
        found = self._owner_of[key] = self._find_owner(key)
        return found

    def _find_owner(self, key: Key) -> Key | None:
        if self._owners is None:
            owners: dict[str, dict[frozenset[int], set[Cube]]] = {}
            for formula, cube in self._roots:
                group = frozenset(abs(literal) for literal in cube)
                owners.setdefault(formula, {}).setdefault(group, set()).add(cube)
            self._owners = owners
        formula, cube = key
        for group, cubes in self._owners.get(formula, {}).items():
            restricted = tuple(literal for literal in cube if abs(literal) in group)
            if len(restricted) == len(group) and restricted in cubes:
                return (formula, restricted)
        return None

    def _facts(self, key: Key) -> NodeFacts:
        facts = self._nodes.get(key)
        if facts is None:
            facts = self._nodes[key] = NodeFacts()
        return facts

    def _snapshot(self, seq: int, payload: Header | Resume) -> None:
        self.policy = payload.policy
        self.machinery = payload.machinery
        self.memory_budget = payload.resources.memory_budget_bytes
        self.snapshot_seq = seq
        self.epochs.append((seq, payload.policy.sha256))
        self.session = Session()

    def _split_record(self, seq: int, payload: SplitRecord) -> None:
        key = key_of(payload.node)
        count = self.view.variables.get(key[0])
        if count is None:  # the reader refuses foreign formulas; never schedule on one
            self.malformed.append((seq, "formula"))
            return
        problem = split_problem(payload.variables, key[1], count)
        if problem is not None:
            self.malformed.append((seq, problem.removeprefix("split.")))
            return
        self._add_split(key, payload.variables, source=seq)

    def _add_split(self, key: Key, variables: tuple[int, ...], *, source: int) -> None:
        del source
        ident = split_id(node_id(*key), variables)
        self._facts(key).splits[ident] = tuple(variables)

    def _attempt(self, seq: int, attempt: Attempt) -> None:
        assert self.machinery is not None and self.policy is not None
        key = key_of(attempt.node)
        facts = self._facts(key)
        facts.attempts += 1
        facts.last_outcome = attempt.outcome
        facts.last_reason = attempt.reason
        facts.last_retry = False
        outcome = attempt.outcome
        if outcome is Outcome.TOOL_FAILED:
            facts.consecutive_failures += 1
            self.session.machine_failures += 1
        else:
            facts.consecutive_failures = 0
            self.session.machine_failures = 0
        if outcome in (Outcome.INVALID_MODEL, Outcome.CHECK_REJECTED):
            self.session.anomalies += 1
        if outcome is Outcome.MODEL:
            facts.model = True
        elif outcome is Outcome.VERIFIED_UNSAT:
            reason = admission_reason(self.view.admit, self.machinery)
            if reason is None:
                reason = success_problem(attempt.to_json())
            if reason is None:
                if facts.verified_seq is None:
                    facts.verified_seq = seq
            else:
                facts.unadmitted += 1
                self.not_admitted.append((seq, reason))
        elif outcome is Outcome.EXHAUSTED:
            judge = self.stream_retry if self._retry is None else self._retry
            facts.last_retry = attempt.proof_mode is ProofMode.STREAM and judge(
                attempt, self.policy
            )
        facts.stream_floor = raise_floor(facts.stream_floor, arena_floor(attempt, self.policy))

    def stream_retry(self, attempt: Attempt, policy: Policy) -> bool:
        """The default judge (specification §6.4): the record calls for a fresh stream attempt whose
        derived arena is within the policy maxima and whose stream reservation (solver, checker with
        that arena, relay, overheads; specification §8.3) fits the memory budget of the snapshot in
        force. Judged when the record is applied, so a later resume does not rewrite the
        decision."""
        budget = self.memory_budget

        def fits(heap_mib: int, stack_mib: int) -> bool:
            need = stream_need(policy, 0, "work", arena=(heap_mib, stack_mib))
            return budget is None or need.memory_bytes <= budget

        return next_stream_attempt(attempt, policy, fits) is not None

    def stream_arena(self, key: Key) -> tuple[int, int]:
        """The ``(heap_mib, stack_mib)`` of the node's next stream attempt: the policy's first
        stream arena raised to the floor of the node's own attempts (``leaf.retry``), and never
        beyond the current maxima (a resume may have lowered them)."""
        policy = self.policy
        if policy is None:
            raise ValueError("no policy before the header")
        facts = self._nodes.get(key)
        floor = raise_floor(
            initial_stream_arena(policy), None if facts is None else facts.stream_floor
        )
        assert floor is not None
        return (
            min(floor[0], policy.checker_max_heap_mib),
            min(floor[1], policy.checker_max_stack_mib),
        )

    def _floor_within_maxima(self, key: Key, policy: Policy) -> bool:
        facts = self._nodes.get(key)
        floor = None if facts is None else facts.stream_floor
        return floor is None or (
            floor[0] <= policy.checker_max_heap_mib and floor[1] <= policy.checker_max_stack_mib
        )

    # -- session ---------------------------------------------------------------------------

    @property
    def anomaly_halt(self) -> bool:
        """The session reached ``anomaly_limit``: stop new work (exit 6, specification §6.5)."""
        return self.policy is not None and self.session.anomalies >= self.policy.anomaly_limit

    @property
    def machine_halt(self) -> bool:
        """The session reached ``machine_failure_limit`` consecutive tool failures (exit 5)."""
        return (
            self.policy is not None
            and self.session.machine_failures >= self.policy.machine_failure_limit
        )

    # -- closure ---------------------------------------------------------------------------

    def _known(self, key: Key) -> bool | None:
        if key in self._true:
            return True
        facts = self._nodes.get(key)
        if facts is not None and facts.verified_seq is not None:
            return True  # not memoized: the node's own facts are the memo
        if key in self._false:
            return False
        return None

    def _evaluate(self, key: Key) -> Generator[Key, bool, bool]:
        """Generator protocol: yields child keys, receives their closure, returns the answer."""
        facts = self._nodes.get(key)
        if facts is None:
            return False
        for ident in sorted(facts.splits):
            everything = True
            for child in iter_children(key[1], facts.splits[ident]):
                closed = yield (key[0], child)
                if not closed:
                    everything = False
                    break
            if everything:
                return True
        return False

    def closed(self, start: Key) -> bool:
        """Whether ``start`` is closed (specification §10.2): an admitted verified leaf, or a split
        all of whose children are closed. Explicit stack, no recursion."""
        known = self._known(start)
        if known is not None:
            return known
        stack: list[tuple[Key, Any]] = [(start, self._evaluate(start))]
        send: bool | None = None
        while True:
            key, generator = stack[-1]
            try:
                child = generator.send(send)
            except StopIteration as done:
                value = bool(done.value)
                (self._true if value else self._false).add(key)
                stack.pop()
                if not stack:
                    return value
                send = value
                continue
            answer = self._known(child)
            if answer is not None:
                send = answer
            else:
                stack.append((child, self._evaluate(child)))
                send = None

    # -- open nodes ------------------------------------------------------------------------

    def roots(self) -> list[Key]:
        """Accepted roots outside given-away regions, sorted by ``(formula, node_id)``."""
        return list(self.root_order()[0])

    def root_order(self) -> tuple[Sequence[Key], Sequence[tuple[str, str]]]:
        """The roots of :meth:`roots` and, beside them, their sort keys (:func:`order_key`).

        Both sequences are kept until a shard or a handoff changes the roots; a caller reads
        them and does not modify them.
        """
        if self._sorted_roots is None:
            kept = sorted((k for k in self._roots if not self._within_given(k)), key=order_key)
            self._sorted_roots = (kept, [order_key(k) for k in kept])
        return self._sorted_roots

    def _within_given(self, key: Key) -> bool:
        """True if ``key`` itself was given away; deeper nodes are excluded when the
        traversal reaches the given node (specification §7.4: only unsplit frontier nodes are
        given)."""
        return key in self._given

    def iter_open(self, root: Key) -> Iterator[OpenNode]:
        """The open nodes below ``root`` in depth-first, child-index order (specification §10.3)."""
        if root not in self._roots or self._within_given(root):
            return
        frames: list[Iterator[Cube]] = [iter((root[1],))]
        formula = root[0]
        while frames:
            try:
                cube = next(frames[-1])
            except StopIteration:
                frames.pop()
                continue
            key = (formula, cube)
            if key in self._given or self.closed(key):
                continue
            facts = self._nodes.get(key)
            if facts is not None and facts.model:
                yield OpenNode(key, Disposition.MODEL)
                continue
            if facts is not None and facts.splits:
                frames.append(iter_children(cube, facts.splits[min(facts.splits)]))
                continue
            yield self._open(key, facts)

    def _open(self, key: Key, facts: NodeFacts | None) -> OpenNode:
        if facts is None:
            return OpenNode(key, Disposition.PENDING)
        if facts.stop is not None:
            return OpenNode(key, Disposition.STOPPED, facts.stop[0], facts.stop[1])
        policy = self.policy
        assert policy is not None
        outcome = facts.last_outcome
        if outcome is Outcome.TOOL_FAILED and facts.consecutive_failures > policy.tool_retries:
            return OpenNode(key, Disposition.STOP_DUE, StopState.TOOL_BLOCKED, REASON_TOOL_RETRIES)
        splittable = outcome in (Outcome.EXHAUSTED, Outcome.INVALID_MODEL, Outcome.CHECK_REJECTED)
        retry = facts.last_retry and self._floor_within_maxima(key, policy)
        if not splittable or retry:
            return OpenNode(key, Disposition.PENDING)
        reason = self._unsplittable(key, policy)
        if reason is not None:
            return OpenNode(key, Disposition.STOP_DUE, StopState.STUCK, reason)
        return OpenNode(key, Disposition.NEEDS_SPLIT)

    def _unsplittable(self, key: Key, policy: Policy) -> str | None:
        """Why a node that needs a split cannot get one: the depth limit or no variable left
        (specification §6.5 "STUCK is recorded for max depth or genuinely empty eligibility",
        specification §9.1)."""
        if len(key[1]) >= policy.max_cube_size:
            return REASON_MAX_DEPTH
        if len(key[1]) >= self.view.variables.get(key[0], 0):
            return REASON_NO_VARIABLE
        return None

    def _root_open(self, root: Key) -> _RootOpen:
        """The open nodes below ``root``: computed by :meth:`iter_open`, kept until a record
        touches a node below that root (:meth:`_touched`) or changes what holds everywhere
        (:meth:`_changed`). The cost of an event is then that of the one root it concerns, not
        of every root the worker owns."""
        found = self._open_by_root.get(root)
        if found is None:
            nodes = tuple(self.iter_open(root))
            due = tuple(
                n
                for n in nodes
                if n.disposition is Disposition.STOP_DUE and n.stop_state is not None
            )
            found = self._open_by_root[root] = _RootOpen(
                nodes, frozenset(n.key for n in nodes), due
            )
            self._stale.discard(root)
            if due:
                self._due_roots.add(root)
        return found

    def _all_open(self) -> Iterable[_RootOpen]:
        return (self._root_open(root) for root in self.root_order()[0])

    def open_below(self, root: Key) -> Iterable[OpenNode]:
        """The open nodes below one owned root, in the order of :meth:`iter_open`: the kept ones
        when the root has been looked at since the last record about it (:meth:`_root_open`),
        otherwise the walk itself, which a caller may stop early (a plan with a limit does not
        walk a huge frontier to its end)."""
        found = self._open_by_root.get(root)
        return self.iter_open(root) if found is None else found.nodes

    def open_nodes(self) -> list[OpenNode]:
        """Every open node of every owned root, root by root in the order of :meth:`roots`."""
        if self._open_list is None:
            self._open_list = [node for found in self._all_open() for node in found.nodes]
        return list(self._open_list)

    def followups(self) -> list[Followup]:
        """The node_stop events that the rules imply and the journal lacks, sorted by node."""
        policy = self.policy
        if policy is None:
            return []
        if not self._all_built:
            for _ in self._all_open():  # every root once after a general change
                pass
            self._all_built = True
        for root in tuple(self._stale):  # then only the roots that records touched
            self._root_open(root)
        found = [
            Followup(n.key, n.stop_state, n.reason or "", policy.sha256)
            for root in self._due_roots
            for n in self._open_by_root[root].due
            if n.stop_state is not None
        ]
        return sorted(found, key=lambda f: order_key(f.key))

    def unneeded(self, running: Sequence[Key]) -> list[Key]:
        """Running nodes that are no longer open work: a verified record elsewhere closed an
        ancestor, so their result is not needed and they are cancelled without records
        (specification §6.5). A node that is open stays; a committed in-flight result is harmless
        evidence."""
        unwanted = []
        for key in running:
            owner = self._owner(key)
            if owner is None or self._within_given(owner) or key not in self._root_open(owner).keys:
                unwanted.append(key)
        return sorted(unwanted, key=order_key)

    def check_antichain(self) -> None:
        """The accepted roots are pairwise disjoint (specification §7.4); overlap is an integrity
        error."""
        by_formula: dict[str, list[Cube]] = {}
        for formula, cube in self._roots:
            by_formula.setdefault(formula, []).append(cube)
        for formula, cubes in sorted(by_formula.items()):
            if not pairwise_incompatible(cubes):
                raise IntegrityError("state.roots", f"accepted roots of {formula} overlap")

    # -- views -----------------------------------------------------------------------------

    def given_away(self) -> list[Key]:
        return sorted(self._given, key=order_key)

    def facts(self, key: Key) -> NodeFacts | None:
        return self._nodes.get(key)

    def shards(self) -> list[str]:
        return sorted(self._shards)

    def verified_by_depth(self) -> dict[int, int]:
        """Admitted verified leaves per cube size (status counters)."""
        found: dict[int, int] = {}
        for key, facts in self._nodes.items():
            if facts.verified_seq is not None:
                found[len(key[1])] = found.get(len(key[1]), 0) + 1
        return dict(sorted(found.items()))

    def counts(self) -> dict[tuple[str, int], int]:
        """Open nodes by ``(state, depth)`` for the status (stopped nodes by their stop state)."""
        found: dict[tuple[str, int], int] = {}
        for node in self.open_nodes():
            state = node.stop_state.value if node.stop_state is not None else node.disposition.value
            slot = (state, len(node.key[1]))
            found[slot] = found.get(slot, 0) + 1
        return dict(sorted(found.items()))

    def digest(self) -> dict[str, Any]:
        """The canonical comparison value of the state (live equals replay)."""
        policy = self.policy
        return {
            "journal": self.journal_id,
            "worker": self.worker,
            "seq": self.seq,
            "head": self.head,
            "policy": None if policy is None else policy.sha256,
            "memory_budget": self.memory_budget,
            "snapshot_seq": self.snapshot_seq,
            "epochs": [[s, p] for s, p in self.epochs],
            "session": {
                "anomalies": self.session.anomalies,
                "machine_failures": self.session.machine_failures,
            },
            "halts": {"anomaly": self.anomaly_halt, "machine": self.machine_halt},
            "roots": [[k[0], list(k[1])] for k in sorted(self._roots)],
            "given": [[k[0], list(k[1])] for k in sorted(self._given)],
            "shards": self.shards(),
            "requests": sorted(self._requests),
            "malformed": [list(m) for m in self.malformed],
            "not_admitted": [list(m) for m in self.not_admitted],
            "nodes": [
                [k[0], list(k[1]), self._nodes[k].to_json()]
                for k in sorted(self._nodes)
                if self._nodes[k] != NodeFacts()
            ],
            "open": [
                {
                    "node": [n.key[0], list(n.key[1])],
                    "disposition": n.disposition.value,
                    "stop": None if n.stop_state is None else n.stop_state.value,
                    "reason": n.reason,
                }
                for n in self.open_nodes()
            ],
            "followups": [
                [f.key[0], list(f.key[1]), f.state.value, f.reason] for f in self.followups()
            ],
        }

    def digest_sha256(self) -> str:
        return json_sha256(self.digest())

    # -- the state cache (specification §7.3) ------------------------------------------------------

    def export(self) -> dict[str, Any]:
        """Everything the fold keeps, as a canonical JSON value (the payload of the cache).

        The closure memo and the frontier cache are derived and not exported. A restored
        state must continue exactly like the fold: ``restore`` then ``apply`` of the later
        records has the same :meth:`digest` as ``apply`` of all records.
        """
        policy, machinery = self.policy, self.machinery
        return {
            "journal": self.journal_id,
            "worker": self.worker,
            "seq": self.seq,
            "head": self.head,
            "policy": None if policy is None else policy.to_json(),
            "machinery": None if machinery is None else machinery.to_json(),
            "memory_budget": self.memory_budget,
            "snapshot_seq": self.snapshot_seq,
            "epochs": [[s, p] for s, p in self.epochs],
            "session": {
                "anomalies": self.session.anomalies,
                "machine_failures": self.session.machine_failures,
            },
            "malformed": [list(m) for m in self.malformed],
            "not_admitted": [list(m) for m in self.not_admitted],
            "nodes": [
                [k[0], list(k[1]), self._nodes[k].to_json()]
                for k in sorted(self._nodes)
                if self._nodes[k] != NodeFacts()
            ],
            "roots": [[k[0], list(k[1])] for k in sorted(self._roots)],
            "given": [[k[0], list(k[1])] for k in sorted(self._given)],
            "shards": self.shards(),
            "requests": sorted(self._requests),
        }

    def restore(self, data: Mapping[str, Any]) -> None:
        """Replace the state by an exported one (a state that has applied nothing yet).

        Any defect of ``data`` raises (KeyError, TypeError, ValueError or a CubeproofError);
        the state is then unusable and the caller falls back to a full replay.
        """
        if self.seq != -1:
            raise ValueError("a state is restored before its first record")
        nodes: dict[Key, NodeFacts] = {}
        for formula, cube, facts in data["nodes"]:
            if formula not in self.view.variables:
                raise ValueError("a cached node of another formula")
            nodes[(str(formula), tuple(int(x) for x in cube))] = NodeFacts.from_json(facts)
        for key, variables in self.view.root_splits:
            if split_id(node_id(*key), variables) not in nodes.get(key, NodeFacts()).splits:
                raise ValueError("the cached state lacks a campaign root split")
        policy = data["policy"]
        machinery = data["machinery"]
        seq, head = data["seq"], data["head"]
        if type(seq) is not int or seq < 0 or not isinstance(head, str):
            raise ValueError("no committed position")
        self.journal_id = str(data["journal"])
        self.worker = str(data["worker"])
        self.policy = None if policy is None else Policy.from_json(policy)
        self.machinery = None if machinery is None else Machinery.from_json(machinery)
        budget = data["memory_budget"]
        self.memory_budget = None if budget is None else int(budget)
        self.snapshot_seq = int(data["snapshot_seq"])
        self.epochs = [(int(s), str(p)) for s, p in data["epochs"]]
        session = data["session"]
        self.session = Session(int(session["anomalies"]), int(session["machine_failures"]))
        self.malformed = [(int(s), str(r)) for s, r in data["malformed"]]
        self.not_admitted = [(int(s), str(r)) for s, r in data["not_admitted"]]
        self._nodes = nodes
        self._roots = {(str(f), tuple(int(x) for x in c)) for f, c in data["roots"]}
        self._given = {(str(f), tuple(int(x) for x in c)) for f, c in data["given"]}
        self._shards = {str(s) for s in data["shards"]}
        self._requests = {str(r) for r in data["requests"]}
        self._true.clear()
        self._changed()
        self.seq, self.head = seq, head
        if self.export() != _canonical(data):
            raise ValueError("the cached state is not canonical")


def _canonical(data: Mapping[str, Any]) -> dict[str, Any]:
    """``data`` as plain JSON values (tuples as lists), for comparison with ``export``."""
    return {k: _plain(v) for k, v in data.items()}


def _plain(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {k: _plain(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(v) for v in value]
    return value
