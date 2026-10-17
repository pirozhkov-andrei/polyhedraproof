"""Which regions a worker owns: accepted shards, given-away nodes, handoff history (specification
§4.5, §7.4).

:class:`Ownership` is a fold over the ``shard``, ``handoff`` and ``split`` records of **one**
worker journal, in seq order. It is the coordinator's own bookkeeping next to
:class:`~cubeproof.coordinator.state.ReplayState` (whose ``roots``/``given_away`` it must
agree with; a parity test checks that) and keeps what the scheduling fold does not: the shard
documents by hash, the committed handoff of every request (so a repeated request returns the
prior result and a lost output is recreated from the record), and the journal position at
which every frontier entry appeared (for "oldest first", specification §8.4).

Acceptance of a shard (:meth:`Ownership.judge`, specification §7.4) is a pure decision:

* wrong campaign, a formula the campaign does not contain, a cube out of range: rejected;
* a shard whose hash is already accepted: a **duplicate**, a no-op (also when its nodes were
  given away since; giving away is permanent for this journal);
* a shard that does not fit into one journal line: rejected (writers divide large node lists);
* a shard with a node that **meets** an accepted root or a given-away node, i.e. whose cube
  does not contradict it on some variable (equal, ancestor or descendant included): rejected
  with the two nodes named. Different workers may overlap; this worker never owns a region
  twice, and never takes back what it gave away. Nothing is accepted partially.

Overlap between two node lists is found by partition refinement (the method of
:func:`~cubeproof.contracts.identity.pairwise_incompatible`), near-linear for split-tree
shards, with a plain pairwise fallback if the work grows beyond a bound; it returns a witness.
"""

from __future__ import annotations

import enum
import os
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field

from cubeproof.base.canonical_json import encode, parse_line
from cubeproof.base.errors import ContractError, IntegrityError, ResourceError
from cubeproof.base.hashing import ZERO_HASH
from cubeproof.base.settings import DEFAULT_LIMITS, ReaderLimits
from cubeproof.contracts.documents import HandoffRequest, Shard
from cubeproof.contracts.identity import check_cube, split_id
from cubeproof.contracts.values import Node
from cubeproof.evidence.journal.chain import unsigned_sha256
from cubeproof.evidence.schema import Handoff, Record, ShardRecord, SplitRecord, parse_record

__all__ = [
    "RECORD_OVERHEAD",
    "Given",
    "Judgement",
    "Ownership",
    "Verdict",
    "chunk_nodes",
    "first_overlap",
]

#: Bytes a journal line adds to the shard or request it carries (envelope: format, seq, prev,
#: self, type, utc; the hash fields; the keys). Generous on purpose: a shard that passes the
#: size check always fits into a line.
RECORD_OVERHEAD = 4096


def chunk_nodes(
    campaign_id: str, nodes: Sequence[Node], *, max_line_bytes: int = DEFAULT_LIMITS.line_bytes
) -> list[list[Node]]:
    """Divide ``nodes`` into consecutive runs each of which fits a shard record of one journal
    line (specification §4.7: a large node list is divided into several shards before use).

    The nodes are sorted ``(formula_sha256, node_id)`` and kept in that order, so the division
    is a function of the campaign and the node set alone: the shard planner and a worker that
    makes its own first shards (specification §12.1) divide the same list in the same way.
    """
    ordered = sorted(nodes, key=lambda n: n.sort_key)
    budget = max_line_bytes - RECORD_OVERHEAD - 512
    base = len(encode({"format": "cubeproof-shard-1", "campaign": campaign_id, "name": "x" * 20}))
    chunks: list[list[Node]] = []
    size = budget  # forces a first chunk
    for node in ordered:
        cost = len(encode(node.to_json())) + 1
        if base + cost > budget:
            raise ResourceError(
                "shard.size", f"node {node.node_id[:16]} does not fit one journal line"
            )
        if size + cost > budget:
            chunks.append([])
            size = base
        chunks[-1].append(node)
        size += cost
    return chunks


Cube = tuple[int, ...]
Key = tuple[str, Cube]
_FOLDED = ("shard", "handoff", "split")


def _kind_of(line: bytes) -> str:
    """The record type a line is worth parsing for (a cheap filter; the parse decides)."""
    for kind in _FOLDED:
        if b'"type":"' + kind.encode() + b'"' in line:
            return kind
    return ""


def _chained(value: Mapping[str, object], seq: int, head: str) -> bool:
    return (
        value.get("seq") == seq
        and value.get("prev") == head
        and isinstance(value.get("self"), str)
        and unsigned_sha256(value) == value["self"]
    )


# -- overlap -----------------------------------------------------------------------------------


def _cross_pairs(cubes: Sequence[frozenset[int]], side: Sequence[int]) -> tuple[int, int] | None:
    first = [i for i in range(len(cubes)) if side[i] == 0]
    second = [i for i in range(len(cubes)) if side[i] == 1]
    for i in first:
        for j in second:
            if not any(-x in cubes[j] for x in cubes[i]):
                return i, j
    return None


def _overlap_in_formula(
    cubes: Sequence[frozenset[int]], side: Sequence[int]
) -> tuple[int, int] | None:
    """A compatible ``(side 0, side 1)`` pair, or None.

    Members of one side are pairwise incompatible. Partition refinement: a group's members never
    contradict each other on the variables removed so far; a member without remaining literals
    is therefore compatible with every other member of its group. Otherwise the most frequent
    remaining variable ``v`` splits the group into the members without ``-v`` and those without
    ``+v`` (members not mentioning ``v`` go to both sides). A compatible pair never separates.
    """
    count = len(cubes)
    budget = 64 * count + 4096
    work = 0
    stack: list[tuple[list[int], frozenset[int]]] = [(list(range(count)), frozenset())]
    while stack:
        members, removed = stack.pop()
        if len({side[i] for i in members}) < 2:
            continue
        work += len(members)
        if work > budget:
            return _cross_pairs(cubes, side)
        counts: dict[int, int] = {}
        for index in members:
            remaining = [abs(x) for x in cubes[index] if abs(x) not in removed]
            if not remaining:
                other = next(j for j in members if side[j] != side[index])
                return (index, other) if side[index] == 0 else (other, index)
            for variable in remaining:
                counts[variable] = counts.get(variable, 0) + 1
        chosen = min(counts, key=lambda v: (-counts[v], v))
        narrowed = removed | {chosen}
        stack.append(([i for i in members if -chosen not in cubes[i]], narrowed))
        stack.append(([i for i in members if chosen not in cubes[i]], narrowed))
    return None


def first_overlap(held: Iterable[Node], offered: Iterable[Node]) -> tuple[Node, Node] | None:
    """``(offered node, held node)`` of a pair that is not disjoint, or None.

    Two nodes of one formula are disjoint iff their cubes contradict each other on a variable;
    anything else (equal, ancestor, descendant, unrelated but compatible) overlaps. ``held`` must
    be pairwise disjoint and so must ``offered`` (both are antichains of disjoint regions).
    """
    held_by: dict[str, list[Node]] = {}
    for node in held:
        held_by.setdefault(node.formula_sha256, []).append(node)
    offered_by: dict[str, list[Node]] = {}
    for node in offered:
        offered_by.setdefault(node.formula_sha256, []).append(node)
    for formula in sorted(offered_by):
        mine, theirs = offered_by[formula], held_by.get(formula, [])
        if not theirs:
            continue
        cubes = [frozenset(n.cube) for n in mine] + [frozenset(n.cube) for n in theirs]
        side = [0] * len(mine) + [1] * len(theirs)
        pair = _overlap_in_formula(cubes, side)
        if pair is not None:
            return mine[pair[0]], theirs[pair[1] - len(mine)]
    return None


# -- decisions ---------------------------------------------------------------------------------


class Verdict(str, enum.Enum):
    ACCEPT = "accept"
    DUPLICATE = "duplicate"
    REJECT = "reject"


@dataclass(frozen=True)
class Judgement:
    """The decision on an offered shard; ``rule``/``detail`` explain a rejection."""

    verdict: Verdict
    rule: str | None = None
    detail: str = ""

    @property
    def text(self) -> str:
        return f"{self.rule}: {self.detail}" if self.rule else self.verdict.value


def _describe(node: Node) -> str:
    return f"node {node.node_id[:16]} of formula {node.formula_sha256[:16]} cube {list(node.cube)}"


@dataclass(frozen=True)
class Given:
    """A committed handoff: its seq, the request and the shard given away (None: zero nodes)."""

    seq: int
    request: HandoffRequest
    shard: Shard | None
    shard_sha256: str | None

    @property
    def nodes(self) -> tuple[Node, ...]:
        return self.shard.nodes if self.shard is not None else ()


@dataclass
class Ownership:
    """The fold over one journal's ownership records (module doc)."""

    campaign: str
    variables: Mapping[str, int] | None = None
    shards: dict[str, tuple[int, Shard]] = field(default_factory=dict)
    handoffs: dict[str, Given] = field(default_factory=dict)
    seq: int = -1
    _offset: int = 0
    _head: str = ZERO_HASH
    _roots: list[Node] = field(default_factory=list)
    _given: list[Node] = field(default_factory=list)
    _root_seq: dict[Key, int] = field(default_factory=dict)
    _split_seq: dict[tuple[Key, str], int] = field(default_factory=dict)

    # -- the fold ------------------------------------------------------------------------------

    def observe(self, record: Record) -> None:
        """Apply the next record (any type; only shard, handoff and split matter)."""
        if record.seq != self.seq + 1:
            raise IntegrityError("ownership.seq", f"record {record.seq} after {self.seq}")
        self.seq = record.seq
        self._fold(record)

    def _fold(self, record: Record) -> None:
        payload = record.payload
        if isinstance(payload, ShardRecord):
            if payload.shard_sha256 in self.shards:
                raise IntegrityError("ownership.shard", "the same shard accepted twice")
            self.shards[payload.shard_sha256] = (record.seq, payload.shard)
            for node in payload.shard.nodes:
                self._roots.append(node)
                self._root_seq.setdefault((node.formula_sha256, node.cube), record.seq)
        elif isinstance(payload, Handoff):
            request_id = payload.request.request_id
            if request_id in self.handoffs:
                raise IntegrityError("handoff.request_unique", "a request handed off twice")
            self.handoffs[request_id] = Given(
                record.seq, payload.request, payload.shard, payload.shard_sha256
            )
            if payload.shard is not None:
                self._given.extend(payload.shard.nodes)
        elif isinstance(payload, SplitRecord):
            key = (payload.node.formula_sha256, payload.node.cube)
            ident = split_id(payload.node.node_id, payload.variables)
            self._split_seq.setdefault((key, ident), record.seq)

    @classmethod
    def from_journal(
        cls,
        path: str | os.PathLike[str],
        *,
        campaign: str | None = None,
        variables: Mapping[str, int] | None = None,
        limits: ReaderLimits = DEFAULT_LIMITS,
        verify: bool = True,
    ) -> Ownership:
        """The ownership recorded in the journal file at ``path`` (see :meth:`refresh`)."""
        with open(path, "rb") as stream:
            first = stream.readline(limits.line_bytes + 2)
        if not first.endswith(b"\n"):
            raise IntegrityError("journal.no_header", f"{path} has no complete record")
        header = parse_line(first[:-1], limits=limits)
        found = header.get("campaign") if isinstance(header, dict) else None
        if (
            not isinstance(header, dict)
            or header.get("type") != "header"
            or not isinstance(found, str)
        ):
            raise IntegrityError("journal.header", "a journal starts with its header")
        if campaign is not None and found != campaign:
            raise IntegrityError("journal.campaign", "the journal is of another campaign")
        ownership = cls(found, variables)
        ownership.refresh(path, limits=limits, verify=verify)
        return ownership

    def refresh(
        self,
        path: str | os.PathLike[str],
        *,
        limits: ReaderLimits = DEFAULT_LIMITS,
        verify: bool = True,
    ) -> int:
        """Fold the complete lines appended to the journal since the last call; their count.

        A torn suffix (no LF) is left for the next call. With ``verify`` every line is checked
        against the chain (canonical bytes, self, seq, prev) and the first line against the
        campaign; without it only the records that matter are parsed, which is for a caller that
        has just validated the file under the run lock. The file must be the journal this
        instance has followed so far (an append-only file only grows)."""
        count = 0
        with open(path, "rb") as stream:
            stream.seek(self._offset)
            while True:
                seq = self.seq + 1
                raw = stream.readline(limits.line_bytes + 2)  # one line at a time, never the file
                if not raw.endswith(b"\n"):
                    if len(raw) > limits.line_bytes + 1:
                        raise ResourceError(
                            "limit.line", f"journal line {seq + 1} is longer than allowed"
                        )
                    break  # the end of the file or a torn suffix
                line = raw[:-1]
                self._line(line, seq, limits, verify)
                self.seq = seq
                self._offset += len(raw)
                count += 1
        return count

    def _line(self, line: bytes, seq: int, limits: ReaderLimits, verify: bool) -> None:
        if len(line) > limits.line_bytes:
            raise ResourceError("limit.line", f"journal line {seq + 1} is longer than allowed")
        kind = _kind_of(line)
        if verify or seq == 0:
            value = parse_line(line, limits=limits)
            if verify and not _chained(value, seq, self._head):
                raise IntegrityError("journal.chain", f"journal line {seq + 1}")
            self._head = str(value.get("self"))
            kind = str(value.get("type"))
            if seq == 0 and (kind != "header" or value.get("campaign") != self.campaign):
                raise IntegrityError("journal.header", "not the header of this campaign")
        if seq > 0 and kind in _FOLDED:
            self._fold(parse_record(line, variables=self.variables, limits=limits))

    # -- views ---------------------------------------------------------------------------------

    @property
    def accepted_roots(self) -> tuple[Node, ...]:
        return tuple(self._roots)

    @property
    def given_nodes(self) -> tuple[Node, ...]:
        return tuple(self._given)

    def knows_shard(self, shard_sha256: str) -> bool:
        return shard_sha256 in self.shards

    def prior(self, request_id: str) -> Given | None:
        """The committed handoff of this request (a repeated request returns it)."""
        return self.handoffs.get(request_id)

    def output_owner(self, output_name: str) -> Given | None:
        """The committed handoff that published (or must publish) ``output_name``."""
        for given in self.handoffs.values():
            if given.request.output_name == output_name:
                return given
        return None

    def root_seq(self, key: Key) -> int:
        """The seq of the shard that accepted this root (-1 if it is not an accepted root)."""
        return self._root_seq.get(key, -1)

    def split_seq(self, key: Key, ident: str) -> int:
        """The seq of the journal split, or -1 for one that is not in the journal (campaign)."""
        return self._split_seq.get((key, ident), -1)

    # -- acceptance (specification §7.4) -----------------------------------------------------------

    def judge(self, shard: Shard, *, max_line_bytes: int | None = None) -> Judgement:
        """Accept, ignore (duplicate) or reject an offered shard; the order of the checks is
        the order of the module doc, so a rejection is the same however often it is asked."""
        if shard.campaign != self.campaign:
            return Judgement(Verdict.REJECT, "shard.campaign", "the shard is of another campaign")
        problem = self._content_problem(shard)
        if problem is not None:
            return problem
        if shard.shard_id in self.shards:
            return Judgement(Verdict.DUPLICATE)
        if max_line_bytes is not None:
            size = len(encode(shard.to_json())) + RECORD_OVERHEAD
            if size > max_line_bytes:
                return Judgement(
                    Verdict.REJECT,
                    "shard.size",
                    f"{size} bytes do not fit a journal line of {max_line_bytes}; "
                    "divide the node list into several shards",
                )
        for region, held in (("given-away", self._given), ("accepted", self._roots)):
            pair = first_overlap(held, shard.nodes)
            if pair is not None:
                new, old = pair
                return Judgement(
                    Verdict.REJECT,
                    "shard.overlap",
                    f"{_describe(new)} overlaps the {region} {_describe(old)} of this worker; "
                    "to reclaim work use a new worker and results directory planned from "
                    "open coverage",
                )
        return Judgement(Verdict.ACCEPT)

    def _content_problem(self, shard: Shard) -> Judgement | None:
        counts = self.variables
        if counts is None:
            return None
        for node in shard.nodes:
            if node.formula_sha256 not in counts:
                return Judgement(
                    Verdict.REJECT, "record.formula", f"{_describe(node)}: unknown formula"
                )
            try:
                check_cube(node.cube, counts[node.formula_sha256])
            except ContractError as error:
                return Judgement(Verdict.REJECT, error.rule, f"{_describe(node)}: {error.detail}")
        return None
