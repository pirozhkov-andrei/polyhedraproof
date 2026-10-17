"""The evidence graph: closure, canonical selection and the open frontier (specification §10.2,
§10.3).

Nodes are keyed by ``(formula_sha256, canonical cube)``. The graph holds, per node, the
well-formed splits (by split_id; identical copies from the campaign and journals are one
split), the admitted VERIFIED_UNSAT attempts as :class:`Leaf` values, whether a valid model
exists and each journal's latest node_stop/node_reopen. Callers add complete evidence first;
the first query freezes the graph, so every memoized result is exact (no result depends on
the order in which evidence was added or queried).

- ``closed(n)``: n has an admitted verified attempt, or some split all of whose
  ``2^len(W)`` sign children are closed. Children strictly extend the cube, so the graph is
  acyclic and has depth at most V. Evaluation uses an explicit stack, never recursion.
- ``select(n)`` of a closed node: the smallest attempt Ref if any; otherwise the smallest
  split_id among the **closed** splits, recursively in child-index order. The result is a
  disjoint proof tree: its leaves and the number of selected split nodes.
- ``frontier(n)``: skip closed nodes; a node with a valid model is emitted as ``model``;
  otherwise the children of the smallest split_id are traversed, whether or not another split
  progressed further; a node without splits is emitted with its label. The label of an
  emitted node comes from each journal's latest event affecting exactly that node: if any
  latest event is a stop, the smallest Ref among those stops gives state and reason,
  otherwise ``pending``. Labels never change closure.

``max_nodes`` bounds the number of distinct nodes whose closure is evaluated: exceeding it is
a :class:`~cubeproof.base.errors.ResourceError`, never an open or closed result.
"""

from __future__ import annotations

from collections.abc import Iterator, Sequence
from dataclasses import dataclass

from cubeproof.base.errors import ResourceError
from cubeproof.contracts.identity import node_id, split_children, split_id

Cube = tuple[int, ...]
Key = tuple[str, Cube]


@dataclass(frozen=True, order=True)
class Leaf:
    """An admitted VERIFIED_UNSAT attempt; ordered by its Ref ``(journal, seq)`` first."""

    journal: str
    seq: int
    cnf_sha256: str
    proof_sha256: str
    route: str


@dataclass(frozen=True, order=True)
class _Label:
    journal: str
    seq: int
    state: str | None  # None: node_reopen
    reason: str


class EvidenceGraph:
    """Closure, selection and frontier over the certified evidence (see module doc)."""

    def __init__(self, *, max_nodes: int | None = None) -> None:
        if max_nodes is not None and (type(max_nodes) is not int or max_nodes < 1):
            raise ValueError("max_nodes must be a positive integer or None")
        self._max_nodes = max_nodes
        self._splits: dict[Key, dict[str, tuple[int, ...]]] = {}
        self._verified: dict[Key, Leaf] = {}
        self._models: set[Key] = set()
        self._labels: dict[Key, dict[str, _Label]] = {}
        self._closed: dict[Key, bool] = {}
        self._frozen = False

    # -- evidence --------------------------------------------------------------------------------

    def _mutable(self) -> None:
        if self._frozen:
            raise RuntimeError("evidence added after the graph was queried")

    def add_split(self, key: Key, variables: Sequence[int]) -> None:
        """A well-formed split W of ``key`` (the caller checked the W problems with V)."""
        self._mutable()
        ident = split_id(node_id(*key), variables)
        self._splits.setdefault(key, {})[ident] = tuple(variables)

    def add_verified(self, key: Key, leaf: Leaf) -> None:
        """An admitted, well-formed VERIFIED_UNSAT attempt; only the smallest Ref is kept."""
        self._mutable()
        known = self._verified.get(key)
        if known is None or leaf < known:
            self._verified[key] = leaf

    def add_model(self, key: Key) -> None:
        """A revalidated valid model of exactly this node."""
        self._mutable()
        self._models.add(key)

    def add_label(self, key: Key, journal: str, seq: int, state: str | None, reason: str) -> None:
        """A node_stop (``state`` set) or node_reopen (``state`` None) of one journal."""
        self._mutable()
        labels = self._labels.setdefault(key, {})
        known = labels.get(journal)
        if known is None or seq > known.seq:
            labels[journal] = _Label(journal, seq, state, reason)

    # -- queries ---------------------------------------------------------------------------------

    def _children(self, key: Key, variables: tuple[int, ...]) -> Iterator[Key]:
        formula = key[0]
        return ((formula, child) for child in split_children(key[1], variables))

    def _store(self, key: Key, value: bool) -> None:
        if self._max_nodes is not None and len(self._closed) >= self._max_nodes:
            raise ResourceError(
                "certify.nodes", f"more than {self._max_nodes} evidence graph nodes"
            )
        self._closed[key] = value

    def closed(self, start: Key) -> bool:
        """Whether ``start`` is closed; exact, memoized, evaluated with an explicit stack."""
        self._frozen = True
        memo = self._closed
        stack = [start]
        while stack:
            key = stack[-1]
            if key in memo:
                stack.pop()
                continue
            if key in self._verified:
                self._store(key, True)
                stack.pop()
                continue
            missing: list[Key] = []
            closed = False
            for variables in self._splits.get(key, {}).values():
                values = [(child, memo.get(child)) for child in self._children(key, variables)]
                missing.extend(child for child, value in values if value is None)
                closed = closed or all(value for _, value in values)
            if missing:
                # Children first; every pushed child is memoized before ``key`` is seen again.
                stack.extend(missing)
                continue
            self._store(key, closed)
            stack.pop()
        return memo[start]

    def _closed_split(self, key: Key) -> tuple[int, ...]:
        """W of the smallest split_id among the closed splits of a closed node."""
        for _, variables in sorted(self._splits.get(key, {}).items()):
            if all(self.closed(child) for child in self._children(key, variables)):
                return variables
        raise ValueError(f"node {key!r} has no closed split")  # pragma: no cover - invariant

    def select(self, start: Key) -> tuple[list[tuple[Key, Leaf]], int]:
        """Leaves (in child-index order) and selected split count of a closed node's tree."""
        if not self.closed(start):
            raise ValueError("only a closed node has a selected proof tree")
        leaves: list[tuple[Key, Leaf]] = []
        splits = 0
        stack = [start]
        while stack:
            key = stack.pop()
            leaf = self._verified.get(key)
            if leaf is not None:
                leaves.append((key, leaf))
                continue
            splits += 1
            stack.extend(reversed(list(self._children(key, self._closed_split(key)))))
        return leaves, splits

    def _label(self, key: Key) -> tuple[str, str | None]:
        stops = [label for label in self._labels.get(key, {}).values() if label.state is not None]
        if not stops:
            return "pending", None
        first = min(stops)
        assert first.state is not None
        return first.state, first.reason

    def frontier(self, start: Key) -> list[tuple[Key, str, str | None]]:
        """The emitted open nodes below ``start`` with state and reason (see module doc)."""
        found: list[tuple[Key, str, str | None]] = []
        stack = [start]
        while stack:
            key = stack.pop()
            if self.closed(key):
                continue
            if key in self._models:
                found.append((key, "model", None))
                continue
            options = self._splits.get(key)
            if options:
                smallest = options[min(options)]
                stack.extend(reversed(list(self._children(key, smallest))))
                continue
            found.append((key, *self._label(key)))
        return found
