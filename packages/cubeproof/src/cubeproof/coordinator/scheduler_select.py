"""Which work next: root fairness, split decisions and the pinned tools of a snapshot.

Specification §8.4 ("depth-first within a root, round-robin between requested roots; stable
ties by node_id"), 9.1 (the coordinator validates every choice) and 6.5.

- :class:`RootRotation` and :func:`next_work` pick pending nodes: for every root the
  frontier of :class:`~cubeproof.coordinator.state.ReplayState` in depth-first, child-index
  order (so the smallest child runs first), one node per root and round, the rotation
  continuing after the root served last. Nodes that run, are stopped, are models or wait
  for a stop follow-up are skipped; the frontier is walked lazily, so a call costs
  ``O(limit + skipped)``, not the size of the tree.
- :func:`decide_split` turns a splitter's answer into the coordinator's action: record a
  validated split, run the checked unit route (parent conflict, or a complete conflict-free
  assignment: the model path), fall back to the lowest eligible variables, or stop the node.
  :func:`split_k` is the clamp of ``k`` before any helper is started.
- :func:`leaf_tools` builds the leaf attempt's pinned tools from the **measured machinery
  snapshot** that the header/resume recorded (the obligation of ``leaf.binding``): the binary
  at hand must have exactly the snapshot's hash.
"""

from __future__ import annotations

import bisect
import enum
import itertools
from collections.abc import Collection, Iterator, Sequence
from dataclasses import dataclass

from cubeproof.base.errors import ConfigurationError, ContractError
from cubeproof.contracts.enums import StopState
from cubeproof.contracts.policy import Policy
from cubeproof.coordinator.ledger import Need
from cubeproof.coordinator.resources import CHILD_OVERHEAD, LOG_ALLOWANCE
from cubeproof.coordinator.scheduler import Candidate, Stage
from cubeproof.coordinator.state import Disposition, OpenNode, ReplayState, order_key
from cubeproof.evidence.schema import Machinery
from cubeproof.leaf.attempt import CheckRequest, LeafTools
from cubeproof.split.choice import (
    BUDGET,
    CHOSEN,
    FAILED,
    FALLBACK_ALGORITHM,
    NO_ELIGIBLE,
    PARENT_CONFLICT,
    SplitChoice,
    clamp_k,
    validate_choice,
)
from cubeproof.tools.isolation import PinnedBinary
from cubeproof.tools.machinery import host_cpu

__all__ = [
    "RootRotation",
    "SplitAction",
    "SplitDecision",
    "Work",
    "check_candidate",
    "decide_split",
    "leaf_tools",
    "next_work",
    "split_k",
]

Key = tuple[str, tuple[int, ...]]


@dataclass(frozen=True)
class Work:
    """A node to start: its open-node record, the root it serves and the stage it needs."""

    node: OpenNode
    root: Key
    stage: Stage


class RootRotation:
    """The round-robin cursor over roots, ordered by ``(formula_sha256, node_id)``."""

    def __init__(self) -> None:
        self._last: tuple[str, str] | None = None

    def order(self, roots: Sequence[Key]) -> list[Key]:
        """The roots starting after the one served last (all roots if none was)."""
        ordered = sorted(roots, key=order_key)
        return list(self.rotate(ordered, [order_key(r) for r in ordered]))

    def rotate(self, roots: Sequence[Key], keys: Sequence[tuple[str, str]]) -> Iterator[Key]:
        """The same order for roots that are already sorted, given beside their sort keys
        (:meth:`cubeproof.coordinator.state.ReplayState.root_order`), one root at a time: a plan
        that starts sixteen tasks looks at the roots it needs, not at every root."""
        start = 0 if self._last is None else bisect.bisect_right(keys, self._last)
        return (roots[i] for i in itertools.chain(range(start, len(roots)), range(start)))

    def served(self, root: Key) -> None:
        self._last = order_key(root)


_STAGE = {Disposition.PENDING: Stage.SOLVE, Disposition.NEEDS_SPLIT: Stage.SPLIT}


def _eligible(state: ReplayState, root: Key, running: Collection[Key]) -> Iterator[Work]:
    for node in state.open_below(root):
        stage = _STAGE.get(node.disposition)
        if stage is not None and node.key not in running:
            yield Work(node, root, stage)


def next_work(
    state: ReplayState, *, running: Collection[Key], rotation: RootRotation, limit: int
) -> list[Work]:
    """Up to ``limit`` nodes to start, round-robin over roots, depth-first within each."""
    if type(limit) is not int or limit < 0:
        raise ValueError("limit must be a nonnegative integer")
    if state.anomaly_halt or state.machine_halt:
        return []
    picked: list[Work] = []
    live: list[tuple[Key, Iterator[Work]]] = []
    # first round: one node of each root in rotation order, until the limit; the roots are
    # visited one at a time, so a plan that reaches its limit early stops looking
    for root in rotation.rotate(*state.root_order()):
        if len(picked) >= limit:
            break
        source = _eligible(state, root, running)
        work = next(source, None)
        if work is None:
            continue
        picked.append(work)
        rotation.served(root)
        live.append((root, source))
    while live and len(picked) < limit:
        remaining: list[tuple[Key, Iterator[Work]]] = []
        for index, (root, source) in enumerate(live):
            if len(picked) >= limit:
                remaining.extend(live[index:])
                break
            work = next(source, None)
            if work is None:
                continue
            picked.append(work)
            rotation.served(root)
            remaining.append((root, source))
        live = remaining
    return picked


# -- split decisions (specification §9.1) ----------------------------------------------------------


class SplitAction(str, enum.Enum):
    SPLIT = "split"  # record the validated split
    SOLVE = "solve"  # schedule the checked unit route (the leaf's UP decides proof or model)
    FALLBACK = "fallback"  # ask the lowest-eligible fallback for a choice
    STOP = "stop"  # record node_stop


@dataclass(frozen=True)
class SplitDecision:
    action: SplitAction
    variables: tuple[int, ...] = ()
    stop_state: StopState | None = None
    reason: str = ""

    @classmethod
    def stop(cls, state: StopState, reason: str) -> SplitDecision:
        return cls(SplitAction.STOP, (), state, reason)


def split_k(policy: Policy, cube: Sequence[int], variables: int) -> int:
    """``k`` for the splitter: ``split.vars`` clamped to the remaining policy depth and the
    unassigned variables (specification §9.1). 0 means: do not invoke a splitter (record STUCK)."""
    remaining = max(0, policy.max_cube_size - len(cube))
    return clamp_k(policy.split.vars, remaining, max(0, variables - len(cube)))


def decide_split(
    choice: SplitChoice,
    *,
    variables: int,
    cube: Sequence[int],
    pool: Sequence[int] | None,
    k: int,
    fallback: bool = False,
) -> SplitDecision:
    """The coordinator's action for a splitter answer (module doc).

    ``fallback`` says that ``choice`` already came from the lowest-eligible fallback; its
    own ``budget`` answer (the parent propagation does not fit) blocks the node, never the
    protocol (specification §9.1). A chosen split is validated structurally here; an invalid one is
    a splitter failure and goes to the fallback (or, if it came from there, is an error).
    """
    info = choice.info_dict()
    if choice.status == CHOSEN:
        try:
            chosen = validate_choice(choice, variables, cube, pool, k)
        except (ContractError, ConfigurationError) as error:
            if fallback:
                raise
            return SplitDecision(SplitAction.FALLBACK, reason=f"invalid_choice:{error.rule}")
        return SplitDecision(SplitAction.SPLIT, chosen)
    if choice.status == NO_ELIGIBLE:
        complete = info.get("parent_assigned") == variables
        return _no_eligible(complete, restricted=pool is not None)
    if choice.status == FAILED and info.get("stop") == PARENT_CONFLICT:
        return SplitDecision(SplitAction.SOLVE, reason=PARENT_CONFLICT)
    if choice.status in (BUDGET, FAILED):
        if fallback or info.get("algorithm") == FALLBACK_ALGORITHM:
            return SplitDecision.stop(StopState.RESOURCE_BLOCKED, "split_resources")
        return SplitDecision(SplitAction.FALLBACK, reason=choice.status)
    raise ValueError(f"unknown split status {choice.status!r}")  # pragma: no cover


def _no_eligible(complete: bool, *, restricted: bool) -> SplitDecision:
    """No variable to split on: a complete conflict-free assignment is the model path; an
    empty restricted pool (or nothing left) is STUCK (specification §9.1)."""
    if complete:
        return SplitDecision(SplitAction.SOLVE, reason="complete_assignment")
    return SplitDecision.stop(StopState.STUCK, "no_eligible_pool" if restricted else "no_eligible")


# -- pinned tools of a snapshot ------------------------------------------------------------------


def leaf_tools(machinery: Machinery) -> LeafTools:
    """The solver and checker of a measured machinery snapshot, verified against its hashes.

    Raises :class:`~cubeproof.base.errors.ToolError` (``tool.hash_mismatch``,
    ``tool.missing`` ...) if a binary at the snapshot's path is not exactly the recorded
    one: the binding then compares against pins that cannot differ from what was measured
    (``leaf.binding`` module doc).
    """
    solver = PinnedBinary.pinned(machinery.solver.path, machinery.solver.sha256)
    checker = PinnedBinary.pinned(machinery.checker.path, machinery.checker.sha256)
    return LeafTools(solver, tuple(machinery.solver.argv), checker, host_cpu=host_cpu())


# -- a queued check as a scheduler candidate -----------------------------------------------------


def check_candidate(
    request: CheckRequest, *, task_id: str, node: Key, cnf_bytes: int, group: str, seq: int
) -> Candidate:
    """The scheduler's view of ``LeafAttempt.check_request``: a check that holds its disk.

    The need is the check's CPU, its memory (heap + stack + slack, from the request, plus the
    child overhead) and the disk of the sealed proof, the CNF and the logs, which the
    attempt reserved when the solver exited (specification §8.3): launching it is a restage that
    asks the ledgers only for the CPU and the memory. ``seq`` is the queue age (lower is older).
    """
    need = Need(
        1000,
        request.memory_bytes + CHILD_OVERHEAD,
        ((group, request.proof_bytes + cnf_bytes + LOG_ALLOWANCE),),
    )
    return Candidate(task_id, Stage.CHECK, node, need, seq, holds=True)
