"""The Python reference of ``lookahead-v1`` (specification §9.3, decision 0012).

The native helper ``cubeproof-look`` (``packages/cubeproof/native``) and this module implement
the same bounded algorithm. With the same integer ``probe_limit`` and no wall budget they
return identical choices and identical info; ``wall_ms`` stops are hardware dependent, which is
allowed because the chosen W is recorded.

Definition (decisions that specification §9.3 leaves open are marked *decision*):

1. *Parent*: unit propagation (UP) of F under the canonical parent cube C, one probe unit. A
   conflict makes the choice ``failed`` with ``info.stop = "parent_conflict"``: the checked
   unit route applies, a splitter never turns a conflict into a split. Candidates are the
   variables of the pool (all variables if the pool is None) in ascending order that the
   parent leaves unassigned (cube and UP assignments are excluded). The chosen list W starts
   empty.
2. *Round* r = 1, 2, ... (*decision*: rounds are numbered from 1; the round number only enters
   the sampling hash) while ``len(W) < k`` and candidates remain. The sampled children are the
   sign vectors of W: all ``2^len(W)`` in child-index order if that is at most 16, otherwise
   the 16 smallest ``(SHA256(node_id NUL round NUL child_index), child_index)`` (decimal ASCII
   for round and index, digest compared as 32 big-endian bytes). Child ``t`` assigns ``+W[j]``
   when bit ``j`` of ``t`` is 1 and ``-W[j]`` otherwise. Sampled children are evaluated in
   ascending ``(digest, index)`` order. No host RNG.
3. *Base propagation of the sampled children*: UP of F under ``C`` plus the child's signed W
   literals, once per child and round, one probe unit each (*decision*: the parent UP of step 1
   also serves as the single child of round 1 and is not charged again; a base propagation is
   charged once per round and child, not once per candidate).
4. *Candidate score*: for each remaining candidate v (ascending), for every sampled child D
   that did not conflict and does not already assign v, probe +v and -v on top of D's
   propagation, one probe unit each. ``n+`` / ``n-`` are the assignments the probe adds,
   excluding the probe literal itself; a conflicting probe has ``V + 1``. The child's score is
   ``(n+ + 1)(n- + 1)`` (a conflicting or v-assigning child scores 0) and the candidate's score
   is the sum over the sampled children. The best candidate is the maximum score, ties by the
   lowest variable. It is appended to W. Variables implied in some sampled child score 0 there
   and are *not* discarded globally.
5. *Budget*: ``probe_limit`` counts probe units. A candidate evaluation is atomic: it runs
   completely or its partial score is discarded (*decision*: it runs iff the units it needs
   fit the remaining limit; the first candidate that does not fit ends the round's evaluation
   without trying later, cheaper candidates). ``wall_ms`` is checked before every UP unit on
   the monotonic clock of the run, which starts when the run starts. When the budget ends
   during a round the best completely evaluated candidate of that round, if any, is appended
   and W is returned with status ``chosen``; otherwise the previous W is returned; if that is
   empty the status is ``budget``.

Result info (all integers or strings, deterministic for a probe limit): ``algorithm``,
``candidates`` (count of eligible variables after the parent), ``parent_assigned`` (variables
assigned by the parent: cube plus UP), ``probes`` (units used), ``rounds`` (``len(W)``),
``scores`` (the winning score of each round), ``stop`` (``k``, ``candidates``, ``probe_limit``,
``wall_ms`` or ``parent_conflict``).

The propagation engine here is its own counter-based implementation with an undo trail. UP
is confluent: whether it conflicts and which variables it assigns do not depend on
the traversal order, so scores, and therefore choices, do not either; tests compare it with
``cubeproof.cnf.unit``.

The generator form (:func:`lookahead_steps`) yields before every UP unit and every
``chunk`` literals of index building, so a caller can interleave it with other work (specification
§8.1); one UP unit itself runs to its end and is bounded by the formula size only.
"""

from __future__ import annotations

import hashlib
import heapq
import time
from collections.abc import Callable, Generator, Iterable, Sequence
from dataclasses import dataclass
from typing import Any, TypeVar, cast

from cubeproof.cnf.dimacs import Formula
from cubeproof.cnf.unit import DEFAULT_CHUNK
from cubeproof.contracts.identity import check_cube, node_id
from cubeproof.split.choice import (
    BUDGET,
    CHOSEN,
    FAILED,
    NO_ELIGIBLE,
    PARENT_CONFLICT,
    Budget,
    SplitChoice,
    check_k,
    check_pool,
)

ALGORITHM = "lookahead-v1"
#: At most this many sign children are sampled per round.
SAMPLE_CHILDREN = 16

_T = TypeVar("_T")

_TRUE, _FALSE = 1, 2


def drive(steps: Generator[None, None, _T]) -> _T:
    """Run a step generator to its end and return its value."""
    while True:
        try:
            next(steps)
        except StopIteration as stop:
            return cast(_T, stop.value)


def sample_children(node: str, round_number: int, width: int) -> list[int]:
    """The sampled child indices of ``2^width`` sign vectors in round ``round_number``."""
    if width < 0 or round_number < 1:
        raise ValueError("width must be >= 0 and the round number >= 1")
    if (1 << width) <= SAMPLE_CHILDREN:
        return list(range(1 << width))
    prefix = f"{node}\0{round_number}\0"
    keyed = (
        (hashlib.sha256(f"{prefix}{i}".encode("ascii")).digest(), i) for i in range(1 << width)
    )
    return [index for _, index in heapq.nsmallest(SAMPLE_CHILDREN, keyed)]


def _slot(literal: int) -> int:
    return 2 * literal if literal > 0 else -2 * literal + 1


class Engine:
    """Unit propagation with an undo trail over the clauses of one formula.

    Clauses keep their distinct literals; tautologies never propagate and are not indexed; the
    empty clause makes every propagation conflict. Each clause counts its true and false
    literals, so assigning or undoing a literal touches only its occurrences. :meth:`assume`
    assigns one literal and propagates; :meth:`undo` returns to an earlier trail length. After
    a conflict the counters are consistent, so :meth:`undo` always restores the state.
    """

    def __init__(self, variables: int, formula_sha256: str) -> None:
        self.variables = variables
        self.formula_sha256 = formula_sha256
        self._occ: list[list[int]] = [[] for _ in range(2 * variables + 2)]
        self._clauses: list[tuple[int, ...]] = []
        self._lengths: list[int] = []
        self._ntrue: list[int] = []
        self._nfalse: list[int] = []
        self._units: list[int] = []
        self._empty = False
        self.values = bytearray(variables + 1)
        self.trail: list[int] = []
        self._queue: list[int] = []
        self.root_mark = 0
        self.root_conflict = False

    def add_clause(self, clause: Sequence[int]) -> int:
        """Index the next clause; return the work it took (its literal count, at least 1)."""
        distinct = tuple(dict.fromkeys(clause))
        if not distinct:
            self._empty = True
            return 1
        if len({abs(x) for x in distinct}) < len(distinct):
            return len(clause)
        position = len(self._clauses)
        self._clauses.append(distinct)
        self._lengths.append(len(distinct))
        self._ntrue.append(0)
        self._nfalse.append(0)
        if len(distinct) == 1:
            self._units.append(position)
        for literal in distinct:
            self._occ[_slot(literal)].append(position)
        return len(clause)

    def start(self) -> None:
        """Propagate the units of F once; the result is the root state every query starts from."""
        if self._empty:
            self.root_conflict = True
        else:
            self._queue = list(self._units)
            self.root_conflict = self._propagate()
        self.root_mark = len(self.trail)

    def _set(self, literal: int) -> bool:
        """Assign ``literal`` and update its clauses; True if some clause became all false."""
        self.values[abs(literal)] = _TRUE if literal > 0 else _FALSE
        self.trail.append(literal)
        ntrue, nfalse, lengths = self._ntrue, self._nfalse, self._lengths
        for position in self._occ[_slot(literal)]:
            ntrue[position] += 1
        conflict = False
        for position in self._occ[_slot(-literal)]:
            nfalse[position] += 1
            if not ntrue[position]:
                left = lengths[position] - nfalse[position]
                if left == 0:
                    conflict = True
                elif left == 1:
                    self._queue.append(position)
        return conflict

    def _propagate(self) -> bool:
        queue = self._queue
        head = 0
        conflict = False
        while head < len(queue) and not conflict:
            position = queue[head]
            head += 1
            if self._ntrue[position] or self._lengths[position] - self._nfalse[position] != 1:
                continue
            for literal in self._clauses[position]:
                if not self.values[abs(literal)]:
                    conflict = self._set(literal)
                    break
        queue.clear()
        return conflict

    def assume(self, literal: int) -> bool:
        """Assign ``literal`` (unless already true) and propagate; True on a conflict."""
        current = self.values[abs(literal)]
        if current:
            return (current == _TRUE) != (literal > 0)
        if self._set(literal):
            self._queue.clear()
            return True
        return self._propagate()

    def replay(self, literals: Iterable[int]) -> None:
        """Assign literals of a known conflict-free propagation without propagating again."""
        for literal in literals:
            self._set(literal)
        self._queue.clear()

    def undo(self, mark: int) -> None:
        """Unassign back to trail length ``mark``."""
        trail, values = self.trail, self.values
        ntrue, nfalse = self._ntrue, self._nfalse
        while len(trail) > mark:
            literal = trail.pop()
            values[abs(literal)] = 0
            for position in self._occ[_slot(literal)]:
                ntrue[position] -= 1
            for position in self._occ[_slot(-literal)]:
                nfalse[position] -= 1


def build_engine_steps(
    formula: Formula, *, chunk: int = DEFAULT_CHUNK
) -> Generator[None, None, Engine]:
    """Build the :class:`Engine` of ``formula``, yielding after about ``chunk`` literals."""
    if type(chunk) is not int or chunk < 1:
        raise ValueError("chunk must be a positive integer")
    engine = Engine(formula.variables, formula.sha256)
    work = 0
    for clause in formula.iter_clauses():
        work += engine.add_clause(clause)
        if work >= chunk:
            work = 0
            yield
    engine.start()
    return engine


def build_engine(formula: Formula) -> Engine:
    """The :class:`Engine` of ``formula`` in one call."""
    return drive(build_engine_steps(formula, chunk=1 << 30))


@dataclass
class _Child:
    index: int
    conflict: bool
    closure: tuple[int, ...] = ()
    assigned: bytes = b""


def _info(
    candidates: int,
    parent_assigned: int,
    probes: int,
    scores: Sequence[int],
    stop: str,
) -> dict[str, Any]:
    return {
        "algorithm": ALGORITHM,
        "candidates": candidates,
        "parent_assigned": parent_assigned,
        "probes": probes,
        "rounds": len(scores),
        "scores": list(scores),
        "stop": stop,
    }


def lookahead_steps(
    formula: Formula,
    cube: Sequence[int],
    k: int,
    pool: Iterable[int] | None,
    budget: Budget,
    *,
    engine: Engine | None = None,
    clock: Callable[[], int] = time.monotonic_ns,
    chunk: int = DEFAULT_CHUNK,
) -> Generator[None, None, SplitChoice]:
    """``lookahead-v1`` at ``cube`` as a step generator (module docstring).

    ``engine`` may be a prebuilt :class:`Engine` of ``formula`` shared by many nodes; it is
    returned to its root state. The wall clock starts at the first step, before the engine is
    built. ``clock`` returns monotonic nanoseconds (injectable for tests).
    """
    started = clock()
    check_k(k)
    parent = check_cube(cube, formula.variables)
    members = check_pool(pool, formula.variables)
    node = node_id(formula.sha256, parent)
    wall_ns = None if budget.wall_ms is None else budget.wall_ms * 1_000_000
    limit = budget.probe_limit
    variables = formula.variables

    def over_wall() -> bool:
        return wall_ns is not None and clock() - started >= wall_ns

    if engine is None:
        engine = yield from build_engine_steps(formula, chunk=chunk)
    elif engine.formula_sha256 != formula.sha256 or engine.variables != variables:
        raise ValueError("the engine belongs to another formula")
    engine.undo(engine.root_mark)

    if over_wall():
        return SplitChoice.make((), BUDGET, _info(0, 0, 0, (), "wall_ms"))
    used = 1
    yield
    conflict = engine.root_conflict
    if not conflict:
        for literal in parent:
            if engine.assume(literal):
                conflict = True
                break
    if conflict:
        engine.undo(engine.root_mark)
        return SplitChoice.make((), FAILED, _info(0, 0, used, (), PARENT_CONFLICT))
    parent_mark = len(engine.trail)
    parent_assigned = parent_mark
    values = engine.values
    pool_variables = range(1, variables + 1) if members is None else members
    candidates = [v for v in pool_variables if not values[v]]
    parent_state = bytes(values)

    chosen: list[int] = []
    scores: list[int] = []
    stop = ""
    while len(chosen) < k:
        round_number = len(chosen) + 1
        remaining = [v for v in candidates if v not in chosen]
        if not remaining:
            stop = "candidates"
            break
        # -- the sampled children and their base propagation -------------------------------
        children: list[_Child] = []
        if not chosen:
            children.append(_Child(0, False, (), parent_state))
        else:
            for index in sample_children(node, round_number, len(chosen)):
                if used >= limit:
                    stop = "probe_limit"
                    break
                if over_wall():
                    stop = "wall_ms"
                    break
                used += 1
                yield
                engine.undo(parent_mark)
                clash = False
                for j, w in enumerate(chosen):
                    if engine.assume(w if (index >> j) & 1 else -w):
                        clash = True
                        break
                if clash:
                    children.append(_Child(index, True))
                else:
                    closure = tuple(engine.trail[parent_mark:])
                    children.append(_Child(index, False, closure, bytes(engine.values)))
        engine.undo(parent_mark)
        if stop:
            break
        # -- candidate evaluation ----------------------------------------------------------
        loaded: _Child | None = None
        best_variable = 0
        best_score = -1
        for v in remaining:
            live = [c for c in children if not c.conflict and not c.assigned[v]]
            if used + 2 * len(live) > limit:
                stop = "probe_limit"
                break
            score = 0
            complete = True
            for child in live:
                if loaded is not child:
                    engine.undo(parent_mark)
                    engine.replay(child.closure)
                    loaded = child
                gains = []
                for literal in (v, -v):
                    if over_wall():
                        stop = "wall_ms"
                        complete = False
                        break
                    used += 1
                    yield
                    mark = len(engine.trail)
                    clash = engine.assume(literal)
                    gains.append(variables + 1 if clash else len(engine.trail) - mark - 1)
                    engine.undo(mark)
                if not complete:
                    break
                score += (gains[0] + 1) * (gains[1] + 1)
            if not complete:
                break
            if score > best_score:
                best_variable, best_score = v, score
        engine.undo(parent_mark)
        if best_variable:
            chosen.append(best_variable)
            scores.append(best_score)
        if stop:
            break
    engine.undo(engine.root_mark)
    stop = stop or "k"  # the loop ended because W is complete
    info = _info(len(candidates), parent_assigned, used, scores, stop)
    if chosen:
        return SplitChoice.make(chosen, CHOSEN, info)
    status = NO_ELIGIBLE if stop == "candidates" else BUDGET
    return SplitChoice.make((), status, info)


def lookahead(
    formula: Formula,
    cube: Sequence[int],
    k: int,
    pool: Iterable[int] | None,
    budget: Budget,
    *,
    engine: Engine | None = None,
    clock: Callable[[], int] = time.monotonic_ns,
) -> SplitChoice:
    """``lookahead-v1`` at ``cube`` in one call."""
    return drive(lookahead_steps(formula, cube, k, pool, budget, engine=engine, clock=clock))
