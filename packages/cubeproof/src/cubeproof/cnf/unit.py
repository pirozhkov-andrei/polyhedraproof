"""Unit propagation of CNF(F, C) and the ``unit-v1`` LRAT refutation (specification §3.1, §4.8,
§6.1, §9.1).

Unit propagation (UP) is a proof *producer* and a heuristic, never an authority (specification §5):
a conflict schedules the checked unit route, whose proof goes through the pinned checker like
any other; a complete conflict-free assignment goes through model evaluation
(:mod:`cubeproof.cnf.model`); anything else is undecided. Nothing here closes a node.

All work is a generator that yields after at most ``chunk`` units of work, so a caller (the
coordinator's event loop, through :mod:`cubeproof.tools.unit_helper`) can interleave it
with other work (specification §8.1). :func:`drive` runs a generator to its end for tests and
helpers.

Definition of ``unit-v1`` (normative for this implementation; the machinery records the
name ``unit_algorithm: "unit-v1"``, specification §4.4, and audits regenerate the same bytes,
specification §11.2)
------------------------------------------------------------------------------------------

Input: a canonical formula F with V variables and clauses c_1..c_M, and a canonical cube
C = (u_1..u_d). Clause IDs are those of CNF(F, C): c_i has ID i, the unit clause of u_j has
ID M+j (base clauses first, then the canonical units, specification §6.1). A clause's *distinct
literals* are its literals without repetitions, in first-occurrence order. A clause containing a
literal and its negation is a tautology and takes no part in propagation. A *unit* clause
is a non-tautological clause with exactly one distinct literal.

1. If F contains the empty clause, the hint list is the ID of the first empty clause.
2. Otherwise the trail starts empty. ``assign(l, r)``: if l is already true nothing happens
   (no hint); if l is false, r is appended to the hints and propagation stops with a
   conflict; else l becomes true, l is appended to the trail and r to the hints.
3. Seeds: ``assign(l, id)`` for every unit clause of F in ascending ID order, then for every
   cube literal u_j with ID M+j in cube order.
4. The trail is processed first in, first out. For the next literal l: every clause
   containing l is satisfied; then, for every not yet satisfied non-tautological clause
   containing -l, in ascending ID order, the count of its distinct literals that have been
   *processed* false decreases by one. At zero, the clause ID is appended to the hints and
   propagation stops with a conflict. At one, the first distinct literal of the clause
   whose variable is unassigned (if any) is assigned with that clause as reason.
5. When the trail is exhausted without conflict, propagation ends without a proof.

On a conflict the proof is textual LRAT (specification §6.1). cake_lpr does not merge repeated
literals of a hint clause, so a reason clause in which the literal it implies occurs more than once
is first restated: for each such reason, in trail order, one addition line
``k L 0 r 0`` where L are the distinct literals of clause r and k counts up from M+d+1; the
hint list then uses k in place of r. The last line is ``k 0 H 0`` with the next k and the
hint list H. Tokens are separated by one space and every line ends with LF. Without such
reasons (the usual case) the proof is the single line ``M+d+1 0 H 0``.

Every hint is unit or conflicting when the checker reaches it: a reason clause had all its
other distinct literals processed false, and they were assigned by earlier hints.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Generator, Sequence
from dataclasses import dataclass, field
from typing import TypeVar, cast

from cubeproof.cnf.dimacs import Formula
from cubeproof.contracts.identity import check_cube

#: The name of the algorithm in the machinery snapshot (specification §4.4).
UNIT_ALGORITHM = "unit-v1"

#: Default units of work between two yields: one unit is one clause or occurrence visited.
DEFAULT_CHUNK = 4096

_T = TypeVar("_T")

#: Values of the assignment array.
_UNASSIGNED, _TRUE, _FALSE = 0, 1, 2


def drive(steps: Generator[None, None, _T]) -> _T:
    """Run a step generator to its end and return its value."""
    while True:
        try:
            next(steps)
        except StopIteration as stop:
            return cast(_T, stop.value)


def _slot(literal: int) -> int:
    return 2 * literal if literal > 0 else -2 * literal + 1


def _check_chunk(chunk: object) -> int:
    if type(chunk) is not int or chunk < 1:
        raise ValueError("chunk must be a positive integer")
    return chunk


class UnitIndex:
    """The occurrence index of one formula, built once and reused for many cubes.

    Build it with :func:`build_index` or :func:`build_index_steps`. Clause positions are
    0-based here; clause IDs (1-based) appear only in results and proofs.
    """

    __slots__ = (
        "_clauses",
        "_duplicated",
        "_empty",
        "_lengths",
        "_occurrences",
        "_satisfied",
        "_units",
        "clause_count",
        "formula_sha256",
        "variables",
    )

    def __init__(self, formula: Formula) -> None:
        self.formula_sha256 = formula.sha256
        self.variables = formula.variables
        self.clause_count = formula.clauses
        self._clauses: list[tuple[int, ...]] = []
        self._occurrences: list[list[int]] = [[] for _ in range(2 * formula.variables + 2)]
        self._units: list[int] = []
        self._empty: int | None = None
        self._lengths: list[int] = []
        self._satisfied = bytearray()
        self._duplicated: dict[int, frozenset[int]] = {}

    def _add(self, clause: tuple[int, ...]) -> int:
        """Index the next clause; return the work it took."""
        position = len(self._clauses)
        distinct = tuple(dict.fromkeys(clause))
        self._clauses.append(distinct)
        self._lengths.append(len(distinct))
        if not distinct:
            if self._empty is None:
                self._empty = position
            self._satisfied.append(0)
            return 1
        if len({abs(x) for x in distinct}) < len(distinct):
            self._satisfied.append(1)  # a tautology never propagates nor conflicts
            return len(clause)
        self._satisfied.append(0)
        if len(distinct) < len(clause):
            counts = Counter(clause)
            self._duplicated[position] = frozenset(x for x, n in counts.items() if n > 1)
        if len(distinct) == 1:
            self._units.append(position)
        for literal in distinct:
            self._occurrences[_slot(literal)].append(position)
        return len(clause)

    def distinct_literals(self, clause_id: int) -> tuple[int, ...]:
        """The distinct literals of base clause ``clause_id`` (1-based)."""
        if not 1 <= clause_id <= self.clause_count:
            raise ValueError(f"clause {clause_id} is not a base clause")
        return self._clauses[clause_id - 1]

    def implied_literal_repeated(self, clause_id: int, literal: int) -> bool:
        """True if ``literal`` occurs more than once in base clause ``clause_id``."""
        return literal in self._duplicated.get(clause_id - 1, frozenset())


def build_index_steps(
    formula: Formula, *, chunk: int = DEFAULT_CHUNK
) -> Generator[None, None, UnitIndex]:
    """Build the :class:`UnitIndex` of ``formula``, yielding after about ``chunk`` literals."""
    _check_chunk(chunk)
    index = UnitIndex(formula)
    work = 0
    for clause in formula.iter_clauses():
        work += index._add(clause)
        if work >= chunk:
            work = 0
            yield
    if len(index._clauses) != formula.clauses:  # pragma: no cover - Formula guarantees it
        raise ValueError("the formula does not have its declared clause count")
    return index


def build_index(formula: Formula) -> UnitIndex:
    """The :class:`UnitIndex` of ``formula`` in one call."""
    return drive(build_index_steps(formula, chunk=1 << 30))


@dataclass(frozen=True)
class Propagation:
    """The result of unit-v1 propagation of CNF(F, C).

    ``trail`` holds the assigned literals in assignment order and ``reasons`` the clause ID
    that assigned each (same length). On a conflict ``conflict_clause`` is the ID of the
    clause that ended propagation; ``hints`` is then the unit-v1 hint list before the
    restatement of repeated literals. ``work`` is a non-authoritative cost measure.
    """

    formula_sha256: str
    variables: int
    clause_count: int
    cube: tuple[int, ...]
    trail: tuple[int, ...]
    reasons: tuple[int, ...]
    conflict_clause: int | None
    work: int = field(default=0, compare=False)

    def __post_init__(self) -> None:
        if len(self.trail) != len(self.reasons):
            raise ValueError("every trail literal needs its reason")

    @property
    def conflict(self) -> bool:
        return self.conflict_clause is not None

    @property
    def complete(self) -> bool:
        """No conflict and every variable 1..V assigned."""
        return self.conflict_clause is None and len(self.trail) == self.variables

    @property
    def hints(self) -> tuple[int, ...]:
        if self.conflict_clause is None:
            raise ValueError("propagation ended without a conflict")
        return (*self.reasons, self.conflict_clause)

    def assigned(self) -> frozenset[int]:
        """The variables assigned by propagation (on a conflict: before the conflict)."""
        return frozenset(abs(x) for x in self.trail)

    def values(self) -> tuple[bool, ...]:
        """The values of variables 1..V; only for a complete propagation."""
        if not self.complete:
            raise ValueError("propagation did not assign every variable without conflict")
        out = [False] * self.variables
        for literal in self.trail:
            out[abs(literal) - 1] = literal > 0
        return tuple(out)


def propagate_steps(
    index: UnitIndex, cube: Sequence[int], *, chunk: int = DEFAULT_CHUNK
) -> Generator[None, None, Propagation]:
    """Unit-v1 propagation of CNF(F, C), yielding after about ``chunk`` units of work.

    ``cube`` must be canonical and in range (:class:`ContractError` ``cube.*``).
    """
    _check_chunk(chunk)
    literals = check_cube(cube, index.variables)
    m = index.clause_count
    if len(index._clauses) != m:
        raise ValueError("the index is incomplete: build it with build_index(_steps)")
    trail: list[int] = []
    reasons: list[int] = []

    def result(conflict: int | None, work: int) -> Propagation:
        return Propagation(
            index.formula_sha256,
            index.variables,
            m,
            literals,
            tuple(trail),
            tuple(reasons),
            conflict,
            work,
        )

    if index._empty is not None:
        return result(index._empty + 1, 1)
    values = bytearray(index.variables + 1)
    seeds = [(index._clauses[c][0], c + 1) for c in index._units]
    seeds += [(literal, m + j + 1) for j, literal in enumerate(literals)]
    total = len(seeds)
    for literal, reason in seeds:
        want = _TRUE if literal > 0 else _FALSE
        current = values[abs(literal)]
        if current == want:
            continue
        if current != _UNASSIGNED:
            return result(reason, total)
        values[abs(literal)] = want
        trail.append(literal)
        reasons.append(reason)
    remaining = list(index._lengths)
    satisfied = bytearray(index._satisfied)
    clauses = index._clauses
    occurrences = index._occurrences
    total += len(remaining)
    budget = chunk
    head = 0
    while head < len(trail):
        literal = trail[head]
        head += 1
        for position in occurrences[_slot(literal)]:
            satisfied[position] = 1
            total += 1
            budget -= 1
            if budget <= 0:
                budget = chunk
                yield
        for position in occurrences[_slot(-literal)]:
            total += 1
            budget -= 1
            if budget <= 0:
                budget = chunk
                yield
            if satisfied[position]:
                continue
            left = remaining[position] - 1
            remaining[position] = left
            if left == 0:
                return result(position + 1, total)
            if left == 1:
                for candidate in clauses[position]:
                    if values[abs(candidate)] == _UNASSIGNED:
                        values[abs(candidate)] = _TRUE if candidate > 0 else _FALSE
                        trail.append(candidate)
                        reasons.append(position + 1)
                        break
    return result(None, total)


def propagate(index: UnitIndex, cube: Sequence[int]) -> Propagation:
    """Unit-v1 propagation in one call."""
    return drive(propagate_steps(index, cube, chunk=1 << 30))


def unit_proof(index: UnitIndex, propagation: Propagation) -> bytes:
    """The unit-v1 LRAT refutation of a conflicting propagation (module docstring)."""
    if (
        propagation.formula_sha256 != index.formula_sha256
        or propagation.clause_count != index.clause_count
        or propagation.variables != index.variables
    ):
        raise ValueError("the propagation belongs to another formula")
    if len(index._clauses) != index.clause_count:
        raise ValueError("the index is incomplete: build it with build_index(_steps)")
    hints = propagation.hints  # ValueError without a conflict
    m = index.clause_count
    next_id = m + len(propagation.cube) + 1
    lines: list[str] = []
    used: list[int] = []
    for literal, reason in zip(propagation.trail, propagation.reasons, strict=True):
        if reason <= m and index.implied_literal_repeated(reason, literal):
            restated = " ".join(str(x) for x in index.distinct_literals(reason))
            lines.append(f"{next_id} {restated} 0 {reason} 0\n")
            used.append(next_id)
            next_id += 1
        else:
            used.append(reason)
    used.append(hints[-1])
    lines.append(f"{next_id} 0 {' '.join(str(x) for x in used)} 0\n")
    return "".join(lines).encode("ascii")


def refutation(index: UnitIndex, cube: Sequence[int]) -> bytes | None:
    """The unit-v1 proof for CNF(F, C), or None if propagation finds no conflict."""
    propagation = propagate(index, cube)
    return unit_proof(index, propagation) if propagation.conflict else None
