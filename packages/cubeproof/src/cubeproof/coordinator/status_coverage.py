"""Closed coverage of the selected roots: exact, reduced, order independent (specification §8.4,
§12.3).

For every accepted root outside given-away regions the closed part is the sum of the measures of
the **maximal closed** nodes below it, relative to the root: a cube that fixes ``d`` more variables
than the root has measure ``2^-d``. The traversal is the certifier's (specification §10.3, the same
as :meth:`~cubeproof.coordinator.state.ReplayState.iter_open`): a closed node counts whole, a node
that carries a model counts nothing, a node with splits continues into the children of its
smallest ``split_id``, a node without splits counts nothing. Maximal closed nodes of one root are
pairwise disjoint, so the sum never exceeds 1; full closure is exactly 1 and no closure exactly 0.

The result is an exact rational ``numerator / 2^power`` held as a nonnegative decimal string and a
power (the numerator may exceed 64 bits for a large ``V``), reduced: ``power`` is 0 and the
numerator 0 or 1, or the numerator is odd (requirement ``status.coverage``). It depends only
on the folded state, never on the order in which records arrived, on dictionary order or on the
clock, so the same journal gives the same coverage after a restart or a state-cache restore.

Cost is linear in the visited nodes (closed leaves plus the splitted ancestors); a visit budget
keeps one status from stalling the loop: when it is exhausted :func:`closed_coverage` raises
:class:`CoverageBudget` and the caller keeps its previous value and says so.
"""

from __future__ import annotations

from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from typing import Any

from cubeproof.coordinator.state import Key, ReplayState, iter_children

__all__ = [
    "Coverage",
    "CoverageBudget",
    "closed_coverage",
    "fraction_text",
    "mean_text",
    "reduce_fraction",
]


class CoverageBudget(Exception):
    """The visit budget ran out before every root was traversed (a signal, not a failure)."""

    def __init__(self, visited: int) -> None:
        super().__init__(f"coverage not computed within {visited} node visits")
        self.visited = visited


@dataclass(frozen=True)
class Coverage:
    """The closed measure of one root: ``numerator / 2**power``, reduced."""

    root: Key
    numerator: int
    power: int

    def to_json(self) -> dict[str, Any]:
        return {
            "node": {"formula_sha256": self.root[0], "cube": list(self.root[1])},
            "closed_numerator": str(self.numerator),
            "denominator_power_two": self.power,
        }

    @property
    def closed(self) -> bool:
        return self.numerator == 1 and self.power == 0


def reduce_fraction(numerator: int, power: int) -> tuple[int, int]:
    """``numerator / 2**power`` in lowest terms (zero is ``0 / 2**0``)."""
    if numerator == 0:
        return 0, 0
    while power > 0 and numerator % 2 == 0:
        numerator //= 2
        power -= 1
    return numerator, power


def fraction_text(numerator: int, power: int, digits: int = 4) -> str:
    """The fraction as a decimal rounded down to ``digits`` places (exact integer arithmetic)."""
    scaled = (numerator * 10**digits) >> power
    whole, fraction = divmod(scaled, 10**digits)
    return f"{whole}.{fraction:0{digits}d}"


class _Budget:
    def __init__(self, visits: int) -> None:
        self.total = visits
        self.left = visits

    def visit(self) -> None:
        self.left -= 1
        if self.left < 0:
            raise CoverageBudget(self.total)


def _root_coverage(
    state: ReplayState, root: Key, given: frozenset[Key], budget: _Budget
) -> Coverage:
    counts: dict[int, int] = {}
    formula, base = root[0], len(root[1])
    frames: list[Iterator[tuple[int, ...]]] = [iter((root[1],))]
    while frames:
        try:
            cube = next(frames[-1])
        except StopIteration:
            frames.pop()
            continue
        budget.visit()
        key = (formula, cube)
        if key in given:
            continue
        if state.closed(key):
            depth = len(cube) - base  # variables fixed beyond the root: measure 2^-depth
            counts[depth] = counts.get(depth, 0) + 1
            continue
        facts = state.facts(key)
        if facts is None or facts.model or not facts.splits:
            continue
        frames.append(iter_children(cube, facts.splits[min(facts.splits)]))
    if not counts:
        return Coverage(root, 0, 0)
    deepest = max(counts)
    total = sum(count << (deepest - depth) for depth, count in counts.items())
    numerator, power = reduce_fraction(total, deepest)
    return Coverage(root, numerator, power)


def closed_coverage(state: ReplayState, *, max_visits: int = 250_000) -> list[Coverage]:
    """The closed coverage of every owned root, sorted ``(formula, node_id)`` like the roots.

    Raises :class:`CoverageBudget` after ``max_visits`` node visits in total.
    """
    given = frozenset(state.given_away())
    budget = _Budget(max_visits)
    return [_root_coverage(state, root, given, budget) for root in state.roots()]


def mean_text(parts: Sequence[tuple[int, int]], digits: int = 4) -> str:
    """The mean of the fractions ``(numerator, power)`` rounded down to ``digits`` decimals;
    ``0.0000`` for no fractions. Exact integer arithmetic."""
    if not parts:
        return f"0.{0:0{digits}d}"
    power = max(p for _, p in parts)
    total = sum(n << (power - p) for n, p in parts)
    scaled = (total * 10**digits) // (len(parts) << power)
    return f"{scaled // 10**digits}.{scaled % 10**digits:0{digits}d}"
