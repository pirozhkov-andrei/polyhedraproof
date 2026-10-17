"""Frozen reference implementation of the formula builder.

Not a test module: the differential tests in ``test_cnf_builder.py`` replay the same
operations on this class and on ``neighbourly.cnf.Builder`` and require identical state.
It imports nothing of the package; it is to the builder what a golden file is to bytes.
Do not edit the methods.
"""

from __future__ import annotations

import itertools
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field

Clause = tuple[int, ...]
BracketOracle = Callable[[Sequence[int]], int]


class ReferenceFormulaError(Exception):
    """The error of the reference implementation."""


@dataclass
class LayerCounts:
    variables: int = 0
    clauses: int = 0
    items: int = 0


@dataclass
class Formula:
    oracle: BracketOracle | None = None
    variables: int = 0
    clauses: list[Clause] = field(default_factory=list)
    tags: list[tuple[str, str]] = field(default_factory=list)
    values: dict[int, int] = field(default_factory=dict)
    counts: dict[str, LayerCounts] = field(default_factory=dict)
    violations: dict[str, list[str]] = field(default_factory=dict)
    layer: str = "?"

    def begin_layer(self, name: str) -> None:
        self.layer = name
        self.counts.setdefault(name, LayerCounts())

    def bump(self, count: int = 1) -> None:
        self._layer_counts().items += count

    def _layer_counts(self) -> LayerCounts:
        return self.counts.setdefault(self.layer, LayerCounts())

    def new_variable(self, value: int | None = None) -> int:
        self.variables += 1
        self._layer_counts().variables += 1
        if self.oracle is not None:
            if value is None:
                raise ReferenceFormulaError("oracle mode: every variable needs a value")
            self.values[self.variables] = value & 1
        return self.variables

    def literal_value(self, literal: int) -> int:
        value = self.values[abs(literal)]
        return value if literal > 0 else 1 - value

    def add_clause(self, literals: Iterable[int], tag: str = "") -> None:
        clause: Clause = tuple(dict.fromkeys(literals))
        if any(type(x) is not int or not 1 <= abs(x) <= self.variables for x in clause):
            raise ReferenceFormulaError(
                f"invalid CNF literal in {clause}; allocated variables: {self.variables}"
            )
        if any(-x in clause for x in clause):
            return
        self.clauses.append(clause)
        self.tags.append((self.layer, tag))
        self._layer_counts().clauses += 1
        if self.oracle is not None and not any(self.literal_value(x) for x in clause):
            self.violations.setdefault(self.layer, []).append(tag or str(clause))

    def forbid(self, literals: Sequence[int], values: Sequence[int], tag: str = "") -> None:
        if len(literals) != len(values) or any(v not in (0, 1) for v in values):
            raise ReferenceFormulaError("one Boolean value is required for each literal")
        self.add_clause(
            [
                -literal if value else literal
                for literal, value in zip(literals, values, strict=True)
            ],
            tag,
        )

    def assert_xor(self, literals: Sequence[int], rhs: int, tag: str = "") -> None:
        remaining = list(literals)
        while len(remaining) > 4:
            a, b, c = remaining[0], remaining[1], remaining[2]
            helper = self.new_variable(
                None
                if self.oracle is None
                else self.literal_value(a) ^ self.literal_value(b) ^ self.literal_value(c)
            )
            self._xor_small((a, b, c, helper), 0, tag)
            remaining = [helper, *remaining[3:]]
        self._xor_small(tuple(remaining), rhs, tag)

    def _xor_small(self, literals: Clause, rhs: int, tag: str) -> None:
        for bits in itertools.product((0, 1), repeat=len(literals)):
            if (sum(bits) & 1) != (rhs & 1):
                self.forbid(literals, bits, tag)

    def define_xor(self, literals: Sequence[int], tag: str = "") -> int:
        terms = list(literals)
        if len(terms) == 1:
            return terms[0]
        if self.oracle is None:
            output = self.new_variable()
        else:
            value = 0
            for literal in terms:
                value ^= self.literal_value(literal)
            output = self.new_variable(value)
        self.assert_xor([*terms, output], 0, tag)
        return output

    def define_and(self, a: int, b: int, tag: str = "") -> int:
        value = None if self.oracle is None else self.literal_value(a) & self.literal_value(b)
        output = self.new_variable(value)
        self.add_clause((-output, a), tag)
        self.add_clause((-output, b), tag)
        self.add_clause((output, -a, -b), tag)
        return output

    def layer_of(self, clause_index: int) -> str:
        return self.tags[clause_index][0]

    def counts_table(self) -> list[tuple[str, LayerCounts]]:
        return list(self.counts.items())
