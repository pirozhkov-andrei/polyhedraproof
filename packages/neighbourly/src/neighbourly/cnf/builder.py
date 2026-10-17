"""A deterministic clause set under construction, optionally checked against a witness.

Variables are positive integers handed out in allocation order; a literal is a signed
variable. Allocation order and clause order are part of a formula's identity, because the
DIMACS bytes are, and a cube names a region only relative to a fixed numbering.
:meth:`Builder.add_clause` removes repeated literals (keeping the first occurrence) and drops a
clause that contains a literal and its negation; the DIMACS writer never simplifies anything.

Witness checking (``witness=...``): every variable gets the value the producer passes or,
for a named variable, the value the witness gives its name; every clause whose variables
all have known values is evaluated as it is emitted. A violated clause is collected under
its layer (its tag, or the clause itself when untagged) in the default compatibility mode,
or raises :class:`~neighbourly.cnf.errors.WitnessViolation` with ``strict=True``. Unknown
values are never treated as false. Without a witness the only cost in the emission loop is
one disabled check per variable and per clause.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import ClassVar

from neighbourly.cnf import encodings
from neighbourly.cnf.errors import CnfError, WitnessViolation
from neighbourly.cnf.witness import VariableName, Witness

#: A clause as the builder stores it: literals in emission order, no repeats.
Clause = tuple[int, ...]


@dataclass
class LayerCounts:
    """How much one layer contributed: its variables, clauses and logical items."""

    variables: int = 0
    clauses: int = 0
    items: int = 0


class Builder:
    """A clause set under construction.

    Parameters
    ----------
    witness:
        Turns on witness checking (see the module documentation).
    strict:
        With a witness, raise on the first violated clause instead of collecting it.
    complete:
        With a witness, refuse a variable that gets no value (neither passed nor answered by
        the witness). Semantic controls that must decide every clause use this.

    Errors are raised as :attr:`error`, a :class:`CnfError` subclass that a producer with its
    own error vocabulary may replace in a subclass.
    """

    error: ClassVar[type[CnfError]] = CnfError

    def __init__(
        self,
        witness: Witness | None = None,
        *,
        strict: bool = False,
        complete: bool = False,
    ) -> None:
        self.witness = witness
        self.strict = strict
        self.complete = complete
        self.variables = 0
        self.clauses: list[Clause] = []
        #: ``(layer, tag)`` of every clause, in clause order.
        self.tags: list[tuple[str, str]] = []
        #: Known witness values by variable (only with a witness).
        self.values: dict[int, int] = {}
        #: Names of the variables that were created with one.
        self.names: dict[int, VariableName] = {}
        #: Per-layer counts, layers in the order they were first entered.
        self.counts: dict[str, LayerCounts] = {}
        #: Violated clauses per layer (compatibility mode): their tags, or the clause text.
        self.violations: dict[str, list[str]] = {}
        self.layer = "?"

    # -- layers -------------------------------------------------------------------------

    def begin_layer(self, name: str) -> None:
        self.layer = name
        self.counts.setdefault(name, LayerCounts())

    def bump(self, count: int = 1) -> None:
        """Count one logical item (a relation, a vertex, a gauge generator)."""
        self._layer_counts().items += count

    def _layer_counts(self) -> LayerCounts:
        return self.counts.setdefault(self.layer, LayerCounts())

    # -- variables ----------------------------------------------------------------------

    def new_variable(self, value: int | None = None, name: VariableName | None = None) -> int:
        """Allocate the next variable.

        With a witness, `value` (0 or 1) is its value; without one, `value` is ignored. A
        named variable without a passed value asks the witness for the value of its name.
        """
        self.variables += 1
        variable = self.variables
        self._layer_counts().variables += 1
        if name is not None:
            self.names[variable] = name
        if self.witness is not None:
            if value is None and name is not None:
                value = self.witness(name)
            if value is None:
                if self.complete:
                    raise self.error(f"witness mode: variable {variable} needs a value")
            elif value in (0, 1):
                self.values[variable] = int(value)
            else:
                raise self.error(f"witness value of variable {variable} is {value!r}, not 0 or 1")
        return variable

    def literal_value(self, literal: int) -> int:
        """The witness value of a literal; ``KeyError`` if its variable has none."""
        value = self.values[abs(literal)]
        return value if literal > 0 else 1 - value

    def known_value(self, literal: int) -> int | None:
        """The witness value of a literal, or ``None`` if it is unknown."""
        value = self.values.get(abs(literal))
        if value is None:
            return None
        return value if literal > 0 else 1 - value

    # -- clauses ------------------------------------------------------------------------

    def add_clause(self, literals: Iterable[int], tag: str = "") -> None:
        """Append a clause; repeated literals collapse, a tautology is dropped."""
        clause: Clause = tuple(dict.fromkeys(literals))  # de-duplicate, keep order
        if any(type(x) is not int or not 1 <= abs(x) <= self.variables for x in clause):
            raise self.error(
                f"invalid CNF literal in {clause}; allocated variables: {self.variables}"
            )
        if any(-x in clause for x in clause):
            return  # a tautology constrains nothing
        self.clauses.append(clause)
        self.tags.append((self.layer, tag))
        self._layer_counts().clauses += 1
        if self.witness is not None:
            self._check(clause, tag)

    def _check(self, clause: Clause, tag: str) -> None:
        values = self.values
        for literal in clause:
            value = values.get(abs(literal))
            if value is None or (value if literal > 0 else 1 - value):
                return  # undecided, or satisfied
        if self.strict:
            raise WitnessViolation(self.layer, tag, clause)
        self.violations.setdefault(self.layer, []).append(tag or str(clause))

    def forbid(self, literals: Sequence[int], values: Sequence[int], tag: str = "") -> None:
        """Forbid the single assignment `values` to the truth values of `literals`."""
        if len(literals) != len(values) or any(v not in (0, 1) for v in values):
            raise self.error("one Boolean value is required for each literal")
        self.add_clause(
            [
                -literal if value else literal
                for literal, value in zip(literals, values, strict=True)
            ],
            tag,
        )

    # -- gates (neighbourly.cnf.encodings) ----------------------------------------------

    def assert_xor(self, literals: Sequence[int], rhs: int, tag: str = "") -> None:
        """Assert that the XOR of the truth values of `literals` equals `rhs`."""
        encodings.assert_xor(self, literals, rhs, tag)

    def define_xor(self, literals: Sequence[int], tag: str = "") -> int:
        """A variable equal to the XOR of `literals`; a single literal is returned as is."""
        return encodings.define_xor(self, literals, tag)

    def define_and(self, a: int, b: int, tag: str = "") -> int:
        """A fresh variable equal to the conjunction of two literals."""
        return encodings.define_and(self, a, b, tag)

    # -- reporting ----------------------------------------------------------------------

    def layer_of(self, clause_index: int) -> str:
        return self.tags[clause_index][0]

    def counts_table(self) -> list[tuple[str, LayerCounts]]:
        """Layers in emission order with their counts."""
        return list(self.counts.items())
