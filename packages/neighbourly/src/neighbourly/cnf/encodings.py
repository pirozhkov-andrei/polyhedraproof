"""The gate encodings the formula uses: parity (XOR) constraints and Tseitin AND/XOR.

Each function emits into a builder (anything with the methods of :class:`Emitter`) and
fixes the emission exactly: the same fresh variables in the same order, the same
clauses with the same literal order, and the same chunking of long XOR chains. Changing any
of that changes the formula bytes and therefore the formula's identity.

NOTE FOR ANYONE READING A CLAUSE BACK OUT: the arguments are LITERALS, not variables, so a
parity constraint carries a constant that depends on their signs. Recovering that constant
by taking ``abs()`` and assuming zero is a mistake that survives every check which does not
compare against a real model.
"""

from __future__ import annotations

import itertools
from collections.abc import Iterable, Sequence
from typing import Protocol

from neighbourly.cnf.witness import VariableName, Witness

#: Literals in one XOR link of a long chain; a longer chain is cut with fresh variables.
XOR_CHUNK = 4


class Emitter(Protocol):
    """What an encoding needs of a builder."""

    @property
    def witness(self) -> Witness | None: ...

    def new_variable(self, value: int | None = None, name: VariableName | None = None) -> int: ...

    def add_clause(self, literals: Iterable[int], tag: str = "") -> None: ...

    def forbid(self, literals: Sequence[int], values: Sequence[int], tag: str = "") -> None: ...

    def known_value(self, literal: int) -> int | None: ...


def xor_value(target: Emitter, literals: Iterable[int]) -> int | None:
    """The XOR of the values of `literals`; ``None`` without a witness or if one is unknown."""
    if target.witness is None:
        return None
    value = 0
    for literal in literals:
        bit = target.known_value(literal)
        if bit is None:
            return None
        value ^= bit
    return value


def and_value(target: Emitter, a: int, b: int) -> int | None:
    """The conjunction of two literals in three-valued logic; ``None`` without a witness."""
    if target.witness is None:
        return None
    left, right = target.known_value(a), target.known_value(b)
    if left == 0 or right == 0:
        return 0
    if left is None or right is None:
        return None
    return 1


def forbid_odd_assignments(target: Emitter, literals: Sequence[int], rhs: int, tag: str) -> None:
    """Forbid, one clause each, every assignment whose parity differs from `rhs`.

    Assignments are taken in ``itertools.product((0, 1), ...)`` order, so for
    ``k`` literals this emits ``2**(k-1)`` clauses (fewer when a literal repeats and a clause
    becomes a tautology, which the builder drops).
    """
    for bits in itertools.product((0, 1), repeat=len(literals)):
        if (sum(bits) & 1) != (rhs & 1):
            target.forbid(literals, bits, tag)


def assert_xor(target: Emitter, literals: Sequence[int], rhs: int, tag: str = "") -> None:
    """Assert that the XOR of the truth values of `literals` equals `rhs`.

    While more than four literals remain, the first three are replaced by a fresh helper
    equal to their XOR (four clauses, helper last), and the helper is put in front of the
    rest; the final at most four literals get ``rhs``.
    """
    remaining = list(literals)
    while len(remaining) > XOR_CHUNK:
        a, b, c = remaining[0], remaining[1], remaining[2]
        helper = target.new_variable(xor_value(target, (a, b, c)))
        forbid_odd_assignments(target, (a, b, c, helper), 0, tag)
        remaining = [helper, *remaining[3:]]
    forbid_odd_assignments(target, tuple(remaining), rhs, tag)


def define_xor(target: Emitter, literals: Sequence[int], tag: str = "") -> int:
    """A variable equal to the XOR of the truth values of `literals`.

    A fresh one, except that a single literal is returned unchanged. The fresh variable is
    allocated before the parity clauses, and it is the last literal of the chain.
    """
    terms = list(literals)
    if len(terms) == 1:
        return terms[0]
    output = target.new_variable(xor_value(target, terms))
    assert_xor(target, [*terms, output], 0, tag)
    return output


def define_and(target: Emitter, a: int, b: int, tag: str = "") -> int:
    """A fresh variable equal to the conjunction of two literals (three Tseitin clauses)."""
    output = target.new_variable(and_value(target, a, b))
    target.add_clause((-output, a), tag)
    target.add_clause((-output, b), tag)
    target.add_clause((output, -a, -b), tag)
    return output
