"""Witnesses: an exact assignment checked against the clauses while they are emitted.

A witness is consulted only by a :class:`~neighbourly.cnf.builder.Builder` that was given
one. It answers for a variable *name*, a tuple chosen by the producer (for example the
four elements of a bracket), with 1 (true), 0 (false) or ``None`` (unknown). A producer may
also hand a value to ``Builder.new_variable`` directly; that value takes precedence.

Unknown values never become false. A clause is checked only when every one of its
variables has a known value, so a partial witness checks the clauses it can decide and
leaves the rest alone. Semantic controls that must check every clause build with
``complete=True``, which refuses a variable without a value.
"""

from __future__ import annotations

from collections.abc import Callable, Hashable, Sequence
from typing import Protocol

#: The name of a variable as a producer chooses it: a tuple of hashable parts.
VariableName = tuple[Hashable, ...]


class Witness(Protocol):
    """An exact assignment, queried by variable name: 1, 0 or ``None`` (unknown)."""

    def __call__(self, name: VariableName, /) -> int | None: ...


class OracleWitness:
    """A bracket oracle, as a witness.

    A bracket oracle maps a tuple of plane indices (a bracket) to its bit, ``oracle(S) == 1``
    iff ``chi(S) < 0``, and is never unknown. The encoder hands every other variable its
    value explicitly, computed from the same embedding, so a builder that wraps an oracle
    in this adapter is built with ``complete=True``: a variable without a value is an
    error, and violated clauses are collected per layer.
    """

    __slots__ = ("oracle",)

    def __init__(self, oracle: Callable[[Sequence[int]], int]) -> None:
        self.oracle = oracle

    def __call__(self, name: VariableName, /) -> int | None:
        elements = tuple(
            part for part in name if isinstance(part, int) and not isinstance(part, bool)
        )
        if len(elements) != len(name):
            return None  # not a tuple of plane indices: the oracle does not answer for it
        return self.oracle(elements) & 1
