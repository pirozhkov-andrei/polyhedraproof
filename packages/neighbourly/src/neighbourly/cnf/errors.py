"""Errors raised by neighbourly.cnf.

Every error the module raises deliberately is a :class:`CnfError`, which is a
:class:`ValueError`: the caller handed over a literal, value, name or file layout that the
contract does not allow. A producer that has its own error vocabulary may subclass
:class:`CnfError` and set :attr:`neighbourly.cnf.builder.Builder.error` to that subclass.
"""

from __future__ import annotations

from collections.abc import Sequence


class CnfError(ValueError):
    """Input that the CNF emission contract does not allow."""


class WitnessViolation(CnfError):
    """A clause whose literals are all known under the witness and all false (strict mode)."""

    def __init__(self, layer: str, tag: str, clause: Sequence[int]) -> None:
        super().__init__(f"layer {layer}: clause {tuple(clause)} violated ({tag or 'untagged'})")
        self.layer = layer
        self.tag = tag
        self.clause = tuple(clause)
