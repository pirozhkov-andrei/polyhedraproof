"""What every part of the encoding shares: elements, errors, the builder and the oracle.

The encoder's elements are the `n` face planes `1..n` and the plane at infinity `0`.
Clauses are emitted through :class:`EncodingBuilder`, the :class:`neighbourly.cnf.Builder`
whose errors are :class:`EncodingError`; the emission itself is the builder's, unchanged.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import ClassVar, Final, Protocol

from neighbourly.cnf import Builder, CnfError

__all__ = [
    "PLANE_AT_INFINITY",
    "Bracket",
    "EncodingBuilder",
    "EncodingError",
    "Oracle",
    "permutation_parity",
]

#: Index of the plane at infinity among the encoder's elements.
PLANE_AT_INFINITY: Final = 0

#: A bracket: four distinct elements (sorted where it names a variable).
Bracket = tuple[int, ...]


class EncodingError(CnfError):
    """A request the encoder refuses: a map outside its domain, a bad layer, gauge or pool."""


class EncodingBuilder(Builder):
    """The CNF builder of the encoder; it raises :class:`EncodingError`."""

    error: ClassVar[type[CnfError]] = EncodingError


class Oracle(Protocol):
    """The whole truth of one explicit embedding, as the encoder's ground-truth mode needs it.

    The planes fix every bracket: `oracle(S) == 1` iff `chi(S) < 0` for a sorted 4-subset
    `S` of the elements.  `orientation` is the one bit they do not fix (paper: lem:sf):
    `s_f` says whether the boundary traversal the combinatorial map prescribes for face `f`
    runs against that face's normal, so it depends on the map as well as on the planes.
    :class:`neighbourly.exact.PlaneOracle` is one.
    """

    def __call__(self, elements: Sequence[int], /) -> int: ...

    def orientation(self, face: int, /) -> int: ...


def permutation_parity(items: Sequence[int]) -> int:
    """Parity of the permutation that sorts `items`: 0 if even, 1 if odd."""
    return (
        sum(1 for a in range(len(items)) for b in range(a + 1, len(items)) if items[a] > items[b])
        & 1
    )
