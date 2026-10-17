"""The formula of an orientable neighbourly map: `n` planes, a plane at infinity, five
layers and one gauge (paper: def:formula).

    S, H, A   the bracket bits are a uniform rank-4 chirotope   (encoding.chirotope)
    B, I      simple faces, orientations, one reflex corner      (encoding.faces)
    gauge     `n+1` unit clauses fixing the reorientation class  (encoding.gauge)

The article proves the lemma behind each layer: S (paper: thm:order), H and A
(paper: lem:cutorder, thm:chirotope), B (paper: lem:B), I (paper: lem:I) and the gauge
(paper: cor:gauge).  Only NECESSITY is claimed and only necessity is used: every clause
holds of every realization once it is put in general position and moved into gauge
(paper: thm:necessity), so unsatisfiability refutes (paper: cor:conditional), and
satisfiability would prove nothing (paper: rem:noconverse).

THE DOMAIN.  :class:`Encoder` accepts a :class:`~neighbourly.maps.CombinatorialMap` (which
validated its own structure: integer `n >= 4`, neighbourly, single-cycle links) only if
`n mod 12` is in `{0, 3, 4, 7}` and the map is orientable.  The residue condition is
necessary for an orientable neighbourly map (its Euler characteristic `n(7-n)/6` must be an
even integer); it is not claimed to be sufficient for existence, and nothing here assumes
that a map exists for a given `n`.  Results proved for particular `n` (such as the
twelve-face census) live with their data, not here.

THE ORDER.  One :class:`Encoder` class owns the state and the emission order; its layer
methods are written in :mod:`~neighbourly.encoding.chirotope` and
:mod:`~neighbourly.encoding.faces`.  The bracket block is allocated in the constructor,
:meth:`Encoder.build` emits the selected layers in `S, H, A, B, I` order and then the gauge.
"""

from __future__ import annotations

import itertools
from collections.abc import Callable, Mapping
from types import MappingProxyType
from typing import Final

from neighbourly.cnf import OracleWitness
from neighbourly.encoding.common import Bracket, EncodingBuilder, EncodingError, Oracle
from neighbourly.encoding.faces import FaceLayers
from neighbourly.encoding.gauge import gauge_targets
from neighbourly.encoding.layers import DEFAULT_LAYERS, layer_letters, normalize_layers
from neighbourly.maps import CombinatorialMap

__all__ = [
    "ENCODABLE_RESIDUES",
    "POOLS",
    "Encoder",
    "build_encoder",
    "check_encodable",
    "clause_tags",
    "describe_sizes",
]

#: `n mod 12` of every orientable neighbourly map (a necessary condition, not sufficient).
ENCODABLE_RESIDUES: Final = frozenset({0, 3, 4, 7})
#: The variable pools a partition may split on.
POOLS: Final = ("order", "brackets")


def check_encodable(cmap: object) -> CombinatorialMap:
    """The map, if the encoder accepts it; otherwise :class:`EncodingError`.

    The map validated its structure when it was built; this adds the residue condition
    `n mod 12 in {0, 3, 4, 7}` and orientability.
    """
    if not isinstance(cmap, CombinatorialMap):
        raise EncodingError(f"the encoder needs a CombinatorialMap, not {type(cmap).__name__}")
    n = cmap.n
    if type(n) is not int or n < 4:
        raise EncodingError("n must be an integer of at least 4")
    if n % 12 not in ENCODABLE_RESIDUES:
        raise EncodingError(
            f"n = {n}: an orientable neighbourly map needs n mod 12 in {{0, 3, 4, 7}}"
        )
    if not cmap.is_orientable():
        raise EncodingError(f"the map on n = {n} faces is not orientable")
    return cmap


class Encoder(FaceLayers):
    """Builds one map's formula.

    Variable blocks, in this order and no other -- the order is part of the formula's
    identity, because a cube or partition index names a case only relative to a fixed
    numbering:

        1 .. C(n+1,4)      X_S, the bracket bits:  X_S = 1 iff chi(S) < 0
        then               o^{ij}_{kl}, the order bits on the real lines         (Layer S)
        then               d^{b}_{xy},  the cut order bits on the lines at infinity (A)
        then               the auxiliaries of Layers B and I

    An instance builds once.  `oracle` turns on ground-truth mode, in which every
    variable is also given the value one explicit embedding gives it and every clause is
    checked as it is emitted (violations are collected per layer in ``formula.violations``).
    Every variable but one is determined by the brackets; the exception is the per-face
    orientation bit `s_f` (paper: lem:sf), which the oracle supplies from the same embedding.
    """

    def __init__(self, cmap: CombinatorialMap, oracle: Oracle | None = None) -> None:
        self.map = check_encodable(cmap)
        self.n = cmap.n
        self.elements = tuple(range(cmap.n + 1))  # 0 = the plane at infinity
        self.oracle = oracle
        self.formula = EncodingBuilder(
            None if oracle is None else OracleWitness(oracle), complete=oracle is not None
        )
        self.selection = ""

        self.formula.begin_layer("brackets")
        self._brackets = {}
        for subset in itertools.combinations(self.elements, 4):
            self._brackets[subset] = self.formula.new_variable(
                oracle(subset) & 1 if oracle is not None else None
            )

        self._line_orders = {}
        self._cut_orders = {}
        self._boundary_bits = {}
        self._corner_bits = {}
        self._orientation_bits = {}

    # -- public read-only views ---------------------------------------------------------

    @property
    def brackets(self) -> Mapping[Bracket, int]:
        """`X_S` for every 4-subset of the `n+1` elements."""
        return MappingProxyType(self._brackets)

    @property
    def line_orders(self) -> Mapping[tuple[int, int], Mapping[tuple[int, int], int]]:
        """`o^{ij}_{kl}` grouped by the real line `L_ij`."""
        return MappingProxyType(self._line_orders)

    @property
    def cut_orders(self) -> Mapping[tuple[int, int], Mapping[tuple[int, int], int]]:
        """`d^{b}_{xy}` grouped by the line at infinity `L_{0b}` and its cut point."""
        return MappingProxyType(self._cut_orders)

    @property
    def boundary_bits(self) -> Mapping[tuple[int, int, int], int]:
        """`OnB(i,j;u)`: the point `P_iju` lies inside the edge `E(i,j)`."""
        return MappingProxyType(self._boundary_bits)

    @property
    def corner_bits(self) -> Mapping[tuple[int, int, int], int]:
        """The corner literal of each face corner, keyed in link-cycle direction."""
        return MappingProxyType(self._corner_bits)

    @property
    def face_orientation_bits(self) -> Mapping[int, int]:
        """`s_f`: whether the fixed boundary traversal of face `f` runs against `n_f`."""
        return MappingProxyType(self._orientation_bits)

    # -- the gauge, which is a run parameter and not a layer ------------------------------

    def gauge_targets(self, face: int | None = None) -> list[Bracket]:
        """The pinned brackets of :func:`neighbourly.encoding.gauge.gauge_targets`."""
        self._check_gauge_face(face)
        return gauge_targets(self.n, face)

    def add_gauge(self, face: int | None = None) -> None:
        self.formula.begin_layer("gauge")
        for subset in self.gauge_targets(face):
            self.formula.add_clause((-self._brackets[subset],), f"gauge:{subset}")
            self.formula.bump()

    def _check_gauge_face(self, face: int | None) -> None:
        if face is None:
            return
        if type(face) is not int or face not in self.map.faces:
            raise EncodingError(f"gauge face must be between 1 and {self.n}, or None")

    # -- driver ---------------------------------------------------------------------------

    def build(self, layers: str = DEFAULT_LAYERS, gauge_face: int | None = 1) -> Encoder:
        """Emit the selected layers in order, then the gauge.  Returns `self`.

        The order is not cosmetic: it fixes the variable numbering, and a cube or partition
        index names a case only relative to that numbering.
        """
        if self.selection:
            raise EncodingError("an Encoder instance can only be built once")
        self._check_gauge_face(gauge_face)
        builders: dict[str, Callable[[], None]] = {
            "S": self.layer_S,
            "H": self.layer_H,
            "A": self.layer_A,
            "B": self.layer_B,
            "I": self.layer_I,
        }
        letters = layer_letters(layers)
        for letter in letters:
            builders[letter]()
        if gauge_face is not None:
            self.add_gauge(gauge_face)
        self.selection = normalize_layers(layers) + (
            f"+gauge@{gauge_face}" if gauge_face is not None else ""
        )
        return self

    # -- convenience ----------------------------------------------------------------------

    @property
    def clauses(self) -> list[tuple[int, ...]]:
        return self.formula.clauses

    @property
    def variables(self) -> int:
        return self.formula.variables

    def pool(self, name: str) -> set[int]:
        """The variables a partition may split on."""
        if name == "order":
            return {v for row in self._line_orders.values() for v in row.values()}
        if name == "brackets":
            return set(self._brackets.values())
        raise EncodingError(f"unknown pool {name!r}; the pools are 'order' and 'brackets'")


def build_encoder(
    cmap: CombinatorialMap,
    layers: str = DEFAULT_LAYERS,
    gauge_face: int | None = 1,
    oracle: Oracle | None = None,
) -> Encoder:
    """Construct and build one encoder in a single call."""
    return Encoder(cmap, oracle=oracle).build(layers, gauge_face)


def describe_sizes(encoder: Encoder) -> list[tuple[str, int, int, int]]:
    """`(layer, clauses, variables, items)` rows for reports."""
    return [
        (name, counts.clauses, counts.variables, counts.items)
        for name, counts in encoder.formula.counts_table()
    ]


def clause_tags(encoder: Encoder, prefix: str) -> list[str]:
    """Tags of the clauses a layer emitted, for structural self-checks."""
    return [tag for _, tag in encoder.formula.tags if tag.startswith(prefix)]
