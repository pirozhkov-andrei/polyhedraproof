"""The encoder: from an orientable neighbourly map to its formula of necessary conditions.

See (paper: def:formula) for the formula and (paper: thm:necessity) for why every clause
holds. Submodules: :mod:`~neighbourly.encoding.chirotope` (S, H, A),
:mod:`~neighbourly.encoding.faces` (B, I), :mod:`~neighbourly.encoding.gauge`,
:mod:`~neighbourly.encoding.layers` (layer selection) and
:mod:`~neighbourly.encoding.formula` (the :class:`Encoder`, its domain and emission order).
"""

from __future__ import annotations

from neighbourly.encoding.common import PLANE_AT_INFINITY, EncodingError, Oracle
from neighbourly.encoding.formula import (
    ENCODABLE_RESIDUES,
    POOLS,
    Encoder,
    build_encoder,
    check_encodable,
)
from neighbourly.encoding.gauge import gauge_targets
from neighbourly.encoding.layers import DEFAULT_LAYERS, LAYERS, layer_letters, normalize_layers

__all__ = [
    "DEFAULT_LAYERS",
    "ENCODABLE_RESIDUES",
    "LAYERS",
    "PLANE_AT_INFINITY",
    "POOLS",
    "Encoder",
    "EncodingError",
    "Oracle",
    "build_encoder",
    "check_encodable",
    "gauge_targets",
    "layer_letters",
    "normalize_layers",
]
