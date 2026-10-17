"""Which layers a formula contains, and which layers imply which.

A layer selection is written as a canonical comma-separated string such as
`S,H,A,B,I`, because that string is part of the formula's description and must not depend
on how the user typed it.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Final

from neighbourly.encoding.common import EncodingError

__all__ = [
    "DEFAULT_LAYERS",
    "LAYERS",
    "LAYER_DESCRIPTIONS",
    "layer_letters",
    "normalize_layers",
]

#: Layers in the order they are emitted.  The order fixes the variable numbering.
LAYERS: Final = "SHABI"
#: Every layer: the selection of the base formulas.
DEFAULT_LAYERS: Final = "S,H,A,B,I"

#: What each layer says, for help text and reports.
LAYER_DESCRIPTIONS: Mapping[str, str] = {
    "S": "order-bit definitions on the real lines",
    "H": "transitivity of the order on the real lines",
    "A": "transitivity of the cut order on the lines at infinity",
    "B": "face boundaries are simple polygons",
    "I": "face orientations and at most one reflex corner per vertex",
}

#: Layers each layer needs in order to mean anything. S defines the order variables every
#: other layer reads; B and I read betweenness and turn bits, which presuppose that the
#: line orders are total (H); I reuses the betweenness bits of B.
_REQUIRES: Mapping[str, str] = {"H": "S", "A": "S", "B": "SH", "I": "SHB"}


def normalize_layers(selection: str) -> str:
    """Canonical `S,H,A,B,I`-style string, with implied layers added.

    Accepts any spelling: `SHABI`, `s,h,a,b,i`, `i, a`.  Selecting a layer selects
    everything it is defined in terms of, because a layer without its definitions
    would silently constrain fresh variables instead of the intended predicate.
    """
    if not isinstance(selection, str):
        raise EncodingError("layers must be given as a string")
    chosen = {c for c in selection.replace(",", "").upper() if not c.isspace()}
    unknown = chosen - set(LAYERS)
    if unknown:
        raise EncodingError(
            f"unknown layer(s) {''.join(sorted(unknown))}; the layers are {', '.join(LAYERS)}"
        )
    if not chosen:
        raise EncodingError(f"select at least one layer from {', '.join(LAYERS)}")
    for letter in sorted(chosen):
        chosen.update(_REQUIRES.get(letter, ""))
    return ",".join(letter for letter in LAYERS if letter in chosen)


def layer_letters(selection: str) -> tuple[str, ...]:
    """The normalized selection as single letters in emission order."""
    return tuple(normalize_layers(selection).replace(",", ""))
