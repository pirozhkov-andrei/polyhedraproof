"""Mathematical controls of the encoding, for any encodable map (specification §13.2).

- :mod:`~neighbourly.checks.identities`: the identities the encoder rests on (order bits,
  cut order, gauge, corner symmetry, adjacency, Layer I structure, octants) -- the
  self-test identity checks, with the map as a parameter;
- :mod:`~neighbourly.checks.per_face`: per-face controls of the face predicates and of
  Layer B against exact plane and polygon geometry, on random or realized plane families;
- :mod:`~neighbourly.checks.rational`: the exact operations those controls use, which share
  no code with the encoder or :mod:`neighbourly.exact`.

Every control is a finite computation on the maps, seeds and planes it is given; none of
them is a theorem about other configurations or other `n`. This package reads no package
data and does not import the twelve-face corpus.
"""

from __future__ import annotations

from neighbourly.checks.identities import (
    SAMPLES,
    SEED,
    Check,
    adjacency_check,
    corner_symmetry_check,
    cut_order_check,
    gauge_check,
    identity_checks,
    layer_i_check,
    octant_check,
    order_bits_check,
    selftest_planes,
)
from neighbourly.checks.per_face import (
    ChecksError,
    FaceReport,
    PerFaceResult,
    per_face_check,
    random_planes,
)

__all__ = [
    "SAMPLES",
    "SEED",
    "Check",
    "ChecksError",
    "FaceReport",
    "PerFaceResult",
    "adjacency_check",
    "corner_symmetry_check",
    "cut_order_check",
    "gauge_check",
    "identity_checks",
    "layer_i_check",
    "octant_check",
    "order_bits_check",
    "per_face_check",
    "random_planes",
    "selftest_planes",
]
