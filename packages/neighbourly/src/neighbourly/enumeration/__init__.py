"""Exhaustive enumerations: orientable neighbourly maps, tournaments and vertex octants.

- :mod:`~neighbourly.enumeration.oriented`: orientable neighbourly maps on `n` faces and
  their isomorphism classes (paper: lem:oriented, lem:framing), for any integer `n >= 4`;
- :mod:`~neighbourly.enumeration.tournaments`: the cut-order census (paper: lem:cutorder,
  rem:counts);
- :mod:`~neighbourly.enumeration.vertex_profiles`: the octant table (paper: lem:onereflex,
  rem:octants).

Each result is a finite computation for the parameters it was run on. The twelve-face
census lives in :mod:`neighbourly.corpus12`.
"""

from __future__ import annotations

from neighbourly.enumeration.oriented import (
    SMALL_REFERENCE_COUNTS,
    EnumerationResult,
    SearchStatistics,
    canonical,
    canonical_map,
    classes_of,
    enumerate_classes,
    enumerate_oriented,
)

__all__ = [
    "SMALL_REFERENCE_COUNTS",
    "EnumerationResult",
    "SearchStatistics",
    "canonical",
    "canonical_map",
    "classes_of",
    "enumerate_classes",
    "enumerate_oriented",
]
