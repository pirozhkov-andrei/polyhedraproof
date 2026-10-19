"""cubeproof: generic cube-tree refutation campaigns with checked LRAT attestations.

The package consumes formula bundles from disk, schedules bounded leaf work, records
evidence in hash-chained journals, certifies coverage and audits it. Its runtime depends on
the Python standard library and on external pinned tools only; it never imports
`neighbourly` or `faces12_campaign` (specification §2.1 and §2.3).
"""

from __future__ import annotations

__version__ = "1.0.0"

__all__ = ["__version__"]
