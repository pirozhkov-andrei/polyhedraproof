"""neighbourly: neighbourly maps, exact geometry and their CNF encodings.

The package holds the mathematics that turns a combinatorial map into a formula: maps,
enumeration, exact geometry, the S/H/A/B/I encoding, the gauge, interpretation and the
n = 12 corpus. Generic CNF emission lives in the subpackage `neighbourly.cnf`, which imports
only the standard library and its own submodules (specification §2.1 and §13).
"""

from __future__ import annotations

__version__ = "1.0.0rc1"

__all__ = ["__version__"]
