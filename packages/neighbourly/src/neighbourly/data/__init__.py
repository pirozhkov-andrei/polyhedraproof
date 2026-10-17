"""Package data of neighbourly, read through :mod:`importlib.resources` (specification §2.2).

Layout::

    n12/matrices/topology_01.txt .. topology_59.txt   the 59 maps with twelve faces
    n12/matrices/SHA256SUMS                           their SHA-256 sums
    n12/formula_hashes_n12.json                       the 59 base formula hashes
    fixtures/tetrahedron/                             n = 4: map and realizing planes
    fixtures/szilassi/                                n = 7: Csaszar map, Szilassi planes
    fixtures/n15/, fixtures/n16/                      one generated map each (structural)
    provenance.json                                   origin and SHA-256 of every file

Every file except ``provenance.json`` and the tetrahedron, n = 15 and n = 16 fixtures is a
byte-for-byte copy of the repository file named in ``provenance.json``; the n = 15 and n = 16 maps
were generated once by ``tools/neighbourly_fixtures/generate_maps.py``. The data are finite
inputs and references; they prove nothing about other values of ``n``. Only
:mod:`neighbourly.corpus12` reads the n = 12 files; the generic modules read no package data.
"""

from __future__ import annotations

import sys
from importlib.resources import files

if sys.version_info >= (3, 11):
    from importlib.resources.abc import Traversable
else:  # pragma: no cover - CPython 3.10
    from importlib.abc import Traversable

__all__ = ["Traversable", "read_bytes", "resource"]


def resource(*parts: str) -> Traversable:
    """The packaged file or directory at ``parts`` below this package (it may not exist)."""
    node = files(__name__)
    for part in parts:
        node = node.joinpath(part)
    return node


def read_bytes(*parts: str) -> bytes:
    """The bytes of one packaged file; ``FileNotFoundError`` if it is not there."""
    node = resource(*parts)
    if not node.is_file():
        raise FileNotFoundError(f"neighbourly package data has no file {'/'.join(parts)}")
    return node.read_bytes()
