"""The proof tools of this release, by the SHA-256 of their binaries.

A campaign names its solver and its checker by hash, and a certificate admits the records of
exactly the checkers the campaign lists (specification §10.1). Nothing in a campaign says that a
listed hash *is* cake_lpr: a campaign created with another program as its checker certifies as
well as any other. The binaries that the release image builds from the pinned sources
(``docker/test/tools.json``) are therefore recorded here, and ``campaign init`` and the claim gate
compare a campaign with them (specification §13.3).

The values are those of the ``linux/amd64`` release image of this version; the image tests fail
when a build produces other bytes. They identify a build, they do not re-prove it: the checker's
guarantee is the theorem of its authors about these sources (docs/SOURCES.md).
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Final

__all__ = [
    "RELEASE_CHECKER_SHA256",
    "RELEASE_SOLVER_SHA256",
    "RELEASE_SOLVER_VERSION",
    "unpinned",
]

#: cake_lpr as the ``linux/amd64`` release image builds it from the pinned ``cake_lpr.S`` and
#: ``basis_ffi.c``.
RELEASE_CHECKER_SHA256: Final = "6526bd1462cfdaaa36662ebc87faa9dad7db330b6b3f9b8c175a7852a0e6eedd"
#: CaDiCaL as the release image builds it from the pinned commit.
RELEASE_SOLVER_SHA256: Final = "c3a77cbc3a354106b0cf0d710aae00d433a8250ba06805d5794b7b07991be7f4"
#: The version that binary reports.
RELEASE_SOLVER_VERSION: Final = "3.0.1"


def unpinned(
    checkers: Iterable[str], pinned: Iterable[str] = (RELEASE_CHECKER_SHA256,)
) -> list[str]:
    """The checker hashes of ``checkers`` that are not among ``pinned``, sorted."""
    known = set(pinned)
    return sorted({sha for sha in checkers if sha not in known})
