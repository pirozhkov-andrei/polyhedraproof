"""The gauge: `n+1` pinned brackets, one per generator of the reorientation group.

The gauge is a run parameter, not a layer, because it says nothing about geometry
(paper: lem:gaugegroup, cor:gauge).  :func:`gauge_targets` is the pure choice of the
pinned brackets; :class:`neighbourly.encoding.formula.Encoder` emits one unit clause per
target in this order, in a layer named ``gauge`` after every selected layer.
"""

from __future__ import annotations

import itertools

from neighbourly.encoding.common import Bracket, EncodingError

__all__ = ["gauge_targets"]


def gauge_targets(n: int, face: int | None = None) -> list[Bracket]:
    """Brackets to pin at `chi(S) > 0`, one per generator of the reorientation group.

    Reorienting plane `p` flips `X_S` exactly when `p` is in `S`, and an
    orientation-reversing affine map flips every `X_S`; both map realizations to
    realizations of the same map (paper: lem:gaugegroup).  Pinning brackets whose GF(2)
    functionals are independent keeps exactly one representative of each orbit, so
    every realization can be moved into gauge (paper: cor:gauge): if the pinned formula
    is unsatisfiable, no realization exists.

    The elements are `0..n`, the sorted 4-subsets are tried in lexicographic order.
    `face` aims the basis: brackets through that face are tried first, so `n` of the
    `n+1` pinned brackets contain it and one avoids it.  The brackets through a single
    element span only an `n`-dimensional space of functionals, so the completing
    bracket is necessary (paper: cor:gauge and the remark after it).  The `n+1`
    functionals chosen are independent, and the group acts simply transitively on
    their sign patterns.  The caller checks that `face` is a face (`1..n`) or ``None``.
    """
    elements = tuple(range(n + 1))
    candidates: list[Bracket] = list(itertools.combinations(elements, 4))
    if face is not None:
        through = [S for S in candidates if face in S]
        candidates = through + [S for S in candidates if face not in S]
    basis: list[int] = []
    chosen: list[Bracket] = []
    for subset in candidates:
        vector = 1  # bit 0: global negation
        for element in subset:
            if element >= 1:
                vector |= 1 << element
        reduced = vector
        for row in basis:
            reduced = min(reduced, reduced ^ row)
        if reduced:
            basis.append(reduced)
            basis.sort(reverse=True)
            chosen.append(subset)
            if len(chosen) == n + 1:
                return chosen
    raise EncodingError(f"gauge reached rank {len(chosen)}, expected {n + 1}")
