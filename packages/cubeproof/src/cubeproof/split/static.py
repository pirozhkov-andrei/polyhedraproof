"""Static splits: an explicitly supplied ordered W (specification §9.2).

A static split uses a caller-supplied order of variables ``order`` and a prefix length ``p``;
the split is ``W = order[:p]``, validated against the parent cube like any split (distinct,
in range, not in the cube, at most K_MAX). A prefix of zero means *no root split*: the node
stays whole, and no zero-variable split is ever recorded (:func:`static_split` returns None).

Child ``t`` of the split assigns ``+W[j]`` when bit ``j`` of ``t`` is 1 and ``-W[j]``
otherwise (:func:`child_cube`); this is the case numbering of a prefix split and the
definition of ``contracts.identity.split_children``. :func:`child_index` is its inverse.

:func:`frozen_split` looks up a node in a validated ``cubeproof-prefixes-1`` document, the
frozen result of a ``proof-prefix-v1`` or static construction that a campaign may reuse.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from cubeproof.base.errors import ConfigurationError, ContractError
from cubeproof.contracts.documents import Prefixes
from cubeproof.contracts.identity import Cube, check_cube, check_split
from cubeproof.contracts.values import JsonObject, Node, Split, Splitter
from cubeproof.split.choice import CHOSEN, SplitChoice

STATIC_NAME = "static"


def _order(order: Sequence[int]) -> tuple[int, ...]:
    values = tuple(order)
    if any(type(v) is not int or v < 1 for v in values):
        raise ConfigurationError("split.static", "the order lists positive integers")
    if len(set(values)) != len(values):
        raise ConfigurationError("split.static", "the order lists a variable twice")
    return values


def static_split(
    variables: int, cube: Sequence[int], order: Sequence[int], prefix: int | None = None
) -> tuple[int, ...] | None:
    """``W = order[:prefix]`` validated at ``cube`` in a formula with V = ``variables``.

    ``prefix=None`` takes the whole order. Returns None for a prefix of zero (no split).
    A prefix longer than the order or than K_MAX is an error, never silently shortened.
    """
    parent = check_cube(cube, variables)
    listed = _order(order)
    length = len(listed) if prefix is None else prefix
    if type(length) is not int or not 0 <= length <= len(listed):
        raise ConfigurationError(
            "split.static", f"prefix {length!r} is not in 0..{len(listed)} (the order's length)"
        )
    if length == 0:
        return None
    return check_split(listed[:length], parent, variables)


def static_choice(
    variables: int, cube: Sequence[int], order: Sequence[int], prefix: int | None = None
) -> SplitChoice | None:
    """:func:`static_split` as a :class:`SplitChoice` (status chosen), or None for no split."""
    chosen = static_split(variables, cube, order, prefix)
    if chosen is None:
        return None
    return SplitChoice.make(
        chosen,
        CHOSEN,
        {"algorithm": STATIC_NAME, "order": len(_order(order)), "prefix": len(chosen)},
    )


def static_splitter(order: Sequence[int], prefix: int | None = None, **provenance: Any) -> Splitter:
    """The ``splitter`` value recorded with a static split (name ``static``, open info)."""
    listed = _order(order)
    length = len(listed) if prefix is None else prefix
    info = {"order": list(listed), "prefix": length, **provenance}
    return Splitter(STATIC_NAME, JsonObject.from_json(info))


def child_cube(parent: Sequence[int], variables: Sequence[int], index: int) -> Cube:
    """Child ``index`` of the split ``variables`` at ``parent`` (canonical cube)."""
    base = check_cube(parent)
    check_split(variables, base, 2**63 - 1)
    if type(index) is not int or not 0 <= index < 1 << len(variables):
        raise ConfigurationError("split.static", f"child index {index!r} out of range")
    signed = [v if (index >> j) & 1 else -v for j, v in enumerate(variables)]
    return tuple(sorted((*base, *signed), key=abs))


def child_index(parent: Sequence[int], variables: Sequence[int], child: Sequence[int]) -> int:
    """The index ``t`` with ``child_cube(parent, variables, t) == child``."""
    base = check_cube(parent)
    check_split(variables, base, 2**63 - 1)
    cube = check_cube(child)
    positions = {v: j for j, v in enumerate(variables)}
    index = 0
    seen = 0
    for literal in cube:
        j = positions.get(abs(literal))
        if j is None:
            continue
        seen += 1
        if literal > 0:
            index |= 1 << j
    if seen != len(variables) or set(base) - set(cube) or len(cube) != len(base) + seen:
        raise ContractError("split.static", "the cube is not a child of the split")
    return index


def frozen_split(prefixes: Prefixes, node: Node) -> Split | None:
    """The split of ``node`` in a validated prefixes document, or None if it has none."""
    for split in prefixes.splits:
        if split.node == node:
            return split
    return None
