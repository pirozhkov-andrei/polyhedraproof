"""Cubes, node and split identities and sign children (specification §3.2; decision 0010).

- A cube is a sequence of nonzero literals sorted strictly by absolute value: each variable
  at most once, so no repeated or contradictory literal (``cube.canonical``), and every
  literal in range of its formula, ``abs(l) <= V`` (``cube.range``). The empty cube is ``()``.
- ``node_id = SHA256("node" NUL formula_sha256 NUL literals)`` with the canonical literals
  joined by one space (empty for the empty cube).
- A split W of a cube is an ordered list of distinct positive variables not in the cube,
  ``1 <= len(W) <= K_MAX``, all ``<= V``. Problems are reported in the order empty,
  too_long, repeated, out_of_range, in_cube.
- ``split_id = SHA256(J({"node_id": node_id, "variables": W}))``; the order of W matters.
- Child ``t`` of a split assigns ``+W[j]`` when bit ``j`` of ``t`` is 1 and ``-W[j]``
  otherwise, then is canonicalized; there are always exactly ``2^len(W)`` children.

Functions here take any integer sequence and return tuples; they are pure.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable, Sequence

from cubeproof.base.canonical_json import json_sha256
from cubeproof.base.errors import ContractError
from cubeproof.contracts.primitives import INT_MAX, K_MAX, is_hash

Cube = tuple[int, ...]


def _is_literal(value: object) -> bool:
    return type(value) is int and value != 0 and -INT_MAX <= value <= INT_MAX


def cube_problem(cube: Sequence[int], variables: int | None = None) -> str | None:
    """The rule a cube of literals violates (``cube.canonical``, ``cube.range``) or None.

    ``variables`` is V of the cube's formula; None skips the range rule. Elements that are
    not literals at all are a schema matter and reported as ``schema``.
    """
    if any(not _is_literal(x) for x in cube):
        return "schema"
    previous = 0
    for literal in cube:
        if abs(literal) <= previous:
            return "cube.canonical"
        previous = abs(literal)
    if variables is not None and previous > variables:
        return "cube.range"
    return None


def check_cube(cube: Sequence[int], variables: int | None = None) -> Cube:
    """``cube`` as a tuple; :class:`ContractError` named by :func:`cube_problem` otherwise."""
    if isinstance(cube, (str, bytes)):
        raise ContractError("schema", "a cube is a sequence of literals")
    problem = cube_problem(cube, variables)
    if problem is not None:
        raise ContractError(problem, f"cube {list(cube)!r}")
    return tuple(cube)


def canonical_cube(literals: Iterable[int]) -> Cube:
    """Construction helper: sort otherwise valid literals by variable (specification §3.2).

    Readers must use :func:`check_cube` instead: they reject noncanonical input.
    """
    values = list(literals)
    if any(not _is_literal(x) for x in values):
        raise ContractError("schema", f"{values!r} contains a value that is not a literal")
    return check_cube(sorted(values, key=abs))


def node_id(formula_sha256: str, cube: Sequence[int]) -> str:
    """The node identity of specification §3.2 (the cube must be canonical)."""
    if not is_hash(formula_sha256):
        raise ContractError("schema", f"{formula_sha256!r} is not a Hash")
    literals = " ".join(str(x) for x in check_cube(cube))
    data = b"node\0" + formula_sha256.encode("ascii") + b"\0" + literals.encode("ascii")
    return hashlib.sha256(data).hexdigest()


def split_problem(variables: Sequence[int], cube: Sequence[int], count: int) -> str | None:
    """The first problem of split variables W at ``cube`` in a formula with V = ``count``.

    Values that are not positive integers are a schema matter (``schema``).
    """
    if any(type(v) is not int or not 1 <= v <= INT_MAX for v in variables):
        return "schema"
    used = {abs(x) for x in cube}
    rules = (
        ("split.empty", not variables),
        ("split.too_long", len(variables) > K_MAX),
        ("split.repeated", len(set(variables)) != len(variables)),
        ("split.out_of_range", any(v > count for v in variables)),
        ("split.in_cube", any(v in used for v in variables)),
    )
    return next((rule for rule, violated in rules if violated), None)


def check_split(variables: Sequence[int], cube: Sequence[int], count: int) -> tuple[int, ...]:
    """W as a tuple; :class:`ContractError` named by :func:`split_problem` otherwise."""
    problem = split_problem(variables, cube, count)
    if problem is not None:
        raise ContractError(problem, f"split {list(variables)!r} at {list(cube)!r}")
    return tuple(variables)


def split_id(node: str, variables: Sequence[int]) -> str:
    """``SHA256(J({"node_id": node, "variables": W}))``."""
    if not is_hash(node):
        raise ContractError("schema", f"{node!r} is not a node id")
    return json_sha256({"node_id": node, "variables": list(variables)})


def split_children(cube: Sequence[int], variables: Sequence[int]) -> tuple[Cube, ...]:
    """All ``2^len(W)`` sign children of a well-formed split, in child-index order."""
    parent = check_cube(cube)
    check_split(variables, parent, INT_MAX)
    children = []
    for index in range(1 << len(variables)):
        signed = [v if (index >> j) & 1 else -v for j, v in enumerate(variables)]
        children.append(tuple(sorted((*parent, *signed), key=abs)))
    return tuple(children)


def incompatible(a: Sequence[int], b: Sequence[int]) -> bool:
    """Some variable occurs with opposite signs in the two cubes (they are disjoint)."""
    other = set(b)
    return any(-x in other for x in a)


def compatible(a: Sequence[int], b: Sequence[int]) -> bool:
    return not incompatible(a, b)


def _pairwise(sets: Sequence[frozenset[int]]) -> bool:
    for i, first in enumerate(sets):
        for second in sets[i + 1 :]:
            if not any(-x in second for x in first):
                return False
    return True


def pairwise_incompatible(cubes: Sequence[Sequence[int]]) -> bool:
    """True iff every two of ``cubes`` conflict on some variable (they are pairwise disjoint).

    Partition refinement: in a group whose members never conflict on the removed variables,
    pick the most frequent remaining variable v; the members with +v and those with -v are
    disjoint from each other, and the members without v go with both sides. A compatible
    pair always stays together in some group until one member has no remaining literal,
    which is then detected; every group member without remaining literals is compatible with
    every other member. This is near-linear for split-tree shards; if the work exceeds that
    of the plain pairwise check, the plain check decides.
    """
    sets = [frozenset(c) for c in cubes]
    limit = max(len(sets), 1) ** 2
    work = 0
    stack: list[tuple[list[int], frozenset[int]]] = [(list(range(len(sets))), frozenset())]
    while stack:
        members, removed = stack.pop()
        if len(members) < 2:
            continue
        work += len(members)
        if work > limit:
            return _pairwise(sets)
        counts: dict[int, int] = {}
        for index in members:
            remaining = [abs(x) for x in sets[index] if abs(x) not in removed]
            if not remaining:
                return False
            for variable in remaining:
                counts[variable] = counts.get(variable, 0) + 1
        chosen = min(counts, key=lambda v: (-counts[v], v))
        positive = [i for i in members if -chosen not in sets[i]]
        negative = [i for i in members if chosen not in sets[i]]
        narrowed = removed | {chosen}
        stack.append((positive, narrowed))
        stack.append((negative, narrowed))
    return True
