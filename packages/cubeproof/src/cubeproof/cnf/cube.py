"""Cubes bound to a formula: nodes in range, unit lines and sign children (specification §3.2).

The identities themselves (canonical cubes, node_id, split_id, children) are contract rules
in :mod:`cubeproof.contracts.identity`; this module adds the checks that need the formula:
``cube.range`` against V and the W problems with V.
"""

from __future__ import annotations

from collections.abc import Sequence

from cubeproof.base.errors import ContractError
from cubeproof.cnf.dimacs import Formula
from cubeproof.contracts.identity import check_cube, check_split, split_children
from cubeproof.contracts.values import Node


def node_of(formula: Formula, cube: Sequence[int]) -> Node:
    """The node of ``cube`` in ``formula``; the cube must be canonical and in range."""
    return Node(formula.sha256, check_cube(cube, formula.variables))


def cube_units(cube: Sequence[int]) -> bytes:
    """One unit clause line ``l 0`` per literal, in the given (canonical) order."""
    return "".join(f"{literal} 0\n" for literal in cube).encode("ascii")


def child_nodes(formula: Formula, node: Node, variables: Sequence[int]) -> tuple[Node, ...]:
    """The ``2^len(W)`` children of ``node`` split on W, in child-index order."""
    if node.formula_sha256 != formula.sha256:
        raise ContractError("record.formula", "the node belongs to another formula")
    check_cube(node.cube, formula.variables)
    check_split(variables, node.cube, formula.variables)
    return tuple(Node(formula.sha256, c) for c in split_children(node.cube, variables))
