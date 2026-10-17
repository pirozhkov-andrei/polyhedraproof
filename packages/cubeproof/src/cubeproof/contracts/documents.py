"""Shard, handoff request, roots, prefixes and weights documents (specification §4.5, §12.1).

Each reader takes the parsed JSON value of a canonical document and returns an immutable
value; ``to_json`` gives back the same JSON value. Node lists of shards and roots are sorted
strictly by ``(formula_sha256, node_id)`` and pairwise incompatible within a formula, so a
shard covers disjoint regions (shard.nodes, roots.nodes). Where the caller knows the
formulas, it passes V per formula hash and cube ranges are checked too; a node of an unknown
formula is then ``record.formula``.
"""

from __future__ import annotations

import functools
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from itertools import pairwise
from types import MappingProxyType
from typing import Any

from cubeproof.base.canonical_json import json_sha256
from cubeproof.base.errors import ContractError
from cubeproof.contracts import fields as f
from cubeproof.contracts.identity import (
    check_cube,
    pairwise_incompatible,
    split_id,
    split_problem,
)
from cubeproof.contracts.primitives import INT_MAX, is_hash, is_id128, is_name
from cubeproof.contracts.values import Node, Split, SplitEntry, make_node, node_from_json


def _read_nodes(
    value: Any, at: str, variables: Mapping[str, int] | None
) -> list[tuple[str, tuple[int, ...]]]:
    """Schema level of a nonempty node list, then canonical cubes and ranges, node by node."""
    raw = f.items(value, at, node_from_json, min_items=1)
    for index, (formula, cube) in enumerate(raw):
        location = f.member(f.item(at, index), "cube")
        count: int | None = None
        if variables is not None:
            if formula not in variables:
                raise ContractError(
                    "record.formula", f"unknown formula {formula}", location=location
                )
            count = variables[formula]
        try:
            check_cube(cube, count)
        except ContractError as error:
            raise ContractError(error.rule, error.detail, location=location) from None
    return raw


def disjoint_sorted_nodes(nodes: Sequence[Node]) -> bool:
    """Strictly sorted by ``(formula_sha256, node_id)`` and pairwise incompatible per formula."""
    keys = [n.sort_key for n in nodes]
    if any(a >= b for a, b in pairwise(keys)):
        return False
    by_formula: dict[str, list[tuple[int, ...]]] = {}
    for node in nodes:
        by_formula.setdefault(node.formula_sha256, []).append(node.cube)
    return all(pairwise_incompatible(group) for group in by_formula.values())


def _node_list(
    value: Any, at: str, variables: Mapping[str, int] | None, rule: str
) -> tuple[Node, ...]:
    nodes = tuple(Node(formula, cube) for formula, cube in _read_nodes(value, at, variables))
    if not disjoint_sorted_nodes(nodes):
        raise ContractError(rule, "nodes not strictly sorted or not pairwise incompatible")
    return nodes


@dataclass(frozen=True)
class Shard:
    """``cubeproof-shard-1``: named disjoint nodes of one campaign; ID = SHA256(J(shard))."""

    campaign: str
    name: str
    nodes: tuple[Node, ...]

    def __post_init__(self) -> None:
        if not is_hash(self.campaign) or not is_name(self.name):
            raise ContractError("schema", "shard campaign must be a Hash and name a Name")
        if not self.nodes or not disjoint_sorted_nodes(self.nodes):
            raise ContractError("shard.nodes", "nodes empty, unsorted or overlapping")

    @classmethod
    def from_json(
        cls, value: Any, at: str = "$", *, variables: Mapping[str, int] | None = None
    ) -> Shard:
        f.obj(value, at, ("format", "campaign", "name", "nodes"))
        m = functools.partial(f.member, at)
        f.const(value["format"], m("format"), "cubeproof-shard-1")
        campaign = f.matching(value["campaign"], m("campaign"), is_hash, "Hash")
        name = f.matching(value["name"], m("name"), is_name, "Name")
        nodes = _node_list(value["nodes"], m("nodes"), variables, "shard.nodes")
        return cls(campaign, name, nodes)

    def to_json(self) -> dict[str, Any]:
        return {
            "format": "cubeproof-shard-1",
            "campaign": self.campaign,
            "name": self.name,
            "nodes": [n.to_json() for n in self.nodes],
        }

    @functools.cached_property
    def shard_id(self) -> str:
        return json_sha256(self.to_json())


@dataclass(frozen=True)
class HandoffRequest:
    """``cubeproof-handoff-request-1``; ``output_name`` names a file in the configured outbox."""

    campaign: str
    request_id: str
    node_count: int
    output_name: str

    def __post_init__(self) -> None:
        if not (
            is_hash(self.campaign)
            and is_id128(self.request_id)
            and type(self.node_count) is int
            and 1 <= self.node_count <= INT_MAX
            and is_name(self.output_name)
        ):
            raise ContractError("schema", "invalid handoff request fields")

    @classmethod
    def from_json(cls, value: Any, at: str = "$") -> HandoffRequest:
        names = ("format", "campaign", "request_id", "node_count", "output_name")
        f.obj(value, at, names)
        m = functools.partial(f.member, at)
        f.const(value["format"], m("format"), "cubeproof-handoff-request-1")
        return cls(
            campaign=f.matching(value["campaign"], m("campaign"), is_hash, "Hash"),
            request_id=f.matching(value["request_id"], m("request_id"), is_id128, "Id128"),
            node_count=f.positive(value["node_count"], m("node_count")),
            output_name=f.matching(value["output_name"], m("output_name"), is_name, "Name"),
        )

    def to_json(self) -> dict[str, Any]:
        return {
            "format": "cubeproof-handoff-request-1",
            "campaign": self.campaign,
            "request_id": self.request_id,
            "node_count": self.node_count,
            "output_name": self.output_name,
        }


@dataclass(frozen=True)
class Roots:
    """``cubeproof-roots-1``: requested roots with the constraints of specification §4.4."""

    roots: tuple[Node, ...]

    @classmethod
    def from_json(
        cls, value: Any, at: str = "$", *, variables: Mapping[str, int] | None = None
    ) -> Roots:
        f.obj(value, at, ("format", "roots"))
        f.const(value["format"], f.member(at, "format"), "cubeproof-roots-1")
        return cls(_node_list(value["roots"], f.member(at, "roots"), variables, "roots.nodes"))

    def to_json(self) -> dict[str, Any]:
        return {"format": "cubeproof-roots-1", "roots": [n.to_json() for n in self.roots]}


@dataclass(frozen=True)
class Prefixes:
    """``cubeproof-prefixes-1``: static prefix splits, sorted by split_id, well-formed W."""

    splits: tuple[Split, ...]

    @classmethod
    def from_json(
        cls, value: Any, at: str = "$", *, variables: Mapping[str, int] | None = None
    ) -> Prefixes:
        """``variables`` gives V per formula hash; without it W ranges are not checked."""
        f.obj(value, at, ("format", "splits"))
        f.const(value["format"], f.member(at, "format"), "cubeproof-prefixes-1")
        where = f.member(at, "splits")
        entries = f.items(value["splits"], where, SplitEntry.from_json)
        nodes = [
            make_node(e.formula_sha256, e.cube, f.member(f.item(where, i), "node"))
            for i, e in enumerate(entries)
        ]
        ids = [split_id(node.node_id, e.variables) for node, e in zip(nodes, entries, strict=True)]
        if any(a >= b for a, b in pairwise(ids)):
            raise ContractError("prefixes.order", "splits not strictly sorted by split_id")
        counts = variables or {}
        for index, (node, entry) in enumerate(zip(nodes, entries, strict=True)):
            count = counts.get(node.formula_sha256, INT_MAX)
            problem = split_problem(entry.variables, node.cube, count)
            if problem is not None:
                location = f.member(f.item(where, index), "variables")
                raise ContractError(problem, f"split {list(entry.variables)!r}", location=location)
        splits = (Split(n, e.variables, e.splitter) for n, e in zip(nodes, entries, strict=True))
        return cls(tuple(splits))

    def to_json(self) -> dict[str, Any]:
        return {"format": "cubeproof-prefixes-1", "splits": [s.to_json() for s in self.splits]}


@dataclass(frozen=True)
class Weights:
    """``cubeproof-weights-1``: estimated costs of planned node IDs; unspecified nodes cost 1."""

    campaign: str
    costs: Mapping[str, int]

    def __post_init__(self) -> None:
        object.__setattr__(self, "costs", MappingProxyType(dict(sorted(self.costs.items()))))

    @classmethod
    def from_json(
        cls, value: Any, at: str = "$", *, planned: Iterable[str] | None = None
    ) -> Weights:
        """``planned`` is the set of node IDs the planner knows; others are weights.unknown."""
        f.obj(value, at, ("format", "campaign", "costs"))
        m = functools.partial(f.member, at)
        f.const(value["format"], m("format"), "cubeproof-weights-1")
        campaign = f.matching(value["campaign"], m("campaign"), is_hash, "Hash")
        costs = f.obj(value["costs"], m("costs"), (), closed=False)
        f.property_names(costs, m("costs"), is_hash)
        checked = {k: f.positive(v, f.member(m("costs"), k)) for k, v in costs.items()}
        if planned is not None:
            known = set(planned)
            unknown = sorted(set(checked) - known)
            if unknown:
                raise ContractError("weights.unknown", f"unknown node IDs {unknown[:3]!r}")
        return cls(campaign, checked)

    def cost(self, node_id: str) -> int:
        return self.costs.get(node_id, 1)

    def to_json(self) -> dict[str, Any]:
        return {
            "format": "cubeproof-weights-1",
            "campaign": self.campaign,
            "costs": dict(self.costs),
        }
