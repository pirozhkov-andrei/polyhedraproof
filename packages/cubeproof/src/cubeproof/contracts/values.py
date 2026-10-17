"""Immutable shared values of specification §4.1: Node, Ref, Artifact, open objects, splitters and
splits.

Every value validates itself on construction, has ``from_json(value, at="$")`` (schema level
first, then its own rules) and ``to_json()`` returning a fresh JSON value whose J bytes are the
canonical form. ``from_json(x).to_json() == x`` for every valid ``x``.
"""

from __future__ import annotations

import functools
import json
from dataclasses import dataclass
from typing import Any

from cubeproof.base.canonical_json import encode
from cubeproof.base.errors import ContractError
from cubeproof.contracts import fields as f
from cubeproof.contracts.identity import (
    Cube,
    check_cube,
    check_split,
    node_id,
    split_children,
    split_id,
)
from cubeproof.contracts.primitives import INT_MAX, is_hash, is_relpath


@dataclass(frozen=True)
class JsonObject:
    """An explicitly open JSON object (``info``, producer parameters), stored as J text.

    Its contents obey the common JSON rules of specification §4.1; ``to_json`` returns a fresh copy,
    so the value cannot be changed through it.
    """

    text: str

    def __post_init__(self) -> None:
        if type(self.text) is not str:
            raise ContractError("schema", "JsonObject text must be a string")
        try:
            value = json.loads(self.text)
        except ValueError:
            raise ContractError("schema", "JsonObject text is not JSON") from None
        if type(value) is not dict or encode(value).decode("utf-8") != self.text:
            raise ContractError("schema", "JsonObject text is not J of an object")

    @classmethod
    def from_json(cls, value: Any, at: str = "$") -> JsonObject:
        f.open_object(value, at)
        return cls(encode(value).decode("utf-8"))

    def to_json(self) -> dict[str, Any]:
        result: dict[str, Any] = json.loads(self.text)
        return result


def node_from_json(value: Any, at: str) -> tuple[str, Cube]:
    """Schema level of a Node: ``{formula_sha256: Hash, cube: [Literal...]}``."""
    f.obj(value, at, ("formula_sha256", "cube"))
    formula = f.matching(value["formula_sha256"], f.member(at, "formula_sha256"), is_hash, "Hash")
    cube = tuple(f.items(value["cube"], f.member(at, "cube"), f.literal))
    return formula, cube


@dataclass(frozen=True)
class Node:
    """``{formula_sha256, cube}`` with a canonical cube; the range needs the formula (cnf)."""

    formula_sha256: str
    cube: Cube

    def __post_init__(self) -> None:
        if not is_hash(self.formula_sha256):
            raise ContractError("schema", f"{self.formula_sha256!r} is not a Hash")
        if type(self.cube) is not tuple:
            raise ContractError("schema", "a Node cube is a tuple of literals")
        check_cube(self.cube)

    @classmethod
    def from_json(cls, value: Any, at: str = "$") -> Node:
        formula, cube = node_from_json(value, at)
        return make_node(formula, cube, at)

    @functools.cached_property
    def node_id(self) -> str:
        return node_id(self.formula_sha256, self.cube)

    @property
    def sort_key(self) -> tuple[str, str]:
        """The order of node lists: ``(formula_sha256, node_id)``."""
        return (self.formula_sha256, self.node_id)

    def to_json(self) -> dict[str, Any]:
        return {"formula_sha256": self.formula_sha256, "cube": list(self.cube)}


@dataclass(frozen=True)
class Ref:
    """A journal record: ``journal`` is the header self hash, ``seq`` its sequence number."""

    journal: str
    seq: int

    def __post_init__(self) -> None:
        if not is_hash(self.journal):
            raise ContractError("schema", f"{self.journal!r} is not a Hash")
        if type(self.seq) is not int or not 0 <= self.seq <= INT_MAX:
            raise ContractError("schema", f"{self.seq!r} is not a nonnegative integer")

    @classmethod
    def from_json(cls, value: Any, at: str = "$") -> Ref:
        f.obj(value, at, ("journal", "seq"))
        journal = f.matching(value["journal"], f.member(at, "journal"), is_hash, "Hash")
        return cls(journal, f.nonnegative(value["seq"], f.member(at, "seq")))

    @property
    def sort_key(self) -> tuple[str, int]:
        return (self.journal, self.seq)

    def to_json(self) -> dict[str, Any]:
        return {"journal": self.journal, "seq": self.seq}


@dataclass(frozen=True)
class Artifact:
    """A file relative to its evidence/results root, with its SHA-256 and size."""

    path: str
    sha256: str
    bytes: int

    def __post_init__(self) -> None:
        if not is_relpath(self.path):
            raise ContractError("schema", f"{self.path!r} is not a RelPath")
        if not is_hash(self.sha256):
            raise ContractError("schema", f"{self.sha256!r} is not a Hash")
        if type(self.bytes) is not int or not 0 <= self.bytes <= INT_MAX:
            raise ContractError("schema", f"{self.bytes!r} is not a nonnegative integer")

    @classmethod
    def from_json(cls, value: Any, at: str = "$") -> Artifact:
        f.obj(value, at, ("path", "sha256", "bytes"))
        path = f.matching(value["path"], f.member(at, "path"), is_relpath, "RelPath")
        sha = f.matching(value["sha256"], f.member(at, "sha256"), is_hash, "Hash")
        return cls(path, sha, f.nonnegative(value["bytes"], f.member(at, "bytes")))

    def to_json(self) -> dict[str, Any]:
        return {"path": self.path, "sha256": self.sha256, "bytes": self.bytes}


@dataclass(frozen=True)
class Splitter:
    """``{name: string, info: open object}`` of a split."""

    name: str
    info: JsonObject

    def __post_init__(self) -> None:
        if type(self.name) is not str or not isinstance(self.info, JsonObject):
            raise ContractError("schema", "a splitter is a name and an info object")

    @classmethod
    def from_json(cls, value: Any, at: str = "$") -> Splitter:
        f.obj(value, at, ("name", "info"))
        name = f.string(value["name"], f.member(at, "name"))
        return cls(name, JsonObject.from_json(value["info"], f.member(at, "info")))

    def to_json(self) -> dict[str, Any]:
        return {"name": self.name, "info": self.info.to_json()}


def make_node(formula_sha256: str, cube: Cube, at: str) -> Node:
    """A Node from schema-checked parts; a noncanonical cube is reported at ``at.cube``."""
    try:
        return Node(formula_sha256, cube)
    except ContractError as error:
        raise ContractError(error.rule, error.detail, location=f.member(at, "cube")) from None


@dataclass(frozen=True)
class SplitEntry:
    """The schema level of ``{node, variables, splitter}`` (campaign root splits, prefixes).

    Nothing beyond the schema is checked yet: documents check every entry's schema before
    any cube or W rule, and W problems need V to keep their order.
    """

    formula_sha256: str
    cube: Cube
    variables: tuple[int, ...]
    splitter: Splitter

    @classmethod
    def from_json(cls, value: Any, at: str) -> SplitEntry:
        f.obj(value, at, ("node", "variables", "splitter"))
        formula, cube = node_from_json(value["node"], f.member(at, "node"))
        variables = tuple(f.items(value["variables"], f.member(at, "variables"), f.positive))
        splitter = Splitter.from_json(value["splitter"], f.member(at, "splitter"))
        return cls(formula, cube, variables, splitter)


@dataclass(frozen=True)
class Split:
    """A split of a node: ordered variables W and the splitter that chose them (specification §3.2).

    The constructor checks every rule that does not need V (empty, too_long, repeated,
    in_cube). ``split.out_of_range`` needs the formula; a reader that knows V calls
    :func:`~cubeproof.contracts.identity.split_problem` first, so that the problems keep
    their specified order.
    """

    node: Node
    variables: tuple[int, ...]
    splitter: Splitter

    def __post_init__(self) -> None:
        if type(self.variables) is not tuple:
            raise ContractError("schema", "split variables are a tuple")
        check_split(self.variables, self.node.cube, INT_MAX)

    @functools.cached_property
    def split_id(self) -> str:
        return split_id(self.node.node_id, self.variables)

    def children(self) -> tuple[Node, ...]:
        """The ``2^len(W)`` children in child-index order."""
        formula = self.node.formula_sha256
        return tuple(Node(formula, c) for c in split_children(self.node.cube, self.variables))

    def to_json(self) -> dict[str, Any]:
        return {
            "node": self.node.to_json(),
            "variables": list(self.variables),
            "splitter": self.splitter.to_json(),
        }
