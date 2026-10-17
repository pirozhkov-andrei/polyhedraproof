"""The campaign document ``cubeproof-campaign-1`` (specification §4.4) and its cross-field rules.

Reading a campaign has two steps, because most rules need the formulas (V, pools) of its
bundles:

1. :meth:`Campaign.from_json` checks the schema level of the whole document, then that every
   node cube is canonical (``cube.canonical``);
2. :func:`check_campaign` checks the campaign rules given :class:`FormulaFacts` per formula
   hash, in this order: utc.calendar, campaign.formulas_order,
   campaign.formula_hash_unique, campaign.node_formula, cube.range, campaign.roots_order,
   campaign.roots_per_formula, campaign.roots_incompatible, then per root split the W
   problems (empty, too_long, repeated, out_of_range, in_cube) and campaign.root_split_node,
   then campaign.splits_order, policy.stack, policy.stream_heap, campaign.pool,
   campaign.argv, campaign.admit_order, campaign.tools_admitted.

A campaign is valid only after both steps; ``cubeproof.cnf.campaign.load_campaign`` performs
them with the bundles of the campaign. The campaign ID is ``SHA256(J(campaign))``.
"""

from __future__ import annotations

import functools
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from itertools import pairwise
from typing import Any

from cubeproof.base.canonical_json import encode, json_sha256
from cubeproof.base.errors import ContractError
from cubeproof.contracts import fields as f
from cubeproof.contracts.identity import pairwise_incompatible, split_id, split_problem
from cubeproof.contracts.policy import Policy
from cubeproof.contracts.primitives import is_hash, is_name, is_relpath, utc_problem
from cubeproof.contracts.values import (
    JsonObject,
    Node,
    SplitEntry,
    Splitter,
    make_node,
    node_from_json,
)


@dataclass(frozen=True)
class FormulaFacts:
    """What the campaign rules need from a verified bundle: V and the variable pools."""

    variables: int
    pools: Mapping[str, tuple[int, ...]] = field(default_factory=dict)


@dataclass(frozen=True)
class FormulaEntry:
    key: str
    formula_sha256: str
    bundle: str

    @classmethod
    def from_json(cls, value: Any, at: str) -> FormulaEntry:
        f.obj(value, at, ("key", "formula_sha256", "bundle"))
        m = functools.partial(f.member, at)
        return cls(
            key=f.matching(value["key"], m("key"), is_name, "Name"),
            formula_sha256=f.matching(
                value["formula_sha256"], m("formula_sha256"), is_hash, "Hash"
            ),
            bundle=f.matching(value["bundle"], m("bundle"), is_relpath, "RelPath"),
        )

    def to_json(self) -> dict[str, Any]:
        return {"key": self.key, "formula_sha256": self.formula_sha256, "bundle": self.bundle}


@dataclass(frozen=True)
class RootSplit:
    """A campaign root split ``{node, variables, splitter}``; W is checked by check_campaign."""

    node: Node
    variables: tuple[int, ...]
    splitter: Splitter

    @functools.cached_property
    def split_id(self) -> str:
        return split_id(self.node.node_id, self.variables)

    def to_json(self) -> dict[str, Any]:
        return {
            "node": self.node.to_json(),
            "variables": list(self.variables),
            "splitter": self.splitter.to_json(),
        }


@dataclass(frozen=True)
class SolverTool:
    """``tools.solver``: CaDiCaL, its hash and argv (options only, no paths)."""

    sha256: str
    argv: tuple[str, ...]
    name: str = "cadical"

    def to_json(self) -> dict[str, Any]:
        return {"name": self.name, "sha256": self.sha256, "argv": list(self.argv)}


@dataclass(frozen=True)
class Tools:
    """``tools``: the configured solver and checker (cake_lpr) of the campaign."""

    solver: SolverTool
    checker_sha256: str

    @classmethod
    def from_json(cls, value: Any, at: str) -> Tools:
        f.obj(value, at, ("solver", "checker"))
        where = f.member(at, "solver")
        solver = f.obj(value["solver"], where, ("name", "sha256", "argv"))
        f.const(solver["name"], f.member(where, "name"), "cadical")
        sha = f.matching(solver["sha256"], f.member(where, "sha256"), is_hash, "Hash")
        argv = f.strings(solver["argv"], f.member(where, "argv"))
        where = f.member(at, "checker")
        checker = f.obj(value["checker"], where, ("name", "sha256"))
        f.const(checker["name"], f.member(where, "name"), "cake_lpr")
        checker_sha = f.matching(checker["sha256"], f.member(where, "sha256"), is_hash, "Hash")
        return cls(SolverTool(sha, argv), checker_sha)

    def to_json(self) -> dict[str, Any]:
        return {
            "solver": self.solver.to_json(),
            "checker": {"name": "cake_lpr", "sha256": self.checker_sha256},
        }


@dataclass(frozen=True)
class AdmittedSolver:
    sha256: str
    argv: tuple[str, ...]

    def to_json(self) -> dict[str, Any]:
        return {"sha256": self.sha256, "argv": list(self.argv)}


def _admitted_solver(value: Any, at: str) -> AdmittedSolver:
    f.obj(value, at, ("sha256", "argv"))
    sha = f.matching(value["sha256"], f.member(at, "sha256"), is_hash, "Hash")
    return AdmittedSolver(sha, f.strings(value["argv"], f.member(at, "argv")))


def _admitted_solvers(value: Any, at: str) -> tuple[AdmittedSolver, ...]:
    return tuple(f.items(value, at, _admitted_solver, min_items=1))


@dataclass(frozen=True)
class Admit:
    """``admit``: admitted checker hashes and, unless null, admitted solver (hash, argv)."""

    checker_sha256: tuple[str, ...]
    solvers: tuple[AdmittedSolver, ...] | None

    @classmethod
    def from_json(cls, value: Any, at: str) -> Admit:
        f.obj(value, at, ("checker_sha256", "solvers"))
        checkers = f.items(
            value["checker_sha256"],
            f.member(at, "checker_sha256"),
            lambda v, where: f.matching(v, where, is_hash, "Hash"),
            min_items=1,
        )
        solvers = f.nullable(value["solvers"], f.member(at, "solvers"), _admitted_solvers)
        return cls(tuple(checkers), solvers)

    def admits_checker(self, sha256: str) -> bool:
        return sha256 in self.checker_sha256

    def admits_solver(self, sha256: str, argv: Sequence[str]) -> bool:
        """A solver is admitted when ``solvers`` is null or lists its hash with this argv."""
        if self.solvers is None:
            return True
        return AdmittedSolver(sha256, tuple(argv)) in self.solvers

    def to_json(self) -> dict[str, Any]:
        solvers = None if self.solvers is None else [s.to_json() for s in self.solvers]
        return {"checker_sha256": list(self.checker_sha256), "solvers": solvers}


CAMPAIGN_FIELDS = (
    "format",
    "created_utc",
    "author",
    "formulas",
    "roots",
    "root_splits",
    "policy",
    "tools",
    "admit",
)


@dataclass(frozen=True)
class Campaign:
    """A campaign document; valid after :func:`check_campaign` with its formula facts.

    The policy is kept as its schema-checked JSON object; :attr:`policy` builds the
    :class:`Policy` value, which raises policy.stack or policy.stream_heap if the stored
    policy violates them (check_campaign evaluates it at its place in the rule order).
    """

    created_utc: str
    author: str
    formulas: tuple[FormulaEntry, ...]
    roots: tuple[Node, ...]
    root_splits: tuple[RootSplit, ...]
    policy_json: JsonObject
    tools: Tools
    admit: Admit

    @classmethod
    def from_json(cls, value: Any, at: str = "$") -> Campaign:
        """The schema level of the whole document, then canonical node cubes."""
        f.obj(value, at, CAMPAIGN_FIELDS)
        m = functools.partial(f.member, at)
        f.const(value["format"], m("format"), "cubeproof-campaign-1")
        created = f.matching(value["created_utc"], m("created_utc"), _utc_form, "UTC string")
        author = f.string(value["author"], m("author"), min_length=1)
        formulas = f.items(value["formulas"], m("formulas"), FormulaEntry.from_json, min_items=1)
        roots = f.items(value["roots"], m("roots"), node_from_json, min_items=1)
        entries = f.items(value["root_splits"], m("root_splits"), SplitEntry.from_json)
        Policy.parse_schema(value["policy"], m("policy"))
        policy_json = JsonObject.from_json(value["policy"], m("policy"))
        tools = Tools.from_json(value["tools"], m("tools"))
        admit = Admit.from_json(value["admit"], m("admit"))
        root_nodes = tuple(
            make_node(formula, cube, f.item(m("roots"), i))
            for i, (formula, cube) in enumerate(roots)
        )
        splits = tuple(
            RootSplit(
                make_node(e.formula_sha256, e.cube, f.member(f.item(m("root_splits"), i), "node")),
                e.variables,
                e.splitter,
            )
            for i, e in enumerate(entries)
        )
        return cls(created, author, tuple(formulas), root_nodes, splits, policy_json, tools, admit)

    @functools.cached_property
    def policy(self) -> Policy:
        return Policy.from_json(self.policy_json.to_json(), "$.policy")

    def to_json(self) -> dict[str, Any]:
        return {
            "format": "cubeproof-campaign-1",
            "created_utc": self.created_utc,
            "author": self.author,
            "formulas": [x.to_json() for x in self.formulas],
            "roots": [x.to_json() for x in self.roots],
            "root_splits": [x.to_json() for x in self.root_splits],
            "policy": self.policy_json.to_json(),
            "tools": self.tools.to_json(),
            "admit": self.admit.to_json(),
        }

    @functools.cached_property
    def campaign_id(self) -> str:
        """``SHA256(J(campaign))``; not stored inside the campaign."""
        return json_sha256(self.to_json())


def _utc_form(text: str) -> bool:
    return utc_problem(text) != "schema"


def _strictly_increasing(keys: Sequence[Any]) -> bool:
    return all(a < b for a, b in pairwise(keys))


def _fail(rule: str, detail: str) -> None:
    raise ContractError(rule, detail)


def check_campaign(campaign: Campaign, facts: Mapping[str, FormulaFacts]) -> None:
    """The campaign rules of specification §4.4 in the order listed in the module documentation.

    ``facts`` maps formula hashes to the V and pools of their verified bundles.
    """
    if utc_problem(campaign.created_utc) is not None:
        _fail("utc.calendar", campaign.created_utc)
    keys = [x.key for x in campaign.formulas]
    if not _strictly_increasing(keys):
        _fail("campaign.formulas_order", "formulas not strictly sorted by key")
    hashes = [x.formula_sha256 for x in campaign.formulas]
    if len(set(hashes)) != len(hashes):
        _fail("campaign.formula_hash_unique", "a formula hash occurs twice")
    nodes = [*campaign.roots, *(s.node for s in campaign.root_splits)]
    known = set(hashes) & set(facts)
    for node in nodes:
        if node.formula_sha256 not in known:
            _fail("campaign.node_formula", node.formula_sha256)
    for node in nodes:
        count = facts[node.formula_sha256].variables
        if node.cube and abs(node.cube[-1]) > count:
            _fail("cube.range", f"{list(node.cube)!r} with V={count}")
    if not _strictly_increasing([r.sort_key for r in campaign.roots]):
        _fail("campaign.roots_order", "roots not strictly sorted by (formula_sha256, node_id)")
    if {r.formula_sha256 for r in campaign.roots} != set(hashes):
        _fail("campaign.roots_per_formula", "a formula has no requested root")
    for formula in hashes:
        cubes = [r.cube for r in campaign.roots if r.formula_sha256 == formula]
        if not pairwise_incompatible(cubes):
            _fail("campaign.roots_incompatible", f"compatible requested roots of {formula}")
    roots = set(campaign.roots)
    for entry in campaign.root_splits:
        count = facts[entry.node.formula_sha256].variables
        problem = split_problem(entry.variables, entry.node.cube, count)
        if problem is not None:
            _fail(problem, f"root split {list(entry.variables)!r} at {list(entry.node.cube)!r}")
        if entry.node.cube and entry.node not in roots:
            _fail("campaign.root_split_node", "a root split below a requested root")
    if not _strictly_increasing([s.split_id for s in campaign.root_splits]):
        _fail("campaign.splits_order", "root_splits not strictly sorted by split_id")
    policy = campaign.policy  # raises policy.stack / policy.stream_heap
    pool = policy.split.pool
    if pool is not None and any(pool not in facts[h].pools for h in hashes):
        _fail("campaign.pool", f"a campaign bundle has no pool {pool!r}")
    tools, admit = campaign.tools, campaign.admit
    argvs = [tools.solver.argv, *(s.argv for s in admit.solvers or ())]
    if any("--lrat" not in argv or not all(a.startswith("-") for a in argv) for argv in argvs):
        _fail("campaign.argv", "an argv lacks --lrat or has an element that is not an option")
    solvers = admit.solvers or ()
    if not _strictly_increasing(list(admit.checker_sha256)) or not _strictly_increasing(
        [(s.sha256, encode(list(s.argv))) for s in solvers]
    ):
        _fail("campaign.admit_order", "admit lists not strictly sorted")
    if not admit.admits_checker(tools.checker_sha256) or not admit.admits_solver(
        tools.solver.sha256, tools.solver.argv
    ):
        _fail("campaign.tools_admitted", "the configured tools are not admitted")
