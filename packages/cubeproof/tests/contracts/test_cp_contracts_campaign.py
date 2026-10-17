"""The campaign value and its cross-field rules, given formula facts (specification §4.4)."""

from __future__ import annotations

import copy
import hashlib
from typing import Any

import cp_corpus
import pytest

from cubeproof.base.canonical_json import encode
from cubeproof.base.errors import ContractError
from cubeproof.contracts.campaign import Campaign, FormulaFacts, check_campaign
from cubeproof.contracts.identity import node_id

ALL3 = "83ef822c62746022fb52b0d52f6050c2f8a699e171512c9eb61356bda5d553d4"
FACTS = {ALL3: FormulaFacts(variables=3, pools={"all": (1, 2, 3), "none": ()})}


def _all3() -> dict[str, Any]:
    value: dict[str, Any] = cp_corpus.load_json("campaigns/all3/campaign.json")
    return value


def _rule(value: dict[str, Any], facts: dict[str, FormulaFacts] | None = None) -> str | None:
    try:
        check_campaign(Campaign.from_json(value), FACTS if facts is None else facts)
    except ContractError as error:
        return error.rule
    return None


def test_valid_campaign_round_trip_and_identity() -> None:
    value = _all3()
    campaign = Campaign.from_json(value)
    check_campaign(campaign, FACTS)
    assert campaign.to_json() == value
    assert campaign.campaign_id == hashlib.sha256(encode(value)).hexdigest()
    assert campaign.policy.proof_mode.value == "transient"
    assert [r.node_id for r in campaign.roots] == [
        "5e1fff6f071fe019657a52a5fda90a3e08196d01524e7a157b70df624b676720"
    ]
    assert campaign.root_splits[0].split_id == (
        "0254e0b4b11f72001d9c76c0b60c1d97ee4d3da3fff271eba10dd51909a67388"
    )
    assert campaign.tools.checker_sha256 in campaign.admit.checker_sha256
    assert campaign.admit.admits_checker(campaign.tools.checker_sha256)
    assert campaign.admit.admits_solver(campaign.tools.solver.sha256, campaign.tools.solver.argv)
    assert not campaign.admit.admits_solver(campaign.tools.solver.sha256, ("--lrat", "-q"))


def test_open_splitter_info_is_preserved_exactly() -> None:
    value = _all3()
    value["root_splits"][0]["splitter"]["info"] = {"z": [1, {"é": None}], "a": "x"}
    assert Campaign.from_json(value).to_json() == value


def test_admit_solvers_null_admits_every_solver() -> None:
    value = _all3()
    value["admit"]["solvers"] = None
    campaign = Campaign.from_json(value)
    check_campaign(campaign, FACTS)
    assert campaign.admit.admits_solver("f" * 64, ("--anything",))


def test_rules_in_the_listed_order() -> None:
    value = _all3()
    value["created_utc"] = "2023-02-29T00:00:00.000Z"
    value["root_splits"][0]["variables"] = [9]
    assert _rule(value) == "utc.calendar"


def test_node_formula_needs_facts_for_every_node() -> None:
    assert _rule(_all3(), facts={}) == "campaign.node_formula"


def test_pool_must_exist_in_every_bundle() -> None:
    value = _all3()
    value["policy"]["split"]["pool"] = "all"
    assert _rule(value) is None
    value["policy"]["split"]["pool"] = "missing"
    assert _rule(value) == "campaign.pool"


def test_nested_campaign_splits_are_refused() -> None:
    value = _all3()
    assert value["root_splits"][0]["variables"] == [1]
    value["root_splits"][0]["node"]["cube"] = [2]
    assert _rule(value) == "campaign.root_split_node"
    # A W problem of the same entry is reported first.
    value["root_splits"][0]["node"]["cube"] = [1]
    assert _rule(value) == "split.in_cube"


@pytest.mark.parametrize(
    ("argv", "rule"),
    [
        (["--lrat"], None),
        (["--lrat", "-q"], None),
        (["-q"], "campaign.argv"),
        (["--lrat", "x"], "campaign.argv"),
        (["--lrat=1"], "campaign.argv"),
        (["--lrat", ""], "campaign.argv"),
    ],
)
def test_argv_rules(argv: list[str], rule: str | None) -> None:
    value = copy.deepcopy(_all3())
    value["tools"]["solver"]["argv"] = argv
    value["admit"]["solvers"] = None
    assert _rule(value) == rule


def test_configured_solver_must_be_admitted_with_its_exact_argv() -> None:
    value = _all3()
    value["tools"]["solver"]["argv"] = ["--lrat", "-q"]
    assert _rule(value) == "campaign.tools_admitted"
    value["admit"]["solvers"][0]["argv"] = ["--lrat", "-q"]
    assert _rule(value) is None


def test_admitted_solvers_are_sorted_by_the_bytes_of_j_argv() -> None:
    # J(argv) byte order and Python tuple order disagree for a proper prefix: "]" (0x5d)
    # sorts after "," (0x2c), so ["-a","--lrat","-b"] comes first in J order.
    short, long = ["-a", "--lrat"], ["-a", "--lrat", "-b"]
    assert encode(long) < encode(short)
    assert tuple(short) < tuple(long)
    value = _all3()
    solver = value["tools"]["solver"]["sha256"]
    value["tools"]["solver"]["argv"] = short
    value["admit"]["solvers"] = [
        {"sha256": solver, "argv": long},
        {"sha256": solver, "argv": short},
    ]
    assert _rule(value) is None
    value["admit"]["solvers"].reverse()  # tuple order
    assert _rule(value) == "campaign.admit_order"
    # A repeated entry is not strictly sorted.
    value["admit"]["solvers"] = [{"sha256": solver, "argv": short}] * 2
    assert _rule(value) == "campaign.admit_order"
    # The hash is the first key: a smaller hash comes first whatever its argv.
    smaller = "0" * 64
    assert smaller < solver
    value["admit"]["solvers"] = [
        {"sha256": smaller, "argv": short},
        {"sha256": solver, "argv": long},
        {"sha256": solver, "argv": short},
    ]
    assert _rule(value) is None
    value["admit"]["solvers"] = [
        {"sha256": solver, "argv": long},
        {"sha256": solver, "argv": short},
        {"sha256": smaller, "argv": long},
    ]
    assert _rule(value) == "campaign.admit_order"


def _with_roots(value: dict[str, Any], cubes: list[list[int]]) -> dict[str, Any]:
    # Requested roots of one formula are sorted by node_id (campaign.roots_order).
    ordered = sorted(cubes, key=lambda cube: node_id(ALL3, cube))
    value["roots"] = [{"formula_sha256": ALL3, "cube": cube} for cube in ordered]
    return value


def test_root_split_at_the_empty_cube_is_allowed_beside_nonempty_roots() -> None:
    # Requirement campaign.root_split_node: the node of a root split is a requested root or
    # the empty cube of a campaign formula (coverage outside a pilot scope, specification §4.4).
    value = _all3()
    assert value["root_splits"][0]["node"]["cube"] == []
    for cubes in ([[-1]], [[-1], [1]], [[2]]):
        assert _rule(_with_roots(copy.deepcopy(value), cubes)) is None
    # A root split at a requested nonempty root is allowed as well.
    at_root = _with_roots(copy.deepcopy(value), [[-1]])
    at_root["root_splits"][0]["node"]["cube"] = [-1]
    at_root["root_splits"][0]["variables"] = [2]
    assert _rule(at_root) is None
    # A nonempty cube that is not a requested root is a nested campaign split.
    below = _with_roots(copy.deepcopy(value), [[-1]])
    below["root_splits"][0]["node"]["cube"] = [-1, 2]
    below["root_splits"][0]["variables"] = [3]
    assert _rule(below) == "campaign.root_split_node"
    other = _with_roots(copy.deepcopy(value), [[-1]])
    other["root_splits"][0]["node"]["cube"] = [1]
    other["root_splits"][0]["variables"] = [2]
    assert _rule(other) == "campaign.root_split_node"


def test_node_formula_is_checked_against_the_campaign_formulas_not_the_facts() -> None:
    # Facts of a formula that the campaign does not list do not make its nodes valid.
    other = "1" * 64
    facts = {**FACTS, other: FormulaFacts(variables=3)}
    value = _all3()
    assert _rule(value, facts) is None
    value["root_splits"][0]["node"]["formula_sha256"] = other
    assert _rule(value, facts) == "campaign.node_formula"
    value = _all3()
    value["roots"].insert(0, {"formula_sha256": other, "cube": []})
    assert _rule(value, facts) == "campaign.node_formula"


def test_schema_errors_are_reported_before_rules() -> None:
    value = _all3()
    value["policy"]["checker_stack_mib"] = 0
    with pytest.raises(ContractError) as info:
        Campaign.from_json(value)
    assert info.value.rule == "schema"
    assert info.value.location == "$.policy.checker_stack_mib"


def test_policy_rules_are_campaign_rules() -> None:
    value = _all3()
    value["policy"]["checker_max_stack_mib"] = 128
    Campaign.from_json(value)  # schema-valid
    assert _rule(value) == "policy.stack"
