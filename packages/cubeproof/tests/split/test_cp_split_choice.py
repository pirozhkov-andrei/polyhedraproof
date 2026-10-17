"""The common splitter interface: choices, budgets, clamping, eligibility, the fallback
(specification §9.1)."""

from __future__ import annotations

import pytest
from cp_split_support import make_formula

from cubeproof.base.errors import ConfigurationError, ContractError
from cubeproof.cnf import unit
from cubeproof.contracts.values import JsonObject
from cubeproof.split import choice as ch
from cubeproof.split.choice import (
    Budget,
    SplitChoice,
    check_k,
    check_pool,
    clamp_k,
    eligible,
    lowest_eligible_choice,
    validate_choice,
)

INFO = JsonObject.from_json({"algorithm": "x"})


def test_a_chosen_split_has_one_to_k_max_distinct_positive_variables() -> None:
    assert SplitChoice((3, 1), "chosen", INFO).variables == (3, 1)
    assert len(SplitChoice(tuple(range(1, 21)), "chosen", INFO).variables) == 20
    for variables, rule in (
        ((), "split.too_long"),
        (tuple(range(1, 22)), "split.too_long"),
        ((1, 1), "split.repeated"),
        ((0,), "schema"),
        ((-2,), "schema"),
    ):
        with pytest.raises(ContractError) as error:
            SplitChoice(variables, "chosen", INFO)
        assert error.value.rule == rule


@pytest.mark.parametrize("status", ["no_eligible", "budget", "failed"])
def test_other_statuses_carry_no_variables(status: str) -> None:
    assert SplitChoice((), status, INFO).variables == ()
    with pytest.raises(ContractError):
        SplitChoice((1,), status, INFO)


def test_status_and_info_are_validated() -> None:
    with pytest.raises(ContractError):
        SplitChoice((1,), "ok", INFO)
    with pytest.raises(ContractError):
        SplitChoice((1,), "chosen", {"algorithm": "x"})  # type: ignore[arg-type]
    with pytest.raises(ContractError):
        SplitChoice([1], "chosen", INFO)  # type: ignore[arg-type]
    assert ch.STATUSES == ("chosen", "no_eligible", "budget", "failed")


def test_to_json_is_the_interface_object() -> None:
    choice = SplitChoice.make([2, 5], "chosen", {"algorithm": "x", "n": 3})
    assert choice.to_json() == {
        "variables": [2, 5],
        "status": "chosen",
        "info": {"algorithm": "x", "n": 3},
    }
    assert choice.info_dict() == {"algorithm": "x", "n": 3}
    with pytest.raises(ContractError):
        SplitChoice.make([1], "chosen", {"float": 1.5})


def test_budget_values() -> None:
    assert Budget(1000, None).wall_ms is None
    for bad in (0, -1, 2**63, True, 1.5, "7"):
        with pytest.raises(ConfigurationError):
            Budget(bad)  # type: ignore[arg-type]
    for bad in (0, -5, 2**63, 1.5):
        with pytest.raises(ConfigurationError):
            Budget(10, bad)  # type: ignore[arg-type]


def test_k_zero_is_never_a_split() -> None:
    for bad in (0, -1, 21, True, 2.0):
        with pytest.raises(ConfigurationError):
            check_k(bad)  # type: ignore[arg-type]
    assert [check_k(k) for k in (1, 20)] == [1, 20]


def test_k_is_clamped_to_depth_and_unassigned_variables() -> None:
    assert clamp_k(4, 10, 100) == 4
    assert clamp_k(4, 2, 100) == 2
    assert clamp_k(4, 10, 3) == 3
    assert clamp_k(25, 30, 30) == 20
    assert clamp_k(4, 0, 100) == 0  # the depth limit: STUCK, no helper invoked
    assert clamp_k(4, 10, 0) == 0
    for args in ((-1, 1, 1), (1, -1, 1), (1, 1, -1), (1.5, 1, 1)):
        with pytest.raises(ConfigurationError):
            clamp_k(*args)


def test_pools_are_sorted_distinct_and_in_range() -> None:
    assert check_pool(None, 5) is None
    assert check_pool([], 5) == ()
    assert check_pool((1, 5), 5) == (1, 5)
    for bad in ([0], [6], [2, 1], [2, 2], [True], [1.5]):
        with pytest.raises(ConfigurationError):
            check_pool(bad, 5)  # type: ignore[arg-type]


def test_eligible_excludes_the_cube_assigned_and_non_pool_variables() -> None:
    assert eligible(6, (1, -3), None, [2]) == [4, 5, 6]
    assert eligible(6, (), [2, 4, 5], [4]) == [2, 5]
    assert eligible(6, (), [], []) == []
    assert eligible(3, (), None, (-1, 3)) == [2]  # signed assigned literals count by variable


def test_lowest_eligible_takes_the_lowest_unassigned_pool_variables() -> None:
    formula = make_formula(6, [[1], [-1, 2], [3, 4, 5]])
    result = lowest_eligible_choice(formula, (), 3, None, reason="helper_failure")
    assert result.status == "chosen"
    assert result.variables == (3, 4, 5)  # 1 and 2 are assigned by propagation
    info = result.info_dict()
    assert info["algorithm"] == "lowest-eligible"
    assert info["fallback"] == {"reason": "helper_failure"}
    assert info["candidates"] == 4 and info["parent_assigned"] == 2
    restricted = lowest_eligible_choice(
        formula, (-4,), 2, [1, 4, 5, 6], reason="r", details={"d": 1}
    )
    assert restricted.variables == (5, 6)
    assert restricted.info_dict()["fallback"] == {"reason": "r", "d": 1}


def test_lowest_eligible_uses_the_parent_propagation_under_the_cube() -> None:
    formula = make_formula(4, [[-1, 2], [-2, 3]])
    result = lowest_eligible_choice(formula, (1,), 4, None, reason="r")
    assert result.variables == (4,)  # the cube assigns 1, propagation 2 and 3


def test_lowest_eligible_empty_pool_and_complete_assignment_are_no_eligible() -> None:
    formula = make_formula(3, [[1], [2], [-3]])
    complete = lowest_eligible_choice(formula, (), 2, None, reason="r")
    assert complete.status == "no_eligible" and complete.info_dict()["parent_assigned"] == 3
    open_formula = make_formula(3, [[1, 2, 3]])
    empty_pool = lowest_eligible_choice(open_formula, (), 2, [], reason="r")
    assert empty_pool.status == "no_eligible"
    assert empty_pool.info_dict()["parent_assigned"] == 0  # tells the caller it is the pool


def test_lowest_eligible_after_a_conflict_is_failed_not_a_split() -> None:
    formula = make_formula(3, [[1], [-1, 2], [-2]])
    conflict = lowest_eligible_choice(formula, (), 2, None, reason="r")
    assert (conflict.status, conflict.variables) == ("failed", ())
    assert conflict.info_dict()["stop"] == "parent_conflict"
    under_cube = lowest_eligible_choice(make_formula(2, [[-1, 2]]), (1, -2), 1, None, reason="r")
    assert under_cube.status == "failed"


def test_lowest_eligible_blocks_the_node_when_the_parent_cannot_fit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail(formula: object) -> object:
        raise MemoryError

    monkeypatch.setattr(ch, "build_index", fail)
    result = lowest_eligible_choice(make_formula(3, [[1, 2]]), (), 2, None, reason="r")
    assert result.status == "budget" and result.variables == ()
    assert result.info_dict()["stop"] == "resources"
    # an index the caller already built is used as is
    monkeypatch.undo()
    formula = make_formula(3, [[1, 2]])
    index = unit.build_index(formula)
    assert lowest_eligible_choice(formula, (), 2, None, reason="r", index=index).variables == (1, 2)


def test_lowest_eligible_validates_its_inputs() -> None:
    formula = make_formula(3, [[1, 2]])
    with pytest.raises(ConfigurationError):
        lowest_eligible_choice(formula, (), 0, None, reason="r")
    with pytest.raises(ContractError):
        lowest_eligible_choice(formula, (2, 1), 1, None, reason="r")
    with pytest.raises(ContractError):
        lowest_eligible_choice(formula, (4,), 1, None, reason="r")
    with pytest.raises(ConfigurationError):
        lowest_eligible_choice(formula, (), 1, [3, 2], reason="r")


def test_the_coordinator_check_accepts_a_well_formed_choice_in_the_pool() -> None:
    choice = SplitChoice.make([4, 2], "chosen", {"algorithm": "x"})
    assert validate_choice(choice, 6, (1,), None, 3) == (4, 2)
    assert validate_choice(choice, 6, (-1,), [2, 4, 5], 2) == (4, 2)  # the order of W is kept


@pytest.mark.parametrize(
    ("variables", "cube", "pool", "k", "rule"),
    [
        ((4, 7), (), None, 3, "split.out_of_range"),
        ((4, 1), (-1,), None, 3, "split.in_cube"),
        ((4, 2, 3), (), None, 2, "split.too_long"),
        ((4, 2), (), [2, 5], 3, "split.pool"),
    ],
)
def test_the_coordinator_check_refuses_a_malformed_choice(
    variables: tuple[int, ...],
    cube: tuple[int, ...],
    pool: list[int] | None,
    k: int,
    rule: str,
) -> None:
    choice = SplitChoice.make(variables, "chosen", {"algorithm": "x"})
    with pytest.raises(ContractError) as error:
        validate_choice(choice, 6, cube, pool, k)
    assert error.value.rule == rule


def test_the_coordinator_check_needs_a_chosen_split() -> None:
    for status in ("no_eligible", "budget", "failed"):
        with pytest.raises(ValueError):
            validate_choice(SplitChoice.make([], status, {}), 6, (), None, 2)
    with pytest.raises(ContractError):  # a noncanonical cube is refused too
        validate_choice(SplitChoice.make([1], "chosen", {}), 6, (3, 2), None, 2)
