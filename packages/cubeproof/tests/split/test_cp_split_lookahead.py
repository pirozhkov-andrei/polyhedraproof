"""lookahead-v1, the Python reference (specification §9.3): worked examples, budgets, oracle,
engine."""

from __future__ import annotations

import hashlib
import random
from collections.abc import Callable

import pytest
from cp_split_support import (
    make_formula,
    oracle_lookahead,
    random_cube,
    random_formula,
    random_pool,
    summary,
)

from cubeproof.base.errors import ConfigurationError, ContractError
from cubeproof.cnf.dimacs import Formula
from cubeproof.cnf.unit import build_index, propagate
from cubeproof.contracts.identity import node_id
from cubeproof.split.choice import Budget
from cubeproof.split.lookahead import (
    Engine,
    build_engine,
    lookahead,
    lookahead_steps,
    sample_children,
)
from cubeproof.tools.unit_helper import SlicedTask, TaskState

BIG = Budget(10**9)

# V=4: +1 implies 2, 3 and then 4. Scores at the root: v1 (3+1)(0+1)=4, v2 (0+1)(1+1)=2,
# v3 2, v4 1. Probes: the parent plus 2 per candidate = 9. With W=[1] the children are
# -1 (nothing) and +1 (everything assigned); 2, 3, 4 score 1 each, ties go to 2: 8 more.
CHAIN = [[-1, 2], [-1, 3], [-2, -3, 4]]

# V=5: +2 implies 3, 4, 5; -2 implies -1. v2 scores (3+1)(1+1) = 8. In round 2 the child -2
# implies -1 (so 1 scores 0 there) yet 1 is chosen: the +2 child gives every candidate 1.
STAR = [[-1, 2], [-2, 3], [-2, 4], [-2, 5]]


def test_the_worked_example_round_one() -> None:
    result = lookahead(make_formula(4, CHAIN), (), 1, None, BIG)
    assert (result.status, result.variables) == ("chosen", (1,))
    assert result.info_dict() == {
        "algorithm": "lookahead-v1",
        "candidates": 4,
        "parent_assigned": 0,
        "probes": 9,
        "rounds": 1,
        "scores": [4],
        "stop": "k",
    }


def test_the_worked_example_round_two_with_a_tie() -> None:
    result = lookahead(make_formula(4, CHAIN), (), 2, None, BIG)
    assert result.variables == (1, 2)  # 2, 3 and 4 tie at 1: the lowest wins
    info_ = result.info_dict()
    assert (info_["scores"], info_["probes"], info_["rounds"], info_["stop"]) == (
        [4, 1],
        17,
        2,
        "k",
    )
    assert lookahead(make_formula(4, CHAIN), (), 4, None, BIG).variables == (1, 2, 3, 4)


@pytest.mark.parametrize(
    ("limit", "variables", "scores", "probes", "stop"),
    [
        (1, (), [], 1, "probe_limit"),
        (2, (), [], 1, "probe_limit"),
        (3, (1,), [4], 3, "probe_limit"),
        (4, (1,), [4], 3, "probe_limit"),
        (5, (1,), [4], 5, "probe_limit"),
        (9, (1,), [4], 9, "probe_limit"),  # round 2 cannot even propagate its children
        (10, (1,), [4], 10, "probe_limit"),  # ... one child is not a round
        (11, (1,), [4], 11, "probe_limit"),  # both children, no candidate fits
        (12, (1,), [4], 11, "probe_limit"),
        (13, (1, 2), [4, 1], 13, "probe_limit"),  # one candidate fits: best of the evaluated
        (16, (1, 2), [4, 1], 15, "probe_limit"),
        (17, (1, 2), [4, 1], 17, "k"),
        (10**6, (1, 2), [4, 1], 17, "k"),
    ],
)
def test_probe_limit_cuts_at_candidate_granularity(
    limit: int, variables: tuple[int, ...], scores: list[int], probes: int, stop: str
) -> None:
    result = lookahead(make_formula(4, CHAIN), (), 2, None, Budget(limit))
    got = result.info_dict()
    assert result.variables == variables
    assert (got["scores"], got["probes"], got["stop"]) == (scores, probes, stop)
    assert got["probes"] <= limit
    assert result.status == ("chosen" if variables else "budget")


def test_a_budget_before_any_candidate_is_the_budget_status() -> None:
    result = lookahead(make_formula(4, CHAIN), (), 2, None, Budget(2))
    assert (result.status, result.variables) == ("budget", ())
    assert result.info_dict()["stop"] == "probe_limit"


def test_an_implied_variable_is_not_discarded_globally() -> None:
    result = lookahead(make_formula(5, STAR), (), 2, None, BIG)
    assert result.variables == (2, 1)
    got = result.info_dict()
    assert (got["scores"], got["probes"], got["candidates"]) == ([8, 1], 21, 5)


def test_all_ties_go_to_the_lowest_variable() -> None:
    free = make_formula(4, [])
    result = lookahead(free, (), 3, None, BIG)
    assert result.variables == (1, 2, 3)
    assert result.info_dict()["scores"] == [1, 2, 4]  # every child contributes 1 per candidate
    restricted = lookahead(free, (), 2, [2, 4], BIG)
    assert restricted.variables == (2, 4)


def test_parent_assignments_and_the_cube_are_not_candidates() -> None:
    formula = make_formula(5, [[1], [-1, 2]])
    result = lookahead(formula, (-4,), 3, None, BIG)
    assert result.variables == (3, 5)  # 1, 2 by propagation and 4 by the cube
    got = result.info_dict()
    assert (got["candidates"], got["parent_assigned"], got["scores"]) == (2, 3, [1, 2])
    assert got["stop"] == "candidates" and got["rounds"] == 2


def test_empty_and_unusable_pools_are_no_eligible() -> None:
    formula = make_formula(4, [*CHAIN, [3]])  # 3 is assigned at the root
    empty = lookahead(formula, (), 2, [], BIG)
    assert (empty.status, empty.variables) == ("no_eligible", ())
    assert empty.info_dict()["candidates"] == 0 and empty.info_dict()["parent_assigned"] == 1
    assigned_only = lookahead(formula, (), 2, [3], BIG)
    assert assigned_only.status == "no_eligible"
    assert assigned_only.info_dict()["stop"] == "candidates"
    assert assigned_only.info_dict()["probes"] == 1  # only the parent propagation


def test_a_complete_conflict_free_assignment_has_no_candidates() -> None:
    formula = make_formula(3, [[1], [-2], [-1, 3]])
    result = lookahead(formula, (), 2, None, BIG)
    got = result.info_dict()
    assert result.status == "no_eligible"
    assert got["parent_assigned"] == 3 == formula.variables  # tells the caller: evaluate it
    assert got["candidates"] == 0


def test_a_parent_conflict_is_failed_never_a_split() -> None:
    conflicting = make_formula(3, [[1], [-1, 2], [-2]])
    result = lookahead(conflicting, (), 2, None, BIG)
    got = result.info_dict()
    assert (result.status, result.variables, got["stop"]) == ("failed", (), "parent_conflict")
    assert got["probes"] == 1 and got["candidates"] == 0
    under_cube = lookahead(make_formula(3, [[-1, 2]]), (1, -2), 1, None, BIG)
    assert under_cube.status == "failed"
    assert lookahead(make_formula(2, [[]]), (), 1, None, BIG).status == "failed"  # empty clause


def test_k_larger_than_the_candidates_stops_with_candidates() -> None:
    result = lookahead(make_formula(3, [[1, 2, 3]]), (), 9, None, BIG)
    assert len(result.variables) == 3 and result.info_dict()["stop"] == "candidates"


def test_the_pool_restricts_candidates_without_reordering() -> None:
    result = lookahead(make_formula(4, CHAIN), (), 2, [2, 3, 4], BIG)
    # without variable 1 nothing is implied: all candidates tie, so the lowest wins
    assert result.variables == (2, 3)


def test_inputs_are_validated() -> None:
    formula = make_formula(4, CHAIN)
    for k in (0, 21, -1, True):
        with pytest.raises(ConfigurationError):
            lookahead(formula, (), k, None, BIG)
    with pytest.raises(ContractError):
        lookahead(formula, (2, 1), 1, None, BIG)
    with pytest.raises(ContractError):
        lookahead(formula, (5,), 1, None, BIG)
    with pytest.raises(ConfigurationError):
        lookahead(formula, (), 1, [3, 3], BIG)
    with pytest.raises(ConfigurationError):
        lookahead(formula, (), 1, [9], BIG)
    other = make_formula(4, [*CHAIN, [4]])
    with pytest.raises(ValueError, match="another formula"):
        lookahead(formula, (), 1, None, BIG, engine=build_engine(other))


# -- sampling ------------------------------------------------------------------------------------

NODE = node_id("ab" * 32, (1, -3))
# Vectors from the definition: the 16 smallest (SHA256(node_id NUL round NUL index), index).
SAMPLES = {
    (6, 5): [21, 29, 26, 7, 23, 9, 17, 19, 14, 20, 12, 18, 4, 10, 1, 13],
    (7, 6): [1, 24, 18, 14, 6, 49, 19, 29, 13, 9, 59, 20, 27, 43, 35, 26],
    (12, 11): [
        601,
        828,
        1840,
        960,
        733,
        1124,
        1376,
        769,
        1639,
        119,
        1906,
        249,
        570,
        886,
        1027,
        579,
    ],
}


def test_sampled_children_are_the_sixteen_smallest_hashes() -> None:
    assert NODE == "e1e4fd62eb1157696cc3c52aa5bede3b3754c191a049500646c96931134aa81b"
    for (round_number, width), expected in SAMPLES.items():
        assert sample_children(NODE, round_number, width) == expected
    first = hashlib.sha256(f"{NODE}\x006\x000".encode("ascii")).hexdigest()
    assert first == "be5a118eb077fcfb3a18d5f718e1a3113f3b2064c43c777dfa1abc684e5ba28c"


def test_up_to_sixteen_sign_vectors_are_all_used_in_index_order() -> None:
    for width in range(5):
        assert sample_children(NODE, width + 1, width) == list(range(1 << width))


def test_the_round_number_enters_the_hash_and_is_numbered_from_one() -> None:
    assert sample_children(NODE, 6, 5) != sample_children(NODE, 5, 5)
    assert sample_children(NODE, 6, 5) != sample_children(NODE, 7, 5)
    with pytest.raises(ValueError):
        sample_children(NODE, 0, 5)
    with pytest.raises(ValueError):
        sample_children(NODE, 1, -1)


def test_sampling_depends_on_the_node_not_on_a_host_rng() -> None:
    other = node_id("ab" * 32, (1, -4))
    assert sample_children(other, 6, 5) != sample_children(NODE, 6, 5)
    random.seed(1)
    first = sample_children(NODE, 6, 5)
    random.seed(2)
    assert sample_children(NODE, 6, 5) == first


def test_rounds_beyond_the_fifth_use_the_sample_not_all_children() -> None:
    formula = make_formula(
        14, [[-a, b] for a, b in ((1, 2), (3, 4), (5, 6), (7, 8), (9, 10), (11, 12))] + [[13, 14]]
    )
    result = lookahead(formula, (), 8, None, BIG)
    assert len(result.variables) == 8
    expected = oracle_lookahead(formula, (), 8, None, 10**9)
    assert summary(result) == expected
    assert len(sample_children(node_id(formula.sha256, ()), 6, 5)) == 16  # of 32 sign vectors


# -- the literal oracle and the counter engine ---------------------------------------------------


def random_cases(
    seed: int, n: int
) -> list[tuple[Formula, tuple[int, ...], int, list[int] | None, int]]:
    rng = random.Random(seed)
    cases = []
    for _ in range(n):
        formula = random_formula(rng)
        cases.append(
            (
                formula,
                random_cube(rng, formula),
                rng.randint(1, 10),
                random_pool(rng, formula),
                rng.choice([1, 2, 3, 7, 20, 60, 200, 5000, 10**6, 10**6, 10**6]),
            )
        )
    return cases


def test_the_reference_agrees_with_the_literal_oracle_on_random_inputs() -> None:
    statuses = set()
    for formula, cube, k, pool, limit in random_cases(20240, 150):
        engine = build_engine(formula)
        result = lookahead(formula, cube, k, pool, Budget(limit), engine=engine)
        assert summary(result) == oracle_lookahead(formula, cube, k, pool, limit)
        statuses.add((result.status, result.info_dict()["stop"]))
    assert {("chosen", "k"), ("chosen", "probe_limit"), ("failed", "parent_conflict")} <= statuses
    assert ("budget", "probe_limit") in statuses and ("no_eligible", "candidates") in statuses


def test_a_lower_probe_limit_only_shortens_the_final_round() -> None:
    for formula, cube, k, pool, _ in random_cases(7, 40):
        full = lookahead(formula, cube, k, pool, BIG)
        if full.status != "chosen":
            continue
        for limit in (3, 10, 40, 150):
            partial = lookahead(formula, cube, k, pool, Budget(limit))
            assert partial.info_dict()["probes"] <= limit
            if partial.variables:
                shared = len(partial.variables) - 1
                assert partial.variables[:shared] == full.variables[:shared]


def test_an_engine_is_reusable_and_returns_to_its_root_state() -> None:
    rng = random.Random(3)
    formula = random_formula(rng, low=0.4, high=0.9)
    engine = build_engine(formula)
    root_values, root_trail = bytes(engine.values), list(engine.trail)
    root_counts = (list(engine._ntrue), list(engine._nfalse))
    for _ in range(20):
        cube = random_cube(rng, formula)
        k = rng.randint(1, 6)
        shared = lookahead(formula, cube, k, None, Budget(5000), engine=engine)
        fresh = lookahead(formula, cube, k, None, Budget(5000))
        assert shared == fresh
        assert bytes(engine.values) == root_values and engine.trail == root_trail
        assert (engine._ntrue, engine._nfalse) == root_counts  # the counters are back too


def reference_closure(formula: Formula, literals: tuple[int, ...]) -> tuple[bool, set[int]]:
    propagation = propagate(build_index(formula), tuple(sorted(literals, key=abs)))
    return propagation.conflict, set(propagation.trail)


def test_the_engine_propagates_like_unit_v1() -> None:
    rng = random.Random(99)
    conflicts = 0
    for _ in range(200):
        formula = random_formula(rng, low=0.5, high=2.0)
        engine = build_engine(formula)
        cube = random_cube(rng, formula, most=4)
        conflict = engine.root_conflict
        if not conflict:
            for literal in cube:
                if engine.assume(literal):
                    conflict = True
                    break
        expected_conflict, expected = reference_closure(formula, cube)
        assert conflict == expected_conflict
        if not conflict:
            assert set(engine.trail) == expected
        conflicts += conflict
        engine.undo(0)
        assert not any(engine.values) and engine.trail == []
    assert 20 < conflicts < 180


def test_undo_restores_the_state_also_after_a_conflict() -> None:
    formula = make_formula(4, [[-1, 2], [-1, -2], [3, 4]])
    engine = build_engine(formula)
    before = (bytes(engine.values), list(engine._ntrue), list(engine._nfalse))
    assert engine.assume(1) is True
    engine.undo(engine.root_mark)
    assert (bytes(engine.values), list(engine._ntrue), list(engine._nfalse)) == before
    assert engine.assume(-1) is False and engine.assume(-3) is False
    assert engine.assume(-4) is True  # (3 4) becomes empty
    engine.undo(engine.root_mark)
    assert (bytes(engine.values), list(engine._ntrue), list(engine._nfalse)) == before


def test_clause_forms_do_not_confuse_the_engine() -> None:
    # repeated literals, a tautology (never propagates), a unit given twice, the empty clause
    engine = build_engine(make_formula(3, [[1, 1], [2, -2, 3], [-1, -1, 2]]))
    assert not engine.root_conflict
    assert set(engine.trail) == {1, 2}
    assert build_engine(make_formula(2, [[1], [1]])).trail == [1]
    assert build_engine(make_formula(2, [[1], []])).root_conflict is True
    assert build_engine(make_formula(2, [[1], [-1]])).root_conflict is True
    assert build_engine(make_formula(0, [])).root_conflict is False


def test_assuming_an_assigned_literal_is_free_and_a_clash_is_a_conflict() -> None:
    engine = build_engine(make_formula(2, [[1]]))
    mark = len(engine.trail)
    assert engine.assume(1) is False and len(engine.trail) == mark
    assert engine.assume(-1) is True and len(engine.trail) == mark


# -- wall budget and steps -----------------------------------------------------------------------


def ticking_clock() -> Callable[[], int]:
    calls = [0]

    def clock() -> int:
        calls[0] += 1
        return calls[0] * 1_000_000  # the n-th reading is n ms

    return clock


# 2 is the strong variable: +2 implies 3 and 4 and then 1; v1 scores 1, v2 scores 4.
STRONG_TWO = [[-2, 3], [-2, 4], [-3, -4, 1]]


def test_wall_budget_is_checked_before_each_child_base_propagation() -> None:
    # CHAIN with k = 2: reading 1 starts, 2 is the parent, 3-10 are the eight probes of round 1,
    # reading 11 is the check before the first child of round 2: wall_ms=10 has expired there.
    cut = lookahead(make_formula(4, CHAIN), (), 2, None, Budget(10**6, 10), clock=ticking_clock())
    got = cut.info_dict()
    assert (cut.status, cut.variables) == ("chosen", (1,))  # the previous W, round 2 is dropped
    assert (got["stop"], got["probes"], got["rounds"], got["scores"]) == ("wall_ms", 9, 1, [4])


def test_wall_budget_discards_a_partially_evaluated_candidate() -> None:
    formula = make_formula(4, STRONG_TWO)
    full = lookahead(formula, (), 1, None, BIG)
    assert full.variables == (2,) and full.info_dict()["scores"] == [4]
    # readings: 1 start, 2 parent, 3-4 probes of candidate 1, 5-6 probes of candidate 2.
    # wall_ms=5 expires at the 6th reading: candidate 2 ran one probe and is discarded.
    cut = lookahead(formula, (), 1, None, Budget(10**6, 5), clock=ticking_clock())
    got = cut.info_dict()
    assert (cut.status, cut.variables) == ("chosen", (1,))
    assert (got["stop"], got["probes"], got["scores"]) == ("wall_ms", 4, [1])


def test_wall_budget_before_the_first_candidate_is_the_budget_status() -> None:
    formula = make_formula(4, STRONG_TWO)
    cut = lookahead(formula, (), 1, None, Budget(10**6, 2), clock=ticking_clock())
    assert (cut.status, cut.variables) == ("budget", ())
    assert cut.info_dict()["stop"] == "wall_ms"
    immediately = lookahead(formula, (), 1, None, Budget(10**6, 1), clock=ticking_clock())
    assert immediately.info_dict()["probes"] == 0 and immediately.status == "budget"


def test_a_generous_wall_budget_changes_nothing() -> None:
    formula = make_formula(4, STRONG_TWO)
    assert summary(lookahead(formula, (), 3, None, Budget(10**6, 10**6))) == summary(
        lookahead(formula, (), 3, None, BIG)
    )


def test_the_step_generator_yields_before_every_unit_and_runs_in_slices() -> None:
    formula = make_formula(4, CHAIN)
    task = SlicedTask(lookahead_steps(formula, (), 2, None, BIG), max_steps=10**6)
    states = [task.advance(1)]
    while states[-1] is TaskState.RUNNING:
        states.append(task.advance(1))
    assert task.state is TaskState.DONE
    assert task.result == lookahead(formula, (), 2, None, BIG)
    assert task.steps >= 17  # a step before each of the 17 propagation units
    short = SlicedTask(lookahead_steps(formula, (), 2, None, BIG), max_steps=3)
    assert short.advance(1000) is TaskState.BUDGET  # a step budget ends the task, no result


def test_engine_is_exported_with_its_counters() -> None:
    assert isinstance(build_engine(make_formula(1, [])), Engine)
