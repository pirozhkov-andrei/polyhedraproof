"""Unit propagation and unit-v1 proofs (specification §3.1, §6.1, §9.1).

Every proof generated here is checked by the test LRAT validator on CNF(F, C); the image
tier (``test_cp_um_image.py``) checks the same proofs with the pinned cake_lpr.
"""

from __future__ import annotations

from collections.abc import Generator

import pytest
from cp_um_support import (
    CORPORA,
    UNIT_VECTORS,
    brute_force_satisfiable,
    formula,
    naive_propagation,
    oracle_accepts,
    random_cases,
    satisfies,
)

from cubeproof.base.errors import ContractError
from cubeproof.cnf import unit as up
from cubeproof.cnf.model import propagated_model
from cubeproof.contracts.enums import ModelError


@pytest.mark.parametrize(("variables", "clauses", "cube", "expected"), UNIT_VECTORS)
def test_unit_v1_vectors(
    variables: int, clauses: list[tuple[int, ...]], cube: tuple[int, ...], expected: bytes | None
) -> None:
    f = formula(variables, clauses)
    index = up.build_index(f)
    assert up.refutation(index, cube) == expected
    if expected is not None:
        assert oracle_accepts(f, cube, expected)
        assert not brute_force_satisfiable(variables, clauses, cube)


def test_truth_table_of_tiny_formulas() -> None:
    """Random tiny CNF(F, C) against the naive fixpoint, brute force and the test validator."""
    conflicts = complete = undecided = restated = 0
    for variables, clauses, cube in random_cases(*CORPORA[0]):
        f = formula(variables, clauses)
        index = up.build_index(f)
        result = up.propagate(index, cube)
        conflict, assignment = naive_propagation(clauses, cube)
        assert result.conflict is conflict, (variables, clauses, cube)
        if result.conflict:
            conflicts += 1
            proof = up.unit_proof(index, result)
            restated += proof.count(b"\n") > 1
            assert oracle_accepts(f, cube, proof), (variables, clauses, cube, proof)
            assert not brute_force_satisfiable(variables, clauses, cube)
            continue
        assert {abs(x): x > 0 for x in result.trail} == assignment
        assert len(set(map(abs, result.trail))) == len(result.trail)
        if result.complete:
            complete += 1
            assert satisfies(clauses, cube, result.values())
            model = propagated_model(f, result)
            assert model.model_error is None
        else:
            undecided += 1
            with pytest.raises(ValueError, match="did not assign"):
                result.values()
    # the corpus exercises every route, including restated reasons
    assert min(conflicts, complete, undecided) > 100
    assert restated > 3


def test_every_hint_is_unit_or_the_final_conflict() -> None:
    """The structural property that makes cake_lpr accept the proof (it does not merge
    repeated literals and refuses satisfied or non-unit hints)."""
    for variables, clauses, cube in random_cases(*CORPORA[1]):
        f = formula(variables, clauses)
        index = up.build_index(f)
        result = up.propagate(index, cube)
        if not result.conflict:
            continue
        units = [(x,) for x in cube]
        database = {i + 1: tuple(c) for i, c in enumerate([*clauses, *units])}
        lines = up.unit_proof(index, result).decode("ascii").splitlines()
        for line in lines[:-1]:
            tokens = [int(t) for t in line.split()]
            database[tokens[0]] = tuple(tokens[1:-3])
        tokens = [int(t) for t in lines[-1].split()]
        assert tokens[1] == 0 and tokens[-1] == 0
        hints = tokens[2:-1]
        true: set[int] = set()
        for position, hint in enumerate(hints):
            clause = database[hint]
            rest = [x for x in clause if -x not in true]
            assert not any(x in true for x in clause), "a satisfied hint"
            if position == len(hints) - 1:
                assert rest == [], "the last hint must be falsified"
            else:
                assert len(rest) == 1, f"hint {hint} is not unit as written: {clause}"
                true.add(rest[0])


def test_index_reuse_and_chunking_do_not_change_results() -> None:
    for variables, clauses, cube in random_cases(99, 300):
        f = formula(variables, clauses)
        shared = up.build_index(f)
        small = up.drive(up.build_index_steps(f, chunk=1))
        expected = up.propagate(shared, cube)
        for index in (shared, small):
            for chunk in (1, 2, 7, 1 << 20):
                got = up.drive(up.propagate_steps(index, cube, chunk=chunk))
                assert got == expected
        if expected.conflict:
            assert up.unit_proof(small, expected) == up.unit_proof(shared, expected)


def test_small_chunks_yield_often() -> None:
    clauses = [(-i, i + 1) for i in range(1, 400)]
    f = formula(400, clauses)
    yields = 0
    steps = up.build_index_steps(f, chunk=10)
    while True:
        try:
            next(steps)
            yields += 1
        except StopIteration as stop:
            index = stop.value
            break
    assert yields >= 70
    run = up.propagate_steps(index, (1,), chunk=10)
    yields = 0
    while True:
        try:
            next(run)
            yields += 1
        except StopIteration as stop:
            result = stop.value
            break
    assert result.complete and yields >= 70
    assert result.trail == tuple(range(1, 401))
    assert result.reasons == (400, *range(1, 400))


def _yields(steps: Generator[None, None, object]) -> int:
    count = 0
    while True:
        try:
            next(steps)
        except StopIteration:
            return count
        count += 1


def test_long_occurrence_lists_are_split_into_chunks() -> None:
    """Specification §8.1: one literal occurring in many clauses is no unbounded step, whether its
    clauses become satisfied or lose a literal."""
    n = 3000
    satisfied = formula(n, [(1, i) for i in range(2, n + 1)])
    shrinking = formula(n, [(-1, i, i - 1) for i in range(3, n + 1)])
    for f in (satisfied, shrinking):
        index = up.build_index(f)
        assert _yields(up.propagate_steps(index, (1,), chunk=50)) >= (n - 3) // 50


def test_original_clause_ids_and_cube_units_after_them() -> None:
    """Hints refer to clause IDs of CNF(F, C): base clauses 1..M, cube units M+1..M+d."""
    f = formula(4, [(1, 2, 3, 4), (-4,), (-1, 4), (-2, -3)])
    result = up.propagate(up.build_index(f), (2, 3))
    assert result.trail == (-4, 2, 3, -1)
    assert result.reasons == (2, 5, 6, 3)
    assert result.conflict_clause == 4
    assert up.refutation(up.build_index(f), (2, 3)) == b"7 0 2 5 6 3 4 0\n"


def test_noncanonical_or_out_of_range_cubes_are_refused() -> None:
    index = up.build_index(formula(3, [(1, 2)]))
    cases = [
        ((2, 1), "cube.canonical"),
        ((1, -1), "cube.canonical"),
        ((4,), "cube.range"),
        ((0,), "schema"),
    ]
    for cube, rule in cases:
        with pytest.raises(ContractError) as caught:
            up.propagate(index, cube)
        assert caught.value.rule == rule


def test_proofs_need_a_conflict_of_the_same_formula() -> None:
    f = formula(2, [(1,), (-1, 2)])
    g = formula(2, [(1,), (-1, -2)])
    sat = up.propagate(up.build_index(f), ())
    with pytest.raises(ValueError, match="without a conflict"):
        up.unit_proof(up.build_index(f), sat)
    conflict = up.propagate(up.build_index(g), (2,))
    assert conflict.conflict
    with pytest.raises(ValueError, match="another formula"):
        up.unit_proof(up.build_index(f), conflict)


def test_an_index_must_be_built_completely() -> None:
    f = formula(1, [(1,), (-1,)])
    bare = up.UnitIndex(f)  # constructed, never filled
    with pytest.raises(ValueError, match="incomplete"):
        up.propagate(bare, ())
    conflict = up.propagate(up.build_index(f), ())
    with pytest.raises(ValueError, match="incomplete"):
        up.unit_proof(bare, conflict)


def test_chunk_must_be_positive() -> None:
    f = formula(1, [(1,)])
    for bad in (0, -1, 1.5, True):
        with pytest.raises(ValueError):
            up.drive(up.build_index_steps(f, chunk=bad))  # type: ignore[arg-type]
        with pytest.raises(ValueError):
            up.drive(up.propagate_steps(up.build_index(f), (), chunk=bad))  # type: ignore[arg-type]


def test_assigned_variables_for_split_exclusion() -> None:
    """Specification §9.1: dynamic selection excludes variables assigned by UP under the parent
    cube."""
    f = formula(5, [(-1, 2), (-2, 3), (4, 5)])
    result = up.propagate(up.build_index(f), (1,))
    assert not result.conflict and not result.complete
    assert result.assigned() == frozenset({1, 2, 3})


def test_a_propagated_model_is_evaluated_not_trusted() -> None:
    f = formula(3, [(1, 2), (-1, 3), (-2, -3)])
    result = up.propagate(up.build_index(f), (-3,))
    model = propagated_model(f, result)
    assert (model.assignment, model.model_error) == ("Ag==", None)
    # a forged "complete" propagation that does not satisfy F is caught by evaluation
    forged = up.Propagation(f.sha256, 3, 3, (-3,), (-3, 1, 2), (4, 1, 1), None)
    bad = propagated_model(f, forged)
    assert bad.model_error is ModelError.VIOLATED and bad.assignment == "Aw=="
    assert bad.violated_clause == 2
    # an incomplete or conflicting propagation is no model candidate
    partial = up.propagate(up.build_index(formula(2, [(1, 2)])), ())
    with pytest.raises(ValueError):
        propagated_model(formula(2, [(1, 2)]), partial)
    # a propagation of another formula (same V, different clauses) is refused
    other = formula(3, [(1, 2), (-1, 3), (-2, 3)])
    with pytest.raises(ValueError, match="another formula"):
        propagated_model(other, result)
    with pytest.raises(ValueError, match="another formula"):
        propagated_model(formula(4, [(1, 2), (-1, 3), (-2, -3)]), result)


def test_the_algorithm_name() -> None:
    assert up.UNIT_ALGORITHM == "unit-v1"
