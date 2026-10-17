"""Test-only helpers of the unit/model tests: tiny formulas and independent oracles.

The oracles here share no code with ``cubeproof.cnf.unit``/``cubeproof.cnf.model``: a naive
fixpoint propagation, brute force over all assignments, and the test LRAT validator
(``tests/fakes/lrat_check.py``) and DIMACS/model reader (``tests/fakes/cnf_model.py``).
"""

from __future__ import annotations

import itertools
import random
import sys
from collections.abc import Iterator, Sequence
from pathlib import Path

from cubeproof.cnf.cubecnf import cube_cnf_bytes
from cubeproof.cnf.dimacs import Formula, canonical_dimacs, parse_dimacs

REPO = Path(__file__).resolve().parents[4]
SHARED_TESTS = REPO / "tests"
if str(SHARED_TESTS) not in sys.path:
    sys.path.insert(0, str(SHARED_TESTS))

from fakes import cnf_model, fixture_files, lrat_check  # noqa: E402

__all__ = [
    "CORPORA",
    "REPO",
    "UNIT_VECTORS",
    "all_assignments",
    "brute_force_satisfiable",
    "cnf_model",
    "fixture_files",
    "formula",
    "lrat_check",
    "naive_propagation",
    "oracle_accepts",
    "random_cases",
    "satisfies",
]

Clause = tuple[int, ...]

#: The random corpora of the truth-table and hint-structure tests; the image tier checks
#: every proof of the same corpora with the pinned cake_lpr.
CORPORA: tuple[tuple[int, int], ...] = ((20261007, 1500), (7, 800))

#: Exact unit-v1 vectors: (V, clauses, cube, proof bytes or None). The proof bytes pin the
#: deterministic algorithm of ``cubeproof.cnf.unit`` (specification §11.2: same profile, same proof
#: hash).
UNIT_VECTORS: list[tuple[int, list[Clause], Clause, bytes | None]] = [
    # propagation chain to a conflict: units 4, 5 (cube), then clause 2 implies 3, clause 3 dies
    (3, [(1, 2), (-1, 3), (-2, -3)], (1, 2), b"6 0 4 5 2 3 0\n"),
    # a conflict among the seeds: F unit 1 against cube unit -1
    (1, [(1,)], (-1,), b"3 0 1 2 0\n"),
    # the first empty clause, whatever else there is
    (2, [(1,), (), ()], (2,), b"5 0 2 0\n"),
    (0, [()], (), b"2 0 1 0\n"),
    # a repeated falsified literal needs no restatement; the conflict clause neither
    (2, [(1, 1, 2), (-2,), (-1,)], (), b"4 0 2 3 1 0\n"),
    # a repeated falsified literal in a reason clause (not the conflict) needs no
    # restatement either: only a repeated implied literal is restated (unit-v1)
    (3, [(1, 2, 2), (-2,), (-1, 3), (-3,)], (), b"5 0 2 4 1 3 0\n"),
    # the implied literal 1 is repeated in reason clause 1: restated as lemma 5 first
    (3, [(1, 1, 2), (-2,), (-1, 3), (-3,)], (), b"5 1 2 0 1 0\n6 0 2 4 5 3 0\n"),
    # a unit clause written with a repeated literal
    (1, [(1, 1), (-1,)], (), b"3 1 0 1 0\n4 0 3 2 0\n"),
    # hints use original IDs: F unit 2, cube units 5 and 6, clause 3 implies -1, clause 4 dies
    (4, [(1, 2, 3, 4), (-4,), (-1, 4), (-2, -3)], (2, 3), b"7 0 2 5 6 3 4 0\n"),
    # a tautology never propagates
    (2, [(1, -1, 2), (-2,)], (), None),
    # complete without conflict: a model candidate, no proof
    (3, [(1, 2), (-1, 3), (-2, -3)], (-3,), None),
    # the empty formula
    (0, [], (), None),
]


def formula(variables: int, clauses: Sequence[Sequence[int]]) -> Formula:
    """The canonical formula of the given clauses (literal and clause order kept)."""
    return parse_dimacs(canonical_dimacs(variables, clauses))


def satisfies(
    clauses: Sequence[Sequence[int]], cube: Sequence[int], values: Sequence[bool]
) -> bool:
    """Every clause and every cube unit is true under ``values`` (values[i-1] = variable i)."""

    def true(literal: int) -> bool:
        return values[abs(literal) - 1] == (literal > 0)

    return all(any(true(x) for x in c) for c in clauses) and all(true(x) for x in cube)


def all_assignments(variables: int) -> Iterator[tuple[bool, ...]]:
    return itertools.product((False, True), repeat=variables)


def brute_force_satisfiable(
    variables: int, clauses: Sequence[Sequence[int]], cube: Sequence[int]
) -> bool:
    return any(satisfies(clauses, cube, v) for v in all_assignments(variables))


def naive_propagation(
    clauses: Sequence[Sequence[int]], cube: Sequence[int]
) -> tuple[bool, dict[int, bool]]:
    """(conflict, assignment) of the unit propagation fixpoint, by repeated full scans."""
    value: dict[int, bool] = {}
    work = [tuple(c) for c in clauses] + [(x,) for x in cube]
    changed = True
    while changed:
        changed = False
        for clause in work:
            if any(value.get(abs(x)) == (x > 0) for x in clause):
                continue
            open_literals = {x for x in clause if abs(x) not in value}
            if not open_literals:
                return True, value
            if len(open_literals) == 1:
                (literal,) = open_literals
                value[abs(literal)] = literal > 0
                changed = True
    return False, value


def oracle_accepts(f: Formula, cube: Sequence[int], proof: bytes) -> bool:
    """The test LRAT validator on CNF(F, C) and ``proof`` (not the trusted checker)."""
    cnf = cnf_model.parse_dimacs(cube_cnf_bytes(f, cube))
    return lrat_check.check(cnf, proof).verified


def random_cases(
    seed: int, count: int, *, max_variables: int = 6
) -> Iterator[tuple[int, list[Clause], tuple[int, ...]]]:
    """Random tiny (V, clauses, canonical cube) triples, including empty clauses, repeated
    literals, tautologies, unit clauses, V=0 and the empty cube."""
    rng = random.Random(seed)
    for _ in range(count):
        variables = rng.randint(0, max_variables)
        clauses: list[Clause] = []
        for _ in range(rng.randint(0, 3 * max_variables)):
            if variables == 0 or rng.random() < 0.02:
                if rng.random() < 0.5:
                    clauses.append(())
                continue
            size = rng.choice((1, 1, 2, 2, 2, 3, 3, 4))
            literal_choices = [v if rng.random() < 0.5 else -v for v in range(1, variables + 1)]
            clause = [rng.choice(literal_choices) for _ in range(size)]
            if rng.random() < 0.1:
                clause.append(clause[0])  # a repeated literal
            if rng.random() < 0.05:
                clause.append(-clause[0])  # a tautology
            clauses.append(tuple(clause))
        depth = rng.randint(0, variables)
        chosen = sorted(rng.sample(range(1, variables + 1), depth))
        cube = tuple(v if rng.random() < 0.5 else -v for v in chosen)
        yield variables, clauses, cube
