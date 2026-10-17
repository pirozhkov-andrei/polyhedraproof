"""Truthful tiny evidence versus brute force and the naive oracle (specification §10.2-§10.4,
§15.1).

Random tiny campaigns (V <= 4) get random split graphs with alternatives, verified attempts
only on nodes whose CNF(F, C) is really unsatisfiable, and models that really satisfy. Then:

- soundness by brute force: a proved formula, a closed root and every used leaf are UNSAT;
- the open lists cover every satisfying assignment of each requested root (and each formula)
  exactly once, so the frontier is disjoint and complete below its roots;
- formulas, open lists, used attempts and verdict equal the naive recursive oracle;
- the certificate does not depend on the order of the journal files.
"""

from __future__ import annotations

import random
from pathlib import Path
from typing import Any

import pytest
from cp_certify_support import (
    OTHER_HASH,
    JournalBuilder,
    Scenario,
    certificate_problems,
    children,
    dimacs,
    machinery,
    oracle_expectation,
    satisfying,
    schema_errors,
    within,
)

from cubeproof.evidence.certify import certify

SEEDS = range(48)


def random_formula(rng: random.Random, variables: int) -> bytes:
    clauses = []
    for _ in range(rng.randint(1, 3 * variables)):
        width = rng.randint(1, min(3, variables))
        chosen = rng.sample(range(1, variables + 1), width)
        clauses.append([v if rng.random() < 0.5 else -v for v in chosen])
    if rng.random() < 0.3:
        # Contradictory units somewhere in the clause list: every cube is unsatisfiable.
        variable = rng.randint(1, variables)
        position = rng.randint(0, len(clauses))
        clauses[position:position] = [[variable], [-variable]]
    return dimacs(variables, clauses)


def random_roots(rng: random.Random, keys: list[str], variables: int) -> list[tuple[str, Any]]:
    roots: list[tuple[str, Any]] = []
    for key in keys:
        shape = rng.random()
        if shape < 0.5:
            roots.append((key, ()))
        else:
            width = 1 if shape < 0.8 or variables < 2 else 2
            w = rng.sample(range(1, variables + 1), width)
            pick = rng.sample(children((), w), rng.randint(1, 1 << width))
            roots += [(key, c) for c in pick]
    return roots


def explore(
    rng: random.Random,
    scenario: Scenario,
    journals: list[JournalBuilder],
    key: str,
    cube: tuple[int, ...],
    depth: int,
) -> None:
    formula = scenario.formulas[key]
    variables = scenario.variables(key)
    free = [v for v in range(1, variables + 1) if v not in {abs(x) for x in cube}]
    models = satisfying(formula, cube)
    journal = rng.choice(journals)
    roll = rng.random()
    # Few attempts near the roots, so that selected proof trees use splits of depth >= 2.
    if not models and roll < (0.15, 0.6, 0.8, 0.9)[min(depth, 3)]:
        journal.unsat(key, cube, route=rng.choice(["unit", "cdcl"]))
        if rng.random() < 0.2:
            rng.choice(journals).unsat(key, cube)
        if rng.random() < 0.3:
            return
    elif models and roll < 0.25:
        values = rng.choice(models)
        outcome = "MODEL" if rng.random() < 0.8 else "INVALID_MODEL"
        journal.model(key, cube, values, outcome=outcome, route=rng.choice(["unit", "cdcl"]))
        if rng.random() < 0.5:
            return
    elif roll < 0.35:
        journal.failed(key, cube, "EXHAUSTED", "time")
    if not free or depth >= 3 or rng.random() < 0.3:
        return
    for _ in range(1 if rng.random() < 0.7 else 2):
        w = rng.sample(free, rng.randint(1, min(2, len(free))))
        rng.choice(journals).record_split_fact(key, cube, w)
        for child in children(cube, w):
            explore(rng, scenario, journals, key, child, depth + 1)


def build(tmp_path: Path, seed: int) -> tuple[Scenario, list[Path]]:
    rng = random.Random(seed)
    variables = rng.randint(1, 4)
    keys = sorted(rng.sample(["f", "g", "h"], rng.randint(1, 2)))
    formulas: dict[str, bytes] = {}
    for key in keys:
        formula = random_formula(rng, variables)
        while formula in formulas.values():  # campaign formula hashes are unique
            formula = random_formula(rng, variables)
        formulas[key] = formula
    roots = random_roots(rng, keys, variables)
    root_splits = []
    if rng.random() < 0.4:
        key = rng.choice(keys)
        root_splits.append((key, (), rng.sample(range(1, variables + 1), 1)))
    scenario = Scenario(tmp_path, formulas, roots=roots, root_splits=root_splits)
    journals = [scenario.journal(f"w{i}") for i in range(rng.randint(1, 3))]
    if rng.random() < 0.4:
        journals.append(
            scenario.journal("foreign", machinery=machinery(checker=OTHER_HASH), admitted=False)
        )
    starts = {(k, ()) for k in keys} | {(k, tuple(c)) for k, c in roots}
    starts |= {(k, child) for k, cube, w in root_splits for child in children(cube, w)}
    for key, cube in sorted(starts, key=lambda s: (s[0], len(s[1]), s[1])):
        explore(rng, scenario, journals, key, cube, len(cube))
    paths = [j.write(f"{j.records[0]['worker']}.jsonl") for j in journals]
    return scenario, paths


@pytest.mark.parametrize("seed", SEEDS)
def test_truthful_random_evidence(tmp_path: Path, seed: int) -> None:
    scenario, paths = build(tmp_path, seed)
    result = certify(scenario.campaign_path, paths)
    certificate = result.certificate
    assert schema_errors(certificate) == []
    assert certificate_problems(certificate) == []

    # soundness against brute force, independent of any certifier logic
    formulas = {scenario.sha(k): data for k, data in scenario.formulas.items()}
    for entry in certificate["formulas"]:
        formula = formulas[entry["formula_sha256"]]
        if entry["proved"]:
            assert satisfying(formula) == []
        for root in entry["roots"]:
            if root["closed"]:
                assert satisfying(formula, root["cube"]) == []
    for used in certificate["used_attempts"]:
        assert satisfying(formulas[used["node"]["formula_sha256"]], used["node"]["cube"]) == []
    for model in certificate["models"]:
        assert satisfying(formulas[model["node"]["formula_sha256"]], model["node"]["cube"])

    # the frontier is a disjoint cover of the satisfying assignments below each start
    for field, starts in (
        ("open", scenario.roots),
        ("formula_open", [(scenario.sha(k), ()) for k in scenario.formulas]),
    ):
        entries = certificate[field]
        for formula_sha, cube in starts:
            mine = [
                e["node"]["cube"]
                for e in entries
                if e["node"]["formula_sha256"] == formula_sha
                and all(x in e["node"]["cube"] for x in cube)
            ]
            for values in satisfying(formulas[formula_sha], cube):
                assert sum(within(values, c) for c in mine) == 1, (field, cube, values)

    # the naive oracle of specification §10.2-§10.3
    expected = oracle_expectation(scenario)
    assert certificate["formulas"] == expected["formulas"]
    assert certificate["open"] == expected["open"]
    assert certificate["formula_open"] == expected["formula_open"]
    assert [u["node_id"] for u in certificate["used_attempts"]] == expected["used"]
    assert certificate["verdict"] == expected["verdict"]
    assert expected["verdict"] != "INCONSISTENT"

    # input order has no effect
    shuffled = list(reversed(paths))
    random.Random(seed).shuffle(shuffled)
    assert certify(scenario.campaign_path, shuffled).document == result.document


def test_the_random_scenarios_cover_every_verdict_and_shape(tmp_path: Path) -> None:
    """The seeds above exercise alternatives, models, non-admitted journals and all verdicts."""
    verdicts = set()
    alternatives = nonadmitted = models = deep = 0
    for seed in SEEDS:
        scenario, paths = build(tmp_path / str(seed), seed)
        result = certify(scenario.campaign_path, paths)
        verdicts.add(result.certificate["verdict"])
        alternatives += any(len(v) > 1 for v in scenario.facts.splits.values())
        nonadmitted += bool(result.certificate["not_admitted"])
        models += bool(result.certificate["models"])
        deep += any(f["summary"]["splits"] >= 2 for f in result.certificate["formulas"])
    assert verdicts == {"PROVED", "OPEN", "MODEL_FOUND"}
    assert alternatives >= 5
    assert nonadmitted >= 5
    assert models >= 5
    assert deep >= 3
