"""Audit population, seeded selection and the committed plan (specification §11.1).

Expected values of the selection rule come from the frozen specification vector
``vectors/selection.json`` (written by the specification script, not by this code).
Covered here: sample determinism, plan regeneration and comparison on restart (crash
during the plan), the empty population.
"""

from __future__ import annotations

import copy
import hashlib
import random
import sys
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

import cp_audit_support as s

from cubeproof.base.errors import ConfigurationError, IntegrityError
from cubeproof.commands.audit_inputs import BoundInputs, bind_certified_inputs
from cubeproof.commands.audit_plan import (
    AuditPlan,
    Selection,
    check_plan_prefix,
    make_plan,
    parse_seed,
    percent_count,
    population_of,
    sample_key,
    select_node_ids,
    target_sha256,
    targets_sha256,
)
from cubeproof.contracts.enums import AuditComparison
from cubeproof.evidence.certify.run import CertifyResult
from cubeproof.evidence.schema import AuditBegin, AuditTarget

VECTOR = s.load(s.CORPUS / "vectors" / "selection.json")
SEED = "5e" * 32


def bound_case(tmp_path: Path, case: str) -> BoundInputs:
    files = s.corpus_case(tmp_path, case)
    return bind_certified_inputs(
        files.campaign, files.journals, files.certificate, files.root / "snapshots"
    )


# -- the selection rule -------------------------------------------------------------------------


def test_the_selection_vector() -> None:
    sample = VECTOR["audit_sample"]
    for entry in sample["ranked"]:
        assert sample_key(sample["seed"], entry["node_id"]) == entry["key"]
    chosen = select_node_ids(sample["population"], sample["n"], sample["seed"])
    assert list(chosen) == sample["selected"]


def test_target_hashes_of_the_vector() -> None:
    vector = VECTOR["targets"]
    targets = [AuditTarget.from_json(t) for t in vector["targets"]]
    assert [target_sha256(t) for t in targets] == vector["target_hashes"]
    assert targets_sha256(targets) == vector["targets_sha256"]
    assert targets_sha256([]) == hashlib.sha256(b"").hexdigest()


def test_selection_is_deterministic_and_independent_of_input_order() -> None:
    population = [hashlib.sha256(str(i).encode()).hexdigest() for i in range(200)]
    first = select_node_ids(population, 17, SEED)
    shuffled = list(population)
    random.Random(7).shuffle(shuffled)
    assert select_node_ids(shuffled, 17, SEED) == first
    assert select_node_ids(population + population[:5], 17, SEED) == first
    assert list(first) == sorted(first) and len(first) == 17
    assert select_node_ids(population, 17, "5f" * 32) != first  # the seed matters
    ranked = sorted((sample_key(SEED, n), n) for n in population)
    assert set(first) == {n for _, n in ranked[:17]}


def test_count_is_clamped_and_must_be_positive() -> None:
    population = ["0" * 63 + str(i) for i in range(3)]
    assert select_node_ids(population, 50, SEED) == tuple(sorted(population))
    assert select_node_ids(population, None, SEED) == tuple(sorted(population))
    assert select_node_ids([], 5, SEED) == ()
    for bad in (0, -1, True):
        with pytest.raises(ConfigurationError):
            select_node_ids(population, bad, SEED)
        with pytest.raises(ConfigurationError):
            Selection(sample=bad)


def test_a_percent_sample_counts_targets_not_lines() -> None:
    assert percent_count(0, 5) == 0
    assert percent_count(1, 5) == 1
    assert percent_count(20, 5) == 1
    assert percent_count(21, 5) == 2
    assert percent_count(1000, 5) == 50
    assert all(percent_count(n, 5) == -(-n // 20) for n in range(500))


def test_a_seed_is_a_lowercase_hash() -> None:
    assert parse_seed(SEED) == SEED
    for bad in (SEED.upper(), SEED[:-1], "x" * 64):
        with pytest.raises(ConfigurationError):
            parse_seed(bad)


# -- population and plan -----------------------------------------------------------------------


def test_the_population_is_the_recomputed_used_list_with_source_snapshots(
    tmp_path: Path,
) -> None:
    bound = bound_case(tmp_path, "modes")
    targets = population_of(bound)
    certificate = bound.recertified.certificate
    assert [t.node_id for t in targets] == [u["node_id"] for u in certificate["used_attempts"]]
    snapshots = {
        (m["journal"], m["snapshot_seq"]): m["machinery"] for m in certificate["machinery"]
    }
    for target, used in zip(targets, certificate["used_attempts"], strict=True):
        assert target.source.to_json() == used["record"]
        assert (target.cnf_sha256, target.proof_sha256) == (
            used["cnf_sha256"],
            used["proof_sha256"],
        )
        assert target.machinery.to_json() in snapshots.values()
    # the two sources are under different snapshots (a header and a later resume)
    assert targets[0].machinery != targets[1].machinery or len(set(snapshots)) == 2


def test_a_used_entry_that_its_record_does_not_support_is_refused(tmp_path: Path) -> None:
    bound = bound_case(tmp_path, "base")
    certificate = copy.deepcopy(bound.recertified.certificate)
    certificate["used_attempts"][0]["proof_sha256"] = "ab" * 32
    forged = replace(bound, recertified=CertifyResult(certificate, bound.recertified.inputs))
    with pytest.raises(IntegrityError) as caught:
        population_of(forged)
    assert caught.value.rule == "audit.source"
    certificate = copy.deepcopy(bound.recertified.certificate)
    certificate["machinery"][0]["snapshot_seq"] = 1
    forged = replace(bound, recertified=CertifyResult(certificate, bound.recertified.inputs))
    with pytest.raises(IntegrityError) as caught:
        population_of(forged)
    assert caught.value.rule == "audit.source"


def test_all_selects_the_population_with_the_default_seed(tmp_path: Path) -> None:
    bound = bound_case(tmp_path, "base")
    plan = make_plan(bound, Selection(sample=None))
    assert plan.population == plan.target_count == plan.sample_count == 3
    assert plan.seed == bound.certificate.sha256
    assert plan.comparison == AuditComparison.STRICT
    assert plan.begin() == AuditBegin(
        certificate_sha256=bound.certificate.sha256,
        sample_count=3,
        seed=plan.seed,
        targets_sha256=plan.targets_sha256,
        target_count=3,
        comparison=AuditComparison.STRICT,
    )
    middle = [plan.target_record(i) for i in range(3)]
    assert [m.ordinal for m in middle] == [0, 1, 2]
    assert [m.target for m in middle] == list(plan.targets)
    assert plan.payloads() == (plan.begin(), *middle, plan.ready())
    ready = plan.ready()
    assert (ready.targets_sha256, ready.target_count) == (plan.targets_sha256, 3)


def test_a_sample_is_reproducible_from_the_preserved_inputs(tmp_path: Path) -> None:
    bound = bound_case(tmp_path / "a", "base")
    selection = Selection(sample=2, seed=SEED, comparison=AuditComparison.REPROVE)
    plan = make_plan(bound, selection)
    population = [t.node_id for t in population_of(bound)]
    assert [t.node_id for t in plan.targets] == list(select_node_ids(population, 2, SEED))
    assert (plan.sample_count, plan.target_count, plan.population) == (2, 2, 3)
    again = make_plan(bound_case(tmp_path / "b", "base"), selection)
    assert again == plan
    restarted = bind_certified_inputs(
        bound.campaign.path, [], Path(bound.certificate.path), bound.snapshots[0].parent
    )
    assert make_plan(restarted, selection) == plan
    clamped = make_plan(bound, Selection(sample=10, seed=SEED))
    assert (clamped.sample_count, clamped.target_count) == (10, 3)


def test_an_empty_population_gives_an_empty_plan(tmp_path: Path) -> None:
    bound = bound_case(tmp_path, "split_incomplete")
    plan = make_plan(bound, Selection(sample=5))
    assert (plan.population, plan.target_count, plan.sample_count) == (0, 0, 5)
    assert plan.targets_sha256 == hashlib.sha256(b"").hexdigest()


# -- restart: the plan prefix --------------------------------------------------------------------


def _plan(tmp_path: Path) -> AuditPlan:
    return make_plan(bound_case(tmp_path, "base"), Selection(sample=None))


def test_a_partial_plan_is_completed_from_the_regenerated_plan(tmp_path: Path) -> None:
    plan = _plan(tmp_path)
    assert check_plan_prefix(plan, None, [], None) == 0
    assert check_plan_prefix(plan, plan.begin(), [], None) == 0
    assert check_plan_prefix(plan, plan.begin(), plan.targets[:2], None) == 2
    assert check_plan_prefix(plan, plan.begin(), plan.targets, plan.ready()) == 3


def _changed(plan: AuditPlan, **fields: Any) -> AuditBegin:
    return replace(plan.begin(), **fields)


@pytest.mark.parametrize(
    "fields",
    [
        {"seed": "5f" * 32},
        {"sample_count": 2},
        {"comparison": AuditComparison.REPROVE},
        {"certificate_sha256": "ee" * 32},
    ],
)
def test_a_changed_begin_is_refused(tmp_path: Path, fields: dict[str, Any]) -> None:
    plan = _plan(tmp_path)
    with pytest.raises(IntegrityError) as caught:
        check_plan_prefix(plan, _changed(plan, **fields), [], None)
    assert caught.value.rule == "audit.plan_changed"


def test_changed_targets_or_ready_are_refused(tmp_path: Path) -> None:
    plan = _plan(tmp_path)
    swapped = [plan.targets[1], plan.targets[0]]
    for targets, ready in (
        (swapped, None),
        ([*plan.targets, plan.targets[0]], None),
        (plan.targets[:2], plan.ready()),
    ):
        with pytest.raises(IntegrityError) as caught:
            check_plan_prefix(plan, plan.begin(), targets, ready)
        assert caught.value.rule == "audit.plan_changed"
    with pytest.raises(IntegrityError):
        check_plan_prefix(plan, None, plan.targets[:1], None)
