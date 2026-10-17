"""The status of an audit target from its new attempt (specification §11.2).

The attempts are the corpus fixtures ``attempt-<preset>`` (one per outcome and reason); the
target is the historical leaf of the same node. Covered here: a mismatched proof
that is still valid (MISMATCH, exit 4), an unexpected SAT model (an inconsistency, never
NOT_COMPARABLE), missing source tools (NOT_COMPARABLE), no silent tool swap (a different
solver is a reproof, not a match).
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

import cp_audit_support as s

from cubeproof.commands.audit_compare import (
    INTEGRITY_FAILURES,
    TOOL_FAILURES,
    Classified,
    classify_attempt,
    classify_unavailable,
    exit_class,
    failure_code,
    profile_differences,
    reported_differences,
    strict_runnable,
)
from cubeproof.contracts.campaign import Admit
from cubeproof.contracts.enums import AuditStatus, Route
from cubeproof.contracts.identity import node_id
from cubeproof.evidence.schema import (
    Attempt,
    AuditTarget,
    Header,
    Machinery,
    check_record,
)

OTHER = "0f" * 32


def corpus_machinery() -> Machinery:
    line = s.corpus_lines("journals/base/w1.jsonl")[0]
    header = check_record(json.loads(line)).payload
    assert isinstance(header, Header)
    return header.machinery


M = corpus_machinery()
ADMIT = Admit.from_json({"checker_sha256": [M.checker.sha256], "solvers": None}, "$")


def attempt(preset: str, **changes: Any) -> Attempt:
    value = s.attempt_value(preset)
    if value["route"] == "cdcl":
        value["limits"] = {**value["limits"], "solver_time_ms": None}
    value.update(changes)
    return s.typed_attempt(value)


def target_of(found: Attempt, machinery: Machinery = M, proof: str | None = None) -> AuditTarget:
    target: AuditTarget = AuditTarget.from_json(
        {
            "node": found.node.to_json(),
            "node_id": found.node_id,
            "source": {"journal": OTHER, "seq": 7},
            "cnf_sha256": found.cnf_sha256,
            "proof_sha256": proof or found.proof_sha256 or "1e" * 32,
            "route": found.route.value,
            "machinery": machinery.to_json(),
        }
    )
    return target


def machinery(manifest: dict[str, str] | None = None, **changes: Any) -> Machinery:
    """``M`` with nested fields replaced (``runtime={"libc": "musl"}``) and source manifest
    entries changed (``manifest={path: sha256}``; both digests recomputed as specification §4.6
    says)."""
    value = M.to_json()
    for name, change in changes.items():
        value[name] = {**value[name], **change} if isinstance(change, dict) else change
    if manifest:
        entries = [
            {**e, "sha256": manifest.get(e["path"], e["sha256"])} for e in value["source_manifest"]
        ]
        own = [e for e in entries if e["path"].split("/", 1)[0] == "cubeproof"]
        value.update(
            source_manifest=entries,
            packages_sha256=hashlib.sha256(s.j(entries)).hexdigest(),
            cubeproof_sha256=hashlib.sha256(s.j(own)).hexdigest(),
        )
    found: Machinery = Machinery.from_json(value)
    return found


def classify(found: Attempt, target: AuditTarget, audit: Machinery = M) -> Classified:
    return classify_attempt(target, found, audit, ADMIT)


# -- verified proofs ----------------------------------------------------------------------------


@pytest.mark.parametrize("preset", ["vu_cdcl", "vu_unit", "audit-unlimited"])
def test_the_same_proof_under_the_strict_profile_is_a_hash_match(preset: str) -> None:
    found = attempt(preset)
    result = classify(found, target_of(found))
    assert result == Classified(AuditStatus.HASH_MATCHED, "")
    assert exit_class(result.status, result.reason) == 0


@pytest.mark.parametrize("preset", ["vu_cdcl", "vu_unit"])
def test_a_different_proof_that_passed_is_a_mismatch(preset: str) -> None:
    found = attempt(preset)
    result = classify(found, target_of(found, proof="2b" * 32))
    assert result.status == AuditStatus.MISMATCH
    assert "2b" * 32 in result.reason and str(found.proof_sha256) in result.reason
    assert exit_class(result.status, result.reason) == 4


@pytest.mark.parametrize(
    ("change", "fields"),
    [
        ({"solver": {"sha256": OTHER}}, ["solver.sha256"]),
        ({"solver": {"argv": ["--lrat", "--seed=2"]}}, ["solver.argv"]),
        ({"runtime": {"libc": "musl 1.2"}}, ["runtime.libc"]),
        ({"runtime": {"platform": "Linux-6.0-aarch64"}}, ["runtime.platform"]),
    ],
)
def test_another_cdcl_profile_is_a_reproof_never_a_match(
    change: dict[str, Any], fields: list[str]
) -> None:
    found = attempt("vu_cdcl")
    target = target_of(found)
    audit = machinery(**change)
    assert list(profile_differences(target, audit)) == fields
    for proof in (None, "2b" * 32):  # equal or different hash: still only a reproof
        result = classify(found, target_of(found, proof=proof), audit)
        assert result.status == AuditStatus.REPROVED_UNSAT
        assert fields[0] in result.reason and "not a historical match" in result.reason
        assert exit_class(result.status, result.reason) == 1


def test_unit_profile_is_the_unit_algorithm_and_the_package() -> None:
    found = attempt("vu_unit")
    target = target_of(found)
    other_package = machinery(manifest={"cubeproof/__init__.py": OTHER})
    assert profile_differences(target, other_package) == ("cubeproof_sha256",)
    assert classify(found, target, other_package).status == AuditStatus.REPROVED_UNSAT
    # a different solver or libc does not change a unit proof: reported, still a match
    audit = machinery(solver={"sha256": OTHER}, runtime={"libc": "musl"})
    result = classify(found, target, audit)
    assert result.status == AuditStatus.HASH_MATCHED
    assert "solver.sha256" in result.reason and "runtime.libc" in result.reason


def test_other_differences_are_reported_without_changing_a_match() -> None:
    found = attempt("vu_cdcl")
    audit = machinery(runtime={"python": "3.13.0"}, manifest={"neighbourly/__init__.py": OTHER})
    target = target_of(found)
    assert set(reported_differences(target, audit)) == {"runtime.python", "packages_sha256"}
    result = classify(found, target, audit)
    assert result.status == AuditStatus.HASH_MATCHED
    assert result.reason.startswith("reported differences: ")


# -- failures and open results ---------------------------------------------------------------


@pytest.mark.parametrize(
    ("preset", "status", "code", "exit"),
    [
        ("exhausted_time", AuditStatus.OPEN, None, 1),
        ("exhausted_proof_size", AuditStatus.OPEN, None, 1),
        ("exhausted_check_memory", AuditStatus.OPEN, None, 1),
        ("exhausted_solver_memory", AuditStatus.OPEN, None, 1),
        ("failed_crash", AuditStatus.FAILED, "tool_failed", 5),
        ("failed_launch", AuditStatus.FAILED, "tool_failed", 5),
        ("failed_io", AuditStatus.FAILED, "tool_failed", 5),
        ("rejected", AuditStatus.FAILED, "rejected", 4),
        ("invalid_violated", AuditStatus.FAILED, "invalid_model", 5),
        ("invalid_syntax", AuditStatus.FAILED, "invalid_model", 5),
        ("model_cdcl", AuditStatus.FAILED, "inconsistent_model", 4),
        ("model_unit", AuditStatus.FAILED, "inconsistent_model", 4),
    ],
)
def test_outcomes_other_than_a_proof(
    preset: str, status: AuditStatus, code: str | None, exit: int
) -> None:
    found = attempt(preset)
    result = classify(found, target_of(found))
    assert result.status == status
    if code is not None:
        assert failure_code(result.reason) == code
    else:
        assert result.reason == f"exhausted: {found.reason}"
    assert exit_class(result.status, result.reason) == exit
    if code is not None:
        named = code in INTEGRITY_FAILURES if exit == 4 else code in TOOL_FAILURES
        assert named, f"{code} is not in the declared exit table"


def test_the_failure_tables_are_disjoint_and_cover_every_code() -> None:
    assert not INTEGRITY_FAILURES & TOOL_FAILURES
    ids = [e["id"] for e in s.document_entries("journal-record")]
    presets = [i[len("attempt-") :] for i in ids if i.startswith("attempt-")]
    produced = set()
    for preset in (p for p in presets if "-" not in p):  # one fixture per outcome and reason
        found = attempt(preset)
        result = classify(found, target_of(found))
        if result.status == AuditStatus.FAILED:
            produced.add(failure_code(result.reason))
    produced |= {"attempt_mismatch", "checker_not_admitted", "solver_not_admitted"}
    assert produced == INTEGRITY_FAILURES | TOOL_FAILURES


def test_a_model_is_an_inconsistency_whatever_the_profile_or_admission() -> None:
    found = attempt("model_cdcl")
    target = target_of(found)
    for audit in (machinery(solver={"sha256": OTHER}), machinery(checker={"sha256": OTHER})):
        result = classify(found, target, audit)
        assert failure_code(result.reason) == "inconsistent_model"
        assert result.status != AuditStatus.NOT_COMPARABLE


@pytest.mark.parametrize(
    "change",
    [
        {"node": {"formula_sha256": None, "cube": [-1]}},
        {"cnf_sha256": "77" * 32},
        {"limits": "solver_time"},
        {"route": "unit"},
    ],
)
def test_an_attempt_that_is_not_of_the_target_fails(change: dict[str, Any]) -> None:
    found = attempt("vu_cdcl")
    target = target_of(found).to_json()
    if "node" in change:
        node = {**target["node"], "cube": change["node"]["cube"]}
        target.update(node=node, node_id=node_id(node["formula_sha256"], node["cube"]))
    elif "cnf_sha256" in change:
        target["cnf_sha256"] = change["cnf_sha256"]
    elif "route" in change:
        target["route"] = change["route"]
    else:
        value = s.attempt_value("vu_cdcl")
        found = s.typed_attempt(value)  # the run's attempt keeps its solver time limit
        assert found.limits.solver_time_ms is not None
    result = classify(found, AuditTarget.from_json(target))
    assert failure_code(result.reason) == "attempt_mismatch"
    assert exit_class(result.status, result.reason) == 4


def test_machinery_not_admitted_by_the_campaign_fails() -> None:
    found = attempt("vu_cdcl")
    target = target_of(found)
    result = classify(found, target, machinery(checker={"sha256": OTHER}))
    assert failure_code(result.reason) == "checker_not_admitted"
    assert exit_class(result.status, result.reason) == 5
    restricted = Admit.from_json(
        {"checker_sha256": [M.checker.sha256], "solvers": [{"sha256": OTHER, "argv": ["--lrat"]}]},
        "$",
    )
    result = classify_attempt(target, found, M, restricted)
    assert failure_code(result.reason) == "solver_not_admitted"


# -- strict audits without the source solver -----------------------------------------------------


def test_strict_runs_only_the_source_solver() -> None:
    found = attempt("vu_cdcl")
    target = target_of(found)
    source = M.solver
    assert strict_runnable(target, source.sha256, source.argv)
    assert not strict_runnable(target, OTHER, source.argv)
    assert not strict_runnable(target, source.sha256, ("--lrat", "--seed=2"))
    unit = attempt("vu_unit")
    assert strict_runnable(target_of(unit), OTHER, ())
    result = classify_unavailable(target, machinery(solver={"sha256": OTHER}))
    assert result.status == AuditStatus.NOT_COMPARABLE
    assert "solver.sha256" in result.reason
    assert exit_class(result.status, result.reason) == 1


def test_exit_classes() -> None:
    assert exit_class(AuditStatus.HASH_MATCHED, "") == 0
    assert exit_class(AuditStatus.MISMATCH, "x") == 4
    assert exit_class(AuditStatus.NOT_COMPARABLE, "x") == 1
    assert exit_class(AuditStatus.REPROVED_UNSAT, "x") == 1
    assert exit_class(AuditStatus.OPEN, "x") == 1
    assert exit_class(AuditStatus.FAILED, "tool_failed: crash") == 5
    assert exit_class(AuditStatus.FAILED, "rejected: x") == 4
    assert exit_class(AuditStatus.FAILED, "something else") == 4  # unknown: most severe
    assert Route.CDCL.value == "cdcl"
