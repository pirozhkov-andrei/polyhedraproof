"""The audit report and exit code from a plan and an audit journal (specification §11.2, §12.2).

Audit journals here are written from real certified inputs (corpus cases bound and planned by
the audit code) with the attempts a re-execution would record: the historical attempts
themselves (an exact reproduction, CDCL without a solver time limit), changed proofs, the
model of the corpus' lying journal, and placeholders. The report recomputes every result's
status from its attempt, so a journal cannot claim a match it does not show. Covered
here: real small audit matches (at the evidence level; executor runs: :mod:`test_cp_audit_run`),
mismatched proof still valid, unexpected SAT model, missing source tools, crash between an
attempt and its result, empty population, independent check of result claims.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Mapping
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

import cp_audit_support as s

from cubeproof.base.errors import ContractError, IntegrityError
from cubeproof.commands.audit_compare import Classified, failure_code
from cubeproof.commands.audit_inputs import BoundInputs, bind_certified_inputs
from cubeproof.commands.audit_journal import AuditJournal, CommittedResult, read_audit_journal
from cubeproof.commands.audit_plan import AuditPlan, Selection, make_plan
from cubeproof.commands.audit_report import (
    STATUSES,
    AuditReport,
    build_report,
    check_report,
    expected_result,
)
from cubeproof.contracts.enums import AuditComparison, AuditStatus, Outcome, Purpose, Route
from cubeproof.contracts.values import Ref
from cubeproof.evidence.schema import Attempt, AuditResult, Header, build_record, check_record

OTHER = "0f" * 32


@dataclass(frozen=True)
class World:
    """A bound corpus case, its run journal's header and attempts, and a place to write."""

    root: Path
    bound: BoundInputs
    header: Header
    header_line: bytes
    attempts: dict[str, Attempt]


def world(tmp_path: Path, case: str) -> World:
    files = s.corpus_case(tmp_path, case)
    bound = bind_certified_inputs(
        files.campaign, files.journals, files.certificate, files.root / "snapshots"
    )
    data = files.journals[0].read_bytes()
    records = s.records_of(data)
    header = records[0].payload
    assert isinstance(header, Header)
    attempts: dict[str, Attempt] = {}
    for record in records:
        payload = record.payload
        if isinstance(payload, Attempt) and payload.node_id not in attempts:
            attempts[payload.node_id] = unlimited(payload)
    line = data.split(b"\n")[0]
    return World(files.root, bound, header, s.audit_header(line), attempts)


def unlimited(attempt: Attempt) -> Attempt:
    """The attempt as an audit records it: CDCL without a solver time limit."""
    if attempt.route != Route.CDCL:
        return attempt
    return replace(attempt, limits=replace(attempt.limits, solver_time_ms=None))


def simulate(
    w: World,
    plan: AuditPlan,
    attempts: Mapping[str, Attempt],
    *,
    claims: Mapping[str, Classified] | None = None,
    header_line: bytes | None = None,
) -> AuditJournal:
    """Write the plan, then per target its attempt and the result the comparison rules give
    (or the given claim); read the journal back."""
    builder = s.Builder([header_line or w.header_line])
    for payload in plan.payloads():
        builder.add(payload)
    machinery = check_record(json.loads(builder.lines[0])).payload.machinery  # type: ignore[attr-defined]
    for target in plan.targets:
        found = attempts.get(target.node_id)
        if found is None:
            continue
        seq = builder.add(found).seq
        placeholder = AuditResult(target, Ref(builder.id, seq), AuditStatus.OPEN, "")
        committed = CommittedResult(Ref(builder.id, seq + 1), placeholder, found, machinery)
        claim = (claims or {}).get(target.node_id) or expected_result(
            plan.comparison, committed, w.bound.campaign.campaign.admit
        )
        builder.add(AuditResult(target, Ref(builder.id, seq), claim.status, claim.reason))
    return read_audit_journal(builder.write(w.root / "audit.jsonl"), w.bound.campaign)


def report(w: World, plan: AuditPlan, journal: AuditJournal) -> AuditReport:
    return build_report(plan, journal, admit=w.bound.campaign.campaign.admit)


def statuses(result: AuditReport) -> list[str]:
    return [r["status"] for r in result.document["results"]]


# -- the corpus documents -----------------------------------------------------------------------


@pytest.mark.parametrize("entry", s.document_entries("audit-report"), ids=lambda e: str(e["id"]))
def test_the_audit_report_corpus(entry: dict[str, Any]) -> None:
    value = s.document_value(entry)
    expect = entry["expect"]
    if expect == "valid":
        check_report(value)
        return
    with pytest.raises(ContractError) as caught:
        check_report(value)
    if "rule" in expect:
        assert caught.value.rule == expect["rule"]
    else:
        assert (caught.value.rule, caught.value.location) == ("schema", expect["schema"])


# -- reports -----------------------------------------------------------------------------------


def test_an_exact_reproduction_is_a_strict_success(tmp_path: Path) -> None:
    w = world(tmp_path, "base")
    plan = make_plan(w.bound, Selection(sample=None))
    result = report(w, plan, simulate(w, plan, w.attempts))
    assert statuses(result) == ["HASH_MATCHED"] * 3
    assert result.exit_code == 0 and result.strict_success
    document = result.document
    assert (document["population"], document["selected"], document["pending"]) == (3, 3, [])
    assert document["counts"] == dict.fromkeys(STATUSES, 0) | {"HASH_MATCHED": 3}
    assert document["certificate_sha256"] == w.bound.certificate.sha256
    assert document["targets_sha256"] == plan.targets_sha256
    assert [r["target"]["node_id"] for r in document["results"]] == [
        t.node_id for t in plan.targets
    ]
    for entry in document["results"]:
        assert entry["record"]["journal"] == read_id(w)
    check_report(document)
    assert (
        result.data == (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode()
    )


def read_id(w: World) -> str:
    return str(json.loads(w.header_line)["self"])


def test_a_sample_reports_population_and_selection(tmp_path: Path) -> None:
    w = world(tmp_path, "base")
    plan = make_plan(w.bound, Selection(sample=1, seed="5e" * 32))
    result = report(w, plan, simulate(w, plan, w.attempts))
    assert (result.document["population"], result.document["selected"]) == (3, 1)
    assert result.exit_code == 0  # every *selected* target matched; the report says 1 of 3


def test_a_reprove_audit_never_reads_as_strict_success(tmp_path: Path) -> None:
    w = world(tmp_path, "base")
    plan = make_plan(w.bound, Selection(sample=None, comparison=AuditComparison.REPROVE))
    result = report(w, plan, simulate(w, plan, w.attempts))
    assert statuses(result) == ["HASH_MATCHED"] * 3
    assert result.document["comparison"] == "reprove" and result.exit_code == 1


def test_a_target_without_a_committed_result_is_pending(tmp_path: Path) -> None:
    w = world(tmp_path, "base")
    plan = make_plan(w.bound, Selection(sample=None))
    first = plan.targets[0].node_id
    partial = {k: v for k, v in w.attempts.items() if k != first}
    result = report(w, plan, simulate(w, plan, partial))
    assert result.document["pending"] == [first]
    assert result.document["selected"] == 3 and len(result.document["results"]) == 2
    assert result.exit_code == 1


def test_a_different_proof_that_passed_is_a_strict_mismatch(tmp_path: Path) -> None:
    w = world(tmp_path, "base")
    plan = make_plan(w.bound, Selection(sample=None))
    changed = dict(w.attempts)
    cdcl = next(t for t in plan.targets if t.route == Route.CDCL)
    changed[cdcl.node_id] = replace(w.attempts[cdcl.node_id], proof_sha256="2b" * 32)
    assert changed[cdcl.node_id].outcome == Outcome.VERIFIED_UNSAT
    result = report(w, plan, simulate(w, plan, changed))
    assert result.document["counts"]["MISMATCH"] == 1 and result.exit_code == 4


def test_a_claimed_status_must_be_what_the_attempt_shows(tmp_path: Path) -> None:
    w = world(tmp_path, "base")
    plan = make_plan(w.bound, Selection(sample=None))
    changed = dict(w.attempts)
    cdcl = next(t for t in plan.targets if t.route == Route.CDCL)
    changed[cdcl.node_id] = replace(w.attempts[cdcl.node_id], proof_sha256="2b" * 32)
    for claim in (
        Classified(AuditStatus.HASH_MATCHED, ""),
        Classified(AuditStatus.NOT_COMPARABLE, "source tools unavailable"),
        Classified(AuditStatus.MISMATCH, "a different text"),
    ):
        journal = simulate(w, plan, changed, claims={cdcl.node_id: claim})
        with pytest.raises(IntegrityError) as caught:
            report(w, plan, journal)
        assert caught.value.rule == "audit.result_status"


def other_solver_line(w: World) -> bytes:
    """An audit header whose solver is not the source solver of the CDCL targets (strict:
    such a target is not runnable in that session)."""
    solver = replace(w.header.machinery.solver, sha256=OTHER)
    header = replace(
        w.header,
        purpose=Purpose.AUDIT,
        worker="auditor",
        machinery=replace(w.header.machinery, solver=solver),
    )
    return build_record(header, seq=0, prev="0" * 64, utc=s.UTC).line


def test_strict_without_the_source_solver_is_not_comparable(tmp_path: Path) -> None:
    w = world(tmp_path, "base")
    full = make_plan(w.bound, Selection(sample=None))
    cdcl = next(t for t in full.targets if t.route == Route.CDCL)
    plan = replace(full, targets=(cdcl,))
    line = other_solver_line(w)
    placeholder = s.attempt_value("failed_launch")  # nothing was run for this target
    placeholder.update(
        node=cdcl.node.to_json(),
        node_id=cdcl.node_id,
        cnf_sha256=cdcl.cnf_sha256,
        policy_sha256=w.header.policy.sha256,
        limits={**placeholder["limits"], "solver_time_ms": None},
    )
    attempts = {cdcl.node_id: s.typed_attempt(placeholder)}
    result = report(w, plan, simulate(w, plan, attempts, header_line=line))
    [entry] = result.document["results"]
    assert entry["status"] == "NOT_COMPARABLE" and "solver.sha256" in entry["reason"]
    assert result.exit_code == 1
    # the same journal claimed by a reprove audit: its own solver is not admitted here
    reprove = replace(plan, comparison=AuditComparison.REPROVE)
    failed = report(w, reprove, simulate(w, reprove, attempts, header_line=line))
    [entry] = failed.document["results"]
    assert failure_code(entry["reason"]) == "solver_not_admitted"
    assert failed.exit_code == 5


def test_a_model_of_a_target_used_as_proved_is_an_inconsistency(tmp_path: Path) -> None:
    w = world(tmp_path, "inconsistent")
    plan = make_plan(w.bound, Selection(sample=None))
    model = next(
        a
        for r in s.records_of((w.root / "journals" / "inconsistent" / "w1.jsonl").read_bytes())
        if isinstance(a := r.payload, Attempt) and a.outcome == Outcome.MODEL
    )
    target = next(t for t in plan.targets if t.node_id == model.node_id)
    journal = simulate(w, plan, {target.node_id: model})
    result = report(w, plan, journal)
    [entry] = result.document["results"]
    assert entry["status"] == "FAILED" and failure_code(entry["reason"]) == "inconsistent_model"
    assert result.exit_code == 4
    hidden = Classified(AuditStatus.NOT_COMPARABLE, "x")
    with pytest.raises(IntegrityError):
        report(w, plan, simulate(w, plan, {target.node_id: model}, claims={target.node_id: hidden}))


def test_a_model_is_never_hidden_behind_not_comparable(tmp_path: Path) -> None:
    """Specification §11.2: a valid model of a target used as proved is an inconsistency even
    when the session's machinery could not have run that target in strict mode."""
    w = world(tmp_path, "inconsistent")
    plan = make_plan(w.bound, Selection(sample=None))
    model = next(
        a
        for r in s.records_of((w.root / "journals" / "inconsistent" / "w1.jsonl").read_bytes())
        if isinstance(a := r.payload, Attempt) and a.outcome == Outcome.MODEL
    )
    target = next(t for t in plan.targets if t.node_id == model.node_id)
    assert target.route == Route.CDCL  # strict and another solver: not runnable
    line = other_solver_line(w)
    result = report(w, plan, simulate(w, plan, {target.node_id: model}, header_line=line))
    [entry] = result.document["results"]
    assert entry["status"] == "FAILED" and failure_code(entry["reason"]) == "inconsistent_model"
    assert result.exit_code == 4
    # the claim a non-runnable target would otherwise get is refused for a model
    hidden = Classified(
        AuditStatus.NOT_COMPARABLE,
        "source tools unavailable (solver.sha256); no reproof in strict mode",
    )
    journal = simulate(
        w, plan, {target.node_id: model}, claims={target.node_id: hidden}, header_line=line
    )
    with pytest.raises(IntegrityError) as caught:
        report(w, plan, journal)
    assert caught.value.rule == "audit.result_status"


def test_an_empty_population_is_an_explicit_open_report(tmp_path: Path) -> None:
    w = world(tmp_path, "split_incomplete")
    plan = make_plan(w.bound, Selection(sample=3))
    result = report(w, plan, simulate(w, plan, {}))
    document = result.document
    assert (document["population"], document["selected"], document["results"]) == (0, 0, [])
    assert result.exit_code == 1 and not result.strict_success


def test_a_report_needs_the_regenerated_plan(tmp_path: Path) -> None:
    w = world(tmp_path, "base")
    plan = make_plan(w.bound, Selection(sample=None))
    journal = simulate(w, plan, w.attempts)
    other = make_plan(w.bound, Selection(sample=None, seed="5e" * 32))
    with pytest.raises(IntegrityError) as caught:
        report(w, other, journal)
    assert caught.value.rule == "audit.plan_changed"
