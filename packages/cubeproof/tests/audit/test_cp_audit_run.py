"""Real audits of a certified run with the audit executor (specification §11.1, §11.2, §12.2).

A source run of the real coordinator with the audit fake tools (``cp_audit_tool``) is certified;
each test audits a copy of that evidence in its own results and work directories, with the same
tool installation (the strict profile of the source) reconfigured where a test needs another
behaviour (the binary hash never changes). Covered here: real small audit matches,
mismatched proof still valid, unexpected SAT model, missing tools, sample determinism over a
real run, no silent tool swap (a strict target without its source solver is NOT_COMPARABLE, not
run with another one), retry of a failed execution before the final result, unlimited solver
time with explicit RAM/disk/proof-cap controls, inputs inside the results directory, a changed
selection on restart. Crashes during the plan and the results: :mod:`test_cp_audit_crash`.
"""

from __future__ import annotations

import json
import os
import signal
import sys
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

import cp_audit_world as w
import cp_life_tools as t

from cubeproof import api
from cubeproof.base.canonical_json import document_bytes
from cubeproof.base.errors import (
    ConfigurationError,
    CubeproofError,
    InputError,
    IntegrityError,
    ResourceError,
    ToolError,
)
from cubeproof.base.settings import ToolPaths
from cubeproof.cnf.campaign import load_campaign
from cubeproof.commands import PackageRequest
from cubeproof.commands import audit as audit_module
from cubeproof.commands import audit_report as audit_report_module
from cubeproof.commands.audit import (
    REPORT_NAME,
    SNAPSHOT_DIRECTORY,
    AuditRequest,
    audit_command,
    outcome_exit_code,
)
from cubeproof.commands.audit_journal import read_audit_journal
from cubeproof.commands.audit_plan import Selection, make_plan, select_node_ids
from cubeproof.commands.audit_report import AuditReport, build_report, check_report
from cubeproof.contracts.enums import ProofMode
from cubeproof.coordinator.audit_config import AuditConfig, AuditRun
from cubeproof.coordinator.audit_run import audit_cap
from cubeproof.coordinator.config import RunConfig, Stop, exit_code_of
from cubeproof.leaf.binding import SOURCE_TOOL_UNAVAILABLE
from cubeproof.tools.machinery import package_root

FORMULA = t.unsat(5)
SEED = "5" * 64


@pytest.fixture(scope="module")
def source(tmp_path_factory: pytest.TempPathFactory) -> w.Source:
    root = tmp_path_factory.mktemp("source")
    found = w.make_source(root, {"f": FORMULA}, solver={"max_free": 3})
    assert found.verdict == "PROVED"
    return found


def evidence(
    source: w.Source,
    tmp_path: Path,
    solver: dict[str, Any] | None = None,
    checker: dict[str, Any] | None = None,
) -> w.Source:
    """A copy of the source evidence; the shared fake tools are (re)configured for this test."""
    w.configure(source.tools.solver, max_free=3, **(solver or {}))
    w.configure(source.tools.checker, **(checker or {}))
    return w.copy_source(source, tmp_path / "copy")


def records(tmp_path: Path) -> list[dict[str, Any]]:
    return w.journal_records(tmp_path / "audit")


def of_type(tmp_path: Path, kind: str) -> list[dict[str, Any]]:
    return [r for r in records(tmp_path) if r["type"] == kind]


def used(e: w.Source) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = json.loads(e.certificate.read_text())["used_attempts"]
    return found


def clean(tmp_path: Path) -> None:
    t.wait_clean(tmp_path / "audit", tmp_path / "audit-work")


# -- strict success ----------------------------------------------------------------------------


def test_a_real_small_audit_matches(source: w.Source, tmp_path: Path) -> None:
    e = evidence(source, tmp_path)
    outcome = audit_command(w.request(e, tmp_path))
    report = outcome.report
    assert report is not None and outcome.path == tmp_path / "audit" / REPORT_NAME
    document = report.document
    check_report(document)
    assert outcome.exit_code == 0 and report.strict_success, document
    population = used(e)
    routes = {u["route"] for u in population}
    assert document["population"] == document["selected"] == len(population) > 1
    assert document["counts"]["HASH_MATCHED"] == len(population) and document["pending"] == []
    assert outcome.path.read_bytes() == document_bytes(document)
    found = records(tmp_path)
    assert [r["type"] for r in found[:2]] == ["header", "audit_begin"]
    assert found[0]["purpose"] == "audit" and found[0]["worker"] == "auditor"
    assert found[0]["policy"]["proof_mode"] == "transient"
    attempts = [r for r in found if r["type"] == "attempt"]
    assert len(attempts) == len(population) and "cdcl" in routes
    for attempt in attempts:
        # Specification §11.2: no solver time limit
        assert attempt["limits"]["solver_time_ms"] is None
        assert attempt["outcome"] == "VERIFIED_UNSAT" and attempt["retained"] is None
    kinds = [r["type"] for r in found]
    ready = kinds.index("audit_ready")
    assert kinds[2:ready] == ["audit_target"] * len(population)
    assert "attempt" not in kinds[:ready]  # nothing runs before the plan is durable
    results = [r for r in found if r["type"] == "audit_result"]
    assert [r["target"]["node_id"] for r in results] == sorted(u["node_id"] for u in population)
    by_seq = {r["seq"]: r for r in found}
    for result in results:
        assert by_seq[result["attempt"]["seq"]]["node_id"] == result["target"]["node_id"]
    [snapshot] = (tmp_path / "audit" / SNAPSHOT_DIRECTORY).iterdir()
    assert snapshot.read_bytes() == e.journal.read_bytes()
    assert snapshot.stat().st_mode & 0o222 == 0  # the preserved certified input is read-only
    assert sorted(p.name for p in (tmp_path / "audit-work").iterdir()) == [".run.lock"]
    assert json.loads(json.dumps(outcome.to_json()))["summary"]["strict_success"] is True
    clean(tmp_path)


def test_other_machinery_differences_are_reported_not_hidden(
    source: w.Source, tmp_path: Path
) -> None:
    """The status is decided with the machinery of the audit session (the attempt's snapshot),
    not the source's: a package outside the strict profile is a reported difference."""
    e = evidence(source, tmp_path)
    extra = tmp_path / "extra"
    extra.mkdir()
    (extra / "module.py").write_text("VALUE = 1\n", encoding="utf-8")
    packages = {"cubeproof": package_root("cubeproof"), "extra": extra}
    outcome = audit_command(w.request(e, tmp_path, packages=packages))
    assert outcome.exit_code == 0 and outcome.report is not None
    reasons = {r["reason"] for r in outcome.report.document["results"]}
    assert reasons == {"reported differences: packages_sha256"}
    assert {r["reason"] for r in of_type(tmp_path, "audit_result")} == reasons


def test_a_restart_of_a_finished_audit_adds_no_result(source: w.Source, tmp_path: Path) -> None:
    e = evidence(source, tmp_path)
    first = audit_command(w.request(e, tmp_path))
    before = records(tmp_path)
    again = audit_command(w.request(e, tmp_path))
    after = records(tmp_path)
    assert first.exit_code == again.exit_code == 0
    assert again.report is not None and first.report is not None
    assert again.report.document == first.report.document
    assert after[: len(before)] == before and [r["type"] for r in after[len(before) :]] == [
        "resume"
    ]


def test_a_second_copy_of_a_journal_is_named_in_the_notes(source: w.Source, tmp_path: Path) -> None:
    e = evidence(source, tmp_path)
    copy = tmp_path / "copy" / "evidence" / "again.jsonl"
    copy.write_bytes(e.journal.read_bytes())
    outcome = audit_command(replace(w.request(e, tmp_path), journals=(e.journal, copy)))
    assert outcome.exit_code == 0
    ignored = [n for n in outcome.to_json()["notes"] if "another copy of the same journal" in n]
    assert len(ignored) == 1 and ignored[0].startswith((str(copy), str(e.journal)))


def test_an_audit_from_an_evidence_manifest(source: w.Source, tmp_path: Path) -> None:
    e = evidence(source, tmp_path)
    package = api.package(PackageRequest(e.campaign, [e.journal], tmp_path / "package"))
    manifest = Path(package.manifest)
    config = w.audit_config(tmp_path, e.tools)
    outcome = audit_command(AuditRequest(config, Selection(None), evidence=manifest))
    assert outcome.exit_code == 0 and outcome.report is not None
    assert outcome.report.document["selected"] == len(used(e))
    mixed = AuditRequest(config, Selection(None), evidence=manifest, campaign=e.campaign)
    with pytest.raises(ConfigurationError, match="exclusive"):
        audit_command(mixed)
    with pytest.raises(ConfigurationError, match="required"):
        audit_command(AuditRequest(config, Selection(None), campaign=e.campaign))


# -- selection ---------------------------------------------------------------------------------


def test_a_sample_is_deterministic_and_reported_as_a_sample(
    source: w.Source, tmp_path: Path
) -> None:
    e = evidence(source, tmp_path)
    first = audit_command(w.request(e, tmp_path / "one", sample=2, seed=SEED))
    second = audit_command(w.request(e, tmp_path / "two", sample=2, seed=SEED))
    assert first.report is not None and second.report is not None
    one, two = first.report.document, second.report.document
    population = sorted(u["node_id"] for u in used(e))
    assert one["population"] == len(population) > one["selected"] == 2
    for name in ("targets_sha256", "seed", "counts", "pending", "selected", "population"):
        assert one[name] == two[name], name  # the records (refs) are of two separate journals
    assert [r["target"] for r in one["results"]] == [r["target"] for r in two["results"]]
    chosen = [r["target"]["node_id"] for r in one["results"]]
    assert chosen == list(select_node_ids(population, 2, SEED))
    assert first.exit_code == 0  # every selected target matched; population/selected say a sample
    targets = [r["target"]["node_id"] for r in w.journal_records(tmp_path / "one" / "audit")
               if r["type"] == "audit_target"]  # fmt: skip
    assert targets == chosen
    assert [r["sample_count"] for r in w.journal_records(tmp_path / "one" / "audit")
            if r["type"] == "audit_begin"] == [2]  # fmt: skip
    default = audit_command(w.request(e, tmp_path / "default", sample=2))
    assert default.report is not None
    assert default.report.document["seed"] == one["certificate_sha256"]  # SHA256(J(certificate))


def test_a_changed_selection_on_restart_is_refused(source: w.Source, tmp_path: Path) -> None:
    e = evidence(source, tmp_path)
    assert audit_command(w.request(e, tmp_path, sample=1, seed=SEED)).exit_code == 0
    before = (tmp_path / "audit" / "journal.jsonl").read_bytes()
    with pytest.raises(IntegrityError) as info:
        audit_command(w.request(e, tmp_path, sample=2, seed=SEED))
    assert info.value.rule == "audit.plan_changed" and exit_code_of(info.value) == 4
    assert (tmp_path / "audit" / "journal.jsonl").read_bytes() == before
    clean(tmp_path)


def test_reprove_never_reads_as_strict_success(source: w.Source, tmp_path: Path) -> None:
    e = evidence(source, tmp_path)
    outcome = audit_command(w.request(e, tmp_path, comparison="reprove"))
    assert outcome.report is not None
    assert outcome.report.document["comparison"] == "reprove"
    assert outcome.exit_code == 1 and not outcome.report.strict_success
    assert any("not a historical hash match" in note for note in outcome.to_json()["notes"])


# -- other statuses ----------------------------------------------------------------------------


def test_a_different_valid_proof_is_a_mismatch(source: w.Source, tmp_path: Path) -> None:
    e = evidence(source, tmp_path, solver={"variant": True})
    outcome = audit_command(w.request(e, tmp_path))
    assert outcome.report is not None
    document = outcome.report.document
    assert outcome.exit_code == 4
    cdcl = [u for u in used(e) if u["route"] == "cdcl"]
    assert document["counts"]["MISMATCH"] == len(cdcl) > 0
    assert document["counts"]["HASH_MATCHED"] == len(used(e)) - len(cdcl)  # unit proofs match
    for attempt in of_type(tmp_path, "attempt"):
        assert attempt["outcome"] == "VERIFIED_UNSAT"  # the new proof passed the checker
    reasons = [r["reason"] for r in document["results"] if r["status"] == "MISMATCH"]
    assert all("differs" in reason for reason in reasons)


def test_an_unexpected_model_is_an_inconsistency(tmp_path: Path) -> None:
    lying = w.make_source(
        tmp_path / "source",
        {"f": t.sat(5)},
        solver={"lie": True},
        checker={"accept": True},
        policy=t.make_policy(),
    )
    assert lying.verdict == "PROVED"  # the source's tools lied and the certifier trusted them
    w.configure(lying.tools.solver)
    w.configure(lying.tools.checker)
    outcome = audit_command(w.request(lying, tmp_path))
    assert outcome.report is not None
    [result] = outcome.report.document["results"]
    assert result["status"] == "FAILED" and result["reason"].startswith("inconsistent_model")
    assert outcome.exit_code == 4
    [attempt] = of_type(tmp_path, "attempt")
    assert attempt["outcome"] == "MODEL"


def test_a_failed_execution_is_retried_before_the_final_result(
    source: w.Source, tmp_path: Path
) -> None:
    counter = tmp_path / "solver-runs"
    e = evidence(source, tmp_path, solver={"fail_first": str(counter), "fail_count": 1})
    outcome = audit_command(w.request(e, tmp_path))
    assert outcome.exit_code == 0, outcome.to_json()
    attempts = of_type(tmp_path, "attempt")
    failed = [a for a in attempts if a["outcome"] == "TOOL_FAILED"]
    assert len(failed) == 1 and len(attempts) == len(used(e)) + 1
    [result] = [
        r
        for r in of_type(tmp_path, "audit_result")
        if r["target"]["node_id"] == failed[0]["node_id"]
    ]
    final = next(r for r in records(tmp_path) if r["seq"] == result["attempt"]["seq"])
    assert final["outcome"] == "VERIFIED_UNSAT" and result["status"] == "HASH_MATCHED"


def test_a_persistent_tool_failure_is_failed_after_the_retries(
    source: w.Source, tmp_path: Path
) -> None:
    e = evidence(source, tmp_path, solver={"crash": True})
    outcome = audit_command(w.request(e, tmp_path))
    assert outcome.exit_code == 5 and outcome.report is not None
    cdcl = {u["node_id"] for u in used(e) if u["route"] == "cdcl"}
    attempts = of_type(tmp_path, "attempt")
    retries = records(tmp_path)[0]["policy"]["tool_retries"]
    for node in cdcl:
        assert sum(a["node_id"] == node for a in attempts) == retries + 1
    assert outcome.report.document["counts"]["FAILED"] == len(cdcl)


def test_a_strict_target_without_its_source_solver_is_not_comparable(
    source: w.Source, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No silent tool swap: a strict audit that lacks a target's source solver records a
    placeholder that nothing ran and NOT_COMPARABLE; the report accepts that only while
    the rule says the session could not run it."""
    e = evidence(source, tmp_path)
    never = lambda comparison, target, machinery: False  # noqa: E731
    monkeypatch.setattr(audit_module, "runnable", never)
    monkeypatch.setattr(audit_report_module, "runnable", never)
    outcome = audit_command(w.request(e, tmp_path))
    assert outcome.report is not None
    cdcl = [u for u in used(e) if u["route"] == "cdcl"]
    assert outcome.report.document["counts"]["NOT_COMPARABLE"] == len(used(e))
    assert outcome.exit_code == 1
    attempts = of_type(tmp_path, "attempt")
    assert len(attempts) == len(used(e)) and len(cdcl) > 0
    for attempt in attempts:
        assert (attempt["outcome"], attempt["reason"]) == ("TOOL_FAILED", "launch")
        assert attempt["solver"]["started"] is False
        assert attempt["solver"]["cause"] == SOURCE_TOOL_UNAVAILABLE
        assert attempt["limits"]["solver_time_ms"] is None and attempt["checks"] == []
    monkeypatch.undo()
    # the same journal under the real rule: the session had the source solver, so the claim
    # NOT_COMPARABLE is not what the attempts show
    campaign = load_campaign(e.campaign)
    plan = make_plan(_bound(e, tmp_path), Selection(None))
    journal = read_audit_journal(tmp_path / "audit" / "journal.jsonl", campaign)
    with pytest.raises(IntegrityError) as info:
        build_report(plan, journal, admit=campaign.campaign.admit)
    assert info.value.rule == "audit.result_status"


def _bound(e: w.Source, tmp_path: Path) -> Any:
    from cubeproof.commands.audit_inputs import bind_certified_inputs

    return bind_certified_inputs(
        e.campaign, [e.journal], e.certificate, tmp_path / "audit" / SNAPSHOT_DIRECTORY
    )


def test_an_empty_population_is_an_open_audit(tmp_path: Path) -> None:
    broken = w.make_source(tmp_path / "source", {"f": FORMULA}, solver={"crash": True}, exit_code=5)
    assert broken.verdict == "OPEN"
    outcome = audit_command(w.request(broken, tmp_path))
    assert outcome.report is not None
    document = outcome.report.document
    assert (document["population"], document["selected"], document["results"]) == (0, 0, [])
    assert outcome.exit_code == 1  # never a vacuous success
    assert [r["type"] for r in records(tmp_path)] == ["header", "audit_begin", "audit_ready"]


# -- resources and tools ------------------------------------------------------------------------


def test_the_proof_cap_defaults_to_the_reference_and_can_be_set(
    source: w.Source, tmp_path: Path
) -> None:
    e = evidence(source, tmp_path)
    assert audit_command(w.request(e, tmp_path / "default")).exit_code == 0
    header = w.journal_records(tmp_path / "default" / "audit")[0]
    policy_cap = json.loads(e.campaign.read_text())["policy"]["proof_cap_bytes"]
    assert header["policy"]["proof_cap_bytes"] == policy_cap  # >= every reference proof here
    small = audit_command(w.request(e, tmp_path / "small", proof_cap_bytes=8))
    header = w.journal_records(tmp_path / "small" / "audit")[0]
    assert header["policy"]["proof_cap_bytes"] == 8
    assert small.report is not None
    cdcl = [u for u in used(e) if u["route"] == "cdcl"]
    assert small.report.document["counts"]["OPEN"] >= len(cdcl) > 0  # exhausted, not failed
    assert small.exit_code == 1


def test_a_memory_budget_too_small_fails_preflight(source: w.Source, tmp_path: Path) -> None:
    e = evidence(source, tmp_path)
    with pytest.raises(ResourceError) as info:
        audit_command(w.request(e, tmp_path, memory_bytes=1 << 20))
    assert exit_code_of(info.value) == 1
    assert not (tmp_path / "audit" / "journal.jsonl").exists()  # nothing committed
    clean(tmp_path)


def test_a_missing_tool_fails_before_any_record(source: w.Source, tmp_path: Path) -> None:
    e = evidence(source, tmp_path)
    tools = ToolPaths(solver=str(tmp_path / "nope" / "cadical"), checker=str(e.tools.checker))
    with pytest.raises(ToolError) as info:
        audit_command(w.request(e, tmp_path, tools=tools))
    assert exit_code_of(info.value) == 5
    assert not (tmp_path / "audit" / "journal.jsonl").exists()
    clean(tmp_path)


def test_another_solver_binary_is_refused(source: w.Source, tmp_path: Path) -> None:
    e = evidence(source, tmp_path)
    other = w.install(tmp_path / "other-tools")
    other.solver.write_text(other.solver.read_text() + "\n# another binary\n")
    tools = ToolPaths(solver=str(other.solver), checker=str(e.tools.checker))
    with pytest.raises(CubeproofError) as info:
        audit_command(w.request(e, tmp_path, tools=tools))
    assert exit_code_of(info.value) == 5
    assert not (tmp_path / "audit" / "journal.jsonl").exists()


# -- directories and inputs ---------------------------------------------------------------------


def test_inputs_inside_the_results_directory_are_refused(source: w.Source, tmp_path: Path) -> None:
    e = evidence(source, tmp_path)
    inside = w.copy_source(source, tmp_path / "audit" / "inputs")
    with pytest.raises(ConfigurationError) as info:
        audit_command(w.request(inside, tmp_path))
    assert info.value.rule == "audit.results"
    del e


def test_a_run_results_directory_is_not_an_audit_one(source: w.Source, tmp_path: Path) -> None:
    e = evidence(source, tmp_path)
    run_results = tmp_path / "run"
    run_results.mkdir()
    (run_results / "journal.jsonl").write_bytes(e.journal.read_bytes())
    with pytest.raises(ConfigurationError) as info:
        audit_command(w.request(e, tmp_path, results=run_results))
    assert info.value.rule == "audit.purpose"
    assert (run_results / "journal.jsonl").read_bytes() == e.journal.read_bytes()


def test_another_worker_cannot_continue_an_audit(source: w.Source, tmp_path: Path) -> None:
    e = evidence(source, tmp_path)
    assert audit_command(w.request(e, tmp_path, sample=1)).exit_code == 0
    with pytest.raises(ConfigurationError) as info:
        audit_command(w.request(e, tmp_path, sample=1, worker="other"))
    assert info.value.rule == "audit.worker"


def test_a_tampered_certificate_is_refused_before_any_record(
    source: w.Source, tmp_path: Path
) -> None:
    e = evidence(source, tmp_path)
    document = json.loads(e.certificate.read_text())
    document["used_attempts"] = document["used_attempts"][1:]
    e.certificate.write_bytes(document_bytes(document))
    with pytest.raises(IntegrityError) as info:
        audit_command(w.request(e, tmp_path))
    assert info.value.rule == "audit.certificate" and exit_code_of(info.value) == 4
    assert not (tmp_path / "audit" / "journal.jsonl").exists()


def test_unusable_inputs_are_refused_before_any_directory_exists(
    source: w.Source, tmp_path: Path
) -> None:
    e = evidence(source, tmp_path)
    missing = AuditRequest(
        w.audit_config(tmp_path, e.tools),
        Selection(None),
        campaign=e.campaign,
        certificate=tmp_path / "nope.json",
        journals=(e.journal,),
    )
    with pytest.raises(InputError) as info:
        audit_command(missing)
    assert info.value.rule == "audit.certificate_file" and exit_code_of(info.value) == 3
    document = json.loads(e.certificate.read_text())
    document["campaign"] = "0" * 64
    other = tmp_path / "other-certificate.json"
    other.write_bytes(document_bytes(document))
    with pytest.raises(IntegrityError) as wrong:
        audit_command(w.request(replace(e, certificate=other), tmp_path))
    assert wrong.value.rule == "audit.certificate"
    assert not (tmp_path / "audit").exists() and not (tmp_path / "audit-work").exists()


def test_a_torn_tail_of_the_audit_journal_is_repaired(source: w.Source, tmp_path: Path) -> None:
    e = evidence(source, tmp_path)
    assert audit_command(w.request(e, tmp_path, sample=1)).exit_code == 0
    journal = tmp_path / "audit" / "journal.jsonl"
    with journal.open("ab") as stream:
        stream.write(b'{"format":"cubeproof-journal-1","seq"')
    outcome = audit_command(w.request(e, tmp_path, sample=1))
    assert outcome.exit_code == 0
    assert any("torn tail" in note for note in outcome.run.notes)
    assert [r["type"] for r in records(tmp_path)][-2:] == ["repair", "resume"]


def test_an_audit_of_a_retain_campaign_keeps_no_proof_files(tmp_path: Path) -> None:
    retained = w.make_source(
        tmp_path / "source",
        {"f": FORMULA},
        solver={"max_free": 3},
        policy=t.split_policy(proof_mode=ProofMode.RETAIN),
    )
    outcome = audit_command(w.request(retained, tmp_path))
    assert outcome.exit_code == 0
    header = records(tmp_path)[0]
    assert header["policy"]["proof_mode"] == "transient"
    assert all(a["retained"] is None for a in of_type(tmp_path, "attempt"))
    assert not (tmp_path / "audit" / "proofs").exists()


# -- the rules of the executor and the command, directly -----------------------------------------


def test_the_audit_proof_cap() -> None:
    assert audit_cap(100, 250, None) == 250  # the largest reference proof
    assert audit_cap(300, 250, None) == 300  # never below the policy cap
    # --proof-cap replaces both (then the specification §8.3 clamp)
    assert audit_cap(300, 250, 7) == 7


def _run(stop: Stop) -> AuditRun:
    return AuditRun(stop=stop, journal=None, seq=0, head=None, pending=0)


@pytest.mark.parametrize(
    ("stop", "reported", "expected"),
    [
        (Stop.COMPLETE, 0, 0),
        (Stop.COMPLETE, 1, 1),
        (Stop.COMPLETE, 4, 4),
        (Stop.COMPLETE, None, 1),
        (Stop.SERVICE, 0, 5),
        (Stop.SERVICE, 1, 5),
        (Stop.SERVICE, 4, 4),
        (Stop.INTERRUPTED, 0, 130),
        (Stop.INTERRUPTED, 5, 130),
        (Stop.INTERRUPTED, 4, 4),
        (Stop.INTERRUPTED, None, 130),
    ],
)
def test_the_exit_code_of_an_audit_session(stop: Stop, reported: int | None, expected: int) -> None:
    report = None if reported is None else AuditReport({}, reported)
    assert outcome_exit_code(_run(stop), report) == expected


# -- stop signals ------------------------------------------------------------------------------


def test_a_signal_during_the_audit_shutdown_is_counted_and_the_shutdown_completes(
    source: w.Source, tmp_path: Path
) -> None:
    """The audit keeps its handlers until it has shut down and reported."""
    e = evidence(source, tmp_path)
    before = signal.getsignal(signal.SIGTERM)
    handled: list[tuple[str, bool]] = []

    def hooks(name: str) -> None:
        if name == "shutdown":
            ours = signal.getsignal(signal.SIGTERM) not in (before, signal.SIG_DFL, None)
            handled.append((name, ours))
            if ours:  # never with the default action: that would kill the test process
                os.kill(os.getpid(), signal.SIGTERM)

    outcome = audit_command(w.request(e, tmp_path, hooks=hooks, handle_signals=True))
    assert handled == [("shutdown", True)]
    # the target loop had already ended: the audit reports its completed work
    assert outcome.exit_code == 0 and outcome.report is not None
    assert outcome.report.strict_success, outcome.report.document
    assert outcome.report.document["pending"] == []
    assert signal.getsignal(signal.SIGTERM) == before
    clean(tmp_path)


# -- the known-answer control (specification §7.3) ------------------------------------------------


def test_an_audit_asks_the_checker_its_known_answers_before_any_record(tmp_path: Path) -> None:
    """The tools of this source lie: the solver calls a satisfiable formula unsatisfiable and the
    checker accepts everything, so the source certified PROVED. An audit with the same checker
    and the control (the default of AuditConfig) is refused before it writes anything; without
    the control it runs, which is what the other tests of this file rely on."""
    lying = w.make_source(
        tmp_path / "source",
        {"f": t.sat(5)},
        solver={"lie": True},
        checker={"accept": True},
        policy=t.make_policy(),
    )
    assert lying.verdict == "PROVED"
    with pytest.raises(ToolError) as caught:
        audit_command(w.request(lying, tmp_path / "controlled", known_answer=True))
    assert caught.value.rule == "tool.known_answer" and "was ACCEPTED" in caught.value.detail
    assert not (tmp_path / "controlled" / "audit" / "journal.jsonl").exists()
    outcome = audit_command(w.request(lying, tmp_path / "free"))  # the helper turns it off
    assert outcome.report is not None
    assert (tmp_path / "free" / "audit" / "journal.jsonl").exists()


def test_the_control_is_on_unless_a_caller_turns_it_off() -> None:
    """The library defaults, not only the command line: an API caller who says nothing gets
    the control (a caller with scripted tools says ``known_answer=False``)."""
    assert AuditConfig.__dataclass_fields__["known_answer"].default is True
    assert RunConfig.__dataclass_fields__["known_answer"].default is True
