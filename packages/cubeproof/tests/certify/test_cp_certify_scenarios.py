"""Targeted certifier scenarios (specification §10.1-§10.5, §4.8): admission, selection,
frontier, verdicts.

Each test writes a small campaign and journals with the plain builder of cp_certify_support and
computes the expected choice itself (smallest split_id / Ref by hashing), never from the
certifier.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from cp_certify_support import (
    CHECKER,
    MACHINERY,
    OTHER_HASH,
    POLICY,
    SOLVER,
    Scenario,
    certificate_problems,
    checked,
    children,
    cnf_bytes,
    dimacs,
    j,
    machinery,
    merkle,
    node_id,
    schema_errors,
    sha,
    solver_result,
    split_id,
)

from cubeproof.base.errors import InputError, IntegrityError, ResourceError
from cubeproof.contracts.enums import Verdict
from cubeproof.evidence.certify import CertifyLimits, CertifyResult, certify

F_SAT = b"p cnf 1 1\n1 0\n"
F_UNSAT = b"p cnf 1 2\n1 0\n-1 0\n"
#: Every clause over x1..x3: unsatisfiable, every cube is unsatisfiable (truthful leaves).
ALL3 = dimacs(3, [[a * 1, b * 2, c * 3] for a in (1, -1) for b in (1, -1) for c in (1, -1)])
#: x1 or x2 with V = 3: satisfiable.
SAT3 = dimacs(3, [[1, 2]])


def run(scenario: Scenario, *journals: Path, **options: Any) -> CertifyResult:
    result = certify(scenario.campaign_path, list(journals), **options)
    assert schema_errors(result.certificate) == []
    assert certificate_problems(result.certificate) == []
    return result


def node(formula: str, cube: list[int]) -> dict[str, Any]:
    return {"formula_sha256": formula, "cube": cube}


def opens(result: CertifyResult, field: str = "open") -> list[tuple[list[int], str, Any]]:
    return [(e["node"]["cube"], e["state"], e["reason"]) for e in result.certificate[field]]


def used_refs(result: CertifyResult) -> dict[tuple[int, ...], tuple[str, int]]:
    return {
        tuple(u["node"]["cube"]): (u["record"]["journal"], u["record"]["seq"])
        for u in result.certificate["used_attempts"]
    }


# -- specification §4.10 and literal closure -----------------------------------------------------


def test_a_nonempty_pilot_root_closes_alone_while_the_formula_stays_open(tmp_path: Path) -> None:
    s = Scenario(tmp_path, {"sat": F_SAT}, roots=[("sat", [-1])])
    w = s.journal("w1")
    seq = w.unsat("sat", [-1], route="unit")
    result = run(s, w.write())
    formula = result.certificate["formulas"][0]
    assert formula["proved"] is False
    assert formula["summary"]["leaves"] == 0
    assert formula["roots"][0]["closed"] is True
    assert formula["roots"][0]["summary"]["leaves"] == 1
    assert result.verdict == Verdict.OPEN
    assert result.exit_code == 1
    assert result.certificate["open"] == []
    # no split at the empty cube: the whole formula is the one open node (as corpus pilot_root)
    assert opens(result, "formula_open") == [([], "pending", None)]
    assert used_refs(result) == {(-1,): w.ref(seq)}


def test_a_closed_ancestor_does_not_close_a_requested_root(tmp_path: Path) -> None:
    """Closure is literal: the empty cube closes F, not the roots [1], [-1]."""
    s = Scenario(tmp_path, {"u": F_UNSAT}, roots=[("u", [1]), ("u", [-1])])
    w = s.journal("w1")
    w.unsat("u", [])
    result = run(s, w.write())
    formula = result.certificate["formulas"][0]
    assert formula["proved"] is True
    assert [r["closed"] for r in formula["roots"]] == [False, False]
    assert result.verdict == Verdict.PROVED
    assert sorted(opens(result)) == [([-1], "pending", None), ([1], "pending", None)]
    assert result.certificate["formula_open"] == []


def test_split_needs_every_child_closed(tmp_path: Path) -> None:
    s = Scenario(tmp_path, {"u": F_UNSAT}, root_splits=[("u", [], [1])])
    w = s.journal("w1")
    w.unsat("u", [1])
    path = w.write()
    result = run(s, path)
    assert result.verdict == Verdict.OPEN
    assert opens(result) == [([-1], "pending", None)]
    w.unsat("u", [-1])
    result = run(s, w.write())
    assert result.verdict == Verdict.PROVED
    summary = result.certificate["formulas"][0]["summary"]
    assert (summary["leaves"], summary["splits"], summary["max_cube_size"]) == (2, 1, 1)


# -- selection ------------------------------------------------------------------------------------


def test_an_attempt_is_preferred_to_a_closed_split_and_the_smallest_ref_wins(
    tmp_path: Path,
) -> None:
    s = Scenario(tmp_path, {"a": ALL3}, root_splits=[("a", [], [1])])
    w1, w2 = s.journal("w1"), s.journal("w2")
    a1 = w1.unsat("a", [])
    w1.unsat("a", [1])
    w1.unsat("a", [-1])
    a2 = w2.unsat("a", [])
    first = min(w1.ref(a1), w2.ref(a2))
    result = run(s, w1.write(), w2.write())
    summary = result.certificate["formulas"][0]["summary"]
    assert (summary["leaves"], summary["splits"]) == (1, 0)
    assert used_refs(result) == {(): first}


def test_the_smallest_ref_orders_by_journal_before_seq(tmp_path: Path) -> None:
    s = Scenario(tmp_path, {"a": ALL3})
    w1, w2 = s.journal("w1"), s.journal("w2")
    low, high = sorted([w1, w2], key=lambda w: w.id)
    for _ in range(3):
        low.failed("a", [1], "EXHAUSTED", "time")
    late = low.unsat("a", [])
    early = high.unsat("a", [])
    assert late > early
    result = run(s, w1.write(), w2.write())
    assert used_refs(result) == {(): low.ref(late)}


def test_the_smallest_closed_split_id_is_selected(tmp_path: Path) -> None:
    s = Scenario(tmp_path, {"a": ALL3})
    w = s.journal("w1")
    formula = s.sha("a")
    candidates = [[1], [2], [3, 1]]
    for variables in candidates:
        w.split("a", [], variables)
        for child in children((), variables):
            w.unsat("a", list(child))
    smallest = min(candidates, key=lambda v: split_id(formula, [], v))
    result = run(s, w.write())
    leaves = {tuple(c) for c in children((), smallest)}
    assert set(used_refs(result)) == leaves
    summary = result.certificate["formulas"][0]["summary"]
    assert summary["splits"] == 1
    assert summary["leaves"] == len(leaves)


def test_an_open_split_with_a_smaller_id_does_not_hide_a_closed_one(tmp_path: Path) -> None:
    """Selection uses the smallest **closed** split; the frontier the smallest split."""
    s = Scenario(tmp_path, {"u": dimacs(2, [[1], [-1]])}, roots=[("u", [])])
    formula = s.sha("u")
    order = sorted([[1], [2]], key=lambda v: split_id(formula, [], v))
    small, large = order
    w = s.journal("w1")
    w.split("u", [], small)
    w.split("u", [], large)
    for child in children((), large):
        w.unsat("u", list(child))
    w.unsat("u", list(children((), small)[0]))
    result = run(s, w.write())
    assert result.verdict == Verdict.PROVED
    assert set(used_refs(result)) == set(children((), large))

    s2 = Scenario(tmp_path / "open", {"u": dimacs(2, [[1], [-1]])})
    w2 = s2.journal("w1")
    w2.split("u", [], small)
    w2.split("u", [], large)
    for child in children((), large)[:1]:
        w2.unsat("u", list(child))
    w2.unsat("u", list(children((), small)[0]))
    result = run(s2, w2.write())
    assert result.verdict == Verdict.OPEN
    expected = [(list(children((), small)[1]), "pending", None)]
    assert opens(result) == expected


def test_campaign_and_journal_copies_of_one_split_are_one_split(tmp_path: Path) -> None:
    s = Scenario(tmp_path, {"a": ALL3}, root_splits=[("a", [], [1])])
    w1, w2 = s.journal("w1"), s.journal("w2")
    w1.split("a", [], [1])
    w2.split("a", [], [1])
    w2.split("a", [], [1])
    w1.unsat("a", [1])
    w2.unsat("a", [-1])
    result = run(s, w1.write(), w2.write())
    summary = result.certificate["formulas"][0]["summary"]
    assert (summary["leaves"], summary["splits"]) == (2, 1)
    assert result.certificate["anomalies"] == []


def test_a_split_recorded_with_another_variable_order_is_another_split(tmp_path: Path) -> None:
    """W order is identity (specification §3.2): [1,2] and [2,1] are two alternatives with one
    child set."""
    s = Scenario(tmp_path, {"a": ALL3})
    formula = s.sha("a")
    w = s.journal("w1")
    w.split("a", [], [1, 2])
    w.split("a", [], [2, 1])
    for child in children((), [1, 2]):
        w.unsat("a", list(child))
    result = run(s, w.write())
    assert result.verdict == Verdict.PROVED
    assert result.certificate["formulas"][0]["summary"]["splits"] == 1
    assert split_id(formula, [], [1, 2]) != split_id(formula, [], [2, 1])


def test_max_cube_size_is_not_an_admission_bound(tmp_path: Path) -> None:
    policy = dict(POLICY, max_cube_size=1)
    s = Scenario(tmp_path, {"a": ALL3}, root_splits=[("a", [], [1])], policy=policy)
    w = s.journal("w1", policy=policy)
    w.unsat("a", [1])
    w.split("a", [-1], [2, 3])
    for child in children((-1,), [2, 3]):
        w.unsat("a", list(child))
    result = run(s, w.write())
    assert result.verdict == Verdict.PROVED
    summary = result.certificate["formulas"][0]["summary"]
    assert (summary["leaves"], summary["splits"], summary["max_cube_size"]) == (5, 2, 3)


def test_summary_merkle_root_and_used_attempts(tmp_path: Path) -> None:
    s = Scenario(tmp_path, {"a": ALL3}, root_splits=[("a", [], [1, 2])])
    w = s.journal("w1")
    seqs = {child: w.unsat("a", list(child), route="unit") for child in children((), [1, 2])}
    result = run(s, w.write())
    formula = s.sha("a")
    leaves = []
    for child, seq in seqs.items():
        record = w.records[seq]
        assert record["cnf_sha256"] == sha(cnf_bytes(ALL3, child))
        leaves.append((node_id(formula, child), record["cnf_sha256"], record["proof_sha256"]))
    summary = result.certificate["formulas"][0]["summary"]
    assert summary["leaf_merkle_root"] == merkle(leaves)
    used = result.certificate["used_attempts"]
    assert [u["node_id"] for u in used] == sorted(x[0] for x in leaves)
    assert {u["route"] for u in used} == {"unit"}
    assert result.certificate["machinery"] == [
        {"journal": w.id, "snapshot_seq": 0, "machinery": MACHINERY}
    ]


# -- admission and success fields ------------------------------------------------------------------


def test_admission_follows_the_latest_snapshot_of_the_journal(tmp_path: Path) -> None:
    s = Scenario(tmp_path, {"a": ALL3}, root_splits=[("a", [], [1])])
    w = s.journal("w1")
    first = w.unsat("a", [1])
    w.resume(machinery=machinery(checker=OTHER_HASH))
    refused = w.unsat("a", [-1])
    back = w.resume()
    accepted = w.unsat("a", [-1])
    result = run(s, w.write())
    assert result.certificate["not_admitted"] == [
        {"record": {"journal": w.id, "seq": refused}, "reason": "checker_not_admitted"}
    ]
    assert used_refs(result) == {(1,): w.ref(first), (-1,): w.ref(accepted)}
    assert result.certificate["machinery"] == [
        {"journal": w.id, "snapshot_seq": 0, "machinery": MACHINERY},
        {"journal": w.id, "snapshot_seq": back, "machinery": MACHINERY},
    ]


def test_solver_admission_compares_hash_and_complete_argv(tmp_path: Path) -> None:
    s = Scenario(tmp_path, {"a": ALL3})
    w = s.journal("w1", machinery=machinery(solver_argv=["--lrat", "--seed=1"]), admitted=False)
    seq = w.unsat("a", [], route="unit")
    result = run(s, w.write())
    assert result.certificate["not_admitted"] == [
        {"record": {"journal": w.id, "seq": seq}, "reason": "solver_not_admitted"}
    ]
    assert result.verdict == Verdict.OPEN


def test_checker_reason_comes_before_solver_reason(tmp_path: Path) -> None:
    s = Scenario(tmp_path, {"a": ALL3})
    other = machinery(checker=OTHER_HASH, solver_argv=["--lrat", "-q"])
    w = s.journal("w1", machinery=other, admitted=False)
    seq = w.failed("a", [], "EXHAUSTED", "time")
    result = run(s, w.write())
    assert result.certificate["not_admitted"] == [
        {"record": {"journal": w.id, "seq": seq}, "reason": "checker_not_admitted"}
    ]


def test_null_solver_list_admits_any_solver(tmp_path: Path) -> None:
    admit = {"checker_sha256": [CHECKER], "solvers": None}
    s = Scenario(tmp_path, {"a": ALL3}, admit=admit)
    w = s.journal("w1", machinery=machinery(solver_argv=["--lrat", "--seed=7"]))
    w.unsat("a", [])
    result = run(s, w.write())
    assert result.verdict == Verdict.PROVED
    assert result.certificate["not_admitted"] == []


SUCCESS_CASES: list[tuple[str, dict[str, Any]]] = [
    ("success.proof", {"proof_bytes": None, "proof_sha256": None}),
    ("success.checks", {"checks": []}),
    ("success.checker_output", {"checks": [checked(0, "s VERIFIED UNSAT \n")]}),
    ("success.checker_output", {"checks": [checked(1)]}),
    ("success.checker_output", {"checks": [checked(0), checked(0, "s VERIFIED\n")]}),
    ("success.solver", {"solver": solver_result(0)}),
]


@pytest.mark.parametrize(("rule", "fields"), SUCCESS_CASES, ids=[r for r, _ in SUCCESS_CASES])
def test_admitted_success_fields_are_enforced(
    tmp_path: Path, rule: str, fields: dict[str, Any]
) -> None:
    s = Scenario(tmp_path, {"a": ALL3})
    w = s.journal("w1")
    w.unsat("a", [], **fields)
    with pytest.raises(IntegrityError) as caught:
        certify(s.campaign_path, [w.write()])
    assert caught.value.rule == rule


NONADMITTED_MACHINERY: list[tuple[str, dict[str, Any]]] = [
    ("checker_not_admitted", {"checker": OTHER_HASH}),
    ("solver_not_admitted", {"solver_argv": ["--lrat", "--seed=1"]}),
]


@pytest.mark.parametrize(
    ("reason", "different"), NONADMITTED_MACHINERY, ids=[r for r, _ in NONADMITTED_MACHINERY]
)
@pytest.mark.parametrize(("rule", "fields"), SUCCESS_CASES, ids=[r for r, _ in SUCCESS_CASES])
def test_nonadmitted_success_violations_are_only_listed(
    tmp_path: Path, rule: str, fields: dict[str, Any], reason: str, different: dict[str, Any]
) -> None:
    # Any non-admission reason (checker or solver) turns success.* violations into a mere
    # not_admitted entry (requirements success.proof); gating on the checker alone is wrong.
    del rule
    s = Scenario(tmp_path, {"a": ALL3})
    w = s.journal("w1", machinery=machinery(**different), admitted=False)
    seq = w.unsat("a", [], **fields)
    result = run(s, w.write())
    assert result.certificate["not_admitted"] == [
        {"record": {"journal": w.id, "seq": seq}, "reason": reason}
    ]
    assert result.verdict == Verdict.OPEN


def test_an_accepting_check_after_arena_exhaustions_is_a_success(tmp_path: Path) -> None:
    s = Scenario(tmp_path, {"a": ALL3})
    w = s.journal("w1")
    w.unsat("a", [], checks=[checked(1, "c arena exhausted\n"), checked(0)])
    assert run(s, w.write()).verdict == Verdict.PROVED


def test_stream_and_retain_success_records_are_admitted(tmp_path: Path) -> None:
    s = Scenario(tmp_path, {"a": ALL3}, root_splits=[("a", [], [1])])
    w = s.journal("w1", policy=dict(POLICY, proof_mode="stream"))
    proof = "cd" * 32
    relay = {"bytes": 77, "sha256": proof, "solver_eof": True, "all_written": True, "error": None}
    w.unsat("a", [1], proof_bytes=77, proof_sha256=proof, relay=relay)
    w.resume(policy=dict(POLICY, proof_mode="retain"))
    retained = {"path": f"proofs/x-{proof}.lrat", "sha256": proof, "bytes": 77}
    w.unsat("a", [-1], proof_bytes=77, proof_sha256=proof, retained=retained)
    result = run(s, w.write())
    assert result.verdict == Verdict.PROVED


def test_wrong_cnf_hash_is_an_integrity_error_also_when_not_admitted(tmp_path: Path) -> None:
    s = Scenario(tmp_path, {"a": ALL3})
    w = s.journal("w1", machinery=machinery(checker=OTHER_HASH), admitted=False)
    w.attempt(
        "a",
        [1],
        outcome="TOOL_FAILED",
        reason="io",
        checks=[],
        proof_bytes=None,
        proof_sha256=None,
        cnf_sha256=sha(cnf_bytes(ALL3, [-1])),
    )
    with pytest.raises(IntegrityError) as caught:
        certify(s.campaign_path, [w.write()])
    assert caught.value.rule == "attempt.cnf_sha256"


# -- models and anomalies --------------------------------------------------------------------------


def test_nonadmitted_valid_model_binds_and_is_found(tmp_path: Path) -> None:
    s = Scenario(tmp_path, {"s": SAT3})
    w = s.journal("w1", machinery=machinery(checker=OTHER_HASH), admitted=False)
    values = (True, False, False)
    seq = w.model("s", [], values)
    result = run(s, w.write())
    assert result.certificate["models"] == [
        {
            "record": {"journal": w.id, "seq": seq},
            "node": node(s.sha("s"), []),
            "assignment": "AQ==",
        }
    ]
    assert result.certificate["not_admitted"][0]["record"]["seq"] == seq
    assert result.verdict == Verdict.MODEL_FOUND
    assert result.exit_code == 2
    assert opens(result) == [([], "model", None)]


def test_a_false_model_is_an_integrity_error_also_when_not_admitted(tmp_path: Path) -> None:
    s = Scenario(tmp_path, {"s": SAT3})
    w = s.journal("w1", machinery=machinery(checker=OTHER_HASH), admitted=False)
    w.model("s", [], (False, False, True))
    with pytest.raises(IntegrityError) as caught:
        certify(s.campaign_path, [w.write()])
    assert caught.value.rule == "attempt.model_false"


def test_a_model_must_satisfy_its_cube_units(tmp_path: Path) -> None:
    s = Scenario(tmp_path, {"s": SAT3})
    w = s.journal("w1")
    w.model("s", [-1], (True, True, False))
    with pytest.raises(IntegrityError) as caught:
        certify(s.campaign_path, [w.write()])
    assert caught.value.rule == "attempt.model_false"


def test_invalid_models_mislabelled_models_and_rejections(tmp_path: Path) -> None:
    s = Scenario(tmp_path, {"s": SAT3})
    w = s.journal("w1")
    wrong = w.model("s", [], (False, False, True), outcome="INVALID_MODEL")
    good = w.model("s", [2], (False, True, True), outcome="INVALID_MODEL")
    cube_false = w.model("s", [-1], (True, False, False), outcome="INVALID_MODEL")
    parse = w.parse_error("s", [1], "conflicting")
    rejected = w.failed("s", [1, 2], "CHECK_REJECTED", "rejected")
    result = run(s, w.write())

    def anomaly(seq: int, code: str, info: dict[str, Any]) -> dict[str, Any]:
        return {"record": {"journal": w.id, "seq": seq}, "code": code, "info": info}

    expected = [
        anomaly(wrong, "invalid_model", {"model_error": "violated"}),
        anomaly(good, "mislabelled_model", {}),
        anomaly(cube_false, "invalid_model", {"model_error": "violated"}),
        anomaly(parse, "invalid_model", {"model_error": "conflicting"}),
        anomaly(rejected, "check_rejected", {}),
    ]
    assert result.certificate["anomalies"] == expected
    assert [m["record"]["seq"] for m in result.certificate["models"]] == [good]
    assert result.verdict == Verdict.MODEL_FOUND


def test_a_node_with_a_valid_model_is_emitted_as_model_despite_a_split(tmp_path: Path) -> None:
    s = Scenario(tmp_path, {"s": SAT3})
    w = s.journal("w1")
    w.split("s", [], [1])
    w.model("s", [], (True, True, True), route="unit")
    result = run(s, w.write())
    assert opens(result) == [([], "model", None)]
    assert opens(result, "formula_open") == [([], "model", None)]


def test_a_valid_model_under_a_closed_empty_cube_is_inconsistent(tmp_path: Path) -> None:
    s = Scenario(tmp_path, {"s": SAT3})
    w = s.journal("w1")
    w.unsat("s", [])
    w.model("s", [1], (True, False, False))
    result = run(s, w.write())
    assert result.verdict == Verdict.INCONSISTENT
    assert result.exit_code == 4
    assert result.certificate["formulas"][0]["proved"] is True


@pytest.mark.parametrize("third_proved", [False, True], ids=["one_open", "open_and_proved"])
def test_inconsistency_of_one_formula_is_reported_while_another_is_open(
    tmp_path: Path, third_proved: bool
) -> None:
    # Specification §10.4 rule 1: INCONSISTENT as soon as *some* formula has a valid model and a
    # closed empty cube, regardless of whether the other campaign formulas are proved.
    formulas = {"s": SAT3, "a": ALL3}
    if third_proved:
        formulas["u"] = F_UNSAT
    s = Scenario(tmp_path, formulas)
    w = s.journal("w1")
    w.unsat("s", [])
    w.model("s", [1], (True, False, False))
    if third_proved:
        w.unsat("u", [])
    result = run(s, w.write())
    assert result.verdict == Verdict.INCONSISTENT
    assert result.exit_code == 4
    proved = {f["formula_sha256"]: f["proved"] for f in result.certificate["formulas"]}
    expected = {s.sha("s"): True, s.sha("a"): False}
    if third_proved:
        expected[s.sha("u")] = True
    assert proved == expected


def test_a_model_in_one_formula_and_a_proof_of_another_is_model_found(tmp_path: Path) -> None:
    s = Scenario(tmp_path, {"s": SAT3, "u": F_UNSAT})
    w = s.journal("w1")
    w.unsat("u", [])
    w.model("s", [], (False, True, False))
    result = run(s, w.write())
    assert result.verdict == Verdict.MODEL_FOUND


# -- malformed splits ------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("cube", "variables", "problem"),
    [
        ([], [], "empty"),
        ([], list(range(1, 22)), "too_long"),
        ([], [1, 1], "repeated"),
        ([], [4], "out_of_range"),
        ([1], [1], "in_cube"),
        ([1], [2, 2, 9], "repeated"),
    ],
)
def test_a_malformed_journal_split_is_an_anomaly_and_ignored(
    tmp_path: Path, cube: list[int], variables: list[int], problem: str
) -> None:
    big = dimacs(25, [[1], [-1]])
    s = Scenario(tmp_path, {"a": big if problem == "too_long" else ALL3})
    w = s.journal("w1")
    seq = w.split("a", cube, variables)
    result = run(s, w.write())
    assert result.certificate["anomalies"] == [
        {
            "record": {"journal": w.id, "seq": seq},
            "code": "malformed_split",
            "info": {"problem": problem},
        }
    ]
    assert opens(result) == [([], "pending", None)]


# -- frontier labels -------------------------------------------------------------------------------


def test_labels_use_each_workers_latest_event_and_the_smallest_stop_ref(tmp_path: Path) -> None:
    s = Scenario(tmp_path, {"a": ALL3}, root_splits=[("a", [], [1])])
    w1, w2 = s.journal("w1"), s.journal("w2")
    w1.stop("a", [1], "stuck", "first")
    w1.reopen("a", [1])
    w1.stop("a", [-1], "stuck", "old")
    w1.stop("a", [-1], "tool_blocked", "new")
    w2.stop("a", [-1], "resource_blocked", "disk")
    result = run(s, w1.write(), w2.write())
    labels = {tuple(c): (state, reason) for c, state, reason in opens(result)}
    assert labels[(1,)] == ("pending", None)
    low = min(w1, w2, key=lambda w: w.id)
    expected = ("tool_blocked", "new") if low is w1 else ("resource_blocked", "disk")
    assert labels[(-1,)] == expected


def test_labels_never_change_closure(tmp_path: Path) -> None:
    s = Scenario(tmp_path, {"a": ALL3})
    w = s.journal("w1")
    w.stop("a", [], "stuck", "x")
    w.unsat("a", [])
    result = run(s, w.write())
    assert result.verdict == Verdict.PROVED
    assert result.certificate["open"] == []


# -- journal copies, forks and workers -------------------------------------------------------------


def test_prefix_copies_use_the_longest_and_its_smallest_torn_tail(tmp_path: Path) -> None:
    s = Scenario(tmp_path, {"a": ALL3}, root_splits=[("a", [], [1])])
    w = s.journal("w1")
    w.unsat("a", [1])
    w.unsat("a", [-1])
    full = len(w.records)
    long_torn = w.write("long-torn.jsonl", torn=b'{"seq":')
    long_clean = w.write("long-clean.jsonl", torn=b"{")
    short = w.write("short.jsonl", upto=2, torn=b"x")
    result = run(s, short, long_torn, long_clean)
    [entry] = result.certificate["journals"]
    assert entry["records"] == full
    assert entry["torn_tail_bytes"] == 1
    assert entry["bytes"] == len(w.data())
    assert entry["head"] == w.records[-1]["self"]
    assert result.verdict == Verdict.PROVED
    used = {Path(i.path).name for i in result.inputs if i.used}
    assert used == {"long-clean.jsonl"}


def test_a_fork_is_an_integrity_error(tmp_path: Path) -> None:
    s = Scenario(tmp_path, {"a": ALL3})
    w = s.journal("w1")
    w.unsat("a", [1])
    first = w.write("a.jsonl")
    w.records.pop()
    w.unsat("a", [-1])
    second = w.write("b.jsonl")
    with pytest.raises(IntegrityError) as caught:
        certify(s.campaign_path, [first, second])
    assert caught.value.rule == "journal.fork"


def test_one_worker_with_two_header_ids_is_an_integrity_error(tmp_path: Path) -> None:
    s = Scenario(tmp_path, {"a": ALL3})
    w1 = s.journal("w1")
    other = s.journal("w1", policy=dict(POLICY, tool_retries=4))
    with pytest.raises(IntegrityError) as caught:
        certify(s.campaign_path, [w1.write("one.jsonl"), other.write("two.jsonl")])
    assert caught.value.rule == "journal.worker"


def test_a_foreign_campaign_is_an_input_error(tmp_path: Path) -> None:
    s = Scenario(tmp_path, {"a": ALL3})
    w = s.journal("w1", campaign="12" * 32)
    with pytest.raises(InputError) as caught:
        certify(s.campaign_path, [w.write()])
    assert caught.value.rule == "journal.campaign"


def test_a_campaign_without_journals_is_open(tmp_path: Path) -> None:
    s = Scenario(tmp_path, {"a": ALL3}, root_splits=[("a", [], [1])])
    result = run(s)
    assert result.verdict == Verdict.OPEN
    assert result.certificate["journals"] == []
    assert sorted(opens(result)) == [([-1], "pending", None), ([1], "pending", None)]


# -- explicit stack and resource limits ------------------------------------------------------------


def test_a_split_chain_deeper_than_the_recursion_limit(tmp_path: Path) -> None:
    depth = 1100
    s = Scenario(tmp_path, {"u": dimacs(depth + 1, [[1], [-1]])})
    w = s.journal("w1")
    cube: list[int] = []
    for variable in range(1, depth + 1):
        w.split("u", cube, [variable])
        w.unsat("u", [*cube, -variable], route="unit")
        cube = [*cube, variable]
    w.unsat("u", cube, route="unit")
    result = run(s, w.write())
    summary = result.certificate["formulas"][0]["summary"]
    assert (summary["leaves"], summary["splits"], summary["max_cube_size"]) == (
        depth + 1,
        depth,
        depth,
    )
    assert result.verdict == Verdict.PROVED


def test_a_node_limit_is_a_resource_error_not_an_open_result(tmp_path: Path) -> None:
    s = Scenario(tmp_path, {"a": ALL3}, root_splits=[("a", [], [1, 2, 3])])
    w = s.journal("w1")
    path = w.write()
    with pytest.raises(ResourceError):
        certify(s.campaign_path, [path], limits=CertifyLimits(max_nodes=5))
    assert certify(s.campaign_path, [path], limits=CertifyLimits(max_nodes=9)).verdict == (
        Verdict.OPEN
    )


def test_certificates_are_canonical_documents(tmp_path: Path) -> None:
    s = Scenario(tmp_path, {"a": ALL3})
    w = s.journal("w1")
    w.unsat("a", [])
    result = run(s, w.write())
    assert result.document == j(result.certificate) + b"\n"
    assert json.loads(result.document) == result.certificate
    assert result.certificate["campaign"] == s.campaign_id
    assert result.certificate["machinery"][0]["machinery"]["solver"]["sha256"] == SOLVER
