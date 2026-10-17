"""Evidence cases: campaign + bundles + journals -> certificate or exit 4.

Specification §4.9, §7.1 and §10.

``corpus/cases.json`` lists every case with the expected exit code and either the expected
certificate bytes (J + LF) or the error kind (``input``, ``integrity``, ``resource``) and
rule. The reference reader recomputes each case independently of the generator.
"""

from __future__ import annotations

import hashlib
import itertools
import json
import shutil
from pathlib import Path
from typing import Any

import pytest
from contract_reader import (
    CORPUS,
    DOCUMENT_LIMIT,
    LINE_LIMIT,
    audit_plan_problems,
    certificate_problems,
    certify,
    cube_cnf,
    j_bytes,
    j_hash,
    load_campaign,
    load_json_file,
    open_store,
    parse_dimacs,
    read_journal,
)
from contract_schema import SchemaStore


def cases_file() -> dict[str, Any]:
    data: dict[str, Any] = load_json_file(CORPUS / "cases.json")
    assert data["format"] == "cubeproof-contract-cases-1"
    return data


def cases() -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = cases_file()["cases"]
    return entries


@pytest.fixture(scope="module")
def store() -> SchemaStore:
    return open_store()


def run(case: dict[str, Any], store: SchemaStore, order: list[str] | None = None) -> Any:
    journals = [CORPUS / p for p in (order if order is not None else case["journals"])]
    return certify(CORPUS / case["campaign"], journals, store)


@pytest.mark.parametrize("case", cases(), ids=lambda c: c["id"])
def test_case(store: SchemaStore, case: dict[str, Any]) -> None:
    outcome = run(case, store)
    expect = case["expect"]
    assert outcome.exit == expect["exit"], outcome.detail
    if "certificate" in expect:
        assert outcome.certificate is not None, (outcome.kind, outcome.rule, outcome.detail)
        expected = (CORPUS / expect["certificate"]).read_bytes()
        assert j_bytes(outcome.certificate) + b"\n" == expected
        assert store.errors(outcome.certificate, "certificate.schema.json") == []
        assert certificate_problems(outcome.certificate) == []
    else:
        assert outcome.certificate is None
        assert (outcome.kind, outcome.rule) == (expect["error"]["kind"], expect["error"]["rule"])


def test_case_identifiers_are_unique_and_kinds_are_known() -> None:
    entries = cases()
    assert len({c["id"] for c in entries}) == len(entries)
    kinds = {c["expect"]["error"]["kind"] for c in entries if "error" in c["expect"]}
    assert kinds == {"input", "integrity", "resource"}
    verdicts = {
        load_json_file(CORPUS / c["expect"]["certificate"])["verdict"]
        for c in entries
        if "certificate" in c["expect"]
    }
    assert verdicts == {"PROVED", "OPEN", "MODEL_FOUND", "INCONSISTENT"}


def test_certificates_do_not_depend_on_journal_input_order(store: SchemaStore) -> None:
    """Specification §10.1: input order has no semantic effect; duplicates and prefixes included."""
    checked = 0
    for case in cases():
        journals = case["journals"]
        if "certificate" not in case["expect"] or len(journals) < 2:
            continue
        expected = (CORPUS / case["expect"]["certificate"]).read_bytes()
        orders = list(itertools.permutations(journals))[:24]
        for order in orders:
            outcome = run(case, store, list(order))
            assert outcome.certificate is not None
            assert j_bytes(outcome.certificate) + b"\n" == expected, (case["id"], order)
        checked += 1
    assert checked >= 5


def all_assignments(variables: int) -> list[list[bool]]:
    return [[bool(n >> i & 1) for i in range(variables)] for n in range(1 << variables)]


def test_truthful_cases_use_only_really_unsatisfiable_leaves(store: SchemaStore) -> None:
    """Specification §15.1 soundness on the corpus: every used leaf CNF is UNSAT by brute force,
    and a PROVED certificate of a truthful case has only UNSAT formulas."""
    for case in cases():
        if "certificate" not in case["expect"] or case.get("lying", False):
            continue
        campaign = load_campaign(CORPUS / case["campaign"], store)
        certificate = load_json_file(CORPUS / case["expect"]["certificate"])
        for used in certificate["used_attempts"]:
            node = used["node"]
            formula = parse_dimacs(cube_cnf(campaign.formula(node["formula_sha256"]), node["cube"]))
            for values in all_assignments(formula.variables):
                assert not all(
                    any(values[abs(x) - 1] == (x > 0) for x in clause) for clause in formula.clauses
                ), (case["id"], node)
        for entry in certificate["formulas"]:
            if entry["proved"]:
                formula = campaign.formula(entry["formula_sha256"])
                assert not any(
                    all(any(v[abs(x) - 1] == (x > 0) for x in c) for c in formula.clauses)
                    for v in all_assignments(formula.variables)
                ), case["id"]


def lenient_j(value: Any) -> bytes:
    """J of a value parsed by a lenient reader (floats and big integers kept as parsed)."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


LENIENT_JSON_RULES = {"json.canonical", "json.duplicate_key", "json.number", "json.integer_range"}


def test_json_rule_fixtures_violate_only_their_json_rule() -> None:
    """A journal case named after a json.* rule breaks nothing else.

    A lenient reader (Python json: last duplicate key wins, floats and big integers kept)
    that skips the json.* checks must find every self hash and prev link intact, so the
    case shows that the json rule alone rejects it, not only the specification §7.1 check order.
    """
    checked = set()
    for case in cases():
        error = case["expect"].get("error")
        if error is None or error["rule"] not in LENIENT_JSON_RULES or not case["journals"]:
            continue
        [path] = case["journals"]
        lines = (CORPUS / path).read_bytes().split(b"\n")
        assert lines[-1] == b"", case["id"]
        prev = "0" * 64
        for line in lines[:-1]:
            record = json.loads(line)
            own = record.pop("self")
            assert own == hashlib.sha256(lenient_j(record)).hexdigest(), (case["id"], line[:60])
            assert record["prev"] == prev, case["id"]
            prev = own
        checked.add(error["rule"])
    assert checked == LENIENT_JSON_RULES


def test_lying_cases_are_declared() -> None:
    lying = {c["id"] for c in cases() if c.get("lying", False)}
    assert lying == {"inconsistent"}


# -- dynamic cases: limits and containment that need no large or OS-specific fixture -----------


def copy_case(case_id: str, target: Path) -> tuple[Path, list[Path]]:
    case = next(c for c in cases() if c["id"] == case_id)
    campaign = CORPUS / case["campaign"]
    shutil.copytree(campaign.parent, target / "campaign")
    journals = []
    for index, name in enumerate(case["journals"]):
        copy = target / f"j{index}.jsonl"
        shutil.copyfile(CORPUS / name, copy)
        journals.append(copy)
    return target / "campaign" / campaign.name, journals


def append_record(path: Path, record: dict[str, Any]) -> None:
    lines = path.read_bytes().split(b"\n")[:-1]

    last = json.loads(lines[-1])
    record = record | {"seq": last["seq"] + 1, "prev": last["self"]}
    record.pop("self", None)
    record["self"] = j_hash(record)
    with path.open("ab") as handle:
        handle.write(j_bytes(record) + b"\n")


def test_dynamic_line_limit(store: SchemaStore, tmp_path: Path) -> None:
    """Specification §4.1/§4.7: a line longer than 8 MiB is a reader resource error, not
    evidence."""
    campaign, journals = copy_case("base", tmp_path)

    first = json.loads(journals[0].read_bytes().split(b"\n")[2])
    assert first["type"] == "attempt"
    big = first | {"attempt_id": "f" * 32, "diagnostics": {"pad": "x" * LINE_LIMIT}}
    append_record(journals[0], big)
    outcome = certify(campaign, journals, store)
    assert (outcome.exit, outcome.kind, outcome.rule) == (4, "resource", "limit.line")


def test_dynamic_line_just_below_the_limit_is_read(store: SchemaStore, tmp_path: Path) -> None:
    campaign, journals = copy_case("base", tmp_path)

    first = json.loads(journals[0].read_bytes().split(b"\n")[2])
    record = first | {"attempt_id": "e" * 32, "diagnostics": {"pad": ""}}
    size = len(j_bytes(record | {"seq": 99, "prev": "0" * 64, "self": "0" * 64}))
    record["diagnostics"] = {"pad": "x" * (LINE_LIMIT - size - 2)}
    append_record(journals[0], record)
    assert len(journals[0].read_bytes().split(b"\n")[-2]) <= LINE_LIMIT
    outcome = certify(campaign, journals, store)
    assert outcome.certificate is not None, (outcome.kind, outcome.rule)


def append_record_of_length(path: Path, record: dict[str, Any], length: int) -> None:
    """Append ``record``, padded in diagnostics to a line of ``length`` bytes without LF."""
    lines = path.read_bytes().split(b"\n")[:-1]
    last = json.loads(lines[-1])
    probe = record | {"seq": last["seq"] + 1, "prev": last["self"], "diagnostics": {"pad": ""}}
    probe.pop("self", None)
    size = len(j_bytes(probe | {"self": "0" * 64}))
    assert size < length
    append_record(path, record | {"diagnostics": {"pad": "x" * (length - size)}})
    assert len(path.read_bytes().split(b"\n")[-2]) == length


def test_dynamic_line_of_exactly_the_limit_is_read(store: SchemaStore, tmp_path: Path) -> None:
    """Specification §4.1/§4.7 boundary: a line of exactly 8 MiB (without its LF) is within the
    limit."""
    campaign, journals = copy_case("base", tmp_path)
    first = json.loads(journals[0].read_bytes().split(b"\n")[2])
    append_record_of_length(journals[0], first | {"attempt_id": "d" * 32}, LINE_LIMIT)
    outcome = certify(campaign, journals, store)
    assert outcome.certificate is not None, (outcome.kind, outcome.rule)


def test_dynamic_line_one_byte_over_the_limit(store: SchemaStore, tmp_path: Path) -> None:
    """Specification §4.1/§4.7 boundary: one byte more than 8 MiB is a reader resource error."""
    campaign, journals = copy_case("base", tmp_path)
    first = json.loads(journals[0].read_bytes().split(b"\n")[2])
    append_record_of_length(journals[0], first | {"attempt_id": "c" * 32}, LINE_LIMIT + 1)
    outcome = certify(campaign, journals, store)
    assert (outcome.exit, outcome.kind, outcome.rule) == (4, "resource", "limit.line")


def test_dynamic_document_of_exactly_the_limit_is_read(store: SchemaStore, tmp_path: Path) -> None:
    """Specification §4.1 boundary: a campaign whose J bytes are exactly 64 MiB passes the size
    limit; the spaces used to reach that size then make it noncanonical."""
    campaign, journals = copy_case("base", tmp_path)
    data = campaign.read_bytes()
    campaign.write_bytes(data[:-1] + b" " * (DOCUMENT_LIMIT + 1 - len(data)) + b"\n")
    outcome = certify(campaign, journals, store)
    assert (outcome.exit, outcome.kind, outcome.rule) == (4, "input", "json.canonical")


def test_dynamic_document_limit(store: SchemaStore, tmp_path: Path) -> None:
    """Specification §4.1: a campaign document larger than 64 MiB is a reader resource error."""
    campaign, journals = copy_case("base", tmp_path)
    data = campaign.read_bytes()
    campaign.write_bytes(data[:-1] + b" " * (DOCUMENT_LIMIT + 2 - len(data)) + b"\n")
    outcome = certify(campaign, journals, store)
    assert (outcome.exit, outcome.kind, outcome.rule) == (4, "resource", "limit.document")


def test_dynamic_path_containment_symlinked_bundle(store: SchemaStore, tmp_path: Path) -> None:
    """Specification §4.1: resolve and check containment, including symlinks; bundle files are
    regular."""
    campaign, journals = copy_case("base", tmp_path)
    bundles = campaign.parent / "bundles"
    outside = tmp_path / "outside"
    shutil.move(str(bundles), outside)
    bundles.symlink_to(outside, target_is_directory=True)
    outcome = certify(campaign, journals, store)
    assert (outcome.exit, outcome.kind, outcome.rule) == (4, "input", "path.containment")


def test_dynamic_path_containment_symlinked_formula(store: SchemaStore, tmp_path: Path) -> None:
    campaign, journals = copy_case("base", tmp_path)
    formula = next(campaign.parent.glob("bundles/*/formula.cnf"))
    moved = tmp_path / "formula.cnf"
    shutil.move(str(formula), moved)
    formula.symlink_to(moved)
    outcome = certify(campaign, journals, store)
    assert (outcome.exit, outcome.kind, outcome.rule) == (4, "input", "path.containment")


# -- audit plans (consumer: audit; certify accepts all of them) ---------------------------------


def audit_plans() -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = cases_file()["audit_plans"]
    return entries


@pytest.mark.parametrize("plan", audit_plans(), ids=lambda p: p["id"])
def test_audit_plan(store: SchemaStore, plan: dict[str, Any]) -> None:
    campaign = load_campaign(CORPUS / plan["campaign"], store)
    journal = read_journal(CORPUS / plan["journal"], store, campaign)
    expect = [] if plan["expect"] == "valid" else [plan["expect"]["rule"]]
    assert audit_plan_problems(journal.records) == expect
