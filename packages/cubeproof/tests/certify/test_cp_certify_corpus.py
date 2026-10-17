"""The main certifier on the frozen contract corpus (specification §4.9, §10).

Every evidence case must give exactly the expected certificate bytes and exit code, or no
certificate and exactly the expected error kind and rule. Input order has no effect, neither
on certificates nor on the reported error.
"""

from __future__ import annotations

import itertools
import json
import shutil
from pathlib import Path
from typing import Any

import pytest
from cp_certify_support import (
    CORPUS,
    audit_plans,
    cases,
    certificate_problems,
    j,
    schema_errors,
    sha,
)

from cubeproof.api import _certificate_value
from cubeproof.base.canonical_json import document_bytes
from cubeproof.base.errors import CubeproofError, InputError, ResourceError
from cubeproof.base.settings import ReaderLimits
from cubeproof.contracts.enums import Verdict
from cubeproof.evidence.certify import CertifyLimits, CertifyResult, certify, exit_code


def run(case: dict[str, Any], order: list[str] | None = None) -> CertifyResult:
    journals = [CORPUS / p for p in (order if order is not None else case["journals"])]
    return certify(CORPUS / case["campaign"], journals)


def error_of(case: dict[str, Any], order: list[str] | None = None) -> CubeproofError:
    with pytest.raises(CubeproofError) as caught:
        run(case, order)
    return caught.value


VALID = [c for c in cases() if "certificate" in c["expect"]]
FAILING = [c for c in cases() if "error" in c["expect"]]


def test_the_corpus_has_valid_and_failing_cases() -> None:
    assert len(VALID) >= 16
    assert len(FAILING) >= 80
    verdicts = {
        json.loads((CORPUS / c["expect"]["certificate"]).read_bytes())["verdict"] for c in VALID
    }
    assert verdicts == {v.value for v in Verdict}


@pytest.mark.parametrize("case", VALID, ids=lambda c: c["id"])
def test_valid_case_gives_the_expected_certificate_bytes(case: dict[str, Any]) -> None:
    result = run(case)
    expected = (CORPUS / case["expect"]["certificate"]).read_bytes()
    assert result.document == expected
    assert j(result.certificate) + b"\n" == expected
    assert result.exit_code == case["expect"]["exit"]
    assert result.verdict == Verdict(result.certificate["verdict"])
    assert exit_code(result.verdict) == case["expect"]["exit"]
    assert schema_errors(result.certificate) == []
    assert certificate_problems(result.certificate) == []


@pytest.mark.parametrize("case", FAILING, ids=lambda c: c["id"])
def test_failing_case_gives_no_certificate_and_the_expected_rule(case: dict[str, Any]) -> None:
    error = error_of(case)
    expect = case["expect"]
    assert expect["exit"] == 4
    assert (error.kind, error.rule) == (expect["error"]["kind"], expect["error"]["rule"])


def test_exit_codes_of_the_verdicts() -> None:
    assert exit_code(Verdict.PROVED) == 0
    assert exit_code(Verdict.OPEN) == 1
    assert exit_code(Verdict.MODEL_FOUND) == 2
    assert exit_code(Verdict.INCONSISTENT) == 4


@pytest.mark.parametrize(
    "case", [c for c in VALID if len(c["journals"]) >= 2], ids=lambda c: c["id"]
)
def test_journal_input_order_has_no_effect(case: dict[str, Any]) -> None:
    expected = (CORPUS / case["expect"]["certificate"]).read_bytes()
    for order in itertools.permutations(case["journals"]):
        assert run(case, list(order)).document == expected, order


def test_a_journal_given_twice_counts_once() -> None:
    case = next(c for c in VALID if c["id"] == "base")
    expected = (CORPUS / case["expect"]["certificate"]).read_bytes()
    result = run(case, case["journals"] * 3)
    assert result.document == expected
    assert sum(1 for i in result.inputs if i.used) == 1
    assert len(result.inputs) == 3


@pytest.mark.parametrize(
    "case", [c for c in FAILING if len(c["journals"]) >= 2], ids=lambda c: c["id"]
)
def test_failing_cases_report_the_same_error_in_every_order(case: dict[str, Any]) -> None:
    for order in itertools.permutations(case["journals"]):
        error = error_of(case, list(order))
        assert (error.kind, error.rule) == (
            case["expect"]["error"]["kind"],
            case["expect"]["error"]["rule"],
        )


def test_the_duplicates_case_reports_its_duplicate_inputs() -> None:
    case = next(c for c in VALID if c["id"] == "duplicates")
    result = run(case)
    by_path = {Path(i.path).name: i for i in result.inputs}
    assert set(by_path) == {Path(p).name for p in case["journals"]}
    used = {name for name, i in by_path.items() if i.used}
    duplicates = {name for name, i in by_path.items() if not i.used}
    certificate_ids = {e["id"] for e in result.certificate["journals"]}
    assert {by_path[n].id for n in used} == certificate_ids
    assert len(used) == len(certificate_ids)
    assert duplicates
    assert all(by_path[n].id in certificate_ids for n in duplicates)
    for name, item in by_path.items():
        data = (CORPUS / next(p for p in case["journals"] if p.endswith(name))).read_bytes()
        assert item.sha256 == sha(data)
    assert {i.path for i in result.duplicates} == {i.path for i in result.inputs if not i.used}


@pytest.mark.parametrize("plan", audit_plans(), ids=lambda p: p["id"])
def test_audit_plan_journals_are_certified_as_evidence(plan: dict[str, Any]) -> None:
    """The audit plan rules are the audit's; certify accepts every audit plan journal."""
    result = certify(CORPUS / plan["campaign"], [CORPUS / plan["journal"]])
    assert schema_errors(result.certificate) == []
    assert certificate_problems(result.certificate) == []


# -- dynamic inputs --------------------------------------------------------------------------------


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


def test_a_missing_journal_file_is_an_input_error(tmp_path: Path) -> None:
    campaign, journals = copy_case("base", tmp_path)
    with pytest.raises(InputError) as caught:
        certify(campaign, [*journals, tmp_path / "absent.jsonl"])
    assert caught.value.rule == "journal.file"


def test_a_directory_given_as_journal_is_an_input_error(tmp_path: Path) -> None:
    campaign, journals = copy_case("base", tmp_path)
    with pytest.raises(InputError) as caught:
        certify(campaign, [*journals, tmp_path])
    assert caught.value.rule == "journal.file"


def test_a_missing_campaign_file_is_an_input_error(tmp_path: Path) -> None:
    _, journals = copy_case("base", tmp_path)
    with pytest.raises(InputError) as caught:
        certify(tmp_path / "absent.json", journals)
    assert caught.value.rule == "campaign.file"


def test_a_symlinked_bundle_is_an_input_error(tmp_path: Path) -> None:
    campaign, journals = copy_case("base", tmp_path)
    bundles = campaign.parent / "bundles"
    outside = tmp_path / "outside"
    shutil.move(str(bundles), outside)
    bundles.symlink_to(outside, target_is_directory=True)
    with pytest.raises(InputError) as caught:
        certify(campaign, journals)
    assert caught.value.rule == "path.containment"


def test_a_line_over_the_reader_limit_is_a_resource_error(tmp_path: Path) -> None:
    campaign, journals = copy_case("base", tmp_path)
    longest = max(len(line) for line in journals[0].read_bytes().split(b"\n"))
    limits = CertifyLimits(reader=ReaderLimits(line_bytes=longest - 1))
    with pytest.raises(ResourceError) as caught:
        certify(campaign, journals, limits=limits)
    assert caught.value.rule == "limit.line"
    assert certify(campaign, journals, limits=CertifyLimits(ReaderLimits(line_bytes=longest)))


def test_the_campaign_document_limit_is_a_resource_error(tmp_path: Path) -> None:
    campaign, journals = copy_case("base", tmp_path)
    size = len(campaign.read_bytes()) - 1
    with pytest.raises(ResourceError) as caught:
        certify(campaign, journals, limits=CertifyLimits(ReaderLimits(document_bytes=size - 1)))
    assert caught.value.rule == "limit.document"


def test_the_api_returns_a_certificate_above_the_document_limit() -> None:
    # Specification §4.1: a certificate has no document size limit; the API parses the document
    # the certifier wrote, which for the campaign of 59 formulas exceeds 64 MiB at its start.
    value = {"open": ["a" * (64 << 20)]}
    assert _certificate_value(document_bytes(value)) == value


def test_a_resource_error_and_an_integrity_error_are_reported_independently_of_order(
    tmp_path: Path,
) -> None:
    """With several broken journals the reported error does not depend on input order."""
    campaign, journals = copy_case("base", tmp_path)
    broken = [CORPUS / "journals/x_journal_self/w1.jsonl", CORPUS / "journals/x_json_bom/w1.jsonl"]
    rules = set()
    for order in itertools.permutations([*journals, *broken]):
        with pytest.raises(CubeproofError) as caught:
            certify(campaign, list(order))
        rules.add((caught.value.kind, caught.value.rule))
    assert len(rules) == 1
