"""The plan and results inside an audit journal (specification §4.7, §11.1, §11.2).

The audit-plan cases of the contract corpus fix the four reader rules (``audit.plan_order``,
``audit.targets_hash``, ``audit.result_unique``, ``audit.result_ref``). Covered here:
a crash during the plan or between an attempt and its result leaves a journal that a restart
can read and finish.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

import cp_audit_support as s

from cubeproof.base.errors import IntegrityError
from cubeproof.cnf.campaign import LoadedCampaign, load_campaign
from cubeproof.commands.audit_journal import read_audit_journal
from cubeproof.contracts.values import Ref
from cubeproof.evidence.schema import (
    Attempt,
    AuditReady,
    AuditResult,
    Header,
    Resume,
    check_record,
)

ALL3 = s.CORPUS / "campaigns" / "all3" / "campaign.json"
AUDIT1 = "journals/modes/audit1.jsonl"


@pytest.fixture(scope="module")
def all3() -> LoadedCampaign:
    return load_campaign(ALL3)


def plans() -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = s.load(s.CORPUS / "cases.json")["audit_plans"]
    return entries


@pytest.mark.parametrize("plan", plans(), ids=lambda p: str(p["id"]))
def test_the_audit_plan_corpus(plan: dict[str, Any]) -> None:
    campaign = load_campaign(s.CORPUS / plan["campaign"])
    if plan["expect"] == "valid":
        journal = read_audit_journal(s.CORPUS / plan["journal"], campaign)
        assert journal.ready is not None and len(journal.targets) == 1
        assert len(journal.results) == 1 and journal.attempts == 1
        return
    with pytest.raises(IntegrityError) as caught:
        read_audit_journal(s.CORPUS / plan["journal"], campaign)
    assert caught.value.rule == plan["expect"]["rule"]


def write(tmp_path: Path, lines: list[bytes], tail: bytes = b"") -> Path:
    path = tmp_path / "audit.jsonl"
    path.write_bytes(b"".join(line + b"\n" for line in lines) + tail)
    return path


def test_a_crash_inside_the_plan_leaves_a_readable_prefix(
    tmp_path: Path, all3: LoadedCampaign
) -> None:
    lines = s.corpus_lines(AUDIT1)  # header, begin, target, ready, attempt, result
    for count, targets in ((1, 0), (2, 0), (3, 1)):
        path = write(tmp_path, lines[:count])
        journal = read_audit_journal(path, all3, complete=False)
        assert journal.ready is None and len(journal.targets) == targets
        assert (journal.begin is None) == (count == 1)
        with pytest.raises(IntegrityError) as caught:
            read_audit_journal(path, all3)
        assert caught.value.rule == "audit.plan_order"


def test_a_crash_between_attempt_and_result_leaves_the_target_without_result(
    tmp_path: Path, all3: LoadedCampaign
) -> None:
    lines = s.corpus_lines(AUDIT1)
    path = write(tmp_path, lines[:5], tail=b'{"format":"cubeproof-jou')
    journal = read_audit_journal(path, all3)
    assert journal.ready is not None and journal.attempts == 1 and not journal.results
    assert journal.torn_tail_bytes > 0
    assert journal.result_of(journal.targets[0]) is None


def test_resume_records_may_occur_inside_and_after_the_plan(
    tmp_path: Path, all3: LoadedCampaign
) -> None:
    lines = s.corpus_lines(AUDIT1)
    header = check_record(json.loads(lines[0])).payload
    assert isinstance(header, Header)
    resume = Resume(header.machinery, header.policy, header.resources)
    ready, attempt, result = (check_record(json.loads(x)).payload for x in lines[3:6])
    assert isinstance(ready, AuditReady) and isinstance(attempt, Attempt)
    assert isinstance(result, AuditResult)
    builder = s.Builder(lines[:3])
    builder.add(resume)
    builder.add(ready)
    builder.add(resume)
    seq = builder.add(attempt).seq
    builder.add(AuditResult(result.target, Ref(builder.id, seq), result.status, ""))
    journal = read_audit_journal(builder.write(tmp_path / "a.jsonl"), all3)
    assert len(journal.results) == 1 and journal.results[0].record.seq == seq + 1


def test_a_run_journal_is_not_an_audit_journal(all3: LoadedCampaign) -> None:
    with pytest.raises(IntegrityError) as caught:
        read_audit_journal(s.CORPUS / "journals" / "base" / "w1.jsonl", all3)
    assert caught.value.rule == "audit.purpose"


def test_a_result_must_name_its_targets_attempt(tmp_path: Path, all3: LoadedCampaign) -> None:
    lines = s.corpus_lines(AUDIT1)
    header = check_record(json.loads(lines[0])).payload
    result = check_record(json.loads(lines[5])).payload
    assert isinstance(header, Header) and isinstance(result, AuditResult)
    other = s.attempt_value("vu_cdcl")  # the attempt of node [1]; the target is [-1]
    other["policy_sha256"] = header.policy.sha256
    builder = s.Builder(lines[:4])
    seq = builder.add(s.typed_attempt(other)).seq
    builder.add(AuditResult(result.target, Ref(builder.id, seq), result.status, ""))
    with pytest.raises(IntegrityError) as caught:
        read_audit_journal(builder.write(tmp_path / "a.jsonl"), all3)
    assert caught.value.rule == "audit.result_ref"
