"""``verify-retained`` over the evidence of a real retain run (specification §11.4, §12.2).

A retain run of the real coordinator with the lifecycle fake tools (``tests/lifecycle``)
produces a journal and its retained proofs; each test verifies a copy of that evidence with its
own checker installation. Covered here: every expected artifact is accounted for
(missing, corrupt, rejected), missing tools, separate output directory, evidence read-only, the
retained set is not presented as a verification of unretained leaves.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import sys
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

import pytest

_HERE = Path(__file__).resolve().parent
_LIFECYCLE = _HERE.parent / "lifecycle"
for _path in (_HERE, _LIFECYCLE):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

import cp_audit_world as aw  # noqa: E402
import cp_life_tools as t  # noqa: E402

from cubeproof.base.canonical_json import document_bytes  # noqa: E402
from cubeproof.base.errors import ConfigurationError, InputError, ToolError  # noqa: E402
from cubeproof.cnf.campaign import load_campaign  # noqa: E402
from cubeproof.commands import verify_retained as vr  # noqa: E402
from cubeproof.contracts.enums import ProofMode  # noqa: E402
from cubeproof.contracts.values import Artifact  # noqa: E402
from cubeproof.evidence.journal import RunLock  # noqa: E402

FORMULA = t.unsat(5)
TOOLS = {"max_free": 3}
MIB = 1 << 20


@dataclass(frozen=True)
class Evidence:
    campaign: Path
    journal: Path
    proofs: Path
    tools: t.Tools


def _world(root: Path, mode: ProofMode) -> t.World:
    w = t.make_world(root, {"f": FORMULA}, solver=TOOLS, policy=t.split_policy(proof_mode=mode))
    result = w.run(jobs=2)
    assert result.exit_code == 0
    t.wait_clean(w.results, w.work)
    return w


@pytest.fixture(scope="module")
def retained(tmp_path_factory: pytest.TempPathFactory) -> t.World:
    return _world(tmp_path_factory.mktemp("retain"), ProofMode.RETAIN)


def evidence(w: t.World, tmp_path: Path, **checker: Any) -> Evidence:
    """A copy of the run's results (journal and proofs) and a fresh checker installation."""
    copy = tmp_path / "evidence"
    shutil.copytree(w.results, copy, ignore=shutil.ignore_patterns("run.lock", "status.*"))
    tools = t.install(tmp_path / "tools", solver=TOOLS)
    if checker:
        t.configure(tools.checker, **checker)
    return Evidence(w.campaign, copy / "journal.jsonl", copy, tools)


def request(e: Evidence, tmp_path: Path, **changes: Any) -> vr.VerifyRequest:
    values: dict[str, Any] = {
        "proofs_root": e.proofs,
        "results": tmp_path / "verify",
        "work": tmp_path / "work",
        "worker": "verifier",
        "checker": str(e.tools.checker),
        "campaign": e.campaign,
        "journals": (e.journal,),
    }
    values.update(changes)
    return vr.VerifyRequest(**values)


def tree(root: Path) -> dict[str, str]:
    return {
        str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in sorted(root.rglob("*"))
        if p.is_file()
    }


def proofs(e: Evidence) -> list[Path]:
    return sorted((e.proofs / "proofs").glob("*.lrat"))


def by_status(result: vr.VerifyResult) -> dict[str, int]:
    found: dict[str, int] = {}
    for entry in result.document["results"]:
        found[entry["status"]] = found.get(entry["status"], 0) + 1
    return found


# -- complete and intact ------------------------------------------------------------------------


def test_every_retained_proof_is_verified(retained: t.World, tmp_path: Path) -> None:
    e = evidence(retained, tmp_path)
    before = tree(e.proofs)
    result = vr.verify_retained(request(e, tmp_path))
    verified = [a for a in t.attempts(e.proofs) if a["outcome"] == "VERIFIED_UNSAT"]
    document = result.document
    assert result.exit_code == 0
    assert document["expected"] == document["found"] == document["verified"] == len(verified)
    assert len(verified) == len(proofs(e)) > 1
    assert (document["missing"], document["corrupt"], document["rejected"]) == (0, 0, 0)
    assert document["unretained"] == 0 and document["worker"] == "verifier"
    [journal] = document["scope"]["journals"]
    assert journal["records"] == len(t.journal_records(e.proofs))
    assert document["scope"]["proofs_root"] == str(e.proofs.resolve())
    refs = [(r["record"]["journal"], r["record"]["seq"]) for r in document["results"]]
    assert refs == sorted(refs)
    assert result.path == tmp_path / "verify" / vr.REPORT_NAME
    assert result.path.read_bytes() == document_bytes(document)
    assert tree(e.proofs) == before  # evidence is only read
    assert sorted(p.name for p in (tmp_path / "verify").iterdir()) == ["run.lock", vr.REPORT_NAME]
    assert list((tmp_path / "work").iterdir()) == []  # the private copies are gone
    again = vr.verify_retained(request(e, tmp_path))  # a second run replaces the report
    assert again.document == document


# -- missing, corrupt, rejected ---------------------------------------------------------------


def test_a_missing_proof_is_counted_not_skipped(retained: t.World, tmp_path: Path) -> None:
    e = evidence(retained, tmp_path)
    first = proofs(e)[0]
    first.unlink()
    result = vr.verify_retained(request(e, tmp_path))
    document = result.document
    assert result.exit_code == 4
    assert document["missing"] == 1 and document["found"] == document["expected"] - 1
    assert document["verified"] == document["expected"] - 1
    [entry] = [r for r in document["results"] if r["status"] == "MISSING"]
    assert entry["artifact"]["path"] == f"proofs/{first.name}"


def _flip(path: Path) -> None:
    data = bytearray(path.read_bytes())
    data[len(data) // 2] ^= 0x01
    path.chmod(0o644)  # published proofs are read-only
    path.write_bytes(bytes(data))


def _truncate(path: Path) -> None:
    path.chmod(0o644)
    path.write_bytes(path.read_bytes()[:-1])


def _symlink(path: Path) -> None:
    keep = path.with_name("elsewhere.bin")
    path.rename(keep)
    path.symlink_to(keep)


def _directory(path: Path) -> None:
    path.unlink()
    path.mkdir()


@pytest.mark.parametrize("damage", [_flip, _truncate, _symlink, _directory])
def test_a_corrupt_proof_is_never_checked(retained: t.World, tmp_path: Path, damage: Any) -> None:
    e = evidence(retained, tmp_path)
    damage(proofs(e)[0])
    result = vr.verify_retained(request(e, tmp_path))
    assert result.exit_code == 4
    assert result.document["corrupt"] == 1
    assert result.document["verified"] == result.document["expected"] - 1


def test_a_symlinked_area_directory_is_not_followed(retained: t.World, tmp_path: Path) -> None:
    e = evidence(retained, tmp_path)
    area = e.proofs / "proofs"
    moved = tmp_path / "moved-proofs"
    area.rename(moved)
    area.symlink_to(moved, target_is_directory=True)
    result = vr.verify_retained(request(e, tmp_path))
    assert result.exit_code == 4
    assert by_status(result) == {"CORRUPT": result.document["expected"]}


def test_a_rejected_proof_is_an_integrity_failure(retained: t.World, tmp_path: Path) -> None:
    e = evidence(retained, tmp_path, reject=True)
    result = vr.verify_retained(request(e, tmp_path))
    assert result.exit_code == 4
    assert by_status(result) == {"REJECTED": result.document["expected"]}


def test_a_crashing_checker_is_a_tool_failure(retained: t.World, tmp_path: Path) -> None:
    e = evidence(retained, tmp_path, crash=True)
    result = vr.verify_retained(request(e, tmp_path))
    assert result.exit_code == 5
    assert {r["reason"] for r in result.document["results"]} == {"crash"}


@pytest.fixture(scope="module")
def audit_tools_run(tmp_path_factory: pytest.TempPathFactory) -> aw.Source:
    """A retain run with the audit fake tools, whose checker can change its own inputs."""
    root = tmp_path_factory.mktemp("retain-audit-tools")
    policy = t.split_policy(proof_mode=ProofMode.RETAIN)
    return aw.make_source(root, {"f": FORMULA}, solver=TOOLS, policy=policy)


@pytest.mark.parametrize("tamper", ["proof", "cnf"])
def test_a_checker_that_changes_its_input_is_a_tool_failure(
    audit_tools_run: aw.Source, tmp_path: Path, tamper: str
) -> None:
    """Specification §5: the private copies are hashed before and after every check; a
    checker that changes the proof or CNF it was given is never counted as a verification."""
    source = audit_tools_run
    e = Evidence(source.campaign, source.journal, source.journal.parent, source.tools)
    before = tree(e.proofs)
    control = vr.verify_retained(request(e, tmp_path / "control"))
    assert control.exit_code == 0 and control.document["verified"] > 0
    aw.configure(source.tools.checker, tamper=tamper)
    try:
        result = vr.verify_retained(request(e, tmp_path))
    finally:
        aw.configure(source.tools.checker)
    document = result.document
    assert document["expected"] == control.document["expected"] == len(document["results"])
    assert {(r["status"], r["reason"]) for r in document["results"]} == {("FAILED", "file_changed")}
    assert document["verified"] == 0 and result.exit_code == 5
    assert tree(e.proofs) == before  # only the private copies were changed


def test_arena_exhaustion_within_the_memory_cap_is_open(retained: t.World, tmp_path: Path) -> None:
    e = evidence(retained, tmp_path, arena=True)
    result = vr.verify_retained(request(e, tmp_path, memory_bytes=512 * MIB))
    assert result.exit_code == 1
    assert {(r["status"], r["reason"]) for r in result.document["results"]} == {
        ("EXHAUSTED", "check_memory")
    }
    small = vr.verify_retained(request(e, tmp_path / "small", memory_bytes=MIB))
    assert {r["reason"] for r in small.document["results"]} == {"check_memory"}


# -- tools and directories ------------------------------------------------------------------------


def test_a_missing_or_unadmitted_checker_stops_before_any_check(
    retained: t.World, tmp_path: Path
) -> None:
    e = evidence(retained, tmp_path)
    with pytest.raises(ToolError):
        vr.verify_retained(request(e, tmp_path, checker=str(tmp_path / "no-checker")))
    other = tmp_path / "other-checker"
    other.write_bytes(e.tools.checker.read_bytes() + b"\n# another build\n")
    other.chmod(0o755)
    with pytest.raises(ToolError) as caught:
        vr.verify_retained(request(e, tmp_path, checker=str(other)))
    assert caught.value.rule == "tool.not_admitted"
    assert not (tmp_path / "verify" / vr.REPORT_NAME).exists()


def test_the_output_is_a_separate_directory(retained: t.World, tmp_path: Path) -> None:
    e = evidence(retained, tmp_path)
    for results in (e.proofs, e.proofs / "verify", tmp_path):
        with pytest.raises(ConfigurationError) as caught:
            vr.verify_retained(request(e, tmp_path, results=results))
        assert caught.value.rule == "verify.results"
    for work in (e.proofs / "scratch", e.proofs):  # the private copies never enter the evidence
        with pytest.raises(ConfigurationError) as caught:
            vr.verify_retained(request(e, tmp_path, work=work))
        assert caught.value.rule == "verify.work"
    run_like = tmp_path / "run-like"
    run_like.mkdir()
    (run_like / "journal.jsonl").write_bytes(b"")
    with pytest.raises(ConfigurationError):
        vr.verify_retained(request(e, tmp_path, results=run_like))
    busy = tmp_path / "busy"
    busy.mkdir()
    with RunLock.acquire(busy / vr.LOCK_NAME), pytest.raises(ConfigurationError) as locked:
        vr.verify_retained(request(e, tmp_path, results=busy))
    assert locked.value.rule == "run.locked"
    with pytest.raises(ConfigurationError):
        request(e, tmp_path, worker="Not A Name")


def test_a_journal_given_twice_is_refused(retained: t.World, tmp_path: Path) -> None:
    e = evidence(retained, tmp_path)
    copy = tmp_path / "copy.jsonl"
    shutil.copyfile(e.journal, copy)
    with pytest.raises(InputError) as caught:
        vr.verify_retained(request(e, tmp_path, journals=(e.journal, copy)))
    assert caught.value.rule == "verify.journals"


def test_a_reference_that_does_not_bind_its_record_is_corrupt(retained: t.World) -> None:
    campaign = load_campaign(retained.campaign)
    _, expected, _ = vr.collect_expected(campaign, [retained.journal()])
    item = expected[0]
    assert vr._binding_problem(item) is None
    moved = Artifact("proofs/other.lrat", item.artifact.sha256, item.artifact.bytes)
    assert vr._binding_problem(replace(item, artifact=moved)) is not None
    resized = replace(item.artifact, bytes=item.artifact.bytes + 1)
    assert vr._binding_problem(replace(item, artifact=resized)) is not None


def test_nothing_retained_is_not_a_verification(tmp_path: Path) -> None:
    w = _world(tmp_path / "transient", ProofMode.TRANSIENT)
    e = evidence(w, tmp_path)
    result = vr.verify_retained(request(e, tmp_path))
    document = result.document
    assert (document["expected"], document["verified"]) == (0, 0)
    assert document["unretained"] > 0
    assert result.exit_code == 1
    assert os.path.exists(result.path)
