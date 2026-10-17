"""An audit killed while it writes its plan or its results, then restarted (specification §11.1,
§11.2).

Each case runs the audit of a certified source in a child process (``cp_audit_runner.py``) that
kills itself with SIGKILL at the n-th occurrence of a lifecycle hook, waits until no process of
it survives, and restarts the audit in this process. The restart must regenerate the plan from
the preserved certified inputs, verify what the journal holds against it, finish the missing
plan records and targets, and never repeat a committed record: one ``audit_target`` per ordinal,
one ``audit_result`` per target, a committed attempt reused for its result instead of a new run.

The same child process, with signal handling on, is also interrupted (specification §12.2:
SIGTERM while a target's solver runs cancels it without a record, SIGTERM between records stops
at the next interruption point, both exit 130) and loses its I/O service (exit 5, the durable
journal stays readable); a restart then finishes the audit.
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

import cp_audit_world as w
import cp_life_tools as t

from cubeproof.base.errors import IntegrityError
from cubeproof.commands.audit import REPORT_NAME, audit_command


@pytest.fixture(scope="module")
def source(tmp_path_factory: pytest.TempPathFactory) -> w.Source:
    root = tmp_path_factory.mktemp("source")
    found = w.make_source(root, {"f": t.unsat(5)}, solver={"max_free": 3})
    assert found.verdict == "PROVED"
    return found


def records(tmp_path: Path) -> list[dict[str, Any]]:
    return w.journal_records(tmp_path / "audit")


def crash(source: w.Source, tmp_path: Path, point: str, n: int) -> w.Source:
    """A copy of the source and an audit of it killed at ``point`` (occurrence ``n``)."""
    w.configure(source.tools.solver, max_free=3)
    w.configure(source.tools.checker)
    e = w.copy_source(source, tmp_path / "copy")
    process = w.spawn_audit(e, tmp_path, (point, n))
    code, out, err = t.messages(process)
    assert code == -signal.SIGKILL, (code, out, err)
    t.wait_clean(tmp_path / "audit", tmp_path / "audit-work")
    return e


def finish(e: w.Source, tmp_path: Path) -> dict[str, Any]:
    outcome = audit_command(w.request(e, tmp_path))
    assert outcome.exit_code == 0, outcome.to_json()
    assert outcome.report is not None
    population = len(json.loads(e.certificate.read_text())["used_attempts"])
    assert outcome.report.document["counts"]["HASH_MATCHED"] == population
    return outcome.report.document


def plan_once(found: list[dict[str, Any]]) -> None:
    kinds = Counter(r["type"] for r in found)
    targets = [r["ordinal"] for r in found if r["type"] == "audit_target"]
    assert kinds["audit_begin"] == kinds["audit_ready"] == 1
    assert targets == list(range(len(targets)))
    results = Counter(r["target"]["node_id"] for r in found if r["type"] == "audit_result")
    assert all(count == 1 for count in results.values()) and len(results) == len(targets)


@pytest.mark.parametrize(
    ("point", "n"),
    [("plan.begin", 1), ("plan.target", 1), ("plan.target", 3), ("plan.ready", 1)],
)
def test_a_crash_while_the_plan_is_written(
    source: w.Source, tmp_path: Path, point: str, n: int
) -> None:
    e = crash(source, tmp_path, point, n)
    before = records(tmp_path)
    assert "attempt" not in {r["type"] for r in before}  # nothing ran before audit_ready
    finish(e, tmp_path)
    after = records(tmp_path)
    assert after[: len(before)] == before  # the durable prefix is kept, never rewritten
    plan_once(after)


def test_a_crash_after_an_attempt_reuses_it_for_the_result(
    source: w.Source, tmp_path: Path
) -> None:
    e = crash(source, tmp_path, "attempt.committed", 2)
    before = records(tmp_path)
    attempts = [r for r in before if r["type"] == "attempt"]
    results = [r for r in before if r["type"] == "audit_result"]
    assert (len(attempts), len(results)) == (2, 1)  # the second attempt has no result yet
    finish(e, tmp_path)
    after = records(tmp_path)
    plan_once(after)
    [result] = [
        r
        for r in after
        if r["type"] == "audit_result" and r["target"]["node_id"] == attempts[1]["node_id"]
    ]
    assert result["attempt"]["seq"] == attempts[1]["seq"]  # no second run of that target
    population = len(json.loads(e.certificate.read_text())["used_attempts"])
    assert sum(r["type"] == "attempt" for r in after) == population


def test_a_crash_after_a_result_never_repeats_it(source: w.Source, tmp_path: Path) -> None:
    e = crash(source, tmp_path, "result.committed", 1)
    before = records(tmp_path)
    assert sum(r["type"] == "audit_result" for r in before) == 1
    finish(e, tmp_path)
    plan_once(records(tmp_path))


def test_a_crash_while_a_target_runs_leaves_no_record(source: w.Source, tmp_path: Path) -> None:
    e = crash(source, tmp_path, "attempt.started", 2)
    before = records(tmp_path)
    assert sum(r["type"] == "attempt" for r in before) == 1
    finish(e, tmp_path)
    after = records(tmp_path)
    plan_once(after)
    assert sorted(p.name for p in (tmp_path / "audit-work").iterdir()) == [".run.lock"]


# -- interruption and a failed I/O service (specification §12.2, §7.3) ---------------------------


def copy_of(source: w.Source, tmp_path: Path, **solver: Any) -> w.Source:
    w.configure(source.tools.solver, max_free=3, **solver)
    w.configure(source.tools.checker)
    return w.copy_source(source, tmp_path / "copy")


def ended(process: subprocess.Popen[bytes], timeout_s: float = 90.0) -> tuple[int, str, str]:
    """The exit code and output of an audit child; the test fails if it does not stop."""
    try:
        code, out, err = t.messages(process, timeout_s=timeout_s)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.communicate()
        pytest.fail("the audit did not stop")
    return int(code), str(out), str(err)


def attempted_and_decided(found: list[dict[str, Any]]) -> tuple[set[str], set[str]]:
    attempts = {r["node_id"] for r in found if r["type"] == "attempt"}
    results = {r["target"]["node_id"] for r in found if r["type"] == "audit_result"}
    return attempts, results


def restart(e: w.Source, tmp_path: Path, before: list[dict[str, Any]]) -> None:
    """The restart keeps the durable prefix, finishes every target once, runs no extra one."""
    w.configure(e.tools.solver, max_free=3)
    finish(e, tmp_path)
    after = records(tmp_path)
    assert after[: len(before)] == before
    plan_once(after)
    population = len(json.loads(e.certificate.read_text())["used_attempts"])
    assert sum(r["type"] == "attempt" for r in after) == population


def test_sigterm_while_a_target_runs_cancels_it_without_a_record(
    source: w.Source, tmp_path: Path
) -> None:
    ready = tmp_path / "ready"
    e = copy_of(source, tmp_path, sleep=120, ready=str(ready))
    process = w.spawn_audit(e, tmp_path, None)
    deadline = time.monotonic() + 60
    while not ready.exists():  # the solver of a target is running
        assert time.monotonic() < deadline and process.poll() is None, "no solver started"
        time.sleep(0.01)
    os.kill(process.pid, signal.SIGTERM)
    code, out, err = ended(process)
    assert code == 130, (out, err)
    outcome = json.loads(out)
    assert outcome["reason"] == "interrupted" and outcome["exit_code"] == 130
    t.wait_clean(tmp_path / "audit", tmp_path / "audit-work")
    assert sorted(p.name for p in (tmp_path / "audit-work").iterdir()) == [".run.lock"]
    before = records(tmp_path)
    attempts, results = attempted_and_decided(before)
    assert attempts == results  # the cancelled target left no attempt record
    report = json.loads((tmp_path / "audit" / REPORT_NAME).read_text())
    assert report["pending"] and report["pending"][0] not in attempts
    assert len(report["results"]) == len(results)
    assert report["selected"] == len(results) + len(report["pending"])
    restart(e, tmp_path, before)


@pytest.mark.parametrize(("point", "n"), [("plan.target", 1), ("result.committed", 1)])
def test_sigterm_between_records_stops_at_the_next_interruption_point(
    source: w.Source, tmp_path: Path, point: str, n: int
) -> None:
    e = copy_of(source, tmp_path)
    process = w.spawn_audit(e, tmp_path, (point, n), action="SIGTERM")
    code, out, err = ended(process)
    assert code == 130, (out, err)
    assert json.loads(out)["reason"] == "interrupted"
    t.wait_clean(tmp_path / "audit", tmp_path / "audit-work")
    before = records(tmp_path)
    kinds = Counter(r["type"] for r in before)
    report = tmp_path / "audit" / REPORT_NAME
    if point == "plan.target":  # the plan is incomplete: nothing runs, no report
        assert (kinds["audit_target"], kinds["audit_ready"], kinds["attempt"]) == (1, 0, 0)
        assert not report.exists()
    else:  # the next target never starts
        assert (kinds["audit_result"], kinds["attempt"]) == (1, 1)
        assert len(json.loads(report.read_text())["pending"]) == kinds["audit_target"] - 1
    restart(e, tmp_path, before)


@pytest.mark.parametrize("when", ["between_jobs", "commit_in_flight"])
def test_a_dead_io_service_stops_the_audit_with_exit_five(
    source: w.Source, tmp_path: Path, when: str
) -> None:
    """The service dies before the second target's attempt submits anything (its next submit
    is refused), or while that attempt waits for the result of its commit (it must be told
    that the service failed, or it would wait forever)."""
    e = copy_of(source, tmp_path)
    if when == "between_jobs":
        process = w.spawn_audit(e, tmp_path, ("attempt.started", 2), action="kill_io_service")
    else:
        process = w.spawn_audit(e, tmp_path, None, kill_io_service_at_commit=2)
    code, out, err = ended(process)
    assert code == 5, (out, err)
    outcome = json.loads(out)
    assert outcome["reason"] == "service_failed"
    assert any("I/O service failed" in note for note in outcome["notes"])
    t.wait_clean(tmp_path / "audit", tmp_path / "audit-work")
    before = records(tmp_path)  # the journal on disk is complete and readable
    attempts, results = attempted_and_decided(before)
    assert attempts == results and len(results) == 1
    restart(e, tmp_path, before)


def test_a_plan_changed_after_a_crash_is_refused(source: w.Source, tmp_path: Path) -> None:
    e = crash(source, tmp_path, "plan.target", 2)
    before = (tmp_path / "audit" / "journal.jsonl").read_bytes()
    with pytest.raises(IntegrityError) as info:
        audit_command(w.request(e, tmp_path, sample=1, seed="0" * 64))
    assert info.value.rule == "audit.plan_changed"
    assert (tmp_path / "audit" / "journal.jsonl").read_bytes() == before
