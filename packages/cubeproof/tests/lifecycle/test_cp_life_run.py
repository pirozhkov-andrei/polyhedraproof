"""Specification §7.3, §6.5, §12.2: whole runs of one worker with fake tools, and what each leaves
behind.

Every test runs the real coordinator with real child processes (the I/O service, the fake
solver and checker under the real isolation wrappers) on tiny formulas. The journal is judged
by the real certifier (``cubeproof.evidence.certify``): a run that ends well must certify the
verdict the exit code announces.
"""

from __future__ import annotations

import errno
import json
import os
import signal
import subprocess
import sys
import threading
import time
from collections.abc import Sequence
from dataclasses import replace
from pathlib import Path
from typing import Any

import cp_life_tools as t
import pytest

from cubeproof import api
from cubeproof.base.errors import (
    ConfigurationError,
    CubeproofError,
    IntegrityError,
    ResourceError,
    ToolError,
)
from cubeproof.base.settings import ToolPaths
from cubeproof.cnf.campaign import load_campaign
from cubeproof.cnf.dimacs import canonical_dimacs
from cubeproof.contracts.enums import Purpose
from cubeproof.contracts.io import AppendValue
from cubeproof.contracts.policy import Policy
from cubeproof.coordinator.config import RunResult, Stop, exit_code_of
from cubeproof.coordinator.ledger import Need, ResourceBook, Shortfall
from cubeproof.coordinator.measure import SKIPPED_CONTROL
from cubeproof.coordinator.replay import validator_of
from cubeproof.coordinator.resources import CHILD_OVERHEAD, sealed_need, solve_need
from cubeproof.coordinator.run import Coordinator, _AttemptTask
from cubeproof.coordinator.scheduler import Candidate, Impossible, Stage
from cubeproof.coordinator.state import Key
from cubeproof.evidence.certify.run import certify
from cubeproof.evidence.journal import read_journal
from cubeproof.evidence.schema import build_record
from cubeproof.leaf.attempt import CheckRequest, Phase
from cubeproof.split.choice import Budget
from cubeproof.split.lookahead import lookahead
from cubeproof.tools.machinery import host_cpu

SPLITTING = {"max_free": 3}
#: Eight variables, a five-variable unsatisfiable core: the root and its four children run out
#: of memory in the fake solver, the sixteen grandchildren are refuted by unit propagation.
DEEP = t.unsat(8, core=5)
SHALLOW = t.unsat(5)


def world(tmp_path: Path, formulas: dict[str, bytes], **options: Any) -> t.World:
    return t.make_world(tmp_path, formulas, **options)


def open_states(result: RunResult) -> set[str]:
    return {key.split(":")[0] for key in result.open}


# -- complete runs -------------------------------------------------------------------------------


def test_a_campaign_runs_to_the_end_and_certifies(tmp_path: Path) -> None:
    w = world(tmp_path, {"f": DEEP}, solver=SPLITTING)
    result = w.run()
    assert (result.exit_code, result.reason) == (0, Stop.COMPLETE)
    assert result.open == {} and result.anomalies == 0 and result.models == 0
    assert result.session["outcome:VERIFIED_UNSAT"] == 16
    assert result.session["outcome:EXHAUSTED"] == 5
    assert result.session["splits"] == 5
    assert result.ticks["ticks"] > 0 and set(result.ticks) == {
        "ticks",
        "p50_ms",
        "p99_ms",
        "max_ms",
    }
    summary = w.summary()
    assert summary["verdict"] == "PROVED"
    assert summary["formulas"][0]["summary"]["leaves"] == 16
    kinds = [r["type"] for r in t.journal_records(w.results)]
    assert kinds[:2] == ["header", "shard"]
    assert kinds.count("header") == 1 and kinds.count("resume") == 0
    assert w.records("header")[0]["purpose"] == "run"
    assert w.records("header")[0]["worker"] == "w1"
    t.wait_clean(w.results, w.work)


def test_the_work_directory_is_empty_after_a_clean_run(tmp_path: Path) -> None:
    w = world(tmp_path, {"f": SHALLOW}, solver=SPLITTING)
    assert w.run().exit_code == 0
    assert w.work_files() == []


def test_the_first_shard_holds_the_requested_roots(tmp_path: Path) -> None:
    w = world(tmp_path, {"a": t.unsat(4), "b": SHALLOW}, solver=SPLITTING)
    assert w.run().exit_code == 0
    shards = w.records("shard")
    assert len(shards) == 1
    nodes = shards[0]["shard"]["nodes"]
    assert [n["cube"] for n in nodes] == [[], []]
    assert shards[0]["shard"]["name"] == "initial"
    assert w.summary()["verdict"] == "PROVED"


def test_a_second_run_resumes_and_finds_nothing_to_do(tmp_path: Path) -> None:
    w = world(tmp_path, {"f": SHALLOW}, solver=SPLITTING)
    first = w.run()
    before = t.journal_records(w.results)
    second = w.run()
    after = t.journal_records(w.results)
    assert (first.exit_code, second.exit_code) == (0, 0)
    assert second.session == {"resume": 1}
    assert [r["type"] for r in after[len(before) :]] == ["resume"]
    assert after[: len(before)] == before
    assert second.journal == first.journal and second.seq == first.seq + 1


def test_the_resume_commits_the_snapshot_before_anything_else(tmp_path: Path) -> None:
    w = world(tmp_path, {"f": SHALLOW}, solver=SPLITTING)
    w.run()
    count = len(t.journal_records(w.results))
    t.configure(w.tools.solver, max_free=3, sleep=0)
    w.run()
    new = t.journal_records(w.results)[count:]
    assert new[0]["type"] == "resume"
    assert set(new[0]) >= {"machinery", "policy", "resources"}


def test_the_effective_policy_is_recorded_with_the_overrides(tmp_path: Path) -> None:
    w = world(tmp_path, {"f": SHALLOW}, solver=SPLITTING)
    w.run(policy_overrides={"split.vars": 1, "tool_retries": 2, "leaf_time_ms.0": 5000})
    policy = w.records("header")[0]["policy"]
    assert policy["split"]["vars"] == 1 and policy["tool_retries"] == 2
    assert policy["leaf_time_ms"] == {"default": 60000, "0": 5000}
    assert policy["proof_mode"] == "transient"
    # every attempt names the policy that was in force
    assert {a["policy_sha256"] for a in w.attempts()} == {Policy.from_json(policy).sha256}


def test_a_bad_policy_override_is_a_configuration_error(tmp_path: Path) -> None:
    w = world(tmp_path, {"f": SHALLOW}, solver=SPLITTING)
    with pytest.raises(ConfigurationError) as error:
        w.run(policy_overrides={"no_such_field": 1})
    assert error.value.rule == "run.policy_override" and exit_code_of(error.value) == 3
    with pytest.raises(ConfigurationError):
        w.run(policy_overrides={"split.vars": 99})
    assert not w.journal().exists()


def test_the_stream_mode_runs_and_certifies(tmp_path: Path) -> None:
    """The root is refuted by a coupled solver -> relay -> checker run; the
    record is a stream record and the certifier proves the formula from it."""
    w = world(tmp_path, {"f": SHALLOW})
    result = w.run(proof_mode="stream")
    assert (result.exit_code, result.reason) == (0, Stop.COMPLETE)
    assert w.records("header")[0]["policy"]["proof_mode"] == "stream"
    (attempt,) = w.attempts()
    assert (attempt["outcome"], attempt["route"], attempt["proof_mode"]) == (
        "VERIFIED_UNSAT",
        "cdcl",
        "stream",
    )
    relay = attempt["relay"]
    assert (relay["solver_eof"], relay["all_written"], relay["error"]) == (True, True, None)
    assert (attempt["proof_bytes"], attempt["proof_sha256"]) == (relay["bytes"], relay["sha256"])
    assert w.summary()["verdict"] == "PROVED"
    assert w.work_files() == []
    t.wait_clean(w.results, w.work)


def test_a_stream_task_the_idle_machine_cannot_hold_is_refused_before_any_record(
    tmp_path: Path,
) -> None:
    """Specification §8.2: solver, checker and relay reserve 3000 milli-CPU; two jobs cannot hold
    one."""
    w = world(tmp_path, {"f": SHALLOW}, solver=SPLITTING)
    with pytest.raises(ResourceError) as error:
        w.run(proof_mode="stream", jobs=2)
    assert error.value.rule == "resources.preflight" and exit_code_of(error.value) == 1
    assert "stream" in error.value.detail
    assert not w.journal().exists()
    assert w.run(jobs=2).exit_code == 0  # the file modes need one slot per task


def test_the_retain_mode_runs_and_records_its_policy(tmp_path: Path) -> None:
    w = world(tmp_path, {"f": SHALLOW}, solver=SPLITTING)
    result = w.run(proof_mode="retain")
    assert result.exit_code == 0
    assert w.records("header")[0]["policy"]["proof_mode"] == "retain"
    verified = [a for a in w.attempts() if a["outcome"] == "VERIFIED_UNSAT"]
    assert verified and all(a["proof_mode"] == "retain" for a in verified)
    assert all(a["retained"] is not None for a in verified)
    assert w.summary()["verdict"] == "PROVED"


# -- models, anomalies, tool failures -------------------------------------------------------------


def test_a_model_is_recorded_and_the_run_exits_two(tmp_path: Path) -> None:
    w = world(tmp_path, {"f": t.sat(5)})
    result = w.run()
    assert (result.exit_code, result.models) == (2, 1)
    assert [a["outcome"] for a in w.attempts()] == ["MODEL"]
    assert w.summary()["verdict"] == "MODEL_FOUND"
    assert open_states(result) == {"model"}


def test_a_model_outranks_open_work_and_other_formulas_are_still_proved(tmp_path: Path) -> None:
    w = world(tmp_path, {"a": t.sat(4), "b": SHALLOW}, solver=SPLITTING | {"max_free": 6})
    result = w.run()
    assert result.exit_code == 2
    summary = w.summary()
    proved = {f["key"]: f["proved"] for f in summary["formulas"]}
    assert proved == {"a": False, "b": True}


def test_rejected_proofs_are_anomalies_and_the_limit_stops_new_work(tmp_path: Path) -> None:
    policy = t.split_policy(anomaly_limit=1)
    w = world(tmp_path, {"f": SHALLOW}, policy=policy)
    t.configure(w.tools.checker, reject=True)
    first = w.run()
    assert (first.exit_code, first.reason, first.anomalies) == (6, Stop.ANOMALY, 1)
    assert [a["outcome"] for a in w.attempts()] == ["CHECK_REJECTED"]
    t.configure(w.tools.checker)
    second = w.run()
    # the session counter restarts with the resume; the run now closes the node by splitting
    assert (second.exit_code, second.anomalies) == (0, 0)
    document = w.summary()
    assert document["verdict"] == "PROVED"
    certificate = certify(w.campaign, [w.journal()]).certificate
    assert [a["code"] for a in certificate["anomalies"]] == ["check_rejected"]


def test_repeated_tool_failures_block_the_node_and_reopening_resumes_it(tmp_path: Path) -> None:
    w = world(tmp_path, {"f": SHALLOW}, solver={"crash_if_free_le": 99})
    first = w.run()
    assert first.exit_code == 5
    assert "tool_blocked" in open_states(first)
    outcomes = [(a["outcome"], a["reason"]) for a in w.attempts()]
    assert outcomes == [("TOOL_FAILED", "crash")] * 2  # tool_retries=1: one more try
    stops = w.records("node_stop")
    assert [(s["state"], s["reason"]) for s in stops] == [
        ("tool_blocked", "tool_retries_exhausted")
    ]
    # a second run without the flag does not silently erase the stop
    unchanged = w.run()
    assert unchanged.exit_code == 5 and len(w.attempts()) == 2
    # the explicit reopening records it and the node runs again
    t.configure(w.tools.solver, max_free=3)
    reopened = w.run(reopen_blocked=True)
    assert reopened.exit_code == 0
    assert [r["reason"] for r in w.records("node_reopen")] == ["reopen_blocked"]
    assert w.summary()["verdict"] == "PROVED"


def test_the_machine_failure_limit_stops_the_session_with_exit_five(tmp_path: Path) -> None:
    policy = t.split_policy(machine_failure_limit=2, tool_retries=9)
    w = world(tmp_path, {"f": SHALLOW}, solver={"crash_if_free_le": 99}, policy=policy)
    result = w.run()
    assert (result.exit_code, result.reason) == (5, Stop.MACHINE)
    assert len(w.attempts()) == 2
    assert w.records("node_stop") == []  # retries are not exhausted: the node is not blocked


def test_the_time_allocation_ends_with_exit_one_and_pending_work(tmp_path: Path) -> None:
    w = world(tmp_path, {"f": SHALLOW}, solver={"max_free": 3, "sleep": 2.0})
    result = w.run(max_seconds=1.0)
    assert (result.exit_code, result.reason) == (1, Stop.TIME)
    assert "pending" in open_states(result)
    t.wait_clean(w.results, w.work)
    assert w.summary()["verdict"] == "OPEN"
    t.configure(w.tools.solver, max_free=3)
    resumed = w.run()
    assert resumed.exit_code == 0 and w.summary()["verdict"] == "PROVED"


# -- ownership ------------------------------------------------------------------------------------


def test_a_second_worker_on_a_live_directory_is_refused(tmp_path: Path) -> None:
    w = world(tmp_path, {"f": SHALLOW}, solver={"max_free": 3, "sleep": 1.0})
    trace = tmp_path / "trace.txt"
    child = t.spawn_runner(w.spec(), trace=trace)
    try:
        deadline = time.monotonic() + 30
        while not (trace.exists() and "loop.start" in trace.read_text()):
            assert time.monotonic() < deadline and child.poll() is None
            time.sleep(0.02)
        with pytest.raises(ConfigurationError) as error:
            w.run()
        assert error.value.rule == "run.locked" and exit_code_of(error.value) == 3
        with pytest.raises(ConfigurationError) as other:
            w.run(worker="w2")
        assert other.value.rule == "run.locked"
    finally:
        code, out, _err = t.messages(child)
    assert code == 0, out
    assert w.summary()["verdict"] == "PROVED"
    # the refused workers wrote nothing: the journal has exactly the owner's records
    assert {r["type"] for r in t.journal_records(w.results)} == {
        "header",
        "shard",
        "attempt",
        "split",
    }


def test_two_workers_may_not_share_a_work_directory(tmp_path: Path) -> None:
    w = world(tmp_path, {"f": SHALLOW}, solver={"max_free": 3, "sleep": 1.0})
    trace = tmp_path / "trace.txt"
    child = t.spawn_runner(w.spec(), trace=trace)
    try:
        wait_trace(trace, "loop.start", child)
        elsewhere = tmp_path / "second" / "results"
        with pytest.raises(ConfigurationError) as error:
            w.run(results=elsewhere, worker="w2")
        assert error.value.rule == "run.work_locked" and exit_code_of(error.value) == 3
        assert not (elsewhere / "journal.jsonl").exists()
    finally:
        code, out, _err = t.messages(child)
    assert code == 0, out
    # once the owner is gone, the other worker may use the directory (and clears nothing of the
    # owner's: its journal is in its own results directory)
    assert w.run(results=tmp_path / "second" / "results", worker="w2").exit_code == 0


def test_another_worker_or_campaign_may_not_continue_a_journal(tmp_path: Path) -> None:
    w = world(tmp_path, {"f": SHALLOW}, solver=SPLITTING)
    assert w.run().exit_code == 0
    with pytest.raises(ConfigurationError) as worker:
        w.run(worker="someone-else")
    assert worker.value.rule == "run.worker"
    other = world(tmp_path / "other", {"f": t.unsat(6)}, solver=SPLITTING)
    with pytest.raises(ConfigurationError) as campaign:
        api.run(other.config(results=w.results, work=w.root / "work2"))
    assert campaign.value.rule == "run.campaign"
    assert exit_code_of(campaign.value) == 3


def test_results_and_work_must_be_separate_directories(tmp_path: Path) -> None:
    w = world(tmp_path, {"f": SHALLOW}, solver=SPLITTING)
    with pytest.raises(ConfigurationError) as nested:
        w.run(work=w.results / "work")
    assert nested.value.rule == "run.layout"
    with pytest.raises(ConfigurationError):
        w.run(work=w.root)


# -- the journal on disk --------------------------------------------------------------------------


def test_a_damaged_journal_is_an_integrity_error_and_is_never_repaired(tmp_path: Path) -> None:
    w = world(tmp_path, {"f": SHALLOW}, solver=SPLITTING)
    w.run()
    data = bytearray(w.journal().read_bytes())
    # a byte inside the second line: a complete line that fails its self hash
    start = data.index(b"\n") + 1
    index = data.index(b'"worker"', start) if b'"worker"' in data[start:] else start + 40
    data[index + 12] ^= 0x01
    w.journal().write_bytes(bytes(data))
    damaged = w.journal().read_bytes()
    with pytest.raises(IntegrityError) as error:
        w.run()
    assert exit_code_of(error.value) == 4
    assert w.journal().read_bytes() == damaged  # nothing truncated, nothing appended


def test_a_corrupt_last_complete_line_is_an_error_not_a_torn_tail(tmp_path: Path) -> None:
    w = world(tmp_path, {"f": SHALLOW}, solver=SPLITTING)
    w.run()
    data = w.journal().read_bytes()
    lines = data.split(b"\n")[:-1]
    lines[-1] = lines[-1].replace(b'"seq":', b'"sec":')
    damaged = b"\n".join(lines) + b"\n"
    w.journal().write_bytes(damaged)
    with pytest.raises(IntegrityError):
        w.run()
    assert w.journal().read_bytes() == damaged


def test_a_torn_suffix_is_removed_and_recorded_before_the_resume(tmp_path: Path) -> None:
    w = world(tmp_path, {"f": SHALLOW}, solver=SPLITTING)
    w.run()
    complete = w.journal().read_bytes()
    w.journal().write_bytes(complete + b'{"format":"cubeproof-journal-1","seq":99')
    result = w.run()
    records = t.journal_records(w.results)
    kinds = [r["type"] for r in records]
    index = kinds.index("repair")
    assert kinds[index + 1] == "resume" and kinds.count("repair") == 1
    assert records[index]["removed_bytes"] == len(b'{"format":"cubeproof-journal-1","seq":99')
    assert w.journal().read_bytes().startswith(complete)
    assert result.exit_code == 0 and any("torn tail" in n for n in result.notes)


def test_an_empty_journal_or_a_torn_header_starts_the_worker(tmp_path: Path) -> None:
    w = world(tmp_path, {"f": SHALLOW}, solver=SPLITTING)
    w.results.mkdir(parents=True)
    w.journal().write_bytes(b"")
    assert w.run().exit_code == 0
    assert w.summary()["verdict"] == "PROVED"
    other = world(tmp_path / "torn", {"f": SHALLOW}, solver=SPLITTING)
    other.results.mkdir(parents=True)
    other.journal().write_bytes(b'{"format":"cubeproof-journal-1","seq":0,"typ')
    assert other.run().exit_code == 0
    kinds = [r["type"] for r in t.journal_records(other.results)]
    assert kinds[0] == "header" and kinds[1] == "repair"  # the removed bytes are recorded


# -- the work directory and old processes ---------------------------------------------------------


def test_what_a_dead_run_left_in_the_work_directory_is_removed(tmp_path: Path) -> None:
    w = world(tmp_path, {"f": SHALLOW}, solver=SPLITTING)
    outside = tmp_path / "keep.txt"
    outside.write_text("keep")
    (w.work / "sub").mkdir(parents=True)
    (w.work / "abc-def.cnf").write_text("p cnf 1 0\n")
    (w.work / "sub" / "x.lrat").write_text("1 0 0\n")
    os.symlink(outside, w.work / "link")
    os.symlink(tmp_path, w.work / "dirlink")
    result = w.run()
    assert result.exit_code == 0
    assert outside.read_text() == "keep" and (tmp_path / "campaign.json").exists()
    assert w.work_files() == []
    assert any("left in the work directory" in n for n in result.notes)


def test_a_live_process_in_the_work_directory_blocks_the_startup(tmp_path: Path) -> None:
    w = world(tmp_path, {"f": SHALLOW}, solver=SPLITTING)
    w.work.mkdir(parents=True)
    sleeper = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(60)"], cwd=w.work, start_new_session=True
    )
    try:
        with pytest.raises(ConfigurationError) as error:
            w.run(survivor_wait_ms=100)
        assert error.value.rule == "run.work_in_use"
        assert not w.journal().exists()
    finally:
        sleeper.kill()
        sleeper.wait()
    assert w.run().exit_code == 0


def test_referenced_artifacts_are_kept_and_orphans_removed_at_startup(tmp_path: Path) -> None:
    """The startup recovery on a real retain journal (the references come from the
    validated records, bound by ``leaf.retain``, and must equal the replay's)."""
    from dataclasses import replace as replaced

    from cubeproof.contracts.values import Artifact
    from cubeproof.coordinator.layout import Layout
    from cubeproof.coordinator.replay import replay_journal
    from cubeproof.coordinator.state import CampaignView
    from cubeproof.evidence.journal import RunLock

    w = world(tmp_path, {"f": SHALLOW}, solver=SPLITTING)
    assert w.run(proof_mode="retain").exit_code == 0
    config = w.config(proof_mode="retain")
    coordinator = Coordinator(config)
    coordinator.layout = Layout.of(w.results, w.work)
    coordinator.layout.prepare()
    loaded = load_campaign(w.campaign)
    lock = RunLock.acquire(coordinator.layout.lock)
    try:
        replayed = replay_journal(
            coordinator.layout.journal,
            loaded,
            CampaignView.of(loaded),
            limits=config.limits,
            cache_path=None,
            lock=lock,
            worker=config.worker,
        )
        assert replayed.committed
        proofs = w.results / "proofs"
        artifact = replayed.committed[0]
        kept = w.results / artifact.path
        data = kept.read_bytes()
        (proofs / "tmp").mkdir(exist_ok=True)
        orphan = proofs / f"{'b' * 64}-{artifact.sha256}.lrat"
        orphan.write_bytes(data)
        (proofs / "tmp" / ("c" * 32 + ".lrat")).write_bytes(b"partial")
        coordinator._reconcile(replayed)
        assert kept.read_bytes() == data
        assert not orphan.exists() and not list((proofs / "tmp").iterdir())
        # references the records do not carry (or lack) stop the run and remove nothing
        orphan.write_bytes(data)
        unknown = Artifact(f"proofs/{'a' * 64}-{artifact.sha256}.lrat", artifact.sha256, len(data))
        for committed in ([], [*replayed.committed, unknown]):
            with pytest.raises(IntegrityError) as differ:
                coordinator._reconcile(replaced(replayed, committed=committed))
            assert differ.value.rule == "retain.reference" and orphan.exists()
        # a referenced file that is gone or changed stops the run and removes nothing
        kept.chmod(0o644)
        kept.write_bytes(b"other bytes")
        with pytest.raises(IntegrityError) as error:
            coordinator._reconcile(replayed)
        assert error.value.rule == "artifact.corrupt" and exit_code_of(error.value) == 4
        assert orphan.exists()
        kept.unlink()
        with pytest.raises(IntegrityError) as missing:
            coordinator._reconcile(replayed)
        assert missing.value.rule == "artifact.missing" and orphan.exists()
    finally:
        lock.release()


# -- tools and resources before any record --------------------------------------------------------


def test_a_missing_or_changed_tool_fails_before_any_record(tmp_path: Path) -> None:
    w = world(tmp_path, {"f": SHALLOW}, solver=SPLITTING)
    with pytest.raises(ToolError) as missing:
        w.run(tools=ToolPaths(solver=str(tmp_path / "nope"), checker=str(w.tools.checker)))
    assert missing.value.rule == "tool.missing" and exit_code_of(missing.value) == 5
    original = w.tools.checker.read_text()
    w.tools.checker.write_text(original + "\n# changed\n")
    with pytest.raises(ToolError) as changed:
        w.run()
    assert changed.value.rule == "tool.hash_mismatch"
    assert not w.journal().exists()
    w.tools.checker.write_text(original)
    first = w.tools.solver.read_text()
    w.tools.solver.write_text(first + "\n# changed\n")
    with pytest.raises(ToolError) as solver:
        w.run()
    assert solver.value.rule == "tool.hash_mismatch" and not w.journal().exists()
    w.tools.solver.write_text(first)
    assert w.run().exit_code == 0


def test_a_machine_that_cannot_run_a_solve_fails_preflight(tmp_path: Path) -> None:
    w = world(tmp_path, {"f": SHALLOW}, solver=SPLITTING)
    with pytest.raises(ResourceError) as error:
        w.run(memory_bytes=64 << 20)
    assert error.value.rule.startswith("resources.") and exit_code_of(error.value) == 1
    assert not w.journal().exists()


# -- stops ----------------------------------------------------------------------------------------


def wait_trace(trace: Path, text: str, child: subprocess.Popen[bytes]) -> None:
    deadline = time.monotonic() + 60
    while not (trace.exists() and text in trace.read_text().split()):
        assert time.monotonic() < deadline and child.poll() is None, "the run did not get there"
        time.sleep(0.01)


def wait_ready(ready: Path, child: subprocess.Popen[bytes]) -> None:
    """Until the fake solver (``ready`` in its configuration) is running and has said so."""
    deadline = time.monotonic() + 60
    while not ready.exists():
        assert time.monotonic() < deadline and child.poll() is None, "the solver did not start"
        time.sleep(0.01)


def proof_files(w: t.World) -> list[str]:
    """The proof files of solvers in the work directory."""
    return [name for name in w.work_files() if name.endswith(".lrat")]


@pytest.mark.parametrize("signal_number", [signal.SIGTERM, signal.SIGINT])
def test_a_signal_stops_cleanly_with_exit_130_and_a_restart_continues(
    tmp_path: Path, signal_number: int
) -> None:
    ready = tmp_path / "ready"
    solver = {"max_free": 3, "sleep": 0.3, "proof_at_start": True, "ready": str(ready)}
    w = world(tmp_path, {"f": DEEP}, solver=solver)
    reference = world(tmp_path / "ref", {"f": DEEP}, solver=SPLITTING)
    assert reference.run().exit_code == 0
    trace = tmp_path / "trace.txt"
    child = t.spawn_runner(w.spec(jobs=1), trace=trace)
    wait_trace(trace, "attempt.solve", child)
    wait_ready(ready, child)
    assert proof_files(w), "the solver has not created its proof file"
    os.kill(child.pid, signal_number)
    code, out, err = t.messages(child)
    assert code == 130, (out, err)
    document = json.loads(out.strip().splitlines()[-1])
    assert document["reason"] == "interrupted" and document["open"]
    t.wait_clean(w.results, w.work)
    assert w.summary()["verdict"] == "OPEN"
    assert w.work_files() == []  # cancelled attempts removed their files, the proof included
    finish = w.run()
    assert finish.exit_code == 0
    assert w.summary() == reference.summary()


def test_a_second_signal_kills_without_the_grace_period(tmp_path: Path) -> None:
    ready = tmp_path / "ready"
    solver = {"max_free": 3, "sleep": 30.0, "proof_at_start": True, "ready": str(ready)}
    w = world(tmp_path, {"f": DEEP}, solver=solver)
    trace = tmp_path / "trace.txt"
    child = t.spawn_runner(w.spec(jobs=1), trace=trace)
    wait_trace(trace, "attempt.solve", child)
    wait_ready(ready, child)
    assert proof_files(w), "the solver has not created its proof file"
    os.kill(child.pid, signal.SIGTERM)
    time.sleep(0.2)
    os.kill(child.pid, signal.SIGTERM)
    code, out, err = t.messages(child, timeout_s=30)
    assert code == 130, (out, err)
    t.wait_clean(w.results, w.work)
    assert w.work_files() == []  # the killed solve left neither its proof nor its formula


def test_a_dead_io_service_stops_the_run_with_exit_five(tmp_path: Path) -> None:
    w = world(tmp_path, {"f": DEEP}, solver={"max_free": 3, "sleep": 0.2})
    box: list[Coordinator] = []

    def hooks(name: str) -> None:
        if name == "attempt.solve" and box and box[0].io is not None:
            os.kill(box[0].io.pid, signal.SIGKILL)

    box.append(Coordinator(w.config(hooks=hooks)))
    result = box[0].run()
    assert (result.exit_code, result.reason) == (5, Stop.SERVICE)
    t.wait_clean(w.results, w.work)
    # the journal on disk decides; the next run recovers and finishes
    final = w.run()
    assert final.exit_code == 0 and w.summary()["verdict"] == "PROVED"


def test_resource_blocked_nodes_are_stopped_and_reported_open(tmp_path: Path) -> None:
    w = world(tmp_path, {"f": SHALLOW}, solver=SPLITTING)
    box: list[Coordinator] = []

    def hooks(name: str) -> None:
        if name == "loop.start":
            root = box[0].state.open_nodes()[0].key  # type: ignore[union-attr]
            box[0]._stalled((root,), ("test: nothing fits",))

    box.append(Coordinator(w.config(hooks=hooks)))
    result = box[0].run()
    assert result.exit_code == 1
    assert open_states(result) == {"resource_blocked"}
    assert [(s["state"], s["reason"]) for s in w.records("node_stop")] == [
        ("resource_blocked", "stalled")
    ]
    assert w.attempts() == []
    assert any(n.startswith("stalled:") for n in result.notes)


def test_nodes_at_the_depth_limit_are_stopped_stuck_once_and_stay_open(tmp_path: Path) -> None:
    w = world(tmp_path, {"f": DEEP}, solver=SPLITTING, policy=t.split_policy(max_cube_size=1))
    result = w.run()
    assert (result.exit_code, result.reason) == (1, Stop.COMPLETE)
    assert open_states(result) == {"stuck"}
    stops = w.records("node_stop")
    assert [(s["state"], s["reason"]) for s in stops] == [("stuck", "max_depth")] * 2
    assert {s["policy_sha256"] for s in stops} == {a["policy_sha256"] for a in w.attempts()}
    assert w.summary()["verdict"] == "OPEN"
    again = w.run()
    assert again.exit_code == 1 and len(w.records("node_stop")) == 2  # persisted once
    assert [a["outcome"] for a in w.attempts()] == ["EXHAUSTED"] * 3


def test_every_recorded_split_is_what_the_lookahead_chooses(tmp_path: Path) -> None:
    """Concurrent splits share one engine per formula but never interleave on it."""
    w = world(tmp_path, {"f": DEEP}, solver=SPLITTING)
    assert w.run(jobs=4).exit_code == 0
    formula = load_campaign(w.campaign).bundles
    (bundle,) = formula.values()
    splits = w.records("split")
    assert len(splits) == 5
    for record in splits:
        cube = tuple(record["node"]["cube"])
        choice = lookahead(bundle.formula, cube, 2, None, Budget(probe_limit=100_000))
        assert tuple(record["variables"]) == choice.variables, cube
        splitter = record["splitter"]
        assert splitter["name"] == "lookahead-v1"
        assert splitter["info"]["implementation"] == "python-reference"
        assert splitter["info"]["probes"] == choice.info_dict()["probes"]


class _Stub:
    """What the reservation staging reads of an attempt."""

    def __init__(self, phase: Phase, request: CheckRequest | None = None) -> None:
        self.phase = phase
        self.check_request = request
        self.finished = False
        self.cancelled = False


def test_reservations_shrink_with_the_phases_of_an_attempt_and_never_grow(
    tmp_path: Path,
) -> None:
    w = world(tmp_path, {"f": SHALLOW}, solver=SPLITTING)
    coordinator = Coordinator(w.config())
    policy = t.split_policy()
    coordinator.book = ResourceBook({"cpu": 4000, "memory": 8 << 30, "disk:g": 100 << 30})
    solving = solve_need(policy, 1000, "g")
    coordinator.book.reserve("t1", "solve", solving)
    stub = _Stub(Phase.SOLVE)
    key = (load_campaign(w.campaign).campaign.formulas[0].formula_sha256, ())
    coordinator._attempts = {"t1": _AttemptTask(stub, key, 1000, "g")}  # type: ignore[arg-type]

    def held() -> Need:
        reservation = coordinator.book.get("t1")
        assert reservation is not None
        return reservation.need

    coordinator._stage_reservations()
    assert held() == solving  # solving keeps everything
    stub.phase = Phase.SEAL
    coordinator._stage_reservations()
    assert held() == Need(0, 0, solving.disk)  # the solver exited: CPU and RAM are free
    request = CheckRequest(64, 16, 96 << 20, 30_000, 500)
    stub.phase, stub.check_request = Phase.QUEUED_CHECK, request
    coordinator._stage_reservations()
    assert held() == sealed_need(500, 1000, "g")  # the disk shrinks to the sealed proof
    checking = Need(1000, (96 << 20) + CHILD_OVERHEAD, held().disk)
    coordinator.book.restage("t1", "check", checking)
    stub.phase = Phase.CHECK
    coordinator._stage_reservations()
    assert held() == checking  # a running check is never touched
    stub.phase = Phase.REHASH
    coordinator._stage_reservations()
    assert held() == Need(0, 0, checking.disk)
    big = CheckRequest(64, 16, 96 << 20, 30_000, 50 << 30)
    stub.phase, stub.check_request = Phase.QUEUED_CHECK, big
    coordinator._stage_reservations()
    assert held() == Need(0, 0, checking.disk)  # staging only releases; growing is the plan's
    coordinator.book.check()


def _impossible(stage: Stage, task_id: str, key: Key) -> Impossible:
    found = Shortfall("memory", 1 << 40, 0, 0, 0, "exceeds the capacity")
    return Impossible(Candidate(task_id, stage, key, Need(1000, 1 << 20), 0), found, "test")


def test_a_solve_that_cannot_fit_an_idle_machine_blocks_its_node(tmp_path: Path) -> None:
    w = world(tmp_path, {"f": SHALLOW}, solver=SPLITTING)
    box: list[Coordinator] = []

    def hooks(name: str) -> None:
        if name == "loop.start":
            root = box[0].state.open_nodes()[0].key  # type: ignore[union-attr]
            box[0]._impossible(_impossible(Stage.SOLVE, "a" * 32, root))

    box.append(Coordinator(w.config(hooks=hooks)))
    result = box[0].run()
    assert result.exit_code == 1 and open_states(result) == {"resource_blocked"}
    assert [s["reason"] for s in w.records("node_stop")] == ["solve_resources"]
    assert w.attempts() == []


def test_a_check_that_cannot_fit_an_idle_machine_cancels_its_attempt(tmp_path: Path) -> None:
    w = world(tmp_path, {"f": SHALLOW}, solver={"max_free": 9, "sleep": 0.5})
    box: list[Coordinator] = []
    fired: list[str] = []

    def hooks(name: str) -> None:
        if name == "attempt.solve" and not fired:
            fired.append(name)
            task = next(iter(box[0]._attempts.values()))
            box[0]._impossible(_impossible(Stage.CHECK, task.attempt.attempt_id, task.key))

    box.append(Coordinator(w.config(hooks=hooks)))
    result = box[0].run()
    assert result.exit_code == 1 and open_states(result) == {"resource_blocked"}
    assert [s["reason"] for s in w.records("node_stop")] == ["check_exhausted"]
    # cancelled before its terminal commit: no record (specification §6.3)
    assert w.attempts() == []
    assert w.work_files() == []


def test_a_journal_of_another_purpose_may_not_be_continued(tmp_path: Path) -> None:
    w = world(tmp_path, {"f": SHALLOW}, solver=SPLITTING)
    w.run()
    first = read_journal(w.journal(), validator_of(load_campaign(w.campaign))).records[0]
    audit = build_record(
        replace(first.payload, purpose=Purpose.AUDIT),  # type: ignore[type-var]
        seq=0,
        prev="0" * 64,
        utc=first.utc,
    )
    w.journal().write_bytes(audit.line + b"\n")
    with pytest.raises(ConfigurationError) as error:
        w.run()
    assert error.value.rule == "run.purpose"


def test_a_second_signal_cuts_the_grace_period_for_tools_that_ignore_termination(
    tmp_path: Path,
) -> None:
    policy = t.split_policy(stop_grace_ms=30_000)
    ready = tmp_path / "ready"
    solver = {"max_free": 3, "sleep": 60.0, "ignore_term": True, "ready": str(ready)}
    solver["proof_at_start"] = True
    w = world(tmp_path, {"f": DEEP}, solver=solver, policy=policy)
    trace = tmp_path / "trace.txt"
    child = t.spawn_runner(w.spec(jobs=1), trace=trace)
    wait_trace(trace, "attempt.solve", child)
    deadline = time.monotonic() + 30
    while not ready.exists():  # the solver now ignores TERM
        assert time.monotonic() < deadline and child.poll() is None
        time.sleep(0.01)
    os.kill(child.pid, signal.SIGTERM)
    time.sleep(1.0)
    assert child.poll() is None  # the run waits for the grace period
    started = time.monotonic()
    os.kill(child.pid, signal.SIGTERM)
    code, out, err = t.messages(child, timeout_s=20)
    assert code == 130, (out, err)
    assert time.monotonic() - started < 10  # not the 30 s of the policy
    t.wait_clean(w.results, w.work)
    assert w.work_files() == []  # the solver that ignored TERM left no proof file either


def test_a_journal_that_changes_before_the_service_starts_is_refused(tmp_path: Path) -> None:
    w = world(tmp_path, {"f": SHALLOW}, solver=SPLITTING)
    w.run()

    def hooks(name: str) -> None:
        if name == "startup.measured":  # after the validation, before the service opens it
            lines = w.journal().read_bytes().splitlines(keepends=True)
            w.journal().write_bytes(b"".join(lines[:-1]))

    with pytest.raises(IntegrityError) as error:
        w.run(hooks=hooks)
    assert error.value.rule == "run.tail" and exit_code_of(error.value) == 4


def test_a_commit_position_the_journal_does_not_hold_is_an_integrity_error(
    tmp_path: Path,
) -> None:
    w = world(tmp_path, {"f": SHALLOW}, solver=SPLITTING)
    box: list[Coordinator] = []

    def hooks(name: str) -> None:
        if name == "loop.start":
            coordinator = box[0]
            last = coordinator.tail.seq  # type: ignore[union-attr]
            with pytest.raises(IntegrityError):
                coordinator._acknowledge(AppendValue(last + 50, "a" * 64))
            with pytest.raises(IntegrityError):  # a seq the journal holds, with another head
                coordinator._acknowledge(AppendValue(last, "b" * 64))
            raise IntegrityError("test.done", "stop here")

    box.append(Coordinator(w.config(hooks=hooks)))
    with pytest.raises(IntegrityError) as error:
        box[0].run()
    assert error.value.rule == "test.done"
    t.wait_clean(w.results, w.work)


@pytest.mark.parametrize(
    ("code", "rule", "exit_code"),
    [
        (errno.EACCES, "run.access", 3),
        (errno.ENOENT, "run.access", 3),
        (errno.EROFS, "run.access", 3),
        (errno.EIO, "run.io", 5),
        (errno.ENOSPC, "run.io", 5),
    ],
)
def test_an_unclassified_os_error_is_an_access_problem_or_an_io_failure(
    tmp_path: Path, code: int, rule: str, exit_code: int
) -> None:
    w = world(tmp_path, {"f": SHALLOW}, solver=SPLITTING)

    def hooks(name: str) -> None:
        if name == "startup.replayed":
            raise OSError(code, os.strerror(code), "/some/file")

    with pytest.raises(CubeproofError) as error:
        w.run(hooks=hooks)
    assert error.value.rule == rule and exit_code_of(error.value) == exit_code
    assert "/some/file" in error.value.detail
    t.wait_clean(w.results, w.work)  # the lock was released
    assert w.run().exit_code == 0


def test_a_signal_during_the_startup_ends_it_before_any_record(tmp_path: Path) -> None:
    w = world(tmp_path, {"f": SHALLOW}, solver=SPLITTING)

    def hooks(name: str) -> None:
        if name == "startup.reconciled":
            os.kill(os.getpid(), signal.SIGTERM)

    result = w.run(hooks=hooks, handle_signals=True)
    assert (result.exit_code, result.reason) == (130, Stop.INTERRUPTED)
    assert not w.journal().exists()
    t.wait_clean(w.results, w.work)
    assert w.run().exit_code == 0


def test_a_signal_during_the_shutdown_is_counted_and_the_shutdown_completes(
    tmp_path: Path,
) -> None:
    """The handlers stay installed until the run has shut down and reported."""
    w = world(tmp_path, {"f": SHALLOW}, solver=SPLITTING)
    before = signal.getsignal(signal.SIGTERM)
    handled: list[tuple[str, bool]] = []

    def hooks(name: str) -> None:
        if name in ("shutdown", "cache.written"):
            ours = signal.getsignal(signal.SIGTERM) not in (before, signal.SIG_DFL, None)
            handled.append((name, ours))
            if ours:  # never with the default action: that would kill the test process
                os.kill(os.getpid(), signal.SIGTERM)

    result = w.run(hooks=hooks, handle_signals=True)
    assert handled == [("shutdown", True), ("cache.written", True)]
    # the loop had already ended: the run reports its completed work, not an interruption
    assert (result.exit_code, result.reason) == (0, Stop.COMPLETE)
    assert w.summary()["verdict"] == "PROVED"
    assert signal.getsignal(signal.SIGTERM) == before
    t.wait_clean(w.results, w.work)


def test_at_most_one_reference_split_runs_at_a_time(tmp_path: Path) -> None:
    """The reference lookahead shares one engine per formula; its trail is not reentrant."""
    w = world(tmp_path, {"f": DEEP}, solver=SPLITTING)
    box: list[Coordinator] = []
    most: list[int] = []

    def hooks(name: str) -> None:
        if name == "split.started":
            most.append(len(box[0]._splits))

    box.append(Coordinator(w.config(hooks=hooks, jobs=4)))
    assert box[0].run().exit_code == 0
    assert len(most) == 5 and max(most) == 1


def test_a_service_that_dies_with_a_stop_in_flight_ends_the_run_with_exit_five(
    tmp_path: Path,
) -> None:
    w = world(tmp_path, {"f": DEEP}, solver=SPLITTING, policy=t.split_policy(max_cube_size=1))
    box: list[Coordinator] = []
    killed: list[str] = []

    def hooks(name: str) -> None:
        io = box[0].io
        if name == "stop.submitted" and not killed and io is not None:
            killed.append(name)
            os.kill(io.pid, signal.SIGKILL)

    box.append(Coordinator(w.config(hooks=hooks)))
    result = box[0].run()
    assert (result.exit_code, result.reason) == (5, Stop.SERVICE)
    assert any("I/O service failed" in n for n in result.notes)
    t.wait_clean(w.results, w.work)
    # the journal decides: the next run derives the stops that were lost and ends like any other
    assert w.run().exit_code == 1 and len(w.records("node_stop")) == 2


def test_tasks_the_state_no_longer_needs_are_cancelled_without_a_record(tmp_path: Path) -> None:
    ready = tmp_path / "ready"
    solver = {"max_free": 3, "sleep": 0.3, "proof_at_start": True, "ready": str(ready)}
    w = world(tmp_path, {"f": SHALLOW}, solver=solver)
    box: list[Coordinator] = []
    started: list[str] = []
    patched: list[str] = []
    proofs: list[list[str]] = []

    def hooks(name: str) -> None:
        coordinator = box[0]
        if name == "attempt.started":
            started.append(name)
        if name == "attempt.solve" and not patched:
            patched.append(name)
            deadline = time.monotonic() + 60
            while not ready.exists():  # the solver runs and has created its proof file
                assert time.monotonic() < deadline, "the solver did not start"
                time.sleep(0.01)
            proofs.append(proof_files(w))
            state = coordinator.state
            assert state is not None
            original = state.unneeded

            def once(running: Sequence[Key]) -> list[Key]:
                state.unneeded = original  # type: ignore[method-assign]
                return sorted(running)  # as if a verified ancestor had closed them

            state.unneeded = once  # type: ignore[method-assign]
            coordinator._dirty = True

    box.append(Coordinator(w.config(hooks=hooks)))
    result = box[0].run()
    assert result.exit_code == 0
    assert len(started) == len(w.attempts()) + 1  # the cancelled attempt left no record
    assert proofs and proofs[0], "no solver proof file existed when the attempt was cancelled"
    assert w.work_files() == []  # the cancelled solve's proof file is gone with its attempt
    assert w.summary()["verdict"] == "PROVED"


def test_a_run_in_another_thread_leaves_signal_handling_to_its_caller(tmp_path: Path) -> None:
    """Signal handlers can only be installed by the main thread: elsewhere the run simply
    does not install them (a library caller owns its signals)."""
    w = world(tmp_path, {"f": SHALLOW}, solver=SPLITTING)
    found: list[RunResult | BaseException] = []

    def target() -> None:
        try:
            found.append(w.run(handle_signals=True))
        except BaseException as error:  # reported to the test below
            found.append(error)

    thread = threading.Thread(target=target)
    thread.start()
    thread.join(timeout=120)
    assert not thread.is_alive() and len(found) == 1
    outcome = found[0]
    assert isinstance(outcome, RunResult) and outcome.exit_code == 0


def test_a_node_whose_unit_route_keeps_exhausting_the_checker_is_blocked_not_retried_forever(
    tmp_path: Path,
) -> None:
    """A parent conflict is refuted by the unit route, never split (specification §9.1); if that
    route cannot be checked within the arena maxima the run stops the node instead of looping."""
    conflict = canonical_dimacs(2, [(1,), (-1,)])
    policy = t.split_policy(checker_max_heap_mib=512, stream_heap_mib=512)  # a short arena ladder
    w = world(tmp_path, {"f": conflict}, policy=policy)
    t.configure(w.tools.checker, arena=True)
    launches: list[str] = []

    def guard(name: str) -> None:  # a run that never ends fails here, quickly
        if name in ("attempt.started", "split.started"):
            launches.append(name)
            assert len(launches) <= 12, "runaway retries"

    result = w.run(hooks=guard)
    assert (result.exit_code, result.reason) == (1, Stop.COMPLETE)
    assert open_states(result) == {"resource_blocked"}
    attempts = w.attempts()
    assert [(a["outcome"], a["reason"], a["route"]) for a in attempts] == [
        ("EXHAUSTED", "check_memory", "unit")
    ] * 4  # the first attempt and tool_retries + 2 forced ones
    heaps = [[c["heap_mib"] for c in a["checks"]] for a in attempts]
    assert all(h == [64, 128, 256, 512] for h in heaps)  # the doubled arena of one proof
    for a in attempts:  # a unit route has no solver; its usage has one entry for each check
        usage = a["diagnostics"]["usage"]
        assert set(usage) == {"host_cpu", "checks"} and len(usage["checks"]) == 4
    assert w.records("split") == []  # a parent conflict is never turned into a split
    assert [(s["state"], s["reason"]) for s in w.records("node_stop")] == [
        ("resource_blocked", "unit_route_exhausted")
    ]
    assert w.work_files() == []
    # with a checker that works, the same node is refuted on the next run after a reopening
    t.configure(w.tools.checker)
    assert w.run(reopen_blocked=True).exit_code == 0
    assert w.summary()["verdict"] == "PROVED"


# -- the known-answer control of the checker (specification §7.3) ---------------------------------


def test_a_session_asks_the_checker_its_known_answers_before_its_first_record(
    tmp_path: Path,
) -> None:
    """A checker that rejects everything fails the first question: no header, no record. With
    the honest scripted tools the control passes and leaves no note; a session that skips it
    says so in its result."""
    w = world(tmp_path, {"f": SHALLOW}, policy=t.split_policy())
    t.configure(w.tools.checker, reject=True)
    with pytest.raises(ToolError) as caught:
        w.run(known_answer=True)
    assert caught.value.rule == "tool.known_answer" and "was not accepted" in caught.value.detail
    assert not w.journal().exists()
    t.configure(w.tools.checker)
    done = w.run(known_answer=True)
    assert done.exit_code == 0 and SKIPPED_CONTROL not in done.notes
    again = world(tmp_path / "skipped", {"f": SHALLOW}, policy=t.split_policy())
    assert SKIPPED_CONTROL in again.run().notes  # the scripted worlds of these tests skip it


# -- what the tools used (specification §4.8, diagnostics) -----------------------------------------


def test_every_attempt_records_what_its_tools_used(tmp_path: Path) -> None:
    """Processor time and peak memory of each process, and the processor of the machine, are in
    the diagnostics of the attempt; the record's own fields are untouched. Oracle: the shape and
    plausible ranges (the scripted tools are Python interpreters), and one entry per check."""
    w = world(tmp_path, {"f": SHALLOW}, solver=SPLITTING)
    assert w.run().exit_code == 0
    attempts = w.attempts()
    assert attempts
    for attempt in attempts:
        usage = attempt["diagnostics"]["usage"]
        assert set(usage) <= {"host_cpu", "solver", "checks"}  # a file mode
        assert usage["host_cpu"] == host_cpu() and isinstance(usage["host_cpu"], str)
        assert len(usage["checks"]) == len(attempt["checks"])
        runs = usage["checks"] + ([usage["solver"]] if attempt["route"] == "cdcl" else [])
        assert ("solver" in usage) == (attempt["route"] == "cdcl")
        for used in runs:
            assert set(used) == {"cpu_ms", "max_rss_kib", "launch_rss_kib"}
            assert type(used["cpu_ms"]) is int and 0 <= used["cpu_ms"] < 60_000
            assert type(used["launch_rss_kib"]) is int and used["launch_rss_kib"] > 1024
            # counted from the fork: not far below the coordinator's own resident size
            assert type(used["max_rss_kib"]) is int
            assert used["launch_rss_kib"] // 2 <= used["max_rss_kib"] < 1 << 22
    assert w.summary()["verdict"] == "PROVED"  # both certifiers read the records as before


def test_the_processor_model_is_read_from_cpuinfo(tmp_path: Path) -> None:
    listing = tmp_path / "cpuinfo"
    listing.write_text(
        "processor\t: 0\nvendor_id\t: X\nmodel name\t:   Some   CPU \u00e9 9000  \n", "utf-8"
    )
    assert host_cpu(str(listing)) == "Some CPU 9000"  # not ASCII: dropped
    listing.write_text("processor\t: 0\n", "utf-8")
    assert host_cpu(str(listing)) == ""
    assert host_cpu(str(tmp_path / "absent")) == ""
    listing.write_text("model name : " + "x" * 500 + "\n", "utf-8")
    assert len(host_cpu(str(listing))) == 120


# -- the policy of a later session (specification §4.3, §7.3) --------------------------------------


def resumes(w: t.World) -> list[dict[str, Any]]:
    return w.records("resume")


def test_a_session_does_not_silently_drop_the_proof_mode_of_the_session_before(
    tmp_path: Path,
) -> None:
    """A worker started with ``retain`` and restarted without the option would record leaves
    without their proofs. The restart is refused before any record; repeating the option, or
    saying that the campaign's policy is wanted, goes on."""
    w = world(tmp_path, {"f": SHALLOW}, solver=SPLITTING)
    assert w.run(proof_mode="retain").exit_code == 0
    before = t.journal_records(w.results)
    with pytest.raises(ConfigurationError) as caught:
        w.run()
    assert caught.value.rule == "run.policy_changed" and exit_code_of(caught.value) == 3
    assert 'proof_mode="retain"' in caught.value.detail
    assert 'proof_mode="transient"' in caught.value.detail
    assert "--campaign-policy" in caught.value.detail
    assert t.journal_records(w.results) == before  # refused before the resume record
    assert w.run(proof_mode="retain").exit_code == 0
    assert resumes(w)[-1]["policy"]["proof_mode"] == "retain"
    assert w.run(campaign_policy=True).exit_code == 0  # on purpose: back to the campaign
    assert resumes(w)[-1]["policy"]["proof_mode"] == "transient"
    assert w.run().exit_code == 0  # nothing differs from the session before any more


def test_a_dropped_policy_override_is_refused_and_a_named_one_may_change(tmp_path: Path) -> None:
    w = world(tmp_path, {"f": SHALLOW}, solver=SPLITTING)
    assert w.run(policy_overrides={"tool_retries": 2, "split.vars": 1}).exit_code == 0
    with pytest.raises(ConfigurationError) as caught:
        w.run(policy_overrides={"tool_retries": 2})  # split.vars is gone
    assert caught.value.rule == "run.policy_changed"
    assert "split.vars=1" in caught.value.detail and "tool_retries" not in caught.value.detail
    # naming another value of the same object does not cover it: the comparison is by leaf
    with pytest.raises(ConfigurationError) as caught:
        w.run(policy_overrides={"tool_retries": 2, "split.wall_ms": 900})
    assert "split.vars=1" in caught.value.detail and "wall_ms" not in caught.value.detail
    # a value that this command line names may change, also inside a nested field
    assert w.run(policy_overrides={"tool_retries": 5, "split.vars": 2}).exit_code == 0
    assert resumes(w)[-1]["policy"]["tool_retries"] == 5
    assert resumes(w)[-1]["policy"]["split"]["vars"] == 2


def test_a_session_on_other_cubeproof_sources_is_refused_unless_accepted(tmp_path: Path) -> None:
    """A journal continued by another release says so: refused before any record, then
    accepted on purpose with a note; the resume records the new sources."""
    w = world(tmp_path, {"f": SHALLOW}, solver=SPLITTING)
    assert w.run().exit_code == 0
    first = w.records("header")[0]["machinery"]["cubeproof_sha256"]
    other = tmp_path / "other-cubeproof"
    other.mkdir()
    (other / "__init__.py").write_text('__version__ = "9.9.9"\n', "utf-8")
    before = t.journal_records(w.results)
    with pytest.raises(ConfigurationError) as caught:
        w.run(packages={"cubeproof": other})
    assert caught.value.rule == "run.code_changed" and exit_code_of(caught.value) == 3
    assert first in caught.value.detail and "--accept-code-change" in caught.value.detail
    assert t.journal_records(w.results) == before  # refused before the resume record
    result = w.run(packages={"cubeproof": other}, accept_code_change=True)
    assert result.exit_code == 0
    assert any("cubeproof sources differ" in note for note in result.notes)
    assert resumes(w)[-1]["machinery"]["cubeproof_sha256"] != first
    assert w.run(packages={"cubeproof": other}).exit_code == 0  # the same sources again


def test_a_depth_key_and_the_proof_mode_are_values_like_the_others(tmp_path: Path) -> None:
    w = world(tmp_path, {"f": SHALLOW}, solver=SPLITTING)
    assert w.run(proof_mode="retain", policy_overrides={"leaf_time_ms.5": 1000}).exit_code == 0
    with pytest.raises(ConfigurationError) as caught:
        w.run(proof_mode="retain")  # the depth key is gone
    assert "leaf_time_ms.5=1000" in caught.value.detail and "unset" in caught.value.detail
    assert "proof_mode" not in caught.value.detail
    # naming the mode is what allows changing it; the depth key is repeated
    assert w.run(proof_mode="stream", policy_overrides={"leaf_time_ms.5": 1000}).exit_code == 0
    assert resumes(w)[-1]["policy"]["proof_mode"] == "stream"
    with pytest.raises(ConfigurationError) as caught:
        w.run(policy_overrides={"leaf_time_ms.5": 1000})
    assert 'proof_mode="stream"' in caught.value.detail


def test_the_proof_cap_may_differ_between_sessions(tmp_path: Path) -> None:
    """The machine clamps the proof cap at every start (specification §8.3), so it is the one
    field a later session may change without naming it."""
    w = world(tmp_path, {"f": SHALLOW}, solver=SPLITTING)
    assert w.run(policy_overrides={"proof_cap_bytes": 1 << 20}).exit_code == 0
    assert w.run().exit_code == 0
    assert resumes(w)[-1]["policy"]["proof_cap_bytes"] != 1 << 20


def test_a_first_session_has_nothing_to_continue(tmp_path: Path) -> None:
    w = world(tmp_path, {"f": SHALLOW}, solver=SPLITTING)
    assert w.run(proof_mode="retain", policy_overrides={"tool_retries": 1}).exit_code == 0
    assert w.records("header")[0]["policy"]["proof_mode"] == "retain"
