"""The leaf and the I/O service: identity-bound results, failures and commit (specification §7.1,
§8.1).

Results reach an attempt only for jobs it submitted itself, with its own attempt ID and the
operation and path it asked for; anything else stops the attempt (no record). Hash failures
and hashes that disagree are TOOL_FAILED ``io``/``file_changed``. The single append happens
after every input is measured; a refused append leaves no record and the work removed, an
uncertain (fatal) one leaves the files to replay. One test runs the real service process.
"""

from __future__ import annotations

import os
import sys
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from cp_leaf_support import (  # noqa: F401 - fixtures are registered by import
    HERE,
    SAT,
    SRC,
    TINY,
    TINY_PROOFS,
    UNIT_MODEL,
    Bench,
    LocalIo,
    fail_op,
    fake_tools,
    header_payload,
    isolation_fixture,
    journal_lines,
    make_policy,
    p,
    payload_value,
    report_hash,
    resume_payload,
    sha,
    supervisor_fixture,
)

from cubeproof.base.errors import ToolError
from cubeproof.cnf.cubecnf import CnfDigest
from cubeproof.contracts.identity import node_id
from cubeproof.contracts.io import (
    AppendRequest,
    HashRequest,
    HashValue,
    Job,
    Op,
    RemoveRequest,
    RemoveValue,
    Result,
)
from cubeproof.evidence.journal import JournalWriter, RunLock, read_journal
from cubeproof.evidence.schema import RecordSequence
from cubeproof.leaf.attempt import LeafAttempt, LeafError, Phase
from cubeproof.leaf.binding import fitted_check_time_ms
from cubeproof.leaf.driver import drive
from cubeproof.tools.io_service_client import IoClient
from cubeproof.tools.process import Supervisor

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="tool isolation is Linux-only")


@pytest.fixture
def bench(tmp_path: Path, supervisor: Supervisor) -> Iterator[Bench]:
    value = Bench(tmp_path, supervisor, solver=p.solver_unsat(TINY_PROOFS[0]))
    yield value
    value.close()


def run_until(bench: Bench, attempt: LeafAttempt, phase: Phase, limit_s: float = 60.0) -> None:
    """Advance one attempt and the supervisor, without polling the I/O port, until the
    attempt is in ``phase`` (the phases before SEAL need no I/O)."""
    deadline = time.monotonic() + limit_s
    while attempt.phase is not phase:
        assert time.monotonic() < deadline, f"phase {phase} not reached, at {attempt.phase}"
        attempt.advance()
        bench.supervisor.step(5)


# -- hash failures and disagreeing hashes ----------------------------------------------------


@pytest.mark.parametrize(
    ("suffix", "nth", "reason", "checked"),
    [
        (".lrat", 0, "io", False),  # sealing hash fails: never checked
        (".cnf", 0, "io", True),  # the final CNF hash fails
        (".lrat", 1, "io", True),  # the final proof hash fails
    ],
)
def test_a_failed_hash_is_tool_failed_io(
    bench: Bench, suffix: str, nth: int, reason: str, checked: bool
) -> None:
    bench.io.faults.append(fail_op(Op.HASH, nth=nth, suffix=suffix))
    _, record = bench.one(TINY, (3,))
    assert (record["outcome"], record["reason"]) == ("TOOL_FAILED", reason)
    assert (len(bench.checker.calls()) == 1) is checked
    assert bench.work_files() == []


@pytest.mark.parametrize("cube", [(3,), (1,)], ids=["cdcl", "unit"])
@pytest.mark.parametrize(
    ("suffix", "nth", "change", "note"),
    [
        (".lrat", 0, "sha", "proof:changed"),  # the sealed hash disagrees with the final one
        (".lrat", 0, "size", "proof:sealed_size_differs"),  # sealed size vs the file's size
        (".lrat", 1, "sha", "proof:changed"),
        (".cnf", 0, "sha", "cnf:changed"),  # the final CNF hash is not the expected digest
        (".cnf", 0, "size", "cnf:changed"),
    ],
)
def test_a_disagreeing_hash_is_file_changed(
    bench: Bench, suffix: str, nth: int, change: str, note: str, cube: tuple[int, ...]
) -> None:
    """Detected by the attempt itself (its notes), not only by the binding's defence."""
    fault = (
        report_hash(nth=nth, suffix=suffix, sha256="0" * 64)
        if change == "sha"
        else report_hash(nth=nth, suffix=suffix, size=1)
    )
    bench.io.faults.append(fault)
    _, record = bench.one(TINY, cube)
    assert (record["outcome"], record["reason"]) == ("TOOL_FAILED", "file_changed")
    assert record["route"] == ("unit" if cube == (1,) else "cdcl")
    assert "binding" not in record["diagnostics"]
    notes = record["diagnostics"]["notes"]
    if cube == (1,) and (suffix, nth, change) == (".lrat", 0, "sha"):
        note = "proof:not_the_unit_proof"  # the sealed hash is not the generated proof's
    assert note in notes, notes


@pytest.mark.parametrize(
    ("fault", "reason", "note"),
    [
        ("sha", "file_changed", "cnf:changed"),
        ("size", "file_changed", "cnf:changed"),
        ("failed", "io", "hash:cnf_final:io.injected"),
    ],
)
def test_a_unit_model_with_a_bad_final_cnf_hash_is_tool_failed(
    bench: Bench, fault: str, reason: str, note: str
) -> None:
    """A complete propagation (route unit MODEL, no tool ran) whose final CNF hash disagrees
    or fails is TOOL_FAILED (specification §6.3 row 1 precedes the model), without the model."""
    bench.io.faults.append(
        {
            "sha": report_hash(nth=0, suffix=".cnf", sha256="0" * 64),
            "size": report_hash(nth=0, suffix=".cnf", size=1),
            "failed": fail_op(Op.HASH, nth=0, suffix=".cnf"),
        }[fault]
    )
    attempt, record = bench.one(UNIT_MODEL)
    assert (record["outcome"], record["reason"], record["route"]) == ("TOOL_FAILED", reason, "unit")
    assert record["assignment"] is None and record["model_error"] is None
    assert record["solver"] is None and record["checks"] == []
    assert "model" not in record["diagnostics"]
    assert note in record["diagnostics"]["notes"], record["diagnostics"]["notes"]
    assert bench.solver.calls() == [] and bench.checker.calls() == []
    assert attempt.phase is Phase.DONE and bench.work_files() == []


def test_a_fatal_service_failure_abandons_the_attempt_without_a_record(bench: Bench) -> None:
    bench.io.faults.append(fail_op(Op.HASH, nth=1, fatal=True, rule="io.fsync"))
    attempt = bench.attempt(TINY, (3,))
    with pytest.raises(ToolError):
        bench.run(attempt)
    assert attempt.phase is Phase.ABANDONED and attempt.abandoned == "io_failed"
    assert bench.io.attempts() == []


# -- commit ------------------------------------------------------------------------------------


def test_a_refused_append_leaves_no_record_and_removes_the_work(bench: Bench) -> None:
    bench.io.faults.append(fail_op(Op.APPEND, rule="journal.refused"))
    attempt = bench.attempt(TINY, (3,))
    bench.run(attempt)
    assert attempt.phase is Phase.ABANDONED and attempt.abandoned == "commit_refused"
    assert attempt.committed is None
    assert bench.io.attempts() == []
    assert bench.work_files() == []


def test_an_uncertain_append_keeps_the_work_for_replay(bench: Bench) -> None:
    bench.io.faults.append(fail_op(Op.APPEND, fatal=True, rule="journal.fsync"))
    attempt = bench.attempt(TINY, (3,))
    with pytest.raises(ToolError):
        bench.run(attempt)
    assert attempt.phase is Phase.ABANDONED and attempt.abandoned == "commit_uncertain"
    assert sorted(bench.work_files()) == sorted(
        os.path.basename(x) for x in (attempt.cnf_path, attempt.proof_path)
    )


def test_a_failed_cleanup_keeps_the_committed_record(bench: Bench) -> None:
    bench.io.faults.append(fail_op(Op.REMOVE))
    attempt, record = bench.one(TINY, (3,))
    assert record["outcome"] == "VERIFIED_UNSAT"
    assert attempt.phase is Phase.DONE and attempt.committed is not None
    assert attempt.cleanup_error is not None


def test_the_record_is_committed_exactly_once_with_its_attempt_id(bench: Bench) -> None:
    attempt, record = bench.one(TINY, (3,))
    appends = [j for j in bench.io.jobs if j.op is Op.APPEND]
    assert len(appends) == 1 and appends[0].attempt_id == attempt.attempt_id
    assert isinstance(appends[0].request, AppendRequest)
    assert appends[0].request.value()["attempt_id"] == attempt.attempt_id
    assert attempt.record is not None
    assert {"type": "attempt", **attempt.record.to_json()} == appends[0].request.value()
    assert attempt.committed is not None
    assert record["seq"] == attempt.committed.seq and record["self"] == attempt.committed.head


# -- identity of results -----------------------------------------------------------------------


def test_a_result_of_another_attempts_job_is_refused(
    tmp_path: Path, supervisor: Supervisor
) -> None:
    bench = Bench(tmp_path, supervisor, solver=p.solver_unsat(TINY_PROOFS[0]))
    try:
        first, second = bench.attempt(TINY, (3,)), bench.attempt(TINY, (3,))
        run_until(bench, first, Phase.SEAL)
        run_until(bench, second, Phase.SEAL)
        results = bench.io.poll()
        assert len(results) == 2
        ((job, result),) = [(j, r) for j, r in results if second.owns(j)]
        assert not first.owns(job)
        with pytest.raises(LeafError) as caught:
            first.deliver(job, result)
        assert caught.value.rule == "leaf.io_mismatch"
        assert first.phase is Phase.ABANDONED and first.abandoned == "io_mismatch"
        # the stopped attempt submits nothing more and never commits
        before = len(bench.io.jobs)
        first.advance()
        assert len(bench.io.jobs) == before
    finally:
        bench.supervisor.shutdown(200)
        bench.close()


def forged(job: Job, **changes: Any) -> Result:
    values: dict[str, Any] = {
        "job_id": job.job_id,
        "op": job.op,
        "attempt_id": job.attempt_id,
        "outcome": HashValue(1, "0" * 64),
    }
    values.update(changes)
    return Result(**values)


@pytest.mark.parametrize(
    "changes",
    [
        {"attempt_id": "ff" * 16},
        {"attempt_id": None},
        {"job_id": 10_000},
        {"op": Op.REMOVE, "outcome": RemoveValue(())},
    ],
    ids=["other-attempt", "no-attempt", "other-job", "other-op"],
)
def test_a_result_that_does_not_answer_the_job_is_refused(
    bench: Bench, changes: dict[str, Any]
) -> None:
    attempt = bench.attempt(TINY, (3,))
    run_until(bench, attempt, Phase.SEAL)
    job = next(j for j in bench.io.jobs if attempt.owns(j))
    assert isinstance(job.request, HashRequest) and job.request.path == attempt.proof_path
    with pytest.raises(LeafError):
        attempt.deliver(job, forged(job, **changes))
    assert attempt.abandoned == "io_mismatch"


def drive_until(bench: Bench, attempt: LeafAttempt, phase: Phase, limit_s: float = 60.0) -> None:
    """Drive one attempt with I/O delivery until it is in ``phase``; jobs it submitted on
    entering that phase stay queued (unexecuted) in the local port."""
    deadline = time.monotonic() + limit_s
    while attempt.phase is not phase:
        assert time.monotonic() < deadline, f"phase {phase} not reached, at {attempt.phase}"
        attempt.advance()
        bench.supervisor.step(5)
        if attempt.wants_check:
            attempt.start_check()
        for job, result in bench.io.poll():
            attempt.deliver(job, result)
            if attempt.phase is phase:
                break


def test_a_sealed_proof_waits_for_the_check_grant(bench: Bench) -> None:
    """QUEUED_CHECK holds the sealed proof until the scheduler grants the check; the request
    names the arena, its memory cap and the fitted time (specification §8.3, §8.4)."""
    attempt = bench.attempt(TINY, (3,))
    with pytest.raises(LeafError):
        attempt.start_check()
    deadline = time.monotonic() + 60
    while attempt.phase is not Phase.QUEUED_CHECK:
        assert time.monotonic() < deadline
        attempt.advance()
        bench.supervisor.step(5)
        for job, result in bench.io.poll():
            attempt.deliver(job, result)
    for _ in range(5):
        assert attempt.advance() is Phase.QUEUED_CHECK and attempt.wants_check
    assert bench.checker.calls() == [] and attempt.processes == ()
    request = attempt.check_request
    assert request is not None
    size = len(TINY_PROOFS[0])
    policy = bench.policy
    assert (request.heap_mib, request.stack_mib) == (512, policy.checker_stack_mib)
    assert request.memory_bytes == (512 + policy.checker_stack_mib + policy.checker_slack_mib) << 20
    assert request.time_ms == fitted_check_time_ms(policy, size)
    assert request.proof_bytes == size
    attempt.start_check()
    assert attempt.check_request is None and len(attempt.processes) == 1
    drive([attempt], supervisor=bench.supervisor, io=bench.io, timeout_s=60)
    assert attempt.phase is Phase.DONE
    assert [r["outcome"] for r in bench.io.attempts()] == ["VERIFIED_UNSAT"]


def test_a_forged_job_with_a_pending_job_id_is_refused(bench: Bench) -> None:
    """Same job ID and attempt ID, another request (a removal of another file): not the job
    this attempt submitted, whatever its result says."""
    attempt = bench.attempt(TINY, (3,))
    drive_until(bench, attempt, Phase.CLEANUP)
    (job,) = bench.io.queue
    assert attempt.owns(job) and isinstance(job.request, RemoveRequest)
    forged_job = Job(job.job_id, attempt.attempt_id, RemoveRequest((str(bench.work / "other"),)))
    assert not attempt.owns(forged_job)
    with pytest.raises(LeafError):
        attempt.deliver(
            forged_job, Result(job.job_id, Op.REMOVE, attempt.attempt_id, RemoveValue(()))
        )
    bench.io.queue.clear()


def test_a_result_delivered_twice_is_refused(bench: Bench) -> None:
    attempt = bench.attempt(TINY, (3,))
    run_until(bench, attempt, Phase.SEAL)
    ((job, result),) = bench.io.poll()
    attempt.deliver(job, result)
    with pytest.raises(LeafError):
        attempt.deliver(job, result)


def test_a_job_with_another_path_is_never_taken_as_this_attempts_measurement(bench: Bench) -> None:
    """A hash job for another file submitted under this attempt's ID is not its result."""
    attempt = bench.attempt(TINY, (3,))
    run_until(bench, attempt, Phase.SEAL)
    other = bench.io.submit(HashRequest(attempt.cnf_path), attempt_id=attempt.attempt_id)
    assert not attempt.owns(other)
    with pytest.raises(LeafError):
        attempt.deliver(other, forged(other))


class MisbuildingIo:
    """An I/O client that builds another job than the one asked for: another attempt ID, or
    a hash of the CNF when the proof was asked for (the explicit attempt-ID and
    path guards of ``deliver`` do not rely on the client being correct)."""

    def __init__(
        self, inner: LocalIo, *, attempt_id: str | None = None, path: tuple[str, str] | None = None
    ) -> None:
        self.inner = inner
        self.attempt_id = attempt_id
        self.path = path

    @property
    def failure(self) -> Any:
        return self.inner.failure

    def submit(self, request: Any, *, attempt_id: str | None = None) -> Job:
        if (
            self.path is not None
            and isinstance(request, HashRequest)
            and request.path == self.path[0]
        ):
            request = HashRequest(self.path[1])
        return self.inner.submit(request, attempt_id=self.attempt_id or attempt_id)

    def poll(self, timeout: float = 0.0) -> list[tuple[Job, Result]]:
        return self.inner.poll(timeout)


@pytest.mark.parametrize("wrong", ["attempt_id", "path"])
def test_a_job_built_wrongly_by_the_client_is_never_taken(bench: Bench, wrong: str) -> None:
    attempt_id = "ab" * 16
    nid = node_id(TINY.sha256, (3,))
    stem = f"{bench.work}/{nid}-{attempt_id}"
    port = MisbuildingIo(
        bench.io,
        attempt_id="cd" * 16 if wrong == "attempt_id" else None,
        path=(f"{stem}.lrat", f"{stem}.cnf") if wrong == "path" else None,
    )
    attempt = LeafAttempt(
        formula=TINY,
        digest=CnfDigest(TINY),
        cube=(3,),
        policy=bench.policy,
        work_dir=str(bench.work),
        tools=bench.tools,
        supervisor=bench.supervisor,
        io=port,
        attempt_id=attempt_id,
    )
    assert attempt.proof_path == f"{stem}.lrat"
    with pytest.raises(LeafError) as caught:
        drive([attempt], supervisor=bench.supervisor, io=port, timeout_s=60)
    assert caught.value.rule == "leaf.io_mismatch"
    assert attempt.phase is Phase.ABANDONED and attempt.abandoned == "io_mismatch"
    assert attempt.record is None and bench.io.attempts() == []
    assert not any(job.op is Op.APPEND for job in bench.io.jobs)


def test_after_the_io_service_failed_no_record_is_attempted(bench: Bench) -> None:
    attempt = bench.attempt(TINY, (3,))
    run_until(bench, attempt, Phase.SEAL)
    attempt.io_failed("the service died")
    assert attempt.phase is Phase.ABANDONED and attempt.abandoned == "io_failed"
    jobs = len(bench.io.jobs)
    attempt.advance()
    assert len(bench.io.jobs) == jobs


def test_an_unknown_job_stops_the_driver(bench: Bench) -> None:
    attempt = bench.attempt(TINY, (3,))
    stray = bench.io.submit(HashRequest(attempt.cnf_path), attempt_id=None)
    del stray
    with pytest.raises(LeafError) as caught:
        drive([attempt], supervisor=bench.supervisor, io=bench.io, timeout_s=30)
    assert caught.value.rule == "leaf.unknown_job"


# -- the real service process ---------------------------------------------------------------


def test_attempts_through_the_real_service_process(tmp_path: Path, supervisor: Supervisor) -> None:
    """The I/O service as its own process with a real journal: one verified, one model."""
    policy = make_policy()
    results, work = tmp_path / "results", tmp_path / "work"
    results.mkdir()
    work.mkdir()
    lock = RunLock.acquire(results / "run.lock")
    journal = results / "journal.jsonl"
    writer = JournalWriter.create(
        journal,
        payload_value(header_payload(policy)),
        validator=RecordSequence(context=None),
        run_lock=lock,
    )
    writer.close()
    fd = lock._fd
    assert fd is not None
    argv = [
        sys.executable,
        str(HERE / "cp_leaf_service_main.py"),
        "--results",
        str(results),
        "--work",
        str(work),
        "--journal",
        str(journal),
        "--lock",
        str(lock.path),
        "--lock-fd",
        str(fd),
    ]
    env = {
        "PATH": "/usr/bin:/bin",
        "LC_ALL": "C",
        "PYTHONPATH": os.pathsep.join([str(SRC), str(HERE)]),
    }
    unsat_tools, _, _ = fake_tools(tmp_path / "unsat-tools", solver=p.solver_unsat(TINY_PROOFS[0]))
    sat_tools, _, _ = fake_tools(tmp_path / "sat-tools", solver=p.solver_sat([1, -2, 3]))
    client = IoClient.spawn(argv, cwd=str(tmp_path), pass_fds=(fd,), env=env)
    try:
        resume = client.submit(AppendRequest.of(resume_payload(policy)))
        assert client.wait(resume, 30).ok
        common: dict[str, Any] = {
            "policy": policy,
            "work_dir": str(work),
            "supervisor": supervisor,
            "io": client,
        }
        unsat = LeafAttempt(
            formula=TINY, digest=CnfDigest(TINY), cube=(3,), tools=unsat_tools, **common
        )
        model = LeafAttempt(formula=SAT, digest=CnfDigest(SAT), cube=(), tools=sat_tools, **common)
        drive([unsat, model], supervisor=supervisor, io=client, timeout_s=120)
        assert unsat.phase is Phase.DONE and model.phase is Phase.DONE
    finally:
        client.close()
    contents = read_journal(journal, RecordSequence(context=None))
    assert [r.payload.TYPE.value for r in contents.records] == [
        "header",
        "resume",
        "attempt",
        "attempt",
    ]
    records = [r for r in journal_lines(journal) if r["type"] == "attempt"]
    outcomes = {r["attempt_id"]: r["outcome"] for r in records}
    assert outcomes == {unsat.attempt_id: "VERIFIED_UNSAT", model.attempt_id: "MODEL"}
    assert sorted(os.listdir(work)) == []
    proof = next(r for r in records if r["outcome"] == "VERIFIED_UNSAT")
    assert proof["proof_sha256"] == sha(TINY_PROOFS[0])
    lock.release()
