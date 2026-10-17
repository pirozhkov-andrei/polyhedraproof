"""The I/O service as one long-lived supervised process (specification §8.1).

One service process serves every job (no process per chunk or append). The client never
blocks the coordinator: submissions are buffered and written nonblocking, results are read
nonblocking, and a stalled fsync in the service does not stall ``poll``. Every result is
checked against its job; a swapped job or attempt ID, a wrong operation or artifact, a
duplicate, a sequence gap, garbage or the death of the service stops new work, kills the
service and leaves the unanswered jobs as uncertain (replay decides about them).
"""

from __future__ import annotations

import gc
import os
import signal
import subprocess
import sys
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import cp_io_support as sup
import pytest

from cubeproof.base.errors import ToolError
from cubeproof.contracts.io import (
    AppendRequest,
    AppendValue,
    Area,
    Failure,
    HashRequest,
    HashValue,
    Hello,
    Job,
    Op,
    PublishRequest,
    PublishValue,
    ReconcileRequest,
    RemoveRequest,
    Result,
)
from cubeproof.evidence.journal import RunLock
from cubeproof.tools.io_service_client import IoClient, IoServiceError, Tracker

A1 = sup.new_attempt_id(1)
A2 = sup.new_attempt_id(2)
FAKE = sup.HERE / "cp_io_fake_service.py"


class Setup:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.results = root / "results"
        self.work = root / "work"
        self.work.mkdir(parents=True)
        self.journal, self.lock = sup.create_journal(self.results)
        self.clients: list[IoClient] = []

    def spawn(self, **options: Any) -> IoClient:
        argv = sup.service_argv(
            self.results, self.work, journal=self.journal, lock=self.lock, **options
        )
        client = IoClient.spawn(
            argv, cwd=str(self.root), pass_fds=(sup.lock_fd(self.lock),), env=sup.service_env()
        )
        self.clients.append(client)
        return client

    def publish_request(self, data: bytes, name: str) -> PublishRequest:
        source = sup.write_file(self.work / name, data)
        return PublishRequest(str(source), Area.PROOFS, sup.NODE_ID, sup.sha(data), len(data))

    def close(self) -> None:
        for client in self.clients:
            client.close(timeout=10)
        self.lock.release()


@pytest.fixture
def setup(tmp_path: Path) -> Iterator[Setup]:
    value = Setup(tmp_path)
    yield value
    value.close()


def wait_hello(client: IoClient) -> Hello:
    assert sup.wait_until(lambda: client.poll(0.05) is not None and client.hello is not None)
    assert client.hello is not None
    return client.hello


# -- normal operation ------------------------------------------------------------------------------


def test_one_service_process_serves_publish_commit_and_cleanup(setup: Setup) -> None:
    client = setup.spawn(chunk=1 << 16)
    hello = wait_hello(client)
    records = sup.journal_records(setup.journal)
    assert hello.pid == client.pid
    assert (hello.seq, hello.head) == (len(records) - 1, records[-1]["self"])
    resume = client.wait(client.submit(AppendRequest.of(sup.resume_payload())), timeout=30)
    assert isinstance(resume.outcome, AppendValue)
    data = sup.proof_bytes(300_000)
    request = setup.publish_request(data, "a1.lrat")
    published = client.wait(client.submit(request, attempt_id=A1), timeout=30)
    assert published.outcome == PublishValue(request.artifact, reused=False)
    payload = sup.attempt_payload(A1, data)
    committed = client.wait(client.submit(AppendRequest.of(payload), attempt_id=A1), timeout=30)
    records = sup.journal_records(setup.journal)
    assert committed.outcome == AppendValue(len(records) - 1, records[-1]["self"])
    assert sup.payload_of(records[-1]) == payload
    removed = client.wait(
        client.submit(RemoveRequest((request.source,)), attempt_id=A1), timeout=30
    )
    assert removed.ok
    hashed = client.wait(client.submit(HashRequest(str(setup.results / request.artifact.path))), 30)
    assert hashed.outcome == HashValue(len(data), sup.sha(data))
    assert client.pid == hello.pid  # the same process for every job
    assert client.failure is None
    assert client.close(timeout=10) == 0


def test_many_jobs_are_answered_with_contiguous_sequence_numbers(setup: Setup) -> None:
    client = setup.spawn()
    jobs = [client.submit(AppendRequest.of(sup.resume_payload())) for _ in range(20)]
    path = str(sup.write_file(setup.work / "f", b"abc"))
    jobs += [client.submit(HashRequest(path)) for _ in range(20)]
    results = {job.job_id: client.wait(job, timeout=30) for job in jobs}
    seqs = [results[j.job_id].outcome.seq for j in jobs[:20]]  # type: ignore[union-attr]
    assert seqs == list(range(seqs[0], seqs[0] + 20))
    assert all(r.ok for r in results.values())
    assert client.failure is None


def test_a_commit_overtakes_a_long_copy(setup: Setup) -> None:
    client = setup.spawn(chunk=1 << 14)
    wait_hello(client)
    data = sup.proof_bytes(48 << 20)
    publish = client.submit(setup.publish_request(data, "big.lrat"), attempt_id=A1)
    commit = client.submit(AppendRequest.of(sup.resume_payload()))
    order: list[int] = []
    deadline = time.monotonic() + 120
    while len(order) < 2 and time.monotonic() < deadline:
        order += [job.job_id for job, _ in client.poll(0.1)]
    assert order == [commit.job_id, publish.job_id]
    assert client.failure is None


def test_poll_stays_responsive_while_the_service_waits_for_fsync(setup: Setup) -> None:
    client = setup.spawn(slow_fsync=0.5)
    wait_hello(client)
    data = sup.proof_bytes(1000)
    job = client.submit(setup.publish_request(data, "slow.lrat"), attempt_id=A1)
    slowest = 0.0
    got: list[Result] = []
    deadline = time.monotonic() + 60
    while not got and time.monotonic() < deadline:
        start = time.monotonic()
        got = [result for _, result in client.poll(0.0)]
        slowest = max(slowest, time.monotonic() - start)
        time.sleep(0.01)
    assert got and got[0].job_id == job.job_id
    assert slowest < 0.1, slowest  # specification §8.1: tick latency is not the service's fsync


def test_a_closed_client_never_closes_descriptors_again(setup: Setup) -> None:
    """Regression: the pipe ends must have one owner. File objects of Popen closed again by
    the garbage collector would close whatever later reused those numbers (the journal)."""
    client = setup.spawn()
    wait_hello(client)
    client.close(timeout=10)
    setup.clients.remove(client)
    opened = [os.open(os.devnull, os.O_RDONLY) for _ in range(8)]
    try:
        del client
        gc.collect()
        for fd in opened:
            os.fstat(fd)  # EBADF if a finalizer closed it
    finally:
        for fd in opened:
            os.close(fd)


def test_the_service_ends_when_its_input_closes(setup: Setup) -> None:
    client = setup.spawn()
    wait_hello(client)
    start = time.monotonic()
    assert client.close(timeout=10) == 0
    assert time.monotonic() - start < 5


def test_the_service_dies_with_its_coordinator(setup: Setup) -> None:
    """No orphan process: a killed coordinator closes the pipe; the service exits."""
    argv = sup.service_argv(setup.results, setup.work)
    script = (
        "import os, sys, time\n"
        "from cubeproof.tools.io_service_client import IoClient\n"
        f"client = IoClient.spawn({argv!r}, cwd={str(setup.root)!r}, env={sup.service_env()!r})\n"
        "while client.hello is None:\n"
        "    client.poll(0.1)\n"
        "print(client.pid, flush=True)\n"
        "time.sleep(600)\n"
    )
    coordinator = subprocess.Popen(
        [sys.executable, "-c", script],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        env=sup.service_env(),
    )
    try:
        assert coordinator.stdout is not None
        line = coordinator.stdout.readline()
        assert line.strip().isdigit(), line
        pid = int(line)
        coordinator.kill()
        coordinator.wait()

        def gone() -> bool:
            try:
                state = Path(f"/proc/{pid}/stat").read_text().split(") ")[1][0]
            except (FileNotFoundError, ProcessLookupError, IndexError):
                # ProcessLookupError (ESRCH): it exited between the open and the read.
                return True
            return state == "Z"

        assert sup.wait_until(gone, timeout=30)
    finally:
        if coordinator.poll() is None:
            coordinator.kill()


# -- failures --------------------------------------------------------------------------------------


def test_service_death_stops_new_work_and_leaves_jobs_uncertain(setup: Setup) -> None:
    client = setup.spawn(chunk=1 << 12)
    wait_hello(client)
    data = sup.proof_bytes(32 << 20)
    request = setup.publish_request(data, "big.lrat")
    job = client.submit(request, attempt_id=A1)
    staging = setup.results / "proofs" / "tmp" / f"{A1}.lrat"
    assert sup.wait_until(staging.exists)
    os.kill(client.pid, signal.SIGKILL)
    assert sup.wait_until(lambda: client.poll(0.05) is not None and client.failure is not None)
    assert client.failure is not None
    assert client.failure.rule == "io.service_died"
    assert isinstance(client.failure, ToolError)
    assert [j.job_id for j in client.uncertain()] == [job.job_id]
    with pytest.raises(IoServiceError):
        client.submit(HashRequest(request.source))
    assert Path(request.source).read_bytes() == data  # the source is kept
    # Restart: a new service reconciles; the staged copy is an orphan and goes.
    fresh = setup.spawn()
    result = fresh.wait(fresh.submit(ReconcileRequest(())), timeout=60)
    assert result.ok
    assert not staging.exists()
    assert fresh.failure is None


@pytest.mark.parametrize(
    ("mode", "rule"),
    [
        ("swap-job", "io.unknown_job"),
        ("swap-attempt", "io.mismatch"),
        ("wrong-op", "io.mismatch"),
        ("wrong-artifact", "io.mismatch"),
        ("duplicate", "io.unknown_job"),
        ("garbage", "io.protocol"),
        ("seq-gap", "io.sequence"),
        ("no-hello", "io.protocol"),
        ("exit", "io.service_died"),
    ],
)
def test_a_misbehaving_service_is_stopped(tmp_path: Path, mode: str, rule: str) -> None:
    client = IoClient.spawn(
        [sys.executable, str(FAKE), mode], cwd=str(tmp_path), env=sup.service_env()
    )
    try:
        source = sup.write_file(tmp_path / "work" / "p.lrat", b"proof")
        if mode in ("wrong-artifact", "swap-attempt"):
            request: Any = PublishRequest(
                str(source), Area.PROOFS, sup.NODE_ID, sup.sha(b"proof"), 5
            )
            job = client.submit(request, attempt_id=A1)
        elif mode == "seq-gap":
            job = client.submit(AppendRequest.of(sup.resume_payload()))
        else:
            job = client.submit(HashRequest(str(source)))
        delivered: list[tuple[Job, Result]] = []

        def failed() -> bool:
            delivered.extend(client.poll(0.05))
            return client.failure is not None

        assert sup.wait_until(failed, timeout=30)
        assert client.failure is not None
        assert client.failure.rule == rule
        if mode == "duplicate":  # the first copy was a valid answer; the second is not
            assert [j.job_id for j, _ in delivered] == [job.job_id]
            assert client.uncertain() == []
        else:
            assert delivered == []  # nothing unverified reaches the caller
            assert [j.job_id for j in client.uncertain()] == [job.job_id]
        with pytest.raises(IoServiceError):
            client.submit(HashRequest(str(source)))
        assert sup.wait_until(lambda: client.returncode is not None, timeout=10)
        # The fake ignores its closed input: only the client's KILL ends it.
        assert client.returncode == (7 if mode == "exit" else -signal.SIGKILL)
    finally:
        client.close(timeout=5)


@pytest.mark.parametrize(
    ("mode", "rule"),
    [
        ("garbage+valid", "io.protocol"),
        ("swap-job+valid", "io.unknown_job"),
        ("swap-attempt+valid", "io.mismatch"),
        ("seq-gap+valid", "io.sequence"),
    ],
)
def test_nothing_after_a_bad_frame_reaches_the_caller(tmp_path: Path, mode: str, rule: str) -> None:
    """A bad frame and a well-formed commit acknowledgement arrive in one read: the client
    stops at the bad frame. The commit stays uncertain (replay decides), it is never
    delivered as verified output of a service declared untrustworthy (specification §8.1)."""
    client = IoClient.spawn(
        [sys.executable, str(FAKE), mode], cwd=str(tmp_path), env=sup.service_env()
    )
    try:
        job = client.submit(AppendRequest.of(sup.resume_payload()))
        delivered: list[tuple[Job, Result]] = []

        def failed() -> bool:
            delivered.extend(client.poll(0.05))
            return client.failure is not None

        assert sup.wait_until(failed, timeout=30)
        # Later polls deliver nothing either (the rest of the output is never trusted).
        for _ in range(5):
            delivered.extend(client.poll(0.05))
        assert client.failure is not None
        assert client.failure.rule == rule
        assert delivered == []
        assert [j.job_id for j in client.uncertain()] == [job.job_id]
        with pytest.raises(IoServiceError):
            client.submit(HashRequest("/nonexistent"))
        assert sup.wait_until(lambda: client.returncode is not None, timeout=10)
        assert client.returncode == -signal.SIGKILL
    finally:
        client.close(timeout=5)


def test_a_service_that_reported_a_fatal_failure_exits(setup: Setup) -> None:
    client = setup.spawn(fail_fsync=True)
    wait_hello(client)
    data = sup.proof_bytes(1000)
    result = client.wait(client.submit(setup.publish_request(data, "p.lrat"), attempt_id=A1), 30)
    assert isinstance(result.outcome, Failure)
    assert result.outcome.fatal
    assert result.outcome.rule == "io.fsync"
    assert client.failure is not None
    # The service exits by itself (status 1) without waiting for its input to close.
    assert sup.wait_until(lambda: client.returncode is not None, timeout=10)
    assert client.returncode == 1


def test_a_fatal_failure_reported_by_the_service_stops_new_work(tmp_path: Path) -> None:
    client = IoClient.spawn(
        [sys.executable, str(FAKE), "fatal"], cwd=str(tmp_path), env=sup.service_env()
    )
    try:
        source = sup.write_file(tmp_path / "work" / "p.lrat", b"proof")
        job = client.submit(HashRequest(str(source)))
        result = client.wait(job, timeout=30)
        assert isinstance(result.outcome, Failure)
        assert result.outcome.fatal
        assert client.failure is not None
        assert client.failure.rule == "io.service_failed"
        assert client.uncertain() == []  # answered: the job failed, nothing is uncertain
        with pytest.raises(IoServiceError):
            client.submit(HashRequest(str(source)))
    finally:
        client.close(timeout=5)


# -- the result tracker (pure) ---------------------------------------------------------------------


def test_the_tracker_assigns_increasing_job_ids() -> None:
    tracker = Tracker()
    first = tracker.job(HashRequest("/w/a"), None)
    second = tracker.job(HashRequest("/w/b"), A1)
    assert (first.job_id, second.job_id) == (1, 2)
    assert set(tracker.pending) == {1, 2}


def test_the_tracker_checks_append_sequence_numbers_from_the_hello() -> None:
    tracker = Tracker()
    tracker.hello(Hello(9, 4, "a" * 64))
    jobs = [tracker.job(AppendRequest.of(sup.resume_payload()), None) for _ in range(3)]
    assert tracker.accept(Result(1, Op.APPEND, None, AppendValue(5, "b" * 64))) == jobs[0]
    with pytest.raises(IoServiceError) as caught:
        tracker.accept(Result(2, Op.APPEND, None, AppendValue(7, "c" * 64)))
    assert caught.value.rule == "io.sequence"


def test_the_tracker_needs_the_hello_first() -> None:
    tracker = Tracker()
    job = tracker.job(HashRequest("/w/a"), None)
    with pytest.raises(IoServiceError) as caught:
        tracker.accept(Result(job.job_id, Op.HASH, None, HashValue(1, "a" * 64)))
    assert caught.value.rule == "io.protocol"
    tracker.hello(Hello(9, None, None))
    with pytest.raises(IoServiceError):
        tracker.hello(Hello(9, None, None))


def test_the_tracker_refuses_unknown_and_repeated_results() -> None:
    tracker = Tracker()
    tracker.hello(Hello(9, None, None))
    job = tracker.job(HashRequest("/w/a"), A1)
    result = Result(job.job_id, Op.HASH, A1, HashValue(1, "a" * 64))
    assert tracker.accept(result) == job
    with pytest.raises(IoServiceError) as caught:
        tracker.accept(result)
    assert caught.value.rule == "io.unknown_job"
    other = tracker.job(HashRequest("/w/b"), A1)
    with pytest.raises(IoServiceError) as mismatch:
        tracker.accept(Result(other.job_id, Op.HASH, A2, HashValue(1, "a" * 64)))
    assert mismatch.value.rule == "io.mismatch"


def test_a_lock_holding_service_keeps_the_run_lock(setup: Setup) -> None:
    """The service holds the coordinator's run lock descriptor (specification §7.3): while it lives,
    no second coordinator can take the results directory, even after its parent let go."""
    client = setup.spawn()
    wait_hello(client)
    setup.lock.release()
    from cubeproof.base.errors import ConfigurationError

    with pytest.raises(ConfigurationError):
        RunLock.acquire(setup.results / "run.lock")
    client.close(timeout=10)
    RunLock.acquire(setup.results / "run.lock").release()
