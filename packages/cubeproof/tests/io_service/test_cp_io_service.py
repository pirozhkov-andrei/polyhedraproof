"""The I/O service core in process (specification §7.1, §7.2, §8.1).

The service executes typed jobs: chunked hash/copy, publication, journal commits through the
journal writer (the sole writer, injected as a JournalPort), removal of disposable files and
reconciliation. It never builds a record: it commits the coordinator's payload unchanged, and
only after every artifact the payload references was durably published by this service for
the same attempt. Journal commits run between chunks of other work. Durability failures and
unexpected errors make the service fatal: it stops all further work (replay decides).
"""

from __future__ import annotations

import errno
import inspect
import json
import os
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import cp_io_support as sup
import pytest
from cp_io_support import Crash, FaultCalls

from cubeproof.base.errors import ContractError
from cubeproof.contracts.io import (
    AppendRequest,
    AppendValue,
    Area,
    Failure,
    HashRequest,
    HashValue,
    Job,
    Op,
    PublishRequest,
    PublishValue,
    ReconcileRequest,
    RemoveRequest,
    Result,
)
from cubeproof.contracts.values import Artifact
from cubeproof.evidence.journal import JournalWriter, SysCalls
from cubeproof.tools import io_service
from cubeproof.tools.io_service import Scheduler, Service, ServiceConfig

A1 = sup.new_attempt_id(1)
A2 = sup.new_attempt_id(2)
CHUNK = 4096


class Env:
    """A results directory with a journal (header + resume retain) and a work directory."""

    def __init__(self, root: Path, *, calls: FaultCalls | None = None) -> None:
        self.root = root
        self.results = root / "results"
        self.work = root / "work"
        self.work.mkdir(parents=True)
        self.journal, self.lock = sup.create_journal(self.results)
        self.port = sup.open_port(self.journal, self.lock)
        self.calls = calls if calls is not None else FaultCalls()
        self.service = self.new_service()
        self.next_id = 1
        result = self.run(None, AppendRequest.of(sup.resume_payload()))
        assert result.ok, result

    def new_service(self) -> Service:
        config = ServiceConfig(
            results_root=str(self.results), work_root=str(self.work), chunk_bytes=CHUNK
        )
        return Service(config, self.port, calls=self.calls)

    def job(self, attempt_id: str | None, request: Any) -> Job:
        job = Job(self.next_id, attempt_id, request)
        self.next_id += 1
        return job

    def run(self, attempt_id: str | None, request: Any) -> Result:
        job = self.job(attempt_id, request)
        result = self.service.run(job)
        assert result.problem(job) is None
        return result

    def proof(self, data: bytes, name: str = "n-a.lrat") -> Path:
        return sup.write_file(self.work / name, data)

    def publish(self, attempt_id: str, data: bytes, area: Area = Area.PROOFS) -> Result:
        source = self.proof(data, f"{attempt_id}.lrat")
        request = PublishRequest(str(source), area, sup.NODE_ID, sup.sha(data), len(data))
        return self.run(attempt_id, request)

    def close(self) -> None:
        self.port.writer.close()
        self.lock.release()


@pytest.fixture
def env(tmp_path: Path) -> Iterator[Env]:
    environment = Env(tmp_path)
    yield environment
    environment.close()


def forged(job_id: int, attempt_id: str | None, request: Any) -> Job:
    """A job that bypasses the contract's own checks (to test the service's checks)."""
    job = object.__new__(Job)
    object.__setattr__(job, "job_id", job_id)
    object.__setattr__(job, "attempt_id", attempt_id)
    object.__setattr__(job, "request", request)
    return job


def failure(result: Result) -> Failure:
    assert isinstance(result.outcome, Failure), result
    return result.outcome


# -- basics ----------------------------------------------------------------------------------------


def test_hello_reports_the_committed_journal_position(env: Env) -> None:
    records = sup.journal_records(env.journal)
    hello = env.service.hello(4321)
    assert (hello.pid, hello.seq, hello.head) == (4321, len(records) - 1, records[-1]["self"])
    no_journal = Service(ServiceConfig(str(env.results), str(env.work)), None)
    assert (no_journal.hello(1).seq, no_journal.hello(1).head) == (None, None)


def test_hash_measures_and_does_not_judge(env: Env) -> None:
    data = sup.proof_bytes(3 * CHUNK + 1)
    path = env.proof(data)
    result = env.run(A1, HashRequest(str(path)))
    assert result.outcome == HashValue(len(data), sup.sha(data))
    missing = env.run(A1, HashRequest(str(env.work / "missing")))
    assert failure(missing).rule == "io.source"
    assert not failure(missing).fatal
    assert env.service.fatal is None


def test_configuration_is_checked() -> None:
    with pytest.raises(ContractError):
        ServiceConfig("relative", "/w")
    with pytest.raises(ContractError):
        ServiceConfig("/r", "/w", chunk_bytes=8 * 1024 * 1024 + 1)
    with pytest.raises(ContractError):
        ServiceConfig("/r", "/w", chunk_bytes=0)
    # The work root may not be the results root or lie inside it (removal rules) ...
    for work in ["/r", "/r/", "/r/w", "/r/proofs/tmp"]:
        with pytest.raises(ContractError):
            ServiceConfig("/r", work)
    # ... but a sibling that merely shares the name prefix is another directory.
    assert ServiceConfig("/r", "/r2").work_root == "/r2"
    assert ServiceConfig("/data/w2", "/data/w").results_root == "/data/w2"


# -- publish before commit -------------------------------------------------------------------------


def test_publish_then_commit_then_cleanup(env: Env) -> None:
    data = sup.proof_bytes(2 * CHUNK + 9)
    published = env.publish(A1, data)
    assert isinstance(published.outcome, PublishValue)
    artifact = published.outcome.artifact
    payload = sup.attempt_payload(A1, data)
    committed = env.run(A1, AppendRequest.of(payload))
    records = sup.journal_records(env.journal)
    assert committed.outcome == AppendValue(len(records) - 1, records[-1]["self"])
    # The service commits the coordinator's payload unchanged (it builds no record).
    assert sup.payload_of(records[-1]) == payload
    assert sup.committed_artifacts(env.journal) == [artifact]
    source = env.work / f"{A1}.lrat"
    removed = env.run(A1, RemoveRequest((str(source),)))
    assert removed.ok
    assert not source.exists()
    assert (env.results / artifact.path).read_bytes() == data


def test_a_commit_referencing_an_unpublished_artifact_is_refused_before_any_byte(env: Env) -> None:
    data = sup.proof_bytes(100)
    before = env.journal.read_bytes()
    result = env.run(A1, AppendRequest.of(sup.attempt_payload(A1, data)))
    assert failure(result).rule == "io.unpublished"
    assert not failure(result).fatal
    assert env.journal.read_bytes() == before
    assert env.service.fatal is None


def test_an_artifact_published_for_another_attempt_does_not_count(env: Env) -> None:
    data = sup.proof_bytes(100)
    assert env.publish(A2, data).ok
    before = env.journal.read_bytes()
    result = env.run(A1, AppendRequest.of(sup.attempt_payload(A1, data)))
    assert failure(result).rule == "io.unpublished"
    assert env.journal.read_bytes() == before


def test_a_commit_naming_other_bytes_than_published_is_refused(env: Env) -> None:
    data = sup.proof_bytes(100)
    assert env.publish(A1, data).ok
    other = sup.proof_bytes(100, seed=5)
    wrong = Artifact(sup.artifact_for(data).path, sup.sha(other), 100)
    before = env.journal.read_bytes()
    result = env.run(A1, AppendRequest.of(sup.attempt_payload(A1, data, retained=wrong)))
    assert failure(result).rule == "io.unpublished"
    assert env.journal.read_bytes() == before


def test_the_service_checks_the_attempt_binding_itself(env: Env) -> None:
    data = sup.proof_bytes(100)
    assert env.publish(A1, data).ok
    before = env.journal.read_bytes()
    for job in [
        forged(env.next_id, A2, AppendRequest.of(sup.attempt_payload(A1, data))),
        forged(env.next_id + 1, None, AppendRequest.of(sup.attempt_payload(A1, data))),
        forged(env.next_id + 2, A1, AppendRequest.of(sup.resume_payload())),
    ]:
        result = env.service.run(job)
        assert failure(result).rule == "io.attempt_mismatch"
    assert env.journal.read_bytes() == before


def test_an_invalid_record_is_refused_without_stopping_the_service(env: Env) -> None:
    data = sup.proof_bytes(100)
    assert env.publish(A1, data).ok
    payload = sup.attempt_payload(A1, data)
    payload["policy_sha256"] = "0" * 64
    before = env.journal.read_bytes()
    result = env.run(A1, AppendRequest.of(payload))
    assert failure(result).rule == "attempt.policy_sha256"
    assert not failure(result).fatal
    assert env.journal.read_bytes() == before
    # The publication is still pending: the corrected record commits.
    assert env.run(A1, AppendRequest.of(sup.attempt_payload(A1, data))).ok


def test_a_retained_artifact_must_be_published_in_the_proofs_area(env: Env) -> None:
    data = sup.proof_bytes(100)
    published = env.publish(A1, data, Area.QUARANTINE)
    assert isinstance(published.outcome, PublishValue)
    payload = sup.attempt_payload(A1, data, retained=published.outcome.artifact)
    before = env.journal.read_bytes()
    result = env.run(A1, AppendRequest.of(payload))
    assert failure(result).rule == "io.unpublished"
    assert env.journal.read_bytes() == before


def test_a_quarantined_artifact_needs_its_publication_too(env: Env) -> None:
    data = sup.proof_bytes(100)
    payload = sup.attempt_payload(A1, None)
    payload["quarantined"] = sup.artifact_for(data, Area.QUARANTINE).to_json()
    result = env.run(A1, AppendRequest.of(payload))
    assert failure(result).rule == "io.unpublished"


# -- failures that stop the service ----------------------------------------------------------------


class FailingWrites(SysCalls):
    def write(self, fd: int, data: memoryview) -> int:
        raise OSError(errno.EIO, "injected")


def test_a_journal_write_failure_is_fatal_and_stops_all_work(tmp_path: Path) -> None:
    environment = Env(tmp_path)
    environment.port.writer.close()
    writer = JournalWriter.open(
        environment.journal,
        validator=sup.validator(),
        run_lock=environment.lock,
        calls=FailingWrites(),
    )
    environment.port = sup.WriterPort(writer)
    environment.service = environment.new_service()
    try:
        result = environment.run(None, AppendRequest.of(sup.resume_payload()))
        assert failure(result).fatal
        assert failure(result).rule == "journal.write"
        assert environment.service.fatal is not None
        data = sup.proof_bytes(10)
        later = environment.run(A1, HashRequest(str(environment.proof(data))))
        assert failure(later).rule == "io.service_failed"
        assert failure(later).fatal
    finally:
        environment.close()


class GarbledPort:
    """A journal that commits but answers with an unusable head."""

    failed = False

    def __init__(self) -> None:
        self.appended: list[dict[str, Any]] = []

    def position(self) -> tuple[int, str] | None:
        return 0, "a" * 64

    def append(self, payload: Any) -> tuple[int, str]:
        self.appended.append(dict(payload))
        return 1, "not a hash"


def test_an_unusable_answer_after_a_commit_is_fatal_not_a_refusal(tmp_path: Path) -> None:
    """A non-fatal append failure means nothing was written; after the writer returned,
    the record may be durable, so any problem is fatal (replay decides)."""
    port = GarbledPort()
    service = Service(ServiceConfig(str(tmp_path / "r"), str(tmp_path / "w")), port)
    result = service.run(Job(1, None, AppendRequest.of(sup.resume_payload())))
    assert len(port.appended) == 1
    assert failure(result).rule == "io.commit_uncertain"
    assert failure(result).fatal
    assert service.fatal is not None


def test_a_durability_failure_in_publication_is_fatal(tmp_path: Path) -> None:
    calls = FaultCalls(faults={"fsync": sup.fail_with(errno.EIO)})
    environment = Env(tmp_path, calls=calls)
    try:
        result = environment.publish(A1, sup.proof_bytes(100))
        assert failure(result).rule == "io.fsync"
        assert failure(result).fatal
        assert environment.service.fatal is not None
    finally:
        environment.close()


def test_an_unexpected_error_is_fatal(tmp_path: Path) -> None:
    def boom(number: int, *args: object) -> None:
        raise RuntimeError("bug")

    environment = Env(tmp_path, calls=FaultCalls(faults={"pread": boom}))
    try:
        result = environment.run(A1, HashRequest(str(environment.proof(b"abc"))))
        assert failure(result).rule == "io.internal"
        assert failure(result).fatal
    finally:
        environment.close()


def test_a_full_disk_is_not_fatal(tmp_path: Path) -> None:
    environment = Env(tmp_path, calls=FaultCalls(faults={"write": sup.fail_with(errno.ENOSPC)}))
    try:
        result = environment.publish(A1, sup.proof_bytes(3 * CHUNK))
        assert failure(result).rule == "io.no_space"
        assert failure(result).kind == "resource"
        assert not failure(result).fatal
        assert environment.service.fatal is None
        assert sup.tree(environment.results / "proofs") == {}
    finally:
        environment.close()


# -- removal and reconciliation --------------------------------------------------------------------


def test_removal_is_limited_to_disposable_files(env: Env) -> None:
    data = sup.proof_bytes(100)
    published = env.publish(A1, data)
    assert isinstance(published.outcome, PublishValue)
    final = env.results / published.outcome.artifact.path
    staging = sup.write_file(env.results / "proofs" / "tmp" / f"{A2}.lrat", b"x", mode=0o644)
    outside = sup.write_file(env.root / "elsewhere" / "f", b"x")
    (env.work / "sub").symlink_to(env.results / "proofs")
    for path in [final, outside, env.journal, env.work / "sub" / final.name, env.results]:
        result = env.run(None, RemoveRequest((str(path),)))
        assert failure(result).rule == "io.protected", path
    assert final.exists()
    assert outside.exists()
    result = env.run(None, RemoveRequest((str(staging), str(env.work / "missing"))))
    assert result.ok
    assert not staging.exists()
    assert result.outcome.removed == (str(staging),)  # type: ignore[union-attr]


def test_removal_does_not_reach_a_sibling_sharing_a_root_name_prefix(env: Env) -> None:
    """``<work>2`` and ``<results>2`` are other directories (e.g. another worker's results),
    not "below" the work or results root: their files are protected (specification §7.2)."""
    data = sup.proof_bytes(100)
    name = sup.artifact_for(data).path.split("/")[-1]
    work_sibling = Path(f"{env.work}2")
    results_sibling = Path(f"{env.results}2")
    victims = [
        sup.write_file(work_sibling / "proofs" / name, data),
        sup.write_file(work_sibling / "f", b"x"),
        sup.write_file(results_sibling / "proofs" / "tmp" / f"{A1}.lrat", b"x"),
        # Same prefix with the separator replaced: "<results>Xproofs/tmp/<name>".
        sup.write_file(env.root / f"{env.results.name}Xproofs" / "tmp" / f"{A1}.lrat", b"x"),
    ]
    for path in victims:
        result = env.run(None, RemoveRequest((str(path),)))
        assert failure(result).rule == "io.protected", path
        assert not failure(result).fatal
    assert all(path.exists() for path in victims)
    assert (work_sibling / "proofs" / name).read_bytes() == data
    assert env.service.fatal is None


def test_reconciliation_keeps_committed_and_pending_publications(env: Env) -> None:
    committed_data = sup.proof_bytes(100, seed=1)
    pending_data = sup.proof_bytes(100, seed=2)
    assert env.publish(A1, committed_data).ok
    assert env.run(A1, AppendRequest.of(sup.attempt_payload(A1, committed_data))).ok
    pending = env.publish(A2, pending_data)
    assert isinstance(pending.outcome, PublishValue)
    orphan = sup.write_file(env.results / sup.artifact_for(b"orphan").path, b"orphan")
    committed = sup.committed_artifacts(env.journal)
    result = env.run(None, ReconcileRequest(tuple(committed)))
    assert result.ok
    assert result.outcome.removed == (sup.artifact_for(b"orphan").path,)  # type: ignore[union-attr]
    assert not orphan.exists()
    assert (env.results / pending.outcome.artifact.path).exists()
    # The pending publication still commits afterwards.
    assert env.run(A2, AppendRequest.of(sup.attempt_payload(A2, pending_data))).ok


def test_reconciliation_with_a_missing_reference_is_an_integrity_failure(env: Env) -> None:
    data = sup.proof_bytes(100)
    assert env.publish(A1, data).ok
    assert env.run(A1, AppendRequest.of(sup.attempt_payload(A1, data))).ok
    committed = sup.committed_artifacts(env.journal)
    path = env.results / committed[0].path
    path.unlink()
    result = env.run(None, ReconcileRequest(tuple(committed)))
    assert failure(result).rule == "artifact.missing"
    assert failure(result).kind == "integrity"


# -- scheduling: commits between chunks ------------------------------------------------------------


def test_journal_commits_run_between_chunks_of_a_long_copy(env: Env) -> None:
    data = sup.proof_bytes(40 * CHUNK)
    source = env.proof(data)
    scheduler = Scheduler(env.service)
    publish = env.job(
        A1, PublishRequest(str(source), Area.PROOFS, sup.NODE_ID, sup.sha(data), len(data))
    )
    scheduler.accept(publish)
    assert scheduler.step() is None  # first chunk of the copy
    commit = env.job(None, AppendRequest.of(sup.resume_payload()))
    scheduler.accept(commit)
    done: list[Result] = []
    while scheduler.busy:
        result = scheduler.step()
        if result is not None:
            done.append(result)
    assert [r.job_id for r in done] == [commit.job_id, publish.job_id]
    assert all(r.ok for r in done)


def test_commits_keep_their_order_and_other_jobs_are_fifo(env: Env) -> None:
    scheduler = Scheduler(env.service)
    path = str(env.proof(b"abc"))
    jobs = [
        env.job(None, HashRequest(path)),
        env.job(None, AppendRequest.of(sup.resume_payload())),
        env.job(None, HashRequest(path)),
        env.job(None, AppendRequest.of(sup.resume_payload())),
    ]
    for job in jobs:
        scheduler.accept(job)
    done: list[int] = []
    while scheduler.busy:
        result = scheduler.step()
        if result is not None:
            done.append(result.job_id)
    ids = [j.job_id for j in jobs]
    assert done == [ids[1], ids[3], ids[0], ids[2]]
    seqs = [r["seq"] for r in sup.journal_records(env.journal)]
    assert seqs == list(range(len(seqs)))


def test_job_ids_must_increase(env: Env) -> None:
    scheduler = Scheduler(env.service)
    path = str(env.proof(b"abc"))
    scheduler.accept(Job(10, None, HashRequest(path)))
    for job_id in (10, 9):
        with pytest.raises(ContractError) as caught:
            scheduler.accept(Job(job_id, None, HashRequest(path)))
        assert caught.value.rule == "io.job_order"


def test_the_service_cannot_construct_a_record() -> None:
    source = inspect.getsource(io_service)
    for word in ("VERIFIED_UNSAT", "build_record", '"outcome"', "cubeproof.evidence"):
        assert word not in source


# -- crash before/after each durable effect of publish -> commit -> cleanup ------------------------


def flow(environment: Env, data: bytes, *, crash_journal: str | None) -> None:
    """Publish, commit, remove the work file; a Crash may stop it anywhere."""

    def crash() -> None:
        raise Crash("journal")

    if crash_journal == "before":
        environment.port.before = crash
    elif crash_journal == "after":
        environment.port.after = crash
    published = environment.publish(A1, data)
    if not published.ok:
        raise AssertionError(published)
    committed = environment.run(A1, AppendRequest.of(sup.attempt_payload(A1, data)))
    assert committed.ok
    environment.run(A1, RemoveRequest((str(environment.work / f"{A1}.lrat"),)))


def recover_and_check(environment: Env, data: bytes) -> None:
    """Restart: journal recovery, replay of committed references, reconciliation, invariants."""
    environment.port.writer.close()
    port = sup.open_port(environment.journal, environment.lock)
    try:
        committed = sup.committed_artifacts(environment.journal)
        config = ServiceConfig(str(environment.results), str(environment.work), chunk_bytes=CHUNK)
        service = Service(config, port)
        first = service.run(Job(1, None, ReconcileRequest(tuple(committed))))
        assert first.ok, first
        files = sup.tree(environment.results)
        names = {p for p in files if p.startswith(("proofs/", "quarantine/"))}
        assert names == {a.path for a in committed}  # no orphan, no staging file
        for artifact in committed:
            assert sup.sha(files[artifact.path]) == artifact.sha256  # nothing referenced lost
        if not committed:
            assert (environment.work / f"{A1}.lrat").read_bytes() == data  # source kept
        second = service.run(Job(2, None, ReconcileRequest(tuple(committed))))
        assert second.ok
        assert second.outcome.removed == ()  # type: ignore[union-attr]
        assert sup.tree(environment.results) == files
    finally:
        port.writer.close()


def count_mutations(tmp_path: Path, data: bytes) -> int:
    environment = Env(tmp_path / "count")
    try:
        environment.calls.mutations = 0
        flow(environment, data, crash_journal=None)
        return environment.calls.mutations
    finally:
        environment.close()


@pytest.mark.parametrize("crash_journal", ["before", "after"])
def test_a_crash_around_the_journal_commit(tmp_path: Path, crash_journal: str) -> None:
    data = sup.proof_bytes(2 * CHUNK + 1)
    environment = Env(tmp_path)
    try:
        with pytest.raises(Crash):
            flow(environment, data, crash_journal=crash_journal)
        records = sup.journal_records(environment.journal)
        assert (records[-1]["type"] == "attempt") is (crash_journal == "after")
        recover_and_check(environment, data)
    finally:
        environment.lock.release()


def test_a_crash_at_every_file_system_effect_of_the_flow(tmp_path: Path) -> None:
    data = sup.proof_bytes(2 * CHUNK + 1)
    points = count_mutations(tmp_path, data)
    assert points >= 10
    seen_committed = seen_uncommitted = 0
    for point in range(1, points + 1):
        environment = Env(tmp_path / f"p{point}")
        try:
            environment.calls.mutations = 0
            environment.calls.crash_at = point
            with pytest.raises(Crash):
                flow(environment, data, crash_journal=None)
            committed = bool(sup.committed_artifacts(environment.journal))
            seen_committed += committed
            seen_uncommitted += not committed
            recover_and_check(environment, data)
        finally:
            environment.lock.release()
    assert seen_committed and seen_uncommitted


def test_records_after_recovery_still_bind_to_their_files(env: Env) -> None:
    data = sup.proof_bytes(100)
    assert env.publish(A1, data).ok
    assert env.run(A1, AppendRequest.of(sup.attempt_payload(A1, data))).ok
    record = sup.journal_records(env.journal)[-1]
    artifact = Artifact.from_json(record["retained"])
    assert (env.results / artifact.path).read_bytes() == data
    assert json.loads(json.dumps(record))["proof_sha256"] == artifact.sha256
    assert os.stat(env.results / artifact.path).st_size == record["proof_bytes"]
    assert Op.APPEND.value == "append"
