"""Crash boundaries of the retained/quarantined publication protocol (specification §7.2, §7.5).

The protocol of one attempt through the I/O service: publish the checked proof (copy to
``<area>/tmp/<attempt_id>.lrat``, fsync, no-replace name, directory fsync), commit the record
that references it, remove the disposable work proof. A process death is simulated before
every mutating or durable file-system call and immediately before/after the journal append.
After each death the restart recovery (``retain.recover`` on the replayed records) must leave:

- a committed record: its reference resolves to the checked hash (nothing else in the areas);
- no committed record: no published or staging file (orphans removed), the node pending;

the work proof is never touched by recovery (the coordinator clears work), a second recovery
changes nothing, and a fresh attempt afterwards publishes and commits normally.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pytest
from cp_retain_support import (
    CHUNK,
    NODE_ID,
    Crash,
    Env,
    FaultCalls,
    artifact_for,
    attempt_id,
    attempts_of,
    proof_bytes,
    rejected_payload,
    retained_payload,
    sha,
    tree,
)

from cubeproof.contracts.io import Area, PublishValue
from cubeproof.leaf import retain
from cubeproof.leaf.binding import FileHash

A1, A2 = attempt_id(1), attempt_id(2)
DATA = proof_bytes(3 * CHUNK + 17)


def payload(area: Area, attempt: str, data: bytes) -> dict[str, Any]:
    if area is Area.PROOFS:
        return retained_payload(attempt, data)
    return rejected_payload(attempt, data)


def protocol(env: Env, area: Area, attempt: str, data: bytes) -> FileHash:
    """Publish, commit, clean up (one attempt); returns the work proof."""
    sealed = env.source(attempt, data)
    request = retain.publication_request(area, NODE_ID, sealed)
    result = env.publish(attempt, request)
    assert isinstance(result.outcome, PublishValue), result
    committed = env.append(attempt, payload(area, attempt, data))
    assert committed.ok, committed
    removed = env.remove(attempt, sealed.path)
    assert removed.ok, removed
    return sealed


def run_until(tmp_path: Path, area: Area, crash_at: int | None) -> tuple[Env, FaultCalls, bool]:
    calls = FaultCalls(crash_at=crash_at)
    env = Env(
        tmp_path,
        calls=calls,
        before_append=lambda: calls._mutation(("append",)),
        after_append=lambda: calls._mutation(("acknowledged",)),
    )
    crashed = False
    try:
        protocol(env, area, A1, DATA)
    except Crash:
        crashed = True
    env.port.writer.close()
    return env, calls, crashed


def points(tmp_path: Path, area: Area) -> int:
    env, calls, crashed = run_until(tmp_path / "count", area, None)
    env.lock.release()
    assert not crashed
    return calls.mutations


@pytest.mark.parametrize("area", [Area.PROOFS, Area.QUARANTINE])
def test_every_crash_point_recovers_to_committed_evidence_or_nothing(
    tmp_path: Path, area: Area
) -> None:
    total = points(tmp_path, area)
    assert total >= 10  # mkdirs, staging open/writes/fsync, link, dir fsync, append, cleanup
    outcomes: dict[str, int] = {}
    for crash_at in range(1, total + 1):
        root = tmp_path / f"crash-{crash_at}"
        env, calls, crashed = run_until(root, area, crash_at)
        assert crashed, f"no crash at point {crash_at}"
        where = calls.log[-1]
        records = attempts_of(env.journal)
        committed = [r for r in records if r.attempt_id == A1]
        artifact = artifact_for(DATA, area)
        report = retain.recover(str(env.results), records, chunk_bytes=CHUNK)
        files = env.area_files()
        if committed:
            outcomes["committed"] = outcomes.get("committed", 0) + 1
            reference = committed[0].retained if area is Area.PROOFS else committed[0].quarantined
            assert reference == artifact, where
            assert files == {artifact.path: DATA}, where
            assert sha((env.results / artifact.path).read_bytes()) == sha(DATA)
        else:
            outcomes["pending"] = outcomes.get("pending", 0) + 1
            assert files == {}, where  # orphan and staging removed; the node stays pending
        # recovery never touches the work proof (evidence until the commit, then disposable)
        work_proof = env.work / f"{NODE_ID}-{A1}.lrat"
        assert work_proof.read_bytes() == DATA, where
        # idempotent
        again = retain.recover(str(env.results), records, chunk_bytes=CHUNK)
        assert again.removed == () and env.area_files() == files, where
        assert (again.retained, again.quarantined) == (report.retained, report.quarantined)
        env.lock.release()
    assert outcomes.get("committed", 0) >= 2  # crash after the append, before the cleanup
    assert outcomes.get("pending", 0) >= 8


@pytest.mark.parametrize("area", [Area.PROOFS, Area.QUARANTINE])
def test_after_a_crash_before_the_commit_a_new_attempt_publishes_normally(
    tmp_path: Path, area: Area
) -> None:
    total = points(tmp_path, area)
    for crash_at in range(1, total + 1):
        root = tmp_path / f"retry-{crash_at}"
        env, _, _ = run_until(root, area, crash_at)
        records = attempts_of(env.journal)
        retain.recover(str(env.results), records, chunk_bytes=CHUNK)
        env.lock.release()
        if any(r.attempt_id == A1 for r in records):
            continue
        # restart: a new service session, the node is solved again by a new attempt
        (env.work / f"{NODE_ID}-{A1}.lrat").unlink()  # the coordinator clears work
        restarted = Env(root, restart=True)
        try:
            protocol(restarted, area, A2, DATA)
            records = restarted.attempts()
            assert [r.attempt_id for r in records] == [A2]
            report = retain.recover(str(restarted.results), records, chunk_bytes=CHUNK)
            assert (report.retained + report.quarantined, report.removed) == (1, ())
        finally:
            restarted.close()


def test_a_committed_retained_proof_survives_restart_and_resolves(tmp_path: Path) -> None:
    env = Env(tmp_path)
    datas = [proof_bytes(CHUNK * k + k, k) for k in (1, 2, 3)]
    try:
        for index, data in enumerate(datas):
            protocol(env, Area.PROOFS, attempt_id(10 + index), data)
        protocol(env, Area.QUARANTINE, attempt_id(20), proof_bytes(CHUNK, 99))
    finally:
        env.close()
    records = attempts_of(env.journal)
    report = retain.recover(str(env.results), records, chunk_bytes=CHUNK)
    assert (report.retained, report.quarantined, report.removed) == (3, 1, ())
    for record in records:
        reference = record.retained or record.quarantined
        assert reference is not None
        assert sha((env.results / reference.path).read_bytes()) == record.proof_sha256
        assert reference.bytes == record.proof_bytes
    assert tree(env.work) == {}  # cleanup ran after each commit


def cross_device_dir(tmp_path: Path) -> Path | None:
    for candidate in (Path("/dev/shm"), Path("/run/user") / str(os.getuid())):
        usable = candidate.is_dir() and os.access(candidate, os.W_OK)
        if usable and os.stat(candidate).st_dev != os.stat(tmp_path).st_dev:
            return Path(os.path.realpath(candidate))
    return None


def test_a_cross_device_publication_commits_and_recovers(tmp_path: Path) -> None:
    other = cross_device_dir(tmp_path)
    if other is None:
        pytest.skip("no second writable file system (the image tier mounts one)")
    work = other / f"cp-retain-{os.getpid()}-{tmp_path.name}"
    work.mkdir()
    env = Env(tmp_path, work=work)
    try:
        sealed = protocol(env, Area.PROOFS, A1, DATA)
        assert os.stat(work).st_dev != os.stat(env.results).st_dev
        assert not Path(sealed.path).exists()
        records = env.attempts()
        report = retain.recover(str(env.results), records, chunk_bytes=CHUNK)
        assert (report.retained, report.removed) == (1, ())
        reference = records[-1].retained
        assert reference is not None
        assert (env.results / reference.path).read_bytes() == DATA
    finally:
        env.close()
        for path in work.iterdir():
            path.unlink()
        work.rmdir()
