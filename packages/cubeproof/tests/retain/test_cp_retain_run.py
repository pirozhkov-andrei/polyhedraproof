"""Retain mode at the coordinator level: whole ``run`` sessions (specification §6.1, §7.2, §7.3,
§7.5, §12.2).

The real coordinator runs with its real I/O service process and the lifecycle fake tools
(``tests/lifecycle/cp_life_tools.py``). What is checked at this level:

- every VERIFIED_UNSAT of a retain run references its published proof, which resolves to the
  checked hash; nothing else is left below ``proofs/`` (no orphan, no staging copy);
- a crash at every boundary of the retained commit (before the publication, after it and
  before the append, with the append in flight, after the commit and before the cleanup, after
  the cleanup) is recovered by the next run alone: committed evidence is kept, an unreferenced
  copy is removed, no node is verified twice, and the end state equals an uninterrupted run;
  a further run is idempotent;
- retain-full stops new work with its diagnostic and exit code and commits no VERIFIED_UNSAT
  without its reference; the node is still pending for the next run;
- the startup recovery binds every committed record to its references (``leaf.retain``), not
  only the files: a retain-mode VERIFIED_UNSAT without a reference, or one that names another
  node's file, stops the run with exit 4 before anything is removed or appended;
- a rejected proof is quarantined in a run, and a quota miss records null plus the reason;
  the quota also counts the quarantine files committed by earlier sessions.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import signal
import sys
import tempfile
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

import pytest

_LIFECYCLE = Path(__file__).resolve().parents[1] / "lifecycle"
if str(_LIFECYCLE) not in sys.path:
    sys.path.insert(0, str(_LIFECYCLE))

import cp_life_tools as t  # noqa: E402

from cubeproof.base.errors import IntegrityError, ResourceError  # noqa: E402
from cubeproof.base.resources import StorageGroups  # noqa: E402
from cubeproof.base.settings import DEFAULT_LIMITS  # noqa: E402
from cubeproof.cnf.campaign import load_campaign  # noqa: E402
from cubeproof.contracts.enums import ProofMode  # noqa: E402
from cubeproof.coordinator.config import exit_code_of  # noqa: E402
from cubeproof.coordinator.replay import validator_of  # noqa: E402
from cubeproof.coordinator.resources import DISK_RESERVE  # noqa: E402
from cubeproof.evidence.journal import JournalWriter, RunLock  # noqa: E402
from cubeproof.evidence.schema import PAYLOADS  # noqa: E402

DEEP = t.unsat(8, core=5)
SHALLOW = t.unsat(5)
TOOLS = {"max_free": 3, "sleep": 0.02}
JOBS = 2
RETAIN = t.split_policy(proof_mode=ProofMode.RETAIN)
GIB = 1 << 30


def retain_world(root: Path, formula: bytes = DEEP, **policy: Any) -> t.World:
    return t.make_world(root, {"f": formula}, solver=TOOLS, policy=replace(RETAIN, **policy))


def area_files(w: t.World, area: str = "proofs") -> dict[str, bytes]:
    """Every file below ``results/<area>``, staging included (relative paths)."""
    folder = w.results / area
    if not folder.exists():
        return {}
    return {
        str(p.relative_to(w.results)): p.read_bytes()
        for p in sorted(folder.rglob("*"))
        if p.is_file()
    }


def assert_references_resolve(w: t.World) -> None:
    """Post-restart: every retained reference resolves to its checked hash, nothing else is
    below ``proofs/``, and no retain-mode VERIFIED_UNSAT lacks its reference."""
    verified = [a for a in w.attempts() if a["outcome"] == "VERIFIED_UNSAT"]
    assert verified
    files = area_files(w)
    for record in verified:
        assert record["proof_mode"] == "retain"
        reference = record["retained"]
        assert reference is not None, record["attempt_id"]
        assert reference["path"] == f"proofs/{record['node_id']}-{record['proof_sha256']}.lrat"
        data = files[reference["path"]]
        assert hashlib.sha256(data).hexdigest() == record["proof_sha256"] == reference["sha256"]
        assert len(data) == record["proof_bytes"] == reference["bytes"]
    assert set(files) == {a["retained"]["path"] for a in verified}


def check_invariants(w: t.World, before: bytes, expected: dict[str, Any]) -> None:
    assert w.summary() == expected
    records = t.journal_records(w.results)
    ids = [r["attempt_id"] for r in records if r["type"] == "attempt"]
    assert len(ids) == len(set(ids)), "an attempt ID was committed twice"
    verified = [r["node_id"] for r in records if r.get("outcome") == "VERIFIED_UNSAT"]
    assert len(verified) == len(set(verified)), "a node was verified by two attempts"
    assert w.journal().read_bytes().startswith(before)
    assert_references_resolve(w)
    assert w.work_files() == []
    t.wait_clean(w.results, w.work)


def complete_journal_bytes(w: t.World) -> bytes:
    if not w.journal().exists():
        return b""
    data = w.journal().read_bytes()
    return data[: data.rfind(b"\n") + 1]


def crash_once(w: t.World, point: tuple[str, int]) -> bool:
    child = t.spawn_runner(w.spec(jobs=JOBS), crash=point)
    code, out, err = t.messages(child)
    if code == -signal.SIGKILL:
        t.wait_clean(w.results, w.work)
        return True
    assert code == 0, (code, out, err)
    return False


def finish(w: t.World) -> str:
    child = t.spawn_runner(w.spec(jobs=JOBS))
    code, out, err = t.messages(child)
    assert code == 0, (code, out, err)
    return out


@pytest.fixture(scope="module")
def reference(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    """The uninterrupted retain run: the certifier's view."""
    w = retain_world(tmp_path_factory.mktemp("reference"))
    result = w.run(jobs=JOBS)
    assert result.exit_code == 0
    assert_references_resolve(w)
    return w.summary()


def test_a_retain_run_publishes_every_verified_proof_before_its_record(
    tmp_path: Path, reference: dict[str, Any]
) -> None:
    w = retain_world(tmp_path)
    names: list[str] = []
    result = w.run(jobs=JOBS, hooks=names.append)
    assert result.exit_code == 0 and result.session["outcome:VERIFIED_UNSAT"] == 16
    assert w.summary() == reference and reference["verdict"] == "PROVED"
    assert_references_resolve(w)
    assert w.work_files() == []
    # one publication per verified attempt, each before that attempt's commit
    assert names.count("attempt.published") == 16
    assert names.count("attempt.publish") >= 16
    t.wait_clean(w.results, w.work)


#: The boundaries of the retained commit (specification §7.2 steps 1-5, §7.5 rows 1-3).
CRASHES = [
    ("attempt.publish", 1),  # checked, reserved, nothing published
    ("attempt.published", 1),  # durable copy, no record: an orphan
    ("attempt.published", 4),
    ("attempt.commit", 2),  # the append in flight: committed or not
    ("attempt.committed", 1),  # committed record before its cleanup
    ("attempt.committed", 5),
    ("attempt.cleanup", 1),  # the removal of the work files in flight
    ("attempt.done", 3),  # committed and cleaned
]


@pytest.mark.parametrize("point", CRASHES, ids=lambda p: f"{p[0]}#{p[1]}")
def test_a_crash_at_every_boundary_of_the_retained_commit_is_recovered(
    tmp_path: Path, reference: dict[str, Any], point: tuple[str, int]
) -> None:
    w = retain_world(tmp_path)
    assert crash_once(w, point), f"{point} was not reached"
    committed = {a["retained"]["path"] for a in w.attempts() if a["retained"] is not None}
    left = set(area_files(w))
    if point[0] == "attempt.published":
        assert left - committed, "the premise: a durable copy without its record"
    if point[0] == "attempt.committed":
        assert w.work_files(), "the premise: a committed record before its cleanup"
        assert w.attempts(), "the premise: the record is durable"
    assert committed <= left  # nothing committed was lost by the crash
    if w.journal().exists():
        t.summary(w.campaign, w.results)  # the journal certifies after the crash
    before = complete_journal_bytes(w)
    finish(w)
    check_invariants(w, before, reference)
    # recovery is idempotent: a further run finds nothing to do and changes nothing
    files = area_files(w)
    journal = w.journal().read_bytes()
    finish(w)
    assert area_files(w) == files
    added = t.journal_records(w.results)[len(journal.splitlines()) :]
    assert [r["type"] for r in added] == ["resume"]


def cross_device_dir(root: Path) -> Path | None:
    """A writable directory on another file system than ``root`` (tmpfs), or None."""
    for candidate in (Path("/dev/shm"), Path("/run/user") / str(os.getuid())):
        usable = candidate.is_dir() and os.access(candidate, os.W_OK)
        if usable and os.stat(candidate).st_dev != os.stat(root).st_dev:
            return Path(os.path.realpath(candidate))
    return None


def test_a_cross_device_retain_run_crashes_after_a_copy_and_recovers(
    tmp_path: Path, reference: dict[str, Any]
) -> None:
    """Cross-device publication through the coordinator: the work directory (sealed proofs) and the
    results (published proofs) are on different file systems, so every publication is a copy.
    A crash after a durable copy and before its record leaves an orphan; the next run alone
    removes it, verifies the node again and ends in the uninterrupted run's state."""
    other = cross_device_dir(tmp_path)
    if other is None:
        pytest.skip("no second writable file system (the image tier mounts one)")
    work = Path(tempfile.mkdtemp(prefix="cp-retain-run-", dir=other))
    try:
        w = retain_world(tmp_path)
        spec = w.spec(jobs=JOBS, work=str(work))
        w.results.mkdir(parents=True, exist_ok=True)
        assert os.stat(work).st_dev != os.stat(w.results).st_dev
        child = t.spawn_runner(spec, crash=("attempt.published", 2))
        code, out, err = t.messages(child)
        assert code == -signal.SIGKILL, (code, out, err)
        t.wait_clean(w.results, work)
        committed = {a["retained"]["path"] for a in w.attempts() if a["retained"] is not None}
        assert set(area_files(w)) - committed, "the premise: a durable copy without its record"
        before = complete_journal_bytes(w)
        code, out, err = t.messages(t.spawn_runner(spec))
        assert code == 0, (code, out, err)
        t.wait_clean(w.results, work)
        assert w.summary() == reference
        assert w.journal().read_bytes().startswith(before)
        assert_references_resolve(w)
        assert [p.name for p in work.iterdir() if p.name != ".run.lock"] == []
    finally:
        shutil.rmtree(work, ignore_errors=True)


# -- retain-full ---------------------------------------------------------------------------------


@dataclass
class TwoGroups(t.FixedProbes):
    """Results and work on independent storage; the results group has ``results_free``."""

    results_free: int = DISK_RESERVE

    def storage(self, paths: Any) -> StorageGroups:
        group_of = {p: ("results" if p.endswith("/results") else "work") for p in paths}
        members: dict[str, list[str]] = {}
        for path, group in group_of.items():
            members.setdefault(group, []).append(path)
        free = {g: self.results_free if g == "results" else 64 * GIB for g in members}
        return StorageGroups(group_of, {g: tuple(v) for g, v in members.items()}, free)


def test_retain_full_stops_new_work_and_commits_no_verified_record(tmp_path: Path) -> None:
    """The results group cannot take the copy (its budget is 0): the first checked proof is
    not recorded at all, the run stops new work with ``retain.blocked`` (exit 1), and the next
    run with space verifies the node (it stayed pending)."""
    w = retain_world(tmp_path, SHALLOW)
    with pytest.raises(ResourceError) as caught:
        w.run(jobs=JOBS, probes=TwoGroups())
    error = caught.value
    assert error.rule == "retain.blocked" and exit_code_of(error) == 1
    assert "retain.full" in error.detail and "disk:results" in error.detail
    assert [a for a in w.attempts() if a["outcome"] == "VERIFIED_UNSAT"] == []
    assert area_files(w) == {}
    assert w.work_files() == []
    t.wait_clean(w.results, w.work)
    result = w.run(jobs=JOBS)
    assert result.exit_code == 0 and w.summary()["verdict"] == "PROVED"
    assert_references_resolve(w)


# -- startup recovery binds records to references ------------------------------------------------


def typed(value: dict[str, Any]) -> Any:
    fields = {k: v for k, v in value.items() if k not in ("type", "format", "seq", "prev", "self")}
    fields.pop("utc", None)
    spec = PAYLOADS[value["type"]].SPEC
    spec.check(fields, "$")
    return spec.build(fields)


def append_forged(w: t.World, attempt: dict[str, Any]) -> None:
    """A new session (resume) and ``attempt`` appended through the journal writer, valid for the
    schema and the certifier's rules (which do not bind references to names)."""
    loaded = load_campaign(w.campaign, limits=DEFAULT_LIMITS)
    header = t.journal_records(w.results)[0]
    resume = {
        "type": "resume",
        "machinery": header["machinery"],
        "policy": header["policy"],
        "resources": header["resources"],
    }
    lock = RunLock.acquire(w.results / "run.lock")
    try:
        writer = JournalWriter.open(w.journal(), validator=validator_of(loaded), run_lock=lock)
        try:
            writer.append(typed(resume))
            writer.append(typed(attempt))
        finally:
            writer.close()
    finally:
        lock.release()


@pytest.mark.parametrize("forgery", ["unreferenced", "other_node"])
def test_a_record_that_does_not_bind_its_reference_stops_the_restart(
    tmp_path: Path, forgery: str
) -> None:
    w = retain_world(tmp_path, SHALLOW)
    assert w.run(jobs=JOBS).exit_code == 0
    verified = next(a for a in w.attempts() if a["outcome"] == "VERIFIED_UNSAT")
    forged = {k: v for k, v in verified.items() if k not in ("format", "seq", "prev", "self")}
    forged["attempt_id"] = "f0" * 16
    if forgery == "unreferenced":
        forged["retained"] = None
        rule = "retain.unreferenced"
    else:
        other = "ab" * 32
        path = f"proofs/{other}-{verified['proof_sha256']}.lrat"
        source = w.results / verified["retained"]["path"]
        (w.results / path).write_bytes(source.read_bytes())  # the file itself is intact
        forged["retained"] = dict(verified["retained"], path=path)
        rule = "retain.reference"
    append_forged(w, forged)
    files = area_files(w)
    journal = w.journal().read_bytes()
    with pytest.raises(IntegrityError) as caught:
        w.run(jobs=JOBS)
    assert caught.value.rule == rule and exit_code_of(caught.value) == 4
    assert w.journal().read_bytes() == journal  # nothing appended
    assert area_files(w) == files  # nothing removed
    t.wait_clean(w.results, w.work)


# -- quarantine in a run -------------------------------------------------------------------------


@pytest.mark.parametrize("mode", [ProofMode.TRANSIENT, ProofMode.RETAIN])
def test_a_rejected_proof_is_quarantined_in_a_run(tmp_path: Path, mode: ProofMode) -> None:
    policy = t.split_policy(anomaly_limit=1, proof_mode=mode)
    w = t.make_world(tmp_path, {"f": SHALLOW}, policy=policy)
    t.configure(w.tools.checker, reject=True)
    result = w.run()
    assert result.exit_code == 6
    (rejected,) = w.attempts()
    assert rejected["outcome"] == "CHECK_REJECTED" and rejected["proof_mode"] == mode.value
    reference = rejected["quarantined"]
    assert reference["path"] == (
        f"quarantine/{rejected['node_id']}-{rejected['proof_sha256']}.lrat"
    )
    files = area_files(w, "quarantine")
    assert set(files) == {reference["path"]}
    assert hashlib.sha256(files[reference["path"]]).hexdigest() == rejected["proof_sha256"]
    # the next session keeps the committed quarantine file (recovery validates it)
    t.configure(w.tools.checker)
    assert w.run().exit_code == 0
    assert set(area_files(w, "quarantine")) == {reference["path"]}


def test_a_quarantine_quota_miss_in_a_run_is_null_plus_reason(tmp_path: Path) -> None:
    policy = t.split_policy(anomaly_limit=1, quarantine_quota_bytes=0)
    w = t.make_world(tmp_path, {"f": SHALLOW}, policy=policy)
    t.configure(w.tools.checker, reject=True)
    assert w.run().exit_code == 6
    (rejected,) = w.attempts()
    assert rejected["quarantined"] is None
    assert rejected["diagnostics"]["quarantine_unavailable"] == "quota"
    assert area_files(w, "quarantine") == {}


def rejecting_world(root: Path, quota: int) -> t.World:
    policy = t.split_policy(anomaly_limit=1, quarantine_quota_bytes=quota)
    w = t.make_world(root, {"f": SHALLOW}, policy=policy)
    t.configure(w.tools.checker, reject=True)
    return w


def test_the_quarantine_quota_counts_the_files_of_earlier_sessions(tmp_path: Path) -> None:
    """Bounded quarantine across sessions: a new session's ledger starts from the committed
    quarantine files. Each session stops at its first rejection (anomaly limit 1); the next one
    splits the node and a child is rejected. The quota holds exactly the first proof, so the
    child's smaller proof would fit an empty quota but not the remainder: null plus ``quota``."""
    probe = rejecting_world(tmp_path / "probe", GIB)
    assert probe.run(jobs=1).exit_code == 6
    assert probe.run(jobs=1).exit_code == 6
    first, second = (a["quarantined"] for a in probe.attempts())
    assert first is not None and second is not None
    assert first["path"] != second["path"] and second["bytes"] <= first["bytes"]  # the premise
    w = rejecting_world(tmp_path / "real", first["bytes"])
    assert w.run(jobs=1).exit_code == 6
    assert w.run(jobs=1).exit_code == 6
    kept, missed = w.attempts()
    assert kept["quarantined"] == first
    assert missed["node_id"] != kept["node_id"] and missed["proof_sha256"] == second["sha256"]
    assert missed["quarantined"] is None
    assert missed["diagnostics"]["quarantine_unavailable"] == "quota"
    files = area_files(w, "quarantine")
    assert set(files) == {first["path"]}
    assert sum(map(len, files.values())) <= first["bytes"]
