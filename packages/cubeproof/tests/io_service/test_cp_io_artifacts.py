"""Artifact publication and reconciliation (specification §7.2, §7.3, §7.5).

Publication: keep the checked source; copy to a fresh ``<area>/tmp/<attempt_id>.lrat`` on the
target file system, hash and fsync it, require the checked hash and size; give it its final
name ``<area>/<node_id>-<proof_sha256>.lrat`` without ever overwriting other bytes; fsync the
directory; only then report. Reconciliation validates every committed reference first; a
missing or corrupt one is an IntegrityError and nothing is removed; afterwards unreferenced
published files and staging files are orphans and are removed; it is idempotent.
"""

from __future__ import annotations

import errno
import os
import stat
from pathlib import Path

import cp_io_support as sup
import pytest
from cp_io_support import Crash, FaultCalls

from cubeproof.base.errors import ContractError, IntegrityError, ResourceError, ToolError
from cubeproof.contracts.io import Area, PublishRequest, PublishValue, staging_path
from cubeproof.contracts.values import Artifact
from cubeproof.tools.artifacts import publish, publish_steps, reconcile
from cubeproof.tools.atomic import DurabilityError

A1 = sup.new_attempt_id(1)
A2 = sup.new_attempt_id(2)
CHUNK = 4096


def setup(tmp_path: Path, data: bytes, name: str = "n-a.lrat") -> tuple[Path, Path, Path]:
    results = tmp_path / "results"
    work = tmp_path / "work"
    results.mkdir(parents=True, exist_ok=True)
    source = sup.write_file(work / name, data)
    return results, work, source


def request(source: Path, data: bytes, area: Area = Area.PROOFS) -> PublishRequest:
    return PublishRequest(str(source), area, sup.NODE_ID, sup.sha(data), len(data))


def final(results: Path, data: bytes, area: Area = Area.PROOFS) -> Path:
    return results / sup.artifact_for(data, area).path


# -- publication -----------------------------------------------------------------------------------


@pytest.mark.parametrize("area", list(Area))
@pytest.mark.parametrize("size", [0, 1, CHUNK, 3 * CHUNK + 5])
def test_publish_copies_hashes_and_names_the_proof(tmp_path: Path, area: Area, size: int) -> None:
    data = sup.proof_bytes(size)
    results, _, source = setup(tmp_path, data)
    calls = FaultCalls()
    value = publish(str(results), A1, request(source, data, area), calls=calls, chunk_bytes=CHUNK)
    assert value == PublishValue(sup.artifact_for(data, area), reused=False)
    target = final(results, data, area)
    assert target.read_bytes() == data
    assert not stat.S_IMODE(target.stat().st_mode) & 0o222  # published read-only
    assert source.read_bytes() == data  # the source is kept (deleted after the commit)
    assert sup.tree(results) == {value.artifact.path: data}  # no staging file is left


def test_publish_order_of_durable_effects(tmp_path: Path) -> None:
    data = sup.proof_bytes(3 * CHUNK + 5)
    results, _, source = setup(tmp_path, data)
    calls = FaultCalls()
    publish(str(results), A1, request(source, data), calls=calls, chunk_bytes=CHUNK)
    tmp = str(results / staging_path(Area.PROOFS, A1))
    target = str(final(results, data))
    area = str(results / "proofs")
    effects = calls.events("write", "fsync", "link", "rename", "unlink")
    kinds = [(e[0], e[1]) for e in effects]
    first_publish = next(i for i, e in enumerate(effects) if e[0] in ("link", "rename"))
    # Every byte is written to the staging file and synced before it gets its final name
    # (the other fsyncs before it are those of newly created area directories).
    assert all(e[1] == tmp for e in effects[:first_publish] if e[0] == "write")
    directories = {str(results), area}
    assert all(e[1] in directories | {tmp} for e in effects[:first_publish] if e[0] == "fsync")
    assert ("fsync", tmp) in kinds[:first_publish]
    last_write = max(i for i, e in enumerate(effects) if e[0] == "write")
    assert kinds.index(("fsync", tmp)) > last_write
    assert effects[first_publish][-1] == target
    # The directory entry is synced before publication is reported; the staging name goes last.
    after = kinds[first_publish + 1 :]
    assert ("fsync", area) in after
    if ("unlink", tmp) in after:
        assert after.index(("fsync", area)) < after.index(("unlink", tmp))
    # The source is only read, never renamed, linked or removed (cross-FS safe, specification §7.2
    # step 1).
    assert not any(str(source) in map(str, e[1:]) for e in effects)


def test_publish_reads_and_writes_in_chunks_and_never_beyond_the_declared_size(
    tmp_path: Path,
) -> None:
    data = sup.proof_bytes(5 * CHUNK)
    results, _, source = setup(tmp_path, data)
    calls = FaultCalls()
    generator = publish_steps(
        str(results), A1, request(source, data), calls=calls, chunk_bytes=CHUNK
    )
    steps = 0
    try:
        while True:
            next(generator)
            steps += 1
    except StopIteration:
        pass
    assert steps >= 5  # yields between chunks: the service can run journal commits meanwhile
    reads = [e for e in calls.events("pread") if e[1] == str(source)]
    assert all(e[2] <= CHUNK + 1 for e in reads)
    assert max(e[3] + e[2] for e in reads) <= len(data) + 1
    assert sum(e[2] for e in calls.events("write")) == len(data)


def test_publish_completes_short_writes(tmp_path: Path) -> None:
    data = sup.proof_bytes(3 * CHUNK)
    results, _, source = setup(tmp_path, data)
    calls = FaultCalls(write_limit=1000, faults={"write": sup.interrupt(3)})
    publish(str(results), A1, request(source, data), calls=calls, chunk_bytes=CHUNK)
    assert final(results, data).read_bytes() == data


def test_a_source_with_other_bytes_is_refused_and_nothing_is_published(tmp_path: Path) -> None:
    data = sup.proof_bytes(3 * CHUNK)
    results, _, source = setup(tmp_path, data)
    changed = bytearray(data)
    changed[CHUNK + 7] ^= 1
    source.chmod(0o644)
    source.write_bytes(bytes(changed))
    with pytest.raises(ToolError) as caught:
        publish(str(results), A1, request(source, data), chunk_bytes=CHUNK)
    assert caught.value.rule == "io.hash_mismatch"
    assert source.read_bytes() == bytes(changed)  # kept for the binding's diagnosis
    assert sup.tree(results) == {}


@pytest.mark.parametrize("delta", [-1, 1, CHUNK])
def test_a_source_of_another_size_is_refused(tmp_path: Path, delta: int) -> None:
    data = sup.proof_bytes(2 * CHUNK)
    results, _, source = setup(tmp_path, data)
    other = sup.proof_bytes(2 * CHUNK + delta)
    source.chmod(0o644)
    source.write_bytes(other)
    calls = FaultCalls()
    with pytest.raises(ToolError) as caught:
        publish(str(results), A1, request(source, data), calls=calls, chunk_bytes=CHUNK)
    assert caught.value.rule == "io.source_changed"
    assert sup.tree(results) == {}
    assert calls.events("write") == []  # refused at open, before any byte is copied


@pytest.mark.parametrize("change", ["grow", "shrink"])
def test_a_source_changing_during_the_copy_never_overflows_the_reservation(
    tmp_path: Path, change: str
) -> None:
    data = sup.proof_bytes(2 * CHUNK + 10)
    results, _, source = setup(tmp_path, data)

    def mutate(number: int, *args: object) -> None:
        if number == 2:
            source.chmod(0o644)
            if change == "grow":
                with source.open("ab") as handle:
                    handle.write(b"x" * CHUNK)
            else:
                os.truncate(source, CHUNK + 5)

    calls = FaultCalls(faults={"pread": mutate})
    with pytest.raises(ToolError) as caught:
        publish(str(results), A1, request(source, data), calls=calls, chunk_bytes=CHUNK)
    assert caught.value.rule == "io.source_changed"
    assert sum(e[2] for e in calls.events("write")) <= len(data)  # the reserved bytes
    assert sup.tree(results) == {}


def test_a_final_name_that_vanishes_during_the_check_is_published_normally(
    tmp_path: Path,
) -> None:
    data = sup.proof_bytes(2 * CHUNK)
    results, _, source = setup(tmp_path, data)
    target = final(results, data)
    target.parent.mkdir(parents=True)
    sup.write_file(target, b"stale")

    class Vanishing(FaultCalls):
        def lstat(self, path: str) -> os.stat_result:
            info = super().lstat(path)
            if path == str(target) and target.exists():
                target.unlink()  # gone between the existence check and its verification
            return info

    value = publish(str(results), A1, request(source, data), calls=Vanishing(), chunk_bytes=CHUNK)
    assert value.reused is False
    assert target.read_bytes() == data


def test_a_source_that_grows_during_the_copy_is_refused(tmp_path: Path) -> None:
    data = sup.proof_bytes(2 * CHUNK)
    results, _, source = setup(tmp_path, data)

    def grow(number: int, *args: object) -> None:
        if number == 2:
            source.chmod(0o644)
            with source.open("ab") as handle:
                handle.write(b"more")

    calls = FaultCalls(faults={"pread": grow})
    with pytest.raises(ToolError) as caught:
        publish(str(results), A1, request(source, data), calls=calls, chunk_bytes=CHUNK)
    assert caught.value.rule == "io.source_changed"
    assert sup.tree(results) == {}


def test_a_symlinked_or_missing_source_is_refused(tmp_path: Path) -> None:
    data = sup.proof_bytes(10)
    results, work, source = setup(tmp_path, data)
    link = work / "link.lrat"
    link.symlink_to(source)
    with pytest.raises(ContractError) as caught:
        publish(str(results), A1, request(link, data))
    assert caught.value.rule == "io.not_regular"
    with pytest.raises(ToolError) as caught_missing:
        publish(str(results), A1, request(work / "missing.lrat", data))
    assert caught_missing.value.rule == "io.source"
    assert sup.tree(results) == {}


def test_an_existing_equal_artifact_is_reused_and_its_entry_synced(tmp_path: Path) -> None:
    data = sup.proof_bytes(2 * CHUNK)
    results, _, source = setup(tmp_path, data)
    first = publish(str(results), A1, request(source, data), chunk_bytes=CHUNK)
    calls = FaultCalls()
    again = publish(str(results), A2, request(source, data), calls=calls, chunk_bytes=CHUNK)
    assert again == PublishValue(first.artifact, reused=True)
    assert calls.events("write", "link", "rename") == []
    # The entry may come from a run that died before its directory sync.
    assert ("fsync", str(results / "proofs")) in calls.log
    assert sup.tree(results) == {first.artifact.path: data}


@pytest.mark.parametrize("kind", ["bytes", "size", "symlink", "directory"])
def test_an_existing_unequal_artifact_is_never_overwritten(tmp_path: Path, kind: str) -> None:
    data = sup.proof_bytes(2 * CHUNK)
    results, _, source = setup(tmp_path, data)
    target = final(results, data)
    target.parent.mkdir(parents=True)
    if kind == "bytes":
        other = bytearray(data)
        other[0] ^= 1
        sup.write_file(target, bytes(other))
    elif kind == "size":
        sup.write_file(target, data[:-1])
    elif kind == "symlink":
        target.symlink_to(source)
    else:
        target.mkdir()
    before = sup.tree(results)
    with pytest.raises(IntegrityError) as caught:
        publish(str(results), A1, request(source, data), chunk_bytes=CHUNK)
    assert caught.value.rule == "artifact.conflict"
    assert sup.tree(results) == before


def test_an_unequal_artifact_appearing_during_the_copy_is_not_overwritten(tmp_path: Path) -> None:
    data = sup.proof_bytes(2 * CHUNK)
    results, _, source = setup(tmp_path, data)
    other = bytes(reversed(data))
    target = final(results, data)

    def sneak(number: int, *args: object) -> None:
        if number == 1:
            sup.write_file(target, other)

    calls = FaultCalls(faults={"link": sneak, "rename": sneak})
    with pytest.raises(IntegrityError) as caught:
        publish(str(results), A1, request(source, data), calls=calls, chunk_bytes=CHUNK)
    assert caught.value.rule == "artifact.conflict"
    assert target.read_bytes() == other
    assert not (results / staging_path(Area.PROOFS, A1)).exists()


def test_a_full_disk_during_the_copy_is_a_resource_error_without_leftovers(tmp_path: Path) -> None:
    data = sup.proof_bytes(4 * CHUNK)
    results, _, source = setup(tmp_path, data)
    calls = FaultCalls(faults={"write": sup.fail_with(errno.ENOSPC, after=2)})
    with pytest.raises(ResourceError) as caught:
        publish(str(results), A1, request(source, data), calls=calls, chunk_bytes=CHUNK)
    assert caught.value.rule == "io.no_space"
    assert source.read_bytes() == data
    assert sup.tree(results) == {}


def test_too_little_free_space_is_refused_before_any_byte(tmp_path: Path) -> None:
    data = sup.proof_bytes(4 * CHUNK)
    results, _, source = setup(tmp_path, data)
    calls = FaultCalls(free_bytes=len(data) - 1)
    with pytest.raises(ResourceError) as caught:
        publish(str(results), A1, request(source, data), calls=calls, chunk_bytes=CHUNK)
    assert caught.value.rule == "io.no_space"
    assert calls.events("write") == []
    assert sup.tree(results) == {}


@pytest.mark.parametrize("which", [1, 2])
def test_a_failed_fsync_is_a_durability_error(tmp_path: Path, which: int) -> None:
    data = sup.proof_bytes(2 * CHUNK)
    results, _, source = setup(tmp_path, data)
    # The first fsyncs create the area directories; fail the staging file's or the entry's.
    probe = FaultCalls()
    (tmp_path / "probe").mkdir()
    publish(str(tmp_path / "probe"), A1, request(source, data), calls=probe, chunk_bytes=CHUNK)
    fsyncs = [e[1] for e in probe.events("fsync")]
    tmp_index = fsyncs.index(str(tmp_path / "probe" / staging_path(Area.PROOFS, A1)))
    target_index = tmp_index + 1 if which == 2 else tmp_index
    calls = FaultCalls(faults={"fsync": sup.fail_with(errno.EIO, after=target_index)})
    with pytest.raises(DurabilityError) as caught:
        publish(str(results), A1, request(source, data), calls=calls, chunk_bytes=CHUNK)
    assert caught.value.rule == "io.fsync"
    assert not (results / staging_path(Area.PROOFS, A1)).exists() or which == 2


def test_a_symlinked_area_directory_is_refused(tmp_path: Path) -> None:
    data = sup.proof_bytes(10)
    results, _, source = setup(tmp_path, data)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (results / "proofs").symlink_to(elsewhere)
    with pytest.raises(ContractError) as caught:
        publish(str(results), A1, request(source, data))
    assert caught.value.rule == "io.layout"
    assert list(elsewhere.iterdir()) == []


def test_an_existing_staging_file_is_refused(tmp_path: Path) -> None:
    data = sup.proof_bytes(10)
    results, _, source = setup(tmp_path, data)
    staging = results / staging_path(Area.PROOFS, A1)
    sup.write_file(staging, b"old", mode=0o644)
    with pytest.raises(ToolError) as caught:
        publish(str(results), A1, request(source, data))
    assert caught.value.rule == "io.staging_exists"
    assert staging.read_bytes() == b"old"


@pytest.mark.parametrize("code", [errno.EPERM, errno.EOPNOTSUPP])
def test_a_file_system_without_hard_links_still_publishes(tmp_path: Path, code: int) -> None:
    data = sup.proof_bytes(2 * CHUNK)
    results, _, source = setup(tmp_path, data)
    calls = FaultCalls(faults={"link": sup.fail_with(code)})
    value = publish(str(results), A1, request(source, data), calls=calls, chunk_bytes=CHUNK)
    assert sup.tree(results) == {value.artifact.path: data}


def cross_device_dirs(tmp_path: Path) -> tuple[Path, Path] | None:
    for candidate in (Path("/dev/shm"), Path("/run/user") / str(os.getuid())):
        usable = candidate.is_dir() and os.access(candidate, os.W_OK)
        if usable and os.stat(candidate).st_dev != os.stat(tmp_path).st_dev:
            return candidate, tmp_path
    return None


def test_publication_across_real_file_systems(tmp_path: Path) -> None:
    pair = cross_device_dirs(tmp_path)
    if pair is None:
        pytest.skip("no second writable file system (the image tier mounts one)")
    other, _ = pair
    data = sup.proof_bytes(3 * CHUNK + 1)
    work = Path(os.path.realpath(other)) / f"cp-io-{os.getpid()}-{tmp_path.name}"
    work.mkdir()
    try:
        source = sup.write_file(work / "n-a.lrat", data)
        results = tmp_path / "results"
        results.mkdir()
        assert os.stat(source).st_dev != os.stat(results).st_dev
        value = publish(str(results), A1, request(source, data), chunk_bytes=CHUNK)
        assert final(results, data).read_bytes() == data
        assert os.stat(final(results, data)).st_dev == os.stat(results).st_dev
        assert source.read_bytes() == data
        assert value.reused is False
    finally:
        for path in work.iterdir():
            path.unlink()
        work.rmdir()


def test_cross_device_simulation_never_renames_the_source(tmp_path: Path) -> None:
    """A rename/link of the source would fail with EXDEV across file systems; none is made."""
    data = sup.proof_bytes(2 * CHUNK)
    results, _, source = setup(tmp_path, data)

    def exdev(number: int, src: str, *rest: object) -> None:
        if os.path.dirname(src) == str(source.parent):
            raise OSError(errno.EXDEV, os.strerror(errno.EXDEV))

    calls = FaultCalls(faults={"link": exdev, "rename": exdev})
    publish(str(results), A1, request(source, data), calls=calls, chunk_bytes=CHUNK)
    assert final(results, data).read_bytes() == data


# -- reconciliation --------------------------------------------------------------------------------


def published(tmp_path: Path, *seeds: int, area: Area = Area.PROOFS) -> tuple[Path, list[Artifact]]:
    results = tmp_path / "results"
    results.mkdir(exist_ok=True)
    out = []
    for index, seed in enumerate(seeds):
        data = sup.proof_bytes(CHUNK + seed, seed=seed)
        source = sup.write_file(tmp_path / "work" / f"{seed}.lrat", data)
        attempt = sup.new_attempt_id(100 + index + 10 * seed)
        out.append(publish(str(results), attempt, request(source, data, area)).artifact)
    return results, out


def test_reconcile_validates_and_removes_only_orphans(tmp_path: Path) -> None:
    results, (kept, orphan) = published(tmp_path, 1, 2)
    _, (quarantined,) = published(tmp_path, 3, area=Area.QUARANTINE)
    sup.write_file(results / "proofs" / "tmp" / f"{A1}.lrat", b"partial", mode=0o644)
    sup.write_file(results / "quarantine" / "tmp" / f"{A2}.lrat", b"partial", mode=0o644)
    (results / "proofs" / "stray-link").symlink_to(results / kept.path)
    other = results / "journal.jsonl"
    other.write_bytes(b"not ours")
    value = reconcile(str(results), [kept, quarantined], chunk_bytes=CHUNK)
    assert value.validated == 2
    assert sorted(value.removed) == sorted(
        [
            orphan.path,
            f"proofs/tmp/{A1}.lrat",
            f"quarantine/tmp/{A2}.lrat",
            "proofs/stray-link",
        ]
    )
    files = sup.tree(results)
    assert set(files) == {kept.path, quarantined.path, "journal.jsonl"}
    assert sup.sha(files[kept.path]) == kept.sha256
    # Idempotent: a second run validates the same references and removes nothing.
    again = reconcile(str(results), [kept, quarantined], chunk_bytes=CHUNK)
    assert again.validated == 2
    assert again.removed == ()
    assert sup.tree(results) == files


def test_reconcile_keeps_protected_pending_publications(tmp_path: Path) -> None:
    results, (kept, pending) = published(tmp_path, 1, 2)
    value = reconcile(str(results), [kept], protected=[pending.path])
    assert value.removed == ()
    assert (results / pending.path).exists()


@pytest.mark.parametrize("damage", ["missing", "bytes", "truncated", "symlink", "directory"])
def test_a_missing_or_corrupt_reference_is_an_integrity_error_and_nothing_is_removed(
    tmp_path: Path, damage: str
) -> None:
    results, (good, bad, orphan) = published(tmp_path, 1, 2, 3)
    path = results / bad.path
    path.chmod(0o644)
    if damage == "missing":
        path.unlink()
    elif damage == "bytes":
        data = bytearray(path.read_bytes())
        data[-1] ^= 1
        path.write_bytes(bytes(data))
    elif damage == "truncated":
        path.write_bytes(path.read_bytes()[:-1])
    elif damage == "symlink":
        path.unlink()
        path.symlink_to(results / good.path)
    else:
        path.unlink()
        path.mkdir()
    sup.write_file(results / "proofs" / "tmp" / f"{A1}.lrat", b"partial", mode=0o644)
    before = sup.tree(results)
    with pytest.raises(IntegrityError) as caught:
        reconcile(str(results), [good, bad], chunk_bytes=CHUNK)
    rule = "artifact.missing" if damage == "missing" else "artifact.corrupt"
    assert caught.value.rule == rule
    assert bad.path in caught.value.detail
    # Committed references first: the orphan and the staging file are still there.
    assert sup.tree(results) == before
    assert (results / orphan.path).exists()


def test_reconcile_of_an_empty_results_directory(tmp_path: Path) -> None:
    results = tmp_path / "results"
    results.mkdir()
    assert reconcile(str(results), []).removed == ()
    with pytest.raises(IntegrityError):
        reconcile(str(results), [sup.artifact_for(b"x")])


def test_reconcile_refuses_symlinked_areas(tmp_path: Path) -> None:
    results = tmp_path / "results"
    results.mkdir()
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    sup.write_file(elsewhere / "victim", b"keep")
    (results / "proofs").symlink_to(elsewhere)
    with pytest.raises(ContractError) as caught:
        reconcile(str(results), [])
    assert caught.value.rule == "io.layout"
    assert (elsewhere / "victim").exists()


def test_a_reference_reached_through_a_symlinked_area_is_corrupt(tmp_path: Path) -> None:
    """The intact bytes elsewhere do not count: references are not followed through links."""
    results, (kept,) = published(tmp_path, 1)
    elsewhere = tmp_path / "elsewhere"
    (results / "proofs").rename(elsewhere)
    (results / "proofs").symlink_to(elsewhere)
    assert (results / kept.path).read_bytes()  # reachable through the link
    with pytest.raises(IntegrityError) as caught:
        reconcile(str(results), [kept])
    assert caught.value.rule == "artifact.corrupt"


def test_reconcile_never_unlinks_a_referenced_path(tmp_path: Path) -> None:
    results, (kept, orphan) = published(tmp_path, 1, 2)
    calls = FaultCalls()
    reconcile(str(results), [kept], calls=calls)
    unlinked = [e[1] for e in calls.events("unlink")]
    assert unlinked == [str(results / orphan.path)]


# -- crash before/after each durable effect -------------------------------------------------------


def crash_points(tmp_path: Path, data: bytes) -> int:
    results, _, source = setup(tmp_path / "count", data)
    calls = FaultCalls()
    publish(str(results), A1, request(source, data), calls=calls, chunk_bytes=CHUNK)
    return calls.mutations


def test_a_crash_at_any_durable_effect_of_publication_is_recovered(tmp_path: Path) -> None:
    data = sup.proof_bytes(2 * CHUNK + 3)
    points = crash_points(tmp_path, data)
    assert points >= 8
    for point in range(1, points + 1):
        base = tmp_path / f"p{point}"
        results, _, source = setup(base, data)
        calls = FaultCalls(crash_at=point)
        with pytest.raises(Crash):
            publish(str(results), A1, request(source, data), calls=calls, chunk_bytes=CHUNK)
        assert source.read_bytes() == data
        target = final(results, data)
        if target.exists():  # never a partial file under the final name
            assert target.read_bytes() == data
        # Not committed: recovery removes everything that was published or staged.
        value = reconcile(str(results), [], chunk_bytes=CHUNK)
        assert sup.tree(results) == {}, (point, value)
        assert reconcile(str(results), []).removed == ()
        # The retried attempt (a fresh attempt ID) publishes normally.
        again = publish(str(results), A2, request(source, data), chunk_bytes=CHUNK)
        assert sup.tree(results) == {again.artifact.path: data}
