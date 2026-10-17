"""Restart validation of committed retained/quarantined references (specification §7.2, §7.3, §7.5).

``retain.recover`` first checks that every committed reference binds to its record (the name
``<area>/<node_id>-<proof_sha256>.lrat`` with the record's proof size and hash; a retain-mode
VERIFIED_UNSAT without ``retained`` is a silent downgrade), then validates every referenced
file and only then removes orphans through the I/O service's reconciliation. Missing/corrupt
references are IntegrityError and nothing is removed. Recovery is idempotent.
"""

from __future__ import annotations

import copy
import os
from pathlib import Path
from typing import Any

import pytest
from cp_retain_support import (
    CHUNK,
    FaultCalls,
    artifact_for,
    attempt_id,
    proof_bytes,
    rejected_payload,
    retained_payload,
    sha,
    tree,
    typed,
)

from cubeproof.base.errors import IntegrityError
from cubeproof.contracts.enums import Outcome, ProofMode
from cubeproof.contracts.io import Area, staging_path
from cubeproof.contracts.values import Artifact
from cubeproof.evidence.schema import Attempt
from cubeproof.leaf import retain

A1, A2, A3, A4 = (attempt_id(i) for i in range(1, 5))
OTHER_NODE = "a6c396b2bee289fc402100f50e75f841b4e8a69465a710ad08022d67d44c2f51"


def forge(record: Attempt, **fields: Any) -> Attempt:
    """``record`` with other field values, without the schema's own rules: the record validator
    already refuses most of these records at replay; the recovery checks them again."""
    forged = copy.copy(record)
    for name, value in fields.items():
        object.__setattr__(forged, name, value)
    return forged


def write(root: Path, relative: str, data: bytes) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    path.chmod(0o444)


# -- record-level binding ------------------------------------------------------------------------


def test_a_retained_record_binds_to_its_own_proof_name() -> None:
    data = proof_bytes(100)
    assert retain.reference_problem(typed(retained_payload(A1, data))) is None
    assert retain.expected_reference(Area.PROOFS, typed(retained_payload(A1, data))) == (
        artifact_for(data)
    )


def test_a_retain_mode_verified_record_without_reference_is_a_silent_downgrade() -> None:
    record = typed(retained_payload(A1, proof_bytes(100), retained=None))
    assert retain.reference_problem(record) == "retain.unreferenced"


def test_a_transient_verified_record_has_no_reference() -> None:
    record = typed(retained_payload(A1, proof_bytes(100), retained=None))
    transient = forge(record, proof_mode=ProofMode.TRANSIENT)
    assert retain.reference_problem(transient) is None


@pytest.mark.parametrize(
    "name",
    ["other_node", "other_hash", "other_bytes", "quarantine_area", "odd_name"],
)
def test_a_retained_reference_with_another_name_or_content_does_not_bind(name: str) -> None:
    data = proof_bytes(100)
    good = artifact_for(data)
    wrong = {
        "other_node": artifact_for(data, node_id=OTHER_NODE),
        "other_hash": Artifact(good.path, sha(b"other"), good.bytes),
        "other_bytes": Artifact(good.path, good.sha256, good.bytes + 1),
        "quarantine_area": artifact_for(data, Area.QUARANTINE),
        "odd_name": Artifact(f"proofs/{sha(data)}.lrat", good.sha256, good.bytes),
    }[name]
    record = forge(typed(retained_payload(A1, data)), retained=wrong)
    assert retain.reference_problem(record) == "retain.reference"


def test_a_quarantined_reference_binds_to_the_rejected_proof() -> None:
    data = proof_bytes(100)
    record = typed(rejected_payload(A1, data))
    assert retain.reference_problem(record) is None
    assert retain.reference_problem(typed(rejected_payload(A1, data, quarantined=None))) is None
    wrong = artifact_for(proof_bytes(100, 9), Area.QUARANTINE)
    assert retain.reference_problem(forge(record, quarantined=wrong)) == "quarantine.reference"


def test_references_on_the_wrong_outcome_do_not_bind() -> None:
    data = proof_bytes(100)
    rejected = typed(rejected_payload(A1, data))
    assert (
        retain.reference_problem(forge(rejected, retained=artifact_for(data))) == "retain.reference"
    )
    verified = typed(retained_payload(A1, data))
    quarantined = artifact_for(data, Area.QUARANTINE)
    assert (
        retain.reference_problem(forge(verified, quarantined=quarantined)) == "quarantine.reference"
    )
    assert verified.outcome is Outcome.VERIFIED_UNSAT
    # a quarantined reference exists only in the file modes: not in stream mode
    assert rejected.quarantined is not None and retain.reference_problem(rejected) is None
    streamed = forge(rejected, proof_mode=ProofMode.STREAM)
    assert retain.reference_problem(streamed) == "quarantine.reference"


def test_committed_references_are_listed_once_per_path() -> None:
    a, b = proof_bytes(100, 1), proof_bytes(100, 2)
    records = [
        typed(retained_payload(A1, a)),
        typed(retained_payload(A2, a)),  # the same proof retained twice: one file
        typed(rejected_payload(A3, b)),
        typed(rejected_payload(A4, b, quarantined=None)),
    ]
    assert retain.committed_references(records) == (
        artifact_for(a),
        artifact_for(b, Area.QUARANTINE),
    )


def test_two_records_claiming_one_name_with_other_sizes_are_refused() -> None:
    data = proof_bytes(100)
    first = typed(retained_payload(A1, data))
    claimed = Artifact(artifact_for(data).path, sha(data), len(data) + 1)
    second = forge(typed(retained_payload(A2, data)), proof_bytes=len(data) + 1, retained=claimed)
    assert retain.reference_problem(second) is None  # each record binds on its own
    with pytest.raises(IntegrityError) as caught:
        retain.committed_references([first, second])
    assert caught.value.rule == "retain.reference"
    assert A2 in caught.value.detail


def test_committed_references_refuse_an_unbound_record() -> None:
    record = typed(retained_payload(A1, proof_bytes(10), retained=None))
    with pytest.raises(IntegrityError) as caught:
        retain.committed_references([record])
    assert caught.value.rule == "retain.unreferenced"
    assert A1 in caught.value.detail


# -- recovery on disk ----------------------------------------------------------------------------


def populated(results: Path) -> tuple[list[Attempt], dict[str, bytes]]:
    """Two retained proofs, one quarantined proof, an orphan, a staging leftover."""
    a, b, c = proof_bytes(3 * CHUNK, 1), proof_bytes(CHUNK + 1, 2), proof_bytes(2 * CHUNK, 3)
    records = [
        typed(retained_payload(A1, a)),
        typed(retained_payload(A2, b)),
        typed(rejected_payload(A3, c)),
    ]
    for data, area in ((a, Area.PROOFS), (b, Area.PROOFS), (c, Area.QUARANTINE)):
        write(results, artifact_for(data, area).path, data)
    kept = tree(results)
    write(results, artifact_for(proof_bytes(10, 4)).path, proof_bytes(10, 4))  # orphan
    write(results, staging_path(Area.PROOFS, A4), b"partial copy")
    write(results, staging_path(Area.QUARANTINE, A4), b"partial copy")
    return records, kept


def test_recovery_validates_references_then_removes_only_orphans(tmp_path: Path) -> None:
    results = tmp_path / "results"
    records, kept = populated(results)
    calls = FaultCalls()
    report = retain.recover(str(results), records, calls=calls, chunk_bytes=CHUNK)
    assert (report.retained, report.quarantined) == (2, 1)
    assert sorted(report.removed) == sorted(
        [
            artifact_for(proof_bytes(10, 4)).path,
            staging_path(Area.PROOFS, A4),
            staging_path(Area.QUARANTINE, A4),
        ]
    )
    assert tree(results) == kept
    referenced = {str(results / a.path) for a in retain.committed_references(records)}
    assert not referenced & {e[1] for e in calls.events("unlink")}
    # every validated reference resolves to its checked hash
    for record in records:
        for artifact in (record.retained, record.quarantined):
            if artifact is not None:
                assert sha((results / artifact.path).read_bytes()) == record.proof_sha256


def test_recovery_is_idempotent(tmp_path: Path) -> None:
    results = tmp_path / "results"
    records, kept = populated(results)
    first = retain.recover(str(results), records, chunk_bytes=CHUNK)
    calls = FaultCalls()
    second = retain.recover(str(results), records, calls=calls, chunk_bytes=CHUNK)
    assert first.removed and second.removed == ()
    assert (second.retained, second.quarantined) == (first.retained, first.quarantined)
    assert tree(results) == kept
    assert not calls.events("unlink", "write", "link", "rename")


@pytest.mark.parametrize("damage", ["missing", "corrupt", "symlink", "shrunk"])
@pytest.mark.parametrize("area", [Area.PROOFS, Area.QUARANTINE])
def test_a_missing_or_corrupt_reference_is_an_integrity_error_and_nothing_is_removed(
    tmp_path: Path, damage: str, area: Area
) -> None:
    results = tmp_path / "results"
    records, _ = populated(results)
    target = next(
        results / (r.retained or r.quarantined).path  # type: ignore[union-attr]
        for r in records
        if (r.retained if area is Area.PROOFS else r.quarantined) is not None
    )
    data = target.read_bytes()
    target.chmod(0o644)
    if damage == "missing":
        target.unlink()
    elif damage == "corrupt":
        target.write_bytes(bytes([data[0] ^ 1]) + data[1:])
    elif damage == "shrunk":
        target.write_bytes(data[:-1])
    else:
        target.unlink()
        elsewhere = tmp_path / "elsewhere.lrat"
        elsewhere.write_bytes(data)
        target.symlink_to(elsewhere)
    before = tree(results)
    with pytest.raises(IntegrityError) as caught:
        retain.recover(str(results), records, chunk_bytes=CHUNK)
    expected = "artifact.missing" if damage == "missing" else "artifact.corrupt"
    assert caught.value.rule == expected
    assert tree(results) == before  # the orphans are still there: nothing was removed


@pytest.mark.parametrize("problem", ["unreferenced", "reference"])
def test_an_unbound_record_stops_recovery_before_any_file_is_touched(
    tmp_path: Path, problem: str
) -> None:
    results = tmp_path / "results"
    records, _ = populated(results)
    if problem == "unreferenced":
        records.append(typed(retained_payload(A4, proof_bytes(7, 7), retained=None)))
    else:
        wrong = artifact_for(proof_bytes(10, 4))  # the orphan's name, another proof
        records.append(forge(typed(retained_payload(A4, proof_bytes(7, 7))), retained=wrong))
    before = tree(results)
    calls = FaultCalls()
    with pytest.raises(IntegrityError) as caught:
        retain.recover(str(results), records, calls=calls, chunk_bytes=CHUNK)
    assert caught.value.rule == f"retain.{problem}"
    assert tree(results) == before
    assert not calls.log  # decided from the records alone


def test_pending_publications_are_protected(tmp_path: Path) -> None:
    results = tmp_path / "results"
    records, kept = populated(results)
    pending = artifact_for(proof_bytes(10, 4)).path
    report = retain.recover(str(results), records, protected={pending}, chunk_bytes=CHUNK)
    assert pending not in report.removed
    assert (results / pending).exists()
    del kept


def test_recovery_of_an_empty_results_directory(tmp_path: Path) -> None:
    results = tmp_path / "results"
    results.mkdir()
    report = retain.recover(str(results), [], chunk_bytes=CHUNK)
    assert report == retain.Recovery(retained=0, quarantined=0, removed=())
    assert os.listdir(results) == []


def test_recovery_runs_in_bounded_steps(tmp_path: Path) -> None:
    results = tmp_path / "results"
    records, _ = populated(results)
    steps = retain.recover_steps(str(results), records, chunk_bytes=CHUNK)
    count = 0
    try:
        while True:
            next(steps)
            count += 1
    except StopIteration as stop:
        report = stop.value
    assert isinstance(report, retain.Recovery)
    assert count >= (3 * CHUNK + (CHUNK + 1) + 2 * CHUNK) // CHUNK
