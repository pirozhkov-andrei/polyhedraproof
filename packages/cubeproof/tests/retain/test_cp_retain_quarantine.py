"""Bounded quarantine of rejected file proofs (specification §4.8, §6.1 step 6, §7.2, §8.3).

Only CHECK_REJECTED in a file mode is quarantined. The quota (``quarantine_quota_bytes``)
counts committed quarantine files **and** pending copies (and copies published but never
referenced, until the startup reconciliation removes them). A quota miss or a failed
quarantine publication still commits the CHECK_REJECTED record, with ``quarantined: null`` and
the reason under ``quarantine_unavailable``. Nothing is ever deleted to make room: the module
has no deletion path, and a retained proof is untouched when quarantine is full.
"""

from __future__ import annotations

import errno
from pathlib import Path
from typing import Any

import pytest
from cp_retain_support import (
    CHUNK,
    NODE_ID,
    Env,
    FaultCalls,
    artifact_for,
    attempt_id,
    proof_bytes,
    rejected_payload,
    retained_payload,
    sha,
    typed,
)

from cubeproof.base.errors import ContractError, IntegrityError, ResourceError, ToolError
from cubeproof.contracts.enums import Outcome, ProofMode
from cubeproof.contracts.io import Area, Failure, PublishRequest, PublishValue
from cubeproof.contracts.values import Artifact
from cubeproof.leaf import quarantine as q
from cubeproof.leaf import retain
from cubeproof.leaf.binding import FileHash

A1, A2, A3 = attempt_id(1), attempt_id(2), attempt_id(3)


def proof(data: bytes, attempt: str = A1) -> FileHash:
    return FileHash(attempt, f"/w/{NODE_ID}-{attempt}.lrat", len(data), sha(data))


def art(data: bytes) -> Artifact:
    return artifact_for(data, Area.QUARANTINE)


def refused_detail(available: int, needed: int) -> str:
    return f"quarantine quota: {available} bytes available, {needed} needed"


# -- which attempts --------------------------------------------------------------------------------


@pytest.mark.parametrize("mode", list(ProofMode))
@pytest.mark.parametrize("outcome", list(Outcome))
def test_only_rejected_file_proofs_are_quarantined(mode: ProofMode, outcome: Outcome) -> None:
    expected = outcome is Outcome.CHECK_REJECTED and mode is not ProofMode.STREAM
    assert q.quarantine_applies(mode, outcome) is expected


def test_the_quarantine_request_names_the_rejected_proof() -> None:
    data = proof_bytes(100)
    sealed = proof(data)
    request = q.quarantine_request(NODE_ID, sealed)
    assert request == PublishRequest(sealed.path, Area.QUARANTINE, NODE_ID, sha(data), len(data))
    assert request.artifact == art(data)


# -- the ledger --------------------------------------------------------------------------------


def test_the_ledger_starts_from_the_committed_quarantine_files() -> None:
    a, b = proof_bytes(100, 1), proof_bytes(50, 2)
    ledger = q.QuarantineLedger(1000, [art(a), art(b), art(a)])  # one file per path
    assert (ledger.committed_bytes, ledger.pending_bytes, ledger.orphan_bytes) == (150, 0, 0)
    assert (ledger.used_bytes, ledger.available_bytes) == (150, 850)


def test_the_ledger_is_rebuilt_from_replayed_attempts() -> None:
    a = proof_bytes(100, 1)
    rejected = typed(rejected_payload(A1, a))
    unavailable = typed(rejected_payload(A2, proof_bytes(70, 2), quarantined=None))
    ledger = q.QuarantineLedger.from_attempts(1000, [rejected, unavailable])
    assert ledger.committed_bytes == 100


def test_pending_copies_count_against_the_quota() -> None:
    ledger = q.QuarantineLedger(250)
    assert ledger.reserve(A1, art(proof_bytes(100, 1))) is None
    assert ledger.reserve(A2, art(proof_bytes(100, 2))) is None
    assert ledger.pending_bytes == 200
    refused = ledger.reserve(A3, art(proof_bytes(100, 3)))
    assert isinstance(refused, q.Unavailable)
    assert refused.reason == q.QUOTA
    assert ledger.pending_bytes == 200  # a refusal reserves nothing


def test_a_quota_of_zero_quarantines_nothing() -> None:
    ledger = q.QuarantineLedger(0)
    assert ledger.reserve(A2, art(b"x")) == q.Unavailable(q.QUOTA, None, refused_detail(0, 1))
    assert ledger.reserve(A1, art(b"")) is None  # an empty proof needs no bytes


def test_an_already_committed_path_needs_no_new_bytes() -> None:
    data = proof_bytes(100)
    ledger = q.QuarantineLedger(100, [art(data)])
    assert ledger.available_bytes == 0
    assert ledger.reserve(A1, art(data)) is None
    assert ledger.pending_bytes == 0


def test_reservation_lifetime_commit() -> None:
    data = proof_bytes(100)
    ledger = q.QuarantineLedger(1000)
    assert ledger.reserve(A1, art(data)) is None
    ledger.published(A1)
    assert (ledger.pending_bytes, ledger.committed_bytes) == (100, 0)
    ledger.committed(A1)
    assert (ledger.pending_bytes, ledger.committed_bytes, ledger.used_bytes) == (0, 100, 100)
    # the same path committed twice is one file; reusing it needs no new bytes
    assert ledger.reserve(A2, art(data)) is None
    assert ledger.pending_bytes == 0
    ledger.published(A2)
    ledger.committed(A2)
    assert ledger.committed_bytes == 100


def test_reservation_lifetime_failed_copy_is_released() -> None:
    """The I/O service removes its staging file on a failed copy: nothing stays on disk."""
    ledger = q.QuarantineLedger(1000)
    assert ledger.reserve(A1, art(proof_bytes(100))) is None
    ledger.failed(A1)
    assert ledger.used_bytes == 0


def test_reservation_lifetime_published_but_not_committed_stays_counted() -> None:
    """A published copy without a record is an orphan until the startup reconciliation removes
    it (specification §7.2 step 5: release only after deletion/accounting)."""
    ledger = q.QuarantineLedger(1000)
    assert ledger.reserve(A1, art(proof_bytes(100))) is None
    ledger.published(A1)
    ledger.abandoned(A1)
    assert (ledger.pending_bytes, ledger.orphan_bytes, ledger.used_bytes) == (0, 100, 100)


def test_reservation_lifetime_abandoned_before_publication_is_released() -> None:
    ledger = q.QuarantineLedger(1000)
    assert ledger.reserve(A1, art(proof_bytes(100))) is None
    ledger.abandoned(A1)
    assert ledger.used_bytes == 0


def test_an_unknown_or_repeated_reservation_is_a_misuse() -> None:
    ledger = q.QuarantineLedger(1000)
    with pytest.raises(ContractError):
        ledger.committed(A1)
    assert ledger.reserve(A1, art(b"a")) is None
    with pytest.raises(ContractError):
        ledger.reserve(A1, art(b"b"))
    with pytest.raises(ContractError):
        ledger.committed(A1)  # not published yet
    with pytest.raises(ContractError):
        ledger.reserve(A2, artifact_for(b"c", Area.PROOFS))  # not a quarantine artifact
    ledger.published(A1)
    with pytest.raises(ContractError):
        ledger.failed(A1)  # a durable copy is not released as failed
    assert ledger.pending_bytes == 1


def test_the_ledger_never_offers_to_delete_anything() -> None:
    public = {name for name in dir(q.QuarantineLedger) if not name.startswith("_")}
    assert not {n for n in public if any(w in n for w in ("delete", "remove", "evict", "unlink"))}


# -- the decision ------------------------------------------------------------------------------


def test_decide_reserves_and_returns_the_request() -> None:
    data = proof_bytes(100)
    ledger = q.QuarantineLedger(1000)
    decision = q.decide(
        ledger, A1, NODE_ID, proof(data), mode=ProofMode.RETAIN, outcome=Outcome.CHECK_REJECTED
    )
    assert decision == q.quarantine_request(NODE_ID, proof(data))
    assert ledger.pending_bytes == 100


def test_decide_on_a_quota_miss_gives_null_plus_reason() -> None:
    ledger = q.QuarantineLedger(10)
    decision = q.decide(
        ledger,
        A1,
        NODE_ID,
        proof(proof_bytes(100)),
        mode=ProofMode.TRANSIENT,
        outcome=Outcome.CHECK_REJECTED,
    )
    assert isinstance(decision, q.Unavailable)
    assert decision.diagnostics() == {
        "quarantine_unavailable": "quota",
        "quarantine_detail": refused_detail(10, 100),
    }


def test_decide_refuses_a_proof_of_another_attempt() -> None:
    ledger = q.QuarantineLedger(1000)
    with pytest.raises(ContractError):
        q.decide(
            ledger,
            A2,
            NODE_ID,
            proof(b"x", A1),
            mode=ProofMode.RETAIN,
            outcome=Outcome.CHECK_REJECTED,
        )
    assert ledger.used_bytes == 0


def test_decide_refuses_an_attempt_that_is_not_quarantined() -> None:
    with pytest.raises(ValueError):
        q.decide(
            q.QuarantineLedger(1000),
            A1,
            NODE_ID,
            proof(b"x"),
            mode=ProofMode.RETAIN,
            outcome=Outcome.VERIFIED_UNSAT,
        )


@pytest.mark.parametrize(
    ("error", "reason"),
    [
        (ResourceError("io.no_space", "ENOSPC"), q.NO_SPACE),
        (IntegrityError("artifact.conflict", "other bytes"), q.CONFLICT),
        (ToolError("io.source_changed", "grew"), q.SOURCE_CHANGED),
        (ToolError("io.hash_mismatch", "other"), q.SOURCE_CHANGED),
        (ToolError("io.source", "missing"), q.SOURCE_CHANGED),
        (ToolError("io.write", "EIO"), q.IO),
    ],
)
def test_a_failed_quarantine_publication_is_null_plus_reason(error: ToolError, reason: str) -> None:
    request = q.quarantine_request(NODE_ID, proof(b"r"))
    outcome = q.quarantine_result(request, Failure.of(error, fatal=False))
    assert isinstance(outcome, q.Unavailable)
    assert outcome.reason == reason
    diagnostics = outcome.diagnostics()
    assert diagnostics["quarantine_unavailable"] == reason
    assert diagnostics["quarantine_error"] == {"rule": error.rule, "detail": error.detail}


def test_a_quarantine_publication_result_gives_the_reference() -> None:
    request = q.quarantine_request(NODE_ID, proof(b"r"))
    outcome = q.quarantine_result(request, PublishValue(request.artifact, reused=False))
    assert outcome == q.Quarantined(request.artifact, reused=False)
    other = art(b"another proof")
    with pytest.raises(ContractError) as caught:
        q.quarantine_result(request, PublishValue(other, reused=False))
    assert caught.value.rule == "quarantine.mismatch"
    with pytest.raises(ValueError):
        q.quarantine_result(
            retain.retain_request(NODE_ID, proof(b"r")),
            PublishValue(request.artifact, reused=False),
        )


# -- through the I/O service ----------------------------------------------------------------------


def test_quarantine_full_records_null_and_never_touches_retained_proofs(tmp_path: Path) -> None:
    env = Env(tmp_path)
    try:
        kept = proof_bytes(2 * CHUNK, 1)
        request = retain.retain_request(NODE_ID, env.source(A1, kept))
        published = retain.retain_result(request, env.publish(A1, request).outcome)  # type: ignore[arg-type]
        assert isinstance(published, retain.Published)
        assert env.append(A1, _retained(A1, kept)).ok
        before = env.area_files()
        ledger = q.QuarantineLedger(CHUNK)
        rejected = proof_bytes(2 * CHUNK, 2)
        decision = q.decide(
            ledger,
            A2,
            NODE_ID,
            env.source(A2, rejected),
            mode=ProofMode.RETAIN,
            outcome=Outcome.CHECK_REJECTED,
        )
        assert isinstance(decision, q.Unavailable) and decision.reason == q.QUOTA
        assert env.append(A2, _rejected(A2, rejected, quarantined=None)).ok
        assert env.area_files() == before
    finally:
        env.close()


def test_a_full_disk_quarantine_is_null_and_the_record_is_still_committed(tmp_path: Path) -> None:
    data = proof_bytes(2 * CHUNK)
    env = Env(tmp_path, calls=FaultCalls(free_bytes=CHUNK))
    try:
        ledger = q.QuarantineLedger(10 * CHUNK)
        request = q.decide(
            ledger,
            A1,
            NODE_ID,
            env.source(A1, data),
            mode=ProofMode.RETAIN,
            outcome=Outcome.CHECK_REJECTED,
        )
        assert isinstance(request, PublishRequest)
        outcome = q.quarantine_result(request, env.publish(A1, request).outcome)  # type: ignore[arg-type]
        assert isinstance(outcome, q.Unavailable) and outcome.reason == q.NO_SPACE
        ledger.failed(A1)
        assert ledger.used_bytes == 0
        payload = _rejected(A1, data, quarantined=None)
        payload["diagnostics"] = outcome.diagnostics()
        assert env.append(A1, payload).ok
        assert env.area_files() == {}
        assert env.attempts()[-1].quarantined is None
    finally:
        env.close()


def test_a_published_quarantine_copy_is_referenced_by_the_committed_record(
    tmp_path: Path,
) -> None:
    data = proof_bytes(3 * CHUNK)
    env = Env(tmp_path)
    try:
        ledger = q.QuarantineLedger(10 * CHUNK)
        request = q.decide(
            ledger,
            A1,
            NODE_ID,
            env.source(A1, data),
            mode=ProofMode.TRANSIENT,
            outcome=Outcome.CHECK_REJECTED,
        )
        assert isinstance(request, PublishRequest)
        outcome = q.quarantine_result(request, env.publish(A1, request).outcome)  # type: ignore[arg-type]
        assert outcome == q.Quarantined(request.artifact, reused=False)
        ledger.published(A1)
        assert env.append(A1, _rejected(A1, data)).ok
        ledger.committed(A1)
        assert env.attempts()[-1].quarantined == request.artifact
        assert env.area_files() == {request.artifact.path: data}
        assert ledger.committed_bytes == len(data)
    finally:
        env.close()


def _rejected(attempt: str, data: bytes, *, quarantined: Artifact | bool | None = True) -> Any:
    return rejected_payload(attempt, data, quarantined=quarantined)


def _retained(attempt: str, data: bytes) -> Any:
    return retained_payload(attempt, data)


def test_errno_is_reported_by_rule_not_by_text() -> None:
    error = ResourceError("io.no_space", f"[Errno {errno.ENOSPC}] no space")
    outcome = q.quarantine_result(
        q.quarantine_request(NODE_ID, proof(b"z")), Failure.of(error, fatal=False)
    )
    assert isinstance(outcome, q.Unavailable) and outcome.reason == q.NO_SPACE
