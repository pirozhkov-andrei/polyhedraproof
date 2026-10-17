"""The I/O service protocol values (specification §8.1): typed jobs and results with attempt IDs.

The protocol has a job ID, an operation, an attempt ID, expected paths/hashes and a typed
result. Every result is checked against the job it claims to answer; a swapped job or
attempt ID, a different operation or a value that does not fit the request is a problem.
"""

from __future__ import annotations

from typing import Any

import cp_io_support as sup
import pytest

from cubeproof.base.canonical_json import encode
from cubeproof.base.errors import (
    ConfigurationError,
    ContractError,
    CubeproofError,
    InputError,
    IntegrityError,
    ResourceError,
    ToolError,
)
from cubeproof.contracts.io import (
    FRAME_LIMITS,
    IO_PROTOCOL,
    MAX_CHUNK_BYTES,
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
    ReconcileValue,
    RemoveRequest,
    RemoveValue,
    Result,
    artifact_path,
    decode_frame,
    encode_frame,
    staging_path,
)
from cubeproof.contracts.values import Artifact

A1 = sup.new_attempt_id(1)
A2 = sup.new_attempt_id(2)
H1 = "a" * 64
H2 = "b" * 64
DATA = sup.proof_bytes(100)


def publish_request(data: bytes = DATA) -> PublishRequest:
    return PublishRequest(
        source="/w/work/n-a.lrat",
        area=Area.PROOFS,
        node_id=sup.NODE_ID,
        proof_sha256=sup.sha(data),
        proof_bytes=len(data),
    )


def jobs() -> list[Job]:
    return [
        Job(1, None, HashRequest("/w/work/x.cnf")),
        Job(2, A1, HashRequest("/w/work/x.lrat")),
        Job(3, A1, publish_request()),
        Job(4, A1, AppendRequest.of(sup.attempt_payload(A1, DATA))),
        Job(5, None, AppendRequest.of(sup.resume_payload())),
        Job(6, A1, RemoveRequest(("/w/work/x.cnf", "/w/work/x.lrat"))),
        Job(7, None, ReconcileRequest((sup.artifact_for(DATA),))),
        Job(8, None, RemoveRequest(())),
        Job(9, None, ReconcileRequest(())),
    ]


def test_the_constants_follow_the_specification() -> None:
    assert IO_PROTOCOL == "cubeproof-io-1"
    assert MAX_CHUNK_BYTES == 8 * 1024 * 1024  # specification §8.1: at most 8 MiB per chunk
    # A frame carries one journal line (at most 8 MiB, specification §4.7) plus the job envelope.
    assert FRAME_LIMITS.line_bytes > 8 * 1024 * 1024
    assert FRAME_LIMITS.line_bytes < 9 * 1024 * 1024


def test_artifact_and_staging_paths() -> None:
    assert artifact_path(Area.PROOFS, H1, H2) == f"proofs/{H1}-{H2}.lrat"
    assert artifact_path(Area.QUARANTINE, H1, H2) == f"quarantine/{H1}-{H2}.lrat"
    assert staging_path(Area.PROOFS, A1) == f"proofs/tmp/{A1}.lrat"
    assert staging_path(Area.QUARANTINE, A1) == f"quarantine/tmp/{A1}.lrat"
    with pytest.raises(ContractError):
        artifact_path(Area.PROOFS, "x", H2)
    with pytest.raises(ContractError):
        staging_path(Area.PROOFS, "../x")


@pytest.mark.parametrize("job", jobs(), ids=lambda j: f"{j.job_id}-{j.op.value}")
def test_jobs_round_trip_through_canonical_frames(job: Job) -> None:
    frame = encode_frame(job.to_json())
    assert frame.endswith(b"\n")
    assert frame.count(b"\n") == 1
    value = decode_frame(frame[:-1])
    assert value["protocol"] == IO_PROTOCOL
    again = Job.from_json(value)
    assert again == job
    assert again.op is job.op


def test_a_publish_job_names_the_artifact_it_will_produce() -> None:
    request = publish_request()
    assert request.artifact == Artifact(
        f"proofs/{sup.NODE_ID}-{sup.sha(DATA)}.lrat", sup.sha(DATA), len(DATA)
    )


@pytest.mark.parametrize(
    "build",
    [
        lambda: Job(0, None, HashRequest("/x")),  # job IDs are positive
        lambda: Job(True, None, HashRequest("/x")),
        lambda: Job(1, "xyz", HashRequest("/x")),  # attempt IDs are Id128
        lambda: Job(1, None, HashRequest("relative/x")),  # paths are absolute
        lambda: Job(1, None, HashRequest("/a/../b")),  # and normalized
        lambda: Job(1, None, HashRequest("/a//b")),
        lambda: Job(1, None, HashRequest("/a/\0")),
        lambda: Job(1, None, publish_request()),  # publication needs the attempt ID
        lambda: Job(1, A1, AppendRequest.of(sup.attempt_payload(A2, DATA))),  # swapped
        lambda: Job(1, None, AppendRequest.of(sup.attempt_payload(A1, DATA))),
        lambda: Job(1, A1, AppendRequest.of(sup.resume_payload())),  # not an attempt
        lambda: Job(1, None, AppendRequest.of({"no": "type"})),
        lambda: Job(1, None, RemoveRequest(("/a", "/a"))),
        lambda: Job(1, None, ReconcileRequest((sup.artifact_for(DATA), sup.artifact_for(DATA)))),
        lambda: Job(1, None, ReconcileRequest((Artifact("work/x.lrat", H1, 3),))),
        lambda: Job(1, None, ReconcileRequest((Artifact("proofs/tmp/x.lrat", H1, 3),))),
        lambda: PublishRequest("/w/x", Area.PROOFS, sup.NODE_ID, H1, -1),
        lambda: PublishRequest("/w/x", Area.PROOFS, "x", H1, 1),
        lambda: PublishRequest("/w/x", Area.PROOFS, sup.NODE_ID, "x", 1),
    ],
)
def test_invalid_jobs_are_refused(build: Any) -> None:
    with pytest.raises(ContractError):
        build()


@pytest.mark.parametrize(
    "change",
    [
        {"protocol": "cubeproof-io-0"},
        {"op": "delete"},
        {"op": "remove"},  # args do not fit the operation
        {"job": -1},
        {"job": "1"},
        {"attempt_id": "x"},
        {"extra": 1},
        {"args": {"path": "/x", "extra": 1}},
    ],
)
def test_malformed_job_values_are_refused(change: dict[str, Any]) -> None:
    value = Job(3, A1, HashRequest("/w/x")).to_json()
    value.update(change)
    with pytest.raises(ContractError):
        Job.from_json(value)


def test_frames_are_canonical_and_bounded() -> None:
    value = Job(1, None, HashRequest("/w/x")).to_json()
    line = encode(value)
    assert decode_frame(line) == value
    with pytest.raises(ContractError):
        decode_frame(b'{"protocol": "cubeproof-io-1"}')  # not J(x)
    with pytest.raises(ContractError):
        decode_frame(b"[1]")  # not an object
    with pytest.raises(ResourceError):
        decode_frame(b"x" * (FRAME_LIMITS.line_bytes + 1))
    # The largest journal line fits into a frame.
    payload = {"type": "split", "pad": "x" * (8 * 1024 * 1024 - 64)}
    frame = encode_frame(Job(1, None, AppendRequest.of(payload)).to_json())
    assert decode_frame(frame[:-1])["args"]["payload"] == payload


def results_for(job: Job) -> Result:
    request = job.request
    outcome: Any
    if isinstance(request, HashRequest):
        outcome = HashValue(5, H1)
    elif isinstance(request, PublishRequest):
        outcome = PublishValue(request.artifact, reused=False)
    elif isinstance(request, AppendRequest):
        outcome = AppendValue(7, H2)
    elif isinstance(request, RemoveRequest):
        outcome = RemoveValue(request.paths[:1])
    else:
        outcome = ReconcileValue(len(request.committed), ("proofs/tmp/x.lrat",))
    return Result(job.job_id, job.op, job.attempt_id, outcome)


@pytest.mark.parametrize("job", jobs(), ids=lambda j: f"{j.job_id}-{j.op.value}")
def test_results_round_trip_and_answer_their_job(job: Job) -> None:
    result = results_for(job)
    assert result.ok
    again = Result.from_json(decode_frame(encode_frame(result.to_json())[:-1]))
    assert again == result
    assert again.problem(job) is None


def test_failures_round_trip_with_their_kind() -> None:
    job = Job(3, A1, publish_request())
    for error, fatal in [
        (IntegrityError("artifact.conflict", "unequal bytes"), False),
        (ResourceError("io.no_space", "ENOSPC"), False),
        (ToolError("io.fsync", "EIO"), True),
        (InputError("x", "y"), False),
        (ConfigurationError("io.layout", "symlink"), False),
        (ContractError("io.unpublished", "z"), False),
    ]:
        failure = Failure.of(error, fatal=fatal)
        result = Result(job.job_id, job.op, job.attempt_id, failure)
        assert not result.ok
        again = Result.from_json(result.to_json())
        assert again == result
        assert again.problem(job) is None
        raised = again.outcome.error() if isinstance(again.outcome, Failure) else None
        assert type(raised) is type(error)
        assert isinstance(raised, CubeproofError)
        assert raised.rule == error.rule
        assert again.outcome.fatal is fatal  # type: ignore[union-attr]


def test_swapped_job_ids_operations_and_attempts_do_not_answer_a_job() -> None:
    publish = Job(3, A1, publish_request())
    good = results_for(publish)
    assert good.problem(publish) is None
    swapped_job = Result(4, publish.op, publish.attempt_id, good.outcome)
    swapped_attempt = Result(3, publish.op, A2, good.outcome)
    no_attempt = Result(3, publish.op, None, good.outcome)
    other_op = Result(3, Op.HASH, A1, HashValue(len(DATA), sup.sha(DATA)))
    for result in (swapped_job, swapped_attempt, no_attempt, other_op):
        assert result.problem(publish) is not None


def test_a_publication_result_must_name_exactly_the_requested_artifact() -> None:
    publish = Job(3, A1, publish_request())
    art = publish_request().artifact
    other = sup.proof_bytes(100, seed=9)
    for wrong in [
        Artifact(art.path, sup.sha(other), art.bytes),
        Artifact(art.path, art.sha256, art.bytes + 1),
        Artifact(artifact_path(Area.QUARANTINE, sup.NODE_ID, art.sha256), art.sha256, art.bytes),
        Artifact(artifact_path(Area.PROOFS, H1, art.sha256), art.sha256, art.bytes),
    ]:
        assert Result(3, Op.PUBLISH, A1, PublishValue(wrong, reused=False)).problem(publish)


def test_a_removal_or_reconciliation_result_cannot_claim_other_paths() -> None:
    remove = Job(6, A1, RemoveRequest(("/w/work/a",)))
    assert Result(6, Op.REMOVE, A1, RemoveValue(("/w/work/b",))).problem(remove)
    art = sup.artifact_for(DATA)
    reconcile = Job(7, None, ReconcileRequest((art,)))
    # A reconciliation that reports removing a committed reference is never accepted.
    assert Result(7, Op.RECONCILE, None, ReconcileValue(1, (art.path,))).problem(reconcile)
    assert Result(7, Op.RECONCILE, None, ReconcileValue(0, ())).problem(reconcile)


def test_append_payload_is_kept_exactly() -> None:
    payload = sup.attempt_payload(A1, DATA)
    job = Job(4, A1, AppendRequest.of(payload))
    assert isinstance(job.request, AppendRequest)
    assert job.request.value() == payload
    assert job.request.value() is not job.request.value()  # a fresh copy each time
    assert encode(job.request.value()) == encode(payload)


def test_hello_round_trip() -> None:
    for hello in [Hello(1234, None, None), Hello(5, 3, H1)]:
        assert Hello.from_json(decode_frame(encode_frame(hello.to_json())[:-1])) == hello
    with pytest.raises(ContractError):
        Hello(5, 3, None)
    with pytest.raises(ContractError):
        Hello(0, None, None)
