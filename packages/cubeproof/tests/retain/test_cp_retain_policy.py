"""Retain mode: the publication request, its result and the retain-full decision (specification
§6.1 step 6, §7.2, §8.3).

A retained proof is published through the single publication of the I/O service (a
``PublishRequest``) **before** its record. A failed retained publication (quota/no space, a
conflicting artifact, a changed source, a failed service) never becomes a VERIFIED_UNSAT without
``retained``: no record is committed, the node stays pending and the run stops new work with
a diagnostic (exit 1 for a resource block, 4 for an integrity failure, 5 for a tool/service
failure, specification §12.2).
"""

from __future__ import annotations

import errno
import os
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from cp_retain_support import CHUNK, NODE_ID, Env, FaultCalls, attempt_id, proof_bytes, sha

from cubeproof.base.errors import ContractError, IntegrityError, ResourceError, ToolError
from cubeproof.contracts.io import Area, Failure, PublishRequest, PublishValue
from cubeproof.contracts.values import Artifact
from cubeproof.leaf import retain
from cubeproof.leaf.binding import FileHash

A1 = attempt_id(1)
A2 = attempt_id(2)
OTHER_NODE = "a6c396b2bee289fc402100f50e75f841b4e8a69465a710ad08022d67d44c2f51"


def proof(data: bytes, attempt: str = A1) -> FileHash:
    return FileHash(attempt, f"/w/{NODE_ID}-{attempt}.lrat", len(data), sha(data))


# -- the request -------------------------------------------------------------------------------


def test_the_retain_request_publishes_the_checked_proof_under_its_node_and_hash() -> None:
    data = proof_bytes(1000)
    sealed = proof(data)
    request = retain.retain_request(NODE_ID, sealed)
    assert request == PublishRequest(sealed.path, Area.PROOFS, NODE_ID, sha(data), len(data))
    assert request.artifact == Artifact(f"proofs/{NODE_ID}-{sha(data)}.lrat", sha(data), len(data))


def test_a_publication_request_names_the_checked_bytes_not_a_new_measurement() -> None:
    sealed = proof(b"x" * 10)
    request = retain.publication_request(Area.QUARANTINE, NODE_ID, sealed)
    assert (request.source, request.proof_bytes, request.proof_sha256) == (
        sealed.path,
        sealed.bytes,
        sealed.sha256,
    )
    assert request.area is Area.QUARANTINE


def test_the_request_refuses_a_proof_of_another_node() -> None:
    sealed = proof(b"y")
    with pytest.raises(ContractError) as caught:
        retain.retain_request(OTHER_NODE, sealed)
    assert caught.value.rule == "retain.source"


def test_the_request_needs_a_file_measurement() -> None:
    with pytest.raises(ContractError):
        retain.retain_request(NODE_ID, ("/w/x.lrat", 1, sha(b"x")))  # type: ignore[arg-type]


# -- reservations ------------------------------------------------------------------------------


def test_the_target_copy_is_reserved_on_its_storage_group() -> None:
    """Specification §7.2 step 1: the source stays until cleanup, so the copy needs its full size
    again on the target group; on one shared group that is double occupancy."""
    assert retain.publication_need(1000, source_group="work", target_group="results") == {
        "work": 1000,
        "results": 1000,
    }
    assert retain.publication_need(1000, source_group="disk", target_group="disk") == {"disk": 2000}
    assert retain.publication_need(0, source_group="a", target_group="b") == {"a": 0, "b": 0}


@pytest.mark.parametrize("size", [-1, 1.5, True, "1"])
def test_a_publication_need_is_a_byte_count(size: object) -> None:
    with pytest.raises(ValueError):
        retain.publication_need(size, source_group="a", target_group="b")  # type: ignore[arg-type]


# -- the result --------------------------------------------------------------------------------


def test_a_publication_result_gives_the_artifact_to_reference() -> None:
    data = proof_bytes(64)
    request = retain.retain_request(NODE_ID, proof(data))
    outcome = retain.retain_result(request, PublishValue(request.artifact, reused=False))
    assert outcome == retain.Published(request.artifact, reused=False)
    reused = retain.retain_result(request, PublishValue(request.artifact, reused=True))
    assert reused == retain.Published(request.artifact, reused=True)


def test_a_result_for_another_artifact_is_refused() -> None:
    request = retain.retain_request(NODE_ID, proof(b"a"))
    other = Artifact(f"proofs/{NODE_ID}-{sha(b'b')}.lrat", sha(b"b"), 1)
    with pytest.raises(ContractError) as caught:
        retain.retain_result(request, PublishValue(other, reused=False))
    assert caught.value.rule == "retain.mismatch"


def test_retain_result_is_only_for_retained_publications() -> None:
    request = retain.publication_request(Area.QUARANTINE, NODE_ID, proof(b"a"))
    with pytest.raises(ValueError):
        retain.retain_result(request, PublishValue(request.artifact, reused=False))


@pytest.mark.parametrize(
    ("error", "fatal", "exit_code"),
    [
        (ResourceError("io.no_space", "ENOSPC"), False, 1),
        (IntegrityError("artifact.conflict", "other bytes"), False, 4),
        (ToolError("io.source_changed", "grew"), False, 5),
        (ToolError("io.hash_mismatch", "other bytes"), False, 5),
        (ToolError("io.service_failed", "stopped"), True, 5),
    ],
)
def test_a_failed_retained_publication_blocks_without_a_record(
    error: ToolError, fatal: bool, exit_code: int
) -> None:
    request = retain.retain_request(NODE_ID, proof(b"p"))
    outcome = retain.retain_result(request, Failure.of(error, fatal=fatal))
    assert isinstance(outcome, retain.RetainBlocked)
    assert (outcome.kind, outcome.rule, outcome.fatal) == (error.kind, error.rule, fatal)
    assert outcome.exit_code == exit_code
    diagnostic = outcome.diagnostic()
    assert diagnostic[retain.RETAIN_BLOCKED]["rule"] == error.rule
    assert diagnostic[retain.RETAIN_BLOCKED]["kind"] == error.kind
    assert error.rule in outcome.note


def test_retain_full_before_any_copy_is_a_resource_block() -> None:
    blocked = retain.RetainBlocked.full("results: 10 bytes free, 1000 needed")
    assert (blocked.kind, blocked.rule, blocked.fatal, blocked.exit_code) == (
        "resource",
        "retain.full",
        False,
        1,
    )
    assert "1000 needed" in blocked.detail


def test_diagnostic_text_is_bounded() -> None:
    request = retain.retain_request(NODE_ID, proof(b"p"))
    failure = Failure.of(ToolError("io.write", "x" * 10_000), fatal=False)
    outcome = retain.retain_result(request, failure)
    assert isinstance(outcome, retain.RetainBlocked)
    assert len(outcome.detail) <= 300
    assert len(outcome.note) <= 400


# -- through the I/O service ----------------------------------------------------------------------


def test_a_retained_proof_is_published_durably_and_the_source_is_kept(tmp_path: Path) -> None:
    env = Env(tmp_path)
    try:
        data = proof_bytes(3 * CHUNK + 5)
        sealed = env.source(A1, data)
        request = retain.retain_request(NODE_ID, sealed)
        outcome = retain.retain_result(request, env.publish(A1, request).outcome)  # type: ignore[arg-type]
        assert outcome == retain.Published(request.artifact, reused=False)
        assert env.area_files() == {request.artifact.path: data}
        assert Path(sealed.path).read_bytes() == data  # kept until the cleanup after commit
        assert env.calls.events("link"), "published through a no-replace link"
    finally:
        env.close()


def test_an_existing_equal_artifact_is_reused_not_copied_again(tmp_path: Path) -> None:
    env = Env(tmp_path)
    try:
        data = proof_bytes(2 * CHUNK)
        first = retain.retain_request(NODE_ID, env.source(A1, data))
        assert env.publish(A1, first).ok
        writes_before = len(env.calls.events("write"))
        second = retain.retain_request(NODE_ID, env.source(A2, data))
        outcome = retain.retain_result(second, env.publish(A2, second).outcome)  # type: ignore[arg-type]
        assert outcome == retain.Published(second.artifact, reused=True)
        assert len(env.calls.events("write")) == writes_before
        assert env.area_files() == {second.artifact.path: data}
    finally:
        env.close()


def test_an_existing_unequal_artifact_is_never_overwritten_and_blocks(tmp_path: Path) -> None:
    env = Env(tmp_path)
    try:
        data = proof_bytes(CHUNK)
        request = retain.retain_request(NODE_ID, env.source(A1, data))
        final = env.results / request.artifact.path
        final.parent.mkdir(parents=True, exist_ok=True)
        final.write_bytes(b"other bytes under the checked name")
        outcome = retain.retain_result(request, env.publish(A1, request).outcome)  # type: ignore[arg-type]
        assert isinstance(outcome, retain.RetainBlocked)
        assert (outcome.rule, outcome.exit_code) == ("artifact.conflict", 4)
        assert final.read_bytes() == b"other bytes under the checked name"
    finally:
        env.close()


@pytest.mark.parametrize("where", ["precheck", "write"])
def test_enospc_blocks_retain_and_leaves_no_partial_copy(tmp_path: Path, where: str) -> None:
    data = proof_bytes(4 * CHUNK)
    if where == "precheck":
        calls = FaultCalls(free_bytes=len(data) - 1)
    else:
        calls = FaultCalls(faults={"write": _fail_writes_to_staging(errno.ENOSPC)})
    env = Env(tmp_path, calls=calls)
    try:
        sealed = env.source(A1, data)
        request = retain.retain_request(NODE_ID, sealed)
        outcome = retain.retain_result(request, env.publish(A1, request).outcome)  # type: ignore[arg-type]
        assert isinstance(outcome, retain.RetainBlocked)
        assert (outcome.kind, outcome.rule, outcome.exit_code) == ("resource", "io.no_space", 1)
        assert env.area_files() == {}
        assert Path(sealed.path).read_bytes() == data  # the evidence is preserved
        assert len(env.attempts()) == 0
    finally:
        env.close()


def _fail_writes_to_staging(code: int) -> Callable[..., Any]:
    """Every publication write fails (the journal writes through its own calls)."""

    def fault(number: int, fd: int, data: bytes) -> None:
        del number, fd, data
        raise OSError(code, os.strerror(code))

    return fault
