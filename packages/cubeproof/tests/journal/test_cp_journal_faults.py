"""Further failure paths of journal storage and the reader (specification §7.1, §7.5).

They pin behaviour the storage and reader tests do not reach (directory sync failure, lock
failure, oversized records at append, anchors of tiny files, error details, non-blocking sources,
context validation).
"""

from __future__ import annotations

import errno
import fcntl
import hashlib
import io
import json
import os
from collections.abc import Iterator
from dataclasses import replace
from pathlib import Path
from typing import Any

import cp_journal_support as sup
import pytest
from cp_journal_support import read_journal

from cubeproof.base.errors import (
    ConfigurationError,
    ContractError,
    CubeproofError,
    InputError,
    IntegrityError,
    ResourceError,
)
from cubeproof.base.settings import ReaderLimits
from cubeproof.contracts.values import JsonObject
from cubeproof.evidence.journal import JournalReader, JournalWriteError, RunLock, capture_anchor
from cubeproof.evidence.schema import (
    Attempt,
    Header,
    JournalContext,
    Record,
    RecordSequence,
    Repair,
    record_problem,
)

UTC = "2026-10-02T00:00:00.000Z"


@pytest.fixture
def run_lock(tmp_path: Path) -> Iterator[RunLock]:
    lock = RunLock.acquire(tmp_path / "run.lock")
    try:
        yield lock
    finally:
        lock.release()


def _records(relative: str = "journals/base/w1.jsonl") -> list[Record]:
    return list(read_journal(sup.CORPUS / relative).records)


def _header(records: list[Record]) -> Header:
    header = records[0].payload
    assert isinstance(header, Header)
    return header


def test_a_failed_directory_sync_fails_creation(tmp_path: Path, run_lock: RunLock) -> None:
    records = _records()
    path = tmp_path / "journal.jsonl"

    def fault(number: int, *args: Any) -> Any:
        if number == 2:  # the file is synced first, then its directory
            raise OSError(errno.EIO, "directory sync failed")
        return None

    calls = sup.TraceCalls(faults={"fsync": fault})
    with pytest.raises(JournalWriteError) as info:
        sup.create(path, _header(records), run_lock=run_lock, utc=records[0].utc, calls=calls)
    assert info.value.rule == "journal.fsync"
    # Recovery re-reads the disk: the header line is there; create refuses, open continues.
    with pytest.raises(ConfigurationError):
        sup.create(path, _header(records), run_lock=run_lock, utc=records[0].utc)
    with sup.open_writer(path, run_lock=run_lock, utc=UTC) as writer:
        assert writer.chain.records == 1


def test_a_lock_failure_is_a_write_failure(tmp_path: Path, run_lock: RunLock) -> None:
    records = _records()
    path = tmp_path / "journal.jsonl"
    armed = {"on": False}

    def fault(number: int, *args: Any) -> Any:
        if armed["on"] and args[1] == fcntl.LOCK_EX:
            raise OSError(errno.ENOLCK, "no locks")
        return None

    calls = sup.TraceCalls(faults={"flock": fault})
    writer = sup.create(path, _header(records), run_lock=run_lock, utc=records[0].utc, calls=calls)
    size = path.stat().st_size
    armed["on"] = True
    with pytest.raises(JournalWriteError) as info:
        writer.append(records[1].payload, utc=records[1].utc)
    assert info.value.rule == "journal.lock"
    assert writer.failed
    assert path.stat().st_size == size
    writer.close()


def test_an_oversized_record_is_refused_before_writing(tmp_path: Path, run_lock: RunLock) -> None:
    records = _records()
    path = tmp_path / "journal.jsonl"
    limit = max(len(r.line) for r in records)
    with sup.create(
        path,
        _header(records),
        run_lock=run_lock,
        utc=records[0].utc,
        limits=ReaderLimits(line_bytes=limit),
    ) as writer:
        attempt = records[2].payload
        assert isinstance(attempt, Attempt)
        fields = {n: getattr(attempt, n) for n in attempt.__dataclass_fields__}
        text = sup.j({"x": "y" * limit}).decode("utf-8")
        big = Attempt(**{**fields, "diagnostics": JsonObject(text)})
        size = path.stat().st_size
        with pytest.raises(ResourceError) as info:
            writer.append(big, utc=UTC)
        assert info.value.rule == "limit.line"
        assert path.stat().st_size == size
        assert not writer.failed
        writer.append(records[1].payload, utc=records[1].utc)


def test_capture_anchor_of_tiny_files(tmp_path: Path, run_lock: RunLock) -> None:
    records = _records()
    path = tmp_path / "journal.jsonl"
    sup.create(path, _header(records), run_lock=run_lock, utc=records[0].utc).close()
    anchor = capture_anchor(path)
    assert (anchor.journal, anchor.seq, anchor.head) == (records[0].self_hash, 0, anchor.journal)
    assert anchor.offset == len(records[0].line) + 1
    for data in (b"", b'{"torn'):
        path.write_bytes(data)
        with pytest.raises(InputError) as info:
            capture_anchor(path)
        assert info.value.rule == "journal.no_header"
    path.write_bytes(b"[1]\n")
    with pytest.raises(IntegrityError) as broken:
        capture_anchor(path)
    assert broken.value.rule == "schema"
    path.write_bytes(b'{"self": 1}\n')
    with pytest.raises(IntegrityError) as noncanonical:
        capture_anchor(path)
    assert noncanonical.value.rule == "json.canonical"


def test_capture_anchor_refuses_an_overlong_last_line(tmp_path: Path, run_lock: RunLock) -> None:
    records = _records()
    path = tmp_path / "journal.jsonl"
    sup.create(path, _header(records), run_lock=run_lock, utc=records[0].utc).close()
    with path.open("ab") as stream:
        stream.write(b"x" * 300 + b"\n")
    with pytest.raises(ResourceError) as info:
        capture_anchor(path, limits=ReaderLimits(line_bytes=200))
    assert info.value.rule == "limit.line"


def test_errors_keep_the_json_location_in_the_detail() -> None:
    data = sup.corpus_bytes("journals/base/w1.jsonl")
    lines = sup.lines_of(data)
    lines[2] = sup.j({**json.loads(lines[2]), "extra": 1})
    with pytest.raises(IntegrityError) as info:
        read_journal(io.BytesIO(b"".join(x + b"\n" for x in lines)), name="w")
    assert (info.value.rule, info.value.location) == ("schema", "w:3")
    assert "$.extra" in info.value.detail


def test_a_nonblocking_source_is_refused() -> None:
    class Empty:
        def read(self, size: int = -1, /) -> bytes | None:
            return None

    with pytest.raises(OSError):
        list(JournalReader(Empty(), RecordSequence(context=None)))


def test_context_and_payload_validation() -> None:
    with pytest.raises(ConfigurationError):
        JournalContext("not a hash")
    with pytest.raises(ConfigurationError):
        JournalContext("a" * 64, {"b" * 64: -1})
    with pytest.raises(ConfigurationError):
        JournalContext("a" * 64, {"B" * 64: 1})
    with pytest.raises(ContractError) as info:
        RecordSequence(context=None).payload_json({"type": "repair"})
    assert info.value.rule == "schema"
    context = JournalContext("a" * 64, {"b" * 64: 3})
    assert dict(context.variables) == {"b" * 64: 3}


def test_the_campaign_context_is_an_explicit_choice() -> None:
    # Without a context the campaign rules are skipped; callers must say so.
    with pytest.raises(TypeError):
        RecordSequence()  # type: ignore[call-arg]
    context = JournalContext("a" * 64, {"b" * 64: 3})
    assert RecordSequence(context=context).context is context
    assert RecordSequence(context=None).context is None


def test_a_lone_surrogate_is_a_typed_error_before_any_byte(
    tmp_path: Path, run_lock: RunLock
) -> None:
    records = _records()
    header = _header(records)
    # a free string of the header: the Python version of the measured runtime
    runtime = replace(header.machinery.runtime, python="3\udc80")
    bad = replace(header, machinery=replace(header.machinery, runtime=runtime))
    path = tmp_path / "journal.jsonl"
    with pytest.raises(CubeproofError) as info:
        sup.create(path, bad, run_lock=run_lock, utc=records[0].utc)
    assert info.value.rule == "json.surrogate"
    assert not path.exists()


def test_unclosed_writer_failure_leaves_the_file_readable(
    tmp_path: Path, run_lock: RunLock
) -> None:
    records = _records()
    path = tmp_path / "journal.jsonl"
    writer = sup.create(path, _header(records), run_lock=run_lock, utc=records[0].utc)
    for record in records[1:3]:
        writer.append(record.payload, utc=record.utc)
    os.truncate(path, path.stat().st_size - 1)  # an outside actor removes the last LF
    with pytest.raises(IntegrityError) as info:
        writer.append(records[3].payload, utc=records[3].utc)
    assert info.value.rule == "journal.tail"
    writer.close()
    summary = read_journal(path).summary
    assert (summary.records, summary.torn_tail_bytes) == (2, len(records[2].line))


# -- further boundary cases of the codec and the storage layer --------------------------------


def _fixture_value(entry_id: str) -> dict[str, Any]:
    entry = next(e for e in sup.documents("journal-record") if e["id"] == entry_id)
    value: dict[str, Any] = json.loads(sup.fixture_bytes(entry))
    return value


def test_the_prev_of_the_header_is_64_zeros() -> None:
    header = sup.records_of(sup.corpus_bytes("journals/base/w1.jsonl"))[0]
    line = sup.j(sup.sign({**header, "prev": "a" * 64}))
    with pytest.raises(IntegrityError) as info:
        read_journal(io.BytesIO(line + b"\n"), name="w")
    assert (info.value.rule, info.value.location) == ("journal.prev", "w:1")


def test_a_repeated_manifest_path_is_not_sorted() -> None:
    value = _fixture_value("record-header")
    machinery = dict(value["machinery"])
    manifest = [machinery["source_manifest"][0], *machinery["source_manifest"]]
    own = [e for e in manifest if e["path"].split("/", 1)[0] == "cubeproof"]
    machinery.update(
        source_manifest=manifest,
        packages_sha256=hashlib.sha256(sup.j(manifest)).hexdigest(),
        cubeproof_sha256=hashlib.sha256(sup.j(own)).hexdigest(),
    )
    assert record_problem({**value, "machinery": machinery}) == "machinery.manifest_order"


def test_shard_node_order_comes_before_the_shard_hash() -> None:
    value = _fixture_value("record-shard")
    shard = dict(value["shard"])
    shard["nodes"] = list(reversed(shard["nodes"]))
    assert record_problem({**value, "shard": shard}) == "shard.nodes"


@pytest.mark.parametrize("entry_id", ["record-shard", "record-handoff", "record-audit-target"])
def test_ranges_of_shard_handoff_and_audit_nodes(entry_id: str) -> None:
    value = _fixture_value(entry_id)
    variables = sup.variables_for(sup.j(value), 3)
    assert record_problem(value, variables) is None
    assert record_problem(value, dict.fromkeys(variables, 0)) == "cube.range"


def test_constructors_store_canonical_values() -> None:
    record = read_journal(sup.CORPUS / "journals/catalogue/w1.jsonl").records[2]
    attempt = record.payload
    assert isinstance(attempt, Attempt)
    fields: dict[str, Any] = {n: getattr(attempt, n) for n in attempt.__dataclass_fields__}
    raw = Attempt(
        **{
            **fields,
            "route": attempt.route.value,
            "outcome": attempt.outcome.value,
            "checks": list(attempt.checks),
            "node": attempt.node.to_json(),
        }
    )
    assert raw == attempt
    assert raw.route is attempt.route
    assert raw.outcome is attempt.outcome
    assert type(raw.checks) is tuple
    assert type(raw.node) is type(attempt.node)


def test_a_directly_built_record_must_carry_its_self() -> None:
    record = read_journal(sup.CORPUS / "journals/base/w1.jsonl").records[1]
    assert Record(record.seq, record.prev, record.self_hash, record.utc, record.payload) == record
    with pytest.raises(ContractError) as info:
        Record(record.seq, record.prev, "f" * 64, record.utc, record.payload)
    assert info.value.rule == "journal.self"
    payload: Any = {"not": "a payload"}
    with pytest.raises(ContractError):
        Record(record.seq, record.prev, record.self_hash, record.utc, payload)


def test_callers_never_append_a_repair(tmp_path: Path, run_lock: RunLock) -> None:
    records = _records()
    path = tmp_path / "journal.jsonl"
    with sup.create(path, _header(records), run_lock=run_lock, utc=records[0].utc) as writer:
        with pytest.raises(ContractError) as info:
            writer.append(Repair(removed_bytes=1, removed_sha256="a" * 64), utc=UTC)
        assert info.value.rule == "journal.session"
        assert writer.chain.records == 1
