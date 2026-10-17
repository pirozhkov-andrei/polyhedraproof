"""Journal reader (evidence.journal): corpus cases, validation order, limits, state.

The corpus cases name the first violated rule and its kind for whole certify runs. The
reader owns the journal-level rules that one journal decides; rules that need bundles,
admission or several journals (attempt.cnf_sha256, attempt.model_false, success.*,
journal.fork, journal.worker) belong to the certifier and must not be reported here.
"""

from __future__ import annotations

import hashlib
import io
import json
import random
import tracemalloc
from collections.abc import Callable, Iterator
from typing import Any

import cp_journal_support as sup
import pytest
from cp_journal_support import read_journal

from cubeproof.base.errors import (
    CubeproofError,
    InputError,
    IntegrityError,
    ResourceError,
)
from cubeproof.base.settings import ReaderLimits
from cubeproof.contracts.enums import RecordType
from cubeproof.evidence.journal import (
    Anchor,
    JournalReader,
    JournalSummary,
)
from cubeproof.evidence.journal import reader as journal_reader
from cubeproof.evidence.schema import Attempt, Header, JournalContext, Record, Resume

ALL3 = "campaigns/all3/campaign.json"
KIND = {"integrity": IntegrityError, "input": InputError, "resource": ResourceError}


def _journal_cases() -> list[dict[str, Any]]:
    return [c for c in sup.cases() if c["journals"]]


def _read(data: bytes, **options: Any) -> Any:
    return read_journal(io.BytesIO(data), name="w", **options)


def _error(data: bytes, **options: Any) -> CubeproofError:
    with pytest.raises(CubeproofError) as info:
        _read(data, **options)
    return info.value


@pytest.mark.parametrize("case", _journal_cases(), ids=[c["id"] for c in _journal_cases()])
def test_corpus_cases(case: dict[str, Any]) -> None:
    context = sup.campaign_context(case["campaign"])
    outcomes: dict[str, CubeproofError | None] = {}
    for relative in case["journals"]:
        try:
            read_journal(sup.CORPUS / relative, context=context)
            outcomes[relative] = None
        except CubeproofError as error:
            outcomes[relative] = error
    expect = case["expect"]
    expected = expect.get("error")
    if expected is None or expected["rule"] in sup.DELEGATED_RULES:
        assert all(v is None for v in outcomes.values()), outcomes
        return
    assert expected["rule"] in sup.JOURNAL_READER_RULES, expected
    failed = [e for e in outcomes.values() if e is not None]
    assert failed, outcomes
    for found in failed:
        assert found.rule == expected["rule"], outcomes
        assert type(found) is KIND[expected["kind"]], outcomes


def test_corpus_summaries_match_the_expected_certificates() -> None:
    checked = 0
    for case in _journal_cases():
        expect = case["expect"]
        if "certificate" not in expect:
            continue
        context = sup.campaign_context(case["campaign"])
        summaries = [
            read_journal(sup.CORPUS / rel, context=context).summary for rel in case["journals"]
        ]
        certificate = sup.load_json(expect["certificate"])
        for entry in certificate["journals"]:
            copies = [s for s in summaries if s.id == entry["id"]]
            longest = max(copies, key=lambda s: s.records)
            assert longest.records == entry["records"]
            assert longest.bytes == entry["bytes"]
            assert longest.head == entry["head"]
            assert longest.worker == entry["worker"]
            torn = min(s.torn_tail_bytes for s in copies if s.records == longest.records)
            assert torn == entry["torn_tail_bytes"]
            checked += 1
    assert checked >= 20


def test_audit_plan_journals_are_structurally_valid() -> None:
    # audit.* plan rules belong to the audit; the reader accepts the records.
    for plan in sup.load_json("cases.json")["audit_plans"]:
        context = sup.campaign_context(plan["campaign"])
        contents = read_journal(sup.CORPUS / plan["journal"], context=context)
        assert contents.summary.purpose == "audit"


def test_torn_tail_summary() -> None:
    data = sup.corpus_bytes("journals/torn_tail/w1.jsonl")
    end = data.rindex(b"\n") + 1
    contents = _read(data, context=sup.campaign_context(ALL3))
    summary = contents.summary
    assert isinstance(summary, JournalSummary)
    assert summary.records == data.count(b"\n") == len(contents.records)
    assert summary.bytes == end
    assert summary.torn_tail_bytes == len(data) - end > 0
    assert summary.torn_tail_sha256 == hashlib.sha256(data[end:]).hexdigest()
    assert summary.id == contents.records[0].self_hash
    assert summary.head == contents.records[-1].self_hash
    assert summary.anchor == Anchor(summary.id, summary.records - 1, summary.head, end)


def test_records_are_typed_and_in_order() -> None:
    data = sup.corpus_bytes("journals/modes/w1.jsonl")
    contents = _read(data)
    types = [r.type for r in contents.records]
    assert types[0] is RecordType.HEADER
    assert isinstance(contents.records[0].payload, Header)
    assert isinstance(contents.records[1].payload, Resume)
    assert [r.seq for r in contents.records] == list(range(len(types)))
    assert b"".join(r.line + b"\n" for r in contents.records) == data


def test_location_names_the_file_and_line() -> None:
    error = _error(sup.corpus_bytes("journals/x_journal_seq/w1.jsonl"))
    assert error.rule == "journal.seq"
    assert error.location is not None
    assert error.location.startswith("w:")
    line = int(error.location.split(":")[1])
    assert 1 <= line <= 5


# -- validation order ------------------------------------------------------------------------------


def _base_records() -> list[dict[str, Any]]:
    return sup.records_of(sup.corpus_bytes("journals/base/w1.jsonl"))


def test_no_header() -> None:
    for data in (b"", b'{"format":"cubeproof-journal-1"', b"x" * 100):
        error = _error(data)
        assert (type(error), error.rule) == (InputError, "journal.no_header")


def test_header_must_be_first_and_unique() -> None:
    records = _base_records()
    error = _error(sup.chain(records[1:]))
    assert (type(error), error.rule, error.location) == (IntegrityError, "journal.header", "w:1")
    error = _error(sup.chain([*records, records[0]]))
    assert (error.rule, error.location) == ("journal.header", f"w:{len(records) + 1}")


def test_campaign_of_the_header_is_an_input_error_only_with_a_context() -> None:
    records = _base_records()
    data = sup.chain(records)
    other = JournalContext("e" * 64, sup.campaign_context(ALL3).variables)
    error = _error(data, context=other)
    assert (type(error), error.rule, error.location) == (InputError, "journal.campaign", "w:1")
    assert _read(data).summary.records == len(records)


def test_chain_errors_are_reported_before_earlier_record_rule_errors() -> None:
    """Self, seq and prev of every complete line come before record rules."""
    records = _base_records()
    broken = [dict(r) for r in records]
    attempt = next(i for i, r in enumerate(broken) if r["type"] == "attempt")
    broken[attempt]["node_id"] = "f" * 64  # record.node_id, but chain intact after re-signing
    data = sup.chain(broken)
    error = _error(data)
    assert (error.rule, error.location) == ("record.node_id", f"w:{attempt + 1}")
    # Same journal with a later line whose self is broken: journal.self wins.
    lines = sup.lines_of(data)
    last = json.loads(lines[-1])
    last["utc"] = "2026-10-01T00:00:09.000Z"
    lines[-1] = sup.j(last)
    tampered = b"".join(line + b"\n" for line in lines)
    error = _error(tampered)
    assert (error.rule, error.location) == ("journal.self", f"w:{len(lines)}")
    assert isinstance(error, IntegrityError)


def test_reader_yields_records_only_up_to_the_first_invalid_one() -> None:
    records = _base_records()
    broken = [dict(r) for r in records]
    broken[2]["node_id"] = "f" * 64
    reader = JournalReader(io.BytesIO(sup.chain(broken)), sup.records(), name="w")
    seen: list[Record] = []
    with pytest.raises(IntegrityError) as info:
        for record in reader:
            seen.append(record)
    assert info.value.rule == "record.node_id"
    assert [r.seq for r in seen] == [0, 1]


def test_self_seq_prev_order_within_a_line() -> None:
    records = _base_records()
    good = sup.chain(records)
    lines = sup.lines_of(good)
    value = json.loads(lines[2])
    # seq wrong but re-signed: journal.seq.
    lines_seq = list(lines)
    lines_seq[2] = sup.j(sup.sign({**value, "seq": 7}))
    error = _error(b"".join(x + b"\n" for x in lines_seq))
    assert (error.rule, error.location) == ("journal.seq", "w:3")
    # prev wrong but re-signed: journal.prev.
    lines_prev = list(lines)
    lines_prev[2] = sup.j(sup.sign({**value, "prev": "a" * 64}))
    error = _error(b"".join(x + b"\n" for x in lines_prev))
    assert (error.rule, error.location) == ("journal.prev", "w:3")
    # both wrong and self broken: self first.
    lines_all = list(lines)
    lines_all[2] = sup.j({**value, "seq": 7, "prev": "a" * 64})
    error = _error(b"".join(x + b"\n" for x in lines_all))
    assert error.rule == "journal.self"
    # schema before self.
    lines_schema = list(lines)
    lines_schema[2] = sup.j({**value, "extra": 1})
    error = _error(b"".join(x + b"\n" for x in lines_schema))
    assert (error.rule, error.location) == ("schema", "w:3")


def test_purpose_rules() -> None:
    records = _base_records()
    audit_ready = {
        "format": "cubeproof-journal-1",
        "type": "audit_ready",
        "utc": "2026-10-01T00:00:09.000Z",
        "targets_sha256": "0" * 64,
        "target_count": 0,
    }
    error = _error(sup.chain([*records, audit_ready]))
    assert (error.rule, type(error)) == ("journal.purpose", IntegrityError)
    header = {**records[0], "purpose": "audit"}
    split = next(r for r in records if r["type"] == "split")
    error = _error(sup.chain([header, split]))
    assert (error.rule, error.location) == ("journal.purpose", "w:2")
    attempts = [r for r in records if r["type"] == "attempt"]
    assert _read(sup.chain([header, *attempts, audit_ready])).summary.purpose == "audit"


def test_attempt_policy_follows_the_latest_snapshot() -> None:
    records = _base_records()
    header = records[0]
    policy = dict(header["policy"])
    policy["tool_retries"] = 7
    resume = {
        "format": "cubeproof-journal-1",
        "type": "resume",
        "utc": "2026-10-01T00:00:05.000Z",
        "machinery": header["machinery"],
        "policy": policy,
        "resources": header["resources"],
    }
    attempt = next(r for r in records if r["type"] == "attempt")
    error = _error(sup.chain([header, resume, attempt]))
    assert (error.rule, error.location) == ("attempt.policy_sha256", "w:3")
    rehashed = {**attempt, "policy_sha256": hashlib.sha256(sup.j(policy)).hexdigest()}
    contents = _read(sup.chain([header, resume, rehashed]))
    assert sup.sequence_of(contents).snapshot == contents.records[1].payload


def test_committed_identifiers_are_recognized() -> None:
    data = sup.corpus_bytes("journals/frontier/w1.jsonl")
    contents = _read(data)
    state = sup.sequence_of(contents)
    for record in contents.records:
        payload = record.payload
        if isinstance(payload, Attempt):
            assert state.committed_attempt(payload.attempt_id) == record.seq
        if record.type is RecordType.HANDOFF:
            request_id = record.to_json()["request"]["request_id"]
            assert state.committed_request(request_id) == record.seq
    assert state.committed_attempt("0" * 32) is None
    assert state.committed_request("0" * 32) is None


def test_duplicate_attempt_and_request_ids() -> None:
    records = _base_records()
    attempt = next(r for r in records if r["type"] == "attempt")
    error = _error(sup.chain([*records, attempt]))
    assert (error.rule, error.location) == ("attempt.attempt_id", f"w:{len(records) + 1}")


# -- extra rules hook (certifier/binding) ----------------------------------------------------------


class _Hooks:
    def __init__(self) -> None:
        self.calls: list[tuple[str, int, str]] = []

    def attempt_record(self, record: Record, snapshot: Header | Resume) -> str | None:
        self.calls.append(("record", record.seq, snapshot.policy.sha256))
        return None

    def attempt_context(self, record: Record, snapshot: Header | Resume) -> str | None:
        self.calls.append(("context", record.seq, snapshot.policy.sha256))
        return "attempt.cnf_sha256" if record.seq == 4 else None


def test_extra_rules_run_in_place_and_fail_as_integrity_errors() -> None:
    data = sup.corpus_bytes("journals/base/w1.jsonl")
    hooks = _Hooks()
    error = _error(data, extra=hooks)
    assert (type(error), error.rule, error.location) == (
        IntegrityError,
        "attempt.cnf_sha256",
        "w:5",
    )
    policy = json.loads(sup.lines_of(data)[0])["policy"]
    expected_policy = hashlib.sha256(sup.j(policy)).hexdigest()
    assert hooks.calls[:2] == [("record", 2, expected_policy), ("context", 2, expected_policy)]
    assert [c[1] for c in hooks.calls] == [2, 2, 3, 3, 4, 4]


# -- bounded line reads ----------------------------------------------------------------------------


def test_line_limit_is_a_resource_error_for_complete_lines() -> None:
    data = sup.corpus_bytes("journals/base/w1.jsonl")
    longest = max(len(line) for line in sup.lines_of(data))
    assert _read(data, limits=ReaderLimits(line_bytes=longest)).summary.records == 5
    error = _error(data, limits=ReaderLimits(line_bytes=longest - 1))
    assert (type(error), error.rule) == (ResourceError, "limit.line")


def test_an_oversized_torn_tail_is_still_a_torn_tail() -> None:
    data = sup.corpus_bytes("journals/base/w1.jsonl")
    tail = b"x" * 5000
    summary = _read(data + tail, limits=ReaderLimits(line_bytes=4096)).summary
    assert summary.torn_tail_bytes == 5000
    assert summary.torn_tail_sha256 == hashlib.sha256(tail).hexdigest()
    assert summary.records == 5


class _Zeros(io.RawIOBase):
    """A stream of ``size`` bytes of b"x" produced on demand (never held whole)."""

    def __init__(self, prefix: bytes, size: int, suffix: bytes = b"") -> None:
        self._prefix = prefix
        self._size = size
        self._suffix = suffix
        self._position = 0
        self.largest_request = 0

    def readable(self) -> bool:
        return True

    def _segment(self, start: int, stop: int) -> bytes:
        """Bytes ``[start, stop)`` of prefix + x * size + suffix."""
        middle = len(self._prefix) + self._size
        parts = [self._prefix[start:stop]]
        low, high = max(start, len(self._prefix)), min(stop, middle)
        if high > low:
            parts.append(b"x" * (high - low))
        parts.append(self._suffix[max(start, middle) - middle : max(stop, middle) - middle])
        return b"".join(parts)

    def readinto(self, buffer: Any) -> int:
        view = memoryview(buffer)
        self.largest_request = max(self.largest_request, len(view))
        total = len(self._prefix) + self._size + len(self._suffix)
        stop = min(self._position + len(view), total)
        data = self._segment(self._position, stop)
        view[: len(data)] = data
        self._position = stop
        return len(data)


def _chunks(stream: Any) -> Iterator[bytes]:
    while chunk := stream.read(1 << 16):
        yield chunk


def test_the_generated_stream_is_what_it_claims() -> None:
    prefix = b"abc"
    stream = io.BufferedReader(_Zeros(prefix, 1000, b"\nz"))
    assert b"".join(_chunks(stream)) == prefix + b"x" * 1000 + b"\nz"


def test_reading_memory_is_bounded_by_the_line_limit() -> None:
    prefix = sup.corpus_bytes("journals/base/w1.jsonl")
    size = 48 * 1024 * 1024
    stream = _Zeros(prefix, size)
    tracemalloc.start()
    try:
        summary = read_journal(
            io.BufferedReader(stream), name="w", limits=ReaderLimits(line_bytes=1 << 20)
        ).summary
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert summary.torn_tail_bytes == size
    assert peak < 12 * 1024 * 1024, peak


def test_an_oversized_complete_line_fails_without_holding_it() -> None:
    prefix = sup.corpus_bytes("journals/base/w1.jsonl")
    stream = _Zeros(prefix, 24 * 1024 * 1024, b"\n")
    tracemalloc.start()
    try:
        with pytest.raises(ResourceError) as info:
            read_journal(
                io.BufferedReader(stream), name="w", limits=ReaderLimits(line_bytes=1 << 20)
            )
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert (info.value.rule, info.value.location) == ("limit.line", "w:6")
    assert peak < 12 * 1024 * 1024, peak


def test_read_journal_accepts_a_path(tmp_path: Any) -> None:
    data = sup.corpus_bytes("journals/base/w1.jsonl")
    path = tmp_path / "w1.jsonl"
    path.write_bytes(data)
    summary = read_journal(path).summary
    assert summary.bytes == len(data)
    error = _error(sup.corpus_bytes("journals/x_journal_prev/w1.jsonl"))
    assert error.rule == "journal.prev"


def test_a_retained_artifact_outside_retain_mode_is_an_integrity_error() -> None:
    values = sup.records_of(sup.corpus_bytes("journals/modes/w1.jsonl"))
    at = next(i for i, v in enumerate(values) if v.get("retained") is not None)
    assert values[at]["proof_mode"] == "retain" and values[at]["outcome"] == "VERIFIED_UNSAT"
    assert _read(sup.chain(values)).summary.records == len(values)
    values[at] = {**values[at], "proof_mode": "transient"}
    error = _error(sup.chain(values))
    assert (type(error), error.rule, error.location) == (
        IntegrityError,
        "attempt.retained",
        f"w:{at + 1}",
    )


# -- read sizes and chunk boundaries ---------------------------------------------------------------
#
# Whether bytes form a complete line or a torn tail depends only on the bytes, never on how
# reads split them (specification §7.1). The sources below return short reads of chosen sizes; the
# reader's chunk size is also lowered so that every LF of a journal falls on a chunk boundary.


class _Trickle:
    """A byte source returning at most ``next_size()`` (>= 1) bytes per read."""

    def __init__(self, data: bytes, next_size: Callable[[], int]) -> None:
        self._data = data
        self._position = 0
        self._next_size = next_size
        self.reads = 0

    def read(self, size: int = -1, /) -> bytes:
        want = self._next_size()
        assert want >= 1
        if size >= 0:
            want = min(want, size)
        chunk = self._data[self._position : self._position + want]
        self._position += len(chunk)
        self.reads += 1
        return chunk


def _boundary_cases() -> dict[str, tuple[bytes, ReaderLimits]]:
    base = sup.corpus_bytes("journals/base/w1.jsonl")
    longest = max(len(line) for line in sup.lines_of(base))
    small = ReaderLimits(line_bytes=longest + 10)
    default = ReaderLimits()
    return {
        "base": (base, default),
        "frontier": (sup.corpus_bytes("journals/frontier/w1.jsonl"), default),
        "torn_tail": (sup.corpus_bytes("journals/torn_tail/w1.jsonl"), default),
        "one_byte_tail": (base + b"{", default),
        "short_tail": (base + b'{"x', default),
        "overlong_tail": (base + b"y" * (longest + 200), small),
        "overlong_line": (base + b"y" * (longest + 200) + b"\n", small),
        "overlong_line_then_tail": (base + b"y" * (longest + 200) + b"\nz", small),
        "corrupt_last_line": (base + b"{}\n", default),
        "broken_prev": (sup.corpus_bytes("journals/x_journal_prev/w1.jsonl"), default),
        "torn_header": (base[:40], default),
        "lf_only": (b"\n", default),
    }


def _outcome(read: Callable[[], Any]) -> tuple[Any, ...]:
    """The summary and lines of a read, or the error's kind, rule and location."""
    try:
        contents = read()
    except CubeproofError as error:
        return ("error", type(error), error.rule, error.location)
    return ("ok", contents.summary, tuple(r.line for r in contents.records))


def _reference(data: bytes, limits: ReaderLimits) -> tuple[Any, ...]:
    return _outcome(lambda: _read(data, limits=limits))


def test_the_boundary_references_are_what_they_claim() -> None:
    cases = _boundary_cases()
    base = _reference(*cases["base"])
    assert base[0] == "ok" and base[1].records == 5 and base[1].torn_tail_bytes == 0
    for name, torn in (("one_byte_tail", 1), ("short_tail", 3)):
        outcome = _reference(*cases[name])
        assert outcome[0] == "ok" and outcome[1].torn_tail_bytes == torn
        assert outcome[1].records == 5
    overlong_tail = _reference(*cases["overlong_tail"])
    assert overlong_tail[0] == "ok" and overlong_tail[1].torn_tail_bytes > 0
    assert _reference(*cases["overlong_line"])[1:3] == (ResourceError, "limit.line")
    assert _reference(*cases["overlong_line_then_tail"])[1:3] == (ResourceError, "limit.line")
    assert _reference(*cases["corrupt_last_line"])[1] is IntegrityError
    assert _reference(*cases["broken_prev"])[2] == "journal.prev"
    assert _reference(*cases["torn_header"])[1:3] == (InputError, "journal.no_header")
    assert _reference(*cases["lf_only"])[0] == "error"


#: Read sizes: fixed, or seeded random choices (seed, sizes).
_SCHEDULES: dict[str, int | tuple[int, tuple[int, ...]]] = {
    "1": 1,
    "2": 2,
    "3": 3,
    "7": 7,
    "64": 64,
    "random-0": (0, tuple(range(1, 98))),
    "random-1": (1, (1, 2, 3, 100, 1000, 4096)),
    "random-2": (2, (1, 1, 2, 5000)),
}


def _sizes(schedule: str) -> Callable[[], int]:
    plan = _SCHEDULES[schedule]
    if isinstance(plan, int):
        fixed: int = plan
        return lambda: fixed
    seed, choices = plan
    generator = random.Random(seed)
    return lambda: generator.choice(choices)


@pytest.mark.parametrize("schedule", list(_SCHEDULES))
def test_short_reads_give_the_same_result(schedule: str) -> None:
    for name, (data, limits) in _boundary_cases().items():
        source = _Trickle(data, _sizes(schedule))

        def read(source: _Trickle = source, limits: ReaderLimits = limits) -> Any:
            return read_journal(source, name="w", limits=limits)

        outcome = _outcome(read)
        assert outcome == _reference(data, limits), (schedule, name)
        if schedule == "1" and outcome[0] == "ok":  # every byte arrived in its own read
            assert source.reads > len(data)


@pytest.mark.parametrize("name", list(_boundary_cases()))
def test_every_lf_on_a_chunk_boundary_gives_the_same_result(
    monkeypatch: pytest.MonkeyPatch, name: str
) -> None:
    data, limits = _boundary_cases()[name]
    reference = _reference(data, limits)
    lfs = [i for i, byte in enumerate(data) if byte == 0x0A]
    # chunk = i: the LF at i starts the second read; chunk = i + 1: it ends the first one.
    sizes = sorted({size for i in lfs for size in (i, i + 1) if size > 0} | {1, 2, 3})
    for size in sizes:
        monkeypatch.setattr(journal_reader, "CHUNK_BYTES", size)
        assert _reference(data, limits) == reference, (name, size)
