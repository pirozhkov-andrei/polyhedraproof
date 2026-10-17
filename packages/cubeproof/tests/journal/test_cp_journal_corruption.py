"""Corruption, torn suffixes and external anchors (specification §7.1).

- Every single-byte corruption of a complete fixture fails the checksum (journal.self) or
  syntax/schema, except the final LF: losing it turns the last record into a torn tail,
  which a reader without an anchor cannot tell from an interrupted append.
- Every torn suffix length is handled: a nonempty suffix without LF after a valid prefix is a
  torn tail (ignored and reported with length and hash); no complete line is no_header.
- Removing complete records from the end, or replacing the last record by another validly
  chained one, is undetectable from the file alone (self is not a signature). Only a trusted
  external anchor (journal ID, seq, head, byte offset) detects it.
"""

from __future__ import annotations

import hashlib
import io
from typing import Any

import cp_journal_support as sup
import pytest
from cp_journal_support import read_journal

from cubeproof.base.errors import CubeproofError, InputError, IntegrityError
from cubeproof.evidence.journal import Anchor

ALL3 = "campaigns/all3/campaign.json"
FIXTURES = {
    "pilot_root": ("journals/pilot_root/w1.jsonl", "campaigns/pilot/campaign.json"),
    "base": ("journals/base/w1.jsonl", ALL3),
    "frontier": ("journals/frontier/w1.jsonl", None),
}
CORRUPTION_RULES = {
    "json.utf8",
    "json.syntax",
    "json.canonical",
    "json.duplicate_key",
    "json.number",
    "json.integer_range",
    "json.surrogate",
    "schema",
    "journal.self",
}


def _context(name: str) -> Any:
    campaign = FIXTURES[name][1]
    return sup.campaign_context(campaign) if campaign else None


def _data(name: str) -> bytes:
    return sup.corpus_bytes(FIXTURES[name][0])


def _outcome(data: bytes, **options: Any) -> Any:
    try:
        return read_journal(io.BytesIO(data), name="w", **options).summary
    except CubeproofError as error:
        return error


def _check_corruption(name: str, data: bytes, position: int, value: int, full: Any) -> None:
    corrupted = bytearray(data)
    corrupted[position] = value
    outcome = _outcome(bytes(corrupted), context=_context(name))
    if position == len(data) - 1:
        # The final LF: the last record becomes a torn tail (visible, but not an error).
        assert not isinstance(outcome, CubeproofError), outcome
        assert outcome.records == full.records - 1
        assert outcome.torn_tail_bytes == len(data) - data.rindex(b"\n", 0, -1) - 1
        anchored = _outcome(bytes(corrupted), anchor=full.anchor)
        assert isinstance(anchored, IntegrityError)
        assert anchored.rule == "journal.anchor"
        return
    assert isinstance(outcome, IntegrityError), (position, value, outcome)
    assert outcome.rule in CORRUPTION_RULES, (position, value, outcome)


# Tiers: every byte of the small fixtures in the fast tier, every bit and every
# byte value in the slow tier (several minutes, about 1 ms per journal read).
FAST = ["pilot_root", "base"]
SLOW = [pytest.param(name, marks=pytest.mark.slow) for name in sorted(FIXTURES)]


@pytest.mark.parametrize("name", FAST)
def test_every_byte_position_with_one_bit_flip(name: str) -> None:
    data = _data(name)
    full = read_journal(io.BytesIO(data), context=_context(name)).summary
    assert full.torn_tail_bytes == 0
    for position in range(len(data)):
        _check_corruption(name, data, position, data[position] ^ (1 << position % 8), full)


@pytest.mark.parametrize("name", SLOW)
def test_every_single_bit_flip_is_detected(name: str) -> None:
    data = _data(name)
    full = read_journal(io.BytesIO(data), context=_context(name)).summary
    assert full.torn_tail_bytes == 0
    for position in range(len(data)):
        for bit in range(8):
            _check_corruption(name, data, position, data[position] ^ (1 << bit), full)


@pytest.mark.slow
def test_every_single_byte_value_is_detected() -> None:
    name = "pilot_root"
    data = _data(name)
    full = read_journal(io.BytesIO(data), context=_context(name)).summary
    for position in range(len(data)):
        for value in range(256):
            if value != data[position]:
                _check_corruption(name, data, position, value, full)


def test_a_sample_of_byte_values_in_the_fast_tier() -> None:
    name = "pilot_root"
    data = _data(name)
    full = read_journal(io.BytesIO(data), context=_context(name)).summary
    for position in range(0, len(data), 7):
        for value in (0x00, 0x0A, 0x20, 0x22, 0x30, 0x39, 0x5C, 0x7B, 0x7D, 0x80, 0xC3, 0xFF):
            if value != data[position]:
                _check_corruption(name, data, position, value, full)


@pytest.mark.parametrize("name", ["pilot_root", *(p for p in SLOW if p.values[0] != "pilot_root")])
def test_every_torn_suffix_length(name: str) -> None:
    data = _data(name)
    full = read_journal(io.BytesIO(data)).summary
    ends = [i + 1 for i, byte in enumerate(data) if byte == 0x0A]
    for length in range(len(data) + 1):
        prefix = data[:length]
        complete = max((e for e in ends if e <= length), default=0)
        outcome = _outcome(prefix, context=_context(name))
        if complete == 0:
            assert isinstance(outcome, InputError), (length, outcome)
            assert outcome.rule == "journal.no_header"
            continue
        assert not isinstance(outcome, CubeproofError), (length, outcome)
        assert outcome.records == ends.index(complete) + 1
        assert outcome.bytes == complete
        assert outcome.torn_tail_bytes == length - complete
        expected = hashlib.sha256(prefix[complete:]).hexdigest() if length > complete else None
        assert outcome.torn_tail_sha256 == expected
        anchored = _outcome(prefix, anchor=full.anchor)
        if length == len(data):
            assert not isinstance(anchored, CubeproofError), anchored
        else:
            assert isinstance(anchored, IntegrityError), (length, anchored)
            assert anchored.rule == "journal.anchor"


def test_full_suffix_removal_is_detected_only_with_an_anchor() -> None:
    data = _data("base")
    full = read_journal(io.BytesIO(data)).summary
    lines = sup.lines_of(data)
    for keep in range(1, len(lines)):
        shorter = b"".join(line + b"\n" for line in lines[:keep])
        alone = _outcome(shorter)
        # The documented limit: a shorter valid journal without torn tail.
        assert not isinstance(alone, CubeproofError)
        assert (alone.records, alone.torn_tail_bytes) == (keep, 0)
        anchored = _outcome(shorter, anchor=full.anchor)
        assert isinstance(anchored, IntegrityError)
        assert anchored.rule == "journal.anchor"
        # An anchor on a record that is still present accepts the shorter copy.
        early = Anchor(full.id, keep - 1, alone.head, alone.bytes)
        assert not isinstance(_outcome(shorter, anchor=early), CubeproofError)
        assert not isinstance(_outcome(data, anchor=early), CubeproofError)


def test_replacement_of_the_last_record_is_detected_only_with_an_anchor() -> None:
    data = _data("base")
    full = read_journal(io.BytesIO(data)).summary
    records = sup.records_of(data)
    replaced = [*records[:-1], {**records[-1], "utc": "2026-10-01T00:00:59.000Z"}]
    forged = sup.chain(replaced)
    kept = data.rindex(b"\n", 0, len(data) - 1) + 1
    assert forged[:kept] == data[:kept]
    assert forged != data
    alone = _outcome(forged)
    assert not isinstance(alone, CubeproofError)
    assert alone.head != full.head
    anchored = _outcome(forged, anchor=full.anchor)
    assert isinstance(anchored, IntegrityError)
    assert anchored.rule == "journal.anchor"


def test_middle_line_corruption_is_an_integrity_error_even_if_resigned() -> None:
    data = _data("base")
    lines = sup.lines_of(data)
    middle = sup.records_of(data)[2]
    lines[2] = sup.j(sup.sign({**middle, "utc": "2026-10-01T00:00:59.000Z"}))
    outcome = _outcome(b"".join(line + b"\n" for line in lines))
    assert isinstance(outcome, IntegrityError)
    assert (outcome.rule, outcome.location) == ("journal.prev", "w:4")


def test_complete_invalid_last_line_is_not_a_torn_tail() -> None:
    data = _data("base")
    for garbage in (b"x", b"{}", b'{"format":', b"\xff"):
        outcome = _outcome(data + garbage + b"\n")
        assert isinstance(outcome, IntegrityError), garbage
        assert outcome.location == "w:6"
        # Without its LF the same bytes are a torn tail.
        torn = _outcome(data + garbage)
        assert not isinstance(torn, CubeproofError)
        assert torn.torn_tail_bytes == len(garbage)


def test_anchor_mismatches() -> None:
    data = _data("base")
    full = read_journal(io.BytesIO(data)).summary
    anchor = full.anchor
    for bad in (
        Anchor("e" * 64, anchor.seq, anchor.head, anchor.offset),
        Anchor(anchor.journal, anchor.seq, "e" * 64, anchor.offset),
        Anchor(anchor.journal, anchor.seq, anchor.head, anchor.offset - 1),
        Anchor(anchor.journal, anchor.seq + 1, anchor.head, anchor.offset),
        Anchor(anchor.journal, anchor.seq - 1, anchor.head, anchor.offset),
    ):
        outcome = _outcome(data, anchor=bad)
        assert isinstance(outcome, IntegrityError), bad
        assert outcome.rule == "journal.anchor"
    assert not isinstance(_outcome(data, anchor=anchor), CubeproofError)
