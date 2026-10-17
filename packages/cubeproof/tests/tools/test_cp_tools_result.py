"""ProcessResult, CheckerCheck and bounded output draining (specification §4.6, §6.2; process.*
rules).

The record value of a child process has exactly the specification §4.6 fields; exit and signal are
exclusive, a process that did not start has neither, tails are at most 16 KiB of UTF-8.
``OutputTail`` keeps the last bytes of an output stream in bounded memory while counting all
of them; its text is never longer than the limit, and ``truncated`` is true whenever a byte
of the stream is not represented in the tail.
"""

from __future__ import annotations

import pytest

from cubeproof.base.errors import ContractError
from cubeproof.base.process import (
    TAIL_BYTES,
    Cause,
    CheckerCheck,
    OutputTail,
    ProcessResult,
    decode_tail,
)
from cubeproof.evidence.schema import values as schema

FIELDS = (
    "started",
    "exit",
    "signal",
    "elapsed_ms",
    "stdout_tail",
    "stderr_tail",
    "stdout_bytes",
    "stdout_truncated",
    "cause",
    "conflicts",
)


def make(**changes: object) -> ProcessResult:
    values: dict[str, object] = {
        "started": True,
        "exit": 0,
        "signal": None,
        "elapsed_ms": 5,
        "stdout_tail": "s VERIFIED UNSAT\n",
        "stderr_tail": "",
        "stdout_bytes": 17,
        "stdout_truncated": False,
        "cause": None,
        "conflicts": None,
    }
    values.update(changes)
    return ProcessResult(**values)  # type: ignore[arg-type]


def test_fields_are_exactly_those_of_the_specification() -> None:
    assert tuple(make().to_json()) == FIELDS


def test_round_trip_through_the_journal_schema_value() -> None:
    for value in (
        make(),
        make(exit=None, signal=9, cause="deadline"),
        make(started=False, exit=None, cause="launch", stdout_tail="", stdout_bytes=0),
        make(exit=20, conflicts=123, stdout_tail="s UNSATISFIABLE\n", stdout_bytes=16),
    ):
        recorded = schema.ProcessResult.from_json(value.to_json())
        assert recorded.to_json() == value.to_json()
    check = CheckerCheck(result=make(), heap_mib=512, stack_mib=256)
    assert schema.CheckerCheck.from_json(check.to_json()).to_json() == check.to_json()


@pytest.mark.parametrize(
    ("changes", "rule"),
    [
        ({"exit": 0, "signal": 9}, "process.exit_signal"),
        ({"started": False, "exit": 0}, "process.not_started"),
        ({"started": False, "exit": None, "signal": 15}, "process.not_started"),
        ({"stdout_tail": "x" * (TAIL_BYTES + 1)}, "process.tail_size"),
        ({"stderr_tail": "é" * (TAIL_BYTES // 2 + 1)}, "process.tail_size"),
        ({"exit": 256}, "schema"),
        ({"exit": -1}, "schema"),
        ({"signal": 0, "exit": None}, "schema"),
        ({"elapsed_ms": -1}, "schema"),
        ({"stdout_bytes": -1}, "schema"),
        ({"conflicts": -1}, "schema"),
        ({"started": 1}, "schema"),
        ({"exit": True}, "schema"),
        ({"stdout_truncated": None}, "schema"),
        ({"cause": ""}, "schema"),
        ({"stdout_tail": "\ud800"}, "schema"),
    ],
)
def test_invalid_results_are_refused(changes: dict[str, object], rule: str) -> None:
    with pytest.raises(ContractError) as caught:
        make(**changes)
    assert caught.value.rule == rule


def test_not_started_has_neither_exit_nor_signal() -> None:
    value = ProcessResult.not_started(Cause.LAUNCH, elapsed_ms=3)
    assert value.to_json() == {
        "started": False,
        "exit": None,
        "signal": None,
        "elapsed_ms": 3,
        "stdout_tail": "",
        "stderr_tail": "",
        "stdout_bytes": 0,
        "stdout_truncated": False,
        "cause": "launch",
        "conflicts": None,
    }


def test_checker_check_needs_positive_arenas() -> None:
    for heap, stack in ((0, 1), (1, 0), (-1, 1)):
        with pytest.raises(ContractError):
            CheckerCheck(result=make(), heap_mib=heap, stack_mib=stack)


# -- bounded draining ------------------------------------------------------------------------


def drained(chunks: list[bytes], limit: int = TAIL_BYTES, capture: int = 0) -> OutputTail:
    tail = OutputTail(limit=limit, capture=capture)
    for chunk in chunks:
        tail.feed(chunk)
    return tail


def test_small_output_is_complete_and_exact() -> None:
    tail = drained([b"s VERIFIED", b" UNSAT\n"])
    assert tail.total == 17
    assert tail.text() == ("s VERIFIED UNSAT\n", False)


def test_a_flood_keeps_only_the_last_bytes_and_counts_all() -> None:
    tail = drained([b"c noise\n" * 4096] * 64 + [b"s VERIFIED UNSAT\n"])
    text, truncated = tail.text()
    assert truncated
    assert tail.total == 8 * 4096 * 64 + 17
    assert text.endswith("s VERIFIED UNSAT\n")
    assert len(text.encode()) <= TAIL_BYTES
    assert tail.retained <= TAIL_BYTES


@pytest.mark.parametrize("size", [TAIL_BYTES - 1, TAIL_BYTES, TAIL_BYTES + 1])
def test_truncation_starts_exactly_beyond_the_limit(size: int) -> None:
    text, truncated = drained([b"a" * size]).text()
    assert truncated == (size > TAIL_BYTES)
    assert len(text) == min(size, TAIL_BYTES)


def test_invalid_utf8_never_exceeds_the_limit_and_counts_as_truncated() -> None:
    # Each invalid byte decodes to U+FFFD (3 bytes): the text must be cut, not overflow.
    tail = drained([b"\xff" * TAIL_BYTES])
    text, truncated = tail.text()
    assert len(text.encode()) <= TAIL_BYTES
    assert truncated
    assert tail.total == TAIL_BYTES


def test_decoding_never_produces_surrogates() -> None:
    text, represented = decode_tail(b"\xed\xa0\x80abc", 16)
    assert "\ud800" not in text
    assert text.endswith("abc")
    assert represented == 6


def test_a_cut_inside_a_multibyte_character_is_bounded() -> None:
    data = "é".encode() * TAIL_BYTES
    text, truncated = drained([data]).text()
    assert truncated
    assert len(text.encode()) <= TAIL_BYTES


def test_capture_keeps_the_full_output_only_within_its_bound() -> None:
    small = drained([b"v 1 -2 0\n"], capture=64)
    assert small.captured == b"v 1 -2 0\n"
    big = drained([b"v 1 -2 0\n"] * 10, capture=64)
    assert big.captured is None
    assert big.total == 90
    none = drained([b"x"], capture=0)
    assert none.captured is None


def test_limits_are_validated() -> None:
    for limit, capture in ((0, 0), (-1, 0), (TAIL_BYTES + 1, 0), (16, -1)):
        with pytest.raises(ValueError):
            OutputTail(limit=limit, capture=capture)
