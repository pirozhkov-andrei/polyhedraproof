"""Canonical JSON J(x) and the strict document/line readers (specification §4.1)."""

from __future__ import annotations

import hashlib
import json
import random
import sys
from pathlib import Path
from typing import Any

import pytest

from cubeproof.base.canonical_json import (
    INT_MAX,
    document_bytes,
    encode,
    json_sha256,
    parse_document,
    parse_json,
    parse_line,
)
from cubeproof.base.errors import ContractError, ResourceError
from cubeproof.base.settings import DEFAULT_LIMITS, ReaderLimits

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "contracts"))
import cp_corpus

MIB = 1024 * 1024


def _plain_j(value: Any) -> bytes:
    """The definition of J in specification §4.1, written out here as the test oracle."""
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


# -- encoding ---------------------------------------------------------------------------------


@pytest.mark.parametrize("entry", cp_corpus.vectors("json")["encode"], ids=lambda e: e["text"])
def test_encode_matches_the_frozen_vectors(entry: dict[str, Any]) -> None:
    data = encode(entry["value"])
    assert data == entry["text"].encode("utf-8")
    assert hashlib.sha256(data).hexdigest() == entry["sha256"]
    assert json_sha256(entry["value"]) == entry["sha256"]
    assert document_bytes(entry["value"]) == data + b"\n"


def test_encode_accepts_tuples_as_arrays() -> None:
    assert encode({"a": (1, (2, 3))}) == b'{"a":[1,[2,3]]}'


@pytest.mark.parametrize(
    ("value", "rule"),
    [
        (1.0, "json.number"),
        ({"a": 0.5}, "json.number"),
        (float("nan"), "json.number"),
        (float("inf"), "json.number"),
        (INT_MAX + 1, "json.integer_range"),
        (-INT_MAX - 1, "json.integer_range"),
        ([2**64], "json.integer_range"),
        ("\ud800", "json.surrogate"),
        ({"\udc00": 1}, "json.surrogate"),
    ],
)
def test_encode_refuses_values_outside_the_json_rules(value: Any, rule: str) -> None:
    with pytest.raises(ContractError) as info:
        encode(value)
    assert info.value.rule == rule


@pytest.mark.parametrize("value", [{1: 2}, {"a": object()}, {"a": b"x"}, {(1,): 2}, {"a": {1}}])
def test_encode_refuses_python_values_that_are_not_json(value: Any) -> None:
    with pytest.raises(TypeError):
        encode(value)


def test_booleans_stay_booleans_and_limits_are_inclusive() -> None:
    assert encode([True, False, None, INT_MAX, -INT_MAX]) == (
        b"[true,false,null,9223372036854775807,-9223372036854775807]"
    )


# -- strict reading: the corpus document fixtures of type json -------------------------------


@pytest.mark.parametrize("entry", cp_corpus.documents("json"), ids=lambda e: e["id"])
def test_json_document_fixtures(entry: dict[str, Any]) -> None:
    data = cp_corpus.fixture_bytes(entry)
    kind, rule = cp_corpus.expectation(entry)
    if kind == "valid":
        value = parse_document(data)
        assert document_bytes(value) == data
        return
    assert kind == "rule"
    expected_type = ResourceError if str(rule).startswith("limit.") else ContractError
    with pytest.raises((ContractError, ResourceError)) as info:
        parse_document(data)
    assert type(info.value) is expected_type
    assert info.value.rule == rule


def test_reader_errors_are_context_free_rejections() -> None:
    with pytest.raises(ContractError) as info:
        parse_document(b'{"a": 1}\n')
    assert info.value.kind == "reject"
    with pytest.raises(ResourceError) as limit:
        parse_document(b"[" * 33 + b"]" * 33 + b"\n")
    assert limit.value.kind == "resource"


def test_huge_integer_literals_are_range_errors_not_syntax_errors() -> None:
    with pytest.raises(ContractError) as info:
        parse_json(b'{"a":' + b"9" * 5000 + b"}")
    assert info.value.rule == "json.integer_range"
    with pytest.raises(ContractError) as negative:
        parse_json(b"-" + b"1" * 30)
    assert negative.value.rule == "json.integer_range"


def test_reader_integer_range_is_symmetric_and_inclusive() -> None:
    # -(2^63) has 19 digits like INT_MAX, so only the value check can refuse it.
    assert parse_json(b"[-9223372036854775807,9223372036854775807]") == [-INT_MAX, INT_MAX]
    for literal in (
        b"-9223372036854775808",
        b"9223372036854775808",
        b'{"a":[-9223372036854775808]}',
    ):
        with pytest.raises(ContractError) as info:
            parse_json(literal)
        assert info.value.rule == "json.integer_range"


def test_very_deep_nesting_is_a_resource_error_without_recursion_error() -> None:
    deep = b"[" * 200_000 + b"]" * 200_000
    with pytest.raises(ResourceError) as info:
        parse_json(deep)
    assert info.value.rule == "limit.depth"


def test_depth_limit_is_configurable_and_inclusive() -> None:
    shallow = ReaderLimits(depth=2)
    assert parse_json(b"[[1]]", limits=shallow) == [[1]]
    assert parse_json(b'{"a":{"b":1}}', limits=shallow) == {"a": {"b": 1}}
    with pytest.raises(ResourceError):
        parse_json(b"[[[1]]]", limits=shallow)
    with pytest.raises(ResourceError):
        parse_json(b'[{"a":[]}]', limits=shallow)
    assert parse_json(b"7", limits=ReaderLimits(depth=1)) == 7


def test_scalars_have_depth_zero() -> None:
    assert parse_json(b'"x"', limits=ReaderLimits(depth=1)) == "x"


def test_document_size_limit_counts_bytes_without_the_final_lf() -> None:
    limits = ReaderLimits(document_bytes=9)
    exact = document_bytes({"a": "xx"})  # {"a":"xx"} is 10 bytes
    assert len(exact) == 11
    assert parse_document(exact, limits=ReaderLimits(document_bytes=10)) == {"a": "xx"}
    with pytest.raises(ResourceError) as info:
        parse_document(exact, limits=limits)
    assert info.value.rule == "limit.document"


def test_document_of_exactly_the_default_limit_is_read_and_one_more_byte_is_refused() -> None:
    body = b'"' + b"a" * (64 * MIB - 2) + b'"'
    assert len(body) == DEFAULT_LIMITS.document_bytes
    assert parse_document(body + b"\n") == "a" * (64 * MIB - 2)
    with pytest.raises(ResourceError):
        parse_document(b'"' + b"a" * (64 * MIB - 1) + b'"\n')


def test_journal_lines_are_exact_j_without_lf() -> None:
    assert parse_line(b'{"a":1}') == {"a": 1}
    for bad in (b'{"a":1}\n', b'{"a": 1}', b'{"b":1,"a":2}', b' {"a":1}'):
        with pytest.raises(ContractError) as info:
            parse_line(bad)
        assert info.value.rule == "json.canonical"


def test_line_limit() -> None:
    line = encode({"a": "x" * 20})
    assert parse_line(line, limits=ReaderLimits(line_bytes=len(line))) == {"a": "x" * 20}
    with pytest.raises(ResourceError) as info:
        parse_line(line, limits=ReaderLimits(line_bytes=len(line) - 1))
    assert info.value.rule == "limit.line"


def test_parse_document_requires_bytes() -> None:
    with pytest.raises(TypeError):
        parse_document('{"a":1}\n')  # type: ignore[arg-type]


# -- properties ---------------------------------------------------------------------------------


def _random_value(rng: random.Random, depth: int) -> Any:
    choice = rng.randrange(8 if depth < 5 else 5)
    if choice == 0:
        return None
    if choice == 1:
        return rng.random() < 0.5
    if choice == 2:
        return rng.choice([0, 1, -1, INT_MAX, -INT_MAX, rng.randint(-(10**12), 10**12)])
    if choice in (3, 4):
        alphabet = 'ab"\\/\n\t\x00\x1f\x7fé\u2028😀 '
        return "".join(rng.choice(alphabet) for _ in range(rng.randrange(6)))
    if choice == 5:
        return [_random_value(rng, depth + 1) for _ in range(rng.randrange(4))]
    keys = ["a", "B", "é", "", "ab", "\u2028", "😀", "a\x00"]
    return {rng.choice(keys): _random_value(rng, depth + 1) for _ in range(rng.randrange(4))}


def test_random_values_round_trip_and_match_the_plain_definition() -> None:
    rng = random.Random(1010)
    for _ in range(2000):
        value = _random_value(rng, 0)
        data = encode(value)
        assert data == _plain_j(value)
        assert parse_document(data + b"\n") == value
        assert parse_line(data) == value


def test_every_accepted_mutation_is_canonical() -> None:
    """Whatever the strict reader accepts re-encodes to exactly the bytes it read."""
    rng = random.Random(1011)
    seeds = [document_bytes(_random_value(rng, 0)) for _ in range(60)]
    seeds.append(b'{"a":[1,-2,"x\\u0001\\n"],"b":{"c":null,"d":true}}\n')
    alphabet = b' \t\r\n0123456789-+.eE"\\{}[],:abtrufnl\x00\xff\xc3\xa9'
    accepted = 0
    for _ in range(6000):
        data = bytearray(rng.choice(seeds))
        for _ in range(rng.randint(1, 3)):
            op = rng.randrange(3)
            pos = rng.randrange(len(data) + 1)
            if op == 0 and data:
                del data[min(pos, len(data) - 1)]
            elif op == 1:
                data.insert(pos, rng.choice(alphabet))
            elif data:
                data[min(pos, len(data) - 1)] = rng.choice(alphabet)
        raw = bytes(data)
        try:
            value = parse_document(raw)
        except (ContractError, ResourceError):
            continue
        accepted += 1
        assert document_bytes(value) == raw
    assert accepted > 0
