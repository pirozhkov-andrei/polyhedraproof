"""Primitive types, enums and shared values of specification §4.1 against the corpus vectors."""

from __future__ import annotations

import datetime
import random
from collections.abc import Callable
from typing import Any

import cp_corpus
import pytest

from cubeproof.base.errors import ContractError
from cubeproof.contracts import enums
from cubeproof.contracts.primitives import (
    INT_MAX,
    K_MAX,
    SUCCESS_LINE,
    format_utc,
    is_hash,
    is_id128,
    is_int64,
    is_literal,
    is_name,
    is_nonnegative,
    is_positive,
    is_relpath,
    is_utc,
    parse_utc,
    utc_problem,
)
from cubeproof.contracts.values import Artifact, JsonObject, Node, Ref

PRIMITIVES = cp_corpus.vectors("primitives")["primitives"]

PREDICATES: dict[str, Callable[[Any], bool]] = {
    "Hash": is_hash,
    "Id128": is_id128,
    "Name": is_name,
    "RelPath": is_relpath,
    "UTC": is_utc,
    "Int64": is_int64,
    "NonNegative": is_nonnegative,
    "Positive": is_positive,
    "Literal": is_literal,
}


def _cases(valid: bool) -> list[tuple[str, Any]]:
    key = "valid" if valid else "invalid"
    return [(name, value) for name in PREDICATES for value in PRIMITIVES[name][key]]


@pytest.mark.parametrize(("name", "value"), _cases(True), ids=repr)
def test_valid_primitives(name: str, value: Any) -> None:
    assert PREDICATES[name](value) is True


@pytest.mark.parametrize(("name", "value"), _cases(False), ids=repr)
def test_invalid_primitives(name: str, value: Any) -> None:
    assert PREDICATES[name](value) is False


def test_predicates_never_raise_on_foreign_types() -> None:
    for predicate in PREDICATES.values():
        for value in (None, 1.0, b"x", [], {}, object(), True):
            assert predicate(value) is False


def test_patterns_do_not_accept_a_final_newline_or_unicode_digits() -> None:
    assert not is_hash("0" * 64 + "\n")
    assert not is_id128("0" * 32 + "\n")
    assert not is_name("a\n")
    assert not is_utc("2026-10-04T12:00:00.000Z\n")
    assert not is_utc("２026-10-04T12:00:00.000Z")  # noqa: RUF001 (a fullwidth digit on purpose)
    assert not is_relpath("a\n/..")


def test_utc_problem_names_schema_or_calendar() -> None:
    assert utc_problem("2026-10-04T12:00:00.000Z") is None
    assert utc_problem("2026-10-04T12:00:00Z") == "schema"
    assert utc_problem("2023-02-29T00:00:00.000Z") == "utc.calendar"
    assert utc_problem(5) == "schema"


def test_format_and_parse_utc() -> None:
    assert format_utc(0) == "1970-01-01T00:00:00.000Z"
    assert format_utc(1_791_115_200_123) == "2026-10-04T12:00:00.123Z"
    assert parse_utc("2026-10-04T12:00:00.123Z") == 1_791_115_200_123
    rng = random.Random(4)
    for _ in range(500):
        ms = rng.randint(-62_135_596_800_000, 253_402_300_799_999)
        text = format_utc(ms)
        assert is_utc(text)
        assert parse_utc(text) == ms
        expected = datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc) + (
            datetime.timedelta(milliseconds=ms)
        )
        assert text == (
            f"{expected.year:04d}-{expected.month:02d}-{expected.day:02d}T"
            f"{expected.hour:02d}:{expected.minute:02d}:{expected.second:02d}.{ms % 1000:03d}Z"
        )
    with pytest.raises(ContractError):
        parse_utc("2023-02-29T00:00:00.000Z")
    with pytest.raises(ValueError):
        format_utc(253_402_300_800_000)
    with pytest.raises(TypeError):
        format_utc(True)


def test_constants() -> None:
    assert K_MAX == 20
    assert INT_MAX == 2**63 - 1
    assert SUCCESS_LINE == "s VERIFIED UNSAT\n"
    assert len(SUCCESS_LINE.encode("ascii")) == 17


def test_enums_carry_the_specified_spellings() -> None:
    assert [o.value for o in enums.Outcome] == [
        "VERIFIED_UNSAT",
        "EXHAUSTED",
        "MODEL",
        "INVALID_MODEL",
        "CHECK_REJECTED",
        "TOOL_FAILED",
    ]
    assert {r.value for r in enums.Route} == {"unit", "cdcl"}
    assert [m.value for m in enums.ProofMode] == ["transient", "retain", "stream"]
    assert {e.value for e in enums.ModelError} == {
        "missing",
        "conflicting",
        "out_of_range",
        "syntax",
        "violated",
    }
    assert {s.value for s in enums.StopState} == {"stuck", "tool_blocked", "resource_blocked"}
    assert {s.value for s in enums.OpenState} == {
        "pending",
        "stuck",
        "tool_blocked",
        "resource_blocked",
        "model",
    }
    assert [v.value for v in enums.Verdict] == ["PROVED", "OPEN", "MODEL_FOUND", "INCONSISTENT"]
    assert {s.value for s in enums.AuditStatus} == {
        "HASH_MATCHED",
        "REPROVED_UNSAT",
        "MISMATCH",
        "NOT_COMPARABLE",
        "FAILED",
        "OPEN",
    }
    assert {c.value for c in enums.AuditComparison} == {"strict", "reprove"}
    assert {p.value for p in enums.Purpose} == {"run", "audit"}
    assert [t.value for t in enums.RecordType] == [
        "header",
        "resume",
        "shard",
        "split",
        "attempt",
        "node_stop",
        "node_reopen",
        "handoff",
        "repair",
        "audit_begin",
        "audit_target",
        "audit_ready",
        "audit_result",
    ]
    assert {lc.value for lc in enums.Lifecycle} == {"running", "draining", "stopped"}
    assert {code.name: int(code) for code in enums.ExitCode} == {
        "SUCCESS": 0,
        "OPEN": 1,
        "MODEL": 2,
        "USAGE": 3,
        "INTEGRITY": 4,
        "TOOL": 5,
        "ANOMALY": 6,
        "INTERRUPTED": 130,
    }
    assert enums.Outcome("MODEL") is enums.Outcome.MODEL
    assert enums.Outcome.MODEL == "MODEL"


def test_reason_vocabulary_is_closed_per_outcome() -> None:
    assert {
        enums.Outcome.EXHAUSTED: frozenset(
            {"proof_size", "time", "check_time", "check_memory", "check_stack", "solver_memory"}
        ),
        enums.Outcome.TOOL_FAILED: frozenset(
            {"launch", "binary_changed", "io", "file_changed", "crash", "protocol", "relay"}
        ),
        enums.Outcome.CHECK_REJECTED: frozenset({"rejected"}),
    } == enums.REASONS


@pytest.mark.parametrize("value", PRIMITIVES["Node"]["valid"], ids=repr)
def test_valid_nodes(value: Any) -> None:
    node = Node.from_json(value)
    assert node.to_json() == value
    assert node.cube == tuple(value["cube"])


@pytest.mark.parametrize("value", PRIMITIVES["Node"]["invalid"], ids=repr)
def test_invalid_nodes(value: Any) -> None:
    with pytest.raises(ContractError) as info:
        Node.from_json(value)
    assert info.value.rule == "schema"


@pytest.mark.parametrize("cube", PRIMITIVES["Cube"]["valid"], ids=repr)
def test_cube_valid_at_schema_level(cube: Any) -> None:
    value = {"formula_sha256": "0" * 64, "cube": cube}
    try:
        Node.from_json(value)
    except ContractError as error:
        assert error.rule == "cube.canonical"


@pytest.mark.parametrize("cube", PRIMITIVES["Cube"]["invalid"], ids=repr)
def test_cube_invalid_at_schema_level(cube: Any) -> None:
    with pytest.raises(ContractError) as info:
        Node.from_json({"formula_sha256": "0" * 64, "cube": cube})
    assert info.value.rule == "schema"
    assert str(info.value.location).startswith("$.cube")


def test_node_constructor_validates() -> None:
    with pytest.raises(ContractError):
        Node("X", ())
    with pytest.raises(ContractError) as info:
        Node("0" * 64, (2, 1))
    assert info.value.rule == "cube.canonical"
    with pytest.raises(ContractError):
        Node("0" * 64, (True,))
    with pytest.raises(ContractError):
        Node("0" * 64, [1])  # type: ignore[arg-type]


@pytest.mark.parametrize("value", PRIMITIVES["Ref"]["valid"], ids=repr)
def test_valid_refs(value: Any) -> None:
    ref = Ref.from_json(value)
    assert ref.to_json() == value
    assert ref.sort_key == (value["journal"], value["seq"])


@pytest.mark.parametrize("value", PRIMITIVES["Ref"]["invalid"], ids=repr)
def test_invalid_refs(value: Any) -> None:
    with pytest.raises(ContractError) as info:
        Ref.from_json(value)
    assert info.value.rule == "schema"


@pytest.mark.parametrize("value", PRIMITIVES["Artifact"]["valid"], ids=repr)
def test_valid_artifacts(value: Any) -> None:
    assert Artifact.from_json(value).to_json() == value


@pytest.mark.parametrize("value", PRIMITIVES["Artifact"]["invalid"], ids=repr)
def test_invalid_artifacts(value: Any) -> None:
    with pytest.raises(ContractError) as info:
        Artifact.from_json(value)
    assert info.value.rule == "schema"


def test_artifact_constructor_validates() -> None:
    digest = "0" * 64
    assert Artifact("a/b.txt", digest, 0).to_json() == {
        "path": "a/b.txt",
        "sha256": digest,
        "bytes": 0,
    }
    bad: list[tuple[Any, Any, Any]] = [
        ("../x", digest, 0),
        ("/abs", digest, 0),
        ("a//b", digest, 0),
        ("C:x", digest, 0),
        ("a\\b", digest, 0),
        ("", digest, 0),
        ("x", "A" * 64, 0),
        ("x", digest, -1),
        ("x", digest, True),
    ]
    for path, sha, size in bad:
        with pytest.raises(ContractError) as info:
            Artifact(path, sha, size)
        assert info.value.rule == "schema", (path, sha, size)


def test_json_object_is_an_immutable_open_object() -> None:
    original: dict[str, Any] = {"b": [1, {"c": None}], "a": "é"}
    obj = JsonObject.from_json(original)
    original["b"] = 0
    first = obj.to_json()
    assert first == {"b": [1, {"c": None}], "a": "é"}
    first["a"] = "changed"
    assert obj.to_json()["a"] == "é"
    assert obj == JsonObject.from_json({"a": "é", "b": [1, {"c": None}]})
    assert hash(obj) == hash(JsonObject.from_json({"a": "é", "b": [1, {"c": None}]}))
    with pytest.raises(ContractError) as info:
        JsonObject.from_json([1])
    assert info.value.rule == "schema"
    with pytest.raises(ContractError) as number:
        JsonObject.from_json({"x": 1.5})
    assert number.value.rule == "json.number"


def test_json_object_constructor_accepts_only_j_of_an_object() -> None:
    assert JsonObject('{"a":"é","b":[1]}').to_json() == {"a": "é", "b": [1]}
    assert JsonObject("{}").to_json() == {}
    noncanonical = (
        '{"b":1,"a":2}',  # key order
        '{"a": 1}',  # whitespace
        '{"a":"\\u00e9"}',  # escape instead of the character
        '{"a":1,"a":1}',  # duplicate key
        '{"a":1.0}',  # floating point
        "[1]",  # not an object
        "{",  # not JSON
        "",
    )
    for text in noncanonical:
        with pytest.raises(ContractError) as info:
            JsonObject(text)
        assert info.value.rule in ("schema", "json.number"), text
    with pytest.raises(ContractError):
        JsonObject(b"{}")  # type: ignore[arg-type]
