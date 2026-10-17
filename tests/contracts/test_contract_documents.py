"""Single-document fixtures: every type has valid examples and every rule an invalid one.

``corpus/documents.json`` holds byte-exact fixtures with an expectation each: ``"valid"``,
``{"rule": id}`` (exactly that requirement is violated) or ``{"schema": location}`` (the
schema rejects the document, and only at that location). The reference reader must agree
with every expectation.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from contract_reader import (
    CORPUS,
    DOCUMENT_SCHEMAS,
    fixture_bytes,
    load_json_file,
    open_store,
    validate_document,
)
from contract_schema import SchemaStore

DOCUMENT_TYPES = {*DOCUMENT_SCHEMAS, "json", "dimacs", "names-tsv", "tags-tsv"} - {"campaign"}


def documents() -> list[dict[str, Any]]:
    data = load_json_file(CORPUS / "documents.json")
    assert data["format"] == "cubeproof-contract-documents-1"
    entries: list[dict[str, Any]] = data["documents"]
    return entries


@pytest.fixture(scope="module")
def store() -> SchemaStore:
    return open_store()


def expected(entry: dict[str, Any]) -> list[str]:
    expect = entry["expect"]
    if expect == "valid":
        return []
    if "rule" in expect:
        return [expect["rule"]]
    return ["schema@" + expect["schema"]]


@pytest.mark.parametrize("entry", documents(), ids=lambda e: e["id"])
def test_document_fixture(store: SchemaStore, entry: dict[str, Any]) -> None:
    found = validate_document(store, entry["type"], fixture_bytes(entry), entry.get("context"))
    assert found == expected(entry)


def test_identifiers_are_unique_and_types_known() -> None:
    entries = documents()
    ids = [e["id"] for e in entries]
    assert len(ids) == len(set(ids))
    assert {e["type"] for e in entries} == DOCUMENT_TYPES


def test_every_type_has_valid_and_invalid_fixtures() -> None:
    entries = documents()
    for kind in DOCUMENT_TYPES:
        expects = [e["expect"] for e in entries if e["type"] == kind]
        assert "valid" in expects, kind
        assert any(x != "valid" for x in expects), kind


def test_every_record_type_route_and_outcome_has_a_valid_record() -> None:
    valid = [
        load_json_bytes(fixture_bytes(e))
        for e in documents()
        if e["type"] == "journal-record" and e["expect"] == "valid"
    ]
    assert {r["type"] for r in valid} == {
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
    }
    attempts = [r for r in valid if r["type"] == "attempt"]
    combos = {(a["route"], a["proof_mode"], a["outcome"]) for a in attempts}
    for outcome in ("VERIFIED_UNSAT", "EXHAUSTED", "CHECK_REJECTED", "TOOL_FAILED"):
        for mode in ("transient", "retain", "stream"):
            assert ("cdcl", mode, outcome) in combos, (mode, outcome)
    for mode in ("transient", "retain", "stream"):
        assert ("unit", mode, "VERIFIED_UNSAT") in combos
    for route in ("unit", "cdcl"):
        assert (route, "transient", "MODEL") in combos
    assert ("cdcl", "stream", "MODEL") in combos
    reasons = {(a["outcome"], a["reason"]) for a in attempts}
    for code in ("proof_size", "time", "check_time", "check_memory", "check_stack"):
        assert ("EXHAUSTED", code) in reasons
    assert ("EXHAUSTED", "solver_memory") in reasons
    for code in ("launch", "binary_changed", "io", "file_changed", "crash", "protocol", "relay"):
        assert ("TOOL_FAILED", code) in reasons
    for code in ("missing", "conflicting", "out_of_range", "syntax", "violated"):
        assert ("INVALID_MODEL", code) in reasons


def load_json_bytes(data: bytes) -> dict[str, Any]:
    value: dict[str, Any] = json.loads(data)
    return value
