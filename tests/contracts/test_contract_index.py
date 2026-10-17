"""The shared schema index lists every frozen cubeproof v1 schema with its hash.

Specification §2.2 (repository layout): ``schemas/`` holds the schema descriptions and an
index. The hashes of the index freeze the schema files and the requirement matrix, so any
later change to them must also change the index.
"""

from __future__ import annotations

import hashlib
from typing import Any

from contract_reader import REPO, SCHEMAS, load_json_file

INDEX = REPO / "schemas" / "index.json"


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def family() -> dict[str, Any]:
    index = load_json_file(INDEX)
    assert index["format"] == "polyhedraproof-schema-index-1"
    families = {(f["name"], f["version"]): f for f in index["families"]}
    assert len(families) == len(index["families"])
    found: dict[str, Any] = families[("cubeproof", "v1")]
    return found


def own_format(schema: dict[str, Any]) -> str | None:
    """The document format a schema fixes, read directly from its definitions."""
    if "format" in schema.get("properties", {}):
        value: str = schema["properties"]["format"]["const"]
        return value
    consts = {
        definition["properties"]["format"]["const"]
        for definition in schema.get("$defs", {}).values()
        if "format" in definition.get("properties", {})
    }
    return consts.pop() if len(consts) == 1 and "anyOf" in schema else None


def test_the_index_lists_exactly_the_cubeproof_v1_schemas() -> None:
    entries = family()["schemas"]
    paths = [e["path"] for e in entries]
    assert paths == sorted(paths)
    on_disk = sorted(f"cubeproof/v1/{p.name}" for p in SCHEMAS.glob("*.schema.json"))
    assert paths == on_disk


def test_the_index_freezes_each_schema_by_hash_title_and_format() -> None:
    for entry in family()["schemas"]:
        path = REPO / "schemas" / entry["path"]
        data = path.read_bytes()
        assert entry["sha256"] == sha(data), entry["path"]
        schema = load_json_file(path)
        assert entry["title"] == schema["title"], entry["path"]
        assert entry["format"] == own_format(schema), entry["path"]


def test_the_index_freezes_the_requirement_matrix() -> None:
    entry = family()["requirements"]
    assert entry["path"] == "cubeproof/v1/requirements.json"
    data = (SCHEMAS / "requirements.json").read_bytes()
    assert entry["sha256"] == sha(data)
    assert entry["format"] == load_json_file(SCHEMAS / "requirements.json")["format"]


def test_the_journal_record_schema_is_indexed_with_the_journal_format() -> None:
    by_path = {e["path"]: e for e in family()["schemas"]}
    assert by_path["cubeproof/v1/journal-record.schema.json"]["format"] == "cubeproof-journal-1"
    assert by_path["cubeproof/v1/common.schema.json"]["format"] is None
    assert by_path["cubeproof/v1/policy.schema.json"]["format"] is None
