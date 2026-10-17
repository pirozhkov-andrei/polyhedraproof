"""Access to the frozen contract corpus for the cubeproof contract tests (test-only).

The corpus (``tests/contracts/corpus``) and the schemas (``schemas/cubeproof/v1``) are produced
independently of this package; these tests use them as the expected values. The schema
validator ``tests/contracts/contract_schema.py`` is the independent oracle of the
differential schema tests. Nothing here is imported by runtime code.
"""

from __future__ import annotations

import base64
import json
import sys
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[4]
CORPUS = REPO / "tests" / "contracts" / "corpus"
SCHEMAS = REPO / "schemas" / "cubeproof" / "v1"
CONTRACT_TESTS = REPO / "tests" / "contracts"


def load_json(relative: str) -> Any:
    """A JSON file of the corpus, by path relative to the corpus root."""
    return json.loads((CORPUS / relative).read_bytes())


def vectors(name: str) -> Any:
    """``corpus/vectors/<name>.json``."""
    return load_json(f"vectors/{name}.json")


def documents(kind: str) -> list[dict[str, Any]]:
    """Single-document fixtures of one type (``corpus/documents.json``)."""
    data = load_json("documents.json")
    assert data["format"] == "cubeproof-contract-documents-1"
    entries = [e for e in data["documents"] if e["type"] == kind]
    assert entries, kind
    return entries


def fixture_bytes(entry: dict[str, Any]) -> bytes:
    data = entry["data"]
    if "base64" in data:
        return base64.b64decode(data["base64"])
    text: str = data["text"]
    return text.encode("utf-8")


def expectation(entry: dict[str, Any]) -> tuple[str, str | None]:
    """``("valid", None)``, ``("rule", id)`` or ``("schema", location)``."""
    expect = entry["expect"]
    if expect == "valid":
        return ("valid", None)
    if "rule" in expect:
        return ("rule", str(expect["rule"]))
    return ("schema", str(expect["schema"]))


def cases() -> list[dict[str, Any]]:
    data = load_json("cases.json")
    entries: list[dict[str, Any]] = data["cases"]
    return entries


def schema_store() -> Any:
    """A contract ``SchemaStore`` over ``schemas/cubeproof/v1`` (independent schema oracle)."""
    if str(CONTRACT_TESTS) not in sys.path:
        sys.path.insert(0, str(CONTRACT_TESTS))
    import contract_schema

    return contract_schema.SchemaStore(SCHEMAS)


def schema_locations(errors: list[str]) -> set[str]:
    """The locations of ``SchemaStore.errors`` messages (``"$.a: why"`` -> ``"$.a"``)."""
    return {e.split(": ", 1)[0] for e in errors}
