"""The tiny CNF, proof and model fixtures in ``tests/fakes/data`` and their manifest."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

DATA = Path(__file__).resolve().with_name("data")
MANIFEST_FORMAT = "polyhedraproof-test-fixtures-1"


def manifest() -> list[dict[str, Any]]:
    data = json.loads((DATA / "fixtures.json").read_text(encoding="utf-8"))
    if data.get("format") != MANIFEST_FORMAT:
        raise ValueError(f"{DATA / 'fixtures.json'} is not a {MANIFEST_FORMAT} manifest")
    return list(data["fixtures"])


def entry(name: str) -> dict[str, Any]:
    for item in manifest():
        if item["file"] == name:
            return item
    raise KeyError(name)


def fixture(name: str) -> Path:
    """Path of a fixture whose bytes match the manifest."""
    path = DATA / name
    expected = entry(name)["sha256"]
    if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
        raise ValueError(f"{path} does not match its manifest hash")
    return path


def of_kind(kind: str) -> list[dict[str, Any]]:
    return [item for item in manifest() if item["kind"] == kind]
