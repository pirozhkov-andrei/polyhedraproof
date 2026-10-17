"""Access to the shared contract corpus and its independent reference reader.

The neighbourly.cnf tests compare the producer writer with the frozen byte vectors of
``tests/contracts/corpus`` and validate its output with ``tests/contracts/contract_reader.py``,
an implementation that shares no code with this package (specification §2.1: tests may compare
independent implementations across package boundaries). These tests run from the checkout.
"""

from __future__ import annotations

import importlib
import json
import sys
from functools import cache
from pathlib import Path
from types import ModuleType
from typing import Any

REPO = Path(__file__).resolve().parents[4]
CONTRACTS = REPO / "tests" / "contracts"
CORPUS = CONTRACTS / "corpus"
CAMPAIGNS = CORPUS / "campaigns"

if not (CONTRACTS / "contract_reader.py").is_file():  # pragma: no cover - layout guard
    raise RuntimeError(f"the contract corpus is missing under {CONTRACTS}")


@cache
def reader() -> ModuleType:
    """The independent reference reader (imported from tests/contracts)."""
    if str(CONTRACTS) not in sys.path:
        sys.path.append(str(CONTRACTS))
    return importlib.import_module("contract_reader")


@cache
def cnf_vectors() -> dict[str, Any]:
    data: dict[str, Any] = json.loads((CORPUS / "vectors" / "cnf.json").read_text("utf-8"))
    return data


@cache
def documents() -> dict[str, dict[str, Any]]:
    data = json.loads((CORPUS / "documents.json").read_text("utf-8"))
    return {entry["id"]: entry for entry in data["documents"]}


def document_bytes(identifier: str) -> bytes:
    data = documents()[identifier]["data"]
    assert "text" in data, identifier
    return str(data["text"]).encode("utf-8")


def bundle_dir(campaign: str, name: str) -> Path:
    return CAMPAIGNS / campaign / "bundles" / name
