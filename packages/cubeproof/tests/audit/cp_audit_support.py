"""Test-only helpers of the audit and verify-retained tests.

- Corpus access: the frozen contract corpus (``tests/contracts/corpus``) gives campaigns, journals,
  their certificates (exact certify output), the audit-plan journals, the selection vector and
  the audit-report documents. :func:`corpus_case` copies one case into a temporary directory so
  that a test may append to a journal or edit a certificate.
- :class:`Builder` appends records to a journal prefix (``build_record`` with the chain of the
  last line), so that audit journals with given plans, attempts and results can be written.
- :func:`attempt_value` gives a corpus attempt fixture (the ``attempt-<preset>`` journal-record
  documents) as JSON payload fields to vary.

Nothing here is imported by runtime code.
"""

from __future__ import annotations

import base64
import json
import shutil
from collections.abc import Iterable
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from cubeproof.base.canonical_json import document_bytes, encode
from cubeproof.contracts.enums import Purpose
from cubeproof.evidence.schema import (
    Attempt,
    Header,
    Payload,
    Record,
    build_record,
    check_record,
    record_self,
)

REPO = Path(__file__).resolve().parents[4]
CORPUS = REPO / "tests" / "contracts" / "corpus"
UTC = "2026-01-02T03:04:05.678Z"


def load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write_document(path: Path, value: Any) -> Path:
    path.write_bytes(document_bytes(value))
    return path


@dataclass(frozen=True)
class CaseFiles:
    """A corpus certify case copied below a temporary directory."""

    root: Path
    campaign: Path
    journals: tuple[Path, ...]
    certificate: Path


def corpus_case(tmp: Path, case_id: str) -> CaseFiles:
    """Copy the campaign directory, the journals and the certificate of a valid certify case."""
    cases = {c["id"]: c for c in load(CORPUS / "cases.json")["cases"]}
    case = cases[case_id]
    campaign_dir = (CORPUS / case["campaign"]).parent
    target = tmp / "case"
    shutil.copytree(campaign_dir, target / "campaign")
    campaign = target / "campaign" / Path(case["campaign"]).name
    journals = []
    for relative in case["journals"]:
        copy = target / "journals" / Path(relative).parent.name / Path(relative).name
        copy.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(CORPUS / relative, copy)
        journals.append(copy)
    certificate = target / "certificate.json"
    shutil.copyfile(CORPUS / case["expect"]["certificate"], certificate)
    return CaseFiles(target, campaign, tuple(journals), certificate)


def corpus_lines(relative: str) -> list[bytes]:
    """Complete lines (without LF) of a corpus journal."""
    data = (CORPUS / relative).read_bytes()
    return data[: data.rfind(b"\n") + 1].split(b"\n")[:-1]


def records_of(data: bytes) -> list[Record]:
    """The records of journal bytes (complete lines only; rules without the campaign)."""
    complete = data[: data.rfind(b"\n") + 1]
    return [check_record(json.loads(line)) for line in complete.split(b"\n")[:-1]]


def document(identifier: str) -> dict[str, Any]:
    """One entry of the corpus ``documents.json``."""
    entries = load(CORPUS / "documents.json")["documents"]
    found: dict[str, Any] = next(e for e in entries if e["id"] == identifier)
    return found


def document_entries(kind: str) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = load(CORPUS / "documents.json")["documents"]
    return [e for e in entries if e["type"] == kind]


def document_value(entry: dict[str, Any]) -> Any:
    data = entry["data"]
    raw = data["text"].encode("utf-8") if "text" in data else base64.b64decode(data["base64"])
    return json.loads(raw)


def attempt_value(preset: str) -> dict[str, Any]:
    """The payload fields of the corpus fixture ``attempt-<preset>`` (envelope removed)."""
    value = dict(document_value(document(f"attempt-{preset}")))
    for name in ("format", "seq", "prev", "self", "type", "utc"):
        value.pop(name)
    return value


def typed_attempt(value: dict[str, Any]) -> Attempt:
    """An Attempt payload from JSON payload fields, through the record schema and rules."""
    unsigned = {
        **value,
        "format": "cubeproof-journal-1",
        "seq": 1,
        "prev": "0" * 64,
        "type": "attempt",
        "utc": UTC,
    }
    payload = check_record({**unsigned, "self": record_self(unsigned)}).payload
    assert isinstance(payload, Attempt)
    return payload


def audit_header(line: bytes, worker: str = "auditor") -> bytes:
    """The header line of a new audit journal with the snapshot of a run journal's header."""
    header = check_record(json.loads(line)).payload
    assert isinstance(header, Header)
    payload = replace(header, purpose=Purpose.AUDIT, worker=worker)
    return build_record(payload, seq=0, prev="0" * 64, utc=UTC).line


class Builder:
    """Append records to the complete lines of a journal (see module doc)."""

    def __init__(self, lines: Iterable[bytes]) -> None:
        self.lines = list(lines)
        last = json.loads(self.lines[-1])
        self.seq = int(last["seq"])
        self.prev = str(last["self"])
        self.id = str(json.loads(self.lines[0])["self"])

    def add(self, payload: Payload) -> Record:
        record = build_record(payload, seq=self.seq + 1, prev=self.prev, utc=UTC)
        self.lines.append(record.line)
        self.seq, self.prev = record.seq, record.self_hash
        return record

    def add_value(self, kind: str, value: dict[str, Any]) -> Record:
        """A record from JSON payload fields (checked like a read record)."""
        envelope = {"format": "cubeproof-journal-1", "seq": self.seq + 1, "prev": self.prev}
        unsigned = {**value, **envelope, "type": kind, "utc": UTC}
        record = check_record({**unsigned, "self": record_self(unsigned)})
        self.lines.append(record.line)
        self.seq, self.prev = record.seq, record.self_hash
        return record

    def data(self) -> bytes:
        return b"".join(line + b"\n" for line in self.lines)

    def write(self, path: Path) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(self.data())
        return path


def j(value: Any) -> bytes:
    return encode(value)
