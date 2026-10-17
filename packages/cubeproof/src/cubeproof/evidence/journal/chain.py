"""The chain of complete journal lines (specification §7.1) and the record validator protocol.

A line is J(record) + LF. ``self = SHA256(J(record without self))``; ``prev`` is the previous
record's self, or 64 zeros at seq 0; seq is contiguous from 0; the record at seq 0 is the
only header. Journal ID = header self; head = self of the last complete record.

The journal layer may not import the record schema (specification §2.3: ``evidence.journal`` and
``evidence.schema`` are separate subsystems of one layer). The caller therefore passes a
:class:`RecordValidator` (``cubeproof.evidence.schema.RecordSequence``), and the chain calls it
at the positions of specification §7.1: canonical bytes, **schema**, self, seq, prev, header,
**campaign of the header**; the record rules come after the chain (see the reader).
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from typing import Any, Protocol, TypeVar

from cubeproof.base.canonical_json import parse_line
from cubeproof.base.errors import CubeproofError, IntegrityError, contextualize
from cubeproof.base.hashing import ZERO_HASH
from cubeproof.base.settings import DEFAULT_LIMITS, ReaderLimits

JOURNAL_FORMAT = "cubeproof-journal-1"
#: Record types the journal protocol itself names (specification §4.7, §7.1, §7.3).
HEADER, RESUME, REPAIR = "header", "resume", "repair"

R = TypeVar("R")


class RecordValidator(Protocol[R]):
    """Record schema and rules of one journal, called in line order (see module doc).

    ``check_*`` methods never mutate; ``commit`` applies a record returned by
    ``check_rules``. Errors are CubeproofError values; the journal converts plain contract
    errors to integrity errors and adds the line location.
    """

    def check_schema(self, value: Any) -> None: ...

    def check_header(self, value: Mapping[str, Any]) -> None: ...

    def check_rules(self, value: Mapping[str, Any]) -> R: ...

    def commit(self, record: R) -> None: ...

    def payload_json(self, payload: Any) -> dict[str, Any]: ...


def unsigned_sha256(value: Mapping[str, Any]) -> str:
    """``SHA256(J(record without self))`` of a record value whose types are J types.

    Values come from the strict reader or from a schema-checked payload: J is the same
    ``json.dumps`` call as :func:`cubeproof.base.canonical_json.encode`, without repeating
    its per-character checks; a lone surrogate still fails when encoding.
    """
    unsigned = {k: v for k, v in value.items() if k != "self"}
    text = json.dumps(
        unsigned, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    )
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def located(error: CubeproofError, location: str) -> CubeproofError:
    """``error`` in journal context at ``location`` (``<file>:<line>``).

    A plain contract error becomes an integrity error; input, resource and other classified
    errors keep their kind. A JSON location inside the record (``$.node.cube``) moves into
    the detail.
    """
    converted = contextualize(error, IntegrityError)
    if converted.location == location:
        return converted
    detail = converted.detail
    if converted.location is not None:
        detail = f"{converted.location}: {detail}" if detail else converted.location
    result = type(converted)(converted.rule, detail, location=location)
    result.__cause__ = error
    return result


def envelope_ok(value: Any) -> bool:
    """The envelope fields the chain reads have the right JSON types."""
    return (
        type(value) is dict
        and type(value.get("seq")) is int
        and type(value.get("self")) is str
        and type(value.get("prev")) is str
        and type(value.get("type")) is str
    )


class ChainState:
    """The validated chain of complete lines of one journal."""

    def __init__(self, *, name: str = "journal", limits: ReaderLimits = DEFAULT_LIMITS) -> None:
        self.name = name
        self.limits = limits
        self.records = 0
        self.offset = 0
        self.head: str | None = None
        self.journal_id: str | None = None
        self.last_line: bytes | None = None
        self.worker: str | None = None
        self.purpose: str | None = None

    def location(self, seq: int | None = None) -> str:
        return f"{self.name}:{(self.records if seq is None else seq) + 1}"

    def check(self, line: bytes, validator: RecordValidator[Any]) -> dict[str, Any]:
        """The record value of the next complete line (without LF), chain-checked; no mutation."""
        where = self.location()
        try:
            value: Any = parse_line(line, limits=self.limits)
            validator.check_schema(value)
            if not envelope_ok(value):
                raise IntegrityError("schema", "the validator accepted a record without envelope")
            if unsigned_sha256(value) != value["self"]:
                raise IntegrityError("journal.self", "self is not SHA256(J(record without self))")
            seq = self.records
            if value["seq"] != seq:
                raise IntegrityError("journal.seq", f"seq {value['seq']}, expected {seq}")
            expected = self.head if self.head is not None else ZERO_HASH
            if value["prev"] != expected:
                raise IntegrityError("journal.prev", "prev is not the previous self")
            if (seq == 0) != (value["type"] == HEADER):
                raise IntegrityError("journal.header", "seq 0 is the only header")
            if seq == 0:
                validator.check_header(value)
        except CubeproofError as error:
            raise located(error, where) from None
        result: dict[str, Any] = value
        return result

    def advance(self, value: Mapping[str, Any], line: bytes) -> None:
        """Apply a line accepted by :meth:`check`."""
        if self.records == 0:
            self.journal_id = value["self"]
            worker, purpose = value.get("worker"), value.get("purpose")
            self.worker = worker if isinstance(worker, str) else None
            self.purpose = purpose if isinstance(purpose, str) else None
        self.records += 1
        self.offset += len(line) + 1
        self.head = value["self"]
        self.last_line = bytes(line)
