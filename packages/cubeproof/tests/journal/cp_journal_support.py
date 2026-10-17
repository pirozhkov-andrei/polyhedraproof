"""Test-only helpers of the journal tests: corpus access, journal surgery, fault injection.

The corpus (``tests/contracts/corpus``) and the schemas (``schemas/cubeproof/v1``) are produced
independently of this package and are the expected values here. The schema
validator ``tests/contracts/contract_schema.py`` is the independent oracle of the differential
schema tests. Nothing here is imported by runtime code.
"""

from __future__ import annotations

import base64
import errno
import hashlib
import json
import os
import re
import sys
from collections.abc import Callable, Iterable, Mapping
from pathlib import Path
from typing import Any

from cubeproof.cnf.campaign import load_campaign
from cubeproof.evidence import journal
from cubeproof.evidence.journal import Anchor, JournalContents, JournalWriter, SysCalls
from cubeproof.evidence.schema import ExtraRules, JournalContext, Record, RecordSequence

REPO = Path(__file__).resolve().parents[4]
CORPUS = REPO / "tests" / "contracts" / "corpus"
SCHEMAS = REPO / "schemas" / "cubeproof" / "v1"
CONTRACT_TESTS = REPO / "tests" / "contracts"
ZERO = "0" * 64

#: Journal-context rules whose consumers include the journal reader (requirements.json);
#: the reader must report exactly these on the corpus cases.
JOURNAL_READER_RULES = frozenset(
    {
        "json.utf8",
        "json.bom",
        "json.syntax",
        "json.duplicate_key",
        "json.number",
        "json.integer_range",
        "json.surrogate",
        "json.canonical",
        "limit.depth",
        "limit.line",
        "schema",
        "utc.calendar",
        "cube.canonical",
        "cube.range",
        "shard.nodes",
        "shard.hash",
        "shard.campaign",
        "handoff.pair",
        "handoff.count",
        "handoff.request_unique",
        "machinery.manifest_order",
        "machinery.packages_sha256",
        "machinery.cubeproof_sha256",
        "policy.stack",
        "policy.stream_heap",
        "process.exit_signal",
        "process.not_started",
        "process.tail_size",
        "journal.no_header",
        "journal.header",
        "journal.self",
        "journal.seq",
        "journal.prev",
        "journal.campaign",
        "journal.purpose",
        "record.formula",
        "record.node_id",
        "attempt.policy_sha256",
        "attempt.attempt_id",
        "attempt.reason",
        "attempt.solver",
        "attempt.relay",
        "attempt.proof_pair",
        "attempt.stream_proof",
        "attempt.model_shape",
        "attempt.model_error",
        "attempt.assignment",
        "attempt.retained",
        "attempt.quarantined",
    }
)
#: Rules that need the bundles, admission or several journals: the certifier's and the
#: binding's. The journal reader accepts journals that violate only these.
DELEGATED_RULES = frozenset(
    {
        "attempt.cnf_sha256",
        "attempt.model_false",
        "success.proof",
        "success.checks",
        "success.checker_output",
        "success.solver",
        "success.relay",
        "journal.fork",
        "journal.worker",
    }
)


# -- corpus -------------------------------------------------------------------------------------


def load_json(relative: str) -> Any:
    return json.loads((CORPUS / relative).read_bytes())


def corpus_bytes(relative: str) -> bytes:
    return (CORPUS / relative).read_bytes()


def documents(kind: str) -> list[dict[str, Any]]:
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


def cases() -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = load_json("cases.json")["cases"]
    return entries


def schema_store() -> Any:
    """A contract ``SchemaStore`` over ``schemas/cubeproof/v1`` (independent schema oracle)."""
    if str(CONTRACT_TESTS) not in sys.path:
        sys.path.insert(0, str(CONTRACT_TESTS))
    import contract_schema

    return contract_schema.SchemaStore(SCHEMAS)


def record_schema_errors(store: Any, value: Any) -> list[str]:
    """Schema errors of one record, against the definition named by its type."""
    kind = value.get("type") if isinstance(value, dict) else None
    if isinstance(kind, str) and kind in load_json_schema_types():
        errors: list[str] = store.errors(value, "journal-record.schema.json", "/$defs/" + kind)
        return errors
    root: list[str] = store.errors(value, "journal-record.schema.json")
    return root


_TYPES: list[frozenset[str]] = []


def load_json_schema_types() -> frozenset[str]:
    if not _TYPES:
        schema = json.loads((SCHEMAS / "journal-record.schema.json").read_bytes())
        _TYPES.append(frozenset(schema["$defs"]))
    return _TYPES[0]


def schema_locations(errors: list[str]) -> set[str]:
    return {e.split(": ", 1)[0] for e in errors}


_CONTEXTS: dict[str, JournalContext] = {}


def campaign_context(relative: str) -> JournalContext:
    """The journal context (campaign ID, V per formula) of a corpus campaign, from its loader."""
    if relative not in _CONTEXTS:
        loaded = load_campaign(CORPUS / relative)
        variables = {sha: b.formula.variables for sha, b in loaded.bundles.items()}
        _CONTEXTS[relative] = JournalContext(loaded.campaign.campaign_id, variables)
    return _CONTEXTS[relative]


_HASH_TEXT = re.compile(r'"formula_sha256":"([0-9a-f]{64})"')


def variables_for(text: bytes, count: int) -> dict[str, int]:
    """V = ``count`` for every formula a record mentions (document fixtures' context)."""
    return dict.fromkeys(_HASH_TEXT.findall(text.decode("utf-8", "replace")), count)


# -- wiring of the journal layer with the record schema (as certify/leaf/coordinator do) ---------


def records(
    context: JournalContext | None = None, extra: ExtraRules | None = None
) -> RecordSequence:
    """A validator; ``context=None`` (no campaign) is the tests' deliberate default."""
    return RecordSequence(context=context, extra=extra)


def sequence_of(owner: Any) -> RecordSequence:
    """The RecordSequence validator of a reader result or writer (typed for the tests)."""
    validator = owner.validator
    assert isinstance(validator, RecordSequence)
    return validator


def read_journal(
    source: Any,
    *,
    context: JournalContext | None = None,
    extra: ExtraRules | None = None,
    **options: Any,
) -> JournalContents[Record]:
    return journal.read_journal(source, records(context, extra), **options)


def create(
    path: Any, header: Any, *, context: JournalContext | None = None, **options: Any
) -> JournalWriter[Record]:
    return JournalWriter.create(path, header, validator=records(context), **options)


def open_writer(
    path: Any, *, context: JournalContext | None = None, **options: Any
) -> JournalWriter[Record]:
    return JournalWriter.open(path, validator=records(context), **options)


def repair(path: Any, **options: Any) -> journal.RepairOutcome | None:
    return journal.repair_journal(path, validator=records(), **options)


def snapshot(path: Any, anchor: Anchor, **options: Any) -> JournalContents[Record]:
    return journal.read_snapshot(path, anchor, records(), **options)


# -- journal surgery ------------------------------------------------------------------------------


def j(value: Any) -> bytes:
    """J(x), written independently of the runtime encoder."""
    text = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return text.encode("utf-8")


def sign(record: dict[str, Any]) -> dict[str, Any]:
    """The record with ``self`` recomputed (specification §7.1)."""
    unsigned = {k: v for k, v in record.items() if k != "self"}
    return {**unsigned, "self": hashlib.sha256(j(unsigned)).hexdigest()}


def records_of(data: bytes) -> list[dict[str, Any]]:
    """The complete records of journal bytes (no validation)."""
    lines = data.split(b"\n")[:-1]
    return [json.loads(line) for line in lines]


def chain(records: Iterable[dict[str, Any]]) -> bytes:
    """Journal bytes with seq, prev and self recomputed for ``records`` in order."""
    out = []
    prev = ZERO
    for seq, record in enumerate(records):
        signed = sign({**record, "seq": seq, "prev": prev})
        prev = signed["self"]
        out.append(j(signed) + b"\n")
    return b"".join(out)


def lines_of(data: bytes) -> list[bytes]:
    return data.split(b"\n")[:-1]


# -- fault injection -------------------------------------------------------------------------------


class Crash(BaseException):
    """A simulated process death at a chosen system call (not an OSError)."""


class TraceCalls(SysCalls):
    """Real system calls, recorded in order, with optional faults per call kind.

    ``faults`` maps a call name to a function ``(call_number, *args) -> None`` that may raise
    or return a replacement result; the call number counts calls of that name from 1.
    ``write_limit`` caps the bytes accepted by one write (short writes).
    """

    def __init__(
        self,
        *,
        faults: Mapping[str, Callable[..., Any]] | None = None,
        write_limit: int | None = None,
        sync: bool = True,
    ) -> None:
        self.log: list[tuple[Any, ...]] = []
        self.faults = dict(faults or {})
        self.counts: dict[str, int] = {}
        self.write_limit = write_limit
        self.sync = sync

    def _fault(self, name: str, *args: Any) -> Any:
        self.counts[name] = self.counts.get(name, 0) + 1
        fault = self.faults.get(name)
        if fault is None:
            return None
        return fault(self.counts[name], *args)

    def open(self, path: str, flags: int, mode: int = 0o644) -> int:
        self._fault("open", path, flags)
        fd = super().open(path, flags, mode)
        self.log.append(("open", os.fspath(path), flags, fd))
        return fd

    def close(self, fd: int) -> None:
        self.log.append(("close", fd))
        super().close(fd)

    def write(self, fd: int, data: memoryview) -> int:
        replaced = self._fault("write", fd, bytes(data))
        if replaced is not None:
            self.log.append(("write", fd, replaced))
            count: int = replaced
            return count
        view = data if self.write_limit is None else data[: self.write_limit]
        written = super().write(fd, view)
        self.log.append(("write", fd, written))
        return written

    def fsync(self, fd: int) -> None:
        self._fault("fsync", fd)
        self.log.append(("fsync", fd))
        if self.sync:
            super().fsync(fd)

    def flock(self, fd: int, operation: int) -> None:
        self._fault("flock", fd, operation)
        self.log.append(("flock", fd, operation))
        super().flock(fd, operation)

    def ftruncate(self, fd: int, length: int) -> None:
        self._fault("ftruncate", fd, length)
        self.log.append(("ftruncate", fd, length))
        super().ftruncate(fd, length)

    def size(self, fd: int) -> int:
        replaced = self._fault("size", fd)
        if replaced is not None:
            size: int = replaced
            return size
        return super().size(fd)

    def pread(self, fd: int, count: int, offset: int) -> bytes:
        return super().pread(fd, count, offset)

    def names(self) -> list[str]:
        return [entry[0] for entry in self.log]


def fail_with(code: int, *, after: int = 0) -> Callable[..., Any]:
    """A fault raising ``OSError(code)`` from call number ``after + 1`` on."""

    def fault(number: int, *args: Any) -> Any:
        if number > after:
            raise OSError(code, os.strerror(code))
        return None

    return fault


def interrupt(times: int) -> Callable[..., Any]:
    """A fault raising InterruptedError (EINTR) on the first ``times`` calls."""

    def fault(number: int, *args: Any) -> Any:
        if number <= times:
            raise InterruptedError(errno.EINTR, "interrupted")
        return None

    return fault
