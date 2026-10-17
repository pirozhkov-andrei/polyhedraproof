"""Journal records ``cubeproof-journal-1`` (specification §4.7, §4.8, §7.1): payloads, envelope,
codec.

A record is flat: the envelope fields ``format, seq, prev, self, type, utc`` sit beside the
payload fields (requirement record.flat). ``self = SHA256(J(record without self))``. A line
is J(record); on disk it is followed by one LF.

- :func:`check_record_schema` checks the schema of the record's type.
- :func:`parse_record` reads one line (without its LF) in the order of specification §7.1 for a
  single record: canonical bytes, schema, self, then the record rules of
  :mod:`cubeproof.evidence.schema.rules`. Chain rules (seq, prev, header, campaign) need the
  journal and are checked by :mod:`cubeproof.evidence.journal`.
- :func:`build_record` makes the record of a payload at a given seq/prev/utc (the writer).

Payload values validate themselves on construction ("record building is structural
validation"); rules that need V, the bundles, admission or other records are not part of
construction. Binding a checker result to a VERIFIED_UNSAT record is ``leaf.binding``'s.
Errors are plain :class:`~cubeproof.base.errors.ContractError` (or ResourceError for reader
limits); the journal reader decides that they are integrity errors.
"""

from __future__ import annotations

import functools
import hashlib
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, ClassVar

from cubeproof.base.canonical_json import parse_line
from cubeproof.base.errors import ContractError
from cubeproof.base.settings import DEFAULT_LIMITS, ReaderLimits
from cubeproof.contracts import fields as f
from cubeproof.contracts.documents import HandoffRequest, Shard
from cubeproof.contracts.enums import (
    REASONS,
    AuditComparison,
    AuditStatus,
    ModelError,
    Outcome,
    ProofMode,
    Purpose,
    RecordType,
    Route,
    StopState,
)
from cubeproof.contracts.policy import Policy
from cubeproof.contracts.primitives import utc_problem
from cubeproof.contracts.values import Artifact, JsonObject, Node, Ref, Splitter
from cubeproof.evidence.schema import spec as s
from cubeproof.evidence.schema.rules import payload_problem, record_problem
from cubeproof.evidence.schema.values import (
    AUDIT_TARGET,
    CHECK,
    LIMITS,
    MACHINERY,
    PROCESS,
    RELAY,
    RESOURCES,
    AuditTarget,
    CheckerCheck,
    Limits,
    Machinery,
    ProcessResult,
    Relay,
    ResourceSnapshot,
)

JOURNAL_FORMAT = "cubeproof-journal-1"
ENVELOPE: tuple[str, ...] = ("format", "seq", "prev", "self", "type", "utc")

#: The closed reason vocabulary of attempts (requirement attempt.reason_vocabulary).
REASON_VOCABULARY: frozenset[str] = frozenset().union(*REASONS.values()) | frozenset(
    m.value for m in ModelError
)
#: The schema pattern of ``assignment``; canonicality and length are attempt.assignment.
_BASE64_PATTERN = re.compile(r"(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?")


def _is_base64(text: str) -> bool:
    return _BASE64_PATTERN.fullmatch(text) is not None


_BASE64 = s.Scalar(
    lambda value, at: f.matching(value, at, _is_base64, "padded standard base64 string")
)


class Payload:
    """Base of the payload of one record type (specification §4.7 table). Validates on
    construction."""

    TYPE: ClassVar[RecordType]
    SPEC: ClassVar[s.Struct]

    def __post_init__(self) -> None:
        s.validate(self, type(self).SPEC)

    def to_json(self) -> dict[str, Any]:
        """The payload fields only (no envelope)."""
        value: dict[str, Any] = type(self).SPEC.dump(self)
        return value


@dataclass(frozen=True)
class Header(Payload):
    """Seq 0 of every journal: worker, campaign, purpose and the first snapshot."""

    worker: str
    campaign: str
    purpose: Purpose
    machinery: Machinery
    policy: Policy
    resources: ResourceSnapshot


@dataclass(frozen=True)
class Resume(Payload):
    """A new snapshot on every restart, before new activity (specification §7.3)."""

    machinery: Machinery
    policy: Policy
    resources: ResourceSnapshot


@dataclass(frozen=True)
class ShardRecord(Payload):
    shard: Shard
    shard_sha256: str


@dataclass(frozen=True)
class SplitRecord(Payload):
    """A journal split; semantic problems of W are anomalies of the certifier (specification
    §10.1)."""

    node: Node
    variables: tuple[int, ...]
    splitter: Splitter


@dataclass(frozen=True)
class Attempt(Payload):
    """One terminal attempt (specification §4.8)."""

    node: Node
    node_id: str
    attempt_id: str
    policy_sha256: str
    route: Route
    proof_mode: ProofMode
    outcome: Outcome
    reason: str | None
    cnf_sha256: str
    limits: Limits
    solver: ProcessResult | None
    checks: tuple[CheckerCheck, ...]
    proof_bytes: int | None
    proof_sha256: str | None
    relay: Relay | None
    assignment: str | None
    model_error: ModelError | None
    retained: Artifact | None
    quarantined: Artifact | None
    diagnostics: JsonObject


@dataclass(frozen=True)
class NodeStop(Payload):
    node: Node
    state: StopState
    reason: str
    policy_sha256: str


@dataclass(frozen=True)
class NodeReopen(Payload):
    node: Node
    reason: str
    policy_sha256: str


@dataclass(frozen=True)
class Handoff(Payload):
    """A completed handoff: the request and the shard given away (null: zero nodes)."""

    request: HandoffRequest
    shard: Shard | None
    shard_sha256: str | None


@dataclass(frozen=True)
class Repair(Payload):
    """A removed torn tail: its length and SHA-256 (specification §7.1)."""

    removed_bytes: int
    removed_sha256: str


@dataclass(frozen=True)
class AuditBegin(Payload):
    certificate_sha256: str
    sample_count: int
    seed: str
    targets_sha256: str
    target_count: int
    comparison: AuditComparison


@dataclass(frozen=True)
class AuditTargetRecord(Payload):
    target: AuditTarget
    ordinal: int


@dataclass(frozen=True)
class AuditReady(Payload):
    targets_sha256: str
    target_count: int


@dataclass(frozen=True)
class AuditResult(Payload):
    target: AuditTarget
    attempt: Ref
    status: AuditStatus
    reason: str


_NODE = s.NodeSpec()
_POLICY = s.PolicySpec()
_SHARD = s.ShardSpec()


def _payload_spec(cls: type[Payload], fields: tuple[tuple[str, s.Spec], ...]) -> s.Struct:
    kind = cls.TYPE

    def rule(value: dict[str, Any]) -> str | None:
        return payload_problem(kind, value)

    return s.Struct(cls, fields, rule)


_FIELDS: dict[type[Payload], tuple[RecordType, tuple[tuple[str, s.Spec], ...]]] = {
    Header: (
        RecordType.HEADER,
        (
            ("worker", s.NAME),
            ("campaign", s.HASH),
            ("purpose", s.Enum(Purpose)),
            ("machinery", MACHINERY),
            ("policy", _POLICY),
            ("resources", RESOURCES),
        ),
    ),
    Resume: (
        RecordType.RESUME,
        (("machinery", MACHINERY), ("policy", _POLICY), ("resources", RESOURCES)),
    ),
    ShardRecord: (RecordType.SHARD, (("shard", _SHARD), ("shard_sha256", s.HASH))),
    SplitRecord: (
        RecordType.SPLIT,
        (
            ("node", _NODE),
            ("variables", s.Array(s.POSITIVE)),
            ("splitter", s.Wrapped(Splitter)),
        ),
    ),
    Attempt: (
        RecordType.ATTEMPT,
        (
            ("node", _NODE),
            ("node_id", s.HASH),
            ("attempt_id", s.ID128),
            ("policy_sha256", s.HASH),
            ("route", s.Enum(Route)),
            ("proof_mode", s.Enum(ProofMode)),
            ("outcome", s.Enum(Outcome)),
            ("reason", s.Nullable(s.Choice(REASON_VOCABULARY))),
            ("cnf_sha256", s.HASH),
            ("limits", LIMITS),
            ("solver", s.Nullable(PROCESS)),
            ("checks", s.Array(CHECK)),
            ("proof_bytes", s.Nullable(s.NONNEGATIVE)),
            ("proof_sha256", s.Nullable(s.HASH)),
            ("relay", s.Nullable(RELAY)),
            ("assignment", s.Nullable(_BASE64)),
            ("model_error", s.Nullable(s.Enum(ModelError))),
            ("retained", s.Nullable(s.Wrapped(Artifact))),
            ("quarantined", s.Nullable(s.Wrapped(Artifact))),
            ("diagnostics", s.OpenSpec()),
        ),
    ),
    NodeStop: (
        RecordType.NODE_STOP,
        (
            ("node", _NODE),
            ("state", s.Enum(StopState)),
            ("reason", s.STRING),
            ("policy_sha256", s.HASH),
        ),
    ),
    NodeReopen: (
        RecordType.NODE_REOPEN,
        (("node", _NODE), ("reason", s.STRING), ("policy_sha256", s.HASH)),
    ),
    Handoff: (
        RecordType.HANDOFF,
        (
            ("request", s.Wrapped(HandoffRequest)),
            ("shard", s.Nullable(_SHARD)),
            ("shard_sha256", s.Nullable(s.HASH)),
        ),
    ),
    Repair: (
        RecordType.REPAIR,
        (("removed_bytes", s.POSITIVE), ("removed_sha256", s.HASH)),
    ),
    AuditBegin: (
        RecordType.AUDIT_BEGIN,
        (
            ("certificate_sha256", s.HASH),
            ("sample_count", s.NONNEGATIVE),
            ("seed", s.HASH),
            ("targets_sha256", s.HASH),
            ("target_count", s.NONNEGATIVE),
            ("comparison", s.Enum(AuditComparison)),
        ),
    ),
    AuditTargetRecord: (
        RecordType.AUDIT_TARGET,
        (("target", AUDIT_TARGET), ("ordinal", s.NONNEGATIVE)),
    ),
    AuditReady: (
        RecordType.AUDIT_READY,
        (("targets_sha256", s.HASH), ("target_count", s.NONNEGATIVE)),
    ),
    AuditResult: (
        RecordType.AUDIT_RESULT,
        (
            ("target", AUDIT_TARGET),
            ("attempt", s.Wrapped(Ref)),
            ("status", s.Enum(AuditStatus)),
            ("reason", s.STRING),
        ),
    ),
}

#: Payload class of each wire type.
PAYLOADS: dict[str, type[Payload]] = {}
for _cls, (_kind, _fields) in _FIELDS.items():
    _cls.TYPE = _kind
    _cls.SPEC = _payload_spec(_cls, _fields)
    PAYLOADS[_kind.value] = _cls
if set(PAYLOADS) != {t.value for t in RecordType}:  # pragma: no cover - table invariant
    raise RuntimeError("every record type needs exactly one payload class")


def _envelope(kind: str) -> tuple[tuple[str, s.Spec], ...]:
    return (
        ("format", s.Const(JOURNAL_FORMAT)),
        ("seq", s.NONNEGATIVE),
        ("prev", s.HASH),
        ("self", s.HASH),
        ("type", s.Const(kind)),
        ("utc", s.UTC),
    )


def check_record_schema(value: Any) -> None:
    """The schema of the record type named by ``value["type"]`` (ContractError ``schema``).

    A value that is not an object, or names no known type, fails at ``$`` (the root
    ``anyOf`` of journal-record.schema.json).
    """
    if type(value) is not dict:
        f.fail("$", f"expected a record object, got {type(value).__name__}")
    kind = value.get("type")
    if type(kind) is not str or kind not in PAYLOADS:
        f.fail("$", f"no record type {kind!r}")
    fields = _envelope(kind) + PAYLOADS[kind].SPEC.fields
    f.obj(value, "$", tuple(name for name, _ in fields))
    for name, spec in fields:
        spec.check(value[name], f.member("$", name))


def record_self(value: Mapping[str, Any]) -> str:
    """``SHA256(J(record without self))`` (specification §7.1); ``self`` itself is ignored."""
    unsigned = {k: v for k, v in value.items() if k != "self"}
    return hashlib.sha256(s.checked_j(unsigned)).hexdigest()


@dataclass(frozen=True)
class Record:
    """One complete, validated journal record: envelope and typed payload.

    Build it with :func:`build_record` (writer) or :func:`parse_record` (reader); direct
    construction checks the envelope and that ``self_hash`` is the record's self.
    """

    seq: int
    prev: str
    self_hash: str
    utc: str
    payload: Payload

    def __post_init__(self) -> None:
        if not isinstance(self.payload, Payload):
            raise ContractError("schema", "a record payload is a Payload value")
        _check_envelope(self.seq, self.prev, self.utc)
        s.HASH.check(self.self_hash, "$.self")
        if record_self(self.to_json()) != self.self_hash:
            raise ContractError("journal.self", "self is not SHA256(J(record without self))")

    @property
    def type(self) -> RecordType:
        return self.payload.TYPE

    def to_json(self) -> dict[str, Any]:
        value = self.payload.to_json()
        value.update(
            format=JOURNAL_FORMAT,
            seq=self.seq,
            prev=self.prev,
            self=self.self_hash,
            type=self.payload.TYPE.value,
            utc=self.utc,
        )
        return value

    @functools.cached_property
    def line(self) -> bytes:
        """J(record): the line on disk without its LF."""
        return s.checked_j(self.to_json())


def _check_envelope(seq: Any, prev: Any, utc: Any) -> None:
    s.NONNEGATIVE.check(seq, "$.seq")
    s.HASH.check(prev, "$.prev")
    s.UTC.check(utc, "$.utc")
    if utc_problem(utc) is not None:
        raise ContractError("utc.calendar", f"{utc!r} is not a valid instant", location="$.utc")


def record_from_checked(value: Mapping[str, Any]) -> Record:
    """The Record of a value that passed the schema, self and the record rules (trusted)."""
    payload = PAYLOADS[value["type"]].SPEC.build(value)
    return s.construct(
        Record,
        {
            "seq": value["seq"],
            "prev": value["prev"],
            "self_hash": value["self"],
            "utc": value["utc"],
            "payload": payload,
        },
    )


def check_record(value: Any, *, variables: Mapping[str, int] | None = None) -> Record:
    """Schema, self and record rules of a parsed record value, in this order."""
    check_record_schema(value)
    if record_self(value) != value["self"]:
        raise ContractError("journal.self", "self is not SHA256(J(record without self))")
    problem = record_problem(value, variables)
    if problem is not None:
        raise ContractError(problem, f"{value['type']} record violates {problem}")
    return record_from_checked(value)


def parse_record(
    line: bytes,
    *,
    variables: Mapping[str, int] | None = None,
    limits: ReaderLimits = DEFAULT_LIMITS,
) -> Record:
    """One journal line without its LF: canonical bytes, schema, self, record rules.

    ``variables`` maps formula hashes to V; with it, node formulas must be among its keys
    (record.formula) and cube ranges and assignment lengths are checked.
    """
    return check_record(parse_line(line, limits=limits), variables=variables)


def read_record(
    data: bytes,
    *,
    variables: Mapping[str, int] | None = None,
    limits: ReaderLimits = DEFAULT_LIMITS,
) -> Record:
    """A standalone record document: exactly J(record) followed by one LF."""
    raw = bytes(data)
    if not raw.endswith(b"\n"):
        raise ContractError("json.canonical", "a journal line ends with LF")
    return parse_record(raw[:-1], variables=variables, limits=limits)


def build_record(payload: Payload, *, seq: int, prev: str, utc: str) -> Record:
    """The record of ``payload`` at ``seq`` after ``prev`` (``self`` computed)."""
    if not isinstance(payload, Payload):
        raise ContractError("schema", "a record payload is a Payload value")
    _check_envelope(seq, prev, utc)
    value = payload.to_json()
    value.update(format=JOURNAL_FORMAT, seq=seq, prev=prev, type=payload.TYPE.value, utc=utc)
    self_hash = record_self(value)
    return s.construct(
        Record, {"seq": seq, "prev": prev, "self_hash": self_hash, "utc": utc, "payload": payload}
    )


__all__ = [
    "ENVELOPE",
    "JOURNAL_FORMAT",
    "PAYLOADS",
    "REASON_VOCABULARY",
    "Attempt",
    "AuditBegin",
    "AuditReady",
    "AuditResult",
    "AuditTargetRecord",
    "Handoff",
    "Header",
    "NodeReopen",
    "NodeStop",
    "Payload",
    "Record",
    "Repair",
    "Resume",
    "ShardRecord",
    "SplitRecord",
    "build_record",
    "check_record",
    "check_record_schema",
    "parse_record",
    "read_record",
    "record_from_checked",
    "record_self",
]
