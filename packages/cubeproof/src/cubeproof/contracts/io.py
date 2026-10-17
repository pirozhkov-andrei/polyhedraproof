"""The protocol of the I/O service (specification §7.2, §8.1): typed jobs and results with attempt
IDs.

The coordinator sends one :class:`Job` per line and the service answers each with one
:class:`Result`; the first line the service sends is a :class:`Hello`. A line is
``J(value) + LF`` (specification §4.1), at most :data:`FRAME_LIMITS` long, so that one journal line
of 8 MiB fits into an append job. Every value carries ``protocol: cubeproof-io-1``.

A job has a positive job ID (strictly increasing per service), an optional attempt ID
(Id128), and a request naming the operation with its expected paths and hashes:

- ``hash``: measure size and SHA-256 of a regular file (no verdict: the binding compares);
- ``publish``: copy a checked proof to ``<area>/<node_id>-<proof_sha256>.lrat`` through
  ``<area>/tmp/<attempt_id>.lrat`` (specification §7.2 steps 1-3); needs the attempt ID;
- ``append``: commit a record payload supplied by the coordinator; an ``attempt`` payload
  needs the job's attempt ID to be its ``attempt_id``, any other payload no attempt ID;
- ``remove``: delete disposable files (work files, staging files);
- ``reconcile``: validate every committed artifact reference, then remove orphans.

A result names the job ID, the operation and the attempt ID of the job it answers, and
either a typed value or a :class:`Failure` (error kind, rule, detail, and whether the
service stopped). :meth:`Result.problem` checks that a result really answers a job: a
swapped job or attempt ID, another operation or a value that does not fit the request
(another artifact, a removal of a path that was not requested, a reconciliation that
claims to have removed a committed reference) is a problem, and the client stops the
service (specification §8.1: mismatched job/attempt IDs stop new work).

This module is pure: values, their JSON form and the frame codec.
"""

from __future__ import annotations

import enum
import functools
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, ClassVar

from cubeproof.base.canonical_json import encode, parse_line
from cubeproof.base.errors import (
    ConfigurationError,
    ContractError,
    CubeproofError,
    InputError,
    IntegrityError,
    ResourceError,
    ToolError,
)
from cubeproof.base.settings import DEFAULT_LIMITS, ReaderLimits
from cubeproof.contracts import fields as f
from cubeproof.contracts.primitives import INT_MAX, is_hash, is_id128, is_relpath
from cubeproof.contracts.values import Artifact, JsonObject

IO_PROTOCOL = "cubeproof-io-1"
MIB = 1 << 20
#: Specification §8.1: hash/copy work is done in chunks of at most 8 MiB, with journal commits
#: between.
MAX_CHUNK_BYTES = 8 * MIB
#: One frame: a journal line (specification §4.7: at most 8 MiB) plus the job envelope; two more
#: levels of nesting than a record.
FRAME_LIMITS = ReaderLimits(
    line_bytes=DEFAULT_LIMITS.line_bytes + 64 * 1024, depth=DEFAULT_LIMITS.depth + 4
)

#: The payload type whose records bind an attempt (specification §4.8), and its artifact fields.
ATTEMPT_TYPE = "attempt"
ARTIFACT_FIELDS = ("retained", "quarantined")


class Op(str, enum.Enum):
    """The operations of the service."""

    HASH = "hash"
    PUBLISH = "publish"
    APPEND = "append"
    REMOVE = "remove"
    RECONCILE = "reconcile"


class Area(str, enum.Enum):
    """A published artifact area below the results root (specification §7.2; decision 0011)."""

    PROOFS = "proofs"
    QUARANTINE = "quarantine"


STAGING = "tmp"


def artifact_path(area: Area, node_id: str, proof_sha256: str) -> str:
    """``<area>/<node_id>-<proof_sha256>.lrat``, relative to the results root."""
    if not is_hash(node_id) or not is_hash(proof_sha256):
        raise ContractError("schema", "an artifact name needs a node ID and a proof hash")
    return f"{Area(area).value}/{node_id}-{proof_sha256}.lrat"


def staging_path(area: Area, attempt_id: str) -> str:
    """``<area>/tmp/<attempt_id>.lrat``: the fresh copy on the target file system."""
    if not is_id128(attempt_id):
        raise ContractError("schema", f"{attempt_id!r} is not an Id128")
    return f"{Area(area).value}/{STAGING}/{attempt_id}.lrat"


def artifact_area(path: str) -> Area | None:
    """The area of a published artifact path ``<area>/<name>``, or None for any other path."""
    parts = path.split("/")
    if len(parts) != 2 or parts[1] in ("", ".", "..", STAGING):
        return None
    for area in Area:
        if parts[0] == area.value:
            return area
    return None


def absolute_path_problem(value: object) -> str | None:
    """Why ``value`` is not a normalized absolute local path, or None."""
    if type(value) is not str or not value.startswith("/"):
        return "not an absolute path"
    if "\0" in value:
        return "NUL in a path"
    if value == "/":
        return "the root directory"
    if any(part in ("", ".", "..") for part in value[1:].split("/")):
        return "not normalized (empty, '.' or '..' component, or a trailing '/')"
    return None


def _absolute(value: Any, at: str) -> str:
    problem = absolute_path_problem(value)
    if problem is not None:
        f.fail(at, f"{value!r}: {problem}")
    return str(value)


def _id128(value: Any, at: str) -> str:
    return f.matching(value, at, is_id128, "Id128")


def _hash(value: Any, at: str) -> str:
    return f.matching(value, at, is_hash, "Hash")


def _check(condition: bool, rule: str, detail: str) -> None:
    if not condition:
        raise ContractError(rule, detail)


# -- requests ------------------------------------------------------------------------------------


@dataclass(frozen=True)
class HashRequest:
    """Size and SHA-256 of the regular file ``path`` (opened without following a symlink)."""

    OP: ClassVar[Op] = Op.HASH
    path: str

    def __post_init__(self) -> None:
        _absolute(self.path, "$.args.path")

    @classmethod
    def from_json(cls, value: Any, at: str) -> HashRequest:
        f.obj(value, at, ("path",))
        return cls(_absolute(value["path"], f.member(at, "path")))

    def to_json(self) -> dict[str, Any]:
        return {"path": self.path}


@dataclass(frozen=True)
class PublishRequest:
    """Publish the checked proof ``source`` (``proof_bytes`` bytes, ``proof_sha256``)."""

    OP: ClassVar[Op] = Op.PUBLISH
    source: str
    area: Area
    node_id: str
    proof_sha256: str
    proof_bytes: int

    def __post_init__(self) -> None:
        _absolute(self.source, "$.args.source")
        if not isinstance(self.area, Area):
            raise ContractError("schema", f"{self.area!r} is not an artifact area")
        _hash(self.node_id, "$.args.node_id")
        _hash(self.proof_sha256, "$.args.proof_sha256")
        f.nonnegative(self.proof_bytes, "$.args.proof_bytes")

    @property
    def artifact(self) -> Artifact:
        """The artifact this publication produces (path, hash and size)."""
        path = artifact_path(self.area, self.node_id, self.proof_sha256)
        return Artifact(path, self.proof_sha256, self.proof_bytes)

    @classmethod
    def from_json(cls, value: Any, at: str) -> PublishRequest:
        f.obj(value, at, ("source", "area", "node_id", "proof_sha256", "proof_bytes"))
        area = f.choice(value["area"], f.member(at, "area"), [a.value for a in Area])
        return cls(
            _absolute(value["source"], f.member(at, "source")),
            Area(area),
            _hash(value["node_id"], f.member(at, "node_id")),
            _hash(value["proof_sha256"], f.member(at, "proof_sha256")),
            f.nonnegative(value["proof_bytes"], f.member(at, "proof_bytes")),
        )

    def to_json(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "area": self.area.value,
            "node_id": self.node_id,
            "proof_sha256": self.proof_sha256,
            "proof_bytes": self.proof_bytes,
        }


@dataclass(frozen=True)
class AppendRequest:
    """Commit ``payload`` (the record's ``type`` and payload fields) to the journal.

    The service passes it to the journal writer unchanged; it never builds a record.
    """

    OP: ClassVar[Op] = Op.APPEND
    payload: JsonObject

    def __post_init__(self) -> None:
        if not isinstance(self.payload, JsonObject):
            raise ContractError("schema", "an append payload is a JSON object")
        if type(self.payload_type) is not str:
            raise ContractError("schema", "an append payload names its record type")

    @classmethod
    def of(cls, value: Mapping[str, Any]) -> AppendRequest:
        return cls(JsonObject.from_json(dict(value), "$.args.payload"))

    @functools.cached_property
    def payload_type(self) -> object:
        return self.value().get("type")

    def value(self) -> dict[str, Any]:
        """A fresh copy of the payload value."""
        return self.payload.to_json()

    @classmethod
    def from_json(cls, value: Any, at: str) -> AppendRequest:
        f.obj(value, at, ("payload",))
        return cls(JsonObject.from_json(value["payload"], f.member(at, "payload")))

    def to_json(self) -> dict[str, Any]:
        return {"payload": self.value()}


@dataclass(frozen=True)
class RemoveRequest:
    """Delete these disposable files (missing ones are skipped: removal is repeatable)."""

    OP: ClassVar[Op] = Op.REMOVE
    paths: tuple[str, ...]

    def __post_init__(self) -> None:
        if type(self.paths) is not tuple:
            raise ContractError("schema", "remove paths are a tuple")
        for index, path in enumerate(self.paths):
            _absolute(path, f"$.args.paths[{index}]")
        _check(len(set(self.paths)) == len(self.paths), "schema", "repeated remove path")

    @classmethod
    def from_json(cls, value: Any, at: str) -> RemoveRequest:
        f.obj(value, at, ("paths",))
        return cls(tuple(f.items(value["paths"], f.member(at, "paths"), _absolute)))

    def to_json(self) -> dict[str, Any]:
        return {"paths": list(self.paths)}


@dataclass(frozen=True)
class ReconcileRequest:
    """Validate the committed references ``committed``, then remove orphans (specification §7.2,
    §7.3).

    ``committed`` are the retained/quarantined artifacts of every committed record (one per
    path, each ``<area>/<name>``).
    """

    OP: ClassVar[Op] = Op.RECONCILE
    committed: tuple[Artifact, ...]

    def __post_init__(self) -> None:
        if type(self.committed) is not tuple or not all(
            isinstance(a, Artifact) for a in self.committed
        ):
            raise ContractError("schema", "committed references are a tuple of artifacts")
        paths = [a.path for a in self.committed]
        _check(len(set(paths)) == len(paths), "schema", "repeated committed artifact path")
        for path in paths:
            _check(artifact_area(path) is not None, "schema", f"{path!r} is not in an area")

    @classmethod
    def of(cls, committed: Any) -> ReconcileRequest:
        return cls(tuple(sorted(committed, key=lambda a: a.path)))

    @property
    def paths(self) -> frozenset[str]:
        return frozenset(a.path for a in self.committed)

    @classmethod
    def from_json(cls, value: Any, at: str) -> ReconcileRequest:
        f.obj(value, at, ("committed",))
        return cls(
            tuple(f.items(value["committed"], f.member(at, "committed"), Artifact.from_json))
        )

    def to_json(self) -> dict[str, Any]:
        return {"committed": [a.to_json() for a in self.committed]}


Request = HashRequest | PublishRequest | AppendRequest | RemoveRequest | ReconcileRequest
REQUESTS: dict[Op, Any] = {
    Op.HASH: HashRequest,
    Op.PUBLISH: PublishRequest,
    Op.APPEND: AppendRequest,
    Op.REMOVE: RemoveRequest,
    Op.RECONCILE: ReconcileRequest,
}


def attempt_binding_problem(attempt_id: str | None, request: Any) -> str | None:
    """Why an attempt ID does not fit a request, or None (shared by contract and service)."""
    if isinstance(request, PublishRequest) and attempt_id is None:
        return "a publication belongs to an attempt"
    if isinstance(request, AppendRequest):
        payload = request.value()
        if payload.get("type") == ATTEMPT_TYPE:
            if attempt_id is None or payload.get("attempt_id") != attempt_id:
                return "the job's attempt ID is not the record's attempt_id"
        elif attempt_id is not None:
            return f"a {payload.get('type')!r} record belongs to no attempt"
    return None


@dataclass(frozen=True)
class Job:
    """One request to the service, with its job ID and attempt ID."""

    job_id: int
    attempt_id: str | None
    request: Request

    def __post_init__(self) -> None:
        if type(self.job_id) is not int or not 1 <= self.job_id <= INT_MAX:
            raise ContractError("schema", f"job ID {self.job_id!r} is not a positive integer")
        if self.attempt_id is not None and not is_id128(self.attempt_id):
            raise ContractError("schema", f"{self.attempt_id!r} is not an Id128")
        if type(self.request) not in REQUESTS.values():
            raise ContractError("schema", f"{type(self.request).__name__} is not a request")
        problem = attempt_binding_problem(self.attempt_id, self.request)
        if problem is not None:
            raise ContractError("io.attempt_mismatch", problem)

    @property
    def op(self) -> Op:
        op: Op = self.request.OP
        return op

    @classmethod
    def from_json(cls, value: Any, at: str = "$") -> Job:
        f.obj(value, at, ("protocol", "job", "op", "attempt_id", "args"))
        f.const(value["protocol"], f.member(at, "protocol"), IO_PROTOCOL)
        job_id = f.positive(value["job"], f.member(at, "job"))
        op = Op(f.choice(value["op"], f.member(at, "op"), [o.value for o in Op]))
        attempt = f.nullable(value["attempt_id"], f.member(at, "attempt_id"), _id128)
        request = REQUESTS[op].from_json(value["args"], f.member(at, "args"))
        return cls(job_id, attempt, request)

    def to_json(self) -> dict[str, Any]:
        return {
            "protocol": IO_PROTOCOL,
            "job": self.job_id,
            "op": self.op.value,
            "attempt_id": self.attempt_id,
            "args": self.request.to_json(),
        }


# -- results -------------------------------------------------------------------------------------


@dataclass(frozen=True)
class HashValue:
    bytes: int
    sha256: str

    def __post_init__(self) -> None:
        f.nonnegative(self.bytes, "$.value.bytes")
        _hash(self.sha256, "$.value.sha256")

    @classmethod
    def from_json(cls, value: Any, at: str) -> HashValue:
        f.obj(value, at, ("bytes", "sha256"))
        return cls(value["bytes"], value["sha256"])

    def to_json(self) -> dict[str, Any]:
        return {"bytes": self.bytes, "sha256": self.sha256}


@dataclass(frozen=True)
class PublishValue:
    """The durable artifact; ``reused`` when an equal file already had the final name."""

    artifact: Artifact
    reused: bool

    def __post_init__(self) -> None:
        if not isinstance(self.artifact, Artifact):
            raise ContractError("schema", "a publication result names an Artifact")
        f.boolean(self.reused, "$.value.reused")

    @classmethod
    def from_json(cls, value: Any, at: str) -> PublishValue:
        f.obj(value, at, ("artifact", "reused"))
        return cls(Artifact.from_json(value["artifact"], f.member(at, "artifact")), value["reused"])

    def to_json(self) -> dict[str, Any]:
        return {"artifact": self.artifact.to_json(), "reused": self.reused}


@dataclass(frozen=True)
class AppendValue:
    """The committed record's seq and self (the journal's new head), after its fsync."""

    seq: int
    head: str

    def __post_init__(self) -> None:
        f.nonnegative(self.seq, "$.value.seq")
        _hash(self.head, "$.value.head")

    @classmethod
    def from_json(cls, value: Any, at: str) -> AppendValue:
        f.obj(value, at, ("seq", "head"))
        return cls(value["seq"], value["head"])

    def to_json(self) -> dict[str, Any]:
        return {"seq": self.seq, "head": self.head}


@dataclass(frozen=True)
class RemoveValue:
    """The requested paths that existed and were removed."""

    removed: tuple[str, ...]

    def __post_init__(self) -> None:
        if type(self.removed) is not tuple:
            raise ContractError("schema", "removed paths are a tuple")
        for index, path in enumerate(self.removed):
            _absolute(path, f"$.value.removed[{index}]")

    @classmethod
    def from_json(cls, value: Any, at: str) -> RemoveValue:
        f.obj(value, at, ("removed",))
        return cls(tuple(f.items(value["removed"], f.member(at, "removed"), _absolute)))

    def to_json(self) -> dict[str, Any]:
        return {"removed": list(self.removed)}


def _relpath(value: Any, at: str) -> str:
    return f.matching(value, at, is_relpath, "RelPath")


@dataclass(frozen=True)
class ReconcileValue:
    """How many committed references were validated, and the removed orphans (relative)."""

    validated: int
    removed: tuple[str, ...]

    def __post_init__(self) -> None:
        f.nonnegative(self.validated, "$.value.validated")
        if type(self.removed) is not tuple:
            raise ContractError("schema", "removed paths are a tuple")
        for index, path in enumerate(self.removed):
            _relpath(path, f"$.value.removed[{index}]")

    @classmethod
    def from_json(cls, value: Any, at: str) -> ReconcileValue:
        f.obj(value, at, ("validated", "removed"))
        removed = tuple(f.items(value["removed"], f.member(at, "removed"), _relpath))
        return cls(value["validated"], removed)

    def to_json(self) -> dict[str, Any]:
        return {"validated": self.validated, "removed": list(self.removed)}


Value = HashValue | PublishValue | AppendValue | RemoveValue | ReconcileValue
VALUES: dict[Op, Any] = {
    Op.HASH: HashValue,
    Op.PUBLISH: PublishValue,
    Op.APPEND: AppendValue,
    Op.REMOVE: RemoveValue,
    Op.RECONCILE: ReconcileValue,
}

#: Error kinds (``CubeproofError.kind``) and their classes.
ERROR_KINDS: dict[str, type[CubeproofError]] = {
    cls.kind: cls
    for cls in (
        ConfigurationError,
        ToolError,
        ResourceError,
        ContractError,
        InputError,
        IntegrityError,
    )
}


@dataclass(frozen=True)
class Failure:
    """A job that failed: the typed error, and whether the service stopped (``fatal``).

    A fatal failure (durability, journal write, unexpected error) means the service accepts
    no further work; the coordinator stops new work and recovers by replay (specification §7.1,
    §8.1).
    """

    kind: str
    rule: str
    detail: str
    fatal: bool

    def __post_init__(self) -> None:
        f.choice(self.kind, "$.error.kind", ERROR_KINDS)
        f.string(self.rule, "$.error.rule", 1)
        f.string(self.detail, "$.error.detail")
        f.boolean(self.fatal, "$.error.fatal")

    @classmethod
    def of(cls, error: CubeproofError, *, fatal: bool) -> Failure:
        kind = error.kind if error.kind in ERROR_KINDS else ToolError.kind
        return cls(kind, error.rule, error.detail, fatal)

    def error(self) -> CubeproofError:
        """The error to raise for this failure (same class, rule and detail)."""
        return ERROR_KINDS[self.kind](self.rule, self.detail)

    @classmethod
    def from_json(cls, value: Any, at: str) -> Failure:
        f.obj(value, at, ("kind", "rule", "detail", "fatal"))
        return cls(value["kind"], value["rule"], value["detail"], value["fatal"])

    def to_json(self) -> dict[str, Any]:
        return {"kind": self.kind, "rule": self.rule, "detail": self.detail, "fatal": self.fatal}


def value_problem(outcome: Value | Failure, request: Request) -> str | None:
    """Why a value does not fit the request it answers, or None."""
    problem: str | None = None
    if isinstance(outcome, PublishValue) and isinstance(request, PublishRequest):
        if outcome.artifact != request.artifact:
            problem = "the published artifact is not the requested one"
    elif isinstance(outcome, RemoveValue) and isinstance(request, RemoveRequest):
        if not set(outcome.removed) <= set(request.paths):
            problem = "a removed path was not requested"
        elif len(set(outcome.removed)) != len(outcome.removed):
            problem = "a path reported removed twice"
    elif isinstance(outcome, ReconcileValue) and isinstance(request, ReconcileRequest):
        if set(outcome.removed) & request.paths:
            problem = "a committed reference reported removed"
        elif outcome.validated != len(request.committed):
            problem = "not every committed reference was validated"
    return problem


@dataclass(frozen=True)
class Result:
    """The answer to one job: its IDs and operation, and a value or a failure."""

    job_id: int
    op: Op
    attempt_id: str | None
    outcome: Value | Failure

    def __post_init__(self) -> None:
        if type(self.job_id) is not int or not 1 <= self.job_id <= INT_MAX:
            raise ContractError("schema", f"job ID {self.job_id!r} is not a positive integer")
        if not isinstance(self.op, Op):
            raise ContractError("schema", f"{self.op!r} is not an operation")
        if self.attempt_id is not None and not is_id128(self.attempt_id):
            raise ContractError("schema", f"{self.attempt_id!r} is not an Id128")
        if not isinstance(self.outcome, (Failure, VALUES[self.op])):
            raise ContractError("schema", f"a {self.op.value} result cannot hold this value")

    @property
    def ok(self) -> bool:
        return not isinstance(self.outcome, Failure)

    def problem(self, job: Job) -> str | None:
        """Why this result does not answer ``job``, or None."""
        if self.job_id != job.job_id:
            return f"result for job {self.job_id}, not {job.job_id}"
        if self.op is not job.op:
            return f"a {self.op.value} result for a {job.op.value} job"
        if self.attempt_id != job.attempt_id:
            return f"attempt {self.attempt_id} answered for attempt {job.attempt_id}"
        return value_problem(self.outcome, job.request)

    @classmethod
    def from_json(cls, value: Any, at: str = "$") -> Result:
        f.obj(value, at, ("protocol", "job", "op", "attempt_id", "status", "value", "error"))
        f.const(value["protocol"], f.member(at, "protocol"), IO_PROTOCOL)
        job_id = f.positive(value["job"], f.member(at, "job"))
        op = Op(f.choice(value["op"], f.member(at, "op"), [o.value for o in Op]))
        attempt = f.nullable(value["attempt_id"], f.member(at, "attempt_id"), _id128)
        status = f.choice(value["status"], f.member(at, "status"), ("ok", "failed"))
        outcome: Value | Failure
        if status == "ok":
            if value["error"] is not None:
                f.fail(f.member(at, "error"), "an ok result has no error")
            outcome = VALUES[op].from_json(value["value"], f.member(at, "value"))
        else:
            if value["value"] is not None:
                f.fail(f.member(at, "value"), "a failed result has no value")
            outcome = Failure.from_json(value["error"], f.member(at, "error"))
        return cls(job_id, op, attempt, outcome)

    def to_json(self) -> dict[str, Any]:
        failed = isinstance(self.outcome, Failure)
        return {
            "protocol": IO_PROTOCOL,
            "job": self.job_id,
            "op": self.op.value,
            "attempt_id": self.attempt_id,
            "status": "failed" if failed else "ok",
            "value": None if failed else self.outcome.to_json(),
            "error": self.outcome.to_json() if failed else None,
        }


@dataclass(frozen=True)
class Hello:
    """The service's first line: its process ID and the committed journal position."""

    pid: int
    seq: int | None
    head: str | None

    def __post_init__(self) -> None:
        if type(self.pid) is not int or not 1 <= self.pid <= INT_MAX:
            raise ContractError("schema", f"pid {self.pid!r} is not a positive integer")
        if (self.seq is None) != (self.head is None):
            raise ContractError("schema", "a journal position has both seq and head")
        if self.seq is not None:
            f.nonnegative(self.seq, "$.hello.seq")
            _hash(self.head, "$.hello.head")

    @classmethod
    def from_json(cls, value: Any, at: str = "$") -> Hello:
        f.obj(value, at, ("protocol", "hello"))
        f.const(value["protocol"], f.member(at, "protocol"), IO_PROTOCOL)
        body = f.obj(value["hello"], f.member(at, "hello"), ("pid", "seq", "head"))
        return cls(body["pid"], body["seq"], body["head"])

    def to_json(self) -> dict[str, Any]:
        return {
            "protocol": IO_PROTOCOL,
            "hello": {"pid": self.pid, "seq": self.seq, "head": self.head},
        }


# -- frames --------------------------------------------------------------------------------------


def encode_frame(value: Mapping[str, Any]) -> bytes:
    """One line: ``J(value) + LF``."""
    return encode(dict(value)) + b"\n"


def decode_frame(line: bytes) -> dict[str, Any]:
    """The object of one frame without its LF: canonical J, bounded (ResourceError)."""
    value = parse_line(line, limits=FRAME_LIMITS)
    if type(value) is not dict:
        raise ContractError("schema", "a frame is a JSON object")
    return value
