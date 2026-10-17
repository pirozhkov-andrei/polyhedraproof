"""Shared value types of journal records (specification §4.6-§4.8, §11.1): machinery, resources,
processes.

Every value is a frozen dataclass whose field names are the JSON names. Direct construction
validates: the value is dumped to JSON, checked against its schema and its own rules
(machinery.*, process.*, record.node_id of an audit target) and its fields are replaced by
canonical ones (tuples, enum members, contract values). ``to_json`` returns a fresh JSON value.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, ClassVar

from cubeproof.base.errors import ContractError
from cubeproof.contracts.enums import Route
from cubeproof.contracts.identity import cube_problem, node_id
from cubeproof.contracts.values import Node, Ref
from cubeproof.evidence.schema import spec as s
from cubeproof.evidence.schema.rules import machinery_problem, process_problem


class _Value:
    """Mixin: validation on construction and ``to_json`` through the class's spec."""

    SPEC: ClassVar[s.Struct]

    def __post_init__(self) -> None:
        s.validate(self, type(self).SPEC)

    def to_json(self) -> dict[str, Any]:
        value: dict[str, Any] = type(self).SPEC.dump(self)
        return value

    @classmethod
    def from_json(cls, value: Any, at: str = "$") -> Any:
        """Schema level and rules of a JSON value, then the value (ContractError otherwise)."""
        spec = cls.SPEC
        spec.check(value, at)
        if spec.rule is not None:
            problem = spec.rule(value)
            if problem is not None:
                raise ContractError(problem, f"{cls.__name__} violates {problem}", location=at)
        return spec.build(value)


@dataclass(frozen=True)
class SolverInfo(_Value):
    path: str
    sha256: str
    version: str
    argv: tuple[str, ...]


@dataclass(frozen=True)
class CheckerInfo(_Value):
    path: str
    sha256: str


@dataclass(frozen=True)
class HelperInfo(_Value):
    sha256: str
    algorithm: str


@dataclass(frozen=True)
class RuntimeInfo(_Value):
    python: str
    libc: str
    platform: str
    image_digest: str | None


@dataclass(frozen=True)
class ManifestEntry(_Value):
    path: str
    sha256: str


@dataclass(frozen=True)
class Machinery(_Value):
    """Measured tools, runtime and installed sources of a header/resume (specification §4.6)."""

    solver: SolverInfo
    checker: CheckerInfo
    helper: HelperInfo | None
    runtime: RuntimeInfo
    source_manifest: tuple[ManifestEntry, ...]
    packages_sha256: str
    cubeproof_sha256: str
    unit_algorithm: str = "unit-v1"


@dataclass(frozen=True)
class Filesystem(_Value):
    id: str
    paths: tuple[str, ...]
    free_bytes: int
    budget_bytes: int


@dataclass(frozen=True)
class ResourceSnapshot(_Value):
    """Observed resources (specification §4.7); an observation, not an admission condition."""

    cpu_milli: int
    memory_budget_bytes: int
    filesystems: tuple[Filesystem, ...]
    coordinator_rss_bytes: int


@dataclass(frozen=True)
class ProcessResult(_Value):
    """Status of one child process (specification §4.6). ``cause`` is diagnostic, never
    authority."""

    started: bool
    exit: int | None
    signal: int | None
    elapsed_ms: int
    stdout_tail: str
    stderr_tail: str
    stdout_bytes: int
    stdout_truncated: bool
    cause: str | None
    conflicts: int | None


@dataclass(frozen=True)
class CheckerCheck(_Value):
    result: ProcessResult
    heap_mib: int
    stack_mib: int


@dataclass(frozen=True)
class Limits(_Value):
    solver_time_ms: int | None
    proof_cap_bytes: int
    solver_memory_bytes: int
    check_time_ms: int


@dataclass(frozen=True)
class Relay(_Value):
    """Stream transfer counters (specification §4.8, §6.4); partial counts never stand for a
    proof."""

    bytes: int
    sha256: str
    solver_eof: bool
    all_written: bool
    error: str | None


@dataclass(frozen=True)
class AuditTarget(_Value):
    """A planned audit target (specification §11.1); its identity hash is SHA256(J(target))."""

    node: Node
    node_id: str
    source: Ref
    cnf_sha256: str
    proof_sha256: str
    route: Route
    machinery: Machinery


SOLVER_INFO = s.Struct(
    SolverInfo,
    (("path", s.STRING), ("sha256", s.HASH), ("version", s.STRING), ("argv", s.Array(s.STRING))),
)
CHECKER_INFO = s.Struct(CheckerInfo, (("path", s.STRING), ("sha256", s.HASH)))
HELPER_INFO = s.Struct(HelperInfo, (("sha256", s.HASH), ("algorithm", s.STRING)))
RUNTIME_INFO = s.Struct(
    RuntimeInfo,
    (
        ("python", s.STRING),
        ("libc", s.STRING),
        ("platform", s.STRING),
        ("image_digest", s.Nullable(s.STRING)),
    ),
)
MANIFEST_ENTRY = s.Struct(ManifestEntry, (("path", s.RELPATH), ("sha256", s.HASH)))
MACHINERY = s.Struct(
    Machinery,
    (
        ("solver", SOLVER_INFO),
        ("checker", CHECKER_INFO),
        ("helper", s.Nullable(HELPER_INFO)),
        ("runtime", RUNTIME_INFO),
        ("source_manifest", s.Array(MANIFEST_ENTRY)),
        ("packages_sha256", s.HASH),
        ("cubeproof_sha256", s.HASH),
        ("unit_algorithm", s.Const("unit-v1")),
    ),
    machinery_problem,
)
FILESYSTEM = s.Struct(
    Filesystem,
    (
        ("id", s.STRING),
        ("paths", s.Array(s.STRING)),
        ("free_bytes", s.NONNEGATIVE),
        ("budget_bytes", s.NONNEGATIVE),
    ),
)
RESOURCES = s.Struct(
    ResourceSnapshot,
    (
        ("cpu_milli", s.POSITIVE),
        ("memory_budget_bytes", s.NONNEGATIVE),
        ("filesystems", s.Array(FILESYSTEM)),
        ("coordinator_rss_bytes", s.NONNEGATIVE),
    ),
)
PROCESS = s.Struct(
    ProcessResult,
    (
        ("started", s.BOOLEAN),
        ("exit", s.Nullable(s.integer(0, 255))),
        ("signal", s.Nullable(s.POSITIVE)),
        ("elapsed_ms", s.NONNEGATIVE),
        ("stdout_tail", s.STRING),
        ("stderr_tail", s.STRING),
        ("stdout_bytes", s.NONNEGATIVE),
        ("stdout_truncated", s.BOOLEAN),
        ("cause", s.Nullable(s.STRING)),
        ("conflicts", s.Nullable(s.NONNEGATIVE)),
    ),
    process_problem,
)


def _check_rule(value: dict[str, Any]) -> str | None:
    return process_problem(value["result"])


CHECK = s.Struct(
    CheckerCheck,
    (("result", PROCESS), ("heap_mib", s.POSITIVE), ("stack_mib", s.POSITIVE)),
    _check_rule,
)
LIMITS = s.Struct(
    Limits,
    (
        ("solver_time_ms", s.Nullable(s.POSITIVE)),
        ("proof_cap_bytes", s.POSITIVE),
        ("solver_memory_bytes", s.POSITIVE),
        ("check_time_ms", s.POSITIVE),
    ),
)
RELAY = s.Struct(
    Relay,
    (
        ("bytes", s.NONNEGATIVE),
        ("sha256", s.HASH),
        ("solver_eof", s.BOOLEAN),
        ("all_written", s.BOOLEAN),
        ("error", s.Nullable(s.STRING)),
    ),
)


def _audit_target_rule(value: dict[str, Any]) -> str | None:
    node = value["node"]
    problem = cube_problem(node["cube"])
    if problem is not None:
        return problem
    if value["node_id"] != node_id(node["formula_sha256"], node["cube"]):
        return "record.node_id"
    return machinery_problem(value["machinery"])


AUDIT_TARGET = s.Struct(
    AuditTarget,
    (
        ("node", s.NodeSpec()),
        ("node_id", s.HASH),
        ("source", s.Wrapped(Ref)),
        ("cnf_sha256", s.HASH),
        ("proof_sha256", s.HASH),
        ("route", s.Enum(Route)),
        ("machinery", MACHINERY),
    ),
    _audit_target_rule,
)

SolverInfo.SPEC = SOLVER_INFO
CheckerInfo.SPEC = CHECKER_INFO
HelperInfo.SPEC = HELPER_INFO
RuntimeInfo.SPEC = RUNTIME_INFO
ManifestEntry.SPEC = MANIFEST_ENTRY
Machinery.SPEC = MACHINERY
Filesystem.SPEC = FILESYSTEM
ResourceSnapshot.SPEC = RESOURCES
ProcessResult.SPEC = PROCESS
CheckerCheck.SPEC = CHECK
Limits.SPEC = LIMITS
Relay.SPEC = RELAY
AuditTarget.SPEC = AUDIT_TARGET
