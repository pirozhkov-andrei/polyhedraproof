"""Enumerations of the file formats (specification §4.3-§4.9, §11, §12) with their exact wire
spellings.

Each enum is a ``str`` (or ``int``) enum, so a member compares equal to its wire value and
``Enum(value)`` parses it. The reason vocabulary per outcome is closed
(requirement attempt.reason_vocabulary): any other reason is a schema violation.
"""

from __future__ import annotations

import enum
from collections.abc import Mapping
from types import MappingProxyType


class Outcome(str, enum.Enum):
    VERIFIED_UNSAT = "VERIFIED_UNSAT"
    EXHAUSTED = "EXHAUSTED"
    MODEL = "MODEL"
    INVALID_MODEL = "INVALID_MODEL"
    CHECK_REJECTED = "CHECK_REJECTED"
    TOOL_FAILED = "TOOL_FAILED"


class Route(str, enum.Enum):
    UNIT = "unit"
    CDCL = "cdcl"


class ProofMode(str, enum.Enum):
    TRANSIENT = "transient"
    RETAIN = "retain"
    STREAM = "stream"


class ModelError(str, enum.Enum):
    MISSING = "missing"
    CONFLICTING = "conflicting"
    OUT_OF_RANGE = "out_of_range"
    SYNTAX = "syntax"
    VIOLATED = "violated"


class StopState(str, enum.Enum):
    """``node_stop.state`` (specification §4.7)."""

    STUCK = "stuck"
    TOOL_BLOCKED = "tool_blocked"
    RESOURCE_BLOCKED = "resource_blocked"


class OpenState(str, enum.Enum):
    """``OpenNode.state`` of a certificate (specification §4.9)."""

    PENDING = "pending"
    STUCK = "stuck"
    TOOL_BLOCKED = "tool_blocked"
    RESOURCE_BLOCKED = "resource_blocked"
    MODEL = "model"


class Verdict(str, enum.Enum):
    PROVED = "PROVED"
    OPEN = "OPEN"
    MODEL_FOUND = "MODEL_FOUND"
    INCONSISTENT = "INCONSISTENT"


class AuditStatus(str, enum.Enum):
    HASH_MATCHED = "HASH_MATCHED"
    REPROVED_UNSAT = "REPROVED_UNSAT"
    MISMATCH = "MISMATCH"
    NOT_COMPARABLE = "NOT_COMPARABLE"
    FAILED = "FAILED"
    OPEN = "OPEN"


class AuditComparison(str, enum.Enum):
    STRICT = "strict"
    REPROVE = "reprove"


class Purpose(str, enum.Enum):
    RUN = "run"
    AUDIT = "audit"


class RecordType(str, enum.Enum):
    """Journal record types in the order of the table of specification §4.7."""

    HEADER = "header"
    RESUME = "resume"
    SHARD = "shard"
    SPLIT = "split"
    ATTEMPT = "attempt"
    NODE_STOP = "node_stop"
    NODE_REOPEN = "node_reopen"
    HANDOFF = "handoff"
    REPAIR = "repair"
    AUDIT_BEGIN = "audit_begin"
    AUDIT_TARGET = "audit_target"
    AUDIT_READY = "audit_ready"
    AUDIT_RESULT = "audit_result"


class Lifecycle(str, enum.Enum):
    """``status.json`` lifecycle (specification §12.3)."""

    RUNNING = "running"
    DRAINING = "draining"
    STOPPED = "stopped"


class ExitCode(enum.IntEnum):
    """Process exit codes of the CLI (specification §12.2); only the CLI exits."""

    SUCCESS = 0
    OPEN = 1
    MODEL = 2
    USAGE = 3
    INTEGRITY = 4
    TOOL = 5
    ANOMALY = 6
    INTERRUPTED = 130


#: The closed reason vocabulary of outcomes that carry a reason. VERIFIED_UNSAT and MODEL
#: have reason null; INVALID_MODEL has reason = its model_error.
REASONS: Mapping[Outcome, frozenset[str]] = MappingProxyType(
    {
        Outcome.EXHAUSTED: frozenset(
            {"proof_size", "time", "check_time", "check_memory", "check_stack", "solver_memory"}
        ),
        Outcome.TOOL_FAILED: frozenset(
            {"launch", "binary_changed", "io", "file_changed", "crash", "protocol", "relay"}
        ),
        Outcome.CHECK_REJECTED: frozenset({"rejected"}),
    }
)
