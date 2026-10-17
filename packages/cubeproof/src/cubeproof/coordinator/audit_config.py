"""The values that configure an audit execution and describe its end (specification §11.2, §12.1,
§12.2).

:class:`AuditConfig` is the execution environment of ``audit`` (results and work directories,
worker, tool paths, RAM/disk budgets, proof cap, the I/O service command); the CLI or API
boundary builds it. :class:`AuditWork` is what the command layer decided before anything runs:
the bound campaign, the plan records and the rules that judge a target. The executor
(:mod:`.audit_run`) asks for it through a ``prepare`` callback only once it holds the results
directory's lock, so the certified-input snapshots and the plan are made under that lock; it
never selects targets or decides a status itself. :class:`AuditRun` is how an execution ended.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cubeproof.base.errors import ConfigurationError
from cubeproof.base.settings import DEFAULT_LIMITS, ReaderLimits, ToolPaths
from cubeproof.cnf.campaign import LoadedCampaign
from cubeproof.contracts.enums import AuditStatus
from cubeproof.contracts.primitives import is_name
from cubeproof.coordinator.config import Hooks, Stop
from cubeproof.coordinator.resources import Probes
from cubeproof.evidence.schema import (
    Attempt,
    AuditBegin,
    AuditReady,
    AuditTarget,
    AuditTargetRecord,
    Machinery,
    Payload,
    Record,
)

__all__ = ["AuditConfig", "AuditRun", "AuditWork", "CheckPlan", "Decide", "Prepare", "Runnable"]

#: Whether the session with the given measured machinery runs ``target`` (strict: only with
#: the source solver; ``commands.audit_report.runnable``).
Runnable = Callable[[AuditTarget, Machinery], bool]
#: The ``(status, reason)`` of a target's audit_result from its attempt and the machinery in
#: force at that attempt (``commands.audit_report.classify_result``).
Decide = Callable[[AuditTarget, Attempt, Machinery], tuple[AuditStatus, str]]
#: How many plan targets the journal already holds (IntegrityError if anything differs).
CheckPlan = Callable[[AuditBegin | None, Sequence[AuditTarget], AuditReady | None], int]
#: Called with the locked, resolved results directory; returns the work of this audit.
Prepare = Callable[[Path], "AuditWork"]


@dataclass(frozen=True)
class AuditConfig:
    """Everything the audit executor needs besides the plan (specification §11.2, §12.1).

    ``tools`` are the explicit absolute local paths of the solver and checker (a helper is
    not used: an audit never splits); ``memory_bytes``/``disk_bytes`` are budgets like
    ``run --memory/--disk``; ``proof_cap_bytes`` replaces the default cap (the larger of the
    campaign policy's cap and the largest selected reference proof) before the specification §8.3
    clamp."""

    results: Path
    work: Path
    worker: str
    tools: ToolPaths
    limits: ReaderLimits = DEFAULT_LIMITS
    memory_bytes: int | None = None
    disk_bytes: int | None = None
    proof_cap_bytes: int | None = None
    #: as ``RunConfig.known_answer``: the known-answer control of the checker before any record
    known_answer: bool = True
    #: argv of the I/O service process (the command layer builds ``python -m cubeproof ...``)
    service_argv: tuple[str, ...] = ()
    service_env: Mapping[str, str] | None = None
    #: package name -> directory of the sources recorded in the machinery manifest
    packages: Mapping[str, Path] | None = None
    probes: Probes | None = None
    hooks: Hooks | None = None
    handle_signals: bool = True
    survivor_wait_ms: int = 3000
    tick_ms: int = 10
    clock: Callable[[], int] = time.monotonic_ns

    def __post_init__(self) -> None:
        if not is_name(self.worker):
            raise ConfigurationError(
                "audit.worker", f"{self.worker!r} is not a worker Name (a-z, 0-9, _ and -)"
            )
        for name in ("memory_bytes", "disk_bytes", "proof_cap_bytes"):
            value = getattr(self, name)
            if value is not None and (type(value) is not int or value < 1):
                raise ConfigurationError(f"audit.{name}", f"{value!r} is not a positive integer")
        for name in ("survivor_wait_ms", "tick_ms"):
            value = getattr(self, name)
            if type(value) is not int or value < 0:
                raise ConfigurationError(f"audit.{name}", f"{value!r} is not a nonnegative integer")
        if self.tools.solver is None or self.tools.checker is None:
            raise ConfigurationError("audit.tools", "the solver and the checker paths are required")


@dataclass(frozen=True)
class AuditWork:
    """The plan and the rules of one audit, decided by the command layer (module doc).

    ``plan`` are the plan records in journal order: ``audit_begin``, one ``audit_target`` per
    ordinal, ``audit_ready``. ``observe`` sees every record of the journal (replayed and new)
    and raises at the first violated audit-journal rule. ``conclude`` is called with the
    journal path after a session that ended without an error and with a complete plan, while
    the lock is still held (the command layer derives and publishes the report there).
    ``reference_bytes`` is the size of the largest selected reference proof."""

    campaign: LoadedCampaign
    plan: tuple[Payload, ...]
    runnable: Runnable
    decide: Decide
    check_plan: CheckPlan
    observe: Callable[[Record], None] | None = None
    conclude: Callable[[Path], None] | None = None
    reference_bytes: int = 0

    def __post_init__(self) -> None:
        plan = self.plan
        if len(plan) < 2 or not isinstance(plan[0], AuditBegin):
            raise ValueError("a plan starts with audit_begin")
        if not isinstance(plan[-1], AuditReady):
            raise ValueError("a plan ends with audit_ready")
        middle = plan[1:-1]
        if not all(isinstance(p, AuditTargetRecord) for p in middle):
            raise ValueError("the plan's middle records are audit_target records")
        if [p.ordinal for p in middle if isinstance(p, AuditTargetRecord)] != list(
            range(len(middle))
        ):
            raise ValueError("audit_target ordinals are 0..n-1 in order")
        if type(self.reference_bytes) is not int or self.reference_bytes < 0:
            raise ValueError("reference_bytes is a nonnegative integer")

    @property
    def begin(self) -> AuditBegin:
        first = self.plan[0]
        assert isinstance(first, AuditBegin)
        return first

    @property
    def ready(self) -> AuditReady:
        last = self.plan[-1]
        assert isinstance(last, AuditReady)
        return last

    @property
    def targets(self) -> tuple[AuditTarget, ...]:
        return tuple(p.target for p in self.plan[1:-1] if isinstance(p, AuditTargetRecord))


@dataclass(frozen=True)
class AuditRun:
    """How an audit execution ended (the report is the command layer's).

    ``stop`` is ``complete`` when every target has a committed result, ``interrupted`` after a
    signal, ``service_failed`` when the I/O service failed; ``pending`` counts the targets
    without a committed result."""

    stop: Stop
    journal: str | None
    seq: int
    head: str | None
    pending: int
    session: Mapping[str, int] = field(default_factory=dict)
    notes: tuple[str, ...] = ()

    def to_json(self) -> dict[str, Any]:
        return {
            "reason": self.stop.value,
            "journal": self.journal,
            "seq": self.seq,
            "head": self.head,
            "pending": self.pending,
            "session": dict(self.session),
            "notes": list(self.notes),
        }
