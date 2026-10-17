"""The values that configure a run and describe its end (specification §12.1, §12.2).

:class:`RunConfig` is built by the CLI or API boundary (which alone reads the environment and
the command line); everything below receives it as one immutable value. :class:`RunResult` is
what a finished run reports: the exit code of specification §12.2 with the reason, the position of
the journal, the open work by state and the counters of the session. Errors that stop a run before
or while it works are raised as typed :class:`~cubeproof.base.errors.CubeproofError` values
after an orderly shutdown; :func:`exit_code_of` maps them to the same exit codes.
"""

from __future__ import annotations

import enum
import re
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cubeproof.base.errors import (
    ConfigurationError,
    InputError,
    IntegrityError,
    ResourceError,
    ToolError,
)
from cubeproof.base.settings import DEFAULT_LIMITS, ReaderLimits, ToolPaths
from cubeproof.contracts.enums import ExitCode
from cubeproof.contracts.primitives import is_name
from cubeproof.coordinator.resources import Probes

__all__ = ["Hooks", "RunConfig", "RunResult", "Stop", "exit_code_of"]

#: A named point of the run lifecycle (crash tests inject faults here; see ``Coordinator``).
Hooks = Callable[[str], None]

_POLICY_KEY = re.compile(r"[a-z_0-9]+(\.[a-z_0-9]+)*")


class Stop(str, enum.Enum):
    """Why the event loop ended (the cause behind the exit code)."""

    COMPLETE = "complete"  # nothing left that can be started
    INTERRUPTED = "interrupted"  # SIGINT/SIGTERM
    TIME = "time"  # --max-hours
    ANOMALY = "anomaly_limit"  # specification §6.5: stop new work, exit 6
    MACHINE = "machine_failures"  # specification §6.5: consecutive tool failures, exit 5
    SERVICE = "service_failed"  # the I/O service failed, exit 5


@dataclass(frozen=True)
class RunConfig:
    """Everything ``run`` needs (specification §12.1). ``tools`` are the explicit absolute paths."""

    campaign: Path
    results: Path
    work: Path
    worker: str
    tools: ToolPaths
    limits: ReaderLimits = DEFAULT_LIMITS
    jobs: int | None = None
    memory_bytes: int | None = None
    disk_bytes: int | None = None
    max_seconds: float | None = None
    policy_overrides: Mapping[str, Any] = field(default_factory=dict)
    proof_mode: str | None = None
    reopen_blocked: bool = False
    #: accept that policy fields of the session before, which this session does not name,
    #: return to the campaign's values (``check_policy_continuity`` of coordinator.measure)
    campaign_policy: bool = False
    #: accept that the cubeproof sources differ from those of the session before
    #: (``check_code_continuity`` of coordinator.measure)
    accept_code_change: bool = False
    #: ask the checker its known-answer questions before the session's first record
    #: (:mod:`cubeproof.tools.known_answer`). Off only for tests with scripted tools; a session
    #: that skips the control says so in its notes
    known_answer: bool = True
    #: argv of the I/O service process (the command layer builds ``python -m cubeproof ...``)
    service_argv: tuple[str, ...] = ()
    service_env: Mapping[str, str] | None = None
    #: package name -> directory of the sources recorded in the machinery manifest
    packages: Mapping[str, Path] | None = None
    probes: Probes | None = None
    hooks: Hooks | None = None
    cache: bool = True
    handle_signals: bool = True
    survivor_wait_ms: int = 3000
    stall_patience_ms: int = 30_000
    tick_ms: int = 10
    service_timeout_s: float = 60.0
    clock: Callable[[], int] = time.monotonic_ns

    def __post_init__(self) -> None:
        if not is_name(self.worker):
            raise ConfigurationError(
                "run.worker", f"{self.worker!r} is not a worker Name (a-z, 0-9, _ and -)"
            )
        for name in ("jobs", "memory_bytes", "disk_bytes"):
            value = getattr(self, name)
            if value is not None and (type(value) is not int or value < 1):
                raise ConfigurationError(f"run.{name}", f"{value!r} is not a positive integer")
        if self.max_seconds is not None and not self.max_seconds > 0:
            raise ConfigurationError("run.max_hours", "the time allocation must be positive")
        for key in self.policy_overrides:
            if not isinstance(key, str) or _POLICY_KEY.fullmatch(key) is None:
                raise ConfigurationError("run.policy_override", f"{key!r} is not a policy key")
        if self.proof_mode is not None and self.proof_mode not in ("transient", "retain", "stream"):
            raise ConfigurationError("run.proof_mode", f"{self.proof_mode!r} is not a proof mode")
        for name in ("survivor_wait_ms", "stall_patience_ms", "tick_ms"):
            value = getattr(self, name)
            if type(value) is not int or value < 0:
                raise ConfigurationError(f"run.{name}", f"{value!r} is not a nonnegative integer")


@dataclass(frozen=True)
class RunResult:
    """The end of a run that was not stopped by an error (see module doc)."""

    exit_code: int
    reason: Stop
    campaign: str
    worker: str
    journal: str | None
    seq: int
    head: str | None
    #: open work by ``(state, depth)`` as ``"<state>:<depth>" -> count``
    open: Mapping[str, int]
    #: counters of this session: attempts committed, splits, stops, reopens ...
    session: Mapping[str, int]
    anomalies: int
    models: int
    given_away: int
    #: ``used``, ``absent`` or ``fallback:<reason>``/``disabled``
    cache: str
    replayed_records: int
    #: the loop's own work per tick in milliseconds (``TickStats.report``): ticks, p50, p99, max
    ticks: Mapping[str, float] = field(default_factory=dict)
    notes: tuple[str, ...] = ()

    def to_json(self) -> dict[str, Any]:
        return {
            "exit_code": self.exit_code,
            "reason": self.reason.value,
            "campaign": self.campaign,
            "worker": self.worker,
            "journal": self.journal,
            "seq": self.seq,
            "head": self.head,
            "open": dict(self.open),
            "session": dict(self.session),
            "anomalies": self.anomalies,
            "models": self.models,
            "given_away": self.given_away,
            "cache": self.cache,
            "replayed_records": self.replayed_records,
            "ticks": dict(self.ticks),
            "notes": list(self.notes),
        }


def exit_code_of(error: BaseException) -> int:
    """The specification §12.2 exit code of an error that ended a command.

    ``ConfigurationError`` (usage, configuration, lock conflict) 3; an input error about the
    campaign or its bundles 3; an integrity error, a journal or reader-limit failure 4; a tool,
    I/O service or journal write failure 5; a resource shortage found by preflight 1 (a
    resource block: open work). Anything unclassified is an internal error: 4.
    """
    if isinstance(error, ConfigurationError):
        return int(ExitCode.USAGE)
    if isinstance(error, ToolError):
        return int(ExitCode.TOOL)
    if isinstance(error, ResourceError):
        reader = error.rule.startswith(("limit.", "certify."))
        return int(ExitCode.INTEGRITY if reader else ExitCode.OPEN)
    if isinstance(error, InputError) and not isinstance(error, IntegrityError):
        reader = error.rule.startswith(("journal.", "limit."))
        return int(ExitCode.INTEGRITY if reader else ExitCode.USAGE)
    return int(ExitCode.INTEGRITY)
