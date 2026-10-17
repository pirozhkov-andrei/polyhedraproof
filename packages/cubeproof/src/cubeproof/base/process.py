"""Pure values of child processes: ProcessResult, CheckerCheck, typed causes, bounded tails.

Nothing here starts, waits for or signals a process; the supervisor that does lives in
``cubeproof.tools.process``. These values are shared by the tool layer and its callers and
mirror the journal schema values of specification §4.6 (``evidence.schema.values``) field for field.

- :class:`ProcessResult` has exactly the specification §4.6 fields and rules: exit and signal are
  exclusive, a process that did not start has neither (process.exit_signal,
  process.not_started), tails hold at most 16 KiB of UTF-8 (process.tail_size). ``cause`` is a
  diagnostic code, never authority for verification.
- :class:`Cause` is the vocabulary of typed supervisor actions and observations (specification §6.3:
  coordinator actions are tracked as typed causes). The outcome table reads these, never a
  signal number alone.
- :class:`OutputTail` drains an output stream in bounded memory: the last ``limit`` bytes, the
  total count and, optionally, the complete output while it fits ``capture`` bytes.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass
from typing import Any

from cubeproof.base.errors import ContractError

#: Maximum UTF-8 length of a stdout/stderr tail (specification §4.1 reader limit, rule
#: process.tail_size).
TAIL_BYTES = 16 * 1024


class Cause(str, enum.Enum):
    """Typed causes the supervisor records for one process, in the order they happen."""

    #: The process could not be started (fork/exec/working directory/wrapper start failure).
    LAUNCH = "launch"
    #: The pinned binary was missing or not identical before the spawn or after the exit.
    BINARY_CHANGED = "binary_changed"
    #: The supervisor reached the process deadline and sent TERM (KILL after the grace).
    DEADLINE = "deadline"
    #: The supervisor observed the watched output file at its cap while the process ran.
    PROOF_CAP = "proof_cap"
    #: A deliberate user stop terminated the process; it is not a tool failure (specification §6.2).
    CANCELLED = "cancelled"
    #: The coordinator attributed a memory event (cgroup OOM) to this process.
    MEMORY_EVENT = "memory_event"
    #: After the exit, an untracked descendant kept stdout/stderr open beyond the grace.
    HELD_OPEN = "output_held_open"


def _utf8_length(text: str) -> int:
    return len(text.encode("utf-8"))


def _int(value: object, low: int, high: int | None = None) -> bool:
    return type(value) is int and value >= low and (high is None or value <= high)


def _text(value: object) -> bool:
    if not isinstance(value, str):
        return False
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


def _schema(condition: bool, name: str, value: object) -> None:
    if not condition:
        raise ContractError("schema", f"ProcessResult.{name} = {value!r}")


@dataclass(frozen=True)
class ProcessResult:
    """Status of one child process (specification §4.6), validated on construction."""

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

    def __post_init__(self) -> None:
        _schema(type(self.started) is bool, "started", self.started)
        _schema(self.exit is None or _int(self.exit, 0, 255), "exit", self.exit)
        _schema(self.signal is None or _int(self.signal, 1), "signal", self.signal)
        _schema(_int(self.elapsed_ms, 0), "elapsed_ms", self.elapsed_ms)
        _schema(_text(self.stdout_tail), "stdout_tail", self.stdout_tail)
        _schema(_text(self.stderr_tail), "stderr_tail", self.stderr_tail)
        _schema(_int(self.stdout_bytes, 0), "stdout_bytes", self.stdout_bytes)
        _schema(type(self.stdout_truncated) is bool, "stdout_truncated", self.stdout_truncated)
        _schema(self.cause is None or (_text(self.cause) and self.cause != ""), "cause", self.cause)
        _schema(self.conflicts is None or _int(self.conflicts, 0), "conflicts", self.conflicts)
        if self.exit is not None and self.signal is not None:
            raise ContractError("process.exit_signal", f"exit {self.exit} and signal {self.signal}")
        if not self.started and (self.exit is not None or self.signal is not None):
            raise ContractError("process.not_started", "a process that did not start has no status")
        for name in ("stdout_tail", "stderr_tail"):
            if _utf8_length(getattr(self, name)) > TAIL_BYTES:
                raise ContractError("process.tail_size", f"{name} exceeds {TAIL_BYTES} bytes")

    @classmethod
    def not_started(cls, cause: Cause, *, elapsed_ms: int = 0) -> ProcessResult:
        """The result of a process that never ran."""
        return cls(
            started=False,
            exit=None,
            signal=None,
            elapsed_ms=elapsed_ms,
            stdout_tail="",
            stderr_tail="",
            stdout_bytes=0,
            stdout_truncated=False,
            cause=cause.value,
            conflicts=None,
        )

    def to_json(self) -> dict[str, Any]:
        """The specification §4.6 JSON object, fields in specification order."""
        return {
            "started": self.started,
            "exit": self.exit,
            "signal": self.signal,
            "elapsed_ms": self.elapsed_ms,
            "stdout_tail": self.stdout_tail,
            "stderr_tail": self.stderr_tail,
            "stdout_bytes": self.stdout_bytes,
            "stdout_truncated": self.stdout_truncated,
            "cause": self.cause,
            "conflicts": self.conflicts,
        }


@dataclass(frozen=True)
class CheckerCheck:
    """One checker run with the arenas it was given (specification §4.6)."""

    result: ProcessResult
    heap_mib: int
    stack_mib: int

    def __post_init__(self) -> None:
        if not isinstance(self.result, ProcessResult):
            raise ContractError("schema", "CheckerCheck.result is not a ProcessResult")
        for name in ("heap_mib", "stack_mib"):
            value = getattr(self, name)
            if not _int(value, 1):
                raise ContractError("schema", f"CheckerCheck.{name} = {value!r}")

    def to_json(self) -> dict[str, Any]:
        return {
            "result": self.result.to_json(),
            "heap_mib": self.heap_mib,
            "stack_mib": self.stack_mib,
        }


def decode_tail(data: bytes, limit: int = TAIL_BYTES) -> tuple[str, int]:
    """Text of a suffix of ``data`` (at most ``limit`` bytes long) that fits ``limit`` bytes.

    Invalid bytes become U+FFFD (never a surrogate), which can triple the size, so the suffix
    is shortened until its text fits. Returns the text and how many bytes of ``data`` it
    represents (a suffix of that length); the caller reports truncation from that count.
    """
    if type(limit) is not int or limit < 1:
        raise ValueError("limit must be a positive integer")
    size = min(len(data), limit)
    while True:
        text = data[len(data) - size :].decode("utf-8", "replace")
        excess = _utf8_length(text) - limit
        if excess <= 0:
            return text, size
        size -= max(1, excess // 3)


class OutputTail:
    """Bounded drain buffer of one output stream.

    ``feed`` accepts any amount of data in constant memory (at most ``limit`` tail bytes and
    ``capture`` captured bytes are kept). ``total`` counts every byte. ``text()`` gives the
    tail text and whether any byte of the stream is not represented in it. ``captured`` is
    the complete output when it fits ``capture`` bytes, otherwise None.
    """

    def __init__(self, limit: int = TAIL_BYTES, capture: int = 0) -> None:
        if type(limit) is not int or not 1 <= limit <= TAIL_BYTES:
            raise ValueError(f"tail limit must be 1..{TAIL_BYTES}")
        if type(capture) is not int or capture < 0:
            raise ValueError("capture must be a nonnegative integer")
        self.limit = limit
        self.capture = capture
        self.total = 0
        self._tail = bytearray()
        self._captured: bytearray | None = bytearray() if capture > 0 else None

    def feed(self, data: bytes) -> None:
        if not data:
            return
        self.total += len(data)
        if self._captured is not None:
            if len(self._captured) + len(data) <= self.capture:
                self._captured += data
            else:
                self._captured = None
        self._tail += data[-self.limit :]
        if len(self._tail) > self.limit:
            del self._tail[: len(self._tail) - self.limit]

    @property
    def retained(self) -> int:
        """Bytes of the tail currently held."""
        return len(self._tail)

    @property
    def captured(self) -> bytes | None:
        return None if self._captured is None else bytes(self._captured)

    def text(self) -> tuple[str, bool]:
        """The tail text (at most ``limit`` UTF-8 bytes) and whether the stream was cut."""
        text, represented = decode_tail(bytes(self._tail), self.limit)
        return text, self.total > represented
