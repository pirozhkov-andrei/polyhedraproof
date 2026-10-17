"""Writing ``status.json`` and ``status.txt`` into the results directory (specification §8.4,
§12.3).

Both files are derived monitors, so they are written for cheapness and atomicity, not durability: a
temporary file in the same directory, one ``rename`` over the final name, no fsync (a crash loses at
most the last snapshot, and the next run writes a new one). ``status.txt`` is replaced first and
``status.json`` last, so a reader that sees a new ``status.json`` also finds the text of that or a
newer snapshot. At most one snapshot is written per ``interval_ms`` (default 10 s) except
for a lifecycle change, which is forced through.

A failing write never reaches the loop as an exception: the :class:`PublishOutcome` carries the
error and the publisher counts it. Slow disks are visible: the time of the last write and the
number of writes slower than ``slow_ms`` are reported in :meth:`details`, which the next snapshot
embeds in ``info.status_write``."""

from __future__ import annotations

import os
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from cubeproof.base.errors import CubeproofError
from cubeproof.base.ids import new_id128
from cubeproof.coordinator.status_format import render_status, status_bytes
from cubeproof.tools.atomic import OS_FILE_CALLS, FileCalls, os_failure, remove_quietly, write_all

__all__ = ["JSON_NAME", "TEXT_NAME", "PublishOutcome", "StatusPublisher"]

JSON_NAME = "status.json"
TEXT_NAME = "status.txt"


def _monotonic_ms() -> int:
    return int(time.monotonic() * 1000)


@dataclass(frozen=True)
class PublishOutcome:
    """The result of one publication: written or not, how long it took, the error if any."""

    written: bool
    ms: int
    bytes: int
    error: CubeproofError | None = None


class StatusPublisher:
    """Rate-limited atomic publication of status documents (module doc)."""

    def __init__(
        self,
        results: str | os.PathLike[str],
        *,
        interval_ms: int = 10_000,
        slow_ms: int = 1_000,
        calls: FileCalls = OS_FILE_CALLS,
        monotonic_ms: Callable[[], int] = _monotonic_ms,
    ) -> None:
        if interval_ms < 1 or slow_ms < 1:
            raise ValueError("interval_ms and slow_ms must be positive")
        self.results = os.fspath(results)
        self.interval_ms = interval_ms
        self.slow_ms = slow_ms
        self._calls = calls
        self._now = monotonic_ms
        self._last: int | None = None
        self.writes = 0
        self.failures = 0
        self.slow_writes = 0
        self.last_ms = 0
        self.last_bytes = 0
        self.last_error: str | None = None

    def due(self, now_ms: int | None = None) -> bool:
        """Whether the interval since the last publication has passed (always true at first)."""
        now = self._now() if now_ms is None else now_ms
        return self._last is None or now - self._last >= self.interval_ms

    def publish(
        self, doc: dict[str, Any], now_ms: int | None = None, *, force: bool = False
    ) -> PublishOutcome:
        """Write ``doc`` unless the interval has not passed (``force`` ignores it).

        The document is validated first: an invalid status is a programming error and raises
        :class:`~cubeproof.base.errors.ContractError` instead of being published. I/O errors are
        returned, not raised.
        """
        now = self._now() if now_ms is None else now_ms
        if not force and not self.due(now):
            return PublishOutcome(False, 0, 0)
        data = status_bytes(doc)
        text = render_status(doc).encode("utf-8")
        started = self._now()
        try:
            self._replace(TEXT_NAME, text)
            self._replace(JSON_NAME, data)
        except CubeproofError as error:
            self.failures += 1
            self.last_error = f"{error.rule}: {error.detail}"[:200]
            self._last = now
            return PublishOutcome(False, max(0, self._now() - started), 0, error)
        elapsed = max(0, self._now() - started)
        self._last = now
        self.writes += 1
        self.last_ms, self.last_bytes, self.last_error = elapsed, len(data) + len(text), None
        if elapsed >= self.slow_ms:
            self.slow_writes += 1
        return PublishOutcome(True, elapsed, len(data) + len(text))

    def _replace(self, name: str, data: bytes) -> None:
        calls = self._calls
        final = os.path.join(self.results, name)
        temporary = os.path.join(self.results, f".{name}.{new_id128()}.tmp")
        try:
            fd = calls.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
        except OSError as error:
            raise os_failure("status.write", error, temporary) from error
        try:
            try:
                write_all(calls, fd, data)
            finally:
                calls.close(fd)
            calls.rename(temporary, final)
        except OSError as error:
            remove_quietly(calls, temporary)
            raise os_failure("status.write", error, final) from error
        except BaseException:
            remove_quietly(calls, temporary)
            raise

    def details(self) -> dict[str, Any]:
        """Bounded facts for ``info.status_write`` (the previous writes; the current one is not
        yet known when the snapshot is built)."""
        found: dict[str, Any] = {
            "interval_ms": self.interval_ms,
            "writes": self.writes,
            "last_ms": self.last_ms,
            "last_bytes": self.last_bytes,
            "slow_writes": self.slow_writes,
            "failures": self.failures,
        }
        if self.last_error is not None:
            found["last_error"] = self.last_error
        return found
