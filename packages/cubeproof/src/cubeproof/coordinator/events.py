"""Human log events: one line each, a progress line at most once a minute (specification §8.4).

The log is for people watching a run, not evidence and not an interface: its wording may change.
:class:`EventLog` formats lines and hands them to a ``sink`` the caller provides (the CLI passes
:func:`stream_sink` over standard error, so progress goes there while reports go to standard
output; this module never prints and reads the wall clock only through the injected function).
``min_level`` is the verbose/quiet switch.

- ``<utc> <LEVEL> <kind> key=value ...``: values are single tokens (a control character becomes
  ``?``, a value with a space, quote or ``=`` is quoted as JSON), fields are sorted, one event is
  one line;
- events below ``min_level`` (``debug``, ``info``, ``warn``, ``error``; default ``info``) are not
  logged; a sink that fails never stops a run (the failure is counted in ``sink_failures``);
- an event with a ``dedupe`` key is suppressed while the same key was logged less than
  ``quiet_ms`` ago, and the next line that is logged carries ``repeated=<n>`` for what was left out;
  a failing export therefore produces a line per minute, not per tick;
- :meth:`progress` renders a status document as ``progress ...`` and emits it at most once per
  ``progress_interval_ms`` (default one minute).
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable, Mapping
from typing import Any, TextIO

from cubeproof.contracts.primitives import format_utc
from cubeproof.coordinator.status_coverage import mean_text
from cubeproof.coordinator.status_format import duration_text

__all__ = ["LEVELS", "EventLog", "format_event", "progress_fields", "stream_sink"]

LEVELS = ("debug", "info", "warn", "error")
_VALUE_LIMIT = 200


def _wall_ms() -> int:
    return int(time.time() * 1000)


def _token(value: object) -> str:
    text = str(value)
    if len(text) > _VALUE_LIMIT:
        text = text[: _VALUE_LIMIT - 3] + "..."
    text = "".join(c if c.isprintable() else "?" for c in text)
    if text == "" or any(c in text for c in ' "=') or text != text.strip():
        return json.dumps(text, ensure_ascii=False)
    return text


def stream_sink(stream: TextIO) -> Callable[[str], None]:
    """A sink that writes each line and a newline to ``stream`` and flushes (progress of a long
    run must be visible at once). A closed or broken stream is ignored: logging never stops a
    run."""

    def write(line: str) -> None:
        try:
            stream.write(line + "\n")
            stream.flush()
        except (OSError, ValueError):
            pass

    return write


def format_event(wall_ms: int, level: str, kind: str, fields: Mapping[str, Any]) -> str:
    """The line of an event (no trailing newline)."""
    if level not in LEVELS:
        raise ValueError(f"unknown level {level!r}")
    parts = [format_utc(wall_ms), level.upper(), _token(kind)]
    parts += [f"{key}={_token(fields[key])}" for key in sorted(fields)]
    return " ".join(parts)


def progress_fields(doc: Mapping[str, Any]) -> dict[str, Any]:
    """The fields of the progress line of a (valid) status document."""
    states: dict[str, int] = {}
    for entry in doc["node_counts"]:
        states[entry["state"]] = states.get(entry["state"], 0) + entry["count"]
    coverage = doc["coverage"]
    found: dict[str, Any] = {
        "lifecycle": doc["lifecycle"],
        "seq": doc["seq"],
        "nodes": ",".join(f"{k}:{v}" for k, v in sorted(states.items())) or "none",
        "active": len(doc["active"]),
        "oldest": duration_text(doc["oldest_elapsed_ms"]),
    }
    if coverage:
        closed = sum(
            1 for c in coverage if c["closed_numerator"] == "1" and c["denominator_power_two"] == 0
        )
        found["closed_roots"] = f"{closed}/{len(coverage)}"
        found["mean_closed"] = mean_text(
            [(int(c["closed_numerator"]), c["denominator_power_two"]) for c in coverage]
        )
    export = doc["export"]
    found["export_lag"] = "none" if export is None else duration_text(export["lag_ms"])
    found["eta"] = "n/a" if doc["eta_ms"] is None else duration_text(doc["eta_ms"])
    stalls = doc["info"].get("stalls")
    if isinstance(stalls, list) and stalls:
        found["stalls"] = len(stalls)
    anomalies = doc["counters"].get("anomalies", 0)
    models = doc["counters"].get("models", 0)
    if anomalies:
        found["anomalies"] = anomalies
    if models:
        found["models"] = models
    return found


class EventLog:
    """Formats events and progress lines into a sink (module doc)."""

    def __init__(
        self,
        sink: Callable[[str], None],
        *,
        wall_ms: Callable[[], int] = _wall_ms,
        progress_interval_ms: int = 60_000,
        quiet_ms: int = 60_000,
        min_level: str = "info",
    ) -> None:
        if min_level not in LEVELS:
            raise ValueError(f"unknown level {min_level!r}")
        self._sink = sink
        self._wall = wall_ms
        self._floor = LEVELS.index(min_level)
        self.progress_interval_ms = progress_interval_ms
        self.quiet_ms = quiet_ms
        self.sink_failures = 0
        self._last_progress: int | None = None
        self._quiet: dict[str, tuple[int, int]] = {}

    def event(
        self,
        level: str,
        kind: str,
        fields: Mapping[str, Any] | None = None,
        *,
        dedupe: str | None = None,
    ) -> bool:
        """Log one event; False if it is below ``min_level`` or a ``dedupe`` key suppressed it."""
        if level not in LEVELS:
            raise ValueError(f"unknown level {level!r}")
        if LEVELS.index(level) < self._floor:
            return False
        now = self._wall()
        values = dict(fields or {})
        if dedupe is not None:
            last, skipped = self._quiet.get(dedupe, (None, 0))
            if last is not None and now - last < self.quiet_ms:
                self._quiet[dedupe] = (last, skipped + 1)
                return False
            if skipped:
                values["repeated"] = skipped
            self._quiet[dedupe] = (now, 0)
            if len(self._quiet) > 256:
                self._quiet = dict(sorted(self._quiet.items(), key=lambda kv: kv[1][0])[-128:])
        self._emit(format_event(now, level, kind, values))
        return True

    def _emit(self, line: str) -> None:
        try:
            self._sink(line)
        except Exception:
            self.sink_failures += 1

    def progress(self, doc: Mapping[str, Any], now_ms: int) -> bool:
        """Log the progress line of ``doc`` unless one was logged within the interval.

        ``now_ms`` is the caller's monotonic clock (the wall clock only stamps the line)."""
        if self._floor > LEVELS.index("info"):
            return False
        last = self._last_progress
        if last is not None and now_ms - last < self.progress_interval_ms:
            return False
        self._last_progress = now_ms
        self._emit(format_event(self._wall(), "info", "progress", progress_fields(doc)))
        return True
