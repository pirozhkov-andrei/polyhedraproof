"""``status``: read the monitor a worker publishes into its results directory (specification §12.1,
§12.3).

``cubeproof status --results DIR`` shows the latest ``status.json`` of a worker. It reads only that
file (never the journal, so it works against a live run without taking any lock), validates it
strictly and renders it. The document is a derived monitor: a stale one is reported as stale, and
nothing it says is evidence. Like every command module it neither prints nor exits.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass
from typing import Any

from cubeproof.base.canonical_json import parse_document
from cubeproof.base.errors import ContractError, CubeproofError, InputError, ResourceError
from cubeproof.base.settings import DEFAULT_LIMITS, ReaderLimits
from cubeproof.contracts.primitives import parse_utc
from cubeproof.coordinator.status_format import duration_text, render_status, validate_status
from cubeproof.coordinator.status_publish import JSON_NAME

__all__ = ["StatusReport", "status_command"]

#: A status older than this while the worker claims to be running is shown as stale.
STALE_AFTER_MS = 30_000


@dataclass(frozen=True)
class StatusReport:
    """The validated document, its text rendering and its age."""

    document: dict[str, Any]
    text: str
    #: Milliseconds since the document's ``utc`` (0 if the clock is behind it).
    age_ms: int
    #: The worker says it is running or draining but has not published for a while.
    stale: bool


def status_command(
    results: str | os.PathLike[str],
    *,
    now_ms: int | None = None,
    stale_after_ms: int = STALE_AFTER_MS,
    limits: ReaderLimits = DEFAULT_LIMITS,
) -> StatusReport:
    """Read, validate and render ``<results>/status.json``.

    Raises :class:`~cubeproof.base.errors.InputError` when there is no status or it is not a valid
    ``cubeproof-status-1`` document (the CLI maps it to a usage/input exit code).
    """
    path = os.path.join(os.fspath(results), JSON_NAME)
    try:
        with open(path, "rb") as stream:
            data = stream.read(limits.document_bytes + 2)
    except FileNotFoundError:
        raise InputError(
            "status.absent", f"{path} does not exist: no worker has published here"
        ) from None
    except OSError as error:
        raise InputError("status.unreadable", f"{path}: {error.strerror}") from None
    try:
        document = validate_status(parse_document(data, limits=limits))
    except ResourceError:
        raise
    except CubeproofError as error:
        rule = error.rule if isinstance(error, ContractError) else "status.invalid"
        raise InputError("status.invalid", f"{path}: {rule}: {error.detail}"[:300]) from None
    now = int(time.time() * 1000) if now_ms is None else now_ms
    age = max(0, now - parse_utc(document["utc"]))
    stale = document["lifecycle"] != "stopped" and age > stale_after_ms
    text = render_status(document)
    if stale:
        text = (
            f"WARNING: the last status is {duration_text(age)} old; the worker may have died "
            f"(or be stuck). This status is a monitor, not evidence.\n{text}"
        )
    return StatusReport(document, text, age, stale)
