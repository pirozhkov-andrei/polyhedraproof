"""Run leaf attempts to their end with one supervisor and one I/O port (tests, simple runs).

This is the smallest event loop that satisfies the attempt's contract: advance every
attempt, start queued checks (no scheduler: every check fits), step the supervisor so that
children are drained and reaped, and hand each I/O result to the attempt that submitted the
job. A result for a job no attempt submitted, or a failed I/O service, stops the loop (specification
§8.1: mismatched job/attempt IDs or a failed service stop new work). The coordinator's real loop
adds reservations, priorities and recovery.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Sequence
from typing import Any, Protocol

from cubeproof.contracts.io import Job, Request, Result
from cubeproof.leaf.attempt import LeafAttempt, LeafError
from cubeproof.tools.process import Supervisor

__all__ = ["PolledIo", "drive"]


class PolledIo(Protocol):
    """An I/O port whose results are fetched by polling (``tools.io_service_client.IoClient``).

    ``failure`` is None while the service is healthy, otherwise the error that stopped it.
    """

    @property
    def failure(self) -> Any: ...

    def submit(self, request: Request, *, attempt_id: str | None = None) -> Job: ...

    def poll(self, timeout: float = 0.0) -> list[tuple[Job, Result]]: ...


def drive(
    attempts: Sequence[LeafAttempt],
    *,
    supervisor: Supervisor,
    io: PolledIo,
    auto_check: bool = True,
    timeout_s: float | None = None,
    slice_ms: int = 20,
    step_ms: int = 5,
    on_tick: Callable[[], None] | None = None,
) -> None:
    """Drive ``attempts`` until every one is finished (DONE or ABANDONED).

    Raises :class:`LeafError` ``leaf.unknown_job`` for a result no attempt owns,
    ``leaf.timeout`` after ``timeout_s`` seconds, and the I/O port's failure once every
    attempt has been told about it.
    """
    group = list(attempts)
    deadline = None if timeout_s is None else time.monotonic() + timeout_s
    while not all(attempt.finished for attempt in group):
        if deadline is not None and time.monotonic() > deadline:
            phases = [(a.attempt_id, a.phase.value) for a in group if not a.finished]
            raise LeafError("leaf.timeout", f"attempts not finished: {phases}")
        if on_tick is not None:
            on_tick()
        for attempt in group:
            if not attempt.finished:
                attempt.advance(slice_ms)
            if auto_check and attempt.wants_check:
                attempt.start_check()
        busy = bool(supervisor.active)
        if busy:
            supervisor.step(step_ms)
        for job, result in io.poll(0.0 if busy else step_ms / 1000):
            owner = next((a for a in group if a.owns(job)), None)
            if owner is None:
                raise LeafError("leaf.unknown_job", f"a result for job {job.job_id} of no attempt")
            owner.deliver(job, result)
        failure = io.failure
        if failure is not None:
            for attempt in group:
                attempt.io_failed(str(failure))
            if isinstance(failure, BaseException):
                raise failure
            raise LeafError("leaf.io_failed", str(failure))
