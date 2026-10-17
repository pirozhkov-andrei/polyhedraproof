"""The supervised I/O service (specification §7.1, §7.2, §8.1).

One long-lived process per coordinator runs the large hash/copy/fsync/journal jobs, so that a
blocking fsync stalls this process, never the coordinator's event loop. It is part of the
binding/durability trust boundary:

- It executes typed jobs (:mod:`cubeproof.contracts.io`) and answers each with a typed
  result carrying the job's ID, operation and attempt ID. It produces measurements and
  durable effects, never a verdict: it hashes, copies, publishes, commits and removes.
- It is the **sole journal writer** (specification §7.1, §8.1). The journal writer is injected as a
  :class:`JournalPort` by the entry point that starts the process (the coordinator layer;
  ``tools`` may not import ``evidence``, specification §2.3). The coordinator supplies validated
  payloads; the service commits them **unchanged** and returns the committed seq and head
  only after the writer's fsync. It cannot build a record of its own.
- Publish before record (specification §7.2 step 4): an ``attempt`` payload is committed only if its
  job carries the record's attempt ID and every artifact it references (``retained`` in
  ``proofs/``, ``quarantined`` in ``quarantine/``) was durably published by this service,
  for that attempt, with exactly that path, hash and size. Otherwise the job fails before
  any journal byte (``io.unpublished``/``io.attempt_mismatch``).
- Removal is limited to disposable files: below the work root, or staging files
  ``<results>/<area>/tmp/<name>``; final artifacts are removed only by reconciliation,
  which never removes a committed or pending reference (:mod:`cubeproof.tools.artifacts`).
- Hash/copy/verification work runs in chunks of at most ``chunk_bytes`` (<= 8 MiB);
  :class:`Scheduler` runs journal commits between chunks, ahead of other work, in order.
- Failure acknowledgement follows the journal writer: a failed fsync (DurabilityError), a journal
  writer that failed, or an unexpected error makes the service **fatal**: that job's failure says
  so, every later job fails with ``io.service_failed``, and :func:`serve` exits. The
  coordinator then stops new work; replay decides about uncertain commits. Other failures
  (a full disk, a changed source, an unpublished reference, a refused record) are typed
  results; the service goes on.

:func:`serve` runs the service on a pair of descriptors (one frame per line): it sends a
:class:`~cubeproof.contracts.io.Hello`, reads jobs nonblockingly between steps, and ends
when its input closes (the coordinator closed it or died), so the process never outlives
its coordinator by more than one step.
"""

from __future__ import annotations

import os
import selectors
import stat
from collections import deque
from collections.abc import Generator, Mapping
from dataclasses import dataclass, field
from typing import Any, Protocol

from cubeproof.base.errors import (
    ConfigurationError,
    ContractError,
    CubeproofError,
    ResourceError,
    ToolError,
)
from cubeproof.contracts.io import (
    ARTIFACT_FIELDS,
    ATTEMPT_TYPE,
    FRAME_LIMITS,
    MAX_CHUNK_BYTES,
    STAGING,
    AppendRequest,
    AppendValue,
    Area,
    Failure,
    HashRequest,
    HashValue,
    Hello,
    Job,
    Op,
    PublishRequest,
    PublishValue,
    ReconcileRequest,
    RemoveRequest,
    RemoveValue,
    Result,
    Value,
    absolute_path_problem,
    artifact_area,
    attempt_binding_problem,
    decode_frame,
    encode_frame,
)
from cubeproof.contracts.values import Artifact
from cubeproof.tools.artifacts import publish_steps, reconcile_steps
from cubeproof.tools.atomic import (
    OS_FILE_CALLS,
    DurabilityError,
    FileCalls,
    drive,
    hash_steps,
    open_regular,
    os_failure,
    write_all,
)

#: Input read per step at most (the service's input buffer stays bounded).
_READ_BYTES = 1 << 20
#: The field of an attempt record that must lie in each area.
_FIELD_AREAS = dict(zip(ARTIFACT_FIELDS, (Area.PROOFS, Area.QUARANTINE), strict=True))


class CommitUncertain(ToolError):
    """The journal accepted a commit but its answer is unusable (fatal, ``io.commit_uncertain``).

    A non-fatal append failure always means "nothing was written"; anything after the
    writer returned is therefore fatal.
    """


class JournalPort(Protocol):
    """The journal writer as the service uses it (the ``JournalWriter`` behind it).

    ``append`` commits a payload value (``type`` plus payload fields) unchanged and returns
    ``(seq, self)`` of the committed record only after it is durable; it raises a
    CubeproofError otherwise. ``failed`` is true once a write, fsync or lock failed (the
    writer then refuses further appends). ``position`` is ``(seq, head)`` of the last
    committed record, or None for an empty journal.
    """

    @property
    def failed(self) -> bool: ...

    def position(self) -> tuple[int, str] | None: ...

    def append(self, payload: Mapping[str, Any]) -> tuple[int, str]: ...


def _inside(path: str, root: str) -> bool:
    return path.startswith(root.rstrip("/") + "/")


@dataclass(frozen=True)
class ServiceConfig:
    """Where the service works: the results root (artifacts) and the work root.

    The work root may not be the results root or lie inside it (removal rules below).
    """

    results_root: str
    work_root: str
    chunk_bytes: int = MAX_CHUNK_BYTES

    def __post_init__(self) -> None:
        for name in ("results_root", "work_root"):
            problem = absolute_path_problem(getattr(self, name))
            if problem is not None:
                raise ContractError("io.layout", f"{name}: {problem}")
        if self.work_root == self.results_root or _inside(self.work_root, self.results_root):
            raise ContractError("io.layout", "the work root may not lie in the results root")
        chunk = self.chunk_bytes
        if type(chunk) is not int or not 1 <= chunk <= MAX_CHUNK_BYTES:
            raise ContractError("io.layout", f"chunk_bytes must be 1..{MAX_CHUNK_BYTES}")


@dataclass
class Service:
    """The job executor of one service process (see module doc)."""

    config: ServiceConfig
    journal: JournalPort | None
    calls: FileCalls = OS_FILE_CALLS
    #: The first fatal failure; afterwards every job fails with ``io.service_failed``.
    fatal: Failure | None = None
    #: Durable publications not yet referenced by a committed record, per attempt ID.
    pending: dict[str, set[Artifact]] = field(default_factory=dict)

    def hello(self, pid: int) -> Hello:
        position = self.journal.position() if self.journal is not None else None
        if position is None:
            return Hello(pid, None, None)
        return Hello(pid, position[0], position[1])

    def run(self, job: Job) -> Result:
        """Execute ``job`` to its end."""
        return drive(self.steps(job))

    def steps(self, job: Job) -> Generator[None, None, Result]:
        """Execute ``job``, one bounded step per iteration; the value is its result."""
        outcome: Value | Failure
        if self.fatal is not None:
            stopped = ToolError("io.service_failed", f"the service stopped: {self.fatal.rule}")
            return self._result(job, Failure.of(stopped, fatal=True))
        try:
            outcome = yield from self._execute(job)
        except (DurabilityError, CommitUncertain) as error:
            outcome = self._stop(error)
        except CubeproofError as error:
            if self.journal is not None and self.journal.failed:
                outcome = self._stop(error)
            else:
                outcome = Failure.of(error, fatal=False)
        except OSError as error:
            outcome = Failure.of(os_failure("io.os_error", error, job.op.value), fatal=False)
        except Exception as error:
            outcome = self._stop(ToolError("io.internal", f"{type(error).__name__}: {error}"))
        return self._result(job, outcome)

    def _result(self, job: Job, outcome: Value | Failure) -> Result:
        return Result(job.job_id, job.op, job.attempt_id, outcome)

    def _stop(self, error: CubeproofError) -> Failure:
        failure = Failure.of(error, fatal=True)
        if self.fatal is None:
            self.fatal = failure
        return failure

    def _execute(self, job: Job) -> Generator[None, None, Value]:
        problem = attempt_binding_problem(job.attempt_id, job.request)
        if problem is not None:
            raise ContractError("io.attempt_mismatch", problem)
        request = job.request
        if isinstance(request, HashRequest):
            return (yield from self._hash(request))
        if isinstance(request, PublishRequest):
            assert job.attempt_id is not None
            return (yield from self._publish(job.attempt_id, request))
        if isinstance(request, AppendRequest):
            return self._append(job.attempt_id, request)
        if isinstance(request, RemoveRequest):
            return self._remove(request)
        if isinstance(request, ReconcileRequest):
            protected = {a.path for published in self.pending.values() for a in published}
            return (
                yield from reconcile_steps(
                    self.config.results_root,
                    request.committed,
                    protected=protected,
                    calls=self.calls,
                    chunk_bytes=self.config.chunk_bytes,
                )
            )
        raise ContractError("schema", f"unknown request {type(request).__name__}")

    # -- operations --------------------------------------------------------------------------

    def _hash(self, request: HashRequest) -> Generator[None, None, HashValue]:
        try:
            fd, _ = open_regular(self.calls, request.path)
        except FileNotFoundError as error:
            raise ToolError("io.source", f"{request.path}: {error.strerror}") from None
        except OSError as error:
            raise ToolError("io.source", f"{request.path}: {error}") from error
        try:
            size, sha256 = yield from hash_steps(
                self.calls, fd, chunk_bytes=self.config.chunk_bytes
            )
        finally:
            self.calls.close(fd)
        return HashValue(size, sha256)

    def _publish(
        self, attempt_id: str, request: PublishRequest
    ) -> Generator[None, None, PublishValue]:
        value = yield from publish_steps(
            self.config.results_root,
            attempt_id,
            request,
            calls=self.calls,
            chunk_bytes=self.config.chunk_bytes,
        )
        self.pending.setdefault(attempt_id, set()).add(value.artifact)
        return value

    def _append(self, attempt_id: str | None, request: AppendRequest) -> AppendValue:
        journal = self.journal
        if journal is None:
            raise ConfigurationError("io.no_journal", "this service has no journal")
        payload = request.value()
        if payload.get("type") == ATTEMPT_TYPE:
            assert attempt_id is not None
            published = self.pending.get(attempt_id, set())
            for name, area in _FIELD_AREAS.items():
                raw = payload.get(name)
                if raw is None:
                    continue
                artifact = Artifact.from_json(raw, f"$.{name}")
                if artifact_area(artifact.path) is not area or artifact not in published:
                    raise ContractError(
                        "io.unpublished",
                        f"{name} {artifact.path} was not published for attempt {attempt_id}",
                    )
        seq, head = journal.append(payload)
        try:
            value = AppendValue(seq, head)
        except CubeproofError as error:
            # The record may be durable now: never report this as a refusal (nothing
            # written); stop instead and let replay decide (specification §7.1).
            raise CommitUncertain("io.commit_uncertain", f"{error}") from error
        if attempt_id is not None:
            self.pending.pop(attempt_id, None)
        return value

    def _remove(self, request: RemoveRequest) -> RemoveValue:
        for path in request.paths:
            if not self._removable(path):
                raise ContractError("io.protected", f"{path} is not a disposable file")
        removed: list[str] = []
        for path in request.paths:
            try:
                mode = self.calls.lstat(path).st_mode
            except FileNotFoundError:
                continue
            if stat.S_ISDIR(mode):
                raise ContractError("io.protected", f"{path} is a directory")
            try:
                self.calls.unlink(path)
            except FileNotFoundError:
                continue
            except OSError as error:
                raise os_failure("io.remove", error, path) from error
            removed.append(path)
        return RemoveValue(tuple(removed))

    def _removable(self, path: str) -> bool:
        """Below the work root, or a staging file ``<results>/<area>/tmp/<name>``."""
        results = self.config.results_root
        if path == results or _inside(path, results):
            parts = path[len(results.rstrip("/")) + 1 :].split("/")
            areas = {a.value for a in Area}
            if len(parts) != 3 or parts[0] not in areas or parts[1] != STAGING:
                return False
            return self._real_directories(results, parts[:-1])
        work = self.config.work_root
        if _inside(path, work):
            parts = path[len(work.rstrip("/")) + 1 :].split("/")
            return self._real_directories(work, parts[:-1])
        return False

    def _real_directories(self, root: str, parts: list[str]) -> bool:
        """No component below ``root`` is a symlink or a non-directory (missing is fine)."""
        path = root
        for part in parts:
            path = os.path.join(path, part)
            try:
                mode = self.calls.lstat(path).st_mode
            except FileNotFoundError:
                return True
            if not stat.S_ISDIR(mode):
                return False
        return True


class Scheduler:
    """The order of work in the service: commits first and in order, other jobs FIFO.

    :meth:`step` does one bounded unit: a queued journal commit, or one chunk of the active
    job. A commit therefore waits for at most one chunk of a long copy or hash (specification §8.1).
    """

    def __init__(self, service: Service) -> None:
        self.service = service
        self._commits: deque[Job] = deque()
        self._queue: deque[Job] = deque()
        self._active: Generator[None, None, Result] | None = None
        self._last_id = 0

    def accept(self, job: Job) -> None:
        """Queue ``job``; job IDs must increase (ContractError ``io.job_order``)."""
        if job.job_id <= self._last_id:
            raise ContractError("io.job_order", f"job {job.job_id} after job {self._last_id}")
        self._last_id = job.job_id
        (self._commits if job.op is Op.APPEND else self._queue).append(job)

    @property
    def busy(self) -> bool:
        return bool(self._commits or self._queue or self._active is not None)

    def step(self) -> Result | None:
        """One unit of work; the result of a job that finished in it, else None."""
        if self._commits:
            return self.service.run(self._commits.popleft())
        if self._active is None:
            if not self._queue:
                return None
            self._active = self.service.steps(self._queue.popleft())
        try:
            next(self._active)
        except StopIteration as stop:
            self._active = None
            result: Result = stop.value
            return result
        return None


class _Input:
    """Nonblocking line reader of the job descriptor with a bounded buffer."""

    def __init__(self, fd: int) -> None:
        self.fd = fd
        self.buffer = bytearray()
        self.eof = False

    def fill(self) -> None:
        try:
            data = os.read(self.fd, _READ_BYTES)
        except BlockingIOError:
            return
        if not data:
            self.eof = True
        self.buffer += data

    def lines(self) -> list[bytes]:
        out: list[bytes] = []
        while True:
            end = self.buffer.find(b"\n")
            if end < 0:
                break
            out.append(bytes(self.buffer[:end]))
            del self.buffer[: end + 1]
        if len(self.buffer) > FRAME_LIMITS.line_bytes:
            raise ResourceError("limit.line", "a job frame beyond the frame limit")
        return out


#: Exit statuses of :func:`serve`.
EXIT_CLOSED = 0
EXIT_FATAL = 1
EXIT_PROTOCOL = 2
EXIT_OUTPUT = 3


def serve(service: Service, in_fd: int, out_fd: int, *, pid: int | None = None) -> int:
    """Serve jobs from ``in_fd`` and write results to ``out_fd`` until the input closes.

    Returns 0 when the input closed, 1 after a fatal failure (reported first), 2 for an
    unreadable job frame or a job ID out of order, 3 when the results cannot be written.
    Work still queued when the input closes is dropped (nobody waits for its results).
    """

    def send(value: Mapping[str, Any]) -> None:
        write_all(OS_FILE_CALLS, out_fd, encode_frame(value))

    scheduler = Scheduler(service)
    reader = _Input(in_fd)
    selector = selectors.DefaultSelector()
    try:
        send(service.hello(os.getpid() if pid is None else pid).to_json())
        os.set_blocking(in_fd, False)
        selector.register(in_fd, selectors.EVENT_READ)
        while True:
            if selector.select(0 if scheduler.busy else None):
                reader.fill()
            try:
                for line in reader.lines():
                    scheduler.accept(Job.from_json(decode_frame(line)))
            except CubeproofError:
                return EXIT_PROTOCOL
            if reader.eof:
                return EXIT_CLOSED
            result = scheduler.step()
            if result is not None:
                send(result.to_json())
                if isinstance(result.outcome, Failure) and result.outcome.fatal:
                    return EXIT_FATAL
    except OSError:
        return EXIT_OUTPUT
    finally:
        selector.close()
