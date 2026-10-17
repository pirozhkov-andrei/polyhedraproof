"""The coordinator's side of the I/O service (specification §8.1).

:class:`IoClient` starts the one long-lived service process, sends jobs and reads results
without ever blocking the coordinator's event loop: submissions go to a bounded buffer that
is written nonblockingly, results are read nonblockingly, and ``poll(timeout)`` waits at most
``timeout`` seconds. A stalled fsync in the service therefore stalls nothing here.

:class:`Tracker` checks every result before the caller sees it: it must answer a pending job
(same job ID, operation and attempt ID, a value that fits the request, see
:meth:`~cubeproof.contracts.io.Result.problem`), and commit results must continue the
journal's sequence numbers from the service's hello. Any problem, a garbled line, a fatal
failure reported by the service or the service's death sets :attr:`IoClient.failure`
(a ToolError, exit 5 at the CLI, specification §12.2): new submissions are refused (stop new work),
a misbehaving service is killed, and the jobs without a verified result are
:meth:`IoClient.uncertain` (replay decides whether a commit happened, specification §7.1).

The entry point (argv) that runs :func:`cubeproof.tools.io_service.serve` with the journal
writer is the coordinator layer's. It should pass the run lock's descriptor so
that the service holds the results directory's lock for as long as it lives (specification §7.3).
"""

from __future__ import annotations

import contextlib
import os
import selectors
import signal
import subprocess
import time
from collections.abc import Mapping, Sequence
from typing import Any

from cubeproof.base.errors import CubeproofError, ResourceError, ToolError
from cubeproof.base.process import OutputTail
from cubeproof.contracts.io import (
    FRAME_LIMITS,
    AppendValue,
    Failure,
    Hello,
    Job,
    Request,
    Result,
    decode_frame,
    encode_frame,
)

#: Specification §8.3: the I/O buffer cap (pending job frames not yet written to the service).
BUFFER_BYTES = 32 << 20
_READ_BYTES = 1 << 20
_READ_PER_POLL = 8 << 20


class IoServiceError(ToolError):
    """The I/O service failed or misbehaved; no new work may be submitted.

    Rules: ``io.service_died``, ``io.protocol`` (unreadable output, no hello first),
    ``io.unknown_job`` (a result for no pending job), ``io.mismatch`` (a result that does not
    answer its job), ``io.sequence`` (a commit out of sequence), ``io.service_failed`` (a
    fatal failure reported by the service), ``io.closed``.
    """


class Tracker:
    """Job IDs, pending jobs and the verification of results (no I/O)."""

    def __init__(self) -> None:
        self.pending: dict[int, Job] = {}
        self.hello_value: Hello | None = None
        self._next_id = 1
        self._next_seq: int | None = None

    def job(self, request: Request, attempt_id: str | None) -> Job:
        """A new job with the next job ID, registered as pending."""
        job = Job(self._next_id, attempt_id, request)
        self._next_id += 1
        self.pending[job.job_id] = job
        return job

    def hello(self, hello: Hello) -> None:
        if self.hello_value is not None:
            raise IoServiceError("io.protocol", "a second hello")
        self.hello_value = hello
        self._next_seq = 0 if hello.seq is None else hello.seq + 1

    def accept(self, result: Result) -> Job:
        """The job ``result`` answers, removed from the pending jobs; IoServiceError if none."""
        if self.hello_value is None:
            raise IoServiceError("io.protocol", "a result before the hello")
        job = self.pending.get(result.job_id)
        if job is None:
            raise IoServiceError("io.unknown_job", f"a result for job {result.job_id}")
        problem = result.problem(job)
        if problem is not None:
            raise IoServiceError("io.mismatch", f"job {job.job_id}: {problem}")
        if isinstance(result.outcome, AppendValue):
            if result.outcome.seq != self._next_seq:
                raise IoServiceError(
                    "io.sequence", f"committed seq {result.outcome.seq}, expected {self._next_seq}"
                )
            self._next_seq = result.outcome.seq + 1
        del self.pending[job.job_id]
        return job


class IoClient:
    """One running I/O service process (see module doc). Use :meth:`spawn`."""

    def __init__(
        self, process: subprocess.Popen[bytes], stdin: int, stdout: int, stderr: int
    ) -> None:
        # The pipe ends are plain descriptors owned by this object (no file objects that a
        # garbage collector could close again after their numbers were reused).
        self.process = process
        self.pid: int = process.pid
        self.tracker = Tracker()
        self.failure: IoServiceError | None = None
        self.stderr = OutputTail()
        self._stdin: int | None = stdin
        self._stdout: int | None = stdout
        self._stderr: int | None = stderr
        self._out = bytearray()
        self._in = bytearray()
        self._backlog: list[tuple[Job, Result]] = []
        self._closing = False
        for fd in (self._stdin, self._stdout, self._stderr):
            os.set_blocking(fd, False)
        self._selector = selectors.DefaultSelector()
        self._selector.register(self._stdout, selectors.EVENT_READ)
        self._selector.register(self._stderr, selectors.EVENT_READ)

    @classmethod
    def spawn(
        cls,
        argv: Sequence[str],
        *,
        cwd: str,
        pass_fds: Sequence[int] = (),
        env: Mapping[str, str] | None = None,
    ) -> IoClient:
        """Start the service process ``argv`` (own session: terminal signals do not hit it
        mid-fsync; it ends when its input closes)."""
        pipes = [os.pipe() for _ in range(3)]  # not inheritable (PEP 446)
        (in_read, in_write), (out_read, out_write), (err_read, err_write) = pipes
        try:
            process = subprocess.Popen(
                list(argv),
                stdin=in_read,
                stdout=out_write,
                stderr=err_write,
                cwd=cwd,
                env=None if env is None else dict(env),
                pass_fds=tuple(pass_fds),
                close_fds=True,
                start_new_session=True,
            )
        except BaseException:
            for fd in (in_write, out_read, err_read):
                os.close(fd)
            raise
        finally:
            for fd in (in_read, out_write, err_write):
                os.close(fd)
        return cls(process, in_write, out_read, err_read)

    # -- state --------------------------------------------------------------------------------

    @property
    def hello(self) -> Hello | None:
        return self.tracker.hello_value

    @property
    def returncode(self) -> int | None:
        return self.process.poll()

    @property
    def wants_write(self) -> bool:
        return bool(self._out) and self._stdin is not None

    def fileno(self) -> int:
        """The descriptor to watch for results (for the coordinator's selector)."""
        assert self._stdout is not None
        return self._stdout

    def uncertain(self) -> list[Job]:
        """Pending jobs without a verified result (meaningful after a failure).

        Not listed: jobs answered with a failure. An append answered with a *fatal* failure
        (``journal.write``, ``journal.fsync``, ``io.commit_uncertain``) may nevertheless be
        durable; "not uncertain" never means "not committed". After any fatal failure the
        journal on disk decides (replay, specification §7.1).
        """
        return [self.tracker.pending[k] for k in sorted(self.tracker.pending)]

    # -- submitting ---------------------------------------------------------------------------

    def submit(self, request: Request, *, attempt_id: str | None = None) -> Job:
        """Queue a job; it is written to the service as the pipe accepts it."""
        if self.failure is not None:
            raise IoServiceError("io.service_failed", f"no new work: {self.failure}")
        if self._closing or self._stdin is None:
            raise IoServiceError("io.closed", "the service is being closed")
        job = self.tracker.job(request, attempt_id)
        frame = encode_frame(job.to_json())
        if len(self._out) + len(frame) > BUFFER_BYTES:
            del self.tracker.pending[job.job_id]
            raise ResourceError("io.buffer", f"more than {BUFFER_BYTES} bytes of queued jobs")
        self._out += frame
        self._flush()
        return job

    def _flush(self) -> None:
        while self._out and self._stdin is not None:
            try:
                count = os.write(self._stdin, self._out[:_READ_BYTES])
            except BlockingIOError:
                return
            except BrokenPipeError:
                self._fail(IoServiceError("io.service_died", "the service closed its input"))
                return
            del self._out[:count]

    # -- receiving ----------------------------------------------------------------------------

    def poll(self, timeout: float = 0.0) -> list[tuple[Job, Result]]:
        """Write pending jobs, read results; wait at most ``timeout`` seconds for output.

        Returns the verified results with their jobs, in arrival order. Results verified
        before a failure in the same batch are returned; nothing after it.
        """
        if self._backlog:
            done, self._backlog = self._backlog, []
            return done + self._receive(0.0)
        return self._receive(timeout)

    def _receive(self, timeout: float) -> list[tuple[Job, Result]]:
        self._flush()
        if self._stdout is None:
            return []
        if self.wants_write and self._stdin is not None:
            with contextlib.suppress(KeyError):
                self._selector.register(self._stdin, selectors.EVENT_WRITE)
        events = self._selector.select(timeout)
        with contextlib.suppress(KeyError, ValueError):
            if self._stdin is not None:
                self._selector.unregister(self._stdin)
        self._flush()
        done: list[tuple[Job, Result]] = []
        for key, _ in events:
            if key.fd == self._stderr:
                self._drain_stderr()
        if self._stdout is not None:
            self._read_results(done)
        return done

    def _drain_stderr(self) -> None:
        assert self._stderr is not None
        try:
            data = os.read(self._stderr, _READ_BYTES)
        except BlockingIOError:
            return
        if data:
            self.stderr.feed(data)
        else:
            self._selector.unregister(self._stderr)
            os.close(self._stderr)
            self._stderr = None

    def _read_results(self, done: list[tuple[Job, Result]]) -> None:
        assert self._stdout is not None
        eof = False
        total = 0
        while total < _READ_PER_POLL:
            try:
                data = os.read(self._stdout, _READ_BYTES)
            except BlockingIOError:
                break
            if not data:
                eof = True
                break
            total += len(data)
            self._in += data
        while self.failure is None:
            end = self._in.find(b"\n")
            if end < 0:
                if len(self._in) > FRAME_LIMITS.line_bytes:
                    self._fail(IoServiceError("io.protocol", "an overlong result line"))
                break
            line = bytes(self._in[:end])
            del self._in[: end + 1]
            try:
                self._line(line, done)
            except IoServiceError as error:
                self._fail(error)
        if eof and self.failure is None:
            if self._closing:
                self._stop_reading()
            else:
                self._fail(IoServiceError("io.service_died", self._death()))
        elif eof:
            self._stop_reading()

    def _line(self, line: bytes, done: list[tuple[Job, Result]]) -> None:
        try:
            value = decode_frame(line)
            if self.tracker.hello_value is None:
                self.tracker.hello(Hello.from_json(value))
                return
            result = Result.from_json(value)
        except CubeproofError as error:
            if isinstance(error, IoServiceError):
                raise
            raise IoServiceError("io.protocol", f"unreadable service output: {error}") from None
        job = self.tracker.accept(result)
        done.append((job, result))
        outcome = result.outcome
        if isinstance(outcome, Failure) and outcome.fatal:
            self.failure = IoServiceError("io.service_failed", f"{outcome.kind}: {outcome.rule}")

    def _death(self) -> str:
        code = self.process.poll()
        tail = self.stderr.text()[0][-400:] if self.stderr.total else ""
        return f"the service ended (exit {code}) {tail}".strip()

    def _fail(self, error: IoServiceError) -> None:
        """Stop new work and the service itself: it can no longer be trusted (specification
        §8.1)."""
        if self.failure is None:
            self.failure = error
        with contextlib.suppress(ProcessLookupError, PermissionError):
            if self.process.poll() is None:
                os.kill(self.pid, signal.SIGKILL)
        self._close_stdin()
        self._out.clear()

    def _stop_reading(self) -> None:
        if self._stdout is not None:
            with contextlib.suppress(KeyError, ValueError):
                self._selector.unregister(self._stdout)
            os.close(self._stdout)
            self._stdout = None

    def _close_stdin(self) -> None:
        if self._stdin is not None:
            with contextlib.suppress(KeyError, ValueError):
                self._selector.unregister(self._stdin)
            with contextlib.suppress(OSError):
                os.close(self._stdin)
            self._stdin = None

    def wait(self, job: Job, timeout: float) -> Result:
        """Poll until ``job`` has its result (startup and tests; not for the event loop).

        Results of other jobs that arrive meanwhile are kept and returned by the next
        :meth:`poll` (or a later :meth:`wait` for them).
        """
        deadline = time.monotonic() + timeout
        while True:
            for index, (done, result) in enumerate(self._backlog):
                if done.job_id == job.job_id:
                    del self._backlog[index]
                    return result
            self._backlog += self._receive(min(0.1, max(0.0, deadline - time.monotonic())))
            if self.failure is not None and job.job_id in self.tracker.pending:
                raise self.failure
            if time.monotonic() >= deadline:
                raise IoServiceError("io.timeout", f"no result for job {job.job_id}")

    # -- ending -------------------------------------------------------------------------------

    def close(self, timeout: float = 10.0) -> int | None:
        """End the service: wait (within ``timeout`` seconds) for the results of submitted
        jobs, close its input, wait for it to exit; KILL when the time is up.

        Results that arrive meanwhile stay available to :meth:`poll`; jobs still without a
        result are :meth:`uncertain` (the service drops queued work when its input closes).
        """
        self._closing = True
        deadline = time.monotonic() + timeout
        while (
            self.tracker.pending
            and self.failure is None
            and self._stdout is not None
            and time.monotonic() < deadline
        ):
            self._backlog += self._receive(0.05)
        self._close_stdin()
        while self.process.poll() is None and time.monotonic() < deadline:
            if self._stdout is not None:
                self._backlog += self._receive(0.05)
            else:
                time.sleep(0.01)
        if self.process.poll() is None:
            with contextlib.suppress(ProcessLookupError):
                os.kill(self.pid, signal.SIGKILL)
        code = self.process.wait()
        self._stop_reading()
        if self._stderr is not None:
            with contextlib.suppress(KeyError, ValueError):
                self._selector.unregister(self._stderr)
            os.close(self._stderr)
            self._stderr = None
        self._selector.close()
        return code

    def __enter__(self) -> IoClient:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def failure_error(result: Result) -> Any:
    """The error of a failed result (None for a value)."""
    outcome = result.outcome
    return outcome.error() if isinstance(outcome, Failure) else None
