"""The nonblocking process supervisor (specification §4.6, §6.2, §6.3, §8.1).

One :class:`Supervisor` drives any number of child processes from a single thread:
``start`` launches, ``step`` waits (bounded) for output, exits and timers and returns the
runs that finished. A coordinator calls ``step`` from its event loop; nothing here blocks
for longer than the requested timeout, and stdout/stderr are drained on every step.

Each child:

- is started through :class:`~cubeproof.tools.isolation.Isolation` (``setpriv --pdeathsig
  KILL``, ``prlimit --as/--fsize/--core=0``) in its **own session and process group**, with
  stdin from /dev/null, the environment :data:`TOOL_ENVIRONMENT` only, no inherited
  descriptors and an absolute working directory;
- dies with the supervisor from the fork on: the forked child sets the parent-death signal
  KILL itself, before it executes anything, and then exits unless its parent is still the
  process that forked it (:func:`_parent_death_guard`). A supervisor that dies before the
  signal is set is seen by that check; one that dies later is answered by the kernel. Without
  the check a tool whose supervisor died while ``setpriv`` was still starting would never get
  the signal: it would run without supervisor, deadline or cap, and one blocked on a proof
  FIFO whose other end died would never end;
- runs the pinned binary only if it still has its hash; the hash is checked again after the
  exit (:attr:`Cause.BINARY_CHANGED`);
- has a monotonic deadline: at the deadline the group gets TERM and, after
  ``term_grace_ms``, KILL (:attr:`Cause.DEADLINE`); a watched file that reaches its cap
  while the process runs does the same (:attr:`Cause.PROOF_CAP`); a user stop or
  :meth:`Supervisor.cancel` likewise (:attr:`Cause.CANCELLED`);
- is reaped exactly once. When the leader has exited it is still a zombie, so its process
  group id cannot be reused yet: the supervisor then sends KILL to the whole group (no
  descendant outlives the tool in its group), reaps the leader, and drains the pipes until
  EOF. A descendant that left the group and still holds a pipe end is reported as
  :attr:`Cause.HELD_OPEN` after ``eof_grace_ms`` and its pipe ends are closed here. The exit
  is checked before the timers, so a process that already ended is never charged with a
  deadline or cap. If another party reaped the child, its status is unknown: the result
  has neither exit nor signal (``Popen`` would report a fabricated 0).

Causes are recorded in the order they happen; the first is the process's primary cause and
the record's diagnostic ``cause``. Classification (``tools.process_outcome``) reads the typed
causes, never a signal number alone.

The parent-death signal belongs to the thread that started the child (Linux semantics), so
use one supervisor from one long-lived thread (the coordinator's event loop thread).
"""

from __future__ import annotations

import contextlib
import ctypes
import os
import selectors
import signal
import subprocess
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass

from cubeproof.base.errors import ToolError
from cubeproof.base.process import TAIL_BYTES, Cause, OutputTail, ProcessResult
from cubeproof.tools.isolation import TOOL_ENVIRONMENT, Isolation, PinnedBinary

__all__ = ["TOOL_ENVIRONMENT", "Launch", "Process", "ProcessRun", "Supervisor"]

_CHUNK = 1 << 16
#: At most this much is read from one pipe per step, so a flood cannot starve the loop.
_READ_PER_STEP = 1 << 20
_WATCH_INTERVAL_NS = 50_000_000
#: Exit polling interval where pidfd_open is unavailable.
_POLL_INTERVAL_NS = 20_000_000
_NS_PER_MS = 1_000_000
_SHUTDOWN_EXTRA_S = 60.0
#: ``prctl`` option (linux/prctl.h): the signal this process gets when its parent dies.
_PR_SET_PDEATHSIG = 1
_PR_GET_PDEATHSIG = 2

Clock = Callable[[], int]


def _libc_prctl() -> Callable[..., int] | None:
    """``prctl(2)`` of the C library, or None where there is none (not Linux)."""
    if not sys.platform.startswith("linux"):
        return None
    try:
        function = ctypes.CDLL(None, use_errno=True).prctl
    except (OSError, AttributeError):
        return None
    function.argtypes = [ctypes.c_int] + [ctypes.c_ulong] * 4
    function.restype = ctypes.c_int
    # One call here, in the supervisor's process: it shows that the call works and leaves
    # nothing to be resolved or loaded at the first call in a forked child.
    current = ctypes.c_int()
    if function(_PR_GET_PDEATHSIG, ctypes.addressof(current), 0, 0, 0) != 0:
        return None
    return function


#: Resolved once, in the supervisor's process: the forked child only calls it.
_PRCTL = _libc_prctl()
_KILL = int(signal.SIGKILL)


def _parent_death_guard(parent: int) -> Callable[[], None] | None:
    """What a forked child runs before it executes the wrapper chain (``preexec_fn``).

    It sets the parent-death signal KILL and then requires that its parent is still
    ``parent``, the process that forked it. The order closes the launch window: a parent
    that died before the ``prctl`` call has been replaced as parent (by init or a
    subreaper), so the child exits here; a parent that dies after it makes the kernel send
    KILL. The signal survives the ``execve`` of ``setpriv``, ``prlimit`` and the tool (none
    is set-user-ID), and ``setpriv --pdeathsig KILL`` sets it once more.

    ``preexec_fn`` runs Python in the child of a fork, where a lock that another thread of
    the supervisor's process held at the fork is never released (the reason for ruff's
    PLW1509). The guard therefore takes none: it makes two system calls through objects
    that exist before the fork, and it imports and logs nothing.
    """
    prctl = _PRCTL
    if prctl is None:
        return None

    def guard() -> None:
        if prctl(_PR_SET_PDEATHSIG, _KILL, 0, 0, 0) != 0:
            raise OSError(ctypes.get_errno(), "prctl(PR_SET_PDEATHSIG)")
        if os.getppid() != parent:
            # Ends the child before any exec (the interpreter exits it with status 255);
            # the process that would read the error is the dead one.
            raise ProcessLookupError(f"the supervisor {parent} died during the launch")

    return guard


def _resident_kib() -> int | None:
    """The resident memory of this process now, in KiB (``/proc/self/statm``); None if unknown.

    A forked child starts with these pages, and the kernel carries that peak over the exec into
    the usage it reports for the tool (:class:`ProcessRun`).
    """
    try:
        with open("/proc/self/statm", encoding="ascii") as stream:
            pages = int(stream.read().split()[1])
    except (OSError, ValueError, IndexError):
        return None
    return pages * os.sysconf("SC_PAGE_SIZE") // 1024


def _positive(name: str, value: object, *, optional: bool = False) -> None:
    if optional and value is None:
        return
    if type(value) is not int or value < 1:
        raise ValueError(f"Launch.{name} must be a positive integer, not {value!r}")


@dataclass(frozen=True)
class Launch:
    """What to run and under which limits."""

    binary: PinnedBinary
    args: tuple[str, ...]
    cwd: str
    memory_bytes: int
    file_bytes: int | None = None
    deadline_ms: int | None = None
    term_grace_ms: int = 10_000
    watch: tuple[str, int] | None = None
    stdout_capture: int = 0
    tail_bytes: int = TAIL_BYTES
    eof_grace_ms: int = 1_000

    def __post_init__(self) -> None:
        if not isinstance(self.binary, PinnedBinary):
            raise ValueError("Launch.binary must be a PinnedBinary")
        if not isinstance(self.args, tuple) or not all(
            isinstance(a, str) and "\0" not in a for a in self.args
        ):
            raise ValueError("Launch.args must be a tuple of strings without NUL")
        if not isinstance(self.cwd, str) or not self.cwd.startswith("/") or "\0" in self.cwd:
            raise ValueError("Launch.cwd must be an absolute path")
        _positive("memory_bytes", self.memory_bytes)
        _positive("file_bytes", self.file_bytes, optional=True)
        _positive("deadline_ms", self.deadline_ms, optional=True)
        _positive("term_grace_ms", self.term_grace_ms)
        _positive("eof_grace_ms", self.eof_grace_ms)
        if not 1 <= self.tail_bytes <= TAIL_BYTES or type(self.tail_bytes) is not int:
            raise ValueError(f"Launch.tail_bytes must be 1..{TAIL_BYTES}")
        if type(self.stdout_capture) is not int or self.stdout_capture < 0:
            raise ValueError("Launch.stdout_capture must be a nonnegative integer")
        if self.watch is not None:
            path, cap = self.watch
            if not isinstance(path, str) or not path.startswith("/") or "\0" in path:
                raise ValueError("Launch.watch path must be absolute")
            _positive("watch cap", cap)


@dataclass(frozen=True)
class ProcessRun:
    """A finished process: its record value, its typed causes and the raw extras."""

    result: ProcessResult
    causes: tuple[Cause, ...] = ()
    #: The complete stdout if it fit ``Launch.stdout_capture`` bytes, otherwise None.
    stdout: bytes | None = None
    #: True if some stderr byte is not represented in ``result.stderr_tail``.
    stderr_truncated: bool = False
    #: Processor time (user and system) and peak resident memory of the process and of the
    #: descendants it waited for, as the kernel reported them when the leader was reaped; None
    #: when the status was lost to another reaper. Both count from the fork: the child starts
    #: as a copy of the supervising process, so the peak is about what that process had
    #: resident at the launch (``launch_rss_kib``) or more, and the time includes the launch
    #: wrappers. A peak clearly above ``launch_rss_kib`` is the tool's own; one near or below
    #: it says only that the tool stayed below about that size. Measurements for the record's
    #: diagnostics, never an input of a verdict.
    cpu_ms: int | None = None
    max_rss_kib: int | None = None
    launch_rss_kib: int | None = None

    @property
    def primary(self) -> Cause | None:
        return self.causes[0] if self.causes else None


class Process:
    """One supervised child process (created by :meth:`Supervisor.start`)."""

    def __init__(self, launch: Launch, started_ns: int) -> None:
        self.launch = launch
        self.pid: int | None = None
        self.run: ProcessRun | None = None
        self.causes: list[Cause] = []
        self._started_ns = started_ns
        self._popen: subprocess.Popen[bytes] | None = None
        self._pipes: dict[int, OutputTail] = {}
        self._stdout = OutputTail(launch.tail_bytes, launch.stdout_capture)
        self._stderr = OutputTail(launch.tail_bytes)
        self._pidfd: int | None = None
        self._deadline_ns = (
            None if launch.deadline_ms is None else started_ns + launch.deadline_ms * _NS_PER_MS
        )
        self._term_sent = False
        self._kill_ns: int | None = None
        self._next_watch_ns = started_ns
        self._next_poll_ns = started_ns
        self._reaped = False
        self._status_lost = False
        self._returncode: int | None = None
        self._usage: tuple[int, int] | None = None
        self._launch_rss_kib: int | None = None
        self._ended_ns: int | None = None
        self._eof_deadline_ns: int | None = None

    # -- causes and signals ----------------------------------------------------------------

    def _cause(self, cause: Cause) -> None:
        if cause not in self.causes:
            self.causes.append(cause)

    def _signal_group(self, number: int) -> None:
        # Only while the leader is unreaped: its pid (= the group id) cannot be reused.
        if self.pid is not None and not self._reaped and not self._status_lost:
            with contextlib.suppress(ProcessLookupError, PermissionError):
                os.killpg(self.pid, number)

    def _terminate(self, now: int, grace_ms: int) -> None:
        kill_at = now + grace_ms * _NS_PER_MS
        if not self._term_sent:
            self._term_sent = True
            self._signal_group(signal.SIGTERM)
        self._kill_ns = kill_at if self._kill_ns is None else min(self._kill_ns, kill_at)

    # -- timers ----------------------------------------------------------------------------

    def next_timer(self) -> int | None:
        """The earliest time at which :meth:`tick` has something to do."""
        times: list[int] = []
        if not self._reaped:
            if self._deadline_ns is not None and not self._term_sent:
                times.append(self._deadline_ns)
            if self._kill_ns is not None:
                times.append(self._kill_ns)
            if self.launch.watch is not None and not self._term_sent:
                times.append(self._next_watch_ns)
            if self._pidfd is None:
                times.append(self._next_poll_ns)
        elif self._eof_deadline_ns is not None:
            times.append(self._eof_deadline_ns)
        return min(times) if times else None

    def tick(self, now: int) -> None:
        """Apply the timers of a running process (call only after checking for its exit)."""
        if self._reaped:
            return
        if self._deadline_ns is not None and now >= self._deadline_ns and not self._term_sent:
            self._cause(Cause.DEADLINE)
            self._terminate(now, self.launch.term_grace_ms)
        if self.launch.watch is not None and not self._term_sent and now >= self._next_watch_ns:
            self._next_watch_ns = now + _WATCH_INTERVAL_NS
            path, cap = self.launch.watch
            try:
                size = os.stat(path).st_size
            except OSError:
                size = 0
            if size >= cap:
                self._cause(Cause.PROOF_CAP)
                self._terminate(now, self.launch.term_grace_ms)
        if self._kill_ns is not None and now >= self._kill_ns:
            self._kill_ns = None
            self._signal_group(signal.SIGKILL)
        if self._pidfd is None:
            self._next_poll_ns = now + _POLL_INTERVAL_NS

    # -- exit and output ---------------------------------------------------------------------

    def leader_exited(self) -> bool:
        """True once the leader has exited (it is not reaped by this call)."""
        if self.pid is None or self._reaped:
            return self._reaped
        try:
            state = os.waitid(os.P_PID, self.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
        except ChildProcessError:
            # Someone else reaped our child: its status is unknown, and its pid (the group
            # id) may already be reused, so the group must not be signalled any more.
            self._status_lost = True
            return True
        return state is not None

    def reap(self, now: int) -> None:
        """Kill what is left of the group, reap the leader, start the EOF grace."""
        assert self._popen is not None
        if not self._status_lost:
            self._signal_group(signal.SIGKILL)
        code = self._wait()
        # Popen reports 0 for a child it could not wait for (ECHILD): never trust that.
        self._returncode = None if self._status_lost else code
        self._reaped = True
        self._ended_ns = now
        self._kill_ns = None
        self._eof_deadline_ns = now + self.launch.eof_grace_ms * _NS_PER_MS

    def _wait(self) -> int:
        """Reap the leader and keep what the kernel says it used.

        ``wait4`` returns the exit status together with the resource usage of the child and of
        the descendants it waited for; the tool is the leader itself, since the isolation
        wrappers exec. The status is given to the ``Popen`` object, which would otherwise wait
        again and find no child. A child that somebody else reaped has neither.
        """
        assert self._popen is not None and self.pid is not None
        if self._popen.returncode is not None:
            return self._popen.returncode
        try:
            _, status, usage = os.wait4(self.pid, 0)
        except ChildProcessError:
            self._status_lost = True
            return self._popen.wait()
        code = os.waitstatus_to_exitcode(status)
        self._popen.returncode = code
        cpu_ms = int((usage.ru_utime + usage.ru_stime) * 1000)
        self._usage = (cpu_ms, int(usage.ru_maxrss))  # Linux reports ru_maxrss in KiB
        return code

    def drain(self, fd: int, budget: int = _READ_PER_STEP) -> bool:
        """Read what is available from one pipe; True when it reached EOF."""
        sink = self._pipes[fd]
        while budget > 0:
            try:
                data = os.read(fd, min(_CHUNK, budget))
            except BlockingIOError:
                return False
            except InterruptedError:
                continue
            if not data:
                return True
            sink.feed(data)
            budget -= len(data)
        return False

    def finish(self) -> ProcessRun:
        assert self._reaped and self._ended_ns is not None
        if self.launch.binary.changed():
            self._cause(Cause.BINARY_CHANGED)
        code = self._returncode
        stdout_text, stdout_cut = self._stdout.text()
        stderr_text, stderr_cut = self._stderr.text()
        result = ProcessResult(
            started=True,
            # An unknown status (lost to another reaper) has neither exit nor signal.
            exit=code if code is not None and code >= 0 else None,
            signal=-code if code is not None and code < 0 else None,
            elapsed_ms=max(0, (self._ended_ns - self._started_ns) // _NS_PER_MS),
            stdout_tail=stdout_text,
            stderr_tail=stderr_text,
            stdout_bytes=self._stdout.total,
            stdout_truncated=stdout_cut,
            cause=self.causes[0].value if self.causes else None,
            conflicts=None,
        )
        self.run = ProcessRun(
            result=result,
            causes=tuple(self.causes),
            stdout=self._stdout.captured,
            stderr_truncated=stderr_cut,
            cpu_ms=None if self._usage is None else self._usage[0],
            max_rss_kib=None if self._usage is None else self._usage[1],
            launch_rss_kib=self._launch_rss_kib,
        )
        return self.run

    def not_started(self, cause: Cause, now: int) -> ProcessRun:
        self._cause(cause)
        elapsed = max(0, (now - self._started_ns) // _NS_PER_MS)
        self.run = ProcessRun(
            result=ProcessResult.not_started(cause, elapsed_ms=elapsed), causes=tuple(self.causes)
        )
        return self.run


class Supervisor:
    """Starts, watches, stops and reaps tool processes from one thread."""

    def __init__(self, isolation: Isolation, *, clock: Clock = time.monotonic_ns) -> None:
        self.isolation = isolation
        self.clock = clock
        self.stopping = False
        self._selector = selectors.DefaultSelector()
        self._active: list[Process] = []

    @property
    def active(self) -> list[Process]:
        """Processes not finished yet, in start order."""
        return list(self._active)

    # -- launching ---------------------------------------------------------------------------

    def start(self, launch: Launch) -> Process:
        """Launch a process; a refused or failed launch returns an already finished one."""
        now = self.clock()
        process = Process(launch, now)
        if self.stopping:
            process.not_started(Cause.CANCELLED, now)
            return process
        if launch.binary.changed():
            process.not_started(Cause.BINARY_CHANGED, self.clock())
            return process
        command = self.isolation.wrap(
            launch.binary.path,
            launch.args,
            memory_bytes=launch.memory_bytes,
            file_bytes=launch.file_bytes,
        )
        out_read, out_write = os.pipe()
        err_read, err_write = os.pipe()
        process._launch_rss_kib = _resident_kib()
        try:
            popen = subprocess.Popen(
                command,
                stdin=subprocess.DEVNULL,
                stdout=out_write,
                stderr=err_write,
                cwd=launch.cwd,
                env=dict(TOOL_ENVIRONMENT),
                close_fds=True,
                start_new_session=True,
                preexec_fn=_parent_death_guard(os.getpid()),  # noqa: PLW1509 - see there
            )
        except (OSError, subprocess.SubprocessError):
            for fd in (out_read, out_write, err_read, err_write):
                os.close(fd)
            process.not_started(Cause.LAUNCH, self.clock())
            return process
        os.close(out_write)
        os.close(err_write)
        process._popen = popen
        process.pid = popen.pid
        process._pipes = {out_read: process._stdout, err_read: process._stderr}
        for fd in (out_read, err_read):
            os.set_blocking(fd, False)
            self._selector.register(fd, selectors.EVENT_READ, process)
        try:
            process._pidfd = os.pidfd_open(popen.pid)
        except (AttributeError, OSError):
            process._pidfd = None
        if process._pidfd is not None:
            self._selector.register(process._pidfd, selectors.EVENT_READ, process)
        self._active.append(process)
        return process

    # -- control -----------------------------------------------------------------------------

    def cancel(self, process: Process, grace_ms: int) -> None:
        """Deliberately stop one process: TERM to its group now, KILL after ``grace_ms``."""
        if process.run is not None or process not in self._active:
            return
        process._cause(Cause.CANCELLED)
        process._terminate(self.clock(), grace_ms)

    def stop(self, grace_ms: int) -> None:
        """User stop (specification §6.2): no further launches; every running process is
        cancelled."""
        self.stopping = True
        for process in self.active:
            self.cancel(process, grace_ms)

    def note(self, process: Process, cause: Cause) -> None:
        """Record a cause the coordinator observed (e.g. an attributable cgroup OOM event)."""
        if process.run is None:
            process._cause(cause)

    # -- the loop ------------------------------------------------------------------------------

    def step(self, timeout_ms: int | None) -> list[ProcessRun]:
        """Wait at most ``timeout_ms`` for events, handle them; return the newly finished runs."""
        if not self._active:
            return []
        now = self.clock()
        wait_ns = None if timeout_ms is None else max(0, timeout_ms) * _NS_PER_MS
        timers = [t for t in (p.next_timer() for p in self._active) if t is not None]
        if timers:
            until = max(0, min(timers) - now)
            wait_ns = until if wait_ns is None else min(wait_ns, until)
        events = self._selector.select(None if wait_ns is None else wait_ns / 1e9)
        for key, _ in events:
            process = key.data
            assert isinstance(process, Process)
            if key.fd == process._pidfd:
                continue  # readiness only; leader_exited() below decides
            if key.fd in process._pipes and process.drain(key.fd):
                self._close_pipe(process, key.fd)
        now = self.clock()
        finished: list[ProcessRun] = []
        for process in self.active:
            # The exit is checked before the timers: a process that has already ended is
            # never charged with a deadline or cap the supervisor did not need to enforce.
            if not process._reaped and process.leader_exited():
                self._close_pidfd(process)
                process.reap(now)
            if process._reaped:
                run = self._try_finish(process, now)
                if run is not None:
                    finished.append(run)
            else:
                process.tick(now)
        return finished

    def _try_finish(self, process: Process, now: int) -> ProcessRun | None:
        for fd in list(process._pipes):
            if process.drain(fd):
                self._close_pipe(process, fd)
        if process._pipes:
            deadline = process._eof_deadline_ns
            if deadline is None or now < deadline:
                return None
            process._cause(Cause.HELD_OPEN)
            for fd in list(process._pipes):
                self._close_pipe(process, fd)
        self._active.remove(process)
        return process.finish()

    def _close_pipe(self, process: Process, fd: int) -> None:
        with contextlib.suppress(KeyError, ValueError):
            self._selector.unregister(fd)
        process._pipes.pop(fd, None)
        os.close(fd)

    def _close_pidfd(self, process: Process) -> None:
        if process._pidfd is not None:
            with contextlib.suppress(KeyError, ValueError):
                self._selector.unregister(process._pidfd)
            os.close(process._pidfd)
            process._pidfd = None

    def shutdown(self, grace_ms: int) -> None:
        """Stop, then drive the loop until every child is killed, reaped and drained."""
        self.stop(grace_ms)
        limit = time.monotonic() + grace_ms / 1000 + _SHUTDOWN_EXTRA_S
        while self._active:
            if time.monotonic() > limit:
                raise ToolError("supervisor.shutdown", f"{len(self._active)} process(es) remain")
            self.step(50)
        self._selector.close()  # stopped: start() refuses, step() has nothing to wait for
