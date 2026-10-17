"""The stream relay: a bounded process that moves the solver's proof to the checker (specification
§6.4).

Run as its own supervised process, exactly as the stream leaf launches it::

    python -I -S -B .../cubeproof/tools/relay.py SOLVER_FIFO CHECKER_FIFO CAP [BUFFER]

It reads the proof from the solver's FIFO, hashes and counts every byte it accepts, and
writes the bytes in order to the checker's FIFO; on exit it prints one report line on stdout
(:class:`RelayReport`, the specification §4.8 ``relay`` fields plus the count written) and exits
with :data:`EXIT_COMPLETE`, :data:`EXIT_TRANSPORT`, :data:`EXIT_CAP`, :data:`EXIT_USAGE` or
:data:`EXIT_TERMINATED`. The module imports only the standard library: the interpreter runs
isolated (``-I -S``), without site-packages, so the script stands alone (its bytes are part of
the cubeproof source manifest, specification §4.6).

Transport rules:

- Both endpoints must be FIFOs (``lstat``, never a symlink; the opened descriptor must be the
  same inode). The solver side is opened at once with ``O_NONBLOCK`` (never blocks); the
  checker side is opened with ``O_NONBLOCK`` too, which fails with ENXIO until the checker
  has opened it for reading, so it is retried with a short backoff: the explicit readiness
  of specification §6.4, no start-order deadlock whichever process opens first or late.
- A FIFO that never had a writer reads as end of file; the relay takes EOF only after
  ``poll`` reported the solver side readable or hung up, which Linux does only once a writer
  has connected (and, for HUP, gone).
- Writes are nonblocking and may be partial or refused (EAGAIN): the relay resumes exactly
  where it stopped. At most ``BUFFER`` bytes (default 1 MiB) are held; reading pauses while
  the buffer is full, so a slow checker slows the solver instead of growing memory.
- More than ``CAP`` bytes from the solver is the proof cap (:data:`ERROR_CAP`): the bytes of
  the crossing read are not accepted, both FIFOs are closed (the solver then gets EPIPE or
  SIGPIPE, the checker EOF) and the counters cover only accepted bytes.
- The checker closing its end is a transport error (EPIPE) as soon as a byte cannot be
  written. Closing it while nothing is pending is not an error by itself: cake_lpr stops
  reading at the empty clause, possibly before the solver's EOF arrives; if the solver then
  sends nothing more, every byte was written and the transfer is complete (specification §6.4: an
  early checker exit fails "unless the complete EOF/all-written criteria actually hold").
- TERM/INT/HUP (a teardown, the coordinator's deadline or a stop) end an incomplete transfer
  with :data:`ERROR_TERMINATED`; a transfer that already completed, or that completes without
  waiting (the solver's EOF read, nothing pending, the output open), keeps its complete
  report.

``solver_eof`` means the solver side reached EOF; ``all_written`` means every accepted byte was
written to the checker FIFO and that end was closed without error. Only a complete report
(:attr:`RelayReport.complete`) may stand for a proof; partial counters stay in the record's
``relay`` value only (specification §4.8).
"""

from __future__ import annotations

import builtins
import errno
import hashlib
import json
import os
import select
import signal
import stat
import sys
import time
from dataclasses import dataclass
from types import FrameType
from typing import Any

__all__ = [
    "CHUNK",
    "DEFAULT_BUFFER",
    "ERROR_CAP",
    "ERROR_TERMINATED",
    "EXIT_CAP",
    "EXIT_COMPLETE",
    "EXIT_TERMINATED",
    "EXIT_TRANSPORT",
    "EXIT_USAGE",
    "FORMAT",
    "RelayReport",
    "main",
    "parse_report",
]

FORMAT = "cubeproof-relay-1"
EXIT_COMPLETE = 0
EXIT_TRANSPORT = 1
EXIT_CAP = 2
EXIT_USAGE = 3
EXIT_TERMINATED = 4
ERROR_CAP = "proof_cap"
ERROR_TERMINATED = "terminated"
DEFAULT_BUFFER = 1 << 20
CHUNK = 1 << 16
#: Largest accepted buffer (the relay's address space is capped at 128 MiB, specification §8.3).
MAX_BUFFER = 64 << 20
#: Longest accepted ``--linger-ms`` (a test hook: wait after a completed transfer).
MAX_LINGER_MS = 10_000
_OPEN_RETRY_FIRST_MS = 1
_OPEN_RETRY_MAX_MS = 10
_HEX = frozenset("0123456789abcdef")
_FIELDS = ("format", "bytes", "sha256", "solver_eof", "all_written", "error", "written")
_EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()


@dataclass(frozen=True)
class RelayReport:
    """What the relay observed (specification §4.8 ``relay`` fields) and how many bytes it wrote."""

    bytes: int
    sha256: str
    solver_eof: bool
    all_written: bool
    error: str | None
    written: int

    @property
    def complete(self) -> bool:
        """The complete-transfer criterion of specification §6.4: EOF, everything written, no
        error."""
        return (
            self.solver_eof
            and self.all_written
            and self.error is None
            and self.written == self.bytes
        )

    def record_value(self) -> dict[str, Any]:
        """The record's ``relay`` object (specification §4.8), in specification order."""
        return {
            "bytes": self.bytes,
            "sha256": self.sha256,
            "solver_eof": self.solver_eof,
            "all_written": self.all_written,
            "error": self.error,
        }

    def to_line(self) -> builtins.bytes:
        value = {"format": FORMAT, **self.record_value(), "written": self.written}
        return (json.dumps(value, separators=(",", ":"), ensure_ascii=True) + "\n").encode()


def _count(value: object) -> bool:
    return type(value) is int and value >= 0


def parse_report(stdout: bytes | None) -> RelayReport | None:
    """The report of a relay's complete stdout, or None unless it is exactly one valid line."""
    if not stdout or not stdout.endswith(b"\n") or stdout.count(b"\n") != 1:
        return None
    try:
        value = json.loads(stdout)
    except ValueError:
        return None
    if not isinstance(value, dict) or tuple(sorted(value)) != tuple(sorted(_FIELDS)):
        return None
    digest, error = value["sha256"], value["error"]
    if (
        value["format"] != FORMAT
        or not _count(value["bytes"])
        or not _count(value["written"])
        or value["written"] > value["bytes"]
        or not isinstance(digest, str)
        or len(digest) != 64
        or not set(digest) <= _HEX
        or type(value["solver_eof"]) is not bool
        or type(value["all_written"]) is not bool
        or not (error is None or (isinstance(error, str) and error != ""))
        or (value["all_written"] and value["written"] != value["bytes"])
    ):
        return None
    return RelayReport(
        bytes=value["bytes"],
        sha256=digest,
        solver_eof=value["solver_eof"],
        all_written=value["all_written"],
        error=error,
        written=value["written"],
    )


# -- the process -------------------------------------------------------------------------------


class _Usage(Exception):
    """A bad command line or endpoint: report and exit EXIT_USAGE."""


def _errno_name(error: OSError) -> str:
    name = errno.errorcode.get(error.errno or 0, str(error.errno))
    return f"{name} ({error.strerror})" if error.strerror else name


def _fifo_identity(path: str, which: str) -> tuple[int, int]:
    try:
        info = os.lstat(path)
    except OSError as error:
        raise _Usage(f"{which}: {path}: {_errno_name(error)}") from None
    if not stat.S_ISFIFO(info.st_mode):
        raise _Usage(f"{which}: {path} is not a FIFO")
    return info.st_dev, info.st_ino


def _same_fifo(fd: int, identity: tuple[int, int]) -> bool:
    info = os.fstat(fd)
    return stat.S_ISFIFO(info.st_mode) and (info.st_dev, info.st_ino) == identity


class _Transfer:
    """One relay run (module doc); :meth:`run` returns the exit code, :attr:`report` the rest."""

    def __init__(self, source: str, sink: str, cap: int, buffer: int, linger_ms: int) -> None:
        self.source = source
        self.sink = sink
        self.cap = cap
        self.buffer = buffer
        self.linger_ms = linger_ms
        self.digest = hashlib.sha256()
        self.received = 0
        self.written = 0
        #: Accepted bytes not yet known to be written start at ``offset`` (bounded by buffer).
        self.pending = bytearray()
        self.offset = 0
        self.solver_eof = False
        self.all_written = False
        self.error: str | None = None
        self.capped = False
        self.terminated = False
        #: The checker closed its input (POLLERR on the write end) while nothing was pending.
        self.reader_gone = False
        self.in_fd: int | None = None
        self.out_fd: int | None = None
        self._wake_read, self._wake_write = os.pipe2(os.O_NONBLOCK | os.O_CLOEXEC)

    # -- signals -------------------------------------------------------------------------------

    def _on_signal(self, signum: int, frame: FrameType | None) -> None:
        del signum, frame
        self.terminated = True

    def install(self) -> None:
        signal.signal(signal.SIGPIPE, signal.SIG_IGN)  # a closed reader is EPIPE, not death
        signal.set_wakeup_fd(self._wake_write, warn_on_full_buffer=False)
        for number in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
            signal.signal(number, self._on_signal)

    # -- the transfer --------------------------------------------------------------------------

    def report(self) -> RelayReport:
        return RelayReport(
            bytes=self.received,
            sha256=self.digest.hexdigest(),
            solver_eof=self.solver_eof,
            all_written=self.all_written,
            error=self.error,
            written=self.written,
        )

    def run(self) -> int:
        source_id = _fifo_identity(self.source, "source")
        sink_id = _fifo_identity(self.sink, "sink")
        flags = os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC
        try:
            self.in_fd = os.open(self.source, os.O_RDONLY | flags)
        except OSError as error:
            raise _Usage(f"source: {self.source}: {_errno_name(error)}") from None
        if not _same_fifo(self.in_fd, source_id):
            raise _Usage(f"source: {self.source} changed while it was opened")
        try:
            self._loop(sink_id, flags)
        finally:
            self._close_input()
            if self.out_fd is not None:
                fd, self.out_fd = self.out_fd, None
                try:
                    os.close(fd)
                except OSError as error:
                    self._fail(f"close: {_errno_name(error)}")
        if self.all_written and self.linger_ms:
            time.sleep(self.linger_ms / 1000)  # test hook: a late teardown keeps completion
        if self.all_written and self.error is None:
            return EXIT_COMPLETE
        if self.capped:
            return EXIT_CAP
        if self.error == ERROR_TERMINATED:
            return EXIT_TERMINATED
        return EXIT_TRANSPORT

    def _fail(self, message: str) -> None:
        if self.error is None:
            self.error = message
        self.all_written = False

    def _close_input(self) -> None:
        if self.in_fd is not None:
            fd, self.in_fd = self.in_fd, None
            os.close(fd)

    def _loop(self, sink_id: tuple[int, int], flags: int) -> None:  # noqa: PLR0911 - one exit per end
        poller = select.poll()
        poller.register(self._wake_read, select.POLLIN)
        retry_ms = _OPEN_RETRY_FIRST_MS
        next_open = 0.0
        registered: dict[int, int] = {}
        while True:
            if self.out_fd is None and (self.terminated or time.monotonic() >= next_open):
                try:
                    self.out_fd = os.open(self.sink, os.O_WRONLY | flags)
                except OSError as error:
                    if error.errno != errno.ENXIO:
                        self._fail(f"open: {_errno_name(error)}")
                        return
                    next_open = time.monotonic() + retry_ms / 1000
                    retry_ms = min(_OPEN_RETRY_MAX_MS, retry_ms * 2)
                else:
                    if not _same_fifo(self.out_fd, sink_id):
                        self._fail(f"open: {self.sink} changed while it was opened")
                        return
            if self.solver_eof and not self.pending and self.out_fd is not None:
                fd, self.out_fd = self.out_fd, None
                try:
                    os.close(fd)
                except OSError as error:
                    self._fail(f"close: {_errno_name(error)}")
                    return
                self.all_written = True
                return
            # A termination ends the transfer here, after a completion that needed no wait
            # (the solver's EOF already read, nothing pending) was taken just above.
            if self.terminated:
                self._fail(ERROR_TERMINATED)
                return
            wanted: dict[int, int] = {}
            if self.in_fd is not None and len(self.pending) < self.buffer:
                wanted[self.in_fd] = select.POLLIN
            if self.out_fd is not None and (self.pending or not self.reader_gone):
                wanted[self.out_fd] = select.POLLOUT if self.pending else 0
            for fd in set(registered) - set(wanted):
                poller.unregister(fd)
            for fd, mask in wanted.items():
                if registered.get(fd) != mask:
                    poller.register(fd, mask)
            registered = wanted
            timeout = None
            if self.out_fd is None:
                timeout = max(0, int((next_open - time.monotonic()) * 1000) + 1)
            for fd, events in poller.poll(timeout):
                if fd == self._wake_read:
                    self._drain_wakeups()
                elif fd == self.in_fd:
                    if not self._read():
                        return
                elif fd == self.out_fd and not self._write(events):
                    return

    def _drain_wakeups(self) -> None:
        try:
            while os.read(self._wake_read, 512):
                pass
        except BlockingIOError:
            pass

    def _read(self) -> bool:
        assert self.in_fd is not None
        want = min(CHUNK, self.buffer - len(self.pending))
        try:
            data = os.read(self.in_fd, want)
        except BlockingIOError:
            return True
        except OSError as error:
            self._fail(f"read: {_errno_name(error)}")
            return False
        if not data:  # poll reported readiness: a writer connected, so this is its EOF
            self.solver_eof = True
            self._close_input()
            return True
        if self.received + len(data) > self.cap:
            self.capped = True
            self._fail(ERROR_CAP)
            return False
        self.digest.update(data)
        self.received += len(data)
        self.pending += data
        return True

    def _write(self, events: int) -> bool:
        assert self.out_fd is not None
        if not self.pending:
            if events & (select.POLLERR | select.POLLHUP):
                # The checker closed its input. That is not yet a failure: if the solver
                # sends nothing more, every byte was written (specification §6.4). A further byte
                # fails.
                self.reader_gone = True
            return True
        try:
            with memoryview(self.pending) as view:
                count = os.write(self.out_fd, view[self.offset : self.offset + CHUNK])
        except BlockingIOError:
            return True
        except OSError as error:
            self._fail(f"write: {_errno_name(error)}")
            return False
        self.offset += count
        self.written += count
        if self.offset == len(self.pending):
            self.pending.clear()
            self.offset = 0
        elif 2 * self.offset >= len(self.pending):
            del self.pending[: self.offset]  # amortized: moves at most what was written
            self.offset = 0
        return True


def _positive(text: str, what: str, *, upper: int | None = None, zero: bool = False) -> int:
    if not text.isdigit() or not text.isascii():
        raise _Usage(f"{what} must be a decimal integer, not {text!r}")
    value = int(text)
    if (value < 1 and not zero) or (upper is not None and value > upper):
        raise _Usage(f"{what} {value} is out of range")
    return value


def _absolute(text: str, what: str) -> str:
    if not text.startswith("/") or "\0" in text:
        raise _Usage(f"{what} must be an absolute path, not {text!r}")
    return text


def _arguments(argv: list[str]) -> tuple[str, str, int, int, int]:
    args = list(argv)
    linger = 0
    if "--linger-ms" in args:
        at = args.index("--linger-ms")
        if at + 1 >= len(args):
            raise _Usage("--linger-ms needs a value")
        linger = _positive(args[at + 1], "--linger-ms", upper=MAX_LINGER_MS, zero=True)
        del args[at : at + 2]
    if len(args) not in (3, 4):
        raise _Usage("usage: relay.py SOLVER_FIFO CHECKER_FIFO CAP [BUFFER] [--linger-ms N]")
    source = _absolute(args[0], "SOLVER_FIFO")
    sink = _absolute(args[1], "CHECKER_FIFO")
    cap = _positive(args[2], "CAP")
    buffer = _positive(args[3], "BUFFER", upper=MAX_BUFFER) if len(args) == 4 else DEFAULT_BUFFER
    return source, sink, cap, buffer, linger


def _emit(report: RelayReport) -> None:
    line = report.to_line()
    view = memoryview(line)
    while view:
        try:
            view = view[os.write(1, view) :]
        except InterruptedError:
            continue
        except OSError:
            return  # nobody reads the report: the leaf treats a missing report as failure


def main(argv: list[str]) -> int:
    """Run one relay; print the report line; return the exit code (module doc)."""
    try:
        source, sink, cap, buffer, linger = _arguments(argv)
    except _Usage as usage:
        _emit(RelayReport(0, _EMPTY_SHA256, False, False, f"usage: {usage}", 0))
        return EXIT_USAGE
    transfer = _Transfer(source, sink, cap, buffer, linger)
    transfer.install()
    try:
        code = transfer.run()
    except _Usage as usage:
        transfer._fail(f"usage: {usage}")
        code = EXIT_USAGE
    _emit(transfer.report())
    return code


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
