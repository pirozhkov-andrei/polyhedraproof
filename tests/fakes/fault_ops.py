"""Read/write/fsync/rename fault adapters for durability tests.

``FaultyOS`` has the ``os`` functions durable I/O uses (``open``, ``read``, ``write``,
``fsync``, ``fdatasync``, ``rename``, ``replace``, ``close``) and forwards them to the real
module, except where a ``Fault`` fires: an errno (EIO, ENOSPC, ...), a short read/write, an
``InterruptedError``, a torn write (some bytes written, then a crash) or a simulated crash
before or after the real call. Every call is logged. Code under test receives a
``FaultyOS`` as its ``os``-like dependency, or the adapter is installed over the ``os``
module for the duration of a ``with patched(faults):`` block.

A crash is ``SimulatedCrash``, a ``BaseException``: ordinary ``except Exception`` and
``except OSError`` handlers do not swallow it, so the code under test stops where a killed
process would stop, and the test then inspects or recovers the files it left.

Limits: only calls through these ``os`` functions are seen. Buffered file objects
(``open(...).write``) and ``from os import write`` taken before patching bypass the adapter.
"""

from __future__ import annotations

import errno as errno_codes
import fnmatch
import os
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any

OPERATIONS = ("open", "read", "write", "fsync", "fdatasync", "rename", "replace", "close")
EFFECTS = ("error", "short", "eintr", "torn", "crash_before", "crash_after")


class SimulatedCrash(BaseException):
    """The process 'died' at an injection point."""


@dataclass(frozen=True)
class Fault:
    """Fire on matching calls number `nth`, `nth`+1, ..., `nth`+`times`-1 (1-based).

    A call matches when its operation is `op` and, if `path` is given, one of its paths
    matches the fnmatch pattern `path`. The paths of a call: for ``open`` the opened path; for
    descriptor operations the path the descriptor was opened with through this adapter, else
    its /proc link; for ``rename``/``replace`` the source **and** the destination (either may
    match). `times=0` means every matching call from `nth` on. `keep` is the byte count a short
    or torn transfer performs.

    Every fault counts every call that matches it, whether or not another fault fires on that
    call, so `nth` always refers to the matching calls of the code under test. When several
    faults are due on the same call, the first in the adapter's list fires; the others have
    used that call up (a fault due only on that call does not fire at all).
    """

    op: str
    effect: str = "error"
    nth: int = 1
    times: int = 1
    path: str | None = None
    errno: int = errno_codes.EIO
    keep: int = 0

    def __post_init__(self) -> None:
        if self.op not in OPERATIONS:
            raise ValueError(f"unknown operation {self.op!r}")
        if self.effect not in EFFECTS:
            raise ValueError(f"unknown effect {self.effect!r}")
        if self.effect in ("short", "torn") and self.op not in ("read", "write"):
            raise ValueError(f"{self.effect} applies to read and write only")
        if self.nth < 1 or self.times < 0 or self.keep < 0:
            raise ValueError("nth >= 1, times >= 0, keep >= 0")


@dataclass
class Call:
    """One call seen by the adapter; for rename/replace `path` is the destination."""

    op: str
    path: str
    size: int | None
    outcome: str
    source: str | None = None


@dataclass
class FaultyOS:
    """An ``os``-like object that injects `faults` into the real calls."""

    faults: Sequence[Fault] = ()
    real: Any = os
    calls: list[Call] = field(default_factory=list)
    _seen: dict[int, int] = field(default_factory=dict)
    _paths: dict[int, str] = field(default_factory=dict)

    # -- matching -------------------------------------------------------------------------

    def _path_of_fd(self, fd: int) -> str:
        if fd in self._paths:
            return self._paths[fd]
        try:
            return str(self.real.readlink(f"/proc/self/fd/{fd}"))
        except OSError:
            return ""

    def _fire(self, op: str, paths: Sequence[str]) -> Fault | None:
        """Count this call for every matching fault; return the first one that is due."""
        chosen: Fault | None = None
        for index, fault in enumerate(self.faults):
            if fault.op != op:
                continue
            if fault.path is not None and not any(fnmatch.fnmatch(p, fault.path) for p in paths):
                continue
            seen = self._seen.get(index, 0) + 1
            self._seen[index] = seen
            last = fault.nth + fault.times - 1
            due = seen >= fault.nth and (fault.times == 0 or seen <= last)
            if due and chosen is None:
                chosen = fault
        return chosen

    def _call(
        self,
        op: str,
        path: str,
        size: int | None,
        real: Callable[[], Any],
        partial: Callable[[int], Any] | None = None,
        source: str | None = None,
    ) -> Any:
        fault = self._fire(op, (path,) if source is None else (source, path))
        if fault is None:
            result = real()
            self.calls.append(Call(op, path, size, "ok", source))
            return result
        self.calls.append(Call(op, path, size, fault.effect, source))
        if fault.effect == "error":
            raise OSError(
                fault.errno, f"injected {errno_codes.errorcode.get(fault.errno, fault.errno)}", path
            )
        if fault.effect == "eintr":
            raise InterruptedError(errno_codes.EINTR, "injected EINTR", path)
        if fault.effect == "crash_before":
            raise SimulatedCrash(f"{op} {path}: crash before the call")
        if fault.effect == "crash_after":
            real()
            raise SimulatedCrash(f"{op} {path}: crash after the call")
        assert partial is not None
        result = partial(fault.keep)
        if fault.effect == "torn":
            raise SimulatedCrash(f"{op} {path}: crash after {fault.keep} bytes")
        return result

    # -- the os functions -----------------------------------------------------------------

    def open(self, path: str | os.PathLike[str], flags: int, mode: int = 0o777, **kw: Any) -> int:
        name = os.fspath(path)
        fd = int(self._call("open", name, None, lambda: self.real.open(name, flags, mode, **kw)))
        self._paths[fd] = name
        return fd

    def read(self, fd: int, size: int) -> bytes:
        return bytes(
            self._call(
                "read",
                self._path_of_fd(fd),
                size,
                lambda: self.real.read(fd, size),
                lambda keep: self.real.read(fd, min(keep, size)),
            )
        )

    def write(self, fd: int, data: bytes | bytearray | memoryview) -> int:
        view = memoryview(data)
        return int(
            self._call(
                "write",
                self._path_of_fd(fd),
                len(view),
                lambda: self.real.write(fd, view),
                lambda keep: self.real.write(fd, view[: min(keep, len(view))]) if keep else 0,
            )
        )

    def fsync(self, fd: int) -> None:
        self._call("fsync", self._path_of_fd(fd), None, lambda: self.real.fsync(fd))

    def fdatasync(self, fd: int) -> None:
        self._call("fdatasync", self._path_of_fd(fd), None, lambda: self.real.fdatasync(fd))

    def rename(self, src: str | os.PathLike[str], dst: str | os.PathLike[str], **kw: Any) -> None:
        self._call(
            "rename",
            os.fspath(dst),
            None,
            lambda: self.real.rename(src, dst, **kw),
            source=os.fspath(src),
        )

    def replace(self, src: str | os.PathLike[str], dst: str | os.PathLike[str], **kw: Any) -> None:
        self._call(
            "replace",
            os.fspath(dst),
            None,
            lambda: self.real.replace(src, dst, **kw),
            source=os.fspath(src),
        )

    def close(self, fd: int) -> None:
        path = self._path_of_fd(fd)
        try:
            self._call("close", path, None, lambda: self.real.close(fd))
        finally:
            self._paths.pop(fd, None)

    def __getattr__(self, name: str) -> Any:
        """Everything else (``stat``, ``O_*`` constants, ``fspath``...) is the real module's."""
        return getattr(self.real, name)

    def outcomes(self, op: str | None = None) -> list[str]:
        return [c.outcome for c in self.calls if op is None or c.op == op]


@contextmanager
def patched(faults: Sequence[Fault], module: Any = os) -> Iterator[FaultyOS]:
    """Install a FaultyOS over `module`'s functions; restore them afterwards."""
    originals = {name: getattr(module, name) for name in OPERATIONS}

    class _Real:
        def __getattr__(self, name: str) -> Any:
            return originals[name] if name in originals else getattr(module, name)

    adapter = FaultyOS(faults, real=_Real())
    try:
        for name in OPERATIONS:
            setattr(module, name, getattr(adapter, name))
        yield adapter
    finally:
        for name, function in originals.items():
            setattr(module, name, function)
