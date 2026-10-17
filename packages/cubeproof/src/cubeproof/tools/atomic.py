"""Atomic and durable file helpers of the I/O service (specification §7.1, §7.2, §7.4; Linux,
specification §14).

- :class:`FileCalls`: every file system call of publication and reconciliation, so that
  tests can inject short writes, EINTR, ENOSPC, failing fsync and simulated process death.
- :func:`write_all`: complete short writes, retry EINTR, refuse a write without progress.
- :func:`fsync_directory`: make a directory entry durable. A failed fsync is a
  :class:`DurabilityError`: after it the state of the page cache is unknown, so the caller
  (the service) stops all further work instead of retrying (specification §7.1, "do not continue
  past uncertain bytes").
- :func:`link_no_replace`: give a synced file its final name without ever replacing another
  file (``link`` fails with EEXIST). File systems without hard links fall back to a rename
  after checking that the name is free; that check-then-rename relies on the single owner of
  the results directory (run lock, specification §7.3).
- :func:`atomic_write`: a small document written to a fresh temporary name, synced,
  published without replacement and its directory synced; equal existing bytes are a no-op
  (replay publishes the same bytes), unequal ones are never overwritten.
- :func:`hash_steps`: chunked hashing as a generator that yields between chunks, so the
  service can run journal commits in between (specification §8.1).

No path is followed through a symlink where it matters: files are opened ``O_NOFOLLOW`` and
checked to be regular files on the descriptor.
"""

from __future__ import annotations

import contextlib
import errno
import hashlib
import os
import stat
from collections.abc import Generator
from typing import TypeVar

from cubeproof.base.errors import (
    ContractError,
    CubeproofError,
    IntegrityError,
    ResourceError,
    ToolError,
)
from cubeproof.base.ids import new_id128

_T = TypeVar("_T")

_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
_NONBLOCK = getattr(os, "O_NONBLOCK", 0)

#: errno values meaning "out of space": a resource condition, not a tool failure.
NO_SPACE = frozenset({errno.ENOSPC, errno.EDQUOT})
#: errno values of ``link`` on file systems without hard links (fall back to rename).
NO_HARD_LINKS = frozenset({errno.EPERM, errno.EOPNOTSUPP, errno.ENOSYS, errno.EMLINK})


class DurabilityError(ToolError):
    """An fsync failed: whether the bytes or the entry are durable is unknown (rule io.fsync).

    The I/O service treats it as fatal: it reports it and stops (specification §7.1, §8.1).
    """


class FileCalls:
    """The file system calls of the I/O service; replaced in tests to inject faults."""

    def open(self, path: str, flags: int, mode: int = 0o600) -> int:
        return os.open(path, flags | _CLOEXEC, mode)

    def close(self, fd: int) -> None:
        os.close(fd)

    def pread(self, fd: int, count: int, offset: int) -> bytes:
        return os.pread(fd, count, offset)

    def write(self, fd: int, data: memoryview) -> int:
        return os.write(fd, data)

    def fsync(self, fd: int) -> None:
        os.fsync(fd)

    def fstat(self, fd: int) -> os.stat_result:
        return os.fstat(fd)

    def lstat(self, path: str) -> os.stat_result:
        return os.lstat(path)

    def link(self, source: str, target: str) -> None:
        os.link(source, target, follow_symlinks=False)

    def rename(self, source: str, target: str) -> None:
        os.rename(source, target)

    def unlink(self, path: str) -> None:
        os.unlink(path)

    def mkdir(self, path: str, mode: int = 0o755) -> None:
        os.mkdir(path, mode)

    def listdir(self, path: str) -> list[str]:
        return os.listdir(path)

    def free_bytes(self, path: str) -> int:
        """Bytes available to this user on the file system of ``path``."""
        info = os.statvfs(path)
        return info.f_bavail * info.f_frsize


OS_FILE_CALLS = FileCalls()


def os_failure(rule: str, error: OSError, what: str) -> CubeproofError:
    """The typed error of a failed call: ENOSPC/EDQUOT is ``io.no_space`` (resource)."""
    if error.errno in NO_SPACE:
        return ResourceError("io.no_space", f"{what}: {error}")
    return ToolError(rule, f"{what}: {error}")


def drive(steps: Generator[None, None, _T]) -> _T:
    """Run a step generator to its end and return its value."""
    while True:
        try:
            next(steps)
        except StopIteration as stop:
            value: _T = stop.value
            return value


def write_all(calls: FileCalls, fd: int, data: bytes | memoryview) -> None:
    """Write every byte of ``data``: complete short writes, retry EINTR, refuse no progress."""
    view = memoryview(data)
    while view.nbytes:
        try:
            count = calls.write(fd, view)
        except InterruptedError:
            continue
        if type(count) is not int or count <= 0:
            raise OSError(errno.EIO, f"write accepted {count!r} bytes")
        if count > view.nbytes:
            raise OSError(errno.EIO, f"write reported {count} of {view.nbytes} bytes")
        view = view[count:]


def fsync(calls: FileCalls, fd: int, what: str) -> None:
    """fsync, a failure being a :class:`DurabilityError` (``io.fsync``)."""
    try:
        calls.fsync(fd)
    except OSError as error:
        raise DurabilityError("io.fsync", f"{what}: {error}") from error


def fsync_directory(calls: FileCalls, path: str) -> None:
    """Make the entries of directory ``path`` durable (DurabilityError on failure)."""
    try:
        fd = calls.open(path, os.O_RDONLY | _DIRECTORY)
    except OSError as error:
        raise DurabilityError("io.fsync", f"{path}: {error}") from error
    try:
        fsync(calls, fd, path)
    finally:
        calls.close(fd)


def ensure_directory(calls: FileCalls, path: str) -> bool:
    """A real directory at ``path`` (created, and its parent synced, if missing).

    A symlink or a non-directory there is ContractError ``io.layout``: the layout of a
    results directory is not followed through links. Returns whether it was created.
    """
    try:
        mode = calls.lstat(path).st_mode
    except FileNotFoundError:
        mode = None
    if mode is not None:
        if not stat.S_ISDIR(mode):
            raise ContractError("io.layout", f"{path} is not a directory (or is a symlink)")
        return False
    try:
        calls.mkdir(path, 0o755)
    except FileExistsError:
        return ensure_directory(calls, path)
    fsync_directory(calls, os.path.dirname(path))
    return True


def open_regular(calls: FileCalls, path: str) -> tuple[int, int]:
    """Open the regular file ``path`` for reading without following a symlink: (fd, size).

    A symlink, FIFO, device or directory is ContractError ``io.not_regular``; a missing
    file raises FileNotFoundError.
    """
    try:
        fd = calls.open(path, os.O_RDONLY | _NOFOLLOW | _NONBLOCK)
    except OSError as error:
        if error.errno in (errno.ELOOP, errno.ENXIO, errno.EISDIR):
            raise ContractError("io.not_regular", f"{path}: {error.strerror}") from None
        raise
    try:
        info = calls.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise ContractError("io.not_regular", f"{path} is not a regular file")
        os.set_blocking(fd, True)
        return fd, info.st_size
    except BaseException:
        calls.close(fd)
        raise


def read_chunk(calls: FileCalls, fd: int, count: int, offset: int) -> bytes:
    """Up to ``count`` bytes at ``offset`` (fewer only at end of file), EINTR retried."""
    parts: list[bytes] = []
    got = 0
    while got < count:
        try:
            data = calls.pread(fd, count - got, offset + got)
        except InterruptedError:
            continue
        if not data:
            break
        parts.append(data)
        got += len(data)
    return b"".join(parts)


def hash_steps(
    calls: FileCalls, fd: int, *, chunk_bytes: int
) -> Generator[None, None, tuple[int, str]]:
    """Size and SHA-256 of everything readable from ``fd``; one chunk per step."""
    digest = hashlib.sha256()
    offset = 0
    while True:
        data = read_chunk(calls, fd, chunk_bytes, offset)
        if not data:
            return offset, digest.hexdigest()
        digest.update(data)
        offset += len(data)
        yield


def same_bytes(calls: FileCalls, path: str, data: bytes) -> bool:
    """Whether the regular file ``path`` holds exactly ``data`` (small documents)."""
    fd, size = open_regular(calls, path)
    try:
        return size == len(data) and read_chunk(calls, fd, size + 1, 0) == data
    finally:
        calls.close(fd)


def link_no_replace(calls: FileCalls, source: str, target: str) -> bool:
    """Give ``source`` the additional name ``target`` unless ``target`` exists.

    True when ``target`` was created (the caller removes ``source`` afterwards; on the rename
    fallback it is already gone), False when ``target`` already existed (nothing changed).
    """
    try:
        calls.link(source, target)
    except FileExistsError:
        return False
    except OSError as error:
        if error.errno not in NO_HARD_LINKS:
            raise
        try:
            calls.lstat(target)
        except FileNotFoundError:
            calls.rename(source, target)
            return True
        return False
    return True


def remove_quietly(calls: FileCalls, path: str) -> None:
    """Best-effort removal of a staging file on an error path (the original error wins)."""
    with contextlib.suppress(OSError):
        calls.unlink(path)


def atomic_write(path: str, data: bytes, *, calls: FileCalls = OS_FILE_CALLS) -> bool:
    """Publish the small document ``data`` at ``path`` atomically and durably.

    Returns True when written, False when ``path`` already holds exactly ``data`` (replay
    publishes the same bytes). Other bytes at ``path`` are IntegrityError
    ``artifact.conflict`` and are never overwritten. The temporary file is in the same
    directory (the same file system) and is removed on every error that is not a crash.
    """
    directory, name = os.path.split(path)
    try:
        calls.lstat(path)
        exists = True
    except FileNotFoundError:
        exists = False
    if exists:
        if same_bytes(calls, path, data):
            fsync_directory(calls, directory)
            return False
        raise IntegrityError("artifact.conflict", f"{path} holds other bytes")
    temporary = os.path.join(directory, f".{name}.{new_id128()}.tmp")
    try:
        fd = calls.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW, 0o444)
    except OSError as error:
        raise os_failure("io.write", error, temporary) from error
    try:
        try:
            write_all(calls, fd, data)
        except OSError as error:
            raise os_failure("io.write", error, temporary) from error
        fsync(calls, fd, temporary)
    except BaseException as error:
        calls.close(fd)
        if not _is_crash(error):
            remove_quietly(calls, temporary)
        raise
    calls.close(fd)
    try:
        try:
            created = link_no_replace(calls, temporary, path)
        except OSError as error:
            raise os_failure("io.write", error, path) from error
        if not created:
            if same_bytes(calls, path, data):
                fsync_directory(calls, directory)
                remove_quietly(calls, temporary)
                return False
            raise IntegrityError("artifact.conflict", f"{path} holds other bytes")
        fsync_directory(calls, directory)
    except BaseException as error:
        if not _is_crash(error):
            remove_quietly(calls, temporary)
        raise
    remove_quietly(calls, temporary)
    return True


def _is_crash(error: BaseException) -> bool:
    """Errors that end the process (no cleanup is attempted for them)."""
    return not isinstance(error, Exception)
