"""Work files of one attempt (specification §6.1 stages 1-3): CNF(F, C), unit proofs and sealing.

- :func:`write_cnf_steps` creates ``work/<node_id>-<attempt_id>.cnf`` exclusively (never
  through an existing name or a symlink), writes exactly CNF(F, C) (specification §3.2: header
  ``p cnf V (M+d)``, the formula body, one unit line per cube literal) in bounded chunks with
  a yield between chunks, hashes exactly the bytes the file accepted and makes it read-only.
  The caller compares that hash with the independent digest of the verified bundle.
- :func:`write_new_file` writes a small file (a unit-v1 proof) the same way.
- :func:`seal` makes a completed proof read-only and measures its size, refusing anything
  but a regular file reached without following a symlink (specification §6.1 step 3). The hash comes
  from the I/O service. Read-only modes are not protection against a hostile writer (specification
  §5); the re-hash after the check is.
"""

from __future__ import annotations

import errno
import os
import stat
from collections.abc import Generator, Sequence

from cubeproof.base.hashing import HashingWriter
from cubeproof.cnf.cube import cube_units
from cubeproof.cnf.cubecnf import cube_cnf_header
from cubeproof.cnf.dimacs import Formula
from cubeproof.contracts.identity import check_cube
from cubeproof.leaf.binding import attempt_paths

__all__ = [
    "DEFAULT_CHUNK",
    "READ_ONLY",
    "absent",
    "regular_file",
    "seal",
    "work_paths",
    "write_cnf_steps",
    "write_new_file",
]

DEFAULT_CHUNK = 1 << 20
READ_ONLY = 0o444
_CREATE = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
_OPEN_SEALED = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC


def work_paths(work_dir: str, node_id: str, attempt_id: str) -> tuple[str, str]:
    """The CNF and proof paths of one attempt (``leaf.binding.attempt_paths``)."""
    return attempt_paths(work_dir, node_id, attempt_id)


class _Descriptor:
    """A raw writable descriptor for :class:`HashingWriter` (short writes are completed)."""

    def __init__(self, fd: int) -> None:
        self.fd = fd

    def write(self, data: memoryview, /) -> int:
        return os.write(self.fd, data)


def write_cnf_steps(
    formula: Formula, cube: Sequence[int], path: str, *, chunk: int = DEFAULT_CHUNK
) -> Generator[None, None, tuple[int, str]]:
    """Create ``path`` and write CNF(F, C); value ``(bytes, sha256)`` of what was written.

    The first step only creates the file (so a caller knows it owns it); every later step
    writes at most ``chunk`` bytes of the body. OSError on any failure.
    """
    if type(chunk) is not int or chunk < 1:
        raise ValueError("chunk must be a positive integer")
    literals = check_cube(cube, formula.variables)
    fd = os.open(path, _CREATE, 0o600)
    try:
        yield
        writer = HashingWriter(_Descriptor(fd))
        writer.write(cube_cnf_header(formula.variables, formula.clauses, len(literals)))
        body = memoryview(formula.data)[formula.header_length :]
        for start in range(0, len(body), chunk):
            yield
            writer.write(body[start : start + chunk])
        writer.write(cube_units(literals))
        os.fchmod(fd, READ_ONLY)
    finally:
        os.close(fd)
    return writer.bytes_written, writer.hexdigest()


def write_new_file(path: str, data: bytes) -> tuple[int, str]:
    """Create ``path`` exclusively and write ``data``; ``(bytes, sha256)`` of what was written."""
    fd = os.open(path, _CREATE, 0o600)
    try:
        writer = HashingWriter(_Descriptor(fd))
        writer.write(data)
    finally:
        os.close(fd)
    return writer.bytes_written, writer.hexdigest()


def seal(path: str) -> int:
    """Make the regular file ``path`` read-only and return its size (specification §6.1 step 3)."""
    fd = os.open(path, _OPEN_SEALED)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError(errno.EINVAL, "not a regular file", path)
        os.fchmod(fd, READ_ONLY)
        return os.fstat(fd).st_size
    finally:
        os.close(fd)


def absent(path: str) -> bool:
    """True only if nothing at all (not even a dangling symlink) has this name."""
    try:
        os.lstat(path)
    except FileNotFoundError:
        return True
    except OSError:
        return False
    return False


def regular_file(path: str) -> bool:
    """True if ``path`` itself (not a symlink target) is a regular file."""
    try:
        return stat.S_ISREG(os.lstat(path).st_mode)
    except OSError:
        return False
