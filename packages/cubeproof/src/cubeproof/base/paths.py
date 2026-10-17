"""Relative paths inside a root, checked for containment before access (specification §4.1).

Campaign bundle paths are relative to the campaign file, artifact paths relative to their
evidence/results root. A RelPath is a nonempty relative POSIX path without empty, ``.`` or
``..`` components, leading ``/``, drive prefix, backslash or NUL. Containment is checked
component by component without following symlinks (requirement ``path.containment``): every
intermediate component must be a real directory and the last one a regular file. The final
open uses ``O_NOFOLLOW`` and checks the opened descriptor, so the file read is the file
checked. (The threat model of specification §5 excludes hostile same-UID writers racing these
checks.)
"""

from __future__ import annotations

import errno
import os
import re
import stat
from pathlib import Path
from typing import BinaryIO

from cubeproof.base.errors import ContractError

_DRIVE = re.compile(r"[A-Za-z]:")


def relpath_problem(text: object) -> str | None:
    """Why ``text`` is not a RelPath, or None."""
    if not isinstance(text, str) or not text:
        return "not a nonempty string"
    if "\0" in text or "\\" in text:
        return "NUL or backslash"
    if _DRIVE.match(text):
        return "drive prefix"
    if any(part in ("", ".", "..") for part in text.split("/")):
        return "empty, '.' or '..' component (or a leading or trailing '/')"
    return None


def split_relpath(text: str) -> tuple[str, ...]:
    """The components of a RelPath; :class:`ContractError` ``path.containment`` otherwise."""
    problem = relpath_problem(text)
    if problem is not None:
        raise ContractError("path.containment", f"{text!r}: {problem}")
    return tuple(text.split("/"))


def contained_file(root: Path, relative: str) -> Path:
    """The regular file ``root/relative``, reached without any symlink component.

    Raises :class:`ContractError` ``path.containment`` for a symlink, a non-directory
    intermediate component or a non-regular final file, and :class:`FileNotFoundError` when
    a component does not exist.
    """
    parts = split_relpath(relative)
    path = Path(root)
    for index, part in enumerate(parts):
        path = path / part
        mode = os.lstat(path).st_mode
        last = index == len(parts) - 1
        if stat.S_ISLNK(mode):
            raise ContractError("path.containment", f"{path}: symlink component")
        if last and not stat.S_ISREG(mode):
            raise ContractError("path.containment", f"{path}: not a regular file")
        if not last and not stat.S_ISDIR(mode):
            raise ContractError("path.containment", f"{path}: not a directory")
    return path


_READ_CHUNK = 1 << 20


def read_at_most(stream: BinaryIO, count: int) -> bytes:
    """At most ``count`` bytes from ``stream``, read in chunks (never one huge allocation).

    A document reader passes its byte limit plus a margin, so an oversized file is detected
    by its length without reading the whole file into memory.
    """
    if type(count) is not int or count < 0:
        raise ValueError("count must be a nonnegative integer")
    chunks: list[bytes] = []
    remaining = count
    while remaining > 0:
        chunk = stream.read(min(remaining, _READ_CHUNK))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def open_regular_file(path: Path) -> BinaryIO:
    """Open ``path`` for reading if it is a regular file; OSError otherwise.

    The open does not block (a FIFO without a writer would), and a file that is not regular (a
    FIFO, a device, a directory) is an OSError ``EINVAL`` "not a regular file": a reader that
    reads a whole file needs it to end."""
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise OSError(errno.EINVAL, "not a regular file")
        if hasattr(os, "set_blocking"):
            os.set_blocking(descriptor, True)
        return os.fdopen(descriptor, "rb")
    except BaseException:
        os.close(descriptor)
        raise


def open_contained(root: Path, relative: str) -> BinaryIO:
    """Open ``root/relative`` for reading after :func:`contained_file`, without following links."""
    path = contained_file(root, relative)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        if isinstance(exc, FileNotFoundError):
            raise
        raise ContractError("path.containment", f"{path}: {exc.strerror}") from None
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise ContractError("path.containment", f"{path}: not a regular file")
        if hasattr(os, "set_blocking"):
            os.set_blocking(descriptor, True)
        return os.fdopen(descriptor, "rb")
    except BaseException:
        os.close(descriptor)
        raise
