"""Durable artifact publication and reconciliation (specification §7.2, §7.3, §7.5; decision 0011).

Publication of a checked proof (retain or quarantine), :func:`publish_steps`:

1. The checked source file is only read; it is kept until the caller deletes it after the
   commit. Its size must be the declared ``proof_bytes``; the copy never writes more than
   that many bytes to the target (the reserved destination bytes).
2. Copy it to a fresh ``<area>/tmp/<attempt_id>.lrat`` on the **target** file system,
   hashing while copying, in chunks of at most ``chunk_bytes``; fsync it; require exactly
   the declared size and SHA-256. A copy is used on every file system (also the same one),
   so a cross-device source is no special case.
3. Give it the name ``<area>/<node_id>-<proof_sha256>.lrat`` without replacing anything
   (:func:`~cubeproof.tools.atomic.link_no_replace`), fsync the area directory, then remove
   the staging name. If the final name exists, its size and hash must be equal and it is
   reused (its directory is synced again: an earlier run may have died before doing so);
   unequal bytes are IntegrityError ``artifact.conflict`` and are never overwritten.

Only after the publication result may the caller commit the record that references it
(specification §7.2 step 4); the I/O service enforces that order.

Reconciliation on restart, :func:`reconcile_steps`: **first** every committed reference is
validated (a regular file reached without symlinks, with its size and SHA-256); a missing
or corrupt one is IntegrityError ``artifact.missing``/``artifact.corrupt`` and nothing is
removed. Then unreferenced files in the areas and every staging file are orphans and are
removed. A referenced (or explicitly protected, i.e. published but not yet committed in
this session) path is never removed. The procedure is idempotent. Its precondition is the
run lock of the results directory: no older process can still be using these files.

Every function is a generator yielding between chunks (one step reads at most
``chunk_bytes``), so that the I/O service can run journal commits between steps.
"""

from __future__ import annotations

import errno
import hashlib
import os
import stat
from collections.abc import Collection, Generator, Iterable

from cubeproof.base.errors import ContractError, IntegrityError, ToolError
from cubeproof.contracts.io import (
    MAX_CHUNK_BYTES,
    STAGING,
    Area,
    PublishRequest,
    PublishValue,
    ReconcileValue,
    artifact_area,
    staging_path,
)
from cubeproof.contracts.values import Artifact
from cubeproof.tools.atomic import (
    OS_FILE_CALLS,
    FileCalls,
    drive,
    ensure_directory,
    fsync,
    fsync_directory,
    hash_steps,
    link_no_replace,
    open_regular,
    os_failure,
    read_chunk,
    remove_quietly,
    write_all,
)

_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)

#: Outcomes of :func:`verify_steps`.
MISSING = "missing"
CORRUPT = "corrupt"


def _join(root: str, relative: str) -> str:
    return os.path.join(root, *relative.split("/"))


def _check_chunk(chunk_bytes: int) -> None:
    if type(chunk_bytes) is not int or not 1 <= chunk_bytes <= MAX_CHUNK_BYTES:
        raise ValueError(f"chunk_bytes must be 1..{MAX_CHUNK_BYTES}")


def area_directory(calls: FileCalls, root: str, area: Area, *, create: bool) -> str | None:
    """The real directory ``root/<area>``: created if asked, None if absent; symlinks refused."""
    path = _join(root, area.value)
    if create:
        ensure_directory(calls, path)
        ensure_directory(calls, os.path.join(path, STAGING))
        return path
    try:
        mode = calls.lstat(path).st_mode
    except FileNotFoundError:
        return None
    if not stat.S_ISDIR(mode):
        raise ContractError("io.layout", f"{path} is not a directory (or is a symlink)")
    return path


# -- verification -----------------------------------------------------------------------------


def verify_steps(  # noqa: PLR0911 - one outcome per check, in order
    root: str, artifact: Artifact, *, calls: FileCalls = OS_FILE_CALLS, chunk_bytes: int
) -> Generator[None, None, str | None]:
    """None when ``root/artifact.path`` is a regular file with its size and hash.

    Otherwise :data:`MISSING` (absent) or :data:`CORRUPT` (other bytes or size, a symlink, a
    directory, a symlink component on the way). One chunk per step.
    """
    path = root
    parts = artifact.path.split("/")
    for index, part in enumerate(parts):
        path = os.path.join(path, part)
        try:
            mode = calls.lstat(path).st_mode
        except FileNotFoundError:
            return MISSING
        last = index == len(parts) - 1
        if (last and not stat.S_ISREG(mode)) or (not last and not stat.S_ISDIR(mode)):
            return CORRUPT
    try:
        fd, size = open_regular(calls, path)
    except FileNotFoundError:
        return MISSING
    except ContractError:
        return CORRUPT
    try:
        if size != artifact.bytes:
            return CORRUPT
        measured = yield from hash_steps(calls, fd, chunk_bytes=chunk_bytes)
    finally:
        calls.close(fd)
    if measured != (artifact.bytes, artifact.sha256):
        return CORRUPT
    return None


# -- publication ------------------------------------------------------------------------------


def publish_steps(
    root: str,
    attempt_id: str,
    request: PublishRequest,
    *,
    calls: FileCalls = OS_FILE_CALLS,
    chunk_bytes: int = MAX_CHUNK_BYTES,
) -> Generator[None, None, PublishValue]:
    """Publish ``request.source`` as ``request.artifact`` below ``root`` (see module doc).

    Errors: ToolError ``io.source`` (source unreadable or missing), ContractError
    ``io.not_regular`` (source not a regular file), ToolError ``io.source_changed`` (size
    other than declared, or the file grew), ToolError ``io.hash_mismatch`` (other bytes),
    IntegrityError ``artifact.conflict`` (other bytes under the final name), ResourceError
    ``io.no_space``, ToolError ``io.staging_exists``, ContractError ``io.layout``,
    DurabilityError ``io.fsync``, ToolError ``io.write``. On every error except a crash, the
    staging file is removed and the source is unchanged.
    """
    _check_chunk(chunk_bytes)
    artifact = request.artifact
    area = area_directory(calls, root, request.area, create=True)
    assert area is not None
    final = _join(root, artifact.path)
    reused = yield from _existing(calls, final, artifact, chunk_bytes)
    if reused:
        fsync_directory(calls, area)
        return PublishValue(artifact, reused=True)
    try:
        source, size = open_regular(calls, request.source)
    except FileNotFoundError as error:
        raise ToolError("io.source", f"{request.source}: {error.strerror}") from None
    except OSError as error:
        raise ToolError("io.source", f"{request.source}: {error}") from error
    try:
        if size != artifact.bytes:
            raise ToolError(
                "io.source_changed", f"{request.source}: {size} bytes, checked {artifact.bytes}"
            )
        try:
            free = calls.free_bytes(area)
        except OSError as error:
            raise os_failure("io.write", error, area) from error
        if free < artifact.bytes:
            raise os_failure(
                "io.write", OSError(errno.ENOSPC, "not enough free space"), f"{area}: {free}"
            )
        staging = _join(root, staging_path(request.area, attempt_id))
        try:
            target = calls.open(staging, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW, 0o444)
        except FileExistsError:
            raise ToolError("io.staging_exists", f"{staging} already exists") from None
        except OSError as error:
            raise os_failure("io.write", error, staging) from error
        try:
            yield from _copy(calls, source, target, staging, request, chunk_bytes)
        except BaseException as error:
            calls.close(target)
            if isinstance(error, Exception):
                remove_quietly(calls, staging)
            raise
        calls.close(target)
    finally:
        calls.close(source)
    try:
        yield from _name(calls, staging, final, area, artifact, chunk_bytes)
    except BaseException as error:
        if isinstance(error, Exception):
            remove_quietly(calls, staging)
        raise
    return PublishValue(artifact, reused=False)


def _existing(
    calls: FileCalls, final: str, artifact: Artifact, chunk_bytes: int
) -> Generator[None, None, bool]:
    """True when ``final`` already holds the artifact; IntegrityError for other content."""
    try:
        calls.lstat(final)
    except FileNotFoundError:
        return False
    problem = yield from verify_steps(
        os.path.dirname(os.path.dirname(final)),
        artifact,
        calls=calls,
        chunk_bytes=chunk_bytes,
    )
    if problem == MISSING:  # removed meanwhile: publish normally
        return False
    if problem is not None:
        raise IntegrityError("artifact.conflict", f"{final} holds other bytes; not overwritten")
    return True


def _copy(
    calls: FileCalls,
    source: int,
    target: int,
    staging: str,
    request: PublishRequest,
    chunk_bytes: int,
) -> Generator[None, None, None]:
    """Copy exactly ``proof_bytes`` bytes, hashing them, then fsync and check."""
    expected = request.proof_bytes
    digest = hashlib.sha256()
    offset = 0
    while offset < expected:
        try:
            data = read_chunk(calls, source, min(chunk_bytes, expected - offset), offset)
        except OSError as error:
            raise ToolError("io.source", f"{request.source}: {error}") from error
        if not data:
            raise ToolError("io.source_changed", f"{request.source} shrank to {offset} bytes")
        digest.update(data)
        try:
            write_all(calls, target, data)
        except OSError as error:
            raise os_failure("io.write", error, staging) from error
        offset += len(data)
        yield
    try:
        extra = read_chunk(calls, source, 1, offset)
    except OSError as error:
        raise ToolError("io.source", f"{request.source}: {error}") from error
    if extra:
        raise ToolError("io.source_changed", f"{request.source} grew beyond {expected} bytes")
    if digest.hexdigest() != request.proof_sha256:
        raise ToolError("io.hash_mismatch", f"{request.source} is not the checked proof")
    fsync(calls, target, staging)
    if calls.fstat(target).st_size != expected:
        raise ToolError("io.write", f"{staging} does not hold {expected} bytes after fsync")


def _name(
    calls: FileCalls,
    staging: str,
    final: str,
    area: str,
    artifact: Artifact,
    chunk_bytes: int,
) -> Generator[None, None, None]:
    """Give the synced staging file its final name (never replacing), sync, drop staging."""
    try:
        created = link_no_replace(calls, staging, final)
    except OSError as error:
        raise os_failure("io.write", error, final) from error
    if not created:
        reused = yield from _existing(calls, final, artifact, chunk_bytes)
        if not reused:
            raise IntegrityError("artifact.conflict", f"{final} appeared and is not equal")
    fsync_directory(calls, area)
    remove_quietly(calls, staging)


def publish(
    root: str,
    attempt_id: str,
    request: PublishRequest,
    *,
    calls: FileCalls = OS_FILE_CALLS,
    chunk_bytes: int = MAX_CHUNK_BYTES,
) -> PublishValue:
    """:func:`publish_steps` run to its end."""
    return drive(publish_steps(root, attempt_id, request, calls=calls, chunk_bytes=chunk_bytes))


# -- reconciliation ---------------------------------------------------------------------------


def reconcile_steps(
    root: str,
    committed: Iterable[Artifact],
    *,
    protected: Collection[str] = (),
    calls: FileCalls = OS_FILE_CALLS,
    chunk_bytes: int = MAX_CHUNK_BYTES,
) -> Generator[None, None, ReconcileValue]:
    """Validate every committed reference, then remove orphans (see module doc)."""
    _check_chunk(chunk_bytes)
    references = sorted(set(committed), key=lambda a: a.path)
    paths = [a.path for a in references]
    if len(set(paths)) != len(paths):
        raise ContractError("schema", "two committed artifacts with one path")
    for path in paths:
        if artifact_area(path) is None:
            raise ContractError("schema", f"committed artifact {path!r} is not in an area")
    keep = frozenset(paths) | frozenset(protected)
    # 1. Committed references first; nothing is removed unless every one is intact.
    problems: dict[str, list[str]] = {MISSING: [], CORRUPT: []}
    for artifact in references:
        problem = yield from verify_steps(root, artifact, calls=calls, chunk_bytes=chunk_bytes)
        if problem is not None:
            problems[problem].append(artifact.path)
    for kind in (MISSING, CORRUPT):
        if problems[kind]:
            listed = ", ".join(problems[kind][:10])
            more = len(problems[kind]) - 10
            suffix = f" and {more} more" if more > 0 else ""
            raise IntegrityError(f"artifact.{kind}", f"committed artifact {listed}{suffix}")
    # 2. Orphans: unreferenced published files and every staging file.
    removed: list[str] = []
    for area in Area:
        directory = area_directory(calls, root, area, create=False)
        if directory is None:
            continue
        for name in sorted(calls.listdir(directory)):
            relative = f"{area.value}/{name}"
            path = os.path.join(directory, name)
            mode = calls.lstat(path).st_mode
            if name == STAGING and stat.S_ISDIR(mode):
                for staged in sorted(calls.listdir(path)):
                    staged_path = os.path.join(path, staged)
                    if not stat.S_ISDIR(calls.lstat(staged_path).st_mode):
                        _remove_orphan(calls, staged_path, f"{relative}/{staged}", keep)
                        removed.append(f"{relative}/{staged}")
                        yield  # one removal per step: commits are not held up
                continue
            if relative in keep or stat.S_ISDIR(mode):
                continue
            _remove_orphan(calls, path, relative, keep)
            removed.append(relative)
            yield
        yield
    return ReconcileValue(len(references), tuple(removed))


def _remove_orphan(calls: FileCalls, path: str, relative: str, keep: frozenset[str]) -> None:
    # The last guard before an irreversible deletion: never a referenced path (specification §7.2).
    if relative in keep:
        raise AssertionError(f"refusing to remove the referenced artifact {relative}")
    try:
        calls.unlink(path)
    except FileNotFoundError:
        pass
    except OSError as error:
        raise os_failure("io.remove", error, path) from error


def reconcile(
    root: str,
    committed: Iterable[Artifact],
    *,
    protected: Collection[str] = (),
    calls: FileCalls = OS_FILE_CALLS,
    chunk_bytes: int = MAX_CHUNK_BYTES,
) -> ReconcileValue:
    """:func:`reconcile_steps` run to its end."""
    return drive(
        reconcile_steps(root, committed, protected=protected, calls=calls, chunk_bytes=chunk_bytes)
    )
