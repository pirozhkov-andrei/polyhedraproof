"""Where a worker keeps its files, and what startup may remove (specification §2.3, §7.2, §7.3,
§7.5).

A worker owns two directories and nothing else:

``results/``  the durable part: ``run.lock`` (exclusive while a coordinator or its I/O service
              lives), ``journal.jsonl`` (the worker's journal), the derived state cache and
              the published artifact areas (``proofs/``, ``quarantine/``);
``work/``     disposable files of attempts and helpers (CNF files, unsealed proofs, request
              files). Nothing in it is evidence or referenced by a record.

The two must be disjoint (no nesting in either direction): the removal rules below delete
below ``work/`` and the service refuses to remove anything else. :func:`clear_work` removes
what a previous process left; :func:`survivors` finds processes that still use the work
directory (a tool dies with its coordinator from the fork on, ``tools.process``; what can
remain is a descendant that a tool started and that left its group, or a tool that has not
been killed yet): the startup waits for them or refuses, it never deletes files they use.
"""

from __future__ import annotations

import contextlib
import os
import stat
import time
from collections.abc import Collection
from dataclasses import dataclass
from pathlib import Path

from cubeproof.base.errors import ConfigurationError

__all__ = [
    "CACHE_NAME",
    "JOURNAL_NAME",
    "LOCK_NAME",
    "WORK_LOCK_NAME",
    "Layout",
    "ancestors",
    "clear_work",
    "survivors",
    "wait_for_survivors",
]

JOURNAL_NAME = "journal.jsonl"
LOCK_NAME = "run.lock"
CACHE_NAME = "state.cache"
#: The lock of the work directory (it lives in it, and clearing the directory keeps it): two
#: workers with different results directories may not share a work directory (specification §7.3).
WORK_LOCK_NAME = ".run.lock"


def _inside(path: Path, root: Path) -> bool:
    return path == root or root in path.parents


@dataclass(frozen=True)
class Layout:
    """The resolved results and work directories of one worker."""

    results: Path
    work: Path

    @classmethod
    def of(cls, results: str | os.PathLike[str], work: str | os.PathLike[str]) -> Layout:
        """Resolve both paths (symlinks followed once, here) and require them disjoint."""
        first, second = Path(results).resolve(), Path(work).resolve()
        if _inside(first, second) or _inside(second, first):
            raise ConfigurationError(
                "run.layout", f"results {first} and work {second} must be separate directories"
            )
        return cls(first, second)

    @property
    def journal(self) -> Path:
        return self.results / JOURNAL_NAME

    @property
    def lock(self) -> Path:
        return self.results / LOCK_NAME

    @property
    def cache(self) -> Path:
        return self.results / CACHE_NAME

    @property
    def work_lock(self) -> Path:
        return self.work / WORK_LOCK_NAME

    def prepare(self) -> None:
        """Create both directories (and parents) if needed."""
        for directory in (self.results, self.work):
            try:
                directory.mkdir(parents=True, exist_ok=True)
            except OSError as error:
                raise ConfigurationError(
                    "run.layout", f"{directory}: {error.strerror or error}"
                ) from None
            if not directory.is_dir():
                raise ConfigurationError("run.layout", f"{directory} is not a directory")


def clear_work(work: Path, keep: Collection[str] = ()) -> int:
    """Remove every file and directory below ``work`` (not ``work`` itself); return the count.
    The names in ``keep`` directly below ``work`` stay (the work lock).

    Links are unlinked, never followed; directories are walked bottom-up without crossing a
    link. Nothing outside ``work`` is touched. Call this only after the run lock is held and
    :func:`survivors` found nothing.
    """
    removed = 0
    for directory, subdirs, files in os.walk(work, topdown=False, followlinks=False):
        base = Path(directory)
        for name in files:
            if base == work and name in keep:
                continue
            os.unlink(base / name)
            removed += 1
        for name in subdirs:
            path = base / name
            mode = os.lstat(path).st_mode
            if stat.S_ISLNK(mode):
                os.unlink(path)
            else:
                os.rmdir(path)
            removed += 1
    return removed


def _links(pid: str, proc: str) -> list[str]:
    found: list[str] = []
    base = f"{proc}/{pid}"
    with contextlib.suppress(OSError):
        found.append(os.readlink(f"{base}/cwd"))
    try:
        descriptors = os.listdir(f"{base}/fd")
    except OSError:
        descriptors = []
    for descriptor in descriptors:
        try:
            found.append(os.readlink(f"{base}/fd/{descriptor}"))
        except OSError:
            continue
    return found


def ancestors(pid: int, *, proc: str = "/proc") -> list[int]:
    """The parent, grandparent ... of ``pid`` up to (excluding) process 0, from ``stat``."""
    found: list[int] = []
    current = pid
    while current > 1:
        try:
            with open(f"{proc}/{current}/stat", encoding="utf-8", errors="replace") as stream:
                text = stream.read()
        except OSError:
            break
        # "pid (comm) state ppid ...": comm may contain spaces and parentheses
        fields = text[text.rfind(")") + 2 :].split()
        if len(fields) < 2 or not fields[1].isdigit():
            break
        current = int(fields[1])
        if current in found or current < 1:
            break
        found.append(current)
    return found


def survivors(work: Path, *, proc: str = "/proc", own: int | None = None) -> list[int]:
    """Processes whose working directory or an open file is below ``work``, other than
    ``own`` and its ancestors (the shell that started this process may sit in the directory;
    an old run's orphans are children of init, never ancestors).

    Processes of other users that cannot be inspected are not listed; a process that exits
    while it is inspected is not listed either.
    """
    me = os.getpid() if own is None else own
    excluded = {me, *ancestors(me, proc=proc)}
    root = str(work)
    prefix = root.rstrip("/") + "/"
    found: list[int] = []
    try:
        entries = os.listdir(proc)
    except OSError:
        return []
    for entry in entries:
        if not entry.isdigit() or int(entry) in excluded:
            continue
        if any(link == root or link.startswith(prefix) for link in _links(entry, proc)):
            found.append(int(entry))
    return sorted(found)


def wait_for_survivors(
    work: Path, *, wait_ms: int, proc: str = "/proc", poll_ms: int = 20
) -> list[int]:
    """:func:`survivors`, repeated for at most ``wait_ms``; the ones still alive at the end."""
    deadline = time.monotonic() + wait_ms / 1000
    while True:
        alive = survivors(work, proc=proc)
        if not alive or time.monotonic() >= deadline:
            return alive
        time.sleep(poll_ms / 1000)
