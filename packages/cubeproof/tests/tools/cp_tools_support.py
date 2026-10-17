"""Test-only helpers of the tool tests: the fake tools, fixtures, small builders.

The fake tools (``tests/fakes``) are real executables driven by a script; they log their
argv, process group, session, resource limits, parent-death signal and open descriptors, so
the tests observe what the supervisor really did to the child. Nothing here is imported by
runtime code.

The fixtures ``isolation`` and ``supervisor`` are defined here (not in a conftest: the
package test directories have no ``__init__.py`` and ``mypy`` would see two top-level
``conftest`` modules); a test module imports ``isolation_fixture``/``supervisor_fixture``.
"""

from __future__ import annotations

import os
import sys
import time
from collections.abc import Callable, Iterator, Sequence
from pathlib import Path
from typing import Any

import pytest

from cubeproof.base.process import Cause, ProcessResult
from cubeproof.tools.isolation import Isolation, PinnedBinary
from cubeproof.tools.process import Launch, ProcessRun, Supervisor

REPO = Path(__file__).resolve().parents[4]
SHARED_TESTS = REPO / "tests"
if str(SHARED_TESTS) not in sys.path:
    sys.path.insert(0, str(SHARED_TESTS))

from fakes import fixture_files  # noqa: E402
from fakes import presets as p  # noqa: E402
from fakes import toolkit as fk  # noqa: E402

__all__ = [
    "FAKE_MEMORY",
    "REPO",
    "alive",
    "assert_fds_return_to",
    "finished",
    "fixture_files",
    "fk",
    "isolation_fixture",
    "launch",
    "linux_only",
    "make_binary",
    "open_fds",
    "p",
    "pid_of",
    "result",
    "run_one",
    "supervisor_fixture",
    "wait_until",
]

linux_only = pytest.mark.skipif(
    not sys.platform.startswith("linux"),
    reason="tool isolation is Linux-only (specification §6.2, §14)",
)

#: Generous caps for fakes: a Python interpreter needs a few hundred MiB of address space.
FAKE_MEMORY = 2 << 30


@pytest.fixture(scope="session", name="isolation")
def isolation_fixture() -> Isolation:
    """The util-linux wrappers of this host; missing wrappers fail, they never skip."""
    if not sys.platform.startswith("linux"):
        pytest.skip("tool isolation is Linux-only (specification §6.2)")
    return Isolation.probe()


@pytest.fixture(name="supervisor")
def supervisor_fixture(isolation: Isolation) -> Iterator[Supervisor]:
    sup = Supervisor(isolation)
    try:
        yield sup
    finally:
        # A failing test must not leave fakes running: stop, kill and reap everything.
        sup.shutdown(grace_ms=200)


def make_binary(
    directory: Path, name: str, steps: Sequence[dict[str, Any]] = (), **options: Any
) -> tuple[fk.FakeTool, PinnedBinary]:
    """A fake tool and its measured pin."""
    tool = fk.make_tool(directory, name, steps, **options)
    return tool, PinnedBinary.measure(str(tool.path))


def launch(binary: PinnedBinary, args: Sequence[str], cwd: Path, **options: Any) -> Launch:
    options.setdefault("memory_bytes", FAKE_MEMORY)
    return Launch(binary=binary, args=tuple(args), cwd=str(cwd), **options)


def run_one(supervisor: Supervisor, spec: Launch, *, limit_s: float = 60.0) -> ProcessRun:
    """Start one process and drive the supervisor until it is finished."""
    process = supervisor.start(spec)
    deadline = time.monotonic() + limit_s
    while process.run is None:
        assert time.monotonic() < deadline, "process did not finish in time"
        supervisor.step(50)
    return process.run


def wait_until(predicate: Callable[[], bool], limit_s: float = 30.0) -> None:
    deadline = time.monotonic() + limit_s
    while not predicate():
        assert time.monotonic() < deadline, "condition not reached in time"
        time.sleep(0.02)


def open_fds() -> dict[str, str]:
    """This process's open descriptors and what they refer to."""
    found = {}
    for name in os.listdir("/proc/self/fd"):
        try:
            found[name] = os.readlink(f"/proc/self/fd/{name}")
        except OSError:
            continue  # the descriptor of the listing itself
    return found


def assert_fds_return_to(before: dict[str, str], limit_s: float = 10.0) -> None:
    """Wait until no descriptor is open beyond ``before``; name the extra ones if not.

    Descriptors of ``before`` may have been closed meanwhile (e.g. the garbage collector
    releasing an unrelated object); only extra ones are leaks.
    """
    deadline = time.monotonic() + limit_s
    while True:
        extra = {k: v for k, v in open_fds().items() if before.get(k) != v}
        if not extra:
            return
        if time.monotonic() >= deadline:
            raise AssertionError(f"descriptors left open: {extra}")
        time.sleep(0.02)


def alive(pid: int) -> bool:
    """True while ``pid`` exists and is not a zombie."""
    try:
        with open(f"/proc/{pid}/stat", encoding="ascii") as handle:
            state = handle.read().rsplit(")", 1)[1].split()[0]
    except (FileNotFoundError, ProcessLookupError):  # gone, also between open and read
        return False
    return state not in {"Z", "X"}


def pid_of(path: Path) -> int:
    return int(path.read_text(encoding="ascii").strip())


def result(
    *,
    started: bool = True,
    exit: int | None = 0,
    signal: int | None = None,
    stdout: str = "",
    stderr: str = "",
    stdout_bytes: int | None = None,
    truncated: bool = False,
    cause: str | None = None,
    conflicts: int | None = None,
    elapsed_ms: int = 1,
) -> ProcessResult:
    """A ProcessResult with defaults of a clean exit 0."""
    return ProcessResult(
        started=started,
        exit=exit,
        signal=None if signal is None else int(signal),  # plain int, as in a record
        elapsed_ms=elapsed_ms,
        stdout_tail=stdout,
        stderr_tail=stderr,
        stdout_bytes=len(stdout.encode()) if stdout_bytes is None else stdout_bytes,
        stdout_truncated=truncated,
        cause=cause,
        conflicts=conflicts,
    )


def finished(
    process_result: ProcessResult,
    causes: Sequence[Cause] = (),
    stdout: bytes | None = None,
    *,
    stderr_truncated: bool = False,
) -> ProcessRun:
    """A synthetic finished run for the pure classification tests."""
    return ProcessRun(
        result=process_result,
        causes=tuple(causes),
        stdout=stdout,
        stderr_truncated=stderr_truncated,
    )
