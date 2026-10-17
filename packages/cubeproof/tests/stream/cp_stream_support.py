"""Test-only helpers of the stream tests: fake tools, relay harness and synthetic runs.

Nothing here is imported by runtime code.

- Fake tools are the fakes of ``tests/fakes``: real executables run by the process supervisor
  under the real isolation wrappers, so every coupled-run test exercises the real process
  layer and the real relay process (``cubeproof/tools/relay.py``) on real FIFOs.
- :class:`RelayHarness` runs the relay script alone between two FIFOs whose other ends are
  test threads (a writer standing in for the solver, a reader for the checker), so transport
  properties (partial writes, cap, EPIPE, open order) are observed byte for byte.
- :func:`run` builds synthetic :class:`~cubeproof.tools.process.ProcessRun` values for the
  pure classification table.
- The fixtures ``isolation`` and ``supervisor`` are defined here; a test module imports
  ``isolation_fixture``/``supervisor_fixture`` (no conftest: see
  ``tests/tools/cp_tools_support.py``).
"""

from __future__ import annotations

import dataclasses
import hashlib
import os
import signal
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Iterator, Sequence
from pathlib import Path
from typing import Any

import pytest

from cubeproof.base.process import Cause, ProcessResult
from cubeproof.cnf.dimacs import Formula, canonical_dimacs, parse_dimacs
from cubeproof.contracts.policy import Policy, default_policy
from cubeproof.tools.isolation import Isolation, PinnedBinary
from cubeproof.tools.process import ProcessRun, Supervisor

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[3]
SRC = REPO / "packages" / "cubeproof" / "src"
RELAY_SCRIPT = SRC / "cubeproof" / "tools" / "relay.py"
SHARED_TESTS = REPO / "tests"
SCHEDULER_TESTS = HERE.parent / "scheduler"
for _path in (SHARED_TESTS, SCHEDULER_TESTS):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

from cp_sched_support import MACHINERY, RESOURCES, Journal, formula_bytes  # noqa: E402
from cp_sched_support import policy as policy_value  # noqa: E402

from fakes import cnf_model, lrat_check  # noqa: E402
from fakes import presets as p  # noqa: E402
from fakes import toolkit as fk  # noqa: E402

__all__ = [
    "MACHINERY",
    "RELAY_SCRIPT",
    "RESOURCES",
    "TINY",
    "TINY_PROOF",
    "Journal",
    "RelayHarness",
    "cnf_model",
    "fk",
    "formula",
    "formula_bytes",
    "isolation_fixture",
    "lrat_check",
    "make_policy",
    "p",
    "policy_value",
    "run",
    "sha",
    "supervisor_fixture",
    "wait_until",
]


@pytest.fixture(scope="session", name="isolation")
def isolation_fixture() -> Isolation:
    """The util-linux wrappers of this host; missing wrappers fail, they never skip."""
    if not sys.platform.startswith("linux"):
        pytest.skip("tool isolation and FIFOs are Linux-only (specification §6.2)")
    return Isolation.probe()


@pytest.fixture(name="supervisor")
def supervisor_fixture(isolation: Isolation) -> Iterator[Supervisor]:
    sup = Supervisor(isolation)
    try:
        yield sup
    finally:
        sup.shutdown(grace_ms=200)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def formula(variables: int, clauses: Sequence[Sequence[int]]) -> Formula:
    return parse_dimacs(canonical_dimacs(variables, clauses))


#: x1, x2 in every sign combination: UNSAT, unit propagation undecided (the CDCL route).
TINY = formula(2, [(1, 2), (1, -2), (-1, 2), (-1, -2)])
#: A valid LRAT refutation of TINY under the empty cube (clauses 1..4, lemmas from 5).
TINY_PROOF = b"5 1 0 1 2 0\n6 0 5 3 4 0\n"


def make_policy(**changes: Any) -> Policy:
    """The specification §4.3 defaults in stream mode with short test times, then ``changes``."""
    values: dict[str, Any] = {
        "leaf_time_ms": {"default": 60_000},
        "checker_time_base_ms": 30_000,
        "term_grace_ms": 500,
        "stop_grace_ms": 500,
    }
    values.update(changes)
    return dataclasses.replace(default_policy("stream"), **values)


def wait_until(predicate: Callable[[], bool], limit_s: float = 30.0) -> None:
    deadline = time.monotonic() + limit_s
    while not predicate():
        assert time.monotonic() < deadline, "condition not reached in time"
        time.sleep(0.01)


def make_tool(directory: Path, name: str, steps: Sequence[Any]) -> tuple[fk.FakeTool, PinnedBinary]:
    tool = fk.make_tool(directory, name, steps)
    return tool, PinnedBinary.measure(str(tool.path))


# -- synthetic process runs ----------------------------------------------------------------------


def run(
    *,
    exit: int | None = 0,
    signal_number: int | None = None,
    causes: Sequence[Cause] = (),
    stdout: str = "",
    stderr: str = "",
    started: bool = True,
    capture: bytes | None = None,
    stdout_truncated: bool = False,
    stderr_truncated: bool = False,
) -> ProcessRun:
    """A finished (or never started) process run with exactly these facts."""
    if not started:
        cause = causes[0] if causes else Cause.LAUNCH
        return ProcessRun(ProcessResult.not_started(cause), causes=tuple(causes) or (cause,))
    if signal_number is not None:
        exit = None
    result = ProcessResult(
        started=True,
        exit=exit,
        signal=signal_number,
        elapsed_ms=5,
        stdout_tail=stdout,
        stderr_tail=stderr,
        stdout_bytes=len(stdout.encode()) if capture is None else len(capture),
        stdout_truncated=stdout_truncated,
        cause=causes[0].value if causes else None,
        conflicts=None,
    )
    stdout_bytes = stdout.encode() if capture is None else capture
    return ProcessRun(
        result, causes=tuple(causes), stdout=stdout_bytes, stderr_truncated=stderr_truncated
    )


# -- the relay alone between two FIFOs ------------------------------------------------------------


class _Peer(threading.Thread):
    def __init__(self, target: Callable[[], None]) -> None:
        super().__init__(daemon=True)
        self._target_function = target
        self.error: BaseException | None = None

    def run(self) -> None:
        try:
            self._target_function()
        except BaseException as error:  # reported to the test, never swallowed
            self.error = error


class RelayHarness:
    """``tools/relay.py`` as a child process between two FIFOs and two test threads."""

    def __init__(self, root: Path, *, python: str = sys.executable) -> None:
        root.mkdir(parents=True, exist_ok=True)
        self.root = root
        self.source = root / "solver.lrat"
        self.sink = root / "checker.lrat"
        os.mkfifo(self.source, 0o600)
        os.mkfifo(self.sink, 0o600)
        self.python = python
        self.process: subprocess.Popen[bytes] | None = None
        self.received = bytearray()
        self.written = 0
        self.writer_error: BaseException | None = None
        self.peers: list[_Peer] = []
        self.stdout = b""
        self.stderr = b""

    def start(self, cap: int, *extra: str) -> subprocess.Popen[bytes]:
        command = [self.python, "-I", "-S", str(RELAY_SCRIPT), str(self.source), str(self.sink)]
        command += [str(cap), *extra]
        self.process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={"LC_ALL": "C"},
            start_new_session=True,
        )
        return self.process

    def writer(
        self,
        data: bytes,
        *,
        delay: float = 0.0,
        chunk: int = 1 << 16,
        pause: float = 0.0,
        never_open: bool = False,
    ) -> None:
        """The solver's side: open the FIFO (blocking, as a C program does), write, close."""

        def body() -> None:
            if never_open:
                return
            time.sleep(delay)
            fd = os.open(self.source, os.O_WRONLY)
            try:
                view = memoryview(data)
                while view:
                    count = os.write(fd, view[:chunk])
                    self.written += count
                    view = view[count:]
                    if pause:
                        time.sleep(pause)
            except BrokenPipeError as error:
                self.writer_error = error
            finally:
                os.close(fd)

        self._spawn(body)

    def reader(
        self,
        *,
        delay: float = 0.0,
        chunk: int = 1 << 16,
        pause: float = 0.0,
        limit: int | None = None,
    ) -> None:
        """The checker's side: open (blocking), read until EOF or ``limit`` bytes, close."""

        def body() -> None:
            time.sleep(delay)
            fd = os.open(self.sink, os.O_RDONLY)
            try:
                while limit is None or len(self.received) < limit:
                    want = chunk if limit is None else min(chunk, limit - len(self.received))
                    block = os.read(fd, want)
                    if not block:
                        break
                    self.received += block
                    if pause:
                        time.sleep(pause)
            finally:
                os.close(fd)

        self._spawn(body)

    def _spawn(self, body: Callable[[], None]) -> None:
        peer = _Peer(body)
        peer.start()
        self.peers.append(peer)

    def finish(self, timeout: float = 60.0) -> int:
        """Wait for the relay and both peers; return the relay's exit code."""
        assert self.process is not None
        try:
            self.stdout, self.stderr = self.process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            self.kill()
            raise
        for peer in self.peers:
            peer.join(timeout)
            assert not peer.is_alive(), "a FIFO peer is still blocked"
            if peer.error is not None:
                raise peer.error
        return self.process.returncode

    def terminate(self) -> None:
        assert self.process is not None
        os.killpg(self.process.pid, signal.SIGTERM)

    def kill(self) -> None:
        if self.process is not None and self.process.poll() is None:
            os.killpg(self.process.pid, signal.SIGKILL)
            self.process.wait()
        # unblock peers stuck in a blocking open of a FIFO without a partner
        for path, flags in ((self.source, os.O_RDONLY), (self.sink, os.O_WRONLY)):
            try:
                fd = os.open(path, flags | os.O_NONBLOCK)
            except OSError:
                continue
            os.close(fd)
