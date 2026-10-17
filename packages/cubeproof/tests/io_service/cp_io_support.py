"""Test-only helpers of the I/O service tests: fault injection, journal wiring, records.

Nothing here is imported by runtime code. The journal wiring (:class:`WriterPort`) is what a
coordinator-layer entry point does: ``tools`` may not import ``evidence`` (specification §2.3),
so the service receives the journal writer through the :class:`JournalPort` protocol.
"""

from __future__ import annotations

import errno
import hashlib
import json
import os
import sys
import time
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from cubeproof.base.errors import ContractError
from cubeproof.contracts.io import Area, artifact_path
from cubeproof.contracts.values import Artifact
from cubeproof.evidence.journal import JournalWriter, RunLock
from cubeproof.evidence.schema import PAYLOADS, Record, RecordSequence
from cubeproof.tools.atomic import FileCalls

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[3]
CORPUS = REPO / "tests" / "contracts" / "corpus"
SRC = REPO / "packages" / "cubeproof" / "src"
MAIN = HERE / "cp_io_service_main.py"
MIB = 1 << 20


# -- fault injection ------------------------------------------------------------------------------


class Crash(BaseException):
    """A simulated process death at a chosen system call (not an OSError)."""


class FaultCalls(FileCalls):
    """Real file system calls, recorded in order, with optional faults per call kind.

    ``faults`` maps a call name to ``(call_number, *args) -> None | replacement``; the call
    number counts calls of that name from 1. ``crash_at`` raises :class:`Crash` at the n-th
    *mutating or durable* call (open for writing, write, fsync, link, rename, unlink, mkdir),
    counted over all kinds: the enumeration of "crash before/after each durable effect".
    ``write_limit`` caps the bytes accepted by one write (short writes).
    """

    MUTATING = ("open_w", "write", "fsync", "link", "rename", "unlink", "mkdir")

    def __init__(
        self,
        *,
        faults: Mapping[str, Callable[..., Any]] | None = None,
        write_limit: int | None = None,
        crash_at: int | None = None,
        free_bytes: int | None = None,
    ) -> None:
        self.log: list[tuple[Any, ...]] = []
        self.faults = dict(faults or {})
        self.counts: dict[str, int] = {}
        self.write_limit = write_limit
        self.crash_at = crash_at
        self.mutations = 0
        self.free = free_bytes
        self.paths: dict[int, str] = {}

    def _fault(self, name: str, *args: Any) -> Any:
        self.counts[name] = self.counts.get(name, 0) + 1
        fault = self.faults.get(name)
        if fault is None:
            return None
        return fault(self.counts[name], *args)

    def _mutation(self, what: tuple[Any, ...]) -> None:
        self.mutations += 1
        if self.crash_at is not None and self.mutations == self.crash_at:
            self.log.append(("crash", *what))
            raise Crash(what)

    def open(self, path: str, flags: int, mode: int = 0o600) -> int:
        writing = bool(flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT))
        if writing:
            self._mutation(("open", path))
        self._fault("open", path, flags)
        fd = super().open(path, flags, mode)
        self.paths[fd] = os.fspath(path)
        self.log.append(("open", os.fspath(path), flags, fd))
        return fd

    def close(self, fd: int) -> None:
        self.log.append(("close", self.paths.get(fd, fd)))
        super().close(fd)

    def pread(self, fd: int, count: int, offset: int) -> bytes:
        replaced = self._fault("pread", fd, count, offset)
        self.log.append(("pread", self.paths.get(fd, fd), count, offset))
        if replaced is not None:
            data: bytes = replaced
            return data
        return super().pread(fd, count, offset)

    def write(self, fd: int, data: memoryview) -> int:
        self._mutation(("write", self.paths.get(fd, fd)))
        replaced = self._fault("write", fd, bytes(data))
        if replaced is not None:
            self.log.append(("write", self.paths.get(fd, fd), replaced))
            count: int = replaced
            return count
        view = data if self.write_limit is None else data[: self.write_limit]
        written = super().write(fd, view)
        self.log.append(("write", self.paths.get(fd, fd), written))
        return written

    def fsync(self, fd: int) -> None:
        self._mutation(("fsync", self.paths.get(fd, fd)))
        self._fault("fsync", fd)
        self.log.append(("fsync", self.paths.get(fd, fd)))
        super().fsync(fd)

    def link(self, source: str, target: str) -> None:
        self._mutation(("link", source, target))
        self._fault("link", source, target)
        self.log.append(("link", os.fspath(source), os.fspath(target)))
        super().link(source, target)

    def rename(self, source: str, target: str) -> None:
        self._mutation(("rename", source, target))
        self._fault("rename", source, target)
        self.log.append(("rename", os.fspath(source), os.fspath(target)))
        super().rename(source, target)

    def unlink(self, path: str) -> None:
        self._mutation(("unlink", path))
        self._fault("unlink", path)
        self.log.append(("unlink", os.fspath(path)))
        super().unlink(path)

    def mkdir(self, path: str, mode: int = 0o755) -> None:
        self._mutation(("mkdir", path))
        self._fault("mkdir", path)
        self.log.append(("mkdir", os.fspath(path)))
        super().mkdir(path, mode)

    def free_bytes(self, path: str) -> int:
        self._fault("free_bytes", path)
        if self.free is not None:
            return self.free
        return super().free_bytes(path)

    def names(self) -> list[str]:
        return [entry[0] for entry in self.log]

    def events(self, *kinds: str) -> list[tuple[Any, ...]]:
        return [entry for entry in self.log if entry[0] in kinds]


def fail_with(code: int, *, after: int = 0) -> Callable[..., Any]:
    """A fault raising ``OSError(code)`` from call number ``after + 1`` on."""

    def fault(number: int, *args: Any) -> Any:
        if number > after:
            raise OSError(code, os.strerror(code))
        return None

    return fault


def interrupt(times: int) -> Callable[..., Any]:
    """A fault raising InterruptedError (EINTR) on the first ``times`` calls."""

    def fault(number: int, *args: Any) -> Any:
        if number <= times:
            raise InterruptedError(errno.EINTR, "interrupted")
        return None

    return fault


# -- files ----------------------------------------------------------------------------------------


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def proof_bytes(size: int, seed: int = 0) -> bytes:
    """Deterministic pseudo-random bytes (a stand-in for an LRAT proof)."""
    return hashlib.shake_256(f"proof:{seed}".encode()).digest(size)


def write_file(path: Path, data: bytes, mode: int = 0o444) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    path.chmod(mode)
    return path


def tree(root: Path) -> dict[str, bytes]:
    """Every regular file below ``root`` (relative POSIX path -> bytes); symlinks as markers."""
    out: dict[str, bytes] = {}
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            out[relative] = b"<symlink>"
        elif path.is_file():
            out[relative] = path.read_bytes()
    return out


NODE_ID = "95757059a8564a7fddcbc2d3bff92b5425a2e31ec57681f863fc70f3fbc286ae"


def artifact_for(data: bytes, area: Area = Area.PROOFS, node_id: str = NODE_ID) -> Artifact:
    return Artifact(artifact_path(area, node_id, sha(data)), sha(data), len(data))


def new_attempt_id(index: int) -> str:
    return hashlib.sha256(f"attempt-{index}".encode()).hexdigest()[:32]


# -- journal records (corpus journal modes/w1: header, resume retain, retained attempt) ------------

_ENVELOPE = ("format", "seq", "prev", "self", "utc")


def _corpus_records() -> list[dict[str, Any]]:
    lines = (CORPUS / "journals" / "modes" / "w1.jsonl").read_bytes().split(b"\n")[:-1]
    return [json.loads(line) for line in lines]


def payload_of(record: Mapping[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in record.items() if k not in _ENVELOPE}


def header_payload() -> dict[str, Any]:
    return payload_of(_corpus_records()[0])


def resume_payload() -> dict[str, Any]:
    """A resume with policy proof_mode retain."""
    value = payload_of(_corpus_records()[1])
    assert value["type"] == "resume"
    assert value["policy"]["proof_mode"] == "retain"
    return value


def attempt_payload(
    attempt_id: str, data: bytes | None, *, retained: Artifact | None = None
) -> dict[str, Any]:
    """The corpus' retained VERIFIED_UNSAT attempt with a new attempt ID and proof ``data``.

    ``retained`` defaults to the proof's artifact; success.* rules are delegated, so the
    proof hash may change without touching the checks.
    """
    value = payload_of(_corpus_records()[2])
    assert value["type"] == "attempt"
    assert value["node_id"] == NODE_ID
    value["attempt_id"] = attempt_id
    if data is not None:
        value["proof_sha256"] = sha(data)
        value["proof_bytes"] = len(data)
        art = retained if retained is not None else artifact_for(data)
        value["retained"] = art.to_json()
    return value


def payload_value(value: Mapping[str, Any]) -> Any:
    """The typed journal payload of a payload JSON value (what a coordinator adapter does)."""
    kind = value.get("type")
    if not isinstance(kind, str) or kind not in PAYLOADS:
        raise ContractError("schema", f"unknown record type {kind!r}")
    fields = {k: v for k, v in value.items() if k != "type"}
    spec = PAYLOADS[kind].SPEC
    spec.check(fields, "$")
    return spec.build(fields)


class WriterPort:
    """The JournalWriter behind the service's JournalPort protocol."""

    def __init__(
        self,
        writer: JournalWriter[Record],
        *,
        before: Callable[[], None] | None = None,
        after: Callable[[], None] | None = None,
    ) -> None:
        self.writer = writer
        self.before = before
        self.after = after

    @property
    def failed(self) -> bool:
        return self.writer.failed

    def position(self) -> tuple[int, str] | None:
        chain = self.writer.chain
        if chain.head is None:
            return None
        return chain.records - 1, chain.head

    def append(self, payload: Mapping[str, Any]) -> tuple[int, str]:
        if self.before is not None:
            self.before()
        record = self.writer.append(payload_value(payload))
        if self.after is not None:
            self.after()
        return record.seq, record.self_hash


def validator() -> RecordSequence:
    return RecordSequence(context=None)


def create_journal(results: Path) -> tuple[Path, RunLock]:
    """A results directory with run.lock held and a journal holding the corpus header."""
    results.mkdir(parents=True, exist_ok=True)
    lock = RunLock.acquire(results / "run.lock")
    path = results / "journal.jsonl"
    writer = JournalWriter.create(
        path, payload_value(header_payload()), validator=validator(), run_lock=lock
    )
    writer.close()
    return path, lock


def open_port(path: Path, lock: RunLock, **options: Any) -> WriterPort:
    writer = JournalWriter.open(path, validator=validator(), run_lock=lock)
    return WriterPort(writer, **options)


def journal_records(path: Path) -> list[dict[str, Any]]:
    data = path.read_bytes()
    return [json.loads(line) for line in data.split(b"\n")[:-1]]


def committed_artifacts(path: Path) -> list[Artifact]:
    """Replay: the retained/quarantined artifacts of the committed attempt records."""
    out: list[Artifact] = []
    for record in journal_records(path):
        if record["type"] != "attempt":
            continue
        for key in ("retained", "quarantined"):
            if record[key] is not None:
                out.append(Artifact.from_json(record[key]))
    return out


# -- service subprocess ----------------------------------------------------------------------------


def service_argv(
    results: Path,
    work: Path,
    *,
    journal: Path | None = None,
    lock: RunLock | None = None,
    chunk: int | None = None,
    slow_fsync: float | None = None,
    fail_fsync: bool = False,
) -> list[str]:
    argv = [sys.executable, str(MAIN), "--results", str(results), "--work", str(work)]
    if journal is not None:
        assert lock is not None
        argv += ["--journal", str(journal), "--lock", str(lock.path), "--lock-fd"]
        argv.append(str(lock_fd(lock)))
    if chunk is not None:
        argv += ["--chunk", str(chunk)]
    if slow_fsync is not None:
        argv += ["--slow-fsync", str(slow_fsync)]
    if fail_fsync:
        argv.append("--fail-fsync")
    return argv


def lock_fd(lock: RunLock) -> int:
    fd = lock._fd
    assert fd is not None
    return fd


def service_env() -> dict[str, str]:
    env = {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}
    env["PYTHONPATH"] = os.pathsep.join([str(SRC), str(HERE)])
    return env


def wait_until(condition: Callable[[], bool], timeout: float = 30.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if condition():
            return True
        time.sleep(0.01)
    return condition()
