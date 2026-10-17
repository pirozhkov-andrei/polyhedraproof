"""Test-only helpers of the retain/quarantine tests.

The I/O service helpers (fault injection, journal wiring, corpus records) are reused from
``tests/io_service/cp_io_support.py``. :class:`Env` is an in-process I/O service (the
``Service`` with the journal writer behind a ``WriterPort``) on a results directory whose
journal holds the corpus header and a resume with policy ``proof_mode: retain``.
"""

from __future__ import annotations

import copy
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

_IO_TESTS = Path(__file__).resolve().parents[1] / "io_service"
if str(_IO_TESTS) not in sys.path:
    sys.path.insert(0, str(_IO_TESTS))

import cp_io_support as io  # noqa: E402
from cp_io_support import NODE_ID, Crash, FaultCalls, sha  # noqa: E402

from cubeproof.contracts.io import (  # noqa: E402
    AppendRequest,
    Area,
    Job,
    PublishRequest,
    RemoveRequest,
    Request,
    Result,
    artifact_path,
)
from cubeproof.contracts.values import Artifact  # noqa: E402
from cubeproof.evidence.journal import RunLock  # noqa: E402
from cubeproof.evidence.schema import Attempt  # noqa: E402
from cubeproof.leaf.binding import FileHash  # noqa: E402
from cubeproof.tools.io_service import Service, ServiceConfig  # noqa: E402

__all__ = [
    "CHUNK",
    "NODE_ID",
    "Crash",
    "Env",
    "FaultCalls",
    "artifact_for",
    "attempt_id",
    "attempts_of",
    "proof_bytes",
    "rejected_payload",
    "retained_payload",
    "sha",
    "tree",
    "typed",
]

CHUNK = 4096
proof_bytes = io.proof_bytes
tree = io.tree

#: A rejecting check (exit 1, ``s NOT VERIFIED``) as in the contract corpus.
_REJECTING_CHECK: dict[str, Any] = {
    "heap_mib": 512,
    "stack_mib": 256,
    "result": {
        "cause": None,
        "conflicts": None,
        "elapsed_ms": 12,
        "exit": 1,
        "signal": None,
        "started": True,
        "stderr_tail": "",
        "stdout_bytes": 15,
        "stdout_tail": "s NOT VERIFIED\n",
        "stdout_truncated": False,
    },
}


def attempt_id(index: int) -> str:
    return io.new_attempt_id(index)


def artifact_for(data: bytes, area: Area = Area.PROOFS, node_id: str = NODE_ID) -> Artifact:
    return Artifact(artifact_path(area, node_id, sha(data)), sha(data), len(data))


def retained_payload(
    attempt: str, data: bytes, *, retained: Artifact | bool | None = True
) -> dict[str, Any]:
    """The corpus' retain-mode VERIFIED_UNSAT attempt with proof ``data``.

    ``retained=True`` references the proof's own artifact, None leaves the field null, an
    Artifact is used as given.
    """
    value = io.attempt_payload(attempt, data)
    if retained is None:
        value["retained"] = None
    elif isinstance(retained, Artifact):
        value["retained"] = retained.to_json()
    return value


def rejected_payload(
    attempt: str, data: bytes, *, quarantined: Artifact | bool | None = True
) -> dict[str, Any]:
    """A retain-mode CHECK_REJECTED attempt with proof ``data`` (corpus shape)."""
    value = io.attempt_payload(attempt, data)
    value["outcome"] = "CHECK_REJECTED"
    value["reason"] = "rejected"
    value["retained"] = None
    value["checks"] = [copy.deepcopy(_REJECTING_CHECK)]
    if quarantined is True:
        value["quarantined"] = artifact_for(data, Area.QUARANTINE).to_json()
    elif isinstance(quarantined, Artifact):
        value["quarantined"] = quarantined.to_json()
    else:
        value["quarantined"] = None
    return value


def typed(payload: dict[str, Any]) -> Attempt:
    value = io.payload_value(payload)
    assert isinstance(value, Attempt)
    return value


def attempts_of(journal: Path) -> list[Attempt]:
    """Replay: the committed attempt records of a journal, typed."""
    out: list[Attempt] = []
    for record in io.journal_records(journal):
        if record["type"] == "attempt":
            out.append(typed(io.payload_of(record)))
    return out


class Env:
    """Results directory with journal (header + resume retain), work directory, service."""

    def __init__(
        self,
        root: Path,
        *,
        calls: FaultCalls | None = None,
        work: Path | None = None,
        before_append: Callable[[], None] | None = None,
        after_append: Callable[[], None] | None = None,
        restart: bool = False,
    ) -> None:
        self.root = root
        self.results = root / "results"
        self.work = work if work is not None else root / "work"
        self.work.mkdir(parents=True, exist_ok=True)
        if restart:  # a new session on the existing results directory and journal
            self.journal = self.results / "journal.jsonl"
            self.lock = RunLock.acquire(self.results / "run.lock")
        else:
            self.journal, self.lock = io.create_journal(self.results)
        self.port = io.open_port(self.journal, self.lock, before=before_append, after=after_append)
        self.calls = calls if calls is not None else FaultCalls()
        config = ServiceConfig(
            results_root=str(self.results), work_root=str(self.work), chunk_bytes=CHUNK
        )
        self.service = Service(config, self.port, calls=self.calls)
        self.next_id = 1
        # every session starts with a resume (specification §7.3), after the header of a new journal
        hooks = (self.port.before, self.port.after)
        self.port.before = self.port.after = None
        result = self.run(None, AppendRequest.of(io.resume_payload()))
        self.port.before, self.port.after = hooks
        assert result.ok, result

    def run(self, attempt: str | None, request: Request) -> Result:
        job = Job(self.next_id, attempt, request)
        self.next_id += 1
        result = self.service.run(job)
        assert result.problem(job) is None
        return result

    def source(self, attempt: str, data: bytes) -> FileHash:
        """The sealed work proof ``<work>/<node_id>-<attempt_id>.lrat`` (read-only)."""
        path = io.write_file(self.work / f"{NODE_ID}-{attempt}.lrat", data)
        return FileHash(attempt, str(path), len(data), sha(data))

    def publish(self, attempt: str, request: PublishRequest) -> Result:
        return self.run(attempt, request)

    def append(self, attempt: str, payload: dict[str, Any]) -> Result:
        return self.run(attempt, AppendRequest.of(payload))

    def remove(self, attempt: str, *paths: str) -> Result:
        return self.run(attempt, RemoveRequest(tuple(paths)))

    def attempts(self) -> list[Attempt]:
        return attempts_of(self.journal)

    def area_files(self) -> dict[str, bytes]:
        """Every file below ``proofs/`` and ``quarantine/`` (including staging)."""
        return {
            path: data
            for path, data in tree(self.results).items()
            if path.split("/")[0] in (Area.PROOFS.value, Area.QUARANTINE.value)
        }

    def close(self) -> None:
        self.port.writer.close()
        self.lock.release()
