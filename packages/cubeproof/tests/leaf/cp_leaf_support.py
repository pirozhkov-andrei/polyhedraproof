"""Test-only helpers of the leaf tests: formulas, policies, fake tools and an I/O port.

Nothing here is imported by runtime code.

- Fake tools are the fakes of ``tests/fakes``: real executables run by the process supervisor
  under the real isolation wrappers, so every attempt test exercises the real process layer.
- :class:`LocalIo` is the :class:`~cubeproof.tools.io_service.Service` executed in this
  process when polled, with results verified by its :class:`Tracker` and a real journal
  writer behind it (the wiring of the coordinator layer, as in the I/O service tests).
  Fault hooks replace the result of chosen jobs (failures, other hashes) to drive the leaf
  through every I/O outcome. It records every submitted job and which jobs were still
  unanswered when each job was submitted ("no append before final inputs").
- The fixtures ``isolation`` and ``supervisor`` are defined here; a test module imports
  ``isolation_fixture``/``supervisor_fixture`` (no conftest: see
  ``tests/tools/cp_tools_support.py``).
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import sys
import time
from collections.abc import Callable, Iterator, Mapping, Sequence
from pathlib import Path
from typing import Any

import pytest

from cubeproof.base.errors import ContractError
from cubeproof.cnf.cubecnf import CnfDigest, cube_cnf_bytes
from cubeproof.cnf.dimacs import Formula, canonical_dimacs, parse_dimacs
from cubeproof.contracts.io import (
    AppendRequest,
    Failure,
    HashRequest,
    HashValue,
    Job,
    Op,
    RemoveRequest,
    Request,
    Result,
)
from cubeproof.contracts.policy import Policy, default_policy
from cubeproof.evidence.journal import JournalWriter, RunLock
from cubeproof.evidence.schema import PAYLOADS, Record, RecordSequence
from cubeproof.leaf.attempt import LeafAttempt, LeafTools
from cubeproof.leaf.driver import drive
from cubeproof.tools.io_service import Service, ServiceConfig
from cubeproof.tools.io_service_client import IoServiceError, Tracker
from cubeproof.tools.isolation import Isolation, PinnedBinary
from cubeproof.tools.process import Supervisor

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[3]
SRC = REPO / "packages" / "cubeproof" / "src"
SHARED_TESTS = REPO / "tests"
CORPUS = SHARED_TESTS / "contracts" / "corpus"
if str(SHARED_TESTS) not in sys.path:
    sys.path.insert(0, str(SHARED_TESTS))

from fakes import cnf_model, lrat_check  # noqa: E402
from fakes import presets as p  # noqa: E402
from fakes import toolkit as fk  # noqa: E402

__all__ = [
    "CORPUS",
    "HERE",
    "REPO",
    "SAT",
    "TINY",
    "TINY_PROOFS",
    "UNIT_MODEL",
    "Bench",
    "LocalIo",
    "cnf_model",
    "fk",
    "formula",
    "header_payload",
    "isolation_fixture",
    "lrat_check",
    "make_policy",
    "p",
    "payload_value",
    "sha",
    "supervisor_fixture",
    "wait_until",
]


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
        sup.shutdown(grace_ms=200)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def formula(variables: int, clauses: Sequence[Sequence[int]]) -> Formula:
    return parse_dimacs(canonical_dimacs(variables, clauses))


#: x1, x2 in every sign combination (UNSAT, no unit clause: unit propagation is undecided),
#: and a free x3 so that a cube on x3 adds a unit line without deciding anything.
TINY = formula(3, [(1, 2), (1, -2), (-1, 2), (-1, -2)])
#: Two different valid LRAT refutations of TINY under any cube (lemma 1 or lemma 2 first).
#: Clause IDs follow CNF(F, C) with one cube unit: base 1..4, unit 5, lemmas from 6.
TINY_PROOFS = (
    b"6 1 0 1 2 0\n7 0 6 3 4 0\n",
    b"6 2 0 1 3 0\n7 0 6 2 4 0\n",
)
#: The same proofs for the empty cube (lemmas from 5).
TINY_PROOFS_ROOT = (
    b"5 1 0 1 2 0\n6 0 5 3 4 0\n",
    b"5 2 0 1 3 0\n6 0 5 2 4 0\n",
)
#: Satisfiable, unit propagation undecided: the CDCL route; model [1, -2, 3] satisfies it.
SAT = formula(3, [(1, 2), (-1, 3)])
#: Unit propagation assigns every variable without a conflict: the unit model route.
UNIT_MODEL = formula(2, [(1,), (-1, 2)])


def make_policy(**changes: Any) -> Policy:
    """The specification §4.3 defaults in transient mode with short test times, then ``changes``."""
    values: dict[str, Any] = {
        "leaf_time_ms": {"default": 60_000},
        "checker_time_base_ms": 30_000,  # below the fitted time of any proof (60 s)
        "term_grace_ms": 500,
        "stop_grace_ms": 500,
    }
    values.update(changes)
    return dataclasses.replace(default_policy("transient"), **values)


def wait_until(predicate: Callable[[], bool], limit_s: float = 30.0) -> None:
    deadline = time.monotonic() + limit_s
    while not predicate():
        assert time.monotonic() < deadline, "condition not reached in time"
        time.sleep(0.01)


# -- journal -----------------------------------------------------------------------------------

_ENVELOPE = ("format", "seq", "prev", "self", "utc")


def header_payload(policy: Policy) -> dict[str, Any]:
    """The corpus pilot_root header (transient) with ``policy``."""
    line = (CORPUS / "journals" / "pilot_root" / "w1.jsonl").read_bytes().split(b"\n")[0]
    value = {k: v for k, v in json.loads(line).items() if k not in _ENVELOPE}
    assert value["type"] == "header"
    value["policy"] = policy.to_json()
    return value


def resume_payload(policy: Policy) -> dict[str, Any]:
    header = header_payload(policy)
    return {
        "type": "resume",
        "machinery": header["machinery"],
        "policy": header["policy"],
        "resources": header["resources"],
    }


def payload_value(value: Mapping[str, Any]) -> Any:
    """The typed journal payload of a payload JSON value (what the coordinator wiring does)."""
    kind = value.get("type")
    if not isinstance(kind, str) or kind not in PAYLOADS:
        raise ContractError("schema", f"unknown record type {kind!r}")
    fields = {k: v for k, v in value.items() if k != "type"}
    spec = PAYLOADS[kind].SPEC
    spec.check(fields, "$")
    return spec.build(fields)


class WriterPort:
    """The JournalWriter behind the service's JournalPort protocol."""

    def __init__(self, writer: JournalWriter[Record]) -> None:
        self.writer = writer

    @property
    def failed(self) -> bool:
        return self.writer.failed

    def position(self) -> tuple[int, str] | None:
        chain = self.writer.chain
        if chain.head is None:
            return None
        return chain.records - 1, chain.head

    def append(self, payload: Mapping[str, Any]) -> tuple[int, str]:
        record = self.writer.append(payload_value(payload))
        return record.seq, record.self_hash


def journal_lines(path: Path) -> list[dict[str, Any]]:
    data = path.read_bytes()
    return [json.loads(line) for line in data.split(b"\n")[:-1]]


# -- in-process I/O port -----------------------------------------------------------------------

Fault = Callable[[Job], Result | None]


def failure(
    job: Job, *, rule: str = "io.injected", kind: str = "tool", fatal: bool = False
) -> Result:
    return Result(job.job_id, job.op, job.attempt_id, Failure(kind, rule, "injected", fatal))


class LocalIo:
    """The I/O service in this process (see module doc)."""

    def __init__(self, results: Path, work: Path, policy: Policy) -> None:
        results.mkdir(parents=True, exist_ok=True)
        work.mkdir(parents=True, exist_ok=True)
        self.results = results
        self.work = work
        self.lock = RunLock.acquire(results / "run.lock")
        self.journal = results / "journal.jsonl"
        self.writer: JournalWriter[Record] = JournalWriter.create(
            self.journal,
            payload_value(header_payload(policy)),
            validator=RecordSequence(context=None),
            run_lock=self.lock,
        )
        self.service = Service(ServiceConfig(str(results), str(work)), WriterPort(self.writer))
        self.tracker = Tracker()
        self.tracker.hello(self.service.hello(os.getpid()))
        self.failure: IoServiceError | None = None
        self.queue: list[Job] = []
        #: Every submitted job, in submission order.
        self.jobs: list[Job] = []
        #: Job ID -> IDs of the jobs without a delivered result when it was submitted.
        self.open_at_submit: dict[int, frozenset[int]] = {}
        self.answered: set[int] = set()
        self.faults: list[Fault] = []
        #: Called with each job just before it is executed (e.g. to cancel an attempt).
        self.before_run: list[Callable[[Job], None]] = []

    def submit(self, request: Request, *, attempt_id: str | None = None) -> Job:
        if self.failure is not None:
            raise IoServiceError("io.service_failed", f"no new work: {self.failure}")
        job = self.tracker.job(request, attempt_id)
        self.open_at_submit[job.job_id] = frozenset(
            j.job_id for j in self.jobs if j.job_id not in self.answered
        )
        self.jobs.append(job)
        self.queue.append(job)
        return job

    def poll(self, timeout: float = 0.0) -> list[tuple[Job, Result]]:
        del timeout
        out: list[tuple[Job, Result]] = []
        while self.queue and self.failure is None:
            job = self.queue.pop(0)
            for hook in self.before_run:
                hook(job)
            result: Result | None = None
            for fault in self.faults:
                result = fault(job)
                if result is not None:
                    break
            if result is None:
                result = self.service.run(job)
            self.tracker.accept(result)
            self.answered.add(job.job_id)
            out.append((job, result))
            outcome = result.outcome
            if isinstance(outcome, Failure) and outcome.fatal:
                self.failure = IoServiceError("io.service_failed", outcome.rule)
        return out

    def records(self) -> list[dict[str, Any]]:
        return journal_lines(self.journal)

    def attempts(self) -> list[dict[str, Any]]:
        return [r for r in self.records() if r["type"] == "attempt"]

    def jobs_of(self, attempt_id: str) -> list[Job]:
        return [j for j in self.jobs if j.attempt_id == attempt_id or _mentions(j, attempt_id)]

    def close(self) -> None:
        self.writer.close()
        self.lock.release()


def _mentions(job: Job, attempt_id: str) -> bool:
    request = job.request
    if isinstance(request, HashRequest):
        return attempt_id in request.path
    if isinstance(request, RemoveRequest):
        return any(attempt_id in path for path in request.paths)
    return False


def op_trace(io: LocalIo, attempt_id: str) -> list[tuple[str, str]]:
    """``(op, basename or record type)`` of the jobs of one attempt, in submission order."""
    trace = []
    for job in io.jobs_of(attempt_id):
        request = job.request
        if isinstance(request, HashRequest):
            trace.append((Op.HASH.value, os.path.basename(request.path)))
        elif isinstance(request, AppendRequest):
            trace.append((Op.APPEND.value, str(request.payload_type)))
        elif isinstance(request, RemoveRequest):
            names = ",".join(sorted(os.path.basename(path) for path in request.paths))
            trace.append((Op.REMOVE.value, names))
        else:
            trace.append((job.op.value, ""))
    return trace


def fail_op(
    op: Op, *, nth: int = 0, suffix: str = "", fatal: bool = False, rule: str = "io.injected"
) -> Fault:
    """Fail the ``nth`` job (0-based) of operation ``op`` whose path ends with ``suffix``."""
    seen = [0]

    def fault(job: Job) -> Result | None:
        if job.op is not op:
            return None
        request = job.request
        if suffix and not (isinstance(request, HashRequest) and request.path.endswith(suffix)):
            return None
        index = seen[0]
        seen[0] += 1
        if index != nth:
            return None
        return failure(job, rule=rule, fatal=fatal)

    return fault


def report_hash(
    *, nth: int, suffix: str, sha256: str | None = None, size: int | None = None
) -> Fault:
    """The ``nth`` hash job of a path ending with ``suffix`` reports another hash/size."""
    seen = [0]

    def fault(job: Job) -> Result | None:
        request = job.request
        if not (isinstance(request, HashRequest) and request.path.endswith(suffix)):
            return None
        index = seen[0]
        seen[0] += 1
        if index != nth:
            return None
        data = Path(request.path).read_bytes()
        value = HashValue(
            len(data) if size is None else size, sha(data) if sha256 is None else sha256
        )
        return Result(job.job_id, job.op, job.attempt_id, value)

    return fault


# -- tools and the bench -----------------------------------------------------------------------


def make_tool(
    directory: Path, name: str, steps: Sequence[Any], cases: Sequence[Any] = ()
) -> tuple[fk.FakeTool, PinnedBinary]:
    tool = fk.make_tool(directory, name, steps, cases=cases)
    return tool, PinnedBinary.measure(str(tool.path))


def fake_tools(
    directory: Path,
    *,
    solver: Sequence[Any] = (),
    checker: Sequence[Any] = (),
    solver_cases: Sequence[Any] = (),
    checker_cases: Sequence[Any] = (),
    solver_argv: tuple[str, ...] = ("--lrat",),
) -> tuple[LeafTools, fk.FakeTool, fk.FakeTool]:
    """Fake solver (default: brute force) and checker (default: the test LRAT validator)."""
    solver_tool, solver_pin = make_tool(
        directory, "cadical", solver or p.solver_brute_force(), solver_cases
    )
    checker_tool, checker_pin = make_tool(
        directory, "cake_lpr", checker or p.checker_lrat(), checker_cases
    )
    tools = LeafTools(solver=solver_pin, solver_argv=solver_argv, checker=checker_pin)
    return tools, solver_tool, checker_tool


class Bench:
    """One test's worker: work and results directories, policy, fake tools, I/O port."""

    def __init__(
        self,
        root: Path,
        supervisor: Supervisor,
        *,
        solver: Sequence[Any] = (),
        checker: Sequence[Any] = (),
        solver_cases: Sequence[Any] = (),
        checker_cases: Sequence[Any] = (),
        policy: Policy | None = None,
        solver_argv: tuple[str, ...] = ("--lrat",),
    ) -> None:
        self.root = root
        self.supervisor = supervisor
        self.policy = policy if policy is not None else make_policy()
        self.work = root / "work"
        self.results = root / "results"
        self.io = LocalIo(self.results, self.work, self.policy)
        self.tools, self.solver, self.checker = fake_tools(
            root / "tools",
            solver=solver,
            checker=checker,
            solver_cases=solver_cases,
            checker_cases=checker_cases,
            solver_argv=solver_argv,
        )
        self.digests: dict[str, CnfDigest] = {}

    def attempt(self, f: Formula, cube: Sequence[int] = (), **options: Any) -> LeafAttempt:
        digest = self.digests.setdefault(f.sha256, CnfDigest(f))
        options.setdefault("policy", self.policy)
        return LeafAttempt(
            formula=f,
            digest=digest,
            cube=tuple(cube),
            work_dir=str(self.work),
            tools=self.tools,
            supervisor=self.supervisor,
            io=self.io,
            **options,
        )

    def run(self, *attempts: LeafAttempt, timeout_s: float = 120.0, **options: Any) -> None:
        drive(attempts, supervisor=self.supervisor, io=self.io, timeout_s=timeout_s, **options)

    def one(
        self, f: Formula, cube: Sequence[int] = (), **options: Any
    ) -> tuple[LeafAttempt, dict[str, Any]]:
        """Run one attempt to its end; return it and its committed record (JSON)."""
        attempt = self.attempt(f, cube, **options)
        self.run(attempt)
        records = [r for r in self.io.attempts() if r["attempt_id"] == attempt.attempt_id]
        assert len(records) == 1, (attempt.phase, attempt.abandoned, records)
        return attempt, records[0]

    def work_files(self) -> list[str]:
        return sorted(name for name in os.listdir(self.work))

    def close(self) -> None:
        self.io.close()


def expected_cnf_sha256(f: Formula, cube: Sequence[int]) -> str:
    """The independent oracle: SHA-256 of the plainly constructed CNF(F, C) bytes."""
    return sha(cube_cnf_bytes(f, tuple(cube)))
