"""``verify-retained``: re-check every committed retained proof without a solver (specification
§11.4).

Scope: exactly the journals given (explicit paths or an evidence manifest) and one proofs root.
Every committed attempt of those journals with a nonnull ``retained`` artifact is an
**expected** proof; none is skipped because its file happens to be absent. For each, in Ref
order:

1. the reference must bind its record: ``retained`` is ``proofs/<node_id>-<proof_sha256>.lrat``
   with the record's ``proof_bytes`` and ``proof_sha256`` (otherwise CORRUPT);
2. the file below the proofs root is reached without symlinks; absent: MISSING; not a regular
   file, another size or another SHA-256: CORRUPT. The bytes are hashed while they are copied
   into a private work directory, and only that verified copy is checked, so a later change of
   the evidence file cannot reach the checker;
3. CNF(F, C) is regenerated from the verified bundle; its hash must be the record's
   ``cnf_sha256``;
4. the admitted checker runs on the copies with the arenas, memory cap and fitted check time of
   the record's effective policy (specification §8.3), arena retries as in a run; the result is
   classified by the specification §6.3 table of a unit proof (no solver): VERIFIED (exact checker
   success), REJECTED (clean rejection), EXHAUSTED (check time, arenas beyond the policy maxima or
   ``--memory``) or FAILED (crash, protocol, launch, changed file).

Evidence files are only read; the work directory of the private copies must not overlap the
proofs root either. The command writes into its own results directory (locked with
``run.lock``; it must not be the proofs root, overlap it, or hold a run journal) the report
``verify-retained.json``:

``{format:"cubeproof-verify-retained-report-1", campaign, worker, scope:{journals:[{id,
worker, records, head, bytes, torn_tail_bytes}], proofs_root}, expected, found, verified,
missing, corrupt, rejected, exhausted, failed, unretained, results:[{record, node_id, artifact,
status, reason}]}``; ``proofs_root`` is the absolute (resolved) directory that was searched.

``found = expected - missing``; ``unretained`` counts the VERIFIED_UNSAT records in scope that
have no retained proof (transient or stream): a retained set is not a verification of those.
Exit code (4 > 5 > 1 > 0): any MISSING, CORRUPT or REJECTED -> 4; any FAILED -> 5; any
EXHAUSTED, or nothing expected -> 1; otherwise 0.
"""

from __future__ import annotations

import contextlib
import enum
import hashlib
import os
import shutil
import stat
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cubeproof.base.canonical_json import document_bytes
from cubeproof.base.errors import ConfigurationError, InputError, IntegrityError, ToolError
from cubeproof.base.ids import new_id128
from cubeproof.base.settings import DEFAULT_LIMITS, ReaderLimits
from cubeproof.cnf.campaign import LoadedCampaign, load_campaign
from cubeproof.cnf.cubecnf import write_cube_cnf
from cubeproof.commands.audit_inputs import validator_of
from cubeproof.commands.inputs import resolve_inputs
from cubeproof.contracts.enums import ExitCode, Outcome
from cubeproof.contracts.io import Area, artifact_path
from cubeproof.contracts.policy import Policy
from cubeproof.contracts.primitives import is_name
from cubeproof.contracts.values import Artifact, Node, Ref
from cubeproof.evidence.journal import JournalReader, RunLock
from cubeproof.evidence.schema import Attempt, Header, Resume
from cubeproof.tools import checker as ck
from cubeproof.tools.isolation import Isolation, PinnedBinary, file_sha256
from cubeproof.tools.process import Launch, ProcessRun, Supervisor
from cubeproof.tools.process_outcome import (
    Action,
    ArenaLimits,
    CheckFacts,
    Failure,
    classify,
)

__all__ = [
    "LOCK_NAME",
    "REPORT_FORMAT",
    "REPORT_NAME",
    "Expected",
    "Status",
    "VerifyRequest",
    "VerifyResult",
    "collect_expected",
    "publish_replacing",
    "verify_retained",
]

REPORT_FORMAT = "cubeproof-verify-retained-report-1"
REPORT_NAME = "verify-retained.json"
LOCK_NAME = "run.lock"
_RUN_JOURNAL = "journal.jsonl"
_CHUNK = 1 << 20
_STEP_MS = 100
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)


class Status(str, enum.Enum):
    VERIFIED = "VERIFIED"
    MISSING = "MISSING"
    CORRUPT = "CORRUPT"
    REJECTED = "REJECTED"
    EXHAUSTED = "EXHAUSTED"
    FAILED = "FAILED"


_COUNTED = {
    Status.VERIFIED: "verified",
    Status.MISSING: "missing",
    Status.CORRUPT: "corrupt",
    Status.REJECTED: "rejected",
    Status.EXHAUSTED: "exhausted",
    Status.FAILED: "failed",
}


@dataclass(frozen=True)
class VerifyRequest:
    """``verify-retained`` inputs: journals (or an evidence manifest), a proofs root, the
    command's own results and work directories, its worker name and the checker path."""

    proofs_root: Path
    results: Path
    work: Path
    worker: str
    checker: str
    campaign: Path | None = None
    journals: tuple[Path, ...] = ()
    evidence: Path | None = None
    memory_bytes: int | None = None
    limits: ReaderLimits = field(default=DEFAULT_LIMITS)

    def __post_init__(self) -> None:
        if not is_name(self.worker):
            raise ConfigurationError("usage", f"--worker {self.worker!r} is not a Name")
        if self.memory_bytes is not None and (
            type(self.memory_bytes) is not int or self.memory_bytes < 1
        ):
            raise ConfigurationError("usage", "--memory must be a positive size")
        if not isinstance(self.checker, str) or not os.path.isabs(self.checker):
            raise ConfigurationError("usage", "--checker must be an absolute path")


@dataclass(frozen=True)
class Expected:
    """One committed retained reference and what its check needs."""

    record: Ref
    node: Node
    cnf_sha256: str
    artifact: Artifact
    proof_bytes: int
    proof_sha256: str
    policy: Policy


@dataclass(frozen=True)
class VerifyResult:
    """The report (also published as ``results/verify-retained.json``) and the exit code."""

    document: dict[str, Any]
    exit_code: int
    path: Path

    def to_json(self) -> dict[str, Any]:
        """The summary the command prints: the counts, the scope size and the report file."""
        names = ("expected", "found", "verified", "missing", "corrupt", "rejected")
        summary = {name: self.document[name] for name in (*names, "exhausted", "failed")}
        return {
            "exit_code": self.exit_code,
            "report": str(self.path),
            "campaign": self.document["campaign"],
            "journals": len(self.document["scope"]["journals"]),
            **summary,
            "unretained": self.document["unretained"],
        }


# -- scope ---------------------------------------------------------------------------------------


@dataclass
class _Scope:
    journals: list[dict[str, Any]]
    expected: list[Expected]
    unretained: int


def collect_expected(
    campaign: LoadedCampaign, journals: Sequence[Path], *, limits: ReaderLimits = DEFAULT_LIMITS
) -> tuple[list[dict[str, Any]], list[Expected], int]:
    """The scope entries, every expected retained proof (Ref order) and the unretained count.

    Each journal is read completely with the certifier's record rules; a journal given twice
    (same header ID) is an InputError ``verify.journals``.
    """
    scope = _Scope([], [], 0)
    seen: dict[str, Path] = {}
    for path in sorted({Path(p) for p in journals}, key=os.fspath):
        _read_journal(path, campaign, limits, scope)
        ident = scope.journals[-1]["id"]
        if ident in seen:
            raise InputError(
                "verify.journals", f"{path} and {seen[ident]} are copies of journal {ident}"
            )
        seen[ident] = path
    scope.journals.sort(key=lambda j: j["id"])
    scope.expected.sort(key=lambda e: e.record.sort_key)
    return scope.journals, scope.expected, scope.unretained


def _read_journal(
    path: Path, campaign: LoadedCampaign, limits: ReaderLimits, scope: _Scope
) -> None:
    policy: Policy | None = None
    ident: str | None = None
    try:
        stream = path.open("rb")
    except OSError as error:
        raise InputError("journal.file", f"{path}: {error.strerror or error}") from None
    with stream:
        reader = JournalReader(stream, validator_of(campaign), name=path.name, limits=limits)
        for record in reader:
            payload = record.payload
            if isinstance(payload, Header):
                ident = record.self_hash
            if isinstance(payload, (Header, Resume)):
                policy = payload.policy
                continue
            if not isinstance(payload, Attempt) or payload.outcome != Outcome.VERIFIED_UNSAT:
                continue
            if payload.retained is None:
                scope.unretained += 1
                continue
            assert ident is not None and policy is not None
            assert payload.proof_bytes is not None and payload.proof_sha256 is not None
            scope.expected.append(
                Expected(
                    record=Ref(ident, record.seq),
                    node=payload.node,
                    cnf_sha256=payload.cnf_sha256,
                    artifact=payload.retained,
                    proof_bytes=payload.proof_bytes,
                    proof_sha256=payload.proof_sha256,
                    policy=policy,
                )
            )
    summary = reader.summary
    scope.journals.append(
        {
            "id": summary.id,
            "worker": summary.worker,
            "records": summary.records,
            "head": summary.head,
            "bytes": summary.bytes,
            "torn_tail_bytes": summary.torn_tail_bytes,
        }
    )


# -- one proof -----------------------------------------------------------------------------------


def _binding_problem(item: Expected) -> str | None:
    wanted = artifact_path(Area.PROOFS, item.node.node_id, item.proof_sha256)
    artifact = item.artifact
    if artifact.path != wanted:
        return f"retained path {artifact.path!r} is not {wanted!r}"
    if (artifact.bytes, artifact.sha256) != (item.proof_bytes, item.proof_sha256):
        return "the retained artifact does not name the record's proof bytes and hash"
    return None


def _stage_proof(  # noqa: PLR0911 - one outcome per check, in order
    root: Path, artifact: Artifact, target: Path
) -> tuple[Status | None, str]:
    """Copy ``root/artifact.path`` to ``target`` while hashing; (None, "") when intact."""
    path = os.fspath(root)
    parts = artifact.path.split("/")
    for index, part in enumerate(parts):
        path = os.path.join(path, part)
        try:
            mode = os.lstat(path).st_mode
        except FileNotFoundError:
            return Status.MISSING, f"{artifact.path} is absent"
        last = index == len(parts) - 1
        if (last and not stat.S_ISREG(mode)) or (not last and not stat.S_ISDIR(mode)):
            return Status.CORRUPT, f"{artifact.path}: a symlink or not a regular file on the way"
    try:
        source = os.open(path, os.O_RDONLY | _NOFOLLOW | os.O_CLOEXEC)
    except FileNotFoundError:
        return Status.MISSING, f"{artifact.path} is absent"
    except OSError as error:
        return Status.CORRUPT, f"{artifact.path}: {error.strerror or error}"
    try:
        info = os.fstat(source)
        if not stat.S_ISREG(info.st_mode) or info.st_size != artifact.bytes:
            return (
                Status.CORRUPT,
                f"{artifact.path}: {info.st_size} bytes, expected {artifact.bytes}",
            )
        digest = hashlib.sha256()
        copied = 0
        with target.open("xb") as sink:
            while chunk := os.read(source, _CHUNK):
                digest.update(chunk)
                sink.write(chunk)
                copied += len(chunk)
                if copied > artifact.bytes:
                    break
    finally:
        os.close(source)
    if (copied, digest.hexdigest()) != (artifact.bytes, artifact.sha256):
        return Status.CORRUPT, f"{artifact.path}: the bytes are not {artifact.sha256}"
    return None, ""


@dataclass
class _Checker:
    binary: PinnedBinary
    supervisor: Supervisor
    memory_bytes: int | None

    def fits(self, policy: Policy) -> ck.Fits:
        memory = self.memory_bytes

        def fits(heap: int, stack: int) -> bool:
            return (
                memory is None
                or ck.checker_memory_bytes(heap, stack, policy.checker_slack_mib) <= memory
            )

        return fits

    def run(
        self, policy: Policy, heap: int, stack: int, cnf: Path, proof: Path, size: int
    ) -> ProcessRun:
        launch = Launch(
            binary=self.binary,
            args=ck.checker_args(heap, stack, os.fspath(cnf), os.fspath(proof)),
            cwd=os.fspath(cnf.parent),
            memory_bytes=ck.checker_memory_bytes(heap, stack, policy.checker_slack_mib),
            deadline_ms=ck.check_time_ms(
                size, policy.checker_time_base_ms, policy.checker_time_per_100mb_ms
            ),
            term_grace_ms=policy.term_grace_ms,
        )
        process = self.supervisor.start(launch)
        while process.run is None:
            self.supervisor.step(_STEP_MS)
        return process.run


def _check(item: Expected, checker: _Checker, cnf: Path, proof: Path) -> tuple[Status, str]:
    policy = item.policy
    heap = ck.initial_heap_mib(item.proof_bytes, policy.heap_fit)
    stack = policy.checker_stack_mib
    fits = checker.fits(policy)
    if heap > policy.checker_max_heap_mib or not fits(heap, stack):
        return Status.EXHAUSTED, "check_memory"
    limits = ArenaLimits(policy.checker_max_heap_mib, policy.checker_max_stack_mib, fits)
    hashes = (file_sha256(os.fspath(cnf)), file_sha256(os.fspath(proof)))
    checks: list[CheckFacts] = []
    while True:
        run = checker.run(policy, heap, stack, cnf, proof, item.proof_bytes)
        checks.append(CheckFacts(run, heap, stack))
        after = (file_sha256(os.fspath(cnf)), file_sha256(os.fspath(proof)))
        failures = [] if after == hashes else [Failure.FILE_CHANGED]
        decision = classify(solve=None, checks=checks, limits=limits, failures=failures)
        if decision.action is Action.RETRY_CHECK:
            assert decision.arena is not None
            heap, stack = decision.arena
            continue
        if decision.action is not Action.RECORD:
            return Status.FAILED, f"unexpected checker state {decision.action.value}"
        outcome, reason = decision.outcome, decision.reason or ""
        if outcome == Outcome.VERIFIED_UNSAT:
            return Status.VERIFIED, ""
        if outcome == Outcome.CHECK_REJECTED:
            return Status.REJECTED, reason
        if outcome == Outcome.EXHAUSTED:
            return Status.EXHAUSTED, reason
        return Status.FAILED, reason


def _verify_one(
    item: Expected, campaign: LoadedCampaign, root: Path, scratch: Path, checker: _Checker
) -> tuple[Status, str]:
    problem = _binding_problem(item)
    if problem is not None:
        return Status.CORRUPT, problem
    proof = scratch / "proof.lrat"
    cnf = scratch / "cube.cnf"
    try:
        status, reason = _stage_proof(root, item.artifact, proof)
        if status is not None:
            return status, reason
        formula = campaign.formula(item.node.formula_sha256)
        with cnf.open("xb") as stream:
            written = write_cube_cnf(formula, item.node.cube, stream)
        if written.sha256 != item.cnf_sha256:
            raise IntegrityError(
                "verify.cnf", f"record {item.record.seq}: the regenerated CNF hash differs"
            )
        return _check(item, checker, cnf, proof)
    except OSError as error:
        return Status.FAILED, f"io: {error.strerror or error}"
    finally:
        for path in (proof, cnf):
            with contextlib.suppress(FileNotFoundError):
                path.unlink()


# -- the command -------------------------------------------------------------------------------


def _inside(inner: Path, outer: Path) -> bool:
    return inner == outer or outer in inner.parents


def _check_directories(request: VerifyRequest, journals: Sequence[Path]) -> tuple[Path, Path]:
    results = Path(request.results).resolve()
    root = Path(request.proofs_root).resolve()
    if not root.is_dir():
        raise ConfigurationError("usage", f"--proofs-root {request.proofs_root} is not a directory")
    if _inside(results, root) or _inside(root, results):
        raise ConfigurationError(
            "verify.results", "the results directory must be separate from the proofs root"
        )
    for journal in journals:
        if _inside(Path(journal).resolve(), results):
            raise ConfigurationError(
                "verify.results", f"input journal {journal} lies in the results directory"
            )
    if (results / _RUN_JOURNAL).exists():
        raise ConfigurationError(
            "verify.results", f"{results} holds a run journal; use a separate results directory"
        )
    work = Path(request.work).resolve()
    if _inside(work, root) or _inside(root, work):
        raise ConfigurationError(
            "verify.work", "the work directory must be separate from the proofs root"
        )
    return results, root


def publish_replacing(path: Path, data: bytes) -> None:
    """Publish ``data`` at ``path`` atomically and durably, replacing an older version (a
    derived report of this command's own results directory, never evidence)."""
    temporary = path.with_name(f".{path.name}.{new_id128()}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    try:
        view = memoryview(data)
        while view:
            view = view[os.write(descriptor, view) :]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, path)
    directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def _exit_code(counts: dict[str, int]) -> int:
    if counts["missing"] or counts["corrupt"] or counts["rejected"]:
        return int(ExitCode.INTEGRITY)
    if counts["failed"]:
        return int(ExitCode.TOOL)
    if counts["exhausted"] or not counts["expected"]:
        return int(ExitCode.OPEN)
    return int(ExitCode.SUCCESS)


def verify_retained(request: VerifyRequest, *, isolation: Isolation | None = None) -> VerifyResult:
    """Run ``verify-retained`` (module doc); the report is published before returning.

    Errors before any check: ConfigurationError (usage, lock, directories), InputError and
    IntegrityError (inputs), ToolError (checker missing, unusable or not admitted; isolation).
    """
    inputs = resolve_inputs(
        campaign=request.campaign,
        journals=request.journals,
        evidence=request.evidence,
        limits=request.limits,
    )
    # unusable inputs and tools are refused before any directory is created
    campaign = load_campaign(inputs.campaign, limits=request.limits)
    results, root = _check_directories(request, inputs.journals)
    binary = PinnedBinary.measure(request.checker)
    if not campaign.campaign.admit.admits_checker(binary.sha256):
        raise ToolError(
            "tool.not_admitted", f"{binary.path} ({binary.sha256}) is not an admitted checker"
        )
    results.mkdir(parents=True, exist_ok=True)
    work = Path(request.work).resolve()
    work.mkdir(parents=True, exist_ok=True)
    with RunLock.acquire(results / LOCK_NAME):
        scope, expected, unretained = collect_expected(
            campaign, inputs.journals, limits=request.limits
        )
        supervisor = Supervisor(isolation if isolation is not None else Isolation.probe())
        checker = _Checker(binary, supervisor, request.memory_bytes)
        scratch = Path(tempfile.mkdtemp(prefix="verify-retained-", dir=work))
        entries: list[dict[str, Any]] = []
        try:
            for item in expected:
                status, reason = _verify_one(item, campaign, root, scratch, checker)
                entries.append(
                    {
                        "record": item.record.to_json(),
                        "node_id": item.node.node_id,
                        "artifact": item.artifact.to_json(),
                        "status": status.value,
                        "reason": reason,
                    }
                )
        finally:
            supervisor.shutdown(grace_ms=1000)
            shutil.rmtree(scratch, ignore_errors=True)
        counts = dict.fromkeys(_COUNTED.values(), 0)
        for entry in entries:
            counts[_COUNTED[Status(entry["status"])]] += 1
        document: dict[str, Any] = {
            "format": REPORT_FORMAT,
            "campaign": campaign.campaign.campaign_id,
            "worker": request.worker,
            "scope": {"journals": scope, "proofs_root": os.fspath(root)},
            "expected": len(entries),
            "found": len(entries) - counts["missing"],
            **counts,
            "unretained": unretained,
            "results": entries,
        }
        path = results / REPORT_NAME
        publish_replacing(path, document_bytes(document))
        return VerifyResult(document, _exit_code({**counts, "expected": len(entries)}), path)
