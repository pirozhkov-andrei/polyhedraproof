"""Retain mode: publication of checked proofs before their record, and restart validation of
committed retained/quarantined references (specification §6.1 step 6, §7.2, §7.3, §7.5, §8.3).

Publication itself is one implementation (``PublishRequest`` executed by the I/O
service, ``tools.artifacts.publish_steps``); this module only decides what is published and
what a result means for the attempt. It never deletes a file: orphan removal is the artifact
reconciliation, which refuses to remove any committed reference.

Retained publication (VERIFIED_UNSAT in retain mode):

- :func:`retain_request` publishes exactly the checked bytes (the sealed proof's size and
  hash, its work path as the source) as ``proofs/<node_id>-<proof_sha256>.lrat``.
- :func:`publication_need` is the disk the copy needs while the source still exists: the
  full proof size on the target storage group in addition to the source's own reservation
  (double occupancy on one shared group, specification §7.2 step 1, §8.3).
- :func:`retain_result` turns the service's answer into :class:`Published` (the artifact the
  record references) or :class:`RetainBlocked`. A blocked retained publication commits **no**
  record (a VERIFIED_UNSAT without ``retained`` would be a silent downgrade): the node stays
  pending, the run stops new work with the diagnostic, the committed evidence is untouched
  and the uncommitted work proof is disposable (specification §7.5 row 1). Exit codes follow
  specification §12.2: a resource block 1, an integrity failure 4, a tool/service failure 5.

Restart recovery (:func:`recover_steps`), under the run lock, before any new work:

1. Every committed attempt must bind its references (:func:`reference_problem`): a retained
   artifact only on a retain-mode VERIFIED_UNSAT and exactly
   ``proofs/<node_id>-<proof_sha256>.lrat`` with the record's ``proof_bytes``; a quarantined
   artifact only on CHECK_REJECTED in a file mode, exactly the ``quarantine/`` name of the
   rejected proof; a retain-mode VERIFIED_UNSAT **without** a retained reference is
   IntegrityError ``retain.unreferenced``. These are decided from the records alone, before
   any file is opened.
2. The artifact reconciliation validates every referenced file (no symlink, regular, size,
   SHA-256); a missing/corrupt one is IntegrityError ``artifact.missing``/``artifact.corrupt``
   and nothing is removed. Only then are unreferenced published files and staging copies
   removed (publications still pending in this session may be protected).

The procedure is idempotent: a second run validates the same references and removes nothing.
"""

from __future__ import annotations

from collections.abc import Collection, Generator, Iterable
from dataclasses import dataclass
from typing import Any

from cubeproof.base.errors import (
    ConfigurationError,
    ContractError,
    CubeproofError,
    IntegrityError,
    ResourceError,
    ToolError,
)
from cubeproof.contracts.enums import Outcome, ProofMode
from cubeproof.contracts.io import (
    MAX_CHUNK_BYTES,
    Area,
    Failure,
    PublishRequest,
    PublishValue,
    artifact_path,
)
from cubeproof.contracts.primitives import is_hash
from cubeproof.contracts.values import Artifact
from cubeproof.evidence.schema import Attempt
from cubeproof.leaf.binding import FileHash
from cubeproof.tools.artifacts import reconcile_steps
from cubeproof.tools.atomic import OS_FILE_CALLS, FileCalls, drive

__all__ = [
    "RETAIN_BLOCKED",
    "RETAIN_BLOCKED_RULE",
    "Published",
    "Recovery",
    "RetainBlocked",
    "committed_references",
    "expected_reference",
    "may_reference",
    "publication_need",
    "publication_request",
    "recover",
    "recover_steps",
    "reference_problem",
    "retain_request",
    "retain_result",
]

#: The diagnostic key of a blocked retained publication.
RETAIN_BLOCKED = "retain_blocked"
#: The rule of the error that ends a run stopped by a blocked retained publication.
RETAIN_BLOCKED_RULE = "retain.blocked"
#: Bounds of diagnostic text (specification §4.8: bounded metadata only).
_TEXT = 300
#: Specification §12.2 exit codes by error kind; any other kind is a tool/service failure (5).
_EXIT = {"resource": 1, "configuration": 3, "integrity": 4}
_ERRORS: dict[str, type[CubeproofError]] = {
    "resource": ResourceError,
    "configuration": ConfigurationError,
    "integrity": IntegrityError,
}
_FILE_MODES = (ProofMode.TRANSIENT, ProofMode.RETAIN)
#: Canonical-JSON fragments (specification §4.1: sorted keys, no spaces, quotes inside strings
#: escaped) of an attempt line that carries or requires a reference: retain mode, a nonnull retained
#: or quarantined field. A nested key of the same name is a harmless false positive.
_REFERENCE_MARKS = (b'"proof_mode":"retain"', b'"retained":{', b'"quarantined":{')


def _bounded(text: str) -> str:
    return text if len(text) <= _TEXT else text[: _TEXT - 3] + "..."


# -- publication -----------------------------------------------------------------------------------


def publication_request(area: Area, node_id: str, proof: FileHash) -> PublishRequest:
    """Publish the checked proof ``proof`` (its work path, size and hash) in ``area``.

    The source must be this node's work proof ``<work>/<node_id>-<attempt_id>.lrat``
    (ContractError ``retain.source`` otherwise): the published name binds the node.
    """
    if not isinstance(proof, FileHash):
        raise ContractError("retain.source", "a publication needs the sealed proof's FileHash")
    if not is_hash(node_id):
        raise ContractError("retain.source", f"{node_id!r} is not a node ID")
    expected = f"{node_id}-{proof.attempt_id}.lrat"
    if proof.path.rsplit("/", 1)[-1] != expected:
        raise ContractError(
            "retain.source", f"{proof.path} is not the work proof {expected} of this attempt"
        )
    return PublishRequest(proof.path, Area(area), node_id, proof.sha256, proof.bytes)


def retain_request(node_id: str, proof: FileHash) -> PublishRequest:
    """The retained publication ``proofs/<node_id>-<proof_sha256>.lrat`` of a checked proof."""
    return publication_request(Area.PROOFS, node_id, proof)


def publication_need(proof_bytes: int, *, source_group: str, target_group: str) -> dict[str, int]:
    """Disk bytes per storage group from the start of the copy until the source is removed.

    The source keeps its size on its group (it stays until the cleanup after the commit) and
    the copy needs the full size on the target group (staging and final name share the
    bytes); one shared group therefore needs twice the size (specification §7.2 step 1, §8.3).
    """
    if type(proof_bytes) is not int or proof_bytes < 0:
        raise ValueError(f"{proof_bytes!r} is not a byte count")
    if source_group == target_group:
        return {source_group: 2 * proof_bytes}
    return {source_group: proof_bytes, target_group: proof_bytes}


@dataclass(frozen=True)
class Published:
    """A durable publication: the artifact the record references (``reused``: it existed)."""

    artifact: Artifact
    reused: bool


@dataclass(frozen=True)
class RetainBlocked:
    """A retained publication that did not complete (module doc): no record, stop new work."""

    kind: str
    rule: str
    detail: str
    fatal: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "detail", _bounded(self.detail))

    @classmethod
    def full(cls, detail: str) -> RetainBlocked:
        """The target storage cannot take the copy (refused before any byte is written)."""
        return cls("resource", "retain.full", detail)

    @classmethod
    def of(cls, failure: Failure) -> RetainBlocked:
        return cls(failure.kind, failure.rule, failure.detail, failure.fatal)

    @property
    def exit_code(self) -> int:
        """Specification §12.2: 1 for a resource block, 4 for integrity, 3 configuration, otherwise
        5."""
        return _EXIT.get(self.kind, 5)

    @property
    def note(self) -> str:
        """One line for the run's notes/status."""
        return _bounded(f"{RETAIN_BLOCKED}: {self.kind} {self.rule}") + (
            f": {self.detail[:90]}" if self.detail else ""
        )

    def diagnostic(self) -> dict[str, Any]:
        return {
            RETAIN_BLOCKED: {
                "kind": self.kind,
                "rule": self.rule,
                "detail": self.detail,
                "fatal": self.fatal,
            }
        }

    def error(self) -> CubeproofError:
        """The error that ends the run after it stopped new work (``retain.blocked``).

        Its class gives the specification §12.2 exit code of :attr:`exit_code` through the command
        layer's mapping: resource 1, configuration 3, integrity 4, anything else 5.
        """
        error_type = _ERRORS.get(self.kind, ToolError)
        return error_type(RETAIN_BLOCKED_RULE, _bounded(f"{self.kind} {self.rule}: {self.detail}"))


def retain_result(
    request: PublishRequest, outcome: PublishValue | Failure
) -> Published | RetainBlocked:
    """What the I/O service's answer to a retained publication means (module doc)."""
    if not isinstance(request, PublishRequest) or request.area is not Area.PROOFS:
        raise ValueError("retain_result answers a retained (proofs/) publication")
    if isinstance(outcome, PublishValue):
        if outcome.artifact != request.artifact:
            raise ContractError(
                "retain.mismatch",
                f"published {outcome.artifact.path}, requested {request.artifact.path}",
            )
        return Published(outcome.artifact, outcome.reused)
    if not isinstance(outcome, Failure):
        raise ValueError(f"{type(outcome).__name__} is not a publication result")
    return RetainBlocked.of(outcome)


# -- committed references ------------------------------------------------------------------------


def expected_reference(area: Area, attempt: Attempt) -> Artifact | None:
    """The artifact ``area`` would hold for this record's proof (None without a proof)."""
    if attempt.proof_sha256 is None or attempt.proof_bytes is None:
        return None
    path = artifact_path(area, attempt.node_id, attempt.proof_sha256)
    return Artifact(path, attempt.proof_sha256, attempt.proof_bytes)


def reference_problem(attempt: Attempt) -> str | None:
    """Why a committed attempt's artifact references do not bind (module doc), or None."""
    retained, quarantined = attempt.retained, attempt.quarantined
    verified_retain = (
        attempt.outcome is Outcome.VERIFIED_UNSAT and attempt.proof_mode is ProofMode.RETAIN
    )
    if retained is not None:
        if not verified_retain or retained != expected_reference(Area.PROOFS, attempt):
            return "retain.reference"
    elif verified_retain:
        return "retain.unreferenced"
    if quarantined is not None:
        rejected = attempt.outcome is Outcome.CHECK_REJECTED and attempt.proof_mode in _FILE_MODES
        if not rejected or quarantined != expected_reference(Area.QUARANTINE, attempt):
            return "quarantine.reference"
    return None


def may_reference(line: bytes) -> bool:
    """Whether a validated canonical journal line can carry or require an artifact reference.

    The startup recovery re-reads the journal prefix that replay validated (under the same run
    lock) and parses only these lines, so a transient journal costs one byte scan. Retained is
    nonnull only in retain mode, so the marks find every record :func:`reference_problem` could
    object to; a false positive only costs a parse.
    """
    return any(mark in line for mark in _REFERENCE_MARKS)


def committed_references(attempts: Iterable[Attempt]) -> tuple[Artifact, ...]:
    """Every artifact referenced by the committed attempts, once per path, sorted by path.

    IntegrityError (the rule of :func:`reference_problem`) if any record does not bind.
    """
    found: dict[str, Artifact] = {}
    problems: dict[str, list[str]] = {}
    for attempt in attempts:
        if not isinstance(attempt, Attempt):
            raise ValueError("committed references are read from Attempt records")
        problem = reference_problem(attempt)
        if problem is not None:
            problems.setdefault(problem, []).append(attempt.attempt_id)
            continue
        for artifact in (attempt.retained, attempt.quarantined):
            if artifact is None:
                continue
            known = found.setdefault(artifact.path, artifact)
            if known != artifact:  # one name, two sizes: the records contradict each other
                problems.setdefault("retain.reference", []).append(attempt.attempt_id)
    for rule in sorted(problems):
        ids = problems[rule]
        more = f" and {len(ids) - 10} more" if len(ids) > 10 else ""
        raise IntegrityError(rule, f"committed attempts {', '.join(ids[:10])}{more}")
    return tuple(found[path] for path in sorted(found))


# -- recovery ------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Recovery:
    """Validated retained/quarantined references and the removed orphans (relative paths)."""

    retained: int
    quarantined: int
    removed: tuple[str, ...]


def recover_steps(
    root: str,
    attempts: Iterable[Attempt],
    *,
    protected: Collection[str] = (),
    calls: FileCalls = OS_FILE_CALLS,
    chunk_bytes: int = MAX_CHUNK_BYTES,
) -> Generator[None, None, Recovery]:
    """Restart recovery of the artifact areas below ``root`` (module doc), in bounded steps."""
    references = committed_references(attempts)
    value = yield from reconcile_steps(
        root, references, protected=protected, calls=calls, chunk_bytes=chunk_bytes
    )
    retained = sum(1 for a in references if a.path.startswith(f"{Area.PROOFS.value}/"))
    return Recovery(retained, len(references) - retained, value.removed)


def recover(
    root: str,
    attempts: Iterable[Attempt],
    *,
    protected: Collection[str] = (),
    calls: FileCalls = OS_FILE_CALLS,
    chunk_bytes: int = MAX_CHUNK_BYTES,
) -> Recovery:
    """:func:`recover_steps` run to its end."""
    return drive(
        recover_steps(root, attempts, protected=protected, calls=calls, chunk_bytes=chunk_bytes)
    )
