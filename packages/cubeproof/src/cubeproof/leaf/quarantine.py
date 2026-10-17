"""Bounded quarantine of rejected file proofs (specification §4.8, §6.1 step 6, §7.2, §8.3).

A CHECK_REJECTED attempt in a file mode (transient or retain) may keep its rejected proof as
``quarantine/<node_id>-<proof_sha256>.lrat``, published through the single publication
**before** the record is committed. The record is committed in every case: with the
quarantined reference after a successful publication, otherwise with ``quarantined: null``
and the reason in the diagnostics (``quarantine_unavailable``). Quarantine never blocks the
run and never deletes anything to make room (no deletion path exists here; retained proofs
are not quarantine files at all).

The quota (``policy.quarantine_quota_bytes``) is kept by :class:`QuarantineLedger`. It counts

- committed quarantine files (from replay; one file per path),
- pending copies (reserved before the publication is submitted; specification §8.3 "quarantine quota
  includes pending copies"),
- copies published in this session that no committed record references (an attempt that
  ended without a record): they stay on disk until the startup reconciliation removes them,
  so their bytes are released only by that removal (specification §7.2 step 5), i.e. by a new
  ledger.

Reservation lifetime of one attempt: :meth:`QuarantineLedger.reserve` -> the publication
result -> :meth:`~QuarantineLedger.published` or :meth:`~QuarantineLedger.failed` (the publication
removed its staging copy) -> after the record :meth:`~QuarantineLedger.committed`, or
:meth:`~QuarantineLedger.abandoned` if no record follows.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from cubeproof.base.errors import ContractError
from cubeproof.contracts.enums import Outcome, ProofMode
from cubeproof.contracts.io import Area, Failure, PublishRequest, PublishValue, artifact_area
from cubeproof.contracts.primitives import is_id128
from cubeproof.contracts.values import Artifact
from cubeproof.evidence.schema import Attempt
from cubeproof.leaf.binding import FileHash
from cubeproof.leaf.retain import publication_request

__all__ = [
    "CONFLICT",
    "IO",
    "NOT_SUPPORTED",
    "NO_SPACE",
    "QUOTA",
    "SOURCE_CHANGED",
    "QuarantineLedger",
    "Quarantined",
    "Unavailable",
    "decide",
    "quarantine_applies",
    "quarantine_request",
    "quarantine_result",
]

#: Reasons recorded under ``quarantine_unavailable``.
QUOTA = "quota"
NO_SPACE = "no_space"
CONFLICT = "conflict"
SOURCE_CHANGED = "source_changed"
IO = "io"
NOT_SUPPORTED = "not_supported"

_TEXT = 300
_BY_RULE = {
    "io.no_space": NO_SPACE,
    "artifact.conflict": CONFLICT,
    "io.source_changed": SOURCE_CHANGED,
    "io.hash_mismatch": SOURCE_CHANGED,
    "io.source": SOURCE_CHANGED,
}


def _bounded(text: str) -> str:
    return text if len(text) <= _TEXT else text[: _TEXT - 3] + "..."


def quarantine_applies(mode: ProofMode, outcome: Outcome) -> bool:
    """Specification §4.8: quarantined only for CHECK_REJECTED in the file modes."""
    return Outcome(outcome) is Outcome.CHECK_REJECTED and ProofMode(mode) in (
        ProofMode.TRANSIENT,
        ProofMode.RETAIN,
    )


def quarantine_request(node_id: str, proof: FileHash) -> PublishRequest:
    """The publication ``quarantine/<node_id>-<proof_sha256>.lrat`` of a rejected proof."""
    return publication_request(Area.QUARANTINE, node_id, proof)


@dataclass(frozen=True)
class Quarantined:
    """The quarantined artifact the CHECK_REJECTED record references."""

    artifact: Artifact
    reused: bool


@dataclass(frozen=True)
class Unavailable:
    """No quarantine for this attempt: the record carries null plus this reason."""

    reason: str
    rule: str | None = None
    detail: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "detail", _bounded(self.detail))

    def diagnostics(self) -> dict[str, Any]:
        """The record diagnostics (merged into the attempt's diagnostics by the caller)."""
        value: dict[str, Any] = {"quarantine_unavailable": self.reason}
        if self.rule is not None:
            value["quarantine_error"] = {"rule": self.rule, "detail": self.detail}
        elif self.detail:
            value["quarantine_detail"] = self.detail
        return value


def quarantine_result(
    request: PublishRequest, outcome: PublishValue | Failure
) -> Quarantined | Unavailable:
    """What the I/O service's answer to a quarantine publication means.

    Any failure is "unavailable" with a reason by its rule (no space, conflicting artifact,
    changed source, otherwise ``io``); the CHECK_REJECTED record is still committed. A fatal
    failure stops the attempt before this is asked (specification §8.1: no further record from it).
    """
    if not isinstance(request, PublishRequest) or request.area is not Area.QUARANTINE:
        raise ValueError("quarantine_result answers a quarantine publication")
    if isinstance(outcome, PublishValue):
        if outcome.artifact != request.artifact:
            raise ContractError(
                "quarantine.mismatch",
                f"published {outcome.artifact.path}, requested {request.artifact.path}",
            )
        return Quarantined(outcome.artifact, outcome.reused)
    if not isinstance(outcome, Failure):
        raise ValueError(f"{type(outcome).__name__} is not a publication result")
    return Unavailable(_BY_RULE.get(outcome.rule, IO), outcome.rule, outcome.detail)


@dataclass
class _Reservation:
    artifact: Artifact
    bytes: int
    published: bool = False


class QuarantineLedger:
    """Quarantine bytes against the quota (module doc). Never deletes anything."""

    def __init__(self, quota_bytes: int, committed: Iterable[Artifact] = ()) -> None:
        if type(quota_bytes) is not int or quota_bytes < 0:
            raise ValueError(f"{quota_bytes!r} is not a quota in bytes")
        self.quota_bytes = quota_bytes
        self._committed: dict[str, int] = {}
        self._pending: dict[str, _Reservation] = {}
        self._orphans: dict[str, int] = {}
        for artifact in committed:
            self._check_artifact(artifact)
            self._committed[artifact.path] = artifact.bytes

    @classmethod
    def from_attempts(cls, quota_bytes: int, attempts: Iterable[Attempt]) -> QuarantineLedger:
        """The ledger of a session start: the quarantined files of the committed records."""
        return cls(quota_bytes, (a.quarantined for a in attempts if a.quarantined is not None))

    # -- amounts -------------------------------------------------------------------------------

    @property
    def committed_bytes(self) -> int:
        return sum(self._committed.values())

    @property
    def pending_bytes(self) -> int:
        return sum(r.bytes for r in self._pending.values())

    @property
    def orphan_bytes(self) -> int:
        return sum(self._orphans.values())

    @property
    def used_bytes(self) -> int:
        return self.committed_bytes + self.pending_bytes + self.orphan_bytes

    @property
    def available_bytes(self) -> int:
        return max(0, self.quota_bytes - self.used_bytes)

    # -- one attempt's reservation ---------------------------------------------------------------

    def reserve(self, attempt_id: str, artifact: Artifact) -> Unavailable | None:
        """Reserve the copy of ``artifact`` for ``attempt_id``; None when granted.

        A path already committed (or published in this session) needs no new bytes: the publication
        reuses an equal file without copying. Otherwise the full size counts until the
        publication's outcome is known.
        """
        if not is_id128(attempt_id):
            raise ContractError("quarantine.attempt", f"{attempt_id!r} is not an Id128")
        if attempt_id in self._pending:
            raise ContractError("quarantine.attempt", f"attempt {attempt_id} already reserved")
        self._check_artifact(artifact)
        on_disk = artifact.path in self._committed or artifact.path in self._orphans
        need = 0 if on_disk else artifact.bytes
        if need > self.available_bytes:
            return Unavailable(
                QUOTA,
                None,
                f"quarantine quota: {self.available_bytes} bytes available, {need} needed",
            )
        self._pending[attempt_id] = _Reservation(artifact, need)
        return None

    def published(self, attempt_id: str) -> None:
        """The copy is durable under its final name (the record will reference it)."""
        self._reservation(attempt_id).published = True

    def failed(self, attempt_id: str) -> None:
        """The publication failed without a durable copy (the publication removed its staging
        file)."""
        reservation = self._reservation(attempt_id)
        if reservation.published:
            raise ContractError("quarantine.attempt", f"attempt {attempt_id} was published")
        del self._pending[attempt_id]

    def committed(self, attempt_id: str) -> None:
        """The record referencing the published copy is durable."""
        reservation = self._reservation(attempt_id)
        if not reservation.published:
            raise ContractError("quarantine.attempt", f"attempt {attempt_id} is not published")
        del self._pending[attempt_id]
        artifact = reservation.artifact
        self._orphans.pop(artifact.path, None)
        self._committed[artifact.path] = artifact.bytes

    def abandoned(self, attempt_id: str) -> None:
        """No record follows. A published copy stays counted until reconciliation removes it."""
        reservation = self._pending.pop(attempt_id, None)
        if reservation is None:
            return
        artifact = reservation.artifact
        if reservation.published and artifact.path not in self._committed:
            self._orphans[artifact.path] = artifact.bytes

    # -- helpers ---------------------------------------------------------------------------------

    def _reservation(self, attempt_id: str) -> _Reservation:
        reservation = self._pending.get(attempt_id)
        if reservation is None:
            raise ContractError("quarantine.attempt", f"attempt {attempt_id} has no reservation")
        return reservation

    @staticmethod
    def _check_artifact(artifact: Artifact) -> None:
        if (
            not isinstance(artifact, Artifact)
            or artifact_area(artifact.path) is not Area.QUARANTINE
        ):
            raise ContractError("quarantine.artifact", f"{artifact!r} is not a quarantine file")


def decide(
    ledger: QuarantineLedger,
    attempt_id: str,
    node_id: str,
    proof: FileHash,
    *,
    mode: ProofMode,
    outcome: Outcome,
) -> PublishRequest | Unavailable:
    """The quarantine step of a rejected attempt: a reserved publication or null plus reason."""
    if not quarantine_applies(mode, outcome):
        raise ValueError(f"{Outcome(outcome).value} in {ProofMode(mode).value} is not quarantined")
    if proof.attempt_id != attempt_id:
        raise ContractError("quarantine.attempt", "the proof belongs to another attempt")
    request = quarantine_request(node_id, proof)
    refused = ledger.reserve(attempt_id, request.artifact)
    return request if refused is None else refused
