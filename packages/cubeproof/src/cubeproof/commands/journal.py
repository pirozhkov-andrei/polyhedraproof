"""``journal verify`` and ``journal repair`` (specification §7.1, §12.1).

Both take the journal and the **campaign** it belongs to: the record rules need the campaign's
formulas (V per formula), and a journal is validated with the campaign context or not at all
(``RecordSequence(context=JournalContext(...))``, never ``None``).

``verify`` reads the whole file with the certifier's own record rules (:func:`validator_of`), takes
no lock and writes nothing: a live worker may be appending, and a suffix without LF is reported as
the torn tail it may be. ``repair`` removes **only** a torn tail and records the removal
(specification §7.1); it takes the containing results directory's ``run.lock`` without waiting and
so refuses a live coordinator (ConfigurationError ``run.locked``, exit 3). Any other damage is an
integrity error that leaves the file unchanged.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cubeproof.base.errors import ConfigurationError, InputError
from cubeproof.base.settings import DEFAULT_LIMITS, ReaderLimits
from cubeproof.cnf.campaign import load_campaign
from cubeproof.coordinator.layout import LOCK_NAME
from cubeproof.coordinator.replay import validator_of
from cubeproof.evidence.journal import RunLock, read_journal, repair_journal

__all__ = ["JournalReport", "RepairReport", "journal_repair", "journal_verify"]


@dataclass(frozen=True)
class JournalReport:
    """The validated journal: its identity, extent and torn tail (``journal verify``)."""

    path: str
    id: str
    worker: str
    purpose: str
    records: int
    bytes: int
    head: str
    torn_tail_bytes: int

    @property
    def exit_code(self) -> int:
        """Specification §12.2: a journal that validates completely is a completed success (0); the
        torn tail, if any, is reported (``repair`` removes it)."""
        return 0

    def to_json(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "id": self.id,
            "worker": self.worker,
            "purpose": self.purpose,
            "records": self.records,
            "bytes": self.bytes,
            "head": self.head,
            "torn_tail_bytes": self.torn_tail_bytes,
        }


@dataclass(frozen=True)
class RepairReport:
    """The result of ``journal repair``: what was removed (nothing if no torn tail)."""

    path: str
    removed_bytes: int
    removed_sha256: str | None
    #: the journal after the repair, validated again
    verified: JournalReport

    @property
    def exit_code(self) -> int:
        return 0

    def to_json(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "removed_bytes": self.removed_bytes,
            "removed_sha256": self.removed_sha256,
            "verified": self.verified.to_json(),
        }


def _missing(path: Path) -> InputError:
    return InputError("journal.file", f"{path} is not a journal file")


def journal_verify(
    journal: Path, campaign: Path, *, limits: ReaderLimits = DEFAULT_LIMITS
) -> JournalReport:
    """Validate every complete record of ``journal`` against ``campaign`` (module doc)."""
    path = Path(journal)
    if not path.is_file():
        raise _missing(path)
    loaded = load_campaign(Path(campaign), limits=limits)
    contents = read_journal(path, validator_of(loaded), name=path.name, limits=limits)
    summary = contents.summary
    return JournalReport(
        str(path),
        summary.id,
        summary.worker,
        summary.purpose,
        summary.records,
        summary.bytes,
        summary.head,
        summary.torn_tail_bytes,
    )


def journal_repair(
    journal: Path, campaign: Path, *, limits: ReaderLimits = DEFAULT_LIMITS
) -> RepairReport:
    """Remove a torn tail of ``journal`` under the containing results directory's lock."""
    path = Path(journal).resolve()
    if not path.is_file():
        raise _missing(path)
    loaded = load_campaign(Path(campaign), limits=limits)
    try:
        lock = RunLock.acquire(path.parent / LOCK_NAME)
    except OSError as error:
        raise ConfigurationError(
            "run.access", f"{path.parent / LOCK_NAME}: {error.strerror or error}"
        ) from None
    try:
        outcome = repair_journal(path, validator=validator_of(loaded), run_lock=lock, limits=limits)
        verified = journal_verify(path, campaign, limits=limits)
    finally:
        lock.release()
    return RepairReport(
        str(path),
        0 if outcome is None else outcome.removed_bytes,
        None if outcome is None else outcome.removed_sha256,
        verified,
    )
