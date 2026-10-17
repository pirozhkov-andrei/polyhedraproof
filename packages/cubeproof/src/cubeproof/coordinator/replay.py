"""Startup replay: validate the journal, rebuild the scheduling state (specification §7.3 steps
1-3).

:func:`replay_journal` reads the worker's journal **record by record through the same validator
as the certifier** (``RecordSequence`` with the certifier's attempt rules: admission-independent
integrity such as the recomputed CNF hash, model evaluation and the success fields), folds the
records into a :class:`~cubeproof.coordinator.state.ReplayState` and collects the committed
artifact references. A complete invalid line anywhere, including the last one, is an
:class:`~cubeproof.base.errors.IntegrityError` and nothing is truncated. A torn suffix (no LF)
is repaired here, under the run lock the caller holds, with ``repair_journal``; the
repair record is then read like any other.

The derived cache (:mod:`.cache`) shortens only the fold: every record is still validated, and
the cached state is accepted only if the validated record at the cached ``seq`` has the cached
``head`` (a prefix of exactly this journal). Otherwise the journal is read again from the
start and the reason is reported.

The result keeps the chain and the validator of the finished read, so that
:class:`~cubeproof.coordinator.tail.JournalTail` continues exactly where the replay stopped.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from cubeproof.base.canonical_json import parse_line
from cubeproof.base.errors import ConfigurationError, CubeproofError, InputError
from cubeproof.base.settings import ReaderLimits
from cubeproof.cnf.campaign import LoadedCampaign
from cubeproof.contracts.enums import Purpose
from cubeproof.contracts.values import Artifact
from cubeproof.coordinator.cache import CacheHit, CacheMiss, load_cache
from cubeproof.coordinator.state import CampaignView, ReplayState
from cubeproof.coordinator.tail import JournalTail
from cubeproof.evidence.certify.admission import AttemptRules
from cubeproof.evidence.certify.inputs import context_of
from cubeproof.evidence.journal import JournalReader, RunLock
from cubeproof.evidence.journal.chain import ChainState
from cubeproof.evidence.journal.storage import repair_journal
from cubeproof.evidence.schema import Attempt, Header, Record, RecordSequence

__all__ = ["Replayed", "check_owner", "peek_header", "replay_journal", "validator_of"]


def validator_of(loaded: LoadedCampaign) -> RecordSequence:
    """A fresh record validator of the campaign with the certifier's attempt rules."""
    formulas = {sha: bundle.formula for sha, bundle in loaded.bundles.items()}
    return RecordSequence(
        context=context_of(loaded), extra=AttemptRules(loaded.campaign.admit, formulas)
    )


@dataclass
class Replayed:
    """The outcome of the replay: the state and where the journal stands."""

    state: ReplayState
    tail: JournalTail | None
    #: the header record, None when there is no journal (a new worker)
    header: Header | None = None
    records: int = 0
    committed: list[Artifact] = field(default_factory=list)
    cache: str = "absent"
    repaired: int = 0


def peek_header(path: Path, limits: ReaderLimits) -> tuple[str, str, str] | None:
    """``(worker, campaign, purpose)`` of the header line, or None if there is no usable one.

    Used only to give "this results directory belongs to another campaign/worker" the exit
    code of a configuration conflict before the (possibly long) validation; an unreadable
    first line is left to the reader, which reports it precisely.
    """
    try:
        with path.open("rb") as stream:
            data = stream.read(limits.line_bytes + 1)
    except OSError:
        return None
    end = data.find(b"\n")
    if end < 0 or end > limits.line_bytes:
        return None
    try:
        value = parse_line(data[:end], limits=limits)
    except CubeproofError:
        return None
    if not isinstance(value, dict) or value.get("type") != "header":
        return None
    worker, campaign, purpose = value.get("worker"), value.get("campaign"), value.get("purpose")
    if not all(isinstance(x, str) for x in (worker, campaign, purpose)):
        return None
    return str(worker), str(campaign), str(purpose)


def check_owner(path: Path, view: CampaignView, worker: str, limits: ReaderLimits) -> None:
    """ConfigurationError ``run.campaign``/``run.worker``/``run.purpose`` when the header line of
    the journal at ``path`` names another campaign or worker or an audit (:func:`peek_header`);
    no journal or an unusable first line passes: the replay decides."""
    header = peek_header(path, limits)
    if header is None:
        return
    owner, campaign, purpose = header
    if campaign != view.campaign_id:
        raise ConfigurationError("run.campaign", f"{path} belongs to another campaign ({campaign})")
    if owner != worker:
        raise ConfigurationError("run.worker", f"{path} belongs to worker {owner}, not {worker}")
    if purpose != Purpose.RUN.value:
        raise ConfigurationError("run.purpose", f"{path} is a {purpose} journal, not a run")


def _read(
    path: Path,
    loaded: LoadedCampaign,
    view: CampaignView,
    limits: ReaderLimits,
    hit: CacheHit | None,
) -> tuple[Replayed, bool]:
    """One pass over the journal; ``confirmed`` is False when a cache hit was not confirmed."""
    validator = validator_of(loaded)
    state = hit.state if hit is not None else ReplayState(view)
    replayed = Replayed(state=state, tail=None)
    confirmed = hit is None
    with path.open("rb") as stream:
        reader = JournalReader(stream, validator, name=path.name, limits=limits)
        for record in reader:
            replayed.records += 1
            _collect(replayed, record)
            if hit is not None and record.seq <= hit.seq:
                if record.seq == hit.seq:
                    confirmed = (
                        record.self_hash == hit.head and reader.chain.journal_id == hit.journal
                    )
                    if not confirmed:
                        # not a prefix of this journal: nothing may be applied to that state
                        return replayed, False
                continue  # the cached state already includes this record
            state.apply(record)
    chain: ChainState = reader.chain
    replayed.tail = JournalTail(path, chain, validator, limits=limits)
    replayed.cache = "used" if hit is not None else "absent"
    return replayed, confirmed


def _collect(replayed: Replayed, record: Record) -> None:
    payload = record.payload
    if isinstance(payload, Header):
        replayed.header = payload
    elif isinstance(payload, Attempt):
        for artifact in (payload.retained, payload.quarantined):
            if artifact is not None:
                replayed.committed.append(artifact)


def replay_journal(
    path: Path,
    loaded: LoadedCampaign,
    view: CampaignView,
    *,
    limits: ReaderLimits,
    cache_path: Path | None,
    lock: RunLock,
    worker: str,
) -> Replayed:
    """Validate and fold the journal at ``path`` (module doc); a new worker gets an empty state.

    ConfigurationError ``run.campaign``/``run.worker``/``run.purpose`` when the journal belongs
    to another campaign, worker or an audit; the reader's errors for a damaged journal.
    """
    if not path.exists() or path.stat().st_size == 0:
        return Replayed(state=ReplayState(view), tail=None, cache="absent")
    check_owner(path, view, worker, limits)
    status = "disabled"
    hit: CacheHit | None = None
    if cache_path is not None:
        found = load_cache(cache_path, view, limits=limits)
        if isinstance(found, CacheHit):
            hit, status = found, "used"
        else:
            assert isinstance(found, CacheMiss)
            status = "absent" if found.reason == "absent" else f"fallback:{found.reason}"
    try:
        replayed, confirmed = _read(path, loaded, view, limits, hit)
    except InputError as error:
        if error.rule == "journal.no_header":
            # An empty file or a torn initial header: nothing was launched before the header
            # (specification §7.1); the I/O service initializes the journal under the same lock.
            return Replayed(state=ReplayState(view), tail=None, cache=status)
        raise
    if hit is not None and not confirmed:
        status = "fallback:position"
        replayed, confirmed = _read(path, loaded, view, limits, None)
    replayed.cache = status
    assert replayed.tail is not None
    torn = _torn_tail(path, replayed.tail.chain.offset)
    if torn:
        outcome = repair_journal(path, validator=validator_of(loaded), run_lock=lock)
        replayed.repaired = 0 if outcome is None else outcome.removed_bytes
        for record in replayed.tail.poll():
            replayed.records += 1
            _collect(replayed, record)
            replayed.state.apply(record)
    return replayed


def _torn_tail(path: Path, offset: int) -> int:
    """Bytes after the last complete line (a torn tail, specification §7.1)."""
    return max(0, os.stat(path).st_size - offset)
