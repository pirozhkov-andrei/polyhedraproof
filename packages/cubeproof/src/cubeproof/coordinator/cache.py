"""The derived state cache (specification §7.3).

``results/state.cache`` is one canonical document ``{format, campaign, head, journal, seq,
sha256, state}``: the cache format version, the campaign, the journal ID (the header's self),
the committed position and the SHA-256 of J(state), where ``state`` is
:meth:`~cubeproof.coordinator.state.ReplayState.export`. It is **derived**: the journal stays
the authority, neither certifier reads it, and startup uses it only for the part of the fold
it can prove equal:

- the file parses as canonical JSON, has exactly these fields and this format version, names
  this campaign, and its checksum is the SHA-256 of its state;
- the state restores (schema, canonical form, root splits of this campaign);
- the journal that startup validates **record by record** has the cached journal ID and the
  cached ``head`` as the ``self`` of the record at the cached ``seq`` (so the cache is a prefix
  of exactly this journal).

Every other case, including any exception while loading, is a miss: the caller replays the
whole journal (``CacheMiss.reason`` says why) and the run goes on. A cache is written
atomically (temporary file, fsync, rename, directory fsync) and only from a state that equals
the committed journal. Writing a cache is an optimisation; a failure to write is reported, never
fatal.
"""

from __future__ import annotations

import contextlib
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cubeproof.base.canonical_json import document_bytes, json_sha256, parse_document
from cubeproof.base.errors import CubeproofError
from cubeproof.base.settings import DEFAULT_LIMITS, ReaderLimits
from cubeproof.coordinator.state import CampaignView, ReplayState, RetryJudge

__all__ = ["CACHE_FORMAT", "CacheHit", "CacheMiss", "load_cache", "write_cache"]

CACHE_FORMAT = "cubeproof-state-cache-1"
_FIELDS = frozenset({"format", "campaign", "journal", "seq", "head", "sha256", "state"})
#: A cache larger than this is not read (a miss): it would take longer than a replay.
MAX_CACHE_BYTES = 1 << 30


@dataclass(frozen=True)
class CacheMiss:
    """No usable cache; ``reason`` is a short diagnostic code."""

    reason: str


@dataclass(frozen=True)
class CacheHit:
    """A restored state at ``(journal, seq, head)``; the caller must still confirm that the
    validated journal has ``head`` as the self of record ``seq``."""

    state: ReplayState
    journal: str
    seq: int
    head: str


class _Miss(Exception):
    """Internal: the cache is not usable, for this reason."""


def _document(path: Path, limits: ReaderLimits) -> dict[str, Any]:
    """The cache document of ``path`` (canonical, with exactly the fields), else :class:`_Miss`."""
    try:
        if os.stat(path).st_size > MAX_CACHE_BYTES:
            raise _Miss("too_large")
        data = path.read_bytes()
    except FileNotFoundError:
        raise _Miss("absent") from None
    except OSError:
        raise _Miss("unreadable") from None
    wide = ReaderLimits(
        line_bytes=limits.line_bytes,
        document_bytes=MAX_CACHE_BYTES,
        depth=limits.depth,
        tail_bytes=limits.tail_bytes,
    )
    try:
        value: Any = parse_document(data, limits=wide)
    except (CubeproofError, RecursionError):
        raise _Miss("not_canonical") from None
    if not isinstance(value, dict) or set(value) != _FIELDS:
        raise _Miss("schema")
    found: dict[str, Any] = value
    return found


def _decode(value: dict[str, Any], view: CampaignView, retry_judge: RetryJudge | None) -> CacheHit:
    if value["format"] != CACHE_FORMAT:
        raise _Miss("format")
    if value["campaign"] != view.campaign_id:
        raise _Miss("campaign")
    state = value["state"]
    seq, head, journal = value["seq"], value["head"], value["journal"]
    try:
        if json_sha256(state) != value["sha256"]:
            raise _Miss("checksum")
        if type(seq) is not int or seq < 0 or not isinstance(head, str):
            raise _Miss("schema")
        restored = ReplayState(view, retry_judge=retry_judge)
        restored.restore(state)
        if (restored.journal_id, restored.seq, restored.head) != (journal, seq, head):
            raise _Miss("position")
    except _Miss:
        raise
    except Exception:
        raise _Miss("state") from None
    return CacheHit(restored, str(journal), seq, str(head))


def load_cache(
    path: Path,
    view: CampaignView,
    *,
    retry_judge: RetryJudge | None = None,
    limits: ReaderLimits = DEFAULT_LIMITS,
) -> CacheHit | CacheMiss:
    """The restored state of the cache file at ``path``, or the reason there is none."""
    try:
        return _decode(_document(path, limits), view, retry_judge)
    except _Miss as miss:
        return CacheMiss(str(miss))


def write_cache(path: Path, state: ReplayState, campaign: str) -> None:
    """Write the cache of ``state`` atomically (module doc); OSError if that fails."""
    if state.journal_id is None or state.head is None or state.seq < 0:
        raise ValueError("there is no committed state to cache")
    exported = state.export()
    document = {
        "format": CACHE_FORMAT,
        "campaign": campaign,
        "journal": state.journal_id,
        "seq": state.seq,
        "head": state.head,
        "sha256": json_sha256(exported),
        "state": exported,
    }
    data = document_bytes(document)
    temporary = path.with_name(path.name + ".tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
    try:
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            view = view[written:]
        os.fsync(descriptor)
    except BaseException:
        os.close(descriptor)
        _discard(temporary)
        raise
    os.close(descriptor)
    try:
        os.rename(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except BaseException:
        _discard(temporary)
        raise


def _discard(path: Path) -> None:
    with contextlib.suppress(OSError):
        os.unlink(path)
