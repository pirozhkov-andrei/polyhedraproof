"""Worker journals (specification §7.1): chain, bounded reading, anchors, durable append, repair.

- :mod:`.chain`: self/seq/prev/header of complete lines and the record validator protocol.
- :mod:`.reader`: bounded reading of complete lines, torn tails, anchors, snapshots.
- :mod:`.storage`: the single writer, run lock, torn-tail repair and anchor capture.

Records are checked by a validator the caller passes in (``cubeproof.evidence.schema.
RecordSequence``): this layer may not import the record schema (specification §2.3). No tool,
coordinator or process code is reachable from here.
"""

from __future__ import annotations

from cubeproof.evidence.journal.chain import (
    JOURNAL_FORMAT,
    ChainState,
    RecordValidator,
    envelope_ok,
    unsigned_sha256,
)
from cubeproof.evidence.journal.reader import (
    CHUNK_BYTES,
    Anchor,
    ByteSource,
    JournalContents,
    JournalReader,
    JournalSummary,
    drain,
    read_journal,
    read_snapshot,
)
from cubeproof.evidence.journal.storage import (
    OS_CALLS,
    JournalWriteError,
    JournalWriter,
    RepairOutcome,
    RunLock,
    SysCalls,
    capture_anchor,
    repair_journal,
    write_all,
)

__all__ = [
    "CHUNK_BYTES",
    "JOURNAL_FORMAT",
    "OS_CALLS",
    "Anchor",
    "ByteSource",
    "ChainState",
    "JournalContents",
    "JournalReader",
    "JournalSummary",
    "JournalWriteError",
    "JournalWriter",
    "RecordValidator",
    "RepairOutcome",
    "RunLock",
    "SysCalls",
    "capture_anchor",
    "drain",
    "envelope_ok",
    "read_journal",
    "read_snapshot",
    "repair_journal",
    "unsigned_sha256",
    "write_all",
]
