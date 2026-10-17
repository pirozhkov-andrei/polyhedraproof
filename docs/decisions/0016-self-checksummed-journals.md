# 0016. Self-checksummed journals, strict torn-tail recovery, external anchors and snapshots

## Context

A crash can only leave an unterminated last line; everything else is damage that must be
seen, not repaired away. The self hash detects accidental edits of a complete line and the
chain detects reordering and removal inside the file. Neither is a signature: removal of a
complete suffix or replacement of the whole file is detected only against a trusted
external anchor (a published head and length), which exports and evidence manifests
provide.

## Decision

A journal is a file of canonical JSON lines, one flat record per line (the payload fields
sit beside `format, seq, prev, self, type, utc`). Each record carries
`self = SHA256(J(record without self))`, `prev` (the previous record's self, 64 zeros at
seq 0) and a contiguous `seq` from zero. The journal ID is the header's self and the head
is the last complete record's self. Readers validate canonical bytes, schema, self, seq and
prev, in that order.

Only a nonempty suffix without a terminating LF after a valid complete prefix is a torn
tail. A run truncates it under lock, syncs and appends a repair record with its length and
hash; certify ignores it and reports its length as `torn_tail_bytes`. Any complete invalid
line, including the last one, is an integrity error, and no automatic repair discards it.
`journal repair` handles torn tails only and refuses a live coordinator.

One writer owns a journal: append under an exclusive lock, write all bytes on an
append-only descriptor, fsync (and sync the directory on creation), acknowledge only after
durability, and stop on any write failure. Exports read committed prefixes by snapshot
(decision [0014](0014-offline-shards-and-handoff.md)).

Three rules cover sets of journals. A file with no complete line is an input error
(`journal.no_header`) unless the caller excludes it; copies of one journal must be prefixes
of the longest one, which is used once (`journal.fork`); the same worker name with two
journal IDs is an integrity error (`journal.worker`).

## Consequences

- Damage other than a torn tail needs restoration from a backup; the damaged file is
  preserved for investigation.
- Certificates record each journal's ID, record count, head and byte length, so an audit
  binds exactly the certified prefixes and ignores later appends.
