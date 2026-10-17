# 0014. Offline shards, an idempotent durable handoff outbox and prefix exports

## Context

Independent machines of collaborators share no service, and transfer is a user action.
Committing before publishing and embedding the complete shard make every transfer
reconstructible from the journal after a crash. Duplicate work is harmless because the
certifier selects evidence deterministically (decision [0010](0010-cube-evidence-graph.md)),
so the design needs idempotence, not exactly-once delivery.

## Decision

Machines coordinate only through files; there is no network coordination.

- A shard (`cubeproof-shard-1`) names a campaign and a sorted, nonempty list of nodes that
  are pairwise incompatible within each formula. A worker accepts a shard from the command
  line or an atomically published inbox file by committing a shard record before launching
  any of its nodes, then moving the inbox file to `accepted/`. An identical shard is a
  no-op; a shard overlapping the worker's accepted or given-away region is rejected whole.
- Giving work away starts with an immutable handoff request (`cubeproof-handoff-request-1`)
  in the inbox. The coordinator selects up to `node_count` oldest pending frontier nodes,
  commits one handoff record that embeds the request and the complete shard, and only then
  publishes `outbox/<output_name>.json` atomically. After the commit it no longer owns those
  subtrees. Replay publishes the same bytes and never chooses a second node set; zero
  available nodes give `shard = null`, not an empty shard.
- Exports copy a committed journal prefix: `(journal_id, seq, head, byte_offset)` is
  captured under a brief shared lock and the immutable prefix is copied outside it,
  validated, synced and published with its descriptor last. The default interval is 60 s
  plus an export at clean stop.

## Consequences

- A lost or undelivered handoff leaves coverage visibly open; the outbox file stays
  available for retransmission. Work is reclaimed by planning a new worker from the open
  coverage, not by reversing ownership implicitly.
- Exports are backups with the export interval as recovery point, not synchronous
  replication.
- Large node lists are divided into several shards or handoffs so that every journal line
  stays within 8 MiB.
