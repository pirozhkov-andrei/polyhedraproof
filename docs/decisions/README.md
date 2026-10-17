# Design decisions

These records explain the design and its tradeoffs: each states the context of a decision
of the project, the decision and its consequences. The normative description of
behavior and file formats is the [SPECIFICATION](../SPECIFICATION.md); the overview of the
code is [ARCHITECTURE](../ARCHITECTURE.md).

| Record | Decision |
|---|---|
| [0001](0001-the-article-is-canonical.md) | One canonical mathematical article |
| [0002](0002-the-checker-decides.md) | Only the verified checker closes a case |
| [0003](0003-identity-by-hash.md) | A formula is identified by its hash, not by a version number |
| [0004](0004-layers-s-h-a-b-i.md) | The published formula uses S, H, A, B and I |
| [0005](0005-no-runtime-dependencies.md) | The runtime is the standard library |
| [0006](0006-english-repository.md) | Public documentation is in English |
| [0007](0007-documentation-system.md) | Documentation by task, with generated references |
| [0008](0008-explicit-release-list.md) | A release is built from an explicit list of files |
| [0009](0009-three-distributions.md) | Three distributions, one release train |
| [0010](0010-cube-evidence-graph.md) | A canonical cube evidence graph with a deterministic selected tree |
| [0011](0011-three-proof-modes.md) | Three proof modes; proofs are not stored by default |
| [0012](0012-proof-prefix-and-lookahead.md) | The fixed prefix split is separate from lookahead-v1; choices are recorded |
| [0013](0013-admission-and-guarantees.md) | Checker and optional solver admission; attestation and reproof are different guarantees |
| [0014](0014-offline-shards-and-handoff.md) | Offline shards, an idempotent durable handoff outbox and prefix exports |
| [0015](0015-single-event-loop.md) | One coordinator event loop with supervised, bounded helper processes |
| [0016](0016-self-checksummed-journals.md) | Self-checksummed journals, strict torn-tail recovery, external anchors and snapshots |
