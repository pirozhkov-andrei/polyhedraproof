# 0003. A formula is identified by its hash, not by a version number

## Context

A cube has meaning only relative to its formula. A hash states that exactly; a version
label alongside it adds a second name for the same thing, which can only ever agree with
the hash or contradict it.

## Decision

A formula carries no version label. Bundles, campaigns, journal records and certificates
name it by `formula_sha256`. The hashes of the 59 formulas are pinned in
`data/fixtures/formula_hashes.json` and, with identical bytes, in the package data of
`neighbourly` (`packages/neighbourly/src/neighbourly/data/n12/formula_hashes_n12.json`).
Every document carries a `format` string, which says how the document is shaped, not
what it is about. The further identities are hashes too: node, split, campaign and
certificate ([0010](0010-cube-evidence-graph.md)).

## Consequences

Changing clauses changes the hash, and evidence made under the old bytes stops
matching: bundles, campaigns, journals and certificates alike. That is deliberate:
incompatible evidence is rejected, not silently converted. See
[CONTRIBUTING](../CONTRIBUTING.md).
