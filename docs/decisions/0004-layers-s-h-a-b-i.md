# 0004. The published formula uses S, H, A, B and I

## Context

A fixed encoding gives reviewers and workers one formula identity per map.
Additional constraints require proofs of necessity; omitting constraints may
make refutation harder.

## Decision

The full formula consists of layers S, H, A, B and I, plus the symmetry gauge
(paper: def:formula). Each layer has a stated mathematical justification. The encoding
is `neighbourly.encoding`, emitting through `neighbourly.cnf`; the 59 base formulas are
fixed byte for byte ([0003](0003-identity-by-hash.md)).

## Consequences

Layer selections support diagnostics; a campaign of the 59 formulas uses the full
formula. No claim of optimality is made; a change of encoding needs a proof of necessity
for every added clause and gives new formula hashes.
