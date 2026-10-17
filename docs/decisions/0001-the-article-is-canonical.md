# 0001. One canonical mathematical article

## Context

Keeping parallel mathematical specifications makes discrepancies difficult to
detect. Printed numbers also change when statements are inserted. One article
and stable labels give reviewers a clear path from code to its justification.

## Decision

`paper/faces12-en.tex` is the mathematical source of record. Code and documentation
cite its statements by stable labels, such as `(paper: lem:parity)`, rather than
by printed numbers. The statements table of [THEORY_MAP](../THEORY_MAP.md) and the
table of [CLAIMS](../CLAIMS.md) are generated from those labels and the claims ledger
`docs/claims.json`. The rule covers the cube-tree statements of the article as well
(paper: thm:coverage, lem:closure), on which certification rests
([0010](0010-cube-evidence-graph.md)).

## Consequences

A changed statement requires review of dependent code, tests and claims.
`tools/checks/claims_docs.py --check` (part of `make lint`) and
`faces12-campaign release docs --check` fail on a cited label that does not exist in the
article; they check references and do not verify proofs.
