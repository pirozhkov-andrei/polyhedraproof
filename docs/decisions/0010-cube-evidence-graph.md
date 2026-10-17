# 0010. A canonical cube evidence graph with a deterministic selected tree

## Context

Duplicate and alternative work is normal with offline machines and dynamic splitting. A
graph keyed by canonical cubes absorbs it without any priority between campaign and
journal or between workers, and a fixed selection rule makes two independent certifiers
produce the same used attempts, open lists, verdicts and Merkle roots. Sorting literals by
variable makes a cube's identity independent of the order in which it was reached. The
empty-root rule keeps a closed nonempty requested root (a pilot root) visibly different
from a proof of the formula (paper: rem:pilotroot).

## Decision

Evidence is a graph whose nodes are `(formula_sha256, canonical cube)`. A cube is a list of
literals sorted by variable, each variable at most once; its identity is
`node_id = SHA256("node" NUL formula_sha256 NUL literals)`. A split of a cube is an ordered
list W of 1 to 20 distinct unassigned variables; it has all `2^len(W)` sign children (bit j
of child t gives +W[j] when set) and the identity `split_id = SHA256(J({node_id, variables}))`.
Copies of one split from the campaign and from journals are one split.

A cube's identity does not depend on the order in which the cube was reached: the unit
clauses of a cube CNF are appended in canonical order, sorted by variable, not in the order
in which a prefix selected its variables. Otherwise alternative evidence for the same
region could not be recognized. The 59 base formula byte strings are fixed (decision
[0003](0003-identity-by-hash.md)); a change to any base formula byte is a mathematical
change.

A node is closed if it has an admitted, well-formed VERIFIED_UNSAT attempt, or a
well-formed split all of whose children are closed. Closure is literal: a requested root is
closed only by its own attempt or by a closed split at it, never by a closed ancestor. At
a closed node the certifier selects the smallest admitted verified attempt Ref; otherwise
the smallest closed split_id, recursing in child-index order. The selected subgraph of any
closed root is a complete disjoint proof tree. A formula is proved exactly when its empty
cube is closed; closing a nonempty requested root never proves the formula.

The open frontier is equally deterministic: skip closed nodes, emit a node with a valid
model as `model`, otherwise follow the smallest split_id (even if another split progressed
further), and emit a node without splits. Leaf Merkle roots hash the selected leaves sorted
by node_id with `leaf`/`branch` domain tags; an odd last element is carried up unchanged.

Three further rules make the result unique. Certificate lists are sorted as stated in the
requirement matrix `schemas/cubeproof/v1/requirements.json` (rule `certificate.order`). A campaign
root split must sit at a requested root or at the empty cube (`campaign.root_split_node`). A
journal split with a bad W is ignored and reported as the anomaly `malformed_split` with the first
problem in the order empty, too_long, repeated, out_of_range, in_cube. Malformed inputs, integrity
and resource errors make certify exit 4 without a certificate.

## Consequences

- The coverage argument (a checked leaf refutes its regenerated formula and cube; every
  satisfying assignment of a cube belongs to exactly one sign child) is a statement of the
  article (paper: thm:coverage, lem:closure), not of the software alone.
- Certify exits 0 only for PROVED; a campaign whose nonempty requested root closed still
  exits 1 (OPEN).
- The frozen contract corpus contains the expected certificates for the normative examples
  and for full, incomplete, alternative and malformed split evidence; both certifiers are
  tested against it.
- The open frontier is reproducible, not optimal: it need not minimize remaining work.
