# 0012. The fixed prefix split is separate from lookahead-v1; choices are recorded

## Context

A prefix stored in a campaign must be reproducible from its recorded parameters and tool, so the
algorithm behind a name never changes, and improving dynamic selection must not quietly change
stored prefixes. Recording the choices makes wall-clock budgets harmless: hardware-dependent
stopping may choose different split variables, which is allowed because the variables are recorded,
and correctness depends only on the split being well formed (all sign children present).

## Decision

There are two kinds of split selection, and neither is an authority for UNSAT:

- `proof-prefix-v1` is the proof-prefix split: a named, fixed, reproducible algorithm that
  selects an ordered list of K variables (twelve in the default faces12 campaign) for the empty cube of a
  formula. It ranks the variables of a pool by their occurrence counts in the proof
  prefixes of sampled solver runs (after Battleman, Reeves and Heule; see
  [SOURCES](../SOURCES.md)). Its sampling, seeded random profile, clause and unit order in
  heuristic scratch files, single-literal exclusion, proof-prefix counting and tie order are
  part of its definition, as are its parameters (samples 2, addition steps 100000, conflicts
  90000, seed 5, pool `order`; SPECIFICATION §9.2). It runs only at campaign construction,
  and its output is stored as campaign root splits with parameter and tool provenance. Its
  scratch files are not evidence; every leaf attempt uses canonical cube bytes. A case number
  of a prefix designates a sign vector: bit j is the sign of the j-th prefix variable.
- `lookahead-v1` is the dynamic splitter, specified as a deterministic bounded
  algorithm (unit propagation under the parent cube, at most 16 sampled sign children chosen
  by SHA-256, product scores, ties by lowest variable). A native helper and a Python reference
  implement the same algorithm; the helper speaks the frozen `cubeproof-look-request-1` /
  `cubeproof-look-result-1` documents.

Every split actually used, static, proof-prefix or dynamic, is recorded with its ordered
variable list. The coordinator validates a choice before recording it; certification and replay
read the recorded W and never re-run a splitter.

## Consequences

- The algorithm of `proof-prefix-v1` and its parameters are fixed by its name; a different
  rule is a differently named algorithm.
- The prefixes the algorithm selects for maps 1 and 2 are pinned by fixtures
  (SPECIFICATION §9.2); a computed prefix that differs from them is a defect.
- A restricted pool without eligible variables records STUCK(no_eligible_pool); a helper
  timeout or failure falls back to the lowest eligible variables and says so in the
  splitter info.
- Static prefix files (`cubeproof-prefixes-1`) have exactly the shape of campaign root
  splits.
