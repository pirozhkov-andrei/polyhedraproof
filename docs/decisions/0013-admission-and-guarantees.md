# 0013. Checker and optional solver admission; attestation and reproof are different guarantees

## Context

A journal is an attestation, not a stored proof, and its hash chain does not authenticate
its writer. Matching a checker hash cannot make a record by a faulty writer authentic, so
the model states exactly what is checked. Closing the vocabularies and fixing which rules
bind which records lets two certifiers agree on every certificate field.

## Decision

An attempt is admitted when, in the machinery snapshot of the latest header or resume
record preceding it in its journal, the checker hash is in the campaign's
`admit.checker_sha256` and, if `admit.solvers` is a list, the solver `{sha256, argv}` is in
that list. `admit.solvers = null` means the solver is not an admission filter; an empty list
is invalid. The unit route uses the same snapshot admission although no solver runs. Source
hashes and limits are reported provenance, not admission filters.

The rules in detail:

- Two levels of checks. Field consistency binds every attempt, admitted or not, and a
  violation is an integrity error (node and CNF hashes recomputed, unique attempt IDs,
  reason/solver/relay/proof/model/retained/quarantined combinations, satisfying MODEL
  assignments). The success conditions (proof fields, last check exit 0 with full stdout
  exactly `s VERIFIED UNSAT\n`, solver exit 20, complete relay transfer) bind only admitted
  VERIFIED_UNSAT records; a non-admitted record that violates them is only listed.
- The `reason` vocabulary is closed: the codes of the outcome table (proof_size, time,
  check_time, check_memory, check_stack, solver_memory; launch, binary_changed, io,
  file_changed, crash, protocol, relay; rejected) and, for INVALID_MODEL, its `model_error`.
- `not_admitted` lists every non-admitted attempt with reason `checker_not_admitted` or
  `solver_not_admitted`. Models and anomalies of non-admitted records still bind.
- Solver argv in the campaign contains `--lrat` and only options (every element starts
  with `-`). The deny list of options that disable proofs or set competing limits for the
  pinned CaDiCaL is tool knowledge and is kept with the solver launch code
  (`cubeproof.tools.solver`, rule `writer.argv_deny_list`).

An audit distinguishes guarantees: `HASH_MATCHED` (same execution profile, same proof
bytes), `REPROVED_UNSAT` (a new checked proof under a different profile), `MISMATCH`,
`NOT_COMPARABLE`, `FAILED` and `OPEN`. Only all selected targets HASH_MATCHED is strict
success; a reprove report says that its guarantee is different.

## Consequences

- Admission cannot repair records: if a writer version is found to be faulty, the leaves
  it recorded have to be recomputed independently.
- A new diagnostic code or admission filter is a specification change with new fixtures.
- A sample audit verifies only its sample; it is never described as full verification.
