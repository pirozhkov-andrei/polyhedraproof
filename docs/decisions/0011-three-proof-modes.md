# 0011. Three proof modes; proofs are not stored by default

## Context

Retaining all proofs can dominate storage: the pilot computation of 1.0.0rc1 wrote 1.2 and
1.4 TB of checked proofs for the formulas of maps 1 and 2, which extrapolates to about 76 TB
for the 59 formulas ([STATUS](../../STATUS.md#the-pilot-computation)). Transient gives a
checked proof per leaf without storing it. Retain adds proof storage for collaborators who
have it, and publishing before recording means that a committed record never points at a
proof that a crash could lose. Stream removes the disk high-water mark of large proofs at the
price of coupling solver and checker time and losing the proof on failure.

## Decision

A campaign policy selects one of three proof modes:

- `transient`: solve once to a per-attempt file on local disk, seal it (read-only, size and
  hash), check the sealed proof with cake_lpr, record the attempt, delete the proof. A
  checker heap or stack exhaustion repeats only the check, on the same sealed proof, with
  the exhausted arena doubled within the configured maxima.
- `retain`: as transient, but the checked proof is published durably as
  `proofs/<node_id>-<proof_sha256>.lrat` (copy to the target filesystem, hash, fsync,
  rename, fsync the directory) **before** the attempt record that references it is
  committed. A rejected file proof may likewise be published to a bounded quarantine before
  its record.
- `stream`: solver, a separate bounded relay process and the checker run coupled through
  pipes; no proof is spooled. The relay counts and hashes the bytes; its hash becomes the
  proof hash only for a complete transfer (solver EOF, all bytes written, no error).
  Quarantine is metadata only: `quarantined` is null with the diagnostic
  `quarantine_unavailable: "stream_not_spooled"`.

Unit-propagation refutations are small files and always use the file protocol, even under
stream; only retain mode retains.

By default a campaign therefore does not keep its LRAT proofs. A journal record states that
cake_lpr accepted a proof, with a given hash, of a cube CNF with a given hash. Anyone can
check that statement again by recomputation (`cubeproof audit`): regenerate the CNF from
the formula and the cube and compare its hash, prove the leaf again, have cake_lpr check
the new proof, and compare its hash with the recorded one.

## Consequences

- `retained` is non-null only for VERIFIED_UNSAT in retain mode and `quarantined` only for
  CHECK_REJECTED in a file mode (rules `attempt.retained`, `attempt.quarantined` of the
  requirement matrix);
  stream partial counts live only in `relay`, never as a complete proof
  (`attempt.stream_proof`).
- A missing or corrupt retained proof is an integrity error for `run` and
  `verify-retained`; it is never silently treated as transient.
- An arena-exhausted stream attempt is recorded as EXHAUSTED; a fresh attempt with a larger
  arena is scheduled only if it fits the maxima and the idle machine, otherwise the node
  is split. There is no infinite retry ladder.
- Recomputing a sample checks the sampled leaves only; only recomputing every leaf
  verifies the computation independently of the original run. A proof hash can be compared
  only under the same solver binary and options; under others a recomputed leaf is
  verified again, not reproduced, and the audit report says which (decision
  [0013](0013-admission-and-guarantees.md)).
- Reproducing a stream rejection is an explicit audit or debug run in a file mode.
