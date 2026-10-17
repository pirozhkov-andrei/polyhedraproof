# Trust and evidence

The end-to-end claim has three obligations: the article's mathematical reduction
(paper: cor:conditional), the exhaustive list of 59 maps (paper: thm:59), and checked
refutations that cover every one of the 59 formulas (paper: thm:coverage, cor:treecover).
**The complete computation has not been carried out.** [CLAIMS](CLAIMS.md) records evidence for
individual obligations; [STATUS](../STATUS.md) says what is tested and what has not been
done; [AUDITING](AUDITING.md) gives the verification procedure. This page explains what
each piece of evidence establishes and what it does not; the normative statement of the
guarantees and of the threat model is in the [SPECIFICATION](SPECIFICATION.md)
(SPECIFICATION §1.4, §5).

## What establishes a leaf

A *leaf* is one cube of a formula, with its regenerated CNF: the formula's bytes plus one
unit clause for each literal of the cube, in canonical order. A leaf is *verified* only
when all of this holds for one attempt:

- the CNF written for the attempt hashes to the digest computed independently from the
  verified bundle, and both files are unchanged after the check;
- the pinned checker cake_lpr exits 0 and its complete standard output is exactly
  `s VERIFIED UNSAT` and a line feed;
- for a solver proof, the solver exited with status 20 and the proof is complete (in stream
  mode the relay reports end of input, every byte written, and no error).

Before a worker or an audit records anything, the checker must answer four questions with
known answers, one refutation to accept and three to reject (SPECIFICATION §7.3); a program that
accepts a wrong proof on that machine is stopped before it can close a leaf. The control is a
sanity check of the installation, not evidence of correctness.

CaDiCaL proposes proofs; its answer alone is never evidence. A leaf that unit propagation
already refutes gets a small proof written by the package (route `unit`); it goes through the
same checker. A faulty proof generator can therefore cause a rejection, not a
false refutation. A checker that is killed, runs out of memory, or prints the success line
together with an exhaustion message is not an acceptance.

The checker's formal guarantee has execution assumptions about the operating system, the
files and the hardware; see [SOURCES](SOURCES.md). The small C layer through which the
verified machine code reads its files, the relay that carries a streamed proof, and the
package's own proof route for unit refutations lie outside that theorem. The images pin the
sources and record the hashes of the binaries that ran ([RELEASE](RELEASE.md)); recording a
binary does not re-prove it.

A leaf says that a cube is unsatisfiable together with the formula. The mathematical
reduction, the encoding, the coverage of a formula by cubes and the classification of the
maps are separate obligations. Exact geometric controls, finite tests and two references
support the implementation. The reference encoder of the package tests shares numbering and
sign conventions with the encoder, so agreement with it cannot exclude a common convention
error. The reference of `tests/reference` was written from the article's text without those
conventions: it compares the substantive clauses of each of the 59 formulas with the ones the
article prescribes, shows that the rest are definitions that forbid nothing, and checks the
variables against geometry on random planes and on genuine realizations with four and seven
faces. A clause the article does not prescribe fails there even when the pinned hashes were
changed with it. Neither tests nor AI-assisted reviews replace mathematical proof or human
review.

## Identities

| Name | Identifies |
|---|---|
| `formula_sha256` | The exact canonical DIMACS bytes of a formula. Identity is by bytes, not by logical equivalence |
| `node_id` | A formula and a cube; the cube is sorted by variable, so the way it was reached does not matter |
| `split_id` | A cube and the ordered variables on which it is split |
| `cnf_sha256` | The formula plus the units of one cube, in canonical order |
| `proof_sha256` | The proof bytes that were checked |
| campaign ID | The hash of the campaign document: formulas, requested roots, root splits, policy, pinned tools and admission |
| Ref | `(journal ID, seq)`: one record of one journal |
| certificate | The certificate document: the campaign, the exact journal prefixes it used (ID, record count, head, byte length), the used leaves, per-formula summaries with Merkle roots, models, anomalies and the verdict |

The hashes of the formulas of the 59 maps are pinned in
`packages/neighbourly/src/neighbourly/data/n12/formula_hashes_n12.json`. The unit clauses of
a leaf CNF are sorted by variable, whatever the order in which a split chose its variables,
so a cube has one CNF and one `cnf_sha256` (SPECIFICATION §3.3,
[decision 0010](decisions/0010-cube-evidence-graph.md)).

## From leaves to a formula

Evidence is a graph of cubes, not a fixed partition. A cube is *closed* when it has a
verified leaf attempt or a recorded split all of whose children are closed. A formula is
proved when its **empty** cube is closed. Closing a nonempty requested root (a pilot root)
settles only that region and leaves the formula open (paper: rem:pilotroot). The certifier
selects the evidence deterministically: among the
alternatives for a closed cube it takes the verified attempt with the smallest Ref, otherwise
the closed split with the smallest `split_id`, so duplicate work, alternative splits and the
order of the input files cannot change the result
([decision 0010](decisions/0010-cube-evidence-graph.md)). The argument that a closed tree
refutes its root is in the article (paper: thm:coverage, lem:closure); it is a written
proof, and the software only implements its premises.

`cubeproof certify` returns one of four verdicts. `PROVED`: every campaign formula's empty
cube is closed and no valid model exists. `MODEL_FOUND`: a valid model exists. `OPEN`:
neither. `INCONSISTENT`: a formula is both modelled and closed, which means that the
computation contradicts itself, and it exits with an integrity failure. A model is a Boolean
assignment of necessary conditions; it is not automatically a geometric realization
(paper: rem:noconverse).

## What a journal and a certificate attest

A journal is an append-only file of canonical JSON lines. Each record carries its own hash
(`self`), the hash of the previous record (`prev`) and a contiguous sequence number. A
record of a verified leaf states that a checker accepted a proof with a given hash for a
CNF with a given hash. A certificate is a recomputed summary of such statements. Be exact
about the limits (paper: rem:attestation):

- The chain detects accidental edits and reordering. It is not a signature: it cannot
  authenticate who wrote a record, detect a removed tail by itself, or prevent wholesale
  replacement. Removal of complete trailing records is detected only against an
  independently kept head and length, which the exports, the evidence packages and the
  certificate provide ([decision 0016](decisions/0016-self-checksummed-journals.md)).
- Admission is a filter on the recorded machinery: a record counts when its checker hash
  (and, if the campaign lists solvers, its solver hash and arguments) is admitted. Source
  hashes and limits are reported provenance, not filters. A dishonest or faulty writer that
  records admitted tool hashes is not made authentic by them: the certifier cannot know that
  the checker actually ran
  ([decision 0013](decisions/0013-admission-and-guarantees.md)). A version of the writer
  that is found to be faulty has to be named with any published result, and the leaves it
  wrote rechecked independently (SPECIFICATION §10.1).
- Which checkers a campaign admits is the campaign's own statement: the certifier believes a
  listed hash whatever program it stands for. The application closes that gap for the 59
  formulas. The SHA-256 of the cake_lpr binary of the release image is recorded in
  `faces12_campaign.pins`; `campaign init` refuses another checker unless told otherwise, and
  `faces12-campaign claim` refuses a campaign that configures or admits another one unless the
  operator accepts it by its hash, names every checker in its statement, and requires the
  review to name them (SPECIFICATION §13.3). The pin identifies a build; the correctness of
  cake_lpr remains the theorem of its authors ([SOURCES](SOURCES.md)).
- Two certifiers exist: `cubeproof certify` and the independently written
  `tools/certify_min.py`, which imports nothing from the project. They are required to agree
  on the certificate bytes, the used attempts, the open lists, the verdict and the Merkle
  roots. Agreement shows that closure was evaluated the same way twice; it is not evidence
  that the journals are honest.
- Anomalies (a model that is not one, a rejected proof) do not invalidate an otherwise
  complete proof tree, but they stay in the certificate and must be resolved explicitly in
  the claim review before an application claim is made ([COMPUTE](COMPUTE.md)).
- The state cache, the derived models, `status.json` and the exports are not evidence.
  Neither certifier reads the cache.

The threat model is a trusted operating system, hardware and file system, and an immutable,
correctly identified tool installation. Tools may be wrong; hostile processes of the same
user that rewrite input files or binaries during an attempt are outside it (pre- and
post-hashes and per-attempt paths detect ordinary misbinding, and `chmod` is not a sandbox).
Protection against hostile workers would need proof retention or independent recomputation,
and a separate isolation and authentication design.

## Verifying independently of the journals

Two routes exist, both checked by a person who holds the evidence, not by the writer:

1. **Check retained proofs.** In `retain` mode the checked proof is kept under the results
   directory, published durably before its record is committed. `cubeproof verify-retained`
   regenerates every CNF, matches the hashes and has cake_lpr check each proof without a
   solver. A partial set of proofs verifies only what it contains.
2. **Recompute leaves.** `cubeproof audit` binds the exact journal prefixes the certificate
   names, recomputes the certificate, then regenerates selected leaves and checks the new
   proofs again. It reports each target as `HASH_MATCHED` (same execution profile, same proof
   bytes), `REPROVED_UNSAT` (a new checked proof under another profile; a different
   guarantee), `MISMATCH`, `NOT_COMPARABLE`, `OPEN` or `FAILED`. Only an audit in which every
   selected target is `HASH_MATCHED` exits 0, and a `--sample` verifies only its sample.
   [AUDITING](AUDITING.md) explains the choices.

A campaign keeps no proofs in `transient` mode (the default) or `stream` mode: retaining every
proof can dominate storage, and the full campaign's storage requirement is unmeasured ([decision 0011](decisions/0011-three-proof-modes.md)).
Strict reproduction rests on determinism of the pinned CaDiCaL under one execution profile.
It is tested on the small workloads of the test-image tier, in file and stream modes
([STATUS](../STATUS.md)), and is not a theorem for other versions or platforms. A strict
audit that does not reproduce a proof reports `MISMATCH`, which has to be explained before
the campaign is relied on; a new proof under another profile is reported separately as a
reproof (SPECIFICATION §11.3).

## What is not claimed

- No nonexistence result. The campaign has not been run for the 59 formulas
  ([STATUS](../STATUS.md)).
- No claim that a sample audit verifies unsampled leaves, that a journal is authentic, or
  that a bounded run which leaves a formula open says anything about satisfiability.
- No cost figure for the computation over the 59 formulas ([STATUS](../STATUS.md)).
- No security against hostile workers (above).
