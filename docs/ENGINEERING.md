# Engineering overview

This project connects a mathematical argument to an executable, recoverable proof
workflow. Can twelve flat polygonal faces form a closed surface with every face
touching every other face along an edge? Only the tetrahedron (4 faces) and the
Szilassi polyhedron (7 faces) are known to have this property; twelve faces is the next
case that counting allows, and it is an open question of discrete geometry. Trying
coordinates can find an example; failing to find one cannot establish that none exists.
The article translates the geometric question into 59 finite Boolean problems. A complete
checked refutation of all 59 would settle the stated model.

The delivered work is the reduction, formula generator, verification controls and
computation infrastructure. **The full computation is unfinished**, and no nonexistence
result is claimed. A [pilot computation](../STATUS.md#the-pilot-computation) refuted two
of the 59 formulas in a rehearsal campaign and measured their cost; the cost of the other
57 is an extrapolation. The software separates work completed by a worker, coverage of a
whole formula, and the mathematical conclusion.

## What to inspect in ten minutes

| Engineering question | Design and evidence to inspect |
|---|---|
| How is a domain argument made executable? | Five layers of constraints with exact determinant identities; the [theory map](THEORY_MAP.md) connects article statements to code and tests. Each of the 59 formulas has 5,257 variables and 52,177 clauses. |
| How can a result be checked without trusting the search? | CaDiCaL proposes LRAT proofs; cake_lpr checks them. Two separately implemented certifiers reconstruct coverage. [Trust](TRUST.md) identifies what each check establishes and what remains assumed. |
| How does work survive interruption? | A single journal writer, checksummed records, explicit recovery rules and atomic exports. [Decision 0016](decisions/0016-self-checksummed-journals.md) explains the failure model and the limits of a hash chain. |
| How is computation distributed? | Disjoint shards and durable, idempotent handoff; the evidence records ownership transitions. [Decision 0014](decisions/0014-offline-shards-and-handoff.md) explains the operation without a central service. |
| How are resource failures handled? | CPU, memory and disk reservations, bounded subprocesses, adaptive subdivision and explicit open-work outcomes. See [architecture](ARCHITECTURE.md) and [resource policy](RUNNING.md#the-policy). |
| How are correlated implementation errors addressed? | A separate mathematical encoder checks signs and Boolean identities; exact geometric fixtures exercise realized examples. [Claims](CLAIMS.md) records the tested scope and shared assumptions. |
| How are releases made inspectable? | An explicit file list, pinned external tools, isolated wheel installation, deterministic source bundles and comparisons of two image builds. See the [release procedure](RELEASE.md). |
| Has it run at scale? | The pilot ran one worker with 124 parallel jobs on one machine for 5.5 hours on two formulas: 31,187 leaves, each closed by an LRAT proof that cake_lpr checked (2.57 TB of proofs, checked and deleted), 1,533 adaptive splits, no anomaly. Both certifiers wrote the same certificate, and a strict audit on another machine reproduced all 50 sampled proofs byte for byte. Shards, handoff and several workers were not exercised at that scale. The journal, the certificates and the audit are [published](https://doi.org/10.5281/zenodo.23464843). |

## Code to read first

These files show the main design decisions in the code itself; the first five are under
300 lines each.

| File | What it shows |
|---|---|
| [`neighbourly/encoding/formula.py`](../packages/neighbourly/src/neighbourly/encoding/formula.py) | how one formula is assembled from the five layers and the gauge, each tied to the lemma of the article that justifies it |
| [`cubeproof/tools/checker.py`](../packages/cubeproof/src/cubeproof/tools/checker.py) | the single function that recognizes checker success, and why nothing else may |
| [`cubeproof/tools/known_answer.py`](../packages/cubeproof/src/cubeproof/tools/known_answer.py) | the checker is asked four questions with known answers before its verdicts count |
| [`cubeproof/evidence/journal/chain.py`](../packages/cubeproof/src/cubeproof/evidence/journal/chain.py) | the hash-chained, self-checksummed journal line format |
| [`cubeproof/evidence/certify/closure.py`](../packages/cubeproof/src/cubeproof/evidence/certify/closure.py) | coverage of a formula by a tree of refuted cubes, independent of the order in which evidence arrives |
| [`tools/certify_min.py`](../tools/certify_min.py) | the second certifier: one file, standard library only, written from the specification without reading the first |
| [`tests/reference/`](../tests/reference) | a second encoder written from the article alone, which shows for each of the 59 maps that the formula is the one the article defines |

## Boundaries and tradeoffs

The implementation separates three responsibilities. `neighbourly` translates the
geometry into formulas. `cubeproof` operates on formula bundles and has no dependency
on the polyhedral mathematics. `faces12-campaign` binds these components to the
59 published formulas and controls the application-level claim. Import boundaries
and purity of the certification layers are checked automatically.

Proof storage is an explicit tradeoff. The default `transient` mode checks a proof
and removes it, reducing retained storage but requiring solver recomputation for a
later independent audit. `retain` permits checking the proof again without rerunning
the solver; `stream` avoids a proof file. None removes the need to account for every
case. Extrapolated from the pilot, the full campaign is estimated at about 19,000
core-hours, and about 76 TB if its proofs are retained: an order-of-magnitude estimate.

The project uses a formally verified external checker; the Python application and
the mathematical reduction are not formally verified. A certificate reconstructs
what journals attest. Independent checking of retained proofs or recomputation of
all used leaves addresses a different obligation. A sample audit covers only its
sample. These boundaries are documented rather than hidden behind one success flag.

## Reproduce and review

Start with the [quickstart](QUICKSTART.md): a clean installation, exact self-tests,
formula hashes, then a small complete worker example. The
[full campaign procedure](RUNNING.md#full-campaign-on-one-host) continues from source
and image setup through monitoring, recovery, certification and independent audit.
For code review, [CONTRIBUTING](CONTRIBUTING.md) gives the test tiers;
[STATUS](../STATUS.md) distinguishes implemented behavior from work still outstanding.

Andrei Pirozhkov is the project author and is responsible for the mathematical claims,
architecture, implementation and documentation. The
[AI-use disclosure](../README.md#use-of-generative-ai) describes assistance in the
development process. Upstream solvers, the verified checker and the published
classification are credited separately. Contact:
[pirozhkov.andrey.u@gmail.com](mailto:pirozhkov.andrey.u@gmail.com).
