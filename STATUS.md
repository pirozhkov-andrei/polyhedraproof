# Project status

**This is research software for carrying out a computational proof. The complete computation
over the 59 formulas has not been carried out, and no nonexistence result is claimed.** A
Boolean model of a formula would not be a geometric realization, and a timeout, a resource
failure or incomplete coverage settles nothing about the geometric question.

This page states what release 1.0.0 contains and how each part is checked, what the pilot
computation on two of the formulas measured, what has not been done, and the known
limitations. [CLAIMS](docs/CLAIMS.md) lists every claim with its tests and limits;
[TRUST](docs/TRUST.md) explains what each kind of evidence establishes.

## What the release contains

| Part | What it is |
|---|---|
| The article, [`paper/faces12-en.pdf`](paper/faces12-en.pdf) | the reduction of the question to 59 Boolean formulas (paper: cor:conditional), the list of the 59 maps (paper: thm:59), and the statements on which certification of cube trees rests (paper: thm:coverage, lem:closure, cor:treecover, rem:pilotroot, rem:attestation). It is the revision of 17 October 2026, released with 1.0.0rc1 and unchanged since. It was written before the [pilot computation](#the-pilot-computation): its section 11 does not report it, and its sentence "for none of the 59 formulas has a refuted cube tree with the empty root been recorded" predates it |
| `neighbourly` | maps, enumeration, exact geometry, the encoding in layers S, H, A, B, I with the gauge, the interpretation of assignments, the 59 maps with twelve faces and the pinned hashes of their formulas, and the CNF emission module `neighbourly.cnf` |
| `cubeproof` | bundles, campaigns, workers, the three proof modes, splitters, shards and handoff, exports, status, journals, certification, audit, verification of retained proofs, the command line and the API |
| `tools/certify_min.py` | the independent certifier: one file that imports only the standard library |
| `faces12-campaign` | the 59 formulas as bundles, the default campaign, pilot roots, the description of models, the claim gate and the release tools |
| `docker/release/`, `pipeline/` | the release image (`linux/amd64`, pinned CaDiCaL and cake_lpr) and the host wrapper that runs one worker in it |

## Implemented and tested

The checks are grouped in tiers; each tier has one command
([REFERENCE](docs/REFERENCE.md#make-targets)). A tier establishes what its tests check and
nothing more: tests support the implementation, they do not prove the reduction.

| Tier | Command | Needs | What it checks |
|---|---|---|---|
| Static checks | `make lint` | a source checkout, `make install-dev` | style, types (`mypy --strict`), and the consistency of the claims ledger with the code, the tests, the article's labels and the links of the documents |
| Architecture | `make test-architecture` | the same | package boundaries and transitive import rules, the configuration, the release list |
| Fast | `make test-fast` | the same | the fast tests of the three packages and the shared suites (except `tests/architecture` and `tests/release`): the encoding and its exact controls, the bytes of the formulas of maps 1, 2 and 59, cube and split identities, journals, the coordinator with fake tools, certification, audit, the contract corpus on which both certifiers must agree, and the end-to-end suites with fake tools |
| Slow | pytest `--run-slow` | the same; minutes | the census of the maps with twelve faces against the 59 shipped matrices, the bytes of all 59 formulas, the tournament counts for seven elements |
| Installed | `make test-installed` | the same, and network access or a pip cache | wheels and source distributions installed in clean environments outside the checkout |
| Release view | `make test-release-view` | the same | the files named by `RELEASE_FILES.txt`, alone, pass their own fast suites |
| Test image | `make test-all` in the test image (`docker/test/run.sh`) | Docker, `linux/amd64` | everything above and the tests that run the pinned CaDiCaL and cake_lpr |
| Release image | `bash docker/release/validate.sh DIR` | Docker, `linux/amd64`, network at build time | two builds of the release image without cache, the comparison of their recorded hashes, the image's `selfcheck`, the tests of the image and of the wrapper, and a run of two workers in containers of the image with crashes, a handoff, certification and a strict audit |

In the public repository the workflow `.github/workflows/checks.yml` repeats the static
checks, the architecture tier and the fast tier under Python 3.10 and 3.12 on every push to
`main`, every release tag, every pull request and every start by hand, and the test-image tier
on release tags and when started by hand.

Two commands check the mathematical data without any test framework:
`faces12-campaign selftest` (identities on map 1, the 59 maps, the formula of map 1) and
`faces12-campaign formulas --check` (all 59 formulas against their pinned hashes); see
[QUICKSTART](docs/QUICKSTART.md).

## Checked only inside the images

The tiers that run from a source checkout use fake tools wherever a solver or a checker is
needed. The following is exercised only by the test-image and release-image tiers, which need
Docker:

- the behavior of the pinned CaDiCaL and cake_lpr themselves: the acceptance of a leaf by the
  real checker, the stream relay with real tools, the twelve-variable proof-prefix split
  (`proof-prefix-v1`) computed with the real solver;
- the end-to-end workloads with real tools: runs of one and of two workers in every proof
  mode, interruption and recovery, agreement of the two certifiers on their journals, strict
  audits (`HASH_MATCHED`) and the verification of retained proofs. The workloads are small:
  pigeonhole formulas, the encodings of two small maps and a bounded run below one nonempty
  requested root of a twelve-face formula (it leaves that formula open);
- the release image: that it installs only the built wheels, passes its `selfcheck`, that
  two builds give the same tools, helper, sources, wheels, source archive, formulas and
  installed files, and that two workers in its containers, killed and recovered and with a
  handoff between them, end with the same certificate from both certifiers and a passing
  strict audit (`docker/release/validate.sh`);
- the host wrapper against a real Docker engine.

Results of the image tiers are not shipped: whoever relies on an image runs
`docker/release/validate.sh` for that image and keeps its output directory
([RELEASE](docs/RELEASE.md)).

## The pilot computation

Release 1.0.0rc1 was used to refute the formulas of maps 1 and 2, to measure what the
computation of the 59 formulas takes. The campaign, the complete journal, the evidence package,
the certificates, the audit and the logs of the run are published with the commands that check
them: [doi:10.5281/zenodo.23464843](https://doi.org/10.5281/zenodo.23464843).

- **What was run.** A rehearsal campaign of these two formulas alone (`campaign init --maps
  1,2`, campaign ID `fd1e454e…`) with the release image of 1.0.0rc1
  ([doi:10.5281/zenodo.23434450](https://doi.org/10.5281/zenodo.23434450)), the default policy
  and proof mode `transient`. Its requested roots are the empty cubes of the two formulas: it
  has no pilot root. One worker with `--jobs 124` ran one session of 5 h 30 min on 2026-10-18
  on an AWS EC2 `c7a.32xlarge` (2 × AMD EPYC 9R14, 128 cores without SMT, 256 GiB) and ended
  with exit code 0.
- **What it gave.** The certificate is PROVED: both formulas are closed at their empty cube by
  31,187 leaves, each refuted by an LRAT proof that cake_lpr accepted. `cubeproof certify` and
  `tools/certify_min.py` write the same certificate byte for byte (`certificate.json`, SHA-256
  `8f166700…`). Every attempt either closed its leaf or reached its time limit: no model, no
  anomaly, no failed tool, no blocked node. A strict audit of a sample of 50 leaves on another
  machine (a laptop with an AMD Ryzen 7 7840HS), with the same image, reproduced all 50 proof
  hashes (`HASH_MATCHED`); its seed was drawn before the worker started but was not published
  in advance.
- **What it is not.** It is not part of the result. The journal of a rehearsal campaign cannot
  be certified with the campaign of the 59 formulas, and `faces12-campaign claim` refuses a
  campaign that lacks formulas ([RUNNING](docs/RUNNING.md#before-a-campaign-is-created)): the
  two formulas will be computed again in that campaign. The audit verifies the 50 leaves it
  selected; for the others the certificate attests what the journal records (paper:
  rem:attestation).

| | map 1 | map 2 | both |
|---|---|---|---|
| Leaves, each closed by a checked proof | 13,981 | 17,206 | 31,187 |
| Splits of cases that reached their time limit (`lookahead-v1`, 16 subcases each) | 659 | 874 | 1,533 |
| Deepest leaf (literals in its cube) | 32 | 40 | |
| Processor time of the solver and the checker | 300.2 core-hours | 348.3 core-hours | 648.5 core-hours |
| Proofs written, checked and deleted | 1.19 TB | 1.38 TB | 2.57 TB |

Of the 8,192 cases of the two proof prefixes, 7,901 closed at their first attempt. A case that
reaches its time limit (900 s at depth 12, 300 s deeper) costs the whole limit before it is
split: the 1,533 such attempts took 176 of the 648.5 core-hours, the leaves 473. Checking took
about a sixth of the solver time of the leaves. One solver process used at most 166 MiB and one
check at most 1.0 GiB, and every check passed with its first arena. The processor time leaves
out the splitter, the coordinator and `campaign init` (191 s for the two formulas on a laptop);
the 124 jobs were busy 95 % of the 5.5 hours. The journal has 34,255 records, 80 MB.

**An estimate for the 59 formulas.** If the other 57 formulas are like these two, the
computation takes about 19,000 core-hours, about 160 hours of a machine like the one above.
Keeping its proofs (`retain`) would take about 76 TB, its journals about 2.4 GB. This is an
order of magnitude, not a forecast: the two formulas differ by 16 % in processor time and by
eight literals in depth, maps 1 and 2 have no automorphism other than the identity (like 39 of
the 59 maps), and no other formula has been measured.

## Not done

- **The computation.** No campaign of the 59 formulas has been run. Apart from the two formulas
  of the pilot's rehearsal campaign, no formula has been closed at its empty cube, and no
  certificate, evidence package or audit of a campaign of the 59 formulas exists (claim
  `faces12:campaign` in [CLAIMS](docs/CLAIMS.md) is open, and so is
  `faces12:leaf-verification`).
- **The cost of the other 57 formulas.** It has not been measured: the estimate above
  extrapolates two formulas. The default policy constants
  ([RUNNING](docs/RUNNING.md#the-policy)) are starting values fitted to a small number of
  exploratory solver runs; in the pilot they blocked no node.
- **Refereeing.** The article has not been refereed. Its proofs are written proofs, not
  machine-checked ones.
- **Source checks.** Some citations of the article have not been compared with the printed
  source; [SOURCES](docs/SOURCES.md) lists each one.

## Known limitations

- Machines coordinate only through files (shards, handoff files, exports); there is no cluster
  service. Delivery of a handoff file is the operator's job, and an undelivered one leaves its
  region visibly open.
- Process execution, journal writing and audits need Linux with util-linux, POSIX locks and
  `fsync`, on a local file system. The release image is `linux/amd64` only.
- Proofs are not kept by default. Verification is then by recomputation, which in full costs
  about as much as closing the leaves did (473 core-hours for the leaves of the pilot);
  `retain` mode keeps checked proofs for whoever has the storage (about 76 TB for the 59
  formulas).
- Strict reproduction of proof bytes depends on the determinism of the pinned CaDiCaL under one
  execution profile. It is tested on the small workloads of the test-image tier, and the
  pilot's audit reproduced the proofs of 50 leaves of twelve-face formulas on a processor other
  than the one that wrote them (both AMD Zen 4, the same image); it is not a theorem, and nothing
  is known about it for other versions, options or platforms.
- A journal is an attestation, not a signature. The removal of its tail is detected only
  against a head and length kept elsewhere, and nothing authenticates the writer. Exports are
  backups whose interval is the recovery point; a journal with one copy has no promise beyond
  the life of that copy ([RUNNING](docs/RUNNING.md#stop-resume-and-recovery)).
- Crash recovery is tested by killing processes and by constructed on-disk states. Power loss
  and failing disks are not simulated end to end; fault injection covers the journal and
  artifact components.
- The memory, CPU and disk budgets of a worker are accounting, not a sandbox, and the limits
  on the tools are per process.
- The reference encoder of the package tests shares numbering and sign conventions with the
  encoder, so their agreement cannot exclude an error in a shared convention. The reference of
  `tests/reference` has its own numbering, signs and splitting of the parity constraints: it
  was written from the article, reads from the encoder its clauses, the names of its variables
  and its choices among sound alternatives, and shows, for each of the 59 maps, that the
  formula is the one the article defines. It is a second implementation by the
  same project, not a formal proof, and it does not show that the article's lemmas are true.
- No realization with twelve faces is known, so the encoding is exercised geometrically only
  on smaller maps (the tetrahedron and a Szilassi polyhedron).

## What a complete result needs

1. A campaign of the 59 formulas, run to the end, for which `cubeproof certify` exits 0, with
   the independent certifier producing the same certificate and no unresolved anomaly.
2. Verification independent of the journals: recomputation of the used leaves (all of them
   for complete verification; a sample verifies only the sample) or a check of retained
   proofs, by a party that did not run the campaign ([AUDITING](docs/AUDITING.md)).
3. Review of the reduction, the enumeration and the encoding by people, and then
   `faces12-campaign claim` ([COMPUTE](docs/COMPUTE.md#the-claim-review)).

See [COMPUTE](docs/COMPUTE.md) to contribute resources, [RUNNING](docs/RUNNING.md) to operate a
worker and [AUDITING](docs/AUDITING.md) to assess the evidence.
