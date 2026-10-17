# Project status

**This is research software for carrying out a computational proof. The complete computation
over the 59 formulas has not been carried out, and no nonexistence result is claimed.** A
Boolean model of a formula would not be a geometric realization, and a timeout, a resource
failure or incomplete coverage settles nothing about the geometric question.

This page states what release 1.0.0rc1 contains and how each part is checked, what has not been
done, and the known limitations. [CLAIMS](docs/CLAIMS.md) lists every claim with its tests
and limits; [TRUST](docs/TRUST.md) explains what each kind of evidence establishes.

## What the release contains

| Part | What it is |
|---|---|
| The article, [`paper/faces12-en.pdf`](paper/faces12-en.pdf) | the reduction of the question to 59 Boolean formulas (paper: cor:conditional), the list of the 59 maps (paper: thm:59), and the statements on which certification of cube trees rests (paper: thm:coverage, lem:closure, cor:treecover, rem:pilotroot, rem:attestation) |
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
| Release image | `bash docker/release/validate.sh DIR` | Docker, `linux/amd64`, network at build time | two builds of the release image without cache, the comparison of their recorded hashes, the image's `selfcheck`, and the tests of the image and of the wrapper |

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
- the release image: that it installs only the built wheels, passes its `selfcheck`, and that
  two builds give the same tools, helper, sources, wheels, source archive, formulas and
  installed files (`docker/release/validate.sh`);
- the host wrapper against a real Docker engine.

Results of the image tiers are not shipped: whoever relies on an image runs
`docker/release/validate.sh` for that image and keeps its output directory
([RELEASE](docs/RELEASE.md)).

## Not done

- **The computation.** No campaign of the 59 formulas has been run. No formula has been closed
  at its empty cube, and no certificate, evidence package or audit of such a campaign exists
  (claim `faces12:campaign` in [CLAIMS](docs/CLAIMS.md) is open, and so is
  `faces12:leaf-verification`).
- **Cost.** No cost figure exists for the computation over the 59 formulas. The default policy
  constants ([RUNNING](docs/RUNNING.md#the-policy)) are starting values fitted to a small
  number of exploratory solver runs.
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
  as much as the computation itself; `retain` mode keeps checked proofs for whoever has the
  storage.
- Strict reproduction of proof bytes depends on the determinism of the pinned CaDiCaL under one
  execution profile. It is tested on the small workloads of the test-image tier; it is not a
  theorem, and nothing is known about it for other versions, options or platforms.
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
