# Architecture

Where the boundaries in the code are and why, so that a change lands in one place instead
of five. The mathematics is in the article, mapped to the code by
[THEORY_MAP](THEORY_MAP.md); the trust argument is in [TRUST](TRUST.md); how to make a
change is in [CONTRIBUTING](CONTRIBUTING.md); the decisions behind the structure are the
[design records](decisions/README.md); the normative description of behavior and file formats
is the [SPECIFICATION](SPECIFICATION.md), cited below as "SPECIFICATION §n". This page is an
overview written by hand; where it and the specification differ, the specification governs.

## Three distributions

The project is three distributions, built, tested and released together under one version
(SPECIFICATION §2.1, [decision 0009](decisions/0009-three-distributions.md)):

| Distribution (import) | Depends on | Holds |
|---|---|---|
| `cubeproof` | nothing but the standard library and the pinned external tools | the generic prover: bundles, campaigns, cube evidence, journals, leaf work, splitters, the coordinator, certification, audit, command line and API |
| `neighbourly` | the standard library | maps, enumeration, exact geometry, the S/H/A/B/I encoding and gauge, interpretation, controls, the corpus of the 59 maps with twelve faces, and `neighbourly.cnf` |
| `faces12-campaign` (`faces12_campaign`) | `cubeproof` and `neighbourly`, the same release | the 59-formula campaign, model description, the claim gate, release and documentation adapters |

`cubeproof` never imports `neighbourly` or `faces12_campaign`: its only mathematical input is a
bundle on disk, a formula's bytes and their SHA-256, so its trust boundary contains none of the
mathematics of one problem. `neighbourly.cnf` is the canonical *producer* of DIMACS bytes and
`cubeproof` has its own strict reader and cube-CNF writer; the byte contract between them is
fixed by frozen test vectors (`tests/contracts`), not by shared code. `neighbourly.cnf`
imports only the standard library and its own submodules and reads no package data, so it is
separable from the rest of the distribution. The independent certifier
`tools/certify_min.py` imports nothing of the project. The layout of the repository is
SPECIFICATION §2.2.

## Layers of `cubeproof`

A module imports only from its own subsystem or from a lower layer (SPECIFICATION §2.3; the
table is the one `tools/checks/archcheck.py` enforces, directly and transitively):

| Layer | Modules | What it holds |
|---|---|---|
| command line and API | `cubeproof.cli`, `cubeproof.api` | parsing, printing, exit codes; the typed API that returns values and neither prints nor exits |
| commands | `cubeproof.commands` | the modules of the commands, assembling configuration; no scheduler |
| coordinator | `cubeproof.coordinator` | the single event loop, resource ledgers, replay, shards, handoff, exports, status, the state cache |
| leaf and split | `cubeproof.leaf`, `cubeproof.split` | the attempt state machine and the binding of its evidence to a record; the proof-prefix, static and lookahead splitters ([decision 0012](decisions/0012-proof-prefix-and-lookahead.md)) |
| certifier | `cubeproof.evidence.certify` | the closure, the selected tree, the certificate ([decision 0010](decisions/0010-cube-evidence-graph.md)); pure |
| schema and journal | `cubeproof.evidence.schema`, `cubeproof.evidence.journal` | record rules; the journal codec and recovery primitives ([decision 0016](decisions/0016-self-checksummed-journals.md)); pure |
| tools | `cubeproof.tools` | process isolation, solver, checker, relay, the supervised I/O service, artifact publication |
| CNF | `cubeproof.cnf` | DIMACS, cube CNF, unit propagation and the unit proof route; pure |
| contracts and base | `cubeproof.contracts`, `cubeproof.base` | typed values, identities, canonical JSON, hashing, settings |

The order is not total: the leaf and split layers do not import the certifier; the certifier,
the schema and the journal do not import tools; the schema and the journal import only the
contracts and base. SPECIFICATION §2.3 lists the allowed imports of each layer, and of the
layers of `neighbourly` and `faces12_campaign`.

## The rules that keep it that way

The architecture tests (`make test-architecture`) check the import and environment rules
below, including through chains of imports, so a forbidden import cannot hide behind another
module; the rules about processes, ledgers and derived state are SPECIFICATION §7 and §8 and
are covered by the package tests:

- **Pure layers stay pure.** The certifier, the evidence readers, CNF and the contracts reach no
  process, thread, signal, socket or resource module, however indirectly. Certification therefore
  runs wherever Python does, and nothing in it can start a tool.
- **Only the command line talks to the world.** Only the command-line layer reads the
  environment or the process arguments, prints, or exits (the stream relay, which runs as its own
  isolated process, is the one other boundary). The API returns result values; a
  failure is a typed error with an exit code.
- **Tools are configuration.** The solver, checker and helper are absolute local paths given
  explicitly and matched against the hashes in the campaign. Nothing is searched on `PATH`.
- **One loop, one writer.** Each worker has one single-threaded coordinator loop; solver,
  checker, splitter helper and stream relay are supervised subprocesses in their own process
  groups, with the parent-death signal and address-space limits. Large hashing, copying, fsync
  and every journal append run in one supervised I/O service process, the only journal writer
  ([decision 0015](decisions/0015-single-event-loop.md)). It cannot construct a `VERIFIED_UNSAT`
  record: the coordinator hands it validated values.
- **Ownership before work.** CPU, memory and disk are reserved through ledgers before a task
  starts, and a task that does not fit is not started (SPECIFICATION §8.3).
- **Derived state is disposable.** The state cache, `status.json` and `status.txt`, the exports
  and the derived models are rebuilt from the journal and are never evidence
  (SPECIFICATION §7.3).
- **Configuration is a value.** The campaign document embeds the complete policy; a run's
  overrides are recorded in the journal (SPECIFICATION §4.3, §4.4).

## Where the trust boundary is in the code

The obligations and the code that carries each are the matrix of SPECIFICATION §5; the
argument is [TRUST](TRUST.md). A leaf is verified only if all the following hold, in code
that can be named ([decision 0002](decisions/0002-the-checker-decides.md)):

- `cubeproof.tools.checker.accepts` is the only function that recognizes checker success:
  the process started, exited 0 without a signal, and its *complete* standard output was
  exactly `s VERIFIED UNSAT` and a line feed, 17 bytes, none truncated.
- `cubeproof.leaf.binding` is the only place that constructs a `VERIFIED_UNSAT` attempt
  (`bind_verified` for the file modes and for unit refutations, `bind_stream_verified` for a
  streamed CDCL proof). It is pure: it judges the evidence the state machine collected and
  refuses, with a `TOOL_FAILED` reason, unless the identity of every file and launch, the CNF
  hash before and after the last check, the proof hash, the solver's clean exit 20, the arena
  ladder and the exact checker success all agree.
- The certifier accepts a record only after checking the same conditions again from the record
  (`cubeproof.evidence.certify`), and `tools/certify_min.py` does so independently
  (SPECIFICATION §10.5). The tests require both to produce the expected certificates of the
  contract corpus byte for byte (`packages/cubeproof/tests/certify`,
  `tests/independent`). Agreement of two
  implementations shows that closure is evaluated the same way twice; it does not show that
  the journals are honest ([TRUST](TRUST.md),
  [decision 0013](decisions/0013-admission-and-guarantees.md)).
- The supervised I/O service is part of the binding and durability boundary: it writes the
  journal and publishes retained proofs before their records are committed.

Everything else treats `VERIFIED_UNSAT` as given and never makes one up. The relay, the C layer
through which the verified machine code reads its files and the package's own unit-proof route lie
outside the checker's theorem; they are covered by the checks above and identified by the hashes
recorded with each result.

## What is deliberately not here

- No framework, plugin system or configuration file format. The runtime is the standard
  library, and the trust boundary stays short
  ([decision 0005](decisions/0005-no-runtime-dependencies.md)).
- No database as the evidence store. Journals are append-only canonical JSON lines with a hash
  chain ([decision 0016](decisions/0016-self-checksummed-journals.md)); the state cache is
  derived and thrown away on any mismatch.
- No network coordination. Machines exchange files
  ([decision 0014](decisions/0014-offline-shards-and-handoff.md)).
- No stored proofs by default. A record names the proof the checker accepted by its hash
  ([decision 0011](decisions/0011-three-proof-modes.md)).
- No abstraction over the solver or the checker. There is one of each, pinned by hash, because
  the argument depends on which ones they are.

## Distribution

`RELEASE_FILES.txt` is the explicit list of the files a release contains; the source archive and
the provenance of a checkout are built from it, so a stray file in a working copy is never
shipped ([decision 0008](decisions/0008-explicit-release-list.md)). The release image
`docker/release/Dockerfile` builds the three wheels from the sources, installs only those
wheels, and pins the tools; it is validated by building twice and comparing hashes
(SPECIFICATION §14, [RELEASE](RELEASE.md), [RUNNING](RUNNING.md)). The root distribution
`polyhedraproof` is a meta-package: it holds no code and requires the three distributions at the
exact version of the release, so installing `polyhedraproof` installs the three at that version.

The documents that describe claims are kept consistent by checks rather than by care:
`tools/checks/claims_docs.py` renders the ledger `docs/claims.json` into
[CLAIMS](CLAIMS.md) and the table of [THEORY_MAP](THEORY_MAP.md) and, in `make lint`, checks
that the code and tests each claim names exist, that every label cited exists in the article
and that every relative link resolves; the command references of `cubeproof` and
`faces12-campaign` are generated from their parsers and compared in their packages' tests.
