# Reference

Where to look things up. The command references are generated from the parsers and compared
with them by the packages' tests; this page is written by hand and links to them.
[RUNNING](RUNNING.md) explains how the pieces are used together, and the
[SPECIFICATION](SPECIFICATION.md), cited below as "SPECIFICATION §n", is the normative
description of the behavior and of the file formats.

## Commands

| Program | Reference | Run as |
|---|---|---|
| `cubeproof` | [cubeproof command reference](cubeproof/cli-reference.md); the contract of each command in [cubeproof commands](cubeproof/commands.md) | `python3 -m cubeproof COMMAND ...`, or `cubeproof ...` in the release image |
| `faces12-campaign` | [faces12-campaign command reference](faces12/cli-reference.md); the workflow in [the application guide](faces12/application.md) | `python3 -m faces12_campaign COMMAND ...`, or `faces12-campaign ...` in the release image |
| `certify_min.py` | the independent certifier; its usage is in [AUDITING](AUDITING.md) | `python3 tools/certify_min.py ...` |
| `pipeline/faces12-worker.sh` | the host wrapper of the release image, in [RUNNING](RUNNING.md#one-command-workflow-docker) | `bash pipeline/faces12-worker.sh COMMAND ...` |

The exit codes of each program are listed in its command reference (SPECIFICATION §12.2). The
packages install no console scripts.

## Configuration

The packages read no environment variables: everything a run uses is given as an option of
the command line, and the policy of a campaign (time and memory limits, splitting, proof
mode) is part of the campaign document, with a run's overrides recorded in its journal. The
solver, checker and helper are given as absolute paths and matched against the hashes the
campaign admits; nothing is looked up on `PATH`. The release image passes its pinned tools
explicitly ([RELEASE](RELEASE.md)).

## Layers

| Layer | What it says | Why it holds |
|---|---|---|
| `S` | order-bit definitions on the 66 real lines | (paper: thm:order) |
| `H` | transitivity of the order on the real lines | (paper: thm:chirotope) |
| `A` | transitivity of the cut order on the twelve lines at infinity | (paper: lem:cutorder) |
| `B` | face boundaries are simple polygons | (paper: lem:B) |
| `I` | face orientations and at most one reflex corner per vertex | (paper: lem:I) |

The gauge is not a layer: it pins brackets to remove the reorientation symmetry (paper:
cor:gauge). The layers are emitted by `neighbourly.encoding` in the order S, H, A, B, I,
which fixes the numbering of the variables.

## Documents and records

Every document `cubeproof` reads or writes is canonical JSON with a `format` field
(SPECIFICATION §4), described by a JSON schema in `schemas/cubeproof/v1/` and listed in
`schemas/index.json`: bundle manifests, campaigns, policies, shards and handoff requests,
journal records, certificates, evidence manifests, status and audit reports, and the
documents of the lookahead helper. Journals are self-checksummed JSON lines
([decision 0016](decisions/0016-self-checksummed-journals.md)). The frozen contract corpus
that both certifiers are tested against is in `tests/contracts`.

## Make targets

| Target | What it does |
|---|---|
| `make install-dev` | the three packages and the meta-package, editable, with the pinned development tools |
| `make lint` | style and types (mypy --strict), and that the claims documents are consistent |
| `make test-architecture` | the package boundaries, transitive import rules, configuration, claims documents and release list |
| `make test-release-view` | the release view (the files of RELEASE_FILES.txt alone) passes its own fast suites |
| `make test-fast` | every fast test of the packages and the shared suites, except tests/architecture (run by test-architecture) and tests/release (run by test-installed); no slow or image tests |
| `make test-installed` | wheels and sdists in clean environments outside the checkout |
| `make test-all` | every supported test; only inside the declared Linux test image |
| `make docs` | regenerate the generated blocks of docs/CLAIMS.md and docs/THEORY_MAP.md |
| `make maps` | recompute the census of the maps with twelve faces (paper: thm:59) |
| `make image` | build the release image |
| `make paper` | rebuild the article twice and check the PDF |
| `make bundle` | the deterministic source archive, under dist/ |
| `make format` | apply the formatter and the automatic lint fixes |
| `make clean` | remove tool caches, `__pycache__` directories and LaTeX build files |
