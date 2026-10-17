# Twelve pairwise adjacent faces

**Is there a polyhedron with twelve faces in which every face shares an edge with every other
face?** Only two polyhedra with this property are known: the tetrahedron (4 faces) and the
toroidal Szilassi polyhedron (7 faces). Counting with Euler's formula leaves twelve faces, on a
surface of genus 6, as the next possible case, and whether such a polyhedron exists is an open
question of discrete geometry ([Arseneva et al., *Discrete Comput. Geom.*
2024](https://doi.org/10.1007/s00454-023-00537-6)). The dual question, for twelve vertices, was
answered negatively with a SAT solver ([Schewe, *Discrete Comput. Geom.*
2010](https://doi.org/10.1007/s00454-009-9222-y)); duality does not carry that answer over to
faces.

This project turns the question into a finite computation, and builds the software to carry it
out so that a third party can check the result without trusting the program that produced it:

- **Mathematics.** The [article](paper/faces12-en.pdf) proves that, under its
  [hypotheses](docs/THEORY_MAP.md#what-the-article-proves-in-one-paragraph), such a polyhedron
  exists only if one of **59 Boolean formulas** is satisfiable: one formula for each
  combinatorial type, each with 5,257 variables and 52,177 clauses. The
  [theory map](docs/THEORY_MAP.md) links every statement of the article to the code and the
  tests that implement it.
- **Checked computation.** Each formula is split into a recorded tree of cubes (a cube fixes
  the values of some variables, so a split divides a formula into smaller cases). The SAT solver
  CaDiCaL proposes a proof that a leaf is unsatisfiable, in LRAT (a proof format that a small
  program can check step by step), and the formally verified checker **cake_lpr** checks it.
  Two independently written certifiers must agree that the checked leaves cover the formula. A
  solver's answer alone is never accepted.
- **Engineering.** The hard part is making a long computation independently checkable:
  preserve exactly what was computed, recover after interruption, distribute work without
  losing cases, and distinguish evidence from a program's claim of success. Self-checksummed
  journals, work moved between machines as files (no central service), a release image with
  pinned tools whose two builds are compared, three packages with checked boundaries and no
  third-party runtime dependencies, `mypy --strict` and more than 6,800 fast tests. The generic
  prover `cubeproof` accepts formulas unrelated to polyhedra. The
  [engineering overview](docs/ENGINEERING.md) is a ten-minute technical tour.

**Status.** The reduction, the 59 formulas and the tools are implemented and tested. The
computation over the 59 formulas has not been carried out, so the question remains open and no
nonexistence result is claimed. If all 59 formulas are refuted, no such polyhedron exists in the
article's model; a satisfying assignment would be a lead to examine, not by itself a polyhedron.
[STATUS](STATUS.md) says what is implemented and tested, what has not been done, and the known
limitations.

## Start here

| Your goal | Start with |
|---|---|
| Understand the mathematical question and reduction | [Article](paper/faces12-en.pdf) and [theory map](docs/THEORY_MAP.md) |
| Inspect the formulas and run small checks | [Quickstart](docs/QUICKSTART.md) |
| Evaluate the engineering without a geometry background | [Engineering overview](docs/ENGINEERING.md) |
| Run the computation of the 59 formulas, on one host or several, and recover from failures | [Running](docs/RUNNING.md), starting with the [full campaign on one host](docs/RUNNING.md#full-campaign-on-one-host) |
| Contribute computing resources, storage or verification | [Computing collaboration](docs/COMPUTE.md) |
| Assess the evidence and the remaining obligations | [Status](STATUS.md), [trust](docs/TRUST.md), [auditing guide](docs/AUDITING.md) and [claim evidence](docs/CLAIMS.md) |
| Look up the normative behavior of the tools and file formats | [Specification](docs/SPECIFICATION.md) |
| Change the implementation | [Contributing](docs/CONTRIBUTING.md) and [architecture](docs/ARCHITECTURE.md) |

## The packages

The release consists of three distributions, versioned together
([decision 0009](docs/decisions/0009-three-distributions.md)):

| Package | What it is |
|---|---|
| [`cubeproof`](packages/cubeproof/README.md) | the generic prover: formula bundles, cube trees, bounded leaf work with pinned tools, journals, certification (checked against the independent `tools/certify_min.py`) and audit. It knows nothing about polyhedra |
| [`neighbourly`](packages/neighbourly/README.md) | the mathematics: maps, exact geometry, the encoding, the corpus of the 59 maps, and the CNF emission module `neighbourly.cnf` |
| [`faces12-campaign`](packages/faces12-campaign/README.md) | the application: the 59 formulas and their campaign, the description of models, the claim gate and the release integration |

The root distribution `polyhedraproof` is a meta-package that installs the three at the same
version. What the tools must do, and the formats of the files they read and write, is fixed by
the [specification](docs/SPECIFICATION.md); the [architecture](docs/ARCHITECTURE.md) is its
overview.

## What help is needed

The project seeks collaborators for a reproducible computation across all 59 maps: CPU
capacity, independent recomputation of leaves, mathematical review -- and storage. Proofs are
not stored by default (the storage cost of a full campaign is not yet measured), so a computation is verified by
recomputing leaves and comparing proof hashes; anyone able to hold proofs would make it possible
to check them without the solver as well. No cost figure exists for the computation over the
59 formulas; the default policy constants are starting values fitted to a small number of
exploratory solver runs. [COMPUTE](docs/COMPUTE.md) explains the workflow and deliverables.

## Requirements

Supported platform: Linux x86-64 (native, WSL 2 or a container)
([RUNNING](docs/RUNNING.md#support-matrix)). Formula generation and the checks without proof
search need Python 3.10 or newer, with no third-party Python runtime dependencies. Proof
production and checking also need util-linux, CaDiCaL and cake_lpr; the release image
`docker/release/Dockerfile` provides pinned builds of them (`linux/amd64`) and the wrapper
`pipeline/faces12-worker.sh` starts a worker with one command. [STATUS](STATUS.md) says which
checks run from a source checkout and which need the images.

An installed wheel includes the map data. Development checks and publication tools use a source
checkout.

## Use of generative AI

Generative AI assisted with mathematical review, software development and checking,
and English exposition. The author is responsible for the final claims, code and
text. AI output is not proof, independent peer review or formal verification; the
article includes the disclosure and describes the computational checking protocol.

## License

Everything in this repository except the article is under the [MIT license](LICENSE): the
code, the data, the documentation and `paper/Makefile`. The article, `paper/faces12-en.tex`
and `paper/faces12-en.pdf`, is under the [Creative Commons Attribution 4.0 International
license](https://creativecommons.org/licenses/by/4.0/) (CC BY 4.0), not under the MIT license.

The upstream tools this project builds and runs keep their own licenses: CaDiCaL the MIT
license, cake_lpr the CakeML license (a BSD-style license); pinning or building them does not
change those. The release image installs their license texts in `/opt/faces12/licenses` and
the sources it built them from in `/opt/faces12/sources`.

## Further documentation

Beyond the pages of the table above: [Reference](docs/REFERENCE.md) ·
[cubeproof commands](docs/cubeproof/cli-reference.md) ·
[faces12-campaign commands](docs/faces12/cli-reference.md) ·
[Glossary](docs/GLOSSARY.md) · [Sources](docs/SOURCES.md) ·
[Design decisions](docs/decisions/README.md) · [Release guide](docs/RELEASE.md) ·
[Reporting a soundness problem](docs/SECURITY.md)

Release **1.0.0rc1**.
Author: Andrei Pirozhkov ([ORCID 0009-0008-6901-7843](https://orcid.org/0009-0008-6901-7843)).
[Repository](https://github.com/pirozhkov-andrei/polyhedraproof) · [License](#license) ·
[Citation metadata](CITATION.cff) · [Changelog](CHANGELOG.md).
