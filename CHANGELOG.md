# Changelog

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the three
distributions and the meta-package share one version, written as in PEP 440 (`1.0.0rc1`, `1.0.0`).
How versions are numbered and when a campaign may change its release:
[RELEASE](docs/RELEASE.md#versions).

## Unreleased

## 1.0.0 - 2026-10-19

The first release. The code of the packages, the release image and the wrapper is that of
1.0.0rc1, with which the pilot computation was run; only the version changed. The article is
the revision of 17 October 2026, released with 1.0.0rc1, and does not report the pilot. The
complete computation over the 59 formulas has not been carried out, and no nonexistence result
is claimed ([STATUS](STATUS.md)).

### Added

- **The pilot computation** ([STATUS](STATUS.md#the-pilot-computation)): with release
  1.0.0rc1, a rehearsal campaign of the formulas of maps 1 and 2 was certified PROVED by both
  certifiers, with 31,187 leaves, each with a proof checked by cake_lpr, in 648.5 core-hours of
  solver and checker time, and a strict audit of 50 leaves on a second machine reproduced
  every proof hash. Its data are published
  ([doi:10.5281/zenodo.23464843](https://doi.org/10.5281/zenodo.23464843)). It does not count
  for the result: the two formulas will be computed again in the campaign of the 59.
- **Continuous integration in the public repository**: `.github/workflows/checks.yml` runs
  `make lint`, `make test-architecture` and `make test-fast` under Python 3.10 and 3.12 on
  every push to `main`, every release tag, every pull request and every start by hand, and
  `make test-all` in the test image on a release tag or when started by hand
  ([CONTRIBUTING](docs/CONTRIBUTING.md)).
  `.gitignore` and `.dockerignore` keep `.github`, and a test checks that both keep every
  hidden entry of the release list.
- **A DOI**: `CITATION.cff` and the README name the concept DOI of the software on Zenodo,
  [10.5281/zenodo.23434449](https://doi.org/10.5281/zenodo.23434449), and `CITATION.cff`
  cites the data of the pilot.
- The term *rehearsal campaign* in the [GLOSSARY](docs/GLOSSARY.md).

### Changed

- Where the documents said that no cost figure existed, they give the pilot's measurements and
  the estimate they support for the 59 formulas: about 19,000 core-hours, and about 76 TB of
  proofs in `retain` mode (STATUS, README, COMPUTE, ENGINEERING, QUICKSTART, RUNNING with the
  sizing of one formula, TRUST, decision 0011, and the limits of the claims
  `faces12:campaign` and `faces12:strict-reproduction`).

## 1.0.0rc1 - 2026-10-17

First public release candidate. It contains the reduction and the tools to carry out the
computation; the complete computation over the 59 formulas has not been carried out, and no
nonexistence result is claimed ([STATUS](STATUS.md)).

### Added

- **The article** (`paper/`): the reduction of the question to the satisfiability of 59 Boolean
  formulas (paper: cor:conditional), the list of the 59 maps, which rests on the published
  classification of the orientable triangulations of genus 6 with twelve vertices
  (paper: thm:59), and the coverage of a formula by a refuted cube tree (paper: thm:coverage).
- **Three distributions under one version**: `cubeproof` (the generic prover), `neighbourly`
  (maps, exact geometry, the encoding and the 59 maps) and `faces12-campaign` (the
  application), with the meta-package `polyhedraproof`; no third-party runtime dependency.
- **The 59 formulas**, generated deterministically and identified by the SHA-256 of their
  bytes. The 59 maps are recomputed by an exhaustive search and compared one by one with the
  published list of the Manifold Page (F. H. Lutz) through recorded relabellings
  (`data/fixtures/lutz_correspondence.json`; [SOURCES](docs/SOURCES.md) says what was checked).
- **An independent reference of the formula** (`tests/reference`), written from the article's
  text without the encoder's conventions: for each of the 59 maps the substantive clauses are
  exactly those the article prescribes; every variable is checked against geometry on random
  planes, and genuine realizations with four and seven faces are taken through relabellings,
  mirror, affine and projective images.
- **The prover**: evidence as a recorded graph of cubes; leaves that count only when the
  verified checker cake_lpr accepts a proof; a known-answer control of the checker before a
  session records anything; the proof modes `transient`, `retain` and `stream`; the splitters
  `proof-prefix-v1` and `lookahead-v1`; workers that stop, resume and recover from
  self-checksummed journals; shards (`shard --formula` for single formulas of a campaign) and
  handoff through files. Each attempt records the processor time and peak memory of its tools.
- **Continuity of a worker.** A session that resumes a journal is refused when its policy
  differs from the session before in a value its command line does not name
  (`run.policy_changed`; `--campaign-policy` accepts the campaign's values on purpose), or when
  it runs other cubeproof sources, a later release or a rebuilt image (`run.code_changed`;
  `--accept-code-change` continues on purpose and says so in the session's notes).
- **Certification and audit**: `cubeproof certify` and the independent
  `tools/certify_min.py`, which must agree byte for byte; `cubeproof audit` and
  `cubeproof verify-retained`. Certificates of the size of the campaign of the 59 formulas
  (about 130 MB at its start) can be planned from and audited.
- **The claim gate** (`faces12-campaign claim`): the SHA-256 of the cake_lpr and CaDiCaL
  binaries of the release image are pinned (`faces12_campaign.pins`); the claim requires the
  admitted checkers to be that cake_lpr or accepted by hash, and names the checkers, the solver
  and the cubeproof sources of the records the certificate uses.
- **Commands**: `cubeproof` (`bundle import`, `campaign create`, `shard`, `run`, `handoff`,
  `status`, `certify`, `evidence package`, `journal verify`, `journal repair`, `audit`,
  `verify-retained`) and `faces12-campaign` (`formulas`, `campaign init`, `campaign prefixes`,
  `run`, `shard`, `handoff`, `certify`, `audit`, `status`, `claim`, `model`, `maps`,
  `selftest`, `release bundle`, `release verify`, `release provenance`, `release docs`).
- **The release image and the host wrapper**: `docker/release/` (`linux/amd64`, pinned CaDiCaL
  and cake_lpr) and `pipeline/faces12-worker.sh`.
- **The specification, schemas and contract corpus**: [SPECIFICATION](docs/SPECIFICATION.md),
  `schemas/` and `tests/contracts`.
- **Documentation**: the guides and references under `docs/`, among them what cannot be changed
  after a campaign is created ([RUNNING](docs/RUNNING.md)), the claims ledger
  ([CLAIMS](docs/CLAIMS.md)) and the [design decisions](docs/decisions/README.md).
- **Licenses**: the code and the data under the MIT license, the article under CC BY 4.0
  ([README](README.md#license)).
