# 0009. Three distributions, one release train

## Context

A prover of cube trees is useful for any CNF, and its trust boundary should not contain the
mathematics of one problem: it should see only the bytes of a formula and their SHA-256. The
encoder and the geometric controls belong with the article's obligations. Problem, policy
and publication should meet in one place only, and a combination of versions that was never
tested together should not exist. The name of the problem should refer to the twelve faces
directly and avoid confusion with the dual twelve-vertex triangulation problem studied by
Schewe: both involve the complete graph, but combinatorial duality does not preserve
polyhedral realizability.

## Decision

The project is three distributions released together under one version:

- `cubeproof`: the generic prover. It consumes formula bundles from disk, runs and checks
  leaves, records evidence, certifies and audits. Runtime: the Python standard library and
  the pinned external tools. It imports neither of the other two distributions.
- `neighbourly`: the mathematics of neighbourly maps (maps, exact geometry, the S/H/A/B/I
  encoding, gauge, interpretation, the corpus of 12) and the generic CNF emission module
  `neighbourly.cnf`. The whole distribution is standard-library only. `neighbourly.cnf`
  imports only the standard library and its own submodules, never another `neighbourly`
  module, and reads no package data, so it is separable from the rest of the distribution.
- `faces12-campaign` (import `faces12_campaign`): the 59-formula campaign, the claim gate
  and the launch, release and documentation integration. It depends on the other two.

Own-package dependencies are declared in packaging metadata. The root `polyhedraproof`
distribution is a meta-package that requires the three exact versions of the same
release.

The name `faces12` identifies the problem: the application distribution is
`faces12-campaign` (import `faces12_campaign`) and the artifact formats of the application
have the `faces12-` prefix. The formats of the generic prover are `cubeproof-*-1`. No
environment variable configures `cubeproof`; the host wrapper takes
`POLYHEDRAPROOF_IMAGE`.

## Consequences

- Architecture tests enforce the internal layer graph of `cubeproof` (transitively, so a
  forbidden import cannot hide behind another module), the `neighbourly.cnf` boundary and
  the environment boundary of CLI and API, consistent with decision
  [0005](0005-no-runtime-dependencies.md): no third-party runtime dependency.
- `neighbourly.cnf` is the canonical producer of DIMACS bytes; `cubeproof` has its own
  strict reader and cube-CNF writer and does not import the producer. The shared byte
  contract is fixed by the frozen vectors of the contract corpus (`tests/contracts/corpus`),
  not by shared code.
- External DIMACS needs no producer library: `cubeproof bundle import` normalizes it
  explicitly into a bundle.
- A release builds and tests all three wheels together and individually in clean
  environments.
