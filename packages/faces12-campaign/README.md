# faces12-campaign

The twelve pairwise-adjacent faces problem as a `cubeproof` campaign.

`faces12-campaign` (import name `faces12_campaign`) combines the two libraries of the
release: it exports the 59 formulas of `neighbourly`, creates and runs the campaign with
`cubeproof`, gates the mathematical claim on a recomputed certificate, and integrates
launch, release and documentation. Its commands are thin adapters over the libraries, not a
second scheduler or certifier.

The package itself makes no nonexistence claim. `claim` prints the unconditional article
conclusion only when the certificate of the evidence is `PROVED` for exactly the 59
published formulas and a human review attests the enumeration, the encoding and the
reduction with verified artifacts; otherwise it prints a conditional statement or refuses.
The repository's root distribution `polyhedraproof` is a meta-package that requires this
package and the two libraries at the same version.

## Install

```sh
python3 -m pip install packages/cubeproof packages/neighbourly packages/faces12-campaign
```

Python 3.10 or newer. The distribution requires exactly the same release of `cubeproof` and
`neighbourly`. It installs no console script: run it as
`python3 -m faces12_campaign COMMAND ...` (the release image of the repository calls it
`faces12-campaign`).

## Usage

These commands need no solver and run in seconds:

```sh
python3 -m faces12_campaign selftest                    # identities, corpus, base formula
python3 -m faces12_campaign formulas --check --maps 1   # recompute map 1, compare the hash
python3 -m faces12_campaign formulas -o bundles --maps 1    # write the bundle bundles/map01
```

`formulas -o DIR` without `--maps` writes all 59 bundles. `campaign init` then creates the
campaign beside them, with the solver and checker binaries given explicitly, and `run`,
`certify` and `audit` are the `cubeproof` commands; the running guide of the repository
describes the procedure.

## Commands

`formulas` (write or verify the bundles of the 59 formulas), `campaign init` and
`campaign prefixes`, `run`, `shard`, `handoff`, `certify`, `audit` and `status` (delegated
unchanged to `cubeproof`), `claim`, `model`, `maps`, `selftest` and `release bundle|verify|
provenance|docs`. Options and exit codes are in the generated
[command reference](../../docs/faces12/cli-reference.md), and the workflow in the
[application guide](../../docs/faces12/application.md).

## Boundaries

- Runtime dependencies: the standard library, `cubeproof` and `neighbourly`, declared in the
  package metadata.
- Layers: command line and API, then commands, then the release, campaign, claim, formulas
  and model adapters (sharing the constants of `pins`), then the libraries. Only the command
  line reads the environment, prints or exits. The architecture tests of the repository check
  these rules.
- The supported platform is Linux x86-64 (native, WSL 2 or a container); process execution
  also needs util-linux (see the running guide).

## Documentation

In the [repository](https://github.com/pirozhkov-andrei/polyhedraproof):
[running a campaign](../../docs/RUNNING.md),
[auditing](../../docs/AUDITING.md), the [trust argument](../../docs/TRUST.md), the
[specification](../../docs/SPECIFICATION.md) (§13.3 for this package) and the article
`paper/faces12-en.tex`.

## License

MIT, see `LICENSE`.
