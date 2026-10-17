# cubeproof

Generic cube-tree refutation campaigns with checked LRAT attestations.

`cubeproof` takes a formula bundle from disk, splits the formula into a recorded tree of
cubes, runs bounded leaf work with external pinned tools (a SAT solver writing an LRAT proof
and a proof checker), records every result in hash-chained journals, and certifies or audits
the coverage of the tree. It knows nothing about the problem a formula encodes.

A certificate attests what the journals claim: a leaf counts only when the checker accepted
its proof, and a formula is reported proved only when its empty cube is closed. What is
trusted and what is not is stated in the trust document of the repository. No claim about
any particular formula follows from the package itself.

## Install

```sh
python3 -m pip install packages/cubeproof
```

Python 3.10 or newer; no third-party dependency. From a source checkout, `make install-dev`
installs the three packages of the repository in editable mode together with the pinned
development tools. The package installs no console script: run it as
`python3 -m cubeproof COMMAND ...` (the release image of the repository calls it `cubeproof`).

## Usage

Normalizing an external DIMACS file into a bundle needs no tool and shows the first step
of every campaign:

```sh
printf 'p cnf 2 4\n1 2 0\n-1 2 0\n1 -2 0\n-1 -2 0\n' > tiny.cnf
python3 -m cubeproof bundle import tiny.cnf -o tiny-bundle
```

It prints one JSON line with the size of the formula and its `formula_sha256`, the name by
which campaigns, journals and certificates refer to it, and writes `tiny-bundle/formula.cnf`
and `tiny-bundle/manifest.json`. The further steps are `campaign create` (the campaign
document with its policy and the hashes of the solver and the checker), `run` (one worker,
on Linux, with the tools given as explicit paths), `certify` (the certificate, recomputed
from the journals) and `audit` (recomputation of certified leaves).
`python3 -m cubeproof COMMAND --help` describes every command.

## Commands

`bundle import`, `campaign create`, `shard`, `run`, `handoff`, `status`, `certify`,
`evidence package`, `journal verify`, `journal repair`, `audit` and `verify-retained`. Every
option, exit code (0 success, 1 open work, 2 a valid model, 3 usage, 4 integrity, 5 tool
failure, 6 anomaly, 130 interrupted) and rule is in the generated
[command reference](../../docs/cubeproof/cli-reference.md), and the behavior a parser
cannot state in the [commands guide](../../docs/cubeproof/commands.md). The Python API
(`cubeproof.api`) mirrors the commands with typed immutable values and returns result
documents; it does not print or exit.

## Boundaries

- Runtime dependencies: the Python standard library only. The solver and the checker are
  external programs located explicitly in the configuration and matched against the hashes
  recorded in the campaign.
- `cubeproof` never imports `neighbourly` or `faces12_campaign`. Its mathematical input is a
  bundle on disk.
- Inside the package, layers depend only downwards (command line and API, commands,
  coordinator, leaf and split, evidence, tools, CNF, contracts and base), and the certifier
  depends only on the pure part of that stack. The architecture tests of the repository
  check these rules, including transitive imports.
- Only the command line reads the environment, prints or exits; the API returns values.
- Process execution, journal writing and repair, runs, audits and retained-proof
  verification require util-linux and working POSIX locks and `fsync`. The supported platform
  is Linux x86-64 (native, WSL 2 or a container).

## Documentation

In the [repository](https://github.com/pirozhkov-andrei/polyhedraproof):
the [specification](../../docs/SPECIFICATION.md) (normative), the
[architecture overview](../../docs/ARCHITECTURE.md), the
[trust argument](../../docs/TRUST.md) and the
[design decisions](../../docs/decisions/README.md).

## License

MIT, see `LICENSE`.
