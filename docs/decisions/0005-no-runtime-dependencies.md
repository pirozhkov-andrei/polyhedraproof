# 0005. The runtime is the standard library

## Context

Everything outside the checker has to be trusted by argument and by test
([TRUST](../TRUST.md)). Every dependency is code that a reader would have to trust too,
and a version that changes under the project can change the formula's bytes or the
evidence.

## Decision

At run time each of the three distributions ([0009](0009-three-distributions.md)) needs
Python 3.10 or newer and nothing else from Python, except that `faces12-campaign` requires
the other two distributions of the same release. The only proof tools are CaDiCaL and
cake_lpr; the process isolation of the tools uses `setpriv` (parent-death signal) and
`prlimit` (process limits) of util-linux on Linux. Exact arithmetic uses `fractions`, and
processes are driven with `subprocess` and `os`. Tests, linting and type checking have
their own development dependencies in the root `pyproject.toml`, pinned in
`constraints/dev.txt`.

Two alternatives were rejected. NumPy or SymPy for the exact controls would be faster or
shorter, but a large trusted base for small determinants that `fractions` computes exactly.
A workflow or database framework for journals and scheduling has more features than the
project needs, and more to audit; the state cache of a worker is derived from its journal,
discarded on any mismatch and read by neither certifier.

## Consequences

Installing the distributions brings in no third-party Python package, the release image
installs nothing at run time, and `faces12-campaign release provenance` can describe an
installation by the three packages (version and a digest of their installed files), the
Python runtime and platform, the solver and checker binaries given to it and, for a source
tree, the hash of every file of the release list.
