# 0008. A release is built from an explicit list of files

## Context

A source archive built by walking directories contains whatever happens to lie in them:
a stray file or build output can end up in a published archive without anybody having
decided to publish it. Exclusion rules do not help: every new kind of stray file needs a new
exclusion, and a forgotten one is published.

## Decision

`RELEASE_FILES.txt` lists every file of a release. `faces12-campaign release bundle` and
`faces12-campaign release provenance` read it, with the source root given explicitly; the
bundle refuses a listed file that is missing, a symbolic link, or a path outside the
source root. The architecture tests fail when a file of the checkout is not listed, when
a listed file does not exist, and when the list is unsorted or repeats a name. The
release view, a copy of exactly the listed files, must pass the fast test suites on its
own (`make test-release-view`).

## Consequences

A new file is shipped only once it is added to the list, and the architecture tests say
so when it is not. The source archive is deterministic, so two builds of the same list
can be compared by hash; the release image builds it from the built wheels
([RELEASE](../RELEASE.md)). `faces12-campaign release verify` checks an unpacked archive
against its manifest.
