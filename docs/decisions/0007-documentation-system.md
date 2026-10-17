# 0007. Documentation by task, with generated references

## Context

New readers should not have to read an evidence ledger to understand the goal.
Auditors still need precise links between claims, code, tests and their limits.
Command options and other repeated facts should be generated from their source.

## Decision

Each document has one job:

- README introduces the question and directs readers to a starting point.
- ENGINEERING gives a short evaluation route through design decisions and evidence,
  including for readers without a geometry background.
- STATUS states what is established and which obligations are open.
- QUICKSTART teaches the basic commands; COMPUTE explains resource contributions.
- RUNNING, AUDITING, CONTRIBUTING and RELEASE describe procedures.
- REFERENCE, THEORY_MAP, CLAIMS, GLOSSARY, SOURCES and the two command references support
  detailed lookup; SPECIFICATION is the normative description of behavior and file formats.
- The article, TRUST, ARCHITECTURE and these records explain the reasoning.

Facts that have a source are generated from it. The command references are written by the
code they describe: `docs/cubeproof/cli-reference.md` by `python -m cubeproof.cli.reference`
and `docs/faces12/cli-reference.md` by `faces12-campaign release docs`. The table of CLAIMS
and the statements table of THEORY_MAP are rendered from the claims ledger
`docs/claims.json` and the article by `tools/checks/claims_docs.py`.

## Consequences

`tools/checks/claims_docs.py --check` (in `make lint`) detects stale generated blocks,
claims whose code or tests do not exist, article labels that do not exist and relative
links that point nowhere; the package tests compare each command reference with its
parser. These checks validate structure and names, not the truth of prose or proofs.
Markdown keeps the documentation readable without a site build.
