# Contributing

How to change this project without breaking what it claims. Read
[ARCHITECTURE](ARCHITECTURE.md) first for where things live; the normative description of
behavior and file formats is the [SPECIFICATION](SPECIFICATION.md), cited here as
"SPECIFICATION §n".

## Proposing a change

Open an [issue](https://github.com/pirozhkov-andrei/polyhedraproof/issues) to report a problem
or to discuss a change before larger work, and a pull request for a change; contributions are
accepted under the license of the part they change (the MIT
license for the code and the data, CC BY 4.0 for the article). A pull request says which checks
of this page were run and, for a trust-relevant change (below), which obligation it touches. A
possible soundness defect, anything that could make a certificate or a claim say more than the
evidence supports, is reported as [SECURITY](SECURITY.md) describes, not in a public issue.

## Setting up

The project needs Python 3.10 or newer, `make` and `git`. The fast test suites need no
solver; the tests with the pinned CaDiCaL and cake_lpr run in the Linux test image (below).

```sh
python3 -m venv .venv
. .venv/bin/activate
make install-dev
```

installs the three packages and the meta-package in editable mode, with the development
tools at the versions pinned in `constraints/dev.txt`. Use a virtual environment; with
another interpreter, pass `PYTHON=/path/to/python` to `make`. `make install-dev` and
`make test-installed` download packages from PyPI, or use a pip cache.

The code is three packages under `packages/`: `cubeproof` (the generic prover),
`neighbourly` (the mathematics, with the generic CNF emission module `neighbourly.cnf`) and
`faces12-campaign` (this problem as a campaign). The root of the checkout is the
meta-package `polyhedraproof`, which holds no code and requires the three at the version of
the release. Shared test suites are under `tests/`, the checks and generators under
`tools/`, the images under `docker/` and the article under `paper/`.

## The standard checks

Each target has one stable meaning.

| Target | What it checks |
|---|---|
| `make lint` | `ruff check` and `ruff format --check` on the code, `mypy --strict` on the packages, their tests, the shared suites and the tools, and `tools/checks/claims_docs.py --check` (the claims documents, cited article labels and relative links) |
| `make test-architecture` | `tests/architecture`: package boundaries and transitive import rules, the configuration of the packages, the claims documents and the release list |
| `make test-release-view` | a copy of exactly the files of `RELEASE_FILES.txt` passes the fast suites of the three packages on its own (several minutes) |
| `make test-fast` | every fast test of the three packages and of the shared suites other than `tests/architecture` (run by `make test-architecture`) and `tests/release` (run by `make test-installed`); no `slow` or `image` test. It runs in two passes: in parallel workers, then the `serial` tests alone |
| `make test-installed` | `tests/release` with the slow tier: wheels and sdists built and installed in clean environments outside the checkout |
| `make test-all` | every supported test including the `slow` and `image` tiers; it refuses to start outside the Linux test image |

There is no hosted continuous integration: the checks are run locally, and a change is
proposed only after they pass. Before proposing a change run `make lint`,
`make test-architecture` and `make test-fast`.
Run `make test-release-view` when files were added, moved or removed, `make test-installed`
when packaging, package data, entry points, `pipeline/` or `docker/` scripts changed, and `make test-all` in the test image
when process execution, the tools or the proof path changed:

```sh
bash docker/test/run.sh build   # the test image with the pinned CaDiCaL and cake_lpr
bash docker/test/run.sh run     # make test-all inside it; the checkout is mounted read-only
```

The image needs Docker on x86-64 and a full clone (not a `git worktree`).
`make format` applies the formatter and the automatic lint fixes. Changing a pin of
`constraints/dev.txt` is a change of its own: rerun the checks with the new set and
investigate new diagnostics.

## Test tiers and markers

A plain `pytest` never starts long work. The markers are declared in the root
`pyproject.toml` (unknown markers are an error) and the tiers are implemented in the root
`conftest.py`:

| Marker | Meaning | How it runs |
|---|---|---|
| `slow` | runs for more than about ten seconds | skipped unless `--run-slow` is given |
| `image` | needs the pinned Linux tools of the test image | skipped unless `--run-image` is given |
| `serial` | has wall-clock assertions (latency bounds, kill windows); assigned in `conftest.py` by test identifier, not written in the test | never in parallel workers; second pass of `make test-fast` |
| `release_view` | re-runs the fast suites in the release view | selected by `make test-release-view`, deselected by `make test-architecture` |

A single suite, file or test runs without installation, since the root `pyproject.toml` puts
the three `src` directories on the import path, for example:

```sh
python3 -m pytest packages/cubeproof/tests/cli -q
python3 -m pytest packages/cubeproof/tests/cli/test_cp_cli_reference.py::test_the_reference_in_the_repository_is_the_generated_one -q
python3 -m pytest packages/neighbourly/tests --run-slow -q   # with the slow tier
```

Test file names are unique across all test directories, and a test checks that they are.
Never weaken a test to make a change pass: a failing golden value or frozen vector means
that the bytes changed, which is the question to answer.

`tests/architecture` checks what the architecture requires of the packages: `cubeproof`
and `neighbourly` import neither each other nor the application; layers depend only
downwards, also through chains of imports and package initialisers; the certifier reaches no
process, thread or resource code, nor the process functions of `os`; `neighbourly.cnf`
imports only itself and the standard library and reads no package data; only a command line
reads the environment, prints, writes to the standard streams or exits. Each rule is tested
against a deliberately broken package as well.

## The release list

`RELEASE_FILES.txt` lists every file of a release, one path per line, sorted
([decision 0008](decisions/0008-explicit-release-list.md)). It is edited by hand: add the
line when a file is added and remove it when the file is removed.
`tests/architecture/test_release_list.py` fails when a file of the checkout (tracked, or
untracked and not ignored) is not listed, when a listed file does not exist, and when the
list is unsorted or repeats a name; `make test-release-view` then shows that nothing
depends on a file outside the list. Generated output and local results belong in ignored
locations, not in the list.

## Generated and hash-pinned files

Some files are produced by a generator or are frozen by a recorded hash. Edit their
source and regenerate; never edit the output. Every generator has a check mode that
changes nothing, and the tests run the same comparison.

| Files | Source | Regenerate | Check |
|---|---|---|---|
| the contract corpus `tests/contracts/corpus/` | `tools/spec_vectors/` and its `inputs/`; the corpus also records the SHA-256 of `docs/SPECIFICATION.md` and of the generator | `python3 tools/spec_vectors/generate.py` | `python3 tools/spec_vectors/generate.py --check` |
| the marked blocks of `docs/CLAIMS.md` and `docs/THEORY_MAP.md` | the claims ledger `docs/claims.json` and the article | `make docs` (`python3 tools/checks/claims_docs.py`) | `python3 tools/checks/claims_docs.py --check` |
| `docs/cubeproof/cli-reference.md` | the command table `cubeproof.cli.spec` | `python3 -m cubeproof.cli.reference > docs/cubeproof/cli-reference.md` | the tests of `packages/cubeproof/tests/cli` |
| `docs/faces12/cli-reference.md` | the parser `faces12_campaign.cli` | `python3 -m faces12_campaign release docs --root .` | `python3 -m faces12_campaign release docs --check --root .` |
| the stored maps with 15 and 16 faces in the package data of `neighbourly` | the enumeration of `neighbourly` | `python3 tools/neighbourly_fixtures/generate_maps.py --out DIR`, then copy the files of `DIR` into the package data | `python3 tools/neighbourly_fixtures/generate_maps.py --check` |

Three consequences are easy to miss:

- **Any edit of `docs/SPECIFICATION.md` changes the contract corpus**, because the corpus
  records the hash of the specification. Regenerate the corpus in the same change;
  `scripts/bump_version.py` does so when it rewrites the version there.
- **`schemas/index.json` has no generator.** It records the SHA-256 of every schema of
  `schemas/cubeproof/v1/` and of the requirement matrix `requirements.json` in that directory
  (the rules a schema cannot express, SPECIFICATION §4.1); update the hash by hand in the
  change that edits the file. `tests/contracts/test_contract_index.py` compares them.
- **Golden data is not regenerated to make a test pass.** The hashes of the 59 formulas
  (`data/fixtures/formula_hashes.json` and its copy in the package data of `neighbourly`),
  the expected certificates of the corpus and the golden values of the package tests change
  only with a deliberate, reviewed change of what they pin.

## The documentation

The documentation has four kinds of page, and each kind has one job
([decision 0007](decisions/0007-documentation-system.md)):

| Kind | Pages | Its job |
|---|---|---|
| tutorial | [QUICKSTART](QUICKSTART.md) | a first run that works |
| how-to | [RUNNING](RUNNING.md), [AUDITING](AUDITING.md), [COMPUTE](COMPUTE.md), [RELEASE](RELEASE.md), this page | a task, step by step |
| reference | [SPECIFICATION](SPECIFICATION.md), [REFERENCE](REFERENCE.md), the command references of [cubeproof](cubeproof/cli-reference.md) and [faces12-campaign](faces12/cli-reference.md), [THEORY_MAP](THEORY_MAP.md), [CLAIMS](CLAIMS.md), [GLOSSARY](GLOSSARY.md), [SOURCES](SOURCES.md) | commands, formats, definitions and evidence to look up |
| explanation | [ENGINEERING](ENGINEERING.md), [TRUST](TRUST.md), [ARCHITECTURE](ARCHITECTURE.md), [decisions](decisions/README.md), the article | why |

[STATUS](../STATUS.md) states what is established; [CLAIMS](CLAIMS.md) records the evidence
and limits for individual claims. The rules that keep these pages consistent:

**The article is the mathematics of record.** `paper/faces12-en.tex` is canonical
([decision 0001](decisions/0001-the-article-is-canonical.md)). Rebuild its PDF with
`make paper` after changing the source; this needs pdfLaTeX, the only engine the builder
accepts, and [RELEASE](RELEASE.md#2-the-complete-test-run-and-the-article) names the
installation that writes the tracked PDF byte for byte. A revision of the article that changes
its PDF also sets its `\date` to the day of the revision, which the builder makes the date the PDF
records, and names in appendix B the release it is published with; `scripts/bump_version.py`
leaves the article alone.

**Cite statements by label.** Code, comments and documents refer to the article as
`(paper: lem:parity)`, never by number, since numbers move when a statement is added.
`make lint` (`tools/checks/claims_docs.py --check`) fails on a label that does not exist.

**Every statement has a claim.** Each theorem, lemma, proposition and corollary of the
article has an entry in `docs/claims.json`, and so does every claim about the software
(`faces12:...`). An entry names the code that implements the statement, the tests that check
it and what those tests cover, and the limits: what is *not* checked. A claim that is not
yet established is marked `"open": true` and may not list tests. The check fails when an
entry is missing, when its code or its tests do not exist, or when a listed test is
marked to be skipped or to fail unconditionally.

**Generated means generated.** See the table above. A command's help string is its
documentation: change the help string and regenerate the reference.

**Links in documents must resolve.** The check also fails on a relative link of a released
document that points nowhere.

**Public material is in English** ([decision 0006](decisions/0006-english-repository.md)).

## Changing the mathematics

- **A new layer** goes in `neighbourly.encoding` (the chirotope layers in `chirotope`, the
  face layers in `faces`, the order of emission in `formula`) with its letter in
  `neighbourly.encoding.layers.LAYERS` and its description in `LAYER_DESCRIPTIONS`, and needs a
  lemma in the article, the same layer in the test reference encoder
  (`packages/neighbourly/tests/encoding/nb_reference_encoder.py`), its constraints in the
  independent reference (`tests/reference/ref_paper.py`, written from the article and never
  from the encoder) and a claim
  ([decision 0004](decisions/0004-layers-s-h-a-b-i.md)).
- **Any change to the clauses** changes the formula's bytes, and the 59 base formulas must
  keep the hashes of the fixture `data/fixtures/formula_hashes.json` (and of its packaged
  copy in `neighbourly`); the package tests fail otherwise. A deliberate change is a
  new formula: new hashes, new bundles and a new campaign. The formula carries no version
  number of its own: bundles, journals and certificates name it by its hash, so evidence of
  the old formula stops matching, which is the point
  ([decision 0003](decisions/0003-identity-by-hash.md)).
- **A change to a proof** requires mathematical review and a rebuilt PDF. If the
  statement or the evidence changes, update its claim as well.

## Changing the software

- **A new `cubeproof` command** is a row of the table in `cubeproof.cli.spec`, a handler in
  `cubeproof.cli.handlers`, the work in a module of `cubeproof.commands` and a function of
  `cubeproof.api`, with a help string for every option; regenerate its reference. A
  `faces12-campaign` command is a parser in `faces12_campaign.cli` and its work in
  `faces12_campaign.commands`.
- **A new document or record format** of `cubeproof` is a contract (SPECIFICATION §4): its
  schema in `schemas/cubeproof/v1/`, listed with its hash in `schemas/index.json`, its type
  in `cubeproof.contracts` or `cubeproof.evidence.schema`, and vectors in the contract
  corpus. Documents are canonical JSON and are published atomically by the supervised I/O
  service.
- **Configuration** is explicit: the packages read no environment variables; only the command
  line reads options, and a campaign's policy is part of the campaign document.
- **A new file** that belongs to the release goes into `RELEASE_FILES.txt` (above).
- **A decision** that someone will later ask about (a design with alternatives that were
  rejected for a reason) gets a short record in `docs/decisions/`, with the next free number
  and a row in its index. Code cites the records by number, so numbers are never reused.

## Trust-relevant changes

Some code carries the argument that a certificate means what it says: the recognition of
checker success, the binding of a result to a record, the journal codec and recovery, the
certifier, the CNF and cube writers, and the encoder. [TRUST](TRUST.md) states what is
trusted and why; SPECIFICATION §5 lists the obligations and the code that carries each.
A change there needs, in addition to the checks above:

- a statement of which obligation of SPECIFICATION §5 it touches and why the obligation
  still holds;
- tests of the invariant, including the failing cases SPECIFICATION §15.1 names (a loose
  checker line or exit code, a missing rehash or binding, a wrong CNF header, order or
  formula identity, an omitted split child, a proof at a nonempty root, stale admission, a
  broken journal chain, unsafe recovery order, a missing end of stream);
- agreement of both certifiers, `cubeproof.evidence.certify` and `tools/certify_min.py`, on
  the contract corpus, and review by a second person.

Nothing in the scheduler, the splitters or a cache may become a reason to record a leaf as
verified.
