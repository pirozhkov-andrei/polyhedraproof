# Preparing a release

How to build and verify a release from this tree: the local checks, the complete test run
in the test image, the article, the source archive, the Python distributions and the
release image. Every step is a command of the `Makefile`, of `faces12-campaign release` or
of `docker/`; nothing is published by any of them. A release of the software is not a
result about the mathematical question: what is established is stated in
[STATUS](../STATUS.md). The requirements behind this procedure are SPECIFICATION §14
([SPECIFICATION](SPECIFICATION.md)).

The version is declared once per distribution (`pyproject.toml` and `__version__` of each
package, and the pins of the meta-package at the root); the architecture tests fail unless
all agree. The examples below use 1.0.0rc1.

## 1. Checks in a source checkout

After `make install-dev` ([CONTRIBUTING](CONTRIBUTING.md) explains each target):

```sh
make lint
make test-architecture
make test-release-view
make test-fast
make test-installed
```

`make test-installed` builds the wheels and sdists of the three packages and of the
meta-package and installs them in clean environments outside the checkout, without Docker.

## 2. The complete test run and the article

```sh
bash docker/test/run.sh build   # the test image, with the pinned CaDiCaL and cake_lpr
bash docker/test/run.sh run     # make test-all inside it
make paper                      # build the article twice and check the PDF
```

`make test-all` runs only inside the test image, from a full clone (not a `git worktree`); it
includes the slow tests (all-map encoder comparisons, the census, all 59 formula hashes) and
the tests with the pinned CaDiCaL and cake_lpr. It is not a campaign of the 59 maps; that
procedure is in [RUNNING](RUNNING.md#full-campaign-on-one-host).

The article is built with pdfLaTeX only: its source declares `\pdfoutput=1`, as arXiv expects
of a pdfLaTeX source, and `scripts/build_paper.py` refuses an engine whose `--version` does not
name pdfTeX (XeTeX, LuaTeX, Tectonic). `make paper` runs `pdflatex` from `PATH`;
`python3 scripts/build_paper.py --engine /path/to/pdflatex` runs another installation. The
builder runs pdfLaTeX twice, then twice more in the same directory, rejects unresolved
references, missing characters, overfull boxes and bookmark defects, requires the two PDFs to
be identical and writes `paper/faces12-en.pdf`; `git status` then shows whether the tracked PDF
changed. Inspect the rendered pages as well. Bytes repeat only within one TeX installation: the
tracked PDF was written by pdfTeX 1.40.25 of TeX Live 2023/Debian (the packages
`texlive-latex-extra` and `cm-super` of Ubuntu 24.04), which writes it again byte for byte.

## 3. The source archive and the distributions

`RELEASE_FILES.txt` is the explicit publication list
([decision 0008](decisions/0008-explicit-release-list.md)). Files that are not listed do not
enter the source archive. Read the list before packaging.

```sh
make bundle
```

writes the deterministic archive `dist/polyhedraproof-1.0.0rc1-source.tar.gz` and prints its
SHA-256; it is `python3 -m faces12_campaign release bundle --root . --output FILE --author
NAME`. The archive has one top-level directory, `polyhedraproof-1.0.0rc1/`, with the listed
files and the manifest `SOURCE_MANIFEST.json` (format `faces12-source-bundle-1`). Check it
from the unpacked copy, with an installed copy of the packages:

```sh
mkdir -p /tmp/release && tar -xzf dist/polyhedraproof-1.0.0rc1-source.tar.gz -C /tmp/release
export PYTHONDONTWRITEBYTECODE=1    # no unlisted compiled files in the unpacked tree
python3 -m faces12_campaign release verify --directory /tmp/release/polyhedraproof-1.0.0rc1
```

`release verify` compares every file with the manifest and refuses missing, unlisted or
changed files and symbolic links. Build the Python distributions from this clean directory,
each package and the meta-package at the root:

```sh
cd /tmp/release/polyhedraproof-1.0.0rc1
for p in packages/cubeproof packages/neighbourly packages/faces12-campaign .; do
    python3 -m build --outdir dist "$p"
done
python3 -m pip install --no-index --find-links dist polyhedraproof
python3 -m faces12_campaign selftest
```

The `build` package is a development dependency, needed for this step only; the runtime
code has no third-party dependency. By default `build` fetches the build backend into an
isolated environment; `--no-isolation` uses the installed `setuptools` instead, as
`make test-installed` does. Install into a fresh virtual environment, so that the
self-test runs the built wheels and not an editable installation.

The provenance of an installation is recorded with

```sh
python3 -m faces12_campaign release provenance --root . \
        --solver /path/to/cadical --checker /path/to/cake_lpr --output provenance.json
```

which lists the three packages (version and a digest of their installed files), the Python
runtime (`python`, `implementation`), the operating system with the machine architecture
(`platform`, for example `linux-x86_64`), the C library (`libc`, for example `glibc 2.36`),
the binaries given to it and, with `--root`, the SHA-256 of every file of the release list.
Every option is optional; binaries are never searched for. Nothing of the machine that
happens to run the command is recorded: no kernel release, host name or user. The document
of the release image (`release-provenance.json`) is therefore the same wherever the image
is built, except for `recorded_utc`, the time of recording. Provenance is recorded, not
certified: it lets somebody else notice that they are running something else.

## 4. The release image

`docker/release/Dockerfile` builds `faces12-campaign:VERSION` (linux/amd64) in four stages
from one pinned Debian digest:

| Stage | Contents |
|---|---|
| `tools` | CaDiCaL and cake_lpr, identical to the `tools` stage of the test image `docker/test/Dockerfile` (same pins, same steps; a test fails if they drift apart) |
| `helper` | the native lookahead helper `cubeproof-look` with its build record, and archives of the exact tool and helper sources |
| `artifacts` | an sdist of each of `cubeproof`, `neighbourly` and `faces12-campaign`, the wheel built from that sdist, and the deterministic source archive of `RELEASE_FILES.txt` made by those wheels (`docker/release/release_artifacts.py`) |
| `release` | the wheels installed with `pip --no-index` into `/opt/faces12/venv`, the tools and helper in `/opt/faces12/bin`, sources in `/opt/faces12/sources`, the license texts of the tools in `/opt/faces12/licenses`, provenance in `/opt/faces12/provenance`, a non-root user `faces12` (1000:1000) |

The checkout is never on the import path: the entry point and every Python process it starts
run isolated (`python -I`), so neither `PYTHONPATH` nor the working directory can put other
code in front of the installed packages. The entry point passes the tools explicitly
(`--solver /opt/faces12/bin/cadical --checker /opt/faces12/bin/cake_lpr
--helper /opt/faces12/bin/cubeproof-look`) to the commands that need them; nothing is
looked up on `PATH`. The image installs the three wheels it pins; the root distribution
`polyhedraproof`, the meta-package that requires exactly those three versions, is built and
installed by `make test-installed` instead.

```sh
make image                      # docker build ... -t faces12-campaign:1.0.0rc1 .
docker run --rm --init --network none faces12-campaign:1.0.0rc1 selfcheck
docker run --rm --init --network none faces12-campaign:1.0.0rc1 provenance > provenance.json
docker run --rm --init --network none faces12-campaign:1.0.0rc1 help
```

`make image` tags the image `faces12-campaign:VERSION` with the version of the packages; set
`IMAGE=NAME:TAG` for another tag. The build needs Docker on x86-64 and network access for
the pinned base image, tool sources and build tools; containers run without network.
`provenance` prints every provenance record of the image as one JSON document.

`selfcheck` checks the non-root user, the tool and helper binaries against their build
records, the cake_lpr and CaDiCaL binaries against the SHA-256 that the application pins
(`faces12_campaign.pins`; `campaign init` and the claim gate compare a campaign with the same
values, and a change of the pinned sources or of the base image needs new values there), every
installed file against the hashes recorded at build time, that the packages
import from the installation even with a hostile `PYTHONPATH`, the application self-test,
one pigeonhole formula solved and checked by the pinned tools, and that both volume mount
points are writable.

### Validation: two builds

```sh
bash docker/release/validate.sh /path/outside/the/checkout/release-validation
```

builds the image twice with `--no-cache --pull`, and requires identical tool, helper and
source hashes, wheel and source-archive hashes, the 59 formula hashes, every installed
file hash and the release provenance document without its time of recording
(`reproduced-{1,2}.sha256`). Image IDs, layer timestamps and sdists (their gzip
header records the build time) are not compared. It then runs, against the first build:

1. `selfcheck`;
2. the release-image test tier (`tests/release` with `POLYHEDRAPROOF_RELEASE_IMAGE` set),
   including the wrapper procedure of [RUNNING](RUNNING.md#one-command-workflow-docker) with
   host paths that contain spaces;
3. the installed two-worker run (below).

The script exits 0 only if every compared hash is identical and all three pass; on success it
tags the first build `faces12-campaign:VERSION` (or the tag given as second argument). A run
that skipped the two-worker run can exit 0 but gives no tag. It
needs `python3` (3.10 or later) with `pytest` on the host. Keep the output directory with
the release; its `summary.txt` lists the image ID and the hashes of every log.

The two builds are tagged `faces12-release-validate:ID-1` and `faces12-release-validate:ID-2`.
`ID` names the run: by default the UTC time, the process ID and the name of the output
directory, so that two runs never share a tag and a later run does not retag the images of
an earlier one; `summary.txt` records it. Both intermediate tags are removed when the script
ends, whatever the result. The image of the first build stays under the release tag when
the validation held; the image of the second build is deleted with its tag.

| Variable | Effect |
|---|---|
| `VALIDATE_RUN_ID=ID` | use `ID` in the two tags (letters, digits, `_`, `.` and `-`; at most 100 characters). A tag that already exists is refused before anything is built |
| `VALIDATE_KEEP_IMAGES=1` | keep the two intermediate tags, for example to inspect a failed build; remove them afterwards with `docker image rm` |
| `VALIDATE_SKIP_CLUSTER=1` | do not run the installed two-worker run; `summary.txt` then says `SKIPPED` and the image is not tagged |

`docker/test/validate.sh OUTPUT_DIR` validates the test image in the same way (two builds,
the comparison of their provenance, `make test-all` in the first). Its builds are tagged
`polyhedraproof-test-validate:ID-1` and `-2`, with the same `VALIDATE_RUN_ID` and
`VALIDATE_KEEP_IMAGES`; both tags are removed at the end, because the test image for daily
use is the one `docker/test/run.sh build` tags.

### The installed two-worker run

```sh
python3 tests/endtoend/cluster/cluster_installed.py IMAGE OUTDIR
```

is the check of several workers against the release image, and `validate.sh` runs it on
the first build (`cluster.log`, `cluster-installed/`). `IMAGE` is a tag or digest of a built
release image, and `OUTDIR` a directory of its own, best outside the checkout: the script
replaces it, and an existing `OUTDIR` is deleted first. Two workers of one small campaign (three pigeonhole
formulas, created and planned for two machines inside the image) run in containers of the
image, driven only through `pipeline/faces12-worker.sh` and `docker kill`. One worker
answers a handoff request, each is killed and started again, one is stopped cleanly and
started, and the container of the other is recreated on its volumes. At the end the exported
journals must equal the journals in the results volumes; the certifier of the image and the
main and independent certifiers of the checkout must write byte-identical PROVED
certificates; and the strict audit of every used leaf and `verify-retained` of the retained
proofs must pass in the image. It writes `OUTDIR/transcript.log` (every command with its
output and exit code) and `OUTDIR/result.json` (the facts and a list `problems`), and exits
0 when that list is empty, 1 otherwise, 2 for a wrong number of arguments. It needs Docker,
`bash` and `python3` on the host, runs from a checkout or an unpacked source archive, takes
three to five minutes on an 8-core machine and is not a performance measurement. It removes
only the containers and volumes of its own two workers (`e2e-installed-a-TAG`,
`e2e-installed-b-TAG`); `E2E_CLUSTER_KEEP_WORKERS=1` keeps them.

Build and validate the image from the same clean source as the archive, and keep the
output directory of `validate.sh` with the release. The checks of steps 1 and 2 do not
establish that the image builds or reproduces its binaries.

## 5. Publishing

Nothing above publishes anything. For a release `VERSION` (`MAJOR.MINOR.PATCH`, or
`MAJOR.MINOR.PATCHrcN` for a release candidate; [below](#versions)):

1. `python3 scripts/bump_version.py VERSION` rewrites every declaration and mention of the
   version and regenerates the contract corpus, which records the hash of the specification
   (read its diff); give the section of `CHANGELOG.md` its heading `## VERSION -
   YYYY-MM-DD` with an empty `## Unreleased` above it, and set `date-released` in
   `CITATION.cff`.
2. Run steps 1 to 4 on that commit: the checks, `make test-all` in the test image, `make paper`,
   `make bundle` and `release verify`, and `docker/release/validate.sh`.
3. Tag that commit `vVERSION` with an annotated tag of the author (`git tag -s vVERSION -m
   "Polyhedraproof VERSION"`). A tag is never moved: a fix is a new version. The repository
   of the releases, <https://github.com/pirozhkov-andrei/polyhedraproof>, starts from the
   unpacked, verified source archive of its first release, without its manifest, so that
   every tagged tree is exactly the listed files (a tracked
   `SOURCE_MANIFEST.json` is a file `RELEASE_FILES.txt` does not list, and the architecture
   tests refuse it):

   ```sh
   mkdir -p /tmp/public
   tar -xzf dist/polyhedraproof-VERSION-source.tar.gz -C /tmp/public
   cd /tmp/public/polyhedraproof-VERSION
   python3 -m faces12_campaign release verify --directory .
   rm SOURCE_MANIFEST.json
   git init -b main && git add -A && git commit -m "Polyhedraproof VERSION"
   git tag -s vVERSION -m "Polyhedraproof VERSION"
   git remote add origin https://github.com/pirozhkov-andrei/polyhedraproof.git
   git push origin main vVERSION
   ```

   The repository is created empty on GitHub (no README, license or `.gitignore`), so that
   this first push is accepted; enable its private vulnerability reporting (Settings, Advanced
   Security), to which [SECURITY](SECURITY.md) sends reports. `make bundle` in that repository
   then writes the same archive, byte for byte. Later releases are commits of that repository,
   and their archives are checked in the same way.
4. Publish a release of the tag with the source archive and its SHA-256, the wheels and the
   `artifacts.json` of the validated build, the image provenance (`selfcheck` output and the
   image digest), the `summary.txt` of `validate.sh` and the PDF of the article. Keep the image
   itself (`docker save`) with the release; the digest alone does not rebuild it.
5. Archive the release where it gets a DOI (for example Zenodo) and add the DOI to
   `CITATION.cff`, and to appendix B of the article when it is next revised, in the next
   release.

## Versions

A version is `MAJOR.MINOR.PATCH`, with release candidates `MAJOR.MINOR.PATCHrcN` before a
release. The public interface is the command lines and their exit codes, the formats of
`schemas/` and of the documents this repository writes, the campaign document, the formulas
(their bytes and hashes) and the pinned tools.

| Change | Version |
|---|---|
| Other formula bytes or hashes, an incompatible format, a command or option removed | MAJOR |
| A command, an option or a field readers may ignore; other pinned tools while earlier campaigns stay checkable | MINOR |
| A fix that changes none of the above; documentation; performance | PATCH |

The formats carry their own version (`faces12-claim-1`, `faces12-source-bundle-1`, ...), raised
only when that format changes incompatibly. A campaign is not bound to a release, but every
session records its cubeproof sources, and a worker restarted on another release is refused
unless `--accept-code-change` is given ([RUNNING](RUNNING.md#what-may-change-after-a-campaign-is-created)):
run a campaign on one release, and change it only for a fix that matters to that campaign.

## The host wrapper

The release image is run through the host wrapper `pipeline/faces12-worker.sh`, which the
release-image test tier exercises. Its commands and options, the names of the containers and
volumes, backup and restore are described in [RUNNING](RUNNING.md#one-command-workflow-docker).

## Before publishing a computational result

Follow [AUDITING](AUDITING.md), and archive the source archive, the image provenance, the
campaign with its bundles, the census, the evidence packages (journals, certificate and
manifest) and the audit reports. Proofs are not stored by default
([decision 0011](decisions/0011-three-proof-modes.md)). Keep the hashes outside the
machines that produced them, and say how much of the computation has been recomputed
independently.
