# Quickstart

Inspect the formulas, run the mathematical checks and, if Docker is available, try the
whole worker workflow on a small example, before any computation of the 59 maps. Steps 1 to 3
need only Python 3.10 or newer and a source checkout; none of them starts a proof search or a
campaign.

## 1. Install from a source checkout

On Linux or inside WSL 2, open a terminal and use Python 3.10 or newer:

```sh
git clone https://github.com/pirozhkov-andrei/polyhedraproof.git
cd polyhedraproof
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install packages/cubeproof packages/neighbourly packages/faces12-campaign
```

If you already have a checkout or unpacked source release, start in its root and skip
the clone. Run subsequent commands from that root. On Debian/Ubuntu, if `venv` or pip
is unavailable, install the distribution's `python3-venv` package first. Installation
can download build dependencies; the checks below need no network.

The three packages are one release and must be installed together; pip needs a build backend
(`setuptools` 77.0.3 or newer). For development, `make install-dev` installs them in editable
mode together with the pinned development tools. The packages install no console scripts: run
them as `python3 -m cubeproof` and `python3 -m faces12_campaign`. (The release image names the same
programs `cubeproof` and `faces12-campaign`, as the other pages do.) The root of the checkout is
the meta-package `polyhedraproof`, which holds no code and requires the three at the same
version; pip resolves that requirement from the packages named on the same command line or from
an index, so `python3 -m pip install packages/cubeproof packages/neighbourly
packages/faces12-campaign .` installs all four.

## 2. Check the mathematical identities

```sh
python3 -m faces12_campaign selftest
```

It runs the exact controls of map 1 (general position, order bits, cut order, gauge, corner
bits, layer I, vertex profiles), checks that the 59 shipped maps are distinct orientable
neighbourly maps, and compares the base formula of map 1 with its published hash. It ends with
`10 of 10 checks hold`. These finite checks exercise identities and combinatorial controls;
they do not prove the general reduction or refute any twelve-face formula. A check that fails
makes the command exit 4.

## 3. Check the 59 formulas

```sh
python3 -m faces12_campaign formulas --check
```

recomputes each formula and compares its SHA-256 with the pinned one
(`packages/neighbourly/src/neighbourly/data/n12/formula_hashes_n12.json`), without writing
anything, and prints one JSON document with the status `recomputed` for each of them. Every
formula has 5,257 variables and 52,177 clauses. Without `--check`, and with `-o DIR`, it writes
the 59 bundles that a campaign is made from ([RUNNING](RUNNING.md)). Constructing a formula does
not solve it.

`python3 -m faces12_campaign maps` recomputes the census of the maps with twelve faces. It takes
minutes.

## 4. Try a worker (Docker, Linux image)

Proof production and checking need Linux, util-linux, CaDiCaL and cake_lpr, which the release
image provides. Build it from a full clone and start the small example campaign (a pigeonhole
formula; it is not a campaign of the article):

```sh
make image       # builds faces12-campaign:1.0.0rc1 from docker/release/Dockerfile
docker run --rm --init --network none faces12-campaign:1.0.0rc1 selfcheck
mkdir -p "$HOME/faces12 runs/worker 1"
bash pipeline/faces12-worker.sh example --image faces12-campaign:1.0.0rc1 --io "$HOME/faces12 runs/worker 1"
bash pipeline/faces12-worker.sh launch --worker w1 --image faces12-campaign:1.0.0rc1 --io "$HOME/faces12 runs/worker 1" -- --jobs 2
bash pipeline/faces12-worker.sh status --worker w1 --image faces12-campaign:1.0.0rc1
```

`selfcheck` verifies the installation and one tiny proof checked by the pinned checker. The
container stops by itself when the example is complete (exit code 0); `status` of a stopped
worker needs `--image` too. Straight after `launch`, `status` can report `status.absent` for
a few seconds, until the worker has published its first status. The example is a toy formula
sized for minutes of work; how long it takes says nothing about the 59 maps.

Wait for completion, then certify and audit what the worker exported. Use the journal
generation named by `export/export.json`; recovery can replace `journal.1.jsonl` with
a later generation. These shell commands assume local Linux storage, including for
the audit's results and work directories:

```sh
IO="$HOME/faces12 runs/worker 1"
docker wait faces12-w1               # prints 0 for a successfully completed example
JOURNAL=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["file"])' "$IO/export/export.json")
run() { docker run --rm --init --network none --user "$(id -u):$(id -g)" -v "$IO:/io" faces12-campaign:1.0.0rc1 "$@"; }
run cubeproof certify --campaign /io/campaign.json --journals "/io/export/$JOURNAL" -o /io/certificate.json
run cubeproof evidence package --campaign /io/campaign.json --journals "/io/export/$JOURNAL" -o /io/evidence
run cubeproof audit --evidence /io/evidence/evidence.json --sample 3 --results /io/audit/results --work /io/audit/work --worker auditor-1
```

The first command prints `PROVED`: the example formula is refuted at its empty cube. That says
nothing about the twelve-face formulas. The audit recomputes three leaves of the certificate
and exits 0 when each reproduces its recorded proof hash (`HASH_MATCHED`); a sample says nothing
about the other leaves ([AUDITING](AUDITING.md)).

The workflow, volumes, stop, resume and recovery are explained in [RUNNING](RUNNING.md). The
worker's live results stay in Docker volumes, and the wrapper never deletes a volume: remove
the example's container and volumes yourself when you have finished
(`docker rm faces12-w1`, `docker volume rm faces12-results-w1 faces12-work-w1`).

## Next steps

- [COMPUTE](COMPUTE.md): coordinate a resource contribution.
- [RUNNING](RUNNING.md): create a campaign, run workers, move work, recover and back up.
- [AUDITING](AUDITING.md) and [TRUST](TRUST.md): what a certificate and an audit establish.
- [STATUS](../STATUS.md): what is tested, and what has not been done.
- [SPECIFICATION](SPECIFICATION.md): the normative behavior of the tools and file formats.
- [cubeproof commands](cubeproof/cli-reference.md) and
  [faces12-campaign commands](faces12/cli-reference.md): every option.

Proof-search cost is input-dependent, and no cost figure exists for the computation over the
59 formulas ([STATUS](../STATUS.md)); the time and memory options bound requested work, they do not
guarantee that a leaf is refuted.
