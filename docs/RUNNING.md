# Running a campaign

This is the canonical procedure: how a worker is started, stopped, recovered and backed up,
how work is divided between machines, and how a campaign is certified and audited. For a
small installation check use [QUICKSTART](QUICKSTART.md); contributors start with
[COMPUTE](COMPUTE.md). The normative behavior behind every step is in the
[SPECIFICATION](SPECIFICATION.md), cited below as "SPECIFICATION §n". Terms such as cube,
shard, handoff, admission and frontier are defined in the [GLOSSARY](GLOSSARY.md).

**No campaign of the 59 formulas has been run.** The procedure is tested on small workloads,
with fake tools and, in the test-image tier, with the pinned CaDiCaL and cake_lpr
([STATUS](../STATUS.md)). The procedure was run with release 1.0.0rc1 on two of the formulas,
in the rehearsal campaign of the [pilot computation](../STATUS.md#the-pilot-computation): one
worker with 124 jobs closed both in 5.5 hours and 648.5 core-hours, and [one formula on one
machine](#one-formula-on-one-machine) gives its measurements. The numbers in the policy table
below are starting values.

## Support matrix

Supported platform: Linux x86-64 (native, WSL 2 or a container).

| What | Needs |
|---|---|
| Formula libraries (`neighbourly`, `neighbourly.cnf`) and `faces12-campaign selftest`, `formulas`, `maps` | Python 3.10 or newer, nothing else |
| Read-only certification (`cubeproof certify`, the independent `tools/certify_min.py`, reading an evidence package) | Python 3.10 or newer, nothing else |
| Process execution and journal writing: `run`, `audit`, `verify-retained`, `journal repair` | util-linux (`prlimit`, `setpriv`) and working POSIX `flock` and `fsync` |
| Release image | `linux/amd64` only: cake_lpr is verified machine code for x86-64. No other architecture is supported |
| Host wrapper `pipeline/faces12-worker.sh` | `bash` and Docker |

Python 3.10 or newer; the runtime of every package is the standard library and, for
`faces12-campaign`, the two other packages of the same release. Results and work directories
must be on local disk: journals are appended under `flock`, so a network file system is not
supported. The wrapper keeps a worker's live results in Docker volumes; it binds a host
directory at `/io` for the immutable inputs and the exchange directories (and, for `backup` and
`restore`, the backup directory). Under WSL 2 keep host directories below the Linux home
directory, not on `/mnt/c`.

## Full campaign on one host

This is the complete path for **all 59 formulas**, using one Linux x86-64 host or WSL 2 with
Docker. It starts an actual proof search: about 19,000 core-hours by the estimate of the [pilot
computation](../STATUS.md#the-pilot-computation), an order of magnitude only, that is about 25
days with 32 jobs. First complete the small example in [QUICKSTART](QUICKSTART.md). You need
Git, Python 3.10+, `make`, Docker access as a non-root user, and local Linux disk space. In
WSL 2 keep the checkout and `IO` below the Linux home directory, not `/mnt/c` or a network
share. The worker's live state stays in Docker volumes.

### 1. Prepare and identify the image

Obtain the source as in [QUICKSTART](QUICKSTART.md), then work from the repository
root. No host Python package installation is needed for the Docker commands below.

```sh
make image
IMAGE=$(docker image inspect --format '{{.Id}}' faces12-campaign:1.0.0)
IO="$HOME/faces12-full"
mkdir -p "$IO"
printf '%s\n' "$IMAGE" > "$IO/image-id.txt"
git rev-parse HEAD > "$IO/source-commit.txt"
git diff --binary HEAD > "$IO/source-changes.patch"
docker run --rm --init --network none "$IMAGE" selfcheck
docker run --rm --init --network none "$IMAGE" provenance > "$IO/provenance.json"
docker image save -o "$IO/image.tar" "$IMAGE"
sha256sum "$IO/image.tar" > "$IO/image.tar.sha256"

f12() { docker run --rm --init --network none --user "$(id -u):$(id -g)" \
    -v "$IO:/io" "$IMAGE" "$@"; }
w() { cmd=$1; shift; bash pipeline/faces12-worker.sh "$cmd" --worker full01 --image "$IMAGE" "$@"; }
```

Use a new `IO` directory, not the example's. `selfcheck` must pass. The immutable
image ID fixes the image used by this shell; saving it preserves the installed
tools and sources for a later audit. The commit and diff record tracked source
changes, staged or not; they do not include untracked files. For a publishable release, also run
the complete [release validation](RELEASE.md), which checks two builds and the
real-tool workflow. `selfcheck` alone is not that validation.

### 2. Generate the full obligation

```sh
f12 formulas -o /io/formulas
f12 campaign init --formulas /io/formulas --solver-argv '["-q", "--lrat"]' \
    --proof-mode transient --author "Your name" -o /io/campaign.json | tee "$IO/campaign-init.json"
sha256sum "$IO/campaign.json" > "$IO/campaign.sha256"   # the file hash, not the campaign ID
f12 campaign prefixes --campaign /io/campaign.json -o /io/prefixes.json
```

Replace `Your name` with the campaign author's name. Formula generation checks all
59 pinned hashes. Initialization selects twelve prefix variables per formula,
giving 4096 initial regions per formula, 241,664 in total; it can take hours and
currently prints its result only when finished. Keep `campaign.json`, `prefixes.json`
and the entire `formulas/` directory. Do not add `--maps` or `--root`: those create
rehearsal campaigns. `--prefix 0` is a valid fully dynamic alternative,
chosen at initialization, but is a different campaign identity. Select `retain`
here if you intend to archive proofs; this walkthrough uses `transient` throughout.
`campaign-init.json` keeps what `campaign init` printed: the campaign ID (the SHA-256 of
the campaign document without its final line feed, not the hash `sha256sum` gives) and the
hashes of the tools.

### 3. Run, monitor and resume

Choose resource limits that fit the host; these example values are not a cost
estimate. `--disk` is lowered to the free space Docker actually has, with a note; choose it
so that the image and the backups keep room.

```sh
bash pipeline/faces12-worker.sh launch --worker full01 --image "$IMAGE" --io "$IO" \
    -- --jobs 4 --memory 8G --disk 50G --max-hours 24
w status
w logs --tail 30
w capacity
```

Omitting `--shard` assigns the full campaign to this worker. The 24-hour limit
bounds this session, not the mathematical obligation. The container runs in the
background. To inspect its final exit code after it stops:

```sh
docker inspect --format '{{.State.Status}} {{.State.ExitCode}}' faces12-full01
```

Exit 0 means that the worker's owned work closed; 1 means unfinished or blocked
work; 2 means a model; 3, 4, 5 or 6 need diagnosis from the log and the
[exit-code table](#exit-codes); 130 is a clean stop. A model requires mathematical investigation, not
more time to turn it into an UNSAT result. Initial `status.absent` is normal until
the first status document appears. For a clean pause and another session:

```sh
w stop
mkdir -p "$IO/backups"
w backup --to "$IO/backups"
w start
```

Do not run `launch` again for the same worker. `start` preserves its arguments;
to change budgets use `recreate` with the same `--io` and the desired run options
([recovery rules](#stop-resume-and-recovery)). Back up stopped results volumes as
well as `IO`; exports have a published lag and are not synchronous replicas.

### 4. Freeze and certify the exported evidence

After the worker has finished, or after `w stop` has returned, read the current
export generation rather than assuming it is always `journal.1.jsonl`:

```sh
JOURNAL=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["file"])' \
    "$IO/export/export.json")
f12 cubeproof certify --campaign /io/campaign.json \
    --journals "/io/export/$JOURNAL" -o /io/certificate.json
f12 cubeproof evidence package --campaign /io/campaign.json \
    --journals "/io/export/$JOURNAL" -o /io/evidence
f12 cubeproof certify --evidence /io/evidence/evidence.json -o /io/certificate-rechecked.json
python3 tools/certify_min.py certify --campaign "$IO/campaign.json" \
    --journals "$IO/export/$JOURNAL" -o "$IO/certificate-min.json"
python3 tools/certify_min.py compare "$IO/certificate-rechecked.json" "$IO/certificate-min.json"
sha256sum "$IO/evidence/evidence.json" "$IO/evidence/certificate.json"
```

Both certifiers must agree. `OPEN` (exit 1) is a valid intermediate result, not a
finished proof; examine the open work and resume. Packaging also works for an open
campaign. `certify -o` and `evidence package -o` refuse an existing output, so give every
later snapshot new names, for example a directory `/io/snap-$(date -u +%Y%m%dT%H%M%SZ)/`. For a full
refutation require `PROVED` (exit 0), all 59 formulas closed at the empty cube, no
models, and an explanation of every recorded anomaly. Preserve the image archive,
evidence directory, hashes and externally recorded journal heads.

### 5. Independently verify leaves and review the conclusion

For this walkthrough's transient proofs, the complete recomputation route is:

```sh
f12 cubeproof audit --evidence /io/evidence/evidence.json --all \
    --results /io/audit-all/results --work /io/audit-all/work --worker audit-all
```

This costs most of what the original computation cost: it recomputes every used leaf, without
the attempts that reached their time limit (in the pilot, 473 of the 648.5 core-hours went to
the used leaves). Run it on the auditor's own
machine with the preserved image, immutable evidence and fresh audit directories;
the local command above also works as a rehearsal. `--all` covers every used leaf;
`--sample N` does not. Strict audit succeeds only if all selected proofs are checked
and their hashes reproduced. A different but valid proof is a separate reproof
outcome, explained in [AUDITING](AUDITING.md). Retained proofs use its
`verify-retained` route instead.

Finally, a reviewer prepares the [claim review](COMPUTE.md#the-claim-review), with
the exact article and certificate hashes, mathematical review artifacts and anomaly
resolutions. With `review.json`, its relative artifacts and the reviewed article
copied into `IO`:

```sh
f12 claim --evidence /io/evidence/evidence.json --review /io/review.json \
    --article /io/faces12-en.tex
```

This step cannot be replaced by a generated approval file. `claim` checks the
review artifacts and journal attestations; it does not run an independent leaf
audit or verify the mathematics of the review. Report those obligations separately.
For several machines, keep this one full campaign and partition its roots using
[shards and handoff](#the-workflow-step-by-step); collect every worker's journal
before certification.

## One-command workflow (Docker)

One container is one worker. The host wrapper `pipeline/faces12-worker.sh` hides the `docker`
details. It controls Docker only: process execution, journals and audits run in Linux inside
the container. The image is `faces12-campaign:VERSION` (built by `docker/release/Dockerfile`,
validated by `docker/release/validate.sh`; [RELEASE](RELEASE.md)); name the one you built with
`--image` or `POLYHEDRAPROOF_IMAGE` (default `faces12-campaign:1.0.0`).

```sh
W="bash pipeline/faces12-worker.sh"
IO="$HOME/faces12 runs/worker 1"        # holds campaign.json and its bundles; spaces are fine
mkdir -p "$IO"
$W example --io "$IO"                   # optional: a small example campaign, minutes of work
$W launch  --worker w1 --io "$IO" -- --jobs 8 --memory 24G --disk 200G
$W status  --worker w1                  # add -- --json for the JSON document
$W logs    --worker w1 --tail 20        # docker logs; further words are passed to it
$W stop    --worker w1                  # docker stop -t 120: a clean stop
$W start   --worker w1                  # resumes from the journal
$W recreate --worker w1 --io "$IO" -- --jobs 8 --memory 24G --disk 200G
$W capacity --worker w1
$W names   --worker w1                  # prints the container and volume names
```

Each worker `NAME` has:

| Name | What |
|---|---|
| container `faces12-NAME` | started with `--init --network none`, as a non-root user |
| volume `faces12-results-NAME`, mounted at `/work/results` | the durable results: the journal and the worker's state. Never on a host bind mount |
| volume `faces12-work-NAME`, mounted at `/work/scratch` | disposable work |
| host directory `--io DIR`, mounted at `/io` | immutable inputs (campaign, shards) and the inbox, outbox and export directories |

`launch` creates the volumes if they are missing, gives empty ones to the worker's user, and
starts `run --campaign /io/campaign.json --results /work/results --work /work/scratch
--inbox /io/inbox --outbox /io/outbox --export /io/export` with the options after `--`. It
refuses a container that already exists: use `start`, or `recreate`, which removes the
container (never a volume) and launches it again. The worker receives container paths only,
so a host path with spaces is quoted once, by the wrapper. The exit code of the container is
the exit code of `run` ([the table below](#exit-codes)). Nothing in the wrapper deletes a
volume. `start` repeats the arguments the container was created with; `recreate` takes them
again, so give it the `--proof-mode` and `--policy-override` options the worker ran with, or
the run is refused (`run.policy_changed`).

| Option | Meaning |
|---|---|
| `--worker NAME` | the worker name of the journal and of the container and volumes: `a-z`, `0-9`, `_` and `-`, starting with a letter or digit, at most 48 characters. Every command but `example` needs it |
| `--io DIR` | the host directory mounted at `/io`; needed by `launch`, `recreate` and `example`. The wrapper refuses a path that contains a colon |
| `--image IMAGE` | the image, for every command that starts a container; `status` of a stopped worker is one of them |
| `--campaign FILE`, `--shard FILE` | below `--io`; the campaign defaults to `campaign.json`, a shard is optional |
| `--inbox DIR`, `--outbox DIR`, `--export DIR` | below `--io`; defaults `inbox`, `outbox`, `export` |
| `--user UID:GID` | the user the worker runs as: by default the caller's IDs; never 0 |
| `--prefix P` | the name prefix in place of `faces12` |
| `--to DIR`, `--from ARCHIVE` | for `backup` and `restore` ([below](#backups-and-the-recovery-point)) |

### Ownership of work

The first launch without `--shard` owns every requested root of the campaign, expanded by its
root splits, and persists that ownership. For the campaign of the 59 formulas with its default
root split that is 241,664 nodes: they are recorded as several shards (`initial-1`, `initial-2`,
...), because one journal line holds about fifty thousand, and the start of such a worker takes
a few minutes. A later launch never reconstructs ownership from a
changed command line: an identical shard is harmless, a different one is validated and
accepted or refused whole.

## Before a campaign is created

A campaign is identified by the hash of its whole document, and a journal belongs to one
campaign. What is decided when the campaign is created, and a few things decided at the first
launch, cannot be changed afterwards without starting again. Go through this list before
`campaign init`; the table [at the end of this page](#what-may-change-after-a-campaign-is-created)
says what stays free.

| Decide or check | Why it is final | How |
|---|---|---|
| The set of formulas | A campaign is one set of formulas. The journal of a campaign of one formula can never be certified with the campaign of the 59, and `claim` refuses a campaign that lacks a published formula. | For work that is to count for the result, create the campaign of all 59 formulas and give each worker its part (`shard`, with `--formula KEY` for single formulas). `--maps` and `--root` of `campaign init` make rehearsal campaigns. |
| The tools | The campaign names the solver and the checker by the SHA-256 of their binaries; a worker and an audit accept no other file. | Build and validate the release image ([RELEASE](RELEASE.md)); `selfcheck` must hold, including "cake_lpr and cadical are the binaries this release pins". Keep the image itself (`docker save`), not only its digest. `campaign init` refuses a checker that is not the release cake_lpr. |
| The solver arguments | They are part of the campaign and of every comparison of proof bytes. | `["-q", "--lrat"]`, the argument list of this release. |
| Whether proofs are kept | A leaf recorded without its proof can only be recomputed; a proof cannot be retained afterwards. | The default and the mode of this guide is `transient`: each proof is written to the work directory, checked, and removed. `retain` keeps every checked proof and `stream` writes none; choose one of them only on purpose, set it in the campaign (`campaign init --proof-mode MODE`), and for `retain` estimate the storage first (below). A mode given only to `run` has to be repeated at every start (a run that drops it is refused). |
| The root split | The requested roots and the root split are part of the campaign. | The default is the twelve-variable proof-prefix split: 4096 cases for each formula. |
| The campaign file | `created_utc` and `author` are in the hashed document, so the same command gives another campaign tomorrow. | Create it once. Keep `campaign.json` with its bundle directories in several places and publish the campaign ID. |
| The worker names | A name is in the header of its journal; two journals with one name cannot be certified together. | Give every worker of the campaign its own name, for good: a worker that replaces a lost one gets a new name. |
| One image for every worker and every audit | A strict audit compares proof bytes only within one execution profile: the solver, the platform and the C library, and for a `unit` leaf the cubeproof sources. | Run workers and audits from the same image, of one release. The proofs of a worker with another profile can be reproved, not compared byte for byte. A worker restarted on another release is refused (`run.code_changed`) unless `--accept-code-change` is given. |
| Where the journal is copied | A journal with one copy has no promise beyond the life of that copy. | Give every worker an export directory on another disk (`--export`; the wrapper uses `/io/export`) and back up the results volume. |
| How the result will be checked | A sample or a seed chosen after the results are known proves little. | Write down before the first launch who recomputes or rechecks, the size and the seed of an audit sample ([AUDITING](AUDITING.md)), and where the journals and their heads are published. |

### One formula on one machine

The smallest real computation is one formula with its default root split, one worker. So that
its work counts for the result, the formula is computed inside the campaign of the 59 formulas:
the campaign is created whole, and the worker is given the shard of that formula. The commands
need Docker, the release image you built and validated, and a checkout of this release for the
wrapper; `IO` is an absolute host path.

```sh
IMAGE=faces12-campaign:1.0.0                  # the tag of the validated image
IO=/data/faces12/io                           # inputs, shards and the exported journal
mkdir -p "$IO"                                # or Docker creates it, owned by root
export POLYHEDRAPROOF_IMAGE="$IMAGE"          # the wrapper's default image
W="bash pipeline/faces12-worker.sh"
f12() { docker run --rm --init --network none --user "$(id -u):$(id -g)" \
            -v "$IO:/io" "$IMAGE" "$@"; }
docker run --rm --init --network none "$IMAGE" selfcheck      # every check must hold
f12 formulas -o /io/formulas                  # the 59 bundles
f12 campaign init --formulas /io/formulas --solver-argv '["-q", "--lrat"]' \
    --proof-mode transient --author "Name" -o /io/campaign.json \
    | tee "$IO/campaign-init.json"            # hours, and silent until it ends
f12 shard --campaign /io/campaign.json --machines 1 --formula map01 -o /io/shards
$W launch --worker map01-a --io "$IO" --image "$IMAGE" --shard shards/shard-1.json \
    -- --jobs 8 --memory 24G --disk 50G
$W logs   --worker map01-a --tail 20          # a refusal at startup shows here
docker inspect -f '{{.State.Status}} {{.State.ExitCode}}' faces12-map01-a
$W status --worker map01-a --image "$IMAGE"
$W stop   --worker map01-a                    # a clean stop
$W start  --worker map01-a                    # resumes from the journal, also after a reboot
```

`campaign init` computes the proof prefix of every formula with the pinned solver: on a laptop
2 min 14 s for the formula of map 1 and 191 s for those of maps 1 and 2 together; the other 57
have not been measured, so allow some hours.
It prints nothing while it works and writes the campaign only at the end, so an interruption
loses all of it: run that line where a closed terminal does not end it (`tmux`, `nohup`). No
test creates the campaign of the 59 formulas with the real tools; this is its first run.
It prints the campaign ID and, under `tools`, the hashes of the solver and the checker with
`release_checker: true`; keep that output with the campaign file. `--proof-mode transient` is
the default and is written out to be explicit: a leaf's proof is checked and removed, and the
journal keeps its hash. `launch` returns when the container has started: a tool that is not
the campaign's, a failed known-answer control or a budget that does not fit ends the container
at once, which shows in `logs` and in the exit code ([the table below](#exit-codes)), not in
the output of `launch`.

The worker owns the 4096 cases of the formula and nothing else. It splits a case that the
solver does not finish within its time limit, and it ends with exit code 0 when its cases are
closed; `status` shows them, and the journal is exported to `IO/export/journal.<g>.jsonl`.
Exit code 0 of that worker, and "roots closed" in its status, are about its shard: the campaign
stays open until the other 58 formulas are closed, and only `certify` and `claim` speak about
it. Certify and package the journal as in steps 6 and 7 below (`f12 cubeproof certify ...` with
paths below `/io`): `certify` then exits 1, verdict OPEN, with `map01` proved. The other
formulas are planned later with their keys (`shard --formula`); a worker started without
`--shard` would own every root and compute map 1 again.

For a rehearsal that is thrown away afterwards, `formulas --maps 1` and `campaign init --maps 1`
create a campaign of that formula alone in about two minutes, and its worker is launched
without `--shard`. Give it another `IO` directory and another worker name: `campaign init`
does not overwrite a campaign file, and the results volume of a worker name keeps its journal.
It is another campaign: nothing of it can be used for the 59.

**Storage.** In `transient` mode a proof lives in the work volume `faces12-work-map01-a` from
its solve until its record is committed: a solve reserves the proof cap (4 GiB) plus its CNF
and logs, so eight jobs need about 35 GiB there, and the worker keeps a reserve of 2 GiB of the
measured free space besides. A `--disk` below one solve lowers the proof cap at startup, with a
note; a smaller budget otherwise means fewer solves at once, not a refusal. The results volume
`faces12-results-map01-a` holds the journal and the worker's state, a few kilobytes per case,
and the proofs the checker rejected (`quarantine/`, up to 20 GiB). Both volumes lie in Docker's
data directory (`docker info -f '{{.DockerRootDir}}'`), not in `IO`. `--disk` bounds the work in
flight and is lowered to the free space with a note; it does not reserve anything.
`$W capacity --worker map01-a` shows the sizes and which volumes share a disk. With
`--proof-mode retain` every checked proof is moved to the results volume and stays there; the
space for all of them (below) has to be free there, and again where `backup --to` writes its
archive.

**Sizing.** In the [pilot computation](../STATUS.md#the-pilot-computation) the formula of map 1
took 300 core-hours of solver and checker time and the formula of map 2 took 348: 13,981 and
17,206 leaves, after 659 and 874 splits, the deepest at 32 and 40 literals. In each formula
96 % of the 4096 cases closed at their first attempt; the attempts that reached their time
limit before a split took about a quarter of the processor time. With `--jobs 8` one formula
is therefore of the order of 40 hours, if it is like these two; no other formula has been
measured. Checking took about a sixth of the solver time of the leaves. A proof had a median of
35 MB, 82 MB on average and at most 1.14 GB, so the proofs of one formula take 1.2 to 1.4 TB
if they are retained. In the modes `transient` and `retain` a job runs the solver and then the
checker, never both (`stream` runs them together): the solver is limited to 1 GiB, and in the
pilot a check was given 1.1 or 1.6 GiB (a heap of 512 MiB, or 1 GiB for 197 large proofs, with
256 MiB of stack and 320 MiB of margin). A solver used at most 166 MiB there, and a check at
most 1.0 GiB. A job can use up to the proof cap (4 GiB) of work disk.

## The workflow, step by step

The commands below are the ones the wrapper runs, written with their explicit paths. Every
option is in the generated references: [cubeproof](cubeproof/cli-reference.md) and
[faces12-campaign](faces12/cli-reference.md); behavior that a parser cannot say is in
[cubeproof commands](cubeproof/commands.md) and the [application guide](faces12/application.md).
The packages install no console scripts: outside the image run them as `python3 -m cubeproof`
and `python3 -m faces12_campaign`; the image's entry point accepts the names `cubeproof` and
`faces12-campaign` (`docker run ... IMAGE cubeproof run ...`), and this page writes the commands
that way (a command without a program name, such as `formulas` or `campaign init`, goes to
`faces12-campaign`). Inside the image they fill in `--solver`, `--checker` and `--helper`;
outside it, give them explicitly: nothing is searched on `PATH`.

1. **Write the formulas.** `faces12-campaign formulas -o formulas` writes the 59 bundles
   and refuses to continue unless each formula has its published hash. Add `--check` to
   recompute and compare without writing.
2. **Create the campaign.**

   ```sh
   faces12-campaign campaign init --formulas formulas --solver /opt/faces12/bin/cadical \
       --solver-argv '["-q", "--lrat"]' --checker /opt/faces12/bin/cake_lpr \
       --author "Name" -o campaign.json
   ```

   `["-q", "--lrat"]` is the solver argument list of this release: the tests with the pinned
   tools and the pilot runs use it, and it belongs to the campaign's identity, so it cannot be
   changed later. With `-q` CaDiCaL prints no statistics and the `conflicts` field of an
   attempt stays null; what a leaf cost is recorded as the processor time and the peak memory
   of each process (`diagnostics.usage` of the attempt), beside the wall-clock `elapsed_ms`.
   The peak counts from the fork of the coordinator: a value near `launch_rss_kib` says only
   that the tool stayed below about the coordinator's own resident size.

   The default campaign has the 59 formulas, each requested root empty, the twelve-variable
   proof-prefix split (`proof-prefix-v1`) as root split, then the dynamic splitter `lookahead-v1`
   with k = 4, in `transient` proof mode (`--proof-mode retain|stream` chooses another). Without
   `--prefixes` the prefix is computed with the pinned solver, which can take long for each formula
   (on a laptop 2 min 14 s for the formula of map 1, 191 s for those of maps 1 and 2 together;
   the others have not been measured);
   `--prefixes FILE` reuses stored selections that validate
   against the pinned algorithm and solver. The campaign file is immutable and its ID is the
   SHA-256 of the document without its final line feed; the hashes of the tools are measured
   and recorded, and every worker must run exactly those tools. Keep the campaign file with its
   bundle directories: they stay below its directory.
3. **Plan machines** (optional: one worker that is started without `--shard` owns
   everything). `cubeproof shard --campaign campaign.json --machines 3
   -o shards` writes `shard-1.json` to `shard-3.json`, a disjoint cover of the requested
   roots, expanded one level through the campaign root split and dealt round robin
   (`--weights FILE` deals the largest costs first to the least loaded machine;
   `--formula KEY`, repeatable, plans the nodes of these formulas only, for example
   `--formula map01`). A machine
   whose nodes do not fit one journal line gets several files, `shard-K-1.json`,
   `shard-K-2.json`, ...: give the first with `--shard` and put the others into the worker's
   inbox, or its share stays partly unowned and visibly open.
4. **Run workers**, one per machine, each with its own results and work directories:

   ```sh
   cubeproof run --campaign campaign.json --shard shards/shard-1.json \
       --results /data/results-w1 --work /data/work-w1 --worker w1 --jobs 8 \
       --memory 24G --disk 200G --inbox /data/io/inbox --outbox /data/io/outbox \
       --export /data/io/export
   ```

   Stop it with SIGINT or SIGTERM (or `--max-hours H`); the next run resumes. `cubeproof status
   --results /data/results-w1` shows the monitor the run publishes. It is derived, not
   evidence, and a stale one is marked.
5. **Move work between machines** ([Handoff](#handoff)).
6. **Collect evidence.** Copy the journals (the live ones while stopped, or the exports),
   then `cubeproof evidence package --campaign campaign.json --journals w1.jsonl w2.jsonl
   -o evidence`: a directory that can be moved and checked elsewhere without any other
   file. Publish the hash of `evidence.json`, of the certificate and the head of every
   journal outside the machines that wrote them.
7. **Certify** with both certifiers and **audit** ([AUDITING](AUDITING.md)). A full campaign
   proof requires `certify` to exit 0: a worker whose requested roots closed has not proved
   anything about a formula whose other regions are open.
8. **Claim.** `faces12-campaign claim` is the only command that speaks about the article's
   conclusion, and only from a recomputed certificate and a human review
   ([COMPUTE](COMPUTE.md)).

### The policy

A campaign embeds a complete policy (SPECIFICATION §4.3). These are the defaults of
`default_policy` (`cubeproof.contracts.policy`). They are starting values: the coefficients of
the heap estimate were fitted to checker heap use observed in exploratory runs, and the arena
ladder (a check that exhausts its arena is repeated with the arena doubled) corrects a misfit
(SPECIFICATION §8.3); in the pilot computation no check needed it, and no node was blocked.
`--policy FILE` of `campaign init` embeds another complete policy.

| Setting | Default |
|---|---|
| Solver time for a leaf | 900 s at depth 12 (a cube of 12 literals), 300 s at every other depth |
| Proof cap; solver address space | 4 GiB; 1 GiB |
| Checker heap; checker stack | estimated from the proof size, at least 512 MiB, doubled after an exhaustion up to 8192 MiB; 256 MiB, doubled up to 2048 MiB |
| Checker time | 600 s, or 60 s for each started 100 MB of proof when that is more |
| Splitter | `lookahead-v1`, k = 4; cubes of at most 60 literals |
| Tool retries; machine failure limit; anomaly limit | 3; 5; 3 |
| Quarantine quota (file proofs the checker rejected) | 20 GiB |

`--policy-override KEY=JSON_VALUE` changes a field for one run and the change is recorded in
that run's journal; a stopped or blocked node stays stopped until `--reopen-blocked` records
an explicit reopen. A new policy alone never erases a stop.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | `run`: every region the worker still owns is closed, with no model, anomaly or block. `certify`: PROVED. `audit`: every selected target matched. Others: done |
| 1 | open work, a resource block or the end of the time allocation. `certify`: OPEN. `audit`: incomplete, not comparable, reproved only or empty. `handoff`: still pending after its wait |
| 2 | a valid model was found (`certify`: MODEL_FOUND) |
| 3 | usage, configuration or a lock conflict |
| 4 | integrity failure, inconsistency or a strict audit mismatch |
| 5 | a missing or failing tool, exhausted retries or an I/O service failure |
| 6 | the run recorded an anomaly and nothing of higher priority |
| 130 | stopped by the user after a clean shutdown |

When several conditions hold the priority is 4, 5, 2, 6, 1, 0 (SPECIFICATION §12.2). A run
reports the nodes it gave away separately and never says that handed-off regions are closed. A
preflight error returns before any work.

## Where the files are

| Place | Holds | Rules |
|---|---|---|
| `results/` (volume `faces12-results-NAME`) | `journal.jsonl`, the worker's only authoritative history; `run.lock`; `state.cache` (derived, discarded on any mismatch); `status.json` and `status.txt` (derived); `proofs/` (retain mode: `<node_id>-<proof_sha256>.lrat`, read-only) and `quarantine/` (file proofs the checker rejected) | local disk; one coordinator at a time (the lock is exclusive); never edited by hand; back it up |
| `work/` (volume `faces12-work-NAME`) | CNF files, unsealed and sealed proofs, helper requests of attempts in flight | disposable: nothing in it is evidence, and startup removes what a dead run left; two active workers must not share it; it must not lie inside `results/` or the other way round |
| `/io/` (a host directory) | the campaign and its bundles, optional `shard.json` (immutable inputs); `inbox/` with `accepted/`, `processed/` and `rejected/`; `outbox/<name>.json`; `export/` | not authoritative; exchanged by copying files; the worker only moves files within `inbox/` and writes `outbox/` and `export/` |
| an audit or verification directory | its own journal, `certified/` snapshots, `audit-report.json` or `verify-retained.json` | separate from the evidence it reads, which is never written |

The container user is non-root (by default the caller's UID and GID). `launch` hands the two
volumes to that user, as root in a throw-away container, only while they are empty; a volume
that already holds files is never re-owned. Evidence packages, retained proofs and snapshots are
written read-only. The results and the work volumes, and the container layer, normally share one
disk (on Docker Desktop, one virtual disk): `capacity` shows which mounts share a file system,
and `--disk` must budget them together, leaving room for the image. The scheduler also groups
paths on one device into one budget and keeps a default reserve of 2 GiB for each independent
storage group.

## Budgets and what happens when they do not fit

`--jobs`, `--memory` and `--disk` bound what the worker may reserve. The coordinator reserves
CPU, memory and disk for every task before it starts and starts nothing that does not fit.
Address-space limits on the tools do not bound physical memory, so the memory budget is derived
from the host or cgroup headroom minus a reserve and checked at least every ten seconds. A
task that could not run even on an idle machine is refused or split instead of waited for;
if nothing can progress, the nodes concerned are recorded as `resource_blocked` and the run
exits 1 stating the capacities and the requirement. A check that needs more memory than the
budget is not retried indefinitely: the arena doubles within its maximum, then the leaf is
split. The budgets are accounting, not a sandbox: give the container its own limit too
(SPECIFICATION §8.2, §8.3).

## Handoff

Giving work to another machine is a request, not a command to a process
(SPECIFICATION §7.4):

1. `cubeproof handoff --results /data/results-w1 --nodes 40 --output-name for-w2 --wait-ms
   60000` writes an immutable request into the inbox of the giving worker and, with a wait,
   follows the answer. With `--wait-ms 0` it only makes the request durable.
2. The running coordinator picks the oldest pending frontier nodes that are not running or
   split, **commits one handoff record that embeds the request and the complete shard**, and
   only then publishes `outbox/for-w2.json` atomically. From the commit on, the giver no
   longer owns those subtrees.
3. A crash between the commit and the publication is repaired at the next start: the same
   bytes are published, and a second node set is never chosen. A repeated request returns the
   earlier answer. A request that finds no node gets an answer without a shard.
4. You deliver the file (copy it into the inbox of the receiving worker, or pass it as
   `--shard`). The receiver commits an acceptance record before launching its nodes and then
   moves the file to `accepted/`. An identical shard is a no-op; one that overlaps what this
   worker already accepted or gave away is rejected whole.

A stopped worker serves requests at its next run; the command exits 1 when its wait ran out
and the request stays durable. Delivery is yours: a file that is never delivered leaves its
region visibly open in the certificate, and the outbox keeps the file for retransmission. To
take work back, plan it from the certificate's open list into a **new** worker and results
directory (`cubeproof shard --from-open CERT --journals ...`); ownership is never reversed
implicitly. Duplicate work on different workers is harmless: the certifier picks its evidence
deterministically.

## Stop, resume and recovery

| Event | What to do | What survives |
|---|---|---|
| Planned stop, reboot, `--max-hours` | `stop`, later `start` | everything; the run resumes from its journal |
| The coordinator or its container is killed | `start` (or `recreate`) | every committed record; an attempt without a committed result runs again (at-least-once, not exactly-once, solving) |
| Container lost, new image | `recreate` with the same inputs | the results volume; the work volume may be empty, the worker rebuilds it |
| Work volume lost | `start` (or `recreate` with the same inputs; `launch` only if the container was removed) | everything durable; unfinished attempts run again |
| Results volume lost, a backup exists | stop, restore the backup into an *empty* volume, then `start` (or `recreate` with the same inputs and `--io`; `launch` only if the container was removed) | what the backup holds and, if the export directory is newer than the backup, what the export holds: the run takes the missing records from it before it resumes ([below](#a-restored-backup-and-the-export-directory)). Only what was committed after both is lost and repeated |
| Results volume lost, only exports exist | plan the open work from the exported journals (`certify`, then `shard --from-open`) and run it in a *new* worker with its own export directory. A `launch` of the old worker stops with exit 3 (`export.foreign`): a new journal cannot continue the exported one | what the export holds; the lost worker's later records are gone |
| Host lost | on another host: copy the inputs, restore the backup or plan from the exports | as above |
| Disk lost, no backup, no export | nothing local | nothing: a local journal makes no promise beyond the life of its only copy |
| A journal ends in a partial line (no final line feed) | start the worker; or `cubeproof journal repair JOURNAL --campaign campaign.json` while no worker holds the lock | only the unterminated suffix is removed, and the repair is recorded |
| A complete line is damaged, or a retained proof is missing or corrupt | none automatically: the run stops with exit 4 | restore from a backup; keep the damaged file for investigation. Nothing truncates a complete line |
| The run stops at once with `export.regressed` or `export.diverged` (exit 4) | decide which history continues ([below](#a-restored-backup-and-the-export-directory)) | both the journal and the export, unchanged |
| A handoff file was published but not delivered | deliver it again from `outbox/` | the region stays open meanwhile |

The rows follow the crash table of SPECIFICATION §7.5. They are tested end to end
(`tests/endtoend`) by killing the process group and by
constructed on-disk states; neither simulates a power loss or a failing disk, which the
journal and artifact components cover by fault injection only ([STATUS](../STATUS.md)).

### Backups and the recovery point

Two copies of a journal can leave the machine:

- **Exports.** With `--export DIR` the worker copies a committed prefix of its journal, checks
  its hash chain, then publishes a descriptor with the exported position and head
  (`export.json`) last; the default interval is 60 seconds, and there is one more at a clean
  stop. `status` shows the export lag. An export is a backup with that lag as its recovery
  point objective, not a synchronous replica, and it lies in the host directory `/io/export`,
  usually on the same disk as the volumes: copy it, with its checksums, to separate storage.
- **Backups of the results volume.** `bash pipeline/faces12-worker.sh backup --worker w1
  --to DIR` (worker stopped) writes `faces12-results-w1-UTC.tar` and its `.sha256`;
  `restore --worker w1 --from ARCHIVE` (worker stopped) fills an *empty* results volume after
  checking the checksum and refuses anything but plain files and directories below `results/`.
  A volume that holds files is never overwritten: to replace damaged results, first move them
  aside yourself. The recovery point is the time of the last backup.

Neither can be better than the last copy that reached other storage. A journal copy that
you keep is anchored by its head and length; keep those with it.

### A restored backup and the export directory

The export directory outlives the results volume, and it is usually newer than the last
backup. A worker's journal and its export must stay one history: a certifier accepts two
copies of one journal only if one is a prefix of the other, and rejects a fork. So every run
compares the two before it writes its first record:

| The export directory holds | The run |
|---|---|
| nothing, or a prefix of the journal (the usual lag), or exactly the journal | starts; the next export continues the directory |
| more records than the journal, and the journal is a prefix of them (a backup older than the export was restored) | checks the exported records like journal records, appends the missing ones to the journal, logs `WARN journal.restored` and a note in its result, then resumes from the exported position. Nothing committed before the last export is lost or solved again |
| more records, but they cannot be taken over: the exported file is missing or damaged, or the records reference retained proofs that are not in the restored volume (`--proof-mode retain`: the proofs were lost with the volume) | stops with `export.regressed`, exit 4, before any record is written |
| another continuation of the same journal (the restored worker already ran with another export directory) | stops with `export.diverged`, exit 4 |
| the export of another journal, or an export while the results volume holds no journal | stops with `export.foreign`, exit 3 |

Nothing is changed when a run stops this way, and nothing in an export directory is ever
replaced by a different history. After `export.regressed` or `export.diverged` you choose:

- **Continue from the restored journal** and repeat the work after the backup: move the export
  directory aside (`mv DIR/export DIR/export-before-restore`) and `start` again, or `recreate`
  with another `--export NAME`; the run starts a new export. Keep the directory you moved: it
  is a valid journal copy of the longer history. Give `certify` and `evidence package` only one
  of the two, since together they are a fork and are refused.
- **Keep the exported history**: restore a backup that also holds the retained proofs, or treat
  the worker as lost and plan the open work of the exported journal into a new worker (the row
  "only exports exist" above).

An export that starts failing during a run (a full or unreachable disk) does not stop the run
and does not change its exit code: the journal is the evidence, the export a copy. It is
retried every interval and shows in three places: `ERROR export.failed` or `WARN export.failed`
in the log, `export consecutive_failures` and `export last_error` in `status`, and, if the
last export at the stop failed too, a note "the final export failed" in the run result.
Compare `status`'s `seq` with its `export: seq` before you rely on an export.

## Preserving what an audit needs

A strict audit needs the *same* tools and execution profile as the run. Keep, for every
campaign: the campaign file and its bundles; the image digest, its `provenance` document
(`docker run ... IMAGE provenance`) and the output directory of `docker/release/validate.sh`;
the exact sources of the tools and of the helper that the image archives under
`/opt/faces12/sources`; the source archive made by `faces12-campaign release bundle`; the
journals or the evidence packages, with the hashes you published.

## What may change after a campaign is created

| Item | Rule |
|---|---|
| Formulas, requested roots, root splits, policy, admission, tool hashes and solver arguments | Part of the campaign ID. A change is a new campaign; the journals of the old one are evidence only for it |
| Run-time overrides of the policy | A run may override fields of the embedded policy with `--policy-override`; the override is recorded in that run's journal and leaves the campaign unchanged. A record is judged against the machinery recorded at its own header or resume. The options are not remembered: a later run that does not repeat an override it was started with is refused (`run.policy_changed`) unless `--campaign-policy` says that the campaign's value is wanted |
| Proof mode | `--proof-mode` for a run; a recorded property of each attempt. A retained proof is never silently treated as transient, and a run started with `--proof-mode` is not silently continued in the campaign's mode: repeat the option at every start, or set the mode in the campaign (`campaign init --proof-mode`) |
| `--jobs`, `--memory`, `--disk`, `--max-hours`, results and work locations | Free to change between runs within the allocation; ownership of nodes is not |
| The release (the image and its cubeproof sources) | Not part of the campaign ID; every header and resume records `cubeproof_sha256`. A run that continues a journal whose session before ran other cubeproof sources is refused (`run.code_changed`, exit 3) unless `--accept-code-change` is given, and the session's notes then say so. Change the release of a running campaign only for a fix that matters to it: a strict audit of a `unit` leaf compares `cubeproof_sha256`, so the unit leaves recorded before the change are reproved, not matched byte for byte, by an audit on the new release ([AUDITING](AUDITING.md)) |
| The article, the documents | Not bound to a campaign: corrections do not affect it |

Do not modify or delete published evidence. A valid local chain cannot detect the removal of
its tail.
