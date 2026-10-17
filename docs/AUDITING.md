# Auditing

Check the release first, then any published campaign. The release checks establish the
software's tested behavior; a campaign audit checks the evidence of a computation. Why each
step matters is explained in [TRUST](TRUST.md). No campaign of the 59 formulas has been run
([STATUS](../STATUS.md)); the procedure below is what the tools support and what the tests
exercise on small workloads. The normative rules of certification and audit are in the
[SPECIFICATION](SPECIFICATION.md) (SPECIFICATION §10, §11).

## The release

1. **Read [STATUS](../STATUS.md)** for what is tested and what has not been done, and
   [CLAIMS](CLAIMS.md) for the evidence and limits of each claim.
2. **Run the checks** from a source checkout (`make install-dev` first):

   ```sh
   make lint               # style, types, the claims ledger, article labels and relative links
   make test-architecture  # package boundaries, transitive imports, configuration, release list
   make test-fast          # the fast tests of the three packages and of the shared suites
   make test-installed     # wheels and sdists in clean environments outside the checkout
   ```

   `make test-all` runs every supported test, including the ones that need the pinned CaDiCaL
   and cake_lpr, and only inside the declared Linux test image
   (`bash docker/test/run.sh build`, then `bash docker/test/run.sh run` from a full clone of the
   source). A green `make test-fast` does not give the same assurance: it skips the tests
   that need the real tools.
3. **Check the image.** `bash docker/release/validate.sh /path/outside/the/checkout/validation`
   builds the release image twice without cache and compares the hashes of the tools, the
   helper, their sources, the three wheels, the source archive, the 59 formulas, every
   installed file and the release provenance document without its time of recording; it
   then runs the image's `selfcheck`, the tests of the image and of the wrapper, and a
   two-worker run in containers of the image with crashes, a handoff, certification and a
   strict audit ([RELEASE](RELEASE.md)). Image IDs, layer timestamps and sdists are not
   compared.
4. **Check the formulas and the controls.**

   ```sh
   python3 -m faces12_campaign selftest          # identities, corpus and map 1
   python3 -m faces12_campaign formulas --check  # all 59 pinned hashes
   python3 -m faces12_campaign maps              # recompute the census (minutes)
   ```

5. **Read the article**, [`paper/faces12-en.pdf`](../paper/faces12-en.pdf).
   [THEORY_MAP](THEORY_MAP.md) lists every statement with the code and the tests that
   check it. The cube-tree coverage statements (paper: thm:coverage, lem:closure) are written
   proofs; the tests check the implementation, not the proofs.
6. **Read what no test can check.** [CLAIMS](CLAIMS.md) marks the statements that have a
   proof and no test, and the limits of the tests that exist: the proofs in the article, the
   conventions the reference encoder shares with the encoder, the scope of the hypotheses
   (H1) to (H3) (paper: hyp:H), and the citations marked open
   ([SOURCES](SOURCES.md)).

## A campaign

The commands below use the release image's command names. Outside that image,
replace `cubeproof` by `python3 -m cubeproof` and `faces12-campaign` by
`python3 -m faces12_campaign`; the packages do not install console scripts.
The [full campaign walkthrough](RUNNING.md#full-campaign-on-one-host) provides a
Docker function for running these commands with consistent paths and pinned tools.

A campaign is the complete obligation: the 59 formulas, each closed at its empty cube
([RUNNING](RUNNING.md)). What you audit is an **evidence directory**: the campaign, its
bundles, snapshots of the journals, the certificate and a manifest `evidence.json` that
lists every file with its size and SHA-256 (`cubeproof evidence package`). Take the
following from the publication and compare them with what you hold: the campaign ID, the
SHA-256 of the certificate and of each journal head, the image digest and the hashes of the
tools. A journal's chain cannot show that its tail is complete; only a head you obtained
independently can.

Two different SHA-256 values describe one certificate. The manifest and the
`certificate_file_sha256` that `cubeproof evidence package` prints are the hash of the file
`certificate.json` as written, the number `sha256sum` prints. The `certificate_sha256` of an
audit report, and the default seed of an audit, is the document hash, which excludes the
final line feed of the file: `head -c -1 certificate.json | sha256sum`. Say which of the two
a published number is.

1. **Certify twice.** The main certifier recomputes the certificate from the evidence, and
   the independent one does it without sharing any code:

   ```sh
   cubeproof certify --evidence EVIDENCE/evidence.json -o certificate.json
   python3 tools/certify_min.py certify --campaign EVIDENCE/campaign.json \
       --journals EVIDENCE/journals/worker-a.jsonl EVIDENCE/journals/worker-b.jsonl \
       -o certificate-min.json
   python3 tools/certify_min.py compare certificate.json certificate-min.json
   ```

   Exit 0 means PROVED; 1, OPEN; 2, a model; 4, an integrity failure, including a packaged
   certificate that its journals do not produce. Both should write the same bytes. If they
   differ, one of them has a defect: do not publish before it is explained.
2. **Read the certificate, not only its verdict.** `open` and `formula_open` list the work that
   remains; `not_admitted` lists attempts made with tools the campaign does not admit (their
   models and anomalies still count); `models` and `anomalies` must each be examined and
   resolved ([COMPUTE](COMPUTE.md)); `machinery` shows which binaries, platform and limits made
   each used leaf. Its `runtime.image_digest` is `null` in every journal the command line
   writes, inside the release image as well: a container cannot read the digest of its own
   image. The field therefore does not identify the image; the image digest is the one you take
   from the publication and check with Docker. A journal names its worker and no machine. A
   bounded run may close a nonempty requested root (a pilot root) while the
   certificate stays OPEN: that is not a proof of the formula (paper: rem:pilotroot).
3. **Choose the verification you can afford.** The certificate is an attestation: it says
   what the journals claim, not that anybody checked a proof afterwards. Either route below
   verifies leaves independently; neither is cheaper than its scope.
4. **Recompute leaves** with the tools of the campaign, in the release image whose digest
   you checked (`IMAGE` is the tag or digest of that image):

   ```sh
   docker run --rm --init --network none --user "$(id -u):$(id -g)" -v "$PWD/audit-io:/io" \
       "$IMAGE" audit --evidence /io/evidence/evidence.json --sample 50 \
       --seed 1111111111111111111111111111111111111111111111111111111111111111 \
       --results /io/audit/results --work /io/audit/work --worker auditor-1
   ```

   The entry point supplies the pinned solver, checker and helper explicitly. Without Docker,
   pass `--solver`, `--checker` and optionally `--helper` yourself and use the same binaries
   the campaign pins. `--results` and `--work` are the audit's own directories, never the
   evidence; the evidence is only read.
5. **Check retained proofs**, if somebody kept them (`retain` mode):

   ```sh
   cubeproof verify-retained --campaign campaign.json --journals worker-a.jsonl \
       --proofs-root /data/results-worker-a --results verify/results --work verify/work \
       --worker verifier-1 --checker /path/to/cake_lpr
   ```

   Every committed retained reference of the journals is expected; a missing, corrupt or
   rejected proof is an integrity failure (exit 4), and nothing is skipped because its file
   is absent. A report that lists `unretained` leaves says that those leaves are not covered
   by it.
6. **Check the application claim.**

   ```sh
   faces12-campaign claim --evidence EVIDENCE/evidence.json --review review.json \
       --article paper/faces12-en.tex
   ```

   It recertifies, requires PROVED for exactly the 59 published formulas and a resolution
   for every anomaly, and prints a conditional statement until the review attests the
   enumeration, the encoding and the reduction with verified artifacts
   ([COMPUTE](COMPUTE.md)). The review is a human attestation, not a signature.

## Strict audit and reproof

`cubeproof audit` first binds the certificate to the exact journal prefixes it names
(records appended later are never read), recomputes the certificate and refuses to go on if
it differs. It then regenerates each selected leaf from the bundle and the cube, runs the
recorded solver **without a time limit** (an audit never splits and never swaps a tool), has
the admitted checker check the new proof, and compares.

| Status | Meaning |
|---|---|
| `HASH_MATCHED` | The same execution profile produced the same proof bytes, and the new proof was checked: the leaf is verified now and reproduced |
| `MISMATCH` | The same profile produced other bytes. The leaf may still be verified, but something differs from the record, which needs an explanation |
| `REPROVED_UNSAT` | Another profile (solver binary, options, platform, libc) produced a checked proof. The leaf is verified now; nothing is reproduced |
| `NOT_COMPARABLE` | The source solver or profile is not available and no reproof was made |
| `OPEN` | The new run exhausted a resource |
| `FAILED` | A tool failed, the new proof was rejected, or the solver found a model of a leaf the certificate used (an inconsistency, never `NOT_COMPARABLE`) |

`--comparison strict` (the default) exits 0 only when every selected target is `HASH_MATCHED`.
`--comparison reprove` never exits 0, and its report says that its guarantee is a new proof, not
a historical match. Strictness depends on determinism of the pinned CaDiCaL under one execution
profile; if it fails, the report shows it as `MISMATCH`, which has to be explained before the
campaign is relied on (SPECIFICATION §11.3). Run a strict audit in the same image (or an
identical build) as the campaign, with the campaign's solver binary and options. A `unit` leaf
is compared by its unit algorithm and `cubeproof_sha256`: the unit leaves recorded by another
release (a journal continued with `--accept-code-change`) are reproved, not matched, by a strict
audit, which then exits 1 for them.

## What a sample shows

`--sample N` selects the N used leaves with the smallest `SHA-256(seed NUL node_id)`
(`N` is clamped to the population, and the report states the population and the number
selected). The default seed is the SHA-256 of the certificate; to fix the selection in advance,
publish an explicit `--seed` before you start. `--sample` takes a count, not a fraction: a
sample of 5 % of the leaves is `ceil(population/20)` leaves. A sample verifies the leaves it
selected and nothing else. The report gives counts, not a statistical bound on the
rest. Only `--all` with every target `HASH_MATCHED` (strict) or verified (reprove) covers
the whole certified tree. An audit whose population is empty is not a success: it reports an
empty, OPEN audit and exits 1.

An audit runs to completion in its own results directory; restarting there continues the
same plan and refuses a different selection (`audit.plan_changed`): use a new directory for
a new selection.

## What does not count

- A journal, certificate or evidence directory you did not recompute: it records that a
  checker once said so, somewhere else.
- A sample, for the leaves it did not select.
- A `REPROVED_UNSAT` as a reproduction of the original proofs.
- The agreement of the two certifiers as evidence that the journals are honest.
- Anybody else's audit results directory, resumed.
- The solver's own answer, which is never evidence.
