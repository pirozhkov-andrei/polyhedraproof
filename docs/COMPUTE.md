# Contribute computing resources

The project needs CPU time, independent recomputation and, if anyone can offer it, storage,
to settle 59 SAT instances. The complete computation has not been carried out, and there is no
public worker queue. A pilot computation refuted two of the formulas in 648.5 core-hours; from
it the 59 are estimated at about 19,000 core-hours, an order-of-magnitude estimate
([STATUS](../STATUS.md#the-pilot-computation)).

## What help is needed

- **CPU time for the campaign.** Linux on x86-64 (a laptop, a server, a batch node, a cloud
  machine), Docker, local disk. Each machine works on its own share of the cube tree
  ([RUNNING](RUNNING.md)). The memory and disk a worker needs depend on the policy of the
  campaign; the options `--jobs`, `--memory` and `--disk` bound what a worker may reserve, and
  a task that does not fit is split or recorded as blocked, not started. In the pilot a formula
  took 300 to 350 core-hours, of the order of 40 hours for a worker with 8 jobs, and no solver
  or checker process used more than 1.0 GiB ([RUNNING](RUNNING.md#one-formula-on-one-machine)).
- **Independent recomputation.** Anyone with the release image can recompute a sample of the
  leaves of a published certificate, or all of them, and compare the proof hashes with the
  journals ([AUDITING](AUDITING.md#a-campaign)). A complete independent recomputation is what
  would verify the computation without trusting the original run; a sample verifies only what it
  selected.
- **Storage for proofs.** Proofs are not kept by default
  ([decision 0011](decisions/0011-three-proof-modes.md)): the pilot wrote 1.2 and 1.4 TB of
  checked proofs for its two formulas, which extrapolates to about 76 TB for the 59. Somebody
  able to hold them (and to receive them) would make a second route possible, checking the
  retained proofs without the solver (`cubeproof verify-retained`, proof mode `retain`). Please
  say so if you can; otherwise verification is by recomputation.
- **Mathematical and systems review** of the reduction, the encoder, the cube-tree statements
  of the article and the pipeline ([TRUST](TRUST.md)).

## How to contribute CPU time

No campaign is being organized at present; this is the procedure an organizer and a contributor
would follow.

1. **Contact the author** by e-mail (the address is on the first page of the article) or in an
   [issue](https://github.com/pirozhkov-andrei/polyhedraproof/issues) of the repository.
   Describe CPU allocation, memory, storage and operating constraints, and say
   whether you can keep a backup of the journal outside the machine. Agree on a bounded share.
2. **Receive the campaign package** from the campaign organizer: the release image
   (or the source archive to build it) with the image digest and the validation output of
   `docker/release/validate.sh` ([RELEASE](RELEASE.md)); the campaign file with its bundles;
   your shard file; a unique worker name; and the published campaign ID. Execution uses CPU
   processes only; there is no GPU backend. The image targets `linux/amd64`.
3. **Check what you received.** The campaign ID is the SHA-256 of the campaign document without
   its final line feed (`head -c -1 campaign.json | sha256sum`; `sha256sum campaign.json` gives
   a different number); compare it and the tool hashes recorded in it with what the image
   reports (`docker run ... IMAGE provenance`).
   A worker refuses a campaign whose pinned tools are not the ones installed. The checker of a
   campaign of the 59 formulas is the cake_lpr binary of the release, whose SHA-256 is recorded
   in `faces12_campaign.pins`; `campaign init` refuses another one unless told otherwise, and the
   image's `selfcheck` fails when its tools are not the recorded ones.
4. **Run the assignment** with the wrapper (`launch`,
   [RUNNING](RUNNING.md#one-command-workflow-docker)), within your allocation: `--jobs`,
   `--memory` and `--disk` inside what the job may use, and a memory limit for the container as
   well, because the budgets are accounting, not a sandbox. Leave the policy as the campaign
   embeds it; `--policy-override` is recorded in the journal and should be agreed beforehand.
   Stop and start the worker as your allocation requires; it resumes from its journal.
5. **Move work if asked.** The organizer may ask you to give nodes away (`cubeproof handoff`)
   or to accept a handoff file. Delivering such a file is a manual step; an undelivered file
   leaves its region visibly open.
6. **Return the evidence.** At the end of an allocation stop the worker and send the journal
   (the live file while stopped, or the periodic export with its `export.json`), and publish its
   head and length where the organizer can compare them; the organizer packages the
   journals with `cubeproof evidence package`. Keep your own copy and a backup of the results
   volume until the organizer confirms receipt; the journal on your machine is the only copy
   until then, and nothing local survives the loss of a disk.

Only an admitted `VERIFIED_UNSAT` attempt closes a node. A timeout or exhausted resource
leaves work open, a model requires investigation but does not stop the run, and a
nonempty requested root that closes does not prove its formula. Whether the whole computation
is complete is decided by `cubeproof certify`, not by any worker's exit code.

Agree on acknowledgements before contributing. See [STATUS](../STATUS.md) for the remaining
obligations and [RUNNING](RUNNING.md#what-may-change-after-a-campaign-is-created) for what may
change after a campaign is created.

## Models and anomalies

A model of a formula is an assignment that satisfies its clauses, which are necessary
conditions only; it is not automatically a geometric realization (paper: rem:noconverse). If a
certificate lists one, `faces12-campaign model --evidence EVIDENCE/evidence.json` describes it
in the article's vocabulary (brackets, orders, violated clauses per layer, reflex corners) and
exits 2. It is examined by a person, and a valid model contradicts a completed proof of the
same formula (`INCONSISTENT`, exit 4).

An *anomaly* (a claimed model that is not one, a rejected proof, a malformed split) does not
invalidate an otherwise complete proof tree, but it stays in the certificate. Before any
application claim, every anomaly needs a written resolution in the claim review.

## The claim review

`faces12-campaign claim --evidence EVIDENCE/evidence.json --review review.json --article
paper/faces12-en.tex` recertifies the evidence and reads a review file of format
`faces12-claim-review-1`, whose fields are listed in the [application
guide](faces12/application.md#the-claim). The review is a human attestation: it names the
reviewer, the certificate and article hashes, the checker hashes of the campaign, whether each
of the three obligations (`enumeration`, `encoding`, `reduction`) is reviewed (with a verified
artifact) or still open (status `outstanding`), and the resolution of every anomaly. The
command prints a conditional statement of computational support while any obligation is still
open, and the unconditional article conclusion only when all three are reviewed with artifacts
that verify. Writing the file does not replace the mathematical review, and the review is not
a signature.
