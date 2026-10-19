# cubeproof commands, planner and portable evidence

This page documents the observable contract of the `cubeproof` command line and Python API
beyond what a parser can say: the input files, the shard planner, the portable evidence package
and how the pieces fit. The complete list of commands, arguments and exit codes is the generated
[command line reference](cli-reference.md); the normative text is
[SPECIFICATION](../SPECIFICATION.md) §4.9, §10, §11 and §12.

## Boundaries

* The **command line** (`python -m cubeproof ...`, `cubeproof.cli.main`) is the only code that
  reads the process arguments, prints to the standard streams or ends the process. It prints a
  result document (one JSON line, except `certify`, `campaign create` and `status`, which print
  one line or the rendered monitor) on standard output and notes, errors and the run log on
  standard error. Every error is reported as `cubeproof: error [rule] detail` and mapped to an
  exit code of SPECIFICATION §12.2.
* The **Python API** (`cubeproof.api`) mirrors the commands one to one with frozen request
  values and result values that have `to_json()` (plain JSON types). It does not read the
  environment, print or exit; a failure is a typed `CubeproofError` and `api.exit_code_of` gives
  the exit code the command would use. A run's log goes to a sink the caller passes.
* The **command layer** (`cubeproof.commands`) contains no scheduler. A run is the coordinator of
  `cubeproof.coordinator`; the command layer only completes its configuration and wires the
  status monitor, the export and the handoff desk around it.
* Tool locations are absolute local paths given on the command line (`--solver`, `--checker`,
  `--helper`); a relative path is made absolute at the command line. They must match the hashes
  of the campaign. Nothing is searched for and nothing is read from the environment.

## Input files

All files are canonical JSON documents (the `J` form of SPECIFICATION §4.1 plus one LF).

| Option | Document | Notes |
|---|---|---|
| `campaign create --policy` | a complete policy object (SPECIFICATION §4.3) | validated with the campaign rules before anything is published |
| `campaign create --admit` | `{checker_sha256, solvers}` | the configured tools must be admitted |
| `campaign create --roots` | `{format:"cubeproof-roots-1", roots:[Node]}` | the requested roots (a nonempty one is a pilot root); the constraints of SPECIFICATION §4.4 apply (one per formula at least, pairwise incompatible) |
| `campaign create --root-split static:FILE` | `{format:"cubeproof-prefixes-1", splits:[...]}` | entries have the shape of `root_splits` (node, variables, splitter), sorted by `split_id`; each lies on a requested root or the empty cube |
| `campaign create --root-split proof-prefix-v1:K` | none | the proof-prefix split of `K` variables (SPECIFICATION §9.2) with the defaults samples 2, steps 100000, conflicts 90000, seed 5, pool `order`, run with the pinned solver on the empty cube of every formula; needs the bundle's `order` pool; records the prefix and its provenance |
| `shard --weights` | `{format:"cubeproof-weights-1", campaign:Hash, costs:{node_id: positive int}}` | unspecified nodes cost 1; an unknown node ID or another campaign is an error |
| `run --shard` | `{format:"cubeproof-shard-1", campaign, name, nodes}` | produced by `shard` or `handoff`; checked against the campaign before the I/O service starts |

A `proof-prefix-v1` prefix for which the heuristic finds no candidate records no split at all
(never a zero-variable split); a static entry with no variables is refused (`split.empty`).
`bundle import` is the only place where an external DIMACS file is normalized: clause and literal
order are kept, the original bytes' hash is recorded as provenance.

## The shard planner

`cubeproof shard` writes `shard-K.json` files (`cubeproof-shard-1`) for machines `K = 1..N` into
a new directory and prints the plan (shards, node counts, costs, hashes, empty machines, the
keys of `--formula`). The nodes of a machine that do not fit one journal line are written as
several files `shard-K-1.json`, `shard-K-2.json`, ...; all of them belong to machine `K` (one
with `--shard`, the others through its inbox).

* **Default plan.** The requested roots are expanded through their direct campaign root split (one
  level) and dealt round robin in `node_id` order: node `i` (counted from 0) goes to machine `(i mod N) + 1`.
* **Weighted plan.** Nodes are taken largest cost first (ties by `node_id`) and each goes to the
  machine with the smallest accumulated cost (ties: the lowest machine index).
* **Plan from a certificate.** `--from-open CERT --journals JOURNAL...` plans the remaining work
  as the certificate's frontier, as it is, without expanding it. The certificate is **recomputed**
  from the journals and the given file must hold its bytes exactly; a certificate that its
  journals do not produce is refused, so a file cannot steer the plan. The file is compared, not
  parsed, so it has no size limit (SPECIFICATION §4.1): at its start the campaign of the 59
  formulas has a certificate of about 130 MB. A frontier containing a model node is refused.
  Stopped entries (`stuck`, `tool_blocked`, `resource_blocked`) are planned like the others and
  counted under `stopped`; a worker that runs them from a fresh results directory tries them again.
* **Scope.** `--scope campaign` (the default) plans `certificate.open`, the frontier below the
  requested roots; `--scope formulas` plans `formula_open`, everything left of every formula
  including what lies outside nonempty requested roots. A campaign with pilot roots must ask
  for the second explicitly.
* **Some formulas.** `--formula KEY` (repeatable) keeps, of the nodes of either plan, those of
  the campaign's formulas with these keys and deals only them. The rest of the campaign is then
  in no file: plan it later with the other keys, or from a certificate. This is how one formula
  is computed first by workers whose journals belong to the campaign of all formulas, which a
  campaign of that formula alone can never join. A key the campaign does not have is refused
  (exit 3), and a weights file may name only nodes that are planned, so the weights of the
  whole campaign are refused together with `--formula` (`weights.unknown`). The plan prints the
  keys under `formulas` (empty when every formula was planned). Three things to know when one
  formula is computed first: the worker ends with exit 0 and its status says that its roots are
  closed, which is about its shard, and only `certify` says that the campaign is open; a later
  worker started without `--shard` owns every root and computes that formula again; and a plan
  from a certificate takes every open node, also those of a formula in progress, unless
  `--formula` restricts it.
* Every plan is a disjoint cover: no node is planned twice and the nodes of a shard are pairwise
  incompatible. A machine without nodes gets no file. An output directory is never overwritten
  with other content (the identical plan again is harmless).

## Run options

`cubeproof run` accepts `--shard FILE` (the first use without it owns all requested roots, in
several shard records `initial-K` when they do not fit one journal line,
expanded by root splits; later runs never reconstruct ownership from a changed command line),
`--inbox DIR` and `--outbox DIR` (the handoff desk; `cubeproof handoff` writes an immutable
request into the inbox and follows the answer), `--export DIR` (the periodic journal export), and
`--reopen-blocked` (a `node_reopen` record for every blocked node before work starts).

The policy of a run is the campaign's policy with the `--proof-mode` and `--policy-override`
options of that command line; nothing is remembered between runs. A run that resumes a journal
with a policy that differs from the one the session before recorded, in a value its command
line does not name (by its dotted key, such as `split.vars`, or a key above it), is refused
with `run.policy_changed` (exit 3) before it records anything. The message lists the keys with
their old values in the form `--policy-override` takes; repeat the options, or pass
`--campaign-policy` to go back to the campaign's values on purpose. The proof cap is exempt, because every start clamps it to the machine.

In the same way a run that resumes a journal compares the cubeproof sources it runs
(`cubeproof_sha256` of the machinery) with those the session before recorded. Other sources, a
later release or a rebuilt image, are refused with `run.code_changed` (exit 3) before anything is
recorded; `--accept-code-change` (in the API, `accept_code_change=True` of `RunConfig`) continues
on purpose, records the new sources in the resume and says so in the notes of the result.

Before a session writes its header or resume record, `run` (and `audit`) ask the checker four
questions with known answers: one small refutation it must accept and three wrong ones it must
reject (SPECIFICATION §7.3). A checker that answers otherwise, or cannot be run, stops the
session with `tool.known_answer` (exit 5) and nothing is recorded. The campaign's hash says
which binary runs; the control says that it behaves as a checker on this machine.
`--no-known-answer` (in the API, `known_answer=False` of `RunConfig` and `AuditConfig`, whose
default is on) skips the control; it is meant only for tests with scripted tools, and a session
that skipped it says so in the notes of its result. `verify-retained` has no such control.

Before a run with `--export DIR` writes its first record it compares its journal with the
export in `DIR` (SPECIFICATION §7.5, [RUNNING](../RUNNING.md#a-restored-backup-and-the-export-directory)):

| Error | Exit | Meaning |
|---|---|---|
| `export.layout` | 3 | `DIR` is not a directory, or its parent does not exist |
| `export.foreign` | 3 | `DIR` holds the export of another journal, or an export while the results directory holds no journal |
| `export.regressed` | 4 | `DIR` holds more records of this journal than the results directory and they cannot be appended to it (damaged or missing export file, missing retained proofs) |
| `export.diverged` | 4 | the journal and the export are different continuations of one journal |

An export that holds more records of which the journal is a prefix is not an error: the missing
records are appended to the journal (`WARN journal.restored`, a note in the result) and the run
resumes after them. An export that fails after the start is logged (`export.failed`), shown by
`status` and retried; a failed last export is a note in the result and does not change the exit
code.

Every run publishes `status.json` and `status.txt` into its results directory (a derived monitor,
never evidence; `cubeproof status` shows them and marks a stale one) and logs progress to
standard error (`-q` quiet, `-v` verbose). The status counters cover the whole journal: a run
that resumes an existing journal feeds the records the replay validated to the monitor before the
I/O service starts, which costs a second validated pass over the journal at startup.

## Journals

`cubeproof journal verify JOURNAL --campaign FILE` validates every complete record with the
certifier's record rules and reports the journal's identity, extent and torn tail (exit 0, the
torn tail is noted on standard error). `cubeproof journal repair JOURNAL --campaign FILE` removes
only a torn tail and records the removal; it takes the containing results directory's `run.lock`
without waiting, so a live worker makes it fail with exit 3, and any other damage leaves the file
unchanged with exit 4 (restore from a backup). Both need the campaign because the record rules
depend on the formulas.

## Portable evidence

`cubeproof evidence package --campaign FILE --journals JOURNAL... -o DIR` certifies the inputs
and publishes a directory that can be moved to another machine and checked there without any
other file:

```text
DIR/
  campaign.json                 the campaign file, byte for byte
  bundles/<key>/manifest.json   the two files of every bundle the campaign names, at the
  bundles/<key>/formula.cnf     campaign's own relative paths
  journals/<worker>.jsonl       one snapshot per journal the certificate used
  certificate.json              recomputed from the copies above
  evidence.json                 the manifest, written last
```

The manifest is `{format:"cubeproof-evidence-1", campaign:Artifact, bundles:[{manifest:Artifact,
formula:Artifact}], journals:[Artifact], certificate:Artifact}` with `Artifact =
{path, sha256, bytes}`. Arrays are sorted by path and every path is a relative path inside the
directory.

**Publication order.** The dependencies (campaign, bundle files, journal snapshots) are written,
fsynced and made read-only first; the certificate is then recomputed from the copies and must
equal the certificate of the original inputs except for the torn tail the snapshots drop; the
manifest is written last, and the finished staging directory is renamed into place. A failure at
any step publishes nothing and removes the staging directory. A snapshot is exactly the
certified prefix of a journal (complete records only): records appended after certification and
a torn tail are not carried. Side files and retained proofs travel separately
(SPECIFICATION §4.9).

**Reading.** `--evidence MANIFEST` is the exclusive alternative to `--campaign`, `--journals` and
`--from-open` in `certify`, `shard` and `run` (and to `--certificate` in `audit`, to the
journals in `verify-retained`). The reader verifies the manifest (schema, order,
containment without symlinks), then the size and SHA-256 of **every** listed file, then that the
listed bundles are exactly the bundles of the campaign. Unlisted files are never read. A
malformed manifest is an input error (exit 3); a missing, resized or altered file is an integrity
error (exit 4). The certificate in a package is a claim: `certify --evidence` and `shard
--evidence` recompute it from the journals, and a packaged certificate that differs is an
integrity error (`evidence.certificate`).

`cubeproof evidence package` exits 0 whenever the package was published, whatever its verdict;
`certify` maps the verdict to the exit code. It prints one JSON line with `output`, `manifest`,
`manifest_sha256`, `certificate_file_sha256`, `campaign`, `verdict`, `bundles`, `journals` and
`duplicates` (input journal files that were copies of a journal already used).
`manifest_sha256` and `certificate_file_sha256` are the SHA-256 of the files `evidence.json` and
`certificate.json` as written, the numbers `sha256sum` prints; the second is the value the
manifest lists for the certificate. The `certificate_sha256` of an audit (the `audit_begin`
record, the audit report and the default seed) is another number: the document hash
SHA256(J(certificate)), which excludes the final line feed of the file (SPECIFICATION §4.1,
§11.1, §11.2).

## Audit

`cubeproof audit` (SPECIFICATION §11.1, §11.2) re-executes certified leaves and compares the new
proofs with the historical ones:

```text
cubeproof audit --campaign FILE --certificate CERT --journals JOURNAL...   (or --evidence MANIFEST)
                --sample N | --all [--seed HEX64] [--comparison strict|reprove]
                --results DIR --work DIR --worker NAME --solver PATH --checker PATH
                [--helper PATH] [--memory SIZE] [--disk SIZE] [--proof-cap SIZE] [--no-known-answer]
```

- **Binding.** The certificate is a claim, read as a regular file without the document size
  limit of campaigns and shards (SPECIFICATION §4.1). Each journal entry of it is an anchor
  `{id, records, head, bytes}`; the first `bytes` bytes of the input journal with that header ID
  are copied into a read-only snapshot `<results>/certified/<id>.jsonl` and must end exactly at
  the anchored record. Records appended after certification are never read. The certifier runs
  again on the snapshots and its result must equal the certificate (except the torn-tail sizes a
  snapshot cannot have); otherwise the audit stops with exit 4 (`audit.certificate`) before any
  target is chosen. An input journal the certificate does not name is refused as well.
- **Targets.** The population is the `used_attempts` of the recomputed certificate. `--all`
  selects all; `--sample N` (N > 0) the N smallest `(SHA256(seed + NUL + node_id), node_id)`,
  ordered by node_id, N clamped to the population. The default seed is the certificate's
  document hash (its SHA-256 without the final line feed); an explicit `--seed` lets a sample be
  fixed before the certificate exists. A 5% sample is `ceil(population/20)`.
- **Plan.** `audit_begin`, one `audit_target` per ordinal and `audit_ready` are committed to the
  audit's own journal `<results>/journal.jsonl` (header purpose `audit`) before any attempt. A
  restart in the same results directory regenerates the plan from the snapshots and refuses any
  difference (`audit.plan_changed`, exit 4): another selection needs another results directory.
- **Execution.** One target at a time, as a normal attempt record: the pinned solver runs with
  **no time limit** (`solver_time_ms: null`), the proof is checked by the admitted checker, a
  model is evaluated. The proof cap defaults to the larger of the policy cap and the largest
  selected reference proof, then is clamped to `--memory`/`--disk` like a run's. An audit keeps
  no proof files (proof mode transient). A TOOL_FAILED attempt is retried up to the policy's
  `tool_retries` before the target's final `audit_result`; a committed result is never repeated.
  An audit never splits a target and never swaps a tool: a strict audit runs only the source
  solver binary with the source argv, and a target whose source solver is not the configured one
  gets a placeholder attempt (TOOL_FAILED `launch`, cause `source_tool_unavailable`) and
  NOT_COMPARABLE.
- **Statuses.** Strict profile: solver hash and argv, platform and libc for CDCL; unit algorithm
  and package hash for unit proofs. Same profile and same proof hash: HASH_MATCHED; same profile
  and another hash: MISMATCH even if the new proof passed; another profile: REPROVED_UNSAT;
  resource exhaustion: OPEN; a valid model of a used target: FAILED `inconsistent_model`;
  a rejected new proof: FAILED `rejected`; tool failures: FAILED with the cause. Other machinery
  differences are listed in the reason.
- **Report.** `<results>/audit-report.json` (`cubeproof-audit-report-1`, exactly the fields of
  SPECIFICATION §11.2) is derived from the regenerated plan and a fresh read of the audit journal;
  every committed status is recomputed from its attempt, so a journal cannot claim a match its
  attempt does not show (`audit.result_status`). Exit 0 only when every selected target of a
  strict audit is HASH_MATCHED; a sample reports `population` and `selected`; a `reprove` audit
  never exits 0 and says that its guarantee is a new proof, not a historical match.

## Verifying retained proofs

`cubeproof verify-retained` (SPECIFICATION §11.4) checks every committed retained proof of the
given journals without a solver:

```text
cubeproof verify-retained --campaign FILE --journals JOURNAL...   (or --evidence MANIFEST)
                          --proofs-root DIR --results DIR --work DIR --worker NAME
                          --checker PATH [--memory SIZE]
```

Every committed VERIFIED_UNSAT record with a `retained` reference is expected; none is skipped
because its file is absent. The reference must name the record's proof
(`proofs/<node_id>-<proof_sha256>.lrat`, size and hash); the file is reached below the proofs
root without symlinks, hashed while it is copied into the work directory, and only the copy is
checked against the regenerated CNF with the record policy's arenas and check time (`--memory`
caps them). The report `<results>/verify-retained.json`
(`cubeproof-verify-retained-report-1`) lists the scope (journal IDs, records, heads and the
resolved proofs root) and the counts `expected, found, verified, missing, corrupt, rejected,
exhausted, failed` plus
`unretained` (verified leaves without a retained proof: a retained set does not verify them).
Exit 4 for any missing, corrupt or rejected proof, 5 for a checker failure, 1 for an exhausted
check or nothing expected, 0 otherwise. The evidence is only read; the results and work
directories must be separate from the proofs root.

## Regenerating the reference

```text
python -m cubeproof.cli.reference > docs/cubeproof/cli-reference.md
```

A test regenerates the document and compares it with the file in the repository.
