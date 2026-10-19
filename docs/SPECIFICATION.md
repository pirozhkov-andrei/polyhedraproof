# Specification

The normative description of the behavior and the file formats of the three packages
`cubeproof`, `neighbourly` and `faces12-campaign`. An overview of the structure of the code
is in [ARCHITECTURE](ARCHITECTURE.md); the decisions behind it are the
[design records](decisions/README.md). The section numbers are stable: documents cite this
text as "SPECIFICATION §7.1", code and schemas as "specification §7.1".

The text is normative and terse: it states rules, often without articles or connectives, and
leaves explanation to the other documents. Where a sentence here and a guide differ, this
text governs.

## Navigation

1. [Scope and guarantees](#1-scope-decisions-and-guarantees)
2. [Components](#2-components-dependencies-and-layout)
3. [CNF and identity](#3-identity-cnf-and-cubes)
4. [File formats](#4-file-formats-and-shared-types)
5. [Trust](#5-trust-and-claim-obligations)
6. [Leaf execution](#6-leaf-execution-and-outcome-precedence)
7. [Durability and handoff](#7-durability-restart-and-offline-transfer)
8. [Scheduling and resources](#8-coordinator-and-resource-model)
9. [Splitters](#9-splitter-contracts)
10. [Certification](#10-certification)
11. [Audit](#11-recompute-audit-and-retained-proof-verification)
12. [Commands](#12-commands-and-observable-behavior)
13. [Mathematical package](#13-mathematical-package-and-application)
14. [Packaging and operation](#14-packaging-platforms-and-operation)
15. [Verification](#15-verification)
16. [Decisions and references](#16-decisions-and-references)

## 1. Scope, decisions and guarantees

### 1.1 Approach

A fixed partition gives no recourse when a case exceeds the configured proof, time or
checker-memory limits. The system therefore uses a recorded tree of cubes: it tries a
bounded leaf, checks its proof, and splits an exhausted leaf into smaller work. The formula
remains fixed throughout a campaign.

The default path is **solve once to local disk, then check the sealed proof**. Checker
arena retries reuse that proof. The coordinator schedules solve, check and split tasks
separately. Independent machines receive offline shards and exchange work by files.

### 1.2 Contract language and authority

**MUST/MUST NOT** specify a contract. **SHOULD** specifies a default engineering choice
whose deviation needs a written reason and review. **MAY** gives an implementation option.
Sections labelled *Informative* describe rationale, not additional requirements.

This document owns behavior and file semantics. A code/spec discrepancy is a defect until
resolved; a contract is not silently changed to fit code. A necessary semantic change is
recorded in a decision with affected schemas, fixtures, consumers and tests. Incompatible
wire changes also require new format versions.

The complete specification is this file, including the field tables. The schemas
(`schemas/cubeproof/v1`) and the test vectors (`tests/contracts/corpus`) are executable
transcriptions, not an opportunity to choose different semantics.

### 1.3 Release scope

The release includes three packages, a Linux CLI/image, a Linux host wrapper, dynamic
splitting, both certifiers, offline handoff, audit, and all three proof modes (`transient`,
`retain`, `stream`).

Not in scope: network coordination, a mandatory database, GPU solving, incremental
assumption-based proof batches, a second external checker, or changes to the encoding.
Derived state on disk, such as the state cache (§7.3), is disposable; journals remain
authoritative.

Names are fixed: `cubeproof`, `neighbourly` (including its CNF-emission module
`neighbourly.cnf`), `faces12-campaign` (import `faces12_campaign`). Local builds and the
image do not require publication on PyPI.

### 1.4 Guarantees and limits

Priority: soundness of claims, auditability, durability, resource efficiency, usability.

| Guarantee | Exact scope |
|---|---|
| Formula identity | Exact canonical DIMACS bytes, verified by SHA-256 |
| UNSAT attestation | Accepted checker attestations plus complete, independently reconstructed cube coverage |
| Independent verification | Recheck retained proofs, or recompute and check selected/all leaves |
| Crash recovery | With intact durable storage, lose only uncommitted work; committed records and retained artifacts survive |
| Resource accounting | Do not start work exceeding measured scheduling budgets; detect and handle external pressure |
| Offline distribution | Duplicate work is safe; missing coverage remains visible; durable handoff publication is recoverable |
| Formula stability | The 59 base formula byte strings are fixed; the units of a case CNF are sorted by variable (§3.3) |

A journal is an attestation, not a stored LRAT proof. Its hash chain does not authenticate
its writer. A certificate cannot establish that a dishonest admitted writer actually
ran the checker. A sample audit does not verify unsampled leaves. Neither tests nor
reviews replace the article's mathematical obligations.

No finite time-to-completion guarantee is made. `STUCK`, resource-blocked work and models
are reported explicitly. External processes, filesystem failure or total disk loss can
defeat local availability. Backups have the published export interval as their RPO.

## 2. Components, dependencies and layout

### 2.1 Three distributions

| Distribution | Responsibility | Runtime dependencies |
|---|---|---|
| `cubeproof` | Generic bundle consumer, leaf protocol, scheduling, evidence, certifying and auditing | Python stdlib; external pinned tools |
| `neighbourly` | Generic CNF emission in `neighbourly.cnf` (deterministic variables/clauses, witness checks, DIMACS and bundle writing); maps, exact geometry, S/H/A/B/I encoding, gauge, interpretation, mathematical corpus | Python stdlib |
| `faces12-campaign` | 59-formula campaign, claim gate (§13.3), launch/release/documentation integration | `cubeproof`, `neighbourly` |

`cubeproof` MUST NOT import the other packages. Its mathematical input is a bundle on
disk. Tests may compare independent implementations across package boundaries; runtime
code may not. There is no third-party Python runtime dependency. Own-package dependencies
above MUST nevertheless be declared in packaging metadata.

`neighbourly.cnf` is problem-independent and keeps a hard boundary: it imports only the
standard library and its own submodules, never another `neighbourly` module, and it does
not read package data. Architecture tests enforce this, so the module is separable from the
rest of the distribution. A producer for another problem may reuse it by depending on
`neighbourly`, whose runtime is stdlib-only. External DIMACS needs no producer library:
`cubeproof bundle import` (§3.1, §12.1).

### 2.2 Repository

```text
packages/
  cubeproof/          pyproject.toml README.md src/cubeproof/ tests/ native/
  neighbourly/        pyproject.toml README.md src/neighbourly/ tests/
    src/neighbourly/cnf/            generic CNF emission: builder witness encodings dimacs bundle
    src/neighbourly/data/n12/       matrices/ formula_hashes_n12.json
    src/neighbourly/data/fixtures/  tetrahedron/ szilassi/ additional maps
  faces12-campaign/   pyproject.toml README.md src/faces12_campaign/ tests/
schemas/cubeproof/v1/               JSON schemas and requirements.json; schemas/index.json
tests/contracts/                    shared fixtures, vectors, expected results
tests/architecture/                 dependency and configuration checks
tests/release/                      installed-artifact checks
tools/certify_min.py                 independent certifier
docker/                             test/release image and pinned toolchain
pipeline/                           thin Linux host wrapper
docs/SPECIFICATION.md               this specification
docs/decisions/                     design records
paper/                             canonical mathematical article
pyproject.toml Makefile RELEASE_FILES.txt README.md STATUS.md CHANGELOG.md
```

The root `polyhedraproof` distribution is a meta-package requiring the three exact
versions of the same release.

Mathematical data specific to 12 belongs to `neighbourly.corpus12`; campaign policy,
publication and operational defaults for this problem belong to `faces12_campaign`.
Package data is accessed through `importlib.resources`, not paths into a checkout.

### 2.3 Internal dependency graph

`cubeproof` uses the following allowed edges; dependencies are transitive, so a forbidden
import cannot be hidden behind another module.

| Layer | May depend on |
|---|---|
| `cli`, `api` | `commands` and lower layers |
| `commands` | coordinator, leaf, split, evidence, tools, cnf, contracts, base |
| `coordinator` | leaf, split, evidence, tools, cnf, contracts, base |
| `leaf`, `split` | evidence storage/schema, tools, cnf, contracts, base |
| `evidence.certify` | evidence.schema, evidence.journal, cnf, contracts, pure base helpers |
| `evidence.schema`, `evidence.journal` | contracts and pure base helpers |
| `tools` | cnf, contracts, base |
| `cnf` | contracts, pure base helpers |
| `contracts`, `base` | stdlib only; contracts may use pure base helpers |

Same-layer imports are allowed only within the named subsystem; no dependency cycles.
The checker-result-to-record binding lives in `leaf.binding`, not the certifier's schema
reader. `contracts` contains immutable values and enums, never subprocess execution.
`base` separates pure hashing/JSON/errors from process/resource probes; certifier imports
only the pure subset. The independent certifier imports none of the project.

Inside `neighbourly.cnf`: bundle -> dimacs/builder -> witness/encodings/pure helpers; it
imports no other `neighbourly` module (§2.1). For the rest of `neighbourly`:
interpret/checks/corpus12 -> encoding/enumeration/exact -> maps/pure helpers, and each of
these may import `neighbourly.cnf`; generic modules do not import corpus12. For the
application: cli/api -> commands -> release/campaign/claim adapters -> libraries; the adapters
share the constants of `faces12_campaign.pins` (the hashes of the release tools, §13.3). Explicit
exceptions must be listed and tested, not silently admitted by a coarse tier number.

CLI and API are both entry boundaries: they construct Settings values. Environment is
read only there. Values are passed down; errors are typed and printed/exited only by CLI.
Workspace owns operational result/work paths. Pure libraries take explicit input/output
paths and need no artificial Workspace abstraction.

## 3. Identity, CNF and cubes

### 3.1 Canonical DIMACS

Let V and M be nonnegative integers. Canonical bytes are ASCII: `p cnf V M\n`, followed by
exactly M clause lines. Each nonempty clause is decimal literals joined with one space
followed by ` 0\n`. The empty clause is **` 0\n`**. An empty formula has only its header.
Literals are nonzero, `abs(literal) <= V`; no plus signs, leading zeros or negative zero.
No comments, CR, blank lines or extra whitespace. Header counts and all literals are
validated.

Clause order and literal order are preserved. Duplicate literals, duplicate clauses and
tautological clauses are legal and not silently simplified. Semantic normalization for
heuristic propagation must retain original clause IDs for proof production. V=0 is legal.

`formula_sha256 = SHA256(canonical DIMACS bytes)` in lowercase hex. Identity is by bytes,
not equivalence of Boolean formulas. The strict reader rejects noncanonical input.
`bundle import` is a separate explicit normalization operation for external DIMACS: it
preserves clause/literal order, writes canonical bytes and records the original source
hash in producer parameters. Certification never silently normalizes.

### 3.2 Cube and split

A cube is a list of nonzero in-range literals sorted by absolute value, with each
variable appearing at most once. Readers reject noncanonical, repeated or contradictory
input; a construction helper may sort otherwise valid literals. The empty cube is `[]`.

`node_id = SHA256(ASCII("node") + NUL + ASCII(formula_sha256) + NUL + ASCII(literals))`,
where `literals` is the canonical list joined with one space and is empty for `[]`.

`CNF(F,C)` is `p cnf V (M+len(C))\n` + the original clause body + one `l 0\n` per literal
in canonical C order. `cnf_sha256` hashes precisely those bytes. A digest implementation
caches, for each used depth d, `SHA256(header(V,M+d) + body)` **as a hash state**, copies
that state and appends units. It MUST NOT combine separate header/body digests. The plain
construction in a test is the independent oracle.

A split of C contains an **ordered** list W of distinct positive variables not in C, all
in `1..V`, with `1 <= len(W) <= 20` (`K_MAX`). Its `2^len(W)` children have every sign
combination; bit j of child number t gives +W[j] if 1, otherwise -W[j]. Each child is
canonicalized after assigning signs. Children are never omitted because propagation or a
heuristic considers them redundant. An omitted child needs an accepted proof, not a guess.

Define `split_id = SHA256(J({"node_id": node_id, "variables": W}))`, using J in §4.1.
The variable list order is identity-relevant for numbering even if coverage is equivalent.

### 3.3 Base formula and case identities

The 59 base formula hashes MUST remain equal to the fixture
`data/fixtures/formula_hashes.json`. A case CNF sorts its units by variable (§3.2), not in
prefix-selection order; the two byte strings of one case have different hashes. A case
number designates the Boolean region under the ordered prefix: bit j of the number is the
sign of the j-th prefix variable. The frozen vectors store, for cases of maps 1 and 2, both
the prefix-order bytes and the canonical cube; they do not assert equal case hashes.

`proof-prefix-v1` is a fixed algorithm (§9.2): its probing bytes and single-literal
exclusion never change. Dynamic selection is a separate algorithm (§9). A different
eligibility rule is a differently named algorithm with its own prefixes.

## 4. File formats and shared types

### 4.1 Common rules

`J(x)` is UTF-8 encoding of Python-compatible
`json.dumps(x, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)`.
Only objects with ASCII schema keys, arrays, strings, booleans, null and signed integers
in `[-(2^63-1), 2^63-1]` are allowed. No floating point, NaN/Infinity, duplicate object
keys, BOM, unpaired surrogates or alternate encodings. Integers must be integers, never
booleans; times/durations are integer milliseconds, sizes bytes unless explicitly named
`_mib`. UTC strings have `YYYY-MM-DDTHH:MM:SS.mmmZ` form. Decimal measurements may be
strings in diagnostic `info`, not arithmetic contract fields.

All object fields in the tables are required unless marked optional; nullable fields are
present with null. Unknown fields are rejected, except contents of explicitly open
`info`/producer-parameter objects. Open objects still obey common JSON types/limits.
Canonical documents are J(x) plus one LF on disk; their document hash excludes that LF.
Readers enforce canonical bytes, including number spelling. Journal hashing is the
exception specified in §7.1. Readers refuse unknown format versions.

Rules that a JSON schema cannot express are rows of the requirement matrix
`schemas/cubeproof/v1/requirements.json`, cited by rule name, such as `certificate.order`.

Primitive types:

| Name | Definition |
|---|---|
| Hash | Exactly 64 lowercase hexadecimal characters |
| Id128 | Exactly 32 lowercase hex characters, generated with OS randomness |
| Name | `[a-z0-9][a-z0-9_-]{0,63}` |
| RelPath | Nonempty relative POSIX path, no empty/`.`/`..` components, drive prefix or NUL |
| Node | `{formula_sha256: Hash, cube: canonical literal list}` |
| Ref | `{journal: Hash, seq: nonnegative integer}`; journal is header self hash |
| Artifact | `{path: RelPath, sha256: Hash, bytes: nonnegative integer}` |

Paths in campaigns are relative to the campaign file. Artifact paths are relative to their
evidence/results root. Readers resolve paths and check containment, including symlinks,
before access; bundle files must be regular files. CLI binary paths are absolute local
paths and are never inferred from untrusted artifact fields.

Default safety limits: 8 MiB per journal line/document record, 64 MiB per campaign or
shard document, nesting depth 32. Diagnostic stdout/stderr tails have at most 16 KiB of
decoded text each (UTF-8 replacement permitted there only). Large certificates are streamed
to a temporary file; there is no 64 MiB certificate limit. Reader byte/node/RAM limits
may be lowered or explicitly raised. Hitting a reader limit is a reported resource error,
never permission to ignore evidence and emit PROVED. Arbitrary CNF means no mathematical
restriction beyond syntax; actual machine resources remain finite.

### 4.2 Bundle: `cubeproof-bundle-1`

Directory contains `formula.cnf`, `manifest.json` and optional side files. Manifest:

| Field | Type/meaning |
|---|---|
| format | `cubeproof-bundle-1` |
| formula_sha256 | Hash |
| variables, clauses | Nonnegative integers; match DIMACS |
| pools | Object Name -> sorted distinct positive variables in range |
| producer | `{name: string, version: string, parameters: open object}` |
| side_files | Array of Artifact, sorted by path; allowed names `names.tsv`, `tags.tsv` |

Names TSV: one line per named variable, sorted numeric ID, `ID<TAB>JSON_STRING\n`.
Tags TSV: clause ranges sorted by `(first,last,tag)`, `FIRST<TAB>LAST<TAB>JSON_STRING\n`,
1-based inclusive. JSON_STRING uses the same JSON string escaping as J. Ranges may
overlap for multiple provenance tags; references must be in range. Missing names/tags
do not affect formula semantics. Side file hashes are checked when those files are used.

A new bundle is published by staging a sibling directory, syncing its files, then
publishing it atomically on the same FS. A live immutable bundle is never overwritten.
Manifest is written last inside staging; a directory without a valid manifest is
incomplete.

### 4.3 Policy

Policy is a **complete object** with exactly the fields below. Defaults are operational
choices, not measured optima. `policy_sha256 = SHA256(J(policy))`.

| Field | Default and allowed values |
|---|---|
| leaf_time_ms | `{"12":900000,"default":300000}`; positive integer ms, depth keys canonical decimal; exact-depth lookup then default |
| proof_cap_bytes | 4294967296; positive |
| solver_memory_bytes | 1073741824; positive |
| checker_max_heap_mib | 8192; >=512 |
| checker_stack_mib | 256; positive |
| checker_max_stack_mib | 2048; >=checker_stack_mib |
| checker_slack_mib | 256; positive |
| checker_time_base_ms | 600000; positive |
| checker_time_per_100mb_ms | 60000; positive; MB here is 1000000 bytes |
| heap_fit | `{"coefficient_milli":3230,"exponent_milli":711,"margin_milli":1500,"min_mib":512}`; positive integers; min_mib >=1 |
| split | `{"method":"lookahead-v1","vars":4,"pool":null,"probe_limit":100000,"wall_ms":1000}`; dynamic method lookahead-v1, vars 1..20, pool Name or null, positive budgets |
| max_cube_size | 60; nonnegative, scheduling policy only |
| proof_mode | `transient`, `retain` or `stream` |
| stream_heap_mib | 1024; 512..checker_max_heap_mib |
| quarantine_quota_bytes | 21474836480; nonnegative |
| tool_retries | 3; nonnegative additional attempts after first failure |
| machine_failure_limit | 5; positive consecutive completed TOOL_FAILED outcomes |
| anomaly_limit | 3; positive anomalous attempts in one run session |
| term_grace_ms | 10000; positive |
| stop_grace_ms | 30000; positive |

Effective policy includes the chosen proof mode, CLI overrides and startup proof-cap
clamp; it is persisted in header/resume before attempts. Nothing of a command line is
remembered: the policy of a session is the campaign's with the options of that session. A
session that resumes a journal therefore compares its policy with the one of the latest
header/resume, value by value (the dotted keys of `--policy-override`): a value that differs
and is not named by `--proof-mode` or by a `--policy-override` key at or above it on this
command line is `run.policy_changed`, exit 3, before the resume record, unless
`--campaign-policy` says that the campaign's values are wanted. `proof_cap_bytes` is exempt,
because the startup clamp may change it. Likewise a resumed session compares its
`cubeproof_sha256` with that of the latest header/resume: other sources are
`run.code_changed`, exit 3, before the resume record, unless `--accept-code-change` accepts
them; the session's notes then name both hashes. Each attempt references its
policy hash and records actual limits. Policy changes affect work, not UNSAT admission.
Static and proof-prefix methods are campaign-construction operations with explicit inputs
(§9.2); they are not incomplete dynamic-policy variants lacking variable lists. The
Splitter interface remains extensible through a separately specified algorithm/config.

### 4.4 Campaign: `cubeproof-campaign-1`

| Field | Type/meaning |
|---|---|
| format | `cubeproof-campaign-1` |
| created_utc, author | UTC string, nonempty string |
| formulas | Nonempty array `{key: Name, formula_sha256: Hash, bundle: RelPath}`, sorted by key; keys and hashes unique |
| roots | Array of Node, at least one per formula; sorted `(formula_sha256,node_id)`; distinct and pairwise incompatible within each formula |
| root_splits | Array `{node: Node, variables: list, splitter: {name: string, info: open object}}`, sorted by split_id, distinct; well-formed §3.2 |
| policy | Policy (§4.3) |
| tools | `{solver: {name:"cadical", sha256:Hash, argv:list of strings}, checker:{name:"cake_lpr",sha256:Hash}}` |
| admit | `{checker_sha256: sorted nonempty list of Hash, solvers: null or nonempty list of {sha256:Hash,argv:list of strings}}` |

Campaign ID is SHA256(J(campaign)); not stored inside itself. Tool argv excludes the
executable and input/output paths, includes every semantic solver option, and must contain
`--lrat` for production CDCL. Resource/time cutoffs and file paths are supervisor inputs,
not hidden solver argv options; argv that disables proof production or sets a competing
termination limit is rejected. Proof-prefix heuristic scratch invocations have their
separate explicit conflict/step limits (§9.2). No shell command strings. Tool locations
come from CLI/API configuration and must match hashes. Admission entries are unique and
sorted by `(sha256,J(argv))`. The configured execution tools must be admitted.

Every Node refers to a campaign formula. Root splits may concern a requested root or
the empty cube, including splits used only for coverage outside a requested-root scope. The
scheduler never expands outside accepted shard/requested-root scope. The certifier
accepts well-formed campaign splits directly; workers need not duplicate them.

### 4.5 Shard and handoff request

Shard fields: `{format:"cubeproof-shard-1",campaign:Hash,name:Name,nodes:list of Node}`.
Nodes are sorted `(formula_sha256,node_id)`, unique, nonempty and pairwise incompatible
within a formula. Its ID is SHA256(J(shard)). Partition planners must satisfy this
stronger disjointness rule even when cubes do not have an ancestor relationship.

Request fields: `{format:"cubeproof-handoff-request-1",campaign:Hash,request_id:Id128,
node_count:positive integer,output_name:Name}`. `output_name` names a file within the
configured outbox, not an arbitrary path. Repeated request IDs must have identical bytes.
The completed handoff record embeds the complete shard, so publication is reconstructible.

### 4.6 Machinery and process results

Machinery fields:
`solver:{path:string,sha256:Hash,version:string,argv:list of strings}`,
`checker:{path:string,sha256:Hash}`,
`helper:null|{sha256:Hash,algorithm:string}`,
`runtime:{python:string,libc:string,platform:string,image_digest:null|string}`,
`source_manifest:list of {path:RelPath,sha256:Hash}`,
`packages_sha256:Hash`, `cubeproof_sha256:Hash`, `unit_algorithm:"unit-v1"`.

Source manifest is sorted and includes installed runtime source/data affecting results,
with package-name path prefixes, excluding pyc, timestamps, output and caches.
`packages_sha256` hashes J(source_manifest); `cubeproof_sha256` hashes J of its cubeproof
entries. Binary hashes identify actual regular files, checked at startup and before each
spawn; source/binaries must not be modified during a run. A change stops with ToolError.

ProcessResult has exactly: `started:bool`, `exit:null|integer 0..255`,
`signal:null|positive integer`, `elapsed_ms:nonnegative integer`,
`stdout_tail:string`, `stderr_tail:string`, `stdout_bytes:nonnegative integer`,
`stdout_truncated:bool`, `cause:null|string`, `conflicts:null|nonnegative integer`.
Exit and signal are mutually exclusive; neither is set if not started. Cause is a
diagnostic code, not authority for verification. Checker success compares **full** stdout;
overflow/truncation never counts as the exact success string. CheckerCheck has
`result:ProcessResult`, `heap_mib:positive integer`, `stack_mib:positive integer`.

### 4.7 Journal records

Each record has `format:"cubeproof-journal-1"`, `seq`, `prev`, `self`, `type`, `utc`
and the payload below. Hashing and validation order are in §7. Every line is at most
8 MiB; large node lists are divided into several independent shards/handoffs before use.

| Type | Payload fields |
|---|---|
| header | worker:Name, campaign:Hash, purpose:`run`/`audit`, machinery:Machinery, policy:Policy, resources:ResourceSnapshot |
| resume | machinery:Machinery, policy:Policy, resources:ResourceSnapshot |
| shard | shard:complete Shard, shard_sha256:Hash |
| split | node:Node, variables:list of positive ints, splitter:{name:string,info:open object} |
| attempt | Fields in §4.8 |
| node_stop | node:Node, state:`stuck`/`tool_blocked`/`resource_blocked`, reason:string, policy_sha256:Hash |
| node_reopen | node:Node, reason:string, policy_sha256:Hash |
| handoff | request:complete Request, shard:null|complete Shard, shard_sha256:null|Hash; null when zero nodes available |
| repair | removed_bytes:positive integer, removed_sha256:Hash |
| audit_begin | certificate_sha256:Hash, sample_count:nonnegative integer, seed:Hash, targets_sha256:Hash, target_count:nonnegative integer, comparison:`strict`/`reprove` |
| audit_target | target:AuditTarget (§11), ordinal:nonnegative integer |
| audit_ready | targets_sha256:Hash, target_count:nonnegative integer |
| audit_result | target:AuditTarget, attempt:Ref, status:`HASH_MATCHED`/`REPROVED_UNSAT`/`MISMATCH`/`NOT_COMPARABLE`/`FAILED`/`OPEN`, reason:string |

ResourceSnapshot: `{cpu_milli:positive integer,memory_budget_bytes:nonnegative integer,
filesystems:list of {id:string,paths:list of strings,free_bytes:nonnegative integer,
budget_bytes:nonnegative integer},coordinator_rss_bytes:nonnegative integer}`.
It records observation, not a certificate admission condition.

Header is exactly seq 0 and occurs once. Resume precedes new activity on every restart.
Purpose `audit` allows only header/resume/repair/attempt and audit_* records; purpose
`run` excludes audit_* records. Certifiers can admit attempt evidence from both.
Node identities and campaign membership are checked for all records, admitted or not.

### 4.8 Attempt schema and models

Attempt fields (all present):

| Field | Type |
|---|---|
| node, node_id, attempt_id | Node, Hash recomputed from node, Id128 unique within journal |
| policy_sha256 | Hash of latest header/resume policy |
| route, proof_mode | `unit`/`cdcl`, one of three modes |
| outcome | VERIFIED_UNSAT, EXHAUSTED, MODEL, INVALID_MODEL, CHECK_REJECTED, TOOL_FAILED |
| reason | null for VERIFIED_UNSAT/MODEL; otherwise nonempty diagnostic code from §6 |
| cnf_sha256 | Hash, independently recomputed from bundle/cube even after file errors |
| limits | `{solver_time_ms:null|positive integer,proof_cap_bytes:positive integer,solver_memory_bytes:positive integer,check_time_ms:positive integer}` |
| solver | null for unit route, otherwise ProcessResult |
| checks | Array of CheckerCheck, in execution order |
| proof_bytes, proof_sha256 | Both null before a complete proof is available; otherwise nonnegative integer and Hash; failed/partial stream rules below |
| relay | null unless stream/CDCL; then `{bytes:nonnegative integer,sha256:Hash,solver_eof:bool,all_written:bool,error:null|string}` |
| assignment | null or complete bitset string below |
| model_error | null or `missing`/`conflicting`/`out_of_range`/`syntax`/`violated` |
| retained, quarantined | null or Artifact |
| diagnostics | Open object for non-authoritative metrics and bounded metadata; the writer records under `usage` the processor model of the machine (`host_cpu`) and for each process `{cpu_ms, max_rss_kib, launch_rss_kib}`: processor time and peak resident memory as the kernel reported them when the process was reaped, and the resident size of the coordinator at the launch (null if unknown). Both measurements count from the fork, so the peak is about `launch_rss_kib` or more and is the tool's own only when clearly above it. File modes: `solver` (route cdcl) and `checks`, one entry for each check of the record; stream mode: `solver`, `relay` and `checker` |

Checks are empty when no checker ran, and there is no null element in the array. For
VERIFIED_UNSAT the last check is the accepting one; preceding checks, if any, are arena
exhaustions. The last checker result has exit 0, signal null, stdout_bytes 17,
stdout_truncated false and stdout_tail exactly `s VERIFIED UNSAT\n`. For CDCL file modes
solver.started is true and exit is 20 without signal. For MODEL/INVALID_MODEL route unit
denotes a complete-assignment result from propagation; no LRAT proof/check is required
for a model, and proof fields are null. For route cdcl the SAT process exited 10.
If no proof reached the checker stage, limits.check_time_ms is the policy base value;
otherwise it is the fitted time used for each check (arena retries keep that time).

Assignment is canonical standard padded base64 of exactly ceil(V/8) bytes. Variable i is
bit `(i-1)%8` of byte `(i-1)//8`, LSB first. Unused high bits are zero; V=0 encodes as the
empty string. MODEL requires a complete satisfying assignment, model_error null.
INVALID_MODEL has model_error set: `violated` requires a complete failing bitset; parse
errors require assignment null. Conflicting, missing and out-of-range solver values are
not silently filled or overwritten. Repeated identical values are permitted in solver
output but omitted in the canonical bitset. Bounded raw text is kept only in diagnostics.

VERIFIED_UNSAT requires nonnull proof hashes, at least one successful check and the
route-specific conditions in §6. EXHAUSTED/TOOL_FAILED may lack a proof; stream partial
hash/count lives only in relay, never masquerading as a complete proof. Retained is
nonnull only for VERIFIED_UNSAT in retain mode; quarantined only for CHECK_REJECTED in
file modes. For a unit proof executed with configured stream mode, relay is null and
the small file path protocol applies. All models and anomalies remain visible even
when machinery is not admitted. Diagnostic strings cannot override structural fields.

### 4.9 Certificate and audit inputs

Certificate has `format:"cubeproof-certificate-1"`, `campaign:Hash`, and these fields:

| Field | Shape |
|---|---|
| journals | Sorted array `{id:Hash,worker:Name,records:positive integer,head:Hash,bytes:positive integer,torn_tail_bytes:nonnegative integer}` |
| formulas | Sorted array `{formula_sha256:Hash,key:Name,proved:bool,summary:Summary,roots:list of {cube:list,closed:bool,summary:Summary}}` |
| open | Disjoint frontier below requested campaign roots (§10); entries OpenNode |
| formula_open | Frontier from each empty cube, including missing scope; entries OpenNode |
| used_attempts | Unique sorted list of `{node:Node,node_id:Hash,record:Ref,cnf_sha256:Hash,proof_sha256:Hash,route:string}` used in any reported closed summary |
| machinery | Array `{journal:Hash,snapshot_seq:nonnegative integer,machinery:Machinery}` for used records |
| not_admitted | Sorted list `{record:Ref,reason:string}` |
| models | Sorted list `{record:Ref,node:Node,assignment:string}` for revalidated valid models |
| anomalies | Sorted list `{record:Ref,code:string,info:open object}` |
| verdict | `PROVED`/`OPEN`/`MODEL_FOUND`/`INCONSISTENT` |

Summary is `{leaves:nonnegative integer,splits:nonnegative integer,max_cube_size:nonnegative integer,
leaf_merkle_root:null|Hash}`. An open summary has zero counts, max_cube_size 0 and root null;
partially closed work is described by open lists and the journals, not a partial claim.
OpenNode is `{node:Node,node_id:Hash,state:"pending"|"stuck"|"tool_blocked"|"resource_blocked"|"model",
reason:null|string}`. Root summaries and lists are sorted by node_id; records by Ref.
Malformed inputs produce an error report and exit 4, **not a certificate with a verdict**.

Certificate paths are not authority. A portable evidence directory holds campaign,
bundles, journal snapshots and a manifest `{format:"cubeproof-evidence-1",campaign:Artifact,
bundles:list of {manifest:Artifact,formula:Artifact},journals:list of Artifact,
certificate:Artifact}`. Arrays are sorted by path/hash, paths contained in that directory.
Optional side files and retained proofs travel separately with their Artifact descriptors.
Certificate and manifest are published only after dependencies; external publication
records their hashes. Audit receives explicit journal files or this manifest and verifies
the certified prefixes. It never tries to reconstruct leaves from a Merkle root alone.

### 4.10 Small normative examples

These are exact CNF strings; escapes below mean actual LF bytes:

```text
F_sat    = "p cnf 1 1\n1 0\n"
F_unsat  = "p cnf 1 2\n1 0\n-1 0\n"
F_empty  = "p cnf 0 0\n"
F_clause = "p cnf 0 1\n 0\n"
CNF(F_sat, [-1]) = "p cnf 1 2\n1 0\n-1 0\n"
```

Empty-scope proof of `F_sat ∧ [-1]` closes only that requested root; the whole formula
remains unproved. `F_unsat` with a split `[1]` requires both `[1]` and `[-1]` closed.
The frozen vectors MUST include byte hashes, node IDs, a self-chained journal,
one/singleton/odd-leaf Merkle examples and certificates for these cases. Expected
values are generated by a separate short specification script and independently checked;
they are not copied from the implementation being tested.

## 5. Trust and claim obligations

The table lists the obligations and the code that carries each. The code in scope is the
critical functions together with their transitive pure helpers.

| Obligation | Trust-relevant implementation |
|---|---|
| Correct leaf CNF | Bundle/parser validation, cubes, DIMACS writer and independent digest |
| Checker accepted these exact inputs | Pinned cake_lpr and its execution assumptions; isolation/spawn, checker status, file I/O/hash helper, relay, leaf binding |
| Faithful durable attestation | Journal codec/validation, append/recovery, record binding |
| Complete accepted coverage | Certifier admission/closure/selection, schemas and hashing helpers |
| Correct SAT/anomaly reporting | Assignment parsing/evaluation, verdict rules |
| Connection to the geometric claim | Article, enumeration, encoder and `neighbourly.cnf` emission, fixture provenance, application claim gate |
| Independent audit result | Certified input selection, recheck, comparison and audit reporting |

UP proof generation, solver search, splitter scores and scheduling are not logical
authorities for UNSAT. Every UP refutation goes through cake_lpr. A bad UP generator
should cause rejection, not a false proof. Schedule/cache/shard decisions cannot bypass
certifier coverage. The independent certifier is an additional implementation, not a
second source of proof authority or authentication.

Execution threat model: trusted OS/hardware/filesystem and an immutable, correctly
identified tool installation; tools may have bugs and produce wrong answers, but hostile
same-UID processes rewriting input files or binaries during execution are excluded.
Pre/post hashes and per-attempt paths detect ordinary mutation/misbinding; chmod is not a
security sandbox against a hostile writer. Hostile workers are outside this model:
guarding against them requires proof retention or independent recomputation and a separate
isolation/authentication design.

Each worker uses a private work directory, no shared attempt files, no symlink following,
and fresh Id128 attempt IDs. The checked binary's hash must match the measured machinery.
Only `tools.checker.accepts` recognizes exact success; only `leaf.binding` may construct a
VERIFIED_UNSAT record after also satisfying all input and transport checks. The certifier
independently validates that recorded success fields satisfy those conditions.

## 6. Leaf execution and outcome precedence

### 6.1 File modes: transient and retain

One attempt proceeds through these stages; all CPU/RAM/disk activity is reserved (§8).

1. Generate `work/<node_id>-<attempt_id>.cnf`; compute hash while writing and compare
   with independent digest from the verified bundle. The file represents only this node.
2. If UP yields a conflict, write a `unit-v1` LRAT proof with original clause numbering:
   base clauses first, then canonical units. Otherwise execute the pinned solver with
   recorded argv, CNF path and proof path. No preliminary proofless solve.
3. A completed UNSAT solve (exit 20, proof file closed and present) seals the proof:
   chmod read-only, determine size and hash. Release solve CPU/RAM after process exit,
   retain disk reservation through sealing/check/commit. Queued sealed proofs are still
   uncommitted attempts; crash may lose them and cause re-solving.
4. Run cake_lpr on that CNF and proof with a fitted initial heap. A checker heap/stack
   exhaustion may repeat **only the check** with the exhausted arena doubled, within
   configured maxima and idle-machine fit. Keep each check result in `checks`.
5. Re-hash CNF and proof after checking. Success requires unchanged hashes and the
   expected CNF digest. A change is TOOL_FAILED(file_changed), regardless of success text.
6. For retain, publish the proof durably as in §7.2 **before** committing the record.
   For rejected file proofs, publish quarantine if quota permits, also before commit.
7. Append exactly one terminal attempt record and await durable acknowledgement. Only
   then update durable-derived scheduling state and delete disposable work files.

SAT goes through complete model parsing and clause/unit evaluation; it does not invoke
checker. Model side files/interpretations are derived exports, recreated from the record.
Interrupted attempts have no terminal record, except an already committed result remains
committed even if acknowledgement had not reached the coordinator.

### 6.2 Tool isolation

Linux process launch uses absolute binaries, own process sessions/groups,
`setpriv --pdeathsig KILL`, `prlimit --as` and (file solver proofs) `--fsize`. Wrappers
must exec rather than leave untracked grandchildren; parent-lifetime handling is verified
and every child is reaped. The parent-death signal is in force from the fork: the forked
child sets it and verifies that its parent is still the coordinator before it executes the
wrapper chain, so a coordinator that dies during a launch leaves no tool. On coordinator
death, tool/relay/I/O children must die; startup must never delete files still used by an
old surviving process.

Deadlines use monotonic clocks. Solver timeout sends TERM then KILL after `term_grace_ms`.
User stop prevents launches, terminates groups, allows `stop_grace_ms`, kills/reaps and
exits 130. It does not turn a deliberately cancelled process into a tool failure. Bounded
stdout/stderr draining must continue throughout hashing, queueing and journal I/O.

### 6.3 Primary causes and classifications

Coordinator actions are tracked as typed causes. A cause is not inferred merely from a
signal that could also mean a crash. All raw secondary failures are preserved in
diagnostics.

Before terminal commit, an explicit user cancellation gives **no record**. Otherwise the
first applicable row applies; file mutation overrides any apparent checker success.

| Condition | Outcome/reason/action |
|---|---|
| Launch failure, missing/mutated binary, I/O/hash failure, violated file binding | TOOL_FAILED: `launch`, `binary_changed`, `io`, `file_changed` |
| Supervisor explicitly reached proof cap, or solver SIGXFSZ | EXHAUSTED: `proof_size` |
| Supervisor explicitly reached solver deadline | EXHAUSTED: `time` |
| Supervisor explicitly reached check deadline | EXHAUSTED: `check_time` |
| Pinned checker arena diagnostic, without contradictory success | Retry check/stream arena if eligible; else EXHAUSTED: `check_memory` or `check_stack` |
| Explicit pinned solver allocation-failure diagnostic or attributable cgroup OOM event | EXHAUSTED: `solver_memory` |
| Unexpected process signal/crash, unsupported exit protocol, broken transport without an earlier classified cause | TOOL_FAILED: `crash`, `protocol`, `relay` |
| Solver exit 10 with parseable or malformed model output | MODEL or INVALID_MODEL with model_error (§4.8) |
| Complete proof, checker cleanly reports a normal unsuccessful result | CHECK_REJECTED: `rejected` |
| Complete proof, checker exit 0, **full stdout exactly** `s VERIFIED UNSAT\n`, all binding/transport checks pass | VERIFIED_UNSAT |
| Any remaining incomplete/unrecognized state | TOOL_FAILED: `protocol` |

Checker clean unsuccessful result means a normal exit without arena failure, including
exit 0 with an incorrect success line. A checker signal is a tool failure, not rejection.
Diagnostic arena patterns include the pinned binary's heap, stack and combined allocation
messages. Combined exhaustion doubles both arenas. A success line combined with an
exhaustion diagnostic is protocol failure, not acceptance. SIGSEGV is never classified as
memory exhaustion solely from RSS.

Solver exit 20 without a complete proof is protocol failure. A nonzero unexpected exit
with a file exactly at cap may be classified as proof_size only when the supervisor
observed the cap event; size alone is not a reliable reason. Checker errors encountered
after a recorded supervisor limit are secondary. This table applies to file and stream
paths; stream-specific precedence is made explicit below.

### 6.4 Stream mode

Stream/CDCL launches solver -> relay -> checker. Relay is a separate bounded process,
not hidden free CPU work. It hashes/counts bytes, handles partial writes, enforces cap,
and reports solver EOF, all-written and transport errors. FIFO opening is nonblocking
with explicit readiness; no start-order deadlock. Full success requires exit 20 from
solver, checker success, `solver_eof && all_written && error == null` and unchanged CNF.
Relay hash/count becomes proof hash/count only for a complete transfer.

The shared stream deadline is the solver's `leaf_time_ms`, covering the coupled stream
task; `check_time_ms` is recorded but does not extend this coupled deadline. Unlike the
file modes, an unfinished stream cannot preserve a completed proof for later check.

When checker arena exhaustion closes its pipe, resulting relay EPIPE and supervisor-
terminated solver are **secondary** to arena exhaustion. Cap enforcement similarly
takes priority over the resulting EPIPE/termination. Unexpected checker crash precedes
its downstream relay errors and is TOOL_FAILED. Unexpected early successful checker
exit is TOOL_FAILED(relay) unless the complete EOF/all-written criteria actually hold.

An arena-exhausted stream attempt records EXHAUSTED(check_memory/check_stack) with raw
results. The coordinator computes the next arena from the last record: at least twice
the exhausted arena and, for heap, at least the fit of observed relay bytes. It schedules
a fresh attempt on the same node only if within maxima and idle-machine resources;
otherwise it splits. No infinite retry ladder. These deterministic retry rules are part
of replay; file modes reuse the existing proof within the same attempt instead.

Stream quarantine is **metadata-only**: `quarantined=null` with diagnostic
`quarantine_unavailable:"stream_not_spooled"`. It does not promise a recoverable full
proof. Reproduction of a rejection is an explicit audit/debug operation in file mode,
not an automatic hidden solve. Unit refutations are small files checked through the
file protocol even when the policy is stream; retain applies only when mode is retain.

### 6.5 Terminal consequences

| Recorded outcome | Next operational state |
|---|---|
| VERIFIED_UNSAT | Closed for scheduling; cancel now-unnecessary descendants without records |
| MODEL | Model; never auto-split/retry; continue unrelated work |
| EXHAUSTED | NeedsSplit, except an eligible stream arena retry |
| INVALID_MODEL / CHECK_REJECTED | Report anomaly, NeedsSplit if session anomaly threshold not reached |
| TOOL_FAILED | Retry node up to `tool_retries` additional failures, then ToolBlocked |

Consecutive TOOL_FAILED counts use journal commit order. Any other committed attempt
resets the machine consecutive counter. `machine_failure_limit` stops the session with
exit 5; missing binaries at preflight fail immediately without synthetic attempts. The
per-node consecutive counter persists across resume until a non-TOOL_FAILED result or
explicit node_reopen. On exhaustion node_stop(tool_blocked) is persisted. It is not split.

INVALID_MODEL/CHECK_REJECTED attempts are counted since the latest header/resume. At
anomaly_limit the run stops new work, cancels uncommitted attempts and reports exit 6.
Successful descendants may eventually establish UNSAT, but anomalies are never erased from
evidence. Reopening blocked nodes is explicit `--reopen-blocked` with node_reopen records.
New policy alone does not silently erase a stopped state. Model/verified nodes cannot be
reopened by that flag. STUCK is recorded for max depth or genuinely empty eligibility.

## 7. Durability, restart and offline transfer

### 7.1 Journal protocol

`self = SHA256(J(record without self))`; `prev` is previous record's self, or 64 zeros
at seq 0. Seq is contiguous from zero. A line is J(complete record) + LF. Journal ID is
header.self, head is last complete record.self.

Validation covers canonical bytes, types/schema, self, seq and prev, in that order. Self
detects accidental edits to a complete last line; it is not a signature. A trusted
external head/length detects removed complete suffixes or replacement against that anchor.

One writer owns a worker journal. Append holds exclusive flock, validates the current
tail, assigns seq/prev/self, writes with **write_all** on an O_APPEND descriptor, checks
short writes/EINTR, fsyncs and (on creation) syncs the directory. Acknowledgement occurs
only after durability. On any write/fsync failure publication and new work stop; no second
version is appended and nothing continues past uncertain bytes. Recovery re-reads disk.
The same attempt_id/request_id must never be committed twice: if acknowledgement was lost,
replay recognizes the committed record.

Only a nonempty suffix **without a terminating LF**, following a valid complete prefix,
is a torn tail. Run saves its length/hash, truncates it under lock, fsyncs, appends repair.
Certify ignores and reports such a suffix. A complete invalid last line, broken self,
seq, prev, schema or UTF-8 is an integrity error just like a middle-line error. Automatic
repair must not discard it. `journal repair` handles torn tails only; other damage needs
restoration from a known backup, preserving the damaged file for investigation.
Standalone `journal repair` must also take the containing results/run.lock nonblocking;
it refuses a live coordinator. Export/read is permitted concurrently only by the prefix
snapshot protocol, not by truncating or repairing under an active writer.

An empty first-run file or only a torn initial header may be initialized under run.lock;
no work may have been launched before header commit. Certify ignores an empty file only
when explicitly excluded by the caller; an included file without a valid header is an
input error. Repair after a torn initial header records the removed hash after writing the
new header. A campaign/worker is never inferred from an unvalidated damaged header.

### 7.2 Artifact commit protocol

For retained/quarantined file proof:

1. Keep the checked source file until publication completes. Reserve target capacity
   including double occupancy during cross-filesystem copy.
2. Copy to a fresh `proofs/tmp/<attempt_id>.lrat` (or quarantine tmp) on the **target FS**;
   hash and fsync it; require the checked hash. Same-FS move may optimize this step.
3. Rename on the target FS to `proofs/<node_id>-<proof_sha256>.lrat`, fsync its directory.
   If that path exists, require equal size/hash and reuse it; never overwrite unequal bytes.
4. Append/fsync the attempt with final relative Artifact descriptor.
5. Delete disposable work/tmp copies; release reservations only after deletion/accounting.

Recovery validates every committed retained reference first. Missing/corrupt retained
proof is IntegrityError for run/verify-retained, never silently converted to transient.
Certifying journals alone can still assess attested coverage; it must not claim retention
availability without checking those files. Unreferenced published/tmp files are orphans,
not evidence: after validating no old process uses them, they are removed (or moved to a
bounded orphan directory). A path referenced by a committed record is never removed. The
recovery procedure is idempotent. Quarantine follows the same ordering, but a quota miss
records null plus a diagnostic; verified retained proof is never deleted to make room.

### 7.3 Durable state and replay

Authoritative mutable history is the journal. Immutable campaign/bundles and pinned
tools/sources must also remain available. Models, status, cache and exports are derived.

Startup order:

1. Take nonblocking exclusive `results/run.lock`; verify results ownership and reject a
   different campaign/worker. Do not share a work directory between active workers.
2. Compare the journal with a given export directory before anything is written (§7.5).
   Verify journal, repair only a torn suffix, validate committed artifact references.
3. Rebuild accepted shards, given-away regions, splits, attempts, stops/reopens, counters,
   policy epochs and pending publication requests. Check that no previous process survives.
4. Re-publish missing handoff outputs from records, reconcile accepted inbox files, then
   remove only unreferenced work/tmp/orphan files.
5. Measure/hash machinery/resources, derive effective policy, commit resume (or initial
   header), apply explicitly requested node_reopen records, then launch work.

Known-answer control. Before step 5 commits its record, `run` and `audit` ask the pinned checker
four fixed questions through the launch path of a leaf check (the isolation of §6.2, the argument
form and the success rule of §6.3, small fixed arenas): a refutation of `p cnf 1 2 / 1 0 / -1 0` that it must accept, and three pairs it must
reject cleanly (that proof for a satisfiable formula, an empty clause whose hints give no
conflict, an empty proof). A wrong or impossible answer is `tool.known_answer`, exit 5, and no
record is written. The control shows that the program named by the campaign's hash tells these
cases apart on this machine; it does not replace the checker's own guarantee (§5). It is on
for the commands and for the API alike; `--no-known-answer` (API: `known_answer=False`) skips it,
exists for tests with scripted tools, and puts a note into the result of the session.

An attempt lacking a committed terminal record returns to pending. A sealed proof
waiting for check is uncommitted work and may be discarded; the guarantee is at-least-once
execution with idempotent committed events, not exactly-once physical solving across crashes.
Node_stop reasons are recorded. If an attempt implies a stop/split but a crash precedes
that follow-up event, replay deterministically re-issues the missing follow-up once.

A state cache contains format version, campaign, journal ID, seq, head and payload checksum.
It is usable only if its prefix matches the validated journal and schema. Any mismatch
falls back to full replay. Cache must never be read by either certifier. Admission and
semantic closure used for scheduling must obey §10, even though scheduling state itself
does not authorize a claim.

### 7.4 Acceptance and handoff

A worker accepts a first shard from CLI or an atomically published inbox file. It
validates the shard's campaign, nodes, size and disjointness, commits a shard record
before launching its nodes, then moves the inbox file to `accepted/`. Replay completes
that move. An identical shard hash is a no-op. A new shard overlapping this worker's
already accepted or given-away region is rejected with a clear diagnostic, not partially
accepted. Different workers may overlap; certifier coverage remains sound. Handed-off work
is reclaimed with a new worker/results directory after planning from open coverage, not by
implicit ownership reversal.

Within an accepted region, campaign/journal splits expand work. A node must be a
descendant of accepted work and outside given-away regions to be scheduled. Pending
frontier is an antichain; closing a parent cancels its unnecessary descendants. In-flight
child results committed before cancellation remain harmless alternative evidence.

Handoff command only writes an immutable request to the configured inbox. Coordinator
selects up to node_count pending, unsplit, not-running frontier nodes, oldest first, and
caps the batch to record/document size limits. It commits one handoff with embedded
request and complete shard; after that commit it no longer owns those subtrees. Then it
publishes `outbox/<output_name>.json` atomically. On crash replay publishes the **same**
bytes, never chooses a second node set. Zero available nodes produces shard=null and a
derived empty-completion response, not an invalid empty shard. Repeated requests return
the prior result. A request is marked processed only after durable output; cleanup is
repeatable.

`handoff --wait-ms` reports pending/completed and output location; timeout leaves a durable
request, not a false transfer acknowledgement. A stopped worker serves requests at its
next run. Delivery to another machine remains the user's file-transfer action. Missing
delivery leaves coverage visibly open and the original outbox available for retransmission.

### 7.5 Crash table and exports

| Crash point | Recovery |
|---|---|
| During CNF/solve/seal/check, before terminal append | Remove unreferenced work; node pending |
| Artifact published, attempt not committed | Remove unreferenced orphan; node pending |
| Attempt committed, acknowledgement/cleanup missing | Keep committed evidence; finish cleanup; do not solve again |
| Shard committed, inbox move missing | Recognize shard hash; finish move; no duplicate acceptance |
| Handoff committed, output missing | Recreate exact embedded shard; giver stays excluded |
| node_stop follow-up missing | Derive and persist stop before scheduling that node |
| Full last line corrupt | Stop with IntegrityError; no automatic truncation |
| Last suffix lacks LF | Remove only suffix, record repair, replay complete prefix |

Export captures a committed `(journal_id,seq,head,byte_offset)` under a brief shared lock,
then copies that immutable prefix outside the lock. Append-only writers do not mutate that
prefix. The copied chain/head is validated, the output fsynced and its descriptor
published last. Incremental copy is allowed if prior exported prefix matches. The journal
lock is never held through a multi-GiB copy. Live recovery/repair and export are
serialized by run ownership. Default export interval is 60 s plus clean-stop export; the
last successful export time/lag is published. Periodic exports are backups with that
possible lag, not synchronous replication.

A run given an export directory compares its journal with the published export under
run.lock, before the journal is repaired or appended to; the first appended record would
otherwise decide whether the two remain one history. An export that is a prefix of the
journal, or equal to it, needs nothing. An export of another journal, or a published
export beside no journal, is a configuration error. If the export holds more records and
the journal file is byte for byte a prefix of the exported prefix (results restored from a
backup older than the export), the run validates the exported records as journal records,
requires every retained or quarantined file that the missing records reference, appends
the missing bytes to the journal and fsyncs; it then resumes from the exported position.
If journal and export are different continuations, or the export cannot supply the
missing records, the run stops with an integrity error before any record is written.
Neither file is ever replaced or truncated. After startup a failing export is reported in
status, log and run result, is retried, and does not change the exit code.

## 8. Coordinator and resource model

### 8.1 Event loop and I/O

One coordinator uses a single-threaded nonblocking event loop. There is no worker pool per
case. Solver/checker/splitter/relay remain subprocesses with explicit lifetimes. Large
hash/copy/fsync/journal jobs run in one long-lived supervised **I/O service process**
(`tools.io_service`); it is part of the binding/durability trust boundary. Its protocol
has job ID, operation, attempt ID, expected paths/hashes and a typed result. It cannot
construct a VERIFIED_UNSAT record independently. The coordinator supplies validated record
values; the service is the sole writer and returns committed seq/head.

The service chunks hash/copy work (at most 8 MiB per chunk) and prioritizes journal
commits between chunks. A blocking fsync may stall that service, but not child draining,
timers or cancellation in the coordinator. Reservations persist while commit is pending.
Failed service or mismatched job/attempt IDs stops new work; replay handles uncertain
commits. No process is started per hash chunk or per append. Pure schema/codec code is
shared with its implementation.

UP and native lookahead must also yield or run in bounded helper tasks; arbitrary-CNF
propagation cannot block the event loop unboundedly. The bounds on ordinary-operation tick
latency are p99 <=100 ms and observed maximum <=1 s; any OS stalls are reported
separately. Delays never authorize skipped checks or early records.

### 8.2 Budgets versus hard limits

CPU capacity respects affinity and cgroup quota, expressed as milli-CPU. A normal tool
reserves 1000; stream reserves solver+checker+relay (3000); I/O/UP/split helpers reserve
their own 1000 while CPU-active, not when idle. Coordinator overhead is measured and
reported. An idle-machine-impossible configured stream task is rejected rather than waited
for.

Child virtual address-space caps are not bounds on total physical RAM. At startup a
conservative total scheduling memory budget is derived from host/cgroup headroom minus 1
GiB system/page-cache reserve, coordinator RSS/frontier allowance and helper resident
costs. Each new child additionally reserves 64 MiB overhead beyond its AS cap. I/O service
and retained in-memory bundles/indexes are included once as resident costs. Cgroup
usage/pressure and coordinator RSS are monitored at least every 10 s, not only after
allocation failure.

Disk ledgers are grouped by backing storage; paths on the same device/share compete for
one budget. If mount identity cannot establish independence (e.g. Docker overlay and
volumes on one VM disk), they are conservatively configured as one storage group. Separate
devices may have separate ledgers. Default reserve is 2 GiB per independent storage group.

Remeasurement avoids double counting:

```text
R = total outstanding reservations in a resource ledger
U = measured currently occupied amount attributable to those reservations
H = measured currently usable headroom, after external/fixed costs and safety reserve
safe_new_capacity = max(0, H - max(0, R-U))
allow a new reservation r only if r <= safe_new_capacity AND R+r <= total_budget
```

An uncertain U counts as U=0 (conservative). At startup with no tasks U=R=0. total_budget
is not redefined as current free space, with full reservations then subtracted again as if
it were an unchanged total. Pressure may lower the total ceiling, never increase above CLI
or initial observed ceiling; existing work is released safely even if a lowered ceiling is
temporarily exceeded. Recorded limit breaches are operational failures, not proof claims.

### 8.3 Reservations and heap fit

| Task | Memory reservation | Disk reservation |
|---|---|---|
| Solve | solver AS cap + overhead | proof cap + actual generated CNF size + bounded logs |
| Check | heap+stack+slack (MiB to bytes) + overhead | sealed proof + CNF/logs retained |
| Stream | solver + checker caps + relay cap/overheads | CNF and bounded logs; no spool |
| Lookahead/UP | explicit cap, default 256 MiB + overhead | input/result scratch bounds |
| Proof-prefix | solver cap + overhead | 256 MiB proof scratch + CNF/logs |
| I/O service | measured resident + bounded buffers | temporary destination copies counted until publication/cleanup |

Relay cap defaults to 128 MiB; I/O buffer cap 32 MiB. Helper inputs too large for their
limits result in a diagnostic/fallback or resource_blocked, never unreserved growth. CNF
size is actual, not a presumed 1–2 MB. Sealed proof disk reservation shrinks to size only
after solver exit; CPU/RAM can be reused while check waits. Retain occupies storage until
explicitly archived/deleted outside a live run. Quarantine quota includes pending copies,
not just final files. The same retained bytes are never reserved in two independent
ledgers for a shared storage group.

Initial heap estimate in MiB is max(min_mib, next power of two >= ceil( margin *
coefficient * (proof_bytes/1000000)^exponent)), where coefficients are stored as integers
divided by 1000 in policy. It is an estimate, not an upper bound. Rounding is
conservative, with vector tests at power-of-two boundaries. Check time is max(base_ms,
ceil(proof_bytes/100000000) * per_100mb_ms). The default coefficients (§4.3) were fitted to
checker heap use observed in exploratory runs and are starting values; the arena retries
(§6.1) correct a misfit.

At start the effective proof cap is clamped downward until predicted initial heap is <=
max heap, heap+initial stack+slack+overhead fits idle-machine RAM, and one solve's full
disk reservation fits idle-machine storage. The effective cap is recorded. It is not
lowered below 1 MiB automatically: if that minimum cannot fit, preflight fails with a
resource diagnostic. Later heap retries may still exceed resources: the attempt is
recorded EXHAUSTED, only uncommitted proofs are deleted and the node is split. A fitted
estimate never guarantees all proofs can be checked.

### 8.4 Scheduling and progress

The loop reaps and classifies finished tasks, commits their records, applies state
transitions, then launches in priority: checks, split work, solves. Depth-first within a
root, round-robin between requested roots; stable ties by node_id. Child push order is
reverse child index so smallest child runs first; recorded split order fixes replay order.
Handoff chooses oldest pending frontier entries with node_id ties.

If the oldest check cannot fit now but can fit idle, existing work is drained: no new
solve/split starts until it fits. Other checks may run only if they do not delay that
reserved check. This deliberate priority may leave CPUs idle. If a queued task cannot fit
even idle, its defined exhaustion/resource-block rule applies immediately. If no progress
is possible and no active task can free resources, the run commits
node_stop(resource_blocked) for affected work and exits 1 with capacities/requirements; it
never spins indefinitely.

Status shows active stages, requested/effective budgets, observed usage, reservations,
proof queue bytes, frontier by depth/state, counters, anomalies/models, exported head,
oldest task and stall reasons. Status is emitted at most every 10 s, and human progress
each minute. `closed_fraction` uses selected disjoint root coverage (cube measure relative
to root), not number of completed leaves alone. ETA is optional, explicitly an estimate
and omitted while branching/rates are unstable. Historical errors remain visible.

## 9. Splitter contracts

### 9.1 Common interface and safety

`choose(bundle, cube, k, pool, budget) -> SplitChoice` returns
`{variables:list, status:"chosen"|"no_eligible"|"budget"|"failed", info:open object}`.
Variables are distinct unassigned variables in pool (or all variables if pool null).
Choices are structural suggestions; coordinator validates them before recording a split.
A caller clamps k to remaining policy depth and unassigned variables. At the depth
limit it records STUCK without invoking a helper. `k=0` is never a split.

Dynamic selection excludes variables assigned by UP under the parent cube. UP conflict
schedules the checked unit route, not an empty split or a trusted UNSAT answer. If all
variables are assigned without conflict, the complete assignment is evaluated; a valid
model uses the ordinary model record/binding path (route unit, solver null). If a
restricted pool has no eligible variable, STUCK(no_eligible_pool) is recorded; changing to
an unrestricted pool and reopening is an explicit policy choice.

`budget`/`failed` is different from true no_eligible. If the helper times out or fails,
the choice falls back to the lowest eligible variable(s), using validated parent UP; the
fallback is recorded in splitter info. If parent UP itself cannot fit resources, the node
is blocked, not the entire correctness protocol. Implied assumptions are never added to a
child without including every sign child of the actual recorded split.

### 9.2 Static and proof prefix

Static uses an explicitly supplied ordered W, validated against the parent cube. Prefix
zero means no root split, not a zero-variable split record.

`proof-prefix-v1` ranks the variables of a pool by their occurrence counts in the proof
prefixes of sampled solver runs (after Battleman, Reeves and Heule; see
[SOURCES](SOURCES.md)). The algorithm and its parameters are fixed by its name; a different
rule is a differently named algorithm. Its sampling, seeded RNG profile, clause/unit
ordering in **heuristic scratch files**, single-literal exclusion, proof-prefix counting
and tie order are part of its definition. Parameters: samples 2, addition steps 100000,
conflicts 90000, seed 5, pool order. Scratch files are not evidence CNFs; all actual leaf
attempts use canonical cube bytes. Selected prefixes and parameter/tool provenance are
stored as campaign root splits. Campaign creation can reuse a validated frozen prefix file.

Fixtures for maps 1 and 2 pin the expected prefixes:

```text
map 1: 1398 858 775 994 1262 811 1213 947 945 1215 3156 853
map 2: 853 1354 992 1305 1399 1260 1216 1259 1533 1488 946 743
```

A computed prefix that differs from these fixtures is a defect.

### 9.3 Lookahead-v1 algorithm

The C helper `cubeproof-look` and Python reference implement the same bounded algorithm.

1. UP F under canonical parent C. Eligible candidates are ascending variable IDs in
   the pool, excluding parent assignments. Maintain ordered chosen list W initially empty.
2. At each round consider sign assignments to current W. If `2^len(W) <=16`, use all in
   child-index order. Otherwise choose the 16 smallest `(SHA256(ASCII(node_id)+NUL+
   ASCII(round)+NUL+ASCII(child_index)),child_index)` among its sign vectors. No host RNG.
3. For each remaining candidate v in ascending order, for every sampled child D run UP
   under C plus W's signed literals. If D conflicts or already assigns v, its score for
   v is zero. Otherwise probe +v and -v from that trail. Let n+ and n- be additional
   assignments excluding the probe literal; for conflict use V+1. Score that child as
   `(n+ + 1)*(n- + 1)`. Candidate score is the sum over sampled children.
4. Choose maximum score, ties by lowest variable ID. Append v to W and repeat until k
   choices or candidates run out. Variables implied on some sampled children get zero
   there; they are not globally discarded. This addresses conditional redundancy without
   claiming pair implication is a sound reason to remove coverage.
5. A probe is one candidate/polarity UP; parent/child base propagation also consumes one
   probe unit. Complete an entire candidate evaluation or discard its partial score.
   If budget ends during a round, choose the best fully evaluated candidate in that
   round if one exists, then return W; if none exists return previous W or budget status.

Deterministic C/Python tests use only the same integer probe_limit, unlimited wall budget,
ascending propagation clause/literal traversal and defined tie-breaking. A run also
applies wall_ms: hardware-dependent stopping may choose different W, which is allowed
because W is recorded. The coordinator validates any partial choice. Other
pair-implication exclusion heuristics belong to a separately named algorithm; lookahead-v1
is never silently changed.

Helper input is one J object with format `cubeproof-look-request-1`, formula path/hash,
cube, k, pool (sorted variables or null), probe_limit, wall_ms (null allowed for tests).
Output is one J object with format `cubeproof-look-result-1`, node_id and SplitChoice
fields. Exit 0 requires valid output; all other exits are helper failures. Stdout only
protocol, bounded stderr diagnostics. Code, compiler flags and binary/source hashes go in
provenance; the build uses warnings-as-errors. Absence selects Python fallback with a
visible warning and identical semantics, subject to its resource/time constraints.

## 10. Certification

### 10.1 Inputs, journal selection and admission

Input is campaign, verified formula bundles and explicit journal snapshots. All files and
campaign membership are validated first. Two files with the same header ID are compatible
only if one validated complete record sequence is a prefix of the other; the longest is
used, duplicate inputs are listed in the command report and forks are rejected. The same
worker Name with different header IDs is an integrity error. A foreign campaign is an
input error, not silently ignored evidence. Input order has no semantic effect.

Schema violations, invalid identities, bad CNF hashes and inconsistent model encodings are
integrity errors. For a structurally typed split record only, semantic errors in W
(empty/too long, repeated, out of range, already in cube) are listed as `malformed_split`
and that split is ignored. Its parent cube must still be valid. Campaign root splits must
be valid at campaign creation/read; an invalid immutable campaign is not tolerated.

Attempt machinery/policy is the latest header/resume preceding it in that journal.
Admission requires checker hash in campaign admit and, when solvers is a list, solver
hash/complete argv in that list. Unit route still uses the snapshot admission policy but
solver is not executed. `admit.solvers=null` means solver is not an admission filter;
empty list is invalid. Source hashes and limits are reported provenance, not admission
filters. This is a deliberate attestation model: records by an incorrect writer are not
made authentic by matching a checker hash. Identified buggy writer versions are flagged in
publication guidance and the affected leaves independently rechecked.

For every attempt node_id and cnf_sha256 are recomputed from bundle/cube. For admitted
VERIFIED_UNSAT the §4.8/§6 success fields, complete proof hash/count, exact checker
stdout/exit, route and stream transport conditions are also enforced. A purported success
with inconsistent fields is integrity error, not merely an unverified leaf. Nonadmitted
outcomes are listed, and their models/anomalies still bind.

### 10.2 Closure and canonical evidence selection

The evidence forms a graph keyed by `(formula_sha256, canonical cube)`. Identical split_id
copies from campaign/journals represent one split, so there is no ambiguous
campaign-vs-journal priority. Alternative splits are sorted by split_id, attempts by
`(journal ID,seq)`.

A node is closed if it has an admitted well-formed VERIFIED_UNSAT attempt, or at least one
well-formed split all of whose sign children are closed. Children strictly increase cube
size, so no valid cycle exists. Evaluation uses an explicit stack or increasing depth;
parser/resource limits produce a reported failure, not false open/closed results. The
scheduler max_cube_size is **not** an evidence admission bound; finite depth is <=V.

At a closed node the selection prefers the smallest admitted verified attempt Ref. If
there is none, it chooses the smallest split_id among **closed** splits and recurses in
child-index order. Summaries count selected split nodes and selected verified leaves and
give the max cube size of selected leaves. Exact results are memoized;
input-order-dependent incomplete memoization is forbidden. The chosen graph for any root
is a complete disjoint proof tree even though the stored alternatives form a graph.

`proved(F)` means `closed(F,[])`. Closing any nonempty requested root alone never proves
F. The mathematical justification is induction on selected evidence: a checked leaf
refutes its regenerated F∧C; every satisfying assignment of F∧C belongs to exactly one
sign child of a valid split.

### 10.3 Deterministic open frontier

Each requested root is traversed as follows: a closed node is skipped; a node with a valid
model is emitted as state model; otherwise, if well-formed splits exist, the smallest
split_id's children are traversed, regardless of whether another incomplete split
progressed further. If none exists, the node is emitted. This deliberately simple choice
gives a reproducible disjoint cover of remaining work; it need not minimize remaining
runtime.

For an emitted nonmodel node, each worker's latest node_stop/node_reopen affecting that
exact node by seq is taken. If at least one latest event is a stop, the smallest Ref among
those stops is chosen and its state/reason reported. Otherwise pending/null. These labels
are informative; they never change closure. Final lists are sorted by
`(formula_sha256,node_id)`. The requested roots themselves are pairwise incompatible
(§4.4), so their union is also disjoint. formula_open is computed separately from each
empty cube with the same traversal.

`shard --from-open` defaults to certificate.open (campaign scope). Explicit
`--scope formulas` uses formula_open. Model nodes are refused; blocked/stuck nodes require
an explicit reopen policy when running. A requested-root campaign must not schedule the
rest of the formula by reading formula_open without that scope option.

### 10.4 Models, anomalies and verdict

Complete MODEL/INVALID_MODEL assignments are re-evaluated on all clauses and cube units,
including nonadmitted records. Claimed MODEL that is false is IntegrityError. A complete
INVALID_MODEL that actually satisfies is included as a valid model plus anomaly
`mislabelled_model`; it cannot be hidden by its label. Parse-error records have no model.

Verdict order:

1. INCONSISTENT if a valid model exists for a formula whose empty cube is closed.
2. MODEL_FOUND if any valid model exists in campaign formulas.
3. PROVED if every campaign formula empty cube is closed and no valid model exists.
4. OPEN otherwise.

Anomalies do not invalidate an independently complete accepted proof tree by themselves,
but remain in the certificate and require a written resolution in the claim review (§13.3)
before an application claim is published. Structural integrity errors prevent certificate
production.

### 10.5 Merkle roots and independence

Within a closed summary, used leaves are sorted by node_id. A leaf hash is SHA256 of ASCII
`leaf` NUL `node_id` NUL `cnf_sha256` NUL `proof_sha256`, with hashes as lowercase hex. At
each level adjacent pairs are hashed as ASCII `branch` NUL `left_hex` NUL `right_hex`; an
odd last element is carried unchanged. Single leaf root equals leaf hash, empty root null.
No timestamp, filename or diagnostic field enters this Merkle tree.

The main certifier's pure closure/admission selection should be compact enough to read
line by line; validation must not be hidden elsewhere.

`tools/certify_min.py` is written from **§3–§7 and §10**, the shared schemas and the frozen
vectors, without reading the main certifier source, and has no project imports. Both
certifiers must agree on semantic certificate content, used Refs, open lists, verdicts and
Merkle roots. Agreement is not proof of journal honesty.

## 11. Recompute audit and retained-proof verification

### 11.1 Audit selection and input binding

`audit` requires a certificate and its campaign/bundles/journals, explicitly or through an
evidence manifest. It verifies exact certified journal prefixes by ID/count/head/byte
offset; later appended records are not silently incorporated. It re-runs certify on those
prefixes and compares semantic certificate fields before choosing targets. Supplied
used_attempts is a convenience, not an unverified authority.

Targets are unique used_attempts across all reported closed formula/root summaries.
`--all` selects all. `--sample N --seed HEX64` chooses the N smallest
`(SHA256(ASCII(seed)+NUL+ASCII(node_id)),node_id)` then orders selected targets by
node_id. N is clamped to population size and the actual population/count reported. Default
seed is SHA256(J(certificate)); an explicit seed lets a sample be fixed in advance. A 5%
sample means ceil(population/20), not 5% of input journal lines. `--sample N` requires
N>0. An empty used population produces an explicit empty/OPEN audit report and exit 1; it
is not successful verification by a vacuous zero-target match.

AuditTarget contains `node`, `node_id`, `source:Ref`, `cnf_sha256`, `proof_sha256`,
`route`, and `machinery` (the source snapshot). Its identity hash is SHA256(J(target)).
`targets_sha256` hashes concatenated `J(target)+LF` in target order. audit_begin, one
audit_target per ordinal, then audit_ready are persisted before any attempt. On restart an
incomplete plan is regenerated from preserved certified inputs and verified against the
begin hash before finishing missing target records. Ready plans cannot change silently.

### 11.2 Execution and results

For CDCL the audit regenerates canonical CNF and runs the recorded binary/options with
**no solver time limit** (`solver_time_ms=null` in audit attempts). Memory and disk
controls remain: the reference proof size allows an appropriate cap, explicitly configured
if necessary. An audit target is never silently split, nor the solver switched, while
claiming comparability. For unit route the `unit-v1` proof is regenerated. Every new proof
is checked with admitted cake_lpr.

Strict comparison requires matching source solver binary/argv, proof encoding, unit
algorithm where applicable and supported execution profile (platform/libc/Python/source
identity differences are reported and must match the declared reproducibility profile).
Same-profile different proof hash is MISMATCH even if the new proof passes. A successful
different-profile reproof is REPROVED_UNSAT and is not a historical hash match. Missing
source tools/profile without reproof is NOT_COMPARABLE. Resource exhaustion is OPEN;
invalid/new rejected proof or tool errors are FAILED with explicit cause. New solver model
contradicting a supposedly proved target is reported as inconsistency, never
NOT_COMPARABLE. Normal attempt evidence is written, and an audit_result referring to it.

Audit summary has the exact fields `format:"cubeproof-audit-report-1"`, `campaign:Hash`,
`certificate_sha256:Hash`, `targets_sha256:Hash`, `comparison:"strict"|"reprove"`,
`population:nonnegative integer`, `selected:nonnegative integer`, `seed:Hash`,
`counts:object` with every status in §4.7 audit_result mapped to a nonnegative integer,
`results:array` of `{target:AuditTarget,record:Ref,status:string,reason:string}` in target
order, and `pending:array` of target node IDs without a committed audit_result. Ref here
points to the audit_result record, which in turn identifies its attempt. Repeated audit
results for a target are rejected; uncommitted/exhausted execution is retried before the
final audit_result is committed, or a new audit plan is started in a new results
directory. Only all selected targets HASH_MATCHED yields strict success. A reprove report
clearly states its different guarantee. Sampling never upgrades to full verification by
description.

### 11.3 Determinism gate and fallback

The determinism gate requires complete successful limited/unlimited and file/stream runs to
give identical proof bytes for several pinned real cases. A killed limited run is not a
comparison candidate. This establishes a tested execution profile, not a theorem for every
CaDiCaL version or platform.

If strict-profile reproduction fails, the mismatch must be explained and corrected before a
campaign is run on that profile; changing the audit guarantee instead is a semantic change
recorded in a decision (§1.2). Re-running unlimited again is not itself a fallback. Independent reproof
remains mathematically useful but is labelled separately.

### 11.4 Verify retained

`verify-retained` receives explicit journals/campaign/bundles and a proofs root. It
enumerates all committed retained references in scope, verifies hash/size and regenerated
CNF, then runs the checker without solver. Missing/corrupt/rejected proofs fail; it never
silently checks only files that happen to exist. It reports
expected/found/verified/missing/corrupt/rejected counts and exact scope. A partial
retained set is not a verification of all transient or stream leaves. Evidence files are
read-only; verification writes to a separate results directory with its own worker
identity.

## 12. Commands and observable behavior

### 12.1 CLI and API

```text
cubeproof bundle import INPUT.cnf -o BUNDLE
cubeproof campaign create --bundle BUNDLE [--bundle ...] --policy POLICY --admit ADMIT
                         --solver PATH --solver-argv JSON --checker PATH
                         [--roots ROOTS] [--root-split none|static:FILE|proof-prefix-v1:K]
                         [--author NAME] -o campaign.json
cubeproof shard --campaign FILE --machines N [--formula KEY ...] [--weights FILE]
                [--from-open CERT --journals JOURNAL... [--scope campaign|formulas]] -o DIR
cubeproof run --campaign FILE --results DIR --work DIR --worker NAME
              --solver PATH --checker PATH [--helper PATH] [--shard FILE]
              [--jobs N] [--memory SIZE] [--disk SIZE] [--max-hours H]
              [--policy-override KEY=JSON_VALUE] [--proof-mode transient|retain|stream]
              [--inbox DIR] [--outbox DIR] [--export DIR] [--reopen-blocked]
              [--campaign-policy] [--accept-code-change] [--no-cache] [--no-known-answer]
              [-v] [-q]
cubeproof handoff --results DIR --nodes N --output-name NAME [--wait-ms N]
cubeproof status --results DIR [--json]
cubeproof certify --campaign FILE --journals JOURNAL... [-o certificate.json]
cubeproof evidence package --campaign FILE --journals JOURNAL... -o DIR
cubeproof audit --campaign FILE --certificate CERT --journals JOURNAL...
                --sample N|--all [--seed HEX64] [--comparison strict|reprove]
                --results DIR --work DIR --worker NAME --solver PATH --checker PATH
                [--helper PATH] [--memory SIZE] [--disk SIZE] [--proof-cap SIZE]
                [--no-known-answer]
cubeproof verify-retained --campaign FILE --journals JOURNAL... --proofs-root DIR
                          --results DIR --work DIR --worker NAME --checker PATH
                          [--memory SIZE]
cubeproof journal verify|repair JOURNAL --campaign FILE
```

`shard`, `run`, `certify`, `audit` and `verify-retained` also accept `--evidence MANIFEST`
as the exclusive alternative to the campaign/certificate/journal path arguments; conflicting
inputs are an error. The generated command reference
([cli-reference](cubeproof/cli-reference.md)) lists every option with its meaning. Bundle
paths resolve through campaign/evidence descriptors. No implicit search through unrelated
results folders. Python API mirrors commands through typed immutable values and returns
result documents; it does not exit or print.

The first run of a worker without `--shard` accepts an internally generated shard of all
campaign requested roots, expanded as needed by root splits. That shard is persisted. When the
nodes do not fit one journal line (§4.7) it is several shards instead, `initial-1`, `initial-2`,
..., the same division of the sorted nodes that `shard` makes for one machine; each is committed
before the next is submitted. A first use that was interrupted between them commits the missing
ones at its next start, and only then: when the accepted shards are some, not all, of exactly
those parts. A
later run never ignores a shard given on the command line: an identical shard is harmless,
a different one is validated and accepted or refused under §7.4. Resume does not
reconstruct ownership from a changed command line.

Weights file maps node_id to positive integer estimated cost; unspecified nodes cost 1.
Its exact object is `{format:"cubeproof-weights-1",campaign:Hash,costs:object}` where
costs maps known planned node IDs to positive integers. Unknown node IDs are rejected. The
roots input is `{format:"cubeproof-roots-1",roots:list of Node}` with §4.4 constraints.
Static prefix input is `{format:"cubeproof-prefixes-1",splits:list}` with entries exactly
the root_splits entry shape in §4.4; the chosen formula hashes bind it to its intended
use. Default sharding expands requested roots through a direct campaign root split if
present, sorts nodes by node_id and assigns round-robin. With weights nodes are taken
largest cost first and assigned to the smallest accumulated load, machine-index tie.
`--from-open` uses validated certificate frontier without expanding it further.
`--formula KEY` (repeatable) plans, of the nodes of either plan, only those of the campaign
formulas with these keys; an unknown key is a usage error and the other formulas are in no
file. No root must be covered twice.

### 12.2 Exit codes

| Code | Meaning |
|---|---|
| 0 | run: all still-owned requested regions closed, no model/anomaly/block; certify: PROVED; audit: all selected strict matches; other commands: completed success |
| 1 | Open work/resource block/time allocation ended; certify OPEN; audit incomplete/not-comparable/reproved-only |
| 2 | Valid model found; certify MODEL_FOUND |
| 3 | Usage/configuration/lock conflict; pending handoff timeout uses 1 instead |
| 4 | Integrity failure, inconsistency or strict audit mismatch |
| 5 | Missing/failing tool, retry exhaustion or I/O service failure |
| 6 | Run has recorded anomaly without a higher-priority condition |
| 130 | Explicit user signal interruption |

Preflight errors return before work. Completed work conditions use priority 4 > 5 > 2 >
6 > 1 > 0; a deliberate interrupted session uses 130 after clean handling, unless a
committed integrity error was already diagnosed (4). Local run success reports
given-away count separately and never asserts that handed-off regions are closed. Full
campaign proof always requires certify. A nonempty requested root may close while
certify exits 1 because the whole formula is still OPEN.

### 12.3 Status format

`status.json` has exactly these fields. It is a derived monitor interface, not evidence.

| Field | Type |
|---|---|
| format | `cubeproof-status-1` |
| campaign, journal, head, policy_sha256 | Hash; journal is header self |
| worker, seq, utc | Name, nonnegative integer, UTC string |
| lifecycle | `running`/`draining`/`stopped` |
| resources | ResourceSnapshot |
| reservations | Sorted list `{task_id:Id128,stage:string,cpu_milli:nonnegative integer,memory_bytes:nonnegative integer,disk:list of {id:string,bytes:nonnegative integer}}` |
| node_counts | Sorted list `{state:string,depth:nonnegative integer,count:nonnegative integer}` |
| active | Sorted list `{task_id:Id128,node_id:null|Hash,stage:string,elapsed_ms:nonnegative integer}` |
| oldest_elapsed_ms | Nonnegative integer, 0 when none |
| counters | Object of ASCII counter name -> nonnegative integer; diagnostics only |
| export | null or `{head:Hash,seq:nonnegative integer,utc:UTC,lag_ms:nonnegative integer}` |
| models, anomalies | Sorted bounded lists of Ref, at most 100 each; full totals in counters |
| coverage | Sorted list `{node:Node,closed_numerator:string,denominator_power_two:nonnegative integer}`; numerator canonical nonnegative decimal, denominator is 2^power |
| eta_ms | null or nonnegative integer |
| info | Open object, including stall reasons and any truncated-list notice |

Coverage numbers may exceed signed 64-bit range; decimal-string numerator avoids a wire
integer overflow for large V. The value sums selected closed disjoint cube measures
relative to the requested root; full closure is 1, no closure 0. Readers ignore unknown
info/counter names but reject unknown top-level fields/version. `status.txt` renders the
same snapshot.

## 13. Mathematical package and application

### 13.1 neighbourly.cnf

The CNF-emission module of `neighbourly`, with the import boundary of §2.1. Its Formula
emission fixes allocation, clause order, XOR chunk sizes, Tseitin definitions and tag
order: these determine the formula bytes (§3.3). Submodules: builder, witness, encodings,
dimacs, bundle. Builder exposes the variable/clause/forbid/AND/XOR/layer operations;
Witness is a protocol returning 0/1/None for a named tuple. With witness present every
clause is checked when all its variable values are known; a violated known clause is
collected with its tag by default. An explicit strict mode raises instead. The
complete-oracle adapter requires every variable value and collects the violations. Unknown
generic witness values do not become false by default; semantic-control tests require
complete assignments. No witness overhead in the ordinary emission loop beyond a single
disabled check.

The module holds only the encodings the formulas use. `neighbourly.cnf` is the canonical
**producer** writer; cubeproof has an independent strict reader/cube-CNF writer and
does not import it. Shared byte-contract fixtures keep both consistent.

### 13.2 neighbourly

Besides `cnf` (§13.1), modules: maps, enumeration, exact/geometry, encoding.chirotope
(S/H/A), encoding.faces (B/I), encoding.gauge, encoding.formula, interpret, checks, corpus12.
The corpus12 module owns 59 matrices, golden counts/hash fixture and 12-specific corpus checks.

Generic map/geometry utilities validate their own structural domains, not a global
mod-12 rule. Enumeration may be asked for n=10 and return zero orientable maps. The
orientable-neighbourly encoding entry validates integer n>=4 and the necessary residue
condition `n mod 12 in {0,3,4,7}` along with map structural/orientability requirements.
This condition is not asserted sufficient for existence. Scope-specific article results
are applied only where their hypotheses hold; the n=12 census is not a generic theorem.

The exact 59 n=12 base hashes (§3.3) and the mathematical controls of `checks` are fixed.
n=4/7 realized fixtures test semantic clauses; n=15/16 stored maps test structural
generality and per-face controls. They do not prove a theorem for every n. Article
citations use labels.

Bundle producer parameters include n, map identity, layers and gauge. Interpretation
must validate formula identity, then rebuild/load the corresponding VariableMap from
verified mathematical input; optional display names are not authoritative semantics.
The model description of a fixed assignment is pinned by a golden document.

### 13.3 faces12-campaign

Commands: `formulas [--check]`, `campaign init|prefixes`, `run`, `shard`, `handoff`,
`certify`, `audit`, `status`, `claim`, `model`, `maps`, `selftest`,
`release bundle|verify|provenance|docs`.

Default campaign contains exactly the 59 corpus formulas, each requested root empty,
`proof-prefix-v1` with 12 variables, then lookahead-v1 with k=4. `--prefix 0` is fully dynamic;
1..20 selects a different initial depth. Prefix selection data may be reused if its
base hash, ordered variables and pinned provenance validate. Paths/commands are thin
adapters over libraries, not a second scheduler/certifier.

A restricted requested root (a pilot root) is a case's
proof-prefix cube, canonicalized; its 12 assignments are not appended a second time, and
its closure is not described as a proof of the full map. A campaign of such roots
certifies closed requested roots, not PROVED.

`claim` re-runs certify on the evidence input and requires PROVED, exactly the 59 published formula
hashes/layers/gauge, and a resolution for every anomaly. It reports the certificate/campaign IDs
and, separately, the obligations for map enumeration, encoding and article reduction that are not
reviewed.

A certificate admits the records of every checker hash in `admit` (§10.1) and cannot say what
program a hash stands for. The application therefore records the SHA-256 of the cake_lpr and
CaDiCaL binaries of its release image (`faces12_campaign.pins`). `campaign init` refuses a
configured or admitted checker that is not that cake_lpr unless `--unpinned-checker` is given, and
reports the tool hashes of the campaign. `claim` requires every checker of `tools` and `admit` to
be that cake_lpr or to be accepted by hash with `--accept-checker`. Its statement and result
name the admitted checkers, an accepted one as not the release binary, and, from the machinery
of the records the certificate uses, the checkers and solvers those records name and the
cubeproof sources (`cubeproof_sha256`, `tools.used_cubeproof_sha256`) that wrote them. The solver
proposes proofs only and is not restricted. A SAT assignment is not automatically a geometric realization. A bare edited certificate
JSON is insufficient input for claim.

Claim review input is `faces12-claim-review-1`: fields `format`,
`certificate_file_sha256:Hash` (the SHA-256 of the certificate file that the evidence manifest
lists; the `certificate_sha256` of an audit, §11.2, is the document hash),
`article_sha256:Hash`, `checker_sha256:sorted nonempty list of distinct Hash` (exactly the
checker hashes of the campaign's `tools` and `admit`), `reviewer:string`, `utc:UTC`,
`obligations:list` of
`{name:"enumeration"|"encoding"|"reduction",status:"reviewed"|"outstanding",evidence:Artifact|null,
note:string}` (exactly one entry per name, sorted), and `anomaly_dispositions:list` of
`{record:Ref,code:string,resolution:string}` sorted by Ref/code. Every certificate anomaly needs a
nonempty resolution. The input is a human review attestation, not a signature. `claim --evidence
MANIFEST --review REVIEW` checks certificate/article/artifact hashes, then prints a conditional
computational-support statement naming the obligations whose status is `outstanding`. It prints an
unconditional article conclusion only when all named obligations are reviewed with nonnull verified
artifact references. Application cannot replace mathematical review by merely creating this file;
provenance identifies the reviewer and review artifacts.

## 14. Packaging, platforms and operation

Support profile: Linux x86-64 (native, WSL 2 or a container), Python >=3.10. Process
execution, journal writing/repair, run/audit/verify-retained require util-linux and working
POSIX flock/fsync. The release image is linux/amd64, with pinned tools. Another architecture
requires its own build and its own determinism gate (§11.3) before a campaign runs on it.

All packages must install/test as wheels outside the source tree with declared local
dependencies. Development tools (pytest, coverage, ruff, mypy, build) are development
dependencies only. The tested development tool set is pinned in a constraints file
(`constraints/dev.txt`). Data is read through `importlib.resources`. Native helper is an
optional separately built executable located explicitly in config; the image includes it.
Without the helper, the tested Python fallback is used; an absent mandatory solver or checker
is a preflight failure.

The development/test image has the pinned CaDiCaL/cake_lpr. The release image installs
built artifacts rather than relying on PYTHONPATH into an unbuilt checkout. A release is
built twice and the binary, formula and source-bundle hashes are compared; image metadata
timestamps need not match. A release preserves the exact tools/sources needed for strict
audits, alongside image digest and package manifests.

A worker uses separate per-worker named volumes for durable results and disposable work.
They may share underlying capacity and must be budgeted accordingly. A worker's
authoritative live journal stays in its results volume, never on a host bind mount; its `/io`
binding holds the immutable inputs, inbox, outbox and exports. Non-root volume ownership is
configured during initialization; the running solver is not required to be root. The
container runs with `--init --network none`.

```text
docker run -d --name faces12-WORKER --init --network none
  -v faces12-results-WORKER:/work/results
  -v faces12-work-WORKER:/work/scratch
  -v HOST_IO:/io
  faces12-campaign:1.0.0 run --campaign /io/campaign.json --shard /io/shard.json
  --results /work/results --work /work/scratch --worker WORKER
  --inbox /io/inbox --outbox /io/outbox --export /io/export
```

The wrapper creates deterministic unique volume/container names, quotes host paths with
spaces and never deletes result volumes. `docker stop -t 120` then `docker start` resumes.
Recreating a container reuses the durable results volume and explicit immutable inputs;
work may be empty. Recovery after a lost container versus a lost disk, and backup restore,
are documented ([RUNNING](RUNNING.md)). Result exports include externally retainable
journal heads/checksums. No local journal promise survives physical loss of its only copy.

`RELEASE_FILES.txt` lists every file of the release explicitly; nothing else is published.
Public docs and code are English.

## 15. Verification

### 15.1 Functional obligations

| Test family |
|---|
| 59 base hashes, layer/tag/pool/model goldens; prefix-order case bytes vs canonical cube mapping |
| Strict JSON/DIMACS/cubes/schema, empty CNF/clause/V=0, malformed base64, pure digest vs full bytes |
| Journal self/prev/seq, last/middle corruption, prefix anchors, short write/EINTR/fsync failures |
| Every primary/secondary tool-outcome combination, exact checker line/exit, swapped IDs/files, no truncated stdout acceptance |
| Retain/quarantine crash points, missing committed artifact, cross-FS publication, idempotent recovery |
| Shard/handoff commit/publish/move failures, duplicate requests, overlaps, model/blocked/reopened replay |
| Both certifiers: missing children, invalid splits, alternative splits, evidence choice, input permutations, requested-root scope, nonadmitted models |
| Budget invariants, no impossible-task wait, cgroup v1/v2, shared storage, pressure and event-loop responsiveness |
| Real pinned tools, complete limited/unlimited and stream/file determinism, UP acceptance, strict and reproof audit |
| Independent wheel/sdist installs, package data/helper, import rules, Linux image and host wrapper |
| Mathematical controls/census, n=4/7 and stored n=15/16 structural fixtures; no overgeneralized theorem claims |
| Multi-worker end-to-end create/shard/handoff/stop/resume/certify/audit/claim with both certifiers |

Random-small-CNF tests separate soundness (`PROVED` implies brute-force UNSAT under
truthful accepted leaf attestations), completeness of a supplied full evidence tree,
and termination of a generous tiny test profile. A bounded operational run may correctly
leave an UNSAT formula OPEN. Lying admitted attestations test the stated trust boundary;
neither certifier is expected to authenticate them cryptographically.

Trust-relevant changes require independent review, invariant tests and targeted mutations:
loose checker string/exit, missing rehash/binding, wrong CNF header/order/formula ID,
omitted split child, nonempty-root proof, stale admission, broken journal self/prev,
unsafe recovery order and missing stream EOF. Full branch coverage is preferred for small
pure validators and the closure. Branches that depend on the operating system are covered by
fault injection where a test cannot reach them; a branch that neither reaches is a documented
exception. Defensive code is not removed for the sake of coverage.

## 16. Decisions and references

| Design record | Decision |
|---|---|
| [0001](decisions/0001-the-article-is-canonical.md) | One canonical mathematical article |
| [0002](decisions/0002-the-checker-decides.md) | Only the verified checker closes a case |
| [0003](decisions/0003-identity-by-hash.md) | A formula is identified by its hash, not by a version number |
| [0004](decisions/0004-layers-s-h-a-b-i.md) | The published formula uses S, H, A, B and I |
| [0005](decisions/0005-no-runtime-dependencies.md) | The runtime is the standard library |
| [0006](decisions/0006-english-repository.md) | Public documentation is in English |
| [0007](decisions/0007-documentation-system.md) | Documentation by task, with generated references |
| [0008](decisions/0008-explicit-release-list.md) | A release is built from an explicit list of files |
| [0009](decisions/0009-three-distributions.md) | Three distributions, one release train |
| [0010](decisions/0010-cube-evidence-graph.md) | A canonical cube evidence graph with a deterministic selected tree |
| [0011](decisions/0011-three-proof-modes.md) | Three proof modes; proofs are not stored by default |
| [0012](decisions/0012-proof-prefix-and-lookahead.md) | The fixed prefix split is separate from lookahead-v1; choices are recorded |
| [0013](decisions/0013-admission-and-guarantees.md) | Checker and optional solver admission; attestation and reproof are different guarantees |
| [0014](decisions/0014-offline-shards-and-handoff.md) | Offline shards, an idempotent durable handoff outbox and prefix exports |
| [0015](decisions/0015-single-event-loop.md) | One coordinator event loop with supervised, bounded helper processes |
| [0016](decisions/0016-self-checksummed-journals.md) | Self-checksummed journals, strict torn-tail recovery, external anchors and snapshots |

*Informative technical references; these explain choices, not additional requirements:*

- [Cube and Conquer, original paper](https://fmv.jku.at/papers/HeuleKullmannWieringaBiere-HVC11.pdf)
- [Concurrent Cube-and-Conquer](https://fmv.jku.at/papers/TakHeuleBiere-SAT12.pdf)
- [CakeML verified proof checkers and their guarantees](https://cakeml.org/checkers.html)
- [Linux write and partial writes](https://man7.org/linux/man-pages/man2/write.2.html)
- [Linux fsync and directory durability](https://man7.org/linux/man-pages/man2/fsync.2.html)
- [Linux rename and filesystem boundaries](https://man7.org/linux/man-pages/man2/rename.2.html)
- [Linux resource limits](https://man7.org/linux/man-pages/man2/getrlimit.2.html)
- [Linux cgroup v2 memory accounting](https://cdn.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html)
- [Python JSON strictness options](https://docs.python.org/3/library/json.html)
- [Docker storage](https://docs.docker.com/engine/storage/)
