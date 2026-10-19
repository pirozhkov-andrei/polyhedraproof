# The faces12-campaign application

`faces12-campaign` (import name `faces12_campaign`) runs the twelve-faces problem as a
`cubeproof` campaign over the formulas of `neighbourly`. Its commands are thin adapters over
the two libraries: it writes and verifies the published formulas, decides the inputs of the
campaign, hands running, sharding, certification, auditing and status to `cubeproof`
unchanged, and gates the mathematical claim. It is not a second scheduler or certifier.
Every command and option is listed in the [command reference](cli-reference.md); the
normative text is [SPECIFICATION](../SPECIFICATION.md) §13.3.

## The published formulas

The campaign is about 59 formulas, one per map of the census (paper: thm:59): every layer
`S,H,A,B,I`, gauge at face 1 (paper: thm:necessity, cor:gauge). `formulas -o DIR` writes them
as `cubeproof-bundle-1` directories `DIR/map01` .. `DIR/map59`; each formula is compared with
the packaged fixture of the 59 base hashes before it is published, and an existing bundle is
verified, never overwritten. `formulas -o DIR --check` rebuilds every bundle from its packaged
map and requires the published hash, layers and gauge; `formulas --check` recomputes the
formulas in memory. A hash equal to the fixture shows that the bytes are the published
formula; it says nothing about satisfiability.

## Campaigns

`campaign init --formulas DIR ... -o campaign.json` creates the campaign beside the bundles
(paths in a campaign are relative to it):

- **default**: the 59 formulas, each requested root empty, the twelve-variable proof-prefix
  split (`proof-prefix-v1`) as campaign root split, then the dynamic policy default
  `lookahead-v1` with `k = 4`; proof mode `transient` unless `--proof-mode` says otherwise;
- `--prefix 0` has no root split (fully dynamic); `--prefix K` (1 to 20) another initial depth;
- without `--prefixes` the prefix is computed with the pinned solver, which can take long for each
  formula (191 s for the formulas of maps 1 and 2 together on a laptop; the others have not been
  measured). `--prefixes FILE` reuses stored selections instead: a
  `cubeproof-prefixes-1` document whose entries are accepted only if the formula is a campaign
  formula, the split is at the empty cube, the `K` ordered variables are in the bundle's `order`
  pool and the recorded provenance is the pinned algorithm (samples 2, steps 100000, conflicts
  90000, seed 5, pool `order`) run with the solver binary the campaign pins. `campaign prefixes
  --campaign FILE -o FILE` exports the stored prefixes of an existing campaign for such reuse;
- `--maps 1,2` restricts the campaign to some formulas: a rehearsal campaign, whose journals never
  count for the campaign of the 59 (the pilot computation in `STATUS.md` was one);
- `--root MAP:CASE` (for example `--root 2:17`) makes a rehearsal campaign with a pilot root:
  the requested root is that case of the map under its stored prefix (bit `j` of the case
  number gives the sign of the `j`-th prefix variable; the cube is sorted by variable), and the
  prefix split stays at the empty cube, so the pilot root is one of its children. Closing a
  pilot root closes that region only (paper: rem:pilotroot): its certificate is OPEN for the
  map.

The solver and checker binaries and the solver options are configuration (`--solver`,
`--checker`, `--solver-argv`); by default the configured checker is the one admitted.

## Running and certifying

`run`, `shard`, `handoff`, `certify`, `audit` and `status` are the `cubeproof` commands with
the same arguments ([cubeproof reference](../cubeproof/cli-reference.md)); a certificate is
always recomputed from journals, and a portable evidence directory is made with
`cubeproof evidence package`.

## Models

`model --evidence MANIFEST` (or `--campaign F --journals J...`) recomputes the certificate and
describes each model in the article's vocabulary: brackets, line orders and orientation bits,
violated clauses per layer and reflex corners per face. The formula is rebuilt from its
packaged map before its variables are interpreted. A model satisfies the clauses of its
formula, which are necessary conditions only; it is not automatically a geometric realization
(paper: rem:noconverse) but a candidate to be examined. The command exits 2 when the
certificate has a model, 0 when it has none, and 4 when the certificate is INCONSISTENT (a
formula both proved and modelled): the inconsistency outranks the model.

## The claim

`claim --evidence MANIFEST --review REVIEW --article paper/faces12-en.tex` re-runs the
certifier on the evidence directory and requires the packaged certificate to be the recomputed
one, the verdict PROVED, exactly the 59 published formulas (each rebuilt from its map with the
published layers and gauge), and a resolution for every anomaly of the certificate. A bare
certificate file is never accepted as input.

The gate also says which program checked the leaves. A certificate admits the records of every
checker hash its campaign lists and cannot know what a hash stands for, so the SHA-256 of the
cake_lpr and CaDiCaL binaries of the release image are recorded in `faces12_campaign.pins`.
`campaign init` refuses a checker that is not that cake_lpr unless `--unpinned-checker` is given,
and prints the tool hashes of the campaign under `tools`. `claim` refuses a campaign that
configures or admits any other checker (`claim.checker`) unless that hash is accepted with
`--accept-checker SHA256`. Its statement and its result name every admitted checker, saying of
an accepted one that it is not the release binary, and separately the checkers and solvers
that the records used by the certificate name and the cubeproof sources that wrote them.

The review is a human attestation in canonical JSON (one line, sorted keys, no spaces, then a
line feed), format `faces12-claim-review-1`:

| Field | Meaning |
|---|---|
| `format` | `faces12-claim-review-1` |
| `certificate_file_sha256` | SHA-256 of the certificate file the evidence manifest lists, the value `cubeproof evidence package` prints under the same name (an audit report's `certificate_sha256` is the document hash, which excludes the final line feed) |
| `article_sha256` | SHA-256 of the article file given with `--article` |
| `checker_sha256` | the checker hashes of the campaign (`tools.checker` and `admit.checker_sha256`), sorted, each once: the reviewer states which binaries the attested checks name |
| `reviewer`, `utc` | who reviewed, and when (`YYYY-MM-DDTHH:MM:SS.mmmZ`) |
| `obligations` | one entry per name `encoding`, `enumeration`, `reduction`, sorted: `{name, status: reviewed or outstanding, evidence: Artifact or null, note}` |
| `anomaly_dispositions` | `{record: {journal, seq}, code, resolution}` for every certificate anomaly, sorted by record and code |

Evidence artifacts are `{path, sha256, bytes}` with a path relative to the review file's
directory; each is verified. The command prints a **conditional** computational-support
statement (exit 1) while any obligation has the status `outstanding` or lacks an artifact, and the
unconditional article conclusion (paper: cor:conditional) only when all three are reviewed
with verified artifacts (exit 0). A refused claim exits 1 for an OPEN certificate, 2 for a
model and 4 otherwise (an INCONSISTENT certificate included). The certificate is an
attestation of the journals (paper: rem:attestation); the review file names who reviewed
what, it is not a signature, and writing it does not replace the mathematical review.

## Controls and release

`selftest` checks the identities of the encoding on map 1, the corpus and the base formula in
seconds; `maps` reruns the census of maps with twelve faces (minutes). `release bundle`,
`release verify`, `release provenance` and `release docs` build and check the deterministic
source archive (manifest format `faces12-source-bundle-1`), record the provenance of an
installation and regenerate the command reference, with the source root and the tool
binaries given explicitly ([RELEASE](../RELEASE.md)).
