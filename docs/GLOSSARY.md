# Glossary

The words this project uses in a sense of its own. Mathematical terms point to the
statement of the article that defines them, by label; [THEORY_MAP](THEORY_MAP.md) gives
the number. The terms of the computation are those of `cubeproof` and `faces12-campaign`;
their normative definitions are in the [SPECIFICATION](SPECIFICATION.md), cited below as
"SPECIFICATION §n".

## The mathematics

**Neighbourly polyhedron.** A polyhedron in which every two faces share an edge
(paper: def:polyhedron), under the hypotheses (H1) to (H3) (paper: hyp:H). With twelve faces
it has 44 vertices, 66 edges and genus 6 (paper: prop:euler).

**Map, neighbourly map.** The combinatorial type of such a polyhedron: the set of triples
of faces that meet at a vertex (paper: def:map). There are 59 orientable types with twelve faces
(paper: thm:59), shipped as `topology_01.txt` to `topology_59.txt` in the data of the
`neighbourly` package (`neighbourly.corpus12`) and read by `neighbourly.maps.CombinatorialMap`.

**General position (G).** No four of the thirteen covectors (the twelve face planes and the
plane at infinity) are linearly dependent, so every bracket is nonzero (paper: hyp:G); every
realization can be moved into general position (paper: thm:genpos).

**Real vertex.** A triple of the map. The planes of three faces that do not form one
also meet in a point under (G), but that point is not a vertex of the polyhedron.

**Link.** The faces around a face `f`, in the cyclic order of its boundary (paper: def:map).
In the code, `CombinatorialMap.link_cycle`.

**Ends.** The two faces at the ends of the edge that faces `i` and `j` share, written
Ends(i,j) = {z0, z1}; `CombinatorialMap.end_pair`.

**Realization.** Twelve planes, as covectors, whose faces form a neighbourly polyhedron of
the given map (paper: def:realization, lem:bridge).

**Element 0, the plane at infinity.** The thirteenth covector, `q_0`. A bracket through
it is a determinant of three face normals (paper: lem:cofactor), and its point on each
line is where the line's circular order is cut (paper: rem:cut).

**Bracket.** The determinant of four of the thirteen covectors; there are 715. Its sign is
the variable `X_S`, true when the bracket is negative
(`neighbourly.encoding.chirotope.ChirotopeLayers.bracket_literal`).

**Chirotope.** An alternating sign function satisfying the oriented-matroid axioms.
The signs of a real vector configuration's determinants give one, but an abstract
chirotope need not have such a realization. *Uniform* means nonzero on tuples of
distinct labels; repeated-label tuples have value zero. General position gives
uniformity here (paper: hyp:G, thm:genpos). Layers S, H and A say
exactly that the bracket bits form a uniform chirotope (paper: thm:chirotope).

**Order bit.** Whether `P_ijk` (the point where the planes of faces `i`, `j` and `k` meet)
comes before `P_ijl` on the line of faces `i` and `j`; a
function of three brackets (paper: thm:order).

**Cut order.** The linear order obtained by cutting a circular order at one element
(paper: lem:cutorder, rem:counts).

**OnB.** Whether the point `P_iju` lies inside the edge `E(i,j)` (paper: def:onb, lem:onb).

**Corner bit, reflex corner.** A corner is reflex when its interior angle exceeds π. The
corner bit is a turn bit corrected by one orientation bit per face (paper: lem:turn,
lem:sf), and a crossing parity fixes that orientation bit (paper: lem:parity).

**Layer.** A group of clauses with one meaning: S, H, A, B and I
([REFERENCE](REFERENCE.md#layers)).

**Gauge, gauge face.** Thirteen unit clauses that pin thirteen brackets, keeping one
representative of each orbit of the reorientation symmetry (paper: lem:gaugegroup,
cor:gauge). The gauge face is the face that twelve of the pinned brackets contain.

**Formula.** The CNF formula of one map: layers S, H, A, B, I and the gauge
(paper: def:formula). `formula_sha256` identifies the exact bytes of one map's formula
([formula identity](#the-evidence)).

## The evidence

**Bundle.** An immutable directory holding one formula's DIMACS bytes and its SHA-256, which
`cubeproof` reads without knowing what the formula means. `faces12-campaign formulas` writes
the bundles of the 59 formulas, through `neighbourly.cnf`; `cubeproof bundle import` makes one
from any external DIMACS file.

**Formula identity (`formula_sha256`).** The hash of the exact canonical bytes of a formula.
Identity is by bytes, not by logical equivalence ([decision
0003](decisions/0003-identity-by-hash.md)).

**Cube, node, root.** A cube is a set of literals over distinct variables, kept sorted by
variable. A *node* is a formula together with a cube; `node_id` hashes both, so the order in
which the cube was reached does not matter (SPECIFICATION §3.2,
[decision 0010](decisions/0010-cube-evidence-graph.md)).
A *requested root* is a node a campaign asks to have closed; the *empty root* is the empty
cube, that is, the whole formula (paper: def:cube).

**Split.** A cube together with an ordered list of one to twenty variables not yet in it; its
`2^k` sign children are the cubes with every combination of signs added (paper: lem:split).
A split is recorded with its variables, and `split_id` identifies it. Splits come from three
sources: a *root split* fixed by the campaign, the dynamic splitter during a run, or a static
file.

**Leaf, leaf CNF.** A node on which a checked refutation is attempted. Its CNF is the
formula's bytes plus one unit clause for each literal of the cube, sorted by variable, so a
cube has one CNF and one `cnf_sha256` ([decision 0010](decisions/0010-cube-evidence-graph.md)).

**Attempt.** One try on one node, ending in one outcome: `VERIFIED_UNSAT` (the only outcome
that closes a node by itself), `EXHAUSTED` (a time, size or memory limit), `MODEL` or
`INVALID_MODEL`, `CHECK_REJECTED` or `TOOL_FAILED`. An attempt on a leaf that unit propagation
refutes (route `unit`) is checked like any other; one that needs the solver has route `cdcl`
([TRUST](TRUST.md#what-establishes-a-leaf)).

**Closed, open.** A node is *closed* when it has an admitted verified attempt or a recorded
split all of whose children are closed. Closure is literal: a closed ancestor does not close a
requested root. A formula is *proved* only when its empty cube is closed (paper: thm:coverage,
lem:closure, cor:treecover). The *open frontier* is what remains to do.

**Pilot root.** A requested root that is not the empty cube: a campaign may ask for one
region of a formula only. `faces12-campaign campaign init --root MAP:CASE` names it as a
*case* (next entry) of the prefix split of a map. Closing it settles
only its region (paper: rem:pilotroot) and the certificate stays OPEN.

**Case.** One of the `2^d` sign children of a split of the empty cube on `d` variables,
numbered by the bits of its signs (paper: prop:cases): the special case of one split.

**Proof mode.** `transient` (the default: solve to a file, seal, check, record, delete),
`retain` (the checked proof is also published under `proofs/` before its record is committed)
or `stream` (solver, relay and checker coupled through pipes, nothing spooled)
([decision 0011](decisions/0011-three-proof-modes.md)).

**Proof-prefix split (`proof-prefix-v1`), `lookahead-v1`.** Two ways to choose splits. The
proof-prefix split chooses the root split of a formula, K variables (twelve in the default
faces12 campaign), from the proof
prefixes of sampled runs of the pinned solver, and runs only when a campaign is made;
`lookahead-v1` is the dynamic splitter of a run, with a native helper and a Python reference
(SPECIFICATION §9, [decision 0012](decisions/0012-proof-prefix-and-lookahead.md)).

**Campaign.** The immutable document that names the formulas, requested roots, root splits,
policy, pinned tools and admission. Its ID is the SHA-256 of the document without its final
line feed, so a change is a new campaign.

**Policy.** The limits and choices a campaign embeds: leaf times, proof caps, checker arena,
splitter, retries, proof mode ([RUNNING](RUNNING.md#the-policy)).

**Admission.** The filter that decides which attempts count: the checker hash and, if the
campaign lists solvers, the solver hash and arguments. Admission is not authentication of
the writer ([decision 0013](decisions/0013-admission-and-guarantees.md)).

**Worker, coordinator.** A worker is one named `cubeproof run` with its own results and work
directories and its own journal. Inside it one coordinator, a process, not a person, runs the event
loop that starts, reaps and records tools ([decision 0015](decisions/0015-single-event-loop.md)).

**Journal, record.** A worker's append-only file of canonical JSON lines, each with its own
hash (`self`), the previous hash (`prev`) and a sequence number. A *Ref* names one record as
`(journal ID, seq)`. The journal ID is the self hash of the header
([decision 0016](decisions/0016-self-checksummed-journals.md)).

**Torn tail.** An unterminated last line after a crash. It is the only damage a run repairs
(`journal repair` does the same); every other damaged line is an integrity failure.

**Head, anchor.** The head is the last complete record's `self` hash. A copy of the head and
the journal's length, kept elsewhere, is an *anchor*: only against one can the removal of a complete tail be
detected.

**Shard.** A list of nodes that one worker owns, as a file (`cubeproof-shard-1`). `shard`
plans them; a worker commits an acceptance record before it launches a node of a shard.

**Handoff.** A request to a worker to give away nodes, answered by a shard file in its outbox.
The giver commits before it publishes ([decision
0014](decisions/0014-offline-shards-and-handoff.md)).

**Export.** A copy of a committed journal prefix with its head, published periodically into
an export directory. It is a backup whose lag is the recovery point, not a replica.

**Certificate, verdict.** The document `cubeproof certify` recomputes from a campaign and its
journals: the used leaves, per-formula summaries with Merkle roots, open lists, models,
anomalies and the verdict `PROVED`, `OPEN`, `MODEL_FOUND` or `INCONSISTENT`. It attests what the
journals claim ([TRUST](TRUST.md)).

**Evidence package.** A portable directory (`cubeproof evidence package`): the campaign, its
bundles, snapshots of the certified journal prefixes, the certificate and a manifest
`evidence.json` that lists every file with its size and SHA-256. `--evidence MANIFEST` is the
exclusive alternative to the path arguments of the consuming commands.

**Anomaly.** A claimed model that is not one, a rejected proof or a malformed split: a fault of
the evidence or of the pipeline, not a hard leaf. It is recorded and stays in the certificate
until a human resolves it ([COMPUTE](COMPUTE.md)).

**Machinery.** The solver and checker binaries, their options and the platform, recorded in
each journal header or resume record; later records are judged against it.

**Audit.** A recomputation of selected leaves from a certificate. *Strict* comparison asks for
the proof bytes the journal recorded (`HASH_MATCHED`); *reprove* asks for a new checked proof
under whatever profile ran (`REPROVED_UNSAT`), a different guarantee ([AUDITING](AUDITING.md)).
A *sample* verifies only the leaves it selects.

**Retained proof.** A checked LRAT proof kept in `proofs/` in retain mode, so that
`verify-retained` can check it without a solver.

**Claim gate, review.** `faces12-campaign claim` recertifies the evidence and reads a human
review file; it prints a conditional statement unless every obligation is reviewed with verified
artifacts. The review is an attestation, not a signature ([COMPUTE](COMPUTE.md)).

## The documentation

**Label.** The `\label` of a statement in `paper/faces12-en.tex`, such as `lem:parity`.
Code and documents cite statements as `(paper: lem:parity)`, because labels stay when
numbers change.

**Claim, claims ledger.** A statement the project makes, with its evidence and its limits,
registered in `docs/claims.json` and listed in [CLAIMS](CLAIMS.md).

**Test tier.** A group of tests with one way to run it: static checks, architecture, fast,
slow, installed, release view, and the test-image and release-image tiers, which need Docker
([STATUS](../STATUS.md#implemented-and-tested)).
