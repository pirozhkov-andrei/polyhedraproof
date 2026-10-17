"""Campaigns, bundles, journals and evidence cases of the corpus.

Specification §4.2-§4.4, §4.7-§4.10, §7 and §10.

Valid cases carry the expected certificate computed by sv_certify. Invalid cases change one
thing of a valid input and name the requirement it violates and the error kind certify
reports (reading 6). Audit plans exercise the audit reader rules of specification §11.1.
"""

from __future__ import annotations

import copy
import json
from collections.abc import Callable, Sequence
from typing import Any

from sv_certify import EXIT, Copy, certify
from sv_records import (
    ARGV,
    ARGV_SEED,
    CHECK_HEAP,
    CHECK_OK,
    CHECKER,
    CHECKER_BAD,
    M_BAD_CHECKER,
    M_OK,
    M_SEED,
    P_RETAIN,
    P_STREAM,
    P_TRANSIENT,
    SOLVER,
    SOLVER_CRASH,
    SOLVER_SAT,
    Journal,
    check,
    ident,
    out,
    policy,
    sign,
)
from sv_spec import ZERO, Formula, document, jbytes, jsha, node, node_id, sha, split_id

F_SAT = Formula("F_sat", 1, [[1]])
F_UNSAT = Formula("F_unsat", 1, [[1], [-1]])
F_EMPTY = Formula("F_empty", 0, [])
F_CLAUSE = Formula("F_clause", 0, [[]])
ALL3 = Formula(
    "all3",
    3,
    [
        [1, 2, 3],
        [-1, 2, 3],
        [1, -2, 3],
        [-1, -2, 3],
        [1, 2, -3],
        [-1, 2, -3],
        [1, -2, -3],
        [-1, -2, -3],
    ],
)
SAT3 = Formula("sat3", 3, [[1, 2], [-1, 3], [-2, -3]])
FORMULAS = [F_SAT, F_UNSAT, F_EMPTY, F_CLAUSE, ALL3, SAT3]

SOLVER_OTHER = sha("cadical unadmitted test binary")

NAMES_TSV = b'1\t"x1"\n2\t"x2"\n3\t"x3 \\"third\\""\n'
TAGS_TSV = b'1\t3\t"all"\n2\t2\t"middle"\n'


def pretty(value: Any) -> bytes:
    """Readable corpus metadata (not a canonical document)."""
    return (json.dumps(value, indent=1, sort_keys=True, ensure_ascii=False) + "\n").encode()


class Files:
    """All generated files, by path relative to the corpus root."""

    def __init__(self) -> None:
        self.files: dict[str, bytes] = {}

    def put(self, path: str, data: bytes) -> str:
        if path in self.files and self.files[path] != data:
            raise ValueError(f"two different contents for {path}")
        self.files[path] = data
        return path


def manifest(
    formula: Formula, pools: dict[str, list[int]], side: dict[str, bytes]
) -> dict[str, Any]:
    return {
        "format": "cubeproof-bundle-1",
        "formula_sha256": formula.sha256,
        "variables": formula.variables,
        "clauses": len(formula.clauses),
        "pools": pools,
        "producer": {
            "name": "spec-vectors",
            "version": "1",
            "parameters": {"formula": formula.name},
        },
        "side_files": [
            {"path": name, "sha256": sha(data), "bytes": len(data)}
            for name, data in sorted(side.items())
        ],
    }


def entry_split_id(entry: dict[str, Any]) -> str:
    """split_id of a root_splits/prefixes entry."""
    parent = entry["node"]
    return split_id(node_id(parent["formula_sha256"], parent["cube"]), entry["variables"])


class CampaignDir:
    """A campaign file with its bundles under ``campaigns/<name>/``."""

    def __init__(
        self,
        files: Files,
        name: str,
        formulas: Sequence[tuple[str, Formula]],
        roots: Sequence[tuple[Formula, Sequence[int]]],
        splits: Sequence[tuple[Formula, Sequence[int], Sequence[int]]] = (),
        solvers: list[dict[str, Any]] | None = None,
        pools: dict[str, dict[str, list[int]]] | None = None,
        side: dict[str, dict[str, bytes]] | None = None,
    ) -> None:
        self.files = files
        self.dir = f"campaigns/{name}"
        self.formulas = {f.sha256: f for _, f in formulas}
        for key, formula in formulas:
            base = f"{self.dir}/bundles/{key}"
            extra = (side or {}).get(key, {})
            files.put(f"{base}/formula.cnf", formula.data)
            value = manifest(formula, (pools or {}).get(key, {}), extra)
            files.put(f"{base}/manifest.json", document(value))
            for file_name, data in extra.items():
                files.put(f"{base}/{file_name}", data)
        root_nodes: list[dict[str, Any]] = sorted(
            (node(f, c) for f, c in roots),
            key=lambda n: (n["formula_sha256"], node_id(n["formula_sha256"], n["cube"])),
        )
        split_entries: list[dict[str, Any]] = [
            {
                "node": node(f, c),
                "variables": list(w),
                "splitter": {"name": "static", "info": {"source": "spec-vectors"}},
            }
            for f, c, w in splits
        ]
        split_entries.sort(key=entry_split_id)
        self.value: dict[str, Any] = {
            "format": "cubeproof-campaign-1",
            "created_utc": "2026-10-01T00:00:00.000Z",
            "author": "polyhedraproof specification vectors",
            "formulas": [
                {"key": key, "formula_sha256": f.sha256, "bundle": f"bundles/{key}"}
                for key, f in sorted(formulas, key=lambda item: item[0])
            ],
            "roots": root_nodes,
            "root_splits": split_entries,
            "policy": P_TRANSIENT,
            "tools": {
                "solver": {"name": "cadical", "sha256": SOLVER, "argv": ARGV},
                "checker": {"name": "cake_lpr", "sha256": CHECKER},
            },
            "admit": {"checker_sha256": [CHECKER], "solvers": solvers},
        }
        self.id = jsha(self.value)
        self.path = files.put(f"{self.dir}/campaign.json", document(self.value))

    def variant(
        self, name: str, change: Callable[[dict[str, Any]], None], raw: bool = False
    ) -> str:
        """Another campaign file in the same directory (same bundles)."""
        value = copy.deepcopy(self.value)
        change(value)
        data = (json.dumps(value, indent=2) + "\n").encode() if raw else document(value)
        return self.files.put(f"{self.dir}/{name}.json", data)


def copies(data: bytes) -> Copy:
    lines = data.split(b"\n")
    records = [json.loads(line) for line in lines[:-1]]
    return Copy(records, sum(len(line) + 1 for line in lines[:-1]), len(lines[-1]))


class Cases:
    def __init__(self, files: Files) -> None:
        self.files = files
        self.cases: list[dict[str, Any]] = []
        self.plans: list[dict[str, Any]] = []

    def journal(self, case: str, name: str, data: bytes) -> str:
        return self.files.put(f"journals/{case}/{name}.jsonl", data)

    def valid(
        self,
        case: str,
        description: str,
        camp: CampaignDir,
        journals: Sequence[tuple[str, bytes]],
        lying: bool = False,
    ) -> dict[str, Any]:
        paths = [self.journal(case, name, data) for name, data in journals]
        certificate = certify(camp.value, camp.formulas, [copies(d) for _, d in journals])
        cert_path = self.files.put(f"certificates/{case}.json", document(certificate))
        entry: dict[str, Any] = {
            "id": case,
            "description": description,
            "campaign": camp.path,
            "journals": paths,
            "expect": {"exit": EXIT[certificate["verdict"]], "certificate": cert_path},
        }
        if lying:
            entry["lying"] = True
        self.cases.append(entry)
        return certificate

    def invalid(
        self,
        case: str,
        description: str,
        campaign: str,
        journals: Sequence[tuple[str, bytes]],
        kind: str,
        rule: str,
    ) -> None:
        paths = [self.journal(case, name, data) for name, data in journals]
        self.cases.append(
            {
                "id": case,
                "description": description,
                "campaign": campaign,
                "journals": paths,
                "expect": {"exit": 4, "error": {"kind": kind, "rule": rule}},
            }
        )

    def plan(self, case: str, campaign: str, journal: str, expect: Any) -> None:
        self.plans.append({"id": case, "campaign": campaign, "journal": journal, "expect": expect})


# -- journal byte helpers -----------------------------------------------------------------------


def lines_of(journal: Journal) -> list[bytes]:
    return [jbytes(r) for r in journal.records]


def join(lines: Sequence[bytes]) -> bytes:
    return b"".join(line + b"\n" for line in lines)


def rechain(records: list[dict[str, Any]], start: int) -> list[dict[str, Any]]:
    """Re-sign record ``start`` and chain the following records to it."""
    out_records = [dict(r) for r in records]
    out_records[start] = sign(out_records[start])
    for i in range(start + 1, len(out_records)):
        out_records[i] = sign(out_records[i] | {"prev": out_records[i - 1]["self"]})
    return out_records


def changed(journal: Journal, index: int, **changes: Any) -> bytes:
    records = [dict(r) for r in journal.records]
    records[index] = records[index] | changes
    for name in [k for k, v in changes.items() if v is DROP]:
        del records[index][name]
    return join([jbytes(r) for r in rechain(records, index)])


DROP = object()


def extended(journal: Journal, build: Callable[[Journal], object]) -> bytes:
    other = copy.deepcopy(journal)
    build(other)
    return other.data()


# -- the campaigns ------------------------------------------------------------------------------


def campaigns(files: Files) -> dict[str, CampaignDir]:
    admitted = [{"sha256": SOLVER, "argv": ARGV}]
    return {
        "pilot": CampaignDir(files, "pilot", [("sat", F_SAT)], [(F_SAT, [-1])]),
        "unsat": CampaignDir(
            files, "unsat", [("unsat", F_UNSAT)], [(F_UNSAT, [])], [(F_UNSAT, [], [1])]
        ),
        "zero": CampaignDir(
            files,
            "zero",
            [("clause", F_CLAUSE), ("empty", F_EMPTY)],
            [(F_CLAUSE, []), (F_EMPTY, [])],
        ),
        "all3": CampaignDir(
            files,
            "all3",
            [("all3", ALL3)],
            [(ALL3, [])],
            [(ALL3, [], [1])],
            solvers=admitted,
            pools={"all3": {"all": [1, 2, 3], "none": []}},
        ),
        "mixed": CampaignDir(
            files,
            "mixed",
            [("all3", ALL3), ("sat3", SAT3)],
            [(ALL3, []), (SAT3, [])],
            solvers=admitted,
            side={"sat3": {"names.tsv": NAMES_TSV, "tags.tsv": TAGS_TSV}},
        ),
    }


# -- valid cases --------------------------------------------------------------------------------


def valid_cases(cases: Cases, c: dict[str, CampaignDir]) -> dict[str, Journal]:
    keep: dict[str, Journal] = {}

    w1 = Journal("w1", c["pilot"].id)
    w1.attempt(F_SAT, [-1], "vu_unit")
    cases.valid(
        "pilot_root",
        "SPECIFICATION §4.10: a proof of F_sat and [-1] closes only that root",
        c["pilot"],
        [("w1", w1.data())],
    )
    keep["pilot_root"] = w1

    w1 = Journal("w1", c["unsat"].id)
    w1.attempt(F_UNSAT, [1], "vu_unit")
    w1.attempt(F_UNSAT, [-1], "vu_unit")
    cases.valid(
        "split_full",
        "SPECIFICATION §4.10: F_unsat with split [1] needs both children",
        c["unsat"],
        [("w1", w1.data())],
    )

    w1 = Journal("w1", c["unsat"].id)
    w1.attempt(F_UNSAT, [1], "vu_unit")
    cases.valid(
        "split_incomplete",
        "One child of the root split is still open",
        c["unsat"],
        [("w1", w1.data())],
    )

    w1 = Journal("w1", c["zero"].id)
    w1.attempt(F_CLAUSE, [], "vu_unit")
    w1.attempt(F_EMPTY, [], "model_unit", true=[])
    cases.valid(
        "zero_vars",
        "V=0: the empty clause is refuted, the empty formula has the empty model",
        c["zero"],
        [("w1", w1.data())],
    )

    base = Journal("w1", c["all3"].id)
    base.split(ALL3, [-1], [2])
    base.attempt(ALL3, [1], "vu_cdcl", diagnostics={"note": "MARK"})
    base.attempt(ALL3, [-1, 2], "vu_unit")
    base.attempt(ALL3, [-1, -2], "vu_unit")
    cases.valid(
        "base",
        "Campaign split [1], journal split [2] under [-1]; three leaves",
        c["all3"],
        [("w1", base.data())],
    )
    keep["base"] = base

    w1 = Journal("w1", c["all3"].id)
    w1.split(ALL3, [], [1])
    w1.split(ALL3, [], [2])
    w1.attempt(ALL3, [1], "vu_cdcl")
    w1.split(ALL3, [1], [2])
    w1.attempt(ALL3, [1, 2], "vu_unit")
    w1.attempt(ALL3, [1, -2], "vu_unit")
    w1.attempt(ALL3, [-1], "vu_cdcl")
    w1.attempt(ALL3, [2], "vu_cdcl")
    w1.attempt(ALL3, [-2], "vu_cdcl")
    w1.split(ALL3, [2], [3])
    w1.attempt(ALL3, [2, 3], "vu_unit")
    w1.attempt(ALL3, [2, -3], "vu_unit")
    w1.attempt(ALL3, [-1], "vu_cdcl")
    w2 = Journal("w2", c["all3"].id)
    w2.attempt(ALL3, [-1], "vu_cdcl")
    w2.attempt(ALL3, [-2], "vu_cdcl")
    cases.valid(
        "alternatives",
        "Two closed root splits (one also in the campaign); attempts beat splits; smallest Ref",
        c["all3"],
        [("w1", w1.data()), ("w2", w2.data())],
    )

    camp = c["all3"]
    w1 = Journal("w1", camp.id)
    shard = {
        "format": "cubeproof-shard-1",
        "campaign": camp.id,
        "name": "all",
        "nodes": [node(ALL3, [])],
    }
    w1.add("shard", shard=shard, shard_sha256=jsha(shard))
    w1.split(ALL3, [1], [2])
    w1.split(ALL3, [1], [3])
    w1.attempt(ALL3, [1, 3], "vu_unit")
    w1.stop(ALL3, [-1], "stuck", "max_depth")
    w1.reopen(ALL3, [-1], "reopen_blocked")
    w1.stop(ALL3, [1, 2], "resource_blocked", "memory")
    request = {
        "format": "cubeproof-handoff-request-1",
        "campaign": camp.id,
        "request_id": ident("frontier-request"),
        "node_count": 1,
        "output_name": "out1",
    }
    w1.add("handoff", request=request, shard=None, shard_sha256=None)
    w1.add("repair", removed_bytes=7, removed_sha256=sha(b"torn ta"))
    w2 = Journal("w2", camp.id)
    w2.stop(ALL3, [-1], "tool_blocked", "tool_retries")
    w2.stop(ALL3, [1, 2], "stuck", "no_eligible_pool")
    w2.stop(ALL3, [1, -3], "stuck", "max_depth")
    w2.reopen(ALL3, [1, -3], "reopen_blocked")
    w2.stop(ALL3, [1, -2], "resource_blocked", "disk")
    cases.valid(
        "frontier",
        "Open frontier under the smallest split_id; labels from each worker's latest stop/reopen",
        camp,
        [("w1", w1.data()), ("w2", w2.data())],
    )
    keep["frontier"] = w1

    w1 = Journal("w1", camp.id)
    w1.split(ALL3, [1], [2])
    w1.stop(ALL3, [-1], "stuck", "max_depth")
    w1.reopen(ALL3, [-1], "reopen_blocked")
    w1.stop(ALL3, [1, 2], "stuck", "max_depth")
    w1.reopen(ALL3, [1, 2], "reopen_blocked")
    w1.stop(ALL3, [1, 2], "resource_blocked", "memory")
    w1.stop(ALL3, [1, -2], "stuck", "max_depth")
    w1.stop(ALL3, [1, -2], "tool_blocked", "tool_retries")
    w2 = Journal("w2", camp.id)
    w2.stop(ALL3, [1, -2], "resource_blocked", "disk")
    w2.reopen(ALL3, [1, -2], "reopen_blocked")
    cases.valid(
        "labels",
        "Only each worker's latest node_stop/node_reopen of an emitted node counts: a stop "
        "followed by its reopen is pending, a later stop replaces an earlier one",
        camp,
        [("w1", w1.data()), ("w2", w2.data())],
    )

    w1 = Journal("w1", camp.id)
    w1.attempt(ALL3, [], "rejected")
    w1.attempt(ALL3, [1], "invalid_syntax")
    w1.attempt(ALL3, [-1], "invalid_violated", true=[1, 2, 3])
    w1.split(ALL3, [-1], [2, 2])
    w1.attempt(ALL3, [1], "vu_cdcl")
    w1.attempt(ALL3, [-1], "vu_cdcl")
    w1.attempt(ALL3, [1, 2], "exhausted_proof_size")
    w1.attempt(ALL3, [-1, 2], "failed_crash")
    cases.valid(
        "anomalies",
        "Anomalies stay visible and do not invalidate a complete proof tree",
        camp,
        [("w1", w1.data())],
    )

    w1 = Journal("w1", camp.id)
    w1.resume(P_RETAIN)
    w1.attempt(ALL3, [1], "vu_cdcl", mode="retain")
    w1.resume(P_STREAM)
    w1.attempt(ALL3, [-1], "vu_cdcl", mode="stream")
    w1.attempt(ALL3, [1, 2], "vu_unit", mode="stream")
    source = w1.records[4]
    target = {
        "node": source["node"],
        "node_id": source["node_id"],
        "source": {"journal": w1.id, "seq": 4},
        "cnf_sha256": source["cnf_sha256"],
        "proof_sha256": source["proof_sha256"],
        "route": "cdcl",
        "machinery": M_OK,
    }
    a1 = Journal("audit1", camp.id, purpose="audit", clock=100)
    audit_plan(a1, [target], "strict")
    a1.attempt(
        ALL3,
        [-1],
        "vu_cdcl",
        proof=source["proof_sha256"],
        limits=source["limits"] | {"solver_time_ms": None},
    )
    a1.add(
        "audit_result",
        target=target,
        attempt={"journal": a1.id, "seq": 4},
        status="HASH_MATCHED",
        reason="",
    )
    cases.valid(
        "modes",
        "Retain, stream and audit-purpose evidence; machinery snapshots",
        camp,
        [("w1", w1.data()), ("audit1", a1.data())],
    )
    keep["modes_a1"] = a1
    keep["modes_w1"] = w1

    w1 = Journal("w1", camp.id)
    w1.attempt(ALL3, [1], "vu_cdcl")
    w1.attempt(ALL3, [-1], "vu_cdcl")
    w2 = Journal("w2", camp.id)
    w2.attempt(ALL3, [1], "vu_cdcl")
    full = w1.data()
    lines = lines_of(w1)
    prefix = join(lines[:2]) + lines[2][:25]
    torn = full + b'{"format":"cubeproof-jou'
    cases.valid(
        "duplicates",
        "Prefix copies with torn tails count once; input order is irrelevant",
        camp,
        [("w1-prefix", prefix), ("w1-torn", torn), ("w1", full), ("w2", w2.data())],
    )

    w1 = Journal("w1", camp.id)
    w1.attempt(ALL3, [1], "vu_cdcl")
    w1.attempt(ALL3, [-1], "vu_cdcl")
    w1.attempt(ALL3, [], "model_cdcl", true=[])
    lines = lines_of(w1)
    cases.valid(
        "torn_tail",
        "A complete record without LF is a torn tail: ignored and reported",
        camp,
        [("w1", join(lines[:3]) + lines[3])],
    )
    keep["torn_tail"] = w1

    w1 = Journal("w1", camp.id)
    for preset in (
        "exhausted_proof_size",
        "exhausted_time",
        "exhausted_check_time",
        "exhausted_check_memory",
        "exhausted_check_stack",
        "exhausted_solver_memory",
        "failed_launch",
        "failed_binary_changed",
        "failed_io",
        "failed_file_changed",
        "failed_crash",
        "failed_protocol",
        "rejected",
        "invalid_missing",
        "invalid_conflicting",
        "invalid_out_of_range",
        "invalid_syntax",
    ):
        w1.attempt(ALL3, [1], preset)
    w1.attempt(ALL3, [1], "invalid_violated", true=[1])
    w1.attempt(ALL3, [1, 2], "vu_unit")
    w1.attempt(ALL3, [1], "vu_cdcl", checks=[check(CHECK_HEAP), check(CHECK_OK, 1024, 256)])
    w1.resume(P_RETAIN)
    w1.attempt(ALL3, [-1], "vu_cdcl", mode="retain")
    w1.attempt(ALL3, [-1], "rejected", mode="retain")
    w1.resume(P_STREAM)
    w1.attempt(ALL3, [-1, 2], "vu_cdcl", mode="stream")
    w1.attempt(ALL3, [-1, -2], "failed_relay", mode="stream")
    w1.attempt(ALL3, [-1, -2], "exhausted_check_memory", mode="stream")
    w1.attempt(ALL3, [-1, -2], "vu_unit", mode="stream")
    w1.attempt(ALL3, [-1], "rejected", mode="stream")
    w1.attempt(ALL3, [-1], "exhausted_time", mode="stream")
    cases.valid(
        "catalogue", "Every outcome and reason in file and stream modes", camp, [("w1", w1.data())]
    )
    keep["catalogue"] = w1

    mixed = c["mixed"]
    bad = Journal("wbad", mixed.id, mach=M_BAD_CHECKER)
    bad.attempt(ALL3, [], "vu_cdcl")
    bad.attempt(ALL3, [], "vu_cdcl", checks=[check(out("s VERIFIED UNSAT"))])
    bad.attempt(SAT3, [], "model_cdcl", true=[1, 3])
    bad.attempt(ALL3, [1], "rejected")
    seed = Journal("wsol", mixed.id, mach=M_SEED)
    seed.attempt(ALL3, [], "vu_cdcl")
    seed.attempt(ALL3, [1, 2], "vu_unit")
    seed.attempt(SAT3, [], "invalid_violated", true=[])
    cases.valid(
        "nonadmitted",
        "Non-admitted attempts are listed, also with bad success fields; their models and "
        "anomalies (check_rejected, invalid_model) bind",
        mixed,
        [("wbad", bad.data()), ("wsol", seed.data())],
    )

    w1 = Journal("w1", mixed.id)
    w1.split(SAT3, [], [1])
    w1.attempt(SAT3, [], "model_cdcl", true=[1, 3])
    w1.attempt(ALL3, [], "vu_cdcl")
    cases.valid(
        "model_split",
        "A node with a valid model is emitted as model although it has a split "
        "(SPECIFICATION §10.3)",
        mixed,
        [("w1", w1.data())],
    )

    w1 = Journal("w1", mixed.id)
    w1.split(SAT3, [], [1])
    w1.attempt(SAT3, [1], "model_cdcl", true=[1, 3])
    w1.attempt(SAT3, [-1], "model_unit", true=[2])
    w1.attempt(ALL3, [], "vu_cdcl")
    cases.valid(
        "models", "Valid models from cdcl and unit routes; MODEL_FOUND", mixed, [("w1", w1.data())]
    )

    w1 = Journal("w1", mixed.id)
    w1.attempt(SAT3, [], "invalid_violated", true=[1, 3])
    w1.attempt(SAT3, [], "invalid_violated", true=[])
    w1.attempt(SAT3, [-1], "invalid_violated", true=[1, 3])
    cases.valid(
        "mislabelled",
        "An INVALID_MODEL that satisfies is a model plus an anomaly; one that satisfies every "
        "clause but not its cube unit stays an invalid model (SPECIFICATION §10.4: clauses and "
        "cube units)",
        mixed,
        [("w1", w1.data())],
    )

    w1 = Journal("w1", mixed.id)
    w1.attempt(SAT3, [], "vu_cdcl")
    w1.attempt(SAT3, [], "model_cdcl", true=[1, 3])
    w1.attempt(ALL3, [], "vu_cdcl")
    cases.valid(
        "inconsistent",
        "A lying admitted attestation and a valid model: INCONSISTENT",
        mixed,
        [("w1", w1.data())],
        lying=True,
    )
    return keep


def audit_plan(journal: Journal, targets: list[dict[str, Any]], comparison: str) -> None:
    digest = sha(b"".join(jbytes(t) + b"\n" for t in targets))
    journal.add(
        "audit_begin",
        certificate_sha256=sha("certificate of the modes case"),
        sample_count=len(targets),
        seed=sha("audit seed"),
        targets_sha256=digest,
        target_count=len(targets),
        comparison=comparison,
    )
    for ordinal, target in enumerate(targets):
        journal.add("audit_target", target=target, ordinal=ordinal)
    journal.add("audit_ready", targets_sha256=digest, target_count=len(targets))


# -- invalid journals ---------------------------------------------------------------------------


def invalid_journal_cases(
    cases: Cases, c: dict[str, CampaignDir], keep: dict[str, Journal]
) -> None:
    camp = c["all3"]
    base = keep["base"]
    lines = lines_of(base)
    rec2 = base.records[2]

    def case(
        name: str, data: bytes, rule: str, kind: str = "integrity", description: str = ""
    ) -> None:
        cases.invalid(name, description or rule, camp.path, [("w1", data)], kind, rule)

    def with_line(index: int, line: bytes) -> bytes:
        return join([*lines[:index], line, *lines[index + 1 :]])

    case(
        "x_json_canonical",
        with_line(
            2,
            json.dumps(rec2, sort_keys=True, separators=(", ", ": "), ensure_ascii=False).encode(),
        ),
        "json.canonical",
        description="A middle line with extra spaces: valid JSON, not J(record)",
    )
    case("x_json_utf8", with_line(2, lines[2].replace(b'"MARK"', b'"\xff"')), "json.utf8")
    case(
        "x_json_syntax_last",
        base.data() + b'{"format":"cubeproof-journal-1",\n',
        "json.syntax",
        description="A complete invalid last line is an integrity error, not a torn tail",
    )
    case(
        "x_json_duplicate_key",
        with_line(2, b'{"diagnostics":{},' + lines[2][1:]),
        "json.duplicate_key",
    )

    def elapsed(value: object) -> list[dict[str, Any]]:
        """checks of record 2 with the first check's elapsed_ms replaced."""
        checks: list[dict[str, Any]] = copy.deepcopy(rec2["checks"])
        checks[0]["result"]["elapsed_ms"] = value
        return checks

    # self and prev are computed over the changed value (as a lenient parser reads it), so
    # the json rule is the only one these lines violate (review round 1, S1).
    case(
        "x_json_number",
        changed(base, 2, checks=elapsed(12.0)),
        "json.number",
        description="elapsed_ms 12.0; self/prev chain intact for a lenient parser",
    )
    case(
        "x_json_integer_range",
        changed(base, 2, checks=elapsed(2**63)),
        "json.integer_range",
        description="elapsed_ms 2^63; self/prev chain intact for a lenient parser",
    )
    case(
        "x_json_surrogate",
        with_line(2, lines[2].replace(b'"MARK"', b'"\\ud800"')),
        "json.surrogate",
    )
    case("x_json_bom", b"\xef\xbb\xbf" + base.data(), "json.bom")
    nest: Any = []
    for _ in range(30):
        nest = [nest]
    case(
        "x_limit_depth",
        changed(base, 2, diagnostics={"note": nest}),
        "limit.depth",
        "resource",
        "Depth 33: record 1, diagnostics 2, lists 3-33",
    )
    case("x_schema_unknown_field", changed(base, 2, extra=1), "schema")
    case("x_schema_missing_field", changed(base, 2, diagnostics=DROP), "schema")
    case(
        "x_schema_bool",
        changed(base, 2, proof_bytes=True),
        "schema",
        description="A boolean is never an integer",
    )
    case("x_schema_record_type", changed(base, 1, type="note"), "schema")
    case(
        "x_journal_self", with_line(2, jbytes(rec2 | {"self": sha("not the self")})), "journal.self"
    )
    case("x_journal_seq", changed(base, 2, seq=3), "journal.seq")
    case("x_journal_prev", changed(base, 2, prev=ZERO), "journal.prev")
    first = sign(
        {k: v for k, v in base.records[1].items() if k != "self"} | {"seq": 0, "prev": ZERO}
    )
    case(
        "x_journal_header_first",
        jbytes(first) + b"\n",
        "journal.header",
        description="seq 0 is not a header",
    )
    case(
        "x_journal_header_twice",
        extended(
            base,
            lambda j: j.add(
                "header",
                **{
                    k: base.records[0][k]
                    for k in (
                        "worker",
                        "campaign",
                        "purpose",
                        "machinery",
                        "policy",
                        "resources",
                    )
                },
            ),
        ),
        "journal.header",
    )
    case(
        "x_journal_purpose",
        extended(base, lambda j: j.add("audit_ready", targets_sha256=sha(b""), target_count=0)),
        "journal.purpose",
    )
    foreign = Journal("w1", c["pilot"].id)
    case(
        "x_journal_campaign",
        foreign.data(),
        "journal.campaign",
        "input",
        "Header of another campaign (reading 6)",
    )
    cases.invalid(
        "x_journal_no_header_empty",
        "An included empty file (reading 6)",
        camp.path,
        [("w1", base.data()), ("w9", b"")],
        "input",
        "journal.no_header",
    )
    cases.invalid(
        "x_journal_no_header_torn",
        "Only a torn header (reading 6)",
        camp.path,
        [("w1", lines[0][:40])],
        "input",
        "journal.no_header",
    )
    # a second start under the same Name: the header differs only in its time, so its ID differs
    other = Journal("w1", camp.id, clock=3600)
    cases.invalid(
        "x_journal_worker",
        "One worker Name, two header IDs",
        camp.path,
        [("w1", base.data()), ("w1-other", other.data())],
        "integrity",
        "journal.worker",
    )
    fork = Journal("w1", camp.id)
    fork.split(ALL3, [-1], [3])
    cases.invalid(
        "x_journal_fork",
        "Two copies of one journal diverge",
        camp.path,
        [("w1", base.data()), ("w1-fork", fork.data())],
        "integrity",
        "journal.fork",
    )

    def more(
        name: str, build: Callable[[Journal], object], rule: str, description: str = ""
    ) -> None:
        case(name, extended(base, build), rule, description=description)

    more(
        "x_record_formula",
        lambda j: j.split(F_SAT, [], [1]),
        "record.formula",
        "A node of a formula outside the campaign",
    )
    more(
        "x_cube_canonical",
        lambda j: j.add(
            "split",
            node={"formula_sha256": ALL3.sha256, "cube": [2, -1]},
            variables=[3],
            splitter={"name": "x", "info": {}},
        ),
        "cube.canonical",
        "A split's parent cube must be valid even though W errors are only anomalies",
    )
    more("x_cube_range", lambda j: j.attempt(ALL3, [4], "vu_cdcl"), "cube.range")
    more(
        "x_record_node_id",
        lambda j: j.attempt(ALL3, [1], "vu_cdcl", node_id=node_id(ALL3.sha256, [-1])),
        "record.node_id",
    )
    more(
        "x_attempt_cnf_sha256",
        lambda j: j.attempt(ALL3, [1], "vu_cdcl", cnf_sha256=ALL3.cube_sha256([-1])),
        "attempt.cnf_sha256",
    )

    def stale(j: Journal) -> None:
        old = j.policy_sha256
        j.resume(P_RETAIN)
        j.attempt(ALL3, [1], "vu_cdcl", policy_sha256=old)

    more(
        "x_attempt_policy_sha256",
        stale,
        "attempt.policy_sha256",
        "The policy hash of the header, after a resume changed the policy",
    )
    more(
        "x_attempt_attempt_id",
        lambda j: j.attempt(ALL3, [1], "vu_cdcl", attempt_id=rec2["attempt_id"]),
        "attempt.attempt_id",
    )
    torn = keep["torn_tail"]
    case(
        "x_attempt_model_false",
        torn.data(),
        "attempt.model_false",
        description="The torn_tail case with its last line complete: a false MODEL",
    )
    cube_model = Journal("w1", c["mixed"].id)
    cube_model.attempt(SAT3, [-1], "model_cdcl", true=[1, 3])
    cases.invalid(
        "x_attempt_model_cube",
        "A MODEL that satisfies every clause but not its cube unit is false (SPECIFICATION §10.4)",
        c["mixed"].path,
        [("w1", cube_model.data())],
        "integrity",
        "attempt.model_false",
    )
    more(
        "x_attempt_reason",
        lambda j: j.attempt(ALL3, [1], "exhausted_time", reason="crash"),
        "attempt.reason",
    )
    more(
        "x_attempt_assignment",
        lambda j: j.attempt(ALL3, [1], "invalid_violated", assignment="AAA="),
        "attempt.assignment",
        "Two bytes for V=3",
    )
    more(
        "x_success_checker_output",
        lambda j: j.attempt(
            ALL3, [1], "vu_cdcl", checks=[check(out("s VERIFIED UNSAT\n", exit=1))]
        ),
        "success.checker_output",
    )
    more("x_success_checks", lambda j: j.attempt(ALL3, [1], "vu_cdcl", checks=[]), "success.checks")
    more(
        "x_success_solver",
        lambda j: j.attempt(ALL3, [1], "vu_cdcl", solver=SOLVER_SAT),
        "success.solver",
    )
    more(
        "x_success_proof",
        lambda j: j.attempt(ALL3, [1, 2], "vu_unit", proof_bytes=None, proof_sha256=None),
        "success.proof",
    )
    more(
        "x_process_exit_signal",
        lambda j: j.attempt(ALL3, [1], "failed_crash", solver=SOLVER_CRASH | {"exit": 1}),
        "process.exit_signal",
    )
    shard = {
        "format": "cubeproof-shard-1",
        "campaign": camp.id,
        "name": "s",
        "nodes": [node(ALL3, [1])],
    }
    more(
        "x_shard_hash",
        lambda j: j.add("shard", shard=shard, shard_sha256=sha("other")),
        "shard.hash",
    )
    other_shard = shard | {"campaign": c["pilot"].id}
    more(
        "x_shard_campaign",
        lambda j: j.add("shard", shard=other_shard, shard_sha256=jsha(other_shard)),
        "shard.campaign",
    )
    two: dict[str, Any] = shard | {"nodes": [node(ALL3, [-1]), node(ALL3, [1])]}
    two["nodes"].sort(key=lambda n: node_id(n["formula_sha256"], n["cube"]))
    request = {
        "format": "cubeproof-handoff-request-1",
        "campaign": camp.id,
        "request_id": ident("r1"),
        "node_count": 1,
        "output_name": "o1",
    }
    more(
        "x_handoff_count",
        lambda j: j.add("handoff", request=request, shard=two, shard_sha256=jsha(two)),
        "handoff.count",
    )

    def two_handoffs(j: Journal) -> None:
        j.add("handoff", request=request, shard=None, shard_sha256=None)
        j.add("handoff", request=request, shard=None, shard_sha256=None)

    more(
        "x_handoff_request_unique",
        two_handoffs,
        "handoff.request_unique",
        "The same request_id committed twice in one journal (SPECIFICATION §7.1, §7.4)",
    )

    def reused_request_id(j: Journal) -> None:
        j.add("handoff", request=request, shard=None, shard_sha256=None)
        j.add("handoff", request=request | {"output_name": "o2"}, shard=None, shard_sha256=None)

    more(
        "x_handoff_request_unique_content",
        reused_request_id,
        "handoff.request_unique",
        "The same request_id committed twice with a different request (SPECIFICATION §7.1, §7.4)",
    )
    more(
        "x_utc_calendar",
        lambda j: j.add(
            "split",
            node=node(ALL3, [-1]),
            variables=[3],
            splitter={"name": "x", "info": {}},
            utc="2026-02-30T00:00:00.000Z",
        ),
        "utc.calendar",
    )
    header = base.records[0]
    bad_machinery = header["machinery"] | {"packages_sha256": sha("wrong")}
    case(
        "x_machinery_packages",
        join([jbytes(sign(header | {"machinery": bad_machinery}))]),
        "machinery.packages_sha256",
    )


# -- invalid campaigns and bundles --------------------------------------------------------------


def invalid_campaign_cases(cases: Cases, c: dict[str, CampaignDir]) -> None:
    all3, mixed = c["all3"], c["mixed"]

    def case(
        name: str,
        camp: CampaignDir,
        change: Callable[[dict[str, Any]], None],
        rule: str,
        raw: bool = False,
        kind: str = "input",
    ) -> None:
        path = camp.variant(f"invalid-{name}", change, raw)
        cases.invalid(f"c_{name}", f"Campaign: {rule}", path, [], kind, rule)

    def roots(*cubes: list[int]) -> Callable[[dict[str, Any]], None]:
        def change(v: dict[str, Any]) -> None:
            v["roots"] = sorted(
                (node(ALL3, cube) for cube in cubes),
                key=lambda n: node_id(n["formula_sha256"], n["cube"]),
            )
            v["root_splits"] = []

        return change

    def split_at(
        cube: list[int], w: list[int], *root_cubes: list[int]
    ) -> Callable[[dict[str, Any]], None]:
        def change(v: dict[str, Any]) -> None:
            if root_cubes:
                roots(*root_cubes)(v)
            v["root_splits"] = [
                {
                    "node": node(ALL3, cube),
                    "variables": w,
                    "splitter": {"name": "static", "info": {}},
                }
            ]

        return change

    def nothing(v: dict[str, Any]) -> None:
        return None

    case("json_canonical", all3, nothing, "json.canonical", raw=True)
    case("schema", all3, lambda v: v.update(extra=True), "schema")
    case("schema_solvers_empty", all3, lambda v: v["admit"].update(solvers=[]), "schema")
    case("utc", all3, lambda v: v.update(created_utc="2026-02-30T00:00:00.000Z"), "utc.calendar")
    case(
        "node_formula", all3, lambda v: v["roots"].append(node(F_SAT, [])), "campaign.node_formula"
    )
    case("cube_canonical", all3, roots([-2, 1]), "cube.canonical")
    case("cube_range", all3, roots([4]), "cube.range")
    case("roots_incompatible", all3, roots([1], [1, 2]), "campaign.roots_incompatible")

    def unsorted_roots(v: dict[str, Any]) -> None:
        roots([1], [-1])(v)
        v["roots"].reverse()

    case("roots_order", all3, unsorted_roots, "campaign.roots_order")

    def unsorted_splits(v: dict[str, Any]) -> None:
        entries: list[dict[str, Any]] = [
            {"node": node(ALL3, []), "variables": [w], "splitter": {"name": "static", "info": {}}}
            for w in (1, 2)
        ]
        entries.sort(key=lambda s: split_id(node_id(ALL3.sha256, []), s["variables"]), reverse=True)
        v["root_splits"] = entries

    case("splits_order", all3, unsorted_splits, "campaign.splits_order")
    case("split_empty", all3, split_at([], []), "split.empty")
    case("split_too_long", all3, split_at([], list(range(1, 22))), "split.too_long")
    case("split_repeated", all3, split_at([], [1, 1]), "split.repeated")
    case("split_out_of_range", all3, split_at([], [4]), "split.out_of_range")
    case("split_in_cube", all3, split_at([1], [1], [1], [-1]), "split.in_cube")
    case("root_split_node", all3, split_at([1, 2], [3], [1], [-1]), "campaign.root_split_node")
    case(
        "policy_stack",
        all3,
        lambda v: v.update(policy=policy(checker_max_stack_mib=128)),
        "policy.stack",
    )
    case(
        "pool",
        all3,
        lambda v: v.update(policy=policy(split=v["policy"]["split"] | {"pool": "brackets"})),
        "campaign.pool",
    )

    def argv(values: list[str]) -> Callable[[dict[str, Any]], None]:
        def change(v: dict[str, Any]) -> None:
            v["tools"]["solver"]["argv"] = values
            v["admit"]["solvers"] = [{"sha256": SOLVER, "argv": values}]

        return change

    case("argv_lrat", all3, argv(["--no-binary"]), "campaign.argv")
    case("argv_dash", all3, argv(["--lrat", "proof.lrat"]), "campaign.argv")
    case(
        "admit_order",
        all3,
        lambda v: v["admit"].update(checker_sha256=sorted([CHECKER, CHECKER_BAD], reverse=True)),
        "campaign.admit_order",
    )
    case(
        "admit_duplicate",
        all3,
        lambda v: v["admit"].update(solvers=[{"sha256": SOLVER, "argv": ARGV}] * 2),
        "campaign.admit_order",
    )
    case(
        "tools_admitted",
        all3,
        lambda v: v["tools"]["checker"].update(sha256=CHECKER_BAD),
        "campaign.tools_admitted",
    )
    case(
        "tools_admitted_solver_argv",
        all3,
        lambda v: v["tools"]["solver"].update(argv=ARGV_SEED),
        "campaign.tools_admitted",
    )
    case(
        "tools_admitted_solver_sha256",
        all3,
        lambda v: v["tools"]["solver"].update(sha256=SOLVER_OTHER),
        "campaign.tools_admitted",
    )
    case("formulas_order", mixed, lambda v: v["formulas"].reverse(), "campaign.formulas_order")

    def duplicate_hash(v: dict[str, Any]) -> None:
        v["formulas"] = [
            {"key": "all3", "formula_sha256": ALL3.sha256, "bundle": "bundles/all3"},
            {"key": "all3b", "formula_sha256": ALL3.sha256, "bundle": "bundles/all3"},
        ]
        v["roots"] = [node(ALL3, [])]

    case("formula_hash_unique", mixed, duplicate_hash, "campaign.formula_hash_unique")
    case(
        "roots_per_formula",
        mixed,
        lambda v: v.update(roots=[node(ALL3, [])]),
        "campaign.roots_per_formula",
    )


def bad_bundle_cases(cases: Cases, files: Files) -> None:
    """Each case: campaigns/bad/<name>.json referencing campaigns/bad/bundles/<name>/."""
    base = "campaigns/bad"

    def case(
        name: str,
        rule: str,
        formula_data: bytes | None,
        value: dict[str, Any] | None,
        entry_sha: str | None = None,
        raw_manifest: bool = False,
    ) -> None:
        bundle = f"bundles/{name}"
        if formula_data is not None:
            files.put(f"{base}/{bundle}/formula.cnf", formula_data)
        if value is not None:
            data = (
                (json.dumps(value, indent=2) + "\n").encode() if raw_manifest else document(value)
            )
            files.put(f"{base}/{bundle}/manifest.json", data)
        sha256 = entry_sha or (value["formula_sha256"] if value else ALL3.sha256)
        campaign = {
            "format": "cubeproof-campaign-1",
            "created_utc": "2026-10-01T00:00:00.000Z",
            "author": "polyhedraproof specification vectors",
            "formulas": [{"key": "f", "formula_sha256": sha256, "bundle": bundle}],
            "roots": [{"formula_sha256": sha256, "cube": []}],
            "root_splits": [],
            "policy": P_TRANSIENT,
            "tools": {
                "solver": {"name": "cadical", "sha256": SOLVER, "argv": ARGV},
                "checker": {"name": "cake_lpr", "sha256": CHECKER},
            },
            "admit": {"checker_sha256": [CHECKER], "solvers": None},
        }
        path = files.put(f"{base}/{name}.json", document(campaign))
        cases.invalid(f"b_{name}", f"Bundle: {rule}", path, [], "input", rule)

    good = manifest(ALL3, {}, {})
    case("files", "bundle.files", None, None)
    case("formula_sha256", "bundle.formula_sha256", SAT3.data, good)
    case("campaign_hash", "bundle.campaign_hash", ALL3.data, good, entry_sha=SAT3.sha256)
    case("counts", "bundle.counts", ALL3.data, good | {"clauses": 7})
    noncanonical = ALL3.data.replace(b"\n1 2 3 0\n", b"\n1  2 3 0\n")
    case("dimacs", "dimacs.clause", noncanonical, good | {"formula_sha256": sha(noncanonical)})
    case("manifest_canonical", "json.canonical", ALL3.data, good, raw_manifest=True)
    case("manifest_schema", "schema", ALL3.data, good | {"extra": 1})
    case("pools", "bundle.pools", ALL3.data, good | {"pools": {"all": [2, 1, 3]}})
    side = good | {
        "side_files": [
            {"path": "tags.tsv", "sha256": sha(TAGS_TSV), "bytes": len(TAGS_TSV)},
            {"path": "names.tsv", "sha256": sha(NAMES_TSV), "bytes": len(NAMES_TSV)},
        ]
    }
    case("side_files", "bundle.side_files", ALL3.data, side)


# -- audit plans --------------------------------------------------------------------------------


def audit_plans(cases: Cases, c: dict[str, CampaignDir], keep: dict[str, Journal]) -> None:
    camp = c["all3"]
    cases.plan("a_valid", camp.path, "journals/modes/audit1.jsonl", "valid")
    w1 = keep["modes_w1"]
    source = w1.records[4]
    target = {
        "node": source["node"],
        "node_id": source["node_id"],
        "source": {"journal": w1.id, "seq": 4},
        "cnf_sha256": source["cnf_sha256"],
        "proof_sha256": source["proof_sha256"],
        "route": "cdcl",
        "machinery": M_OK,
    }

    def journal(name: str, build: Callable[[Journal], object], rule: str) -> None:
        j = Journal("audit2", camp.id, purpose="audit", clock=200)
        build(j)
        path = cases.journal("audit", name, j.data())
        cases.plan(f"a_{name}", camp.path, path, {"rule": rule})

    def attempt(j: Journal) -> None:
        j.attempt(ALL3, [-1], "vu_cdcl", proof=source["proof_sha256"])

    def result(j: Journal, seq: int) -> None:
        j.add(
            "audit_result",
            target=target,
            attempt={"journal": j.id, "seq": seq},
            status="HASH_MATCHED",
            reason="",
        )

    def early(j: Journal) -> None:
        j.add(
            "audit_begin",
            certificate_sha256=sha("c"),
            sample_count=1,
            seed=sha("s"),
            targets_sha256=sha(jbytes(target) + b"\n"),
            target_count=1,
            comparison="strict",
        )
        j.add("audit_target", target=target, ordinal=0)
        attempt(j)
        j.add("audit_ready", targets_sha256=sha(jbytes(target) + b"\n"), target_count=1)

    journal("plan_order", early, "audit.plan_order")

    def wrong_hash(j: Journal) -> None:
        j.add(
            "audit_begin",
            certificate_sha256=sha("c"),
            sample_count=1,
            seed=sha("s"),
            targets_sha256=sha("x"),
            target_count=1,
            comparison="strict",
        )
        j.add("audit_target", target=target, ordinal=0)
        j.add("audit_ready", targets_sha256=sha("x"), target_count=1)

    journal("targets_hash", wrong_hash, "audit.targets_hash")

    def twice(j: Journal) -> None:
        audit_plan(j, [target], "strict")
        attempt(j)
        result(j, 4)
        result(j, 4)

    journal("result_unique", twice, "audit.result_unique")

    def dangling(j: Journal) -> None:
        audit_plan(j, [target], "strict")
        attempt(j)
        result(j, 3)

    journal("result_ref", dangling, "audit.result_ref")

    def later(j: Journal) -> None:
        audit_plan(j, [target], "strict")
        result(j, 5)
        attempt(j)

    journal("result_later", later, "audit.result_ref")


def build(files: Files) -> tuple[Cases, dict[str, Journal]]:
    """All campaigns, journals and cases; also the journals other vector files describe."""
    cases = Cases(files)
    c = campaigns(files)
    keep = valid_cases(cases, c)
    invalid_journal_cases(cases, c, keep)
    invalid_campaign_cases(cases, c)
    bad_bundle_cases(cases, files)
    audit_plans(cases, c, keep)
    files.put(
        "cases.json",
        pretty(
            {
                "format": "cubeproof-contract-cases-1",
                "cases": cases.cases,
                "audit_plans": cases.plans,
            }
        ),
    )
    return cases, keep
