"""Expected certificates of the valid corpus cases.

Specification §4.9 and §10.1-§10.5, readings 4 and 5.

The generator knows its cases are well-formed, so this computes only the certificate:
journal copies, admission, closure by decreasing cube size, selection and frontier with
explicit stacks, models, anomalies and Merkle roots. Validation of invalid inputs is the
business of the readers under test; the contract tests recheck every expected certificate
with an independent reader.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from sv_spec import Formula, bitset_values, children, jsha, merkle, node_id, split_id, w_problem

Key = tuple[str, tuple[int, ...]]
Ref = tuple[str, int]

EMPTY_SUMMARY = {"leaves": 0, "splits": 0, "max_cube_size": 0, "leaf_merkle_root": None}
EXIT = {"PROVED": 0, "OPEN": 1, "MODEL_FOUND": 2, "INCONSISTENT": 4}


@dataclass
class Copy:
    """One journal file: its complete records, complete-line bytes and torn suffix length."""

    records: list[dict[str, Any]]
    size: int
    torn: int


def certify(
    campaign: dict[str, Any], formulas: dict[str, Formula], copies: Sequence[Copy]
) -> dict[str, Any]:
    groups: dict[str, list[Copy]] = defaultdict(list)
    for item in copies:
        groups[item.records[0]["self"]].append(item)
    journals = []
    for ident in sorted(groups):
        longest = max(len(c.records) for c in groups[ident])
        best = [c for c in groups[ident] if len(c.records) == longest]
        journals.append((ident, best[0], min(c.torn for c in best)))

    admit = campaign["admit"]

    def refusal(machinery: dict[str, Any]) -> str | None:
        if machinery["checker"]["sha256"] not in admit["checker_sha256"]:
            return "checker_not_admitted"
        solver = {"sha256": machinery["solver"]["sha256"], "argv": machinery["solver"]["argv"]}
        if admit["solvers"] is not None and solver not in admit["solvers"]:
            return "solver_not_admitted"
        return None

    splits: dict[Key, dict[str, list[int]]] = defaultdict(dict)
    proofs: dict[Key, list[tuple[Ref, dict[str, Any]]]] = defaultdict(list)
    model_nodes: set[Key] = set()
    labels: dict[Key, dict[str, tuple[int, dict[str, Any]]]] = defaultdict(dict)
    snapshot_of: dict[Ref, tuple[str, int, dict[str, Any]]] = {}
    not_admitted, models, anomalies = [], [], []

    def key_of(n: dict[str, Any]) -> Key:
        return (n["formula_sha256"], tuple(n["cube"]))

    for entry in campaign["root_splits"]:
        k = key_of(entry["node"])
        splits[k][split_id(node_id(*k), entry["variables"])] = entry["variables"]

    for ident, item, _ in journals:
        snap = item.records[0]
        for record in item.records:
            ref = {"journal": ident, "seq": record["seq"]}
            kind = record["type"]
            if kind in ("header", "resume"):
                snap = record
                continue
            if kind == "split":
                k = key_of(record["node"])
                problem = w_problem(record["variables"], k[1], formulas[k[0]].variables)
                if problem:
                    anomalies.append(
                        {"record": ref, "code": "malformed_split", "info": {"problem": problem}}
                    )
                else:
                    splits[k][split_id(node_id(*k), record["variables"])] = record["variables"]
            elif kind in ("node_stop", "node_reopen"):
                labels[key_of(record["node"])][ident] = (record["seq"], record)
            elif kind == "attempt":
                k = key_of(record["node"])
                snapshot_of[(ident, record["seq"])] = (ident, snap["seq"], snap["machinery"])
                reason = refusal(snap["machinery"])
                outcome = record["outcome"]
                if reason:
                    not_admitted.append({"record": ref, "reason": reason})
                elif outcome == "VERIFIED_UNSAT":
                    proofs[k].append(((ident, record["seq"]), record))
                if outcome == "CHECK_REJECTED":
                    anomalies.append({"record": ref, "code": "check_rejected", "info": {}})
                if outcome in ("MODEL", "INVALID_MODEL"):
                    formula = formulas[k[0]]
                    text = record["assignment"]
                    values = None if text is None else bitset_values(text, formula.variables)
                    good = values is not None and formula.satisfied_by(k[1], values)
                    if good:
                        models.append({"record": ref, "node": record["node"], "assignment": text})
                        model_nodes.add(k)
                    if outcome == "INVALID_MODEL":
                        code = "mislabelled_model" if good else "invalid_model"
                        info = {} if good else {"model_error": record["model_error"]}
                        anomalies.append({"record": ref, "code": code, "info": info})

    roots = [key_of(r) for r in campaign["roots"]]
    empties = [(f["formula_sha256"], ()) for f in campaign["formulas"]]
    universe: set[Key] = set(roots) | set(empties) | set(splits) | set(proofs)
    for k, options in list(splits.items()):
        for variables in options.values():
            universe |= {(k[0], tuple(c)) for c in children(k[1], variables)}
    closed: dict[Key, bool] = {}
    for k in sorted(universe, key=lambda item: -len(item[1])):
        closed[k] = bool(proofs[k]) or any(
            all(closed.get((k[0], tuple(c)), False) for c in children(k[1], w))
            for w in splits[k].values()
        )

    used: dict[str, dict[str, Any]] = {}

    def summary(root: Key) -> dict[str, Any]:
        leaves: list[tuple[Key, Ref, dict[str, Any]]] = []
        count = 0
        stack = [root]
        while stack:
            k = stack.pop()
            if proofs[k]:
                ref, record = min(proofs[k], key=lambda item: item[0])
                leaves.append((k, ref, record))
                continue
            done = [
                s
                for s, w in splits[k].items()
                if all(closed.get((k[0], tuple(c)), False) for c in children(k[1], w))
            ]
            count += 1
            stack += [(k[0], tuple(c)) for c in children(k[1], splits[k][min(done)])]
        triples = []
        for k, ref, record in leaves:
            identity = node_id(*k)
            triples.append((identity, record["cnf_sha256"], record["proof_sha256"]))
            used[identity] = {
                "node": {"formula_sha256": k[0], "cube": list(k[1])},
                "node_id": identity,
                "record": {"journal": ref[0], "seq": ref[1]},
                "cnf_sha256": record["cnf_sha256"],
                "proof_sha256": record["proof_sha256"],
                "route": record["route"],
            }
        return {
            "leaves": len(leaves),
            "splits": count,
            "max_cube_size": max(len(k[1]) for k, _, _ in leaves),
            "leaf_merkle_root": merkle(triples),
        }

    def frontier(starts: Sequence[Key]) -> list[dict[str, Any]]:
        found = []
        stack = list(starts)
        while stack:
            k = stack.pop()
            if closed.get(k, False):
                continue
            state, reason = "pending", None
            if k in model_nodes:
                state = "model"
            elif splits[k]:
                stack += [(k[0], tuple(c)) for c in children(k[1], splits[k][min(splits[k])])]
                continue
            else:
                stops = sorted(
                    ((ident, seq), record)
                    for ident, (seq, record) in labels[k].items()
                    if record["type"] == "node_stop"
                )
                if stops:
                    state, reason = stops[0][1]["state"], stops[0][1]["reason"]
            found.append(
                {
                    "node": {"formula_sha256": k[0], "cube": list(k[1])},
                    "node_id": node_id(*k),
                    "state": state,
                    "reason": reason,
                }
            )
        return sorted(found, key=lambda e: (e["node"]["formula_sha256"], e["node_id"]))

    formula_entries = []
    for entry in sorted(campaign["formulas"], key=lambda f: f["formula_sha256"]):
        f = entry["formula_sha256"]
        root_entries = []
        for k in sorted((k for k in roots if k[0] == f), key=lambda k: node_id(*k)):
            root_entries.append(
                {
                    "cube": list(k[1]),
                    "closed": closed[k],
                    "summary": summary(k) if closed[k] else dict(EMPTY_SUMMARY),
                }
            )
        proved = closed[(f, ())]
        formula_entries.append(
            {
                "formula_sha256": f,
                "key": entry["key"],
                "proved": proved,
                "summary": summary((f, ())) if proved else dict(EMPTY_SUMMARY),
                "roots": root_entries,
            }
        )

    snapshots: dict[tuple[str, int], dict[str, Any]] = {}
    for leaf_entry in used.values():
        record_ref = leaf_entry["record"]
        ident, seq, machinery = snapshot_of[(record_ref["journal"], record_ref["seq"])]
        snapshots[(ident, seq)] = {"journal": ident, "snapshot_seq": seq, "machinery": machinery}

    model_formulas = {m["node"]["formula_sha256"] for m in models}
    proved_formulas = {e["formula_sha256"] for e in formula_entries if e["proved"]}
    if model_formulas & proved_formulas:
        verdict = "INCONSISTENT"
    elif models:
        verdict = "MODEL_FOUND"
    elif len(proved_formulas) == len(formula_entries):
        verdict = "PROVED"
    else:
        verdict = "OPEN"

    def by_ref(entry: dict[str, Any]) -> tuple[str, int]:
        return (entry["record"]["journal"], entry["record"]["seq"])

    return {
        "format": "cubeproof-certificate-1",
        "campaign": jsha(campaign),
        "journals": [
            {
                "id": ident,
                "worker": item.records[0]["worker"],
                "records": len(item.records),
                "head": item.records[-1]["self"],
                "bytes": item.size,
                "torn_tail_bytes": torn,
            }
            for ident, item, torn in journals
        ],
        "formulas": formula_entries,
        "open": frontier(roots),
        "formula_open": frontier(empties),
        "used_attempts": [used[k] for k in sorted(used)],
        "machinery": [snapshots[k] for k in sorted(snapshots)],
        "not_admitted": sorted(not_admitted, key=by_ref),
        "models": sorted(models, key=by_ref),
        "anomalies": sorted(anomalies, key=lambda e: (*by_ref(e), e["code"])),
        "verdict": verdict,
    }
