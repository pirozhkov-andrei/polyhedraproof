"""The certificate ``cubeproof-certificate-1`` of selected evidence (specification §4.9,
§10.2-§10.5).

Graph: the campaign root splits plus the well-formed splits, admitted VERIFIED_UNSAT attempts,
valid models and node_stop/node_reopen labels of the selected journal copies. Lists:
``not_admitted`` (one entry per non-admitted attempt of any outcome), ``models`` (every
revalidated valid model, admitted or not), ``anomalies`` (``check_rejected``,
``invalid_model``, ``mislabelled_model``, ``malformed_split``).

``proved(F) = closed(F, [])``; each requested root reports its own literal closure. A closed
summary counts the selected leaves and split nodes, the largest leaf cube and the Merkle root
of the leaves ``(node_id, cnf_sha256, proof_sha256)`` sorted by node_id; an open summary is
all zero with a null root. ``used_attempts`` are the leaves of every reported closed summary
(unique by node: selection is a function of the node), ``machinery`` the snapshots of their
records. Verdict: INCONSISTENT if a formula with a valid model has a closed empty cube, else
MODEL_FOUND if any valid model exists, else PROVED if every formula is proved, else OPEN.
Every array is sorted as requirement certificate.order states.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from typing import Any

from cubeproof.base.hashing import merkle_root
from cubeproof.cnf.campaign import LoadedCampaign
from cubeproof.contracts.enums import Outcome, Verdict
from cubeproof.contracts.identity import node_id
from cubeproof.evidence.certify.closure import EvidenceGraph, Key, Leaf
from cubeproof.evidence.certify.inputs import AttemptFacts, Copy

CERTIFICATE_FORMAT = "cubeproof-certificate-1"


def _ref(journal: str, seq: int) -> dict[str, Any]:
    return {"journal": journal, "seq": seq}


def _node(key: Key) -> dict[str, Any]:
    return {"formula_sha256": key[0], "cube": list(key[1])}


def _zero_summary() -> dict[str, Any]:
    return {"leaves": 0, "splits": 0, "max_cube_size": 0, "leaf_merkle_root": None}


class _Builder:
    def __init__(self, campaign: LoadedCampaign, copies: Sequence[Copy], max_nodes: int | None):
        self.campaign = campaign
        self.copies = copies
        self.graph = EvidenceGraph(max_nodes=max_nodes)
        self.not_admitted: list[dict[str, Any]] = []
        self.models: list[dict[str, Any]] = []
        self.anomalies: list[dict[str, Any]] = []
        self.model_formulas: set[str] = set()
        self.snapshots: dict[tuple[str, int], int] = {}
        self.used: dict[str, dict[str, Any]] = {}

    def collect(self) -> None:
        for split in self.campaign.campaign.root_splits:
            node = split.node
            self.graph.add_split((node.formula_sha256, node.cube), split.variables)
        for copy in self.copies:
            journal = copy.evidence
            ident = journal.summary.id
            for _, key, variables in journal.splits:
                self.graph.add_split(key, variables)
            for seq, problem in journal.malformed:
                info = {"problem": problem}
                self.anomalies.append(
                    {"record": _ref(ident, seq), "code": "malformed_split", "info": info}
                )
            for label in journal.labels:
                self.graph.add_label(label.key, ident, label.seq, label.state, label.reason)
            for attempt in journal.attempts:
                self._attempt(ident, attempt)

    def _attempt(self, ident: str, attempt: AttemptFacts) -> None:
        ref = _ref(ident, attempt.seq)
        if attempt.not_admitted is not None:
            self.not_admitted.append({"record": ref, "reason": attempt.not_admitted})
        elif attempt.outcome == Outcome.VERIFIED_UNSAT:
            proof = attempt.proof_sha256
            assert proof is not None  # success.proof of every admitted VERIFIED_UNSAT (reader)
            leaf = Leaf(ident, attempt.seq, attempt.cnf_sha256, proof, attempt.route)
            self.graph.add_verified(attempt.key, leaf)
            self.snapshots[(ident, attempt.seq)] = attempt.snapshot_seq
        if attempt.outcome == Outcome.CHECK_REJECTED:
            self.anomalies.append({"record": ref, "code": "check_rejected", "info": {}})
        if attempt.valid_model:
            node = _node(attempt.key)
            self.models.append({"record": ref, "node": node, "assignment": attempt.assignment})
            self.graph.add_model(attempt.key)
            self.model_formulas.add(attempt.key[0])
        if attempt.outcome == Outcome.INVALID_MODEL:
            if attempt.valid_model:
                self.anomalies.append({"record": ref, "code": "mislabelled_model", "info": {}})
            else:
                info = {"model_error": attempt.model_error}
                self.anomalies.append({"record": ref, "code": "invalid_model", "info": info})

    def summary(self, key: Key) -> dict[str, Any]:
        if not self.graph.closed(key):
            return _zero_summary()
        leaves, splits = self.graph.select(key)
        triples = []
        for leaf_key, leaf in leaves:
            ident = node_id(*leaf_key)
            triples.append((ident, leaf.cnf_sha256, leaf.proof_sha256))
            self.used[ident] = {
                "node": _node(leaf_key),
                "node_id": ident,
                "record": _ref(leaf.journal, leaf.seq),
                "cnf_sha256": leaf.cnf_sha256,
                "proof_sha256": leaf.proof_sha256,
                "route": leaf.route,
            }
        return {
            "leaves": len(leaves),
            "splits": splits,
            "max_cube_size": max(len(leaf_key[1]) for leaf_key, _ in leaves),
            "leaf_merkle_root": merkle_root(triples),
        }

    def formulas(self) -> list[dict[str, Any]]:
        entries = []
        for formula in self.campaign.campaign.formulas:
            sha = formula.formula_sha256
            empty: Key = (sha, ())
            roots = []
            for root in self.campaign.campaign.roots:
                if root.formula_sha256 != sha:
                    continue
                key = (sha, root.cube)
                closed = self.graph.closed(key)
                roots.append(
                    (
                        root.node_id,
                        {"cube": list(root.cube), "closed": closed, "summary": self.summary(key)},
                    )
                )
            entries.append(
                {
                    "formula_sha256": sha,
                    "key": formula.key,
                    "proved": self.graph.closed(empty),
                    "summary": self.summary(empty),
                    "roots": [entry for _, entry in sorted(roots, key=lambda r: r[0])],
                }
            )
        return sorted(entries, key=lambda e: e["formula_sha256"])

    def open_list(self, starts: Iterable[Key]) -> list[dict[str, Any]]:
        entries = []
        for start in starts:
            for key, state, reason in self.graph.frontier(start):
                ident = node_id(*key)
                entries.append(
                    {"node": _node(key), "node_id": ident, "state": state, "reason": reason}
                )
        return sorted(entries, key=lambda e: (e["node"]["formula_sha256"], e["node_id"]))

    def machinery(self) -> list[dict[str, Any]]:
        by_id = {copy.evidence.summary.id: copy.evidence for copy in self.copies}
        wanted = set()
        for item in self.used.values():
            record = item["record"]
            wanted.add((record["journal"], self.snapshots[(record["journal"], record["seq"])]))
        return [
            {"journal": journal, "snapshot_seq": seq, "machinery": by_id[journal].machinery[seq]}
            for journal, seq in sorted(wanted)
        ]


def verdict_of(formulas: Sequence[dict[str, Any]], model_formulas: set[str]) -> Verdict:
    proved = {f["formula_sha256"] for f in formulas if f["proved"]}
    if model_formulas & proved:
        return Verdict.INCONSISTENT
    if model_formulas:
        return Verdict.MODEL_FOUND
    if len(proved) == len(formulas):
        return Verdict.PROVED
    return Verdict.OPEN


def _ref_key(entry: dict[str, Any]) -> tuple[str, int]:
    return (entry["record"]["journal"], entry["record"]["seq"])


def build_certificate(
    campaign: LoadedCampaign, copies: Sequence[Copy], *, max_nodes: int | None = None
) -> dict[str, Any]:
    """The certificate JSON value of the selected journal copies (see module doc)."""
    builder = _Builder(campaign, copies, max_nodes)
    builder.collect()
    formulas = builder.formulas()
    roots = [(r.formula_sha256, r.cube) for r in campaign.campaign.roots]
    empties: list[Key] = [(f.formula_sha256, ()) for f in campaign.campaign.formulas]
    journals = [
        {
            "id": copy.evidence.summary.id,
            "worker": copy.evidence.summary.worker,
            "records": copy.evidence.summary.records,
            "head": copy.evidence.summary.head,
            "bytes": copy.evidence.summary.bytes,
            "torn_tail_bytes": copy.torn_tail_bytes,
        }
        for copy in copies
    ]
    return {
        "format": CERTIFICATE_FORMAT,
        "campaign": campaign.campaign.campaign_id,
        "journals": sorted(journals, key=lambda e: e["id"]),
        "formulas": formulas,
        "open": builder.open_list(roots),
        "formula_open": builder.open_list(empties),
        "used_attempts": sorted(builder.used.values(), key=lambda u: u["node_id"]),
        "machinery": builder.machinery(),
        "not_admitted": sorted(builder.not_admitted, key=_ref_key),
        "models": sorted(builder.models, key=_ref_key),
        "anomalies": sorted(builder.anomalies, key=lambda a: (_ref_key(a), a["code"])),
        "verdict": verdict_of(formulas, builder.model_formulas).value,
    }
