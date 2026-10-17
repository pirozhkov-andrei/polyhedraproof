"""Hand-written expectations of the valid evidence cases.

Specification §4.10 and §10.2-§10.5, with the recorded readings of
``schemas/cubeproof/v1/requirements.json``.

These facts are written from the case designs, not read from the corpus: verdicts, which
requested roots and formulas are closed, the open frontiers with their labels, the used
evidence and the not_admitted/models/anomalies lists. Where the text makes the answer depend
on a hash order (smallest split_id, smallest Ref), the test computes that order itself.
Records are named by (worker, seq), formulas by campaign key.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from contract_reader import (
    CORPUS,
    fixture_bytes,
    j_hash,
    load_json_file,
    merkle_root,
    node_id,
    split_id,
)

Summary = tuple[int, int, int]


class View:
    """A certificate seen through campaign keys and worker names."""

    def __init__(self, case_id: str) -> None:
        cases = load_json_file(CORPUS / "cases.json")["cases"]
        self.case = next(c for c in cases if c["id"] == case_id)
        self.certificate: dict[str, Any] = load_json_file(
            CORPUS / self.case["expect"]["certificate"]
        )
        campaign = load_json_file(CORPUS / self.case["campaign"])
        self.key = {f["formula_sha256"]: f["key"] for f in campaign["formulas"]}
        self.sha = {k: s for s, k in self.key.items()}
        self.worker: dict[str, str] = {}
        self.journal: dict[str, str] = {}
        for name in self.case["journals"]:
            header = json.loads((CORPUS / name).read_bytes().split(b"\n", 1)[0])
            self.worker[header["self"]] = header["worker"]
            self.journal[header["worker"]] = header["self"]

    def ref(self, ref: dict[str, Any]) -> tuple[str, int]:
        return (self.worker[ref["journal"]], ref["seq"])

    def node(self, node: dict[str, Any]) -> tuple[str, tuple[int, ...]]:
        return (self.key[node["formula_sha256"]], tuple(node["cube"]))

    def summary(self, s: dict[str, Any]) -> Summary | None:
        if s["leaves"] == 0:
            return None
        return (s["leaves"], s["splits"], s["max_cube_size"])

    def proved(self) -> dict[str, Summary | None]:
        return {self.key[f["formula_sha256"]]: self.summary(f["summary"]) for f in self.formulas()}

    def formulas(self) -> list[dict[str, Any]]:
        formulas: list[dict[str, Any]] = self.certificate["formulas"]
        return formulas

    def roots(self) -> dict[str, list[tuple[tuple[int, ...], Summary | None]]]:
        return {
            self.key[f["formula_sha256"]]: [
                (tuple(r["cube"]), self.summary(r["summary"])) for r in f["roots"]
            ]
            for f in self.formulas()
        }

    def open(self, field: str = "open") -> set[tuple[str, tuple[int, ...], str, str | None]]:
        return {(*self.node(o["node"]), o["state"], o["reason"]) for o in self.certificate[field]}

    def used(self) -> set[tuple[str, tuple[int, ...], str, int]]:
        used = self.certificate["used_attempts"]
        return {(*self.node(u["node"]), *self.ref(u["record"])) for u in used}

    def not_admitted(self) -> set[tuple[str, int, str]]:
        return {(*self.ref(x["record"]), x["reason"]) for x in self.certificate["not_admitted"]}

    def models(self) -> set[tuple[str, int]]:
        return {self.ref(x["record"]) for x in self.certificate["models"]}

    def anomalies(self) -> set[tuple[str, int, str, str]]:
        return {
            (*self.ref(x["record"]), x["code"], json.dumps(x["info"], sort_keys=True))
            for x in self.certificate["anomalies"]
        }

    def jref(self, worker: str, seq: int) -> tuple[str, int]:
        return (self.journal[worker], seq)

    def sid(self, key: str, cube: tuple[int, ...], variables: list[int]) -> str:
        return split_id(node_id(self.sha[key], cube), variables)


SIMPLE: dict[str, dict[str, Any]] = {
    "pilot_root": {
        "verdict": "OPEN",
        "proved": {"sat": None},
        "roots": {"sat": [((-1,), (1, 0, 1))]},
        "open": set(),
        "formula_open": {("sat", (), "pending", None)},
        "used": {("sat", (-1,), "w1", 1)},
    },
    "split_full": {
        "verdict": "PROVED",
        "proved": {"unsat": (2, 1, 1)},
        "roots": {"unsat": [((), (2, 1, 1))]},
        "open": set(),
        "formula_open": set(),
        "used": {("unsat", (1,), "w1", 1), ("unsat", (-1,), "w1", 2)},
    },
    "split_incomplete": {
        "verdict": "OPEN",
        "proved": {"unsat": None},
        "roots": {"unsat": [((), None)]},
        "open": {("unsat", (-1,), "pending", None)},
        "formula_open": {("unsat", (-1,), "pending", None)},
        "used": set(),
    },
    "zero_vars": {
        "verdict": "MODEL_FOUND",
        "proved": {"clause": (1, 0, 0), "empty": None},
        "roots": {"clause": [((), (1, 0, 0))], "empty": [((), None)]},
        "open": {("empty", (), "model", None)},
        "formula_open": {("empty", (), "model", None)},
        "used": {("clause", (), "w1", 1)},
        "models": {("w1", 2)},
    },
    "base": {
        "verdict": "PROVED",
        "proved": {"all3": (3, 2, 2)},
        "roots": {"all3": [((), (3, 2, 2))]},
        "open": set(),
        "formula_open": set(),
        "used": {("all3", (1,), "w1", 2), ("all3", (-1, 2), "w1", 3), ("all3", (-1, -2), "w1", 4)},
    },
    "anomalies": {
        "verdict": "PROVED",
        "proved": {"all3": (2, 1, 1)},
        "roots": {"all3": [((), (2, 1, 1))]},
        "open": set(),
        "formula_open": set(),
        "used": {("all3", (1,), "w1", 5), ("all3", (-1,), "w1", 6)},
        "anomalies": {
            ("w1", 1, "check_rejected", "{}"),
            ("w1", 2, "invalid_model", '{"model_error": "syntax"}'),
            ("w1", 3, "invalid_model", '{"model_error": "violated"}'),
            ("w1", 4, "malformed_split", '{"problem": "repeated"}'),
        },
    },
    "torn_tail": {
        "verdict": "PROVED",
        "proved": {"all3": (2, 1, 1)},
        "roots": {"all3": [((), (2, 1, 1))]},
        "open": set(),
        "formula_open": set(),
        "used": {("all3", (1,), "w1", 1), ("all3", (-1,), "w1", 2)},
    },
    "nonadmitted": {
        "verdict": "MODEL_FOUND",
        "proved": {"all3": None, "sat3": None},
        "roots": {"all3": [((), None)], "sat3": [((), None)]},
        "open": {("all3", (), "pending", None), ("sat3", (), "model", None)},
        "formula_open": {("all3", (), "pending", None), ("sat3", (), "model", None)},
        "used": set(),
        "not_admitted": {
            ("wbad", 1, "checker_not_admitted"),
            ("wbad", 2, "checker_not_admitted"),
            ("wbad", 3, "checker_not_admitted"),
            ("wbad", 4, "checker_not_admitted"),
            ("wsol", 1, "solver_not_admitted"),
            ("wsol", 2, "solver_not_admitted"),
            ("wsol", 3, "solver_not_admitted"),
        },
        "models": {("wbad", 3)},
        # reading 5: anomalies bind for non-admitted records too
        "anomalies": {
            ("wbad", 4, "check_rejected", "{}"),
            ("wsol", 3, "invalid_model", '{"model_error": "violated"}'),
        },
    },
    "model_split": {
        # Specification §10.3: a node with a valid model is emitted as model, even though it has
        # a split
        "verdict": "MODEL_FOUND",
        "proved": {"all3": (1, 0, 0), "sat3": None},
        "roots": {"all3": [((), (1, 0, 0))], "sat3": [((), None)]},
        "open": {("sat3", (), "model", None)},
        "formula_open": {("sat3", (), "model", None)},
        "used": {("all3", (), "w1", 3)},
        "models": {("w1", 2)},
    },
    "models": {
        "verdict": "MODEL_FOUND",
        "proved": {"all3": (1, 0, 0), "sat3": None},
        "roots": {"all3": [((), (1, 0, 0))], "sat3": [((), None)]},
        "open": {("sat3", (1,), "model", None), ("sat3", (-1,), "model", None)},
        "formula_open": {("sat3", (1,), "model", None), ("sat3", (-1,), "model", None)},
        "used": {("all3", (), "w1", 4)},
        "models": {("w1", 2), ("w1", 3)},
    },
    "mislabelled": {
        "verdict": "MODEL_FOUND",
        "proved": {"all3": None, "sat3": None},
        "roots": {"all3": [((), None)], "sat3": [((), None)]},
        "open": {("all3", (), "pending", None), ("sat3", (), "model", None)},
        "formula_open": {("all3", (), "pending", None), ("sat3", (), "model", None)},
        "used": set(),
        "models": {("w1", 1)},
        "anomalies": {
            ("w1", 1, "mislabelled_model", "{}"),
            ("w1", 2, "invalid_model", '{"model_error": "violated"}'),
            # sat3 [-1] with x1 = x3 = true: every clause holds, the cube unit -1 does not
            ("w1", 3, "invalid_model", '{"model_error": "violated"}'),
        },
    },
    "inconsistent": {
        "verdict": "INCONSISTENT",
        "proved": {"all3": (1, 0, 0), "sat3": (1, 0, 0)},
        "roots": {"all3": [((), (1, 0, 0))], "sat3": [((), (1, 0, 0))]},
        "open": set(),
        "formula_open": set(),
        "used": {("all3", (), "w1", 3), ("sat3", (), "w1", 1)},
        "models": {("w1", 2)},
    },
}


@pytest.mark.parametrize("case_id", sorted(SIMPLE))
def test_simple_case(case_id: str) -> None:
    expect = SIMPLE[case_id]
    view = View(case_id)
    assert view.certificate["verdict"] == expect["verdict"]
    assert view.proved() == expect["proved"]
    assert view.roots() == expect["roots"]
    assert view.open() == expect["open"]
    assert view.open("formula_open") == expect["formula_open"]
    assert view.used() == expect["used"]
    assert view.not_admitted() == expect.get("not_admitted", set())
    assert view.models() == expect.get("models", set())
    assert view.anomalies() == expect.get("anomalies", set())


def test_alternatives_selects_the_smallest_closed_split_and_prefers_attempts() -> None:
    view = View("alternatives")
    assert view.certificate["verdict"] == "PROVED"
    assert view.proved() == {"all3": (2, 1, 1)}
    by_one = view.sid("all3", (), [1]) < view.sid("all3", (), [2])
    if by_one:
        expected = {
            ("all3", (1,), "w1", 3),
            ("all3", (-1,), *min(("w1", 7), ("w2", 1), key=lambda r: view.jref(*r))),
        }
    else:
        expected = {
            ("all3", (2,), "w1", 8),
            ("all3", (-2,), *min(("w1", 9), ("w2", 2), key=lambda r: view.jref(*r))),
        }
    assert view.used() == expected
    assert view.open() == set() and view.open("formula_open") == set()


def test_frontier_follows_the_smallest_split_and_the_latest_labels() -> None:
    view = View("frontier")
    assert view.certificate["verdict"] == "OPEN"
    assert view.proved() == {"all3": None}
    expected: set[tuple[str, tuple[int, ...], str, str | None]] = {
        ("all3", (-1,), "tool_blocked", "tool_retries")
    }
    if view.sid("all3", (1,), [2]) < view.sid("all3", (1,), [3]):
        first = min(("w1", 7), ("w2", 2), key=lambda r: view.jref(*r))
        label = {
            ("w1", 7): ("resource_blocked", "memory"),
            ("w2", 2): ("stuck", "no_eligible_pool"),
        }
        expected |= {
            ("all3", (1, -2), "resource_blocked", "disk"),
            ("all3", (1, 2), *label[first]),
        }
    else:
        expected |= {("all3", (1, -3), "pending", None)}
    assert view.open() == expected
    assert view.open("formula_open") == expected
    assert view.used() == set()


def test_labels_follow_each_workers_latest_stop_or_reopen() -> None:
    """Specification §10.3: per worker only the latest node_stop/node_reopen of a node counts.

    Campaign split [1] at the root, journal split [2] under [1]; nothing is closed, so the
    emitted nodes are [-1], [1,2] and [1,-2]. None of the answers depends on a hash order:
    [-1]: w1 stop, then w1 reopen -> pending (no worker's latest event is a stop);
    [1,2]: w1 stop, w1 reopen, w1 stop again -> the second stop;
    [1,-2]: w1 stops twice (the latest counts); w2 stops and then reopens (does not count).
    """
    view = View("labels")
    assert view.certificate["verdict"] == "OPEN"
    assert view.proved() == {"all3": None}
    expected = {
        ("all3", (-1,), "pending", None),
        ("all3", (1, 2), "resource_blocked", "memory"),
        ("all3", (1, -2), "tool_blocked", "tool_retries"),
    }
    assert view.open() == expected
    assert view.open("formula_open") == expected
    assert view.used() == set()


# Failing cases for rules that the other cases do not distinguish: case id -> (error kind,
# rule).
DISCRIMINATING_CASES = {
    # Specification §4.4: the configured solver {sha256, argv} must be in admit.solvers (not
    # only the checker)
    "c_tools_admitted_solver_argv": ("input", "campaign.tools_admitted"),
    "c_tools_admitted_solver_sha256": ("input", "campaign.tools_admitted"),
    # Specification §7.1/§7.4: one handoff record per request_id in a journal
    "x_handoff_request_unique": ("integrity", "handoff.request_unique"),
    # the same, with a different second request under the same request_id
    "x_handoff_request_unique_content": ("integrity", "handoff.request_unique"),
}
DISCRIMINATING_PLANS = {
    # Specification §11.2: an audit_result refers to an earlier attempt record (here: a later one)
    "a_result_later": "audit.result_ref",
}
DISCRIMINATING_DOCUMENTS = {
    # routine reading 6: cubeproof entries are those whose first path component is "cubeproof";
    # "cubeproofx/..." is not one of them
    "record-header-cubeproof-prefix": "valid",
    "record-cubeproof-hash-prefix": {"rule": "machinery.cubeproof_sha256"},
    # the entry named exactly "cubeproof" has first path component "cubeproof"
    "record-header-cubeproof-bare": "valid",
    "record-cubeproof-hash-bare": {"rule": "machinery.cubeproof_sha256"},
}


def test_discriminating_failure_cases_name_their_rules() -> None:
    cases = load_json_file(CORPUS / "cases.json")
    by_id = {c["id"]: c for c in cases["cases"]}
    for case_id, (kind, rule) in DISCRIMINATING_CASES.items():
        assert case_id in by_id, case_id
        assert by_id[case_id]["expect"] == {"exit": 4, "error": {"kind": kind, "rule": rule}}
    plans = {p["id"]: p for p in cases["audit_plans"]}
    for plan_id, rule in DISCRIMINATING_PLANS.items():
        assert plan_id in plans, plan_id
        assert plans[plan_id]["expect"] == {"rule": rule}
    documents = {d["id"]: d for d in load_json_file(CORPUS / "documents.json")["documents"]}
    for doc_id, expect in DISCRIMINATING_DOCUMENTS.items():
        assert doc_id in documents, doc_id
        assert documents[doc_id]["expect"] == expect


def test_the_audit_result_of_a_result_later_names_a_later_attempt() -> None:
    plan = next(
        p
        for p in load_json_file(CORPUS / "cases.json")["audit_plans"]
        if p["id"] == "a_result_later"
    )
    records = [json.loads(line) for line in (CORPUS / plan["journal"]).read_bytes().splitlines()]
    [result] = [r for r in records if r["type"] == "audit_result"]
    target = records[result["attempt"]["seq"]]
    assert target["type"] == "attempt" and target["seq"] > result["seq"]
    assert result["attempt"]["journal"] == records[0]["self"]


def test_the_cubeproof_prefix_fixtures_differ_only_in_the_prefix_rule() -> None:
    documents = {d["id"]: d for d in load_json_file(CORPUS / "documents.json")["documents"]}
    valid = json.loads(fixture_bytes(documents["record-header-cubeproof-prefix"]))
    invalid = json.loads(fixture_bytes(documents["record-cubeproof-hash-prefix"]))
    paths = [e["path"] for e in valid["machinery"]["source_manifest"]]
    assert any(p.startswith("cubeproof/") for p in paths)
    assert any(p.startswith("cubeproof") and not p.startswith("cubeproof/") for p in paths)
    manifest = valid["machinery"]["source_manifest"]
    assert invalid["machinery"]["source_manifest"] == manifest
    wrong = [e for e in manifest if e["path"].startswith("cubeproof")]
    assert invalid["machinery"]["cubeproof_sha256"] == j_hash(wrong)


def test_the_bare_cubeproof_fixtures_count_the_entry_named_cubeproof() -> None:
    """Routine reading 6: the path "cubeproof" itself has first path component "cubeproof".

    The valid header hashes it together with the "cubeproof/..." entries; its twin hashes only
    the "cubeproof/..." entries, as a reader matching the prefix "cubeproof/" would.
    """
    documents = {d["id"]: d for d in load_json_file(CORPUS / "documents.json")["documents"]}
    valid = json.loads(fixture_bytes(documents["record-header-cubeproof-bare"]))
    invalid = json.loads(fixture_bytes(documents["record-cubeproof-hash-bare"]))
    manifest = valid["machinery"]["source_manifest"]
    paths = [e["path"] for e in manifest]
    assert "cubeproof" in paths
    assert any(p.startswith("cubeproof/") for p in paths)
    own = [e for e in manifest if e["path"] == "cubeproof" or e["path"].startswith("cubeproof/")]
    assert valid["machinery"]["cubeproof_sha256"] == j_hash(own)
    assert invalid["machinery"]["source_manifest"] == manifest
    slash_only = [e for e in manifest if e["path"].startswith("cubeproof/")]
    assert invalid["machinery"]["cubeproof_sha256"] == j_hash(slash_only)
    assert j_hash(slash_only) != j_hash(own)


def test_the_request_unique_fixtures_reuse_one_request_id() -> None:
    """Specification §7.1/§7.4: at most one handoff per request_id in a journal.

    x_handoff_request_unique repeats identical request bytes; x_handoff_request_unique_content
    repeats the request_id with a different request, so a reader keyed by request bytes
    instead of request_id cannot pass both. Both handoffs have shard null (no handoff.count),
    differ in nothing but the request (and seq/prev/self/utc), and the second one ends the
    journal.
    """
    by_id = {c["id"]: c for c in load_json_file(CORPUS / "cases.json")["cases"]}

    def records(case_id: str) -> list[dict[str, Any]]:
        [path] = by_id[case_id]["journals"]
        return [json.loads(line) for line in (CORPUS / path).read_bytes().splitlines()]

    def rest(record: dict[str, Any]) -> dict[str, Any]:
        ignored = ("seq", "prev", "self", "utc", "request")
        return {k: v for k, v in record.items() if k not in ignored}

    same = [r for r in records("x_handoff_request_unique") if r["type"] == "handoff"]
    assert len(same) == 2 and same[0]["request"] == same[1]["request"]
    journal = records("x_handoff_request_unique_content")
    first, second = [r for r in journal if r["type"] == "handoff"]
    assert journal[-1] == second
    assert first["request"]["request_id"] == second["request"]["request_id"]
    assert first["request"] != second["request"]
    assert first["shard"] is None and second["shard"] is None
    assert rest(first) == rest(second)


def test_modes_uses_retain_stream_and_audit_evidence() -> None:
    view = View("modes")
    assert view.certificate["verdict"] == "PROVED"
    minus = min(("w1", 4), ("audit1", 4), key=lambda r: view.jref(*r))
    assert view.used() == {("all3", (1,), "w1", 2), ("all3", (-1,), *minus)}
    entries = view.certificate["machinery"]
    machinery = {(view.worker[m["journal"]], m["snapshot_seq"]) for m in entries}
    assert machinery == {("w1", 1), ("w1", 3) if minus[0] == "w1" else ("audit1", 0)}
    routes = {u["route"] for u in view.certificate["used_attempts"]}
    assert routes == {"cdcl"}


def test_duplicates_use_the_longest_copy_once() -> None:
    view = View("duplicates")
    assert view.certificate["verdict"] == "PROVED"
    journals = {view.worker[j["id"]]: j for j in view.certificate["journals"]}
    assert set(journals) == {"w1", "w2"}
    w1_bytes = (CORPUS / "journals" / "duplicates" / "w1.jsonl").read_bytes()
    assert (journals["w1"]["records"], journals["w1"]["bytes"]) == (3, len(w1_bytes))
    assert journals["w1"]["torn_tail_bytes"] == 0
    assert journals["w2"]["records"] == 2
    first = min(("w1", 1), ("w2", 1), key=lambda r: view.jref(*r))
    assert view.used() == {("all3", (1,), *first), ("all3", (-1,), "w1", 2)}


def test_torn_tail_is_reported_and_ignored() -> None:
    view = View("torn_tail")
    path = CORPUS / view.case["journals"][0]
    data = path.read_bytes()
    suffix = data.rsplit(b"\n", 1)[1]
    assert suffix and json.loads(suffix)["type"] == "attempt"
    [journal] = view.certificate["journals"]
    assert journal["torn_tail_bytes"] == len(suffix)
    assert journal["bytes"] == len(data) - len(suffix)
    assert journal["records"] == 3


def test_catalogue_covers_every_outcome_and_closes_the_formula() -> None:
    view = View("catalogue")
    assert view.certificate["verdict"] == "PROVED"
    assert view.proved() == {"all3": (2, 1, 1)}
    codes = sorted((seq, code) for _, seq, code, _ in view.anomalies())
    assert [c for _, c in codes].count("check_rejected") == 3
    assert [c for _, c in codes].count("invalid_model") == 5
    assert len(codes) == 8


def test_closed_summaries_match_the_used_leaves() -> None:
    """Specification §10.5: leaf count and Merkle root of each closed summary, single-root
    campaigns."""
    for case in load_json_file(CORPUS / "cases.json")["cases"]:
        if "certificate" not in case["expect"]:
            continue
        certificate = load_json_file(CORPUS / case["expect"]["certificate"])
        for formula in certificate["formulas"]:
            if len(formula["roots"]) != 1:
                continue
            leaves = [
                (u["node_id"], u["cnf_sha256"], u["proof_sha256"])
                for u in certificate["used_attempts"]
                if u["node"]["formula_sha256"] == formula["formula_sha256"]
            ]
            summaries = [formula["summary"], formula["roots"][0]["summary"]]
            for summary in summaries:
                if summary["leaves"]:
                    assert summary["leaves"] == len(leaves), case["id"]
                    assert summary["leaf_merkle_root"] == merkle_root(leaves), case["id"]


def test_every_valid_case_has_hand_expectations() -> None:
    cases = load_json_file(CORPUS / "cases.json")["cases"]
    valid = {c["id"] for c in cases if "certificate" in c["expect"]}
    special = {"alternatives", "frontier", "labels", "modes", "duplicates", "catalogue"}
    assert valid == set(SIMPLE) | special
    assert all(Path(CORPUS / c["campaign"]).is_file() for c in cases)
