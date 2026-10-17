"""Multi-worker runs with the fake pinned tools: every proof mode, crashes and recovery.

Every step runs through the public command line in child processes (``campaign create``,
``shard``, ``run``, ``handoff``, ``certify``, ``audit``, ``verify-retained``, ``journal``;
``tools/certify_min.py`` as the independent certifier). The scenarios are those of
``cluster_harness.py`` and the specification §7.5 boundaries of ``cluster_faults.py``; the
detectors they use are unit-tested on fabricated inputs at the end of this file.

The fake tools are test doubles (brute force, ``fakes.lrat_check``): deterministic, so
every complete run of a workload, in any mode and after any crash, must give the
run-independent certificate content of one uninterrupted single worker. The same scenarios
with the pinned CaDiCaL and cake_lpr are in ``test_cluster_pinned.py``.
"""

from __future__ import annotations

import hashlib
import json
import random
from collections import Counter
from pathlib import Path
from typing import Any

import cluster_faults as faults
import cluster_harness as h
import pytest

from cubeproof.base.canonical_json import document_bytes

WORKLOADS = h.fake_workloads()
REFERENCES: dict[str, dict[str, Any]] = {}
RANDOM_SEED = 20261010
RANDOM_ITERATIONS = 50


@pytest.fixture(scope="module")
def reference(tmp_path_factory: pytest.TempPathFactory) -> Any:
    """The single-worker reference of a workload, computed once per module (per name)."""

    def get(name: str) -> dict[str, Any]:
        if name not in REFERENCES:
            root = tmp_path_factory.mktemp(f"reference-{name}")
            tools = h.e2e.fake_tools(root / "tools")
            found = h.reference_run(root / "campaign", WORKLOADS[name], tools)
            assert found["problems"] == [], found
            REFERENCES[name] = found
        return REFERENCES[name]

    return get


def test_two_workers_hand_off_crash_and_agree_with_the_reference(
    tmp_path: Path, reference: Any
) -> None:
    """The fast representative: transient mode, pigeonhole and the eight-variable core."""
    tools = h.e2e.fake_tools(tmp_path / "tools")
    record = h.cluster_scenario(
        tmp_path / "cluster", WORKLOADS["php"], tools, "transient", reference("php")["semantic"]
    )
    h.keep_evidence("fake-cluster-php-transient", record)
    assert record["problems"] == [], record["problems"]


@pytest.mark.slow
@pytest.mark.parametrize("name", sorted(WORKLOADS))
def test_every_proof_mode_gives_the_same_certificate_and_leaf_proofs(
    tmp_path: Path, reference: Any, name: str
) -> None:
    """The two-worker sequence in transient, retain and stream mode; every complete leaf
    proved in several runs has one proof hash (specification §11.3), and every run certifies the
    reference content."""
    workload = WORKLOADS[name]
    ref = reference(name)
    leaves = {"reference": ref["leaf_proofs"]}
    problems: list[str] = []
    for mode in h.MODES:
        tools = h.e2e.fake_tools(tmp_path / mode / "tools")
        record = h.cluster_scenario(tmp_path / mode, workload, tools, mode, ref["semantic"])
        leaves[mode] = record.pop("leaf_proofs")
        h.keep_evidence(f"fake-cluster-{name}-{mode}", record)
        problems += [f"{mode}: {p}" for p in record["problems"]]
    differing, common = h.common_leaf_problems(leaves)
    h.keep_evidence(
        f"fake-modes-{name}",
        {"workload": name, "common_leaves": common, "problems": differing, "leaves": leaves},
    )
    assert common > 0
    assert problems + differing == []


TRANSIENT_ROWS = sorted(faults.ROWS)


@pytest.mark.parametrize("row", TRANSIENT_ROWS)
def test_a_durable_boundary_recovers_as_the_crash_table_says(tmp_path: Path, row: str) -> None:
    tools = h.e2e.fake_tools(tmp_path / "tools")
    record = faults.ROWS[row](tmp_path / "case", tools)
    h.keep_evidence(f"fake-boundary-{row}", record)
    assert record["problems"] == [], record


MODE_ROWS = sorted(faults.MODE_ROWS)


@pytest.mark.slow
@pytest.mark.parametrize("mode", ["retain", "stream"])
@pytest.mark.parametrize("row", MODE_ROWS)
def test_a_durable_boundary_recovers_in_every_proof_mode(
    tmp_path: Path, row: str, mode: str
) -> None:
    tools = h.e2e.fake_tools(tmp_path / "tools")
    record = faults.MODE_ROWS[row](tmp_path / "case", tools, mode)
    h.keep_evidence(f"fake-boundary-{row}-{mode}", record)
    assert record["problems"] == [], record


@pytest.mark.slow
def test_fifty_random_crashes_of_two_workers_recover(tmp_path: Path, reference: Any) -> None:
    """Fifty seeded iterations: two workers at the same time, one to four crashes
    (or stops) of a random worker after a random number of records, a handoff at a random
    moment, a random proof mode; every iteration must pass every final check."""
    landed: Counter[str] = Counter()
    failures: dict[int, list[str]] = {}
    modes: Counter[str] = Counter()
    for index in range(RANDOM_ITERATIONS):
        name = "php" if index % 2 == 0 else "truth"
        seed = RANDOM_SEED + index
        tools = h.e2e.fake_tools(tmp_path / f"i{index}" / "tools")
        record = h.random_crash_scenario(
            tmp_path / f"i{index}", WORKLOADS[name], tools, seed, reference(name)["semantic"]
        )
        h.keep_evidence(f"fake-random-{index:02d}", record)
        modes[record["mode"]] += 1
        for event in record["events"]:
            if event["event"] == "interrupt" and event["signal"]:
                late = " (after the end)" if event.get("after_the_end") else ""
                landed[f"{event['signal']} after {event['after']}{late}"] += 1
        if record["problems"]:
            failures[seed] = record["problems"]
    summary = {
        "iterations": RANDOM_ITERATIONS,
        "modes": dict(modes),
        "interrupts": dict(sorted(landed.items())),
        "failures": failures,
    }
    h.keep_evidence("fake-random-summary", summary)
    print(json.dumps(summary, indent=1))
    assert sum(landed.values()) >= RANDOM_ITERATIONS
    assert failures == {}


# -- detectors on fabricated inputs ---------------------------------------------------------------


def test_the_ground_truth_agrees_with_brute_force() -> None:
    rng = random.Random(7)
    for index in range(40):
        data = h.random_3cnf(8, rng.randint(20, 45), 1000 + index)
        cnf = h.cnf_model.parse_dimacs(data)
        cube = [v if rng.random() < 0.5 else -v for v in rng.sample(range(1, 9), rng.randint(0, 3))]
        extended = h.cnf_model.Cnf(cnf.variables, (*cnf.clauses, *((u,) for u in cube)))
        expected = h.cnf_model.brute_force_model(extended) is not None
        model = h.satisfiable(cnf.clauses, cnf.variables, cube)
        assert (model is not None) == expected
        if model is not None:
            assert h.cnf_model.violated_clause(extended, model) is None


def _formula_entry(
    key: str, data: bytes, proved: bool, roots: list[dict[str, Any]]
) -> dict[str, Any]:
    return {
        "key": key,
        "formula_sha256": hashlib.sha256(data).hexdigest(),
        "proved": proved,
        "roots": roots,
    }


def _bits(assignment: dict[int, bool], variables: int) -> str:
    data = bytearray((variables + 7) // 8)
    for v, value in assignment.items():
        if value:
            data[(v - 1) // 8] |= 1 << ((v - 1) % 8)
    import base64

    return base64.b64encode(bytes(data)).decode()


def test_the_ground_truth_check_sees_every_false_claim() -> None:
    sat = h.canonical_dimacs(3, [(1, 2), (-1, 3)])
    unsat = h.e2e.unsat_formula(4, core=2)
    f_sat, f_unsat = hashlib.sha256(sat).hexdigest(), hashlib.sha256(unsat).hexdigest()
    formulas = {"s": sat, "u": unsat}
    honest = {
        "verdict": "MODEL_FOUND",
        "formulas": [
            _formula_entry("s", sat, False, [{"cube": [], "closed": False}]),
            _formula_entry("u", unsat, True, [{"cube": [], "closed": True}]),
        ],
        "used_attempts": [{"node": {"formula_sha256": f_unsat, "cube": []}}],
        "models": [
            {
                "node": {"formula_sha256": f_sat, "cube": [1]},
                "assignment": _bits({1: True, 2: False, 3: True}, 3),
            }
        ],
    }
    assert h.truth_problems(honest, formulas) == []
    lies = [
        ("formulas", 0, "proved", True),
        ("models", 0, "assignment", _bits({1: True, 2: False, 3: False}, 3)),
    ]
    for section, index, key, value in lies:
        forged = json.loads(json.dumps(honest))
        forged[section][index][key] = value
        assert h.truth_problems(forged, formulas), (section, key)
    forged = json.loads(json.dumps(honest))
    forged["used_attempts"].append({"node": {"formula_sha256": f_sat, "cube": [-1]}})
    assert h.truth_problems(forged, formulas)
    forged = json.loads(json.dumps(honest))
    forged["models"][0]["node"]["cube"] = [-1]
    assert h.truth_problems(forged, formulas)
    forged = json.loads(json.dumps(honest))
    forged["verdict"] = "PROVED"
    assert h.truth_problems(forged, formulas)


def test_regions_and_common_leaves() -> None:
    a = "a" * 64
    assert h.within((a, (1, -2, 3)), [(a, (-2,))])
    assert not h.within((a, (1, 2)), [(a, (-2,))])
    assert not h.within(("b" * 64, (1,)), [(a, ())])
    problems, common = h.common_leaf_problems({"x": {"k": ["p"], "l": ["q"]}, "y": {"k": ["p"]}})
    assert (problems, common) == ([], 1)
    problems, _ = h.common_leaf_problems({"x": {"k": ["p"]}, "y": {"k": ["r"]}})
    assert problems == ["leaf k: 2 different proofs"]


def _journal(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(
        b"".join(json.dumps({"seq": i, **r}).encode() + b"\n" for i, r in enumerate(rows))
    )


def _worker(root: Path, name: str) -> h.Worker:
    tools = h.e2e.Tools("fake", root / "s", root / "c", ())
    return h.Worker(name, root / name, root / "campaign.json", tools, "retain")


def test_the_exclusion_and_handoff_output_checks_see_violations(tmp_path: Path) -> None:
    f = "f" * 64
    shard = {
        "campaign": "c" * 64,
        "format": "cubeproof-shard-1",
        "name": "gift",
        "nodes": [{"formula_sha256": f, "cube": [1]}],
    }
    giver, receiver = _worker(tmp_path, "wa"), _worker(tmp_path, "wb")
    request = {"output_name": "gift"}
    _journal(
        giver.journal,
        [
            {"type": "attempt", "node": {"formula_sha256": f, "cube": [1]}},
            {"type": "handoff", "request": request, "shard": shard},
            {"type": "attempt", "node": {"formula_sha256": f, "cube": [-1]}},
        ],
    )
    _journal(receiver.journal, [{"type": "attempt", "node": {"formula_sha256": f, "cube": [1, 2]}}])
    assert h.exclusion_problems(giver, receiver, [(f, (1,))]) == []
    assert h.handoff_output_problems(giver)[0] == ["the committed handoff output is missing"]
    giver.outbox.mkdir(parents=True)
    (giver.outbox / "gift.json").write_bytes(document_bytes(shard))
    assert h.handoff_output_problems(giver)[0] == []
    (giver.outbox / "gift.json").write_bytes(document_bytes({**shard, "name": "other"}))
    assert h.handoff_output_problems(giver)[0] == [
        "the handoff output differs from the committed shard"
    ]
    _journal(
        giver.journal,
        [
            {"type": "handoff", "request": request, "shard": shard},
            {"type": "split", "node": {"formula_sha256": f, "cube": [1, 3]}},
        ],
    )
    _journal(receiver.journal, [{"type": "attempt", "node": {"formula_sha256": f, "cube": [-1]}}])
    found = h.exclusion_problems(giver, receiver, [(f, (1,))])
    assert found == [
        "wa: split at seq 1 on given-away work",
        "wb: attempt at seq 0 outside its region",
    ]


def test_the_retained_proof_checks_see_missing_changed_and_orphaned_files(tmp_path: Path) -> None:
    worker = _worker(tmp_path, "w1")
    proof = b"proof bytes\n"
    digest = hashlib.sha256(proof).hexdigest()
    path = f"proofs/n-{digest}.lrat"
    artifact: dict[str, Any] = {"path": path, "bytes": len(proof), "sha256": digest}
    _journal(
        worker.journal, [{"type": "attempt", "outcome": "VERIFIED_UNSAT", "retained": artifact}]
    )
    assert h.retained_problems(worker) == ([f"w1: retained {artifact['path']} is missing"], 1)
    (worker.results / "proofs").mkdir()
    (worker.results / path).write_bytes(b"other bytes\n")
    assert h.retained_problems(worker)[0] == [f"w1: retained {artifact['path']} differs"]
    (worker.results / path).write_bytes(proof)
    assert h.retained_problems(worker) == ([], 1)
    assert h.orphan_proofs(worker) == []
    (worker.results / "proofs" / "tmp").mkdir()
    (worker.results / "proofs" / "tmp" / "x.lrat").write_bytes(b"partial")
    assert h.orphan_proofs(worker) == ["proofs/tmp/x.lrat"]


def test_the_export_check_sees_a_stale_or_foreign_copy(tmp_path: Path) -> None:
    worker = _worker(tmp_path, "w1")
    rows = [{"type": "header", "self": "a" * 64}, {"type": "attempt", "self": "b" * 64}]
    _journal(worker.journal, rows)
    data = worker.journal.read_bytes()
    worker.export.mkdir(parents=True)

    def publish(copy: bytes, seq: int, head: str) -> None:
        (worker.export / "journal.1.jsonl").write_bytes(copy)
        descriptor = {"file": "journal.1.jsonl", "offset": len(copy), "seq": seq, "head": head}
        (worker.export / "export.json").write_text(json.dumps(descriptor))

    publish(data, 1, "b" * 64)
    assert h.export_problems(worker) == []
    first = data.splitlines(keepends=True)[0]
    publish(first, 0, "a" * 64)
    assert h.export_problems(worker) == [
        "w1: the export after the clean end is not the whole journal"
    ]
    publish(data, 1, "c" * 64)
    assert h.export_problems(worker) == ["w1: the export descriptor does not describe its copy"]
    publish(b"{}\n" + data, 1, "b" * 64)
    assert "w1: export journal.1.jsonl is not a prefix of the journal" in h.export_problems(worker)
