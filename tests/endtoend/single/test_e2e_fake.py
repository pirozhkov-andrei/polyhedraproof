"""Single-worker runs with the fake pinned tools: the whole command path on tiny workloads.

``campaign create``, ``run`` and ``cubeproof certify`` run as child processes; the journal is
certified by the main certifier and by ``tools/certify_min.py`` (black box), which must
produce byte-identical certificates and the verdict, root closure and routes the workload
expects (specification §10). Interrupted runs (SIGINT, SIGTERM, SIGKILL of the whole process
group) are restarted and must end with the reference run's verdict, selected evidence, Merkle
roots and open lists, satisfy the restart invariants (specification §7.3, §7.5) and give the
same certificate when the interrupted prefix is supplied as a second copy of the journal
(specification §10.1).

The fake tools are test doubles (brute force, ``fakes.lrat_check``); the same
scenarios with the pinned CaDiCaL and cake_lpr are in ``test_e2e_pinned.py``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import e2e_harness as h
import pytest

WORKLOADS = h.tiny_workloads("fake")


@pytest.mark.parametrize("name", sorted(WORKLOADS))
def test_a_tiny_workload_closes_and_both_certifiers_agree(tmp_path: Path, name: str) -> None:
    tools = h.fake_tools(tmp_path / "tools")
    record = h.complete_scenario(tmp_path / "campaign", WORKLOADS[name], tools)
    h.keep_evidence(f"fake-complete-{name}", record)
    assert record["problems"] == [], record


@pytest.mark.parametrize("how", ["SIGINT", "SIGTERM", "SIGKILL"])
def test_an_interrupted_run_resumes_to_the_reference_certificate(tmp_path: Path, how: str) -> None:
    tools = h.fake_tools(tmp_path / "tools")
    workload = h.interrupt_workload("fake")
    record = h.interrupt_scenario(tmp_path, workload, tools, how, after=6)
    h.keep_evidence(f"fake-interrupt-{how}", record)
    assert record["problems"] == [], record
    assert record["prefix_verdict"] == "OPEN" and record["prefix_open"] > 0


@pytest.mark.slow
@pytest.mark.parametrize("after", [1, 3, 9, 14, 18])
def test_a_process_group_crash_after_n_attempts_resumes_to_the_reference(
    tmp_path: Path, after: int
) -> None:
    """SIGKILL of the whole process group once ``after`` attempt records are committed.

    This is a crash, not a power loss: the kernel page cache survives, so unsynced appends are
    never lost and the fsync ordering of specification §7.1/§7.2 is not exercised here
    (component fault injection covers it). The kill points follow a committed attempt record
    (polling), they are not arbitrary instants.
    """
    tools = h.fake_tools(tmp_path / "tools")
    workload = h.interrupt_workload("fake")
    record = h.interrupt_scenario(tmp_path, workload, tools, "SIGKILL", after=after)
    h.keep_evidence(f"fake-crash-after-{after}", record)
    assert record["problems"] == [], record


def test_the_semantic_view_ignores_run_identity_but_not_evidence() -> None:
    """The comparison of two runs is blind to Refs and journal IDs, not to proofs or open nodes."""
    used: dict[str, Any] = {
        "node_id": "b" * 64,
        "cnf_sha256": "c" * 64,
        "proof_sha256": "d" * 64,
        "route": "cdcl",
        "record": {"journal": "e" * 64, "seq": 4},
        "node": {"formula_sha256": "a" * 64, "cube": [1]},
    }
    base: dict[str, Any] = {
        "verdict": "OPEN",
        "formulas": [
            {
                "key": "f",
                "formula_sha256": "a" * 64,
                "proved": False,
                "summary": None,
                "roots": [],
            }
        ],
        "used_attempts": [used],
        "open": [
            {
                "node": {"formula_sha256": "a" * 64, "cube": [-1]},
                "node_id": "f" * 64,
                "state": "pending",
                "reason": None,
            }
        ],
        "formula_open": [],
        "models": [],
        "anomalies": [],
        "journals": [{"id": "e" * 64}],
        "campaign": "0" * 64,
    }
    other_run = {
        **base,
        "used_attempts": [{**used, "record": {"journal": "9" * 64, "seq": 7}}],
        "journals": [{"id": "9" * 64}],
        "campaign": "1" * 64,
    }
    assert h.semantic(base) == h.semantic(other_run)
    other_proof = {**base, "used_attempts": [{**used, "proof_sha256": "7" * 64}]}
    assert h.semantic(base) != h.semantic(other_proof)
    closed = {**base, "open": []}
    assert h.semantic(base) != h.semantic(closed)


def test_the_resume_invariants_see_a_rewritten_prefix_and_repeated_work(tmp_path: Path) -> None:
    def line(seq: int, kind: str, **fields: object) -> str:
        import json

        return json.dumps({"seq": seq, "type": kind, **fields}) + "\n"

    node = {"formula_sha256": "a" * 64, "cube": []}
    before = line(0, "header") + line(1, "attempt", attempt_id="x", outcome="EXHAUSTED", node=node)
    good = before + line(2, "resume") + line(3, "split", node=node, variables=[1])
    path = tmp_path / "journal.jsonl"
    path.write_text(good, encoding="utf-8")
    assert h.resume_invariants(before.encode(), path, 1) == []
    path.write_text(good.replace('"x"', '"y"'), encoding="utf-8")
    assert "does not extend" in " ".join(h.resume_invariants(before.encode(), path, 1))
    repeated = good + line(4, "attempt", attempt_id="x", outcome="EXHAUSTED", node=node)
    path.write_text(repeated, encoding="utf-8")
    assert "attempt ID occurs twice" in " ".join(h.resume_invariants(before.encode(), path, 1))
    proved = (
        good
        + line(4, "attempt", attempt_id="p", outcome="VERIFIED_UNSAT", node=node)
        + line(5, "attempt", attempt_id="q", outcome="VERIFIED_UNSAT", node=node)
        + line(6, "split", node=node, variables=[1])
    )
    path.write_text(proved, encoding="utf-8")
    found = " ".join(h.resume_invariants(before.encode(), path, 1))
    assert "proved more than once" in found and "splits recorded more than once" in found
    assert "resume records" in " ".join(h.resume_invariants(before.encode(), path, 2))


def test_the_certifier_comparison_sees_differing_bytes_codes_and_compare() -> None:
    """Agreement means equal exit codes, byte-identical documents and `compare` exit 0: a
    document that differs only in its bytes (same JSON content) is still a disagreement."""
    import json

    document: dict[str, Any] = {
        "verdict": "OPEN",
        "formulas": [
            {"key": "f", "formula_sha256": "a" * 64, "proved": False, "summary": None, "roots": []}
        ],
        "used_attempts": [],
        "open": [],
        "formula_open": [],
        "models": [],
        "anomalies": [],
    }
    canonical = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    reordered = json.dumps(dict(reversed(list(document.items())))).encode()
    assert canonical != reordered and json.loads(canonical) == json.loads(reordered)

    def done(code: int) -> h.Completed:
        return h.Completed(("x",), code, "", "", 0.0)

    agree = h.Certified(done(1), done(1), done(0), canonical, canonical)
    assert agree.problems() == []
    found = h.Certified(done(1), done(1), done(0), canonical, reordered).problems()
    assert found == ["certificate bytes differ"]
    found = h.Certified(done(1), done(0), done(0), canonical, canonical).problems()
    assert found == ["exit codes differ: main 1, min 0"]
    found = h.Certified(done(1), done(1), done(3), canonical, canonical).problems()
    assert found == ["certify_min compare: exit 3 "]
    closed = json.dumps({**document, "verdict": "PROVED"}, sort_keys=True).encode()
    found = h.Certified(done(1), done(1), done(0), canonical, closed).problems()
    assert found == ["certificate bytes differ", "semantic field verdict differs"]
    missing = h.Certified(done(1), done(2), None, canonical, None).problems()
    assert missing == ["exit codes differ: main 1, min 2", "certificate bytes differ"]
