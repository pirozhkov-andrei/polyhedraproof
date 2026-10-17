"""Single-worker runs with the pinned CaDiCaL and cake_lpr (``image`` tier; real binaries).

The scenarios of ``test_e2e_fake.py`` with the binaries of ``POLYHEDRAPROOF_TEST_TOOLS`` (the
test image, or a prefix built by ``docker/test/pinned_tools.py``; ``image.pinned.locate``
verifies them against ``docker/test/tools.json``). An absent prefix fails, never skips.
Pigeonhole formulas get a 100 ms solver deadline at the empty cube, so the real solver's
deadline, the split and real LRAT proofs checked by cake_lpr are all on the path. The ``slow``
pigeonhole 10 trees (1 s deadline at every depth) give a few hundred real leaves, so the two
certifiers also agree on a nontrivial selected tree and Merkle root, for the whole formula and
for a nonempty requested root that closes while the formula stays unproved.

The bounded pilot root subtree (``pilot_root_smoke.py``) is also ``slow``: a short timed
run that is interrupted and resumed must produce checked evidence on which both certifiers
agree; its root is reported closed only if the budget sufficed, never as a proof of map 2.
It splits with the Python reference (the test image has no compiler for the native helper),
two variables per split and 5 s leaves, so that real leaves verify within the short budget.
"""

from __future__ import annotations

import sys
from pathlib import Path

import e2e_harness as h
import pilot_root_smoke as smoke
import pytest

from image.pinned import Pinned, ToolsUnavailable, locate

pytestmark = [
    pytest.mark.image,
    pytest.mark.skipif(not sys.platform.startswith("linux"), reason="pinned tools are Linux"),
]

WORKLOADS = h.tiny_workloads("pinned")


@pytest.fixture(scope="module")
def pinned() -> Pinned:
    try:
        return locate()
    except ToolsUnavailable as error:
        pytest.fail(str(error), pytrace=False)


@pytest.mark.parametrize("name", sorted(WORKLOADS))
def test_a_tiny_workload_closes_with_real_tools_and_both_certifiers_agree(
    tmp_path: Path, pinned: Pinned, name: str
) -> None:
    tools = h.pinned_tools(pinned.prefix)
    record = h.complete_scenario(tmp_path / "campaign", WORKLOADS[name], tools)
    h.keep_evidence(f"pinned-complete-{name}", record)
    assert record["problems"] == [], record


@pytest.mark.parametrize("how", ["SIGINT", "SIGKILL"])
def test_an_interrupted_real_run_resumes_to_the_reference_certificate(
    tmp_path: Path, pinned: Pinned, how: str
) -> None:
    tools = h.pinned_tools(pinned.prefix)
    record = h.interrupt_scenario(tmp_path, h.interrupt_workload("pinned"), tools, how, after=2)
    h.keep_evidence(f"pinned-interrupt-{how}", record)
    assert record["problems"] == [], record


TREES = h.tree_workloads()


@pytest.mark.slow
@pytest.mark.parametrize("name", sorted(TREES))
def test_a_real_proof_tree_closes_and_both_certifiers_agree_on_its_merkle_root(
    tmp_path: Path, pinned: Pinned, name: str
) -> None:
    tools = h.pinned_tools(pinned.prefix)
    campaign_record = h.complete_scenario(tmp_path / "campaign", TREES[name], tools)
    h.keep_evidence(f"pinned-tree-{name}", campaign_record)
    assert campaign_record["problems"] == [], campaign_record
    roots = [r for f in campaign_record["roots"] for r in f["roots"]]
    assert all(r["closed"] and r["summary"]["leaves"] > 1 for r in roots), roots
    assert all(r["summary"]["leaf_merkle_root"] is not None for r in roots), roots


@pytest.mark.slow
def test_an_interrupted_real_tree_resumes_and_both_certifiers_agree(
    tmp_path: Path, pinned: Pinned
) -> None:
    """A timing-dependent tree: the restarted run must prove the formula with a valid
    selected tree on which both certifiers agree, not necessarily the reference's leaves."""
    tools = h.pinned_tools(pinned.prefix)
    record = h.interrupt_scenario(tmp_path, TREES["php10-tree"], tools, "SIGKILL", after=60)
    h.keep_evidence("pinned-tree-interrupt-SIGKILL", record)
    assert record["problems"] == [], record


@pytest.mark.slow
def test_a_bounded_pilot_root_subtree_produces_checked_evidence(
    tmp_path: Path, pinned: Pinned
) -> None:
    tools = h.pinned_tools(pinned.prefix)
    summary = smoke.smoke(
        tmp_path / "evidence",
        tools,
        phase1_seconds=45,
        phase2_seconds=60,
        jobs=4,
        leaf_ms=5_000,
        split_vars=2,
    )
    h.keep_evidence("pinned-pilot-root-smoke", summary)
    assert smoke.problems(summary) == [], summary
    assert summary["phase2"]["checked_leaves"] > 0, summary["phase2"]["counts"]
    assert summary["status"] in ("OPEN", "CLOSED")
