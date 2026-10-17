"""Multi-worker runs with the pinned CaDiCaL and cake_lpr (``image`` tier).

The two-worker sequence of ``cluster_harness.cluster_scenario`` in transient, retain and stream
mode with the binaries of ``POLYHEDRAPROOF_TEST_TOOLS`` (the test image, or a prefix built by
``docker/test/pinned_tools.py``; ``image.pinned.locate`` verifies them against
``docker/test/tools.json``). An absent prefix fails, never skips.

Workloads (``pinned_workloads``): pigeonhole 7->6 and 8->7 and two small real
formulas (the neighbourly encodings of the tetrahedron and of the Csaszar map, both
satisfiable), each statically split three times, without solver deadlines, so the evidence
tree does not depend on timing; and two seeded random 3-CNF formulas with a DPLL ground truth.
Every complete leaf proved in several runs, in any mode and by the strict recompute audit
(no solver time limit), must have the same proof bytes: the determinism gate of
specification §11.3 for these cases. The ``slow`` tier adds ten random crash iterations with
the real tools.
"""

from __future__ import annotations

import sys
from collections import Counter
from pathlib import Path
from typing import Any

import cluster_harness as h
import pytest

from image.pinned import Pinned, ToolsUnavailable, locate

pytestmark = [
    pytest.mark.image,
    pytest.mark.skipif(not sys.platform.startswith("linux"), reason="pinned tools are Linux"),
]

#: the workloads are built inside the tests: the real formulas are encoded on demand
NAMES = ("php", "real", "truth")
RANDOM_SEED = 20261110
RANDOM_ITERATIONS = 10


@pytest.fixture(scope="module")
def pinned() -> Pinned:
    try:
        return locate()
    except ToolsUnavailable as error:
        pytest.fail(str(error), pytrace=False)


@pytest.mark.parametrize("name", NAMES)
def test_every_proof_mode_gives_the_same_certificate_and_leaf_proofs_with_real_tools(
    tmp_path: Path, pinned: Pinned, name: str
) -> None:
    workload = h.pinned_workloads()[name]
    tools = h.e2e.pinned_tools(pinned.prefix)
    reference = h.reference_run(tmp_path / "reference", workload, tools)
    assert reference["problems"] == [], reference
    leaves = {"reference": reference["leaf_proofs"]}
    problems: list[str] = []
    for mode in h.MODES:
        record = h.cluster_scenario(tmp_path / mode, workload, tools, mode, reference["semantic"])
        leaves[mode] = record.pop("leaf_proofs")
        h.keep_evidence(f"pinned-cluster-{name}-{mode}", record)
        problems += [f"{mode}: {p}" for p in record["problems"]]
    differing, common = h.common_leaf_problems(leaves)
    h.keep_evidence(
        f"pinned-modes-{name}",
        {
            "workload": name,
            "reference_counts": reference["counts"],
            "common_leaves": common,
            "problems": differing,
            "leaves": leaves,
        },
    )
    assert common > 0
    assert problems + differing == []


@pytest.mark.slow
def test_random_crashes_of_two_workers_with_real_tools_recover(
    tmp_path: Path, pinned: Pinned
) -> None:
    tools = h.e2e.pinned_tools(pinned.prefix)
    workloads = h.pinned_workloads()
    references: dict[str, dict[str, Any]] = {}
    failures: dict[int, list[str]] = {}
    landed: Counter[str] = Counter()
    for index in range(RANDOM_ITERATIONS):
        name = NAMES[index % 3]
        if name not in references:
            references[name] = h.reference_run(
                tmp_path / f"reference-{name}", workloads[name], tools
            )
            assert references[name]["problems"] == [], references[name]
        seed = RANDOM_SEED + index
        record = h.random_crash_scenario(
            tmp_path / f"i{index}", workloads[name], tools, seed, references[name]["semantic"]
        )
        h.keep_evidence(f"pinned-random-{index:02d}", record)
        for event in record["events"]:
            if event["event"] == "interrupt" and event["signal"]:
                late = " (after the end)" if event.get("after_the_end") else ""
                landed[f"{event['signal']} after {event['after']}{late}"] += 1
        if record["problems"]:
            failures[seed] = record["problems"]
    h.keep_evidence(
        "pinned-random-summary",
        {
            "iterations": RANDOM_ITERATIONS,
            "interrupts": dict(sorted(landed.items())),
            "failures": failures,
        },
    )
    assert failures == {}
