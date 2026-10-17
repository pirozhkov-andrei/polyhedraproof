"""A run with the pinned CaDiCaL and cake_lpr (``image`` tier).

The same coordinator, journal and certifier as the other lifecycle tests, with the real
binaries of ``POLYHEDRAPROOF_TEST_TOOLS`` (the test image or a prefix built by
``docker/test/pinned_tools.py``): the real solver's deadline and its proofs, the real checker's
verdicts, and an interrupted run that resumes. An absent prefix fails, never skips. This is a
smoke test of the wiring with real tools.
"""

from __future__ import annotations

import signal
import sys
import time
from pathlib import Path

import cp_life_tools as t
import pytest

from cubeproof.cnf.dimacs import canonical_dimacs
from cubeproof.contracts.policy import HeapFit
from cubeproof.tools.isolation import PinnedBinary
from fakes import cnf_model
from image.pinned import Pinned, ToolsUnavailable, locate

pytestmark = [
    pytest.mark.image,
    pytest.mark.skipif(not sys.platform.startswith("linux"), reason="pinned tools are Linux"),
]


@pytest.fixture(scope="module")
def pinned() -> Pinned:
    try:
        return locate()
    except ToolsUnavailable as error:
        pytest.fail(str(error), pytrace=False)


def pigeonhole(holes: int) -> bytes:
    cnf = cnf_model.pigeonhole(holes)
    return canonical_dimacs(cnf.variables, cnf.clauses)


def world(tmp_path: Path, pinned: Pinned, *, root_deadline_ms: int) -> t.World:
    tools = t.Tools(pinned.cadical, pinned.cake_lpr)
    policy = t.split_policy(
        2,
        leaf_time_ms={"default": 120_000, "0": root_deadline_ms},
        solver_memory_bytes=512 * t.MIB,  # the real solver, not a scripted one
        heap_fit=HeapFit(),
        checker_stack_mib=256,
        checker_max_stack_mib=2048,
        checker_slack_mib=256,
        checker_time_base_ms=120_000,
    )
    path = t.campaign(tmp_path, {"php": pigeonhole(8)}, tools, policy, solver_argv=("-q", "--lrat"))
    return t.World(tmp_path, path, tools)


def test_a_real_campaign_splits_after_a_solver_deadline_and_certifies(
    tmp_path: Path, pinned: Pinned
) -> None:
    w = world(tmp_path, pinned, root_deadline_ms=100)
    result = w.run()
    assert result.exit_code == 0, result.notes
    attempts = w.attempts()
    first = attempts[0]
    assert (first["outcome"], first["reason"], first["node"]["cube"]) == ("EXHAUSTED", "time", [])
    assert first["solver"]["cause"] == "deadline"
    leaves = [a for a in attempts if a["outcome"] == "VERIFIED_UNSAT"]
    assert leaves and all(a["checks"][-1]["result"]["exit"] == 0 for a in leaves)
    assert w.summary()["verdict"] == "PROVED"
    assert w.work_files() == []
    header = w.records("header")[0]["machinery"]
    assert header["solver"]["sha256"] == PinnedBinary.measure(str(pinned.cadical)).sha256
    assert header["solver"]["version"]


def test_a_real_run_killed_and_restarted_proves_the_same_formula(
    tmp_path: Path, pinned: Pinned
) -> None:
    reference = world(tmp_path / "reference", pinned, root_deadline_ms=100)
    assert reference.run().exit_code == 0
    w = world(tmp_path / "killed", pinned, root_deadline_ms=100)
    child = t.spawn_runner(w.spec(jobs=1))
    time.sleep(1.5)
    t.kill_and_collect(child, signal.SIGKILL)
    t.wait_clean(w.results, w.work)
    finish = t.spawn_runner(w.spec(jobs=1))
    code, out, err = t.messages(finish, timeout_s=600)
    assert code == 0, (out, err)
    assert w.summary()["verdict"] == "PROVED"
    assert w.summary()["formulas"][0]["summary"]["leaves"] > 0
    assert reference.summary()["verdict"] == "PROVED"
    ids = [a["attempt_id"] for a in w.attempts()]
    assert len(ids) == len(set(ids))
