"""Whole transient attempts with the pinned CaDiCaL and cake_lpr (``image`` tier).

Real tiny UNSAT (CDCL proof), SAT (model), unit-route refutations and checker-only arena
retries go through the leaf state machine, the I/O service and a real journal; the records
are then judged by the certifier's own rules (``attempt.cnf_sha256`` against the bundle
formula, ``success.*``). The tools come from ``POLYHEDRAPROOF_TEST_TOOLS`` (the test image or
a prefix built by ``docker/test/pinned_tools.py``); an absent prefix fails, never skips.
"""

from __future__ import annotations

import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from cp_leaf_support import (  # noqa: F401 - fixtures are registered by import
    SAT,
    LocalIo,
    cnf_model,
    expected_cnf_sha256,
    formula,
    isolation_fixture,
    make_policy,
    sha,
    supervisor_fixture,
)

from cubeproof.cnf.cubecnf import CnfDigest
from cubeproof.cnf.dimacs import Formula
from cubeproof.cnf.unit import build_index, refutation
from cubeproof.contracts.assignment import decode_assignment
from cubeproof.contracts.policy import HeapFit, Policy
from cubeproof.evidence.certify.admission import success_problem
from cubeproof.evidence.schema.rules import attempt_problem
from cubeproof.leaf.attempt import LeafAttempt, LeafTools
from cubeproof.leaf.driver import drive
from cubeproof.tools.isolation import PinnedBinary
from cubeproof.tools.process import Supervisor
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


@pytest.fixture(scope="module")
def tools(pinned: Pinned) -> LeafTools:
    return LeafTools(
        solver=PinnedBinary.measure(str(pinned.cadical)),
        solver_argv=("-q", "--lrat"),
        checker=PinnedBinary.measure(str(pinned.cake_lpr)),
    )


class Real:
    def __init__(
        self, root: Path, supervisor: Supervisor, tools: LeafTools, policy: Policy
    ) -> None:
        self.policy = policy
        self.work = root / "work"
        self.io = LocalIo(root / "results", self.work, policy)
        self.supervisor = supervisor
        self.tools = tools

    def run(self, f: Formula, cube: tuple[int, ...] = ()) -> dict[str, Any]:
        attempt = LeafAttempt(
            formula=f,
            digest=CnfDigest(f),
            cube=cube,
            policy=self.policy,
            work_dir=str(self.work),
            tools=self.tools,
            supervisor=self.supervisor,
            io=self.io,
        )
        drive([attempt], supervisor=self.supervisor, io=self.io, timeout_s=300)
        (record,) = [r for r in self.io.attempts() if r["attempt_id"] == attempt.attempt_id]
        assert attempt_problem(record, f.variables) is None
        assert record["cnf_sha256"] == expected_cnf_sha256(f, cube)
        assert sorted(p.name for p in self.work.iterdir()) == []
        return record


@pytest.fixture
def real(tmp_path: Path, supervisor: Supervisor, tools: LeafTools) -> Iterator[Any]:
    made: list[Real] = []

    def factory(policy: Policy | None = None) -> Real:
        value = Real(tmp_path / f"r{len(made)}", supervisor, tools, policy or make_policy())
        made.append(value)
        return value

    yield factory
    for value in made:
        value.io.close()


def php(holes: int) -> Formula:
    cnf = cnf_model.pigeonhole(holes)
    return formula(cnf.variables, cnf.clauses)


@pytest.mark.parametrize("holes", [2, 3, 4])
def test_real_cdcl_unsat_is_verified(real: Any, holes: int) -> None:
    record = real().run(php(holes))
    assert (record["outcome"], record["route"]) == ("VERIFIED_UNSAT", "cdcl")
    assert record["solver"]["exit"] == 20
    assert success_problem(record) is None


def test_real_cdcl_unsat_under_a_cube(real: Any) -> None:
    f = php(3)
    record = real().run(f, (1, 6))
    assert record["outcome"] == "VERIFIED_UNSAT"
    assert record["node"]["cube"] == [1, 6]


def test_real_sat_is_a_model(real: Any) -> None:
    record = real().run(SAT)
    assert (record["outcome"], record["solver"]["exit"]) == ("MODEL", 10)
    values = decode_assignment(record["assignment"], SAT.variables)
    assert (values[0] or values[1]) and (not values[0] or values[2])


def test_real_unit_refutation_is_checked_by_cake_lpr(real: Any) -> None:
    f = formula(3, [(1, 1, 2), (-2,), (-1, 3), (-3,)])  # restated repeated literal
    proof = refutation(build_index(f), ())
    assert proof is not None
    record = real().run(f)
    assert (record["outcome"], record["route"], record["solver"]) == (
        "VERIFIED_UNSAT",
        "unit",
        None,
    )
    assert record["proof_sha256"] == sha(proof)
    assert success_problem(record) is None


def chain(n: int) -> Formula:
    """The arena recipe: one clause over 1..n refuted by n unit clauses (unit route)."""
    return formula(n, [tuple(range(1, n + 1)), *[(-i,) for i in range(1, n + 1)]])


@pytest.mark.parametrize(
    ("n", "changes", "arena"),
    [
        (5000, {"heap_fit": HeapFit(min_mib=1)}, "heap"),
        (20000, {"checker_stack_mib": 1}, "stack"),
    ],
)
def test_real_checker_only_arena_retries(
    real: Any, n: int, changes: dict[str, Any], arena: str
) -> None:
    record = real(make_policy(**changes)).run(chain(n))
    assert record["outcome"] == "VERIFIED_UNSAT"
    checks = record["checks"]
    assert len(checks) >= 2
    key = "heap_mib" if arena == "heap" else "stack_mib"
    assert [c[key] for c in checks] == [checks[0][key] * 2**i for i in range(len(checks))]
    assert all(c["result"]["exit"] != 0 for c in checks[:-1])
    assert success_problem(record) is None
