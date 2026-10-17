"""proof-prefix-v1 with the pinned CaDiCaL (``image`` tier; specification §9.2).

The tools come from ``POLYHEDRAPROOF_TEST_TOOLS`` (the test image or a prefix built by
``docker/test/pinned_tools.py``); an absent prefix fails, it never skips.

- ``test_a_real_solver_run_equals_the_golden``: ``choose_prefix`` runs the real CaDiCaL on small
  formulas and must make the recorded choices. They were recorded with each pinned CaDiCaL
  build listed below; a build that is not listed has no recorded choice and fails the test.
- ``test_maps_1_and_2_prefixes_match_the_fixture``: the fixtures of specification §9.2, the
  first twelve prefix variables of maps 1 and 2 with samples 2, steps 100000, conflicts 90000,
  seed 5, pool ``order``. A different result is a defect: the fixture is never adjusted to
  match.
"""

from __future__ import annotations

import random
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest
from cp_split_support import make_formula

from cubeproof.cnf.dimacs import canonical_dimacs, parse_dimacs
from cubeproof.split.proof_prefix import ProofPrefixParams, choose_prefix, supervised_solver
from cubeproof.tools.isolation import Isolation, PinnedBinary
from cubeproof.tools.process import Supervisor
from image.pinned import Pinned, ToolsUnavailable, locate
from neighbourly.corpus12 import base_encoder, formula_hashes

pytestmark = [
    pytest.mark.image,
    pytest.mark.skipif(not sys.platform.startswith("linux"), reason="pinned tools are Linux"),
]

# Specification §9.2: the first twelve variables of the prefixes of maps 1 and 2.
EXPECTED = {
    1: [1398, 858, 775, 994, 1262, 811, 1213, 947, 945, 1215, 3156, 853],
    2: [853, 1354, 992, 1305, 1399, 1260, 1216, 1259, 1533, 1488, 946, 743],
}
#: The recorded choices of ``test_a_real_solver_run_equals_the_golden`` ...
REAL_CHOICES_GOLDEN = [[38, 36, 40, 32, 7], [36, 40, 38, 1, 10], [37, 40, 15, 38, 39]]
#: ... identical with each of these builds of the pinned CaDiCaL commit (SHA-256 of the binary).
CADICAL_SHA256_RECORDED = {
    "c3a77cbc3a354106b0cf0d710aae00d433a8250ba06805d5794b7b07991be7f4": "the docker/test image",
    "59f3713a9a020eccf710a9b180a45d81fde9d1a63c8ad0645001ebefa100f0af": "pinned_tools.py on a host",
}


@pytest.fixture(scope="module")
def pinned() -> Pinned:
    try:
        return locate()
    except ToolsUnavailable as error:
        pytest.fail(str(error), pytrace=False)


@pytest.fixture(scope="module")
def supervisor() -> Iterator[Supervisor]:
    sup = Supervisor(Isolation.probe())
    try:
        yield sup
    finally:
        sup.shutdown(grace_ms=500)


def test_a_real_solver_run_equals_the_golden(
    pinned: Pinned, supervisor: Supervisor, tmp_path: Path
) -> None:
    rng = random.Random(77)
    binary = PinnedBinary.measure(str(pinned.cadical))
    assert binary.sha256 in CADICAL_SHA256_RECORDED, "no choice was recorded with this build"
    for case in range(3):
        variables = 40
        clauses = [
            [rng.choice([-1, 1]) * v for v in rng.sample(range(1, variables + 1), 3)]
            for _ in range(165)
        ]
        formula = make_formula(variables, clauses)
        params = ProofPrefixParams(samples=2, steps=2000, conflicts=300, seed=3 + case)
        new = choose_prefix(
            formula,
            5,
            None,
            params,
            supervised_solver(supervisor, binary, params, tmp_path / f"new{case}"),
            tmp_path / f"new{case}",
        )
        assert list(new.variables) == REAL_CHOICES_GOLDEN[case] and len(new.variables) >= 3


@pytest.mark.slow
@pytest.mark.parametrize("map_id", [1, 2])
def test_maps_1_and_2_prefixes_match_the_fixture(
    pinned: Pinned, supervisor: Supervisor, tmp_path: Path, map_id: int
) -> None:
    encoder = base_encoder(map_id)
    formula = parse_dimacs(canonical_dimacs(encoder.variables, encoder.clauses))
    assert formula.sha256 == formula_hashes()[map_id].sha256  # the pinned base formula
    pool = sorted(encoder.pool("order"))
    params = ProofPrefixParams()
    binary = PinnedBinary.measure(str(pinned.cadical))
    result = choose_prefix(
        formula,
        len(EXPECTED[map_id]),
        pool,
        params,
        supervised_solver(supervisor, binary, params, tmp_path),
        tmp_path,
    )
    assert list(result.variables) == EXPECTED[map_id]
