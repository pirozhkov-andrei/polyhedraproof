"""unit-v1 proofs and models with the pinned cake_lpr and CaDiCaL (``image`` tier).

Every proof of the unit vectors and of the random corpora of ``test_cp_um_unit.py`` is
written as ``CNF(F, C)`` + proof files and checked by the real cake_lpr through the process
supervisor; success is recognized only by ``tools.checker.accepts``. Real CaDiCaL models
go through ``cnf.model.solver_model``. The tools come from ``POLYHEDRAPROOF_TEST_TOOLS``
(the test image or a prefix built by ``docker/test/pinned_tools.py``); an absent prefix
fails, it never skips.
"""

from __future__ import annotations

import random
import sys
import time
from collections.abc import Iterator
from pathlib import Path

import pytest
from cp_um_support import (
    CORPORA,
    UNIT_VECTORS,
    brute_force_satisfiable,
    formula,
    random_cases,
    satisfies,
)

from cubeproof.base.process import ProcessResult
from cubeproof.cnf import unit as up
from cubeproof.cnf.cubecnf import cube_cnf_bytes
from cubeproof.cnf.dimacs import Formula
from cubeproof.cnf.model import solver_model
from cubeproof.contracts.assignment import decode_assignment
from cubeproof.contracts.enums import ModelError
from cubeproof.tools import checker as ck
from cubeproof.tools.isolation import Isolation, PinnedBinary
from cubeproof.tools.process import Launch, ProcessRun, Supervisor
from cubeproof.tools.unit_helper import UnitRoute, unit_steps
from image.pinned import Pinned, ToolsUnavailable, locate

pytestmark = [
    pytest.mark.image,
    pytest.mark.skipif(not sys.platform.startswith("linux"), reason="pinned tools are Linux"),
]

HEAP_MIB, STACK_MIB = 64, 16


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
        sup.shutdown(grace_ms=200)


@pytest.fixture(scope="module")
def cake(pinned: Pinned) -> PinnedBinary:
    return PinnedBinary.measure(str(pinned.cake_lpr))


@pytest.fixture(scope="module")
def cadical(pinned: Pinned) -> PinnedBinary:
    return PinnedBinary.measure(str(pinned.cadical))


def run(supervisor: Supervisor, spec: Launch) -> ProcessRun:
    process = supervisor.start(spec)
    limit = time.monotonic() + 120
    while process.run is None:
        assert time.monotonic() < limit, "a real tool did not finish in 120 s"
        supervisor.step(20)
    return process.run


def cake_check(
    supervisor: Supervisor,
    cake: PinnedBinary,
    directory: Path,
    f: Formula,
    cube: tuple[int, ...],
    proof: bytes,
    name: str,
) -> ProcessResult:
    cnf_path = directory / f"{name}.cnf"
    proof_path = directory / f"{name}.lrat"
    cnf_path.write_bytes(cube_cnf_bytes(f, cube))
    proof_path.write_bytes(proof)
    spec = Launch(
        binary=cake,
        args=ck.checker_args(HEAP_MIB, STACK_MIB, str(cnf_path), str(proof_path)),
        cwd=str(directory),
        memory_bytes=ck.checker_memory_bytes(HEAP_MIB, STACK_MIB, 256),
        deadline_ms=60_000,
    )
    return run(supervisor, spec).result


def test_unit_vectors_are_accepted_by_cake_lpr(
    supervisor: Supervisor, cake: PinnedBinary, tmp_path: Path
) -> None:
    checked = 0
    for number, (variables, clauses, cube, expected) in enumerate(UNIT_VECTORS):
        if expected is None:
            continue
        f = formula(variables, clauses)
        result = cake_check(supervisor, cake, tmp_path, f, cube, expected, f"v{number}")
        assert ck.accepts(result), (variables, clauses, cube, result)
        checked += 1
    assert checked >= 8


def test_every_corpus_proof_is_accepted_by_cake_lpr(
    supervisor: Supervisor, cake: PinnedBinary, tmp_path: Path
) -> None:
    checked = restated = 0
    for corpus, (seed, count) in enumerate(CORPORA):
        for number, (variables, clauses, cube) in enumerate(random_cases(seed, count)):
            f = formula(variables, clauses)
            proof = up.refutation(up.build_index(f), cube)
            if proof is None:
                continue
            result = cake_check(supervisor, cake, tmp_path, f, cube, proof, f"c{corpus}-{number}")
            assert ck.accepts(result), (variables, clauses, cube, proof, result)
            checked += 1
            restated += proof.count(b"\n") > 1
    assert checked > 300 and restated > 3


def test_a_damaged_unit_proof_is_rejected(
    supervisor: Supervisor, cake: PinnedBinary, tmp_path: Path
) -> None:
    """Control: cake_lpr is really checking (a dropped hint, a satisfied hint, a lemma with
    the repeated literal kept are rejected, not accepted)."""
    f = formula(3, [(1, 2), (-1, 3), (-2, -3)])
    for name, proof in [
        ("dropped", b"6 0 4 5 3 0\n"),
        ("satisfied", b"6 0 4 1 5 2 3 0\n"),
        ("no-conflict", b"6 0 4 5 2 0\n"),
    ]:
        result = cake_check(supervisor, cake, tmp_path, f, (1, 2), proof, name)
        assert ck.clean_rejection(result), (name, result)
    g = formula(3, [(1, 1, 2), (-2,), (-1, 3), (-3,)])
    unrestated = b"5 0 2 4 1 3 0\n"
    result = cake_check(supervisor, cake, tmp_path, g, (), unrestated, "unrestated")
    assert ck.clean_rejection(result)


def random_sat_formula(rng: random.Random) -> tuple[int, list[tuple[int, ...]]]:
    while True:
        variables = rng.randint(0, 9)
        clauses = []
        for _ in range(rng.randint(0, 3 * variables)):
            size = rng.randint(1, 3)
            clauses.append(
                tuple(rng.choice((-1, 1)) * rng.randint(1, variables) for _ in range(size))
            )
        if brute_force_satisfiable(variables, clauses, ()):
            return variables, clauses


def test_real_cadical_models_are_complete_models(
    supervisor: Supervisor, cadical: PinnedBinary, tmp_path: Path
) -> None:
    rng = random.Random(20261008)
    for number in range(40):
        variables, clauses = random_sat_formula(rng)
        if number == 0:
            variables, clauses = 0, []
        if number == 1:
            variables, clauses = 5, [(1, 2)]  # variables 3..5 occur nowhere
        f = formula(variables, clauses)
        cnf_path = tmp_path / f"s{number}.cnf"
        cnf_path.write_bytes(f.data)
        spec = Launch(
            binary=cadical,
            args=("-q", str(cnf_path)),
            cwd=str(tmp_path),
            memory_bytes=1 << 30,
            stdout_capture=1 << 20,
            deadline_ms=60_000,
        )
        process = run(supervisor, spec)
        assert process.result.exit == 10 and process.stdout is not None
        result = solver_model(process.stdout, f, ())
        assert result.model_error is None, (variables, clauses, process.stdout, result)
        assert result.assignment is not None
        values = decode_assignment(result.assignment, variables)
        assert satisfies(clauses, (), values)
        # the same output judged against a cube it violates is a violated model
        if variables:
            literal = -1 if values[0] else 1
            wrong = solver_model(process.stdout, f, (literal,))
            assert wrong.model_error is ModelError.VIOLATED
            assert wrong.violated_clause == f.clauses + 1


@pytest.mark.parametrize("directory", ["wörk", "tab\tdir", "plain"])
@pytest.mark.parametrize("quiet", [False, True])
def test_cadical_banner_with_a_non_ascii_or_tab_path_is_a_model(
    supervisor: Supervisor, cadical: PinnedBinary, tmp_path: Path, directory: str, quiet: bool
) -> None:
    """Campaign solver argv need not contain -q; then CaDiCaL echoes the input path in a
    comment line. A non-ASCII or TAB byte there must not make a valid model INVALID_MODEL."""
    work = tmp_path / directory
    work.mkdir()
    clauses = [(1, 2), (-1, 3), (-2, -3, 4)]
    f = formula(4, clauses)
    cnf_path = work / "n.cnf"
    cnf_path.write_bytes(f.data)
    spec = Launch(
        binary=cadical,
        args=(("-q",) if quiet else ()) + (str(cnf_path),),
        cwd=str(work),
        memory_bytes=1 << 30,
        stdout_capture=1 << 20,
        deadline_ms=60_000,
    )
    process = run(supervisor, spec)
    assert process.result.exit == 10 and process.stdout is not None
    if not quiet:
        # the precondition of this test: the banner really carries the path bytes
        assert str(cnf_path).encode() in process.stdout
    result = solver_model(process.stdout, f, ())
    assert result.model_error is None, (process.stdout, result)
    assert result.assignment is not None
    assert satisfies(clauses, (), decode_assignment(result.assignment, 4))


def test_unit_routes_agree_with_cadical(
    supervisor: Supervisor, cadical: PinnedBinary, tmp_path: Path
) -> None:
    """A unit-v1 conflict is UNSAT for CaDiCaL; a complete propagation is SAT for it."""
    seen = set()
    for number, (variables, clauses, cube) in enumerate(random_cases(4242, 150)):
        f = formula(variables, clauses)
        answer = up.drive(unit_steps(f, cube))
        if answer.route is UnitRoute.UNDECIDED:
            continue
        seen.add(answer.route)
        cnf_path = tmp_path / f"r{number}.cnf"
        cnf_path.write_bytes(cube_cnf_bytes(f, cube))
        spec = Launch(
            binary=cadical,
            args=("-q", str(cnf_path)),
            cwd=str(tmp_path),
            memory_bytes=1 << 30,
            stdout_capture=1 << 20,
            deadline_ms=60_000,
        )
        exit_code = run(supervisor, spec).result.exit
        assert exit_code == (20 if answer.route is UnitRoute.PROOF else 10), (
            variables,
            clauses,
            cube,
        )
    assert seen == {UnitRoute.PROOF, UnitRoute.MODEL}
