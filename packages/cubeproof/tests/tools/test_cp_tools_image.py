"""Real tiny cases with the pinned CaDiCaL and cake_lpr (``image`` tier).

The tools come from ``POLYHEDRAPROOF_TEST_TOOLS`` (the test image, or a prefix built by
``docker/test/pinned_tools.py build``); an absent or unrecorded prefix fails, it never skips.
Recipes for arena and memory failures are those of ``tests/image/test_presets_match_tools.py``.
"""

from __future__ import annotations

import hashlib
import signal
import time
from pathlib import Path
from typing import Any

import pytest
from cp_tools_support import (  # noqa: F401 - the two fixtures are registered by import
    fixture_files,
    isolation_fixture,
    launch,
    linux_only,
    supervisor_fixture,
)

from cubeproof.base.process import Cause
from cubeproof.contracts.enums import Outcome
from cubeproof.tools import checker as ck
from cubeproof.tools import known_answer
from cubeproof.tools import machinery as mc
from cubeproof.tools import solver as sv
from cubeproof.tools.checker import Arena
from cubeproof.tools.isolation import PinnedBinary
from cubeproof.tools.process import ProcessRun, Supervisor
from cubeproof.tools.process_outcome import (
    Action,
    ArenaLimits,
    CheckFacts,
    SolveFacts,
    classify,
)
from fakes.cnf_model import dimacs, pigeonhole
from image.pinned import Pinned, ToolsUnavailable, locate

pytestmark = [pytest.mark.image, linux_only]

LIMITS = ArenaLimits(max_heap_mib=8192, max_stack_mib=2048)


@pytest.fixture(scope="module")
def pinned() -> Pinned:
    try:
        return locate()
    except ToolsUnavailable as error:
        pytest.fail(str(error), pytrace=False)


@pytest.fixture(scope="module")
def cadical(pinned: Pinned) -> PinnedBinary:
    return PinnedBinary.pinned(
        str(pinned.cadical), hashlib.sha256(pinned.cadical.read_bytes()).hexdigest()
    )


@pytest.fixture(scope="module")
def cake(pinned: Pinned) -> PinnedBinary:
    return PinnedBinary.measure(str(pinned.cake_lpr))


def run(supervisor: Supervisor, spec: Any) -> ProcessRun:
    process = supervisor.start(spec)
    limit = time.monotonic() + 300
    while process.run is None:
        assert time.monotonic() < limit, "a real tool did not finish in 300 s"
        supervisor.step(50)
    return process.run


def chain(directory: Path, n: int) -> tuple[Path, Path]:
    """The arena recipe: one LRAT step with n+1 hints, arena-hungry at small sizes."""
    cnf = directory / f"chain{n}.cnf"
    lines = [f"p cnf {n} {n + 1}", " ".join(str(i) for i in range(1, n + 1)) + " 0"]
    lines += [f"-{i} 0" for i in range(1, n + 1)]
    cnf.write_text("\n".join(lines) + "\n", encoding="ascii")
    proof = directory / f"chain{n}.lrat"
    hints = " ".join(str(i) for i in range(2, n + 2))
    proof.write_text(f"{n + 2} 0 {hints} 1 0\n", encoding="ascii")
    return cnf, proof


def check(
    supervisor: Supervisor, cake: PinnedBinary, cnf: Path, proof: Path, heap: int, stack: int
) -> CheckFacts:
    spec = launch(
        cake,
        ck.checker_args(heap, stack, str(cnf), str(proof)),
        cnf.parent,
        memory_bytes=ck.checker_memory_bytes(heap, stack, 256),
    )
    return CheckFacts(run=run(supervisor, spec), heap_mib=heap, stack_mib=stack)


def test_real_unsat_is_verified(
    supervisor: Supervisor, cadical: PinnedBinary, cake: PinnedBinary, tmp_path: Path
) -> None:
    cnf = tmp_path / "unsat.cnf"
    cnf.write_bytes(fixture_files.fixture("unsat.cnf").read_bytes())
    proof = tmp_path / "unsat.lrat"
    spec = launch(
        cadical,
        sv.solver_args(["--lrat", "--no-binary"], str(cnf), str(proof)),
        tmp_path,
        memory_bytes=1 << 30,
        file_bytes=1 << 20,
        watch=(str(proof), 1 << 20),
    )
    solve = SolveFacts(run=run(supervisor, spec), proof_complete=proof.is_file())
    assert solve.run.result.exit == 20
    assert classify(solve=solve, checks=[], limits=LIMITS).action is Action.CHECK
    checks = [check(supervisor, cake, cnf, proof, 512, 256)]
    decision = classify(solve=solve, checks=checks, limits=LIMITS)
    assert (decision.action, decision.outcome) == (Action.RECORD, Outcome.VERIFIED_UNSAT)
    assert ck.accepts(checks[0].run.result)


def test_real_sat_goes_to_model_parsing(
    supervisor: Supervisor, cadical: PinnedBinary, tmp_path: Path
) -> None:
    cnf = tmp_path / "sat.cnf"
    cnf.write_bytes(fixture_files.fixture("sat.cnf").read_bytes())
    spec = launch(
        cadical,
        sv.solver_args(["--lrat"], str(cnf), str(tmp_path / "p.lrat")),
        tmp_path,
        memory_bytes=1 << 30,
        stdout_capture=1 << 20,
    )
    solve = SolveFacts(run=run(supervisor, spec), proof_complete=False)
    assert solve.run.result.exit == 10
    assert classify(solve=solve, checks=[], limits=LIMITS).action is Action.PARSE_MODEL
    assert solve.run.stdout is not None and b"\nv " in b"\n" + solve.run.stdout


def test_the_pinned_checker_passes_its_known_answer_control(
    supervisor: Supervisor, cake: PinnedBinary, tmp_path: Path
) -> None:
    """The four questions of ``cubeproof.tools.known_answer`` with the real cake_lpr: it accepts
    the refutation and rejects the three others cleanly, so a session may start with it."""
    known_answer.check_checker(supervisor, cake, str(tmp_path))
    assert list(tmp_path.iterdir()) == []


def test_real_rejection(supervisor: Supervisor, cake: PinnedBinary, tmp_path: Path) -> None:
    cnf = fixture_files.fixture("unsat.cnf")
    proof = fixture_files.fixture("bad-hint.lrat")
    checks = [check(supervisor, cake, cnf, proof, 512, 256)]
    assert ck.clean_rejection(checks[0].run.result)
    decision = classify(solve=None, checks=checks, limits=LIMITS)
    assert (decision.outcome, decision.reason) == (Outcome.CHECK_REJECTED, "rejected")


@pytest.mark.parametrize(
    ("kind", "n", "heap", "stack"), [("heap", 5000, 1, 64), ("stack", 20000, 64, 1)]
)
def test_real_arena_exhaustion_retries_until_success(
    supervisor: Supervisor,
    cake: PinnedBinary,
    tmp_path: Path,
    kind: str,
    n: int,
    heap: int,
    stack: int,
) -> None:
    cnf, proof = chain(tmp_path, n)
    checks = [check(supervisor, cake, cnf, proof, heap, stack)]
    assert ck.arena_diagnostic(checks[0].run.result) is Arena(kind)
    while True:
        decision = classify(solve=None, checks=checks, limits=LIMITS)
        if decision.action is not Action.RETRY_CHECK:
            break
        assert decision.arena is not None
        checks.append(check(supervisor, cake, cnf, proof, *decision.arena))
        assert len(checks) < 16
    assert (decision.outcome, decision.reason) == (Outcome.VERIFIED_UNSAT, None)


def test_real_allocation_failure_is_the_combined_arena(
    supervisor: Supervisor, cake: PinnedBinary, tmp_path: Path
) -> None:
    cnf = fixture_files.fixture("unsat.cnf")
    proof = fixture_files.fixture("unsat.lrat")
    spec = launch(
        cake, ck.checker_args(4096, 256, str(cnf), str(proof)), tmp_path, memory_bytes=300 << 20
    )
    value = run(supervisor, spec).result
    assert ck.arena_diagnostic(value) is Arena.BOTH


def test_real_proof_cap_is_proof_size(
    supervisor: Supervisor, cadical: PinnedBinary, tmp_path: Path
) -> None:
    cnf = tmp_path / "php7.cnf"
    cnf.write_bytes(dimacs(pigeonhole(7)))
    proof = tmp_path / "php7.lrat"
    spec = launch(
        cadical,
        sv.solver_args(["--lrat"], str(cnf), str(proof)),
        tmp_path,
        memory_bytes=1 << 30,
        file_bytes=4096,
        watch=(str(proof), 4096),
    )
    solve = SolveFacts(run=run(supervisor, spec), proof_complete=False)
    assert solve.run.result.signal == signal.SIGXFSZ or Cause.PROOF_CAP in solve.run.causes
    decision = classify(solve=solve, checks=[], limits=LIMITS)
    assert (decision.outcome, decision.reason) == (Outcome.EXHAUSTED, "proof_size")


def test_real_deadline_is_time(
    supervisor: Supervisor, cadical: PinnedBinary, tmp_path: Path
) -> None:
    cnf = tmp_path / "php11.cnf"
    cnf.write_bytes(dimacs(pigeonhole(11)))
    proof = tmp_path / "php11.lrat"
    spec = launch(
        cadical,
        sv.solver_args(["--lrat"], str(cnf), str(proof)),
        tmp_path,
        memory_bytes=2 << 30,
        deadline_ms=1000,
        term_grace_ms=5000,
    )
    solve = SolveFacts(run=run(supervisor, spec), proof_complete=False)
    assert solve.run.causes[0] is Cause.DEADLINE
    assert solve.run.result.signal == signal.SIGTERM
    decision = classify(solve=solve, checks=[], limits=LIMITS)
    assert (decision.outcome, decision.reason) == (Outcome.EXHAUSTED, "time")


def test_real_bad_alloc_is_solver_memory(
    supervisor: Supervisor, cadical: PinnedBinary, tmp_path: Path
) -> None:
    cnf = tmp_path / "php8.cnf"
    cnf.write_bytes(dimacs(pigeonhole(8)))
    seen = []
    for megabytes in range(2, 65):
        spec = launch(cadical, ("-q", str(cnf)), tmp_path, memory_bytes=megabytes << 20)
        value = run(supervisor, spec).result
        seen.append((megabytes, value.exit, value.signal))
        if value.exit == 127 and "error while loading shared libraries" in value.stderr_tail:
            continue
        solve = SolveFacts(run=ProcessRun(result=value, causes=()), proof_complete=False)
        decision = classify(solve=solve, checks=[], limits=LIMITS)
        assert (decision.outcome, decision.reason) == (Outcome.EXHAUSTED, "solver_memory"), seen
        return
    pytest.fail(f"CaDiCaL never started below 64 MiB: {seen}")


def test_real_version_probe(supervisor: Supervisor, cadical: PinnedBinary, pinned: Pinned) -> None:
    version = mc.solver_version(supervisor, cadical, str(pinned.prefix))
    assert version == pinned.pin("cadical")["version"]
