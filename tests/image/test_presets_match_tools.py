"""The fakes' constants are what the pinned binaries really print and return (``image``).

``fakes.presets`` lets process tests run without the real tools; this module keeps it honest:
every constant a preset emits is produced here by the real cake_lpr or CaDiCaL and compared
byte for byte. If an image rebuild changes an output, these tests fail before any process
test can rely on a stale fake.
"""

from __future__ import annotations

import shutil
import signal
import subprocess
import time
from pathlib import Path

import pytest

from fakes import fixture_files
from fakes import presets as p
from fakes import toolkit as fk
from fakes.cnf_model import dimacs, pigeonhole
from image.pinned import Pinned

pytestmark = pytest.mark.image

TIMEOUT = 120
PRLIMIT = shutil.which("prlimit")
needs_prlimit = pytest.mark.skipif(PRLIMIT is None, reason="needs util-linux prlimit")


def run(*command: str | Path) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [str(part) for part in command], capture_output=True, timeout=TIMEOUT, check=False
    )


def chain(directory: Path, n: int) -> tuple[Path, Path]:
    """``x1 or ... or xn`` and ``not xi`` for every i, with its one-step LRAT refutation.

    The single step has n+1 hints: cheap to write, yet it needs a large stack and heap,
    so it triggers cake_lpr's arena diagnostics at small arena sizes.
    """
    cnf = directory / f"chain{n}.cnf"
    lines = [f"p cnf {n} {n + 1}", " ".join(str(i) for i in range(1, n + 1)) + " 0"]
    lines += [f"-{i} 0" for i in range(1, n + 1)]
    cnf.write_text("\n".join(lines) + "\n", encoding="ascii")
    proof = directory / f"chain{n}.lrat"
    hints = " ".join(str(i) for i in range(2, n + 2))
    proof.write_text(f"{n + 2} 0 {hints} 1 0\n", encoding="ascii")
    return cnf, proof


def outcome(result: subprocess.CompletedProcess[bytes]) -> tuple[int, bytes, bytes]:
    return result.returncode, result.stdout, result.stderr


# -- checker ------------------------------------------------------------------------------


def test_success_is_exactly_the_preset_line(pinned: Pinned) -> None:
    cnf, proof = fixture_files.fixture("unsat.cnf"), fixture_files.fixture("unsat.lrat")
    assert outcome(run(pinned.cake_lpr, cnf, proof)) == (0, p.CHECKER_SUCCESS, b"")


def test_rejection_matches_the_preset(pinned: Pinned, tmp_path: Path) -> None:
    cnf, proof = fixture_files.fixture("unsat.cnf"), fixture_files.fixture("bad-hint.lrat")
    real = run(pinned.cake_lpr, cnf, proof)
    tool = fk.make_tool(tmp_path, "cake_lpr", p.checker_reject())
    fake = run(tool.path, cnf, proof)
    assert outcome(real) == outcome(fake)
    assert real.returncode == p.CAKE_REJECTION_EXIT


def test_heap_exhaustion_matches_the_preset(pinned: Pinned, tmp_path: Path) -> None:
    cnf, proof = chain(tmp_path, 5000)
    real = run(pinned.cake_lpr, "--CML_HEAP_SIZE=1", "--CML_STACK_SIZE=64", cnf, proof)
    assert outcome(real) == (p.CAKE_HEAP_EXHAUSTED[0], b"", p.CAKE_HEAP_EXHAUSTED[1])
    enough = run(pinned.cake_lpr, "--CML_HEAP_SIZE=64", "--CML_STACK_SIZE=64", cnf, proof)
    assert enough.stdout == p.CHECKER_SUCCESS


def test_stack_exhaustion_matches_the_preset(pinned: Pinned, tmp_path: Path) -> None:
    cnf, proof = chain(tmp_path, 20000)
    real = run(pinned.cake_lpr, "--CML_HEAP_SIZE=64", "--CML_STACK_SIZE=1", cnf, proof)
    assert outcome(real) == (p.CAKE_STACK_EXHAUSTED[0], b"", p.CAKE_STACK_EXHAUSTED[1])
    enough = run(pinned.cake_lpr, "--CML_HEAP_SIZE=64", "--CML_STACK_SIZE=64", cnf, proof)
    assert enough.stdout == p.CHECKER_SUCCESS


@needs_prlimit
def test_arena_allocation_failure_matches_the_preset(pinned: Pinned) -> None:
    assert PRLIMIT is not None
    cnf, proof = fixture_files.fixture("unsat.cnf"), fixture_files.fixture("unsat.lrat")
    real = run(
        PRLIMIT, f"--as={300 << 20}", "--", pinned.cake_lpr, "--CML_HEAP_SIZE=4096", cnf, proof
    )
    assert outcome(real) == (p.CAKE_ALLOCATION_FAILED[0], b"", p.CAKE_ALLOCATION_FAILED[1])


# -- solver -------------------------------------------------------------------------------


def test_unsat_and_sat_status_lines_and_exit_codes(pinned: Pinned, tmp_path: Path) -> None:
    unsat = run(pinned.cadical, "-q", "--lrat", fixture_files.fixture("unsat.cnf"), tmp_path / "p")
    assert outcome(unsat) == (p.SOLVER_UNSAT, p.CADICAL_UNSAT_STDOUT, b"")
    sat = run(pinned.cadical, "-q", fixture_files.fixture("sat.cnf"))
    fake = fk.make_tool(tmp_path, "cadical", p.solver_sat([1, 2, 3]))
    assert outcome(sat) == outcome(run(fake.path, fixture_files.fixture("sat.cnf")))
    assert sat.returncode == p.SOLVER_SAT


def test_termination_prints_unknown_and_dies_of_term(pinned: Pinned, tmp_path: Path) -> None:
    cnf = tmp_path / "php11.cnf"
    cnf.write_bytes(dimacs(pigeonhole(11)))
    proof = tmp_path / "php11.blrat"
    child = subprocess.Popen(
        [str(pinned.cadical), "-q", "--lrat", str(cnf), str(proof)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        deadline = time.monotonic() + 30
        while not (proof.exists() and proof.stat().st_size > 0):
            assert child.poll() is None, "CaDiCaL ended before it could be terminated"
            assert time.monotonic() < deadline
            time.sleep(0.05)
        child.send_signal(signal.SIGTERM)
        out, err = child.communicate(timeout=TIMEOUT)
    finally:
        if child.poll() is None:
            child.kill()
            child.wait()
    assert (child.returncode, out, err) == (-signal.SIGTERM, p.CADICAL_TERM_STDOUT, b"")


@needs_prlimit
def test_a_file_size_limit_kills_cadical_by_sigxfsz(pinned: Pinned, tmp_path: Path) -> None:
    """As the ``solver_proof_flood`` preset under ``--fsize``: SIGXFSZ, the file at the cap."""
    assert PRLIMIT is not None
    cnf = tmp_path / "php7.cnf"
    cnf.write_bytes(dimacs(pigeonhole(7)))
    proof = tmp_path / "php7.blrat"
    real = run(PRLIMIT, "--fsize=4096", "--", pinned.cadical, "-q", "--lrat", cnf, proof)
    assert real.returncode == -signal.SIGXFSZ
    assert proof.stat().st_size == 4096


@needs_prlimit
def test_allocation_failure_matches_the_preset(pinned: Pinned, tmp_path: Path) -> None:
    """Raise RLIMIT_AS from below the dynamic loader's needs until CaDiCaL itself starts:
    its first failure must be the C++ runtime's bad_alloc abort of ``solver_out_of_memory``."""
    assert PRLIMIT is not None
    cnf = tmp_path / "php8.cnf"
    cnf.write_bytes(dimacs(pigeonhole(8)))
    seen = []
    for megabytes in range(2, 65):
        real = run(PRLIMIT, f"--as={megabytes << 20}", "--", pinned.cadical, "-q", cnf)
        seen.append((megabytes, real.returncode))
        if real.returncode == 127 and b"error while loading shared libraries" in real.stderr:
            continue
        assert outcome(real) == (-signal.SIGABRT, b"", p.CADICAL_BAD_ALLOC_STDERR), seen
        return
    pytest.fail(f"CaDiCaL never started below 64 MiB: {seen}")
