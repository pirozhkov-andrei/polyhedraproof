"""The pinned real checker and solver on tiny inputs (``image``: needs the pinned tools).

The pinned cake_lpr accepts the tiny valid proofs and rejects the bad ones exactly as the
fixture manifest records; CaDiCaL's models parse and its proofs verify; the independent
test validator never accepts what cake_lpr rejects. Arena sizes are passed explicitly and
kept small, so the tests do not depend on the machine's free memory.
"""

from __future__ import annotations

import hashlib
import random
import subprocess
from pathlib import Path
from typing import Any

import pytest

from faces12_campaign import pins
from fakes import fixture_files
from fakes.cnf_model import Cnf, dimacs, parse_dimacs, parse_model, pigeonhole
from fakes.lrat_check import check, parse_text
from fakes.presets import CADICAL_UNSAT_STDOUT, CHECKER_SUCCESS, SOLVER_SAT, SOLVER_UNSAT
from image.pinned import Pinned, pinned_tools

pytestmark = pytest.mark.image

TIMEOUT = 120
ARENA = ("--CML_HEAP_SIZE=256", "--CML_STACK_SIZE=64")


def run(*command: str | Path) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [str(part) for part in command], capture_output=True, timeout=TIMEOUT, check=False
    )


def cake(pinned: Pinned, cnf: Path, proof: Path) -> subprocess.CompletedProcess[bytes]:
    return run(pinned.cake_lpr, *ARENA, cnf, proof)


def write_cnf(path: Path, cnf: Cnf) -> Path:
    path.write_bytes(dimacs(cnf))
    return path


def test_the_binaries_are_the_recorded_build(pinned: Pinned) -> None:
    assert pinned_tools.verify(pinned.prefix) == []
    for tool in ("cadical", "cake_lpr"):
        assert pinned.record["tools"][tool]["commit"] == pinned.pin(tool)["commit"]
    assert pinned.record["tools"]["cake_lpr"]["sources"] == pinned.pin("cake_lpr")["sources"]


def test_the_binaries_are_the_ones_the_application_pins(pinned: Pinned) -> None:
    """``faces12_campaign.pins`` names the cake_lpr and CaDiCaL of the release by the SHA-256 of
    their binaries; ``campaign init`` and the claim gate rely on it. Oracle: the bytes this
    image built from the pinned sources."""
    assert hashlib.sha256(pinned.cake_lpr.read_bytes()).hexdigest() == pins.RELEASE_CHECKER_SHA256
    assert hashlib.sha256(pinned.cadical.read_bytes()).hexdigest() == pins.RELEASE_SOLVER_SHA256
    assert pinned.pin("cadical")["version"] == pins.RELEASE_SOLVER_VERSION


def test_cadical_reports_the_pinned_version(pinned: Pinned) -> None:
    result = run(pinned.cadical, "--version")
    assert (result.returncode, result.stdout) == (
        0,
        f"{pinned.pin('cadical')['version']}\n".encode(),
    )


@pytest.mark.parametrize("item", fixture_files.of_kind("proof"), ids=lambda item: str(item["file"]))
def test_the_real_checker_on_the_proof_fixtures(pinned: Pinned, item: dict[str, Any]) -> None:
    """Accepts the tiny valid proofs, rejects the bad ones, byte for byte as recorded."""
    result = cake(pinned, fixture_files.fixture(item["cnf"]), fixture_files.fixture(item["file"]))
    expected = item["checker"]
    assert (result.returncode, result.stdout.decode(), result.stderr.decode()) == (
        expected["exit"],
        expected["stdout"],
        expected["stderr"],
    )
    assert (result.stdout == CHECKER_SUCCESS) is item["valid"]


def test_a_missing_proof_file_is_a_clean_unsuccessful_exit(pinned: Pinned, tmp_path: Path) -> None:
    result = cake(pinned, fixture_files.fixture("unsat.cnf"), tmp_path / "absent.lrat")
    assert (result.returncode, result.stdout) == (0, b"")
    assert result.stderr.startswith(b"c Input file: ")


def test_the_proofs_cadical_writes_for_the_fixture(pinned: Pinned, tmp_path: Path) -> None:
    cnf = fixture_files.fixture("unsat.cnf")
    text = run(pinned.cadical, "-q", "--lrat", "--no-binary", cnf, tmp_path / "p.lrat")
    binary = run(pinned.cadical, "-q", "--lrat", cnf, tmp_path / "p.blrat")
    for result in (text, binary):
        assert (result.returncode, result.stdout) == (SOLVER_UNSAT, CADICAL_UNSAT_STDOUT)
    assert (tmp_path / "p.lrat").read_bytes() == fixture_files.fixture("unsat.lrat").read_bytes()
    assert (tmp_path / "p.blrat").read_bytes() == fixture_files.fixture("unsat.blrat").read_bytes()


def test_the_sat_model_fixture_is_cadicals_output_and_parses(pinned: Pinned) -> None:
    cnf_path = fixture_files.fixture("sat.cnf")
    result = run(pinned.cadical, "-q", cnf_path)
    assert result.returncode == SOLVER_SAT
    assert result.stdout == fixture_files.fixture("sat.model").read_bytes()
    model = parse_model(result.stdout, parse_dimacs(cnf_path.read_bytes()))
    assert model == {1: True, 2: True, 3: True}


@pytest.mark.parametrize("holes", [3, 4, 5, 6])
@pytest.mark.parametrize("encoding", ["text", "binary"])
def test_cadical_proofs_verify_with_both_checkers(
    pinned: Pinned, tmp_path: Path, holes: int, encoding: str
) -> None:
    cnf_path = write_cnf(tmp_path / "php.cnf", pigeonhole(holes))
    proof = tmp_path / "php.proof"
    options = ["--no-binary"] if encoding == "text" else []
    result = run(pinned.cadical, "-q", "--lrat", *options, cnf_path, proof)
    assert (result.returncode, result.stdout) == (SOLVER_UNSAT, CADICAL_UNSAT_STDOUT)
    verdict = cake(pinned, cnf_path, proof)
    assert (verdict.returncode, verdict.stdout, verdict.stderr) == (0, CHECKER_SUCCESS, b"")
    assert check(pigeonhole(holes), proof.read_bytes()).verified


def test_the_test_validator_never_accepts_what_cake_lpr_rejects(
    pinned: Pinned, tmp_path: Path
) -> None:
    """Seeded corruptions of a real proof: validator acceptance implies cake_lpr acceptance.

    The validator is stricter than cake_lpr on purpose (for example on satisfied hints), so
    only the implication is required; dropping the final step must fail in both.
    """
    cnf = pigeonhole(4)
    cnf_path = write_cnf(tmp_path / "php4.cnf", cnf)
    original = tmp_path / "php4.lrat"
    result = run(pinned.cadical, "-q", "--lrat", "--no-binary", cnf_path, original)
    assert result.returncode == SOLVER_UNSAT
    lines = original.read_bytes().decode("ascii").splitlines(keepends=True)
    additions = [i for i, line in enumerate(lines) if " d " not in line]
    rng = random.Random(20261004)
    variants: list[tuple[str, bytes]] = [("no final step", "".join(lines[:-1]).encode())]
    for index in rng.sample(additions, k=min(12, len(additions))):
        tokens = lines[index].split()
        hints_start = tokens.index("0") + 1
        if len(tokens) - hints_start > 1:
            dropped = tokens[:hints_start] + tokens[hints_start + 1 :]
            changed = [*lines[:index], " ".join(dropped) + "\n", *lines[index + 1 :]]
            variants.append((f"line {index}: first hint dropped", "".join(changed).encode()))
        renamed = [*tokens[:hints_start], "999999", *tokens[hints_start:]]
        changed = [*lines[:index], " ".join(renamed) + "\n", *lines[index + 1 :]]
        variants.append((f"line {index}: unknown hint first", "".join(changed).encode()))
    final = parse_text(lines[-1].encode())
    assert len(final) == 1 and final[0].kind == "add" and final[0].lemma == ()
    assert check(cnf, original.read_bytes()).verified
    assert len(variants) > 12
    for name, data in variants:
        path = tmp_path / "variant.lrat"
        path.write_bytes(data)
        real = cake(pinned, cnf_path, path)
        ours = check(cnf, data)
        assert real.returncode == 0, name
        if ours.verified:
            assert real.stdout == CHECKER_SUCCESS, f"{name}: validator accepts, cake_lpr does not"
        if name == "no final step":
            assert (real.stdout, ours.verified) == (b"", False)


def test_cake_lpr_may_accept_a_binary_proof_without_its_last_byte(
    pinned: Pinned, tmp_path: Path
) -> None:
    """Observed leniency: completeness of a proof file cannot be read off the checker; it
    comes from the solver's exit 20 and a closed proof file (specification §6.1, §6.3)."""
    cnf_path = write_cnf(tmp_path / "php6.cnf", pigeonhole(6))
    proof = tmp_path / "php6.blrat"
    assert run(pinned.cadical, "-q", "--lrat", cnf_path, proof).returncode == SOLVER_UNSAT
    data = proof.read_bytes()
    proof.write_bytes(data[:-1])
    assert cake(pinned, cnf_path, proof).stdout == CHECKER_SUCCESS
    assert not check(pigeonhole(6), data[:-1]).verified
    proof.write_bytes(data[: len(data) // 2])
    assert cake(pinned, cnf_path, proof).stdout == b""
