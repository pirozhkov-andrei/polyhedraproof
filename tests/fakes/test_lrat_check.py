"""The test-only LRAT validator accepts valid RUP proofs and rejects everything else."""

from __future__ import annotations

import random
import subprocess
import sys
from pathlib import Path

import pytest

from fakes.cnf_model import Cnf, brute_force_model, dimacs, pigeonhole
from fakes.lrat_check import (
    SUCCESS,
    LratError,
    Step,
    check,
    check_files,
    decision_tree_proof,
    encode_binary,
    encode_text,
    parse_binary,
    parse_proof,
    parse_text,
)

TESTS = Path(__file__).resolve().parents[1]
#: (1 2)(1 -2)(-1 2)(-1 -2): every assignment of two variables is excluded.
SQUARE = Cnf(2, ((1, 2), (1, -2), (-1, 2), (-1, -2)))
SQUARE_PROOF = b"5 1 0 1 2 0\n6 0 5 3 4 0\n"


def test_a_hand_written_proof_is_verified() -> None:
    result = check(SQUARE, SQUARE_PROOF)
    assert result.verified, result.reason
    assert result.steps == 2


def test_text_and_binary_encodings_parse_to_the_same_steps() -> None:
    steps = parse_text(SQUARE_PROOF)
    assert steps == [Step("add", 5, (1,), (1, 2)), Step("add", 6, (), (5, 3, 4))]
    assert parse_binary(encode_binary(steps)) == steps
    assert parse_text(encode_text(steps)) == steps
    assert parse_proof(encode_binary(steps)) == steps
    assert check(SQUARE, encode_binary(steps)).verified


def test_the_cadical_binary_encoding_of_the_tiniest_proof() -> None:
    # CaDiCaL 3.0.1 `--lrat` on p cnf 1 2 / 1 0 / -1 0 writes exactly these bytes.
    data = bytes.fromhex("610600020400")
    assert parse_binary(data) == [Step("add", 3, (), (1, 2))]
    assert encode_binary(parse_binary(data)) == data
    assert check(Cnf(1, ((1,), (-1,))), data).verified


def test_large_values_use_several_varint_bytes() -> None:
    steps = [Step("add", 300, (-200, 70), (1, 299)), Step("delete", 0, (), (299, 1))]
    assert parse_binary(encode_binary(steps)) == steps


def test_deletions_are_applied() -> None:
    proof = b"5 1 0 1 2 0\n5 d 1 2 0\n6 0 5 3 4 0\n"
    assert check(SQUARE, proof).verified
    reused = b"5 1 0 1 2 0\n5 d 1 2 0\n6 0 1 3 4 0\n"
    result = check(SQUARE, reused)
    assert not result.verified
    assert "hint 1 is not an active clause" in result.reason
    twice = b"5 d 1 0\n5 d 1 0\n"
    assert "deletes inactive clause 1" in check(SQUARE, twice).reason


@pytest.mark.parametrize(
    ("proof", "reason"),
    [
        (b"", "empty clause not derived"),
        (b"5 1 0 1 2 0\n", "empty clause not derived"),
        (b"5 1 0 1 0\n", "hints do not reach a conflict"),
        (b"5 1 0 3 0\n", "hint 3 is satisfied"),
        (b"5 0 1 0\n", "hint 1 is not unit"),
        (b"5 1 0 -1 0\n", "RAT hint -1 is not supported"),
        (b"5 1 0 9 0\n", "hint 9 is not an active clause"),
        (b"4 1 0 1 2 0\n", "id 4 is not increasing"),
        (b"5 1 0 1 2 0\n5 0 5 3 4 0\n", "id 5 is not increasing"),
        (b"5 3 0 1 0\n", "literal out of range"),
        (b"5 1 0 1 2\n", "missing 0 terminator"),
        (b"5 1 0 1 2 0 7\n", "values after the hint list"),
        (b"5 d 1 0 2\n", "values after the deletion list"),
        (b"five 1 0 1 2 0\n", "not an integer list"),
        (b"\xff\n", "not ASCII"),
        (b"a\x0a\x02", "truncated binary proof"),
        (b"a\x0a\x01\x00\x00", "encoded value -0"),
        (b"a\x06\x00\x02\x04\x00x", "unknown binary tag"),
        (b"a\x00\x00", "addition without a positive id"),
    ],
)
def test_bad_proofs_are_rejected_with_a_reason(proof: bytes, reason: str) -> None:
    result = check(SQUARE, proof)
    assert not result.verified
    assert reason in result.reason


def test_parse_errors_are_lrat_errors() -> None:
    with pytest.raises(LratError):
        parse_text(b"1 2\n")
    with pytest.raises(LratError):
        parse_binary(b"a\x80")


def test_a_tautological_lemma_needs_no_hints() -> None:
    assert check(SQUARE, b"5 1 -1 0 0\n6 1 0 1 2 0\n7 0 6 3 4 0\n").verified


def test_an_early_conflict_ends_the_chain() -> None:
    assert check(SQUARE, b"5 1 0 1 2 3 0\n6 0 5 3 4 0\n").verified


def test_a_formula_with_the_empty_clause_is_refuted_by_any_proof() -> None:
    assert check(Cnf(1, ((1,), ())), b"").verified


@pytest.mark.parametrize("holes", [1, 2, 3])
def test_decision_tree_proofs_of_pigeonhole_formulas(holes: int) -> None:
    cnf = pigeonhole(holes)
    steps = decision_tree_proof(cnf)
    assert check(cnf, encode_text(steps)).verified
    assert check(cnf, encode_binary(steps)).verified


def test_the_decision_tree_proof_refuses_a_satisfiable_formula() -> None:
    with pytest.raises(ValueError, match="satisfiable"):
        decision_tree_proof(Cnf(2, ((1, 2), (-1,))))


def _random_cnf(rng: random.Random, variables: int, clauses: int) -> Cnf:
    out = []
    for _ in range(clauses):
        chosen = rng.sample(range(1, variables + 1), k=min(3, variables))
        out.append(tuple(v if rng.random() < 0.5 else -v for v in chosen))
    return Cnf(variables, tuple(out))


def test_random_formulas_valid_proofs_verify_and_unsound_ones_do_not() -> None:
    """Soundness on random instances: weakening the formula to a satisfiable one (one clause
    replaced by a tautology, clause ids unchanged) must make the same proof fail."""
    rng = random.Random(20261003)
    unsat = 0
    for _ in range(400):
        cnf = _random_cnf(rng, rng.randint(3, 6), rng.randint(8, 28))
        if brute_force_model(cnf) is not None:
            continue
        unsat += 1
        steps = decision_tree_proof(cnf)
        proof = encode_text(steps)
        assert check(cnf, proof).verified
        for index in range(len(cnf.clauses)):
            weakened = list(cnf.clauses)
            weakened[index] = (1, -1)
            weaker = Cnf(cnf.variables, tuple(weakened))
            if brute_force_model(weaker) is not None:
                assert not check(weaker, proof).verified
    assert unsat >= 60


def test_check_files_reports_unreadable_inputs(tmp_path: Path) -> None:
    (tmp_path / "f.cnf").write_bytes(dimacs(SQUARE))
    (tmp_path / "p.lrat").write_bytes(SQUARE_PROOF)
    assert check_files(tmp_path / "f.cnf", tmp_path / "p.lrat").verified
    assert "formula" in check_files(tmp_path / "x.cnf", tmp_path / "p.lrat").reason
    assert "proof" in check_files(tmp_path / "f.cnf", tmp_path / "x.lrat").reason
    (tmp_path / "bad.cnf").write_bytes(b"p cnf 1 1\n")
    assert "formula" in check_files(tmp_path / "bad.cnf", tmp_path / "p.lrat").reason


def test_the_command_line_answers_like_cake_lpr(tmp_path: Path) -> None:
    (tmp_path / "f.cnf").write_bytes(dimacs(SQUARE))
    (tmp_path / "good.lrat").write_bytes(SQUARE_PROOF)
    (tmp_path / "bad.lrat").write_bytes(b"5 1 0 1 0\n")
    command = [sys.executable, "-m", "fakes.lrat_check", "--CML_HEAP_SIZE=64"]

    def run(*paths: Path) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(
            [*command, *map(str, paths)], cwd=TESTS, capture_output=True, check=False
        )

    good = run(tmp_path / "f.cnf", tmp_path / "good.lrat")
    assert (good.returncode, good.stdout, good.stderr) == (0, SUCCESS, b"")
    bad = run(tmp_path / "f.cnf", tmp_path / "bad.lrat")
    assert (bad.returncode, bad.stdout) == (0, b"")
    assert bad.stderr.startswith(b"c Checking failed: ")
    assert run(tmp_path / "f.cnf").returncode == 2
