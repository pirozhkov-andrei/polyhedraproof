"""Strict canonical DIMACS reader/writer and the explicit external import (specification §3.1)."""

from __future__ import annotations

import hashlib
import random
import sys
from pathlib import Path
from typing import Any

import pytest

from cubeproof.base.errors import ContractError
from cubeproof.cnf.dimacs import (
    Formula,
    canonical_dimacs,
    normalize_external_dimacs,
    parse_dimacs,
)

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "contracts"))
import cp_corpus

CNF = cp_corpus.vectors("cnf")


def _plain_dimacs(variables: int, clauses: list[list[int]]) -> bytes:
    """Specification §3.1 written out as the test oracle."""
    lines = [f"p cnf {variables} {len(clauses)}\n"]
    for clause in clauses:
        lines.append(" ".join(str(x) for x in clause) + " 0\n" if clause else " 0\n")
    return "".join(lines).encode("ascii")


def _random_formula(rng: random.Random) -> tuple[int, list[list[int]]]:
    variables = rng.choice([0, 0, 1, 2, 3, 9, 10, 11, 99, 100, 1000, 5257])
    clauses: list[list[int]] = []
    for _ in range(rng.randrange(12)):
        if variables == 0 or rng.random() < 0.1:
            clauses.append([])
            continue
        width = rng.randrange(1, 6)
        clauses.append([rng.randint(1, variables) * rng.choice((1, -1)) for _ in range(width)])
    return variables, clauses


@pytest.mark.parametrize("entry", cp_corpus.documents("dimacs"), ids=lambda e: e["id"])
def test_dimacs_fixtures(entry: dict[str, Any]) -> None:
    data = cp_corpus.fixture_bytes(entry)
    kind, rule = cp_corpus.expectation(entry)
    if kind == "valid":
        formula = parse_dimacs(data)
        assert formula.data == data
        assert formula.sha256 == hashlib.sha256(data).hexdigest()
        assert canonical_dimacs(formula.variables, formula.iter_clauses()) == data
        return
    with pytest.raises(ContractError) as info:
        parse_dimacs(data)
    assert info.value.rule == rule


@pytest.mark.parametrize("vector", CNF["formulas"], ids=lambda f: f["name"])
def test_formula_vectors(vector: dict[str, Any]) -> None:
    formula = parse_dimacs(vector["text"].encode("ascii"))
    assert formula.sha256 == vector["sha256"]
    assert formula.variables == vector["variables"]
    assert formula.clauses == vector["clauses"]
    header = f"p cnf {vector['variables']} {vector['clauses']}\n".encode("ascii")
    assert formula.header_length == len(header)
    assert formula.body == vector["text"].encode("ascii")[len(header) :]


def test_empty_clause_and_empty_formula_conventions() -> None:
    empty = parse_dimacs(b"p cnf 0 0\n")
    assert (empty.variables, empty.clauses, empty.body, list(empty.iter_clauses())) == (
        0,
        0,
        b"",
        [],
    )
    clause = parse_dimacs(b"p cnf 0 1\n 0\n")
    assert list(clause.iter_clauses()) == [()]
    assert canonical_dimacs(0, [()]) == b"p cnf 0 1\n 0\n"
    assert canonical_dimacs(0, []) == b"p cnf 0 0\n"


def test_duplicates_and_tautologies_are_preserved() -> None:
    data = b"p cnf 2 4\n1 1 0\n1 -1 0\n1 1 0\n-2 1 0\n"
    formula = parse_dimacs(data)
    assert list(formula.iter_clauses()) == [(1, 1), (1, -1), (1, 1), (-2, 1)]


@pytest.mark.parametrize(
    ("data", "rule"),
    [
        (b"p cnf 1 1\n1 0\n\xff", "dimacs.clause"),
        (b"p cnf 1 1\n1 0\nx", "dimacs.clause"),
        (b"p cnf 1 1\n-1 0\n1 0\n", "dimacs.count"),
        (b"p cnf 9223372036854775808 0\n", "dimacs.header"),
        (b"p cnf 1 1\n9223372036854775808 0\n", "dimacs.range"),
        (b"p cnf 1 1\n1 0\x00\n", "dimacs.clause"),
        (b"\np cnf 0 0\n", "dimacs.header"),
        (b"p cnf 0 0\n\n", "dimacs.clause"),
        (b"p cnf 2 1\n1 -0 0\n", "dimacs.clause"),
        (b"p cnf 2 1\n- 0\n", "dimacs.clause"),
        (b"p cnf 2 1\n1 2\n", "dimacs.clause"),
        (b"p cnf \xd9\xa3 0\n", "dimacs.header"),
        (b"p cnf 1 1\n\xd9\xa1 0\n", "dimacs.clause"),
    ],
)
def test_more_rejections(data: bytes, rule: str) -> None:
    with pytest.raises(ContractError) as info:
        parse_dimacs(data)
    assert info.value.rule == rule


def test_parse_refuses_text() -> None:
    with pytest.raises(TypeError):
        parse_dimacs("p cnf 0 0\n")  # type: ignore[arg-type]


def test_random_formulas_round_trip_against_the_plain_writer() -> None:
    rng = random.Random(1060)
    for _ in range(1000):
        variables, clauses = _random_formula(rng)
        data = _plain_dimacs(variables, clauses)
        assert canonical_dimacs(variables, clauses) == data
        formula = parse_dimacs(data)
        assert isinstance(formula, Formula)
        assert [list(c) for c in formula.iter_clauses()] == clauses
        assert (formula.variables, formula.clauses) == (variables, len(clauses))


def test_canonical_writer_refuses_invalid_clauses() -> None:
    for variables, clauses in [(1, [[2]]), (1, [[0]]), (1, [[True]]), (-1, []), (1, [[1.0]])]:
        with pytest.raises(ContractError):
            canonical_dimacs(variables, clauses)  # type: ignore[arg-type]


def test_every_accepted_mutation_is_canonical() -> None:
    """Whatever the strict reader accepts re-serializes to exactly the bytes it read."""
    rng = random.Random(1061)
    seeds = [_plain_dimacs(*_random_formula(rng)) for _ in range(80)]
    alphabet = b" \t\r\n0123456789-+pcnf"
    accepted = 0
    for _ in range(8000):
        data = bytearray(rng.choice(seeds))
        for _ in range(rng.randint(1, 2)):
            op = rng.randrange(3)
            pos = rng.randrange(len(data) + 1)
            if op == 0 and data:
                del data[min(pos, len(data) - 1)]
            elif op == 1:
                data.insert(pos, rng.choice(alphabet))
            elif data:
                data[min(pos, len(data) - 1)] = rng.choice(alphabet)
        raw = bytes(data)
        try:
            formula = parse_dimacs(raw)
        except ContractError as error:
            assert error.rule.startswith("dimacs.")
            continue
        accepted += 1
        assert canonical_dimacs(formula.variables, formula.iter_clauses()) == raw
        assert all(abs(x) <= formula.variables for c in formula.iter_clauses() for x in c)
    assert accepted > 100


# -- external import (explicit normalization) -------------------------------------------------


@pytest.mark.parametrize(
    ("source", "canonical"),
    [
        (b"p cnf 1 1\n1 0\n", b"p cnf 1 1\n1 0\n"),
        (b"c comment\np cnf 2 2\n1 -2 0\n2 0\n", b"p cnf 2 2\n1 -2 0\n2 0\n"),
        (b"p  cnf\t3   2 \r\n 1\t2  0 -3\r\n 0\r\n", b"p cnf 3 2\n1 2 0\n-3 0\n"),
        (b"p cnf 3 2\n1 2\n3 0 -1\n0\n", b"p cnf 3 2\n1 2 3 0\n-1 0\n"),
        (b"p cnf 0 1\n0\n", b"p cnf 0 1\n 0\n"),
        (b"p cnf 2 3\n1 1 0 1 -1 0\nc middle comment\n0\n", b"p cnf 2 3\n1 1 0\n1 -1 0\n 0\n"),
        (b"p cnf 5 0\n", b"p cnf 5 0\n"),
        (b"p cnf 0 0", b"p cnf 0 0\n"),
        (b"\xef\xbb\xbfp cnf 1 1\n+1 0\n", b"p cnf 1 1\n1 0\n"),
        (b"p cnf 2 1\n-02 01 0\n", b"p cnf 2 1\n-2 1 0\n"),
    ],
)
def test_external_dimacs_is_normalized_preserving_order(source: bytes, canonical: bytes) -> None:
    assert normalize_external_dimacs(source) == canonical
    parse_dimacs(canonical)


@pytest.mark.parametrize(
    "source",
    [
        b"",
        b"c only a comment\n",
        b"1 0\np cnf 1 1\n",
        b"p cnf 1 1\np cnf 1 1\n1 0\n",
        b"p cnf 1 2\n1 0\n",
        b"p cnf 1 1\n1 0\n-1 0\n",
        b"p cnf 1 1\n2 0\n",
        b"p cnf 1 1\n1\n",
        b"p cnf 1 1\n1 x 0\n",
        b"p cnf 1 1\n1.0 0\n",
        b"p cnf -1 0\n",
        b"p dnf 1 1\n1 0\n",
        b"p cnf 1\n",
        b"p cnf 1 1 1\n1 0\n",
        b"p cnf 1 1\n1 0\n%\n0\n",
        b"p cnf 1 1\n\xff 0\n",
        b"p cnf 1 1\n-0 0\n",
        b"p cnf 1 1\n- 1 0\n",
        # A signed zero is refused even where a plain 0 would make the count match.
        b"p cnf 1 1\n1 -0\n",
        b"p cnf 1 1\n1 +0\n",
        b"p cnf 1 1\n1 -00\n",
        # An unterminated last clause is refused even when the terminated ones match M.
        b"p cnf 1 1\n1 0\n-1\n",
        b"p cnf 1 1\n1 0 -1",
    ],
)
def test_external_dimacs_errors(source: bytes) -> None:
    with pytest.raises(ContractError) as info:
        normalize_external_dimacs(source)
    assert info.value.rule == "dimacs.import"


def test_import_is_identity_on_canonical_input() -> None:
    rng = random.Random(1062)
    for _ in range(300):
        data = _plain_dimacs(*_random_formula(rng))
        assert normalize_external_dimacs(data) == data
