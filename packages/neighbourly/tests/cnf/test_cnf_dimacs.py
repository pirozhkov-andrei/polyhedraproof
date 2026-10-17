"""The canonical producer writer against the contract DIMACS vectors (specification §3.1)."""

from __future__ import annotations

import hashlib
from typing import Any

import pytest
from cnf_corpus import cnf_vectors, document_bytes, reader

from neighbourly.cnf import (
    Builder,
    CnfError,
    check_clauses,
    checked_clause_bytes,
    clause_bytes,
    dimacs_bytes,
    formula_digest,
    header_bytes,
)


def parse_vector(text: str) -> tuple[int, list[list[int]]]:
    """Clauses of a vector, read by hand (the writer under test is not used)."""
    lines = text.split("\n")[:-1]
    variables = int(lines[0].split(" ")[2])
    return variables, [[int(x) for x in line.split(" ")[:-1] if x] for line in lines[1:]]


FORMULAS = {f["name"]: f for f in cnf_vectors()["formulas"]}


@pytest.mark.parametrize("name", sorted(FORMULAS))
def test_the_writer_reproduces_every_formula_vector(name: str) -> None:
    vector = FORMULAS[name]
    variables, clauses = parse_vector(vector["text"])
    assert (variables, len(clauses)) == (vector["variables"], vector["clauses"])
    body = checked_clause_bytes(variables, clauses)
    data = dimacs_bytes(variables, body, len(clauses))
    assert data == vector["text"].encode("ascii")
    assert formula_digest(variables, body, len(clauses)) == vector["sha256"]
    assert hashlib.sha256(data).hexdigest() == vector["sha256"]


def test_the_empty_clause_is_space_zero() -> None:
    assert clause_bytes([()]) == b" 0\n"
    assert dimacs_bytes(0, clause_bytes([[]]), 1) == document_bytes("dimacs-F_clause")
    assert dimacs_bytes(0, b"", 0) == document_bytes("dimacs-F_empty")


@pytest.mark.parametrize(
    "identifier", ["dimacs-duplicates-and-tautology", "dimacs-unsorted-literals-unused-variables"]
)
def test_the_writer_preserves_order_repeats_and_tautologies(identifier: str) -> None:
    """Writing never simplifies: only Builder.add_clause collapses repeats."""
    expected = document_bytes(identifier)
    variables, clauses = parse_vector(expected.decode("ascii"))
    assert dimacs_bytes(variables, checked_clause_bytes(variables, clauses), len(clauses)) == (
        expected
    )


def test_builder_output_is_read_back_by_the_independent_reader() -> None:
    builder = Builder()
    for _ in range(7):
        builder.new_variable()
    builder.assert_xor([1, -2, 3, -4, 5, -6, 7], 1, "x")
    builder.define_and(-1, 2, "a")
    builder.add_clause([], "empty")
    body = clause_bytes(builder.clauses)
    data = dimacs_bytes(builder.variables, body, len(builder.clauses))
    parsed = reader().parse_dimacs(data)
    assert parsed.variables == builder.variables
    assert list(parsed.clauses) == builder.clauses
    assert parsed.sha256 == formula_digest(builder.variables, body, len(builder.clauses))


@pytest.mark.parametrize(
    ("variables", "clauses"),
    [
        (2, [[1, 0]]),
        (2, [[3]]),
        (2, [[-3]]),
        (0, [[1]]),
        (2, [[True]]),
        (2, [[1.0]]),
        (-1, []),
        (True, []),
    ],
)
def test_the_checked_writer_refuses_noncanonical_input(variables: Any, clauses: Any) -> None:
    with pytest.raises(CnfError):
        check_clauses(variables, clauses)
    with pytest.raises(CnfError):
        checked_clause_bytes(variables, clauses)


@pytest.mark.parametrize(("variables", "count"), [(-1, 0), (0, -1), (1.0, 0), (0, False), ("1", 0)])
def test_the_header_refuses_bad_counts(variables: Any, count: Any) -> None:
    with pytest.raises(CnfError):
        header_bytes(variables, count)


def test_the_header_is_exact() -> None:
    assert header_bytes(0, 0) == b"p cnf 0 0\n"
    assert header_bytes(5257, 52177) == b"p cnf 5257 52177\n"
    assert check_clauses(3, [[1], [], [-3, 2]]) == 3
