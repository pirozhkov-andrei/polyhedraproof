"""The test-only DIMACS and model helpers."""

from __future__ import annotations

import pytest

from fakes.cnf_model import (
    MODEL_ERRORS,
    Cnf,
    DimacsError,
    ModelError,
    brute_force_model,
    dimacs,
    literals_of,
    model_lines,
    parse_dimacs,
    parse_model,
    pigeonhole,
    violated_clause,
)

SAT = Cnf(3, ((1, 2), (-1, 2), (-2, 3)))


def test_parse_and_write_round_trip() -> None:
    data = b"c comment\np cnf 3 3\n1 2 0\n-1 2 0\n-2 3 0\n"
    cnf = parse_dimacs(data)
    assert cnf == SAT
    assert parse_dimacs(dimacs(cnf)) == cnf
    assert dimacs(cnf) == b"p cnf 3 3\n1 2 0\n-1 2 0\n-2 3 0\n"


def test_clauses_may_span_lines_and_the_empty_clause_is_kept() -> None:
    assert parse_dimacs(b"p cnf 2 2\n1\n2 0 0\n").clauses == ((1, 2), ())
    assert parse_dimacs(b"p cnf 0 0\n") == Cnf(0, ())


@pytest.mark.parametrize(
    "data",
    [
        b"",
        b"1 0\n",
        b"p cnf 2\n",
        b"p dnf 2 1\n1 0\n",
        b"p cnf x 1\n1 0\n",
        b"p cnf -1 0\n",
        b"p cnf 2 2\n1 0\n",
        b"p cnf 2 1\n1 2\n",
        b"p cnf 2 1\n3 0\n",
        b"p cnf 2 1\n1 a 0\n",
        b"p cnf 1 1\n\xff 0\n",
    ],
)
def test_malformed_dimacs_is_rejected(data: bytes) -> None:
    with pytest.raises(DimacsError):
        parse_dimacs(data)


def test_brute_force_and_evaluation() -> None:
    model = brute_force_model(SAT)
    assert model is not None
    assert violated_clause(SAT, model) is None
    assert violated_clause(SAT, {1: False, 2: False, 3: False}) == 0
    with pytest.raises(ValueError, match="too many"):
        brute_force_model(Cnf(30, ()))


@pytest.mark.parametrize("holes", [1, 2, 3])
def test_pigeonhole_formulas_are_unsatisfiable(holes: int) -> None:
    cnf = pigeonhole(holes)
    assert cnf.variables == holes * (holes + 1)
    assert brute_force_model(cnf) is None


def test_model_lines_wrap_and_parse_back() -> None:
    cnf = Cnf(40, ())
    literals = [v if v % 3 else -v for v in range(1, 41)]
    text = model_lines(literals)
    lines = text.decode().splitlines()
    assert lines[0] == "s SATISFIABLE"
    assert len(lines) > 2
    assert all(len(line) <= 78 and line.startswith("v ") for line in lines[1:])
    assert lines[-1].endswith(" 0")
    assert literals_of(parse_model(text, cnf)) == literals


@pytest.mark.parametrize(
    ("output", "kind"),
    [
        (b"s SATISFIABLE\nv 1 2 0\n", "missing"),
        (b"s SATISFIABLE\nv 1 2 -2 3 0\n", "conflicting"),
        (b"s SATISFIABLE\nv 1 2 3 4 0\n", "out_of_range"),
        (b"s SATISFIABLE\nv 1 -4 2 3 0\n", "out_of_range"),
        (b"s SATISFIABLE\nv 1 two 3 0\n", "syntax"),
        (b"s SATISFIABLE\nv 1 2 3\n", "syntax"),
        (b"s SATISFIABLE\nv 1 2 3 0 1\n", "syntax"),
        (b"v 1 2 3 0\n", "syntax"),
        (b"s SATISFIABLE\ns SATISFIABLE\nv 1 2 3 0\n", "syntax"),
        (b"s UNSATISFIABLE\n", "syntax"),
        (b"s SATISFIABLE\nx\nv 1 2 3 0\n", "syntax"),
        (b"s SATISFIABLE\nv 1 2 3 0\n\xff\n", "syntax"),
        (b"s SATISFIABLE\nv -1 -2 3 0\n", "violated"),
    ],
)
def test_bad_models_are_classified(output: bytes, kind: str) -> None:
    with pytest.raises(ModelError) as caught:
        parse_model(output, SAT)
    assert caught.value.kind == kind
    assert kind in MODEL_ERRORS


def test_good_models_parse() -> None:
    assert parse_model(b"s SATISFIABLE\nv 1 2 3 0\n", SAT) == {1: True, 2: True, 3: True}
    repeated = b"c x\ns SATISFIABLE\nv -1 2\nv 2 3\nv 0\n"
    assert parse_model(repeated, SAT) == {1: False, 2: True, 3: True}


def test_unknown_model_error_kinds_are_a_programming_error() -> None:
    with pytest.raises(AssertionError):
        ModelError("weird", "")


def test_cnf_validates_literals() -> None:
    with pytest.raises(DimacsError):
        Cnf(1, ((2,),))
    with pytest.raises(DimacsError):
        Cnf(1, ((0,),))
    with pytest.raises(DimacsError):
        Cnf(-1, ())
