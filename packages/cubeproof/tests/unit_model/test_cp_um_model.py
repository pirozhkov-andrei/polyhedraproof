"""Model parsing, evaluation and bitsets (specification §4.8, §6.1).

The truth tables compare against brute force; the model fixtures of ``tests/fakes`` (one defect
each) also against the independent test reader ``fakes.cnf_model.parse_model``.
"""

from __future__ import annotations

import base64
import os
import subprocess
import sys
from pathlib import Path

import pytest
from cp_um_support import all_assignments, cnf_model, fixture_files, formula, satisfies

from cubeproof.base.errors import ContractError
from cubeproof.cnf import model as md
from cubeproof.cnf.unit import drive
from cubeproof.contracts.assignment import decode_assignment, encode_assignment
from cubeproof.contracts.enums import ModelError, Outcome

SAT3 = formula(3, [(1, 2), (-1, 2), (-2, 3)])


def out(*lines: str) -> bytes:
    return "".join(line + "\n" for line in lines).encode("ascii")


def literals(values: tuple[bool, ...]) -> list[int]:
    return [i if v else -i for i, v in enumerate(values, start=1)]


def solver_output(values: tuple[bool, ...]) -> bytes:
    return cnf_model.model_lines(literals(values), width=20)


@pytest.mark.parametrize("item", fixture_files.of_kind("model"), ids=lambda i: str(i["file"]))
def test_model_fixtures(item: dict[str, object]) -> None:
    cnf_path = fixture_files.fixture(str(item["cnf"]))
    output = fixture_files.fixture(str(item["file"])).read_bytes()
    f = formula(*_read(cnf_path.read_bytes()))
    result = md.solver_model(output, f, ())
    expected = item["model_error"]
    assert (None if result.model_error is None else result.model_error.value) == expected
    try:
        oracle: dict[int, bool] | None = cnf_model.parse_model(
            output, cnf_model.parse_dimacs(cnf_path.read_bytes())
        )
        oracle_error = None
    except cnf_model.ModelError as error:
        oracle, oracle_error = None, error.kind
    assert oracle_error == expected
    if expected is None:
        assert oracle is not None
        assert result.assignment == encode_assignment([oracle[v] for v in sorted(oracle)])
        assert item["literals"] == literals(decode_assignment(str(result.assignment), 3))


def _read(data: bytes) -> tuple[int, list[tuple[int, ...]]]:
    cnf = cnf_model.parse_dimacs(data)
    return cnf.variables, list(cnf.clauses)


def test_truth_table_of_tiny_formulas_with_cubes() -> None:
    cases = [
        (formula(0, []), ()),
        (formula(0, [()]), ()),
        (formula(2, [()]), (1,)),
        (formula(3, [(1, 2), (-1, 2), (-2, 3)]), ()),
        (formula(3, [(1, 2), (-1, 2), (-2, 3)]), (-1, -3)),
        (formula(4, [(1, -2, 1), (2, -2), (3, 4, -1)]), (2,)),
        (formula(9, [(1, 9), (-9, 5)]), (-5, 8)),
    ]
    for f, cube in cases:
        clauses = list(f.iter_clauses())
        for values in all_assignments(f.variables):
            expected = satisfies(clauses, cube, values)
            for result in (
                md.check_values(f, cube, values),
                md.solver_model(solver_output(values), f, cube),
            ):
                assert result.assignment == encode_assignment(list(values))
                assert (result.model_error is None) is expected
                assert result.outcome is (Outcome.MODEL if expected else Outcome.INVALID_MODEL)
                if not expected:
                    assert result.model_error is ModelError.VIOLATED
                    assert result.reason == "violated"
            assert (md.assignment_violation(f, cube, encode_assignment(list(values))) is None) is (
                expected
            )


def test_violated_names_the_first_false_clause_or_cube_unit() -> None:
    clause = md.check_values(SAT3, (), (True, False, True))
    assert clause.model_error is ModelError.VIOLATED and clause.violated_clause == 2
    assert clause.assignment == "BQ=="
    unit = md.check_values(SAT3, (-3,), (True, True, True))
    assert unit.violated_clause == 4 and "cube unit 4" in unit.detail
    assert unit.assignment == "Bw=="


def test_empty_formula_and_empty_clause() -> None:
    empty = md.solver_model(out("s SATISFIABLE", "v 0"), formula(0, []), ())
    assert (empty.assignment, empty.model_error) == ("", None)
    clause = md.solver_model(out("s SATISFIABLE", "v 0"), formula(0, [()]), ())
    assert (clause.assignment, clause.model_error, clause.violated_clause) == (
        "",
        ModelError.VIOLATED,
        1,
    )


@pytest.mark.parametrize("variables", [0, 1, 7, 8, 9, 15, 16, 17, 64])
def test_padding_and_unused_bits(variables: int) -> None:
    f = formula(variables, [])
    every = tuple(True for _ in range(variables))
    result = md.solver_model(solver_output(every), f, ())
    assert result.assignment is not None
    raw = base64.b64decode(result.assignment)
    assert len(raw) == (variables + 7) // 8
    if variables % 8:
        assert raw[-1] >> (variables % 8) == 0  # unused high bits stay zero
    assert decode_assignment(result.assignment, variables) == every


def test_complete_model_with_comments_wrapping_and_repeated_values() -> None:
    output = out(
        "c CaDiCaL banner",
        "c",
        "s SATISFIABLE",
        "v -1 2",
        "c interleaved comment",
        "v 2 3 -1",
        "v 0",
        "c after the values",
    )
    result = md.solver_model(output, SAT3, ())
    assert (result.assignment, result.model_error) == ("Bg==", None)


SYNTAX = [
    b"",
    b"s SATISFIABLE\n",  # no values, no terminator
    b"s SATISFIABLE\nv 1 2 3\n",  # not terminated
    b"s SATISFIABLE\nv 1 2 3 0",  # no final LF
    b"v 1 2 3 0\n",  # no status
    b"v 1 2 3 0\ns SATISFIABLE\n",  # values before the status
    b"s SATISFIABLE\ns SATISFIABLE\nv 1 2 3 0\n",
    b"s UNSATISFIABLE\nv 1 2 3 0\n",
    b"s SATISFIABLE\nv 1 2 3 0 4\n",  # value after 0
    b"s SATISFIABLE\nv 1 2 0\nv 3 0\n",
    b"s SATISFIABLE\nv 1 2 3 0\nv 0\n",  # a value line after the terminator
    b"s SATISFIABLE\nv 1 2 3 0\nv\n",  # even an empty one
    b"s SATISFIABLE\nv 1 2 3 0 0\n",
    b"s SATISFIABLE\nv +1 2 3 0\n",
    b"s SATISFIABLE\nv 01 2 3 0\n",
    b"s SATISFIABLE\nv -0 1 2 3 0\n",
    b"s SATISFIABLE\nv 1  2 3 0\n",
    b"s SATISFIABLE\nv 1 2 3 0 \n",
    b"s SATISFIABLE\nv\t1 2 3 0\n",
    b"s SATISFIABLE\r\nv 1 2 3 0\r\n",
    b"s SATISFIABLE\nv 1 2 3 0\r\n",  # CR in a value line
    b"s SATISFIABLE \nv 1 2 3 0\n",
    b"s SATISFIABLE\xc3\xa9\nv 1 2 3 0\n",  # non-ASCII in the status line
    b"s SATISFIABLE\nv 1 2 3\xc3\xa9 0\n",  # non-ASCII in a value line
    b"s SATISFIABLE\nv 1 2 3 0\n\n",  # blank line
    b"s SATISFIABLE\nvalues 1 2 3 0\n",
    b"s SATISFIABLE\nv 1 two 3 0\n",
    b"cX\ns SATISFIABLE\nv 1 2 3 0\n",
    b"c\tTAB is not the comment separator\ns SATISFIABLE\nv 1 2 3 0\n",
    b"c\xc3\xa9\ns SATISFIABLE\nv 1 2 3 0\n",  # a comment needs the space after c
]

#: Comment text is opaque (any bytes except LF): a solver banner that echoes a user's
#: non-ASCII or TAB path (CaDiCaL without -q) must not turn a model into a syntax error.
COMMENT_TEXT = [
    b"c note\r",  # CR inside a comment
    b"c caf\xc3\xa9",
    b"c [ banner ] /tmp/w\xc3\xb6rk/tab\tdir/n.cnf",
    b"c \xff\x00\x01\x7f\x80",
    b"c \t",
    b"c ",
]


@pytest.mark.parametrize("comment", COMMENT_TEXT)
@pytest.mark.parametrize("where", ["first", "between status and values", "between values", "last"])
def test_comment_text_is_any_bytes_except_lf(comment: bytes, where: str) -> None:
    lines = {
        "first": [comment, b"s SATISFIABLE", b"v -1 2", b"v 3 0"],
        "between status and values": [b"s SATISFIABLE", comment, b"v -1 2", b"v 3 0"],
        "between values": [b"s SATISFIABLE", b"v -1 2", comment, b"v 3 0"],
        "last": [b"s SATISFIABLE", b"v -1 2", b"v 3 0", comment],
    }[where]
    result = md.solver_model(b"".join(line + b"\n" for line in lines), SAT3, ())
    assert (result.assignment, result.model_error) == ("Bg==", None)
    # the comment does not hide defects of the other lines (values not terminated)
    unterminated = [b"v 3" if line == b"v 3 0" else line for line in lines]
    broken = md.solver_model(b"".join(line + b"\n" for line in unterminated), SAT3, ())
    assert (broken.model_error, broken.assignment) == (ModelError.SYNTAX, None)


@pytest.mark.parametrize("output", SYNTAX)
def test_syntax_errors(output: bytes) -> None:
    result = md.solver_model(output, SAT3, ())
    assert (result.model_error, result.assignment) == (ModelError.SYNTAX, None)
    assert result.outcome is Outcome.INVALID_MODEL and result.reason == "syntax"
    assert result.detail


@pytest.mark.parametrize(
    ("output", "error"),
    [
        (out("s SATISFIABLE", "v 1 2 0"), ModelError.MISSING),
        (out("s SATISFIABLE", "v 0"), ModelError.MISSING),
        (out("s SATISFIABLE", "v 1 2 -2 3 0"), ModelError.CONFLICTING),
        (out("s SATISFIABLE", "v 1 2 3 -1 0"), ModelError.CONFLICTING),
        (out("s SATISFIABLE", "v 1 2 3 4 0"), ModelError.OUT_OF_RANGE),
        (out("s SATISFIABLE", "v 1 2 3 -4 0"), ModelError.OUT_OF_RANGE),
        (out("s SATISFIABLE", "v 1 2 3 10 0"), ModelError.OUT_OF_RANGE),
        (out("s SATISFIABLE", "v 1 2 3 " + "9" * 5000 + " 0"), ModelError.OUT_OF_RANGE),
    ],
)
def test_parse_errors_carry_no_assignment(output: bytes, error: ModelError) -> None:
    result = md.solver_model(output, SAT3, ())
    assert (result.model_error, result.assignment) == (error, None)
    assert result.reason == error.value


def test_out_of_range_with_zero_variables() -> None:
    result = md.solver_model(out("s SATISFIABLE", "v 1 0"), formula(0, []), ())
    assert result.model_error is ModelError.OUT_OF_RANGE


def test_duplicate_identical_values_are_permitted_and_omitted() -> None:
    result = md.solver_model(out("s SATISFIABLE", "v 1 1 2 2 2 3 1 0"), SAT3, ())
    assert (result.assignment, result.model_error) == ("Bw==", None)


@pytest.mark.parametrize(
    ("output", "error"),
    [
        # syntax outranks everything, wherever it is
        (out("s SATISFIABLE", "v 1 2 -2 7 0", "x"), ModelError.SYNTAX),
        (out("s SATISFIABLE", "v 9 +1 0"), ModelError.SYNTAX),
        # out of range outranks conflicting and missing, even when it comes later
        (out("s SATISFIABLE", "v 1 -1 9 0"), ModelError.OUT_OF_RANGE),
        (out("s SATISFIABLE", "v 9 1 -1 0"), ModelError.OUT_OF_RANGE),
        # conflicting outranks missing (variables 2 and 3 have no value)
        (out("s SATISFIABLE", "v 1 -1 0"), ModelError.CONFLICTING),
        (out("s SATISFIABLE", "v 1 -1 0", "c x"), ModelError.CONFLICTING),
    ],
)
def test_precedence_of_several_defects(output: bytes, error: ModelError) -> None:
    assert md.solver_model(output, SAT3, ()).model_error is error


def test_conflicting_values_are_not_overwritten() -> None:
    """A later opposite value never replaces an earlier one (no silent repair)."""
    parsed = md.parse_solver_values(out("s SATISFIABLE", "v 1 2 3 -3 0"), 3)
    assert (parsed.values, parsed.error) == (None, ModelError.CONFLICTING)


def test_details_are_bounded_and_name_the_first_defect() -> None:
    long = "v " + " ".join(["99999"] * 400) + " 0"
    result = md.solver_model(out("s SATISFIABLE", long), SAT3, ())
    assert result.model_error is ModelError.OUT_OF_RANGE
    assert len(result.detail) <= md.MAX_DETAIL and "line 2" in result.detail
    weird = md.solver_model(b"s SATISFIABLE\n\xff" * 100, SAT3, ())
    assert weird.model_error is ModelError.SYNTAX and "line 2" in weird.detail
    missing = md.solver_model(out("s SATISFIABLE", "v 0"), formula(30, []), ())
    assert missing.detail == "no value for 1 2 3 4 5 6 7 8 9 10 and 20 more"


@pytest.mark.parametrize(
    ("output", "detail"),
    [
        (b"", "no status line 's SATISFIABLE'"),
        (b"c only a comment\n", "no status line 's SATISFIABLE'"),
        (b"s SATISFIABLE\n", "the values are not terminated by 0"),
        (b"s SATISFIABLE\nv 1 2 3 0", "the output does not end with LF"),
        (b"s SATISFIABLE\nv 1 2 3 0\nv\n", "line 3: value line after the terminating 0"),
        (b"s SATISFIABLE\nv 1 2 3 0 4\n", "line 2: value after the terminating 0"),
    ],
)
def test_syntax_details_name_the_defect(output: bytes, detail: str) -> None:
    result = md.solver_model(output, SAT3, ())
    assert (result.model_error, result.detail) == (ModelError.SYNTAX, detail)


def test_model_result_invariants() -> None:
    md.ModelResult("", None)
    md.ModelResult("AA==", ModelError.VIOLATED, "x", 3)
    md.ModelResult(None, ModelError.MISSING, "x")
    bad: list[tuple[object, ...]] = [
        (None, None),  # MODEL needs the assignment
        (None, ModelError.VIOLATED, "", 1),  # violated needs the assignment
        ("AA==", ModelError.SYNTAX),  # parse errors carry none
        ("AA==", ModelError.VIOLATED),  # violated names its clause
        ("AA==", None, "", 1),
        ("AA==", ModelError.VIOLATED, "", 0),
        ("", None, "x" * (md.MAX_DETAIL + 1)),
        ("", None, "line\nbreak"),
        ("", "violated"),
        (b"", None),
    ]
    for args in bad:
        with pytest.raises((TypeError, ValueError)):
            md.ModelResult(*args)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        md.SolverValues(None, None)
    with pytest.raises(ValueError):
        md.SolverValues((True,), ModelError.MISSING)
    with pytest.raises(ValueError):
        md.SolverValues(None, ModelError.VIOLATED)


def test_the_evaluator_does_not_import_the_unit_propagation_producer() -> None:
    """Assignment evaluation (used by certifiers) keeps UP code out of its import closure."""
    code = "import sys, cubeproof.cnf.model; sys.exit('cubeproof.cnf.unit' in sys.modules)"
    src = str(Path(md.__file__).resolve().parents[2])  # the cubeproof under test
    env = {**os.environ, "PYTHONPATH": os.pathsep.join([src, os.environ.get("PYTHONPATH", "")])}
    done = subprocess.run(
        [sys.executable, "-c", code], check=False, timeout=60, env=env, capture_output=True
    )
    assert done.returncode == 0, done.stderr


def test_inputs_are_validated() -> None:
    with pytest.raises(TypeError):
        md.parse_solver_values("s SATISFIABLE\n", 1)  # type: ignore[arg-type]
    for bad in (-1, True, 1.0):
        with pytest.raises(ValueError):
            md.parse_solver_values(b"", bad)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        md.check_values(SAT3, (), (True, True))
    with pytest.raises(ValueError):
        md.check_values(SAT3, (), (1, 1, 1))  # type: ignore[arg-type]
    with pytest.raises(ContractError):
        md.check_values(SAT3, (2, 1), (True, True, True))
    with pytest.raises(ContractError):
        md.solver_model(out("s SATISFIABLE", "v 1 2 3 0"), SAT3, (4,))
    with pytest.raises(ContractError) as caught:
        md.assignment_violation(SAT3, (), "Bw")
    assert caught.value.rule == "attempt.assignment"
    with pytest.raises(ContractError):
        md.assignment_violation(SAT3, (), "Dw==")  # a set unused high bit


def test_steps_yield_and_agree() -> None:
    f = formula(300, [(i, i + 1) for i in range(1, 300)])
    values = tuple(True for _ in range(300))
    output = cnf_model.model_lines(literals(values), width=30)
    steps = md.solver_model_steps(output, f, (5,), chunk=10)
    yields = 0
    while True:
        try:
            next(steps)
            yields += 1
        except StopIteration as stop:
            result = stop.value
            break
    assert yields > 50
    assert result == md.solver_model(output, f, (5,))
    assert result == drive(md.check_values_steps(f, (5,), values, chunk=3))
    assert result.model_error is None
