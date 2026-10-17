"""Models of CNF(F, C): solver output parsing, evaluation and the canonical bitset (specification
§4.8, §6.1).

A model result is MODEL only for a complete assignment that satisfies every clause of F and
every unit of the cube C; otherwise it is INVALID_MODEL with a ``model_error``:

- ``syntax``, ``out_of_range``, ``conflicting``, ``missing``: the solver output is not a
  complete, consistent assignment of variables 1..V; ``assignment`` is null. Values are
  never filled in, overwritten or guessed (specification §4.8).
- ``violated``: a complete assignment that falsifies a clause or a cube unit; ``assignment``
  is that complete failing bitset.

Solver output grammar (CaDiCaL's ``s``/``v`` lines; specification §6.1 "complete model parsing").
The output is a sequence of lines, each ending with LF. A line is a comment (``c`` alone, or
``c`` and a space followed by any bytes other than LF, including CR, TAB and non-ASCII
bytes), the status ``s SATISFIABLE``, a value line (``v`` followed by zero or more tokens,
each preceded by exactly one space), or a syntax error; status and value lines are printable
ASCII (0x20-0x7E) only. Comment text carries no meaning, so a solver banner that echoes a
user's path (CaDiCaL without ``-q``) never turns a model into a syntax error. Exactly one
status line, before every value line. A token is ``0`` or a canonical
nonzero decimal literal (no ``+``, no leading zero, no ``-0``). The token ``0`` occurs once
and terminates the values: it is the last token of its line and no value line follows.
Repeated identical values are permitted and appear once in the bitset.

When one output has several defects the code is chosen by the precedence ``syntax`` >
``out_of_range`` > ``conflicting`` > ``missing`` (structure first, then range, then
consistency, then completeness), independently of where the defects occur; the detail text
names the first defect of that code in reading order. ``violated`` is only possible for a
complete, consistent, in-range assignment.

Details are bounded diagnostic text (specification §4.8: keep bounded raw text only in diagnostics);
they never decide anything. Long work is a generator that yields between chunks (specification
§8.1); :func:`drive` runs it to the end. This module does not import the unit propagation
producer (``cubeproof.cnf.unit``), so assignment evaluation can be used by a certifier
without UP code in its import closure.
"""

from __future__ import annotations

import re
from collections.abc import Generator, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, TypeVar, cast

from cubeproof.cnf.dimacs import Formula
from cubeproof.contracts.assignment import decode_assignment, encode_assignment
from cubeproof.contracts.enums import ModelError, Outcome
from cubeproof.contracts.identity import check_cube
from cubeproof.contracts.primitives import INT_MAX

if TYPE_CHECKING:  # the unit propagation producer stays out of the evaluator's imports
    from cubeproof.cnf.unit import Propagation

_T = TypeVar("_T")

#: Default work units between two yields (specification §8.1).
DEFAULT_CHUNK = 4096

#: Upper bound of a detail text in characters.
MAX_DETAIL = 200


def drive(steps: Generator[None, None, _T]) -> _T:
    """Run a step generator to its end and return its value."""
    while True:
        try:
            next(steps)
        except StopIteration as stop:
            return cast(_T, stop.value)


#: Model error codes by precedence (first wins).
PRECEDENCE: tuple[ModelError, ...] = (
    ModelError.SYNTAX,
    ModelError.OUT_OF_RANGE,
    ModelError.CONFLICTING,
    ModelError.MISSING,
)

_TOKEN = re.compile(rb"0|-?[1-9][0-9]*")
_UNPRINTABLE = re.compile(rb"[^\x20-\x7e]")
_STATUS = b"s SATISFIABLE"


def _bounded(text: str) -> str:
    text = text.encode("ascii", "backslashreplace").decode("ascii")
    text = "".join(ch if " " <= ch <= "~" else "?" for ch in text)
    return text if len(text) <= MAX_DETAIL else text[: MAX_DETAIL - 3] + "..."


def _show(data: bytes) -> str:
    return repr(data[:40]) + ("..." if len(data) > 40 else "")


@dataclass(frozen=True)
class ModelResult:
    """The model fields of an attempt (specification §4.8): ``assignment``, ``model_error``,
    diagnostics.

    ``violated_clause`` is the ID in CNF(F, C) numbering (cube units after the M base
    clauses) of the first false clause of a ``violated`` result, else None. It and
    ``detail`` are diagnostics, not record fields.
    """

    assignment: str | None
    model_error: ModelError | None
    detail: str = ""
    violated_clause: int | None = None

    def __post_init__(self) -> None:
        error = self.model_error
        if error is not None and not isinstance(error, ModelError):
            raise TypeError("model_error must be a ModelError or None")
        if self.assignment is not None and not isinstance(self.assignment, str):
            raise TypeError("assignment must be a bitset string or None")
        if error is None or error is ModelError.VIOLATED:
            if self.assignment is None:
                raise ValueError("MODEL and violated results carry the complete assignment")
        elif self.assignment is not None:
            raise ValueError("a parse error carries no assignment")
        wants_clause = error is ModelError.VIOLATED
        clause = self.violated_clause
        if wants_clause != (clause is not None):
            raise ValueError("violated_clause is set exactly for violated results")
        if clause is not None and (type(clause) is not int or clause < 1):
            raise ValueError("violated_clause is a clause ID")
        if not isinstance(self.detail, str) or _bounded(self.detail) != self.detail:
            raise ValueError("detail must be bounded printable ASCII")

    @property
    def outcome(self) -> Outcome:
        return Outcome.MODEL if self.model_error is None else Outcome.INVALID_MODEL

    @property
    def reason(self) -> str | None:
        """The attempt reason: null for MODEL, the model_error for INVALID_MODEL."""
        return None if self.model_error is None else self.model_error.value


@dataclass(frozen=True)
class SolverValues:
    """Parsed solver output: the values of variables 1..V, or the model error."""

    values: tuple[bool, ...] | None
    error: ModelError | None
    detail: str = ""

    def __post_init__(self) -> None:
        if (self.values is None) == (self.error is None):
            raise ValueError("exactly one of values and error")
        if self.error is ModelError.VIOLATED:
            raise ValueError("violated is not a parse error")


def _variable_count(variables: object) -> int:
    if type(variables) is not int or not 0 <= variables <= INT_MAX:
        raise ValueError(f"{variables!r} is not a variable count")
    return variables


def parse_solver_values_steps(
    output: bytes, variables: int, *, chunk: int = DEFAULT_CHUNK
) -> Generator[None, None, SolverValues]:
    """Parse a solver's stdout (module grammar), yielding after about ``chunk`` tokens."""
    if not isinstance(output, (bytes, bytearray, memoryview)):
        raise TypeError("solver output is bytes")
    if type(chunk) is not int or chunk < 1:
        raise ValueError("chunk must be a positive integer")
    count = _variable_count(variables)
    width = len(str(count))
    raw = bytes(output)
    found: dict[ModelError, str] = {}

    def defect(kind: ModelError, detail: str) -> None:
        found.setdefault(kind, _bounded(detail))

    values = bytearray(count + 1)  # 0 no value, 1 true, 2 false
    lines = raw.split(b"\n")
    complete_last = lines[-1] == b""
    if complete_last:
        lines.pop()
    status = False
    terminated = False
    budget = chunk
    for number, line in enumerate(lines, start=1):
        if ModelError.SYNTAX in found:
            break  # nothing outranks it and its detail is the first one
        budget -= 1
        if budget <= 0:
            budget = chunk
            yield
        if line == b"c" or line.startswith(b"c "):
            continue  # comment text is opaque: any bytes except LF
        bad = _UNPRINTABLE.search(line)
        if bad is not None:
            defect(ModelError.SYNTAX, f"line {number}: byte {bad.start()} is not printable ASCII")
            continue
        if line == _STATUS:
            if status:
                defect(ModelError.SYNTAX, f"line {number}: a second status line")
            status = True
            continue
        if not (line == b"v" or line.startswith(b"v ")):
            defect(ModelError.SYNTAX, f"line {number}: unexpected line {_show(line)}")
            continue
        if not status:
            defect(ModelError.SYNTAX, f"line {number}: value line before the status line")
            continue
        if terminated:
            defect(ModelError.SYNTAX, f"line {number}: value line after the terminating 0")
            continue
        tokens = line[2:].split(b" ") if len(line) > 1 else []
        for token in tokens:
            budget -= 1
            if budget <= 0:
                budget = chunk
                yield
            if terminated:
                defect(ModelError.SYNTAX, f"line {number}: value after the terminating 0")
                break
            if _TOKEN.fullmatch(token) is None:
                defect(ModelError.SYNTAX, f"line {number}: {_show(token)} is not a literal")
                break
            if token == b"0":
                terminated = True
                continue
            digits = token.lstrip(b"-")
            if len(digits) > width or int(digits) > count:
                defect(ModelError.OUT_OF_RANGE, f"line {number}: {_show(token)} with V={count}")
                continue
            variable = int(digits)
            value = 2 if token[:1] == b"-" else 1
            if values[variable] not in (0, value):
                defect(
                    ModelError.CONFLICTING, f"line {number}: variable {variable} has both values"
                )
                continue
            values[variable] = value
    if ModelError.SYNTAX not in found:
        if not complete_last:
            defect(ModelError.SYNTAX, "the output does not end with LF")
        elif not status:
            defect(ModelError.SYNTAX, "no status line 's SATISFIABLE'")
        elif not terminated:
            defect(ModelError.SYNTAX, "the values are not terminated by 0")
    for kind in PRECEDENCE[:3]:
        if kind in found:
            return SolverValues(None, kind, found[kind])
    missing = [v for v in range(1, count + 1) if values[v] == 0]
    if missing:
        shown = " ".join(str(v) for v in missing[:10])
        more = f" and {len(missing) - 10} more" if len(missing) > 10 else ""
        return SolverValues(None, ModelError.MISSING, _bounded(f"no value for {shown}{more}"))
    return SolverValues(tuple(values[v] == 1 for v in range(1, count + 1)), None)


def parse_solver_values(output: bytes, variables: int) -> SolverValues:
    """:func:`parse_solver_values_steps` in one call."""
    return drive(parse_solver_values_steps(output, variables, chunk=1 << 30))


def first_false_clause_steps(
    formula: Formula,
    cube: Sequence[int],
    values: Sequence[bool],
    *,
    chunk: int = DEFAULT_CHUNK,
) -> Generator[None, None, int | None]:
    """ID of the first clause of CNF(F, C) that ``values`` falsifies, or None.

    ``values[i-1]`` is the value of variable i; it must be complete (length V). IDs follow
    CNF(F, C): base clauses 1..M, then the cube units M+1..M+d in canonical order.
    """
    if type(chunk) is not int or chunk < 1:
        raise ValueError("chunk must be a positive integer")
    literals = check_cube(cube, formula.variables)
    if len(values) != formula.variables or any(type(v) is not bool for v in values):
        raise ValueError(f"a complete assignment has {formula.variables} boolean values")
    budget = chunk
    for number, clause in enumerate(formula.iter_clauses(), start=1):
        if not any(values[abs(x) - 1] == (x > 0) for x in clause):
            return number
        budget -= len(clause) + 1
        if budget <= 0:
            budget = chunk
            yield
    for number, literal in enumerate(literals, start=formula.clauses + 1):
        if values[abs(literal) - 1] != (literal > 0):
            return number
    return None


def first_false_clause(formula: Formula, cube: Sequence[int], values: Sequence[bool]) -> int | None:
    """:func:`first_false_clause_steps` in one call."""
    return drive(first_false_clause_steps(formula, cube, values, chunk=1 << 30))


def check_values_steps(
    formula: Formula,
    cube: Sequence[int],
    values: Sequence[bool],
    *,
    chunk: int = DEFAULT_CHUNK,
) -> Generator[None, None, ModelResult]:
    """MODEL or INVALID_MODEL(violated) for a complete assignment of CNF(F, C)."""
    clause = yield from first_false_clause_steps(formula, cube, values, chunk=chunk)
    assignment = encode_assignment(list(values))
    if clause is None:
        return ModelResult(assignment, None)
    kind = "cube unit" if clause > formula.clauses else "clause"
    return ModelResult(
        assignment, ModelError.VIOLATED, f"{kind} {clause} of CNF(F, C) is false", clause
    )


def check_values(formula: Formula, cube: Sequence[int], values: Sequence[bool]) -> ModelResult:
    """:func:`check_values_steps` in one call."""
    return drive(check_values_steps(formula, cube, values, chunk=1 << 30))


def solver_model_steps(
    output: bytes, formula: Formula, cube: Sequence[int], *, chunk: int = DEFAULT_CHUNK
) -> Generator[None, None, ModelResult]:
    """The model result of a SAT solver's stdout for CNF(F, C): parse, then evaluate."""
    check_cube(cube, formula.variables)
    parsed = yield from parse_solver_values_steps(output, formula.variables, chunk=chunk)
    if parsed.values is None:
        assert parsed.error is not None
        return ModelResult(None, parsed.error, parsed.detail)
    return (yield from check_values_steps(formula, cube, parsed.values, chunk=chunk))


def solver_model(output: bytes, formula: Formula, cube: Sequence[int]) -> ModelResult:
    """:func:`solver_model_steps` in one call."""
    return drive(solver_model_steps(output, formula, cube, chunk=1 << 30))


def propagated_model_steps(
    formula: Formula, propagation: Propagation, *, chunk: int = DEFAULT_CHUNK
) -> Generator[None, None, ModelResult]:
    """The model result of a complete, conflict-free unit propagation (route unit, specification
    §9.1).

    The assignment is evaluated like any solver model; propagation is not trusted to have
    satisfied anything. ``ValueError`` if the propagation is incomplete, conflicting or of
    another formula (a caller error: such a propagation is not a model candidate).
    """
    if propagation.formula_sha256 != formula.sha256 or propagation.variables != formula.variables:
        raise ValueError("the propagation belongs to another formula")
    values = propagation.values()
    return (yield from check_values_steps(formula, propagation.cube, values, chunk=chunk))


def propagated_model(formula: Formula, propagation: Propagation) -> ModelResult:
    """:func:`propagated_model_steps` in one call."""
    return drive(propagated_model_steps(formula, propagation, chunk=1 << 30))


def assignment_violation(formula: Formula, cube: Sequence[int], assignment: str) -> int | None:
    """First false clause ID of CNF(F, C) under a recorded bitset, or None if it satisfies.

    ``ContractError attempt.assignment`` if the bitset is not canonical for V (specification §4.8).
    """
    values = decode_assignment(assignment, formula.variables)
    return first_false_clause(formula, cube, values)
