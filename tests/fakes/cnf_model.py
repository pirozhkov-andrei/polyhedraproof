"""Tiny DIMACS and solver-model helpers for tests only.

This is a test oracle, written independently of the production parsers of cubeproof:
small, strict and slow. It parses ``p cnf`` files, evaluates assignments, brute-forces models
of formulas with few variables, generates pigeonhole formulas, and reads a solver's
``s``/``v`` model output into an assignment, classifying a bad model by the ``model_error``
codes of specification §4.8 (``missing``, ``conflicting``, ``out_of_range``, ``syntax``,
``violated``). Which code wins when one output has several defects is the production
contract's business; the fixtures here have exactly one defect each.
"""

from __future__ import annotations

import itertools
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass

Clause = tuple[int, ...]
MODEL_ERRORS = ("missing", "conflicting", "out_of_range", "syntax", "violated")


class DimacsError(ValueError):
    """The bytes are not a well-formed ``p cnf`` file."""


class ModelError(ValueError):
    """A solver's model output is unusable; ``kind`` is one of MODEL_ERRORS."""

    def __init__(self, kind: str, message: str) -> None:
        if kind not in MODEL_ERRORS:
            raise AssertionError(f"unknown model error kind {kind!r}")
        super().__init__(f"{kind}: {message}")
        self.kind = kind


@dataclass(frozen=True)
class Cnf:
    variables: int
    clauses: tuple[Clause, ...]

    def __post_init__(self) -> None:
        if self.variables < 0:
            raise DimacsError("negative variable count")
        for clause in self.clauses:
            for literal in clause:
                if literal == 0 or abs(literal) > self.variables:
                    raise DimacsError(f"literal {literal} out of range 1..{self.variables}")


def parse_dimacs(data: bytes) -> Cnf:
    """Strict ``p cnf V C``: comment lines, then the header, then exactly C clauses."""
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError as error:
        raise DimacsError("not ASCII") from error
    header: tuple[int, int] | None = None
    clauses: list[Clause] = []
    current: list[int] = []
    for number, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("c"):
            continue
        if header is None:
            parts = stripped.split()
            if len(parts) != 4 or parts[:2] != ["p", "cnf"]:
                raise DimacsError(f"line {number}: expected 'p cnf V C'")
            try:
                header = (int(parts[2]), int(parts[3]))
            except ValueError as error:
                raise DimacsError(f"line {number}: header counts are not integers") from error
            if header[0] < 0 or header[1] < 0:
                raise DimacsError(f"line {number}: negative header count")
            continue
        for token in stripped.split():
            try:
                literal = int(token)
            except ValueError as error:
                raise DimacsError(f"line {number}: {token!r} is not a literal") from error
            if literal == 0:
                clauses.append(tuple(current))
                current = []
            else:
                current.append(literal)
    if header is None:
        raise DimacsError("no 'p cnf' header")
    if current:
        raise DimacsError("last clause is not terminated by 0")
    if len(clauses) != header[1]:
        raise DimacsError(f"header says {header[1]} clauses, found {len(clauses)}")
    return Cnf(header[0], tuple(clauses))


def dimacs(cnf: Cnf) -> bytes:
    lines = [f"p cnf {cnf.variables} {len(cnf.clauses)}"]
    lines += [" ".join([*map(str, clause), "0"]) for clause in cnf.clauses]
    return ("\n".join(lines) + "\n").encode("ascii")


def violated_clause(cnf: Cnf, assignment: Mapping[int, bool]) -> int | None:
    """Index of the first clause the (complete) assignment falsifies, or None."""
    for index, clause in enumerate(cnf.clauses):
        if not any(assignment[abs(lit)] == (lit > 0) for lit in clause):
            return index
    return None


def brute_force_model(cnf: Cnf, max_variables: int = 20) -> dict[int, bool] | None:
    """The first satisfying assignment in binary counting order, or None (UNSAT)."""
    if cnf.variables > max_variables:
        raise ValueError(f"{cnf.variables} variables is too many to enumerate")
    for bits in itertools.product((False, True), repeat=cnf.variables):
        assignment = {i + 1: value for i, value in enumerate(bits)}
        if violated_clause(cnf, assignment) is None:
            return assignment
    return None


def pigeonhole(holes: int) -> Cnf:
    """holes+1 pigeons in `holes` holes: unsatisfiable, with short resolution-hard proofs."""
    pigeons = holes + 1

    def var(pigeon: int, hole: int) -> int:
        return pigeon * holes + hole + 1

    clauses: list[Clause] = [tuple(var(p, h) for h in range(holes)) for p in range(pigeons)]
    for h in range(holes):
        for p, q in itertools.combinations(range(pigeons), 2):
            clauses.append((-var(p, h), -var(q, h)))
    return Cnf(pigeons * holes, tuple(clauses))


def model_lines(literals: Iterable[int], width: int = 78) -> bytes:
    """``s SATISFIABLE`` and ``v`` lines of at most `width` characters, ending with 0."""
    out = ["s SATISFIABLE"]
    line = "v"
    for token in [*map(str, literals), "0"]:
        if len(line) + 1 + len(token) > width:
            out.append(line)
            line = "v"
        line += " " + token
    out.append(line)
    return ("\n".join(out) + "\n").encode("ascii")


def parse_model(output: bytes, cnf: Cnf) -> dict[int, bool]:
    """A complete satisfying assignment from solver output, or ModelError."""
    try:
        text = output.decode("ascii")
    except UnicodeDecodeError as error:
        raise ModelError("syntax", "output is not ASCII") from error
    status: list[str] = []
    values: dict[int, bool] = {}
    terminated = False
    for line in text.splitlines():
        if not line or line.startswith("c"):
            continue
        if line.startswith("s "):
            status.append(line)
            continue
        if not line.startswith("v"):
            raise ModelError("syntax", f"unexpected line {line[:40]!r}")
        for token in line[1:].split():
            if terminated:
                raise ModelError("syntax", "value after the terminating 0")
            try:
                literal = int(token)
            except ValueError as error:
                raise ModelError("syntax", f"{token!r} is not a literal") from error
            if literal == 0:
                terminated = True
                continue
            variable = abs(literal)
            if variable > cnf.variables:
                raise ModelError("out_of_range", f"variable {variable} > {cnf.variables}")
            if values.get(variable, literal > 0) != (literal > 0):
                raise ModelError("conflicting", f"variable {variable} has both values")
            values[variable] = literal > 0
    if status != ["s SATISFIABLE"]:
        raise ModelError("syntax", f"status lines {status!r}, expected one 's SATISFIABLE'")
    if not terminated:
        raise ModelError("syntax", "model is not terminated by 0")
    missing = [v for v in range(1, cnf.variables + 1) if v not in values]
    if missing:
        raise ModelError("missing", f"no value for variables {missing[:10]}")
    index = violated_clause(cnf, values)
    if index is not None:
        raise ModelError("violated", f"clause {index + 1} is false")
    return values


def literals_of(assignment: Mapping[int, bool]) -> Sequence[int]:
    return [v if assignment[v] else -v for v in sorted(assignment)]
