"""A tiny, independent LRAT validator for test proofs only.

Tests use it to know, without the pinned checker, whether a small proof is valid: to build
fixtures, to cross-check cake_lpr on them in the image tests, and as the engine of the
``lrat_check`` fake checker. It is deliberately simple and slow (dictionaries, no clause
database tricks) and shares no code with cubeproof. **It is not a trusted checker**: no
production result, claim or theorem may rest on it; only the pinned cake_lpr authorises
VERIFIED_UNSAT (specification §5, §6.3).

Supported: the textual LRAT format (``id lits 0 hints 0`` additions, ``id d ids 0``
deletions) and CaDiCaL's binary encoding (``a``/``d`` followed by variable-length unsigned
integers, a value x encoded as 2x for x > 0 and 2|x|+1 for x < 0). Only RUP steps: a negative
hint (a RAT step) is rejected as unsupported. A step with an empty lemma ends the proof
successfully; a formula that already contains the empty clause is refuted by any proof.
Malformed input is rejected even where cake_lpr is more lenient.

    cd tests && python3 -m fakes.lrat_check FORMULA.cnf PROOF   # s VERIFIED UNSAT on success
"""

from __future__ import annotations

import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from .cnf_model import Cnf, DimacsError, parse_dimacs

SUCCESS = b"s VERIFIED UNSAT\n"


class LratError(ValueError):
    """The proof is malformed or a step does not follow."""


@dataclass(frozen=True)
class Step:
    """One proof line: an addition (id, lemma, hints) or a deletion (ids in `hints`)."""

    kind: str
    id: int
    lemma: tuple[int, ...]
    hints: tuple[int, ...]


@dataclass(frozen=True)
class Result:
    verified: bool
    reason: str
    steps: int


def _ints(tokens: Sequence[str], where: str) -> list[int]:
    try:
        return [int(t) for t in tokens]
    except ValueError as error:
        raise LratError(f"{where}: not an integer list") from error


def _split_zero(values: list[int], where: str) -> tuple[list[int], list[int]]:
    if 0 not in values:
        raise LratError(f"{where}: missing 0 terminator")
    index = values.index(0)
    return values[:index], values[index + 1 :]


def parse_text(data: bytes) -> list[Step]:
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError as error:
        raise LratError("text proof is not ASCII") from error
    steps: list[Step] = []
    for number, line in enumerate(text.splitlines(), 1):
        tokens = line.split()
        if not tokens or tokens[0] == "c":
            continue
        where = f"line {number}"
        if len(tokens) >= 2 and tokens[1] == "d":
            values = _ints([tokens[0], *tokens[2:]], where)
            ids, rest = _split_zero(values[1:], where)
            if rest:
                raise LratError(f"{where}: values after the deletion list")
            steps.append(Step("delete", values[0], (), tuple(ids)))
            continue
        values = _ints(tokens, where)
        lemma, rest = _split_zero(values[1:], where)
        hints, rest = _split_zero(rest, where)
        if rest:
            raise LratError(f"{where}: values after the hint list")
        steps.append(Step("add", values[0], tuple(lemma), tuple(hints)))
    return steps


def _varints(data: bytes, start: int) -> tuple[list[int], int]:
    """Decode mapped integers from `start` up to and including a 0; return values, end."""
    values: list[int] = []
    position = start
    while True:
        shift = 0
        raw = 0
        while True:
            if position >= len(data):
                raise LratError(f"byte {position}: truncated binary proof")
            byte = data[position]
            position += 1
            raw |= (byte & 0x7F) << shift
            shift += 7
            if not byte & 0x80:
                break
        if raw == 0:
            return values, position
        if raw == 1:
            raise LratError(f"byte {position}: encoded value -0")
        values.append(raw >> 1 if raw % 2 == 0 else -(raw >> 1))


def parse_binary(data: bytes) -> list[Step]:
    steps: list[Step] = []
    position = 0
    while position < len(data):
        tag = data[position : position + 1]
        position += 1
        if tag == b"a":
            head, position = _varints(data, position)
            if not head or head[0] <= 0:
                raise LratError(f"byte {position}: addition without a positive id")
            hints, position = _varints(data, position)
            steps.append(Step("add", head[0], tuple(head[1:]), tuple(hints)))
        elif tag == b"d":
            ids, position = _varints(data, position)
            steps.append(Step("delete", 0, (), tuple(ids)))
        else:
            raise LratError(f"byte {position - 1}: unknown binary tag {tag!r}")
    return steps


def parse_proof(data: bytes) -> list[Step]:
    """Binary if it starts with ``a`` or ``d``, textual otherwise."""
    if data[:1] in (b"a", b"d"):
        return parse_binary(data)
    return parse_text(data)


def _rup(
    lemma: tuple[int, ...], hints: tuple[int, ...], clauses: dict[int, tuple[int, ...]]
) -> None:
    """Return if the hints derive a conflict from the negated lemma; else raise LratError."""
    value: dict[int, bool] = {}
    for literal in lemma:
        if value.get(abs(literal), literal < 0) != (literal < 0):
            return  # tautology: trivially implied
        value[abs(literal)] = literal < 0
    for hint in hints:
        if hint < 0:
            raise LratError(f"RAT hint {hint} is not supported by the test validator")
        clause = clauses.get(hint)
        if clause is None:
            raise LratError(f"hint {hint} is not an active clause")
        unassigned: list[int] = []
        for literal in clause:
            assigned = value.get(abs(literal))
            if assigned is None:
                if literal not in unassigned:
                    unassigned.append(literal)
            elif assigned == (literal > 0):
                raise LratError(f"hint {hint} is satisfied")
        if not unassigned:
            return
        if len(unassigned) > 1:
            raise LratError(f"hint {hint} is not unit")
        value[abs(unassigned[0])] = unassigned[0] > 0
    raise LratError("hints do not reach a conflict")


@dataclass
class _Database:
    """The active clauses while a proof is replayed."""

    variables: int
    clauses: dict[int, tuple[int, ...]]
    largest: int

    def apply(self, step: Step) -> bool:
        """Apply one step (LratError if it does not follow); True if it is the empty clause."""
        if step.kind == "delete":
            for identifier in step.hints:
                if self.clauses.pop(identifier, None) is None:
                    raise LratError(f"deletes inactive clause {identifier}")
            return False
        if step.id <= self.largest:
            raise LratError(f"id {step.id} is not increasing")
        if any(abs(lit) > self.variables for lit in step.lemma):
            raise LratError("literal out of range")
        _rup(step.lemma, step.hints, self.clauses)
        if not step.lemma:
            return True
        self.clauses[step.id] = step.lemma
        self.largest = step.id
        return False


def check(cnf: Cnf, proof: bytes) -> Result:
    """Validate `proof` against `cnf`; never raises for a bad proof."""
    if () in cnf.clauses:
        return Result(True, "the formula contains the empty clause", 0)
    clauses = {index + 1: clause for index, clause in enumerate(cnf.clauses)}
    database = _Database(cnf.variables, clauses, len(clauses))
    number = 0
    try:
        for number, step in enumerate(parse_proof(proof), 1):
            if database.apply(step):
                return Result(True, f"step {number}: empty clause derived", number)
    except LratError as error:
        return Result(False, f"step {number}: {error}" if number else str(error), number)
    return Result(False, "empty clause not derived", number)


def encode_text(steps: Sequence[Step]) -> bytes:
    lines = []
    for step in steps:
        if step.kind == "delete":
            lines.append(" ".join(map(str, [step.id, "d", *step.hints, 0])))
        else:
            lines.append(" ".join(map(str, [step.id, *step.lemma, 0, *step.hints, 0])))
    return "".join(line + "\n" for line in lines).encode("ascii")


def _varint(value: int) -> bytes:
    raw = 2 * value if value > 0 else 2 * -value + 1
    out = bytearray()
    while True:
        byte = raw & 0x7F
        raw >>= 7
        if raw:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def encode_binary(steps: Sequence[Step]) -> bytes:
    out = bytearray()
    for step in steps:
        if step.kind == "delete":
            out += b"d" + b"".join(_varint(i) for i in step.hints) + b"\x00"
        else:
            out += b"a" + _varint(step.id) + b"".join(_varint(v) for v in step.lemma) + b"\x00"
            out += b"".join(_varint(h) for h in step.hints) + b"\x00"
    return bytes(out)


def decision_tree_proof(cnf: Cnf) -> list[Step]:
    """A valid RUP proof of an unsatisfiable formula, from its full decision tree.

    Branch on variables 1, 2, ... until an original clause is false; the clause blocking a
    node (the negated path) follows by RUP from the clauses of its two children, or from the
    falsified original clause at a leaf. Exponential: for tiny test formulas only. Raises
    ValueError if the formula is satisfiable.
    """
    steps: list[Step] = []
    next_id = len(cnf.clauses) + 1

    def falsified(path: tuple[int, ...]) -> int | None:
        true = set(path)
        for index, clause in enumerate(cnf.clauses, 1):
            if all(-lit in true for lit in clause):
                return index
        return None

    def derive(path: tuple[int, ...]) -> int | None:
        """Id of a clause equal to the negated path (an original one at a leaf)."""
        nonlocal next_id
        leaf = falsified(path)
        if leaf is not None:
            return leaf
        variable = len(path) + 1
        if variable > cnf.variables:
            return None
        children = [derive((*path, variable)), derive((*path, -variable))]
        if None in children:
            return None
        identifier = next_id
        next_id += 1
        lemma = tuple(-lit for lit in path)
        steps.append(Step("add", identifier, lemma, tuple(c for c in children if c is not None)))
        return identifier

    if derive(()) is None:
        raise ValueError("the formula is satisfiable")
    return steps


def check_files(cnf_path: Path, proof_path: Path) -> Result:
    try:
        cnf = parse_dimacs(cnf_path.read_bytes())
    except (OSError, DimacsError) as error:
        return Result(False, f"formula: {error}", 0)
    try:
        proof = proof_path.read_bytes()
    except OSError as error:
        return Result(False, f"proof: {error}", 0)
    return check(cnf, proof)


def main(argv: Sequence[str]) -> int:
    """cake_lpr's interface: the success line on stdout and exit 0, or a ``c`` line on stderr.

    Arena options (``--CML_HEAP_SIZE=``, ``--CML_STACK_SIZE=``) are accepted and ignored.
    """
    paths = [a for a in argv if not a.startswith("--CML_")]
    if len(paths) != 2:
        sys.stderr.write("usage: lrat_check.py FORMULA PROOF\n")
        return 2
    result = check_files(Path(paths[0]), Path(paths[1]))
    if result.verified:
        sys.stdout.buffer.write(SUCCESS)
    else:
        sys.stderr.write(f"c Checking failed: {result.reason}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
