"""CNF(F, C): the exact bytes of a cube formula, streamed writing and the digest (specification
§3.2).

``CNF(F, C) = "p cnf V (M+len(C))" LF + clause body of F + one "l 0" LF per literal of C``
in canonical cube order; ``cnf_sha256`` hashes exactly those bytes.

:class:`CnfDigest` is the independent digest of these bytes. For every depth d it caches
``SHA256(header(V, M+d) + body)`` **as a hash state**, copies that state and appends the
units. It never combines separately computed header and body digests. The streamed writer
:func:`write_cube_cnf` hashes the bytes as it writes them, so a caller can compare the hash
of the file it produced with :class:`CnfDigest` (specification §6.1, stage 1).
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from cubeproof.base.hashing import HashingWriter
from cubeproof.cnf.cube import cube_units
from cubeproof.cnf.dimacs import Formula
from cubeproof.contracts.identity import check_cube

DEFAULT_CHUNK = 1 << 20


def cube_cnf_header(variables: int, clauses: int, depth: int) -> bytes:
    """``p cnf V (M+d)`` LF."""
    return f"p cnf {variables} {clauses + depth}\n".encode("ascii")


def cube_cnf_bytes(formula: Formula, cube: Sequence[int]) -> bytes:
    """The complete CNF(F, C) in memory (small formulas, tests)."""
    literals = check_cube(cube, formula.variables)
    header = cube_cnf_header(formula.variables, formula.clauses, len(literals))
    return header + formula.body + cube_units(literals)


@dataclass(frozen=True)
class CnfWriteResult:
    """What a streamed write produced: SHA-256 and size of the bytes the stream accepted."""

    sha256: str
    bytes: int


def write_cube_cnf(
    formula: Formula, cube: Sequence[int], stream: Any, *, chunk_size: int = DEFAULT_CHUNK
) -> CnfWriteResult:
    """Write CNF(F, C) to ``stream`` in chunks, hashing exactly the bytes written.

    Short writes are completed; a stream that accepts no byte raises :class:`OSError`.
    The caller owns the stream (opening, flushing, fsync and closing).
    """
    if type(chunk_size) is not int or chunk_size < 1:
        raise ValueError("chunk_size must be a positive integer")
    literals = check_cube(cube, formula.variables)
    writer = HashingWriter(stream)
    writer.write(cube_cnf_header(formula.variables, formula.clauses, len(literals)))
    body = memoryview(formula.body)
    for start in range(0, len(body), chunk_size):
        writer.write(body[start : start + chunk_size])
    writer.write(cube_units(literals))
    return CnfWriteResult(writer.hexdigest(), writer.bytes_written)


class CnfDigest:
    """Independent ``cnf_sha256`` of CNF(F, C) for many cubes of one formula.

    The cache maps a depth d to the hash state after ``header(V, M+d) + body``. Each query
    copies the state of its depth and appends the unit lines; cached states are never
    updated in place.
    """

    def __init__(self, formula: Formula) -> None:
        self._formula = formula
        self._states: dict[int, Any] = {}

    @property
    def formula(self) -> Formula:
        return self._formula

    def _state(self, depth: int) -> Any:
        state = self._states.get(depth)
        if state is None:
            formula = self._formula
            state = hashlib.sha256(cube_cnf_header(formula.variables, formula.clauses, depth))
            state.update(formula.body)
            self._states[depth] = state
        return state

    def cnf_sha256(self, cube: Sequence[int]) -> str:
        literals = check_cube(cube, self._formula.variables)
        state = self._state(len(literals)).copy()
        state.update(cube_units(literals))
        return str(state.hexdigest())
