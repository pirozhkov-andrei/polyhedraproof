"""The canonical producer writer for DIMACS CNF (specification §3.1).

Canonical bytes are ASCII: ``p cnf V M\\n`` followed by exactly M clause lines. A nonempty
clause is its decimal literals joined by one space followed by `` 0\\n``; the empty clause
is `` 0\\n``. No comments, no CR, no blank lines, no plus signs or leading zeros. Clause
order and literal order are preserved; nothing is simplified. The SHA-256 of these bytes,
in lowercase hex, is the formula's identity.

:func:`clause_bytes` is the fast path for clauses whose literals a
:class:`~neighbourly.cnf.builder.Builder` has already validated; :func:`checked_clause_bytes`
validates every literal first and is what the bundle writer uses. cubeproof has its own
independent strict reader and does not import this module.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable, Sequence

from neighbourly.cnf.errors import CnfError

#: A clause as the writer takes it: literals in order.
ClauseLike = Sequence[int]


def _count(value: object, what: str) -> int:
    if type(value) is not int or value < 0:
        raise CnfError(f"{what} must be a nonnegative integer, not {value!r}")
    return value


def header_bytes(variables: int, clause_count: int) -> bytes:
    """``p cnf V M\\n`` for nonnegative integers V and M."""
    return (
        f"p cnf {_count(variables, 'variables')} {_count(clause_count, 'clause count')}\n"
    ).encode("ascii")


def clause_bytes(clauses: Iterable[ClauseLike]) -> bytes:
    """The clause lines alone, each ``' '``-separated and ``0``-terminated, LF endings.

    No validation: for clauses that a Builder emitted. The empty clause becomes `` 0\\n``.
    """
    return "".join(" ".join(map(str, clause)) + " 0\n" for clause in clauses).encode()


def check_clauses(variables: int, clauses: Iterable[ClauseLike]) -> int:
    """Validate every literal (a nonzero ``int``, ``abs <= variables``); return the count."""
    _count(variables, "variables")
    count = 0
    for clause in clauses:
        for literal in clause:
            if type(literal) is not int or literal == 0 or abs(literal) > variables:
                raise CnfError(
                    f"clause {count + 1}: literal {literal!r} is not a nonzero integer "
                    f"with absolute value at most {variables}"
                )
        count += 1
    return count


def checked_clause_bytes(variables: int, clauses: Sequence[ClauseLike]) -> bytes:
    """:func:`clause_bytes` after :func:`check_clauses`."""
    check_clauses(variables, clauses)
    return clause_bytes(clauses)


def dimacs_bytes(variables: int, body: bytes, clause_count: int) -> bytes:
    """The canonical DIMACS file: the header, then `body` (the output of clause_bytes)."""
    return header_bytes(variables, clause_count) + body


def formula_digest(variables: int, body: bytes, clause_count: int) -> str:
    """SHA-256 (lowercase hex) of the canonical DIMACS bytes."""
    return hashlib.sha256(dimacs_bytes(variables, body, clause_count)).hexdigest()
