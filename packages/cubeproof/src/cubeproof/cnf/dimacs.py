"""Canonical DIMACS (specification §3.1): the strict reader, the canonical writer and the explicit
import.

Canonical bytes are ASCII: ``p cnf V M`` LF, then exactly M clause lines. A nonempty clause is
its decimal literals joined by one space followed by `` 0`` LF; the empty clause is `` 0`` LF;
an empty formula is the header alone. Literals are nonzero with ``abs(l) <= V``, without plus
sign, leading zero or negative zero. No comments, CR, blank lines or extra whitespace. Clause
and literal order are preserved; duplicates and tautologies are legal and kept.

:func:`parse_dimacs` rejects anything else (dimacs.header, dimacs.clause, dimacs.count,
dimacs.range). It never normalizes. :func:`normalize_external_dimacs` is the separate,
explicit normalization of external DIMACS used by ``bundle import``.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass, field

from cubeproof.base.errors import ContractError
from cubeproof.contracts.primitives import INT_MAX

_HEADER = re.compile(rb"p cnf (0|[1-9][0-9]*) (0|[1-9][0-9]*)")
_CLAUSE = re.compile(rb"(?:-?[1-9][0-9]* )+0| 0")
_MAX_DIGITS = len(str(INT_MAX))


@dataclass(frozen=True)
class Formula:
    """A validated canonical DIMACS formula: its bytes, V, M and SHA-256."""

    data: bytes = field(repr=False)
    variables: int
    clauses: int
    header_length: int
    sha256: str

    @property
    def body(self) -> bytes:
        """The clause lines (everything after the header line)."""
        return self.data[self.header_length :]

    def iter_clauses(self) -> Iterator[tuple[int, ...]]:
        """The clauses in order, as tuples of literals (the empty clause is ``()``)."""
        body = self.body
        if not body:
            return
        for line in body[:-1].split(b"\n"):
            yield tuple(int(x) for x in line.split(b" ")[:-1] if x)


def _number(token: bytes) -> int:
    """A canonical decimal (already matched by the patterns); ASCII digits only."""
    return int(token)


def parse_dimacs(data: bytes) -> Formula:
    """Validate canonical DIMACS bytes; :class:`ContractError` ``dimacs.*`` otherwise."""
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError("parse_dimacs reads bytes")
    raw = bytes(data)
    end = raw.find(b"\n")
    if end < 0:
        raise ContractError("dimacs.header", "no header line ending in LF")
    header = _HEADER.fullmatch(raw, 0, end)
    if header is None:
        raise ContractError("dimacs.header", repr(raw[: min(end, 40)]))
    v_text, m_text = header.group(1), header.group(2)
    if len(v_text) > _MAX_DIGITS or len(m_text) > _MAX_DIGITS:
        raise ContractError("dimacs.header", "count outside the integer range")
    variables, count = _number(v_text), _number(m_text)
    if variables > INT_MAX or count > INT_MAX:
        raise ContractError("dimacs.header", "count outside the integer range")
    body = raw[end + 1 :]
    if body and not body.endswith(b"\n"):
        raise ContractError("dimacs.clause", "the last clause line does not end in LF")
    lines = body[:-1].split(b"\n") if body else []
    for number, line in enumerate(lines, start=1):
        if _CLAUSE.fullmatch(line) is None:
            raise ContractError("dimacs.clause", f"clause line {number}: {line[:40]!r}")
    if len(lines) != count:
        raise ContractError("dimacs.count", f"{len(lines)} clause lines, header says {count}")
    # Canonical literals have no leading zeros: fewer digits than V is always in range.
    width = len(str(variables))
    for number, line in enumerate(lines, start=1):
        for token in line.split(b" ")[:-1]:
            digits = len(token) - (token[:1] == b"-")
            if digits > width or (digits == width and abs(int(token)) > variables):
                raise ContractError("dimacs.range", f"clause line {number}: literal {token!r}")
    return Formula(raw, variables, count, end + 1, hashlib.sha256(raw).hexdigest())


def canonical_dimacs(variables: int, clauses: Iterable[Sequence[int]]) -> bytes:
    """The canonical bytes of a formula (the writer convention of specification §3.1)."""
    if type(variables) is not int or not 0 <= variables <= INT_MAX:
        raise ContractError("dimacs.header", f"{variables!r} is not a variable count")
    lines = []
    for clause in clauses:
        for literal in clause:
            if type(literal) is not int or literal == 0 or abs(literal) > variables:
                raise ContractError("dimacs.range", f"literal {literal!r} with V={variables}")
        lines.append(" ".join(str(x) for x in clause) + " 0\n" if clause else " 0\n")
    return (f"p cnf {variables} {len(lines)}\n" + "".join(lines)).encode("ascii")


# -- explicit import of external DIMACS -------------------------------------------------------

_INTEGER = re.compile(rb"[+-]?[0-9]+")


def _import_error(detail: str) -> ContractError:
    return ContractError("dimacs.import", detail)


def normalize_external_dimacs(data: bytes) -> bytes:
    """Canonical bytes of external DIMACS, preserving clause and literal order (specification §3.1).

    Accepted input: an optional UTF-8 byte order mark; comment lines whose first non-blank
    character is ``c`` (anywhere); blank lines; any spaces, tabs and CR; exactly one header
    ``p cnf V M`` before the first clause; clauses terminated by ``0``, several per line or one
    spread over lines; ``0`` alone is the empty clause; literals with an optional ``+`` and
    leading zeros. Refused (``dimacs.import``): anything else, including ``-0``/``+0``, a
    missing header, a second header, a last clause without its terminating ``0``, a literal
    outside ``1..V`` in absolute value, a clause count other than M and the SATLIB ``%``
    trailer. The caller records the source hash; this function only computes bytes.
    """
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError("normalize_external_dimacs reads bytes")
    raw = bytes(data)
    if raw.startswith(b"\xef\xbb\xbf"):
        raw = raw[3:]
    header: tuple[int, int] | None = None
    clauses: list[list[int]] = []
    current: list[int] = []
    for number, line in enumerate(raw.split(b"\n"), start=1):
        tokens = line.split()
        if not tokens:
            continue
        if tokens[0].startswith(b"c"):
            continue
        if tokens[0] == b"p":
            if header is not None:
                raise _import_error(f"line {number}: a second header")
            if clauses or current:
                raise _import_error(f"line {number}: header after clauses")
            if len(tokens) != 4 or tokens[1] != b"cnf":
                raise _import_error(f"line {number}: header is not 'p cnf V M'")
            counts = []
            for token in tokens[2:]:
                if not token.isdigit() or not token.isascii() or len(token.lstrip(b"0")) > 19:
                    raise _import_error(f"line {number}: bad count {token!r}")
                counts.append(int(token))
            if any(c > INT_MAX for c in counts):
                raise _import_error(f"line {number}: count outside the integer range")
            header = (counts[0], counts[1])
            continue
        if header is None:
            raise _import_error(f"line {number}: clause before the header")
        variables = header[0]
        for token in tokens:
            if _INTEGER.fullmatch(token) is None:
                raise _import_error(f"line {number}: {token[:20]!r} is not an integer")
            digits = token.lstrip(b"+-").lstrip(b"0")
            if len(digits) > 19:
                raise _import_error(f"line {number}: literal {token[:20]!r} out of range")
            value = int(token)
            if value == 0:
                if token[:1] in (b"+", b"-"):
                    raise _import_error(f"line {number}: signed zero {token!r}")
                clauses.append(current)
                current = []
                continue
            if abs(value) > variables:
                raise _import_error(f"line {number}: literal {value} with V={variables}")
            current.append(value)
    if header is None:
        raise _import_error("no 'p cnf V M' header")
    if current:
        raise _import_error("the last clause has no terminating 0")
    if len(clauses) != header[1]:
        raise _import_error(f"{len(clauses)} clauses, header says {header[1]}")
    return canonical_dimacs(header[0], clauses)
