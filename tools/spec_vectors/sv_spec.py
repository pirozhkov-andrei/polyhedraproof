"""Specification primitives for the vector generator.

Standard library only. This module is written from the text (specification §3.1-§3.2, §4.1,
§4.8, §10.5, §11.1) and shares no code with the runtime packages or with the test-side reader in
tests/contracts; the contract tests compare both against hand-written preimages.
"""

from __future__ import annotations

import base64
import hashlib
import json
from collections.abc import Iterable, Sequence
from typing import Any

INT_MAX = 2**63 - 1
K_MAX = 20
ZERO = "0" * 64
VERIFIED = "s VERIFIED UNSAT\n"


def jbytes(value: Any) -> bytes:
    """J(x): UTF-8 of json.dumps(sort_keys, compact separators, ensure_ascii=False)."""
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def sha(data: bytes | str) -> str:
    raw = data.encode("utf-8") if isinstance(data, str) else data
    return hashlib.sha256(raw).hexdigest()


def jsha(value: Any) -> str:
    return sha(jbytes(value))


def document(value: Any) -> bytes:
    """A canonical document on disk: J(x) plus one LF."""
    return jbytes(value) + b"\n"


def dimacs(variables: int, clauses: Sequence[Sequence[int]]) -> bytes:
    """Canonical DIMACS (specification §3.1); the empty clause is the line ' 0'."""
    lines = [f"p cnf {variables} {len(clauses)}"]
    for clause in clauses:
        lines.append(" ".join(str(x) for x in clause) + " 0" if clause else " 0")
    return ("\n".join(lines) + "\n").encode("ascii")


class Formula:
    """A formula given by its clause list; bytes and identities derive from it."""

    def __init__(self, name: str, variables: int, clauses: Sequence[Sequence[int]]) -> None:
        self.name = name
        self.variables = variables
        self.clauses = [list(c) for c in clauses]
        self.data = dimacs(variables, self.clauses)
        self.sha256 = sha(self.data)

    def cube_cnf(self, cube: Sequence[int]) -> bytes:
        """CNF(F, C), built as the plain construction: all clauses, then one unit per literal."""
        return dimacs(self.variables, self.clauses + [[x] for x in cube])

    def cube_sha256(self, cube: Sequence[int]) -> str:
        return sha(self.cube_cnf(cube))

    def satisfied_by(self, cube: Sequence[int], true_vars: Iterable[int]) -> bool:
        true = set(true_vars)

        def holds(literal: int) -> bool:
            return (abs(literal) in true) == (literal > 0)

        return all(holds(x) for x in cube) and all(
            any(holds(x) for x in clause) for clause in self.clauses
        )


def canonical_cube(literals: Iterable[int]) -> list[int]:
    return sorted(literals, key=abs)


def node_id(formula_sha256: str, cube: Sequence[int]) -> str:
    joined = " ".join(str(x) for x in cube)
    return sha(b"node\x00" + formula_sha256.encode("ascii") + b"\x00" + joined.encode("ascii"))


def node(formula: Formula, cube: Sequence[int]) -> dict[str, Any]:
    return {"formula_sha256": formula.sha256, "cube": list(cube)}


def split_id(identity: str, variables: Sequence[int]) -> str:
    return jsha({"node_id": identity, "variables": list(variables)})


def children(cube: Sequence[int], variables: Sequence[int]) -> list[list[int]]:
    """The 2^k sign children in child-index order: bit j of t set gives +W[j].

    Specification §3.2.
    """
    result = []
    for t in range(2 ** len(variables)):
        signed = [w if t & (1 << j) else -w for j, w in enumerate(variables)]
        result.append(canonical_cube(list(cube) + signed))
    return result


def w_problem(variables: Sequence[int], cube: Sequence[int], count: int) -> str | None:
    """First problem of W in reading 5 order, without the 'split.' prefix."""
    checks = (
        ("empty", len(variables) == 0),
        ("too_long", len(variables) > K_MAX),
        ("repeated", len(set(variables)) < len(variables)),
        ("out_of_range", any(v > count for v in variables)),
        ("in_cube", any(abs(x) in variables for x in cube)),
    )
    return next((name for name, bad in checks if bad), None)


def bitset(variables: int, true_vars: Iterable[int]) -> str:
    """Canonical assignment of specification §4.8: variable i is bit (i-1)%8 of byte (i-1)//8."""
    raw = bytearray((variables + 7) // 8)
    for v in true_vars:
        raw[(v - 1) // 8] |= 1 << ((v - 1) % 8)
    return base64.b64encode(bytes(raw)).decode("ascii")


def bitset_values(text: str, variables: int) -> set[int] | None:
    """True variables of a canonical bitset, or None for a non-canonical/incomplete one."""
    try:
        raw = base64.b64decode(text, validate=True)
    except ValueError:
        return None
    if bitset(variables, _ones(raw, variables)) != text:
        return None
    return set(_ones(raw, variables))


def _ones(raw: bytes, variables: int) -> list[int]:
    return [
        v
        for v in range(1, variables + 1)
        if (v - 1) // 8 < len(raw) and raw[(v - 1) // 8] >> ((v - 1) % 8) & 1
    ]


def leaf(identity: str, cnf: str, proof: str) -> str:
    return sha(f"leaf\x00{identity}\x00{cnf}\x00{proof}".encode("ascii"))


def merkle_levels(leaves: Sequence[tuple[str, str, str]]) -> list[list[str]]:
    """All levels of the leaf Merkle tree (specification §10.5), leaves sorted by node_id first."""
    level = [leaf(*x) for x in sorted(leaves)]
    levels = [level]
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level), 2):
            pair = level[i : i + 2]
            if len(pair) == 2:
                nxt.append(sha(f"branch\x00{pair[0]}\x00{pair[1]}".encode("ascii")))
            else:
                nxt.append(pair[0])
        level = nxt
        levels.append(level)
    return levels


def merkle(leaves: Sequence[tuple[str, str, str]]) -> str | None:
    if not leaves:
        return None
    return merkle_levels(leaves)[-1][0]


def utc(seconds: int) -> str:
    """A deterministic UTC string counted from 2026-10-01T00:00:00.000Z."""
    day, rest = divmod(seconds, 86400)
    hour, rest = divmod(rest, 3600)
    minute, second = divmod(rest, 60)
    return f"2026-10-{1 + day:02d}T{hour:02d}:{minute:02d}:{second:02d}.000Z"
