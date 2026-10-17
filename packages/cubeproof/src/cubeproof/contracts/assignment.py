"""Canonical assignment bitsets of specification §4.8 (requirement attempt.assignment).

An assignment of V variables is the canonical, standard, padded base64 of exactly
``ceil(V/8)`` bytes. Variable ``i`` is bit ``(i-1) % 8`` of byte ``(i-1) // 8``, least
significant bit first; unused high bits of the last byte are zero; V = 0 encodes as the
empty string. Decoding accepts only the one canonical spelling.
"""

from __future__ import annotations

import base64
import binascii
import re
from collections.abc import Iterable, Sequence

from cubeproof.base.errors import ContractError
from cubeproof.contracts.primitives import INT_MAX

_BASE64 = re.compile(r"(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?")


def _count(variables: object) -> int:
    if type(variables) is not int or not 0 <= variables <= INT_MAX:
        raise ContractError("attempt.assignment", f"{variables!r} is not a variable count")
    return variables


def encode_assignment(values: Sequence[bool]) -> str:
    """The bitset of ``values[i-1]`` = value of variable i."""
    raw = bytearray((len(values) + 7) // 8)
    for index, value in enumerate(values):
        if type(value) is not bool:
            raise ContractError("attempt.assignment", f"{value!r} is not a boolean")
        if value:
            raw[index // 8] |= 1 << (index % 8)
    return base64.b64encode(bytes(raw)).decode("ascii")


def assignment_from_true(true_variables: Iterable[int], variables: int) -> str:
    """The bitset in which exactly ``true_variables`` (each in 1..V) are true."""
    count = _count(variables)
    values = [False] * count
    for variable in true_variables:
        if type(variable) is not int or not 1 <= variable <= count:
            raise ContractError("attempt.assignment", f"variable {variable!r} outside 1..{count}")
        values[variable - 1] = True
    return encode_assignment(values)


def decode_assignment(text: str, variables: int) -> tuple[bool, ...]:
    """The values of variables 1..V; :class:`ContractError` attempt.assignment otherwise."""
    count = _count(variables)
    if not isinstance(text, str) or _BASE64.fullmatch(text) is None:
        raise ContractError("attempt.assignment", "not padded standard base64")
    try:
        raw = base64.b64decode(text.encode("ascii"), validate=True)
    except (binascii.Error, ValueError):
        raise ContractError("attempt.assignment", "not padded standard base64") from None
    if base64.b64encode(raw).decode("ascii") != text:
        raise ContractError("attempt.assignment", "noncanonical padding bits")
    if len(raw) != (count + 7) // 8:
        raise ContractError("attempt.assignment", f"{len(raw)} bytes for V={count}")
    if count % 8 and raw[-1] >> (count % 8):
        raise ContractError("attempt.assignment", "an unused high bit is set")
    return tuple(bool(raw[i // 8] >> (i % 8) & 1) for i in range(count))
