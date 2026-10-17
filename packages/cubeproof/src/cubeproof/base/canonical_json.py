"""J(x), the one canonical JSON encoding, and the strict readers of specification §4.1.

``J(x)`` is the UTF-8 encoding of ``json.dumps(x, sort_keys=True, separators=(",", ":"),
ensure_ascii=False, allow_nan=False)``. Values are restricted to objects with string keys,
arrays, strings, booleans, null and integers in ``[-(2^63-1), 2^63-1]``: no floating point,
no unpaired surrogates. A canonical document on disk is ``J(x)`` plus one LF; a journal line
is exactly ``J(record)`` (its LF is the line terminator, handled by the journal reader).

The readers check, in this order: byte order mark, strict UTF-8, JSON syntax with duplicate
keys, non-integer numbers and integer range (also for literals too long to convert), then
unpaired surrogates and nesting depth, and finally canonical bytes (number spelling, key
order, separators, escapes). Every violation raises
:class:`~cubeproof.base.errors.ContractError` named by its requirement (``json.*``); a reader
limit (``limit.depth``, ``limit.document``, ``limit.line``) raises
:class:`~cubeproof.base.errors.ResourceError`. Depth counts a scalar as 0 and each array or
object as 1, so the default limit 32 admits exactly 32 nested containers.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from cubeproof.base.errors import ContractError, ResourceError
from cubeproof.base.settings import DEFAULT_LIMITS, ReaderLimits

INT_MAX = 2**63 - 1
_MAX_DIGITS = len(str(INT_MAX))
_BOM = b"\xef\xbb\xbf"


def _has_surrogate(text: str) -> bool:
    return any(0xD800 <= ord(char) <= 0xDFFF for char in text)


def _check_tree(value: Any, limit: int) -> None:
    """Integer range, surrogates and depth of a decoded value; iterative (no recursion)."""
    stack: list[tuple[Any, int]] = [(value, 0)]
    while stack:
        item, depth = stack.pop()
        if item is None or isinstance(item, bool):
            continue
        if isinstance(item, int):
            if not -INT_MAX <= item <= INT_MAX:
                raise ContractError("json.integer_range", str(item))
            continue
        if isinstance(item, str):
            if _has_surrogate(item):
                raise ContractError("json.surrogate", "unpaired surrogate in a string")
            continue
        if depth + 1 > limit:
            raise ResourceError("limit.depth", f"nesting deeper than {limit}")
        if isinstance(item, list):
            stack.extend((element, depth + 1) for element in item)
        else:
            for key, element in item.items():
                if _has_surrogate(key):
                    raise ContractError("json.surrogate", "unpaired surrogate in a key")
                stack.append((element, depth + 1))


def _check_encodable(value: Any) -> None:
    """Python types allowed by J; JSON rule violations of a value to be written."""
    stack: list[Any] = [value]
    while stack:
        item = stack.pop()
        if item is None or isinstance(item, (bool, str)):
            if isinstance(item, str) and _has_surrogate(item):
                raise ContractError("json.surrogate", "unpaired surrogate in a string")
            continue
        if isinstance(item, int):
            if not -INT_MAX <= item <= INT_MAX:
                raise ContractError("json.integer_range", str(item))
            continue
        if isinstance(item, float):
            raise ContractError("json.number", repr(item))
        if isinstance(item, (list, tuple)):
            stack.extend(item)
            continue
        if isinstance(item, dict):
            for key, element in item.items():
                if not isinstance(key, str):
                    raise TypeError(f"JSON object keys must be strings, not {key!r}")
                if _has_surrogate(key):
                    raise ContractError("json.surrogate", "unpaired surrogate in a key")
                stack.append(element)
            continue
        raise TypeError(f"{type(item).__name__} is not a JSON value")


def encode(value: Any) -> bytes:
    """J(value): the canonical bytes (no final LF). Tuples encode as arrays."""
    _check_encodable(value)
    text = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    )
    return text.encode("utf-8")


def document_bytes(value: Any) -> bytes:
    """A canonical document file: J(value) plus one LF."""
    return encode(value) + b"\n"


def json_sha256(value: Any) -> str:
    """SHA256(J(value)) in lowercase hex (policy, campaign, shard and split identities)."""
    return hashlib.sha256(encode(value)).hexdigest()


def _reject_number(text: str) -> Any:
    raise ContractError("json.number", text)


def _parse_int(text: str) -> int:
    if len(text.lstrip("-")) > _MAX_DIGITS:
        raise ContractError("json.integer_range", f"integer literal of {len(text)} characters")
    return int(text)


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ContractError("json.duplicate_key", repr(key))
        result[key] = value
    return result


def parse_json(data: bytes, *, limits: ReaderLimits = DEFAULT_LIMITS) -> Any:
    """One strict JSON value from ``data`` (specification §4.1), without the canonical-bytes
    check."""
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError("parse_json reads bytes")
    raw = bytes(data)
    if raw.startswith(_BOM):
        raise ContractError("json.bom", "byte order mark")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ContractError("json.utf8", str(exc)) from None
    try:
        value = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_float=_reject_number,
            parse_constant=_reject_number,
            parse_int=_parse_int,
        )
    except ContractError:
        raise
    except RecursionError:
        # Nesting far beyond any configurable depth limit exhausted the decoder stack.
        raise ResourceError("limit.depth", "nesting too deep to decode") from None
    except ValueError as exc:
        raise ContractError("json.syntax", str(exc)) from None
    _check_tree(value, limits.depth)
    return value


def parse_document(data: bytes, *, limits: ReaderLimits = DEFAULT_LIMITS) -> Any:
    """A canonical document: exactly J(x) plus one LF, J(x) at most ``limits.document_bytes``."""
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError("parse_document reads bytes")
    raw = bytes(data)
    body_length = len(raw) - 1 if raw.endswith(b"\n") else len(raw)
    if body_length > limits.document_bytes:
        raise ResourceError("limit.document", f"{body_length} bytes, limit {limits.document_bytes}")
    value = parse_json(raw, limits=limits)
    if raw != encode(value) + b"\n":
        raise ContractError("json.canonical", "not J(x) followed by one LF")
    return value


def parse_line(line: bytes, *, limits: ReaderLimits = DEFAULT_LIMITS) -> Any:
    """One complete journal line without its LF: exactly J(record), at most ``line_bytes``."""
    if not isinstance(line, (bytes, bytearray, memoryview)):
        raise TypeError("parse_line reads bytes")
    raw = bytes(line)
    if len(raw) > limits.line_bytes:
        raise ResourceError("limit.line", f"{len(raw)} bytes, limit {limits.line_bytes}")
    value = parse_json(raw, limits=limits)
    if raw != encode(value):
        raise ContractError("json.canonical", "not exactly J(record)")
    return value
