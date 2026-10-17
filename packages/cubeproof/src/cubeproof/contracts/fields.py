"""Field readers for the schema level of the v1 documents (the JSON Schemas, by hand).

The runtime has no JSON Schema validator; each document reader is written with these helpers
instead and is tested differentially against the frozen schemas. A violation raises
:class:`~cubeproof.base.errors.ContractError` with rule ``schema`` and the JSON location in
the notation of the contract corpus: ``$`` for the document, ``$.field``, ``$.list[3]`` and
``$.object<key>`` for an invalid property name. A missing required field is reported at
the object that lacks it; anything that fails inside an ``anyOf`` (nullable values,
literals) is reported at the location of the ``anyOf``.
"""

from __future__ import annotations

from collections.abc import Callable, Collection, Sequence
from typing import Any, NoReturn, TypeVar

from cubeproof.base.errors import ContractError
from cubeproof.contracts.primitives import INT_MAX

_T = TypeVar("_T")


def fail(at: str, why: str) -> NoReturn:
    raise ContractError("schema", why, location=at)


def member(at: str, name: str) -> str:
    return f"{at}.{name}"


def item(at: str, index: int) -> str:
    return f"{at}[{index}]"


def obj(value: Any, at: str, required: Collection[str], *, closed: bool = True) -> dict[str, Any]:
    """A JSON object with every ``required`` field and (if ``closed``) no other field."""
    if type(value) is not dict:
        fail(at, f"expected an object, got {type(value).__name__}")
    for name in required:
        if name not in value:
            fail(at, f"missing field {name!r}")
    if closed:
        for name in value:
            if name not in required:
                fail(member(at, name), "unknown field")
    return value


def open_object(value: Any, at: str) -> dict[str, Any]:
    """An explicitly open object (info, producer parameters): any fields."""
    return obj(value, at, (), closed=False)


def integer(value: Any, at: str, minimum: int = -INT_MAX, maximum: int = INT_MAX) -> int:
    if type(value) is not int:
        fail(at, f"expected an integer, got {type(value).__name__}")
    if not minimum <= value <= maximum:
        fail(at, f"{value} outside [{minimum}, {maximum}]")
    return value


def nonnegative(value: Any, at: str) -> int:
    return integer(value, at, 0)


def positive(value: Any, at: str) -> int:
    return integer(value, at, 1)


def boolean(value: Any, at: str) -> bool:
    if type(value) is not bool:
        fail(at, f"expected a boolean, got {type(value).__name__}")
    return value


def string(value: Any, at: str, min_length: int = 0) -> str:
    if type(value) is not str:
        fail(at, f"expected a string, got {type(value).__name__}")
    if len(value) < min_length:
        fail(at, f"shorter than {min_length}")
    return value


def matching(value: Any, at: str, predicate: Callable[[str], bool], what: str) -> str:
    """A string accepted by ``predicate`` (a pattern of the schema)."""
    text = string(value, at)
    if not predicate(text):
        fail(at, f"{text!r} is not a {what}")
    return text


def const(value: Any, at: str, expected: str) -> str:
    if type(value) is not str or value != expected:
        fail(at, f"not the constant {expected!r}")
    return value


def choice(value: Any, at: str, allowed: Collection[str]) -> str:
    if type(value) is not str or value not in allowed:
        fail(at, f"{value!r} not in {sorted(allowed)!r}")
    return value


def array(value: Any, at: str, min_items: int = 0) -> list[Any]:
    if type(value) is not list:
        fail(at, f"expected an array, got {type(value).__name__}")
    if len(value) < min_items:
        fail(at, f"fewer than {min_items} items")
    return value


def items(value: Any, at: str, read: Callable[[Any, str], _T], min_items: int = 0) -> list[_T]:
    """An array whose every element is read by ``read(element, location)``."""
    return [read(element, item(at, i)) for i, element in enumerate(array(value, at, min_items))]


def strings(value: Any, at: str) -> tuple[str, ...]:
    return tuple(items(value, at, string))


def nullable(value: Any, at: str, read: Callable[[Any, str], _T]) -> _T | None:
    """``anyOf: [null, X]``: None, or ``read(value)``; any failure is reported at ``at``."""
    if value is None:
        return None
    try:
        return read(value, at)
    except ContractError as error:
        if error.rule != "schema":
            raise
        fail(at, f"matches none of anyOf ({error.detail})")


def literal(value: Any, at: str) -> int:
    """A nonzero Int64 (``Literal``; the range |l| <= V is a separate rule)."""
    if type(value) is not int or value == 0 or not -INT_MAX <= value <= INT_MAX:
        fail(at, f"{value!r} is not a literal")
    return value


def property_names(value: dict[str, Any], at: str, predicate: Callable[[str], bool]) -> None:
    for name in value:
        if not predicate(name):
            fail(f"{at}<{name}>", f"invalid property name {name!r}")


def first_problem(checks: Sequence[Callable[[], str | None]]) -> str | None:
    """The first non-None result of ``checks``, evaluated lazily in order."""
    for check in checks:
        problem = check()
        if problem is not None:
            return problem
    return None
