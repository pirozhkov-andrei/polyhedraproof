"""A small declarative transcription of the v1 record schemas (journal-record.schema.json).

The runtime has no JSON Schema validator. Each record field is described once by a
:class:`Spec` that can

- ``check`` a parsed JSON value at the schema level only (types, required and unknown fields,
  constants, enums, patterns, integer bounds), raising
  :class:`~cubeproof.base.errors.ContractError` ``schema`` at the location notation of
  :mod:`cubeproof.contracts.fields` (a failure inside a nullable ``anyOf`` is reported at the
  ``anyOf``);
- ``build`` the immutable Python value of a value that passed ``check`` and the record rules;
- ``dump`` a Python value back to JSON (values of the wrong type are passed through
  unchanged, so that ``check`` rejects them).

Rules beyond the schema (record rules, specification §4.7-§4.8) are not checked here; they live in
:mod:`cubeproof.evidence.schema.rules` and run between ``check`` and ``build``.
"""

from __future__ import annotations

import enum
import hashlib
import json
from collections.abc import Callable, Collection, Sequence
from typing import Any, TypeVar

from cubeproof.base.errors import ContractError
from cubeproof.contracts import fields as f
from cubeproof.contracts.documents import Shard
from cubeproof.contracts.policy import Policy
from cubeproof.contracts.primitives import is_hash, is_id128, is_name, is_relpath, utc_problem
from cubeproof.contracts.values import JsonObject, Node, node_from_json

_T = TypeVar("_T")


def checked_j(value: Any) -> bytes:
    """J(value) of a value whose types are already known to be J types.

    For values produced by the strict reader or accepted by a :class:`Spec` (open objects are
    :class:`~cubeproof.contracts.values.JsonObject` values, validated on construction): the
    general :func:`~cubeproof.base.canonical_json.encode` would repeat its per-character
    checks. The definition of J is the same ``json.dumps`` call (specification §4.1); a lone
    surrogate, the only J violation a schema cannot see, still fails here (json.surrogate).
    """
    text = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    )
    try:
        return text.encode("utf-8")
    except UnicodeEncodeError:
        raise ContractError("json.surrogate", "unpaired surrogate in a string") from None


def checked_sha256(value: Any) -> str:
    """SHA256(J(value)) of a value whose types are known to be J types (see checked_j)."""
    return hashlib.sha256(checked_j(value)).hexdigest()


class Spec:
    """Schema level, construction and serialization of one JSON value."""

    def check(self, value: Any, at: str) -> None:
        raise NotImplementedError

    def build(self, value: Any) -> Any:
        return value

    def dump(self, obj: Any) -> Any:
        return obj


class Scalar(Spec):
    """A value read by a :mod:`cubeproof.contracts.fields` reader; built as itself."""

    def __init__(self, reader: Callable[[Any, str], Any]) -> None:
        self._reader = reader

    def check(self, value: Any, at: str) -> None:
        self._reader(value, at)


def _bounded(minimum: int, maximum: int) -> Callable[[Any, str], Any]:
    return lambda value, at: f.integer(value, at, minimum, maximum)


def _pattern(predicate: Callable[[str], bool], what: str) -> Callable[[Any, str], Any]:
    return lambda value, at: f.matching(value, at, predicate, what)


def _utc_form(value: Any, at: str) -> Any:
    f.string(value, at)
    if utc_problem(value) == "schema":
        f.fail(at, f"{value!r} is not of the UTC form")
    return value


STRING = Scalar(f.string)
BOOLEAN = Scalar(f.boolean)
NONNEGATIVE = Scalar(f.nonnegative)
POSITIVE = Scalar(f.positive)
HASH = Scalar(_pattern(is_hash, "Hash"))
ID128 = Scalar(_pattern(is_id128, "Id128"))
NAME = Scalar(_pattern(is_name, "Name"))
RELPATH = Scalar(_pattern(is_relpath, "RelPath"))
UTC = Scalar(_utc_form)


def integer(minimum: int, maximum: int) -> Scalar:
    return Scalar(_bounded(minimum, maximum))


class Const(Spec):
    def __init__(self, expected: str) -> None:
        self.expected = expected

    def check(self, value: Any, at: str) -> None:
        f.const(value, at, self.expected)


class Choice(Spec):
    """A string from a closed vocabulary, kept as a string."""

    def __init__(self, allowed: Collection[str]) -> None:
        self._allowed = frozenset(allowed)

    def check(self, value: Any, at: str) -> None:
        f.choice(value, at, self._allowed)


class Enum(Spec):
    """A string enum: checked against the wire values, built as the member."""

    def __init__(self, cls: type[enum.Enum]) -> None:
        self._cls = cls
        self._values = frozenset(str(m.value) for m in cls)

    def check(self, value: Any, at: str) -> None:
        f.choice(value, at, self._values)

    def build(self, value: Any) -> Any:
        return self._cls(value)

    def dump(self, obj: Any) -> Any:
        return obj.value if isinstance(obj, self._cls) else obj


class Nullable(Spec):
    """``anyOf: [null, X]``; any schema failure of X is reported at the ``anyOf``."""

    def __init__(self, inner: Spec) -> None:
        self.inner = inner

    def check(self, value: Any, at: str) -> None:
        if value is None:
            return
        try:
            self.inner.check(value, at)
        except ContractError as error:
            if error.rule != "schema":
                raise
            f.fail(at, f"matches none of anyOf ({error.detail})")

    def build(self, value: Any) -> Any:
        return None if value is None else self.inner.build(value)

    def dump(self, obj: Any) -> Any:
        return None if obj is None else self.inner.dump(obj)


class Array(Spec):
    """An array of one item type, built as a tuple."""

    def __init__(self, item: Spec, min_items: int = 0) -> None:
        self.item = item
        self.min_items = min_items

    def check(self, value: Any, at: str) -> None:
        for index, element in enumerate(f.array(value, at, self.min_items)):
            self.item.check(element, f.item(at, index))

    def build(self, value: Any) -> Any:
        return tuple(self.item.build(element) for element in value)

    def dump(self, obj: Any) -> Any:
        if isinstance(obj, (list, tuple)):
            return [self.item.dump(element) for element in obj]
        return obj


def construct(cls: type[_T], values: dict[str, Any]) -> _T:
    """An instance of the frozen dataclass ``cls`` from already validated field values.

    Bypasses ``__init__``/``__post_init__``: used only by :meth:`Struct.build` after the
    schema and the record rules accepted the JSON value the fields were built from.
    """
    obj = object.__new__(cls)
    for name, value in values.items():
        object.__setattr__(obj, name, value)
    return obj


class Struct(Spec):
    """A closed JSON object with fixed fields, built as the frozen dataclass ``cls``.

    Field names are the JSON names and the dataclass attribute names. ``rule`` (optional)
    names the first record rule a schema-valid value violates; it is used when a value is
    constructed directly (see :func:`validate`), the journal reader applies the rules of
    :mod:`cubeproof.evidence.schema.rules` itself.
    """

    def __init__(
        self,
        cls: type[Any],
        fields: Sequence[tuple[str, Spec]],
        rule: Callable[[dict[str, Any]], str | None] | None = None,
    ) -> None:
        self.cls = cls
        self.fields = tuple(fields)
        self.names = tuple(name for name, _ in self.fields)
        self.rule = rule

    def check(self, value: Any, at: str) -> None:
        f.obj(value, at, self.names)
        for name, spec in self.fields:
            spec.check(value[name], f.member(at, name))

    def build(self, value: Any) -> Any:
        return construct(self.cls, {name: spec.build(value[name]) for name, spec in self.fields})

    def dump(self, obj: Any) -> Any:
        if isinstance(obj, self.cls):
            return {name: spec.dump(getattr(obj, name)) for name, spec in self.fields}
        return obj


class Wrapped(Spec):
    """A value of :mod:`cubeproof.contracts` whose ``from_json`` is schema-level only."""

    def __init__(self, cls: Any) -> None:
        self.cls = cls

    def check(self, value: Any, at: str) -> None:
        self.cls.from_json(value, at)

    def build(self, value: Any) -> Any:
        return self.cls.from_json(value)

    def dump(self, obj: Any) -> Any:
        return obj.to_json() if isinstance(obj, self.cls) else obj


class NodeSpec(Spec):
    """A Node; the canonical cube (``cube.canonical``) is a record rule, checked before build."""

    def check(self, value: Any, at: str) -> None:
        node_from_json(value, at)

    def build(self, value: Any) -> Any:
        return Node(value["formula_sha256"], tuple(value["cube"]))

    def dump(self, obj: Any) -> Any:
        return obj.to_json() if isinstance(obj, Node) else obj


class PolicySpec(Spec):
    """A complete policy (policy.schema.json); policy.* cross-field rules come later."""

    def check(self, value: Any, at: str) -> None:
        Policy.parse_schema(value, at)

    def build(self, value: Any) -> Any:
        return Policy.from_json(value)

    def dump(self, obj: Any) -> Any:
        return obj.to_json() if isinstance(obj, Policy) else obj


class OpenSpec(Spec):
    """An explicitly open object (diagnostics, splitter info), kept as its J text."""

    def check(self, value: Any, at: str) -> None:
        f.open_object(value, at)

    def build(self, value: Any) -> Any:
        return JsonObject.from_json(value)

    def dump(self, obj: Any) -> Any:
        return obj.to_json() if isinstance(obj, JsonObject) else obj


_SHARD_FIELDS = (
    ("format", Const("cubeproof-shard-1")),
    ("campaign", HASH),
    ("name", NAME),
    ("nodes", Array(NodeSpec(), min_items=1)),
)


class ShardSpec(Spec):
    """An embedded shard (shard.schema.json); shard.nodes is a record rule, checked first."""

    def check(self, value: Any, at: str) -> None:
        f.obj(value, at, tuple(name for name, _ in _SHARD_FIELDS))
        for name, spec in _SHARD_FIELDS:
            spec.check(value[name], f.member(at, name))

    def build(self, value: Any) -> Any:
        nodes = tuple(NodeSpec().build(node) for node in value["nodes"])
        return Shard(value["campaign"], value["name"], nodes)

    def dump(self, obj: Any) -> Any:
        return obj.to_json() if isinstance(obj, Shard) else obj


def validate(obj: Any, spec: Struct) -> None:
    """Validate a directly constructed value and store its canonical field values.

    The value is dumped to JSON, checked at the schema level and by ``spec.rule``, and
    rebuilt; every field is then replaced by the rebuilt one (lists become tuples, wire
    strings become enum members, JSON objects become values). Raises ContractError.
    """
    try:
        value = spec.dump(obj)
    except (AttributeError, TypeError, ValueError) as exc:
        raise ContractError("schema", f"{type(obj).__name__}: {exc}") from None
    spec.check(value, "$")
    if spec.rule is not None:
        problem = spec.rule(value)
        if problem is not None:
            raise ContractError(problem, f"{type(obj).__name__} violates {problem}")
    built = spec.build(value)
    for name in spec.names:
        object.__setattr__(obj, name, getattr(built, name))
