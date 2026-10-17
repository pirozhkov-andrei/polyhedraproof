"""A small, strict JSON Schema validator for the frozen cubeproof v1 schemas.

The contract tests do not depend on a third-party validator. This module implements the
subset of JSON Schema (draft 2020-12 keywords) that the files in ``schemas/cubeproof/v1``
use, with the JSON rules of specification §4.1: an integer is never a boolean, ``const`` and
``enum`` compare with the JSON type, and ``pattern`` must match the whole string (every
pattern ends with ``(?![\\s\\S])``, end of input, instead of ``$``, which Python would match
before a final newline). A schema that uses any other keyword
is rejected, so the subset cannot silently grow.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any

ANNOTATIONS = frozenset({"$schema", "$id", "$defs", "$comment", "title", "description"})
KEYWORDS = frozenset(
    {
        "$ref",
        "type",
        "const",
        "enum",
        "properties",
        "required",
        "additionalProperties",
        "propertyNames",
        "items",
        "minItems",
        "maxItems",
        "minimum",
        "maximum",
        "minLength",
        "maxLength",
        "pattern",
        "oneOf",
        "anyOf",
        "allOf",
    }
)
TYPES = {"object", "array", "string", "integer", "boolean", "null"}


class SchemaError(Exception):
    """The schema itself is outside the supported subset or malformed."""


def json_equal(a: Any, b: Any) -> bool:
    """Equality of JSON values that distinguishes booleans from integers."""
    if isinstance(a, bool) or isinstance(b, bool):
        return type(a) is type(b) and a == b
    if isinstance(a, dict) and isinstance(b, dict):
        return a.keys() == b.keys() and all(json_equal(a[k], b[k]) for k in a)
    if isinstance(a, list) and isinstance(b, list):
        return len(a) == len(b) and all(json_equal(x, y) for x, y in zip(a, b))
    return type(a) is type(b) and a == b


_TYPE_NAMES = {
    type(None): "null",
    bool: "boolean",
    int: "integer",
    str: "string",
    list: "array",
    dict: "object",
}


def json_type(value: Any) -> str:
    """The JSON type of a parsed value; a float or other Python type keeps its own name."""
    return _TYPE_NAMES.get(type(value), type(value).__name__)


END_OF_INPUT = "(?![\\s\\S])"


def _full_pattern(pattern: str) -> re.Pattern[str]:
    """Patterns are written ``^body(?![\\s\\S])``: ECMA-262 and Python ``re.search`` both
    read that as a whole-string match, unlike ``$`` (Python matches it before a final LF)."""
    if not (pattern.startswith("^") and pattern.endswith(END_OF_INPUT)):
        raise SchemaError(f"pattern must start with ^ and end with {END_OF_INPUT}: {pattern!r}")
    return re.compile("(?:" + pattern[1 : -len(END_OF_INPUT)] + ")", re.DOTALL)


class SchemaStore:
    """All schema files of one directory, addressed by file name."""

    def __init__(self, directory: Path) -> None:
        self.directory = directory
        self.files: dict[str, dict[str, Any]] = {}
        for path in sorted(directory.glob("*.schema.json")):
            self.files[path.name] = json.loads(path.read_text(encoding="utf-8"))
        self._patterns: dict[str, re.Pattern[str]] = {}
        for name, schema in self.files.items():
            self._check_subset(schema, name)

    def _check_subset(self, schema: Any, where: str) -> None:
        if isinstance(schema, bool):
            return
        if not isinstance(schema, dict):
            raise SchemaError(f"{where}: schema is not an object")
        for key, value in schema.items():
            if key in ANNOTATIONS:
                if key == "$defs":
                    for name, sub in value.items():
                        self._check_subset(sub, f"{where}/$defs/{name}")
                continue
            if key not in KEYWORDS:
                raise SchemaError(f"{where}: unsupported keyword {key!r}")
            if key == "type":
                names = value if isinstance(value, list) else [value]
                if not names or any(n not in TYPES for n in names):
                    raise SchemaError(f"{where}: bad type {value!r}")
            elif key == "properties":
                for name, sub in value.items():
                    self._check_subset(sub, f"{where}/properties/{name}")
            elif key in ("additionalProperties", "items", "propertyNames"):
                self._check_subset(value, f"{where}/{key}")
            elif key in ("oneOf", "anyOf", "allOf"):
                if not isinstance(value, list) or not value:
                    raise SchemaError(f"{where}: {key} must be a nonempty list")
                for index, sub in enumerate(value):
                    self._check_subset(sub, f"{where}/{key}/{index}")
            elif key == "pattern":
                _full_pattern(value)
            elif key == "$ref":
                self.resolve(value, where.split("/", maxsplit=1)[0])

    def resolve(self, ref: str, base: str) -> tuple[dict[str, Any], str]:
        """The schema a ``$ref`` names, and the file it lives in."""
        file_part, _, pointer = ref.partition("#")
        name = file_part or base
        if name not in self.files:
            raise SchemaError(f"unknown schema file in $ref {ref!r}")
        target: Any = self.files[name]
        if pointer:
            if not pointer.startswith("/"):
                raise SchemaError(f"bad pointer in $ref {ref!r}")
            for part in pointer[1:].split("/"):
                if not isinstance(target, dict) or part not in target:
                    raise SchemaError(f"dangling $ref {ref!r}")
                target = target[part]
        if not isinstance(target, dict):
            raise SchemaError(f"$ref {ref!r} is not a schema object")
        return target, name

    def pattern(self, text: str) -> re.Pattern[str]:
        if text not in self._patterns:
            self._patterns[text] = _full_pattern(text)
        return self._patterns[text]

    def errors(self, instance: Any, file_name: str, pointer: str = "") -> list[str]:
        """Every violation of ``instance`` against a schema file (or a $defs entry)."""
        schema, base = self.resolve(file_name + ("#" + pointer if pointer else ""), file_name)
        return list(self._errors(instance, schema, base, "$"))

    def valid(self, instance: Any, file_name: str, pointer: str = "") -> bool:
        return not self.errors(instance, file_name, pointer)

    def _errors(self, value: Any, schema: Any, base: str, at: str) -> Iterator[str]:
        if schema is True:
            return
        if schema is False:
            yield f"{at}: not allowed"
            return
        if "$ref" in schema:
            target, target_base = self.resolve(schema["$ref"], base)
            yield from self._errors(value, target, target_base, at)
        kind = json_type(value)
        if "type" in schema:
            names = schema["type"] if isinstance(schema["type"], list) else [schema["type"]]
            if kind not in names:
                yield f"{at}: type {kind}, expected {names}"
                return
        if "const" in schema and not json_equal(value, schema["const"]):
            yield f"{at}: not the constant {schema['const']!r}"
        if "enum" in schema and not any(json_equal(value, e) for e in schema["enum"]):
            yield f"{at}: {value!r} not in {schema['enum']!r}"
        if kind == "integer":
            if "minimum" in schema and value < schema["minimum"]:
                yield f"{at}: {value} < {schema['minimum']}"
            if "maximum" in schema and value > schema["maximum"]:
                yield f"{at}: {value} > {schema['maximum']}"
        if kind == "string":
            if "minLength" in schema and len(value) < schema["minLength"]:
                yield f"{at}: shorter than {schema['minLength']}"
            if "maxLength" in schema and len(value) > schema["maxLength"]:
                yield f"{at}: longer than {schema['maxLength']}"
            if "pattern" in schema and not self.pattern(schema["pattern"]).fullmatch(value):
                yield f"{at}: {value!r} does not match {schema['pattern']!r}"
        if kind == "array":
            if "minItems" in schema and len(value) < schema["minItems"]:
                yield f"{at}: fewer than {schema['minItems']} items"
            if "maxItems" in schema and len(value) > schema["maxItems"]:
                yield f"{at}: more than {schema['maxItems']} items"
            if "items" in schema:
                for index, item in enumerate(value):
                    yield from self._errors(item, schema["items"], base, f"{at}[{index}]")
        if kind == "object":
            properties = schema.get("properties", {})
            for name in schema.get("required", []):
                if name not in value:
                    yield f"{at}: missing field {name!r}"
            for name, item in value.items():
                if "propertyNames" in schema:
                    yield from self._errors(name, schema["propertyNames"], base, f"{at}<{name}>")
                if name in properties:
                    yield from self._errors(item, properties[name], base, f"{at}.{name}")
                elif "additionalProperties" in schema:
                    yield from self._errors(
                        item, schema["additionalProperties"], base, f"{at}.{name}"
                    )
        for sub in schema.get("allOf", []):
            yield from self._errors(value, sub, base, at)
        if "anyOf" in schema and not any(
            not list(self._errors(value, sub, base, at)) for sub in schema["anyOf"]
        ):
            yield f"{at}: matches none of anyOf"
        if "oneOf" in schema:
            matches = sum(not list(self._errors(value, sub, base, at)) for sub in schema["oneOf"])
            if matches != 1:
                yield f"{at}: matches {matches} of oneOf, expected exactly 1"
