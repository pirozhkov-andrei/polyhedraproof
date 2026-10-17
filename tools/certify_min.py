#!/usr/bin/env python3
"""certify_min: independent minimal certifier of cubeproof v1 evidence.

Its basis is the specification (docs/SPECIFICATION.md), cited below as "specification §n":
it is written from specification §3-§7 and §10, the shared JSON schemas
(schemas/cubeproof/v1) and the frozen contract vectors, without reading the main certifier.
It imports only the Python standard library and no project module.

    certify_min.py certify --campaign CAMPAIGN.json --journals J1.jsonl ... -o CERT.json
    certify_min.py compare A.json B.json
    certify_min.py corpus [--corpus DIR]

certify writes the certificate J(certificate)+LF and prints a JSON report on stdout. Exit codes
(specification §12.2): PROVED 0, OPEN 1, MODEL_FOUND 2, INCONSISTENT 4 (certificate written),
usage 3, and 4 for every input, integrity or resource error (no certificate; the report names
kind and rule).
Any other failure (an unexpected exception or an unwritable output) is reported as kind
"internal" with exit 4, never as a verdict exit code (specification §4.9).

Agreement with the main certifier is not proof of journal honesty (specification §10.5).
"""

from __future__ import annotations

import argparse
import base64
import binascii
import contextlib
import functools
import hashlib
import itertools
import json
import os
import re
import stat
import sys
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

INT_LIMIT = (1 << 63) - 1
DECIMAL_DIGITS = len(str(INT_LIMIT))  # 19: longer canonical decimals exceed INT_LIMIT
LINE_LIMIT = 8 * 1024 * 1024
DOCUMENT_LIMIT = 64 * 1024 * 1024
DEPTH_LIMIT = 32
TAIL_LIMIT = 16 * 1024
K_MAX = 20
ZERO_HASH = "0" * 64
VERIFIED_LINE = "s VERIFIED UNSAT\n"
SCHEMA_DIR = Path(__file__).resolve().parent.parent / "schemas" / "cubeproof" / "v1"

EXHAUSTED_REASONS = {
    "proof_size",
    "time",
    "check_time",
    "check_memory",
    "check_stack",
    "solver_memory",
}
TOOL_FAILED_REASONS = {
    "launch",
    "binary_changed",
    "io",
    "file_changed",
    "crash",
    "protocol",
    "relay",
}
PARSE_ERRORS = {"missing", "conflicting", "out_of_range", "syntax"}
AUDIT_TYPES = {"audit_begin", "audit_target", "audit_ready", "audit_result"}
AUDIT_PURPOSE_ALLOWED = {"header", "resume", "repair", "attempt"} | AUDIT_TYPES


# --------------------------------------------------------------------------------------------
# Errors


class Failure(Exception):
    """A violated requirement, named by its id in requirements.json (or 'schema')."""

    def __init__(self, rule: str, detail: str = "") -> None:
        super().__init__(f"{rule}: {detail}" if detail else rule)
        self.rule = rule
        self.detail = detail


class CertifyError(Exception):
    """An error that prevents a certificate: kind input, integrity or resource (reading 6 of
    schemas/cubeproof/v1/requirements.json)."""

    exit_code = 4

    def __init__(self, kind: str, rule: str, detail: str = "", where: str = "") -> None:
        super().__init__(f"{kind} error {rule} at {where}: {detail}")
        self.kind = kind
        self.rule = rule
        self.detail = detail
        self.where = where

    def report(self) -> dict[str, Any]:
        return {"kind": self.kind, "rule": self.rule, "detail": self.detail, "where": self.where}


def _kind(rule: str, context: str) -> str:
    """Error kind of a violated rule in a reading context (requirements.json, reading 6)."""
    if rule.startswith("limit."):
        return "resource"
    if context == "campaign":
        return "input"
    if rule in ("journal.no_header", "journal.campaign"):
        return "input"
    return "integrity"


# --------------------------------------------------------------------------------------------
# Canonical JSON (specification §4.1)


def canonical_json(value: Any) -> bytes:
    """J(x): sorted keys, no whitespace, UTF-8 without ASCII escaping."""
    text = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    )
    return text.encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hash_value(value: Any) -> str:
    return sha256_hex(canonical_json(value))


class _NotInteger(Exception):
    pass


class _DuplicateKey(Exception):
    pass


def _no_float(text: str) -> Any:
    raise _NotInteger(text)


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise _DuplicateKey(key)
        out[key] = value
    return out


def _has_lone_surrogate(text: str) -> bool:
    return any(0xD800 <= ord(ch) <= 0xDFFF for ch in text)


def _walk_values(value: Any) -> None:
    """Integer range, surrogates and nesting depth, iteratively (no recursion limit)."""
    stack: list[tuple[Any, int]] = [(value, 0)]
    while stack:
        item, depth = stack.pop()
        if isinstance(item, bool) or item is None:
            continue
        if isinstance(item, int):
            if not -INT_LIMIT <= item <= INT_LIMIT:
                raise Failure("json.integer_range", str(item))
        elif isinstance(item, str):
            if _has_lone_surrogate(item):
                raise Failure("json.surrogate")
        elif isinstance(item, list):
            if depth + 1 > DEPTH_LIMIT:
                raise Failure("limit.depth", f"depth {depth + 1}")
            stack.extend((x, depth + 1) for x in item)
        elif isinstance(item, dict):
            if depth + 1 > DEPTH_LIMIT:
                raise Failure("limit.depth", f"depth {depth + 1}")
            for key, x in item.items():
                if _has_lone_surrogate(key):
                    raise Failure("json.surrogate")
                stack.append((x, depth + 1))


def parse_json(data: bytes) -> Any:
    """Strict JSON value of specification §4.1, not yet checked for canonical spelling."""
    if data.startswith(b"\xef\xbb\xbf"):
        raise Failure("json.bom")
    try:
        text = data.decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        raise Failure("json.utf8", str(exc)) from None
    try:
        value = json.loads(
            text, object_pairs_hook=_pairs, parse_float=_no_float, parse_constant=_no_float
        )
    except _NotInteger as exc:
        raise Failure("json.number", str(exc)) from None
    except _DuplicateKey as exc:
        raise Failure("json.duplicate_key", str(exc)) from None
    except RecursionError:
        raise Failure("limit.depth", "recursion") from None
    except ValueError as exc:
        raise Failure("json.syntax", str(exc)) from None
    _walk_values(value)
    return value


def parse_canonical(data: bytes) -> Any:
    """Parse J(x) exactly (no trailing LF)."""
    value = parse_json(data)
    if canonical_json(value) != data:
        raise Failure("json.canonical")
    return value


def read_document_bytes(data: bytes, limit: int = DOCUMENT_LIMIT) -> tuple[Any, str]:
    """A canonical document J(x)+LF; returns the value and its document hash."""
    body = data[:-1] if data.endswith(b"\n") else data
    if len(body) > limit:
        raise Failure("limit.document", f"{len(body)} bytes")
    value = parse_json(body)
    if not data.endswith(b"\n") or canonical_json(value) != body:
        raise Failure("json.canonical")
    return value, sha256_hex(body)


# --------------------------------------------------------------------------------------------
# A small JSON Schema reader for the subset used by schemas/cubeproof/v1


class SchemaStore:
    def __init__(self, directory: Path = SCHEMA_DIR) -> None:
        self.directory = directory
        self.documents: dict[str, Any] = {}
        self.patterns: dict[str, re.Pattern[str]] = {}

    def document(self, name: str) -> Any:
        if name not in self.documents:
            path = self.directory / name
            try:
                self.documents[name] = json.loads(path.read_bytes())
            except OSError as exc:
                raise CertifyError("input", "schema", f"cannot read schema {path}: {exc}") from None
        return self.documents[name]

    def resolve(self, base: str, ref: str) -> tuple[str, Any]:
        name, _, pointer = ref.partition("#")
        name = name or base
        node = self.document(name)
        for part in [p for p in pointer.split("/") if p]:
            node = node[part]
        return name, node

    def pattern(self, text: str) -> re.Pattern[str]:
        if text not in self.patterns:
            self.patterns[text] = re.compile(text)
        return self.patterns[text]

    def problems(self, base: str, schema: Any, value: Any, where: str = "") -> list[str]:
        out: list[str] = []
        self._check(base, schema, value, where or "$", out)
        return out

    def _check(  # noqa: PLR0911 - one early return per keyword keeps the order visible
        self, base: str, schema: Any, value: Any, where: str, out: list[str]
    ) -> None:
        if schema is True or schema == {}:
            return
        if schema is False:
            out.append(where)
            return
        if "$ref" in schema:
            name, target = self.resolve(base, schema["$ref"])
            self._check(name, target, value, where, out)
        if "anyOf" in schema and not any(
            not self.problems(base, s, value, where) for s in schema["anyOf"]
        ):
            out.append(where)
            return
        if "const" in schema and not _same(value, schema["const"]):
            out.append(where)
            return
        if "enum" in schema and not any(_same(value, e) for e in schema["enum"]):
            out.append(where)
            return
        kind = schema.get("type")
        if kind is not None and not _is_type(value, kind):
            out.append(where)
            return
        if isinstance(value, bool):
            return
        if isinstance(value, int):
            if "minimum" in schema and value < schema["minimum"]:
                out.append(where)
            if "maximum" in schema and value > schema["maximum"]:
                out.append(where)
        elif isinstance(value, str):
            if "minLength" in schema and len(value) < schema["minLength"]:
                out.append(where)
            if "pattern" in schema and not self.pattern(schema["pattern"]).search(value):
                out.append(where)
        elif isinstance(value, list):
            if "minItems" in schema and len(value) < schema["minItems"]:
                out.append(where)
            if "items" in schema:
                for i, item in enumerate(value):
                    self._check(base, schema["items"], item, f"{where}[{i}]", out)
        elif isinstance(value, dict):
            for key in schema.get("required", []):
                if key not in value:
                    out.append(f"{where}.{key}")
            props = schema.get("properties", {})
            extra = schema.get("additionalProperties", True)
            names = schema.get("propertyNames")
            for key, item in value.items():
                if names is not None:
                    self._check(base, names, key, f"{where}.{key}", out)
                if key in props:
                    self._check(base, props[key], item, f"{where}.{key}", out)
                else:
                    self._check(base, extra, item, f"{where}.{key}", out)


def _is_type(value: Any, kind: str) -> bool:
    if kind == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if kind == "string":
        return isinstance(value, str)
    if kind == "boolean":
        return isinstance(value, bool)
    if kind == "null":
        return value is None
    if kind == "array":
        return isinstance(value, list)
    if kind == "object":
        return isinstance(value, dict)
    raise ValueError(kind)


def _same(a: Any, b: Any) -> bool:
    if isinstance(a, bool) or isinstance(b, bool):
        return type(a) is type(b) and a == b
    return bool(a == b)


@functools.cache
def store() -> SchemaStore:
    """The process-wide schema store, created on first use."""
    return SchemaStore()


SCHEMA_FILES = {
    "common": "common.schema.json",
    "campaign": "campaign.schema.json",
    "policy": "policy.schema.json",
    "bundle-manifest": "bundle-manifest.schema.json",
    "shard": "shard.schema.json",
    "handoff-request": "handoff-request.schema.json",
    "journal-record": "journal-record.schema.json",
    "certificate": "certificate.schema.json",
}


def schema_problems(kind: str, definition: str | None, value: Any) -> list[str]:
    """Locations where value violates a schema document (or one of its $defs)."""
    name = SCHEMA_FILES[kind]
    ref = f"{name}#/$defs/{definition}" if definition else f"{name}#"
    base, schema = store().resolve(name, ref)
    return store().problems(base, schema, value)


def require_schema(kind: str, definition: str | None, value: Any) -> None:
    found = schema_problems(kind, definition, value)
    if found:
        raise Failure("schema", ", ".join(found[:5]))


# --------------------------------------------------------------------------------------------
# Primitive rules


_UTC = re.compile(r"([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})\.[0-9]{3}Z")


def utc_valid(text: str) -> bool:
    """utc.calendar: a valid instant of the proleptic Gregorian calendar."""
    match = _UTC.fullmatch(text) if text.isascii() else None
    if match is None:
        return False
    year, month, day, hour, minute, second = (int(x) for x in match.groups())
    if not 1 <= month <= 12 or hour > 23 or minute > 59 or second > 59:
        return False
    leap = year % 4 == 0 and (year % 100 != 0 or year % 400 == 0)
    days = [31, 29 if leap else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][month - 1]
    return 1 <= day <= days


def require_utc(text: str) -> None:
    if not utc_valid(text):
        raise Failure("utc.calendar", text)


def strictly_sorted(keys: list[Any]) -> bool:
    return all(a < b for a, b in itertools.pairwise(keys))


def cube_problem(cube: list[int], variables: int) -> str | None:
    """cube.canonical (sorted strictly by |literal|), then cube.range."""
    magnitudes = [abs(x) for x in cube]
    if any(a >= b for a, b in itertools.pairwise(magnitudes)):
        return "cube.canonical"
    if any(m > variables or m == 0 for m in magnitudes):
        return "cube.range"
    return None


def split_problem(w: list[int], cube: list[int], variables: int) -> str | None:
    """W problems in the order of requirements.json, reading 5: empty, too_long, repeated,
    out_of_range, in_cube."""
    if not w:
        return "split.empty"
    if len(w) > K_MAX:
        return "split.too_long"
    if len(set(w)) != len(w):
        return "split.repeated"
    if any(v < 1 or v > variables for v in w):
        return "split.out_of_range"
    used = {abs(x) for x in cube}
    if any(v in used for v in w):
        return "split.in_cube"
    return None


def incompatible(a: Iterable[int], b: Iterable[int]) -> bool:
    """Some variable occurs with opposite signs."""
    signs = {abs(x): x > 0 for x in a}
    return any(abs(y) in signs and signs[abs(y)] != (y > 0) for y in b)


def node_id(formula_sha256: str, cube: Iterable[int]) -> str:
    text = "node\0" + formula_sha256 + "\0" + " ".join(str(x) for x in cube)
    return sha256_hex(text.encode("ascii"))


def split_id(node: str, variables: list[int]) -> str:
    return hash_value({"node_id": node, "variables": variables})


def split_children(cube: Iterable[int], w: list[int]) -> Iterator[tuple[int, ...]]:
    """Children in child-number order; bit j of t set gives +W[j] (specification §3.2)."""
    base = list(cube)
    for t in range(1 << len(w)):
        lits = base + [v if (t >> j) & 1 else -v for j, v in enumerate(w)]
        yield tuple(sorted(lits, key=abs))


def decode_assignment(text: str, variables: int) -> list[bool]:
    """attempt.assignment: canonical padded base64 of ceil(V/8) bytes, unused bits zero."""
    size = (variables + 7) // 8
    try:
        raw = base64.b64decode(text.encode("ascii"), validate=True)
    except (binascii.Error, UnicodeEncodeError, ValueError):
        raise Failure("attempt.assignment", "not base64") from None
    if base64.b64encode(raw).decode("ascii") != text or len(raw) != size:
        raise Failure("attempt.assignment", "not canonical or wrong length")
    if variables % 8 and raw[-1] >> (variables % 8):
        raise Failure("attempt.assignment", "unused bits set")
    return [bool(raw[(i - 1) // 8] >> ((i - 1) % 8) & 1) for i in range(1, variables + 1)]


def leaf_hash(node: str, cnf: str, proof: str) -> str:
    return sha256_hex(f"leaf\0{node}\0{cnf}\0{proof}".encode("ascii"))


def merkle_root(leaves: Iterable[tuple[str, str, str]]) -> str | None:
    """Specification §10.5: leaves sorted by node_id; odd last element carried unchanged."""
    level = [leaf_hash(*x) for x in sorted(leaves, key=lambda x: x[0])]
    if not level:
        return None
    while len(level) > 1:
        paired = [
            sha256_hex(f"branch\0{level[i]}\0{level[i + 1]}".encode("ascii"))
            for i in range(0, len(level) - 1, 2)
        ]
        if len(level) % 2:
            paired.append(level[-1])
        level = paired
    return level[0]


# --------------------------------------------------------------------------------------------
# DIMACS (specification §3.1) and leaf CNF digests (specification §3.2)


_DECIMAL = re.compile(rb"0|[1-9][0-9]*")
_LITERAL = re.compile(rb"-?[1-9][0-9]*")


@dataclass
class Formula:
    variables: int
    clauses: list[tuple[int, ...]]
    body: bytes
    sha256: str
    _states: dict[int, Any] = field(default_factory=dict, repr=False)

    def _state(self, depth: int) -> Any:
        """Cached hash state of header(V, M+depth) + body, copied per use (specification §3.2)."""
        if depth not in self._states:
            state = hashlib.sha256(b"p cnf %d %d\n" % (self.variables, len(self.clauses) + depth))
            state.update(self.body)
            self._states[depth] = state
        return self._states[depth]

    def cnf_sha256(self, cube: Iterable[int]) -> str:
        units = list(cube)
        state = self._state(len(units)).copy()
        for lit in units:
            state.update(b"%d 0\n" % lit)
        return state.hexdigest()


def parse_dimacs(data: bytes) -> Formula:
    """Strict canonical DIMACS reader: dimacs.header, dimacs.clause, dimacs.range, dimacs.count."""
    end = data.find(b"\n")
    if end < 0:
        raise Failure("dimacs.header", "no LF")
    parts = data[:end].split(b" ")
    if (
        len(parts) != 4
        or parts[0] != b"p"
        or parts[1] != b"cnf"
        or not _DECIMAL.fullmatch(parts[2])
        or not _DECIMAL.fullmatch(parts[3])
    ):
        raise Failure("dimacs.header", repr(data[:end][:80]))
    # Bound the length before int(): a canonical decimal of more than DECIMAL_DIGITS digits
    # exceeds INT_LIMIT, and int() itself refuses more than 4300 digits (ValueError).
    if len(parts[2]) > DECIMAL_DIGITS or len(parts[3]) > DECIMAL_DIGITS:
        raise Failure("dimacs.header", "count out of range")
    variables, count = int(parts[2]), int(parts[3])
    if variables > INT_LIMIT or count > INT_LIMIT:
        raise Failure("dimacs.header", "count out of range")
    body = data[end + 1 :]
    clauses: list[tuple[int, ...]] = []
    if body:
        if not body.endswith(b"\n"):
            raise Failure("dimacs.clause", "last line without LF")
        for number, line in enumerate(body[:-1].split(b"\n"), start=1):
            if line == b" 0":
                clauses.append(())
                continue
            tokens = line.split(b" ")
            if len(tokens) < 2 or tokens[-1] != b"0":
                raise Failure("dimacs.clause", f"line {number}")
            lits = []
            for token in tokens[:-1]:
                if not _LITERAL.fullmatch(token):
                    raise Failure("dimacs.clause", f"line {number}")
                if len(token.lstrip(b"-")) > DECIMAL_DIGITS:  # abs > INT_LIMIT >= variables
                    raise Failure("dimacs.range", f"line {number}")
                lit = int(token)
                if abs(lit) > variables:
                    raise Failure("dimacs.range", f"line {number}")
                lits.append(lit)
            clauses.append(tuple(lits))
    if len(clauses) != count:
        raise Failure("dimacs.count", f"{len(clauses)} clause lines, header {count}")
    return Formula(variables, clauses, body, sha256_hex(data))


def cube_cnf(formula: Formula, cube: Iterable[int]) -> bytes:
    """Plain CNF(F, C) bytes (used by tests as the oracle of the cached digest)."""
    units = list(cube)
    head = b"p cnf %d %d\n" % (formula.variables, len(formula.clauses) + len(units))
    return head + formula.body + b"".join(b"%d 0\n" % x for x in units)


def satisfies(formula: Formula, cube: Iterable[int], values: list[bool]) -> bool:
    """Specification §10.4: the assignment satisfies every clause and every cube unit."""

    def true(lit: int) -> bool:
        return values[abs(lit) - 1] == (lit > 0)

    if not all(true(lit) for lit in cube):
        return False
    return all(any(true(lit) for lit in clause) for clause in formula.clauses)


# --------------------------------------------------------------------------------------------
# Policy, machinery and process results


def policy_rules(policy: dict[str, Any]) -> None:
    if policy["checker_max_stack_mib"] < policy["checker_stack_mib"]:
        raise Failure("policy.stack")
    if policy["stream_heap_mib"] > policy["checker_max_heap_mib"]:
        raise Failure("policy.stream_heap")


def machinery_rules(machinery: dict[str, Any]) -> None:
    manifest = machinery["source_manifest"]
    if not strictly_sorted([e["path"] for e in manifest]):
        raise Failure("machinery.manifest_order")
    if machinery["packages_sha256"] != hash_value(manifest):
        raise Failure("machinery.packages_sha256")
    own = [e for e in manifest if e["path"].split("/", 1)[0] == "cubeproof"]
    if machinery["cubeproof_sha256"] != hash_value(own):
        raise Failure("machinery.cubeproof_sha256")


def process_rules(result: dict[str, Any]) -> None:
    if result["exit"] is not None and result["signal"] is not None:
        raise Failure("process.exit_signal")
    if not result["started"] and (result["exit"] is not None or result["signal"] is not None):
        raise Failure("process.not_started")
    for key in ("stdout_tail", "stderr_tail"):
        if len(result[key].encode("utf-8", "surrogatepass")) > TAIL_LIMIT:
            raise Failure("process.tail_size", key)


# --------------------------------------------------------------------------------------------
# Attempt rules (specification §4.8, §6.3; requirements attempt.*, success.*)


def attempt_shape_rules(a: dict[str, Any], variables: int) -> list[bool] | None:
    """Structural attempt rules independent of admission; returns the decoded assignment."""
    outcome, reason, route = a["outcome"], a["reason"], a["route"]
    if outcome in ("VERIFIED_UNSAT", "MODEL"):
        ok = reason is None
    elif outcome == "EXHAUSTED":
        ok = reason in EXHAUSTED_REASONS
    elif outcome == "TOOL_FAILED":
        ok = reason in TOOL_FAILED_REASONS
    elif outcome == "CHECK_REJECTED":
        ok = reason == "rejected"
    else:
        ok = reason is not None and reason == a["model_error"]
    if not ok:
        raise Failure("attempt.reason", f"{outcome}/{reason}")
    if (a["solver"] is None) != (route == "unit"):
        raise Failure("attempt.solver")
    if a["solver"] is not None:
        process_rules(a["solver"])
    for check in a["checks"]:
        process_rules(check["result"])
    stream = a["proof_mode"] == "stream" and route == "cdcl"
    if (a["relay"] is not None) != stream:
        raise Failure("attempt.relay")
    if (a["proof_bytes"] is None) != (a["proof_sha256"] is None):
        raise Failure("attempt.proof_pair")
    relay = a["relay"]
    if relay is not None and a["proof_sha256"] is not None:
        complete = relay["solver_eof"] and relay["all_written"] and relay["error"] is None
        if (
            not complete
            or relay["bytes"] != a["proof_bytes"]
            or relay["sha256"] != a["proof_sha256"]
        ):
            raise Failure("attempt.stream_proof")
    model = outcome in ("MODEL", "INVALID_MODEL")
    if model:
        if a["proof_sha256"] is not None or a["checks"]:
            raise Failure("attempt.model_shape")
        if route == "cdcl" and not (a["solver"]["exit"] == 10 and a["solver"]["signal"] is None):
            raise Failure("attempt.model_shape")
    error, assignment = a["model_error"], a["assignment"]
    if outcome == "MODEL":
        ok = error is None and assignment is not None
    elif outcome == "INVALID_MODEL":
        ok = error is not None and ((assignment is not None) == (error == "violated"))
    else:
        ok = error is None and assignment is None
    if not ok:
        raise Failure("attempt.model_error")
    values = decode_assignment(assignment, variables) if assignment is not None else None
    retained = a["retained"]
    if retained is not None and not (
        outcome == "VERIFIED_UNSAT"
        and a["proof_mode"] == "retain"
        and retained["sha256"] == a["proof_sha256"]
        and retained["bytes"] == a["proof_bytes"]
    ):
        raise Failure("attempt.retained")
    if a["quarantined"] is not None and not (
        outcome == "CHECK_REJECTED" and a["proof_mode"] in ("transient", "retain")
    ):
        raise Failure("attempt.quarantined")
    return values


def success_rules(a: dict[str, Any]) -> None:
    """Success fields of an admitted VERIFIED_UNSAT (specification §4.8, §6.3, §6.4)."""
    if a["proof_sha256"] is None:
        raise Failure("success.proof")
    if not a["checks"]:
        raise Failure("success.checks")
    last = a["checks"][-1]["result"]
    if not (
        last["exit"] == 0
        and last["signal"] is None
        and last["stdout_bytes"] == 17
        and last["stdout_truncated"] is False
        and last["stdout_tail"] == VERIFIED_LINE
    ):
        raise Failure("success.checker_output")
    if a["route"] == "cdcl":
        solver = a["solver"]
        if not (solver["started"] is True and solver["exit"] == 20 and solver["signal"] is None):
            raise Failure("success.solver")
    relay = a["relay"]
    if relay is not None:
        complete = relay["solver_eof"] and relay["all_written"] and relay["error"] is None
        if not (
            complete and relay["bytes"] == a["proof_bytes"] and relay["sha256"] == a["proof_sha256"]
        ):
            raise Failure("success.relay")


# --------------------------------------------------------------------------------------------
# Single documents (used by the corpus document tests and as building blocks)


def _nodes_rules(nodes: list[dict[str, Any]], variables_of: Any) -> None:
    """shard.nodes plus the cube rules of each node; variables_of(formula) -> V or None."""
    for node in nodes:
        v = variables_of(node["formula_sha256"])
        if v is not None:
            problem = cube_problem(node["cube"], v)
            if problem:
                raise Failure(problem)
        elif cube_problem(node["cube"], INT_LIMIT) == "cube.canonical":
            raise Failure("cube.canonical")
    keys = [(n["formula_sha256"], node_id(n["formula_sha256"], n["cube"])) for n in nodes]
    if not strictly_sorted(keys):
        raise Failure("shard.nodes", "order")
    by_formula: dict[str, list[list[int]]] = {}
    for node in nodes:
        by_formula.setdefault(node["formula_sha256"], []).append(node["cube"])
    for cubes in by_formula.values():
        for i, a in enumerate(cubes):
            for b in cubes[i + 1 :]:
                if not incompatible(a, b):
                    raise Failure("shard.nodes", "compatible nodes")


def check_shard(shard: dict[str, Any], variables_of: Any) -> None:
    _nodes_rules(shard["nodes"], variables_of)


def check_document(kind: str, data: bytes, context: dict[str, Any] | None = None) -> list[str]:
    """Validate one standalone document; [] if valid, else [rule] ('schema' for the schema)."""
    context = context or {}
    try:
        _check_document(kind, data, context)
    except Failure as exc:
        return [exc.rule]
    return []


def _context_variables(context: dict[str, Any]) -> Any:
    formulas = context.get("formulas")
    default = context.get("variables")

    def variables_of(formula: str) -> int | None:
        if formulas is not None and formula in formulas:
            return int(formulas[formula])
        return default

    return variables_of


def _check_document(  # noqa: PLR0911 - one early return per document kind
    kind: str, data: bytes, context: dict[str, Any]
) -> None:
    if kind == "dimacs":
        parse_dimacs(data)
        return
    if kind == "journal-record":
        if not data.endswith(b"\n"):
            raise Failure("json.canonical", "no LF")
        body = data[:-1]
        if len(body) > LINE_LIMIT:
            raise Failure("limit.line")
        record = parse_canonical(body)
        record_static_rules(record)
        if record["self"] != hash_value({k: v for k, v in record.items() if k != "self"}):
            raise Failure("journal.self")
        record_document_rules(record, context)
        return
    value, _ = read_document_bytes(data)
    if kind == "json":
        return
    if kind == "bundle-manifest":
        require_schema("bundle-manifest", None, value)
        manifest_rules(value, None)
        formula = context.get("formula")
        if formula is not None:
            manifest_rules(value, parse_dimacs(formula.encode("ascii")))
        return
    if kind == "policy":
        require_schema("policy", None, value)
        policy_rules(value)
        return
    if kind == "shard":
        require_schema("shard", None, value)
        check_shard(value, _context_variables(context))
        return
    if kind == "handoff-request":
        require_schema("handoff-request", None, value)
        return
    raise ValueError(kind)


def record_static_rules(record: Any) -> None:
    """Schema of a journal record, selected by its type (requirement schema, record.flat)."""
    if not isinstance(record, dict) or record.get("type") not in _RECORD_TYPES:
        raise Failure("schema", "record type")
    require_schema("journal-record", record["type"], record)


_RECORD_TYPES = (
    "header",
    "resume",
    "shard",
    "split",
    "attempt",
    "node_stop",
    "node_reopen",
    "handoff",
    "repair",
    "audit_begin",
    "audit_target",
    "audit_ready",
    "audit_result",
)


def record_document_rules(record: dict[str, Any], context: dict[str, Any]) -> None:
    """Rules of one record that need no other record (formula V from the context if any)."""
    variables_of = _context_variables(context)
    require_utc(record["utc"])
    kind = record["type"]
    if kind in ("header", "resume"):
        policy_rules(record["policy"])
        machinery_rules(record["machinery"])
    for node, given_id in _record_nodes(record):
        v = variables_of(node["formula_sha256"])
        problem = cube_problem(node["cube"], v if v is not None else INT_LIMIT)
        if problem:
            raise Failure(problem)
        if given_id is not None and given_id != node_id(node["formula_sha256"], node["cube"]):
            raise Failure("record.node_id")
    if kind == "shard":
        _shard_record_rules(record["shard"], record["shard_sha256"], None, variables_of)
    elif kind == "handoff":
        _handoff_rules(record, None, variables_of)
    elif kind == "attempt":
        v = variables_of(record["node"]["formula_sha256"])
        attempt_shape_rules(record, v if v is not None else 0)
        if context.get("admitted") and record["outcome"] == "VERIFIED_UNSAT":
            success_rules(record)


def _record_nodes(record: dict[str, Any]) -> list[tuple[dict[str, Any], str | None]]:
    """Every Node of a record with the node_id stored beside it (if any)."""
    kind = record["type"]
    if kind in ("split", "node_stop", "node_reopen"):
        return [(record["node"], None)]
    if kind == "attempt":
        return [(record["node"], record["node_id"])]
    if kind == "shard":
        return [(n, None) for n in record["shard"]["nodes"]]
    if kind == "handoff" and record["shard"] is not None:
        return [(n, None) for n in record["shard"]["nodes"]]
    if kind in ("audit_target", "audit_result"):
        return [(record["target"]["node"], record["target"]["node_id"])]
    return []


def _shard_record_rules(
    shard: dict[str, Any], digest: str, campaign: str | None, variables_of: Any
) -> None:
    if digest != hash_value(shard):
        raise Failure("shard.hash")
    if campaign is not None and shard["campaign"] != campaign:
        raise Failure("shard.campaign")
    check_shard(shard, variables_of)


def _handoff_rules(record: dict[str, Any], campaign: str | None, variables_of: Any) -> None:
    shard, digest, request = record["shard"], record["shard_sha256"], record["request"]
    if (shard is None) != (digest is None):
        raise Failure("handoff.pair")
    if campaign is not None and request["campaign"] != campaign:
        raise Failure("shard.campaign")
    if shard is not None:
        _shard_record_rules(shard, digest, campaign, variables_of)
        if len(shard["nodes"]) > request["node_count"]:
            raise Failure("handoff.count")


# --------------------------------------------------------------------------------------------
# Campaign and bundles (specification §4.2, §4.4)


@dataclass
class Bundle:
    key: str
    formula: Formula
    manifest: dict[str, Any]


@dataclass
class Campaign:
    path: Path
    id: str
    doc: dict[str, Any]
    bundles: dict[str, Bundle]  # by formula_sha256

    def variables(self, formula: str) -> int | None:
        bundle = self.bundles.get(formula)
        return bundle.formula.variables if bundle else None


def manifest_rules(manifest: dict[str, Any], formula: Formula | None) -> None:
    for name, pool in manifest["pools"].items():
        if not strictly_sorted(pool) or any(v > manifest["variables"] for v in pool):
            raise Failure("bundle.pools", name)
    if not strictly_sorted([s["path"] for s in manifest["side_files"]]):
        raise Failure("bundle.side_files")
    if formula is not None:
        if manifest["formula_sha256"] != formula.sha256:
            raise Failure("bundle.formula_sha256")
        counts = (formula.variables, len(formula.clauses))
        if (manifest["variables"], manifest["clauses"]) != counts:
            raise Failure("bundle.counts")


def _regular_file(directory: Path, name: str) -> bytes:
    path = directory / name
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        raise Failure("bundle.files", str(path)) from None
    except OSError as exc:
        raise Failure("bundle.files", f"{path}: {exc}") from None
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise Failure("path.containment", f"{path} is not a regular file")
    try:
        return path.read_bytes()
    except OSError as exc:
        raise Failure("bundle.files", f"{path}: {exc}") from None


def _bundle_directory(base: Path, relative: str) -> Path:
    """Resolve a RelPath under the campaign directory without following any symlink."""
    current = base
    info = None
    for part in relative.split("/"):
        current = current / part
        try:
            info = os.lstat(current)
        except FileNotFoundError:
            raise Failure("bundle.files", str(current)) from None
        except OSError as exc:  # e.g. a component is a regular file, or no search permission
            raise Failure("bundle.files", f"{current}: {exc}") from None
        if stat.S_ISLNK(info.st_mode):
            raise Failure("path.containment", f"{current} is a symlink")
    if info is None or not stat.S_ISDIR(info.st_mode):
        raise Failure("bundle.files", f"{current} is not a directory")
    return current


def load_bundle(base: Path, entry: dict[str, Any]) -> Bundle:
    directory = _bundle_directory(base, entry["bundle"])
    manifest_data = _regular_file(directory, "manifest.json")
    formula_data = _regular_file(directory, "formula.cnf")
    manifest, _ = read_document_bytes(manifest_data)
    require_schema("bundle-manifest", None, manifest)
    formula = parse_dimacs(formula_data)
    manifest_rules(manifest, formula)
    if entry["formula_sha256"] != manifest["formula_sha256"]:
        raise Failure("bundle.campaign_hash")
    return Bundle(entry["key"], formula, manifest)


def _argv_ok(argv: list[str]) -> bool:
    return "--lrat" in argv and all(a.startswith("-") for a in argv)


def load_campaign(path: Path) -> Campaign:
    try:
        return _load_campaign(path)
    except Failure as exc:
        raise CertifyError(_kind(exc.rule, "campaign"), exc.rule, exc.detail, str(path)) from None


def _load_campaign(path: Path) -> Campaign:
    try:
        with open(path, "rb") as handle:
            data = handle.read(DOCUMENT_LIMIT + 2)
    except OSError as exc:
        raise Failure("campaign.file", f"cannot read: {exc}") from None
    doc, campaign_id = read_document_bytes(data)
    require_schema("campaign", None, doc)
    require_utc(doc["created_utc"])
    policy_rules(doc["policy"])
    formulas = doc["formulas"]
    if not strictly_sorted([f["key"] for f in formulas]):
        raise Failure("campaign.formulas_order")
    hashes = [f["formula_sha256"] for f in formulas]
    if len(set(hashes)) != len(hashes):
        raise Failure("campaign.formula_hash_unique")
    base = path.resolve().parent
    bundles = {f["formula_sha256"]: load_bundle(base, f) for f in formulas}
    campaign = Campaign(path, campaign_id, doc, bundles)

    def node_rules(node: dict[str, Any]) -> None:
        if node["formula_sha256"] not in bundles:
            raise Failure("campaign.node_formula", node["formula_sha256"])
        problem = cube_problem(node["cube"], bundles[node["formula_sha256"]].formula.variables)
        if problem:
            raise Failure(problem, str(node["cube"]))

    roots = doc["roots"]
    for node in roots:
        node_rules(node)
    keys = [(n["formula_sha256"], node_id(n["formula_sha256"], n["cube"])) for n in roots]
    if not strictly_sorted(keys):
        raise Failure("campaign.roots_order")
    if {n["formula_sha256"] for n in roots} != set(bundles):
        raise Failure("campaign.roots_per_formula")
    for i, a in enumerate(roots):
        for b in roots[i + 1 :]:
            same_formula = a["formula_sha256"] == b["formula_sha256"]
            if same_formula and not incompatible(a["cube"], b["cube"]):
                raise Failure("campaign.roots_incompatible")
    split_keys = []
    for s in doc["root_splits"]:
        node_rules(s["node"])
        split_keys.append(
            split_id(node_id(s["node"]["formula_sha256"], s["node"]["cube"]), s["variables"])
        )
    if not strictly_sorted(split_keys):
        raise Failure("campaign.splits_order")
    root_keys = {(n["formula_sha256"], tuple(n["cube"])) for n in roots}
    for s in doc["root_splits"]:
        node = s["node"]
        problem = split_problem(
            s["variables"], node["cube"], bundles[node["formula_sha256"]].formula.variables
        )
        if problem:
            raise Failure(problem, str(s["variables"]))
        if node["cube"] and (node["formula_sha256"], tuple(node["cube"])) not in root_keys:
            raise Failure("campaign.root_split_node")
    pool = doc["policy"]["split"]["pool"]
    if pool is not None and any(pool not in b.manifest["pools"] for b in bundles.values()):
        raise Failure("campaign.pool", pool)
    tools, admit = doc["tools"], doc["admit"]
    argvs = [tools["solver"]["argv"]] + [s["argv"] for s in admit["solvers"] or []]
    if not all(_argv_ok(argv) for argv in argvs):
        raise Failure("campaign.argv")
    if not strictly_sorted(admit["checker_sha256"]):
        raise Failure("campaign.admit_order")
    if admit["solvers"] is not None:
        order = [(s["sha256"], canonical_json(s["argv"])) for s in admit["solvers"]]
        if not strictly_sorted(order):
            raise Failure("campaign.admit_order")
    if tools["checker"]["sha256"] not in admit["checker_sha256"]:
        raise Failure("campaign.tools_admitted", "checker")
    if admit["solvers"] is not None:
        configured = {"sha256": tools["solver"]["sha256"], "argv": tools["solver"]["argv"]}
        if configured not in admit["solvers"]:
            raise Failure("campaign.tools_admitted", "solver")
    return campaign


# --------------------------------------------------------------------------------------------
# Journals (specification §4.7, §7.1)


@dataclass
class Line:
    record: dict[str, Any]
    raw: bytes  # J(record) + LF


@dataclass
class JournalFile:
    path: str
    lines: list[Line]
    torn: int
    id: str = ""
    head: str = ""
    worker: str = ""

    @property
    def size(self) -> int:
        return sum(len(line.raw) for line in self.lines)


def split_lines(data: bytes) -> tuple[list[bytes], int]:
    """Complete lines (with LF) and the length of a torn suffix without LF."""
    lines = data.split(b"\n")
    torn = len(lines[-1])
    return [line + b"\n" for line in lines[:-1]], torn


def read_journal_bytes(data: bytes, path: str = "") -> JournalFile:
    """Canonical bytes, schema, self, seq and prev of every complete line (specification §7.1
    order)."""
    raw_lines, torn = split_lines(data)
    if not raw_lines:
        raise Failure("journal.no_header", "no complete line")
    lines: list[Line] = []
    prev = ZERO_HASH
    for seq, raw in enumerate(raw_lines):
        body = raw[:-1]
        if len(body) > LINE_LIMIT:
            raise Failure("limit.line", f"line {seq}")
        try:
            record = parse_canonical(body)
            record_static_rules(record)
        except Failure as exc:
            raise Failure(exc.rule, f"line {seq}: {exc.detail}") from None
        unsigned = {k: v for k, v in record.items() if k != "self"}
        if record["self"] != hash_value(unsigned):
            raise Failure("journal.self", f"line {seq}")
        if record["seq"] != seq:
            raise Failure("journal.seq", f"line {seq}")
        if record["prev"] != prev:
            raise Failure("journal.prev", f"line {seq}")
        prev = record["self"]
        lines.append(Line(record, raw))
    journal = JournalFile(path, lines, torn)
    journal.id = lines[0].record["self"]
    journal.head = lines[-1].record["self"]
    return journal


@dataclass
class Snapshot:
    seq: int
    machinery: dict[str, Any]
    policy_sha256: str


def check_journal(journal: JournalFile, campaign: Campaign) -> None:
    """Header, campaign, purpose and per-record rules of one journal (specification §4.7, §4.8,
    §10.1)."""
    first = journal.lines[0].record
    if first["type"] != "header":
        raise Failure("journal.header", "seq 0 is not a header")
    if first["campaign"] != campaign.id:
        raise Failure("journal.campaign", first["campaign"])
    journal.worker = first["worker"]
    purpose = first["purpose"]
    attempt_ids: set[str] = set()
    request_ids: set[str] = set()
    snapshot: Snapshot | None = None
    for line in journal.lines:
        record = line.record
        kind = record["type"]
        if kind == "header" and record["seq"] != 0:
            raise Failure("journal.header", f"second header at seq {record['seq']}")
        if purpose == "audit" and kind not in AUDIT_PURPOSE_ALLOWED:
            raise Failure("journal.purpose", f"{kind} in an audit journal")
        if purpose == "run" and kind in AUDIT_TYPES:
            raise Failure("journal.purpose", f"{kind} in a run journal")
        record_campaign_rules(record, campaign)
        if kind in ("header", "resume"):
            snapshot = Snapshot(record["seq"], record["machinery"], hash_value(record["policy"]))
        elif kind == "attempt":
            assert snapshot is not None
            if record["policy_sha256"] != snapshot.policy_sha256:
                raise Failure("attempt.policy_sha256", f"seq {record['seq']}")
            if record["attempt_id"] in attempt_ids:
                raise Failure("attempt.attempt_id", record["attempt_id"])
            attempt_ids.add(record["attempt_id"])
        elif kind == "handoff":
            request_id = record["request"]["request_id"]
            if request_id in request_ids:
                raise Failure("handoff.request_unique", request_id)
            request_ids.add(request_id)


def record_campaign_rules(record: dict[str, Any], campaign: Campaign) -> None:
    """Record rules with the campaign known: formulas, cubes, ids, hashes (specification §4.7,
    §10.1)."""
    require_utc(record["utc"])
    kind = record["type"]
    if kind in ("header", "resume"):
        policy_rules(record["policy"])
        machinery_rules(record["machinery"])
    for node, given_id in _record_nodes(record):
        variables = campaign.variables(node["formula_sha256"])
        if variables is None:
            raise Failure("record.formula", node["formula_sha256"])
        problem = cube_problem(node["cube"], variables)
        if problem:
            raise Failure(problem, f"seq {record['seq']}")
        if given_id is not None and given_id != node_id(node["formula_sha256"], node["cube"]):
            raise Failure("record.node_id", f"seq {record['seq']}")
    if kind == "shard":
        _shard_record_rules(
            record["shard"], record["shard_sha256"], campaign.id, campaign.variables
        )
    elif kind == "handoff":
        _handoff_rules(record, campaign.id, campaign.variables)
    elif kind == "attempt":
        formula = campaign.bundles[record["node"]["formula_sha256"]].formula
        attempt_shape_rules(record, formula.variables)
        if record["cnf_sha256"] != formula.cnf_sha256(record["node"]["cube"]):
            raise Failure("attempt.cnf_sha256", f"seq {record['seq']}")


def read_journal(path: Path, campaign: Campaign) -> JournalFile:
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise CertifyError("input", "journal.file", str(exc), str(path)) from None
    try:
        journal = read_journal_bytes(data, str(path))
        check_journal(journal, campaign)
    except Failure as exc:
        raise CertifyError(_kind(exc.rule, "journal"), exc.rule, exc.detail, str(path)) from None
    return journal


def select_journals(files: list[JournalFile]) -> tuple[list[JournalFile], list[dict[str, Any]]]:
    """One sequence per header ID (longest; others must be prefixes), one ID per worker."""
    groups: dict[str, list[JournalFile]] = {}
    for f in files:
        groups.setdefault(f.id, []).append(f)
    chosen: list[JournalFile] = []
    duplicates: list[dict[str, Any]] = []
    for jid in sorted(groups):
        copies = sorted(groups[jid], key=lambda f: (-len(f.lines), f.torn, f.path))
        longest = copies[0]
        for other in copies[1:]:
            if [x.raw for x in other.lines] != [x.raw for x in longest.lines[: len(other.lines)]]:
                raise CertifyError(
                    "integrity", "journal.fork", f"{other.path} vs {longest.path}", other.path
                )
            duplicates.append(
                {
                    "path": other.path,
                    "used": longest.path,
                    "journal": jid,
                    "records": len(other.lines),
                }
            )
        chosen.append(longest)
    workers: dict[str, str] = {}
    for f in chosen:
        if f.worker in workers and workers[f.worker] != f.id:
            raise CertifyError("integrity", "journal.worker", f.worker, f.path)
        workers[f.worker] = f.id
    return chosen, duplicates


# --------------------------------------------------------------------------------------------
# Evidence graph, closure and selection (specification §10.2)

Key = tuple[str, tuple[int, ...]]  # (formula_sha256, canonical cube)
Ref = tuple[str, int]  # (journal id, seq)


def ref_doc(ref: Ref) -> dict[str, Any]:
    return {"journal": ref[0], "seq": ref[1]}


def node_doc(key: Key) -> dict[str, Any]:
    return {"formula_sha256": key[0], "cube": list(key[1])}


@dataclass
class Leaf:
    ref: Ref
    record: dict[str, Any]
    snapshot_seq: int


@dataclass
class Selected:
    leaves: list[Key] = field(default_factory=list)
    splits: int = 0


@dataclass
class _Frame:
    node: Key
    sids: list[str]
    next_split: int = 0
    sid: str | None = None
    children: Iterator[Key] | None = None
    waiting: Key | None = None


class Evidence:
    def __init__(self) -> None:
        self.verified: dict[Key, Leaf] = {}  # smallest admitted verified Ref per node
        self.splits: dict[Key, dict[str, list[int]]] = {}  # node -> split_id -> W
        self.models: dict[Key, list[Ref]] = {}
        self.labels: dict[Key, dict[str, tuple[int, str, str | None]]] = {}
        self._closed: dict[Key, bool] = {}
        self._choice: dict[Key, str | None] = {}

    def add_split(self, key: Key, w: list[int]) -> None:
        self.splits.setdefault(key, {})[split_id(node_id(key[0], key[1]), w)] = list(w)

    def add_verified(self, key: Key, leaf: Leaf) -> None:
        current = self.verified.get(key)
        if current is None or leaf.ref < current.ref:
            self.verified[key] = leaf

    def children(self, key: Key, sid: str) -> Iterator[Key]:
        for cube in split_children(key[1], self.splits[key][sid]):
            yield (key[0], cube)

    def closed(self, key: Key) -> bool:
        """Literal closure (specification §10.2), memoized exactly, with an explicit stack.

        A node is closed by its own admitted verified attempt, or by a split all of whose
        children are closed. Splits are tried in split_id order, so the first closed split
        found is the smallest closed split_id, which is the one selection uses.
        """
        stack = [_Frame(key, sorted(self.splits.get(key, {})))]
        while stack:
            frame = stack[-1]
            node = frame.node
            if node in self._closed:
                stack.pop()
                continue
            if node in self.verified:
                self._decide(node, True, None)
                stack.pop()
                continue
            if frame.waiting is not None:
                if not self._closed[frame.waiting]:
                    frame.children = None  # an open child: this split does not close
                frame.waiting = None
            pushed = False
            while not pushed:
                if frame.children is None:
                    if frame.next_split == len(frame.sids):
                        self._decide(node, False, None)
                        break
                    frame.sid = frame.sids[frame.next_split]
                    frame.next_split += 1
                    frame.children = self.children(node, frame.sid)
                child = next(frame.children, None)
                if child is None:
                    self._decide(node, True, frame.sid)
                    break
                known = self._closed.get(child)
                if known is None:
                    frame.waiting = child
                    stack.append(_Frame(child, sorted(self.splits.get(child, {}))))
                    pushed = True
                elif not known:
                    frame.children = None
            if not pushed:
                stack.pop()
        return self._closed[key]

    def _decide(self, node: Key, closed: bool, sid: str | None) -> None:
        self._closed[node] = closed
        self._choice[node] = sid

    def select(self, key: Key) -> Selected:
        """The selected proof tree of a closed node: leaves in traversal order, split count."""
        out = Selected()
        stack = [key]
        while stack:
            node = stack.pop()
            if not self.closed(node):
                raise AssertionError("selecting an open node")
            sid = self._choice[node]
            if sid is None:
                out.leaves.append(node)
            else:
                out.splits += 1
                stack.extend(reversed(list(self.children(node, sid))))
        return out

    def label(self, key: Key) -> tuple[str, str | None]:
        """Specification §10.3: each worker's latest node_stop/node_reopen of this exact node; if
        any of those is a stop, the stop with the smallest Ref gives state and reason."""
        stops = [
            ((journal, seq), state, reason)
            for journal, (seq, state, reason) in self.labels.get(key, {}).items()
            if state != "reopen"
        ]
        if not stops:
            return "pending", None
        _, state, reason = min(stops, key=lambda s: s[0])
        return state, reason

    def frontier(self, start: Key, model_nodes: set[Key]) -> list[Key]:
        out: list[Key] = []
        stack = [start]
        while stack:
            node = stack.pop()
            if self.closed(node):
                continue
            if node in model_nodes:
                out.append(node)
                continue
            splits = self.splits.get(node)
            if splits:
                stack.extend(reversed(list(self.children(node, min(splits)))))
            else:
                out.append(node)
        return out


def empty_summary() -> dict[str, Any]:
    return {"leaves": 0, "splits": 0, "max_cube_size": 0, "leaf_merkle_root": None}


# --------------------------------------------------------------------------------------------
# Certification (specification §10)


@dataclass
class Result:
    certificate: dict[str, Any]
    certificate_bytes: bytes
    exit_code: int
    duplicates: list[dict[str, Any]]


VERDICT_EXIT = {"PROVED": 0, "OPEN": 1, "MODEL_FOUND": 2, "INCONSISTENT": 4}


def certify(campaign_path: Path | str, journal_paths: Iterable[Path | str]) -> Result:
    campaign = load_campaign(Path(campaign_path))
    files = [read_journal(Path(p), campaign) for p in journal_paths]
    journals, duplicates = select_journals(files)
    certificate = build_certificate(campaign, journals)
    data = canonical_json(certificate) + b"\n"
    return Result(certificate, data, VERDICT_EXIT[certificate["verdict"]], duplicates)


def _fail(journal: JournalFile, exc: Failure) -> CertifyError:
    return CertifyError(_kind(exc.rule, "journal"), exc.rule, exc.detail, journal.path)


def build_certificate(campaign: Campaign, journals: list[JournalFile]) -> dict[str, Any]:
    admit = campaign.doc["admit"]
    evidence = Evidence()
    not_admitted: list[tuple[Ref, str]] = []
    models: list[tuple[Ref, Key, str]] = []
    anomalies: list[tuple[Ref, str, dict[str, Any]]] = []
    snapshots: dict[tuple[str, int], dict[str, Any]] = {}

    for split in campaign.doc["root_splits"]:
        node = split["node"]
        evidence.add_split((node["formula_sha256"], tuple(node["cube"])), split["variables"])

    for journal in journals:
        snapshot: Snapshot | None = None
        for line in journal.lines:
            record = line.record
            kind = record["type"]
            ref: Ref = (journal.id, record["seq"])
            if kind in ("header", "resume"):
                snapshot = Snapshot(record["seq"], record["machinery"], "")
                snapshots[(journal.id, record["seq"])] = record["machinery"]
                continue
            if kind == "split":
                node = record["node"]
                key = (node["formula_sha256"], tuple(node["cube"]))
                problem = split_problem(
                    record["variables"],
                    node["cube"],
                    campaign.variables(node["formula_sha256"]) or 0,
                )
                if problem:
                    anomalies.append(
                        (ref, "malformed_split", {"problem": problem.split(".", 1)[1]})
                    )
                else:
                    evidence.add_split(key, record["variables"])
                continue
            if kind in ("node_stop", "node_reopen"):
                node = record["node"]
                key = (node["formula_sha256"], tuple(node["cube"]))
                state = record["state"] if kind == "node_stop" else "reopen"
                reason = record["reason"] if kind == "node_stop" else None
                per_worker = evidence.labels.setdefault(key, {})
                previous = per_worker.get(journal.id)
                if previous is None or previous[0] < record["seq"]:
                    per_worker[journal.id] = (record["seq"], state, reason)
                continue
            if kind != "attempt":
                continue
            assert snapshot is not None
            node = record["node"]
            key = (node["formula_sha256"], tuple(node["cube"]))
            formula = campaign.bundles[node["formula_sha256"]].formula
            machinery = snapshot.machinery
            reason = None
            if machinery["checker"]["sha256"] not in admit["checker_sha256"]:
                reason = "checker_not_admitted"
            elif (
                admit["solvers"] is not None
                and {"sha256": machinery["solver"]["sha256"], "argv": machinery["solver"]["argv"]}
                not in admit["solvers"]
            ):
                reason = "solver_not_admitted"
            outcome = record["outcome"]
            if reason is not None:
                not_admitted.append((ref, reason))
            elif outcome == "VERIFIED_UNSAT":
                try:
                    success_rules(record)
                except Failure as exc:
                    raise _fail(journal, Failure(exc.rule, f"seq {record['seq']}")) from None
                evidence.add_verified(key, Leaf(ref, record, snapshot.seq))
            if outcome == "CHECK_REJECTED":
                anomalies.append((ref, "check_rejected", {}))
            elif outcome in ("MODEL", "INVALID_MODEL"):
                assignment = record["assignment"]
                valid = False
                if assignment is not None:
                    values = decode_assignment(assignment, formula.variables)
                    valid = satisfies(formula, node["cube"], values)
                if outcome == "MODEL" and not valid:
                    raise _fail(journal, Failure("attempt.model_false", f"seq {record['seq']}"))
                if valid:
                    models.append((ref, key, assignment))
                    evidence.models.setdefault(key, []).append(ref)
                    if outcome == "INVALID_MODEL":
                        anomalies.append((ref, "mislabelled_model", {}))
                else:
                    anomalies.append((ref, "invalid_model", {"model_error": record["model_error"]}))

    model_nodes = set(evidence.models)
    used: dict[str, Leaf] = {}
    used_keys: dict[str, Key] = {}

    def summary(key: Key) -> tuple[bool, dict[str, Any]]:
        if not evidence.closed(key):
            return False, empty_summary()
        chosen = evidence.select(key)
        leaves = []
        for leaf_key in chosen.leaves:
            leaf = evidence.verified[leaf_key]
            nid = node_id(leaf_key[0], leaf_key[1])
            used[nid] = leaf
            used_keys[nid] = leaf_key
            leaves.append((nid, leaf.record["cnf_sha256"], leaf.record["proof_sha256"]))
        return True, {
            "leaves": len(chosen.leaves),
            "splits": chosen.splits,
            "max_cube_size": max(len(k[1]) for k in chosen.leaves),
            "leaf_merkle_root": merkle_root(leaves),
        }

    roots_by_formula: dict[str, list[tuple[int, ...]]] = {}
    for root in campaign.doc["roots"]:
        roots_by_formula.setdefault(root["formula_sha256"], []).append(tuple(root["cube"]))

    formulas_doc = []
    open_nodes: list[Key] = []
    formula_open: list[Key] = []
    proved: dict[str, bool] = {}
    for entry in campaign.doc["formulas"]:
        f = entry["formula_sha256"]
        is_proved, formula_summary = summary((f, ()))
        proved[f] = is_proved
        roots_doc = []
        for cube in roots_by_formula.get(f, []):
            closed, root_summary = summary((f, cube))
            roots_doc.append(
                (node_id(f, cube), {"cube": list(cube), "closed": closed, "summary": root_summary})
            )
            open_nodes.extend(evidence.frontier((f, cube), model_nodes))
        formula_open.extend(evidence.frontier((f, ()), model_nodes))
        formulas_doc.append(
            {
                "formula_sha256": f,
                "key": entry["key"],
                "proved": is_proved,
                "summary": formula_summary,
                "roots": [doc for _, doc in sorted(roots_doc, key=lambda x: x[0])],
            }
        )
    formulas_doc.sort(key=lambda d: d["formula_sha256"])

    def open_doc(nodes: list[Key]) -> list[dict[str, Any]]:
        out = []
        for key in nodes:
            nid = node_id(key[0], key[1])
            if key in model_nodes:
                state, reason = "model", None
            else:
                state, reason = evidence.label(key)
            out.append({"node": node_doc(key), "node_id": nid, "state": state, "reason": reason})
        out.sort(key=lambda d: (d["node"]["formula_sha256"], d["node_id"]))
        return out

    used_doc = []
    machinery_keys: set[tuple[str, int]] = set()
    for nid in sorted(used):
        leaf = used[nid]
        used_doc.append(
            {
                "node": node_doc(used_keys[nid]),
                "node_id": nid,
                "record": ref_doc(leaf.ref),
                "cnf_sha256": leaf.record["cnf_sha256"],
                "proof_sha256": leaf.record["proof_sha256"],
                "route": leaf.record["route"],
            }
        )
        machinery_keys.add((leaf.ref[0], leaf.snapshot_seq))

    model_formulas = {key[0] for _, key, _ in models}
    if any(proved[f] for f in model_formulas):
        verdict = "INCONSISTENT"
    elif models:
        verdict = "MODEL_FOUND"
    elif all(proved.values()):
        verdict = "PROVED"
    else:
        verdict = "OPEN"

    return {
        "format": "cubeproof-certificate-1",
        "campaign": campaign.id,
        "journals": sorted(
            (
                {
                    "id": j.id,
                    "worker": j.worker,
                    "records": len(j.lines),
                    "head": j.head,
                    "bytes": j.size,
                    "torn_tail_bytes": j.torn,
                }
                for j in journals
            ),
            key=lambda d: d["id"],
        ),
        "formulas": formulas_doc,
        "open": open_doc(open_nodes),
        "formula_open": open_doc(formula_open),
        "used_attempts": used_doc,
        "machinery": [
            {"journal": jid, "snapshot_seq": seq, "machinery": snapshots[(jid, seq)]}
            for jid, seq in sorted(machinery_keys)
        ],
        "not_admitted": [{"record": ref_doc(r), "reason": why} for r, why in sorted(not_admitted)],
        "models": [
            {"record": ref_doc(r), "node": node_doc(k), "assignment": a}
            for r, k, a in sorted(models, key=lambda m: m[0])
        ],
        "anomalies": [
            {"record": ref_doc(r), "code": code, "info": info}
            for r, code, info in sorted(anomalies, key=lambda a: (a[0], a[1]))
        ],
        "verdict": verdict,
    }


# --------------------------------------------------------------------------------------------
# Comparison driver (specification §10.5) and corpus runner


SEMANTIC_FIELDS = (
    "format",
    "campaign",
    "journals",
    "formulas",
    "open",
    "formula_open",
    "used_attempts",
    "machinery",
    "not_admitted",
    "models",
    "anomalies",
    "verdict",
)


def compare_certificates(a: bytes, b: bytes) -> list[dict[str, Any]]:
    """Field-by-field differences of two certificates; [] when they agree."""
    left, _ = read_document_bytes(a, limit=1 << 62)
    right, _ = read_document_bytes(b, limit=1 << 62)
    if not isinstance(left, dict) or not isinstance(right, dict):
        raise Failure("schema", "a certificate is a JSON object")
    out = []
    for name in sorted(set(left) | set(right)):
        if left.get(name) != right.get(name):
            out.append(
                {"field": name, "left": _brief(left.get(name)), "right": _brief(right.get(name))}
            )
    return out


def _brief(value: Any) -> Any:
    if isinstance(value, list):
        return {"count": len(value), "sha256": hash_value(value)}
    return value


def run_corpus(corpus: Path) -> dict[str, Any]:
    """Run every case of corpus/cases.json and compare with its expected outcome."""
    cases = json.loads((corpus / "cases.json").read_bytes())["cases"]
    failed, passed = [], 0
    for case in cases:
        expect = case["expect"]
        campaign = corpus / case["campaign"]
        journals = [corpus / p for p in case["journals"]]
        try:
            result = certify(campaign, journals)
            got: dict[str, Any] = {"exit": result.exit_code}
            ok = (
                "certificate" in expect
                and result.exit_code == expect["exit"]
                and result.certificate_bytes == (corpus / expect["certificate"]).read_bytes()
            )
            if "certificate" in expect and not ok:
                got["differences"] = compare_certificates(
                    result.certificate_bytes, (corpus / expect["certificate"]).read_bytes()
                )
        except CertifyError as exc:
            got = {"exit": exc.exit_code, "error": {"kind": exc.kind, "rule": exc.rule}}
            ok = got == {"exit": expect["exit"], "error": expect.get("error")}
        if ok:
            passed += 1
        else:
            failed.append({"id": case["id"], "expected": expect, "got": got})
    return {"passed": passed, "failed": failed}


# --------------------------------------------------------------------------------------------
# Command line


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> Any:  # usage errors exit 3 (specification §12.2)
        self.print_usage(sys.stderr)
        print(f"{self.prog}: error: {message}", file=sys.stderr)
        raise SystemExit(3)


def _write_atomic(path: Path, data: bytes) -> None:
    tmp = path.with_name(path.name + ".tmp")
    try:
        with open(tmp, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


def internal_error(exc: BaseException, where: str = "") -> dict[str, Any]:
    """Report of an unexpected failure: never a verdict exit code (specification §4.9, §12.2)."""
    return {
        "kind": "internal",
        "rule": "internal",
        "detail": f"{type(exc).__name__}: {exc}"[:1000],
        "where": where,
    }


def main(argv: list[str] | None = None) -> int:
    """Command line; every failure other than a usage error exits 4 with a JSON report.

    Exit codes 0/1/2 are verdicts (certify) or agreement/results (compare, corpus); an
    unexpected exception (a defect, an OS error, exhausted memory or recursion) must never be
    mistaken for one of them, so it is reported as kind "internal" with exit 4.
    """
    parser = _Parser(prog="certify_min", description=__doc__.split("\n\n")[0])
    args = _arguments(parser, argv)
    report: dict[str, Any] = {
        "format": "certify-min-report-1",
        "error": None,
        "verdict": None,
        "certificate_sha256": None,
        "duplicates": [],
    }
    try:
        return _run(args, report)
    except Exception as exc:  # last resort: no crash may look like a verdict
        report.update(
            error=internal_error(exc), verdict=None, certificate_sha256=None, duplicates=[]
        )
        print(json.dumps(report, sort_keys=True))
        return 4


def _arguments(parser: _Parser, argv: list[str] | None) -> argparse.Namespace:
    parser = _Parser(prog="certify_min", description=__doc__.split("\n\n")[0])
    commands = parser.add_subparsers(dest="command", required=True, parser_class=_Parser)
    p = commands.add_parser("certify", help="certify a campaign and its journals")
    p.add_argument("--campaign", required=True, type=Path)
    p.add_argument("--journals", nargs="*", default=[], type=Path)
    p.add_argument("-o", "--output", required=True, type=Path)
    p = commands.add_parser("compare", help="compare two certificates field by field")
    p.add_argument("left", type=Path)
    p.add_argument("right", type=Path)
    p = commands.add_parser("corpus", help="run the frozen contract corpus")
    p.add_argument(
        "--corpus",
        type=Path,
        default=Path(__file__).resolve().parent.parent / "tests/contracts/corpus",
    )
    return parser.parse_args(argv)


def _run(args: argparse.Namespace, report: dict[str, Any]) -> int:
    if args.command == "compare":
        try:
            found = compare_certificates(args.left.read_bytes(), args.right.read_bytes())
        except (OSError, Failure) as exc:
            print(json.dumps({"error": str(exc)}))
            return 4
        print(json.dumps({"agree": not found, "differences": found}, sort_keys=True))
        return 0 if not found else 1

    if args.command == "corpus":
        summary = run_corpus(args.corpus)
        print(json.dumps(summary, sort_keys=True))
        return 0 if not summary["failed"] else 1

    try:
        result = certify(args.campaign, args.journals)
    except CertifyError as exc:
        report["error"] = exc.report()
        print(json.dumps(report, sort_keys=True))
        return exc.exit_code
    _write_atomic(args.output, result.certificate_bytes)
    report.update(
        verdict=result.certificate["verdict"],
        certificate_sha256=sha256_hex(result.certificate_bytes[:-1]),
        duplicates=result.duplicates,
    )
    print(json.dumps(report, sort_keys=True))
    return result.exit_code


if __name__ == "__main__":
    sys.exit(main())
