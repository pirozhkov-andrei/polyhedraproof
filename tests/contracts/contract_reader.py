"""Requirement-driven reference reader of the cubeproof v1 contract corpus (test-only).

This is the second implementation of the contract: it is written from specification §3-§7
and §9-§12 and the recorded readings of ``schemas/cubeproof/v1/requirements.json``,
separately from the generator in ``tools/spec_vectors``, and it shares no code with it. The
readings are cited below as "reading n" and "routine reading n". It validates documents and
evidence and recomputes the certificates of the tiny corpus cases, so that a fixture or an
expected certificate produced by the generator is accepted only when an independent reading
of the same rules agrees. Every violation is named by its identifier in
``schemas/cubeproof/v1/requirements.json``.

It is deliberately plain and unoptimised (recursion on tiny graphs, whole files in memory);
it is not a model for the production certifiers.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import itertools
import json
import os
import re
import stat
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from contract_schema import SchemaStore

REPO = Path(__file__).resolve().parents[2]
SCHEMAS = REPO / "schemas" / "cubeproof" / "v1"
CORPUS = REPO / "tests" / "contracts" / "corpus"

INT_MAX = 2**63 - 1
LINE_LIMIT = 8 * 1024 * 1024
DOCUMENT_LIMIT = 64 * 1024 * 1024
DEPTH_LIMIT = 32
TAIL_LIMIT = 16 * 1024
K_MAX = 20
ZERO_HASH = "0" * 64
SUCCESS_LINE = "s VERIFIED UNSAT\n"

RECORD_TYPES = (
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
AUDIT_PURPOSE_TYPES = frozenset({"header", "resume", "repair", "attempt"})
REASONS = {
    "EXHAUSTED": frozenset(
        {"proof_size", "time", "check_time", "check_memory", "check_stack", "solver_memory"}
    ),
    "TOOL_FAILED": frozenset(
        {"launch", "binary_changed", "io", "file_changed", "crash", "protocol", "relay"}
    ),
    "CHECK_REJECTED": frozenset({"rejected"}),
}
MODEL_ERRORS = frozenset({"missing", "conflicting", "out_of_range", "syntax", "violated"})
VERDICT_EXIT = {"PROVED": 0, "OPEN": 1, "MODEL_FOUND": 2, "INCONSISTENT": 4}
ZERO_SUMMARY = {"leaves": 0, "splits": 0, "max_cube_size": 0, "leaf_merkle_root": None}

Cube = tuple[int, ...]
Key = tuple[str, Cube]
Ref = tuple[str, int]


class Problem(Exception):
    """A violated requirement. ``kind`` is set by the reader that met it."""

    def __init__(self, rule: str, detail: str = "", kind: str = "reject") -> None:
        super().__init__(f"{kind}: {rule}: {detail}")
        self.rule = rule
        self.detail = detail
        self.kind = kind


# -- bytes, JSON and hashes (specification §4.1) ---------------------------------------------------


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def j_bytes(value: Any) -> bytes:
    """J(x) of specification §4.1."""
    text = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    )
    return text.encode("utf-8")


def j_hash(value: Any) -> str:
    return sha256_hex(j_bytes(value))


def _reject_number(text: str) -> Any:
    raise Problem("json.number", text)


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise Problem("json.duplicate_key", key)
        result[key] = value
    return result


def _lone_surrogate(text: str) -> bool:
    return any(0xD800 <= ord(char) <= 0xDFFF for char in text)


def _check_values(value: Any, depth: int) -> None:
    if isinstance(value, bool) or value is None:
        return
    if isinstance(value, int):
        if not -INT_MAX <= value <= INT_MAX:
            raise Problem("json.integer_range", str(value))
        return
    if isinstance(value, str):
        if _lone_surrogate(value):
            raise Problem("json.surrogate")
        return
    if depth + 1 > DEPTH_LIMIT:
        raise Problem("limit.depth", f"deeper than {DEPTH_LIMIT}")
    if isinstance(value, list):
        for item in value:
            _check_values(item, depth + 1)
        return
    for key, item in value.items():
        if _lone_surrogate(key):
            raise Problem("json.surrogate")
        _check_values(item, depth + 1)


def parse_json(data: bytes) -> Any:
    """Strict parse: UTF-8, no BOM, unique keys, integers only, range, surrogates, depth."""
    if data.startswith(b"\xef\xbb\xbf"):
        raise Problem("json.bom")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise Problem("json.utf8", str(exc)) from None
    try:
        value = json.loads(
            text,
            object_pairs_hook=_unique_pairs,
            parse_float=_reject_number,
            parse_constant=_reject_number,
        )
    except Problem:
        raise
    except (ValueError, RecursionError) as exc:
        raise Problem("json.syntax", str(exc)) from None
    _check_values(value, 0)
    return value


def parse_document(data: bytes) -> Any:
    """A canonical document: J(x) plus exactly one LF."""
    value = parse_json(data)
    if data != j_bytes(value) + b"\n":
        raise Problem("json.canonical")
    return value


def parse_line(line: bytes) -> Any:
    """One complete journal line without its LF: exactly J(record)."""
    value = parse_json(line)
    if line != j_bytes(value):
        raise Problem("json.canonical")
    return value


_UTC = re.compile(r"([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})\.[0-9]{3}Z")


def utc_valid(text: str) -> bool:
    match = _UTC.fullmatch(text)
    if match is None:
        return False
    year, month, day, hour, minute, second = (int(x) for x in match.groups())
    if not 1 <= month <= 12:
        return False
    leap = year % 4 == 0 and (year % 100 != 0 or year % 400 == 0)
    days = (31, 29 if leap else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31)[month - 1]
    return 1 <= day <= days and hour <= 23 and minute <= 59 and second <= 59


def strictly_increasing(keys: Sequence[Any]) -> bool:
    return all(a < b for a, b in itertools.pairwise(keys))


def same_formula_compatible(nodes: Sequence[dict[str, Any]]) -> bool:
    """True if two nodes of one formula have compatible cubes (specification §4.4, §4.5)."""
    for i, a in enumerate(nodes):
        for b in nodes[i + 1 :]:
            same = a["formula_sha256"] == b["formula_sha256"]
            if same and not incompatible(a["cube"], b["cube"]):
                return True
    return False


# -- CNF, cubes, splits, models (specification §3, §4.8) -------------------------------------------

_HEADER = re.compile(rb"p cnf (0|[1-9][0-9]*) (0|[1-9][0-9]*)")
_LITERAL = rb"-?[1-9][0-9]*"
_CLAUSE = re.compile(rb"(?:" + _LITERAL + rb" )+0| 0")


@dataclass(frozen=True)
class Formula:
    data: bytes
    variables: int
    clauses: tuple[tuple[int, ...], ...]
    header_length: int

    @property
    def sha256(self) -> str:
        return sha256_hex(self.data)

    @property
    def body(self) -> bytes:
        return self.data[self.header_length :]


def parse_dimacs(data: bytes) -> Formula:
    if not data.endswith(b"\n"):
        raise Problem("dimacs.header" if b"\n" not in data else "dimacs.clause")
    lines = data[:-1].split(b"\n")
    match = _HEADER.fullmatch(lines[0])
    if match is None:
        raise Problem("dimacs.header", repr(lines[0][:40]))
    variables, count = int(match.group(1)), int(match.group(2))
    clauses = []
    for line in lines[1:]:
        if _CLAUSE.fullmatch(line) is None:
            raise Problem("dimacs.clause", repr(line[:40]))
        clauses.append(tuple(int(x) for x in line.split(b" ")[:-1] if x))
    if len(clauses) != count:
        raise Problem("dimacs.count", f"{len(clauses)} clause lines, header says {count}")
    for clause in clauses:
        if any(abs(literal) > variables for literal in clause):
            raise Problem("dimacs.range")
    return Formula(data, variables, tuple(clauses), len(lines[0]) + 1)


def cube_cnf(formula: Formula, cube: Sequence[int]) -> bytes:
    header = f"p cnf {formula.variables} {len(formula.clauses) + len(cube)}\n".encode()
    units = "".join(f"{literal} 0\n" for literal in cube).encode()
    return header + formula.body + units


def node_id(formula_sha256: str, cube: Sequence[int]) -> str:
    literals = " ".join(str(x) for x in cube)
    return sha256_hex(b"node\0" + formula_sha256.encode() + b"\0" + literals.encode())


def split_id(node: str, variables: Sequence[int]) -> str:
    return j_hash({"node_id": node, "variables": list(variables)})


def cube_problem(cube: Sequence[int], variables: int | None) -> str | None:
    keys = [abs(x) for x in cube]
    if not strictly_increasing(keys):
        return "cube.canonical"
    if variables is not None and any(k > variables for k in keys):
        return "cube.range"
    return None


def split_problem(variables: Sequence[int], cube: Sequence[int], count: int) -> str | None:
    """The first semantic problem of W in the order of reading 5."""
    if not variables:
        return "split.empty"
    if len(variables) > K_MAX:
        return "split.too_long"
    if len(set(variables)) != len(variables):
        return "split.repeated"
    if any(v > count for v in variables):
        return "split.out_of_range"
    if {abs(x) for x in cube} & set(variables):
        return "split.in_cube"
    return None


def split_children(cube: Sequence[int], variables: Sequence[int]) -> list[Cube]:
    children = []
    for index in range(1 << len(variables)):
        signed = [v if (index >> j) & 1 else -v for j, v in enumerate(variables)]
        children.append(tuple(sorted([*cube, *signed], key=abs)))
    return children


def incompatible(a: Sequence[int], b: Sequence[int]) -> bool:
    other = set(b)
    return any(-x in other for x in a)


def decode_assignment(text: str, variables: int) -> list[bool] | None:
    """The values of a canonical bitset (specification §4.8), or None if it is not one."""
    try:
        raw = base64.b64decode(text.encode("ascii"), validate=True)
    except (binascii.Error, UnicodeEncodeError, ValueError):
        return None
    if base64.b64encode(raw).decode("ascii") != text or len(raw) != (variables + 7) // 8:
        return None
    if variables % 8 and raw[-1] >> (variables % 8):
        return None
    return [bool(raw[i // 8] >> (i % 8) & 1) for i in range(variables)]


def satisfies(formula: Formula, cube: Sequence[int], values: Sequence[bool]) -> bool:
    def true(literal: int) -> bool:
        return values[abs(literal) - 1] == (literal > 0)

    return all(true(x) for x in cube) and all(
        any(true(x) for x in clause) for clause in formula.clauses
    )


def leaf_hash(node: str, cnf: str, proof: str) -> str:
    return sha256_hex(b"leaf\0" + node.encode() + b"\0" + cnf.encode() + b"\0" + proof.encode())


def merkle_root(leaves: Iterable[tuple[str, str, str]]) -> str | None:
    level = [leaf_hash(*leaf) for leaf in sorted(leaves)]
    while len(level) > 1:
        paired = [
            sha256_hex(b"branch\0" + level[i].encode() + b"\0" + level[i + 1].encode())
            for i in range(0, len(level) - 1, 2)
        ]
        if len(level) % 2:
            paired.append(level[-1])
        level = paired
    return level[0] if level else None


# -- context-free rules of documents and records ------------------------------------------------


def machinery_problems(machinery: dict[str, Any]) -> list[str]:
    found = []
    manifest = machinery["source_manifest"]
    if not strictly_increasing([e["path"] for e in manifest]):
        found.append("machinery.manifest_order")
    if machinery["packages_sha256"] != j_hash(manifest):
        found.append("machinery.packages_sha256")
    own = [e for e in manifest if e["path"].split("/", 1)[0] == "cubeproof"]
    if machinery["cubeproof_sha256"] != j_hash(own):
        found.append("machinery.cubeproof_sha256")
    return found


def policy_problems(policy: dict[str, Any]) -> list[str]:
    found = []
    if policy["checker_max_stack_mib"] < policy["checker_stack_mib"]:
        found.append("policy.stack")
    if policy["stream_heap_mib"] > policy["checker_max_heap_mib"]:
        found.append("policy.stream_heap")
    return found


def process_problems(result: dict[str, Any]) -> list[str]:
    found = []
    if result["exit"] is not None and result["signal"] is not None:
        found.append("process.exit_signal")
    if not result["started"] and (result["exit"] is not None or result["signal"] is not None):
        found.append("process.not_started")
    tails = (result["stdout_tail"], result["stderr_tail"])
    if any(len(t.encode("utf-8")) > TAIL_LIMIT for t in tails):
        found.append("process.tail_size")
    return found


def nodes_problems(nodes: Sequence[dict[str, Any]], variables: int | None = None) -> list[str]:
    """Shard/roots node lists: canonical cubes, strictly sorted, pairwise incompatible."""
    found = []
    for node in nodes:
        problem = cube_problem(node["cube"], variables)
        if problem:
            found.append(problem)
    if found:
        return found
    keys = [(n["formula_sha256"], node_id(n["formula_sha256"], n["cube"])) for n in nodes]
    if not strictly_increasing(keys) or same_formula_compatible(nodes):
        return ["shard.nodes"]
    return []


def attempt_problems(
    attempt: dict[str, Any], variables: int | None, admitted: bool | None
) -> list[str]:
    """Reading 3 level (i) for every attempt; level (ii) when ``admitted`` is true."""
    found: list[str] = []
    add = found.append
    outcome, reason = attempt["outcome"], attempt["reason"]
    model_error, assignment = attempt["model_error"], attempt["assignment"]
    if outcome in ("VERIFIED_UNSAT", "MODEL"):
        reason_ok = reason is None
    elif outcome == "INVALID_MODEL":
        reason_ok = reason is not None and reason == model_error
    else:
        reason_ok = reason in REASONS[outcome]
    if not reason_ok:
        add("attempt.reason")
    route, mode, solver, relay = (
        attempt["route"],
        attempt["proof_mode"],
        attempt["solver"],
        attempt["relay"],
    )
    if (solver is None) != (route == "unit"):
        add("attempt.solver")
    if (relay is not None) != (mode == "stream" and route == "cdcl"):
        add("attempt.relay")
    proof_bytes, proof_sha256 = attempt["proof_bytes"], attempt["proof_sha256"]
    if (proof_bytes is None) != (proof_sha256 is None):
        add("attempt.proof_pair")
    if relay is not None and proof_sha256 is not None:
        complete = relay["solver_eof"] and relay["all_written"] and relay["error"] is None
        same = relay["bytes"] == proof_bytes and relay["sha256"] == proof_sha256
        if not (complete and same):
            add("attempt.stream_proof")
    if outcome in ("MODEL", "INVALID_MODEL"):
        bad_solver = route == "cdcl" and (solver is None or solver["exit"] != 10)
        if proof_bytes is not None or proof_sha256 is not None or attempt["checks"] or bad_solver:
            add("attempt.model_shape")
    if outcome == "MODEL":
        shape_ok = model_error is None and assignment is not None
    elif outcome == "INVALID_MODEL":
        wants = model_error == "violated"
        shape_ok = model_error is not None and (assignment is not None) == wants
    else:
        shape_ok = model_error is None and assignment is None
    if not shape_ok:
        add("attempt.model_error")
    if (
        assignment is not None
        and variables is not None
        and decode_assignment(assignment, variables) is None
    ):
        add("attempt.assignment")
    retained = attempt["retained"]
    if retained is not None and not (
        outcome == "VERIFIED_UNSAT"
        and mode == "retain"
        and retained["sha256"] == proof_sha256
        and retained["bytes"] == proof_bytes
    ):
        add("attempt.retained")
    quarantined = attempt["quarantined"]
    if quarantined is not None and not (
        outcome == "CHECK_REJECTED" and mode in ("transient", "retain")
    ):
        add("attempt.quarantined")
    results = ([solver] if solver is not None else []) + [c["result"] for c in attempt["checks"]]
    for result in results:
        found.extend(process_problems(result))
    if admitted and outcome == "VERIFIED_UNSAT":
        found.extend(success_problems(attempt))
    return list(dict.fromkeys(found))


def success_problems(attempt: dict[str, Any]) -> list[str]:
    """Reading 3 level (ii): admitted VERIFIED_UNSAT."""
    found = []
    if attempt["proof_bytes"] is None or attempt["proof_sha256"] is None:
        found.append("success.proof")
    if not attempt["checks"]:
        found.append("success.checks")
    else:
        last = attempt["checks"][-1]["result"]
        if not (
            last["exit"] == 0
            and last["signal"] is None
            and last["stdout_bytes"] == len(SUCCESS_LINE)
            and last["stdout_truncated"] is False
            and last["stdout_tail"] == SUCCESS_LINE
        ):
            found.append("success.checker_output")
    if attempt["route"] == "cdcl":
        solver = attempt["solver"]
        if solver is None or not (
            solver["started"] and solver["exit"] == 20 and solver["signal"] is None
        ):
            found.append("success.solver")
    return found


def node_fields(record: dict[str, Any]) -> list[dict[str, Any]]:
    """Every Node of a journal record, in field order."""
    kind = record["type"]
    if kind in ("split", "attempt", "node_stop", "node_reopen"):
        return [record["node"]]
    if kind == "shard":
        return list(record["shard"]["nodes"])
    if kind == "handoff":
        return list(record["shard"]["nodes"]) if record["shard"] is not None else []
    if kind in ("audit_target", "audit_result"):
        return [record["target"]["node"]]
    return []


def record_problems(
    record: dict[str, Any], variables: int | None = None, admitted: bool | None = None
) -> list[str]:
    """Rules of one schema-valid record that need no other record."""
    found: list[str] = []
    kind = record["type"]
    if not utc_valid(record["utc"]):
        found.append("utc.calendar")
    if kind in ("header", "resume"):
        found += machinery_problems(record["machinery"]) + policy_problems(record["policy"])
    for node in node_fields(record):
        problem = cube_problem(node["cube"], variables)
        if problem:
            found.append(problem)
    if found:
        return list(dict.fromkeys(found))
    if kind == "attempt":
        if record["node_id"] != node_id(record["node"]["formula_sha256"], record["node"]["cube"]):
            found.append("record.node_id")
        found += attempt_problems(record, variables, admitted)
    elif kind in ("audit_target", "audit_result"):
        target = record["target"]
        if target["node_id"] != node_id(target["node"]["formula_sha256"], target["node"]["cube"]):
            found.append("record.node_id")
        found += machinery_problems(target["machinery"])
    elif kind == "shard":
        found += nodes_problems(record["shard"]["nodes"])
        if record["shard_sha256"] != j_hash(record["shard"]):
            found.append("shard.hash")
    elif kind == "handoff":
        shard, digest = record["shard"], record["shard_sha256"]
        if (shard is None) != (digest is None):
            found.append("handoff.pair")
        elif shard is not None:
            found += nodes_problems(shard["nodes"])
            if digest != j_hash(shard):
                found.append("shard.hash")
            if len(shard["nodes"]) > record["request"]["node_count"]:
                found.append("handoff.count")
    return list(dict.fromkeys(found))


# -- documents ----------------------------------------------------------------------------------

DOCUMENT_SCHEMAS = {
    "bundle-manifest": "bundle-manifest.schema.json",
    "policy": "policy.schema.json",
    "campaign": "campaign.schema.json",
    "shard": "shard.schema.json",
    "handoff-request": "handoff-request.schema.json",
    "journal-record": "journal-record.schema.json",
    "certificate": "certificate.schema.json",
    "evidence-manifest": "evidence-manifest.schema.json",
    "audit-report": "audit-report.schema.json",
    "status": "status.schema.json",
    "weights": "weights.schema.json",
    "roots": "roots.schema.json",
    "prefixes": "prefixes.schema.json",
    "look-request": "look-request.schema.json",
    "look-result": "look-result.schema.json",
}


def schema_errors(store: SchemaStore, kind: str, value: Any) -> list[str]:
    name = DOCUMENT_SCHEMAS[kind]
    if kind == "journal-record" and isinstance(value, dict) and value.get("type") in RECORD_TYPES:
        return store.errors(value, name, "/$defs/" + value["type"])
    return store.errors(value, name)


def _summary_ok(summary: dict[str, Any], closed: bool) -> bool:
    if not closed:
        return summary == ZERO_SUMMARY
    return summary["leaves"] >= 1 and summary["leaf_merkle_root"] is not None


def _ref_key(ref: dict[str, Any]) -> Ref:
    return (ref["journal"], ref["seq"])


def certificate_problems(cert: dict[str, Any]) -> list[str]:
    found = []
    orders: list[list[Any]] = [
        [j["id"] for j in cert["journals"]],
        [f["formula_sha256"] for f in cert["formulas"]],
        [u["node_id"] for u in cert["used_attempts"]],
        [(m["journal"], m["snapshot_seq"]) for m in cert["machinery"]],
        [_ref_key(x["record"]) for x in cert["not_admitted"]],
        [_ref_key(x["record"]) for x in cert["models"]],
        [(_ref_key(x["record"]), x["code"]) for x in cert["anomalies"]],
        [(o["node"]["formula_sha256"], o["node_id"]) for o in cert["open"]],
        [(o["node"]["formula_sha256"], o["node_id"]) for o in cert["formula_open"]],
    ]
    for formula in cert["formulas"]:
        orders.append([node_id(formula["formula_sha256"], r["cube"]) for r in formula["roots"]])
    if not all(strictly_increasing(keys) for keys in orders):
        found.append("certificate.order")
    summaries_ok = all(
        _summary_ok(f["summary"], f["proved"])
        and all(_summary_ok(r["summary"], r["closed"]) for r in f["roots"])
        for f in cert["formulas"]
    )
    if not summaries_ok:
        found.append("certificate.summary")
    entries = [(u["node"], u["node_id"]) for u in cert["used_attempts"]]
    entries += [(o["node"], o["node_id"]) for o in cert["open"] + cert["formula_open"]]
    if any(ident != node_id(n["formula_sha256"], n["cube"]) for n, ident in entries):
        found.append("record.node_id")
    return found


def status_problems(status: dict[str, Any]) -> list[str]:
    found = []
    orders: list[list[Any]] = [
        [r["task_id"] for r in status["reservations"]],
        [(n["state"], n["depth"]) for n in status["node_counts"]],
        [a["task_id"] for a in status["active"]],
        [_ref_key(r) for r in status["models"]],
        [_ref_key(r) for r in status["anomalies"]],
        [
            (c["node"]["formula_sha256"], node_id(c["node"]["formula_sha256"], c["node"]["cube"]))
            for c in status["coverage"]
        ],
    ]
    if not all(strictly_increasing(keys) for keys in orders):
        found.append("status.order")
    if not utc_valid(status["utc"]) or (
        status["export"] is not None and not utc_valid(status["export"]["utc"])
    ):
        found.append("utc.calendar")
    for entry in status["coverage"]:
        numerator, power = int(entry["closed_numerator"]), entry["denominator_power_two"]
        reduced = numerator in (0, 1) if power == 0 else numerator % 2 == 1
        if not reduced or numerator > (1 << power):
            found.append("status.coverage")
            break
    return found


def names_problems(data: bytes, context: dict[str, Any]) -> list[str]:
    return _tsv_problems(data, context, columns=1)


def tags_problems(data: bytes, context: dict[str, Any]) -> list[str]:
    return _tsv_problems(data, context, columns=2)


_DECIMAL = re.compile(r"[1-9][0-9]*")


def _tsv_problems(  # noqa: PLR0911 - one early return per rule keeps the order visible
    data: bytes, context: dict[str, Any], columns: int
) -> list[str]:
    prefix = "names" if columns == 1 else "tags"
    artifact = context.get("artifact")
    if artifact is not None and (
        artifact["bytes"] != len(data) or artifact["sha256"] != sha256_hex(data)
    ):
        return ["side.artifact"]
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return [f"{prefix}.syntax"]
    if text and not text.endswith("\n"):
        return [f"{prefix}.syntax"]
    keys: list[tuple[Any, ...]] = []
    for line in text.split("\n")[:-1]:
        parts = line.split("\t")
        if len(parts) != columns + 1 or not all(_DECIMAL.fullmatch(p) for p in parts[:-1]):
            return [f"{prefix}.syntax"]
        try:
            label = json.loads(parts[-1])
        except ValueError:
            return [f"{prefix}.syntax"]
        if not isinstance(label, str) or j_bytes(label).decode("utf-8") != parts[-1]:
            return [f"{prefix}.syntax"]
        numbers = tuple(int(p) for p in parts[:-1])
        keys.append(numbers if columns == 1 else (*numbers, label))
    if not strictly_increasing(keys):
        return [f"{prefix}.order"]
    if columns == 1:
        if any(not 1 <= k[0] <= context["variables"] for k in keys):
            return ["names.range"]
    elif any(not 1 <= k[0] <= k[1] <= context["clauses"] for k in keys):
        return ["tags.range"]
    return []


def manifest_problems(manifest: dict[str, Any], formula_data: bytes | None) -> list[str]:
    found = []
    if formula_data is not None:
        try:
            formula = parse_dimacs(formula_data)
        except Problem as problem:
            return [problem.rule]
        if manifest["formula_sha256"] != formula.sha256:
            found.append("bundle.formula_sha256")
        if (manifest["variables"], manifest["clauses"]) != (
            formula.variables,
            len(formula.clauses),
        ):
            found.append("bundle.counts")
    pools_ok = all(
        strictly_increasing(pool) and all(v <= manifest["variables"] for v in pool)
        for pool in manifest["pools"].values()
    )
    if not pools_ok:
        found.append("bundle.pools")
    if not strictly_increasing([a["path"] for a in manifest["side_files"]]):
        found.append("bundle.side_files")
    return found


def _manifest_document(value: Any, context: dict[str, Any]) -> list[str]:
    formula = context.get("formula")
    return manifest_problems(value, formula.encode("utf-8") if formula is not None else None)


def _evidence_manifest(value: Any, context: dict[str, Any]) -> list[str]:
    ordered = strictly_increasing([b["manifest"]["path"] for b in value["bundles"]])
    ordered = ordered and strictly_increasing([j["path"] for j in value["journals"]])
    return [] if ordered else ["evidence.order"]


def _look_request(value: Any, context: dict[str, Any]) -> list[str]:
    found = []
    problem = cube_problem(value["cube"], None)
    if problem:
        found.append(problem)
    if value["pool"] is not None and not strictly_increasing(value["pool"]):
        found.append("look.pool")
    return found


def _look_result(value: Any, context: dict[str, Any]) -> list[str]:
    chosen = value["variables"]
    return [] if len(set(chosen)) == len(chosen) else ["look.variables"]


def _weights(value: Any, context: dict[str, Any]) -> list[str]:
    planned = set(context.get("planned", []))
    return ["weights.unknown"] if set(value["costs"]) - planned else []


def _roots(value: Any, context: dict[str, Any]) -> list[str]:
    return ["roots.nodes" if p == "shard.nodes" else p for p in nodes_problems(value["roots"])]


def _prefixes(value: Any, context: dict[str, Any]) -> list[str]:
    return prefixes_problems(value, context)


SEMANTIC: dict[str, Callable[[Any, dict[str, Any]], list[str]]] = {
    "json": lambda value, context: [],
    "bundle-manifest": _manifest_document,
    "policy": lambda value, context: policy_problems(value),
    "shard": lambda value, context: nodes_problems(value["nodes"], context.get("variables")),
    "handoff-request": lambda value, context: [],
    "journal-record": lambda value, context: record_problems(
        value, context.get("variables"), context.get("admitted")
    ),
    "certificate": lambda value, context: certificate_problems(value),
    "evidence-manifest": _evidence_manifest,
    "audit-report": lambda value, context: audit_report_problems(value),
    "status": lambda value, context: status_problems(value),
    "weights": _weights,
    "roots": _roots,
    "prefixes": _prefixes,
    "look-request": _look_request,
    "look-result": _look_result,
}


def audit_report_problems(report: dict[str, Any]) -> list[str]:
    found = []
    tally = dict.fromkeys(report["counts"], 0)
    for result in report["results"]:
        tally[result["status"]] = tally.get(result["status"], 0) + 1
    if tally != report["counts"]:
        found.append("audit_report.counts")
    if (
        report["selected"] != len(report["results"]) + len(report["pending"])
        or report["selected"] > report["population"]
    ):
        found.append("audit_report.selected")
    return found


def prefixes_problems(value: dict[str, Any], context: dict[str, Any]) -> list[str]:
    splits = value["splits"]
    for entry in splits:
        problem = cube_problem(entry["node"]["cube"], None)
        if problem:
            return [problem]
    ids = [
        split_id(node_id(s["node"]["formula_sha256"], s["node"]["cube"]), s["variables"])
        for s in splits
    ]
    if not strictly_increasing(ids):
        return ["prefixes.order"]
    counts = context.get("formulas", {})
    for entry in splits:
        count = counts.get(entry["node"]["formula_sha256"], INT_MAX)
        problem = split_problem(entry["variables"], entry["node"]["cube"], count)
        if problem:
            return [problem]
    return []


def validate_document(
    store: SchemaStore, kind: str, data: bytes, context: dict[str, Any] | None = None
) -> list[str]:
    """Rule identifiers violated by one document, ``schema@<location>`` for schema errors."""
    context = context or {}
    if kind in TEXT_RULES:
        return TEXT_RULES[kind](data, context)
    try:
        if kind == "journal-record":
            if not data.endswith(b"\n"):
                raise Problem("json.canonical", "a journal line ends with LF")
            value = parse_line(data[:-1])
        else:
            value = parse_document(data)
    except Problem as problem:
        return [problem.rule]
    errors = schema_errors(store, kind, value) if kind != "json" else []
    if errors:
        return sorted({"schema@" + e.split(": ", 1)[0] for e in errors})
    return list(dict.fromkeys(SEMANTIC[kind](value, context)))


def _dimacs_problems(data: bytes, context: dict[str, Any]) -> list[str]:
    try:
        parse_dimacs(data)
    except Problem as problem:
        return [problem.rule]
    return []


TEXT_RULES: dict[str, Callable[[bytes, dict[str, Any]], list[str]]] = {
    "dimacs": _dimacs_problems,
    "names-tsv": names_problems,
    "tags-tsv": tags_problems,
}


# -- evidence: campaign, bundles, journals (specification §4.2-§4.4, §4.7-§4.8, §7.1, §10.1) -------


@dataclass
class Bundle:
    formula: Formula
    pools: dict[str, list[int]]


@dataclass
class Campaign:
    value: dict[str, Any]
    id: str
    bundles: dict[str, Bundle]
    keys: dict[str, str]

    def formula(self, sha: str) -> Formula:
        return self.bundles[sha].formula


@dataclass
class Journal:
    name: str
    lines: list[bytes]
    records: list[dict[str, Any]]
    torn: int

    @property
    def id(self) -> str:
        return str(self.records[0]["self"])

    @property
    def worker(self) -> str:
        return str(self.records[0]["worker"])

    @property
    def size(self) -> int:
        return sum(len(line) + 1 for line in self.lines)


def _fail(kind: str, problem: Problem, where: str) -> Problem:
    actual = "resource" if problem.rule.startswith("limit.") else kind
    return Problem(problem.rule, f"{where}: {problem.detail}", actual)


def _regular_file(base: Path, relative: str, name: str) -> Path:
    path = base
    for part in [*relative.split("/"), name]:
        path = path / part
        try:
            mode = os.lstat(path).st_mode
        except FileNotFoundError:
            raise Problem("bundle.files", str(path), "input") from None
        if stat.S_ISLNK(mode):
            raise Problem("path.containment", str(path), "input")
    if not stat.S_ISREG(mode):
        raise Problem("path.containment", str(path), "input")
    return path


def _load_bundle(base: Path, entry: dict[str, Any], store: SchemaStore) -> Bundle:
    manifest_path = _regular_file(base, entry["bundle"], "manifest.json")
    formula_path = _regular_file(base, entry["bundle"], "formula.cnf")
    try:
        manifest = parse_document(manifest_path.read_bytes())
    except Problem as problem:
        raise _fail("input", problem, str(manifest_path)) from None
    if store.errors(manifest, "bundle-manifest.schema.json"):
        raise Problem("schema", str(manifest_path), "input")
    data = formula_path.read_bytes()
    found = manifest_problems(manifest, data)
    if found:
        raise Problem(found[0], str(manifest_path), "input")
    if manifest["formula_sha256"] != entry["formula_sha256"]:
        raise Problem("bundle.campaign_hash", entry["key"], "input")
    return Bundle(parse_dimacs(data), manifest["pools"])


def campaign_problems(campaign: dict[str, Any], bundles: dict[str, Bundle]) -> list[str]:
    """Readings 8-10 and specification §4.4 cross-field rules; bundles keyed by formula hash."""
    found: list[str] = []
    add = found.append
    if not utc_valid(campaign["created_utc"]):
        add("utc.calendar")
    formulas = campaign["formulas"]
    if not strictly_increasing([f["key"] for f in formulas]):
        add("campaign.formulas_order")
    hashes = [f["formula_sha256"] for f in formulas]
    if len(set(hashes)) != len(hashes):
        add("campaign.formula_hash_unique")
    nodes = [*campaign["roots"], *(s["node"] for s in campaign["root_splits"])]
    if any(n["formula_sha256"] not in bundles for n in nodes):
        add("campaign.node_formula")
        return found
    for node in nodes:
        problem = cube_problem(node["cube"], bundles[node["formula_sha256"]].formula.variables)
        if problem:
            add(problem)
    if found:
        return list(dict.fromkeys(found))
    roots = campaign["roots"]
    if not strictly_increasing([(r["formula_sha256"], node_id(**r)) for r in roots]):
        add("campaign.roots_order")
    if {r["formula_sha256"] for r in roots} != set(hashes):
        add("campaign.roots_per_formula")
    if same_formula_compatible(roots):
        add("campaign.roots_incompatible")
    split_ids = []
    for entry in campaign["root_splits"]:
        node = entry["node"]
        split_ids.append(split_id(node_id(**node), entry["variables"]))
        count = bundles[node["formula_sha256"]].formula.variables
        problem = split_problem(entry["variables"], node["cube"], count)
        if problem:
            add(problem)
        if node["cube"] and node not in roots:
            add("campaign.root_split_node")
    if not strictly_increasing(split_ids):
        add("campaign.splits_order")
    found += policy_problems(campaign["policy"])
    pool = campaign["policy"]["split"]["pool"]
    if pool is not None and any(pool not in b.pools for b in bundles.values()):
        add("campaign.pool")
    tools, admit = campaign["tools"], campaign["admit"]
    argvs = [tools["solver"]["argv"], *(s["argv"] for s in admit["solvers"] or [])]
    if any("--lrat" not in argv or not all(a.startswith("-") for a in argv) for argv in argvs):
        add("campaign.argv")
    solvers = admit["solvers"] or []
    if not strictly_increasing(admit["checker_sha256"]) or not strictly_increasing(
        [(s["sha256"], j_bytes(s["argv"])) for s in solvers]
    ):
        add("campaign.admit_order")
    configured = {"sha256": tools["solver"]["sha256"], "argv": tools["solver"]["argv"]}
    if tools["checker"]["sha256"] not in admit["checker_sha256"] or (
        admit["solvers"] is not None and configured not in admit["solvers"]
    ):
        add("campaign.tools_admitted")
    return list(dict.fromkeys(found))


def load_campaign(path: Path, store: SchemaStore) -> Campaign:
    data = path.read_bytes()
    if len(data) > DOCUMENT_LIMIT + 1:
        raise Problem("limit.document", str(path), "resource")
    try:
        value = parse_document(data)
    except Problem as problem:
        raise _fail("input", problem, str(path)) from None
    if store.errors(value, "campaign.schema.json"):
        raise Problem("schema", str(path), "input")
    bundles: dict[str, Bundle] = {}
    for entry in value["formulas"]:
        bundles[entry["formula_sha256"]] = _load_bundle(path.parent, entry, store)
    found = campaign_problems(value, bundles)
    if found:
        raise Problem(found[0], str(path), "input")
    keys = {f["formula_sha256"]: f["key"] for f in value["formulas"]}
    return Campaign(value, j_hash(value), bundles, keys)


def read_journal(path: Path, store: SchemaStore, campaign: Campaign) -> Journal:
    """Complete-line validation of one file (specification §7.1 order) plus its record rules."""
    data = path.read_bytes()
    parts = data.split(b"\n")
    lines, torn = parts[:-1], parts[-1]
    if not lines:
        raise Problem("journal.no_header", path.name, "input")
    records: list[dict[str, Any]] = []
    for seq, line in enumerate(lines):
        where = f"{path.name}:{seq + 1}"
        if len(line) > LINE_LIMIT:
            raise Problem("limit.line", where, "resource")
        try:
            record = parse_line(line)
        except Problem as problem:
            raise _fail("integrity", problem, where) from None
        if schema_errors(store, "journal-record", record):
            raise Problem("schema", where, "integrity")
        unsigned = {k: v for k, v in record.items() if k != "self"}
        if record["self"] != j_hash(unsigned):
            raise Problem("journal.self", where, "integrity")
        if record["seq"] != seq:
            raise Problem("journal.seq", where, "integrity")
        if record["prev"] != (records[-1]["self"] if records else ZERO_HASH):
            raise Problem("journal.prev", where, "integrity")
        if (seq == 0) != (record["type"] == "header"):
            raise Problem("journal.header", where, "integrity")
        if seq == 0 and record["campaign"] != campaign.id:
            raise Problem("journal.campaign", where, "input")
        records.append(record)
    journal = Journal(path.name, lines, records, len(torn))
    check_records(journal, campaign)
    return journal


def check_records(journal: Journal, campaign: Campaign) -> None:
    purpose = journal.records[0]["purpose"]
    snapshot: dict[str, Any] = journal.records[0]
    attempt_ids: set[str] = set()
    request_ids: set[str] = set()
    for record in journal.records:
        where = f"{journal.name}:{record['seq'] + 1}"
        kind = record["type"]
        allowed = kind in AUDIT_PURPOSE_TYPES or kind.startswith("audit_")
        if (purpose == "run" and kind.startswith("audit_")) or (purpose == "audit" and not allowed):
            raise Problem("journal.purpose", where, "integrity")
        for node in node_fields(record):
            if node["formula_sha256"] not in campaign.bundles:
                raise Problem("record.formula", where, "integrity")
        if kind in ("header", "resume"):
            snapshot = record
        variables = None
        if kind in ("split", "attempt", "node_stop", "node_reopen"):
            variables = campaign.formula(record["node"]["formula_sha256"]).variables
        admitted = admission(campaign, snapshot) is None if kind == "attempt" else None
        found = record_problems(record, variables, admitted)
        if not found and kind in ("shard", "handoff", "audit_target", "audit_result"):
            found = _context_node_problems(record, campaign)
        if not found and kind == "attempt":
            found = _attempt_context_problems(record, campaign, snapshot, attempt_ids)
        if not found and kind == "handoff":
            request_id = record["request"]["request_id"]
            if request_id in request_ids:
                found = ["handoff.request_unique"]
            request_ids.add(request_id)
        if found:
            raise Problem(found[0], where, "integrity")


def _context_node_problems(record: dict[str, Any], campaign: Campaign) -> list[str]:
    for node in node_fields(record):
        problem = cube_problem(node["cube"], campaign.formula(node["formula_sha256"]).variables)
        if problem:
            return [problem]
    shard = record.get("shard")
    request = record.get("request")
    if (shard is not None and shard["campaign"] != campaign.id) or (
        request is not None and request["campaign"] != campaign.id
    ):
        return ["shard.campaign"]
    return []


def _attempt_context_problems(
    attempt: dict[str, Any], campaign: Campaign, snapshot: dict[str, Any], seen: set[str]
) -> list[str]:
    if attempt["policy_sha256"] != j_hash(snapshot["policy"]):
        return ["attempt.policy_sha256"]
    if attempt["attempt_id"] in seen:
        return ["attempt.attempt_id"]
    seen.add(attempt["attempt_id"])
    node = attempt["node"]
    formula = campaign.formula(node["formula_sha256"])
    if attempt["cnf_sha256"] != sha256_hex(cube_cnf(formula, node["cube"])):
        return ["attempt.cnf_sha256"]
    if attempt["outcome"] == "MODEL":
        values = decode_assignment(attempt["assignment"], formula.variables)
        if values is None or not satisfies(formula, node["cube"], values):
            return ["attempt.model_false"]
    return []


def admission(campaign: Campaign, snapshot: dict[str, Any]) -> str | None:
    """None when admitted, otherwise the not_admitted reason of reading 5."""
    admit = campaign.value["admit"]
    machinery = snapshot["machinery"]
    if machinery["checker"]["sha256"] not in admit["checker_sha256"]:
        return "checker_not_admitted"
    solver = {"sha256": machinery["solver"]["sha256"], "argv": machinery["solver"]["argv"]}
    if admit["solvers"] is not None and solver not in admit["solvers"]:
        return "solver_not_admitted"
    return None


def select_journals(journals: Sequence[Journal]) -> list[tuple[Journal, int]]:
    """Longest copy per header ID with the smallest torn tail among the longest
    (specification §10.1)."""
    groups: dict[str, list[Journal]] = {}
    for journal in journals:
        groups.setdefault(journal.id, []).append(journal)
    chosen = []
    workers: dict[str, str] = {}
    for ident in sorted(groups):
        group = sorted(groups[ident], key=lambda j: -len(j.lines))
        longest = group[0]
        for other in group[1:]:
            if other.lines != longest.lines[: len(other.lines)]:
                raise Problem("journal.fork", f"{longest.name} {other.name}", "integrity")
        torn = min(j.torn for j in group if len(j.lines) == len(longest.lines))
        if workers.setdefault(longest.worker, ident) != ident:
            raise Problem("journal.worker", longest.worker, "integrity")
        chosen.append((longest, torn))
    return chosen


# -- certification (specification §10.2-§10.5) -----------------------------------------------------


@dataclass
class Graph:
    campaign: Campaign
    splits: dict[Key, dict[str, tuple[int, ...]]] = field(default_factory=dict)
    verified: dict[Key, list[tuple[Ref, dict[str, Any]]]] = field(default_factory=dict)
    models: dict[Key, list[Ref]] = field(default_factory=dict)
    labels: dict[Key, dict[str, tuple[int, dict[str, Any]]]] = field(default_factory=dict)
    _closed: dict[Key, bool] = field(default_factory=dict)

    def add_split(self, formula: str, cube: Sequence[int], variables: Sequence[int]) -> None:
        key = (formula, tuple(cube))
        ident = split_id(node_id(formula, cube), variables)
        self.splits.setdefault(key, {})[ident] = tuple(variables)

    def closed(self, key: Key) -> bool:
        if key not in self._closed:
            self._closed[key] = bool(self.verified.get(key)) or any(
                all(self.closed((key[0], c)) for c in split_children(key[1], w))
                for w in self.splits.get(key, {}).values()
            )
        return self._closed[key]

    def select(self, key: Key) -> tuple[list[tuple[Key, Ref, dict[str, Any]]], int]:
        """Leaves and split count of the selected tree of a closed node."""
        if self.verified.get(key):
            ref, attempt = min(self.verified[key], key=lambda item: item[0])
            return [(key, ref, attempt)], 0
        closed = sorted(
            ident
            for ident, w in self.splits[key].items()
            if all(self.closed((key[0], c)) for c in split_children(key[1], w))
        )
        leaves: list[tuple[Key, Ref, dict[str, Any]]] = []
        count = 1
        for child in split_children(key[1], self.splits[key][closed[0]]):
            more, splits = self.select((key[0], child))
            leaves += more
            count += splits
        return leaves, count

    def frontier(self, key: Key) -> list[tuple[Key, str, str | None]]:
        if self.closed(key):
            return []
        if self.models.get(key):
            return [(key, "model", None)]
        options = self.splits.get(key)
        if options:
            smallest = options[min(options)]
            found = []
            for child in split_children(key[1], smallest):
                found += self.frontier((key[0], child))
            return found
        stops = [
            ((journal, seq), record)
            for journal, (seq, record) in self.labels.get(key, {}).items()
            if record["type"] == "node_stop"
        ]
        if not stops:
            return [(key, "pending", None)]
        _, record = min(stops, key=lambda item: item[0])
        return [(key, record["state"], record["reason"])]


def _node(key: Key) -> dict[str, Any]:
    return {"formula_sha256": key[0], "cube": list(key[1])}


def _ref(ref: Ref) -> dict[str, Any]:
    return {"journal": ref[0], "seq": ref[1]}


@dataclass
class Outcome:
    exit: int
    certificate: dict[str, Any] | None = None
    kind: str | None = None
    rule: str | None = None
    detail: str = ""
    duplicates: list[str] = field(default_factory=list)


def certify(campaign_path: Path, journal_paths: Sequence[Path], store: SchemaStore) -> Outcome:
    """The reference certify command: a certificate, or exit 4 with kind and rule."""
    try:
        campaign = load_campaign(campaign_path, store)
        journals = [read_journal(p, store, campaign) for p in journal_paths]
        selected = select_journals(journals)
    except Problem as problem:
        return Outcome(4, None, problem.kind, problem.rule, problem.detail)
    certificate = build_certificate(campaign, selected)
    return Outcome(VERDICT_EXIT[certificate["verdict"]], certificate)


def build_certificate(campaign: Campaign, selected: list[tuple[Journal, int]]) -> dict[str, Any]:
    graph = Graph(campaign)
    for entry in campaign.value["root_splits"]:
        graph.add_split(entry["node"]["formula_sha256"], entry["node"]["cube"], entry["variables"])
    not_admitted: list[dict[str, Any]] = []
    models: list[dict[str, Any]] = []
    anomalies: list[dict[str, Any]] = []
    snapshots: dict[Ref, int] = {}
    for journal, _ in selected:
        snapshot = journal.records[0]
        for record in journal.records:
            ref: Ref = (journal.id, record["seq"])
            kind = record["type"]
            if kind in ("header", "resume"):
                snapshot = record
            elif kind == "split":
                node = record["node"]
                count = campaign.formula(node["formula_sha256"]).variables
                problem = split_problem(record["variables"], node["cube"], count)
                if problem is None:
                    graph.add_split(node["formula_sha256"], node["cube"], record["variables"])
                else:
                    info = {"problem": problem.split(".", 1)[1]}
                    anomalies.append({"record": _ref(ref), "code": "malformed_split", "info": info})
            elif kind in ("node_stop", "node_reopen"):
                key = (record["node"]["formula_sha256"], tuple(record["node"]["cube"]))
                graph.labels.setdefault(key, {})[journal.id] = (record["seq"], record)
            elif kind == "attempt":
                snapshots[ref] = snapshot["seq"]
                _attempt(graph, campaign, snapshot, ref, record, not_admitted, models, anomalies)
    formulas = []
    used: dict[str, dict[str, Any]] = {}
    for entry in campaign.value["formulas"]:
        sha = entry["formula_sha256"]
        proved = graph.closed((sha, ()))
        summary = _summary(graph, (sha, ()), used) if proved else dict(ZERO_SUMMARY)
        roots = []
        for root in campaign.value["roots"]:
            if root["formula_sha256"] != sha:
                continue
            key = (sha, tuple(root["cube"]))
            closed = graph.closed(key)
            roots.append(
                {
                    "cube": root["cube"],
                    "closed": closed,
                    "summary": _summary(graph, key, used) if closed else dict(ZERO_SUMMARY),
                }
            )
        roots.sort(key=lambda r: node_id(sha, r["cube"]))
        formulas.append(
            {"formula_sha256": sha, "key": entry["key"], "proved": proved}
            | {"summary": summary, "roots": roots}
        )
    formulas.sort(key=lambda f: f["formula_sha256"])

    def open_entries(keys: Iterable[Key]) -> list[dict[str, Any]]:
        entries = []
        for start in keys:
            for key, state, reason in graph.frontier(start):
                entries.append(
                    {"node": _node(key), "node_id": node_id(key[0], key[1])}
                    | {"state": state, "reason": reason}
                )
        return sorted(entries, key=lambda e: (e["node"]["formula_sha256"], e["node_id"]))

    roots_keys = [(r["formula_sha256"], tuple(r["cube"])) for r in campaign.value["roots"]]
    empty_keys = [(f["formula_sha256"], ()) for f in campaign.value["formulas"]]
    machinery = []
    seen = set()
    by_id = {j.id: j for j, _ in selected}
    for item in used.values():
        ref = (item["record"]["journal"], item["record"]["seq"])
        snap = snapshots[ref]
        if (ref[0], snap) not in seen:
            seen.add((ref[0], snap))
            record = by_id[ref[0]].records[snap]
            machinery.append(
                {"journal": ref[0], "snapshot_seq": snap, "machinery": record["machinery"]}
            )
    valid_model_formulas = {m["node"]["formula_sha256"] for m in models}
    closed_formulas = {f["formula_sha256"] for f in formulas if f["proved"]}
    if valid_model_formulas & closed_formulas:
        verdict = "INCONSISTENT"
    elif models:
        verdict = "MODEL_FOUND"
    elif len(closed_formulas) == len(formulas):
        verdict = "PROVED"
    else:
        verdict = "OPEN"
    return {
        "format": "cubeproof-certificate-1",
        "campaign": campaign.id,
        "journals": [
            {
                "id": j.id,
                "worker": j.worker,
                "records": len(j.records),
                "head": j.records[-1]["self"],
                "bytes": j.size,
                "torn_tail_bytes": torn,
            }
            for j, torn in selected
        ],
        "formulas": formulas,
        "open": open_entries(roots_keys),
        "formula_open": open_entries(empty_keys),
        "used_attempts": sorted(used.values(), key=lambda u: u["node_id"]),
        "machinery": sorted(machinery, key=lambda m: (m["journal"], m["snapshot_seq"])),
        "not_admitted": sorted(not_admitted, key=lambda x: _ref_key(x["record"])),
        "models": sorted(models, key=lambda x: _ref_key(x["record"])),
        "anomalies": sorted(anomalies, key=lambda x: (_ref_key(x["record"]), x["code"])),
        "verdict": verdict,
    }


def _attempt(
    graph: Graph,
    campaign: Campaign,
    snapshot: dict[str, Any],
    ref: Ref,
    attempt: dict[str, Any],
    not_admitted: list[dict[str, Any]],
    models: list[dict[str, Any]],
    anomalies: list[dict[str, Any]],
) -> None:
    node = attempt["node"]
    key = (node["formula_sha256"], tuple(node["cube"]))
    reason = admission(campaign, snapshot)
    outcome = attempt["outcome"]
    if reason is not None:
        not_admitted.append({"record": _ref(ref), "reason": reason})
    elif outcome == "VERIFIED_UNSAT":
        graph.verified.setdefault(key, []).append((ref, attempt))
    if outcome == "CHECK_REJECTED":
        anomalies.append({"record": _ref(ref), "code": "check_rejected", "info": {}})
    if outcome not in ("MODEL", "INVALID_MODEL"):
        return
    formula = campaign.formula(node["formula_sha256"])
    values = None
    if attempt["assignment"] is not None:
        values = decode_assignment(attempt["assignment"], formula.variables)
    valid = values is not None and satisfies(formula, node["cube"], values)
    if valid:
        models.append({"record": _ref(ref), "node": node, "assignment": attempt["assignment"]})
        graph.models.setdefault(key, []).append(ref)
    if outcome == "INVALID_MODEL":
        if valid:
            anomalies.append({"record": _ref(ref), "code": "mislabelled_model", "info": {}})
        else:
            info = {"model_error": attempt["model_error"]}
            anomalies.append({"record": _ref(ref), "code": "invalid_model", "info": info})


def _summary(graph: Graph, key: Key, used: dict[str, dict[str, Any]]) -> dict[str, Any]:
    leaves, splits = graph.select(key)
    triples = []
    for leaf_key, ref, attempt in leaves:
        ident = node_id(leaf_key[0], leaf_key[1])
        triples.append((ident, attempt["cnf_sha256"], attempt["proof_sha256"]))
        used[ident] = {
            "node": _node(leaf_key),
            "node_id": ident,
            "record": _ref(ref),
            "cnf_sha256": attempt["cnf_sha256"],
            "proof_sha256": attempt["proof_sha256"],
            "route": attempt["route"],
        }
    return {
        "leaves": len(leaves),
        "splits": splits,
        "max_cube_size": max(len(k[1]) for k, _, _ in leaves),
        "leaf_merkle_root": merkle_root(triples),
    }


# -- audit plans (specification §11.1; consumer: audit) --------------------------------------------


def audit_plan_problems(records: Sequence[dict[str, Any]]) -> list[str]:
    """Rules of the audit plan inside one audit-purpose journal."""
    sequence = [r for r in records if r["type"] not in ("header", "resume", "repair")]
    if not sequence or sequence[0]["type"] != "audit_begin":
        return ["audit.plan_order"]
    begin = sequence[0]
    targets = []
    index = 1
    while index < len(sequence) and sequence[index]["type"] == "audit_target":
        targets.append(sequence[index])
        index += 1
    ordinals_ok = [t["ordinal"] for t in targets] == list(range(len(targets)))
    ready_ok = index < len(sequence) and sequence[index]["type"] == "audit_ready"
    rest = sequence[index + 1 :] if ready_ok else []
    later_ok = all(r["type"] in ("attempt", "audit_result") for r in rest)
    if not (ordinals_ok and ready_ok and later_ok):
        return ["audit.plan_order"]
    ready = sequence[index]
    digest = sha256_hex(b"".join(j_bytes(t["target"]) + b"\n" for t in targets))
    counts_ok = begin["target_count"] == ready["target_count"] == len(targets)
    if not (counts_ok and begin["targets_sha256"] == ready["targets_sha256"] == digest):
        return ["audit.targets_hash"]
    planned = [j_bytes(t["target"]) for t in targets]
    seen: set[bytes] = set()
    header_id = records[0]["self"]
    attempts = {r["seq"] for r in records if r["type"] == "attempt"}
    for result in (r for r in rest if r["type"] == "audit_result"):
        target = j_bytes(result["target"])
        if target in seen:
            return ["audit.result_unique"]
        seen.add(target)
        ref = result["attempt"]
        if (
            target not in planned
            or ref["journal"] != header_id
            or ref["seq"] not in attempts
            or ref["seq"] >= result["seq"]
        ):
            return ["audit.result_ref"]
    return []


# -- corpus helpers -----------------------------------------------------------------------------


def load_json_file(path: Path) -> Any:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def fixture_bytes(entry: dict[str, Any]) -> bytes:
    data = entry["data"]
    if "text" in data:
        return str(data["text"]).encode("utf-8")
    return base64.b64decode(data["base64"])


def open_store() -> SchemaStore:
    return SchemaStore(SCHEMAS)


def each(items: Iterable[Any], key: Callable[[Any], str]) -> list[tuple[str, Any]]:
    """Items with readable pytest identifiers."""
    return [(key(item), item) for item in items]
