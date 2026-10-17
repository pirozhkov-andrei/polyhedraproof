"""Record rules that need no other record (specification §4.6-§4.8; requirements matrix).

The functions take schema-valid JSON values (``check_record_schema`` passed) and return the
identifier of the first violated rule, or None. The order is the reference order
(requirements convention 10): ``record.formula`` (when V per formula is known),
``utc.calendar``, machinery and policy rules of header/resume, the cube of every node
(``cube.canonical``; ``cube.range`` here for the single node of split, attempt, node_stop and
node_reopen), then the rules of the record type, and last the ranges of shard, handoff and
audit target nodes.

Rules that need the bundles, admission or several records are not here: ``attempt.cnf_sha256``
and ``attempt.model_false`` (certifier), ``success.*`` (admitted VERIFIED_UNSAT; certifier and
binding), ``attempt.policy_sha256``, ``attempt.attempt_id``, ``handoff.request_unique``,
``shard.campaign`` and ``journal.*`` (journal reader).
"""

from __future__ import annotations

from collections.abc import Mapping
from itertools import pairwise
from typing import Any

from cubeproof.base.errors import ContractError
from cubeproof.contracts.assignment import decode_assignment
from cubeproof.contracts.documents import disjoint_sorted_nodes
from cubeproof.contracts.enums import REASONS, Outcome, RecordType
from cubeproof.contracts.identity import cube_problem, node_id
from cubeproof.contracts.policy import Policy
from cubeproof.contracts.primitives import utc_problem
from cubeproof.contracts.values import Node
from cubeproof.evidence.schema.spec import checked_sha256

#: process.tail_size: at most 16 KiB of decoded text per tail, counted as UTF-8 bytes. This
#: is a contract rule of the record (an integrity error), not an adjustable reader limit.
TAIL_BYTES = 16 * 1024

# Wire strings, not members: a str enum member hashes by its name, not by its value.
_SINGLE_NODE = frozenset(
    t.value
    for t in (RecordType.SPLIT, RecordType.ATTEMPT, RecordType.NODE_STOP, RecordType.NODE_REOPEN)
)


def machinery_problem(machinery: Mapping[str, Any]) -> str | None:
    """machinery.manifest_order, machinery.packages_sha256, machinery.cubeproof_sha256."""
    manifest = machinery["source_manifest"]
    if any(a["path"] >= b["path"] for a, b in pairwise(manifest)):
        return "machinery.manifest_order"
    if machinery["packages_sha256"] != checked_sha256(manifest):
        return "machinery.packages_sha256"
    own = [entry for entry in manifest if entry["path"].split("/", 1)[0] == "cubeproof"]
    if machinery["cubeproof_sha256"] != checked_sha256(own):
        return "machinery.cubeproof_sha256"
    return None


def policy_problem(policy: Mapping[str, Any]) -> str | None:
    """policy.stack, policy.stream_heap of a schema-valid policy."""
    try:
        Policy.from_json(dict(policy))
    except ContractError as error:
        return error.rule
    return None


def _utf8_length(text: str) -> int:
    return len(text.encode("utf-8", "surrogatepass"))


def process_problem(result: Mapping[str, Any]) -> str | None:
    """process.exit_signal, process.not_started, process.tail_size."""
    if result["exit"] is not None and result["signal"] is not None:
        return "process.exit_signal"
    if not result["started"] and (result["exit"] is not None or result["signal"] is not None):
        return "process.not_started"
    if any(_utf8_length(result[t]) > TAIL_BYTES for t in ("stdout_tail", "stderr_tail")):
        return "process.tail_size"
    return None


def _reason_ok(outcome: str, reason: Any, model_error: Any) -> bool:
    if outcome in (Outcome.VERIFIED_UNSAT, Outcome.MODEL):
        return reason is None
    if outcome == Outcome.INVALID_MODEL:
        return reason is not None and reason == model_error
    return reason in REASONS[Outcome(outcome)]


def _model_error_ok(outcome: str, model_error: Any, assignment: Any) -> bool:
    if outcome == Outcome.MODEL:
        return model_error is None and assignment is not None
    if outcome == Outcome.INVALID_MODEL:
        wants = model_error == "violated"
        return model_error is not None and (assignment is not None) == wants
    return model_error is None and assignment is None


def attempt_problem(  # noqa: PLR0911 - one early return per rule keeps the order visible
    attempt: Mapping[str, Any], variables: int | None = None
) -> str | None:
    """The specification §4.8 field rules of one attempt in matrix order.

    ``variables`` is V of the attempt's formula; None skips attempt.assignment's length rule.
    """
    outcome = attempt["outcome"]
    route, mode = attempt["route"], attempt["proof_mode"]
    solver, relay = attempt["solver"], attempt["relay"]
    proof_bytes, proof_sha256 = attempt["proof_bytes"], attempt["proof_sha256"]
    model_error, assignment = attempt["model_error"], attempt["assignment"]
    if not _reason_ok(outcome, attempt["reason"], model_error):
        return "attempt.reason"
    if (solver is None) != (route == "unit"):
        return "attempt.solver"
    if (relay is not None) != (mode == "stream" and route == "cdcl"):
        return "attempt.relay"
    if (proof_bytes is None) != (proof_sha256 is None):
        return "attempt.proof_pair"
    if relay is not None and proof_sha256 is not None:
        complete = relay["solver_eof"] and relay["all_written"] and relay["error"] is None
        same = relay["bytes"] == proof_bytes and relay["sha256"] == proof_sha256
        if not (complete and same):
            return "attempt.stream_proof"
    if outcome in (Outcome.MODEL, Outcome.INVALID_MODEL):
        bad_solver = route == "cdcl" and (solver is None or solver["exit"] != 10)
        if proof_bytes is not None or proof_sha256 is not None or attempt["checks"] or bad_solver:
            return "attempt.model_shape"
    if not _model_error_ok(outcome, model_error, assignment):
        return "attempt.model_error"
    if assignment is not None and variables is not None:
        try:
            decode_assignment(assignment, variables)
        except ContractError as error:
            return error.rule
    retained = attempt["retained"]
    if retained is not None and not (
        outcome == Outcome.VERIFIED_UNSAT
        and mode == "retain"
        and retained["sha256"] == proof_sha256
        and retained["bytes"] == proof_bytes
    ):
        return "attempt.retained"
    quarantined = attempt["quarantined"]
    if quarantined is not None and not (
        outcome == Outcome.CHECK_REJECTED and mode in ("transient", "retain")
    ):
        return "attempt.quarantined"
    results = ([solver] if solver is not None else []) + [c["result"] for c in attempt["checks"]]
    for result in results:
        problem = process_problem(result)
        if problem is not None:
            return problem
    return None


def record_nodes(kind: str, payload: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    """Every Node of a record (or payload) of type ``kind``, in field order."""
    if kind in _SINGLE_NODE:
        return [payload["node"]]
    if kind == RecordType.SHARD:
        return list(payload["shard"]["nodes"])
    if kind == RecordType.HANDOFF:
        shard = payload["shard"]
        return list(shard["nodes"]) if shard is not None else []
    if kind in (RecordType.AUDIT_TARGET, RecordType.AUDIT_RESULT):
        return [payload["target"]["node"]]
    return []


def _node_id_of(node: Mapping[str, Any]) -> str:
    return node_id(node["formula_sha256"], node["cube"])


def _shard_nodes_problem(shard: Mapping[str, Any]) -> str | None:
    nodes = [Node(n["formula_sha256"], tuple(n["cube"])) for n in shard["nodes"]]
    return None if disjoint_sorted_nodes(nodes) else "shard.nodes"


def _type_problem(  # noqa: PLR0911 - one early return per rule keeps the order visible
    kind: str, payload: Mapping[str, Any], count: int | None
) -> str | None:
    if kind == RecordType.ATTEMPT:
        if payload["node_id"] != _node_id_of(payload["node"]):
            return "record.node_id"
        return attempt_problem(payload, count)
    if kind in (RecordType.AUDIT_TARGET, RecordType.AUDIT_RESULT):
        target = payload["target"]
        if target["node_id"] != _node_id_of(target["node"]):
            return "record.node_id"
        return machinery_problem(target["machinery"])
    if kind == RecordType.SHARD:
        problem = _shard_nodes_problem(payload["shard"])
        if problem is None and payload["shard_sha256"] != checked_sha256(payload["shard"]):
            problem = "shard.hash"
        return problem
    if kind == RecordType.HANDOFF:
        shard, digest = payload["shard"], payload["shard_sha256"]
        if (shard is None) != (digest is None):
            return "handoff.pair"
        if shard is None:
            return None
        problem = _shard_nodes_problem(shard)
        if problem is None and digest != checked_sha256(shard):
            problem = "shard.hash"
        if problem is None and len(shard["nodes"]) > payload["request"]["node_count"]:
            problem = "handoff.count"
        return problem
    return None


def payload_problem(
    kind: str, payload: Mapping[str, Any], variables: Mapping[str, int] | None = None
) -> str | None:
    """The record rules of a payload (with or without its envelope) of type ``kind``.

    ``variables`` maps formula hashes to V. Without it, cube ranges and the assignment length
    are not checked; with it, a node of a formula outside the mapping is ``record.formula``.
    """
    nodes = record_nodes(kind, payload)
    if variables is not None and any(n["formula_sha256"] not in variables for n in nodes):
        return "record.formula"
    return _rules(kind, payload, nodes, variables)


def _rules(
    kind: str,
    payload: Mapping[str, Any],
    nodes: list[Mapping[str, Any]],
    variables: Mapping[str, int] | None,
) -> str | None:
    if kind in (RecordType.HEADER, RecordType.RESUME):
        problem = machinery_problem(payload["machinery"]) or policy_problem(payload["policy"])
        if problem is not None:
            return problem
    single = kind in _SINGLE_NODE
    count: int | None = None
    if single and variables is not None:
        count = variables[nodes[0]["formula_sha256"]]
    for node in nodes:
        problem = cube_problem(node["cube"], count if single else None)
        if problem is not None:
            return problem
    problem = _type_problem(kind, payload, count)
    if problem is not None or single or variables is None:
        return problem
    for node in nodes:
        problem = cube_problem(node["cube"], variables[node["formula_sha256"]])
        if problem is not None:
            return problem
    return None


def record_problem(
    record: Mapping[str, Any], variables: Mapping[str, int] | None = None
) -> str | None:
    """The first record rule a schema-valid record violates, or None (see module doc)."""
    kind = record["type"]
    nodes = record_nodes(kind, record)
    if variables is not None and any(n["formula_sha256"] not in variables for n in nodes):
        return "record.formula"
    if utc_problem(record["utc"]) is not None:
        return "utc.calendar"
    return _rules(kind, record, nodes, variables)
