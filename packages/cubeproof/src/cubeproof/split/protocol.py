"""The helper protocol: ``cubeproof-look-request-1`` and ``cubeproof-look-result-1`` (specification
§9.3).

``cubeproof-look REQUEST_FILE`` reads one request document and writes one result document to
stdout; both are canonical J documents (J plus one LF). A supervised process has no stdin, so
the request travels in a file. Exit 0 requires a valid result; every other exit, a signal, a
deadline or an invalid result is a helper failure (operational, never a proof verdict).

Request ``{cube, format, formula_path, formula_sha256, k, pool, probe_limit, wall_ms}``:
the formula path is an absolute path of the canonical ``formula.cnf`` whose SHA-256 the helper
verifies; ``cube`` is canonical; ``k`` is 1..K_MAX; ``pool`` is a sorted list of variables or
null; ``probe_limit`` is a positive integer; ``wall_ms`` is a positive integer or null.

Result ``{format, info, node_id, status, variables}``: ``node_id`` is the identity the helper
computed for the formula and cube (it must equal the caller's), ``status``/``variables`` are
the SplitChoice fields and ``info`` is the lookahead-v1 info object of
:mod:`cubeproof.split.lookahead`. :func:`parse_result` validates all of it, including that no
variable lies in the cube or outside the pool and that the probes stay within the limit.
Stdout carries nothing else; diagnostics go to a bounded stderr.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from cubeproof.base.canonical_json import document_bytes, parse_document
from cubeproof.base.errors import CubeproofError, ToolError
from cubeproof.contracts.identity import check_cube
from cubeproof.contracts.primitives import is_hash
from cubeproof.split.choice import (
    BUDGET,
    CHOSEN,
    FAILED,
    NO_ELIGIBLE,
    PARENT_CONFLICT,
    STATUSES,
    SplitChoice,
    check_k,
    check_pool,
)
from cubeproof.split.lookahead import ALGORITHM

REQUEST_FORMAT = "cubeproof-look-request-1"
RESULT_FORMAT = "cubeproof-look-result-1"

INFO_KEYS = frozenset(
    {"algorithm", "candidates", "parent_assigned", "probes", "rounds", "scores", "stop"}
)
STOPS = frozenset({"k", "candidates", "probe_limit", "wall_ms", PARENT_CONFLICT})
_STATUS_STOPS = {
    CHOSEN: frozenset({"k", "candidates", "probe_limit", "wall_ms"}),
    NO_ELIGIBLE: frozenset({"candidates"}),
    BUDGET: frozenset({"probe_limit", "wall_ms"}),
    FAILED: frozenset({PARENT_CONFLICT}),
}
_RULE = "split.helper_protocol"


def _bad(detail: str) -> ToolError:
    return ToolError(_RULE, detail)


def request_document(
    *,
    formula_path: str,
    formula_sha256: str,
    variables: int,
    cube: Sequence[int],
    k: int,
    pool: Sequence[int] | None,
    probe_limit: int,
    wall_ms: int | None,
) -> bytes:
    """The request document (J plus LF) for the arguments, validated like the helper does."""
    if (
        not isinstance(formula_path, str)
        or not formula_path.startswith("/")
        or "\0" in formula_path
    ):
        raise ValueError("formula_path must be an absolute path")
    if not is_hash(formula_sha256):
        raise ValueError("formula_sha256 must be a Hash")
    members = check_pool(pool, variables)
    check_k(k)
    for name, value in (("probe_limit", probe_limit), ("wall_ms", wall_ms)):
        if value is None and name == "wall_ms":
            continue
        if type(value) is not int or not 1 <= value < 2**63:
            raise ValueError(f"{name} must be a positive integer")
    return document_bytes(
        {
            "format": REQUEST_FORMAT,
            "formula_path": formula_path,
            "formula_sha256": formula_sha256,
            "cube": list(check_cube(cube, variables)),
            "k": k,
            "pool": None if members is None else list(members),
            "probe_limit": probe_limit,
            "wall_ms": wall_ms,
        }
    )


def result_document(node: str, choice: SplitChoice) -> bytes:
    """The result document (J plus LF) of ``choice`` at node ``node``.

    This is what the helper writes; the Python reference's choices encode to the same bytes,
    which is how the two implementations are compared.
    """
    if not is_hash(node):
        raise ValueError("node must be a node identity")
    return document_bytes(
        {
            "format": RESULT_FORMAT,
            "node_id": node,
            "status": choice.status,
            "variables": list(choice.variables),
            "info": choice.info.to_json(),
        }
    )


def _count(value: Any, name: str, upper: int | None = None) -> int:
    if type(value) is not int or value < 0 or (upper is not None and value > upper):
        raise _bad(f"info.{name} is not a valid count: {value!r}")
    return value


def parse_result(
    data: bytes,
    *,
    node: str,
    variables: int,
    cube: Sequence[int],
    k: int,
    pool: Sequence[int] | None,
    probe_limit: int,
    wall_ms: int | None,
) -> SplitChoice:
    """Validate a result document against the request; :class:`ToolError` on any defect."""
    try:
        value = parse_document(data)
    except CubeproofError as error:
        raise _bad(f"result is not a canonical document: {error}") from None
    if not isinstance(value, dict) or set(value) != {
        "format",
        "info",
        "node_id",
        "status",
        "variables",
    }:
        raise _bad("result is not an object with exactly format, info, node_id, status, variables")
    if value["format"] != RESULT_FORMAT:
        raise _bad(f"result format {value['format']!r}")
    if value["node_id"] != node:
        raise _bad("the helper computed another node identity")
    status = value["status"]
    if status not in STATUSES:
        raise _bad(f"unknown status {status!r}")
    chosen = value["variables"]
    if not isinstance(chosen, list) or any(type(v) is not int for v in chosen):
        raise _bad("variables is not a list of integers")
    if len(chosen) > k:
        raise _bad(f"{len(chosen)} variables for k = {k}")
    taken = {abs(x) for x in cube}
    members = None if pool is None else set(pool)
    for variable in chosen:
        if not 1 <= variable <= variables or variable in taken:
            raise _bad(f"variable {variable} is out of range or assigned by the cube")
        if members is not None and variable not in members:
            raise _bad(f"variable {variable} is not in the pool")
    info = value["info"]
    if not isinstance(info, dict) or set(info) != INFO_KEYS:
        raise _bad("info does not have exactly the lookahead-v1 keys")
    if info["algorithm"] != ALGORITHM:
        raise _bad(f"info.algorithm {info['algorithm']!r}")
    stop = info["stop"]
    if stop not in STOPS or stop not in _STATUS_STOPS[status]:
        raise _bad(f"stop {stop!r} does not fit status {status!r}")
    if stop == "wall_ms" and wall_ms is None:
        raise _bad("stop wall_ms without a wall budget")
    if stop == "k" and len(chosen) != k:
        raise _bad("stop k with fewer than k variables")
    if stop == "candidates" and status == CHOSEN and len(chosen) >= k:
        raise _bad("candidates ran out although k variables were chosen")
    _count(info["probes"], "probes", probe_limit)
    _count(info["candidates"], "candidates", variables)
    _count(info["parent_assigned"], "parent_assigned", variables)
    rounds = _count(info["rounds"], "rounds", k)
    scores = info["scores"]
    if rounds != len(chosen) or not isinstance(scores, list) or len(scores) != rounds:
        raise _bad("rounds, scores and variables disagree")
    if any(type(s) is not int or s < 0 for s in scores):
        raise _bad("scores are not nonnegative integers")
    if info["candidates"] < len(chosen):
        raise _bad("fewer candidates than chosen variables")
    try:
        return SplitChoice.make(chosen, status, info)
    except CubeproofError as error:
        raise _bad(f"not a split choice: {error}") from None
