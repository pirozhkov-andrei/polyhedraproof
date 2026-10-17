"""Test-only helpers of the scheduler tests: journal records, campaign views, plain-text oracles.

Records are built as plain JSON from the frozen corpus templates (header and attempt of
``journals/base/w1.jsonl``), chained with ``hashlib``/``json`` and then turned into typed
records by the package's own :func:`~cubeproof.evidence.schema.check_record` (schema, self and
record rules), so every record the replay sees is one the journal reader would accept. J, node
and split IDs are transcribed from specification §3.2 and §4.1 without importing the code under
test.
Nothing here is imported by runtime code.
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import json
from collections.abc import Iterator, Mapping, Sequence
from pathlib import Path
from typing import Any

from cubeproof.contracts.campaign import Admit
from cubeproof.coordinator.state import CampaignView
from cubeproof.evidence.schema import Record, check_record

REPO = Path(__file__).resolve().parents[4]
CORPUS = REPO / "tests" / "contracts" / "corpus"
ZERO = "0" * 64
SUCCESS_LINE = "s VERIFIED UNSAT\n"

Cube = tuple[int, ...]
Key = tuple[str, Cube]


def j(value: Any) -> bytes:
    """J(x) of specification §4.1."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def node_id(formula: str, cube: Sequence[int]) -> str:
    return sha(b"node\0" + formula.encode() + b"\0" + " ".join(map(str, cube)).encode())


def split_id(formula: str, cube: Sequence[int], variables: Sequence[int]) -> str:
    return sha(j({"node_id": node_id(formula, cube), "variables": list(variables)}))


def children(cube: Sequence[int], variables: Sequence[int]) -> list[Cube]:
    """Specification §3.2: child t assigns +W[j] when bit j of t is 1; then canonical order."""
    found = []
    for index in range(1 << len(variables)):
        signed = [v if index >> b & 1 else -v for b, v in enumerate(variables)]
        found.append(tuple(sorted([*cube, *signed], key=abs)))
    return found


def formula_bytes(variables: int, clauses: Sequence[Sequence[int]] = ((1, 2),)) -> bytes:
    lines = [f"p cnf {variables} {len(clauses)}"]
    lines += [" ".join(map(str, c)) + " 0" if c else " 0" for c in clauses]
    return ("\n".join(lines) + "\n").encode()


def load_lines(relative: str) -> list[dict[str, Any]]:
    data = (CORPUS / relative).read_bytes().split(b"\n")[:-1]
    return [json.loads(line) for line in data]


_BASE = load_lines("journals/base/w1.jsonl")
_HEADER = _BASE[0]
_ATTEMPT = _BASE[2]
MACHINERY: dict[str, Any] = _HEADER["machinery"]
POLICY: dict[str, Any] = _HEADER["policy"]
RESOURCES: dict[str, Any] = _HEADER["resources"]
CHECKER = MACHINERY["checker"]["sha256"]
SOLVER = MACHINERY["solver"]["sha256"]
CAMPAIGN_ID = "c19" + "0" * 61
OTHER_HASH = "ab" * 32


def utc(seq: int) -> str:
    start = datetime.datetime(2026, 10, 1, tzinfo=datetime.timezone.utc)
    return (start + datetime.timedelta(seconds=seq)).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def machinery(*, checker: str = CHECKER) -> dict[str, Any]:
    value: dict[str, Any] = json.loads(j(MACHINERY))
    value["checker"]["sha256"] = checker
    return value


def policy(**changes: Any) -> dict[str, Any]:
    value: dict[str, Any] = json.loads(j(POLICY))
    value.update(changes)
    return value


def checked(exit_code: int = 0, tail: str = SUCCESS_LINE) -> dict[str, Any]:
    result = dict(_ATTEMPT["checks"][0]["result"])
    result.update(exit=exit_code, stdout_tail=tail, stdout_bytes=len(tail.encode()))
    return {"heap_mib": 512, "result": result, "stack_mib": 256}


def solver_result(exit_code: int = 20) -> dict[str, Any]:
    result = dict(_ATTEMPT["solver"])
    tail = {20: "s UNSATISFIABLE\n", 10: "s SATISFIABLE\n"}.get(exit_code, "")
    result.update(exit=exit_code, stdout_tail=tail, stdout_bytes=len(tail))
    return result


def assignment(variables: int) -> str:
    return base64.b64encode(bytes((variables + 7) // 8)).decode()


class Journal:
    """The records of one journal over named formulas (plain JSON, then typed records)."""

    def __init__(
        self,
        formulas: Mapping[str, bytes],
        *,
        worker: str = "w1",
        policy_value: Mapping[str, Any] | None = None,
        machinery_value: Mapping[str, Any] | None = None,
        campaign: str = CAMPAIGN_ID,
        checker: str = CHECKER,
        header: bool = True,
    ) -> None:
        self.formulas = dict(formulas)
        self.hashes = {k: sha(v) for k, v in formulas.items()}
        self.counts = {
            self.hashes[k]: int(v.split(b"\n", 1)[0].split(b" ")[2]) for k, v in formulas.items()
        }
        self.worker = worker
        self.campaign = campaign
        self.checker = checker
        self.policy_value = dict(policy_value) if policy_value is not None else POLICY
        self.machinery_value = (
            dict(machinery_value) if machinery_value is not None else machinery(checker=checker)
        )
        self.values: list[dict[str, Any]] = []
        self.records: list[Record] = []
        self._ids = 0
        if header:
            self.header()

    # -- plumbing --------------------------------------------------------------------------

    def append(self, payload: Mapping[str, Any]) -> int:
        value = dict(payload)
        seq = len(self.values)
        value.update(format="cubeproof-journal-1", seq=seq, utc=utc(seq))
        value["prev"] = self.values[-1]["self"] if self.values else ZERO
        value.pop("self", None)
        value["self"] = sha(j(value))
        record = check_record(json.loads(j(value)), variables=self.counts)
        self.values.append(value)
        self.records.append(record)
        return seq

    @property
    def view(self) -> CampaignView:
        return CampaignView(
            campaign_id=self.campaign,
            admit=Admit((self.checker,), None),
            variables=dict(self.counts),
        )

    def sha(self, name: str) -> str:
        return self.hashes[name]

    def key(self, name: str, cube: Sequence[int] = ()) -> Key:
        return (self.hashes[name], tuple(cube))

    def node(self, name: str, cube: Sequence[int]) -> dict[str, Any]:
        return {"formula_sha256": self.hashes[name], "cube": list(cube)}

    # -- records ---------------------------------------------------------------------------

    def header(self) -> int:
        return self.append(
            {
                "type": "header",
                "worker": self.worker,
                "campaign": self.campaign,
                "purpose": "run",
                "machinery": self.machinery_value,
                "policy": self.policy_value,
                "resources": RESOURCES,
            }
        )

    def resume(
        self, *, policy_value: Mapping[str, Any] | None = None, checker: str | None = None
    ) -> int:
        if policy_value is not None:
            self.policy_value = dict(policy_value)
        if checker is not None:
            self.machinery_value = machinery(checker=checker)
        return self.append(
            {
                "type": "resume",
                "machinery": self.machinery_value,
                "policy": self.policy_value,
                "resources": RESOURCES,
            }
        )

    def _entries(self, nodes: Sequence[tuple[str, Sequence[int]]]) -> list[dict[str, Any]]:
        entries: list[dict[str, Any]] = [
            {"formula_sha256": self.hashes[f], "cube": list(c)} for f, c in nodes
        ]
        entries.sort(key=lambda n: (n["formula_sha256"], node_id(n["formula_sha256"], n["cube"])))
        return entries

    def _shard(self, nodes: Sequence[tuple[str, Sequence[int]]], name: str) -> dict[str, Any]:
        return {
            "format": "cubeproof-shard-1",
            "campaign": self.campaign,
            "name": name,
            "nodes": self._entries(nodes),
        }

    def shard(self, nodes: Sequence[tuple[str, Sequence[int]]], name: str = "s1") -> int:
        shard = self._shard(nodes, name)
        return self.append({"type": "shard", "shard": shard, "shard_sha256": sha(j(shard))})

    def handoff(
        self, nodes: Sequence[tuple[str, Sequence[int]]], request: str = "1", name: str = "out"
    ) -> int:
        shard = self._shard(nodes, name)
        count = len(nodes)
        req = {
            "format": "cubeproof-handoff-request-1",
            "campaign": self.campaign,
            "request_id": request.rjust(32, "0"),
            "node_count": max(1, count),
            "output_name": name,
        }
        return self.append(
            {
                "type": "handoff",
                "request": req,
                "shard": shard if count else None,
                "shard_sha256": sha(j(shard)) if count else None,
            }
        )

    def split(self, name: str, cube: Sequence[int], variables: Sequence[int]) -> int:
        return self.append(
            {
                "type": "split",
                "node": self.node(name, cube),
                "variables": list(variables),
                "splitter": {"name": "lookahead-v1", "info": {}},
            }
        )

    def attempt(self, name: str, cube: Sequence[int], **fields: Any) -> int:
        formula = self.hashes[name]
        self._ids += 1
        record = json.loads(j(_ATTEMPT))
        for field in ("format", "seq", "prev", "self", "utc"):
            record.pop(field)
        record.update(
            node=self.node(name, cube),
            node_id=node_id(formula, cube),
            attempt_id=f"{self._ids:032x}",
            policy_sha256=sha(j(self.policy_value)),
            cnf_sha256=sha(f"cnf {formula} {list(cube)}".encode()),
            proof_mode=self.policy_value["proof_mode"],
            proof_sha256=sha(f"proof {formula} {list(cube)} {self._ids}".encode()),
            diagnostics={},
        )
        record.update(fields)
        return self.append(record)

    def unsat(self, name: str, cube: Sequence[int], *, route: str = "cdcl", **fields: Any) -> int:
        extra: dict[str, Any] = {
            "route": route,
            "solver": solver_result() if route == "cdcl" else None,
        }
        extra.update(fields)
        return self.attempt(name, cube, **extra)

    def model(self, name: str, cube: Sequence[int], *, outcome: str = "MODEL") -> int:
        error = None if outcome == "MODEL" else "violated"
        return self.attempt(
            name,
            cube,
            outcome=outcome,
            reason=error,
            model_error=error,
            assignment=assignment(self.counts[self.hashes[name]]),
            route="cdcl",
            solver=solver_result(10),
            checks=[],
            proof_bytes=None,
            proof_sha256=None,
        )

    def failed(
        self, name: str, cube: Sequence[int], outcome: str, reason: str, **extra: Any
    ) -> int:
        """EXHAUSTED, TOOL_FAILED or CHECK_REJECTED (a rejected complete proof)."""
        fields: dict[str, Any] = {"outcome": outcome, "reason": reason}
        if outcome == "CHECK_REJECTED":
            fields["checks"] = [checked(1, "s VERIFICATION FAILED\n")]
        else:
            fields.update(checks=[], proof_bytes=None, proof_sha256=None)
        fields.update(extra)
        return self.attempt(name, cube, **fields)

    def stop(self, name: str, cube: Sequence[int], state: str, reason: str = "r") -> int:
        return self.append(
            {
                "type": "node_stop",
                "node": self.node(name, cube),
                "state": state,
                "reason": reason,
                "policy_sha256": sha(j(self.policy_value)),
            }
        )

    def reopen(self, name: str, cube: Sequence[int], reason: str = "reopen") -> int:
        return self.append(
            {
                "type": "node_reopen",
                "node": self.node(name, cube),
                "reason": reason,
                "policy_sha256": sha(j(self.policy_value)),
            }
        )

    # -- convenience -------------------------------------------------------------------------

    def prefix(self, count: int) -> list[Record]:
        return self.records[:count]

    def __iter__(self) -> Iterator[Record]:
        return iter(self.records)
