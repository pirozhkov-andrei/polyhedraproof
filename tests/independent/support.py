"""Shared helpers of the independent certifier tests.

The tests use only the standard library. ``tools/certify_min.py`` is loaded from its path, so
no package installation is needed. The helpers here build evidence for synthetic scenarios with
the plain constructions of specification §3.1-§3.2 and §7.1 (no code of the tool under test),
so that they are an oracle independent of the implementation.
"""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import shutil
import sys
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[2]
TOOL = REPO / "tools" / "certify_min.py"
CORPUS = REPO / "tests" / "contracts" / "corpus"
ZERO = "0" * 64


def load_tool() -> Any:
    """Import tools/certify_min.py as a module (it is a script, not a package)."""
    if "certify_min" in sys.modules:
        return sys.modules["certify_min"]
    spec = importlib.util.spec_from_file_location("certify_min", TOOL)
    if spec is None or spec.loader is None:
        raise ImportError(str(TOOL))
    module = importlib.util.module_from_spec(spec)
    sys.modules["certify_min"] = module
    spec.loader.exec_module(module)
    return module


def j(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def corpus_json(relative: str) -> Any:
    return json.loads((CORPUS / relative).read_bytes())


def node_id(formula: str, cube: list[int]) -> str:
    text = "node\0" + formula + "\0" + " ".join(str(x) for x in cube)
    return sha(text.encode("ascii"))


def split_id(node: str, variables: list[int]) -> str:
    return sha(j({"node_id": node, "variables": variables}))


def cnf_text(formula_text: bytes, cube: list[int]) -> bytes:
    header, body = formula_text.split(b"\n", 1)
    _, _, v, m = header.split(b" ")
    head = b"p cnf %d %d\n" % (int(v), int(m) + len(cube))
    return head + body + b"".join(b"%d 0\n" % x for x in cube)


def assignment(true_vars: list[int], variables: int) -> str:
    raw = bytearray((variables + 7) // 8)
    for v in true_vars:
        raw[(v - 1) // 8] |= 1 << ((v - 1) % 8)
    return base64.b64encode(bytes(raw)).decode("ascii")


def leaf(node: str, cnf: str, proof: str) -> str:
    return sha(f"leaf\0{node}\0{cnf}\0{proof}".encode("ascii"))


def merkle(leaves: list[tuple[str, str, str]]) -> str | None:
    level = [leaf(*x) for x in sorted(leaves)]
    if not level:
        return None
    while len(level) > 1:
        nxt = [
            sha(f"branch\0{level[i]}\0{level[i + 1]}".encode("ascii"))
            for i in range(0, len(level) - 1, 2)
        ]
        if len(level) % 2:
            nxt.append(level[-1])
        level = nxt
    return level[0]


def write_document(path: Path, value: Any) -> str:
    """Write J(value)+LF; return the document hash (without the LF)."""
    data = j(value)
    path.write_bytes(data + b"\n")
    return sha(data)


class JournalWriter:
    """Builds a self-chained journal (specification §7.1) from record payloads."""

    def __init__(self) -> None:
        self.records: list[dict[str, Any]] = []

    def add(self, record: dict[str, Any]) -> dict[str, Any]:
        record = dict(record)
        record.pop("self", None)
        record["format"] = "cubeproof-journal-1"
        record["seq"] = len(self.records)
        record["prev"] = self.records[-1]["self"] if self.records else ZERO
        record["self"] = sha(j(record))
        self.records.append(record)
        return record

    @property
    def id(self) -> str:
        return str(self.records[0]["self"])

    def data(self) -> bytes:
        return b"".join(j(r) + b"\n" for r in self.records)

    def write(self, path: Path) -> Path:
        path.write_bytes(self.data())
        return path


class Scenario:
    """A temporary copy of a corpus campaign with editable campaign and journals."""

    def __init__(self, root: Path, campaign_dir: str = "all3") -> None:
        self.root = root
        shutil.copytree(CORPUS / "campaigns" / campaign_dir, root / "campaign")
        self.campaign_path = root / "campaign" / "campaign.json"
        self.campaign: dict[str, Any] = json.loads(self.campaign_path.read_bytes())
        self.formula_text: dict[str, bytes] = {}
        for entry in self.campaign["formulas"]:
            text = (root / "campaign" / entry["bundle"] / "formula.cnf").read_bytes()
            self.formula_text[entry["formula_sha256"]] = text
        self.template = [
            json.loads(line)
            for line in (CORPUS / "journals" / "base" / "w1.jsonl").read_bytes().splitlines()
        ]
        self.counter = 0

    @property
    def formula(self) -> str:
        return str(self.campaign["formulas"][0]["formula_sha256"])

    def save_campaign(self) -> str:
        return write_document(self.campaign_path, self.campaign)

    def campaign_id(self) -> str:
        return sha(j(self.campaign))

    def header(self, worker: str = "w1", purpose: str = "run") -> dict[str, Any]:
        header = dict(self.template[0])
        header.update(worker=worker, campaign=self.campaign_id(), purpose=purpose)
        return header

    def policy_sha256(self) -> str:
        return sha(j(self.template[0]["policy"]))

    def split(self, cube: list[int], variables: list[int], formula: str | None = None) -> dict:
        record = dict(self.template[1])
        record["node"] = {"formula_sha256": formula or self.formula, "cube": cube}
        record["variables"] = variables
        return record

    def verified(self, cube: list[int], formula: str | None = None, proof: str | None = None):
        formula = formula or self.formula
        record = dict(self.template[2])
        self.counter += 1
        record["node"] = {"formula_sha256": formula, "cube": cube}
        record["node_id"] = node_id(formula, cube)
        record["attempt_id"] = f"{self.counter:032x}"
        record["cnf_sha256"] = sha(cnf_text(self.formula_text[formula], cube))
        record["proof_sha256"] = proof or sha(b"proof %d" % self.counter)
        record["policy_sha256"] = self.policy_sha256()
        return record

    def model(
        self,
        cube: list[int],
        true_vars: list[int],
        outcome: str = "MODEL",
        formula: str | None = None,
        model_error: str | None = None,
    ) -> dict:
        record = self.verified(cube, formula)
        variables = int(self.formula_text[record["node"]["formula_sha256"]].split(b" ")[2])
        record.update(
            outcome=outcome,
            reason=model_error,
            model_error=model_error,
            assignment=assignment(true_vars, variables),
            proof_bytes=None,
            proof_sha256=None,
            checks=[],
        )
        solver = dict(record["solver"] or self.template[3]["solver"] or {})
        if record["route"] == "cdcl":
            solver.update(exit=10, stdout_tail="s SATISFIABLE\n", stdout_bytes=14)
            record["solver"] = solver
        return record

    def stop(self, cube: list[int], state: str, reason: str) -> dict[str, Any]:
        return {
            "type": "node_stop",
            "utc": "2026-10-01T00:00:09.000Z",
            "node": {"formula_sha256": self.formula, "cube": cube},
            "state": state,
            "reason": reason,
            "policy_sha256": self.policy_sha256(),
        }

    def journal(self, name: str, records: list[dict[str, Any]], worker: str = "w1") -> Path:
        writer = JournalWriter()
        writer.add(self.header(worker))
        for record in records:
            writer.add(record)
        return writer.write(self.root / name)
