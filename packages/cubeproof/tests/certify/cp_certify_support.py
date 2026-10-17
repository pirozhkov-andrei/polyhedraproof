"""Test-only helpers of the certifier tests: corpus access, scenario builder, oracles.

The frozen contract corpus (``tests/contracts/corpus``) and schemas are the expected values of
the corpus tests; the schema validator and ``certificate_problems`` of the reference reader
(``tests/contracts``) are independent checks of every produced certificate. Scenarios are
written here with plain ``hashlib``/``json`` (J, node and split IDs, CNF bytes, assignments,
Merkle roots are transcribed from specification §3.2, §4.8 and §10.5 without importing the
certifier). The naive recursive oracle reads specification §10.2-§10.3 literally for small
graphs; brute force over all assignments is the ground truth of the "truthful evidence" tests.
Nothing here is imported by runtime code.
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import itertools
import json
import sys
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[4]
CORPUS = REPO / "tests" / "contracts" / "corpus"
SCHEMAS = REPO / "schemas" / "cubeproof" / "v1"
CONTRACT_TESTS = REPO / "tests" / "contracts"
ZERO = "0" * 64
SUCCESS_LINE = "s VERIFIED UNSAT\n"

Cube = tuple[int, ...]
Key = tuple[str, Cube]
RefKey = tuple[str, int]


# -- primitives, transcribed from the specification ---------------------------------------------


def j(value: Any) -> bytes:
    """J(x) of specification §4.1."""
    text = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return text.encode("utf-8")


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def node_id(formula: str, cube: Sequence[int]) -> str:
    """Specification §3.2: SHA256("node" NUL formula NUL literals)."""
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


def cnf_bytes(formula: bytes, cube: Sequence[int]) -> bytes:
    """Specification §3.2: CNF(F, C) built in the plain way (the test oracle of cnf_sha256)."""
    header, _, body = formula.partition(b"\n")
    _, _, variables, clauses = header.split(b" ")
    units = "".join(f"{x} 0\n" for x in cube).encode()
    return f"p cnf {int(variables)} {int(clauses) + len(cube)}\n".encode() + body + units


def assignment(values: Sequence[bool]) -> str:
    """Specification §4.8 bitset: variable i is bit (i-1)%8 of byte (i-1)//8."""
    raw = bytearray((len(values) + 7) // 8)
    for index, value in enumerate(values):
        if value:
            raw[index // 8] |= 1 << index % 8
    return base64.b64encode(bytes(raw)).decode()


def merkle(leaves: Iterable[tuple[str, str, str]]) -> str | None:
    """The specification §10.5 Merkle root over (node_id, cnf_sha256, proof_sha256), by node_id."""
    level = [sha("\0".join(("leaf", *leaf)).encode()) for leaf in sorted(leaves)]
    if not level:
        return None
    while len(level) > 1:
        nxt = [
            sha("\0".join(("branch", level[i], level[i + 1])).encode())
            for i in range(0, len(level) - 1, 2)
        ]
        if len(level) % 2:
            nxt.append(level[-1])
        level = nxt
    return level[0]


def clauses_of(formula: bytes) -> list[list[int]]:
    lines = formula.decode().split("\n")[1:-1]
    return [[int(x) for x in line.split(" ")[:-1] if x] for line in lines]


def variables_of(formula: bytes) -> int:
    return int(formula.split(b"\n", 1)[0].split(b" ")[2])


def satisfying(formula: bytes, cube: Sequence[int] = ()) -> list[tuple[bool, ...]]:
    """Every assignment of F that satisfies all clauses and the cube (brute force)."""
    count = variables_of(formula)
    clauses = clauses_of(formula)
    found = []
    for values in itertools.product((False, True), repeat=count):
        if all(values[abs(x) - 1] == (x > 0) for x in cube) and all(
            any(values[abs(x) - 1] == (x > 0) for x in clause) for clause in clauses
        ):
            found.append(values)
    return found


def within(values: Sequence[bool], cube: Sequence[int]) -> bool:
    return all(values[abs(x) - 1] == (x > 0) for x in cube)


def dimacs(variables: int, clauses: Sequence[Sequence[int]]) -> bytes:
    lines = [f"p cnf {variables} {len(clauses)}"]
    lines += [" ".join(map(str, c)) + " 0" if c else " 0" for c in clauses]
    return ("\n".join(lines) + "\n").encode()


# -- corpus ----------------------------------------------------------------------------------------


def load_json(path: Path) -> Any:
    return json.loads(path.read_bytes())


def cases() -> list[dict[str, Any]]:
    data = load_json(CORPUS / "cases.json")
    assert data["format"] == "cubeproof-contract-cases-1"
    entries: list[dict[str, Any]] = data["cases"]
    return entries


def audit_plans() -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = load_json(CORPUS / "cases.json")["audit_plans"]
    return entries


def corpus_records(relative: str) -> list[dict[str, Any]]:
    lines = (CORPUS / relative).read_bytes().split(b"\n")[:-1]
    return [json.loads(line) for line in lines]


def _contract_module(name: str) -> Any:
    if str(CONTRACT_TESTS) not in sys.path:
        sys.path.insert(0, str(CONTRACT_TESTS))
    return __import__(name)


def schema_errors(certificate: Mapping[str, Any]) -> list[str]:
    """Errors of the contract schema validator for a certificate (independent oracle)."""
    store = _contract_module("contract_schema").SchemaStore(SCHEMAS)
    errors: list[str] = store.errors(dict(certificate), "certificate.schema.json")
    return errors


def certificate_problems(certificate: Mapping[str, Any]) -> list[str]:
    """certificate.order/certificate.summary of the contract reference reader."""
    problems: list[str] = _contract_module("contract_reader").certificate_problems(
        dict(certificate)
    )
    return problems


# -- scenarios -------------------------------------------------------------------------------------

_HEADER = corpus_records("journals/base/w1.jsonl")[0]
_ATTEMPT = corpus_records("journals/base/w1.jsonl")[2]
_CAMPAIGN = load_json(CORPUS / "campaigns/all3/campaign.json")

MACHINERY: dict[str, Any] = _HEADER["machinery"]
POLICY: dict[str, Any] = _HEADER["policy"]
RESOURCES: dict[str, Any] = _HEADER["resources"]
CHECKER = MACHINERY["checker"]["sha256"]
SOLVER = MACHINERY["solver"]["sha256"]
OTHER_HASH = "ab" * 32


def machinery(*, checker: str = CHECKER, solver_argv: Sequence[str] = ("--lrat",)) -> Any:
    """The template machinery with another checker hash or solver argv (still valid)."""
    value = json.loads(j(MACHINERY))
    value["checker"]["sha256"] = checker
    value["solver"]["argv"] = list(solver_argv)
    return value


def utc(seq: int) -> str:
    start = datetime.datetime(2026, 10, 1, tzinfo=datetime.timezone.utc)
    moment = start + datetime.timedelta(seconds=seq)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.000Z")


def checked(exit_code: int = 0, tail: str = SUCCESS_LINE) -> dict[str, Any]:
    result = dict(_ATTEMPT["checks"][0]["result"])
    result.update(exit=exit_code, stdout_tail=tail, stdout_bytes=len(tail.encode()))
    return {"heap_mib": 512, "result": result, "stack_mib": 256}


def solver_result(exit_code: int = 20) -> dict[str, Any]:
    result = dict(_ATTEMPT["solver"])
    tail = {20: "s UNSATISFIABLE\n", 10: "s SATISFIABLE\n"}.get(exit_code, "")
    result.update(exit=exit_code, stdout_tail=tail, stdout_bytes=len(tail))
    return result


@dataclass
class Facts:
    """What a scenario wrote, for the naive oracle (only admitted evidence counts there)."""

    splits: dict[Key, dict[str, tuple[int, ...]]] = field(default_factory=dict)
    verified: dict[Key, list[tuple[RefKey, str, str, str]]] = field(default_factory=dict)
    models: set[Key] = field(default_factory=set)

    def add_split(self, key: Key, variables: Sequence[int]) -> None:
        self.splits.setdefault(key, {})[split_id(key[0], key[1], variables)] = tuple(variables)


class Scenario:
    """A campaign directory with bundles, written from formula bytes (plain JSON, no package)."""

    def __init__(
        self,
        root: Path,
        formulas: Mapping[str, bytes],
        *,
        roots: Sequence[tuple[str, Sequence[int]]] | None = None,
        root_splits: Sequence[tuple[str, Sequence[int], Sequence[int]]] = (),
        admit: Mapping[str, Any] | None = None,
        policy: Mapping[str, Any] | None = None,
    ) -> None:
        self.root = root
        self.formulas = dict(formulas)
        self.hashes = {key: sha(data) for key, data in formulas.items()}
        self.facts = Facts()
        root.mkdir(parents=True, exist_ok=True)
        entries = []
        for key in sorted(formulas):
            data = formulas[key]
            bundle = root / "bundles" / key
            bundle.mkdir(parents=True)
            (bundle / "formula.cnf").write_bytes(data)
            manifest = {
                "format": "cubeproof-bundle-1",
                "formula_sha256": sha(data),
                "variables": variables_of(data),
                "clauses": len(clauses_of(data)),
                "pools": {},
                "producer": {"name": "c15-tests", "version": "1", "parameters": {}},
                "side_files": [],
            }
            (bundle / "manifest.json").write_bytes(j(manifest) + b"\n")
            entries.append({"key": key, "formula_sha256": sha(data), "bundle": f"bundles/{key}"})
        wanted = roots if roots is not None else [(key, ()) for key in formulas]
        self.roots: list[Key] = [(self.hashes[k], tuple(c)) for k, c in wanted]
        nodes = sorted(self.roots, key=lambda r: (r[0], node_id(*r)))
        splits: list[dict[str, Any]] = []
        for key, cube, variables in root_splits:
            formula = self.hashes[key]
            self.facts.add_split((formula, tuple(cube)), variables)
            splits.append(
                {
                    "node": {"formula_sha256": formula, "cube": list(cube)},
                    "variables": list(variables),
                    "splitter": {"name": "static", "info": {}},
                }
            )
        splits.sort(
            key=lambda s: split_id(s["node"]["formula_sha256"], s["node"]["cube"], s["variables"])
        )
        campaign = dict(_CAMPAIGN)
        campaign.update(
            formulas=entries,
            roots=[{"formula_sha256": f, "cube": list(c)} for f, c in nodes],
            root_splits=splits,
            author="c15 tests",
        )
        if admit is not None:
            campaign["admit"] = dict(admit)
        if policy is not None:
            campaign["policy"] = dict(policy)
        self.campaign_bytes = j(campaign) + b"\n"
        self.campaign_id = sha(j(campaign))
        self.campaign_path = root / "campaign.json"
        self.campaign_path.write_bytes(self.campaign_bytes)
        self._journals = 0

    def sha(self, key: str) -> str:
        return self.hashes[key]

    def variables(self, key: str) -> int:
        return variables_of(self.formulas[key])

    def journal(self, worker: str, **options: Any) -> JournalBuilder:
        return JournalBuilder(self, worker, **options)

    def path(self, name: str) -> Path:
        return self.root / name


class JournalBuilder:
    """Records of one journal, chained with plain hashlib/json (specification §7.1)."""

    def __init__(
        self,
        scenario: Scenario,
        worker: str,
        *,
        purpose: str = "run",
        machinery: Mapping[str, Any] | None = None,
        policy: Mapping[str, Any] | None = None,
        campaign: str | None = None,
        admitted: bool = True,
    ) -> None:
        self.scenario = scenario
        self.records: list[dict[str, Any]] = []
        self.policy = dict(policy) if policy is not None else POLICY
        self.admitted = admitted
        self._ids = 0
        self.id = ""
        header = {
            "type": "header",
            "worker": worker,
            "campaign": campaign or scenario.campaign_id,
            "purpose": purpose,
            "machinery": dict(machinery) if machinery is not None else MACHINERY,
            "policy": self.policy,
            "resources": RESOURCES,
        }
        self.append(header)
        self.id = self.records[0]["self"]

    # records ------------------------------------------------------------------------------------

    def append(self, payload: Mapping[str, Any], *, rechain: bool = True) -> int:
        record = dict(payload)
        seq = len(self.records)
        record.update(format="cubeproof-journal-1", seq=seq, utc=utc(seq))
        record["prev"] = self.records[-1]["self"] if self.records else ZERO
        if rechain or "self" not in record:
            record.pop("self", None)
            record["self"] = sha(j(record))
        self.records.append(record)
        return seq

    def ref(self, seq: int) -> RefKey:
        return (self.id, seq)

    def resume(
        self, *, machinery: Mapping[str, Any] | None = None, policy: Mapping[str, Any] | None = None
    ) -> int:
        if policy is not None:
            self.policy = dict(policy)
        return self.append(
            {
                "type": "resume",
                "machinery": dict(machinery) if machinery is not None else MACHINERY,
                "policy": self.policy,
                "resources": RESOURCES,
            }
        )

    def key(self, formula: str, cube: Sequence[int]) -> Key:
        return (self.scenario.sha(formula), tuple(cube))

    def split(self, formula: str, cube: Sequence[int], variables: Sequence[int]) -> int:
        node = {"formula_sha256": self.scenario.sha(formula), "cube": list(cube)}
        return self.append(
            {
                "type": "split",
                "node": node,
                "variables": list(variables),
                "splitter": {"name": "lookahead-v1", "info": {}},
            }
        )

    def attempt(self, formula: str, cube: Sequence[int], **fields: Any) -> int:
        """An attempt record from the VERIFIED_UNSAT template with ``fields`` replaced."""
        sha_formula = self.scenario.sha(formula)
        self._ids += 1
        record = json.loads(j(_ATTEMPT))
        for name in ("format", "seq", "prev", "self", "utc"):
            record.pop(name)
        data = cnf_bytes(self.scenario.formulas[formula], cube)
        record.update(
            node={"formula_sha256": sha_formula, "cube": list(cube)},
            node_id=node_id(sha_formula, cube),
            attempt_id=f"{self._ids:032x}",
            policy_sha256=sha(j(self.policy)),
            cnf_sha256=sha(data),
            proof_mode=self.policy["proof_mode"],
            proof_sha256=sha(f"proof {sha_formula} {list(cube)} {self._ids}".encode()),
            diagnostics={},
        )
        record.update(fields)
        return self.append(record)

    def unsat(
        self, formula: str, cube: Sequence[int], *, route: str = "cdcl", **fields: Any
    ) -> int:
        """An admitted-looking VERIFIED_UNSAT (cdcl or unit) at ``cube``."""
        extra: dict[str, Any] = {
            "route": route,
            "solver": solver_result() if route == "cdcl" else None,
        }
        extra.update(fields)
        seq = self.attempt(formula, cube, **extra)
        record = self.records[seq]
        if self.admitted and record["outcome"] == "VERIFIED_UNSAT":
            key = self.key(formula, cube)
            leaf = (self.ref(seq), record["node_id"], record["cnf_sha256"], record["proof_sha256"])
            self.scenario.facts.verified.setdefault(key, []).append(leaf)
        return seq

    def model(
        self,
        formula: str,
        cube: Sequence[int],
        values: Sequence[bool],
        *,
        outcome: str = "MODEL",
        route: str = "cdcl",
    ) -> int:
        """A MODEL or INVALID_MODEL(violated) with the bitset of ``values``.

        The oracle learns the node as a model node when ``values`` really satisfies
        CNF(F, C) (brute force), whatever the label says (specification §10.4).
        """
        model_error = None if outcome == "MODEL" else "violated"
        seq = self.attempt(
            formula,
            cube,
            outcome=outcome,
            reason=model_error,
            model_error=model_error,
            assignment=assignment(values),
            route=route,
            solver=solver_result(10) if route == "cdcl" else None,
            checks=[],
            proof_bytes=None,
            proof_sha256=None,
        )
        if tuple(values) in satisfying(self.scenario.formulas[formula], cube):
            self.scenario.facts.models.add(self.key(formula, cube))
        return seq

    def parse_error(self, formula: str, cube: Sequence[int], model_error: str = "syntax") -> int:
        return self.attempt(
            formula,
            cube,
            outcome="INVALID_MODEL",
            reason=model_error,
            model_error=model_error,
            assignment=None,
            solver=solver_result(10),
            checks=[],
            proof_bytes=None,
            proof_sha256=None,
        )

    def failed(self, formula: str, cube: Sequence[int], outcome: str, reason: str) -> int:
        """EXHAUSTED, TOOL_FAILED or CHECK_REJECTED (a rejected complete proof)."""
        fields: dict[str, Any] = {"outcome": outcome, "reason": reason}
        if outcome == "CHECK_REJECTED":
            fields["checks"] = [checked(1, "s VERIFICATION FAILED\n")]
        else:
            fields.update(checks=[], proof_bytes=None, proof_sha256=None)
        return self.attempt(formula, cube, **fields)

    def stop(self, formula: str, cube: Sequence[int], state: str, reason: str) -> int:
        node = {"formula_sha256": self.scenario.sha(formula), "cube": list(cube)}
        payload = {"type": "node_stop", "node": node, "state": state, "reason": reason}
        return self.append(payload | {"policy_sha256": sha(j(self.policy))})

    def reopen(self, formula: str, cube: Sequence[int], reason: str = "reopen") -> int:
        node = {"formula_sha256": self.scenario.sha(formula), "cube": list(cube)}
        payload = {"type": "node_reopen", "node": node, "reason": reason}
        return self.append(payload | {"policy_sha256": sha(j(self.policy))})

    def record_split_fact(self, formula: str, cube: Sequence[int], variables: Sequence[int]) -> int:
        """A well-formed split, also known to the oracle."""
        self.scenario.facts.add_split(self.key(formula, cube), variables)
        return self.split(formula, cube, variables)

    # files --------------------------------------------------------------------------------------

    def data(self, torn: bytes = b"") -> bytes:
        return b"".join(j(r) + b"\n" for r in self.records) + torn

    def write(self, name: str | None = None, *, torn: bytes = b"", upto: int | None = None) -> Path:
        records = self.records if upto is None else self.records[:upto]
        path = self.scenario.path(name or f"{self.records[0]['worker']}.jsonl")
        path.write_bytes(b"".join(j(r) + b"\n" for r in records) + torn)
        return path


# -- the naive oracle (specification §10.2-§10.3 read literally; recursion suits tiny graphs) ----


ZERO_SUMMARY = {"leaves": 0, "splits": 0, "max_cube_size": 0, "leaf_merkle_root": None}


class Oracle:
    def __init__(self, facts: Facts) -> None:
        self.facts = facts

    def closed(self, key: Key) -> bool:
        if self.facts.verified.get(key):
            return True
        return any(
            all(self.closed((key[0], child)) for child in children(key[1], w))
            for w in self.facts.splits.get(key, {}).values()
        )

    def select(self, key: Key) -> tuple[list[tuple[Key, RefKey, str, str, str]], int]:
        if self.facts.verified.get(key):
            ref, ident, cnf, proof = min(self.facts.verified[key])
            return [(key, ref, ident, cnf, proof)], 0
        closed = sorted(
            sid
            for sid, w in self.facts.splits[key].items()
            if all(self.closed((key[0], c)) for c in children(key[1], w))
        )
        leaves: list[tuple[Key, RefKey, str, str, str]] = []
        count = 1
        for child in children(key[1], self.facts.splits[key][closed[0]]):
            more, splits = self.select((key[0], child))
            leaves += more
            count += splits
        return leaves, count

    def summary(self, key: Key) -> dict[str, Any]:
        if not self.closed(key):
            return dict(ZERO_SUMMARY)
        leaves, splits = self.select(key)
        return {
            "leaves": len(leaves),
            "splits": splits,
            "max_cube_size": max(len(k[1]) for k, *_ in leaves),
            "leaf_merkle_root": merkle((ident, cnf, proof) for _, _, ident, cnf, proof in leaves),
        }

    def frontier(self, key: Key) -> list[tuple[Key, str]]:
        if self.closed(key):
            return []
        if key in self.facts.models:
            return [(key, "model")]
        options = self.facts.splits.get(key)
        if options:
            found: list[tuple[Key, str]] = []
            for child in children(key[1], options[min(options)]):
                found += self.frontier((key[0], child))
            return found
        return [(key, "pending")]

    def open_list(self, starts: Iterable[Key]) -> list[dict[str, Any]]:
        entries = [
            {
                "node": {"formula_sha256": k[0], "cube": list(k[1])},
                "node_id": node_id(*k),
                "state": state,
                "reason": None,
            }
            for start in starts
            for k, state in self.frontier(start)
        ]
        return sorted(entries, key=lambda e: (e["node"]["formula_sha256"], e["node_id"]))


def oracle_expectation(scenario: Scenario) -> dict[str, Any]:
    """formulas, open, formula_open, used node IDs and verdict per the naive oracle."""
    oracle = Oracle(scenario.facts)
    formulas = []
    used: set[str] = set()
    for key in sorted(scenario.formulas, key=scenario.sha):
        formula = scenario.sha(key)
        empty: Key = (formula, ())
        roots = []
        for root in sorted(
            (r for r in scenario.roots if r[0] == formula), key=lambda r: node_id(*r)
        ):
            roots.append({"cube": list(root[1]), "closed": oracle.closed(root)})
            roots[-1]["summary"] = oracle.summary(root)
            if oracle.closed(root):
                used |= {leaf[2] for leaf in oracle.select(root)[0]}
        proved = oracle.closed(empty)
        if proved:
            used |= {leaf[2] for leaf in oracle.select(empty)[0]}
        formulas.append(
            {
                "formula_sha256": formula,
                "key": key,
                "proved": proved,
                "summary": oracle.summary(empty),
                "roots": roots,
            }
        )
    model_formulas = {k[0] for k in scenario.facts.models}
    proved_formulas = {f["formula_sha256"] for f in formulas if f["proved"]}
    if model_formulas & proved_formulas:
        verdict = "INCONSISTENT"
    elif model_formulas:
        verdict = "MODEL_FOUND"
    elif len(proved_formulas) == len(formulas):
        verdict = "PROVED"
    else:
        verdict = "OPEN"
    empties = [(scenario.sha(k), ()) for k in scenario.formulas]
    return {
        "formulas": formulas,
        "open": oracle.open_list(scenario.roots),
        "formula_open": oracle.open_list(empties),
        "used": sorted(used),
        "verdict": verdict,
    }
