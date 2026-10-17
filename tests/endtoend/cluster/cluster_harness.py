"""Harness of the multi-worker end-to-end tests: correctness, durability and operation.

Specification §7, §10-§12 and §15.

It builds on the single-worker harness (``tests/endtoend/single/e2e_harness.py``: the fake and
pinned tools, the formulas, both certifiers, :func:`e2e_harness.semantic` and the restart
invariants) and adds several workers of one campaign, each with its own results, work, inbox,
outbox and export directories, planned shards, a handoff from one worker to another, crashes
of the giver and of the receiver, merged journal snapshots, the recompute audit and the
retained-proof verification. Every step goes through the public command line in child
processes (``python -m cubeproof ...`` and ``python tools/certify_min.py ...``), as an
operator runs it; nothing here imports the coordinator or a certifier.

- :class:`Workload`: formulas, the static root split that ``cubeproof shard`` expands into
  the planned nodes, the verdict a complete campaign must certify, and whether a ground truth
  can be computed independently (:func:`satisfiable`, a small DPLL of this module).
- :class:`Worker` and :class:`Live`: one ``cubeproof run`` worker and its running process
  (signalled, or crashed by SIGKILL of its whole process group).
- :func:`cluster_scenario`: the fixed sequence on two workers. The giver is stopped
  (SIGINT), asked for work while stopped, crashed right after it commits the handoff and
  restarted; the receiver gets the published shard, is crashed after it commits the
  shard and restarted; both finish. Then every check of :func:`final_checks`.
- :func:`random_crash_scenario`: the same two workers running at the same time, with crashes
  (and a few stops) of either worker at random record counts; then the same checks.
- :func:`final_checks`: both certifiers on the final journals, on the portable evidence
  package and on several argument orders with the snapshots (byte-identical certificates),
  the expected verdict, the run-independent content against a single-worker reference
  (deterministic workloads), the ground truth, the open scope of each worker alone,
  ``shard --from-open``, the restart invariants of each journal, the exports, the exclusion
  of given-away work, the recovered handoff output, every committed retained proof present
  (and ``verify-retained``), and the strict recompute audit.

``SIGKILL`` does not simulate a power loss: the page cache survives, so unsynced appends are
not lost (as in the single-worker tests). The deterministic durable boundaries of
specification §7.5 are constructed as files in ``cluster_faults.py``. Long runs belong in a
directory outside the checkout; the tests use ``tmp_path`` and write their records to
``$E2E_CLUSTER_EVIDENCE`` when it is set.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import random
import shutil
import signal
import subprocess
import sys
import time
from collections import Counter
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from functools import partial
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
SINGLE_DIR = HERE.parent / "single"
TESTS = HERE.parents[1]
for _path in (SINGLE_DIR, TESTS):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

import e2e_harness as e2e  # noqa: E402

from cubeproof.base.canonical_json import document_bytes  # noqa: E402
from cubeproof.cnf.bundle import publish_bundle  # noqa: E402
from cubeproof.cnf.dimacs import canonical_dimacs  # noqa: E402
from cubeproof.contracts.identity import node_id, split_id  # noqa: E402
from cubeproof.contracts.policy import Policy  # noqa: E402
from cubeproof.tools.isolation import PinnedBinary  # noqa: E402
from fakes import cnf_model  # noqa: E402

Node = tuple[str, tuple[int, ...]]
MODES = ("transient", "retain", "stream")
#: run exit codes of a worker that ended by itself (specification §12.2): 0, or 2 with a model
DONE = (0, 2)
#: a worker stopped by SIGINT or SIGTERM (specification §6.2)
STOPPED = 130
VERDICT_EXIT = e2e.VERDICT_EXIT


# -- formulas and ground truth --------------------------------------------------------------------


def random_3cnf(variables: int, clauses: int, seed: int) -> bytes:
    """A seeded random 3-CNF (distinct variables per clause), canonical DIMACS."""
    rng = random.Random(seed)
    rows: list[tuple[int, ...]] = []
    for _ in range(clauses):
        chosen = rng.sample(range(1, variables + 1), 3)
        rows.append(tuple(v if rng.random() < 0.5 else -v for v in chosen))
    return canonical_dimacs(variables, rows)


def satisfiable(
    clauses: Sequence[Sequence[int]], variables: int, units: Iterable[int] = ()
) -> dict[int, bool] | None:
    """A model of ``clauses`` plus the unit ``units``, or None: a small DPLL with unit
    propagation, independent of the solvers under test (ground truth for small formulas)."""
    assignment: dict[int, bool] = {}
    for literal in units:
        if assignment.get(abs(literal), literal > 0) != (literal > 0):
            return None
        assignment[abs(literal)] = literal > 0
    rows = [tuple(c) for c in clauses]

    def solve(current: dict[int, bool]) -> dict[int, bool] | None:
        values = dict(current)
        while True:
            unit: int | None = None
            for clause in rows:
                free: list[int] = []
                satisfied = False
                for literal in clause:
                    value = values.get(abs(literal))
                    if value is None:
                        free.append(literal)
                    elif value == (literal > 0):
                        satisfied = True
                        break
                if satisfied:
                    continue
                if not free:
                    return None
                if len(free) == 1:
                    unit = free[0]
                    break
            if unit is None:
                break
            values[abs(unit)] = unit > 0
        open_vars = [v for v in range(1, variables + 1) if v not in values]
        if not open_vars:
            return values
        branch = open_vars[0]
        for choice in (True, False):
            found = solve({**values, branch: choice})
            if found is not None:
                return found
        return None

    model = solve(assignment)
    if model is None:
        return None
    return {v: model.get(v, False) for v in range(1, variables + 1)}


def decode_assignment(text: str, variables: int) -> dict[int, bool]:
    """The canonical bitset of specification §4.8 (LSB first) as a complete assignment."""
    data = base64.b64decode(text)
    return {v: bool(data[(v - 1) // 8] >> ((v - 1) % 8) & 1) for v in range(1, variables + 1)}


# -- workloads ------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Workload:
    """A campaign of these tests: formulas, the static root split of each formula (``shard``
    expands it into the planned nodes), the verdict of a complete run and how to judge it.

    ``truth``: the formulas are small enough for :func:`satisfiable` (ground truth of every
    claim). ``deterministic``: the evidence tree does not depend on timing, so every complete
    run (any mode, any crash) must give the run-independent content of a single-worker run.
    """

    name: str
    formulas: Mapping[str, bytes]
    split: Mapping[str, tuple[int, ...]]
    verdict: str
    proved: Mapping[str, bool]
    fake_solver: Mapping[str, Any] = field(default_factory=dict)
    truth: bool = False
    deterministic: bool = True
    gift: int = 2
    policy_changes: Mapping[str, Any] = field(default_factory=dict)

    def policy(self, kind: str, mode: str) -> Policy:
        if kind == "fake":
            return e2e.fake_policy(2, proof_mode=mode, stream_heap_mib=512, **self.policy_changes)
        return e2e.pinned_policy(2, proof_mode=mode, **self.policy_changes)


def fake_workloads() -> dict[str, Workload]:
    """Fake tools (brute force, decision-tree LRAT): pigeonhole 4->3 and an eight-variable
    unsatisfiable core inside twelve variables, both unsatisfiable; and two seeded random
    3-CNF formulas of twelve variables, one satisfiable with refuted quarters and one
    unsatisfiable (ground truth by DPLL). The fake solver runs out of memory while more than
    eight variables are free, so every planned node is split once more by the dynamic
    splitter."""
    slow = {"max_free": 8, "sleep": 0.05}
    items = [
        Workload(
            "php",
            {"php3": e2e.pigeonhole_formula(3), "core": e2e.unsat_formula(12, core=8)},
            {"php3": (1, 2), "core": (1, 2)},
            "PROVED",
            {"php3": True, "core": True},
            fake_solver=slow,
            truth=True,
        ),
        Workload(
            "truth",
            {"r1": random_3cnf(12, 52, 2026101003), "r2": random_3cnf(12, 60, 2026101004)},
            {"r1": (1, 2), "r2": (1, 2)},
            "MODEL_FOUND",
            {"r1": False, "r2": True},
            fake_solver=slow,
            truth=True,
        ),
    ]
    return {w.name: w for w in items}


def neighbourly_formula(n: int) -> bytes:
    """The ``neighbourly`` encoding (layers S,H,A,B,I, gauge face 1) of the tetrahedron
    (n = 4) or of the Csaszar map (n = 7): small real formulas, both satisfiable (realized)."""
    from itertools import combinations

    from neighbourly.data import read_bytes
    from neighbourly.encoding import Encoder
    from neighbourly.maps import CombinatorialMap

    if n == 4:
        cmap = CombinatorialMap(4, combinations(range(1, 5), 3))
    elif n == 7:
        text = read_bytes("fixtures", "szilassi", "csaszar_n7.txt").decode("utf-8")
        cmap = CombinatorialMap.from_text(text, "csaszar_n7.txt")
    else:
        raise ValueError(f"no small real map for n = {n}")
    encoder = Encoder(cmap).build(gauge_face=1)
    return canonical_dimacs(encoder.variables, [tuple(c) for c in encoder.clauses])


def pinned_workloads() -> dict[str, Workload]:
    """Pinned CaDiCaL and cake_lpr: pigeonhole 7->6 and 8->7, each split by a
    static root split of three variables (16 planned leaves, no deadline: deterministic);
    the small real formulas n = 4 and n = 7 (satisfiable; some subcubes refuted); and two
    seeded random 3-CNF formulas of 16 variables (ground truth by DPLL)."""
    items = [
        Workload(
            "php",
            {"php6": e2e.pigeonhole_formula(6), "php7": e2e.pigeonhole_formula(7)},
            {"php6": (1, 2, 3), "php7": (1, 2, 3)},
            "PROVED",
            {"php6": True, "php7": True},
            gift=3,
        ),
        Workload(
            "real",
            {"n4": neighbourly_formula(4), "n7": neighbourly_formula(7)},
            {"n4": (41, 42, 43), "n7": (544, 545, 546)},
            "MODEL_FOUND",
            {"n4": False, "n7": False},
            gift=3,
        ),
        Workload(
            "truth",
            {"r1": random_3cnf(16, 69, 2026101013), "r2": random_3cnf(16, 69, 2026101011)},
            {"r1": (1, 2, 3), "r2": (1, 2, 3)},
            "MODEL_FOUND",
            {"r1": False, "r2": True},
            truth=True,
            gift=3,
        ),
    ]
    return {w.name: w for w in items}


# -- campaign ------------------------------------------------------------------------------------


def make_campaign(root: Path, workload: Workload, tools: e2e.Tools, mode: str) -> Path:
    """Bundles, policy, admission and the static root split, then ``campaign create``."""
    root.mkdir(parents=True, exist_ok=True)
    if tools.kind == "fake":
        tools.configure_fake(**workload.fake_solver)
    inputs = root / "inputs"
    bundles: list[str] = []
    entries: list[tuple[str, list[int]]] = []
    for key, data in sorted(workload.formulas.items()):
        bundle = root / "bundles" / key
        publish_bundle(
            bundle,
            data,
            pools={},
            producer={"name": "e2e-cluster", "version": "1", "parameters": {}},
        )
        bundles += ["--bundle", str(bundle)]
        variables = list(workload.split.get(key, ()))
        if variables:
            entries.append((hashlib.sha256(data).hexdigest(), variables))
    entries.sort(key=lambda e: split_id(node_id(e[0], []), e[1]))
    prefixes = {
        "format": "cubeproof-prefixes-1",
        "splits": [
            {
                "node": {"formula_sha256": formula, "cube": []},
                "variables": variables,
                "splitter": {
                    "name": "static",
                    "info": {"order": variables, "prefix": len(variables)},
                },
            }
            for formula, variables in entries
        ],
    }
    e2e.write_json(inputs / "prefixes.json", prefixes)
    e2e.write_json(inputs / "policy.json", workload.policy(tools.kind, mode).to_json())
    checker = PinnedBinary.measure(str(tools.checker)).sha256
    solver = PinnedBinary.measure(str(tools.solver)).sha256
    admit = {
        "checker_sha256": [checker],
        "solvers": [{"sha256": solver, "argv": list(tools.solver_argv)}],
    }
    e2e.write_json(inputs / "admit.json", admit)
    argv = e2e.cubeproof(
        "campaign",
        "create",
        *bundles,
        "--policy",
        str(inputs / "policy.json"),
        "--admit",
        str(inputs / "admit.json"),
        "--solver",
        str(tools.solver),
        "--solver-argv",
        json.dumps(list(tools.solver_argv)),
        "--checker",
        str(tools.checker),
        "--author",
        "e2e-cluster",
        "--root-split",
        f"static:{inputs / 'prefixes.json'}",
        "-o",
        str(root / "campaign.json"),
    )
    done = e2e.execute(argv)
    if done.code != 0:
        raise AssertionError(f"campaign create failed: {done.err}")
    return root / "campaign.json"


def plan_shards(campaign: Path, machines: int, out: Path) -> list[Path]:
    """``cubeproof shard --machines N``: the shard files in machine order."""
    done = e2e.execute(
        e2e.cubeproof(
            "shard", "--campaign", str(campaign), "--machines", str(machines), "-o", str(out)
        )
    )
    if done.code != 0:
        raise AssertionError(f"shard failed: {done.err}")
    document = e2e._document(done.out)
    if document is None:
        raise AssertionError(f"shard printed no result: {done.out}")
    return [Path(s["path"]) for s in sorted(document["shards"], key=lambda s: s["machine"])]


def shard_nodes(path: Path) -> list[Node]:
    return nodes_of(json.loads(path.read_text(encoding="utf-8")))


def nodes_of(shard: Mapping[str, Any] | None) -> list[Node]:
    if shard is None:
        return []
    return [(str(n["formula_sha256"]), tuple(int(x) for x in n["cube"])) for n in shard["nodes"]]


def node_key(record: Mapping[str, Any]) -> Node:
    node = record["node"]
    return (str(node["formula_sha256"]), tuple(int(x) for x in node["cube"]))


def within(node: Node, region: Iterable[Node]) -> bool:
    """``node`` equals or descends from a node of ``region`` (its cube extends that cube)."""
    literals = set(node[1])
    return any(node[0] == r[0] and set(r[1]) <= literals for r in region)


# -- workers --------------------------------------------------------------------------------------


@dataclass(frozen=True)
class RunEnd:
    """A ``cubeproof run`` that ended: exit code, result document, signal sent to it."""

    code: int
    document: dict[str, Any] | None
    seconds: float
    signal_sent: str | None
    err_tail: str

    def to_json(self) -> dict[str, Any]:
        document = self.document or {}
        return {
            "exit": self.code,
            "seconds": round(self.seconds, 3),
            "signal": self.signal_sent,
            "reason": document.get("reason"),
            "seq": document.get("seq"),
            "given_away": document.get("given_away"),
            "notes": document.get("notes"),
            "err_tail": self.err_tail if self.code not in (*DONE, STOPPED) else "",
        }


@dataclass
class Live:
    """A running worker process (its own session: a crash kills the whole group)."""

    worker: Worker
    process: subprocess.Popen[bytes]
    out: Path
    err: Path
    started: float
    signal_sent: str | None = None

    def alive(self) -> bool:
        return self.process.poll() is None

    def until(self, condition: Callable[[], bool], timeout_s: float = 120.0) -> bool:
        """Poll ``condition`` while the process lives; True when it held while alive."""
        deadline = time.monotonic() + timeout_s
        while self.alive() and time.monotonic() < deadline:
            try:
                if condition():
                    return self.alive()
            except (OSError, ValueError):
                pass  # a record being written; try again
            time.sleep(0.02)
        return False

    def send(self, how: str) -> bool:
        """``SIGKILL`` of the whole process group (a crash) or SIGINT/SIGTERM to the run."""
        if not self.alive():
            return False
        self.signal_sent = how
        if how == "SIGKILL":
            os.killpg(self.process.pid, signal.SIGKILL)
        else:
            os.kill(self.process.pid, getattr(signal, how))
        return True

    def wait(self, timeout_s: float = 600.0) -> RunEnd:
        try:
            self.process.wait(timeout=timeout_s)
        except subprocess.TimeoutExpired:
            os.killpg(self.process.pid, signal.SIGKILL)
            self.process.wait()
            self.signal_sent = f"{self.signal_sent or ''}timeout"
        out = self.out.read_text(encoding="utf-8", errors="replace")
        err = self.err.read_text(encoding="utf-8", errors="replace")
        if self.signal_sent == "SIGKILL":
            self.worker.wait_clean()
        return RunEnd(
            int(self.process.returncode),
            e2e._document(out),
            time.monotonic() - self.started,
            self.signal_sent,
            err[-2000:],
        )


@dataclass
class Worker:
    """One worker of a campaign with its own directories (specification §7.3: never shared)."""

    name: str
    root: Path
    campaign: Path
    tools: e2e.Tools
    mode: str
    shard: Path | None = None
    jobs: int = 4
    starts: int = 0
    ends: list[RunEnd] = field(default_factory=list)

    @property
    def results(self) -> Path:
        return self.root / "results"

    @property
    def work(self) -> Path:
        return self.root / "work"

    @property
    def inbox(self) -> Path:
        return self.root / "inbox"

    @property
    def outbox(self) -> Path:
        return self.root / "outbox"

    @property
    def export(self) -> Path:
        return self.root / "export"

    @property
    def journal(self) -> Path:
        return self.results / "journal.jsonl"

    def argv(self) -> list[str]:
        argv = e2e.cubeproof(
            "run",
            "--campaign",
            str(self.campaign),
            "--results",
            str(self.results),
            "--work",
            str(self.work),
            "--worker",
            self.name,
            "--solver",
            str(self.tools.solver),
            "--checker",
            str(self.tools.checker),
            "--jobs",
            str(self.jobs),
            "--proof-mode",
            self.mode,
            "--inbox",
            str(self.inbox),
            "--outbox",
            str(self.outbox),
            "--export",
            str(self.export),
        )
        if self.tools.helper is not None:
            argv += ["--helper", str(self.tools.helper)]
        if self.shard is not None:
            argv += ["--shard", str(self.shard)]
        return argv

    def start(self) -> Live:
        self.starts += 1
        logs = self.root / "logs"
        logs.mkdir(parents=True, exist_ok=True)
        out, err = logs / f"run-{self.starts}.out", logs / f"run-{self.starts}.err"
        with open(out, "wb") as stdout, open(err, "wb") as stderr:
            process = subprocess.Popen(
                self.argv(),
                env=e2e.child_env(),
                stdout=stdout,
                stderr=stderr,
                start_new_session=True,
            )
        return Live(self, process, out, err, time.monotonic())

    def run(self, timeout_s: float = 600.0) -> RunEnd:
        end = self.start().wait(timeout_s)
        self.ends.append(end)
        return end

    def records(self) -> list[dict[str, Any]]:
        return e2e.records(self.journal)

    def snapshot(self, name: str) -> Path:
        """A byte copy of the journal up to its last LF (an explicit snapshot, specification
        §10.1)."""
        copy = self.root.parent / "snapshots" / f"{self.name}-{name}.jsonl"
        copy.parent.mkdir(parents=True, exist_ok=True)
        copy.write_bytes(e2e.complete_lines(self.journal))
        return copy

    def handoff(self, nodes: int, name: str, wait_ms: int = 0) -> e2e.Completed:
        return e2e.execute(
            e2e.cubeproof(
                "handoff",
                "--results",
                str(self.results),
                "--nodes",
                str(nodes),
                "--output-name",
                name,
                "--wait-ms",
                str(wait_ms),
            )
        )

    def wait_clean(self, timeout_s: float = 30.0) -> None:
        """Until the run lock is free and no process uses the work directory (after a crash
        the I/O service ends when its input closes)."""
        deadline = time.monotonic() + timeout_s
        while e2e._lock_held(self.results / "run.lock") or e2e._users(self.work):
            if time.monotonic() > deadline:
                raise AssertionError(
                    f"{self.name}: a process of the crashed run survives\n"
                    + e2e.survivors_report(self.results / "run.lock", self.work)
                )
            time.sleep(0.05)

    def work_files(self) -> list[str]:
        if not self.work.exists():
            return []
        return sorted(p.name for p in self.work.iterdir() if not p.name.startswith(".run"))

    def handoffs(self) -> list[dict[str, Any]]:
        return [r for r in self.records() if r["type"] == "handoff"]

    def shard_hashes(self) -> list[str]:
        return [str(r["shard_sha256"]) for r in self.records() if r["type"] == "shard"]


def deliver(giver: Worker, receiver: Worker, name: str = "gift") -> Path | None:
    """Copy the giver's published output into the receiver's inbox (the user's transfer)."""
    source = giver.outbox / f"{name}.json"
    if not source.exists():
        return None
    receiver.inbox.mkdir(parents=True, exist_ok=True)
    target = receiver.inbox / f"{name}.json"
    staging = receiver.inbox / f".{name}.json.part"
    shutil.copyfile(source, staging)
    os.replace(staging, target)
    return target


# -- other commands -------------------------------------------------------------------------------


def audit(
    campaign: Path,
    certificate: Path,
    journals: Sequence[Path],
    out: Path,
    tools: e2e.Tools,
    *,
    sample: int | None = None,
) -> tuple[e2e.Completed, dict[str, Any] | None]:
    """``cubeproof audit --comparison strict`` (``--all`` or ``--sample N``)."""
    selection = ["--all"] if sample is None else ["--sample", str(sample)]
    done = e2e.execute(
        e2e.cubeproof(
            "audit",
            "--campaign",
            str(campaign),
            "--certificate",
            str(certificate),
            "--journals",
            *[str(j) for j in journals],
            *selection,
            "--comparison",
            "strict",
            "--results",
            str(out / "results"),
            "--work",
            str(out / "work"),
            "--worker",
            "audit",
            "--solver",
            str(tools.solver),
            "--checker",
            str(tools.checker),
        ),
        timeout_s=1800.0,
    )
    return done, e2e._document(done.out)


def verify_retained(
    campaign: Path, journals: Sequence[Path], proofs_root: Path, out: Path, tools: e2e.Tools
) -> tuple[e2e.Completed, dict[str, Any] | None]:
    done = e2e.execute(
        e2e.cubeproof(
            "verify-retained",
            "--campaign",
            str(campaign),
            "--journals",
            *[str(j) for j in journals],
            "--proofs-root",
            str(proofs_root),
            "--results",
            str(out / "results"),
            "--work",
            str(out / "work"),
            "--worker",
            "verify",
            "--checker",
            str(tools.checker),
        ),
        timeout_s=1800.0,
    )
    return done, e2e._document(done.out)


# -- checks ---------------------------------------------------------------------------------------


def open_nodes(certificate: Mapping[str, Any], key: str = "open") -> list[Node]:
    return sorted(node_key(o) for o in certificate[key])


def truth_problems(certificate: Mapping[str, Any], formulas: Mapping[str, bytes]) -> list[str]:
    """Every claim of a certificate against :func:`satisfiable`: proved formulas, closed roots
    and selected leaves are unsatisfiable, models satisfy their node, a satisfiable formula
    makes the verdict MODEL_FOUND (a complete campaign) and never PROVED."""
    problems: list[str] = []
    parsed = {k: cnf_model.parse_dimacs(v) for k, v in formulas.items()}
    by_hash = {hashlib.sha256(v).hexdigest(): k for k, v in formulas.items()}
    any_sat = False
    for entry in certificate["formulas"]:
        cnf = parsed[entry["key"]]
        sat = satisfiable(cnf.clauses, cnf.variables) is not None
        any_sat |= sat
        if entry["proved"] and sat:
            problems.append(f"formula {entry['key']} proved but satisfiable")
        for root in entry["roots"]:
            if root["closed"] and satisfiable(cnf.clauses, cnf.variables, root["cube"]) is not None:
                problems.append(f"root {entry['key']} {root['cube']} closed but satisfiable")
    for used in certificate["used_attempts"]:
        formula, cube = node_key(used)
        cnf = parsed[by_hash[formula]]
        if satisfiable(cnf.clauses, cnf.variables, cube) is not None:
            problems.append(f"leaf {by_hash[formula]} {list(cube)} used but satisfiable")
    for model in certificate["models"]:
        formula, cube = node_key(model)
        cnf = parsed[by_hash[formula]]
        values = decode_assignment(model["assignment"], cnf.variables)
        if cnf_model.violated_clause(cnf, values) is not None:
            problems.append(f"model of {by_hash[formula]} {list(cube)} violates a clause")
        if any(values[abs(u)] != (u > 0) for u in cube):
            problems.append(f"model of {by_hash[formula]} {list(cube)} violates its cube")
    if any_sat and certificate["verdict"] == "PROVED":
        problems.append("PROVED although a formula is satisfiable")
    return problems


def leaf_proofs(journals: Iterable[Path]) -> dict[str, list[str]]:
    """``node_id|cnf_sha256|route`` -> the proof hashes of its complete VERIFIED_UNSAT
    attempts in these journals (the common-leaf comparison of the card)."""
    found: dict[str, set[str]] = {}
    for journal in journals:
        for attempt in e2e.attempts(journal):
            if attempt["outcome"] == "VERIFIED_UNSAT":
                key = f"{attempt['node_id']}|{attempt['cnf_sha256']}|{attempt['route']}"
                found.setdefault(key, set()).add(str(attempt["proof_sha256"]))
    return {k: sorted(v) for k, v in sorted(found.items())}


def common_leaf_problems(runs: Mapping[str, Mapping[str, Sequence[str]]]) -> tuple[list[str], int]:
    """Leaves proved in several runs must have one proof hash (specification §11.3); the number
    of leaves common to at least two runs."""
    merged: dict[str, set[str]] = {}
    seen: Counter[str] = Counter()
    for leaves in runs.values():
        for key, hashes in leaves.items():
            merged.setdefault(key, set()).update(hashes)
            seen[key] += 1
    problems = [f"leaf {k}: {len(v)} different proofs" for k, v in merged.items() if len(v) > 1]
    return problems, sum(1 for n in seen.values() if n > 1)


def retained_problems(worker: Worker) -> tuple[list[str], int]:
    """Every retained artifact of a committed attempt exists with its size and hash
    (specification §7.2)."""
    problems: list[str] = []
    count = 0
    for attempt in e2e.attempts(worker.journal):
        artifact = attempt.get("retained")
        if not artifact:
            continue
        count += 1
        path = worker.results / artifact["path"]
        if not path.is_file():
            problems.append(f"{worker.name}: retained {artifact['path']} is missing")
            continue
        data = path.read_bytes()
        if len(data) != artifact["bytes"] or hashlib.sha256(data).hexdigest() != artifact["sha256"]:
            problems.append(f"{worker.name}: retained {artifact['path']} differs")
    return problems, count


def orphan_proofs(worker: Worker) -> list[str]:
    """Files below ``proofs/`` that no committed attempt references (tmp/ included)."""
    root = worker.results / "proofs"
    if not root.exists():
        return []
    referenced = {
        str(a["retained"]["path"]) for a in e2e.attempts(worker.journal) if a.get("retained")
    }
    files = [p.relative_to(worker.results).as_posix() for p in root.rglob("*") if p.is_file()]
    return sorted(f for f in files if f not in referenced)


def prefix_problems(name: str, snapshots: Sequence[Path], journal: Path) -> list[str]:
    """Every snapshot taken earlier is a byte prefix of the final journal (specification §7.1)."""
    data = e2e.complete_lines(journal)
    return [
        f"{name}: snapshot {s.name} is not a prefix of the final journal"
        for s in snapshots
        if not data.startswith(s.read_bytes())
    ]


def journal_problems(worker: Worker, snapshots: Sequence[Path]) -> list[str]:
    """Restart invariants of one worker journal (specification §7.3, §7.5): byte-prefix
    extension, one header, one resume per later start, contiguous seq, unique attempt IDs,
    nothing proved twice, no split twice, ``journal verify`` accepts it."""
    problems = [
        f"{worker.name}: {p}" for p in e2e.resume_invariants(b"", worker.journal, worker.starts - 1)
    ]
    problems += prefix_problems(worker.name, snapshots, worker.journal)
    verified = e2e.execute(
        e2e.cubeproof("journal", "verify", "--campaign", str(worker.campaign), str(worker.journal))
    )
    if verified.code != 0:
        problems.append(
            f"{worker.name}: journal verify exit {verified.code}: {verified.err.strip()}"
        )
    return problems


def export_problems(worker: Worker) -> list[str]:
    """Exported journal copies are byte prefixes of the journal; the descriptor names the
    copy, its length, last seq and head; after a clean end the export holds the whole journal
    (the clean-stop export, specification §7.5)."""
    problems: list[str] = []
    data = e2e.complete_lines(worker.journal)
    copies = sorted(worker.export.glob("*.jsonl")) if worker.export.exists() else []
    for copy in copies:
        if not data.startswith(copy.read_bytes()):
            problems.append(f"{worker.name}: export {copy.name} is not a prefix of the journal")
    descriptor = worker.export / "export.json"
    if not descriptor.exists():
        return [*problems, f"{worker.name}: no export descriptor"]
    document = json.loads(descriptor.read_text(encoding="utf-8"))
    copy = worker.export / str(document["file"])
    exported = copy.read_bytes() if copy.exists() else b""
    last = json.loads(exported.splitlines()[-1]) if exported else {}
    if (len(exported), last.get("seq"), last.get("self")) != (
        document["offset"],
        document["seq"],
        document["head"],
    ):
        problems.append(f"{worker.name}: the export descriptor does not describe its copy")
    if exported != data:
        problems.append(f"{worker.name}: the export after the clean end is not the whole journal")
    return problems


def exclusion_problems(
    giver: Worker, receiver: Worker, receiver_region: Sequence[Node]
) -> list[str]:
    """After its handoff record the giver never works on given-away nodes (specification §7.4);
    the receiver works only inside its accepted region."""
    problems: list[str] = []
    kinds = ("attempt", "split", "node_stop", "node_reopen")
    given: list[Node] = []
    for record in giver.records():
        if record["type"] == "handoff":
            given += nodes_of(record["shard"])
        elif record["type"] in kinds and within(node_key(record), given):
            problems.append(
                f"{giver.name}: {record['type']} at seq {record['seq']} on given-away work"
            )
    for record in receiver.records():
        if record["type"] in kinds and not within(node_key(record), receiver_region):
            problems.append(
                f"{receiver.name}: {record['type']} at seq {record['seq']} outside its region"
            )
    return problems


def handoff_output_problems(
    giver: Worker, name: str = "gift"
) -> tuple[list[str], dict[str, Any] | None]:
    """The committed handoff of request ``name`` and its published output (specification §7.4):
    exactly one record, output bytes equal to J(shard)+LF, no file for an empty completion."""
    records = [r for r in giver.handoffs() if r["request"]["output_name"] == name]
    if len(records) != 1:
        return [f"{giver.name}: {len(records)} handoff records for {name}"], None
    record = records[0]
    output = giver.outbox / f"{name}.json"
    problems: list[str] = []
    if record["shard"] is None:
        if output.exists():
            problems.append("an empty completion published a file")
    elif not output.exists():
        problems.append("the committed handoff output is missing")
    elif output.read_bytes() != document_bytes(record["shard"]):
        problems.append("the handoff output differs from the committed shard")
    return problems, record


def evidence_problems(
    campaign: Path, journals: Sequence[Path], out: Path, final: e2e.Certified
) -> list[str]:
    """``evidence package`` of the final journals, then ``certify --evidence`` and
    ``certify_min.py`` on the packaged campaign and journal copies."""
    packed = e2e.execute(
        e2e.cubeproof(
            "evidence", "package", "--campaign", str(campaign), "--journals",
            *[str(j) for j in journals], "-o", str(out),
        )
    )  # fmt: skip
    if packed.code != 0:
        return [f"evidence package: exit {packed.code}: {packed.err.strip()}"]
    problems: list[str] = []
    if (out / "certificate.json").read_bytes() != final.main_bytes:
        problems.append("evidence package: its certificate differs from the final one")
    target = out.parent / f"{out.name}-certificate.json"
    via = e2e.execute(
        e2e.cubeproof("certify", "--evidence", str(out / "evidence.json"), "-o", str(target))
    )
    if (
        via.code != final.main.code
        or not target.exists()
        or target.read_bytes() != final.main_bytes
    ):
        problems.append(f"certify --evidence: exit {via.code}, certificate differs")
    copies = sorted((out / "journals").glob("*.jsonl"))
    independent = e2e.certify_both(
        out / "campaign.json", copies, out.parent / f"{out.name}-certify"
    )
    problems += [f"packaged copies: {x}" for x in independent.problems()]
    if independent.independent_bytes != final.main_bytes:
        problems.append("packaged copies: the independent certificate differs from the final one")
    return problems


@dataclass
class Final:
    """What :func:`final_checks` found, as a JSON record."""

    problems: list[str] = field(default_factory=list)
    facts: dict[str, Any] = field(default_factory=dict)


def final_checks(
    root: Path,
    workload: Workload,
    tools: e2e.Tools,
    campaign: Path,
    giver: Worker,
    receiver: Worker,
    shards: Sequence[Path],
    snapshots: Mapping[str, Sequence[Path]],
    reference: Mapping[str, Any] | None,
    *,
    audit_sample: int | None = None,
    seed: int = 0,
) -> Final:
    """Every check of the card on the finished two-worker campaign (module doc)."""
    found = Final()
    p, facts = found.problems, found.facts
    journals = [giver.journal, receiver.journal]
    final = certify_both(campaign, journals, root / "certify-final")
    p += [f"final: {x}" for x in final.problems()]
    if final.main_bytes is None:
        p.append(f"final: no certificate: {final.main.err.strip()}")
        return found
    cert = final.certificate
    facts["verdict"] = cert["verdict"]
    facts["certificate_sha256"] = e2e._digest(final.main_bytes)
    facts["certify_exit"] = [final.main.code, final.independent.code]
    facts["summaries"] = {f["key"]: f["summary"] for f in cert["formulas"]}
    facts["used_leaves"] = len(cert["used_attempts"])
    facts["models"] = len(cert["models"])
    if cert["verdict"] != workload.verdict:
        p.append(f"verdict {cert['verdict']} != {workload.verdict}")
    if final.main.code != VERDICT_EXIT[workload.verdict]:
        p.append(f"certify exit {final.main.code}")
    proved = {f["key"]: f["proved"] for f in cert["formulas"]}
    for key, expected in workload.proved.items():
        if proved.get(key) != expected:
            p.append(f"formula {key}: proved {proved.get(key)} != {expected}")
    if workload.verdict == "PROVED" and (cert["open"] or cert["formula_open"]):
        p.append("a proved campaign has open nodes")
    if cert["anomalies"] or cert["not_admitted"]:
        p.append("anomalies or nonadmitted evidence in a clean run")
    # the portable evidence directory (specification §4.9, §12.1): its certificate,
    # `certify --evidence` and the independent certifier on the packaged copies are
    # byte-identical to the final one
    p += evidence_problems(campaign, journals, root / "evidence", final)
    # merged snapshots in several argument orders: byte-identical certificates (specification §10.1)
    extra = [s for name in sorted(snapshots) for s in snapshots[name]]
    inputs = [*journals, *extra]
    rng = random.Random(seed)
    shuffled = list(inputs)
    rng.shuffle(shuffled)
    orders = {
        "reversed": list(reversed(inputs)),
        "snapshots-first": [*extra, *journals],
        "shuffled": shuffled,
    }
    facts["merge_inputs"] = len(inputs)
    for label, order in orders.items():
        merged = certify_both(campaign, order, root / f"certify-merge-{label}")
        p += [f"merge {label}: {x}" for x in merged.problems()]
        if merged.main_bytes != final.main_bytes:
            p.append(f"merge {label}: the certificate differs from the final one")
    # the run-independent content of a single-worker reference (deterministic workloads)
    if reference is not None:
        mine = e2e.semantic(cert)
        differs = [k for k in mine if mine[k] != reference.get(k)]
        facts["differs_from_reference"] = differs
        if workload.deterministic and differs:
            p += [f"differs from the single-worker reference: {k}" for k in differs]
    if workload.truth:
        p += truth_problems(cert, workload.formulas)
    # open scope of each worker alone (specification §10.3, §7.4): unsatisfiable workloads only
    handoff_problems, record = handoff_output_problems(giver)
    p += handoff_problems
    gift = nodes_of(record["shard"]) if record else []
    facts["gift"] = [[n[0][:12], list(n[1])] for n in gift]
    first, second = shard_nodes(shards[0]), shard_nodes(shards[1])
    if workload.verdict == "PROVED":
        alone_giver = certify_both(campaign, [giver.journal], root / "certify-giver")
        alone_receiver = certify_both(campaign, [receiver.journal], root / "certify-receiver")
        p += [f"giver alone: {x}" for x in alone_giver.problems()]
        p += [f"receiver alone: {x}" for x in alone_receiver.problems()]
        if alone_giver.main_bytes is not None and alone_receiver.main_bytes is not None:
            want_giver = sorted({*second, *gift})
            want_receiver = sorted(n for n in first if n not in gift)
            if open_nodes(alone_giver.certificate) != want_giver:
                p.append("giver alone: open scope is not the receiver's shard plus the gift")
            if open_nodes(alone_receiver.certificate) != want_receiver:
                p.append("receiver alone: open scope is not the giver's shard minus the gift")
            plan = e2e.execute(
                e2e.cubeproof(
                    "shard",
                    "--campaign",
                    str(campaign),
                    "--from-open",
                    str(root / "certify-giver" / "certificate-main.json"),
                    "--journals",
                    str(giver.journal),
                    "--machines",
                    "1",
                    "-o",
                    str(root / "reclaim"),
                )
            )
            planned = sorted(
                n for s in (root / "reclaim").glob("shard-*.json") for n in shard_nodes(s)
            )
            if plan.code != 0 or planned != want_giver:
                sizes = f"{len(planned)} != {len(want_giver)}"
                p.append(f"shard --from-open: exit {plan.code}, planned {sizes}")
            facts["open_alone"] = [len(want_giver), len(want_receiver)]
    # journals, exclusion, work directories, exports
    p += journal_problems(giver, snapshots.get(giver.name, ()))
    p += journal_problems(receiver, snapshots.get(receiver.name, ()))
    p += exclusion_problems(giver, receiver, [*second, *gift])
    p += export_problems(giver) + export_problems(receiver)
    for worker in (giver, receiver):
        if worker.work_files():
            p.append(f"{worker.name}: work files left: {worker.work_files()}")
    # retained proofs (specification §7.2, §11.4)
    if giver.mode == "retain":
        counts = []
        for worker in (giver, receiver):
            missing, count = retained_problems(worker)
            p += missing
            orphans = orphan_proofs(worker)
            if orphans:
                p.append(f"{worker.name}: unreferenced proof files {orphans}")
            done, document = verify_retained(
                campaign, [worker.journal], worker.results, root / f"verify-{worker.name}", tools
            )
            counts.append(document)
            if (
                done.code != 0
                or document is None
                or document["verified"] != count
                or document["missing"]
            ):
                p.append(f"{worker.name}: verify-retained exit {done.code}: {document}")
        facts["verify_retained"] = counts
    # strict recompute audit of the final certificate (specification §11)
    done, document = audit(
        campaign,
        root / "certify-final" / "certificate-main.json",
        journals,
        root / "audit",
        tools,
        sample=audit_sample,
    )
    summary = (document or {}).get("summary") or {}
    facts["audit"] = {"exit": done.code, "summary": summary}
    population = summary.get("population")
    if not cert["used_attempts"]:
        # no closed formula or root: an explicit empty audit, exit 1, never a vacuous match
        if done.code != 1 or population != 0 or summary.get("strict_success"):
            p.append(f"empty audit population: exit {done.code}: {summary or done.err.strip()}")
    elif done.code != 0 or not summary.get("strict_success"):
        p.append(f"strict audit exit {done.code}: {summary or done.err.strip()}")
    elif summary["counts"].get("HASH_MATCHED") != summary.get("selected"):
        p.append(f"strict audit: {summary['counts']}")
    elif audit_sample is None and population != len(cert["used_attempts"]):
        p.append(f"strict audit population {population} != {len(cert['used_attempts'])} used")
    facts["leaf_proofs"] = leaf_proofs(journals)
    return found


def certify_both(campaign: Path, journals: Sequence[Path], out: Path) -> e2e.Certified:
    return e2e.certify_both(campaign, journals, out)


# -- scenarios ------------------------------------------------------------------------------------


def reference_run(root: Path, workload: Workload, tools: e2e.Tools) -> dict[str, Any]:
    """One worker, transient, no shard, no interruption: the run-independent content of its
    certificate is the reference of the deterministic workloads."""
    campaign = make_campaign(root, workload, tools, "transient")
    worker = Worker("ref", root / "ref", campaign, tools, "transient")
    end = worker.run()
    certified = certify_both(campaign, [worker.journal], root / "certify")
    problems = [f"reference: {x}" for x in certified.problems()]
    if end.code not in DONE:
        problems.append(f"reference run exit {end.code}: {end.err_tail}")
    if certified.main_bytes is None:
        return {"problems": [*problems, "reference: no certificate"], "semantic": None}
    if certified.verdict != workload.verdict:
        problems.append(f"reference verdict {certified.verdict} != {workload.verdict}")
    return {
        "problems": problems,
        "semantic": e2e.semantic(certified.certificate),
        "verdict": certified.verdict,
        "certificate_sha256": e2e._digest(certified.main_bytes),
        "counts": e2e.outcome_counts(worker.journal),
        "leaf_proofs": leaf_proofs([worker.journal]),
    }


def lifecycle(worker: Worker) -> str | None:
    """The lifecycle of the worker's last published status (specification §12.3), or None."""
    try:
        document = json.loads((worker.results / "status.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    value = document.get("lifecycle")
    return None if value is None else str(value)


def _has_records(worker: Worker, count: int) -> bool:
    return len(worker.records()) >= count


def _attempts_after(worker: Worker, seq: int) -> int:
    return sum(1 for r in worker.records() if r["type"] == "attempt" and r["seq"] > seq)


def cluster_scenario(
    root: Path,
    workload: Workload,
    tools: e2e.Tools,
    mode: str,
    reference: Mapping[str, Any] | None,
) -> dict[str, Any]:
    """The fixed two-worker sequence (module doc) and :func:`final_checks`."""
    problems: list[str] = []
    steps: list[dict[str, Any]] = []
    campaign = make_campaign(root, workload, tools, mode)
    shards = plan_shards(campaign, 2, root / "shards")
    jobs = 3  # the stream mode needs three CPU slots (solver, relay, checker)
    giver = Worker("wa", root / "wa", campaign, tools, mode, shards[0], jobs)
    receiver = Worker("wb", root / "wb", campaign, tools, mode, shards[1], jobs)
    snaps: dict[str, list[Path]] = {giver.name: [], receiver.name: []}

    def step(name: str, end: RunEnd, expect: Sequence[int], landed: bool | None = None) -> None:
        steps.append({"step": name, **end.to_json(), "landed": landed})
        if end.code not in expect:
            problems.append(f"{name}: exit {end.code} not in {list(expect)}: {end.err_tail}")
        if landed is False:
            problems.append(f"{name}: the run ended before the signal")

    # 1. the giver is stopped (SIGINT) after its first committed attempt (stop/resume)
    live = giver.start()
    landed = live.until(
        lambda: (
            (giver.results / "ports.json").exists()
            and any(r["type"] == "attempt" for r in giver.records())
        )
    )
    if landed:
        live.send("SIGINT")
    step("giver stopped (SIGINT)", live.wait(), (STOPPED,) if landed else DONE, landed)
    snaps[giver.name].append(giver.snapshot("stopped"))
    # 2. work is requested from the stopped giver: a durable pending request
    asked = giver.handoff(workload.gift, "gift", 0)
    asked_doc = e2e._document(asked.out) or {}
    steps.append(
        {
            "step": "handoff requested while stopped",
            "exit": asked.code,
            "state": asked_doc.get("state"),
        }
    )
    if asked.code != 0 or asked_doc.get("state") != "pending":
        problems.append(f"handoff request: exit {asked.code} state {asked_doc.get('state')}")
    # 3. the giver restarts, commits the handoff and crashes right after the commit
    live = giver.start()
    landed = live.until(lambda: bool(giver.handoffs()))
    if landed:
        live.send("SIGKILL")
    step(
        "giver crashed after the handoff commit (SIGKILL)",
        live.wait(),
        (-signal.SIGKILL,) if landed else DONE,
        landed,
    )
    output_after_crash = (giver.outbox / "gift.json").exists()
    snaps[giver.name].append(giver.snapshot("after-handoff-crash"))
    # 4. the giver restarts (it republishes a missing output before anything else) and runs on
    live_giver = giver.start()
    output = giver.outbox / "gift.json"
    published = live_giver.until(output.exists, 120.0) or output.exists()
    answer = giver.handoff(workload.gift, "gift", 30_000)
    answer_doc = e2e._document(answer.out) or {}
    steps.append(
        {
            "step": "handoff answered",
            "exit": answer.code,
            "state": answer_doc.get("state"),
            "same_request": (answer_doc.get("request") or {}).get("request_id")
            == (asked_doc.get("request") or {}).get("request_id"),
            "output_existed_after_crash": output_after_crash,
            "output_published": published,
        }
    )
    if answer.code != 0 or answer_doc.get("state") != "completed":
        problems.append(f"handoff answer: exit {answer.code} state {answer_doc.get('state')}")
    if not steps[-1]["same_request"]:
        problems.append("the repeated handoff command made a second request")
    # 5. the published shard is delivered; the receiver commits it and crashes after more work
    delivered = deliver(giver, receiver)
    if delivered is None:
        problems.append("no handoff output to deliver")
    live = receiver.start()
    landed = live.until(
        lambda: (
            len(receiver.shard_hashes()) == (2 if delivered else 1)
            and _attempts_after(
                receiver, max(r["seq"] for r in receiver.records() if r["type"] == "shard")
            )
            >= 1
        )
    )
    if landed:
        live.send("SIGKILL")
    step(
        "receiver crashed after the shard commit (SIGKILL)",
        live.wait(),
        (-signal.SIGKILL,) if landed else DONE,
        landed,
    )
    snaps[receiver.name].append(receiver.snapshot("after-shard-crash"))
    # 6. both finish
    receiver_end = receiver.start().wait()
    giver_end = live_giver.wait()
    step("receiver completed", receiver_end, DONE)
    step("giver completed", giver_end, DONE)
    if delivered is not None and delivered.exists():
        problems.append("the delivered shard is still in the receiver's inbox")
    accepted = sorted(p.name for p in (receiver.inbox / "accepted").glob("*")) if delivered else []
    final = final_checks(root, workload, tools, campaign, giver, receiver, shards, snaps, reference)
    return {
        "scenario": "cluster",
        "workload": workload.name,
        "tools": tools.kind,
        "mode": mode,
        "steps": steps,
        "accepted": accepted,
        "counts": {w.name: e2e.outcome_counts(w.journal) for w in (giver, receiver)},
        "starts": {w.name: w.starts for w in (giver, receiver)},
        **final.facts,
        "problems": problems + final.problems,
    }


def random_crash_scenario(
    root: Path,
    workload: Workload,
    tools: e2e.Tools,
    seed: int,
    reference: Mapping[str, Any] | None,
    *,
    modes: Sequence[str] = MODES,
    audit_sample: int | None = 3,
) -> dict[str, Any]:
    """Two workers at the same time; one to four interruptions of a random worker after a
    random number of further records (SIGKILL of the process group, a crash, eight times in
    ten; SIGTERM or SIGINT otherwise), a handoff request at a random moment, restarts until
    both finished with the delivered work; then :func:`final_checks`.

    A stopped run must exit 130 (or end normally if the signal came with its last step). A
    SIGTERM/SIGINT that reaches a run after it ended -- its last status says ``stopped`` and it
    has restored the default handlers while the interpreter exits -- takes the default action;
    that is recorded as ``after_the_end``, not as a problem (the durability checks still run)."""
    rng = random.Random(seed)
    mode = rng.choice(list(modes))
    problems: list[str] = []
    events: list[dict[str, Any]] = []
    campaign = make_campaign(root, workload, tools, mode)
    shards = plan_shards(campaign, 2, root / "shards")
    giver = Worker("wa", root / "wa", campaign, tools, mode, shards[0], 3)
    receiver = Worker("wb", root / "wb", campaign, tools, mode, shards[1], 3)
    workers = (giver, receiver)
    snaps: dict[str, list[Path]] = {w.name: [] for w in workers}
    gift = rng.randint(1, 3)
    request_after = rng.randint(0, 6)  # records of the giver before the request
    kills = rng.randint(1, 4)
    live: dict[str, Live | None] = {w.name: w.start() for w in workers}
    requested = delivered = False
    deadline = time.monotonic() + 600.0

    def accepted_gift() -> bool:
        records = giver.handoffs()
        if not records or records[0]["shard"] is None:
            return True
        return str(records[0]["shard_sha256"]) in receiver.shard_hashes()

    while time.monotonic() < deadline:
        if (
            not requested
            and (giver.results / "ports.json").exists()
            and len(giver.records()) >= request_after
        ):
            asked = giver.handoff(gift, "gift", 0)
            requested = asked.code == 0
            events.append(
                {"event": "request", "exit": asked.code, "giver_records": len(giver.records())}
            )
        if not delivered and deliver(giver, receiver) is not None:
            delivered = True
            events.append({"event": "delivered", "receiver_records": len(receiver.records())})
        running = [w for w in workers if live[w.name] is not None and live[w.name].alive()]  # type: ignore[union-attr]
        if kills and running:
            victim = rng.choice(running)
            process = live[victim.name]
            assert process is not None
            target = len(victim.records()) + rng.randint(1, 8)
            process.until(partial(_has_records, victim, target), 60.0)
            how = rng.choices(["SIGKILL", "SIGTERM", "SIGINT"], weights=[8, 1, 1])[0]
            last = (
                victim.records()[-1]["type"]
                if victim.journal.exists() and victim.records()
                else None
            )
            sent = process.send(how)
            end = process.wait()
            victim.ends.append(end)
            kills -= 1
            events.append(
                {
                    "event": "interrupt",
                    "worker": victim.name,
                    "signal": how if sent else None,
                    "after": last,
                    **end.to_json(),
                }
            )
            if sent:
                snaps[victim.name].append(victim.snapshot(f"kill-{len(events)}"))
                # a stop signal that arrives after the run ended (status "stopped", its handlers
                # restored) while the interpreter exits takes the default action: not a stop
                late = how != "SIGKILL" and end.code == -int(getattr(signal, how))
                late = late and lifecycle(victim) == "stopped"
                events[-1]["after_the_end"] = late
                expected = (-signal.SIGKILL,) if how == "SIGKILL" else (STOPPED, *DONE)
                if end.code not in expected and end.code not in DONE and not late:
                    problems.append(f"{victim.name} {how}: exit {end.code}: {end.err_tail}")
            elif end.code not in DONE:
                problems.append(f"{victim.name}: exit {end.code}: {end.err_tail}")
            live[victim.name] = victim.start()
            continue
        for worker in workers:
            process = live[worker.name]
            if process is not None and not process.alive():
                end = process.wait()
                worker.ends.append(end)
                live[worker.name] = None
                events.append({"event": "ended", "worker": worker.name, **end.to_json()})
                if end.code not in DONE:
                    problems.append(f"{worker.name}: exit {end.code}: {end.err_tail}")
        if all(live[w.name] is None for w in workers):
            if not requested or not giver.handoffs():
                live[giver.name] = (
                    giver.start()
                )  # a stopped worker serves a request at its next run
            elif not accepted_gift():
                if not delivered and deliver(giver, receiver) is not None:
                    delivered = True
                live[receiver.name] = receiver.start()
            else:
                break
        time.sleep(0.05)
    else:
        problems.append("the scenario did not finish in 600 s")
        for worker in workers:
            process = live[worker.name]
            if process is not None:
                process.send("SIGKILL")
                process.wait()
    final = final_checks(
        root,
        workload,
        tools,
        campaign,
        giver,
        receiver,
        shards,
        snaps,
        reference,
        audit_sample=audit_sample,
        seed=seed,
    )
    return {
        "scenario": "random-crash",
        "seed": seed,
        "workload": workload.name,
        "tools": tools.kind,
        "mode": mode,
        "gift_requested": gift,
        "events": events,
        "starts": {w.name: w.starts for w in workers},
        "counts": {w.name: e2e.outcome_counts(w.journal) for w in workers},
        **{k: v for k, v in final.facts.items() if k != "leaf_proofs"},
        "problems": problems + final.problems,
    }


def keep_evidence(name: str, record: Mapping[str, Any]) -> None:
    """Write a scenario record to ``$E2E_CLUSTER_EVIDENCE/<name>.json`` when the variable is set."""
    directory = os.environ.get("E2E_CLUSTER_EVIDENCE")
    if directory:
        e2e.write_json(Path(directory) / f"{name}.json", record)


__all__ = [
    "DONE",
    "MODES",
    "STOPPED",
    "Final",
    "Live",
    "Node",
    "RunEnd",
    "Worker",
    "Workload",
    "audit",
    "canonical_dimacs",
    "cluster_scenario",
    "cnf_model",
    "common_leaf_problems",
    "decode_assignment",
    "deliver",
    "e2e",
    "exclusion_problems",
    "export_problems",
    "fake_workloads",
    "final_checks",
    "handoff_output_problems",
    "keep_evidence",
    "leaf_proofs",
    "make_campaign",
    "node_key",
    "nodes_of",
    "orphan_proofs",
    "pinned_workloads",
    "plan_shards",
    "random_3cnf",
    "random_crash_scenario",
    "reference_run",
    "retained_problems",
    "satisfiable",
    "shard_nodes",
    "truth_problems",
    "verify_retained",
    "within",
]
