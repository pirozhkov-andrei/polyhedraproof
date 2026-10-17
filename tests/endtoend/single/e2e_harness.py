"""Harness of the single-worker end-to-end tests (specification §10, §11, §15).

Every step goes through the public command line, in child processes, exactly as an operator
runs it: ``python -m cubeproof campaign create`` / ``run`` / ``certify`` for the main
implementation and ``python tools/certify_min.py certify`` for the independent certifier
(used as a black box). Nothing here imports the coordinator or a certifier.

- :class:`Tools` are either the fake pinned tools of the cubeproof lifecycle tests (a brute-force
  solver with LRAT proofs and the ``fakes.lrat_check`` validator, copied from
  ``cp_life_solver.py`` as executables; test doubles only) or the pinned CaDiCaL and
  cake_lpr of the test image (``POLYHEDRAPROOF_TEST_TOOLS``, verified by ``image.pinned``).
- :class:`Workload` is a campaign: bundles, requested roots, policy and the verdict and root
  closure a complete run must certify.
- :class:`Campaign` creates the campaign, runs workers (to the end, or interrupted by a signal
  or a SIGKILL of the whole process group after a number of committed attempts) and
  certifies the journal with both certifiers.
- :func:`semantic` is the run-independent view used to compare runs: verdict, per-formula
  proof state and root summaries (with Merkle roots), the selected evidence (node, CNF hash,
  proof hash, route of every used leaf) and both open lists. Journal IDs, Refs, timestamps
  and machinery are excluded because two runs never share them.
- :func:`resume_invariants` lists the violations of the restart contract (specification §7.3,
  §7.5): the journal after a restart extends the interrupted one byte for byte, one
  ``resume`` per restart, unique attempt IDs, nothing proved twice, no split repeated.

Long runs belong in a directory outside the checkout; the tests use ``tmp_path``.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import signal
import subprocess
import sys
import time
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from cubeproof.cnf.bundle import publish_bundle
from cubeproof.cnf.dimacs import canonical_dimacs
from cubeproof.contracts.policy import HeapFit, Policy, default_policy
from cubeproof.tools.isolation import PinnedBinary

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
SRC = REPO / "packages" / "cubeproof" / "src"
TESTS = REPO / "tests"
CERTIFY_MIN = REPO / "tools" / "certify_min.py"
FAKE_TOOL = REPO / "packages" / "cubeproof" / "tests" / "lifecycle" / "cp_life_solver.py"
PREFIX_CASES = TESTS / "contracts" / "corpus" / "prefix_cases"

MIB = 1 << 20
GIB = 1 << 30
VERDICT_EXIT = {"PROVED": 0, "OPEN": 1, "MODEL_FOUND": 2, "INCONSISTENT": 4}


# -- processes ------------------------------------------------------------------------------------


def child_env() -> dict[str, str]:
    """This interpreter's environment plus the package sources (no installation needed)."""
    env = dict(os.environ)
    old = env.get("PYTHONPATH")
    env["PYTHONPATH"] = str(SRC) if not old else f"{SRC}{os.pathsep}{old}"
    return env


@dataclass(frozen=True)
class Completed:
    """A finished command: argv, exit code, output text and its duration."""

    argv: tuple[str, ...]
    code: int
    out: str
    err: str
    seconds: float

    def to_json(self) -> dict[str, Any]:
        return {
            "argv": list(self.argv),
            "exit": self.code,
            "stdout": self.out,
            "stderr": self.err,
            "seconds": round(self.seconds, 3),
        }


def execute(argv: Sequence[str], *, timeout_s: float = 600.0) -> Completed:
    start = time.monotonic()
    done = subprocess.run(
        list(argv),
        env=child_env(),
        capture_output=True,
        text=True,
        timeout=timeout_s,
        check=False,
    )
    return Completed(
        tuple(argv), done.returncode, done.stdout, done.stderr, time.monotonic() - start
    )


def cubeproof(*args: str) -> list[str]:
    return [sys.executable, "-m", "cubeproof", *args]


# -- tools ----------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Tools:
    """A solver and checker pair, the solver argv of the campaign and an optional helper."""

    kind: str  # "fake" or "pinned"
    solver: Path
    checker: Path
    solver_argv: tuple[str, ...]
    helper: Path | None = None

    def configure_fake(self, **settings: Any) -> None:
        """Set the behaviour of the fake tools (their pinned hash does not change)."""
        if self.kind != "fake":
            raise ValueError("only the fake tools are configurable")
        values = {"tests": str(TESTS), **settings}
        Path(f"{self.solver}.json").write_text(json.dumps(values), encoding="utf-8")


def fake_tools(directory: Path, **solver: Any) -> Tools:
    """The fake ``cadical`` and ``cake_lpr`` below ``directory`` (test doubles)."""
    directory.mkdir(parents=True, exist_ok=True)
    body = FAKE_TOOL.read_text(encoding="utf-8")
    paths: dict[str, Path] = {}
    for name in ("cadical", "cake_lpr"):
        path = directory / name
        path.write_text(f"#!{sys.executable} -I\n{body}", encoding="utf-8")
        path.chmod(0o755)
        paths[name] = path
    Path(f"{paths['cake_lpr']}.json").write_text(json.dumps({"tests": str(TESTS)}), "utf-8")
    tools = Tools("fake", paths["cadical"], paths["cake_lpr"], ("--lrat",))
    tools.configure_fake(**solver)
    return tools


def pinned_tools(prefix: Path, helper: Path | None = None) -> Tools:
    """The pinned CaDiCaL and cake_lpr of a verified prefix (``image.pinned.locate``)."""
    return Tools(
        "pinned", prefix / "bin" / "cadical", prefix / "bin" / "cake_lpr", ("-q", "--lrat"), helper
    )


# -- formulas -------------------------------------------------------------------------------------


def sat_formula() -> bytes:
    """Satisfiable, six variables."""
    return canonical_dimacs(6, [(1, 2, 3), (-1, -2), (4, 5, 6), (-4, -5)])


def unsat_formula(total: int = 5, core: int = 3) -> bytes:
    """Every sign combination of variables ``1..core`` plus a clause over the others."""
    clauses: list[tuple[int, ...]] = []
    for bits in range(1 << core):
        clauses.append(tuple(v if bits >> (v - 1) & 1 else -v for v in range(1, core + 1)))
    if total > core:
        clauses.append(tuple(range(core + 1, total + 1)))
    return canonical_dimacs(total, clauses)


def up_formula() -> bytes:
    """Refuted by unit propagation alone: 1, 1 -> 2, 2 -> 3, not (3 and 1)."""
    return canonical_dimacs(4, [(1,), (-1, 2), (-2, 3), (-3, -1), (1, 4)])


def pigeonhole_formula(holes: int) -> bytes:
    """``holes + 1`` pigeons in ``holes`` holes (unsatisfiable)."""
    pigeons = holes + 1

    def var(pigeon: int, hole: int) -> int:
        return pigeon * holes + hole + 1

    clauses: list[tuple[int, ...]] = [
        tuple(var(p, h) for h in range(holes)) for p in range(pigeons)
    ]
    for h in range(holes):
        for p in range(pigeons):
            for q in range(p + 1, pigeons):
                clauses.append((-var(p, h), -var(q, h)))
    return canonical_dimacs(pigeons * holes, clauses)


def map2_base() -> tuple[bytes, dict[str, Any]]:
    """The map 2 base formula of the frozen prefix-case corpus and its entry."""
    import lzma

    cases = json.loads((PREFIX_CASES / "cases.json").read_text(encoding="utf-8"))
    entry = next(b for b in cases["bases"] if b["map"] == 2)
    data = lzma.decompress((PREFIX_CASES.parent / entry["file"]).read_bytes())
    if hashlib.sha256(data).hexdigest() != entry["formula_sha256"]:
        raise ValueError("map 2 base formula does not match its recorded hash")
    return data, entry


def map2_case(index: int) -> dict[str, Any]:
    """A prefix case of map 2 (cube in canonical order, specification §3.3)."""
    cases = json.loads((PREFIX_CASES / "cases.json").read_text(encoding="utf-8"))
    found: dict[str, Any] = next(c for c in cases["cases"] if (c["map"], c["index"]) == (2, index))
    return found


# -- policies -------------------------------------------------------------------------------------


def fake_policy(split_vars: int = 2, **changes: Any) -> Policy:
    """Small caps and short times for the fake tools."""
    base = default_policy("transient")
    values: dict[str, Any] = {
        "leaf_time_ms": {"default": 60_000},
        "proof_cap_bytes": 64 * MIB,
        # as in cp_life_tools.make_policy: a solve of the scripted tools reserves 192 MiB
        "solver_memory_bytes": 128 * MIB,
        "checker_stack_mib": 16,
        "checker_max_stack_mib": 64,
        "checker_slack_mib": 16,
        "checker_time_base_ms": 30_000,
        "heap_fit": HeapFit(min_mib=64),
        "term_grace_ms": 500,
        "stop_grace_ms": 1_000,
        "tool_retries": 1,
        "machine_failure_limit": 3,
        "anomaly_limit": 2,
        "split": replace(base.split, vars=split_vars, wall_ms=60_000),
    }
    values.update(changes)
    return replace(base, **values)


def pinned_policy(
    split_vars: int = 2,
    root_deadline_ms: int | None = None,
    leaf_default_ms: int = 120_000,
    **changes: Any,
) -> Policy:
    """Real tools on tiny formulas: generous checker settings, an optional short root deadline
    (a solver deadline at the empty cube forces a split, as in the cubeproof lifecycle image
    test)."""
    base = default_policy("transient")
    leaf: dict[str, int] = {"default": leaf_default_ms}
    if root_deadline_ms is not None:
        leaf["0"] = root_deadline_ms
    values: dict[str, Any] = {
        "leaf_time_ms": leaf,
        "proof_cap_bytes": 256 * MIB,
        "solver_memory_bytes": 1 * GIB,
        "checker_stack_mib": 256,
        "checker_max_stack_mib": 2048,
        "checker_slack_mib": 256,
        "checker_time_base_ms": 120_000,
        "term_grace_ms": 2_000,
        "stop_grace_ms": 5_000,
        "split": replace(base.split, vars=split_vars, wall_ms=60_000),
    }
    values.update(changes)
    return replace(base, **values)


# -- workloads ------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Workload:
    """A campaign to create and run, and what a complete run must certify.

    ``roots`` are ``(formula key, cube)`` pairs (None: every empty cube); ``closed`` lists the
    expected ``closed`` flag of each requested root in certificate order.
    """

    name: str
    formulas: Mapping[str, bytes]
    verdict: str
    roots: tuple[tuple[str, tuple[int, ...]], ...] | None = None
    closed: tuple[bool, ...] | None = None
    proved: Mapping[str, bool] = field(default_factory=dict)
    fake_solver: Mapping[str, Any] = field(default_factory=dict)
    routes: frozenset[str] = frozenset()
    #: pinned tools: a solver deadline at the empty cube (forces a split there), or None
    root_deadline_ms: int | None = None
    #: pinned tools: the solver deadline at every other depth
    leaf_default_ms: int = 120_000
    #: False when the tree depends on timing (short deadlines at every depth): two runs then
    #: agree on verdict and closure, not necessarily on the selected leaves
    deterministic: bool = True

    def policy(self, kind: str) -> Policy:
        if kind == "fake":
            return fake_policy()
        return pinned_policy(
            2, root_deadline_ms=self.root_deadline_ms, leaf_default_ms=self.leaf_default_ms
        )


def tiny_workloads(kind: str) -> dict[str, Workload]:
    """The tiny complete workloads for fake or pinned tools."""
    php = pigeonhole_formula(3 if kind == "fake" else 8)
    # fake: the solver runs out of memory above ten free variables; pinned: 100 ms at the root
    split: dict[str, Any] = {"max_free": 10} if kind == "fake" else {}
    deadline = None if kind == "fake" else 100
    items = [
        Workload("sat", {"sat": sat_formula()}, "MODEL_FOUND", proved={"sat": False}),
        Workload(
            "unsat",
            {"unsat": unsat_formula()},
            "PROVED",
            proved={"unsat": True},
            routes=frozenset({"cdcl"}),
        ),
        Workload(
            "up", {"up": up_formula()}, "PROVED", proved={"up": True}, routes=frozenset({"unit"})
        ),
        Workload(
            "php",
            {"php": php},
            "PROVED",
            proved={"php": True},
            fake_solver=split,
            routes=frozenset({"cdcl"}),
            root_deadline_ms=deadline,
        ),
        Workload(
            "mixed",
            {"a-sat": sat_formula(), "b-php": php, "c-up": up_formula()},
            "MODEL_FOUND",
            proved={"a-sat": False, "b-php": True, "c-up": True},
            fake_solver=split,
            root_deadline_ms=deadline,
        ),
        Workload(
            "pilot",
            {"php": php},
            "OPEN",
            roots=(("php", (1,)),),
            closed=(True,),
            proved={"php": False},
            fake_solver=split,
        ),
    ]
    return {w.name: w for w in items}


def interrupt_workload(kind: str) -> Workload:
    """A workload with enough attempts to interrupt a run in the middle.

    Fake tools: eight variables with a five-variable unsatisfiable core; the solver runs out
    of memory while more than three variables are free, so the root and four children split
    and sixteen grandchildren are refuted (the ``DEEP`` formula of the cubeproof command-line
    tests), each solve slowed down a little.
    Pinned tools: pigeonhole 9 with a 100 ms root deadline and two split variables.
    """
    if kind == "fake":
        return Workload(
            "deep",
            {"deep": unsat_formula(8, core=5)},
            "PROVED",
            proved={"deep": True},
            fake_solver={"max_free": 3, "sleep": 0.15},
        )
    return Workload(
        "php9",
        {"php9": pigeonhole_formula(9)},
        "PROVED",
        proved={"php9": True},
        routes=frozenset({"cdcl"}),
        root_deadline_ms=100,
    )


def tree_workloads() -> dict[str, Workload]:
    """Pinned tools only: real proof trees of a few hundred leaves (pigeonhole 10, 1 s solver
    deadline at every depth, two split variables), the whole formula and a nonempty requested
    root that closes while the formula stays unproved (specification §10.2). Timing-dependent
    trees."""
    php = pigeonhole_formula(10)
    items = [
        Workload(
            "php10-tree",
            {"php10": php},
            "PROVED",
            proved={"php10": True},
            routes=frozenset({"cdcl"}),
            leaf_default_ms=1_000,
            deterministic=False,
        ),
        Workload(
            "php10-pilot",
            {"php10": php},
            "OPEN",
            roots=(("php10", (1,)),),
            closed=(True,),
            proved={"php10": False},
            routes=frozenset({"cdcl"}),
            leaf_default_ms=1_000,
            deterministic=False,
        ),
    ]
    return {w.name: w for w in items}


# -- certificates ---------------------------------------------------------------------------------


@dataclass(frozen=True)
class Certified:
    """Both certifiers on the same journals: their exit codes, documents and comparison."""

    main: Completed
    independent: Completed
    compare: Completed | None
    main_bytes: bytes | None
    independent_bytes: bytes | None

    @property
    def certificate(self) -> dict[str, Any]:
        if self.main_bytes is None:
            raise AssertionError(f"no main certificate: {self.main.err}")
        loaded: dict[str, Any] = json.loads(self.main_bytes)
        return loaded

    @property
    def verdict(self) -> str:
        return str(self.certificate["verdict"])

    def problems(self) -> list[str]:
        """Disagreements of the two certifiers (empty when they agree)."""
        found = []
        if self.main.code != self.independent.code:
            found.append(f"exit codes differ: main {self.main.code}, min {self.independent.code}")
        if self.main_bytes != self.independent_bytes:
            found.append("certificate bytes differ")
        if self.compare is not None and self.compare.code != 0:
            found.append(f"certify_min compare: exit {self.compare.code} {self.compare.out}")
        if self.main_bytes is not None and self.independent_bytes is not None:
            left = semantic(json.loads(self.main_bytes))
            right = semantic(json.loads(self.independent_bytes))
            for key in left:
                if left[key] != right.get(key):
                    found.append(f"semantic field {key} differs")
        return found


def certify_both(campaign: Path, journals: Sequence[Path], out: Path) -> Certified:
    """``cubeproof certify`` and ``certify_min.py certify`` on the same inputs, then
    ``certify_min.py compare`` of the two documents (when both were produced)."""
    out.mkdir(parents=True, exist_ok=True)
    main_path, min_path = out / "certificate-main.json", out / "certificate-min.json"
    for stale in (main_path, min_path):
        stale.unlink(missing_ok=True)
    names = [str(j) for j in journals]
    main = execute(
        cubeproof(
            "certify", "--campaign", str(campaign), "--journals", *names, "-o", str(main_path)
        )
    )
    independent = execute(
        [
            sys.executable,
            str(CERTIFY_MIN),
            "certify",
            "--campaign",
            str(campaign),
            "--journals",
            *names,
            "-o",
            str(min_path),
        ]
    )
    main_bytes = main_path.read_bytes() if main_path.exists() else None
    min_bytes = min_path.read_bytes() if min_path.exists() else None
    compare = None
    if main_bytes is not None and min_bytes is not None:
        compare = execute(
            [sys.executable, str(CERTIFY_MIN), "compare", str(main_path), str(min_path)]
        )
    return Certified(main, independent, compare, main_bytes, min_bytes)


def _node(entry: Mapping[str, Any]) -> tuple[str, tuple[int, ...]]:
    node = entry["node"]
    return (str(node["formula_sha256"]), tuple(int(x) for x in node["cube"]))


def semantic(certificate: Mapping[str, Any]) -> dict[str, Any]:
    """The run-independent content of a certificate (module doc)."""
    return {
        "verdict": certificate["verdict"],
        "formulas": [
            {
                "key": f["key"],
                "formula_sha256": f["formula_sha256"],
                "proved": f["proved"],
                "summary": f["summary"],
                "roots": f["roots"],
            }
            for f in certificate["formulas"]
        ],
        "merkle": [
            [f["key"], (f["summary"] or {}).get("leaf_merkle_root")]
            for f in certificate["formulas"]
        ],
        "selected": sorted(
            (u["node_id"], u["cnf_sha256"], u["proof_sha256"], u["route"])
            for u in certificate["used_attempts"]
        ),
        "open": [(*_node(o), o["node_id"], o["state"]) for o in certificate["open"]],
        "formula_open": [
            (*_node(o), o["node_id"], o["state"]) for o in certificate["formula_open"]
        ],
        "models": sorted(
            (*_node(m), base64.b64decode(m["assignment"]).hex()) for m in certificate["models"]
        ),
        "anomalies": certificate["anomalies"],
    }


# -- journals -------------------------------------------------------------------------------------


def complete_lines(path: Path) -> bytes:
    """The bytes of a journal up to its last LF (a torn tail removed)."""
    data = path.read_bytes() if path.exists() else b""
    return data[: data.rfind(b"\n") + 1]


def records(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in complete_lines(path).splitlines()]


def attempts(path: Path) -> list[dict[str, Any]]:
    return [r for r in records(path) if r["type"] == "attempt"]


def outcome_counts(path: Path) -> dict[str, int]:
    """Attempt outcomes (and route of the verified ones) of a journal, plus record types."""
    counts: Counter[str] = Counter()
    for record in records(path):
        counts[f"record:{record['type']}"] += 1
        if record["type"] == "attempt":
            counts[f"outcome:{record['outcome']}"] += 1
            if record["outcome"] == "VERIFIED_UNSAT":
                counts[f"verified:{record['route']}"] += 1
    return dict(sorted(counts.items()))


def checked_leaves(path: Path) -> list[dict[str, Any]]:
    """VERIFIED_UNSAT attempts whose last check is the exact successful checker run."""
    found = []
    for attempt in attempts(path):
        if attempt["outcome"] != "VERIFIED_UNSAT" or not attempt.get("checks"):
            continue
        result = attempt["checks"][-1]["result"]
        if result.get("exit") == 0 and "s VERIFIED UNSAT" in str(result.get("stdout_tail", "")):
            found.append(attempt)
    return found


def _node_key(record: Mapping[str, Any]) -> tuple[str, tuple[int, ...]]:
    node = record["node"]
    return (str(node["formula_sha256"]), tuple(node["cube"]))


def resume_invariants(before: bytes, after: Path, restarts: int) -> list[str]:
    """Violations of the restart contract (module doc); ``before`` is the interrupted journal."""
    problems = []
    data = complete_lines(after)
    prefix = before[: before.rfind(b"\n") + 1]
    if not data.startswith(prefix):
        problems.append("the restarted journal does not extend the interrupted one byte for byte")
    rows = records(after)
    kinds = [r["type"] for r in rows]
    if kinds.count("header") != 1:
        problems.append(f"{kinds.count('header')} header records")
    if kinds.count("resume") != restarts:
        problems.append(f"{kinds.count('resume')} resume records for {restarts} restarts")
    if [r["seq"] for r in rows] != list(range(len(rows))):
        problems.append("seq is not contiguous from 0")
    ids = [r["attempt_id"] for r in rows if r["type"] == "attempt"]
    if len(ids) != len(set(ids)):
        problems.append("an attempt ID occurs twice")
    proved = Counter(
        _node_key(r) for r in rows if r["type"] == "attempt" and r["outcome"] == "VERIFIED_UNSAT"
    )
    twice = [k for k, n in proved.items() if n > 1]
    if twice:
        problems.append(f"{len(twice)} nodes proved more than once")
    splits = Counter((_node_key(r), tuple(r["variables"])) for r in rows if r["type"] == "split")
    again = [k for k, n in splits.items() if n > 1]
    if again:
        problems.append(f"{len(again)} splits recorded more than once")
    return problems


# -- campaigns and runs ----------------------------------------------------------------------------


@dataclass(frozen=True)
class RunOutcome:
    """A finished (or interrupted) ``cubeproof run``: the process and its result document."""

    completed: Completed
    document: dict[str, Any] | None
    interrupted_after: int | None = None
    signal_sent: str | None = None

    @property
    def code(self) -> int:
        return self.completed.code

    def to_json(self) -> dict[str, Any]:
        return {
            **self.completed.to_json(),
            "document": self.document,
            "interrupted_after_attempts": self.interrupted_after,
            "signal": self.signal_sent,
        }


@dataclass
class Campaign:
    """A campaign directory with its bundles, results and work directories."""

    root: Path
    tools: Tools
    path: Path
    worker: str = "w1"
    jobs: int | None = 2
    extra_run_args: tuple[str, ...] = ()

    @property
    def results(self) -> Path:
        return self.root / "results"

    @property
    def work(self) -> Path:
        return self.root / "work"

    @property
    def journal(self) -> Path:
        return self.results / "journal.jsonl"

    def run_argv(self, max_hours: float | None = None) -> list[str]:
        argv = cubeproof(
            "run",
            "--campaign",
            str(self.path),
            "--results",
            str(self.results),
            "--work",
            str(self.work),
            "--worker",
            self.worker,
            "--solver",
            str(self.tools.solver),
            "--checker",
            str(self.tools.checker),
        )
        if self.tools.helper is not None:
            argv += ["--helper", str(self.tools.helper)]
        if self.jobs is not None:
            argv += ["--jobs", str(self.jobs)]
        if max_hours is not None:
            argv += ["--max-hours", repr(max_hours)]
        return argv + list(self.extra_run_args)

    def run(self, *, timeout_s: float = 600.0, max_hours: float | None = None) -> RunOutcome:
        """One worker until it ends by itself."""
        done = execute(self.run_argv(max_hours), timeout_s=timeout_s)
        return RunOutcome(done, _document(done.out))

    def run_interrupted(
        self,
        after_attempts: int,
        how: str,
        *,
        timeout_s: float = 600.0,
        max_wait_s: float | None = None,
    ) -> RunOutcome:
        """A worker stopped by ``how`` (``SIGINT``, ``SIGTERM`` or ``SIGKILL`` of its whole
        process group, i.e. a crash) once the journal holds ``after_attempts`` attempt
        records, or after ``max_wait_s`` seconds, whichever comes first.

        ``SIGKILL`` does not simulate a power loss: the kernel page cache survives, so data
        written but not yet synced is never lost."""
        argv = self.run_argv()
        start = time.monotonic()
        process = subprocess.Popen(
            argv,
            env=child_env(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        seen = 0
        while process.poll() is None:
            seen = len(attempts(self.journal))
            waited = time.monotonic() - start
            if seen >= after_attempts or (max_wait_s is not None and waited >= max_wait_s):
                break
            if waited > timeout_s:
                break
            time.sleep(0.02)
        sent = None
        if process.poll() is None:
            sent = how
            if how == "SIGKILL":
                os.killpg(process.pid, signal.SIGKILL)
            else:
                os.kill(process.pid, getattr(signal, how))
        out, err = process.communicate(timeout=timeout_s)
        done = Completed(tuple(argv), process.returncode, out, err, time.monotonic() - start)
        if how == "SIGKILL":
            self.wait_clean()
        return RunOutcome(done, _document(out), seen, sent)

    def wait_clean(self, timeout_s: float = 30.0) -> None:
        """Until the run lock is free and no process uses the work directory."""
        lock = self.results / "run.lock"
        deadline = time.monotonic() + timeout_s
        while True:
            if not _lock_held(lock) and not _users(self.work):
                return
            if time.monotonic() > deadline:
                raise AssertionError(
                    "the run lock or a process of the dead run survives\n"
                    + survivors_report(lock, self.work)
                )
            time.sleep(0.05)

    def work_files(self) -> list[str]:
        if not self.work.exists():
            return []
        return sorted(p.name for p in self.work.iterdir() if p.name != ".run.lock")

    def certify(self, out: Path, journals: Sequence[Path] | None = None) -> Certified:
        return certify_both(self.path, list(journals or [self.journal]), out)

    def snapshot(self, name: str) -> Path:
        """A byte copy of the journal as it is now (an explicit journal snapshot, specification
        §10.1)."""
        copy = self.root / "snapshots" / f"{name}.jsonl"
        copy.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(self.journal, copy)
        return copy


def _document(out: str) -> dict[str, Any] | None:
    for line in reversed(out.strip().splitlines()):
        if line.startswith("{"):
            try:
                value: dict[str, Any] = json.loads(line)
            except ValueError:
                return None
            return value
    return None


def _lock_held(path: Path) -> bool:
    if not path.exists():
        return False
    import fcntl

    with open(path, "rb") as stream:
        try:
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            return True
        fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
    return False


def _users(directory: Path) -> list[int]:
    """Processes whose working directory or open files lie below ``directory``."""
    if not directory.exists():
        return []
    target = str(directory.resolve())
    found = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit() or int(entry.name) == os.getpid():
            continue
        try:
            links = [os.readlink(entry / "cwd")]
            links += [os.readlink(fd) for fd in (entry / "fd").iterdir()]
        except OSError:
            continue
        if any(link == target or link.startswith(target + os.sep) for link in links):
            found.append(int(entry.name))
    return found


def _process_line(pid: int, lock: Path, work: Path) -> str | None:
    """One line about process ``pid`` for :func:`survivors_report`, None if it is gone."""
    entry = Path("/proc") / str(pid)
    try:
        stat = (entry / "stat").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    # "pid (comm) state ppid pgrp session ..."; comm may contain spaces and parentheses
    comm = stat[stat.find("(") + 1 : stat.rfind(")")]
    fields = stat[stat.rfind(")") + 2 :].split()
    state, ppid, pgid, sid = fields[0], fields[1], fields[2], fields[3]
    starttime = fields[19] if len(fields) > 19 else "?"
    try:
        cmdline = (entry / "cmdline").read_bytes().replace(b"\0", b" ").decode("utf-8", "replace")
    except OSError:
        cmdline = "?"
    try:
        cwd = os.readlink(entry / "cwd")
    except OSError as error:
        cwd = f"?({error.strerror})"
    opened: list[str] = []
    try:
        for fd in sorted((entry / "fd").iterdir(), key=lambda item: int(item.name)):
            try:
                opened.append(f"{fd.name}->{os.readlink(fd)}")
            except OSError:
                continue
    except OSError as error:
        opened.append(f"?({error.strerror})")
    try:  # "nr args... sp pc" of a blocked process ("running" otherwise): where it waits
        waits = (entry / "syscall").read_text(encoding="ascii", errors="replace").split()[:3]
    except OSError as error:
        waits = [f"?({error.strerror})"]
    lock_text, work_text = str(lock.resolve()), str(work.resolve())
    marks = []
    if any(item.split("->", 1)[-1] == lock_text for item in opened):
        marks.append("HAS-RUN-LOCK-OPEN")
    below = [cwd, *(item.split("->", 1)[-1] for item in opened)]
    if any(link == work_text or link.startswith(work_text + os.sep) for link in below):
        marks.append("USES-WORK")
    return (
        f"pid={pid} ppid={ppid} pgid={pgid} sid={sid} state={state} start={starttime} "
        f"comm={comm!r} {' '.join(marks)}\n    cmdline: {cmdline.strip()[:600]}\n"
        f"    cwd: {cwd}\n    syscall: {' '.join(waits)}\n    fds: {' '.join(opened)[:1500]}"
    )


def survivors_report(lock: Path, work: Path) -> str:
    """Everything a failed wait for the end of a killed run needs to be diagnosed: whether the
    run lock is held and by which lock table entries, and every process of this PID namespace
    (pid, parent, process group, session, state -- ``Z`` is a zombie, which holds no file and
    cannot write --, command line, working directory, the system call it waits in, open
    files), with the processes that hold the lock file open or use the work directory marked."""
    lines = [f"run lock {lock}: {'HELD' if _lock_held(lock) else 'free'}"]
    lines.append(f"processes using {work}: {_users(work)}")
    try:
        inode = lock.stat().st_ino
        table = Path("/proc/locks").read_text(encoding="utf-8", errors="replace").splitlines()
        lines += [f"/proc/locks: {row}" for row in table if row.endswith(f":{inode} 0 EOF")]
    except OSError as error:
        lines.append(f"/proc/locks: {error}")
    lines.append(f"this test process: pid={os.getpid()}; every process visible here:")
    pids = sorted(int(e.name) for e in Path("/proc").iterdir() if e.name.isdigit())
    for pid in pids:
        line = _process_line(pid, lock, work)
        if line is not None:
            lines.append(line)
    return "\n".join(lines)


def write_json(path: Path, value: Any) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n", "utf-8")
    return path


def create_campaign(
    root: Path,
    formulas: Mapping[str, bytes],
    tools: Tools,
    policy: Policy,
    *,
    roots: Sequence[tuple[str, Sequence[int]]] | None = None,
    admit_solver: bool = True,
    producer: Mapping[str, Any] | None = None,
) -> tuple[Campaign, Completed]:
    """Bundles, policy/admit/roots files and ``cubeproof campaign create`` below ``root``.

    The admission lists name the checker's hash and, with ``admit_solver``, the solver's hash
    with the campaign argv (specification §10.1: a list makes the solver an admission filter).
    """
    root.mkdir(parents=True, exist_ok=True)
    inputs = root / "inputs"
    hashes: dict[str, str] = {}
    bundles: list[str] = []
    for key, data in sorted(formulas.items()):
        bundle = root / "bundles" / key
        publish_bundle(
            bundle,
            data,
            pools={},
            producer=dict(producer or {"name": "e2e-single", "version": "1", "parameters": {}}),
        )
        hashes[key] = hashlib.sha256(data).hexdigest()
        bundles += ["--bundle", str(bundle)]
    checker = PinnedBinary.measure(str(tools.checker)).sha256
    solvers = None
    if admit_solver:
        solver = PinnedBinary.measure(str(tools.solver)).sha256
        solvers = [{"sha256": solver, "argv": list(tools.solver_argv)}]
    write_json(inputs / "policy.json", policy.to_json())
    write_json(inputs / "admit.json", {"checker_sha256": [checker], "solvers": solvers})
    argv = cubeproof(
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
        "e2e-single",
        "-o",
        str(root / "campaign.json"),
    )
    if roots is not None:
        nodes = [{"formula_sha256": hashes[key], "cube": list(cube)} for key, cube in roots]
        write_json(inputs / "roots.json", {"format": "cubeproof-roots-1", "roots": nodes})
        argv += ["--roots", str(inputs / "roots.json")]
    done = execute(argv)
    return Campaign(root, tools, root / "campaign.json"), done


def workload_campaign(root: Path, workload: Workload, tools: Tools, policy: Policy) -> Campaign:
    """Create the campaign of a workload (AssertionError if ``campaign create`` fails)."""
    if tools.kind == "fake":
        tools.configure_fake(**workload.fake_solver)
    campaign, done = create_campaign(root, workload.formulas, tools, policy, roots=workload.roots)
    if done.code != 0:
        raise AssertionError(f"campaign create failed: {done.err}")
    return campaign


def expectation_problems(workload: Workload, certified: Certified) -> list[str]:
    """What a complete run of ``workload`` must certify, compared with the main certificate."""
    problems = certified.problems()
    if certified.main_bytes is None:
        return [*problems, f"no certificate: {certified.main.err.strip()}"]
    cert = certified.certificate
    if cert["verdict"] != workload.verdict:
        problems.append(f"verdict {cert['verdict']} != {workload.verdict}")
    if certified.main.code != VERDICT_EXIT[workload.verdict]:
        problems.append(f"certify exit {certified.main.code}")
    proved = {f["key"]: f["proved"] for f in cert["formulas"]}
    for key, expected in workload.proved.items():
        if proved.get(key) != expected:
            problems.append(f"formula {key}: proved {proved.get(key)} != {expected}")
    if workload.closed is not None:
        flags = tuple(r["closed"] for f in cert["formulas"] for r in f["roots"])
        if flags != workload.closed:
            problems.append(f"root closure {flags} != {workload.closed}")
    routes = {u["route"] for u in cert["used_attempts"]}
    if not workload.routes <= routes:
        problems.append(f"routes {sorted(routes)} lack {sorted(workload.routes - routes)}")
    if workload.verdict == "PROVED" and (cert["open"] or cert["formula_open"]):
        problems.append("a proved campaign has open nodes")
    return problems


# -- scenarios ------------------------------------------------------------------------------------


def run_exit(workload: Workload) -> int:
    """Exit code of a complete run: 2 with a model, else 0 (requested work done, specification
    §12.2)."""
    return 2 if workload.verdict == "MODEL_FOUND" else 0


def complete_scenario(root: Path, workload: Workload, tools: Tools) -> dict[str, Any]:
    """Create, run to the end and certify with both certifiers; the record with ``problems``."""
    campaign = workload_campaign(root, workload, tools, workload.policy(tools.kind))
    run = campaign.run()
    certified = campaign.certify(root / "certify")
    problems = expectation_problems(workload, certified)
    if run.code != run_exit(workload):
        problems.append(f"run exit {run.code} != {run_exit(workload)}: {run.completed.err}")
    if campaign.work_files():
        problems.append(f"work files left after a complete run: {campaign.work_files()}")
    return {
        "scenario": "complete",
        "workload": workload.name,
        "tools": tools.kind,
        "run_exit": run.code,
        "run_seconds": round(run.completed.seconds, 3),
        "counts": outcome_counts(campaign.journal),
        "certify_exit": [certified.main.code, certified.independent.code],
        "certificate_sha256": _digest(certified.main_bytes),
        "independent_sha256": _digest(certified.independent_bytes),
        "verdict": certified.verdict if certified.main_bytes is not None else None,
        "roots": [
            {"key": f["key"], "proved": f["proved"], "roots": f["roots"]}
            for f in certified.certificate["formulas"]
        ]
        if certified.main_bytes is not None
        else None,
        "problems": problems,
    }


def interrupt_scenario(
    root: Path, workload: Workload, tools: Tools, how: str, after: int
) -> dict[str, Any]:
    """An uninterrupted reference run, and a run stopped by ``how`` after ``after`` attempts
    then restarted to the end: both certifiers on the interrupted prefix, on the final journal
    and on the final journal with the prefix copy (both orders); the restart invariants; the
    final certificate equal to the reference in :func:`semantic` content."""
    policy = workload.policy(tools.kind)
    reference = workload_campaign(root / "reference", workload, tools, policy)
    reference_run = reference.run()
    reference_cert = reference.certify(root / "reference" / "certify")
    problems = [f"reference: {p}" for p in expectation_problems(workload, reference_cert)]
    if reference_run.code != run_exit(workload):
        problems.append(f"reference run exit {reference_run.code}")
    campaign = workload_campaign(root / "interrupted", workload, tools, policy)
    stopped = campaign.run_interrupted(after, how)
    stop_exit = -signal.SIGKILL if how == "SIGKILL" else 130
    if stopped.signal_sent is None:
        problems.append("the run ended before it could be interrupted")
    elif stopped.code != stop_exit:
        problems.append(f"interrupted run exit {stopped.code} != {stop_exit}")
    raw = campaign.journal.read_bytes()
    left_after_stop = campaign.work_files()
    snapshot = campaign.snapshot("interrupted")
    prefix = campaign.certify(root / "interrupted" / "certify-prefix")
    problems += [f"prefix: {p}" for p in prefix.problems()]
    prefix_verdict = prefix.verdict if prefix.main_bytes is not None else None
    if prefix_verdict not in ("OPEN", workload.verdict):
        problems.append(f"prefix verdict {prefix_verdict}")
    finish = campaign.run()
    if finish.code != run_exit(workload):
        problems.append(f"restarted run exit {finish.code}: {finish.completed.err}")
    final = campaign.certify(root / "interrupted" / "certify-final")
    problems += [f"final: {p}" for p in expectation_problems(workload, final)]
    problems += resume_invariants(raw, campaign.journal, 1)
    differs: list[str] = []
    if final.main_bytes is not None and reference_cert.main_bytes is not None:
        mine, theirs = semantic(final.certificate), semantic(reference_cert.certificate)
        differs = [k for k in mine if mine[k] != theirs[k]]
        if workload.deterministic:
            problems += [f"differs from the reference: {k}" for k in differs]
    orders = (("a", [snapshot, campaign.journal]), ("b", [campaign.journal, snapshot]))
    for order, journals in orders:
        copies = campaign.certify(root / "interrupted" / f"certify-copies-{order}", journals)
        problems += [f"copies {order}: {p}" for p in copies.problems()]
        if copies.main_bytes != final.main_bytes:
            problems.append(f"copies {order}: a prefix copy changed the certificate")
    if campaign.work_files():
        problems.append(f"work files left after the restarted run: {campaign.work_files()}")
    return {
        "scenario": "interrupt",
        "workload": workload.name,
        "tools": tools.kind,
        "signal": how,
        "after_attempts": stopped.interrupted_after,
        "stop_exit": stopped.code,
        "stop_result": stopped.document,
        "work_files_after_stop": left_after_stop,
        "torn_tail_bytes": len(raw) - raw.rfind(b"\n") - 1,
        "prefix_verdict": prefix_verdict,
        "prefix_open": len(prefix.certificate["open"]) if prefix.main_bytes is not None else None,
        "restart_exit": finish.code,
        "restart_notes": finish.document.get("notes") if finish.document else None,
        "counts": outcome_counts(campaign.journal),
        "reference_counts": outcome_counts(reference.journal),
        "final_sha256": _digest(final.main_bytes),
        "deterministic": workload.deterministic,
        "differs_from_reference": differs,
        "final_summary": [f["summary"] for f in final.certificate["formulas"]]
        if final.main_bytes is not None
        else None,
        "verdict": final.verdict if final.main_bytes is not None else None,
        "problems": problems,
    }


def _digest(data: bytes | None) -> str | None:
    return None if data is None else hashlib.sha256(data).hexdigest()


def keep_evidence(name: str, record: Mapping[str, Any]) -> None:
    """Write a scenario record to ``$E2E_EVIDENCE/<name>.json`` when that variable is set
    (a directory outside the source tree); otherwise nothing."""
    directory = os.environ.get("E2E_EVIDENCE")
    if directory:
        write_json(Path(directory) / f"{name}.json", record)
