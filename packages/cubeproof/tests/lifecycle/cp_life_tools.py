"""Test-only helpers of the lifecycle tests: tools, formulas, campaigns, runs, journals.

- :func:`install` writes the fake solver and checker (``cp_life_solver.py``) as real executables
  whose behaviour a test changes through :func:`configure` without changing their pinned hash.
- The formulas are canonical DIMACS built here: :func:`unsat` (a three-variable unsatisfiable
  core plus free variables), :func:`sat`; :func:`campaign` publishes bundles and a campaign file
  through the package's own ``create_campaign``.
- :func:`config` builds a :class:`~cubeproof.coordinator.config.RunConfig` with fixed probes (so
  the budgets do not depend on the host's free memory) and the environment the I/O service
  needs; the runner script of this directory executes a run in a child process with a crash
  injected at the n-th occurrence of a lifecycle hook (``RunConfig.hooks``).
- :func:`journal_records`, :func:`summary`, :func:`wait_clean` read what a run left behind.

Nothing here is imported by runtime code.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from cubeproof import api
from cubeproof.base.resources import CpuProbe, MemoryProbe
from cubeproof.base.settings import ToolPaths
from cubeproof.cnf.bundle import publish_bundle
from cubeproof.cnf.dimacs import canonical_dimacs
from cubeproof.commands import SERVICE_COMMAND, CampaignRequest, create_campaign
from cubeproof.contracts.campaign import Admit
from cubeproof.contracts.policy import HeapFit, Policy, default_policy
from cubeproof.coordinator.config import Hooks, RunConfig, RunResult
from cubeproof.coordinator.layout import survivors
from cubeproof.coordinator.resources import SystemProbes
from cubeproof.evidence.certify.run import certify
from cubeproof.evidence.journal import RunLock
from cubeproof.tools.isolation import PinnedBinary

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[3]
SRC = REPO / "packages" / "cubeproof" / "src"
TESTS = REPO / "tests"
RUNNER = HERE / "cp_life_runner.py"
TOOL_SOURCE = HERE / "cp_life_solver.py"

if str(TESTS) not in sys.path:
    sys.path.insert(0, str(TESTS))  # the shared test packages: fakes, image

GIB = 1 << 30
MIB = 1 << 20


# -- tools -------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Tools:
    solver: Path
    checker: Path


def configure(tool: Path, **settings: Any) -> None:
    """Set the behaviour of an installed fake tool (its binary hash does not change)."""
    values = {"tests": str(TESTS), **settings}
    Path(str(tool) + ".json").write_text(json.dumps(values), encoding="utf-8")


def install(directory: Path, *, solver: Mapping[str, Any] | None = None) -> Tools:
    """The fake solver ``cadical`` and checker ``cake_lpr`` below ``directory``."""
    directory.mkdir(parents=True, exist_ok=True)
    body = TOOL_SOURCE.read_text(encoding="utf-8")
    found: dict[str, Path] = {}
    for name in ("cadical", "cake_lpr"):
        path = directory / name
        path.write_text(f"#!{sys.executable} -I\n{body}", encoding="utf-8")
        path.chmod(0o755)
        found[name] = path
    configure(found["cadical"], **(solver or {}))
    configure(found["cake_lpr"])
    return Tools(found["cadical"], found["cake_lpr"])


# -- formulas and campaigns ---------------------------------------------------------------------


def unsat(total: int, core: int = 3) -> bytes:
    """Every sign combination of variables ``1..core`` (unsatisfiable) and one positive clause
    over the remaining variables, so all ``total`` variables occur."""
    clauses: list[tuple[int, ...]] = []
    for bits in range(1 << core):
        clauses.append(tuple(v if bits >> (v - 1) & 1 else -v for v in range(1, core + 1)))
    if total > core:
        clauses.append(tuple(range(core + 1, total + 1)))
    return canonical_dimacs(total, clauses)


def sat(total: int) -> bytes:
    """Satisfiable: one clause over the first three variables, the others free."""
    clauses: list[tuple[int, ...]] = [(1, 2, 3)]
    if total > 3:
        clauses.append(tuple(range(4, total + 1)))
    return canonical_dimacs(total, clauses)


def make_policy(**changes: Any) -> Policy:
    """Small caps and short times for the fake tools; ``changes`` replace fields."""
    values: dict[str, Any] = {
        "leaf_time_ms": {"default": 60_000},
        "proof_cap_bytes": 64 * MIB,
        # with the 64 MiB of overhead a solve reserves 192 MiB instead of 576 MiB: a test
        # that runs the real command needs that much beyond the reserves of the preflight
        # (1 GiB for the system and about 130 MiB for the coordinator and the helper)
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
    }
    values.update(changes)
    return replace(default_policy("transient"), **values)


def split_policy(variables: int = 2, **changes: Any) -> Policy:
    """:func:`make_policy` with ``split.vars`` = ``variables`` and a generous wall budget."""
    base = make_policy(**changes)
    split = replace(base.split, vars=variables, wall_ms=60_000)
    return replace(base, split=split)


def campaign(
    root: Path,
    formulas: Mapping[str, bytes],
    tools: Tools,
    policy: Policy | None = None,
    solver_argv: Sequence[str] = ("--lrat",),
) -> Path:
    """Publish a bundle per formula and a campaign over them under ``root``; its path."""
    root.mkdir(parents=True, exist_ok=True)
    bundles = []
    for name, data in sorted(formulas.items()):
        bundle = root / "bundles" / name
        publish_bundle(
            bundle,
            data,
            pools={},
            producer={"name": "lifecycle-tests", "version": "1", "parameters": {}},
        )
        bundles.append(bundle)
    checker = PinnedBinary.measure(str(tools.checker)).sha256
    admit = Admit.from_json({"checker_sha256": [checker], "solvers": None}, "$")
    path = root / "campaign.json"
    create_campaign(
        CampaignRequest(
            bundles=bundles,
            policy=policy or split_policy(),
            admit=admit,
            solver=str(tools.solver),
            solver_argv=list(solver_argv),
            checker=str(tools.checker),
            output=path,
            author="lifecycle-tests",
        )
    )
    return path


# -- runs ----------------------------------------------------------------------------------------


@dataclass
class FixedProbes(SystemProbes):
    """Real storage and RSS probes, a fixed CPU count and memory headroom."""

    milli: int = 4000
    headroom: int = 8 * GIB

    def cpu(self) -> CpuProbe:
        return CpuProbe(self.milli, {"fixed": self.milli})

    def memory(self) -> MemoryProbe:
        return MemoryProbe("fixed", 16 * GIB, self.headroom, None, None, self.headroom, None, None)


def service_env() -> dict[str, str]:
    """The environment of child processes: this interpreter's, plus the package source."""
    env = dict(os.environ)
    old = env.get("PYTHONPATH")
    env["PYTHONPATH"] = str(SRC) if not old else f"{SRC}{os.pathsep}{old}"
    return env


def config(
    root: Path,
    campaign_path: Path,
    installed: Tools,
    *,
    worker: str = "w1",
    hooks: Hooks | None = None,
    **changes: Any,
) -> RunConfig:
    """A run of ``worker`` with results and work below ``root``."""
    values: dict[str, Any] = {
        "campaign": campaign_path,
        "results": root / "results",
        "work": root / "work",
        "worker": worker,
        "tools": ToolPaths(solver=str(installed.solver), checker=str(installed.checker)),
        "service_argv": SERVICE_COMMAND,
        "service_env": service_env(),
        "probes": FixedProbes(),
        "handle_signals": False,
        "survivor_wait_ms": 2000,
        "tick_ms": 5,
        "hooks": hooks,
        # scripted tools: many tests script a checker that is faulty from its first call, which
        # the known-answer control would stop; the tests of the control turn it on
        "known_answer": False,
    }
    values.update(changes)
    return RunConfig(**values)


def spawn_runner(
    spec_path: Path, *, crash: tuple[str, int] | None = None, trace: Path | None = None
) -> subprocess.Popen[bytes]:
    """Run ``cp_life_runner.py`` on a JSON spec in a child process (module doc)."""
    spec = json.loads(spec_path.read_text(encoding="utf-8"))
    spec["crash"] = None if crash is None else {"point": crash[0], "n": crash[1]}
    spec["trace"] = None if trace is None else str(trace)
    run_spec = spec_path.with_name(f"{spec_path.stem}-{os.urandom(4).hex()}.json")
    run_spec.write_text(json.dumps(spec), encoding="utf-8")
    return subprocess.Popen(
        [sys.executable, str(RUNNER), str(run_spec)],
        env=service_env(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )


def write_spec(root: Path, campaign_path: Path, tools: Tools, **options: Any) -> Path:
    """The JSON spec of a runner process: paths, tools and run options."""
    spec = {
        "campaign": str(campaign_path),
        "results": str(root / "results"),
        "work": str(root / "work"),
        "solver": str(tools.solver),
        "checker": str(tools.checker),
        "worker": "w1",
        **options,
    }
    path = root / "spec.json"
    path.write_text(json.dumps(spec), encoding="utf-8")
    return path


# -- what a run leaves behind ---------------------------------------------------------------------


def journal_records(results: Path) -> list[dict[str, Any]]:
    """The complete lines of the worker's journal as JSON values (a torn tail is ignored)."""
    path = results / "journal.jsonl"
    if not path.exists():
        return []
    data = path.read_bytes()
    complete = data[: data.rfind(b"\n") + 1]
    return [json.loads(line) for line in complete.splitlines()]


def attempts(results: Path) -> list[dict[str, Any]]:
    return [r for r in journal_records(results) if r["type"] == "attempt"]


def summary(campaign_path: Path, results: Path) -> dict[str, Any]:
    """The certifier's view of the journal that does not depend on which attempt was chosen
    among alternatives: the verdict, per formula the root summaries, and the open list."""
    result = certify(campaign_path, [results / "journal.jsonl"])
    document = result.certificate
    return {
        "verdict": document["verdict"],
        "formulas": [
            {
                "key": f["key"],
                "proved": f["proved"],
                "summary": f["summary"],
                "roots": f["roots"],
            }
            for f in document["formulas"]
        ],
        "open": document["open"],
        "models": document["models"],
    }


def lock_is_free(results: Path) -> bool:
    try:
        lock = RunLock.acquire(results / "run.lock")
    except Exception:
        return False
    lock.release()
    return True


def wait_clean(results: Path, work: Path, *, timeout_s: float = 20.0) -> None:
    """Until no process uses the work directory and the run lock is free; AssertionError
    otherwise (an orphan process or a surviving service)."""
    deadline = time.monotonic() + timeout_s
    while True:
        alive = survivors(work.resolve()) if work.exists() else []
        if not alive and (not results.exists() or lock_is_free(results)):
            return
        assert time.monotonic() < deadline, f"processes {alive} or the run lock survive"
        time.sleep(0.05)


def fresh(path: Path) -> Path:
    """An empty directory at ``path``."""
    if path.exists():
        shutil.rmtree(path)
    path.mkdir(parents=True)
    return path


def messages(process: subprocess.Popen[bytes], timeout_s: float = 120.0) -> tuple[int, str, str]:
    """Wait for a runner process; its exit code, stdout and stderr text."""
    out, err = process.communicate(timeout=timeout_s)
    return process.returncode, out.decode("utf-8", "replace"), err.decode("utf-8", "replace")


def kill_and_collect(process: subprocess.Popen[bytes], sig: int) -> None:
    """Send ``sig`` to a runner process and reap it (the output is not needed)."""
    if process.poll() is None:
        os.kill(process.pid, sig)
    process.communicate(timeout=60)


# -- a world: one campaign, its tools and directories --------------------------------------------


@dataclass
class World:
    """One campaign with its tools, results and work directories below ``root``."""

    root: Path
    campaign: Path
    tools: Tools

    @property
    def results(self) -> Path:
        return self.root / "results"

    @property
    def work(self) -> Path:
        return self.root / "work"

    def config(self, **changes: Any) -> RunConfig:
        return config(self.root, self.campaign, self.tools, **changes)

    def run(self, **changes: Any) -> RunResult:
        """One run in this process (signal handlers are left alone)."""
        return api.run(self.config(**changes))

    def spec(self, **options: Any) -> Path:
        return write_spec(self.root, self.campaign, self.tools, **options)

    def journal(self) -> Path:
        return self.results / "journal.jsonl"

    def work_files(self) -> list[str]:
        """What is in the work directory besides its lock."""
        if not self.work.exists():
            return []
        return sorted(p.name for p in self.work.iterdir() if p.name != ".run.lock")

    def summary(self) -> dict[str, Any]:
        return summary(self.campaign, self.results)

    def attempts(self) -> list[dict[str, Any]]:
        return attempts(self.results)

    def records(self, kind: str) -> list[dict[str, Any]]:
        return [r for r in journal_records(self.results) if r["type"] == kind]


def make_world(
    root: Path,
    formulas: Mapping[str, bytes],
    *,
    solver: Mapping[str, Any] | None = None,
    policy: Policy | None = None,
) -> World:
    """Tools, bundles and a campaign below ``root``."""
    tools = install(root / "tools", solver=solver)
    return World(root, campaign(root, formulas, tools, policy), tools)
