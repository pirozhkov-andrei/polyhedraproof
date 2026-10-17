"""Bounded real smoke run below a pilot root of map 2 (specification §10.2, §13).

    python tests/endtoend/single/pilot_root_smoke.py --evidence DIR --tools PREFIX [--helper PATH]
        [--phase1-seconds S] [--phase2-seconds S] [--jobs N] [--leaf-ms MS] [--split-vars K]
        [--case INDEX]

The requested root is the ``proof-prefix-v1`` cube of one map 2 case of the prefix cases of
the contract corpus (``--case`` selects another one, e.g. an easy one whose root closes
within a short budget), imported in canonical order (specification §3.3, §13: the
12 assignments are the cube, not extra clauses), on the map 2 base formula of the contract
corpus. With the pinned CaDiCaL and cake_lpr of ``PREFIX`` (verified against
``docker/test/tools.json`` by ``image.pinned.locate``) the script:

1. creates the campaign with ``cubeproof campaign create``;
2. runs one worker for ``--phase1-seconds`` and interrupts it with SIGINT;
3. certifies the interrupted journal with both certifiers;
4. restarts the worker with a time allocation of ``--phase2-seconds`` (``--max-hours``);
5. checks the restart invariants and certifies the final journal with both certifiers, also
   together with the snapshot taken at the interruption (a prefix copy, in both orders).

Everything is written below ``DIR`` (never inside the source tree): the campaign, journal,
snapshots, the four certificates per certification, every command with its output, and
``summary.json``. A nonempty requested root can at most be *closed*; the formula is never
proved by it (specification §10.2), so the expected verdict is OPEN. A root that is not closed
within the budget is recorded as OPEN: a timed smoke run is not a closure of map 2.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import platform
import sys
import time
from collections.abc import Sequence
from dataclasses import replace
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
# Run as a script: the package sources, the shared test packages and this directory.
for _path in (HERE.parents[2] / "packages" / "cubeproof" / "src", HERE.parents[1], HERE):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

import e2e_harness as h  # noqa: E402

from cubeproof.contracts.policy import Policy, default_policy  # noqa: E402

CASE = 3077
KEY = "map02"


def smoke_policy(leaf_ms: int, split_vars: int, proof_cap_bytes: int) -> Policy:
    """Specification §4.3 defaults with a short leaf time at every depth (the tree splits
    early)."""
    base = default_policy("transient")
    return replace(
        base,
        leaf_time_ms={"default": leaf_ms},
        proof_cap_bytes=proof_cap_bytes,
        split=replace(base.split, vars=split_vars),
    )


def hardware() -> dict[str, Any]:
    """The declared environment of the run."""
    cpuinfo = meminfo = ""
    with contextlib.suppress(OSError):
        cpuinfo = Path("/proc/cpuinfo").read_text(encoding="utf-8")
    with contextlib.suppress(OSError):
        meminfo = Path("/proc/meminfo").read_text(encoding="utf-8")
    models = [
        line.split(":", 1)[1].strip()
        for line in cpuinfo.splitlines()
        if ":" in line and line.startswith("model name")
    ]
    model = models[0] if models else ""
    memory = meminfo.splitlines()[0] if meminfo else ""
    return {
        "platform": platform.platform(),
        "kernel": platform.release(),
        "python": platform.python_version(),
        "cpu_model": model,
        "cpu_count": os.cpu_count(),
        "memory": memory,
        "image": container(),
    }


def container() -> str:
    """Whether the run was inside a Docker container (a declaration read from ``/.dockerenv``,
    not a proof of which image; the tools and their hashes are recorded under ``tools``)."""
    if Path("/.dockerenv").exists():
        return "inside a Docker container (/.dockerenv present)"
    return "not inside a Docker container (no /.dockerenv): native tool prefix"


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def certification(certified: h.Certified) -> dict[str, Any]:
    """What a certification produced: exit codes, hashes, agreement, the root and open lists."""
    out: dict[str, Any] = {
        "main_exit": certified.main.code,
        "min_exit": certified.independent.code,
        "agree": not certified.problems(),
        "problems": certified.problems(),
        "main_sha256": None,
        "min_sha256": None,
    }
    if certified.main_bytes is not None:
        out["main_sha256"] = hashlib.sha256(certified.main_bytes).hexdigest()
        cert = certified.certificate
        formula = cert["formulas"][0]
        out.update(
            verdict=cert["verdict"],
            proved=formula["proved"],
            roots=formula["roots"],
            used_attempts=len(cert["used_attempts"]),
            open=len(cert["open"]),
            open_states=sorted({o["state"] for o in cert["open"]}),
            formula_open=len(cert["formula_open"]),
            not_admitted=len(cert["not_admitted"]),
            anomalies=cert["anomalies"],
            models=len(cert["models"]),
        )
    if certified.independent_bytes is not None:
        out["min_sha256"] = hashlib.sha256(certified.independent_bytes).hexdigest()
    return out


def smoke(
    evidence: Path,
    tools: h.Tools,
    *,
    phase1_seconds: float,
    phase2_seconds: float,
    jobs: int,
    leaf_ms: int,
    split_vars: int,
    proof_cap_bytes: int = 2 * h.GIB,
    case_index: int = CASE,
) -> dict[str, Any]:
    """The whole smoke run (module doc); returns the summary that is also written."""
    started = time.time()
    evidence.mkdir(parents=True, exist_ok=False)
    commands: list[dict[str, Any]] = []
    base, entry = h.map2_base()
    case = h.map2_case(case_index)
    policy = smoke_policy(leaf_ms, split_vars, proof_cap_bytes)
    producer = {
        "name": "e2e-single",
        "version": "1",
        "parameters": {"source": "tests/contracts/corpus/" + entry["file"], "map": 2},
    }
    campaign, created = h.create_campaign(
        evidence / "campaign",
        {KEY: base},
        tools,
        policy,
        roots=[(KEY, case["cube"])],
        producer=producer,
    )
    campaign.jobs = jobs
    commands.append({"step": "campaign create", **created.to_json()})
    summary: dict[str, Any] = {
        "format": "pilot-root-smoke-1",
        "hardware": hardware(),
        "tools": {
            "kind": tools.kind,
            "solver": str(tools.solver),
            "solver_sha256": sha256_file(tools.solver),
            "checker": str(tools.checker),
            "checker_sha256": sha256_file(tools.checker),
            "helper": None if tools.helper is None else str(tools.helper),
            "helper_sha256": None if tools.helper is None else sha256_file(tools.helper),
            "solver_argv": list(tools.solver_argv),
        },
        "formula": {
            "map": 2,
            "formula_sha256": entry["formula_sha256"],
            "variables": entry["variables"],
            "clauses": entry["clauses"],
        },
        "root": {
            "case": case_index,
            "prefix_units": case["prefix_units"],
            "cube": case["cube"],
            "expected_node_id": case["node_id"],
        },
        "budget": {
            "phase1_seconds": phase1_seconds,
            "phase2_seconds": phase2_seconds,
            "jobs": jobs,
            "leaf_ms": leaf_ms,
            "split_vars": split_vars,
            "proof_cap_bytes": proof_cap_bytes,
        },
        "policy_sha256": policy.sha256,
    }
    if created.code != 0:
        summary["status"] = "FAILED"
        summary["error"] = created.err
        return _finish(evidence, summary, commands, started)
    summary["campaign_sha256"] = sha256_file(campaign.path)

    first = campaign.run_interrupted(
        10**9, "SIGINT", timeout_s=phase1_seconds + 900, max_wait_s=phase1_seconds
    )
    commands.append({"step": "run phase 1 (SIGINT)", **first.to_json()})
    interrupted = h.complete_lines(campaign.journal)
    raw = campaign.journal.read_bytes() if campaign.journal.exists() else b""
    snapshot = campaign.snapshot("phase1")
    summary["phase1"] = {
        "exit": first.code,
        "signal": first.signal_sent,
        "seconds": round(first.completed.seconds, 1),
        "result": first.document,
        "work_files_after_stop": campaign.work_files(),
        "torn_tail_bytes": len(raw) - len(interrupted),
        "journal_sha256": hashlib.sha256(raw).hexdigest(),
        "counts": h.outcome_counts(campaign.journal),
        "certification": certification(campaign.certify(evidence / "certify-phase1")),
    }

    second = campaign.run(timeout_s=phase2_seconds + 1800, max_hours=phase2_seconds / 3600)
    commands.append({"step": "run phase 2 (--max-hours)", **second.to_json()})
    final = campaign.certify(evidence / "certify-final")
    copies = [
        campaign.certify(evidence / "certify-copies-a", [snapshot, campaign.journal]),
        campaign.certify(evidence / "certify-copies-b", [campaign.journal, snapshot]),
    ]
    checked = h.checked_leaves(campaign.journal)
    final_summary = certification(final)
    summary["phase2"] = {
        "exit": second.code,
        "seconds": round(second.completed.seconds, 1),
        "result": second.document,
        "work_files_after_run": campaign.work_files(),
        "journal_sha256": sha256_file(campaign.journal),
        "counts": h.outcome_counts(campaign.journal),
        "checked_leaves": len(checked),
        "checked_leaf_routes": sorted({a["route"] for a in checked}),
        "resume_invariants": h.resume_invariants(raw, campaign.journal, 1),
        "certification": final_summary,
        "copies": [
            {
                **certification(c),
                "same_as_final": c.main_bytes == final.main_bytes
                and c.independent_bytes == final.independent_bytes,
            }
            for c in copies
        ],
    }
    root = (final_summary.get("roots") or [{}])[0]
    summary["root_closed"] = bool(root.get("closed"))
    summary["status"] = "CLOSED" if summary["root_closed"] else "OPEN"
    return _finish(evidence, summary, commands, started)


def _finish(
    evidence: Path, summary: dict[str, Any], commands: list[dict[str, Any]], started: float
) -> dict[str, Any]:
    summary["wall_seconds"] = round(time.time() - started, 1)
    h.write_json(evidence / "commands.json", commands)
    h.write_json(evidence / "summary.json", summary)
    return summary


def problems(summary: dict[str, Any]) -> list[str]:
    """Conditions of the smoke run that do not depend on the budget."""
    found = []
    if summary.get("status") == "FAILED":
        return [f"campaign create failed: {summary.get('error')}"]
    if summary["phase1"]["exit"] not in (0, 130):
        found.append(f"phase 1 exit {summary['phase1']['exit']}")
    if summary["phase2"]["exit"] not in (0, 1):
        found.append(f"phase 2 exit {summary['phase2']['exit']}")
    for name, cert in (
        ("phase 1", summary["phase1"]["certification"]),
        ("final", summary["phase2"]["certification"]),
        *(("copies", c) for c in summary["phase2"]["copies"]),
    ):
        if not cert["agree"]:
            found.append(f"{name}: certifiers disagree {cert['problems']}")
        if cert.get("verdict") != "OPEN":
            found.append(f"{name}: verdict {cert.get('verdict')} (a nonempty root never proves F)")
        if cert.get("proved"):
            found.append(f"{name}: the formula is reported proved")
    for copy in summary["phase2"]["copies"]:
        if not copy["same_as_final"]:
            found.append("a prefix copy changed the certificate")
    if summary["phase2"]["resume_invariants"]:
        found.append(f"resume invariants: {summary['phase2']['resume_invariants']}")
    roots = summary["phase2"]["certification"].get("roots") or []
    if [r["cube"] for r in roots] != [summary["root"]["cube"]]:
        found.append("the certified root is not the requested case cube")
    for root in roots:
        leaves = root["summary"]["leaves"]
        merkle = root["summary"]["leaf_merkle_root"]
        used = summary["phase2"]["certification"].get("used_attempts")
        if root["closed"] and (leaves == 0 or merkle is None or used != leaves):
            found.append(f"closed root without its proof tree: {leaves} leaves, {used} used")
        if not root["closed"] and (leaves or merkle is not None or used):
            found.append("an open root reports selected evidence")
    attempts = summary["phase2"]["counts"].get("record:attempt", 0)
    if attempts == 0:
        found.append("no attempt was recorded")
    return found


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--tools", required=True, type=Path, help="pinned tool prefix")
    parser.add_argument("--helper", type=Path)
    parser.add_argument("--phase1-seconds", type=float, default=900.0)
    parser.add_argument("--phase2-seconds", type=float, default=2700.0)
    parser.add_argument("--jobs", type=int, default=8)
    parser.add_argument("--leaf-ms", type=int, default=5_000)
    parser.add_argument("--split-vars", type=int, default=2)
    parser.add_argument("--case", type=int, default=CASE, help="map 2 prefix case of the corpus")
    args = parser.parse_args(argv)
    from image.pinned import VARIABLE, locate

    pinned = locate({VARIABLE: str(args.tools)})
    tools = h.pinned_tools(pinned.prefix, args.helper)
    summary = smoke(
        args.evidence.resolve(),
        tools,
        phase1_seconds=args.phase1_seconds,
        phase2_seconds=args.phase2_seconds,
        jobs=args.jobs,
        leaf_ms=args.leaf_ms,
        split_vars=args.split_vars,
        case_index=args.case,
    )
    found = problems(summary)
    report = {
        "status": summary.get("status"),
        "root_closed": summary.get("root_closed"),
        "problems": found,
    }
    print(json.dumps(report, sort_keys=True))
    return 0 if not found else 1


if __name__ == "__main__":
    raise SystemExit(main())
