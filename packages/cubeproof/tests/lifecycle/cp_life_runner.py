"""A run in its own process, with a crash injected at a lifecycle hook (lifecycle tests only).

``python cp_life_runner.py SPEC.json`` runs ``cubeproof.api.run`` for the campaign, directories
and tools of the spec and prints the result document as one JSON line; its exit status is the
result's exit code (or the exit code of the error that ended it, as the command line maps it).
``spec["crash"] = {"point": NAME, "n": K}`` makes the process kill itself with SIGKILL at the
K-th occurrence of the hook NAME (the coordinator reports named points of its lifecycle,
``RunConfig.hooks``), exactly as a power failure of the process would; ``spec["trace"]`` is a
file that receives every hook name, one per line, for tests that need to know which points a
run reached.
"""

from __future__ import annotations

import json
import os
import signal
import sys
from collections import Counter
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from cubeproof import api
from cubeproof.base.errors import CubeproofError
from cubeproof.base.settings import ToolPaths
from cubeproof.commands import SERVICE_COMMAND
from cubeproof.coordinator.config import RunConfig
from cubeproof.coordinator.resources import SystemProbes

sys.path.insert(0, str(Path(__file__).resolve().parent))

from cp_life_tools import FixedProbes, service_env


def _hooks(spec: dict[str, Any]) -> Any:
    seen: Counter[str] = Counter()
    crash = spec.get("crash")
    trace = spec.get("trace")

    def hook(name: str) -> None:
        seen[name] += 1
        if trace:
            with open(trace, "a", encoding="utf-8") as stream:
                stream.write(name + "\n")
        if crash and name == crash["point"] and seen[name] == crash["n"]:
            os.kill(os.getpid(), signal.SIGKILL)

    return hook


def config_of(spec: dict[str, Any]) -> RunConfig:
    probes: SystemProbes = FixedProbes() if spec.get("fixed_probes", True) else SystemProbes()
    values: dict[str, Any] = {
        "campaign": Path(spec["campaign"]),
        "results": Path(spec["results"]),
        "work": Path(spec["work"]),
        "worker": spec["worker"],
        "tools": ToolPaths(solver=spec["solver"], checker=spec["checker"]),
        "service_argv": SERVICE_COMMAND,
        "service_env": service_env(),
        "probes": probes,
        "handle_signals": spec.get("handle_signals", True),
        "survivor_wait_ms": 2000,
        "tick_ms": 5,
        "hooks": _hooks(spec),
        "known_answer": False,  # scripted tools, as in cp_life_tools.config
    }
    for name in (
        "reopen_blocked", "max_seconds", "cache", "stall_patience_ms", "jobs", "known_answer"
    ):  # fmt: skip
        if name in spec:
            values[name] = spec[name]
    if "policy_overrides" in spec:
        values["policy_overrides"] = spec["policy_overrides"]
    return RunConfig(**values)


def main(argv: Sequence[str]) -> int:
    spec = json.loads(Path(argv[1]).read_text(encoding="utf-8"))
    try:
        result = api.run(config_of(spec))
    except CubeproofError as error:
        sys.stdout.write(json.dumps({"error": error.rule, "detail": error.detail}) + "\n")
        sys.stdout.flush()
        return api.exit_code_of(error)
    sys.stdout.write(json.dumps(result.to_json(), sort_keys=True) + "\n")
    sys.stdout.flush()
    return result.exit_code


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
