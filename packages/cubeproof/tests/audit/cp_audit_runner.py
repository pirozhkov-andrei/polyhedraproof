"""Child process of the audit crash tests: one audit that kills itself at a lifecycle hook.

Usage: ``python cp_audit_runner.py SPEC.json``. The spec names the evidence, the tools, the
results and work directories and ``crash: {point, n, action}`` (or null); at the n-th
occurrence of the hook ``point`` the process performs ``action``: ``SIGKILL`` (the default; it
sends itself SIGKILL, no cleanup of any kind runs, as in a power loss of the executor; its I/O
service sees its input close and exits), another signal name such as ``SIGTERM`` (sent to
itself; the audit handles signals as the CLI does), or ``kill_io_service`` (SIGKILL of its I/O
service child). With ``kill_io_service_at_commit: n`` the I/O service is killed (and reaped)
just before the n-th attempt record is submitted, so that attempt waits for a result the dead
service never sends. When the audit returns, the outcome is printed as one JSON line and the
exit code is the audit's.
"""

from __future__ import annotations

import json
import os
import signal
import sys
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
LIFECYCLE = HERE.parent / "lifecycle"
for _path in (HERE, LIFECYCLE):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

import cp_life_tools as t  # noqa: E402

from cubeproof.base.settings import ToolPaths  # noqa: E402
from cubeproof.commands import SERVICE_COMMAND  # noqa: E402
from cubeproof.commands.audit import AuditRequest, audit_command  # noqa: E402
from cubeproof.commands.audit_plan import Selection  # noqa: E402
from cubeproof.contracts.io import Job, Op, Request  # noqa: E402
from cubeproof.coordinator.audit_config import AuditConfig  # noqa: E402
from cubeproof.tools.io_service_client import IoClient  # noqa: E402


def _kill_io_service() -> None:
    """SIGKILL this process's I/O service child (found by its parent and command line)."""
    me = str(os.getpid())
    found: list[int] = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            status = (entry / "status").read_text(encoding="utf-8")
            argv = (entry / "cmdline").read_bytes().split(b"\0")
        except OSError:
            continue
        parent = next((line.split()[1] for line in status.splitlines() if line[:5] == "PPid:"), "")
        if parent == me and b"io-service" in argv:
            found.append(int(entry.name))
    if len(found) != 1:
        sys.stderr.write(f"runner: expected one I/O service child, found {found}\n")
        os._exit(99)
    os.kill(found[0], signal.SIGKILL)


def _kill_io_service_at_commit(n: int) -> None:
    """When an attempt submits its n-th record (its commit), SIGKILL the I/O service and reap
    it first: the job is never read, the attempt waits for a result that cannot come."""
    original = IoClient.submit
    commits = Counter[str]()

    def submit(self: IoClient, request: Request, *, attempt_id: str | None = None) -> Job:
        if attempt_id is not None and request.OP is Op.APPEND:
            commits["append"] += 1
            if commits["append"] == n:
                os.kill(self.pid, signal.SIGKILL)
                self.process.wait()
        return original(self, request, attempt_id=attempt_id)

    IoClient.submit = submit  # type: ignore[method-assign]


def main(spec_path: str) -> int:
    spec = json.loads(Path(spec_path).read_text(encoding="utf-8"))
    if spec.get("kill_io_service_at_commit") is not None:
        _kill_io_service_at_commit(int(spec["kill_io_service_at_commit"]))
    crash = spec.get("crash")
    action = crash.get("action", "SIGKILL") if crash is not None else None
    seen: Counter[str] = Counter()

    def hooks(name: str) -> None:
        seen[name] += 1
        if crash is not None and name == crash["point"] and seen[name] == crash["n"]:
            if action == "kill_io_service":
                _kill_io_service()
            else:
                os.kill(os.getpid(), getattr(signal, str(action)))

    config = AuditConfig(
        results=Path(spec["results"]),
        work=Path(spec["work"]),
        worker=spec.get("worker", "auditor"),
        tools=ToolPaths(solver=spec["solver"], checker=spec["checker"]),
        service_argv=SERVICE_COMMAND,
        service_env=t.service_env(),
        probes=t.FixedProbes(),
        hooks=hooks,
        survivor_wait_ms=2000,
        tick_ms=5,
    )
    request = AuditRequest(
        config=config,
        selection=Selection(spec.get("sample"), spec.get("seed")),
        campaign=Path(spec["campaign"]),
        certificate=Path(spec["certificate"]),
        journals=tuple(Path(j) for j in spec["journals"]),
    )
    outcome = audit_command(request)
    sys.stdout.write(json.dumps(outcome.to_json(), sort_keys=True) + "\n")
    return outcome.exit_code


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1]))
