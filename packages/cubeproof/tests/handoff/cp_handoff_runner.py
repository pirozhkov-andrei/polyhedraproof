"""A run with a handoff desk in its own process, killed at a named point (handoff tests only).

``python cp_handoff_runner.py SPEC.json`` runs a :class:`DeskCoordinator` for the campaign,
directories and tools of the spec (the lifecycle runner's spec, see ``cp_life_runner``) with
``inbox``, ``outbox`` and optionally ``shard`` (a shard document) added, and prints the result
document as one JSON line; its exit status is the result's exit code, or the exit code of the
error that ended it. ``spec["crash"] = {"point": NAME, "n": K}`` makes the process kill itself with
SIGKILL at the K-th occurrence of the hook NAME: lifecycle hooks of the coordinator and the
desk's ``shard.submitted``, ``shard.committed``, ``handoff.submitted``, ``handoff.committed``,
``outbox.published``, ``inbox.accepted``, ``inbox.processed``, ``inbox.rejected`` (specification
§7.5).
"""

from __future__ import annotations

import json
import sys
from collections.abc import Sequence
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lifecycle"))

from cp_life_runner import config_of

from cubeproof import api
from cubeproof.base.errors import CubeproofError
from cubeproof.contracts.documents import Shard
from cubeproof.coordinator.handoff_run import DeskCoordinator


def main(argv: Sequence[str]) -> int:
    spec = json.loads(Path(argv[1]).read_text(encoding="utf-8"))
    shard = Shard.from_json(spec["shard"]) if spec.get("shard") else None
    try:
        result = DeskCoordinator(
            config_of(spec),
            inbox=Path(spec["inbox"]),
            outbox=Path(spec["outbox"]),
            shard=shard,
            scan_interval_ns=0,
        ).run()
    except CubeproofError as error:
        sys.stdout.write(json.dumps({"error": error.rule, "detail": error.detail}) + "\n")
        sys.stdout.flush()
        return api.exit_code_of(error)
    sys.stdout.write(json.dumps(result.to_json(), sort_keys=True) + "\n")
    sys.stdout.flush()
    return result.exit_code


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
