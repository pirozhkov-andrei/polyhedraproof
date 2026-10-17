"""Test entry point of the I/O service process for the leaf tests (the coordinator's wiring).

``python3 cp_leaf_service_main.py --results R --work W --journal J --lock P --lock-fd N``
serves jobs on stdin/stdout with the journal writer behind the I/O service. The run lock is
the test's: its descriptor is inherited, so the service holds the same lock (specification
§7.3).
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path


def main() -> int:
    from cp_leaf_support import WriterPort

    from cubeproof.evidence.journal import JournalWriter, RunLock
    from cubeproof.evidence.journal.storage import OS_CALLS
    from cubeproof.evidence.schema import RecordSequence
    from cubeproof.tools.io_service import Service, ServiceConfig, serve

    parser = argparse.ArgumentParser()
    parser.add_argument("--results", required=True)
    parser.add_argument("--work", required=True)
    parser.add_argument("--journal", required=True)
    parser.add_argument("--lock", required=True)
    parser.add_argument("--lock-fd", type=int, required=True)
    args = parser.parse_args()
    lock = RunLock(Path(args.lock), args.lock_fd, OS_CALLS)
    writer = JournalWriter.open(args.journal, validator=RecordSequence(context=None), run_lock=lock)
    service = Service(
        ServiceConfig(results_root=args.results, work_root=args.work), WriterPort(writer)
    )
    return serve(service, 0, 1, pid=os.getpid())


if __name__ == "__main__":
    raise SystemExit(main())
