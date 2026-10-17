"""Test entry point of the I/O service process (the wiring of the coordinator layer).

``python3 cp_io_service_main.py --results R --work W [--journal J --lock P --lock-fd N]
[--chunk BYTES] [--slow-fsync SECONDS]`` serves jobs on stdin/stdout. The run lock is the
coordinator's: its descriptor is inherited, so the service holds the same lock (specification §7.3)
and a surviving service keeps a new coordinator out until it has exited.
"""

from __future__ import annotations

import argparse
import errno
import os
import time
from pathlib import Path

from cubeproof.evidence.journal import JournalWriter, RunLock
from cubeproof.evidence.journal.storage import OS_CALLS
from cubeproof.tools.atomic import FileCalls
from cubeproof.tools.io_service import Service, ServiceConfig, serve


class SlowFsync(FileCalls):
    """fsync that stalls (a slow disk), to show the coordinator side stays responsive."""

    def __init__(self, seconds: float) -> None:
        self.seconds = seconds

    def fsync(self, fd: int) -> None:
        time.sleep(self.seconds)
        super().fsync(fd)


class FailingFsync(FileCalls):
    """fsync that fails (EIO): the service must report a fatal failure and exit."""

    def fsync(self, fd: int) -> None:
        raise OSError(errno.EIO, "injected fsync failure")


def main() -> int:
    import cp_io_support as sup

    parser = argparse.ArgumentParser()
    parser.add_argument("--results", required=True)
    parser.add_argument("--work", required=True)
    parser.add_argument("--journal")
    parser.add_argument("--lock")
    parser.add_argument("--lock-fd", type=int)
    parser.add_argument("--chunk", type=int)
    parser.add_argument("--slow-fsync", type=float)
    parser.add_argument("--fail-fsync", action="store_true")
    args = parser.parse_args()
    port = None
    if args.journal is not None:
        lock = RunLock(Path(args.lock), args.lock_fd, OS_CALLS)
        writer = JournalWriter.open(args.journal, validator=sup.validator(), run_lock=lock)
        port = sup.WriterPort(writer)
    options = {} if args.chunk is None else {"chunk_bytes": args.chunk}
    config = ServiceConfig(results_root=args.results, work_root=args.work, **options)
    calls = FileCalls() if args.slow_fsync is None else SlowFsync(args.slow_fsync)
    if args.fail_fsync:
        calls = FailingFsync()
    service = Service(config, port, calls=calls)
    return serve(service, 0, 1, pid=os.getpid())


if __name__ == "__main__":
    raise SystemExit(main())
