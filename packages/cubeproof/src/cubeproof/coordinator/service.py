"""The I/O service process of a run: the journal writer behind the service protocol (specification
§7.1, §7.3, §8.1).

``tools.io_service`` may not import the journal (specification §2.3), so the wiring is here: the
coordinator starts ``<python> -m cubeproof io-service ...`` (argv built by the command layer) with
the run lock's descriptor passed on, so the service holds the results directory's lock for as long
as it lives, also after a coordinator that was killed (a restart is refused until the service has
seen its input close and exited, which is the fact that no writer survives, specification §7.3).

:func:`run_service` opens the journal for appending. For a new worker (``header_file``) it
creates the journal with that header **inside the service**, so the coordinator never holds a
writer, the first appended record may be anything (the writer treats a created journal as
having its session), and a crash leaves either no journal or a journal with its header. For an
existing journal it recovers (it validates it whole; a torn tail was already repaired by the
coordinator's startup under the same lock) and demands a ``resume`` first.

The journal validator carries the campaign's :class:`~cubeproof.evidence.schema.JournalContext`;
the heavy certifier attempt rules (which need every formula) run in the
coordinator's own tail validation, not here. The service commits payloads unchanged and answers
only after the writer's fsync.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cubeproof.base.canonical_json import parse_document
from cubeproof.base.errors import ContractError
from cubeproof.evidence.journal import JournalWriter, RunLock
from cubeproof.evidence.journal.storage import OS_CALLS
from cubeproof.evidence.schema import (
    PAYLOADS,
    JournalContext,
    Payload,
    Record,
    RecordSequence,
)
from cubeproof.tools.io_service import Service, ServiceConfig, serve

__all__ = ["ServiceArgs", "WriterPort", "payload_value", "run_service"]


def payload_value(value: Mapping[str, Any]) -> Payload:
    """The typed payload of a payload JSON value (``type`` plus fields)."""
    kind = value.get("type")
    if not isinstance(kind, str) or kind not in PAYLOADS:
        raise ContractError("schema", f"unknown record type {kind!r}")
    fields = {k: v for k, v in value.items() if k != "type"}
    spec = PAYLOADS[kind].SPEC
    spec.check(fields, "$")
    built: Payload = spec.build(fields)
    return built


class WriterPort:
    """The :class:`JournalWriter` behind the service's ``JournalPort`` protocol."""

    def __init__(self, writer: JournalWriter[Record]) -> None:
        self.writer = writer

    @property
    def failed(self) -> bool:
        return self.writer.failed

    def position(self) -> tuple[int, str] | None:
        chain = self.writer.chain
        if chain.head is None:
            return None
        return chain.records - 1, chain.head

    def append(self, payload: Mapping[str, Any]) -> tuple[int, str]:
        record = self.writer.append(payload_value(payload))
        return record.seq, record.self_hash


@dataclass(frozen=True)
class ServiceArgs:
    """What the service process needs (all plain values: they travel on its command line)."""

    results: str
    work: str
    journal: str
    lock: str
    lock_fd: int
    campaign: str
    variables: Mapping[str, int]
    header_file: str | None = None

    def context(self) -> JournalContext:
        return JournalContext(self.campaign, dict(self.variables))


def run_service(args: ServiceArgs, *, in_fd: int = 0, out_fd: int = 1) -> int:
    """Serve jobs on ``in_fd``/``out_fd`` until the input closes (``tools.io_service.serve``)."""
    lock = RunLock(Path(args.lock), args.lock_fd, OS_CALLS)
    validator = RecordSequence(context=args.context())
    writer: JournalWriter[Record]
    if args.header_file is not None:
        header = parse_document(Path(args.header_file).read_bytes())
        writer = JournalWriter.create(
            args.journal, payload_value(header), validator=validator, run_lock=lock
        )
    else:
        writer = JournalWriter.open(args.journal, validator=validator, run_lock=lock)
    try:
        service = Service(
            ServiceConfig(results_root=args.results, work_root=args.work), WriterPort(writer)
        )
        return serve(service, in_fd, out_fd, pid=os.getpid())
    finally:
        writer.close()
