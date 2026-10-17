"""``handoff``: ask a worker to give work away, and follow the answer (specification §4.5, §7.4,
§12.1, §12.2).

``cubeproof handoff --results DIR --nodes N --output-name NAME [--wait-ms N]`` only writes an
**immutable request** into the inbox the worker was configured with (``results/ports.json``,
written by ``run --inbox``): ``<inbox>/<NAME>.request.json``, a ``cubeproof-handoff-request-1``
document published atomically (``tools.atomic.atomic_write``). The worker, running or at its next
run, chooses the nodes, commits the handoff and publishes ``<outbox>/<NAME>.json``.

The request ID is stable: the file name is the output name, so repeating the command with the
same name and count finds the existing request (pending, processed or rejected) and reuses its
ID instead of making a second one; the same name with another count is a ConfigurationError (a
different request for a taken output name). The request's bytes never change.

The command follows the outcome by reading the worker's journal (complete lines, chain-checked)
and the outbox; it never writes either. States (:class:`HandoffState`):

``pending``
    the request is durable in the inbox, no handoff is committed yet (a stopped worker serves it
    at its next run). A timeout of ``--wait-ms`` ends here with exit 1: no transfer is claimed.
``publishing``
    the handoff is committed, the output file is not there yet (the worker will publish it).
``completed``
    committed and the output file holds exactly the committed shard, **or** zero nodes were
    available: the derived empty completion (no file, ``nodes`` 0).
``blocked``
    committed, but the output name holds other bytes: nothing was overwritten, coverage stays
    open and the shard in the journal is the authority.
``rejected``
    the worker rejected the request (reason in ``rejected/<file>.reason.txt``), exit 3.

Delivery to another machine is the user's file transfer; nothing here claims it happened.
"""

from __future__ import annotations

import dataclasses
import enum
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cubeproof.base.canonical_json import document_bytes, parse_document
from cubeproof.base.errors import (
    ConfigurationError,
    ContractError,
    InputError,
    IntegrityError,
    ResourceError,
)
from cubeproof.base.ids import new_id128
from cubeproof.base.settings import DEFAULT_LIMITS, ReaderLimits
from cubeproof.contracts.documents import HandoffRequest
from cubeproof.contracts.primitives import is_name
from cubeproof.coordinator.handoff import Ports, read_ports
from cubeproof.coordinator.inbox import PROCESSED, REJECTED
from cubeproof.coordinator.layout import JOURNAL_NAME
from cubeproof.coordinator.outbox import (
    HandoffResponse,
    OutputState,
    ensure_tree,
    output_file,
    output_state,
    response_of,
)
from cubeproof.coordinator.ownership import Given, Ownership
from cubeproof.tools.atomic import OS_FILE_CALLS, atomic_write

__all__ = [
    "HandoffCommand",
    "HandoffOutcome",
    "HandoffState",
    "handoff_command",
    "request_file_name",
]

REQUEST_SUFFIX = ".request.json"


def request_file_name(output_name: str) -> str:
    return f"{output_name}{REQUEST_SUFFIX}"


class HandoffState(str, enum.Enum):
    PENDING = "pending"
    PUBLISHING = "publishing"
    COMPLETED = "completed"
    BLOCKED = "blocked"
    REJECTED = "rejected"


_FINAL = (HandoffState.COMPLETED, HandoffState.REJECTED, HandoffState.BLOCKED)


@dataclass(frozen=True)
class HandoffCommand:
    """The inputs of ``handoff`` as values."""

    results: Path
    nodes: int
    output_name: str
    wait_ms: int = 0
    poll_ms: int = 100
    #: for tests: the request ID of a new request (otherwise OS randomness)
    request_id: str | None = None
    limits: ReaderLimits = DEFAULT_LIMITS

    def __post_init__(self) -> None:
        if type(self.nodes) is not int or self.nodes < 1:
            raise ConfigurationError("handoff.nodes", f"{self.nodes!r} is not a positive integer")
        if not is_name(self.output_name):
            raise ConfigurationError(
                "handoff.output_name", f"{self.output_name!r} is not a Name (a-z, 0-9, _ and -)"
            )
        for field_name in ("wait_ms", "poll_ms"):
            value = getattr(self, field_name)
            if type(value) is not int or value < 0:
                raise ConfigurationError(f"handoff.{field_name}", f"{value!r} is not >= 0")


@dataclass(frozen=True)
class HandoffOutcome:
    """The state of one request when the command returns."""

    state: HandoffState
    request: HandoffRequest
    request_file: str
    #: the derived completion response, once the handoff is committed
    response: HandoffResponse | None = None
    #: absolute path of the output file when it is published and matches the record
    output: str | None = None
    detail: str = ""
    waited: bool = False

    @property
    def exit_code(self) -> int:
        """Specification §12.2: completed 0; rejected 3 (the request cannot be served); a timeout of
        ``--wait-ms`` and every committed-but-unpublished state 1; a request without
        ``--wait-ms`` has done what was asked (it is durable): 0."""
        if self.state is HandoffState.COMPLETED:
            return 0
        if self.state is HandoffState.REJECTED:
            return 3
        if self.state is HandoffState.PENDING and not self.waited:
            return 0
        return 1

    def to_json(self) -> dict[str, Any]:
        return {
            "state": self.state.value,
            "request": self.request.to_json(),
            "request_file": self.request_file,
            "response": None if self.response is None else self.response.to_json(),
            "output": self.output,
            "detail": self.detail,
            "waited": self.waited,
            "exit_code": self.exit_code,
        }


def _read_request(path: Path, limits: ReaderLimits) -> HandoffRequest | None:
    try:
        data = path.read_bytes()
    except FileNotFoundError:
        return None
    try:
        return HandoffRequest.from_json(parse_document(data, limits=limits))
    except (ContractError, ResourceError) as error:
        raise InputError(
            "handoff.request_file", f"{path} is not a valid handoff request: {error}"
        ) from None


def _find_existing(
    inbox: Path, name: str, limits: ReaderLimits
) -> tuple[HandoffRequest, Path] | None:
    """The request already made for this output name: pending, processed or rejected."""
    for folder in (inbox, inbox / PROCESSED, inbox / REJECTED):
        path = folder / request_file_name(name)
        found = _read_request(path, limits)
        if found is not None:
            return found, path
    return None


def _write_request(
    inbox: Path, command: HandoffCommand, campaign: str
) -> tuple[HandoffRequest, Path]:
    """The request for ``command`` (existing or new), durable in the inbox."""
    existing = _find_existing(inbox, command.output_name, command.limits)
    if existing is None:
        request = HandoffRequest(
            campaign, command.request_id or new_id128(), command.nodes, command.output_name
        )
        path = inbox / request_file_name(command.output_name)
        ensure_tree(inbox, OS_FILE_CALLS)
        try:
            atomic_write(str(path), document_bytes(request.to_json()))
            return request, path
        except IntegrityError:
            existing = _find_existing(inbox, command.output_name, command.limits)  # a racing twin
            if existing is None:
                raise
    request, path = existing
    if request.campaign != campaign or request.node_count != command.nodes:
        raise ConfigurationError(
            "handoff.name_taken",
            f"output name {command.output_name!r} already has a request ({path}) for "
            f"{request.node_count} nodes; use another --output-name for a different request",
        )
    return request, path


class _Follower:
    """The worker's journal, read without any lock (complete lines only)."""

    def __init__(self, results: Path, ports: Ports, limits: ReaderLimits) -> None:
        self.journal = results / JOURNAL_NAME
        self.campaign = ports.campaign
        self.limits = limits
        self.ownership: Ownership | None = None

    def refresh(self) -> Ownership | None:
        try:
            if self.ownership is None:
                self.ownership = Ownership.from_journal(
                    self.journal, campaign=self.campaign, limits=self.limits
                )
            else:
                self.ownership.refresh(self.journal, limits=self.limits)
        except FileNotFoundError:
            return None
        except IntegrityError as error:
            if error.rule == "journal.no_header":
                return None  # a journal that is just being created
            raise
        return self.ownership


def _pending(request: HandoffRequest, inbox: Path) -> HandoffOutcome:
    file_name = request_file_name(request.output_name)
    reason = inbox / REJECTED / f"{file_name}.reason.txt"
    if reason.exists():
        text = reason.read_text(encoding="utf-8", errors="replace").strip()
        return HandoffOutcome(HandoffState.REJECTED, request, file_name, detail=text)
    detail = "the request is durable in the inbox; the worker serves it while running or next run"
    return HandoffOutcome(HandoffState.PENDING, request, file_name, detail=detail)


def _committed(request: HandoffRequest, given: Given, outbox: Path | None) -> HandoffOutcome:
    name = request.output_name
    file_name = request_file_name(name)
    response = response_of(given)
    if given.request != request:
        raise IntegrityError(
            "handoff.request_conflict",
            f"the journal committed request {request.request_id} with other content",
        )

    def outcome(state: HandoffState, detail: str, output: str | None = None) -> HandoffOutcome:
        return HandoffOutcome(state, request, file_name, response, output, detail)

    if given.shard is None:
        return outcome(
            HandoffState.COMPLETED,
            "no node was available: nothing was given away and nothing was published",
        )
    if outbox is None:
        return outcome(HandoffState.BLOCKED, "the worker has no outbox")
    state = output_state(outbox, given)
    path = str(output_file(outbox, name))
    if state is OutputState.PUBLISHED:
        return outcome(
            HandoffState.COMPLETED,
            "deliver the output file to the receiving machine; delivery is not tracked",
            path,
        )
    if state is OutputState.MISSING:
        return outcome(
            HandoffState.PUBLISHING,
            "the handoff is committed; the worker publishes the output at its next step",
        )
    return outcome(
        HandoffState.BLOCKED,
        f"{path} holds other bytes than the committed shard; it was not overwritten",
    )


def handoff_command(
    command: HandoffCommand,
    *,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
) -> HandoffOutcome:
    """Write (or find) the request and report its state, waiting up to ``wait_ms``."""
    results = Path(command.results).resolve()
    ports = read_ports(results, command.limits)
    if ports.inbox is None:
        raise ConfigurationError(
            "handoff.no_inbox", f"the worker of {results} has no inbox: run it with --inbox DIR"
        )
    inbox = Path(ports.inbox)
    outbox = None if ports.outbox is None else Path(ports.outbox)
    try:
        request, _ = _write_request(inbox, command, ports.campaign)
    except OSError as error:
        raise ConfigurationError("handoff.inbox", f"{inbox}: {error.strerror or error}") from None
    follower = _Follower(results, ports, command.limits)
    deadline = clock() + command.wait_ms / 1000
    while True:
        ownership = follower.refresh()
        given = None if ownership is None else ownership.prior(request.request_id)
        outcome = _pending(request, inbox) if given is None else _committed(request, given, outbox)
        if outcome.state in _FINAL or clock() >= deadline:
            return dataclasses.replace(outcome, waited=command.wait_ms > 0)
        sleep(min(command.poll_ms / 1000, max(0.0, deadline - clock())))
