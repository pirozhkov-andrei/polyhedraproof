"""Record rules of a journal read in order (specification §4.7, §7.1, §10.1; journal.*, attempt.*,
handoff.*).

:class:`RecordSequence` is the record validator that :mod:`cubeproof.evidence.journal` calls
for every complete line (the journal layer may not import this one, specification §2.3; the caller
wires them). The journal checks bytes and the chain; this class checks, in the reference order:

- ``check_schema``: the schema of the record type (before ``self``, specification §7.1);
- ``check_header``: for the first record, ``journal.campaign`` against the context (an
  InputError: a foreign campaign is never silently ignored);
- ``check_rules``: journal.purpose, the record rules of :mod:`.rules` (with V per formula from
  the context), shard.campaign, attempt.policy_sha256 against the latest header/resume,
  attempt.attempt_id and handoff.request_unique within the journal, plus the rules of other
  components through :class:`ExtraRules` at their reference positions: ``attempt_record``
  after the attempt's own field rules (``success.*``), ``attempt_context`` after policy and
  attempt ID (``attempt.cnf_sha256``, ``attempt.model_false``).

Checks never mutate; ``commit`` applies a checked record, so a writer can refuse a record
before writing it. Violations are IntegrityError (journal.campaign: InputError); the journal
adds the line location.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Protocol

from cubeproof.base.errors import (
    ConfigurationError,
    ContractError,
    CubeproofError,
    InputError,
    IntegrityError,
    contextualize,
)
from cubeproof.contracts.enums import Purpose, RecordType
from cubeproof.contracts.primitives import is_hash
from cubeproof.evidence.schema.records import (
    Attempt,
    Handoff,
    Header,
    Payload,
    Record,
    Resume,
    ShardRecord,
    check_record_schema,
    record_from_checked,
)
from cubeproof.evidence.schema.rules import record_problem

_AUDIT_PURPOSE = frozenset({"header", "resume", "repair", "attempt"})


@dataclass(frozen=True)
class JournalContext:
    """What a reader knows about the campaign: its ID and V per formula hash."""

    campaign: str
    variables: Mapping[str, int] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not is_hash(self.campaign):
            raise ConfigurationError("journal.context", f"{self.campaign!r} is not a campaign ID")
        frozen = MappingProxyType(dict(self.variables))
        for formula, count in frozen.items():
            if not is_hash(formula) or type(count) is not int or count < 0:
                raise ConfigurationError("journal.context", f"bad formula entry {formula!r}")
        object.__setattr__(self, "variables", frozen)


class ExtraRules(Protocol):
    """Rules of other components, run in place for every attempt (see module doc)."""

    def attempt_record(self, record: Record, snapshot: Header | Resume) -> str | None: ...

    def attempt_context(self, record: Record, snapshot: Header | Resume) -> str | None: ...


def _integrity(error: CubeproofError) -> CubeproofError:
    return contextualize(error, IntegrityError)


class RecordSequence:
    """The record validator of one journal and the identifiers that journal committed.

    ``context`` has no default: ``context=None`` deliberately skips the campaign rules
    (journal.campaign, record.formula, cube.range, shard.campaign, the assignment length).
    Certify, leaf and coordinator wiring must pass the campaign's :class:`JournalContext`.
    """

    def __init__(self, *, context: JournalContext | None, extra: ExtraRules | None = None) -> None:
        self.context = context
        self.extra = extra
        self.header: Header | None = None
        self.snapshot: Header | Resume | None = None
        self._policy_sha256: str | None = None
        self._attempts: dict[str, int] = {}
        self._requests: dict[str, int] = {}

    # -- the journal's validator protocol --------------------------------------------------------

    def check_schema(self, value: Any) -> None:
        try:
            check_record_schema(value)
        except CubeproofError as error:
            raise _integrity(error) from None

    def check_header(self, value: Mapping[str, Any]) -> None:
        context = self.context
        if context is not None and value["campaign"] != context.campaign:
            raise InputError("journal.campaign", f"journal of campaign {value['campaign']}")

    def check_rules(self, value: Mapping[str, Any]) -> Record:
        """The record of a schema- and chain-checked value after every rule; no mutation."""
        kind = value["type"]
        purpose = value["purpose"] if kind == RecordType.HEADER else self._purpose()
        allowed = kind in _AUDIT_PURPOSE or kind.startswith("audit_")
        if (purpose == Purpose.RUN and kind.startswith("audit_")) or (
            purpose == Purpose.AUDIT and not allowed
        ):
            raise IntegrityError("journal.purpose", f"{kind} in a {purpose} journal")
        variables = self.context.variables if self.context is not None else None
        try:
            problem = record_problem(value, variables)
            if problem is not None:
                raise IntegrityError(problem, f"{kind} record")
            record = record_from_checked(value)
        except CubeproofError as error:
            raise _integrity(error) from None
        problem = self._journal_problem(record)
        if problem is not None:
            raise IntegrityError(problem, f"{kind} record")
        return record

    def commit(self, record: Record) -> None:
        """Apply a record accepted by :meth:`check_rules`."""
        payload = record.payload
        if isinstance(payload, Header):
            self.header = payload
        if isinstance(payload, (Header, Resume)):
            self.snapshot = payload
            self._policy_sha256 = payload.policy.sha256
        elif isinstance(payload, Attempt):
            self._attempts[payload.attempt_id] = record.seq
        elif isinstance(payload, Handoff):
            self._requests[payload.request.request_id] = record.seq

    def payload_json(self, payload: Any) -> dict[str, Any]:
        """``type`` and payload fields of a payload value given to a journal writer."""
        if not isinstance(payload, Payload):
            raise ContractError("schema", f"{type(payload).__name__} is not a record payload")
        value = payload.to_json()
        value["type"] = payload.TYPE.value
        return value

    # -- rules -------------------------------------------------------------------------------

    def _purpose(self) -> str:
        if self.header is None:
            raise IntegrityError("journal.header", "no header before this record")
        return self.header.purpose.value

    def _journal_problem(self, record: Record) -> str | None:  # noqa: PLR0911 - rule order
        payload = record.payload
        context = self.context
        if context is not None:
            campaigns: list[str] = []
            if isinstance(payload, ShardRecord):
                campaigns.append(payload.shard.campaign)
            elif isinstance(payload, Handoff):
                if payload.shard is not None:
                    campaigns.append(payload.shard.campaign)
                campaigns.append(payload.request.campaign)
            if any(c != context.campaign for c in campaigns):
                return "shard.campaign"
        if isinstance(payload, Attempt):
            snapshot = self.snapshot
            if snapshot is None:  # pragma: no cover - the header precedes every attempt
                return "journal.header"
            if self.extra is not None:
                problem = self.extra.attempt_record(record, snapshot)
                if problem is not None:
                    return problem
            if payload.policy_sha256 != self._policy_sha256:
                return "attempt.policy_sha256"
            if payload.attempt_id in self._attempts:
                return "attempt.attempt_id"
            if self.extra is not None:
                return self.extra.attempt_context(record, snapshot)
        if isinstance(payload, Handoff) and payload.request.request_id in self._requests:
            return "handoff.request_unique"
        return None

    # -- queries -------------------------------------------------------------------------------

    def committed_attempt(self, attempt_id: str) -> int | None:
        """Seq of the committed attempt with this ID, or None (replay after a lost ack)."""
        return self._attempts.get(attempt_id)

    def committed_request(self, request_id: str) -> int | None:
        """Seq of the committed handoff of this request, or None."""
        return self._requests.get(request_id)

    @property
    def policy_sha256(self) -> str | None:
        """policy_sha256 of the latest header/resume (the policy new attempts must name)."""
        return self._policy_sha256
