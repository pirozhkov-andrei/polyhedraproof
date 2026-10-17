"""Audit targets, seeded selection and the committed audit plan (specification §11.1, §4.7).

**Population.** The targets of an audit are the ``used_attempts`` of the certificate *as the
certifier recomputed it* from the certified journal prefixes (:mod:`.audit_inputs`), never the
supplied list: those are the unique leaves of every reported closed formula/root summary. Each
becomes an ``AuditTarget`` ``{node, node_id, source, cnf_sha256, proof_sha256, route,
machinery}`` whose ``machinery`` is the header/resume snapshot in force at the source record.
The snapshot is found by reading the preserved journal prefix again; it must be one of the
certificate's ``machinery`` entries, and the source record must be the VERIFIED_UNSAT attempt
the certificate names (``audit.source`` otherwise).

**Selection.** ``--all`` takes the whole population. ``--sample N`` (N > 0) takes the N smallest
``(SHA256(ASCII(seed) + NUL + ASCII(node_id)), node_id)``, N clamped to the population; the
selected targets are ordered by node_id. The default seed is ``certificate_sha256``
(SHA256(J(certificate))); an explicit seed can be fixed in advance. A sample of ``p`` percent is
``ceil(population * p / 100)`` targets (:func:`percent_count`), never a share of journal lines.

**Plan.** ``audit_begin`` (certificate hash, requested sample count, seed, targets hash and
count, comparison), one ``audit_target`` per ordinal, then ``audit_ready``. ``targets_sha256``
hashes the concatenated ``J(target) + LF`` in target order; ``sample_count`` is the requested N
(the population for ``--all``), ``target_count`` the selected count. A restart regenerates the
plan from the preserved inputs and compares it with what the journal holds
(:func:`check_plan_prefix`): a ready plan never changes silently.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cubeproof.base.canonical_json import encode
from cubeproof.base.errors import ConfigurationError, CubeproofError, IntegrityError, contextualize
from cubeproof.base.settings import DEFAULT_LIMITS, ReaderLimits
from cubeproof.cnf.campaign import LoadedCampaign
from cubeproof.commands.audit_inputs import BoundInputs, validator_of
from cubeproof.contracts.enums import AuditComparison, Outcome
from cubeproof.contracts.primitives import is_hash
from cubeproof.evidence.journal import JournalReader
from cubeproof.evidence.schema import (
    Attempt,
    AuditBegin,
    AuditReady,
    AuditTarget,
    AuditTargetRecord,
    Header,
    Machinery,
    Payload,
    Resume,
)

__all__ = [
    "AuditPlan",
    "Selection",
    "check_plan_prefix",
    "make_plan",
    "parse_seed",
    "percent_count",
    "population_of",
    "sample_key",
    "select_node_ids",
    "target_bytes",
    "target_sha256",
    "targets_sha256",
]


def parse_seed(text: str) -> str:
    """An explicit ``--seed``: exactly 64 lowercase hexadecimal characters (a Hash)."""
    if not is_hash(text):
        raise ConfigurationError("usage", f"--seed {text!r} is not 64 lowercase hex characters")
    return text


def sample_key(seed: str, node_id: str) -> str:
    """``SHA256(ASCII(seed) + NUL + ASCII(node_id))`` (specification §11.1)."""
    return hashlib.sha256(seed.encode("ascii") + b"\x00" + node_id.encode("ascii")).hexdigest()


def percent_count(population: int, percent: int) -> int:
    """Targets of a ``percent`` sample: ``ceil(population * percent / 100)`` (5% -> /20)."""
    if type(population) is not int or population < 0:
        raise ValueError(f"population {population!r} is not a nonnegative integer")
    if type(percent) is not int or not 0 < percent <= 100:
        raise ValueError(f"percent {percent!r} is not in 1..100")
    return -(-population * percent // 100)


def select_node_ids(population: Iterable[str], count: int | None, seed: str) -> tuple[str, ...]:
    """The selected node IDs ordered by node_id; ``count`` None selects all (``--all``)."""
    unique = sorted(set(population))
    if count is None:
        return tuple(unique)
    if type(count) is not int or count < 1:
        raise ConfigurationError("usage", f"--sample N requires N > 0, not {count!r}")
    ranked = sorted((sample_key(seed, ident), ident) for ident in unique)
    return tuple(sorted(ident for _, ident in ranked[: min(count, len(ranked))]))


def target_bytes(target: AuditTarget) -> bytes:
    """``J(target)``."""
    return encode(target.to_json())


def target_sha256(target: AuditTarget) -> str:
    """The identity hash of a target: ``SHA256(J(target))``."""
    return hashlib.sha256(target_bytes(target)).hexdigest()


def targets_sha256(targets: Sequence[AuditTarget]) -> str:
    """SHA-256 of the concatenated ``J(target) + LF`` in target order."""
    digest = hashlib.sha256()
    for target in targets:
        digest.update(target_bytes(target) + b"\n")
    return digest.hexdigest()


@dataclass(frozen=True)
class Selection:
    """What the command line asks: ``--all`` (sample None) or ``--sample N``, the optional
    ``--seed`` and the comparison."""

    sample: int | None
    seed: str | None = None
    comparison: AuditComparison = AuditComparison.STRICT

    def __post_init__(self) -> None:
        if self.sample is not None and (type(self.sample) is not int or self.sample < 1):
            raise ConfigurationError("usage", f"--sample N requires N > 0, not {self.sample!r}")
        if self.seed is not None:
            parse_seed(self.seed)
        object.__setattr__(self, "comparison", AuditComparison(self.comparison))


# -- the population ------------------------------------------------------------------------------


def _source_problem(entry: Mapping[str, Any], payload: Payload) -> str | None:
    if not isinstance(payload, Attempt):
        return "is not an attempt"
    if payload.outcome != Outcome.VERIFIED_UNSAT:
        return f"is {payload.outcome.value}, not VERIFIED_UNSAT"
    found = (payload.node_id, payload.cnf_sha256, payload.proof_sha256, payload.route.value)
    wanted = (entry["node_id"], entry["cnf_sha256"], entry["proof_sha256"], entry["route"])
    if found != wanted:
        return "differs from the certificate's used attempt"
    return None


def _snapshots(
    path: Path,
    campaign: LoadedCampaign,
    wanted: Mapping[int, Mapping[str, Any]],
    limits: ReaderLimits,
) -> dict[int, tuple[int, Machinery, int]]:
    """seq -> (snapshot seq, machinery, proof bytes) for the wanted source records of one
    journal prefix."""
    found: dict[int, tuple[int, Machinery, int]] = {}
    snapshot: tuple[int, Machinery] | None = None
    with path.open("rb") as stream:
        for record in JournalReader(stream, validator_of(campaign), name=path.name, limits=limits):
            payload = record.payload
            if isinstance(payload, (Header, Resume)):
                snapshot = (record.seq, payload.machinery)
            entry = wanted.get(record.seq)
            if entry is None:
                continue
            problem = _source_problem(entry, payload)
            if problem is not None or snapshot is None:
                raise IntegrityError(
                    "audit.source", f"{path.name} record {record.seq} {problem or 'has no header'}"
                )
            assert isinstance(payload, Attempt) and payload.proof_bytes is not None
            found[record.seq] = (*snapshot, payload.proof_bytes)
    missing = sorted(set(wanted) - set(found))
    if missing:
        raise IntegrityError("audit.source", f"{path.name} has no record {missing[0]}")
    return found


def population_of(
    bound: BoundInputs, *, limits: ReaderLimits = DEFAULT_LIMITS
) -> tuple[AuditTarget, ...]:
    """Every used attempt of the recomputed certificate as an AuditTarget, by node_id."""
    return _population(bound, limits)[0]


def _population(
    bound: BoundInputs, limits: ReaderLimits
) -> tuple[tuple[AuditTarget, ...], dict[str, int]]:
    """The population and the size of each target's reference proof (by node_id)."""
    certificate = bound.recertified.certificate
    used: list[dict[str, Any]] = certificate["used_attempts"]
    by_journal: dict[str, dict[int, Mapping[str, Any]]] = {}
    for entry in used:
        record = entry["record"]
        by_journal.setdefault(record["journal"], {})[record["seq"]] = entry
    paths = {path.name[: -len(".jsonl")]: path for path in bound.snapshots}
    machinery: dict[tuple[str, int], tuple[int, Machinery, int]] = {}
    try:
        for journal, wanted in sorted(by_journal.items()):
            if journal not in paths:
                raise IntegrityError("audit.source", f"no certified journal {journal}")
            for seq, snap in _snapshots(paths[journal], bound.campaign, wanted, limits).items():
                machinery[(journal, seq)] = snap
    except CubeproofError as error:
        raise contextualize(error, IntegrityError) from None
    listed = {(m["journal"], m["snapshot_seq"]): m["machinery"] for m in certificate["machinery"]}
    derived = {(j, snap_seq): m.to_json() for (j, _), (snap_seq, m, _) in machinery.items()}
    if listed != derived:
        raise IntegrityError(
            "audit.source", "the source snapshots differ from the certificate's machinery list"
        )
    targets = []
    sizes: dict[str, int] = {}
    for entry in used:
        record = entry["record"]
        _, snapshot, size = machinery[(record["journal"], record["seq"])]
        sizes[entry["node_id"]] = size
        value = {
            "node": entry["node"],
            "node_id": entry["node_id"],
            "source": record,
            "cnf_sha256": entry["cnf_sha256"],
            "proof_sha256": entry["proof_sha256"],
            "route": entry["route"],
            "machinery": snapshot.to_json(),
        }
        targets.append(AuditTarget.from_json(value))
    return tuple(sorted(targets, key=lambda t: t.node_id)), sizes


# -- the plan ----------------------------------------------------------------------------------


@dataclass(frozen=True)
class AuditPlan:
    """The selected targets and the values of the plan records (module doc)."""

    campaign: str
    certificate_sha256: str
    comparison: AuditComparison
    seed: str
    sample_count: int
    population: int
    targets: tuple[AuditTarget, ...]
    #: the size of the largest selected reference proof (the default audit proof cap, specification
    #: §11.2)
    reference_bytes: int = 0

    def __post_init__(self) -> None:
        ids = [t.node_id for t in self.targets]
        if ids != sorted(set(ids)):
            raise ValueError("plan targets are unique and ordered by node_id")
        if len(ids) > self.population:
            raise ValueError("a plan selects at most the population")
        if type(self.reference_bytes) is not int or self.reference_bytes < 0:
            raise ValueError("reference_bytes is a nonnegative integer")

    @property
    def target_count(self) -> int:
        return len(self.targets)

    @property
    def targets_sha256(self) -> str:
        return targets_sha256(self.targets)

    def begin(self) -> AuditBegin:
        return AuditBegin(
            certificate_sha256=self.certificate_sha256,
            sample_count=self.sample_count,
            seed=self.seed,
            targets_sha256=self.targets_sha256,
            target_count=self.target_count,
            comparison=self.comparison,
        )

    def target_record(self, ordinal: int) -> AuditTargetRecord:
        return AuditTargetRecord(target=self.targets[ordinal], ordinal=ordinal)

    def ready(self) -> AuditReady:
        return AuditReady(targets_sha256=self.targets_sha256, target_count=self.target_count)

    def payloads(self) -> tuple[Payload, ...]:
        """The plan records in journal order: begin, every target, ready."""
        middle = tuple(self.target_record(i) for i in range(self.target_count))
        return (self.begin(), *middle, self.ready())


def make_plan(
    bound: BoundInputs, selection: Selection, *, limits: ReaderLimits = DEFAULT_LIMITS
) -> AuditPlan:
    """The plan of ``selection`` over the population of ``bound`` (module doc)."""
    population, sizes = _population(bound, limits)
    seed = selection.seed if selection.seed is not None else bound.certificate.sha256
    chosen = set(select_node_ids((t.node_id for t in population), selection.sample, seed))
    return AuditPlan(
        campaign=bound.campaign.campaign.campaign_id,
        certificate_sha256=bound.certificate.sha256,
        comparison=selection.comparison,
        seed=seed,
        sample_count=len(population) if selection.sample is None else selection.sample,
        population=len(population),
        targets=tuple(t for t in population if t.node_id in chosen),
        reference_bytes=max((sizes[i] for i in chosen), default=0),
    )


def check_plan_prefix(
    plan: AuditPlan,
    begin: AuditBegin | None,
    targets: Sequence[AuditTarget],
    ready: AuditReady | None,
) -> int:
    """How many target records of ``plan`` a journal already holds (IntegrityError
    ``audit.plan_changed`` if anything it holds differs from the regenerated plan)."""
    if begin is None:
        if targets or ready is not None:
            raise IntegrityError("audit.plan_order", "plan records without audit_begin")
        return 0
    if begin != plan.begin():
        raise IntegrityError(
            "audit.plan_changed", "the journal's audit_begin is not the regenerated plan's"
        )
    if len(targets) > plan.target_count:
        raise IntegrityError("audit.plan_changed", "the journal holds more targets than the plan")
    for ordinal, target in enumerate(targets):
        if target_bytes(target) != target_bytes(plan.targets[ordinal]):
            raise IntegrityError(
                "audit.plan_changed", f"audit_target {ordinal} is not the regenerated plan's"
            )
    if ready is not None and (len(targets) != plan.target_count or ready != plan.ready()):
        raise IntegrityError("audit.plan_changed", "audit_ready is not the regenerated plan's")
    return len(targets)
