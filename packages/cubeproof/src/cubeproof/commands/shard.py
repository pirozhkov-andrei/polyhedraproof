"""``shard``: plan the shards of a campaign for independent machines (specification §4.5, §10.3,
§12.1).

``cubeproof shard --campaign FILE --machines N [--formula KEY ...] [--weights FILE]
[--from-open CERT --journals JOURNAL... --scope campaign|formulas] -o DIR`` writes
``DIR/shard-<k>.json`` (``cubeproof-shard-1`` documents) for machines ``k = 1..N``.

* **Default plan.** The requested roots of the campaign, each expanded through its direct campaign
  root split if there is one (the first-use shard of ``run``, specification §12.1), sorted by
  node_id and dealt round-robin: node ``i`` goes to machine ``i mod N``.
* **Weights.** ``--weights`` maps node IDs of the planned nodes to positive integer costs (unlisted
  nodes cost 1; an unknown ID or another campaign is an error). Nodes are taken largest cost first
  (ties by node_id) and each goes to the machine with the smallest accumulated cost (tie: lowest
  machine index).
* **From open.** ``--from-open CERT --journals ...`` plans the **remaining** work: the frontier of a
  validated certificate, used as it is and not expanded further. The certificate must be exactly
  what the certifier derives from those journals: the file must hold the bytes of the recomputed
  certificate (a certificate that does not match is refused), compared without parsing it, so a
  certificate has no document size limit (specification §4.1). No open entry may be a model.
  Scope ``campaign`` (default) takes ``certificate.open``, the disjoint frontier below the
  requested roots; ``formulas`` takes ``formula_open`` (everything of every formula, including
  what the requested roots do not cover) and must be asked for explicitly.
  Entries stopped as ``stuck``/``tool_blocked``/``resource_blocked`` are planned like the others
  and counted in the result; a worker that runs them from a fresh results directory tries them
  again.
* **Some formulas.** ``--formula KEY`` (repeatable) keeps, of the nodes of either plan, those of
  the named formulas of the campaign and deals only them: the plan is then a disjoint cover of
  that part of the work, and the rest of the campaign is in no file. This is how one formula of
  a campaign is computed first, by workers whose journals belong to the whole campaign. A key
  the campaign does not have is an error; weights may name only nodes that are planned, so a
  weights file of the whole campaign is refused with it.

Every machine gets its nodes sorted ``(formula_sha256, node_id)``; a machine without nodes gets no
file (a shard is never empty) and is listed in ``empty_machines``. A machine whose nodes do not fit
one journal line is given several shards ``shard-<k>-<j>`` (large node lists are divided before
use). No node is planned twice, and each shard's nodes are pairwise incompatible by construction
(the document type checks it). An output directory is never overwritten: an existing file with
other bytes is a ConfigurationError.

Like every command module this neither prints nor exits.
"""

from __future__ import annotations

import contextlib
import hashlib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO

from cubeproof.base.canonical_json import document_bytes
from cubeproof.base.errors import (
    ConfigurationError,
    ContractError,
    CubeproofError,
    InputError,
    IntegrityError,
    ResourceError,
    contextualize,
)
from cubeproof.base.paths import open_regular_file
from cubeproof.base.settings import DEFAULT_LIMITS, ReaderLimits
from cubeproof.cnf.campaign import LoadedCampaign, load_campaign
from cubeproof.commands.campaign import read_json_file
from cubeproof.contracts.documents import Shard, Weights
from cubeproof.contracts.identity import split_children
from cubeproof.contracts.values import Node
from cubeproof.coordinator.outbox import ensure_tree
from cubeproof.coordinator.ownership import chunk_nodes
from cubeproof.evidence.certify.run import CertifyLimits, certify_campaign
from cubeproof.tools.atomic import OS_FILE_CALLS, atomic_write

__all__ = [
    "PlannedShard",
    "ShardRequest",
    "ShardResult",
    "campaign_nodes",
    "deal_round_robin",
    "deal_weighted",
    "formula_hashes",
    "open_nodes",
    "read_shard_file",
    "shard_command",
    "shards_of",
]

SCOPES = ("campaign", "formulas")


# -- the nodes to plan -------------------------------------------------------------------------


def campaign_nodes(loaded: LoadedCampaign) -> list[Node]:
    """The requested roots, each expanded through its direct campaign root split (one level)."""
    campaign = loaded.campaign
    splits = {(s.node.formula_sha256, s.node.cube): s for s in campaign.root_splits}
    nodes: dict[tuple[str, str], Node] = {}
    for root in campaign.roots:
        direct = splits.get((root.formula_sha256, root.cube))
        if direct is None:
            nodes[root.sort_key] = root
            continue
        for cube in split_children(root.cube, direct.variables):
            child = Node(root.formula_sha256, cube)
            nodes[child.sort_key] = child
    return [nodes[k] for k in sorted(nodes)]


def _holds_exactly(stream: BinaryIO, expected: bytes) -> bool:
    """Whether ``stream`` holds exactly the bytes ``expected``, read in chunks of 1 MiB.

    A certificate is compared as bytes, as ``certify --evidence`` compares a packaged one: a
    canonical document has exactly one encoding, and comparing bytes needs neither a second
    parsed copy in memory nor a reader size limit."""
    view = memoryview(expected)
    offset = 0
    while chunk := stream.read(1 << 20):
        if view[offset : offset + len(chunk)] != chunk:
            return False
        offset += len(chunk)
    return offset == len(view)


def open_nodes(
    loaded: LoadedCampaign,
    certificate_path: Path,
    journals: Sequence[Path],
    scope: str,
    *,
    formulas: set[str] | None = None,
    limits: ReaderLimits = DEFAULT_LIMITS,
) -> tuple[list[Node], dict[str, int]]:
    """The frontier of the certificate for ``scope`` and the counts of stopped entries by state,
    both restricted to the formulas with the hashes ``formulas`` if given.

    The certificate is recomputed from the journals and must be identical; a model anywhere in
    the certificate (open entry or revalidated model) is refused, whatever the formulas."""
    if scope not in SCOPES:
        raise ConfigurationError("shard.scope", f"{scope!r} is not campaign or formulas")
    if not journals:
        raise ConfigurationError("shard.journals", "--from-open needs --journals")
    with contextlib.ExitStack() as stack:
        try:
            stream = stack.enter_context(open_regular_file(Path(certificate_path)))
        except OSError as error:
            raise InputError(
                "input.file", f"{certificate_path}: {error.strerror or error}"
            ) from None
        result = certify_campaign(loaded, journals, limits=CertifyLimits(reader=limits))
        try:
            same = _holds_exactly(stream, result.document)
        except OSError as error:
            raise InputError(
                "input.file", f"{certificate_path}: {error.strerror or error}"
            ) from None
    if not same:
        raise InputError(
            "shard.certificate",
            f"{certificate_path} is not the certificate of these journals "
            "(recompute it with certify)",
        )
    derived = result.certificate
    entries = derived["open" if scope == "campaign" else "formula_open"]
    if derived["models"] or any(e["state"] == "model" for e in entries):
        raise InputError(
            "shard.model", "the certificate contains a model: nothing is planned from a model"
        )
    stopped: dict[str, int] = {}
    nodes: list[Node] = []
    for entry in entries:
        node = Node.from_json(entry["node"])
        if formulas is not None and node.formula_sha256 not in formulas:
            continue
        nodes.append(node)
        if entry["state"] != "pending":
            stopped[entry["state"]] = stopped.get(entry["state"], 0) + 1
    return sorted(nodes, key=lambda n: n.sort_key), dict(sorted(stopped.items()))


# -- dealing -----------------------------------------------------------------------------------


def deal_round_robin(nodes: Sequence[Node], machines: int) -> list[list[Node]]:
    """Sorted by node_id, node ``i`` to machine ``i mod machines``."""
    _machines(machines)
    ordered = sorted(nodes, key=lambda n: n.node_id)
    lanes: list[list[Node]] = [[] for _ in range(machines)]
    for index, node in enumerate(ordered):
        lanes[index % machines].append(node)
    return lanes


def deal_weighted(nodes: Sequence[Node], machines: int, weights: Weights) -> list[list[Node]]:
    """Largest cost first (ties by node_id), each to the machine with the smallest load so far
    (ties: the lowest machine index)."""
    _machines(machines)
    ordered = sorted(nodes, key=lambda n: (-weights.cost(n.node_id), n.node_id))
    lanes: list[list[Node]] = [[] for _ in range(machines)]
    load = [0] * machines
    for node in ordered:
        target = min(range(machines), key=lambda m: (load[m], m))
        lanes[target].append(node)
        load[target] += weights.cost(node.node_id)
    return lanes


def _machines(machines: int) -> None:
    if type(machines) is not int or machines < 1:
        raise ConfigurationError("shard.machines", f"{machines!r} is not a positive integer")


def shards_of(
    campaign_id: str,
    machine: int,
    nodes: Sequence[Node],
    *,
    max_line_bytes: int = DEFAULT_LIMITS.line_bytes,
) -> list[Shard]:
    """The shards of one machine (1-based ``machine``): one, or several if the nodes would not
    fit into a journal line. Nodes sorted ``(formula_sha256, node_id)`` and kept in that order."""
    chunks = chunk_nodes(campaign_id, nodes, max_line_bytes=max_line_bytes)
    shards = []
    for index, chunk in enumerate(chunks, 1):
        name = f"shard-{machine}" if len(chunks) == 1 else f"shard-{machine}-{index}"
        shards.append(Shard(campaign_id, name, tuple(chunk)))
    return shards


# -- the command -------------------------------------------------------------------------------


@dataclass(frozen=True)
class ShardRequest:
    """The inputs of ``shard`` as values."""

    campaign: Path
    machines: int
    output: Path
    weights: Path | None = None
    from_open: Path | None = None
    journals: Sequence[Path] = ()
    scope: str = "campaign"
    #: keys of the campaign's formulas to plan; empty for all of them
    formulas: Sequence[str] = ()
    limits: ReaderLimits = DEFAULT_LIMITS


@dataclass(frozen=True)
class PlannedShard:
    """A shard file written: machine, name, file, node count, cost and the shard's ID."""

    machine: int
    name: str
    path: str
    nodes: int
    cost: int
    shard_sha256: str
    file_sha256: str

    def to_json(self) -> dict[str, Any]:
        return {
            "machine": self.machine,
            "name": self.name,
            "path": self.path,
            "nodes": self.nodes,
            "cost": self.cost,
            "shard_sha256": self.shard_sha256,
            "file_sha256": self.file_sha256,
        }


@dataclass(frozen=True)
class ShardResult:
    campaign: str
    machines: int
    scope: str
    source: str  # "roots" or "open"
    nodes: int
    shards: tuple[PlannedShard, ...]
    empty_machines: tuple[int, ...]
    #: stopped entries of a plan from open, by state (they are planned like the rest)
    stopped: Mapping[str, int]
    #: the keys of ``--formula``, sorted; empty when every formula was planned
    formulas: tuple[str, ...] = ()

    def to_json(self) -> dict[str, Any]:
        return {
            "campaign": self.campaign,
            "machines": self.machines,
            "scope": self.scope,
            "source": self.source,
            "nodes": self.nodes,
            "shards": [s.to_json() for s in self.shards],
            "empty_machines": list(self.empty_machines),
            "stopped": dict(self.stopped),
            "formulas": list(self.formulas),
        }


def formula_hashes(loaded: LoadedCampaign, keys: Sequence[str]) -> set[str] | None:
    """The hashes of the campaign's formulas with these keys; None when no key is given.

    A key the campaign does not have is a ConfigurationError: a misspelt formula must not
    become an empty or a smaller plan."""
    if not keys:
        return None
    known = {entry.key: entry.formula_sha256 for entry in loaded.campaign.formulas}
    unknown = sorted(set(keys) - set(known))
    if unknown:
        raise ConfigurationError(
            "shard.formula",
            f"the campaign has no formula {', '.join(unknown)}; its formulas are "
            f"{', '.join(sorted(known))}",
        )
    return {known[key] for key in keys}


def read_shard_file(
    path: Path, *, variables: Mapping[str, int], limits: ReaderLimits = DEFAULT_LIMITS
) -> Shard:
    """A shard document (``run --shard FILE``) valid for these formulas; InputError otherwise."""
    value = read_json_file(path, limits=limits)
    try:
        return Shard.from_json(value, variables=variables)
    except (ContractError, ResourceError) as error:
        raise contextualize(error, InputError) from None


def _publish(directory: Path, name: str, data: bytes) -> Path:
    path = directory / f"{name}.json"
    try:
        atomic_write(str(path), data)
    except IntegrityError:
        raise ConfigurationError(
            "shard.exists", f"{path} exists with other content; use a new output directory"
        ) from None
    return path


def shard_command(request: ShardRequest) -> ShardResult:
    """Plan and write the shards (module doc)."""
    _machines(request.machines)
    loaded = load_campaign(request.campaign, limits=request.limits)
    campaign_id = loaded.campaign.campaign_id
    wanted = formula_hashes(loaded, request.formulas)  # before a certificate is recomputed
    stopped: dict[str, int] = {}
    if request.from_open is not None:
        nodes, stopped = open_nodes(
            loaded,
            request.from_open,
            request.journals,
            request.scope,
            formulas=wanted,
            limits=request.limits,
        )
        source = "open"
    else:
        if request.journals or request.scope != "campaign":
            raise ConfigurationError("shard.scope", "--journals and --scope belong to --from-open")
        nodes = campaign_nodes(loaded)
        source = "roots"
    if wanted is not None:
        nodes = [n for n in nodes if n.formula_sha256 in wanted]
    weights: Weights | None = None
    if request.weights is not None:
        try:
            weights = Weights.from_json(
                read_json_file(request.weights, limits=request.limits),
                planned=[n.node_id for n in nodes],
            )
        except CubeproofError as error:
            raise contextualize(error, InputError) from None
        if weights.campaign != campaign_id:
            raise InputError("shard.weights", "the weights are of another campaign")
    lanes = (
        deal_round_robin(nodes, request.machines)
        if weights is None
        else deal_weighted(nodes, request.machines, weights)
    )
    planned: list[tuple[int, Shard]] = []
    for machine, lane in enumerate(lanes, 1):
        planned.extend(
            (machine, s)
            for s in shards_of(campaign_id, machine, lane, max_line_bytes=request.limits.line_bytes)
        )
    directory = Path(request.output).resolve()
    ensure_tree(directory, OS_FILE_CALLS)
    written: list[PlannedShard] = []
    for machine, shard in planned:
        data = document_bytes(shard.to_json())
        path = _publish(directory, shard.name, data)
        written.append(
            PlannedShard(
                machine,
                shard.name,
                str(path),
                len(shard.nodes),
                sum(1 if weights is None else weights.cost(n.node_id) for n in shard.nodes),
                shard.shard_id,
                hashlib.sha256(data).hexdigest(),
            )
        )
    empty = tuple(m for m, lane in enumerate(lanes, 1) if not lane)
    return ShardResult(
        campaign_id,
        request.machines,
        request.scope if source == "open" else "campaign",
        source,
        len(nodes),
        tuple(written),
        empty,
        stopped,
        tuple(sorted(set(request.formulas))),
    )
