"""Campaign root splits for ``campaign create --root-split`` (specification §4.4, §9.2, §12.1).

``none``                 no root split: a root is one node (the default).
``static:FILE``          the splits of a ``cubeproof-prefixes-1`` document, used as they are
                         (explicit ordered W per node; the formula hashes in the file bind it to
                         its intended use). Entries must be well-formed for the campaign's
                         bundles and lie on a requested root or the empty cube (specification §4.4).
``proof-prefix-v1:K``   the proof-prefix algorithm (specification §9.2) with ``K`` variables per
                         formula, run with the campaign's pinned solver on every formula's empty
                         cube; the chosen prefix and its parameter/tool provenance are recorded as
                         the root split. It needs the bundle's ``order`` pool and runs a solver for
                         minutes to hours: it is a campaign construction step, not a leaf attempt.

A prefix of zero variables, or a formula for which the heuristic finds no candidate, records no
split at all (never a zero-variable split). Root splits are stored sorted by ``split_id``.
"""

from __future__ import annotations

import shutil
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from cubeproof.base.errors import ConfigurationError
from cubeproof.base.settings import DEFAULT_LIMITS, ReaderLimits
from cubeproof.cnf.bundle import Bundle
from cubeproof.commands.inputs import parse_input
from cubeproof.contracts.campaign import RootSplit
from cubeproof.contracts.documents import Prefixes
from cubeproof.contracts.primitives import K_MAX
from cubeproof.contracts.values import Node
from cubeproof.split.proof_prefix import (
    ProofPrefixParams,
    choose_prefix,
    proof_prefix_root_split,
    supervised_solver,
)
from cubeproof.tools.isolation import Isolation, PinnedBinary
from cubeproof.tools.process import Supervisor

__all__ = ["RootSplitSpec", "compute_root_splits"]

NONE = "none"
STATIC = "static"
PROOF_PREFIX = "proof-prefix-v1"


@dataclass(frozen=True)
class RootSplitSpec:
    """The parsed ``--root-split`` value."""

    kind: str = NONE
    path: Path | None = None
    count: int | None = None
    params: ProofPrefixParams = field(default_factory=ProofPrefixParams)

    @classmethod
    def parse(cls, text: str) -> RootSplitSpec:
        """``none``, ``static:FILE`` or ``proof-prefix-v1:K``; ConfigurationError otherwise."""
        if text == NONE:
            return cls()
        name, separator, rest = text.partition(":")
        if name == STATIC and separator and rest:
            return cls(STATIC, path=Path(rest))
        if name == PROOF_PREFIX and separator and rest.isascii() and rest.isdigit():
            count = int(rest)
            if not 1 <= count <= K_MAX:
                raise ConfigurationError("campaign.root_split", f"{text!r}: K must be 1..{K_MAX}")
            return cls(PROOF_PREFIX, count=count)
        raise ConfigurationError(
            "campaign.root_split",
            f"{text!r} is not none, static:FILE or {PROOF_PREFIX}:K",
        )


def _static(
    spec: RootSplitSpec, variables: Mapping[str, int], limits: ReaderLimits
) -> list[RootSplit]:
    assert spec.path is not None
    prefixes = parse_input(
        spec.path, lambda value: Prefixes.from_json(value, variables=variables), limits=limits
    )
    return [RootSplit(s.node, s.variables, s.splitter) for s in prefixes.splits]


def _proof_prefix(
    spec: RootSplitSpec,
    bundles: Mapping[str, Bundle],
    roots: Sequence[Node],
    solver: PinnedBinary,
    scratch: Path,
    supervisor: Supervisor,
) -> list[RootSplit]:
    assert spec.count is not None
    params = spec.params
    found: list[RootSplit] = []
    run_solver = supervised_solver(supervisor, solver, params, scratch)
    for root in roots:
        if root.cube:
            raise ConfigurationError(
                "campaign.root_split",
                f"{PROOF_PREFIX} splits a whole formula; "
                f"requested root {root.node_id[:16]} is a cube",
            )
        bundle = bundles[root.formula_sha256]
        pool = bundle.manifest.pools.get(params.pool)
        if pool is None:
            raise ConfigurationError(
                "campaign.pool",
                f"the bundle of {root.formula_sha256[:16]} has no pool {params.pool!r} "
                f"(needed by {PROOF_PREFIX})",
            )
        prefix = choose_prefix(bundle.formula, spec.count, pool, params, run_solver, scratch)
        if prefix.variables:
            split = proof_prefix_root_split(
                root.formula_sha256, prefix, params, solver_sha256=solver.sha256
            )
            found.append(RootSplit(split.node, split.variables, split.splitter))
    return found


def compute_root_splits(
    spec: RootSplitSpec,
    *,
    bundles: Mapping[str, Bundle],
    roots: Sequence[Node],
    solver: PinnedBinary,
    scratch_parent: Path,
    limits: ReaderLimits = DEFAULT_LIMITS,
) -> list[RootSplit]:
    """The root splits of ``spec`` for a campaign (module doc), sorted by ``split_id``.

    ``scratch_parent`` is a directory in which a ``proof-prefix-v1`` run keeps its disposable
    heuristic files (removed afterwards).
    """
    if spec.kind == NONE:
        return []
    if spec.kind == STATIC:
        found = _static(spec, {sha: b.formula.variables for sha, b in bundles.items()}, limits)
    else:
        scratch = Path(tempfile.mkdtemp(prefix=".proof-prefix-", dir=scratch_parent))
        supervisor = Supervisor(Isolation.probe())
        try:
            found = _proof_prefix(spec, bundles, roots, solver, scratch, supervisor)
        finally:
            supervisor.shutdown(grace_ms=1000)
            shutil.rmtree(scratch, ignore_errors=True)
    return sorted(found, key=_split_key)


def _split_key(split: RootSplit) -> str:
    return split.split_id
