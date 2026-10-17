"""The twelve-faces campaign: defaults, proof prefixes and pilot roots (specification §13.3).

A campaign here is a ``cubeproof-campaign-1`` document made by
:func:`cubeproof.commands.create_campaign`; this adapter only decides its inputs:

- **default**: every given formula (the commands give the 59 verified bundles), each requested
  root empty, the fixed static prefix of 12 variables as campaign root split
  (``proof-prefix-v1``, specification §9.2), then the dynamic policy default
  ``lookahead-v1`` with ``k = 4``; proof mode ``transient`` unless chosen;
- ``prefix 0``: no root split at all (fully dynamic); ``prefix K`` (1..20): another initial
  depth, computed by ``proof-prefix-v1:K`` with the pinned solver (minutes to hours);
- **reuse**: a ``cubeproof-prefixes-1`` file of earlier ``proof-prefix-v1`` selections is
  accepted instead of the computation only if every entry validates: the formula is one of
  the campaign's base formulas, the split is at the empty cube, the ordered variables are
  ``K`` distinct variables of the bundle's ``order`` pool, and the recorded provenance is the
  pinned algorithm (samples 2, steps 100000, conflicts 90000, seed 5, pool ``order``, the RNG
  profile ``python-random-below-0.5-positive``) run with the solver binary this campaign pins
  (its SHA-256). Entries for formulas outside the campaign are ignored; a campaign formula
  without an entry is refused;
- **pilot root** (``map:case``, for example ``2:17``): the requested root is the case's cube
  under the formula's proof prefix -- variable ``W[j]`` positive when bit ``j`` of the case
  number is 1 (the case numbering), canonicalized by sorting -- and the prefix split stays
  at the empty cube, so the pilot root is one of its children. Its 12 literals are not
  appended again anywhere, and closing it says nothing about the rest of the map.

Nothing here schedules or certifies; the campaign document is validated by cubeproof exactly
as every reader validates it.
"""

from __future__ import annotations

import os
import shutil
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final

from cubeproof.base.canonical_json import document_bytes
from cubeproof.base.errors import ConfigurationError, CubeproofError, InputError
from cubeproof.cnf.bundle import Bundle, load_bundle
from cubeproof.commands import (
    CampaignRequest,
    RootSplitSpec,
    create_campaign,
    parse_input,
    read_json_file,
)
from cubeproof.contracts.campaign import Admit, Campaign
from cubeproof.contracts.documents import Prefixes, Roots
from cubeproof.contracts.policy import Policy, default_policy
from cubeproof.contracts.primitives import K_MAX
from cubeproof.contracts.values import Node, Split
from cubeproof.split.proof_prefix import PROOF_PREFIX_NAME, ProofPrefixParams
from cubeproof.tools.isolation import PinnedBinary
from faces12_campaign import pins

__all__ = [
    "DEFAULT_PREFIX",
    "DEFAULT_PROOF_MODE",
    "FORMAT_INIT",
    "PROOF_PREFIX_POOL",
    "CampaignInit",
    "InitResult",
    "PilotRoot",
    "export_prefixes",
    "init_campaign",
    "prefix_cube",
    "prefixes_document",
    "read_proof_prefixes",
]

#: Variables of the static prefix of the default campaign.
DEFAULT_PREFIX: Final = 12
#: The proof mode of the default campaign.
DEFAULT_PROOF_MODE: Final = "transient"
#: The pool the proof prefix is chosen from (the order bits of the bundles).
PROOF_PREFIX_POOL: Final = "order"
#: The RNG profile recorded by ``proof-prefix-v1`` (cubeproof.split.proof_prefix).
PROOF_PREFIX_RNG: Final = "python-random-below-0.5-positive"
#: The result document of ``campaign init``.
FORMAT_INIT: Final = "faces12-campaign-init-1"


@dataclass(frozen=True, order=True)
class PilotRoot:
    """A requested root given as a case: ``case`` of ``map_id`` under its proof prefix."""

    map_id: int
    case: int

    @classmethod
    def parse(cls, text: str) -> PilotRoot:
        """``MAP:CASE`` with decimal numbers (``2:17``)."""
        first, colon, second = text.partition(":")
        if not colon or not first.isdigit() or not second.isdigit():
            raise ConfigurationError("campaign.root", f"{text!r} is not MAP:CASE")
        return cls(int(first), int(second))


def prefix_cube(variables: Sequence[int], case: int) -> tuple[int, ...]:
    """The canonical cube of case ``case`` under the ordered prefix ``variables``.

    Bit ``j`` of the case number gives ``+W[j]`` when set and ``-W[j]`` otherwise (the
    case numbering, equal to the child numbering of specification §3.2); the literals are then
    sorted by variable.
    """
    if not variables:
        raise ConfigurationError("campaign.root", "a case needs a nonempty prefix")
    if type(case) is not int or not 0 <= case < 1 << len(variables):
        raise ConfigurationError(
            "campaign.root", f"case {case!r} is not in 0..{(1 << len(variables)) - 1}"
        )
    signed = [v if case >> j & 1 else -v for j, v in enumerate(variables)]
    return tuple(sorted(signed, key=abs))


# -- proof prefixes ----------------------------------------------------------------------------


def _check_info(info: Mapping[str, Any], solver_sha256: str, where: str) -> None:
    params = ProofPrefixParams()
    expected = {
        "algorithm": PROOF_PREFIX_NAME,
        "samples": params.samples,
        "steps": params.steps,
        "conflicts": params.conflicts,
        "seed": params.seed,
        "pool": PROOF_PREFIX_POOL,
        "rng": PROOF_PREFIX_RNG,
    }
    for name, value in expected.items():
        if name not in info or info[name] != value or type(info[name]) is not type(value):
            raise InputError(
                "campaign.prefix_provenance",
                f"{where}: splitter info {name} is {info.get(name)!r}, the pinned algorithm has "
                f"{value!r}",
            )
    solver = info.get("solver")
    if (
        not isinstance(solver, dict)
        or solver.get("sha256") != solver_sha256
        or solver.get("options") != list(params.solver_options)
    ):
        raise InputError(
            "campaign.prefix_provenance",
            f"{where}: the prefix was not selected with the pinned solver {solver_sha256} and "
            "no extra options",
        )


def read_proof_prefixes(
    path: Path,
    bundles: Mapping[str, Bundle],
    *,
    count: int,
    solver_sha256: str,
) -> dict[str, Split]:
    """The validated proof prefix of every campaign formula from a prefixes file (module doc).

    ``bundles`` maps the campaign's formula hashes to their verified bundles. Returns formula
    hash -> split; InputError naming the rule otherwise.
    """
    variables = {sha: b.formula.variables for sha, b in bundles.items()}
    prefixes = parse_input(Path(path), lambda v: Prefixes.from_json(v, variables=variables))
    found: dict[str, Split] = {}
    for index, split in enumerate(prefixes.splits):
        sha = split.node.formula_sha256
        where = f"{path}: splits[{index}]"
        if sha not in bundles:
            continue  # selections for other formulas (the file may cover all 59)
        if split.node.cube:
            raise InputError(
                "campaign.prefix_cube", f"{where}: a proof prefix splits the empty cube"
            )
        if sha in found:
            raise InputError("campaign.prefix_duplicate", f"{where}: a second prefix of {sha}")
        if split.splitter.name != PROOF_PREFIX_NAME:
            raise InputError(
                "campaign.prefix_provenance", f"{where}: splitter {split.splitter.name!r}"
            )
        _check_info(split.splitter.info.to_json(), solver_sha256, where)
        if len(split.variables) != count:
            raise InputError(
                "campaign.prefix_count",
                f"{where}: {len(split.variables)} variables, the campaign asks for {count}",
            )
        pool = set(bundles[sha].manifest.pools.get(PROOF_PREFIX_POOL, ()))
        outside = [v for v in split.variables if v not in pool]
        if outside:
            raise InputError(
                "campaign.prefix_pool",
                f"{where}: {outside} are not in the {PROOF_PREFIX_POOL} pool",
            )
        found[sha] = split
    missing = sorted(set(bundles) - set(found))
    if missing:
        raise InputError(
            "campaign.prefix_missing", f"{path}: no proof prefix for formulas {missing}"
        )
    return found


def prefixes_document(splits: Sequence[Split]) -> dict[str, Any]:
    """A ``cubeproof-prefixes-1`` document of ``splits`` (sorted by split_id)."""
    ordered = sorted(splits, key=lambda s: s.split_id)
    return Prefixes(tuple(ordered)).to_json()


def export_prefixes(campaign: Path) -> dict[str, Any]:
    """The ``proof-prefix-v1`` root splits (at empty cubes) of an existing campaign as a prefixes
    document, for reuse by a new ``campaign init`` (the receiving init validates them again)."""
    document = read_json_file(Path(campaign))
    try:
        loaded = Campaign.from_json(document)
    except CubeproofError as error:
        raise InputError(error.rule, f"{campaign}: {error.detail}") from None
    splits = [
        Split(s.node, s.variables, s.splitter)
        for s in loaded.root_splits
        if s.splitter.name == PROOF_PREFIX_NAME and not s.node.cube
    ]
    return prefixes_document(splits)


# -- campaign init -------------------------------------------------------------------------------


@dataclass(frozen=True)
class CampaignInit:
    """The inputs of ``campaign init`` as values.

    ``bundles`` maps formula keys to verified bundle directories, which must lie in the
    directory of ``output`` (paths in a campaign are relative to it).
    """

    bundles: Mapping[str, Path]
    output: Path
    solver: str
    solver_argv: tuple[str, ...]
    checker: str
    author: str
    admit: Admit | None = None
    policy: Policy | None = None
    proof_mode: str = DEFAULT_PROOF_MODE
    prefix: int = DEFAULT_PREFIX
    prefixes: Path | None = None
    pilots: Mapping[str, tuple[int, ...]] = field(default_factory=dict)
    unpinned_checker: bool = False


@dataclass(frozen=True)
class InitResult:
    """What ``campaign init`` published."""

    path: str
    campaign_id: str
    formulas: tuple[tuple[str, str], ...]
    roots: tuple[Node, ...]
    root_splits: int
    root_split: str
    split_policy: dict[str, Any]
    solver_sha256: str
    checker_sha256: str
    admitted_checkers: tuple[str, ...]
    release_checker: bool

    def to_json(self) -> dict[str, Any]:
        return {
            "format": FORMAT_INIT,
            "campaign": self.path,
            "campaign_id": self.campaign_id,
            "formulas": [{"key": k, "formula_sha256": s} for k, s in self.formulas],
            "roots": [n.to_json() for n in self.roots],
            "root_splits": self.root_splits,
            "root_split": self.root_split,
            "split_policy": self.split_policy,
            "tools": {
                "solver_sha256": self.solver_sha256,
                "checker_sha256": self.checker_sha256,
                "admitted_checkers": list(self.admitted_checkers),
                "release_checker": self.release_checker,
                "release_solver": self.solver_sha256 == pins.RELEASE_SOLVER_SHA256,
            },
        }


def _load(request: CampaignInit) -> dict[str, tuple[str, Bundle]]:
    """Formula hash -> (key, verified cubeproof bundle) of every given bundle."""
    root = Path(request.output).resolve().parent
    loaded: dict[str, tuple[str, Bundle]] = {}
    for key, directory in sorted(request.bundles.items()):
        if Path(directory).resolve().name != key:
            # cubeproof takes the formula key from the bundle directory name
            raise ConfigurationError("campaign.key", f"bundle {directory} is not named {key!r}")
        relative = os.path.relpath(Path(directory).resolve(), root)
        try:
            bundle = load_bundle(root, Path(relative).as_posix())
        except CubeproofError as error:
            raise InputError(error.rule, f"{directory}: {error.detail}") from None
        loaded[bundle.manifest.formula_sha256] = (key, bundle)
    return loaded


def _pilot_roots(
    request: CampaignInit, loaded: Mapping[str, tuple[str, Bundle]], splits: Mapping[str, Split]
) -> tuple[Node, ...]:
    by_key = {key: sha for sha, (key, _) in loaded.items()}
    if set(request.pilots) != set(by_key):
        raise ConfigurationError(
            "campaign.root",
            "a pilot campaign holds exactly the formulas of its requested roots: "
            f"roots for {sorted(request.pilots)}, formulas {sorted(by_key)}",
        )
    nodes: list[Node] = []
    for key, cases in sorted(request.pilots.items()):
        if not cases or len(set(cases)) != len(cases):
            raise ConfigurationError("campaign.root", f"{key}: cases must be distinct")
        sha = by_key[key]
        prefix = splits[sha].variables
        nodes.extend(Node(sha, prefix_cube(prefix, case)) for case in cases)
    return tuple(sorted(nodes, key=lambda n: n.sort_key))


def _release_checker(checker: str, admit: Admit, unpinned_checker: bool) -> bool:
    """Whether every checker of the campaign is the cake_lpr of the release
    (:mod:`faces12_campaign.pins`).

    A campaign names its checker by hash, and a certificate believes every checker the campaign
    admits; a campaign created with another program in the place of cake_lpr would certify like
    any other. ``campaign init`` therefore refuses a checker that is not the release binary
    unless the caller says so explicitly (``unpinned_checker``); the claim gate checks again.
    The solver only proposes proofs and is not restricted.
    """
    foreign = pins.unpinned({checker, *admit.checker_sha256})
    if foreign and not unpinned_checker:
        raise ConfigurationError(
            "campaign.checker",
            f"the checker {', '.join(foreign)} is not the cake_lpr of this release "
            f"({pins.RELEASE_CHECKER_SHA256}). Use the checker of the release image, or pass "
            "--unpinned-checker to create a campaign that the claim gate accepts only with "
            "--accept-checker",
        )
    return not foreign


def init_campaign(request: CampaignInit) -> InitResult:
    """Decide the inputs (module doc) and publish the campaign with cubeproof."""
    prefix = request.prefix
    if type(prefix) is not int or not 0 <= prefix <= K_MAX:
        raise ConfigurationError("campaign.prefix", f"--prefix must be 0..{K_MAX}, not {prefix!r}")
    if prefix == 0 and request.prefixes is not None:
        raise ConfigurationError("campaign.prefix", "--prefix 0 means no prefix; drop --prefixes")
    if request.pilots and request.prefixes is None:
        raise ConfigurationError(
            "campaign.root",
            "a pilot root is a case of a stored prefix: give --prefixes FILE",
        )
    if not request.bundles:
        raise ConfigurationError("campaign.formulas", "no formula selected")
    output = Path(request.output).resolve()
    if output.exists():
        raise ConfigurationError("campaign.exists", f"{output} already exists")
    loaded = _load(request)
    bundles = {sha: bundle for sha, (_, bundle) in loaded.items()}
    policy = request.policy if request.policy is not None else default_policy(request.proof_mode)
    checker_sha = PinnedBinary.measure(request.checker).sha256
    solver_sha = PinnedBinary.measure(request.solver).sha256
    admit = request.admit
    if admit is None:
        admit = Admit.from_json({"checker_sha256": [checker_sha], "solvers": None}, "$")
    release_checker = _release_checker(checker_sha, admit, request.unpinned_checker)
    roots: Roots | None = None
    staging: Path | None = None
    try:
        if prefix == 0:
            spec, mode = RootSplitSpec(), "none"
        elif request.prefixes is not None:
            splits = read_proof_prefixes(
                request.prefixes, bundles, count=prefix, solver_sha256=solver_sha
            )
            if request.pilots:
                roots = Roots(_pilot_roots(request, loaded, splits))
            staging = Path(tempfile.mkdtemp(prefix=".faces12-prefixes-", dir=output.parent))
            static = staging / "prefixes.json"
            static.write_bytes(document_bytes(prefixes_document(list(splits.values()))))
            spec, mode = (
                RootSplitSpec("static", path=static),
                f"{PROOF_PREFIX_NAME}:{prefix} (reused)",
            )
        else:
            spec = RootSplitSpec("proof-prefix-v1", count=prefix)
            mode = f"{PROOF_PREFIX_NAME}:{prefix} (computed)"
        campaign = create_campaign(
            CampaignRequest(
                bundles=[bundle.directory for bundle in bundles.values()],
                policy=policy,
                admit=admit,
                solver=request.solver,
                solver_argv=list(request.solver_argv),
                checker=request.checker,
                output=output,
                author=request.author,
                roots=roots,
                root_split=spec,
            )
        )
    finally:
        if staging is not None:
            shutil.rmtree(staging, ignore_errors=True)
    return InitResult(
        path=str(output),
        campaign_id=campaign.campaign_id,
        formulas=tuple((e.key, e.formula_sha256) for e in campaign.formulas),
        roots=campaign.roots,
        root_splits=len(campaign.root_splits),
        root_split=mode,
        split_policy=campaign.policy.split.to_json(),
        solver_sha256=solver_sha,
        checker_sha256=checker_sha,
        admitted_checkers=tuple(admit.checker_sha256),
        release_checker=release_checker,
    )
