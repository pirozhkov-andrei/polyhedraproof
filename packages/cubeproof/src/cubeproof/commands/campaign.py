"""``campaign create`` and ``certify``: minimal command entry points (specification §4.4, §10,
§12.1).

``create_campaign`` assembles a ``cubeproof-campaign-1`` document from verified bundles, a
policy, the admission lists and the pinned tools, validates it exactly as every reader does
(``check_campaign`` over the bundles' facts) and publishes it atomically beside its bundles
(bundle paths are relative to the campaign file and stay inside its directory). It refuses to
overwrite an existing file. The solver argv is an explicit input: nothing about the production
CaDiCaL command line is decided here.

``--root-split`` (specification §4.4, §9.2) is a value of the request
(:class:`~.rootsplit.RootSplitSpec`): ``none``, an explicit ``static:FILE`` prefixes document, or
the ``proof-prefix-v1:K`` computation.

``certify_command`` is the library form of ``cubeproof certify``: it runs the certifier on a
campaign and explicit journal files, publishes the certificate and returns the verdict with its
exit code (specification §12.2). Errors are typed; only the CLI exits or prints.
"""

from __future__ import annotations

import os
import time
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from cubeproof.base.canonical_json import document_bytes
from cubeproof.base.errors import ConfigurationError, CubeproofError, InputError, contextualize
from cubeproof.base.ids import new_id128
from cubeproof.base.settings import DEFAULT_LIMITS, ReaderLimits
from cubeproof.cnf.bundle import Bundle, load_bundle
from cubeproof.commands.inputs import read_json_file
from cubeproof.commands.rootsplit import RootSplitSpec, compute_root_splits
from cubeproof.contracts.campaign import Admit, Campaign, check_campaign
from cubeproof.contracts.documents import Roots
from cubeproof.contracts.policy import Policy
from cubeproof.contracts.primitives import format_utc, is_name, is_relpath
from cubeproof.contracts.values import Node
from cubeproof.evidence.certify.run import CertifyLimits, CertifyResult, certify
from cubeproof.tools.isolation import PinnedBinary

__all__ = [
    "CampaignRequest",
    "certify_command",
    "create_campaign",
    "publish_file",
    "read_json_file",
]


@dataclass(frozen=True)
class CampaignRequest:
    """The inputs of ``campaign create`` as values."""

    bundles: Sequence[Path]
    policy: Policy
    admit: Admit
    solver: str
    solver_argv: Sequence[str]
    checker: str
    output: Path
    author: str
    roots: Roots | None = None
    root_split: RootSplitSpec = RootSplitSpec()  # noqa: RUF009 - an immutable value


def _key_of(bundle: Path) -> str:
    key = bundle.resolve().name
    if not is_name(key):
        raise ConfigurationError(
            "campaign.key", f"{key!r} (the bundle directory name) is not a formula key (a Name)"
        )
    return key


def create_campaign(request: CampaignRequest, *, limits: ReaderLimits = DEFAULT_LIMITS) -> Campaign:
    """Build, validate and publish a campaign (module doc); the validated Campaign."""
    output = Path(request.output).resolve()
    if output.exists():
        raise ConfigurationError("campaign.exists", f"{output} already exists")
    if not request.bundles:
        raise ConfigurationError("campaign.bundles", "at least one bundle is required")
    root = output.parent
    entries: list[dict[str, str]] = []
    loaded: dict[str, Bundle] = {}
    for given in request.bundles:
        directory = Path(given).resolve()
        try:
            relative = os.path.relpath(directory, root)
        except ValueError:
            relative = ""
        if not is_relpath(relative):
            raise ConfigurationError(
                "campaign.bundle_path",
                f"bundle {directory} must lie inside the campaign directory {root}",
            )
        bundle = load_bundle(root, relative, limits=limits)
        sha = bundle.manifest.formula_sha256
        entries.append({"key": _key_of(directory), "formula_sha256": sha, "bundle": relative})
        loaded[sha] = bundle
    entries.sort(key=lambda entry: entry["key"])
    roots: tuple[Node, ...]
    if request.roots is not None:
        roots = request.roots.roots
    else:
        roots = tuple(sorted((Node(e["formula_sha256"], ()) for e in entries), key=_sort))
    solver = PinnedBinary.measure(request.solver)
    checker = PinnedBinary.measure(request.checker)
    splits = compute_root_splits(
        request.root_split,
        bundles=loaded,
        roots=roots,
        solver=solver,
        scratch_parent=root,
        limits=limits,
    )
    document = {
        "format": "cubeproof-campaign-1",
        "created_utc": format_utc(time.time_ns() // 1_000_000),
        "author": request.author,
        "formulas": entries,
        "roots": [n.to_json() for n in roots],
        "root_splits": [s.to_json() for s in splits],
        "policy": request.policy.to_json(),
        "tools": {
            "solver": {
                "name": "cadical",
                "sha256": solver.sha256,
                "argv": list(request.solver_argv),
            },
            "checker": {"name": "cake_lpr", "sha256": checker.sha256},
        },
        "admit": request.admit.to_json(),
    }
    try:
        campaign = Campaign.from_json(document)
        check_campaign(campaign, {sha: b.facts for sha, b in loaded.items()})
    except CubeproofError as error:
        raise contextualize(error, InputError) from None
    publish_file(output, document_bytes(campaign.to_json()))
    return campaign


def _sort(node: Node) -> tuple[str, str]:
    return node.sort_key


def publish_file(path: Path, data: bytes) -> None:
    """Write ``data`` to a fresh temporary name beside ``path``, fsync, link without replacing
    (ConfigurationError ``campaign.exists`` if ``path`` appeared), sync the directory."""
    temporary = path.with_name(f".{path.name}.{new_id128()}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    try:
        view = memoryview(data)
        while view:
            view = view[os.write(descriptor, view) :]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    try:
        os.link(temporary, path)  # fails if the target appeared meanwhile: never replaces
    except FileExistsError:
        raise ConfigurationError("campaign.exists", f"{path} already exists") from None
    finally:
        os.unlink(temporary)
    directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def certify_command(
    campaign: Path,
    journals: Sequence[Path],
    output: Path | None,
    *,
    limits: CertifyLimits = CertifyLimits(),  # noqa: B008 - immutable value
) -> CertifyResult:
    """``cubeproof certify``: the certifier's result; the certificate document is published to
    ``output`` (atomically, replacing a previous certificate of the same name is refused)."""
    result = certify(campaign, journals, limits=limits)
    if output is not None:
        publish_file(Path(output).resolve(), result.document)
    return result
