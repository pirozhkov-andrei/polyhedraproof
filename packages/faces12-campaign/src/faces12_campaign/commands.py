"""Command entry points of the application: typed values in, results out; no printing, no exit.

Each function composes the adapters (formulas, campaign, claim, model, release) for one
command of specification §13.3. ``run``, ``shard``, ``handoff``, ``certify``, ``audit`` and
``status`` are not here: the command line hands them to cubeproof unchanged, because the
application adds nothing to them (no second scheduler or certifier).
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cubeproof.base.canonical_json import document_bytes
from cubeproof.base.errors import ConfigurationError
from cubeproof.commands import parse_input, publish_file
from cubeproof.contracts.campaign import Admit
from cubeproof.contracts.policy import Policy
from faces12_campaign import campaign as campaign_adapter
from faces12_campaign import claim as claim_adapter
from faces12_campaign import formulas as formulas_adapter
from faces12_campaign import model as model_adapter
from faces12_campaign.campaign import CampaignInit, InitResult, PilotRoot
from faces12_campaign.claim import ClaimResult, Publication
from faces12_campaign.formulas import FormulasReport
from faces12_campaign.model import MapSource, ModelsResult
from neighbourly.checks import Check

__all__ = [
    "InitCommand",
    "campaign_init",
    "campaign_prefixes",
    "census",
    "claim",
    "formulas",
    "models",
    "selftest",
    "write_document",
]


def formulas(
    directory: Path | None, maps: Sequence[int] | None = None, *, check: bool = False
) -> FormulasReport:
    """``formulas``: write the bundles to ``directory``; with ``check`` verify them instead;
    without a directory (``--check`` only) recompute the formulas and compare the hashes."""
    if directory is None:
        if not check:
            raise ConfigurationError("usage", "formulas needs -o DIR, or --check")
        return formulas_adapter.recompute_formulas(maps)
    if check:
        return formulas_adapter.check_formulas(directory, maps)
    return formulas_adapter.export_formulas(directory, maps)


@dataclass(frozen=True)
class InitCommand:
    """The inputs of ``campaign init``: the verified formulas directory and the choices."""

    formulas: Path
    output: Path
    solver: str
    solver_argv: tuple[str, ...]
    checker: str
    author: str
    maps: Sequence[int] | None = None
    pilots: Sequence[PilotRoot] = ()
    admit: Path | None = None
    policy: Path | None = None
    proof_mode: str = campaign_adapter.DEFAULT_PROOF_MODE
    prefix: int = campaign_adapter.DEFAULT_PREFIX
    prefixes: Path | None = None
    unpinned_checker: bool = False


def campaign_init(command: InitCommand) -> InitResult:
    """``campaign init``: verify the selected bundles (rebuilt from the packaged maps), then
    create the default, restricted or pilot campaign beside them."""
    if command.pilots and command.maps is not None:
        raise ConfigurationError("usage", "--root selects the formulas itself; drop --maps")
    maps: Sequence[int] | None = command.maps
    if command.pilots:
        maps = sorted({p.map_id for p in command.pilots})
    report = formulas_adapter.check_formulas(command.formulas, maps, exact=False)
    bundles = {e.key: Path(command.formulas) / e.key for e in report.entries}
    pilots: dict[str, list[int]] = {}
    for pilot in command.pilots:
        pilots.setdefault(formulas_adapter.bundle_key(pilot.map_id), []).append(pilot.case)
    admit = None
    if command.admit is not None:
        admit = parse_input(command.admit, lambda v: Admit.from_json(v, "$"))
    policy = None
    if command.policy is not None:
        policy = parse_input(command.policy, lambda v: Policy.from_json(v, "$"))
    return campaign_adapter.init_campaign(
        CampaignInit(
            bundles=bundles,
            output=command.output,
            solver=command.solver,
            solver_argv=tuple(command.solver_argv),
            checker=command.checker,
            author=command.author,
            admit=admit,
            policy=policy,
            proof_mode=command.proof_mode,
            prefix=command.prefix,
            prefixes=command.prefixes,
            pilots={key: tuple(cases) for key, cases in pilots.items()},
            unpinned_checker=command.unpinned_checker,
        )
    )


def campaign_prefixes(campaign: Path, output: Path | None = None) -> dict[str, Any]:
    """``campaign prefixes``: the ``proof-prefix-v1`` root splits of a campaign as a prefixes
    document,
    published to ``output`` when given (never over an existing file)."""
    document = campaign_adapter.export_prefixes(campaign)
    if output is not None:
        write_document(output, document)
    return document


def write_document(path: Path, document: Any) -> None:
    """Publish a canonical JSON document (J plus LF) at a new path, atomically."""
    publish_file(Path(path).resolve(), document_bytes(document))


def claim(
    evidence: Path,
    review: Path,
    article: Path,
    *,
    publication: Publication | None = None,
    accept_checkers: Sequence[str] = (),
) -> ClaimResult:
    """``claim``: the gate of :mod:`faces12_campaign.claim`."""
    return claim_adapter.claim(
        evidence, review, article, publication=publication, accept_checkers=accept_checkers
    )


def models(
    *,
    evidence: Path | None = None,
    campaign: Path | None = None,
    journals: Sequence[Path] = (),
    maps: MapSource | None = None,
) -> ModelsResult:
    """``model``: the models of the recomputed certificate in the article's terms."""
    return model_adapter.interpret_models(
        evidence=evidence, campaign=campaign, journals=journals, maps=maps
    )


def selftest(maps: Sequence[int] = (1,)) -> list[Check]:
    """``selftest``: identities, corpus and base formula checks (seconds)."""
    return formulas_adapter.selftest(maps)


def census() -> tuple[bool, dict[str, Any]]:
    """``maps``: the census of maps with twelve faces (minutes)."""
    return formulas_adapter.census()
