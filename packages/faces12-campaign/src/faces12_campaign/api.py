"""The Python API of the application: typed values in, result values out (specification §12.1).

It mirrors the commands of :mod:`faces12_campaign.cli` and never reads the environment,
prints or exits; errors are typed (:class:`cubeproof.base.errors.CubeproofError`, with
:class:`~faces12_campaign.claim.ClaimRefused` for a refused claim). The cubeproof commands that
the application hands over unchanged (``run``, ``shard``, ``handoff``, ``certify``, ``audit``,
``status``) are :mod:`cubeproof.api`.

=======================  =========================================================
``formulas``             :func:`formulas`
``campaign init``        :func:`campaign_init` (an :class:`InitCommand`)
``campaign prefixes``    :func:`campaign_prefixes`
``claim``                :func:`claim`
``model``                :func:`models`
``selftest``, ``maps``   :func:`selftest`, :func:`census`
``release ...``          :func:`release_bundle`, :func:`release_verify`,
                         :func:`release_provenance`
=======================  =========================================================
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from faces12_campaign.campaign import InitResult, PilotRoot
from faces12_campaign.claim import ClaimRefused, ClaimResult, Publication, Review, read_review
from faces12_campaign.commands import (
    InitCommand,
    campaign_init,
    campaign_prefixes,
    census,
    claim,
    formulas,
    models,
    selftest,
)
from faces12_campaign.formulas import FormulasReport
from faces12_campaign.model import ModelsResult
from faces12_campaign.release import build_bundle, provenance_document, verify_bundle

__all__ = [
    "ClaimRefused",
    "ClaimResult",
    "FormulasReport",
    "InitCommand",
    "InitResult",
    "ModelsResult",
    "PilotRoot",
    "Publication",
    "Review",
    "campaign_init",
    "campaign_prefixes",
    "census",
    "claim",
    "formulas",
    "models",
    "read_review",
    "release_bundle",
    "release_provenance",
    "release_verify",
    "selftest",
]


def release_bundle(root: Path, output: Path, author: str = "") -> str:
    """``release bundle``: the deterministic source archive of ``root``; its SHA-256."""
    return build_bundle(root, output, author)


def release_verify(directory: Path) -> int:
    """``release verify``: an unpacked archive against its manifest; the file count."""
    return verify_bundle(directory)


def release_provenance(
    *,
    recorded_ms: int,
    root: Path | None = None,
    solver: Path | None = None,
    checker: Path | None = None,
) -> dict[str, Any]:
    """``release provenance``: what this installation is, by hash."""
    return provenance_document(recorded_ms=recorded_ms, root=root, solver=solver, checker=checker)
