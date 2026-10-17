"""Loading a campaign file with its bundles (specification §4.4, §4.2).

Order: the campaign document (size limit, canonical JSON, schema, canonical node cubes), then
each formula's bundle in campaign order (containment, manifest, formula), then the campaign
rules with the bundles' facts. Every violation is an :class:`~cubeproof.base.errors.InputError`
named by its rule; a reader limit is a :class:`~cubeproof.base.errors.ResourceError`.
Bundle paths are relative to the directory of the campaign file.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType

from cubeproof.base.canonical_json import parse_document
from cubeproof.base.errors import CubeproofError, InputError, contextualize
from cubeproof.base.paths import read_at_most
from cubeproof.base.settings import DEFAULT_LIMITS, ReaderLimits
from cubeproof.cnf.bundle import Bundle, load_bundle
from cubeproof.cnf.dimacs import Formula
from cubeproof.contracts.campaign import Campaign, check_campaign


@dataclass(frozen=True)
class LoadedCampaign:
    """A validated campaign and its verified bundles, keyed by formula hash."""

    path: Path
    campaign: Campaign
    bundles: Mapping[str, Bundle]

    def formula(self, formula_sha256: str) -> Formula:
        return self.bundles[formula_sha256].formula

    def key(self, formula_sha256: str) -> str:
        return next(e.key for e in self.campaign.formulas if e.formula_sha256 == formula_sha256)


def load_campaign(path: Path, *, limits: ReaderLimits = DEFAULT_LIMITS) -> LoadedCampaign:
    """Read, verify and return the campaign at ``path`` with all its bundles."""
    path = Path(path)
    try:
        with path.open("rb") as stream:
            # J(campaign) + LF + one more byte suffices to detect limit.document.
            data = read_at_most(stream, limits.document_bytes + 2)
    except OSError as exc:
        raise InputError("campaign.file", f"{path}: {exc.strerror or exc}") from None
    try:
        campaign = Campaign.from_json(parse_document(data, limits=limits))
    except CubeproofError as error:
        raise contextualize(error, InputError) from None
    bundles: dict[str, Bundle] = {}
    for entry in campaign.formulas:
        bundle = load_bundle(path.parent, entry.bundle, limits=limits)
        if bundle.manifest.formula_sha256 != entry.formula_sha256:
            raise InputError("bundle.campaign_hash", f"{entry.key}: bundle of another formula")
        bundles.setdefault(entry.formula_sha256, bundle)
    try:
        check_campaign(campaign, {sha: b.facts for sha, b in bundles.items()})
    except CubeproofError as error:
        raise contextualize(error, InputError) from None
    return LoadedCampaign(path, campaign, MappingProxyType(bundles))
