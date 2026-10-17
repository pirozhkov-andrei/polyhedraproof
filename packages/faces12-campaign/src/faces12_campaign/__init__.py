"""faces12_campaign: the twelve-faces application of cubeproof and neighbourly.

The 59-formula campaign, the claim gate, and launch, release and documentation
integration. Commands are thin adapters over the `cubeproof` and `neighbourly` libraries,
never a second scheduler or certifier (specification §13.3).

Adapters: :mod:`faces12_campaign.formulas` (the 59 published bundles and the corpus
controls), :mod:`faces12_campaign.campaign` (default, restricted and pilot campaigns,
proof prefixes), :mod:`faces12_campaign.claim` (the claim gate),
:mod:`faces12_campaign.model` (models in the article's terms) and
:mod:`faces12_campaign.release` (source archive, provenance, generated reference).
:mod:`faces12_campaign.commands` composes them; :mod:`faces12_campaign.api` and
:mod:`faces12_campaign.cli` (``python -m faces12_campaign``) are the entry points.
"""

from __future__ import annotations

__version__ = "1.0.0rc1"

__all__ = ["__version__"]
