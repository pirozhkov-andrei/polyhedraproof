"""Release integration: the deterministic source archive, provenance and generated documents.

The functions behind ``release bundle|verify|provenance|docs``, with the source root and the
tool binaries as explicit arguments.
"""

from __future__ import annotations

from faces12_campaign.release.bundle import (
    FORMAT_SOURCE_BUNDLE,
    build_bundle,
    release_payloads,
    verify_bundle,
)
from faces12_campaign.release.docs import CommandLine, check, generated, render_reference, write
from faces12_campaign.release.provenance import FORMAT_PROVENANCE, provenance_document

__all__ = [
    "FORMAT_PROVENANCE",
    "FORMAT_SOURCE_BUNDLE",
    "CommandLine",
    "build_bundle",
    "check",
    "generated",
    "provenance_document",
    "release_payloads",
    "render_reference",
    "verify_bundle",
    "write",
]
