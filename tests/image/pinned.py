"""The pinned tools of the development/test image, checked against their build record.

The image sets ``POLYHEDRAPROOF_TEST_TOOLS`` to the prefix that ``docker/test/pinned_tools.py
build`` installed: ``bin/cadical``, ``bin/cake_lpr`` and ``provenance/tools.json``. A prefix
built by the same script on another Linux host can be used the same way; a report of such a
run must say that it was not the image.

``locate`` accepts a prefix only if its binaries have the recorded SHA-256 and the record was
built from the checkout's ``docker/test/tools.json``: a test never runs unrecorded binaries,
and an image built from other pins is reported as stale instead of being used.
"""

from __future__ import annotations

import json
import os
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
DOCKER_TEST = ROOT / "docker" / "test"
if str(DOCKER_TEST) not in sys.path:
    sys.path.insert(0, str(DOCKER_TEST))

import pinned_tools  # noqa: E402

__all__ = ["ROOT", "VARIABLE", "Pinned", "ToolsUnavailable", "locate", "pinned_tools"]
VARIABLE = "POLYHEDRAPROOF_TEST_TOOLS"


class ToolsUnavailable(LookupError):
    """No usable pinned tools: the variable is unset, the record is missing or differs."""


@dataclass(frozen=True)
class Pinned:
    """A verified tool prefix and its build record (``provenance/tools.json``)."""

    prefix: Path
    record: Mapping[str, Any]

    @property
    def cadical(self) -> Path:
        return self.prefix / "bin" / "cadical"

    @property
    def cake_lpr(self) -> Path:
        return self.prefix / "bin" / "cake_lpr"

    def pin(self, tool: str) -> Mapping[str, Any]:
        """The manifest entry the tool was built from."""
        pins: Mapping[str, Any] = self.record["manifest"]["tools"][tool]
        return pins


def locate(
    environ: Mapping[str, str] | None = None, manifest: Path = pinned_tools.MANIFEST
) -> Pinned:
    """The pinned tools named by ``POLYHEDRAPROOF_TEST_TOOLS``, or ToolsUnavailable."""
    value = (os.environ if environ is None else environ).get(VARIABLE, "")
    if not value:
        raise ToolsUnavailable(
            f"{VARIABLE} is not set: image tests run in the development/test image "
            "(docker/test/run.sh run make test-all) or with a prefix built by "
            "docker/test/pinned_tools.py build"
        )
    prefix = Path(value).resolve()
    record_path = prefix / "provenance" / "tools.json"
    try:
        record = json.loads(record_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise ToolsUnavailable(f"{record_path}: {error}") from error
    problems = pinned_tools.verify(prefix)
    if problems:
        raise ToolsUnavailable(f"{prefix}: " + "; ".join(problems))
    if record.get("manifest") != pinned_tools.load_manifest(manifest):
        raise ToolsUnavailable(
            f"{prefix} was built from other pins than {manifest}; rebuild the image"
        )
    return Pinned(prefix, record)
