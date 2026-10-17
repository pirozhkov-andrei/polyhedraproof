"""Immutable settings values constructed by the CLI and API entry boundaries (specification §2.3,
§4.1).

The environment and the process arguments are read only by the CLI/API boundary; they build
a :class:`Settings` value (directly or from string options with :meth:`Settings.from_options`)
and pass it down. Nothing here reads ``os.environ``.

- :class:`ReaderLimits`: the default safety limits of specification §4.1 (8 MiB per journal line, 64
  MiB per campaign or shard document, nesting depth 32, 16 KiB diagnostic tails). They may be
  lowered or explicitly raised; hitting one is a :class:`~cubeproof.base.errors.ResourceError`.
- :class:`ToolPaths`: absolute local paths of the external programs (specification §4.1: "CLI binary
  paths are absolute local paths and are never inferred from untrusted artifact fields"). Their
  hashes are checked against the campaign by the tool layer, not here.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field

from cubeproof.base.errors import ConfigurationError

MIB = 1024 * 1024
_DECIMAL = re.compile(r"[1-9][0-9]{0,18}")
_INT_MAX = 2**63 - 1


def _positive(name: str, value: object) -> None:
    if type(value) is not int or not 1 <= value <= _INT_MAX:
        raise ConfigurationError(f"settings.{name}", f"{value!r} is not a positive integer")


def _absolute(name: str, value: object) -> None:
    if value is None:
        return
    if not isinstance(value, str) or not value.startswith("/") or "\0" in value:
        raise ConfigurationError(f"settings.{name}", f"{value!r} is not an absolute local path")


@dataclass(frozen=True)
class ReaderLimits:
    """Reader byte and nesting limits (specification §4.1)."""

    line_bytes: int = 8 * MIB
    document_bytes: int = 64 * MIB
    depth: int = 32
    tail_bytes: int = 16 * 1024

    def __post_init__(self) -> None:
        _positive("reader_line_bytes", self.line_bytes)
        _positive("reader_document_bytes", self.document_bytes)
        _positive("reader_depth", self.depth)
        _positive("reader_tail_bytes", self.tail_bytes)


DEFAULT_LIMITS = ReaderLimits()


@dataclass(frozen=True)
class ToolPaths:
    """Absolute paths of the solver, checker and optional splitter helper (or None)."""

    solver: str | None = None
    checker: str | None = None
    helper: str | None = None

    def __post_init__(self) -> None:
        _absolute("solver", self.solver)
        _absolute("checker", self.checker)
        _absolute("helper", self.helper)


#: The string options accepted by :meth:`Settings.from_options`.
OPTION_NAMES: tuple[str, ...] = (
    "reader_line_bytes",
    "reader_document_bytes",
    "reader_depth",
    "reader_tail_bytes",
    "solver",
    "checker",
    "helper",
)
_LIMIT_FIELDS = {
    "reader_line_bytes": "line_bytes",
    "reader_document_bytes": "document_bytes",
    "reader_depth": "depth",
    "reader_tail_bytes": "tail_bytes",
}


@dataclass(frozen=True)
class Settings:
    """Everything lower layers need from the entry boundary, as one immutable value."""

    limits: ReaderLimits = field(default_factory=ReaderLimits)
    tools: ToolPaths = field(default_factory=ToolPaths)

    @classmethod
    def from_options(cls, options: Mapping[str, str]) -> Settings:
        """Settings from string options (``OPTION_NAMES``); absent options keep defaults.

        Integers are canonical positive decimals; paths are absolute. The caller decides
        where the strings come from (command-line options, an API mapping, environment
        variables read at the boundary).
        """
        unknown = sorted(set(options) - set(OPTION_NAMES))
        if unknown:
            raise ConfigurationError("settings.unknown", ", ".join(unknown))
        limits: dict[str, int] = {}
        for option, attribute in _LIMIT_FIELDS.items():
            if option in options:
                text = options[option]
                if not isinstance(text, str) or _DECIMAL.fullmatch(text) is None:
                    raise ConfigurationError(
                        f"settings.{option}", f"{text!r} is not a canonical positive decimal"
                    )
                limits[attribute] = int(text)
        tools = ToolPaths(
            solver=options.get("solver"),
            checker=options.get("checker"),
            helper=options.get("helper"),
        )
        return cls(limits=ReaderLimits(**limits), tools=tools)
