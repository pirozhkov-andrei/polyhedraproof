"""Reading command inputs: explicit files, one source per input, no search (specification §12.1).

Every command reads exactly the files it is given. Two mutually exclusive ways to give the inputs of
a consuming command exist (specification §12.1): explicit ``--campaign``/``--journals`` paths, or
``--evidence MANIFEST``; :func:`resolve_inputs` turns either into one :class:`ResolvedInputs` and
refuses a mixture or an empty request. A certificate path is never an input of a machine command
by itself: it is recomputed from the journals and compared (``shard``, ``certify --evidence``), so
an arbitrary certificate file cannot steer a command.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, TypeVar

from cubeproof.base.canonical_json import parse_document
from cubeproof.base.errors import ConfigurationError, CubeproofError, InputError, contextualize
from cubeproof.base.settings import DEFAULT_LIMITS, ReaderLimits
from cubeproof.commands.evidence import load_evidence

__all__ = ["ResolvedInputs", "parse_input", "read_json_file", "resolve_inputs"]

T = TypeVar("T")


def read_json_file(path: Path, *, limits: ReaderLimits = DEFAULT_LIMITS) -> Any:
    """A JSON document file (canonical J plus LF, specification §4.1) as a value; InputError
    otherwise."""
    try:
        data = Path(path).read_bytes()
    except OSError as error:
        raise InputError("input.file", f"{path}: {error.strerror or error}") from None
    try:
        return parse_document(data, limits=limits)
    except CubeproofError as error:
        raise contextualize(error, InputError) from None


def parse_input(
    path: Path, parse: Callable[[Any], T], *, limits: ReaderLimits = DEFAULT_LIMITS
) -> T:
    """The document at ``path`` parsed by a contract reader; a contract violation is an
    :class:`~cubeproof.base.errors.InputError` naming the rule (a user input, not an internal
    failure) and the file."""
    value = read_json_file(path, limits=limits)
    try:
        return parse(value)
    except CubeproofError as error:
        converted = contextualize(error, InputError)
        if type(converted) is InputError:
            raise InputError(
                converted.rule, f"{path}: {converted.detail}", location=converted.location
            ) from None
        raise converted from None


@dataclass(frozen=True)
class ResolvedInputs:
    """The campaign file and journals of a consuming command and where they came from.

    ``certificate`` is the certificate named by an evidence manifest (``None`` for explicit
    paths); it is a claim to compare with, never an input to trust.
    """

    campaign: Path
    journals: tuple[Path, ...]
    certificate: Path | None = None
    evidence: Path | None = None


def resolve_inputs(
    *,
    campaign: Path | None,
    journals: Sequence[Path],
    evidence: Path | None,
    limits: ReaderLimits = DEFAULT_LIMITS,
    need_journals: bool = True,
) -> ResolvedInputs:
    """``--evidence`` xor ``--campaign`` (+ ``--journals``); ConfigurationError ``usage`` otherwise.

    The evidence manifest is verified here (every artifact's size and hash, containment, bundle
    correspondence): see :func:`cubeproof.commands.evidence.load_evidence`.
    """
    if evidence is not None:
        if campaign is not None or journals:
            raise ConfigurationError(
                "usage", "--evidence is the exclusive alternative to --campaign/--journals"
            )
        found = load_evidence(evidence, limits=limits)
        return ResolvedInputs(
            found.campaign, found.journals, found.certificate, found.manifest_path
        )
    if campaign is None:
        raise ConfigurationError("usage", "one of --campaign or --evidence is required")
    if need_journals and not journals:
        raise ConfigurationError("usage", "--journals (at least one journal) is required")
    return ResolvedInputs(Path(campaign), tuple(Path(j) for j in journals))
