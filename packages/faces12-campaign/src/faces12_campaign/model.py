"""Models in the article's terms (specification §13.2, §13.3; paper: rem:noconverse).

A certificate lists every revalidated valid model as ``{record, node, assignment}`` with the
canonical bitset of specification §4.8. This adapter turns such an assignment into the
model description (brackets, line orders, orientation bits), the violated clauses per layer
and the reflex corners per face, through :func:`neighbourly.interpret.interpret_model`.

The formula is never taken from the bundle on trust: the bundle is rebuilt from a map of a
trusted source (by default the packaged corpus, looked up by the formula's published SHA-256)
before its variable map is used; side files and display names are not read. A model of a
formula that no trusted map produces is reported uninterpreted. Models are always taken from
a certificate the certifier recomputes here, never from a certificate file.

A satisfying assignment is not a geometric realization: the layers are necessary conditions
only (paper: rem:noconverse). The result is a candidate for a person to examine.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from cubeproof.base.canonical_json import parse_document
from cubeproof.base.errors import ContractError, CubeproofError, IntegrityError
from cubeproof.commands import resolve_inputs
from cubeproof.contracts.assignment import decode_assignment
from cubeproof.contracts.campaign import Campaign
from cubeproof.evidence.certify.run import certify
from neighbourly import corpus12
from neighbourly.interpret import InterpretError, ModelInterpretation, interpret_model, read_bundle
from neighbourly.maps import CombinatorialMap

__all__ = [
    "FORMAT_MODELS",
    "MapSource",
    "ModelReport",
    "ModelsResult",
    "corpus_maps",
    "interpret_assignment",
    "interpret_models",
]

FORMAT_MODELS: Final = "faces12-models-1"
NOTE: Final = (
    "A satisfying assignment of necessary conditions is not a geometric realization "
    "(paper: rem:noconverse); examine it before drawing any conclusion."
)

#: formula SHA-256 -> (label, loader of the trusted map)
MapSource = Mapping[str, tuple[str, Callable[[], CombinatorialMap]]]


def corpus_maps() -> dict[str, tuple[str, Callable[[], CombinatorialMap]]]:
    """The trusted maps of the 59 published formulas, by formula SHA-256."""
    found: dict[str, tuple[str, Callable[[], CombinatorialMap]]] = {}
    for map_id, base in corpus12.formula_hashes().items():
        label = corpus12.matrix_name(map_id).removesuffix(".txt")
        found[base.sha256] = (label, _loader(map_id))
    return found


def _loader(map_id: int) -> Callable[[], CombinatorialMap]:
    return lambda: corpus12.load_map(map_id)


def interpret_assignment(
    bundle: Path, cmap: CombinatorialMap, assignment: str
) -> ModelInterpretation:
    """Rebuild the formula of ``bundle`` from ``cmap`` and read the bitset ``assignment``."""
    try:
        verified = read_bundle(bundle, cmap)
    except InterpretError as error:
        raise IntegrityError("model.bundle", f"{bundle}: {error}") from None
    try:
        bits = decode_assignment(assignment, verified.variables)
    except ContractError as error:
        raise IntegrityError("model.assignment", error.detail) from None
    values = {index + 1: int(bit) for index, bit in enumerate(bits)}
    return interpret_model(verified, values)


@dataclass(frozen=True)
class ModelReport:
    """One certificate model and, when its formula has a trusted map, its interpretation."""

    record: Mapping[str, Any]
    node: Mapping[str, Any]
    key: str
    label: str | None
    interpretation: ModelInterpretation | None

    def to_json(self) -> dict[str, Any]:
        summary = None if self.interpretation is None else self.interpretation.summary()
        return {
            "record": dict(self.record),
            "node": dict(self.node),
            "key": self.key,
            "label": self.label,
            "interpretation": summary,
        }


@dataclass(frozen=True)
class ModelsResult:
    """The verdict of the recomputed certificate and every model in it."""

    campaign_id: str
    verdict: str
    models: tuple[ModelReport, ...]

    def to_json(self) -> dict[str, Any]:
        return {
            "format": FORMAT_MODELS,
            "campaign": self.campaign_id,
            "verdict": self.verdict,
            "models": [m.to_json() for m in self.models],
            "note": NOTE,
        }


def models_of(
    campaign_path: Path, certificate: Mapping[str, Any], maps: MapSource
) -> tuple[ModelReport, ...]:
    """Interpret the models of a recomputed ``certificate`` of the campaign at ``campaign_path``."""
    try:
        campaign = Campaign.from_json(parse_document(Path(campaign_path).read_bytes()))
    except CubeproofError as error:
        raise IntegrityError("model.campaign", f"{campaign_path}: {error.detail}") from None
    entries = {e.formula_sha256: e for e in campaign.formulas}
    reports = []
    for model in certificate["models"]:
        sha = model["node"]["formula_sha256"]
        entry = entries[sha]
        source = maps.get(sha)
        interpretation = None
        label = None
        if source is not None:
            label, load = source
            bundle = Path(campaign_path).parent / entry.bundle
            interpretation = interpret_assignment(bundle, load(), model["assignment"])
        reports.append(
            ModelReport(model["record"], model["node"], entry.key, label, interpretation)
        )
    return tuple(reports)


def interpret_models(
    *,
    evidence: Path | None = None,
    campaign: Path | None = None,
    journals: Sequence[Path] = (),
    maps: MapSource | None = None,
) -> ModelsResult:
    """Recompute the certificate of explicit journals or of an evidence directory (whose
    packaged certificate must agree) and interpret its models."""
    inputs = resolve_inputs(campaign=campaign, journals=journals, evidence=evidence)
    result = certify(inputs.campaign, inputs.journals)
    if inputs.certificate is not None and result.document != inputs.certificate.read_bytes():
        raise IntegrityError(
            "evidence.certificate",
            f"{inputs.evidence}: the packaged certificate is not the certificate of its campaign "
            "and journals",
        )
    certificate = result.certificate
    sources = corpus_maps() if maps is None else maps
    return ModelsResult(
        certificate["campaign"],
        certificate["verdict"],
        models_of(inputs.campaign, certificate, sources),
    )
