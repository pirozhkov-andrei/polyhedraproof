"""What a formula's variables mean, and what a model says in the article's terms.

Specification §13.2: a bundle of a neighbourly formula records, as producer parameters, the
number of faces `n`, the identity of the labelled map, the layer selection and the gauge
face. Interpretation never trusts a bundle's side files or display names: it validates the
formula identity by rebuilding the formula from VERIFIED mathematical input -- the map the
caller loaded from its own trusted source (for example :mod:`neighbourly.corpus12`) -- and
comparing sizes, pools and SHA-256 with the manifest; only then does it hand out the
:class:`VariableMap` of the rebuilt encoder. ``names.tsv`` and ``tags.tsv`` are convenience
exports for people and are never read here.

Producer side (:func:`formula_bundle`): the bundle of one map's formula with

    producer    {"name": "neighbourly", "version": <package version>,
                 "parameters": {"n": n, "map": {"sha256": <map_sha256>, "name": <label or null>},
                                "layers": <canonical selection>, "gauge_face": <face or null>}}
    pools       "order" (the order bits o^{ij}_{kl}) and "brackets" (the bracket bits X_S)
    names.tsv   display names of the variables that have a mathematical meaning
    tags.tsv    one range per run of clauses with the same ``(layer, tag)``, written
                ``"<layer>/<tag>"`` (layer names contain no ``/``)

Consumer side: :func:`verify_bundle` / :func:`read_bundle` -> :class:`VerifiedFormula`,
:func:`describe_model` (brackets, line orders, orientation
bits) and :func:`interpret_model` (completeness, clause check per layer, reflex corners).

A satisfying assignment is not a geometric realization (paper: rem:noconverse): it is a
Boolean assignment that the necessary conditions do not refute, to be examined by a person.
Nothing here is specific to `n = 12`.
"""

from __future__ import annotations

import hashlib
import itertools
import json
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Any, Final

from neighbourly import __version__
from neighbourly.cnf import (
    BundleFiles,
    Producer,
    bundle_files,
    canonical_json,
    clause_bytes,
    formula_digest,
)
from neighbourly.encoding import (
    DEFAULT_LAYERS,
    POOLS,
    Encoder,
    EncodingError,
    build_encoder,
    normalize_layers,
)
from neighbourly.maps import CombinatorialMap

__all__ = [
    "BUNDLE_FORMAT",
    "MAP_FORMAT",
    "PRODUCER_NAME",
    "FormulaSpec",
    "InterpretError",
    "Meaning",
    "ModelInterpretation",
    "ProducedBundle",
    "VariableMap",
    "VerifiedFormula",
    "describe_model",
    "formula_bundle",
    "interpret_model",
    "map_sha256",
    "read_bundle",
    "tag_ranges",
    "verify_bundle",
]

#: The bundle format this module writes and reads (specification §4.2).
BUNDLE_FORMAT: Final = "cubeproof-bundle-1"
#: ``producer.name`` of every bundle written here.
PRODUCER_NAME: Final = "neighbourly"
#: The format tag inside the hashed document of :func:`map_sha256`.
MAP_FORMAT: Final = "neighbourly-map-1"
_PARAMETER_KEYS: Final = frozenset({"n", "map", "layers", "gauge_face"})
_MAP_KEYS: Final = frozenset({"sha256", "name"})
_HASH = re.compile(r"[0-9a-f]{64}")
_MANIFEST = "manifest.json"
_FORMULA = "formula.cnf"


class InterpretError(ValueError):
    """A bundle, map or assignment that interpretation refuses; nothing is guessed."""


# -- identities -------------------------------------------------------------------------------


def map_sha256(cmap: CombinatorialMap) -> str:
    """The identity of a LABELLED map: SHA-256 of ``J({"format", "n", "vertices"})``.

    ``vertices`` are the real vertices as sorted triples in increasing order. Relabelling
    the faces changes the identity, as it changes the formula; isomorphic maps are not
    identified here.
    """
    if not isinstance(cmap, CombinatorialMap):
        raise InterpretError(f"a map identity needs a CombinatorialMap, not {type(cmap).__name__}")
    document = {
        "format": MAP_FORMAT,
        "n": cmap.n,
        "vertices": [list(triple) for triple in sorted(cmap.triples)],
    }
    return hashlib.sha256(canonical_json(document)).hexdigest()


@dataclass(frozen=True)
class FormulaSpec:
    """The producer parameters of one formula: map identity, `n`, layers and gauge.

    `map_name` is a display label (for example ``topology_01``) and carries no semantics:
    the map is identified by `map_sha256` alone.
    """

    n: int
    map_sha256: str
    layers: str
    gauge_face: int | None
    map_name: str | None = None

    @classmethod
    def of(
        cls,
        cmap: CombinatorialMap,
        layers: str = DEFAULT_LAYERS,
        gauge_face: int | None = 1,
        map_name: str | None = None,
    ) -> FormulaSpec:
        """The parameters of the formula of `cmap` with this selection and gauge."""
        if map_name is not None and not isinstance(map_name, str):
            raise InterpretError("a map name is a string or None")
        try:
            canonical = normalize_layers(layers)
        except EncodingError as exc:
            raise InterpretError(str(exc)) from None
        return cls(cmap.n, map_sha256(cmap), canonical, gauge_face, map_name)

    def parameters(self) -> dict[str, object]:
        """The JSON object written as ``producer.parameters``."""
        return {
            "n": self.n,
            "map": {"sha256": self.map_sha256, "name": self.map_name},
            "layers": self.layers,
            "gauge_face": self.gauge_face,
        }

    @classmethod
    def from_parameters(cls, parameters: object) -> FormulaSpec:
        """Read ``producer.parameters`` strictly: exact keys, exact types, canonical layers."""
        if not isinstance(parameters, Mapping) or set(parameters) != _PARAMETER_KEYS:
            raise InterpretError(
                f"producer parameters must have exactly the keys {sorted(_PARAMETER_KEYS)}"
            )
        n, identity, layers, gauge = (
            parameters["n"],
            parameters["map"],
            parameters["layers"],
            parameters["gauge_face"],
        )
        if type(n) is not int or n < 4:
            raise InterpretError(f"parameter n = {n!r} is not an integer of at least 4")
        if not isinstance(identity, Mapping) or set(identity) != _MAP_KEYS:
            raise InterpretError(f"parameter map must have exactly the keys {sorted(_MAP_KEYS)}")
        digest, name = identity["sha256"], identity["name"]
        if not isinstance(digest, str) or _HASH.fullmatch(digest) is None:
            raise InterpretError(f"map sha256 {digest!r} is not a lowercase SHA-256")
        if name is not None and not isinstance(name, str):
            raise InterpretError(f"map name {name!r} is neither a string nor null")
        if not isinstance(layers, str):
            raise InterpretError(f"layers {layers!r} is not a string")
        try:
            canonical = normalize_layers(layers)
        except EncodingError as exc:
            raise InterpretError(str(exc)) from None
        if canonical != layers:
            raise InterpretError(f"layers {layers!r} are not canonical (expected {canonical!r})")
        if gauge is not None and (type(gauge) is not int or not 1 <= gauge <= n):
            raise InterpretError(f"gauge face {gauge!r} is not a face of 1..{n} or null")
        return cls(n, digest, layers, gauge, name)


# -- the variable map -------------------------------------------------------------------------


@dataclass(frozen=True)
class Meaning:
    """What one variable stands for.

    ==============  ===============  ==================================================
    kind            key              the variable is 1 iff
    ==============  ===============  ==================================================
    ``bracket``     ``(a,b,c,d)``    `chi(a,b,c,d) < 0` (sorted elements, 0 = infinity)
    ``order``       ``(i,j,k,l)``    `P_ijk < P_ijl` on the real line `L_ij`
    ``cut``         ``(b,c,x,y)``    `d^b(x,y)`: x before y on `L_0b`, cut at `c`
    ``onb``         ``(i,j,u)``      `P_iju` lies inside the edge `E(i,j)` (i < j)
    ``turn``        ``(f,a,b)``      the corner of `f` at `P_fab` is NOT reflex
    ``orientation`` ``(f,)``         `s_f`: the link traversal of `f` runs against `n_f`
    ==============  ===============  ==================================================

    ``turn`` variables are the complements of the corner bits (paper: lem:sf); their key is
    written in link-cycle direction. Variables of no kind are Tseitin auxiliaries.
    """

    kind: str
    key: tuple[int, ...]

    @property
    def name(self) -> str:
        """A display name; it carries no semantics of its own."""
        k = self.key
        if self.kind == "bracket":
            return f"X({','.join(map(str, k))})"
        if self.kind == "order":
            return f"o({k[0]},{k[1]};{k[2]},{k[3]})"
        if self.kind == "cut":
            return f"d({k[0]}|{k[1]};{k[2]},{k[3]})"
        if self.kind == "onb":
            return f"OnB({k[0]},{k[1]};{k[2]})"
        if self.kind == "turn":
            return f"turn({k[0]};{k[1]},{k[2]})"
        return f"s({k[0]})"


def _frozen(rows: Mapping[Any, Mapping[Any, int]]) -> Mapping[Any, Mapping[Any, int]]:
    return MappingProxyType({key: MappingProxyType(dict(row)) for key, row in rows.items()})


@dataclass(frozen=True)
class VariableMap:
    """The meaningful variables of one built formula, read-only.

    Built only from a built :class:`~neighbourly.encoding.Encoder`
    (:meth:`from_encoder`); a consumer obtains one through :func:`verify_bundle`, which
    first proves that the encoder emits exactly the formula of the bundle.
    """

    spec: FormulaSpec
    faces: tuple[int, ...]
    variables: int
    brackets: Mapping[tuple[int, ...], int]
    line_orders: Mapping[tuple[int, int], Mapping[tuple[int, int], int]]
    cut_orders: Mapping[tuple[int, int], Mapping[tuple[int, int], int]]
    boundary_bits: Mapping[tuple[int, int, int], int]
    corner_literals: Mapping[tuple[int, int, int], int]
    orientation_bits: Mapping[int, int]
    _meanings: Mapping[int, Meaning] = field(repr=False, compare=False)

    @classmethod
    def from_encoder(cls, encoder: Encoder, spec: FormulaSpec) -> VariableMap:
        if not encoder.selection:
            raise InterpretError("the encoder has not been built")
        meanings: dict[int, Meaning] = {}

        def record(variable: int, meaning: Meaning) -> None:
            if variable in meanings:
                raise InterpretError(f"variable {variable} has two meanings")
            meanings[variable] = meaning

        for subset, variable in encoder.brackets.items():
            record(variable, Meaning("bracket", tuple(subset)))
        for (i, j), row in encoder.line_orders.items():
            for (k, l), variable in row.items():
                record(variable, Meaning("order", (i, j, k, l)))
        for (b, cut), row in encoder.cut_orders.items():
            for (x, y), variable in row.items():
                record(variable, Meaning("cut", (b, cut, x, y)))
        for key, variable in encoder.boundary_bits.items():
            record(variable, Meaning("onb", key))
        for key, literal in encoder.corner_bits.items():
            record(abs(literal), Meaning("turn", key))
        for face, variable in encoder.face_orientation_bits.items():
            record(variable, Meaning("orientation", (face,)))
        if any(not 1 <= v <= encoder.variables for v in meanings):
            raise InterpretError("a named variable lies outside the formula")
        return cls(
            spec=spec,
            faces=tuple(encoder.map.faces),
            variables=encoder.variables,
            brackets=MappingProxyType(dict(encoder.brackets)),
            line_orders=_frozen(encoder.line_orders),
            cut_orders=_frozen(encoder.cut_orders),
            boundary_bits=MappingProxyType(dict(encoder.boundary_bits)),
            corner_literals=MappingProxyType(dict(encoder.corner_bits)),
            orientation_bits=MappingProxyType(dict(encoder.face_orientation_bits)),
            _meanings=MappingProxyType(dict(sorted(meanings.items()))),
        )

    def meaning(self, variable: int) -> Meaning | None:
        """The meaning of `variable`, or ``None`` for an auxiliary variable."""
        if type(variable) is not int or not 1 <= variable <= self.variables:
            raise InterpretError(f"{variable!r} is not a variable of 1..{self.variables}")
        return self._meanings.get(variable)

    @property
    def meanings(self) -> Mapping[int, Meaning]:
        """Every meaningful variable, by increasing number."""
        return self._meanings

    def names(self) -> dict[int, str]:
        """Display names (``names.tsv``) of the meaningful variables."""
        return {variable: meaning.name for variable, meaning in self._meanings.items()}

    def pools(self) -> dict[str, list[int]]:
        """The pools of the bundle: order bits and bracket bits, sorted."""
        order = sorted(v for row in self.line_orders.values() for v in row.values())
        return {"order": order, "brackets": sorted(self.brackets.values())}


# -- producing a bundle -----------------------------------------------------------------------


def tag_ranges(tags: Iterable[tuple[str, str]]) -> list[tuple[int, int, str]]:
    """``(first, last, "<layer>/<tag>")`` for every maximal run of equal ``(layer, tag)``.

    Clause numbers are 1-based and inclusive, as ``tags.tsv`` writes them.
    """
    ranges: list[tuple[int, int, str]] = []
    for (layer, tag), run in itertools.groupby(enumerate(tags, 1), key=lambda item: item[1]):
        if "/" in layer:
            raise InterpretError(f"layer name {layer!r} contains '/'")
        numbers = [number for number, _ in run]
        ranges.append((numbers[0], numbers[-1], f"{layer}/{tag}"))
    return ranges


@dataclass(frozen=True)
class ProducedBundle:
    """The files of a bundle (nothing written yet) and the variable map they describe."""

    files: BundleFiles
    variable_map: VariableMap


def formula_bundle(
    cmap: CombinatorialMap,
    layers: str = DEFAULT_LAYERS,
    gauge_face: int | None = 1,
    *,
    map_name: str | None = None,
    side_files: bool = True,
) -> ProducedBundle:
    """Build one map's formula and compute its ``cubeproof-bundle-1`` files.

    With `side_files` the bundle carries ``names.tsv`` and ``tags.tsv``. Write it with
    :func:`neighbourly.cnf.publish_bundle`.
    """
    spec = FormulaSpec.of(cmap, layers, gauge_face, map_name)
    encoder = build_encoder(cmap, spec.layers, gauge_face)
    variable_map = VariableMap.from_encoder(encoder, spec)
    files = bundle_files(
        encoder.variables,
        encoder.clauses,
        pools={name: encoder.pool(name) for name in POOLS},
        producer=Producer(PRODUCER_NAME, __version__, spec.parameters()),
        names=variable_map.names() if side_files else None,
        tags=tag_ranges(encoder.formula.tags) if side_files else None,
    )
    return ProducedBundle(files, variable_map)


# -- verifying a bundle -----------------------------------------------------------------------


@dataclass(frozen=True)
class VerifiedFormula:
    """A formula whose identity was proved by rebuilding it from a verified map."""

    spec: FormulaSpec
    formula_sha256: str
    clauses: tuple[tuple[int, ...], ...]
    tags: tuple[tuple[str, str], ...]
    variable_map: VariableMap

    @property
    def variables(self) -> int:
        return self.variable_map.variables


def verify_bundle(
    manifest: Mapping[str, object],
    cmap: CombinatorialMap,
    formula: bytes | None = None,
) -> VerifiedFormula:
    """Prove that `manifest` (and `formula`, the bytes of ``formula.cnf``) is `cmap`'s formula.

    Checked, in order: the bundle format; ``producer.name``; the parameters (exact keys and
    types, canonical layers, gauge face); that `cmap` has the recorded `n` and map identity;
    then the formula is rebuilt and its SHA-256, variable and clause counts and both pools
    must equal the manifest; with `formula`, its SHA-256 must equal the manifest's too.
    `cmap` must come from the caller's own trusted source: a map read from the bundle
    would prove nothing.
    """
    if not isinstance(manifest, Mapping) or manifest.get("format") != BUNDLE_FORMAT:
        raise InterpretError(f"not a {BUNDLE_FORMAT} manifest")
    producer = manifest.get("producer")
    if not isinstance(producer, Mapping) or producer.get("name") != PRODUCER_NAME:
        raise InterpretError(f"the bundle was not produced by {PRODUCER_NAME}")
    if not isinstance(producer.get("version"), str):
        raise InterpretError("producer version is not a string")
    spec = FormulaSpec.from_parameters(producer.get("parameters"))
    if not isinstance(cmap, CombinatorialMap):
        raise InterpretError(f"verification needs a CombinatorialMap, not {type(cmap).__name__}")
    if cmap.n != spec.n:
        raise InterpretError(f"the bundle is for n = {spec.n}, the map given has n = {cmap.n}")
    if map_sha256(cmap) != spec.map_sha256:
        raise InterpretError("the map given is not the map of this bundle (map sha256 differs)")
    try:
        encoder = build_encoder(cmap, spec.layers, spec.gauge_face)
    except EncodingError as exc:
        raise InterpretError(f"the formula cannot be rebuilt: {exc}") from None
    count = len(encoder.clauses)
    digest = formula_digest(encoder.variables, clause_bytes(encoder.clauses), count)
    if manifest.get("formula_sha256") != digest:
        raise InterpretError("the rebuilt formula differs from the bundle (formula_sha256)")
    if manifest.get("variables") != encoder.variables or manifest.get("clauses") != count:
        raise InterpretError("the rebuilt formula differs from the bundle (variables or clauses)")
    if formula is not None and hashlib.sha256(formula).hexdigest() != digest:
        raise InterpretError(f"{_FORMULA} does not have the manifest's formula_sha256")
    variable_map = VariableMap.from_encoder(encoder, spec)
    if manifest.get("pools") != variable_map.pools():
        raise InterpretError("the bundle's pools are not the rebuilt formula's pools")
    return VerifiedFormula(
        spec=spec,
        formula_sha256=digest,
        clauses=tuple(encoder.clauses),
        tags=tuple(encoder.formula.tags),
        variable_map=variable_map,
    )


def read_bundle(directory: str | Path, cmap: CombinatorialMap) -> VerifiedFormula:
    """:func:`verify_bundle` on a bundle directory (manifest and formula; side files unused)."""
    base = Path(directory)
    try:
        raw = (base / _MANIFEST).read_bytes()
        formula = (base / _FORMULA).read_bytes()
    except OSError as exc:
        raise InterpretError(f"{base}: {exc}") from None
    try:
        manifest = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InterpretError(f"{base / _MANIFEST}: not JSON ({exc})") from None
    if not isinstance(manifest, dict) or raw != canonical_json(manifest) + b"\n":
        raise InterpretError(f"{base / _MANIFEST}: not a canonical manifest document")
    return verify_bundle(manifest, cmap, formula)


# -- models -----------------------------------------------------------------------------------


def _complete(values: Mapping[int, int], variables: int) -> dict[int, int]:
    """`values` as a complete 0/1 assignment of 1..variables, or :class:`InterpretError`."""
    if set(values) != set(range(1, variables + 1)):
        missing = len(set(range(1, variables + 1)) - set(values))
        raise InterpretError(
            f"the assignment does not give exactly the variables 1..{variables} "
            f"({missing} missing, {len(set(values) - set(range(1, variables + 1)))} extra)"
        )
    if any(type(v) is not int or v not in (0, 1) for v in values.values()):
        raise InterpretError("every value of an assignment is 0 or 1")
    return dict(values)


def describe_model(variable_map: VariableMap, values: Mapping[int, int]) -> dict[str, Any]:
    """The model in the article's vocabulary: brackets, line orders, orientation bits.

    For a complete assignment: ``chirotope`` maps ``"a,b,c,d"`` to the bracket bit;
    ``line_orders`` lists the other faces on each real line ``Li,j`` and on each line at infinity
    ``L0,b cut at c`` in the order the order bits give (ranked by the number of faces each
    precedes, then by label, so an intransitive model still gets one list on every Python);
    ``face_orientation_s`` maps each face to `s_f`. The assignment must be complete.
    """
    values = _complete(values, variable_map.variables)
    chirotope = {
        ",".join(map(str, subset)): values[variable]
        for subset, variable in sorted(variable_map.brackets.items())
    }

    def ordered(row: Mapping[tuple[int, int], int], elements: Sequence[int]) -> list[int]:
        def before(a: int, b: int) -> bool:
            return values[row[(a, b)]] == 1 if a < b else values[row[(b, a)]] == 0

        # By the number of faces each one precedes, then by label: the order of the bits when
        # they are transitive, and the same list on every Python for an intransitive model
        # (sorted with an inconsistent comparison depends on the sorting algorithm).
        wins = {a: sum(1 for b in elements if b != a and before(a, b)) for a in elements}
        return sorted(elements, key=lambda a: (-wins[a], a))

    faces = variable_map.faces
    lines: dict[str, list[int]] = {}
    for (i, j), row in sorted(variable_map.line_orders.items()):
        lines[f"L{i},{j}"] = ordered(row, [x for x in faces if x not in (i, j)])
    for (b, cut), row in sorted(variable_map.cut_orders.items()):
        lines[f"L0,{b} cut at {cut}"] = ordered(row, [x for x in faces if x not in (b, cut)])
    return {
        "chirotope": chirotope,
        "line_orders": lines,
        "face_orientation_s": {
            str(face): values[variable]
            for face, variable in sorted(variable_map.orientation_bits.items())
        },
    }


@dataclass(frozen=True)
class ModelInterpretation:
    """A complete assignment read against a verified formula.

    `violated` counts the clauses the assignment falsifies, per layer. `reflex_corners`
    is, per face, how many corner bits the assignment sets (empty without Layer I).
    `satisfies` does not make the assignment a realization (paper: rem:noconverse).
    """

    formula_sha256: str
    spec: FormulaSpec
    violated: Mapping[str, int]
    reflex_corners: Mapping[int, int]
    description: Mapping[str, Any]

    @property
    def satisfies(self) -> bool:
        return not self.violated

    def summary(self) -> dict[str, Any]:
        """JSON-ready form; the description is included as is."""
        return {
            "formula_sha256": self.formula_sha256,
            "parameters": self.spec.parameters(),
            "satisfies_formula": self.satisfies,
            "violated_clauses": dict(self.violated),
            "reflex_corners": {str(face): count for face, count in self.reflex_corners.items()},
            "description": dict(self.description),
            "note": (
                "A satisfying assignment of necessary conditions is not a geometric "
                "realization (paper: rem:noconverse)."
            ),
        }


def interpret_model(formula: VerifiedFormula, values: Mapping[int, int]) -> ModelInterpretation:
    """Check a complete assignment against every clause, then describe it."""
    values = _complete(values, formula.variables)
    violated: dict[str, int] = {}
    for clause, (layer, _) in zip(formula.clauses, formula.tags, strict=True):
        if not any(values[abs(x)] == (1 if x > 0 else 0) for x in clause):
            violated[layer] = violated.get(layer, 0) + 1
    reflex: dict[int, int] = {}
    for (face, _, _), literal in sorted(formula.variable_map.corner_literals.items()):
        bit = values[abs(literal)] if literal > 0 else 1 - values[abs(literal)]
        reflex[face] = reflex.get(face, 0) + bit
    return ModelInterpretation(
        formula_sha256=formula.formula_sha256,
        spec=formula.spec,
        violated=MappingProxyType(violated),
        reflex_corners=MappingProxyType(reflex),
        description=MappingProxyType(describe_model(formula.variable_map, values)),
    )
