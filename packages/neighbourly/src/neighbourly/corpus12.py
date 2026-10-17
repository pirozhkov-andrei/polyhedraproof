"""The twelve-face corpus: the 59 maps, their base formulas and the census that lists them.

Everything specific to `n = 12` is here and nowhere else in neighbourly (specification §13.2):
the 59 shipped matrices and their SHA-256 sums, the golden counts of the census
(paper: thm:59), the fixture of the 59 base formula hashes (specification §3.3) and the
checks of the corpus. The data are package data, read through
:mod:`importlib.resources` (:mod:`neighbourly.data`), so an installed wheel needs no
checkout. Generic modules never import this one.

The census is a computation for `n = 12`: :func:`enumerate_corpus` reruns the exhaustive
search of :mod:`neighbourly.enumeration` (minutes, not seconds) and compares its classes
with the shipped matrices. It is not a theorem about other `n`.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Final

from neighbourly import data
from neighbourly.cnf.dimacs import clause_bytes, formula_digest
from neighbourly.encoding import DEFAULT_LAYERS, Encoder, build_encoder
from neighbourly.enumeration import EnumerationResult, classes_of, enumerate_classes
from neighbourly.maps import CombinatorialMap, MapError, Triple

__all__ = [
    "BASE_GAUGE_FACE",
    "BASE_LAYERS",
    "EULER_CHARACTERISTIC",
    "FORMAT_ENUMERATION",
    "GOLDEN_COUNTS",
    "N_FACES",
    "N_MAPS",
    "N_VERTICES",
    "BaseFormula",
    "CorpusError",
    "base_encoder",
    "base_formula",
    "corpus_problems",
    "enumerate_corpus",
    "enumeration_document",
    "formula_hashes",
    "load_map",
    "map_ids",
    "matrix_bytes",
    "matrix_name",
    "matrix_problems",
    "matrix_sums",
    "shipped_classes",
]

#: Faces of the polyhedra the corpus is about.
N_FACES: Final = 12
#: Real vertices of a neighbourly map on `N_FACES` faces: n(n-1)/3.
N_VERTICES: Final = N_FACES * (N_FACES - 1) // 3
#: Isomorphism classes of orientable such maps (paper: thm:59, recomputed by the census).
N_MAPS: Final = 59
#: Euler characteristic of every one of them: V - E + F.
EULER_CHARACTERISTIC: Final = N_VERTICES - N_FACES * (N_FACES - 1) // 2 + N_FACES
#: `(labelled maps with link(0) = (1..11), classes)` the census must reproduce.
GOLDEN_COUNTS: Final = (12144, 59)
#: The layer selection and gauge face of the 59 base formulas.
BASE_LAYERS: Final = DEFAULT_LAYERS
BASE_GAUGE_FACE: Final = 1
#: The census document (the ``maps --output`` format).
FORMAT_ENUMERATION: Final = "faces12-enumeration-1"

_MATRICES = ("n12", "matrices")
_SUMS = "SHA256SUMS"
_HASHES = ("n12", "formula_hashes_n12.json")
_HASHES_FORMAT = "faces12-formula-hashes-1"


class CorpusError(ValueError):
    """The packaged corpus is missing, damaged or disagrees with itself."""


@dataclass(frozen=True)
class BaseFormula:
    """The size and identity of one base formula."""

    variables: int
    clauses: int
    sha256: str


# -- the matrices -----------------------------------------------------------------------------


def map_ids() -> range:
    """The map numbers `1..N_MAPS`."""
    return range(1, N_MAPS + 1)


def matrix_name(map_id: int) -> str:
    """The file name of one map's incidence matrix."""
    if type(map_id) is not int or not 1 <= map_id <= N_MAPS:
        raise CorpusError(f"map {map_id!r} is out of range; the maps are 1 to {N_MAPS}")
    return f"topology_{map_id:02d}.txt"


def matrix_bytes(map_id: int) -> bytes:
    """The packaged incidence matrix of one map, as bytes."""
    name = matrix_name(map_id)
    try:
        return data.read_bytes(*_MATRICES, name)
    except FileNotFoundError as exc:
        raise CorpusError(str(exc)) from None


def load_map(map_id: int) -> CombinatorialMap:
    """One of the 59 maps."""
    name = matrix_name(map_id)
    text = matrix_bytes(map_id).decode("utf-8")
    return CombinatorialMap.from_text(text, f"neighbourly.data:n12/matrices/{name}")


def matrix_sums() -> dict[str, str]:
    """File name -> SHA-256 from the packaged ``SHA256SUMS``."""
    try:
        text = data.read_bytes(*_MATRICES, _SUMS).decode("ascii")
    except FileNotFoundError as exc:
        raise CorpusError(str(exc)) from None
    sums: dict[str, str] = {}
    for number, line in enumerate(text.splitlines(), 1):
        digest, _, name = line.partition("  ")
        if len(digest) != 64 or not name or name in sums:
            raise CorpusError(f"{_SUMS}:{number}: not a sum line: {line!r}")
        sums[name] = digest
    return sums


def matrix_problems() -> list[str]:
    """Every packaged matrix is listed in ``SHA256SUMS`` with its actual SHA-256."""
    sums = matrix_sums()
    names = [matrix_name(map_id) for map_id in map_ids()]
    problems = []
    if sorted(sums) != names:
        problems.append(f"{_SUMS} lists {len(sums)} files, not exactly the {N_MAPS} matrices")
    for name, map_id in zip(names, map_ids(), strict=True):
        try:
            digest = hashlib.sha256(matrix_bytes(map_id)).hexdigest()
        except CorpusError as exc:
            problems.append(str(exc))
            continue
        if sums.get(name) != digest:
            problems.append(f"{name}: SHA-256 {digest} differs from {_SUMS}")
    return problems


# -- the base formulas ------------------------------------------------------------------------


def formula_hashes() -> dict[int, BaseFormula]:
    """The packaged fixture of the 59 base formulas (specification §3.3)."""
    try:
        document = json.loads(data.read_bytes(*_HASHES).decode("utf-8"))
    except FileNotFoundError as exc:
        raise CorpusError(str(exc)) from None
    if (
        document.get("format") != _HASHES_FORMAT
        or document.get("layers") != BASE_LAYERS
        or document.get("gauge_face") != BASE_GAUGE_FACE
    ):
        raise CorpusError("the base formula fixture does not describe the base formulas")
    maps: Mapping[str, Any] = document.get("maps", {})
    if set(maps) != {str(m) for m in map_ids()}:
        raise CorpusError(f"the base formula fixture does not list exactly the {N_MAPS} maps")
    return {
        int(key): BaseFormula(
            variables=entry["variables"], clauses=entry["clauses"], sha256=entry["sha256"]
        )
        for key, entry in sorted(maps.items(), key=lambda item: int(item[0]))
    }


def base_encoder(map_id: int) -> Encoder:
    """The built encoder of one base formula: every layer, gauge at face 1."""
    return build_encoder(load_map(map_id), BASE_LAYERS, BASE_GAUGE_FACE)


def base_formula(map_id: int) -> BaseFormula:
    """Emit one base formula and return its size and SHA-256."""
    encoder = base_encoder(map_id)
    count = len(encoder.clauses)
    digest = formula_digest(encoder.variables, clause_bytes(encoder.clauses), count)
    return BaseFormula(variables=encoder.variables, clauses=count, sha256=digest)


# -- the corpus as a whole ---------------------------------------------------------------------


def shipped_classes() -> dict[tuple[Triple, ...], str]:
    """The canonical form of every shipped matrix; an isomorphic pair is an error."""
    return classes_of(((matrix_name(m), load_map(m)) for m in map_ids()), N_FACES)


def corpus_problems() -> list[str]:
    """Check every shipped matrix is the kind of map the encoder expects, and that no two
    are isomorphic (by canonical form, in a fraction of a second; the exhaustive search
    of :func:`enumerate_corpus` is what shows that no class is missing)."""
    problems = matrix_problems()
    forms = set()
    for map_id in map_ids():
        try:
            cmap = load_map(map_id)
        except (CorpusError, MapError) as exc:
            problems.append(f"{map_id}: {exc}")
            continue
        forms.add(frozenset(cmap.triples))
        if (
            cmap.n != N_FACES
            or len(cmap.triples) != N_VERTICES
            or cmap.euler_characteristic != EULER_CHARACTERISTIC
        ):
            problems.append(
                f"{map_id}: n={cmap.n}, V={len(cmap.triples)}, chi={cmap.euler_characteristic}"
            )
        elif not cmap.is_orientable():
            problems.append(f"{map_id}: non-orientable, so it does not embed in R^3")
    if len(forms) != N_MAPS:
        problems.append(f"{len(forms)} distinct labelled maps, expected {N_MAPS}")
    if not problems:
        try:
            classes = shipped_classes()
        except MapError as exc:
            problems.append(str(exc))
        else:
            if len(classes) != N_MAPS:
                problems.append(f"{len(classes)} isomorphism classes, expected {N_MAPS}")
    return problems


def enumerate_corpus() -> EnumerationResult:
    """The census (paper: thm:59): search `n = 12`, compare with the counts and the matrices.

    Several minutes of exact integer search; not part of any fast check.
    """
    return enumerate_classes(N_FACES, expected=GOLDEN_COUNTS, reference=shipped_classes())


def enumeration_document(result: EnumerationResult) -> dict[str, Any]:
    """The census result as the enumeration document, with the matrix hashes compared."""
    corpus_sha256 = (
        {matrix_name(m): hashlib.sha256(matrix_bytes(m)).hexdigest() for m in map_ids()}
        if result.reference_compared
        else {}
    )
    return {"format": FORMAT_ENUMERATION, **result.summary(), "corpus_sha256": corpus_sha256}
