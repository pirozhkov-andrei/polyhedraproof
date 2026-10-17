"""The 59 published formulas as bundles, and the corpus controls (specification §13.2, §13.3).

The formulas of the campaign are the base formulas of :mod:`neighbourly.corpus12`: one per
map of the census (paper: thm:59), every layer, gauge at face 1. This adapter writes them as
``cubeproof-bundle-1`` directories and verifies such directories; it computes nothing of its
own:

- :func:`export_formulas` builds each map's bundle with
  :func:`neighbourly.interpret.formula_bundle`, compares its SHA-256 with the packaged
  fixture of the 59 base hashes **before** publishing, and publishes it with
  :func:`neighbourly.cnf.publish_bundle` (staged sibling, manifest last, atomic rename) as
  ``<directory>/mapNN``. An existing bundle is never overwritten: it is verified and reported
  as present.
- :func:`check_formulas` verifies a bundle directory: every bundle is rebuilt from the
  packaged map (:func:`neighbourly.interpret.read_bundle`; side files are never trusted), its
  parameters must be the published layers and gauge, its SHA-256 the fixture's, and the
  directory holds no other bundle.
- :func:`recompute_formulas` emits the base formulas in memory and compares them with the
  fixture (no directory).
- :func:`selftest` and :func:`census` are the corpus controls of the ``selftest`` and
  ``maps`` commands, on :mod:`neighbourly.checks` and :mod:`neighbourly.corpus12`.

A hash that equals the fixture shows that the bytes are the published formula; it does not
show that anything about the formula has been computed.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from cubeproof.base.errors import ConfigurationError, IntegrityError
from neighbourly import corpus12
from neighbourly.checks import Check, identity_checks
from neighbourly.cnf import CnfError, publish_bundle
from neighbourly.interpret import InterpretError, formula_bundle, read_bundle

__all__ = [
    "BUNDLE_PREFIX",
    "FORMAT_FORMULAS",
    "FormulaEntry",
    "FormulasReport",
    "bundle_key",
    "census",
    "check_formulas",
    "export_formulas",
    "map_of_key",
    "parse_maps",
    "recompute_formulas",
    "selftest",
]

#: Bundle directories are named ``map01`` .. ``map59``; the name is the campaign formula key.
BUNDLE_PREFIX: Final = "map"
#: The result document of ``formulas``.
FORMAT_FORMULAS: Final = "faces12-formulas-1"
_KEY = re.compile(r"map([0-9]{2})")


def bundle_key(map_id: int) -> str:
    """The bundle directory name and campaign formula key of one map."""
    corpus12.matrix_name(map_id)  # validates the range
    return f"{BUNDLE_PREFIX}{map_id:02d}"


def map_of_key(key: str) -> int | None:
    """The map of a bundle key ``mapNN``, or None for another name."""
    match = _KEY.fullmatch(key)
    if match is None:
        return None
    map_id = int(match.group(1))
    return map_id if map_id in corpus12.map_ids() else None


def parse_maps(text: str) -> tuple[int, ...]:
    """``all`` or a comma list of maps and ranges (``1,2,10-12``), sorted and unique."""
    if text.strip() == "all":
        return tuple(corpus12.map_ids())
    found: set[int] = set()
    for part in text.split(","):
        item = part.strip()
        first, dash, last = item.partition("-")
        if not first.isdigit() or (dash and not last.isdigit()):
            raise ConfigurationError(
                "formulas.maps", f"{text!r} is not 'all' or a list like 1,2,5-7"
            )
        low, high = int(first), int(last) if dash else int(first)
        if not 1 <= low <= high <= corpus12.N_MAPS:
            raise ConfigurationError(
                "formulas.maps", f"{item!r}: the maps are 1 to {corpus12.N_MAPS}"
            )
        found.update(range(low, high + 1))
    return tuple(sorted(found))


def _selection(maps: Iterable[int] | None) -> tuple[int, ...]:
    chosen = tuple(corpus12.map_ids()) if maps is None else tuple(sorted(set(maps)))
    if not chosen:
        raise ConfigurationError("formulas.maps", "no map selected")
    for map_id in chosen:
        if type(map_id) is not int or map_id not in corpus12.map_ids():
            raise ConfigurationError("formulas.maps", f"{map_id!r} is not a map of the corpus")
    return chosen


@dataclass(frozen=True)
class FormulaEntry:
    """One published formula: where it is and what it is."""

    map_id: int
    key: str
    formula_sha256: str
    variables: int
    clauses: int
    status: str  # written | present | verified | recomputed

    def to_json(self) -> dict[str, Any]:
        return {
            "map": self.map_id,
            "key": self.key,
            "formula_sha256": self.formula_sha256,
            "variables": self.variables,
            "clauses": self.clauses,
            "status": self.status,
        }


@dataclass(frozen=True)
class FormulasReport:
    """The result of ``formulas``: the directory (if any) and one entry per map."""

    directory: str | None
    layers: str
    gauge_face: int
    entries: tuple[FormulaEntry, ...]

    def to_json(self) -> dict[str, Any]:
        return {
            "format": FORMAT_FORMULAS,
            "directory": self.directory,
            "layers": self.layers,
            "gauge_face": self.gauge_face,
            "formulas": [entry.to_json() for entry in self.entries],
        }


def _fixture() -> dict[int, corpus12.BaseFormula]:
    try:
        return corpus12.formula_hashes()
    except corpus12.CorpusError as error:
        raise IntegrityError("formulas.fixture", str(error)) from None


def _verify_one(directory: Path, map_id: int, expected: corpus12.BaseFormula) -> FormulaEntry:
    key = bundle_key(map_id)
    try:
        verified = read_bundle(directory / key, corpus12.load_map(map_id))
    except InterpretError as error:
        raise IntegrityError("formulas.bundle", f"{directory / key}: {error}") from None
    spec = verified.spec
    if spec.layers != corpus12.BASE_LAYERS or spec.gauge_face != corpus12.BASE_GAUGE_FACE:
        raise IntegrityError(
            "formulas.parameters",
            f"{directory / key}: layers {spec.layers!r}, gauge {spec.gauge_face!r} are not the "
            f"published {corpus12.BASE_LAYERS!r}, gauge {corpus12.BASE_GAUGE_FACE}",
        )
    if (verified.formula_sha256, verified.variables, len(verified.clauses)) != (
        expected.sha256,
        expected.variables,
        expected.clauses,
    ):
        raise IntegrityError(
            "formulas.hash", f"{directory / key}: not the published base formula of map {map_id}"
        )
    return FormulaEntry(
        map_id, key, expected.sha256, expected.variables, expected.clauses, "verified"
    )


def export_formulas(directory: Path, maps: Iterable[int] | None = None) -> FormulasReport:
    """Write (or verify, when present) the bundle of every selected map below ``directory``."""
    chosen = _selection(maps)
    fixture = _fixture()
    base = Path(directory)
    base.mkdir(parents=True, exist_ok=True)
    entries = []
    for map_id in chosen:
        key = bundle_key(map_id)
        target = base / key
        expected = fixture[map_id]
        if target.exists() or target.is_symlink():
            entry = _verify_one(base, map_id, expected)
            entries.append(
                FormulaEntry(
                    map_id, key, entry.formula_sha256, entry.variables, entry.clauses, "present"
                )
            )
            continue
        produced = formula_bundle(
            corpus12.load_map(map_id),
            corpus12.BASE_LAYERS,
            corpus12.BASE_GAUGE_FACE,
            map_name=corpus12.matrix_name(map_id).removesuffix(".txt"),
        )
        files = produced.files
        manifest = files.manifest
        if (files.formula_sha256, manifest["variables"], manifest["clauses"]) != (
            expected.sha256,
            expected.variables,
            expected.clauses,
        ):
            raise IntegrityError(
                "formulas.hash",
                f"map {map_id}: the emitted formula {files.formula_sha256} is not the published "
                f"base formula {expected.sha256}; nothing written",
            )
        try:
            publish_bundle(target, files)
        except CnfError as error:
            raise ConfigurationError("formulas.publish", str(error)) from None
        entries.append(
            FormulaEntry(
                map_id, key, expected.sha256, expected.variables, expected.clauses, "written"
            )
        )
    return FormulasReport(
        str(base.resolve()), corpus12.BASE_LAYERS, corpus12.BASE_GAUGE_FACE, tuple(entries)
    )


def check_formulas(
    directory: Path, maps: Iterable[int] | None = None, *, exact: bool = True
) -> FormulasReport:
    """Verify the bundles of the selected maps below ``directory`` (module doc).

    With ``exact`` the directory may hold nothing else that is not hidden (a ``.``-name is a
    staging leftover of an interrupted publication and never a bundle).
    """
    chosen = _selection(maps)
    fixture = _fixture()
    base = Path(directory)
    if not base.is_dir():
        raise ConfigurationError("formulas.directory", f"{base} is not a directory")
    if exact:
        expected_keys = {bundle_key(m) for m in chosen}
        extra = sorted(
            p.name
            for p in base.iterdir()
            if not p.name.startswith(".") and p.name not in expected_keys
        )
        if extra:
            raise IntegrityError(
                "formulas.extra", f"{base} holds entries that are not selected bundles: {extra}"
            )
    entries = tuple(_verify_one(base, m, fixture[m]) for m in chosen)
    return FormulasReport(
        str(base.resolve()), corpus12.BASE_LAYERS, corpus12.BASE_GAUGE_FACE, entries
    )


def recompute_formulas(maps: Iterable[int] | None = None) -> FormulasReport:
    """Emit the selected base formulas in memory and compare them with the fixture."""
    chosen = _selection(maps)
    fixture = _fixture()
    entries = []
    for map_id in chosen:
        computed = corpus12.base_formula(map_id)
        expected = fixture[map_id]
        if computed != expected:
            raise IntegrityError(
                "formulas.hash",
                f"map {map_id}: emitted {computed.sha256} ({computed.variables} variables, "
                f"{computed.clauses} clauses), published {expected.sha256}",
            )
        entries.append(
            FormulaEntry(
                map_id,
                bundle_key(map_id),
                computed.sha256,
                computed.variables,
                computed.clauses,
                "recomputed",
            )
        )
    return FormulasReport(None, corpus12.BASE_LAYERS, corpus12.BASE_GAUGE_FACE, tuple(entries))


# -- corpus controls ---------------------------------------------------------------------------


def selftest(maps: Sequence[int] = (1,)) -> list[Check]:
    """The self-test without a solver: the identities of the encoding on the given maps
    (:func:`neighbourly.checks.identity_checks`), the corpus check, and each map's base
    formula against the fixture. Seconds, not minutes."""
    checks: list[Check] = []
    for map_id in _selection(maps):
        cmap = corpus12.load_map(map_id)
        for check in identity_checks(cmap):
            checks.append(Check(f"map {map_id}: {check.name}", check.passed, check.detail))
    problems = corpus12.corpus_problems()
    checks.append(
        Check(
            f"the {corpus12.N_MAPS} shipped maps are distinct orientable neighbourly maps "
            "(paper: thm:59)",
            not problems,
            "; ".join(problems[:5]),
        )
    )
    fixture = _fixture()
    for map_id in _selection(maps):
        computed = corpus12.base_formula(map_id)
        checks.append(
            Check(
                f"map {map_id}: the base formula is the published one",
                computed == fixture[map_id],
                computed.sha256,
            )
        )
    return checks


def census() -> tuple[bool, dict[str, Any]]:
    """The census of maps with twelve faces (paper: thm:59): minutes of exhaustive search,
    compared with the golden counts and the shipped matrices. ``(passed, document)``."""
    result = corpus12.enumerate_corpus()
    return result.passed, corpus12.enumeration_document(result)
