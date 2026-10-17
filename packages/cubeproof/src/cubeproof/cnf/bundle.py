"""Bundles ``cubeproof-bundle-1`` (specification §4.2): manifest, side files, loading and
publication.

A bundle directory holds ``formula.cnf`` (canonical DIMACS), ``manifest.json`` (a canonical
document, written last) and optional side files ``names.tsv``/``tags.tsv``:

- names: one line per named variable, sorted by numeric ID, ``ID<TAB>JSON_STRING<LF>``;
- tags: clause ranges sorted by ``(first, last, tag)``, ``FIRST<TAB>LAST<TAB>JSON_STRING<LF>``,
  1-based inclusive, ``1 <= first <= last <= M``;

where JSON_STRING is exactly J of a string. Side files do not affect formula semantics; their
size and hash are checked when they are used (side.artifact).

Loading checks containment (no symlink component, regular files), the manifest schema and
rules (bundle.pools, bundle.side_files), the strict DIMACS formula and its agreement with the
manifest (bundle.formula_sha256, bundle.counts). Errors raised by :func:`load_bundle` are
input errors (a bundle is an input of a command); reader limits stay resource errors.

Publication stages a sibling directory on the same file system, writes and syncs every file
(manifest last), syncs the staging directory, renames it to the target and syncs the parent.
An existing target is never overwritten. A directory without a valid manifest is incomplete.
"""

from __future__ import annotations

import functools
import hashlib
import json
import os
import re
import shutil
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from itertools import pairwise
from pathlib import Path
from types import MappingProxyType
from typing import Any

import cubeproof
from cubeproof.base.canonical_json import document_bytes, encode, parse_document
from cubeproof.base.errors import ContractError, CubeproofError, InputError, contextualize
from cubeproof.base.ids import new_id128
from cubeproof.base.paths import open_contained, read_at_most
from cubeproof.base.settings import DEFAULT_LIMITS, ReaderLimits
from cubeproof.cnf.dimacs import Formula, normalize_external_dimacs, parse_dimacs
from cubeproof.contracts import fields as f
from cubeproof.contracts.campaign import FormulaFacts
from cubeproof.contracts.primitives import is_hash, is_name
from cubeproof.contracts.values import Artifact, JsonObject

SIDE_FILES = ("names.tsv", "tags.tsv")
_DECIMAL = re.compile(r"[1-9][0-9]*")


@dataclass(frozen=True)
class Producer:
    name: str
    version: str
    parameters: JsonObject

    @classmethod
    def from_json(cls, value: Any, at: str = "$") -> Producer:
        f.obj(value, at, ("name", "version", "parameters"))
        return cls(
            f.string(value["name"], f.member(at, "name")),
            f.string(value["version"], f.member(at, "version")),
            JsonObject.from_json(value["parameters"], f.member(at, "parameters")),
        )

    def to_json(self) -> dict[str, Any]:
        return {"name": self.name, "version": self.version, "parameters": self.parameters.to_json()}


def _side_entry(value: Any, at: str) -> Artifact:
    f.obj(value, at, ("path", "sha256", "bytes"))
    path = f.choice(value["path"], f.member(at, "path"), SIDE_FILES)
    sha = f.matching(value["sha256"], f.member(at, "sha256"), is_hash, "Hash")
    return Artifact(path, sha, f.nonnegative(value["bytes"], f.member(at, "bytes")))


def _pool(value: Any, at: str) -> tuple[int, ...]:
    return tuple(f.items(value, at, f.positive))


MANIFEST_FIELDS = (
    "format",
    "formula_sha256",
    "variables",
    "clauses",
    "pools",
    "producer",
    "side_files",
)


@dataclass(frozen=True)
class BundleManifest:
    """``manifest.json`` of a bundle."""

    formula_sha256: str
    variables: int
    clauses: int
    pools: Mapping[str, tuple[int, ...]]
    producer: Producer
    side_files: tuple[Artifact, ...]

    def __post_init__(self) -> None:
        pools = MappingProxyType(dict(sorted(self.pools.items())))
        object.__setattr__(self, "pools", pools)
        for name, pool in pools.items():
            if not is_name(name) or type(pool) is not tuple:
                raise ContractError("schema", f"pool {name!r}")
            if any(a >= b for a, b in pairwise(pool)) or any(
                type(v) is not int or not 1 <= v <= self.variables for v in pool
            ):
                raise ContractError(
                    "bundle.pools", f"pool {name!r} is not sorted, distinct, in 1..V"
                )
        paths = [a.path for a in self.side_files]
        if any(a >= b for a, b in pairwise(paths)):
            raise ContractError("bundle.side_files", "side_files not strictly sorted by path")

    @classmethod
    def from_json(cls, value: Any, at: str = "$") -> BundleManifest:
        f.obj(value, at, MANIFEST_FIELDS)
        m = functools.partial(f.member, at)
        f.const(value["format"], m("format"), "cubeproof-bundle-1")
        formula = f.matching(value["formula_sha256"], m("formula_sha256"), is_hash, "Hash")
        variables = f.nonnegative(value["variables"], m("variables"))
        clauses = f.nonnegative(value["clauses"], m("clauses"))
        raw_pools = f.obj(value["pools"], m("pools"), (), closed=False)
        f.property_names(raw_pools, m("pools"), is_name)
        pools = {k: _pool(v, f.member(m("pools"), k)) for k, v in raw_pools.items()}
        producer = Producer.from_json(value["producer"], m("producer"))
        side = tuple(f.items(value["side_files"], m("side_files"), _side_entry))
        return cls(formula, variables, clauses, pools, producer, side)

    def to_json(self) -> dict[str, Any]:
        return {
            "format": "cubeproof-bundle-1",
            "formula_sha256": self.formula_sha256,
            "variables": self.variables,
            "clauses": self.clauses,
            "pools": {k: list(v) for k, v in self.pools.items()},
            "producer": self.producer.to_json(),
            "side_files": [a.to_json() for a in self.side_files],
        }

    def side_file(self, name: str) -> Artifact | None:
        return next((a for a in self.side_files if a.path == name), None)


def check_manifest_formula(manifest: BundleManifest, formula: Formula) -> None:
    """bundle.formula_sha256 then bundle.counts."""
    if manifest.formula_sha256 != formula.sha256:
        raise ContractError("bundle.formula_sha256", "manifest hash differs from formula.cnf")
    if (manifest.variables, manifest.clauses) != (formula.variables, formula.clauses):
        raise ContractError("bundle.counts", "manifest V/M differ from the DIMACS header")


@dataclass(frozen=True)
class Bundle:
    """A verified bundle: its directory, manifest and formula."""

    directory: Path
    manifest: BundleManifest
    formula: Formula = field(repr=False)

    @property
    def facts(self) -> FormulaFacts:
        return FormulaFacts(self.formula.variables, self.manifest.pools)


def _read_contained(root: Path, relative: str, limit: int | None = None) -> bytes:
    with open_contained(root, relative) as stream:
        return stream.read() if limit is None else read_at_most(stream, limit)


def load_bundle(root: Path, relative: str, *, limits: ReaderLimits = DEFAULT_LIMITS) -> Bundle:
    """Load and verify the bundle at RelPath ``relative`` below ``root`` (input errors)."""
    try:
        # J(manifest) + LF + one more byte suffices to detect limit.document.
        manifest_bytes = _read_contained(
            root, f"{relative}/manifest.json", limits.document_bytes + 2
        )
        formula_bytes = _read_contained(root, f"{relative}/formula.cnf")
    except FileNotFoundError as exc:
        raise InputError("bundle.files", f"{relative}: {exc.filename} is missing") from None
    except CubeproofError as error:
        raise contextualize(error, InputError) from None
    try:
        manifest = BundleManifest.from_json(parse_document(manifest_bytes, limits=limits))
        formula = parse_dimacs(formula_bytes)
        check_manifest_formula(manifest, formula)
    except CubeproofError as error:
        raise contextualize(error, InputError) from None
    return Bundle(Path(root) / relative, manifest, formula)


# -- side files -------------------------------------------------------------------------------


def _check_artifact(data: bytes, artifact: Artifact | None) -> None:
    if artifact is not None and (
        artifact.bytes != len(data) or artifact.sha256 != hashlib.sha256(data).hexdigest()
    ):
        raise ContractError("side.artifact", f"{artifact.path}: size or hash differs")


def _tsv_lines(data: bytes, columns: int, prefix: str) -> list[tuple[tuple[int, ...], str]]:
    rule = f"{prefix}.syntax"
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise ContractError(rule, "not UTF-8") from None
    if text and not text.endswith("\n"):
        raise ContractError(rule, "the last line does not end in LF")
    lines = []
    for number, line in enumerate(text.split("\n")[:-1], start=1):
        parts = line.split("\t")
        if len(parts) != columns + 1 or not all(_DECIMAL.fullmatch(p) for p in parts[:-1]):
            raise ContractError(rule, f"line {number}")
        try:
            label = json.loads(parts[-1])
        except ValueError:
            raise ContractError(rule, f"line {number}: label is not JSON") from None
        if type(label) is not str:
            raise ContractError(rule, f"line {number}: label is not a JSON string")
        try:
            canonical = encode(label).decode("utf-8")
        except ContractError:
            raise ContractError(rule, f"line {number}: label has a lone surrogate") from None
        if canonical != parts[-1]:
            raise ContractError(rule, f"line {number}: label is not J of a string")
        lines.append((tuple(int(p) for p in parts[:-1]), label))
    return lines


def parse_names_tsv(
    data: bytes, variables: int, *, artifact: Artifact | None = None
) -> tuple[tuple[int, str], ...]:
    """``names.tsv``: (variable, name) pairs; side.artifact, names.syntax/order/range."""
    _check_artifact(data, artifact)
    lines = _tsv_lines(data, 1, "names")
    ids = [numbers[0] for numbers, _ in lines]
    if any(a >= b for a, b in pairwise(ids)):
        raise ContractError("names.order", "IDs not strictly increasing")
    if any(not 1 <= i <= variables for i in ids):
        raise ContractError("names.range", f"an ID outside 1..{variables}")
    return tuple((numbers[0], label) for numbers, label in lines)


def parse_tags_tsv(
    data: bytes, clauses: int, *, artifact: Artifact | None = None
) -> tuple[tuple[int, int, str], ...]:
    """``tags.tsv``: (first, last, tag) ranges; side.artifact, tags.syntax/order/range."""
    _check_artifact(data, artifact)
    lines = _tsv_lines(data, 2, "tags")
    keys = [(numbers[0], numbers[1], label) for numbers, label in lines]
    if any(a >= b for a, b in pairwise(keys)):
        raise ContractError("tags.order", "lines not strictly sorted by (first, last, tag)")
    if any(not 1 <= first <= last <= clauses for first, last, _ in keys):
        raise ContractError("tags.range", f"a range outside 1..{clauses}")
    return tuple(keys)


def read_side_file(bundle: Bundle, name: str) -> tuple[tuple[Any, ...], ...]:
    """Read and verify a side file named in the manifest (side.artifact first)."""
    artifact = bundle.manifest.side_file(name)
    if artifact is None:
        raise ContractError("side.artifact", f"{name} is not listed in the manifest")
    data = _read_contained(bundle.directory, name)
    if name == "names.tsv":
        return parse_names_tsv(data, bundle.formula.variables, artifact=artifact)
    return parse_tags_tsv(data, bundle.formula.clauses, artifact=artifact)


# -- publication ------------------------------------------------------------------------------


def _write_synced(path: Path, data: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    try:
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError(f"no progress writing {path}")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _sync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def publish_bundle(
    target: Path,
    formula: bytes,
    *,
    pools: Mapping[str, Sequence[int]],
    producer: Mapping[str, Any],
    side_files: Mapping[str, bytes] | None = None,
) -> Bundle:
    """Publish a new immutable bundle at ``target`` (which must not exist).

    Everything is validated before anything is written: the formula is strict canonical
    DIMACS, pools and producer follow the manifest rules and side files are valid for this
    formula. The parent directory is created if needed.
    """
    target = Path(target)
    parsed = parse_dimacs(formula)
    sides = dict(side_files or {})
    for name in sides:
        if name not in SIDE_FILES:
            raise ContractError("schema", f"side file {name!r} is not one of {SIDE_FILES}")
    if "names.tsv" in sides:
        parse_names_tsv(sides["names.tsv"], parsed.variables)
    if "tags.tsv" in sides:
        parse_tags_tsv(sides["tags.tsv"], parsed.clauses)
    manifest = BundleManifest.from_json(
        {
            "format": "cubeproof-bundle-1",
            "formula_sha256": parsed.sha256,
            "variables": parsed.variables,
            "clauses": parsed.clauses,
            "pools": {k: list(v) for k, v in pools.items()},
            "producer": dict(producer),
            "side_files": [
                {"path": n, "sha256": hashlib.sha256(d).hexdigest(), "bytes": len(d)}
                for n, d in sorted(sides.items())
            ],
        }
    )
    if os.path.lexists(target):
        raise FileExistsError(f"bundle target exists: {target}")
    target.parent.mkdir(parents=True, exist_ok=True)
    staging = target.parent / f".{target.name}.staging-{new_id128()}"
    staging.mkdir()
    try:
        _write_synced(staging / "formula.cnf", parsed.data)
        for name, data in sorted(sides.items()):
            _write_synced(staging / name, data)
        _write_synced(staging / "manifest.json", document_bytes(manifest.to_json()))
        _sync_directory(staging)
        if os.path.lexists(target):
            raise FileExistsError(f"bundle target exists: {target}")
        os.rename(staging, target)
        _sync_directory(target.parent)
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    return Bundle(target, manifest, parsed)


def import_dimacs(source: Path, target: Path) -> Bundle:
    """``bundle import``: normalize external DIMACS explicitly and publish it as a bundle.

    Clause and literal order are preserved; the producer parameters record the SHA-256 of
    the original source bytes. The bundle has no pools and no side files.
    """
    raw = Path(source).read_bytes()
    canonical = normalize_external_dimacs(raw)
    producer = {
        "name": "cubeproof-import",
        "version": cubeproof.__version__,
        "parameters": {"source_sha256": hashlib.sha256(raw).hexdigest()},
    }
    return publish_bundle(target, canonical, pools={}, producer=producer)
