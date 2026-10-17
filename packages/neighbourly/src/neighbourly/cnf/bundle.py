"""Bundle writing and immutable publication: ``cubeproof-bundle-1`` (specification §4.1, §4.2).

A bundle is a directory with ``formula.cnf`` (canonical DIMACS), ``manifest.json`` and the
optional side files ``names.tsv`` and ``tags.tsv``. :func:`bundle_files` computes the bytes
of every file without touching the disk; :func:`publish_bundle` writes them into a fresh
sibling staging directory, manifest last, syncs them, and renames the directory into place
in one step. A published bundle is never overwritten.

The manifest is ``J(manifest)`` plus one LF, where J is canonical JSON (sorted keys, compact
separators, UTF-8, no floating point). Pools are sorted here; repeated pool variables,
repeated names or tag ranges, values outside the formula and non-JSON parameters are refused,
never silently repaired.
"""

from __future__ import annotations

import hashlib
import itertools
import json
import os
import re
import secrets
import shutil
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType

from neighbourly.cnf.dimacs import ClauseLike, checked_clause_bytes, header_bytes
from neighbourly.cnf.errors import CnfError

FORMAT = "cubeproof-bundle-1"
FORMULA = "formula.cnf"
MANIFEST = "manifest.json"
NAMES = "names.tsv"
TAGS = "tags.tsv"
#: Largest integer of the common JSON rules, in absolute value.
INT_MAX = 2**63 - 1
#: Nesting depth limit of the common JSON rules (a scalar is depth 0).
DEPTH_LIMIT = 32
#: Default reader limit for one document, without its final LF.
DOCUMENT_LIMIT = 64 * 1024 * 1024
_NAME = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}")


# -- canonical JSON (specification §4.1) -----------------------------------------------------------


def _has_lone_surrogate(text: str) -> bool:
    return any(0xD800 <= ord(char) <= 0xDFFF for char in text)


def _check_json(value: object, depth: int, where: str) -> None:
    if value is None or isinstance(value, (bool, str)):
        if isinstance(value, str) and _has_lone_surrogate(value):
            raise CnfError(f"{where}: unpaired surrogate in a string")
        return
    if isinstance(value, int):
        if not -INT_MAX <= value <= INT_MAX:
            raise CnfError(f"{where}: integer {value} outside [-(2^63-1), 2^63-1]")
        return
    if not isinstance(value, (list, tuple, dict)):
        raise CnfError(f"{where}: {type(value).__name__} is not a JSON value of the contract")
    if depth + 1 > DEPTH_LIMIT:
        raise CnfError(f"{where}: nested deeper than {DEPTH_LIMIT}")
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str) or _has_lone_surrogate(key):
                raise CnfError(f"{where}: object key {key!r} is not a valid string")
            _check_json(item, depth + 1, f"{where}.{key}")
        return
    for index, item in enumerate(value):
        _check_json(item, depth + 1, f"{where}[{index}]")


def canonical_json(value: object) -> bytes:
    """J(value): canonical JSON as UTF-8, after checking the common JSON rules."""
    _check_json(value, 0, "$")
    text = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    )
    return text.encode("utf-8")


def _json_string(text: object, where: str) -> str:
    if not isinstance(text, str):
        raise CnfError(f"{where}: {text!r} is not a string")
    return canonical_json(text).decode("utf-8")


def _positive(value: object, limit: int, where: str) -> int:
    if type(value) is not int or not 1 <= value <= limit:
        raise CnfError(f"{where}: {value!r} is not an integer in 1..{limit}")
    return value


# -- side files -------------------------------------------------------------------------


def names_tsv(names: Mapping[int, str], variables: int) -> bytes:
    """``ID<TAB>JSON_STRING\\n`` per named variable, by increasing ID."""
    lines = []
    for variable in sorted(_positive(v, variables, "names") for v in names):
        lines.append(f"{variable}\t{_json_string(names[variable], f'name of {variable}')}\n")
    return "".join(lines).encode("utf-8")


def tags_tsv(tags: Iterable[tuple[int, int, str]], clauses: int) -> bytes:
    """``FIRST<TAB>LAST<TAB>JSON_STRING\\n`` per tagged clause range, sorted by (first, last, tag).

    Ranges are 1-based and inclusive; they may overlap. A repeated (first, last, tag) is refused.
    """
    entries = []
    for entry in tags:
        first, last, tag = entry
        _positive(first, clauses, "tag range start")
        _positive(last, clauses, "tag range end")
        if last < first:
            raise CnfError(f"tag range {first}..{last} is empty")
        entries.append((first, last, _json_string(tag, f"tag of {first}..{last}"), tag))
    entries.sort(key=lambda e: (e[0], e[1], e[3]))
    for previous, current in itertools.pairwise(entries):
        if (previous[0], previous[1], previous[3]) == (current[0], current[1], current[3]):
            raise CnfError(f"tag range {current[0]}..{current[1]} {current[3]!r} is repeated")
    return "".join(f"{first}\t{last}\t{text}\n" for first, last, text, _ in entries).encode("utf-8")


# -- the bundle -------------------------------------------------------------------------


@dataclass(frozen=True)
class Producer:
    """``producer`` of the manifest: who wrote the bundle, with which open parameters."""

    name: str
    version: str
    parameters: Mapping[str, object] = field(default_factory=dict)


@dataclass(frozen=True)
class BundleFiles:
    """The bytes of every file of one bundle, in the order they are written (manifest last).

    `files` and the top level of `manifest` are read-only views; `manifest` is a convenience
    copy of what ``files["manifest.json"]`` holds, and only `files` is ever written.
    """

    files: Mapping[str, bytes]
    formula_sha256: str
    manifest: Mapping[str, object]

    @property
    def manifest_sha256(self) -> str:
        """SHA-256 of J(manifest), the manifest file without its final LF."""
        return hashlib.sha256(self.files[MANIFEST][:-1]).hexdigest()


def _artifact(path: str, data: bytes) -> dict[str, object]:
    return {"path": path, "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}


def _pools(pools: Mapping[str, Iterable[int]], variables: int) -> dict[str, list[int]]:
    result: dict[str, list[int]] = {}
    for name, members in pools.items():
        if not isinstance(name, str) or _NAME.fullmatch(name) is None:
            raise CnfError(f"pool name {name!r} is not a Name ([a-z0-9][a-z0-9_-]{{0,63}})")
        ordered = sorted(_positive(v, variables, f"pool {name}") for v in members)
        for previous, current in itertools.pairwise(ordered):
            if previous == current:
                raise CnfError(f"pool {name}: variable {current} is repeated")
        result[name] = ordered
    return result


def bundle_files(
    variables: int,
    clauses: Sequence[ClauseLike],
    *,
    pools: Mapping[str, Iterable[int]],
    producer: Producer,
    names: Mapping[int, str] | None = None,
    tags: Iterable[tuple[int, int, str]] | None = None,
) -> BundleFiles:
    """Compute every file of a bundle; nothing is written.

    `clauses` are written in order, literal by literal, after validating every literal.
    `names` and `tags`, when given (even empty), become ``names.tsv`` and ``tags.tsv``.
    """
    formula = header_bytes(variables, len(clauses)) + checked_clause_bytes(variables, clauses)
    formula_sha256 = hashlib.sha256(formula).hexdigest()
    side: dict[str, bytes] = {}
    if names is not None:
        side[NAMES] = names_tsv(names, variables)
    if tags is not None:
        side[TAGS] = tags_tsv(tags, len(clauses))
    if not isinstance(producer.name, str) or not isinstance(producer.version, str):
        raise CnfError("producer name and version must be strings")
    manifest: dict[str, object] = {
        "format": FORMAT,
        "formula_sha256": formula_sha256,
        "variables": variables,
        "clauses": len(clauses),
        "pools": _pools(pools, variables),
        "producer": {
            "name": producer.name,
            "version": producer.version,
            "parameters": dict(producer.parameters),
        },
        "side_files": [_artifact(path, side[path]) for path in sorted(side)],
    }
    encoded = canonical_json(manifest)
    if len(encoded) > DOCUMENT_LIMIT:
        raise CnfError(f"manifest of {len(encoded)} bytes exceeds the {DOCUMENT_LIMIT} byte limit")
    files = {FORMULA: formula, **{path: side[path] for path in sorted(side)}}
    files[MANIFEST] = encoded + b"\n"
    return BundleFiles(MappingProxyType(files), formula_sha256, MappingProxyType(manifest))


# -- publication ------------------------------------------------------------------------


def _sync_directory(path: Path) -> None:
    if os.name == "nt":  # Windows cannot open a directory for fsync; renames are durable there
        return
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def publish_bundle(target: str | os.PathLike[str], bundle: BundleFiles) -> Path:
    """Publish `bundle` as the new directory `target`, atomically, and return its path.

    The files are written into a fresh sibling directory (same filesystem), each synced,
    ``manifest.json`` last; the directory is synced and then renamed to `target`, and the
    parent directory is synced. An existing `target` is refused: a live bundle is
    immutable. Only the four bundle file names are written, ``formula.cnf`` first,
    ``manifest.json`` last. On a failure before the rename the staging directory is removed
    and `target` does not exist. If syncing the parent directory fails after the rename, the
    error is raised with the complete bundle in place at `target` but its durability
    unconfirmed.
    """
    destination = Path(target)
    if destination.exists() or destination.is_symlink():
        raise CnfError(f"{destination} exists; a published bundle is never overwritten")
    names = list(bundle.files)
    if not names or names[-1] != MANIFEST or names[0] != FORMULA:
        raise CnfError("a bundle writes formula.cnf first and manifest.json last")
    if any(name not in (NAMES, TAGS) for name in names[1:-1]):
        raise CnfError(f"a bundle holds only {FORMULA}, {NAMES}, {TAGS} and {MANIFEST}: {names}")
    parent = destination.parent
    staging = parent / f".{destination.name}.staging-{os.getpid()}-{secrets.token_hex(8)}"
    staging.mkdir()
    try:
        for name in names:
            with open(staging / name, "xb") as handle:
                handle.write(bundle.files[name])
                handle.flush()
                os.fsync(handle.fileno())
        _sync_directory(staging)
        if destination.exists() or destination.is_symlink():
            raise CnfError(f"{destination} appeared during publication; not overwritten")
        os.rename(staging, destination)
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    _sync_directory(parent)
    return destination
