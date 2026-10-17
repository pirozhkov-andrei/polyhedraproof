"""``bundle import``: normalize external DIMACS explicitly into an immutable bundle (specification
§3.1, §4.2).

``cubeproof bundle import INPUT.cnf -o BUNDLE`` is the only door for a DIMACS file that is not
already canonical: clause and literal order are preserved, the producer records the SHA-256 of the
original bytes, the bundle has no pools and no side files (those come from a producer that knows
them). The bundle directory is published whole or not at all and an existing target is never
overwritten. A formula is never normalized implicitly anywhere else.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cubeproof.base.errors import ConfigurationError, ContractError, InputError
from cubeproof.cnf.bundle import import_dimacs

__all__ = ["BundleImport", "bundle_import"]


@dataclass(frozen=True)
class BundleImport:
    """The published bundle."""

    path: str
    formula_sha256: str
    variables: int
    clauses: int
    source_sha256: str

    @property
    def exit_code(self) -> int:
        return 0

    def to_json(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "formula_sha256": self.formula_sha256,
            "variables": self.variables,
            "clauses": self.clauses,
            "source_sha256": self.source_sha256,
        }


def bundle_import(source: Path, target: Path) -> BundleImport:
    """Import ``source`` (external DIMACS) as the new bundle directory ``target``."""
    source_path, target_path = Path(source), Path(target)
    if not source_path.is_file():
        raise InputError("input.file", f"{source_path} is not a file")
    try:
        bundle = import_dimacs(source_path, target_path)
    except FileExistsError:
        raise ConfigurationError("bundle.exists", f"{target_path} already exists") from None
    except ContractError as error:
        raise InputError(error.rule, f"{source_path}: {error.detail}") from None
    except OSError as error:
        raise InputError("input.file", f"{source_path}: {error.strerror or error}") from None
    manifest = bundle.manifest
    parameters = manifest.producer.parameters.to_json()
    return BundleImport(
        str(target_path.resolve()),
        manifest.formula_sha256,
        manifest.variables,
        manifest.clauses,
        str(parameters["source_sha256"]),
    )
