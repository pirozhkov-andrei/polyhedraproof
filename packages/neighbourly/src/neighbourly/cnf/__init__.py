"""neighbourly.cnf: problem-independent CNF emission.

Deterministic variables and clauses (:mod:`~neighbourly.cnf.builder`), witness checks
(:mod:`~neighbourly.cnf.witness`), the gate encodings the formulas use
(:mod:`~neighbourly.cnf.encodings`), the canonical DIMACS producer writer
(:mod:`~neighbourly.cnf.dimacs`) and bundle writing and publication
(:mod:`~neighbourly.cnf.bundle`); specification §3.1, §4.2 and §13.1.

The module keeps a hard boundary: it imports only the standard library and its own
submodules, never another `neighbourly` module, and it does not read package data. The
architecture tests enforce this boundary.
"""

from __future__ import annotations

from neighbourly.cnf.builder import Builder, Clause, LayerCounts
from neighbourly.cnf.bundle import (
    BundleFiles,
    Producer,
    bundle_files,
    canonical_json,
    names_tsv,
    publish_bundle,
    tags_tsv,
)
from neighbourly.cnf.dimacs import (
    check_clauses,
    checked_clause_bytes,
    clause_bytes,
    dimacs_bytes,
    formula_digest,
    header_bytes,
)
from neighbourly.cnf.errors import CnfError, WitnessViolation
from neighbourly.cnf.witness import OracleWitness, VariableName, Witness

__all__ = [
    "Builder",
    "BundleFiles",
    "Clause",
    "CnfError",
    "LayerCounts",
    "OracleWitness",
    "Producer",
    "VariableName",
    "Witness",
    "WitnessViolation",
    "bundle_files",
    "canonical_json",
    "check_clauses",
    "checked_clause_bytes",
    "clause_bytes",
    "dimacs_bytes",
    "formula_digest",
    "header_bytes",
    "names_tsv",
    "publish_bundle",
    "tags_tsv",
]
