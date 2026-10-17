"""The frozen v1 schemas transcribe the field tables of specification §4, §9.3, §11 and §12.

The field sets below are a second, hand-made transcription of the tables (specification
§4.2-§4.9, §9.3, §11.1-§11.2, §12.1, §12.3). Every object of the contract is closed
(specification §4.1: unknown fields are rejected, every field is required, nullable fields
are present with null), so the schema of each object must list exactly these names as
properties and as required.
"""

from __future__ import annotations

import re
from typing import Any

import pytest
from contract_reader import CORPUS, SCHEMAS, load_json_file, open_store, utc_valid
from contract_schema import SchemaStore

ENVELOPE = {"format", "seq", "prev", "self", "type", "utc"}

RECORDS = {
    "header": {"worker", "campaign", "purpose", "machinery", "policy", "resources"},
    "resume": {"machinery", "policy", "resources"},
    "shard": {"shard", "shard_sha256"},
    "split": {"node", "variables", "splitter"},
    "attempt": {
        "node",
        "node_id",
        "attempt_id",
        "policy_sha256",
        "route",
        "proof_mode",
        "outcome",
        "reason",
        "cnf_sha256",
        "limits",
        "solver",
        "checks",
        "proof_bytes",
        "proof_sha256",
        "relay",
        "assignment",
        "model_error",
        "retained",
        "quarantined",
        "diagnostics",
    },
    "node_stop": {"node", "state", "reason", "policy_sha256"},
    "node_reopen": {"node", "reason", "policy_sha256"},
    "handoff": {"request", "shard", "shard_sha256"},
    "repair": {"removed_bytes", "removed_sha256"},
    "audit_begin": {
        "certificate_sha256",
        "sample_count",
        "seed",
        "targets_sha256",
        "target_count",
        "comparison",
    },
    "audit_target": {"target", "ordinal"},
    "audit_ready": {"targets_sha256", "target_count"},
    "audit_result": {"target", "attempt", "status", "reason"},
}

POLICY = {
    "leaf_time_ms",
    "proof_cap_bytes",
    "solver_memory_bytes",
    "checker_max_heap_mib",
    "checker_stack_mib",
    "checker_max_stack_mib",
    "checker_slack_mib",
    "checker_time_base_ms",
    "checker_time_per_100mb_ms",
    "heap_fit",
    "split",
    "max_cube_size",
    "proof_mode",
    "stream_heap_mib",
    "quarantine_quota_bytes",
    "tool_retries",
    "machine_failure_limit",
    "anomaly_limit",
    "term_grace_ms",
    "stop_grace_ms",
}

#: (schema file, pointer) -> (field names, constant of ``format`` or None)
OBJECTS: dict[tuple[str, str], tuple[set[str], str | None]] = {
    ("bundle-manifest.schema.json", ""): (
        {"format", "formula_sha256", "variables", "clauses", "pools", "producer", "side_files"},
        "cubeproof-bundle-1",
    ),
    ("bundle-manifest.schema.json", "/properties/producer"): (
        {"name", "version", "parameters"},
        None,
    ),
    ("policy.schema.json", ""): (POLICY, None),
    ("policy.schema.json", "/properties/heap_fit"): (
        {"coefficient_milli", "exponent_milli", "margin_milli", "min_mib"},
        None,
    ),
    ("policy.schema.json", "/properties/split"): (
        {"method", "vars", "pool", "probe_limit", "wall_ms"},
        None,
    ),
    ("campaign.schema.json", ""): (
        {
            "format",
            "created_utc",
            "author",
            "formulas",
            "roots",
            "root_splits",
            "policy",
            "tools",
            "admit",
        },
        "cubeproof-campaign-1",
    ),
    ("campaign.schema.json", "/properties/formulas/items"): (
        {"key", "formula_sha256", "bundle"},
        None,
    ),
    ("campaign.schema.json", "/properties/root_splits/items"): (
        {"node", "variables", "splitter"},
        None,
    ),
    ("campaign.schema.json", "/properties/tools"): ({"solver", "checker"}, None),
    ("campaign.schema.json", "/properties/tools/properties/solver"): (
        {"name", "sha256", "argv"},
        None,
    ),
    ("campaign.schema.json", "/properties/tools/properties/checker"): ({"name", "sha256"}, None),
    ("campaign.schema.json", "/properties/admit"): ({"checker_sha256", "solvers"}, None),
    ("shard.schema.json", ""): ({"format", "campaign", "name", "nodes"}, "cubeproof-shard-1"),
    ("handoff-request.schema.json", ""): (
        {"format", "campaign", "request_id", "node_count", "output_name"},
        "cubeproof-handoff-request-1",
    ),
    ("common.schema.json", "/$defs/Node"): ({"formula_sha256", "cube"}, None),
    ("common.schema.json", "/$defs/Ref"): ({"journal", "seq"}, None),
    ("common.schema.json", "/$defs/Artifact"): ({"path", "sha256", "bytes"}, None),
    ("common.schema.json", "/$defs/Splitter"): ({"name", "info"}, None),
    ("common.schema.json", "/$defs/Machinery"): (
        {
            "solver",
            "checker",
            "helper",
            "runtime",
            "source_manifest",
            "packages_sha256",
            "cubeproof_sha256",
            "unit_algorithm",
        },
        None,
    ),
    ("common.schema.json", "/$defs/Machinery/properties/solver"): (
        {"path", "sha256", "version", "argv"},
        None,
    ),
    ("common.schema.json", "/$defs/Machinery/properties/checker"): ({"path", "sha256"}, None),
    ("common.schema.json", "/$defs/Machinery/properties/runtime"): (
        {"python", "libc", "platform", "image_digest"},
        None,
    ),
    ("common.schema.json", "/$defs/ProcessResult"): (
        {
            "started",
            "exit",
            "signal",
            "elapsed_ms",
            "stdout_tail",
            "stderr_tail",
            "stdout_bytes",
            "stdout_truncated",
            "cause",
            "conflicts",
        },
        None,
    ),
    ("common.schema.json", "/$defs/CheckerCheck"): ({"result", "heap_mib", "stack_mib"}, None),
    ("common.schema.json", "/$defs/ResourceSnapshot"): (
        {"cpu_milli", "memory_budget_bytes", "filesystems", "coordinator_rss_bytes"},
        None,
    ),
    ("common.schema.json", "/$defs/Limits"): (
        {"solver_time_ms", "proof_cap_bytes", "solver_memory_bytes", "check_time_ms"},
        None,
    ),
    ("common.schema.json", "/$defs/Relay"): (
        {"bytes", "sha256", "solver_eof", "all_written", "error"},
        None,
    ),
    ("common.schema.json", "/$defs/AuditTarget"): (
        {"node", "node_id", "source", "cnf_sha256", "proof_sha256", "route", "machinery"},
        None,
    ),
    ("common.schema.json", "/$defs/Summary"): (
        {"leaves", "splits", "max_cube_size", "leaf_merkle_root"},
        None,
    ),
    ("common.schema.json", "/$defs/OpenNode"): ({"node", "node_id", "state", "reason"}, None),
    ("certificate.schema.json", ""): (
        {
            "format",
            "campaign",
            "journals",
            "formulas",
            "open",
            "formula_open",
            "used_attempts",
            "machinery",
            "not_admitted",
            "models",
            "anomalies",
            "verdict",
        },
        "cubeproof-certificate-1",
    ),
    ("certificate.schema.json", "/properties/journals/items"): (
        {"id", "worker", "records", "head", "bytes", "torn_tail_bytes"},
        None,
    ),
    ("certificate.schema.json", "/properties/formulas/items"): (
        {"formula_sha256", "key", "proved", "summary", "roots"},
        None,
    ),
    ("certificate.schema.json", "/properties/used_attempts/items"): (
        {"node", "node_id", "record", "cnf_sha256", "proof_sha256", "route"},
        None,
    ),
    ("certificate.schema.json", "/properties/machinery/items"): (
        {"journal", "snapshot_seq", "machinery"},
        None,
    ),
    ("certificate.schema.json", "/properties/not_admitted/items"): ({"record", "reason"}, None),
    ("certificate.schema.json", "/properties/models/items"): (
        {"record", "node", "assignment"},
        None,
    ),
    ("certificate.schema.json", "/properties/anomalies/items"): ({"record", "code", "info"}, None),
    ("evidence-manifest.schema.json", ""): (
        {"format", "campaign", "bundles", "journals", "certificate"},
        "cubeproof-evidence-1",
    ),
    ("evidence-manifest.schema.json", "/properties/bundles/items"): (
        {"manifest", "formula"},
        None,
    ),
    ("audit-report.schema.json", ""): (
        {
            "format",
            "campaign",
            "certificate_sha256",
            "targets_sha256",
            "comparison",
            "population",
            "selected",
            "seed",
            "counts",
            "results",
            "pending",
        },
        "cubeproof-audit-report-1",
    ),
    ("audit-report.schema.json", "/properties/counts"): (
        {"HASH_MATCHED", "REPROVED_UNSAT", "MISMATCH", "NOT_COMPARABLE", "FAILED", "OPEN"},
        None,
    ),
    ("audit-report.schema.json", "/properties/results/items"): (
        {"target", "record", "status", "reason"},
        None,
    ),
    ("status.schema.json", ""): (
        {
            "format",
            "campaign",
            "journal",
            "head",
            "policy_sha256",
            "worker",
            "seq",
            "utc",
            "lifecycle",
            "resources",
            "reservations",
            "node_counts",
            "active",
            "oldest_elapsed_ms",
            "counters",
            "export",
            "models",
            "anomalies",
            "coverage",
            "eta_ms",
            "info",
        },
        "cubeproof-status-1",
    ),
    ("status.schema.json", "/properties/reservations/items"): (
        {"task_id", "stage", "cpu_milli", "memory_bytes", "disk"},
        None,
    ),
    ("status.schema.json", "/properties/node_counts/items"): ({"state", "depth", "count"}, None),
    ("status.schema.json", "/properties/active/items"): (
        {"task_id", "node_id", "stage", "elapsed_ms"},
        None,
    ),
    ("status.schema.json", "/properties/coverage/items"): (
        {"node", "closed_numerator", "denominator_power_two"},
        None,
    ),
    ("weights.schema.json", ""): ({"format", "campaign", "costs"}, "cubeproof-weights-1"),
    ("roots.schema.json", ""): ({"format", "roots"}, "cubeproof-roots-1"),
    ("prefixes.schema.json", ""): ({"format", "splits"}, "cubeproof-prefixes-1"),
    ("prefixes.schema.json", "/properties/splits/items"): (
        {"node", "variables", "splitter"},
        None,
    ),
    ("look-request.schema.json", ""): (
        {"format", "formula_path", "formula_sha256", "cube", "k", "pool", "probe_limit", "wall_ms"},
        "cubeproof-look-request-1",
    ),
    ("look-result.schema.json", ""): (
        {"format", "node_id", "variables", "status", "info"},
        "cubeproof-look-result-1",
    ),
}

for _type, _payload in RECORDS.items():
    OBJECTS[("journal-record.schema.json", f"/$defs/{_type}")] = (
        ENVELOPE | _payload,
        "cubeproof-journal-1",
    )

#: Hand-made primitive cases (specification §4.1 and reading 7); the corpus has more.
PRIMITIVES: dict[str, dict[Any, bool]] = {
    "Hash": {"0" * 64: True, "a" * 64: True, "A" * 64: False, "0" * 63: False, "g" * 64: False},
    "Id128": {"0" * 32: True, "0" * 31: False, "F" * 32: False},
    "Name": {
        "a": True,
        "w1": True,
        "a-b_c": True,
        "a" * 64: True,
        "a" * 65: False,
        "-a": False,
        "_a": False,
        "A": False,
        "": False,
        "a b": False,
        "a\n": False,
    },
    "RelPath": {
        "a": True,
        "a/b.json": True,
        "..a": True,
        "a..": True,
        "ab:c": True,
        "": False,
        ".": False,
        "..": False,
        "./a": False,
        "a/.": False,
        "a/../b": False,
        "a//b": False,
        "/a": False,
        "a/": False,
        "a\\b": False,
        "C:a": False,
        "c:/a": False,
        "a\u0000b": False,
    },
    "UTC": {
        "2026-10-04T12:00:00.000Z": True,
        "2024-02-29T23:59:59.999Z": True,
        "2000-02-29T00:00:00.000Z": True,
        "2023-02-29T00:00:00.000Z": False,
        "1900-02-29T00:00:00.000Z": False,
        "2026-04-31T00:00:00.000Z": False,
        "2026-13-01T00:00:00.000Z": False,
        "2026-10-04T24:00:00.000Z": False,
        "2026-10-04T23:60:00.000Z": False,
        "2026-10-04T23:59:60.000Z": False,
        "2026-10-04T12:00:00Z": False,
        "2026-10-04T12:00:00.000+00:00": False,
        "2026-10-04 12:00:00.000Z": False,
        "\u0662026-10-04T12:00:00.000Z": False,
    },
    "Int64": {2**63 - 1: True, -(2**63 - 1): True, 0: True, 2**63: False, -(2**63): False},
    "NonNegative": {0: True, 2**63 - 1: True, -1: False},
    "Positive": {1: True, 0: False},
    "Literal": {1: True, -1: True, 0: False, 2**63 - 1: True, -(2**63 - 1): True},
}


@pytest.fixture(scope="module")
def store() -> SchemaStore:
    return open_store()


def test_every_schema_uses_only_the_supported_subset_and_its_refs_resolve(
    store: SchemaStore,
) -> None:
    expected = {name for name, _ in OBJECTS} | {"common.schema.json"}
    assert set(store.files) == expected
    for name, schema in store.files.items():
        assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema", name


@pytest.mark.parametrize(("file", "pointer"), sorted(OBJECTS), ids=str)
def test_each_object_lists_exactly_the_fields_of_its_table(
    store: SchemaStore, file: str, pointer: str
) -> None:
    fields, constant = OBJECTS[(file, pointer)]
    schema, _ = store.resolve(file + ("#" + pointer if pointer else ""), file)
    assert schema.get("type") == "object"
    assert set(schema["properties"]) == fields
    assert set(schema["required"]) == fields
    assert schema["additionalProperties"] is False
    if constant is not None:
        assert schema["properties"]["format"] == {"const": constant}


def test_each_record_schema_fixes_its_type(store: SchemaStore) -> None:
    top, _ = store.resolve("journal-record.schema.json", "journal-record.schema.json")
    refs = {item["$ref"] for item in top["anyOf"]}
    assert refs == {f"#/$defs/{t}" for t in RECORDS}
    for record_type in RECORDS:
        schema, _ = store.resolve(
            f"journal-record.schema.json#/$defs/{record_type}", "journal-record.schema.json"
        )
        assert schema["properties"]["type"] == {"const": record_type}


@pytest.mark.parametrize("name", sorted(PRIMITIVES))
def test_hand_made_primitive_cases(store: SchemaStore, name: str) -> None:
    for value, valid in PRIMITIVES[name].items():
        ok = store.valid(value, "common.schema.json", "/$defs/" + name)
        if name == "UTC" and ok:
            ok = utc_valid(value)
        assert ok == valid, (name, value)


def test_the_utc_pattern_alone_rejects_format_errors(store: SchemaStore) -> None:
    """Specification §4.1: the schema pattern itself fixes the format (milliseconds, Z, T);
    utc.calendar only adds the calendar check. A consumer that validates with the schema alone
    must not accept these strings."""
    for value in (
        "2026-10-04T12:00:00Z",
        "2026-10-04T12:00:00.00Z",
        "2026-10-04T12:00:00.000+00:00",
        "2026-10-04 12:00:00.000Z",
        "2026-10-04T12:00:00.000z",
    ):
        assert not store.valid(value, "common.schema.json", "/$defs/UTC"), value


def test_booleans_are_never_integers(store: SchemaStore) -> None:
    for name in ("Int64", "NonNegative", "Positive", "Literal"):
        assert not store.valid(True, "common.schema.json", "/$defs/" + name)
        assert not store.valid(False, "common.schema.json", "/$defs/" + name)


def test_corpus_primitive_vectors(store: SchemaStore) -> None:
    vectors = load_json_file(CORPUS / "vectors" / "primitives.json")
    assert vectors["format"] == "cubeproof-vectors-primitives-1"
    assert set(vectors["primitives"]) >= set(PRIMITIVES)
    for name, cases in vectors["primitives"].items():
        assert cases["valid"] and cases["invalid"], name
        for value in cases["valid"]:
            assert store.valid(value, "common.schema.json", "/$defs/" + name), (name, value)
            assert name != "UTC" or utc_valid(value)
        for value in cases["invalid"]:
            ok = store.valid(value, "common.schema.json", "/$defs/" + name)
            assert not (ok and (name != "UTC" or utc_valid(value))), (name, value)


def test_reason_and_model_error_vocabularies_are_closed(store: SchemaStore) -> None:
    """Readings 1 and 2: reason codes of specification §6.3 only; model errors of §4.8 only."""
    attempt, _ = store.resolve(
        "journal-record.schema.json#/$defs/attempt", "journal-record.schema.json"
    )
    codes = {
        "proof_size",
        "time",
        "check_time",
        "check_memory",
        "check_stack",
        "solver_memory",
        "launch",
        "binary_changed",
        "io",
        "file_changed",
        "crash",
        "protocol",
        "relay",
        "rejected",
        "missing",
        "conflicting",
        "out_of_range",
        "syntax",
        "violated",
    }
    reason = attempt["properties"]["reason"]
    assert set(reason["anyOf"][1]["enum"]) == codes
    assert reason["anyOf"][0] == {"type": "null"}
    errors = attempt["properties"]["model_error"]
    assert set(errors["anyOf"][1]["enum"]) == {
        "missing",
        "conflicting",
        "out_of_range",
        "syntax",
        "violated",
    }
    outcomes = set(attempt["properties"]["outcome"]["enum"])
    assert outcomes == {
        "VERIFIED_UNSAT",
        "EXHAUSTED",
        "MODEL",
        "INVALID_MODEL",
        "CHECK_REJECTED",
        "TOOL_FAILED",
    }


def schema_patterns(value: Any) -> list[str]:
    if isinstance(value, dict):
        found = [value["pattern"]] if isinstance(value.get("pattern"), str) else []
        return found + [p for v in value.values() for p in schema_patterns(v)]
    if isinstance(value, list):
        return [p for v in value for p in schema_patterns(v)]
    return []


END = "(?![\\s\\S])"


def test_patterns_reject_a_final_lf_also_under_search_semantics(store: SchemaStore) -> None:
    """JSON Schema patterns are ECMA-262 and unanchored; Python's re.search lets '$' match
    before a final LF. Every pattern starts with '^' and ends with END (no '$'), so that a
    validator built on re.search (for example the jsonschema package) agrees with ECMA-262
    and with this reader."""
    patterns = [p for schema in store.files.values() for p in schema_patterns(schema)]
    assert len(patterns) >= 10
    for pattern in patterns:
        assert pattern.startswith("^") and pattern.endswith(END), pattern
        assert not pattern.endswith("$"), pattern
    samples = {name: [v for v, ok in PRIMITIVES[name].items() if ok] for name in PRIMITIVES}
    # RelPath is left out: LF is a permitted character inside a POSIX path component
    for name in ("Hash", "Id128", "Name", "UTC"):
        schema, _ = store.resolve(f"common.schema.json#/$defs/{name}", "common.schema.json")
        for value in samples[name]:
            assert re.search(schema["pattern"], value), (name, value)
            assert re.search(schema["pattern"], value + "\n") is None, (name, value)
            assert not store.valid(value + "\n", "common.schema.json", "/$defs/" + name)


def test_schemas_are_readable_pretty_json() -> None:
    for path in sorted(SCHEMAS.glob("*.schema.json")):
        text = path.read_text(encoding="utf-8")
        assert text.endswith("\n") and "\t" not in text, path.name
