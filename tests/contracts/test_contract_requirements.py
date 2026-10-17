"""The requirement matrix: every cross-field/semantic rule is named, sourced and exercised.

``schemas/cubeproof/v1/requirements.json`` lists the rules that JSON Schema cannot express
(specification §1.2: schemas are executable transcriptions, the matrix holds the rest). Each
rule cites its section of the specification and its origin, says what a violation means for
each consumer and how it is exercised: by static corpus fixtures, by a named dynamic test,
or as implied by other rules. Writer obligations that no reader checks are listed
separately, so that no consumer has to guess whether a rule is reader-checked.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from typing import Any

from contract_reader import CORPUS, REPO, SCHEMAS, load_json_file

ORIGINS = {"spec", "routine"} | {f"reading-{n}" for n in range(1, 11)}
ORIGINS |= {f"routine-{n}" for n in range(1, 9)}
#: The components that consume a rule, each with the files or directories that hold its
#: code: parts of cubeproof, the independent certifier (tools/certify_min.py), the CNF
#: producer and the application.
CUBEPROOF = "packages/cubeproof/src/cubeproof"
COMPONENTS: dict[str, tuple[str, ...]] = {
    "contracts": (f"{CUBEPROOF}/contracts",),
    "journal": (f"{CUBEPROOF}/evidence/journal",),
    "tools": (f"{CUBEPROOF}/tools",),
    "unit": (f"{CUBEPROOF}/cnf/unit.py", f"{CUBEPROOF}/tools/unit_helper.py"),
    "certifier": (f"{CUBEPROOF}/evidence/certify",),
    "independent-certifier": ("tools/certify_min.py",),
    "splitters": (f"{CUBEPROOF}/split",),
    "leaf": (
        f"{CUBEPROOF}/leaf/attempt.py",
        f"{CUBEPROOF}/leaf/binding.py",
        f"{CUBEPROOF}/leaf/driver.py",
    ),
    "scheduler": (
        f"{CUBEPROOF}/coordinator/scheduler.py",
        f"{CUBEPROOF}/coordinator/scheduler_loop.py",
        f"{CUBEPROOF}/coordinator/scheduler_select.py",
    ),
    "handoff": (
        f"{CUBEPROOF}/coordinator/handoff.py",
        f"{CUBEPROOF}/coordinator/handoff_run.py",
        f"{CUBEPROOF}/commands/handoff.py",
    ),
    "status": (
        f"{CUBEPROOF}/coordinator/status.py",
        f"{CUBEPROOF}/coordinator/status_coverage.py",
        f"{CUBEPROOF}/coordinator/status_publish.py",
        f"{CUBEPROOF}/commands/status.py",
    ),
    "retain": (f"{CUBEPROOF}/leaf/retain.py", f"{CUBEPROOF}/leaf/quarantine.py"),
    "stream": (f"{CUBEPROOF}/leaf/stream.py",),
    "cli": (f"{CUBEPROOF}/cli",),
    "audit": (
        f"{CUBEPROOF}/commands/audit.py",
        f"{CUBEPROOF}/commands/audit_plan.py",
        f"{CUBEPROOF}/commands/audit_compare.py",
        f"{CUBEPROOF}/coordinator/audit_run.py",
    ),
    "neighbourly.cnf": ("packages/neighbourly/src/neighbourly/cnf",),
    "application": ("packages/faces12-campaign/src/faces12_campaign",),
}
CONSEQUENCES = {"input", "integrity", "resource", "reject", "anomaly"}


def components() -> set[str]:
    """The component names; every file or directory named for a component exists."""
    for name, paths in COMPONENTS.items():
        assert paths, name
        for path in paths:
            assert (REPO / path).exists(), (name, path)
    return set(COMPONENTS)


def matrix() -> dict[str, Any]:
    data: dict[str, Any] = load_json_file(SCHEMAS / "requirements.json")
    assert data["format"] == "cubeproof-requirements-1"
    return data


def sections() -> set[str]:
    text = (REPO / "docs" / "SPECIFICATION.md").read_text(encoding="utf-8")
    found = set(re.findall(r"^### (\d+\.\d+) ", text, re.MULTILINE))
    return found | set(re.findall(r"^## (\d+)\. ", text, re.MULTILINE))


def cited_rules() -> Iterator[str]:
    for entry in load_json_file(CORPUS / "documents.json")["documents"]:
        expect = entry["expect"]
        if expect != "valid":
            yield expect.get("rule", "schema")
    cases = load_json_file(CORPUS / "cases.json")
    for case in cases["cases"]:
        if "error" in case["expect"]:
            yield case["expect"]["error"]["rule"]
    for plan in cases["audit_plans"]:
        if plan["expect"] != "valid":
            yield plan["expect"]["rule"]
    cnf = load_json_file(CORPUS / "vectors" / "cnf.json")
    for entry in cnf["cubes"] + cnf["split_problems"]:
        if entry["expect"] is not None:
            yield entry["expect"]


def test_rows_are_complete_and_well_formed() -> None:
    rows = matrix()["requirements"]
    ids = [r["id"] for r in rows]
    assert len(ids) == len(set(ids))
    known = sections()
    known_components = components()
    used = {name for row in rows for name in row["consumers"]}
    assert used == known_components, sorted(used ^ known_components)
    for row in rows:
        assert set(row) == {
            "id",
            "section",
            "origin",
            "statement",
            "violation",
            "consumers",
            "fixtures",
        }, row["id"]
        assert re.fullmatch(r"[a-z_]+(\.[a-z0-9_]+)*", row["id"]), row["id"]
        assert row["section"] in known, (row["id"], row["section"])
        assert row["origin"] in ORIGINS, row["id"]
        assert row["statement"].strip(), row["id"]
        assert set(row["violation"].values()) <= CONSEQUENCES, row["id"]
        assert row["violation"], row["id"]
        assert set(row["consumers"]) <= known_components and row["consumers"], row["id"]
        assert set(row["violation"]) <= {"journal", "campaign", "document", "audit"}, row["id"]


def test_every_rule_is_exercised() -> None:
    rows = {r["id"]: r for r in matrix()["requirements"]}
    cited = set(cited_rules())
    assert cited <= set(rows), sorted(cited - set(rows))
    tests = "\n".join(
        p.read_text(encoding="utf-8") for p in sorted((REPO / "tests" / "contracts").glob("*.py"))
    )
    for ident, row in rows.items():
        kind, _, detail = row["fixtures"].partition(":")
        if kind == "static":
            assert ident in cited, f"{ident} has no fixture"
        elif kind == "dynamic":
            assert f"def {detail}(" in tests, ident
        elif kind == "implied":
            assert set(detail.split(",")) <= set(rows), ident
        else:
            raise AssertionError(f"{ident}: unknown fixture kind {kind!r}")


def test_writer_obligations_are_explicit() -> None:
    rows = matrix()
    reader = {r["id"] for r in rows["requirements"]}
    known = sections()
    obligations = rows["writer_obligations"]
    assert obligations
    for item in obligations:
        assert set(item) == {"id", "section", "origin", "statement"}, item
        assert item["id"].startswith("writer.") and item["id"] not in reader
        assert item["section"] in known and item["origin"] in ORIGINS


def test_every_recorded_reading_is_present() -> None:
    rows = matrix()
    origins = {r["origin"] for r in rows["requirements"] + rows["writer_obligations"]}
    for n in range(1, 11):
        assert f"reading-{n}" in origins, n
    for n in range(1, 9):
        assert f"routine-{n}" in origins, n


def test_the_matrix_names_the_conventions_it_relies_on() -> None:
    conventions = matrix()["conventions"]
    for word in ("strictly", "code point", "Ref", "first", "ECMA-262"):
        assert any(word in c for c in conventions), word
