"""The packages of this checkout against the import rules (specification §2.1 and §2.3).

The rule engine is ``tools/checks/archcheck.py``; ``test_guard_fixtures.py`` shows that each
rule fires on a deliberately broken tree. Here the real packages must produce no finding,
and the rule tables must still say what the architecture says.
"""

from __future__ import annotations

from pathlib import Path

from archcheck import (
    CAMPAIGN_LAYERS,
    CUBEPROOF_LAYERS,
    INDEPENDENT_TOOLS,
    LAYER_TABLES,
    NEIGHBOURLY_LAYERS,
    SEALED,
    Layer,
    check_repository,
    distribution,
    package_dirs,
)

ROOT = Path(__file__).resolve().parents[2]


def _table(layers: tuple[Layer, ...]) -> dict[str, set[str]]:
    return {layer.name: set(layer.allowed) for layer in layers}


def test_the_packages_follow_the_architecture_rules() -> None:
    found = check_repository(ROOT)
    assert found == [], "\n".join(map(str, found))


def test_every_package_has_a_rule_table() -> None:
    tops = {distribution(d).top for d in package_dirs(ROOT)}
    assert tops == set(LAYER_TABLES) == {"cubeproof", "neighbourly", "faces12_campaign"}


def test_the_cubeproof_table_transcribes_the_dependency_table() -> None:
    """Specification §2.3, row by row; a change needs the specification and this test."""
    below_entry = {
        "commands",
        "coordinator",
        "leaf",
        "split",
        "certify",
        "schema",
        "journal",
        "tools",
        "cnf",
        "contracts",
        "base",
    }
    expected = {
        "root": set(),
        "evidence-root": set(),
        "cli": below_entry,
        "api": below_entry,
        "commands": below_entry - {"commands"},
        "coordinator": below_entry - {"commands", "coordinator"},
        "leaf": {"schema", "journal", "tools", "cnf", "contracts", "base"},
        "split": {"schema", "journal", "tools", "cnf", "contracts", "base"},
        "certify": {"schema", "journal", "cnf", "contracts", "base"},
        "schema": {"contracts", "base"},
        "journal": {"contracts", "base"},
        "tools": {"cnf", "contracts", "base"},
        "cnf": {"contracts", "base"},
        "contracts": {"base"},
        "base": set(),
    }
    assert _table(CUBEPROOF_LAYERS) == expected


def test_the_certifier_and_its_inputs_use_only_pure_helpers() -> None:
    pure = {layer.name for layer in CUBEPROOF_LAYERS if layer.pure}
    assert pure == {"certify", "schema", "journal", "cnf", "contracts"}


def test_only_the_command_line_is_an_environment_and_output_boundary() -> None:
    """Besides the command line, only the stream relay process entry (specification §6.4), which
    imports nothing of the package."""
    for layers in LAYER_TABLES.values():
        boundary = {layer.prefixes for layer in layers if layer.boundary and layer.name != "cli"}
        assert boundary <= {("cubeproof.tools.relay",)}
    relay = [layer for layer in CUBEPROOF_LAYERS if layer.prefixes == ("cubeproof.tools.relay",)]
    assert all(layer.exact and layer.allowed == frozenset() for layer in relay)
    assert not any(layer.boundary for layer in NEIGHBOURLY_LAYERS)


def test_package_roots_import_nothing_of_their_package() -> None:
    for layers in LAYER_TABLES.values():
        for layer in layers:
            if layer.root:
                assert layer.exact
                assert layer.allowed == frozenset()


def test_the_neighbourly_table_keeps_cnf_sealed_and_the_corpus_on_top() -> None:
    table = _table(NEIGHBOURLY_LAYERS)
    assert SEALED == {"neighbourly": ("neighbourly.cnf",)}
    assert table["cnf"] == set()
    assert all("corpus12" not in allowed for allowed in table.values())
    for generic in ("maps", "exact", "enumeration", "encoding"):
        assert table[generic] <= {"maps", "cnf"}


def test_the_application_table_has_thin_entry_points() -> None:
    table = _table(CAMPAIGN_LAYERS)
    adapters = {"release", "campaign", "claim", "formulas", "model"}
    assert table["commands"] == adapters | {"pins"}
    assert table["cli"] == table["api"] == adapters | {"commands", "pins"}
    for adapter in adapters:
        assert table[adapter] == {"pins"}  # the release tool hashes, shared constants
    assert table["pins"] == set()


def test_the_independent_tools_are_checked_when_they_exist() -> None:
    assert INDEPENDENT_TOOLS == ("tools/certify_min.py", "tools/spec_vectors")
