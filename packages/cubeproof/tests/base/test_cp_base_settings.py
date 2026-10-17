"""Typed errors, reader limits and the Settings value shared by CLI and API (specification §2.3,
§4.1)."""

from __future__ import annotations

import dataclasses

import pytest

from cubeproof.base.errors import (
    ConfigurationError,
    ContractError,
    CubeproofError,
    InputError,
    IntegrityError,
    ResourceError,
    ToolError,
    contextualize,
)
from cubeproof.base.settings import (
    DEFAULT_LIMITS,
    OPTION_NAMES,
    ReaderLimits,
    Settings,
    ToolPaths,
)

MIB = 1024 * 1024


def test_error_kinds_and_hierarchy() -> None:
    kinds = {
        ConfigurationError: "configuration",
        ToolError: "tool",
        ResourceError: "resource",
        ContractError: "reject",
        InputError: "input",
        IntegrityError: "integrity",
    }
    for cls, kind in kinds.items():
        error = cls("some.rule", "detail", location="$.a")
        assert isinstance(error, CubeproofError)
        assert error.kind == kind
        assert error.rule == "some.rule"
        assert error.detail == "detail"
        assert error.location == "$.a"
        assert "some.rule" in str(error)
    assert issubclass(InputError, ContractError)
    assert issubclass(IntegrityError, ContractError)
    assert not issubclass(ResourceError, ContractError)
    assert CubeproofError("x").location is None


def test_contextualize_keeps_rule_detail_and_location() -> None:
    error = ContractError("cube.range", "literal 4", location="$.roots[0].cube[0]")
    as_input = contextualize(error, InputError)
    assert type(as_input) is InputError
    assert (as_input.rule, as_input.detail, as_input.location) == (
        "cube.range",
        "literal 4",
        "$.roots[0].cube[0]",
    )
    assert as_input.__cause__ is error
    as_integrity = contextualize(error, IntegrityError)
    assert type(as_integrity) is IntegrityError


def test_contextualize_never_turns_a_resource_limit_into_evidence_errors() -> None:
    limit = ResourceError("limit.depth")
    assert contextualize(limit, InputError) is limit
    assert contextualize(limit, IntegrityError) is limit


def test_contextualize_leaves_an_already_classified_error_alone() -> None:
    error = IntegrityError("journal.self")
    assert contextualize(error, InputError) is error


def test_default_reader_limits_are_the_specified_ones() -> None:
    assert ReaderLimits() == DEFAULT_LIMITS
    assert DEFAULT_LIMITS.line_bytes == 8 * MIB
    assert DEFAULT_LIMITS.document_bytes == 64 * MIB
    assert DEFAULT_LIMITS.depth == 32
    assert DEFAULT_LIMITS.tail_bytes == 16 * 1024


@pytest.mark.parametrize("field", ["line_bytes", "document_bytes", "depth", "tail_bytes"])
@pytest.mark.parametrize("value", [0, -1, True, 1.5, "8"])
def test_reader_limits_must_be_positive_integers(field: str, value: object) -> None:
    with pytest.raises(ConfigurationError):
        ReaderLimits(**{field: value})  # type: ignore[arg-type]


def test_values_are_immutable() -> None:
    settings = Settings()
    with pytest.raises(dataclasses.FrozenInstanceError):
        settings.limits = ReaderLimits(depth=3)  # type: ignore[misc]
    with pytest.raises(dataclasses.FrozenInstanceError):
        DEFAULT_LIMITS.depth = 3  # type: ignore[misc]


def test_tool_paths_are_absolute_local_paths() -> None:
    tools = ToolPaths(solver="/opt/bin/cadical", checker="/opt/bin/cake_lpr")
    assert tools.helper is None
    for bad in ("cadical", "./cadical", "", "/opt/\0bin", "C:\\tools\\cadical.exe"):
        with pytest.raises(ConfigurationError):
            ToolPaths(solver=bad)
    with pytest.raises(ConfigurationError):
        ToolPaths(checker=1)  # type: ignore[arg-type]


def test_settings_from_options() -> None:
    settings = Settings.from_options(
        {
            "reader_line_bytes": "1024",
            "reader_document_bytes": "2048",
            "reader_depth": "40",
            "reader_tail_bytes": "100",
            "solver": "/opt/bin/cadical",
            "checker": "/opt/bin/cake_lpr",
            "helper": "/opt/bin/cubeproof-look",
        }
    )
    assert settings.limits == ReaderLimits(
        line_bytes=1024, document_bytes=2048, depth=40, tail_bytes=100
    )
    assert settings.tools == ToolPaths(
        solver="/opt/bin/cadical", checker="/opt/bin/cake_lpr", helper="/opt/bin/cubeproof-look"
    )
    assert set(OPTION_NAMES) == {
        "reader_line_bytes",
        "reader_document_bytes",
        "reader_depth",
        "reader_tail_bytes",
        "solver",
        "checker",
        "helper",
    }


def test_settings_defaults_from_no_options() -> None:
    assert Settings.from_options({}) == Settings()
    assert Settings().limits == DEFAULT_LIMITS
    assert Settings().tools == ToolPaths()


@pytest.mark.parametrize("text", ["0", "-1", "+5", "08", "1.5", "", " 5", "5 ", "1e3", "٣"])
def test_settings_integers_are_canonical_positive_decimals(text: str) -> None:
    with pytest.raises(ConfigurationError) as info:
        Settings.from_options({"reader_depth": text})
    assert info.value.rule == "settings.reader_depth"


def test_settings_refuse_unknown_options() -> None:
    with pytest.raises(ConfigurationError) as info:
        Settings.from_options({"reader_depht": "3"})
    assert info.value.rule == "settings.unknown"


def test_settings_refuse_relative_tool_paths() -> None:
    with pytest.raises(ConfigurationError) as info:
        Settings.from_options({"checker": "cake_lpr"})
    assert info.value.rule == "settings.checker"


def test_settings_do_not_read_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in OPTION_NAMES:
        monkeypatch.setenv(name, "/x")
        monkeypatch.setenv(name.upper(), "/x")
        monkeypatch.setenv("CUBEPROOF_" + name.upper(), "/x")
    assert Settings.from_options({}) == Settings()
