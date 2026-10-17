"""The fixture files match their manifest; the SAT model fixtures parse as declared."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from fakes import fixture_files
from fakes.cnf_model import ModelError, literals_of, parse_dimacs, parse_model
from fakes.lrat_check import check

NAMES = [item["file"] for item in fixture_files.manifest()]


def test_every_data_file_is_in_the_manifest() -> None:
    present = sorted(p.name for p in fixture_files.DATA.iterdir() if p.name != "fixtures.json")
    assert present == sorted(NAMES)
    assert len(set(NAMES)) == len(NAMES)


@pytest.mark.parametrize("name", NAMES)
def test_fixture_hashes(name: str) -> None:
    path = fixture_files.fixture(name)
    assert hashlib.sha256(path.read_bytes()).hexdigest() == fixture_files.entry(name)["sha256"]


def test_a_changed_fixture_is_detected(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    for item in fixture_files.DATA.iterdir():
        (tmp_path / item.name).write_bytes(item.read_bytes())
    (tmp_path / "sat.cnf").write_bytes(b"p cnf 1 1\n1 0\n")
    monkeypatch.setattr(fixture_files, "DATA", tmp_path)
    with pytest.raises(ValueError, match="does not match"):
        fixture_files.fixture("sat.cnf")
    with pytest.raises(KeyError):
        fixture_files.entry("absent")
    (tmp_path / "fixtures.json").write_text('{"format": "other"}', encoding="utf-8")
    with pytest.raises(ValueError, match="manifest"):
        fixture_files.manifest()


@pytest.mark.parametrize("item", fixture_files.of_kind("model"), ids=lambda i: i["file"])
def test_the_sat_model_fixtures_parse_as_declared(item: dict[str, object]) -> None:
    cnf = parse_dimacs(fixture_files.fixture(str(item["cnf"])).read_bytes())
    output = fixture_files.fixture(str(item["file"])).read_bytes()
    if item["model_error"] is None:
        assert list(literals_of(parse_model(output, cnf))) == item["literals"]
    else:
        with pytest.raises(ModelError) as caught:
            parse_model(output, cnf)
        assert caught.value.kind == item["model_error"]


@pytest.mark.parametrize("item", fixture_files.of_kind("proof"), ids=lambda i: i["file"])
def test_the_proof_fixtures_are_valid_as_declared(item: dict[str, object]) -> None:
    cnf = parse_dimacs(fixture_files.fixture(str(item["cnf"])).read_bytes())
    proof = fixture_files.fixture(str(item["file"])).read_bytes()
    assert check(cnf, proof).verified is item["valid"]


def test_the_cnf_fixtures_parse() -> None:
    for item in fixture_files.of_kind("cnf"):
        cnf = parse_dimacs(fixture_files.fixture(item["file"]).read_bytes())
        assert cnf.clauses
