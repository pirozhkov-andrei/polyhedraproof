"""``formulas``, ``selftest`` and ``maps``: the published bundles and the corpus controls.

Specification §13.3: export and verify the 59 bundles; the base hashes are the
fixture's. The independent oracle of the hashes is the repository fixture
``data/fixtures/formula_hashes.json``, not the packaged copy the adapter reads.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest
from f12_support import REPO, sha

from cubeproof.base.errors import ConfigurationError, IntegrityError
from cubeproof.cnf.bundle import load_bundle
from faces12_campaign import formulas
from faces12_campaign.formulas import (
    bundle_key,
    check_formulas,
    export_formulas,
    map_of_key,
    parse_maps,
    recompute_formulas,
)
from neighbourly import corpus12
from neighbourly.interpret import map_sha256

REPOSITORY_FIXTURE = REPO / "data" / "fixtures" / "formula_hashes.json"


def repository_fixture() -> dict[int, dict[str, Any]]:
    maps = json.loads(REPOSITORY_FIXTURE.read_text(encoding="utf-8"))["maps"]
    return {int(k): v for k, v in maps.items()}


@pytest.fixture(scope="module")
def exported(tmp_path_factory: pytest.TempPathFactory) -> Path:
    directory = tmp_path_factory.mktemp("formulas") / "formulas"
    export_formulas(directory, [1, 2])
    return directory


def test_keys_and_map_selections() -> None:
    assert bundle_key(1) == "map01" and bundle_key(59) == "map59"
    assert map_of_key("map07") == 7 and map_of_key("map60") is None and map_of_key("m01") is None
    assert parse_maps("all") == tuple(range(1, 60))
    assert parse_maps("3,1,2,10-12,2") == (1, 2, 3, 10, 11, 12)
    for wrong in ("0", "60", "1-60", "x", "2-1", ""):
        with pytest.raises(ConfigurationError):
            parse_maps(wrong)


def test_exported_bundles_are_the_published_formulas(exported: Path) -> None:
    expected = repository_fixture()
    for map_id in (1, 2):
        bundle = exported / bundle_key(map_id)
        assert sorted(p.name for p in bundle.iterdir()) == [
            "formula.cnf", "manifest.json", "names.tsv", "tags.tsv",
        ]  # fmt: skip
        manifest = json.loads((bundle / "manifest.json").read_text(encoding="utf-8"))
        assert sha((bundle / "formula.cnf").read_bytes()) == expected[map_id]["sha256"]
        assert manifest["formula_sha256"] == expected[map_id]["sha256"]
        assert (manifest["variables"], manifest["clauses"]) == (
            expected[map_id]["variables"],
            expected[map_id]["clauses"],
        )
        parameters = manifest["producer"]["parameters"]
        assert parameters == {
            "n": 12,
            "map": {
                "sha256": map_sha256(corpus12.load_map(map_id)),
                "name": f"topology_{map_id:02d}",
            },
            "layers": "S,H,A,B,I",
            "gauge_face": 1,
        }
        assert sorted(manifest["pools"]) == ["brackets", "order"]
        # the cubeproof reader accepts it as it is (strict bundle contract, specification §4.2)
        assert (
            load_bundle(exported, bundle_key(map_id)).manifest.formula_sha256
            == manifest["formula_sha256"]
        )
    report = check_formulas(exported, [1, 2])
    assert [e.status for e in report.entries] == ["verified", "verified"]
    assert report.to_json()["format"] == "faces12-formulas-1"


def test_a_second_export_verifies_and_keeps_the_bundles(exported: Path) -> None:
    before = {p: p.stat().st_mtime_ns for p in exported.rglob("*")}
    report = export_formulas(exported, [1, 2])
    assert [e.status for e in report.entries] == ["present", "present"]
    assert {p: p.stat().st_mtime_ns for p in exported.rglob("*")} == before


def _copy(source: Path, target: Path) -> Path:
    target.mkdir(parents=True)
    for path in source.iterdir():
        (target / path.name).write_bytes(path.read_bytes())
    return target


@pytest.mark.parametrize(
    "damage",
    ["formula byte", "layers", "gauge", "map identity", "pools", "swapped"],
)
def test_check_refuses_a_bundle_that_is_not_the_published_one(
    exported: Path, tmp_path: Path, damage: str
) -> None:
    directory = tmp_path / "formulas"
    one = _copy(exported / "map01", directory / "map01")
    two = _copy(exported / "map02", directory / "map02")
    manifest_path = one / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if damage == "formula byte":
        data = bytearray((one / "formula.cnf").read_bytes())
        data[-3] = ord("1") if data[-3] != ord("1") else ord("2")
        (one / "formula.cnf").write_bytes(bytes(data))
    elif damage == "swapped":
        one.rename(directory / "tmp")
        two.rename(directory / "map01")
        (directory / "tmp").rename(directory / "map02")
    else:
        parameters = manifest["producer"]["parameters"]
        if damage == "layers":
            parameters["layers"] = "S,H,A,B"
        elif damage == "gauge":
            parameters["gauge_face"] = None
        elif damage == "map identity":
            parameters["map"]["sha256"] = map_sha256(corpus12.load_map(2))
        else:
            manifest["pools"]["order"] = manifest["pools"]["order"][1:]
        text = json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        manifest_path.write_text(text + "\n", encoding="utf-8")
    with pytest.raises(IntegrityError) as caught:
        check_formulas(directory, [1, 2])
    assert caught.value.rule == "formulas.bundle"


def test_a_consistent_bundle_with_other_parameters_is_not_published(tmp_path: Path) -> None:
    """Map 1 with other layers or no gauge is a correct bundle of another formula."""
    from neighbourly.cnf import publish_bundle
    from neighbourly.interpret import formula_bundle

    for index, (layers, gauge) in enumerate((("S,H,A,B", 1), ("S,H,A,B,I", None))):
        directory = tmp_path / f"formulas{index}"
        directory.mkdir()
        produced = formula_bundle(corpus12.load_map(1), layers, gauge)
        publish_bundle(directory / "map01", produced.files)
        with pytest.raises(IntegrityError) as caught:
            check_formulas(directory, [1])
        assert caught.value.rule == "formulas.parameters"


def test_check_refuses_extra_and_missing_bundles(exported: Path, tmp_path: Path) -> None:
    directory = tmp_path / "formulas"
    _copy(exported / "map01", directory / "map01")
    with pytest.raises(IntegrityError) as missing:
        check_formulas(directory, [1, 2])
    assert missing.value.rule == "formulas.bundle" and "map02" in missing.value.detail
    _copy(exported / "map02", directory / "map02")
    (directory / "notes").mkdir()
    with pytest.raises(IntegrityError) as caught:
        check_formulas(directory, [1, 2])
    assert caught.value.rule == "formulas.extra"
    assert len(check_formulas(directory, [1, 2], exact=False).entries) == 2
    (directory / "notes").rmdir()
    (directory / ".map03.staging-1-x").mkdir()  # an interrupted publication is not a bundle
    assert len(check_formulas(directory, [1, 2]).entries) == 2


def test_export_never_overwrites_a_different_bundle(exported: Path, tmp_path: Path) -> None:
    directory = tmp_path / "formulas"
    wrong = _copy(exported / "map02", directory / "map01")
    before = {p.name: p.read_bytes() for p in wrong.iterdir()}
    with pytest.raises(IntegrityError):
        export_formulas(directory, [1])
    assert {p.name: p.read_bytes() for p in wrong.iterdir()} == before


def test_export_refuses_a_formula_that_differs_from_the_fixture(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    real = corpus12.formula_hashes()
    forged = dict(real)
    forged[1] = corpus12.BaseFormula(real[1].variables, real[1].clauses, "0" * 64)
    monkeypatch.setattr(corpus12, "formula_hashes", lambda: forged)
    with pytest.raises(IntegrityError) as caught:
        export_formulas(tmp_path / "formulas", [1])
    assert caught.value.rule == "formulas.hash"
    assert list((tmp_path / "formulas").iterdir()) == []


def test_recomputed_formulas_have_the_fixture_hashes() -> None:
    expected = repository_fixture()
    report = recompute_formulas([1, 2, 59])
    assert [(e.map_id, e.formula_sha256) for e in report.entries] == [
        (m, expected[m]["sha256"]) for m in (1, 2, 59)
    ]
    assert report.directory is None


@pytest.mark.slow
def test_all_59_bundles_have_the_published_base_hashes(tmp_path: Path) -> None:
    """The 59 base hashes (specification §3.3), through the application's own export and check. A
    hash equal to the fixture shows the bytes are the published formula, nothing more."""
    expected = repository_fixture()
    assert sorted(expected) == list(range(1, 60))
    directory = tmp_path / "formulas"
    written = export_formulas(directory)
    assert [e.status for e in written.entries] == ["written"] * 59
    checked = check_formulas(directory)
    assert {e.map_id: e.formula_sha256 for e in checked.entries} == {
        m: v["sha256"] for m, v in expected.items()
    }
    assert sorted(os.listdir(directory)) == [f"map{m:02d}" for m in range(1, 60)]


def test_selftest_holds_on_map_1() -> None:
    checks = formulas.selftest([1])
    assert checks and all(c.passed for c in checks), [str(c) for c in checks if not c.passed]
    names = " ".join(c.name for c in checks)
    assert "general position" in names and "base formula" in names and "thm:59" in names


def test_selftest_reports_a_wrong_base_formula(monkeypatch: pytest.MonkeyPatch) -> None:
    real = corpus12.formula_hashes()
    forged = dict(real)
    forged[1] = corpus12.BaseFormula(real[1].variables, real[1].clauses, "0" * 64)
    monkeypatch.setattr(corpus12, "formula_hashes", lambda: forged)
    failed = [c for c in formulas.selftest([1]) if not c.passed]
    assert [c.name for c in failed] == ["map 1: the base formula is the published one"]


def test_census_reports_the_enumeration_document(monkeypatch: pytest.MonkeyPatch) -> None:
    class Result:
        passed = False

    monkeypatch.setattr(corpus12, "enumerate_corpus", Result)
    monkeypatch.setattr(corpus12, "enumeration_document", lambda r: {"format": "x", "r": 1})
    assert formulas.census() == (False, {"format": "x", "r": 1})


def test_selection_errors() -> None:
    with pytest.raises(ConfigurationError):
        recompute_formulas([])
    with pytest.raises(ConfigurationError):
        recompute_formulas([60])
    with pytest.raises(ConfigurationError):
        check_formulas(Path("/nonexistent-directory-of-bundles"), [1])
