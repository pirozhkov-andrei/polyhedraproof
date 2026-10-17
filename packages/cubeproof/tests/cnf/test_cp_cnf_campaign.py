"""Campaign loading: document, bundles and every campaign rule of specification §4.4 (the cases
of the contract corpus)."""

from __future__ import annotations

import hashlib
import shutil
import sys
from pathlib import Path
from typing import Any

import pytest

from cubeproof.base.canonical_json import document_bytes, parse_document
from cubeproof.base.errors import InputError, ResourceError
from cubeproof.base.settings import ReaderLimits
from cubeproof.cnf.campaign import load_campaign

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "contracts"))
import cp_corpus

CAMPAIGN_RULE_PREFIXES = (
    "json.",
    "schema",
    "utc.",
    "campaign.",
    "bundle.",
    "dimacs.",
    "cube.",
    "split.",
    "policy.",
    "path.",
)


def _campaign_error_cases() -> list[dict[str, Any]]:
    """Cases whose expected error lies in the campaign or its bundles (no journal needed)."""
    found = []
    for case in cp_corpus.cases():
        error = case["expect"].get("error")
        campaign_rule = (
            error and error["kind"] == "input" and error["rule"].startswith(CAMPAIGN_RULE_PREFIXES)
        )
        if campaign_rule and not case["journals"]:
            found.append(case)
    return found


def _valid_campaign_cases() -> list[dict[str, Any]]:
    return [c for c in cp_corpus.cases() if "certificate" in c["expect"]]


def test_every_campaign_rule_has_a_case() -> None:
    rules = {c["expect"]["error"]["rule"] for c in _campaign_error_cases()}
    assert len(rules) >= 30
    assert {"bundle.files", "bundle.campaign_hash", "campaign.tools_admitted"} <= rules


@pytest.mark.parametrize("case", _campaign_error_cases(), ids=lambda c: c["id"])
def test_campaign_error_cases(case: dict[str, Any]) -> None:
    with pytest.raises(InputError) as info:
        load_campaign(cp_corpus.CORPUS / case["campaign"])
    assert info.value.kind == "input"
    assert info.value.rule == case["expect"]["error"]["rule"]


@pytest.mark.parametrize("case", _valid_campaign_cases(), ids=lambda c: c["id"])
def test_valid_campaigns_load_with_the_certified_id(case: dict[str, Any]) -> None:
    path = cp_corpus.CORPUS / case["campaign"]
    loaded = load_campaign(path)
    certificate = cp_corpus.load_json(case["expect"]["certificate"])
    assert loaded.campaign.campaign_id == certificate["campaign"]
    assert loaded.campaign.campaign_id == hashlib.sha256(path.read_bytes()[:-1]).hexdigest()
    assert document_bytes(loaded.campaign.to_json()) == path.read_bytes()
    assert set(loaded.bundles) == {f.formula_sha256 for f in loaded.campaign.formulas}
    for entry in loaded.campaign.formulas:
        bundle = loaded.bundles[entry.formula_sha256]
        assert bundle.formula.sha256 == entry.formula_sha256
        assert loaded.formula(entry.formula_sha256) is bundle.formula
    assert loaded.key(loaded.campaign.formulas[0].formula_sha256) == loaded.campaign.formulas[0].key


def _copy_campaign(tmp_path: Path, name: str = "all3") -> Path:
    shutil.copytree(cp_corpus.CORPUS / "campaigns" / name, tmp_path / name)
    return tmp_path / name / "campaign.json"


def test_bundle_directory_symlink_is_refused(tmp_path: Path) -> None:
    path = _copy_campaign(tmp_path)
    bundles = path.parent / "bundles"
    (path.parent / "real").mkdir()
    shutil.move(str(bundles / "all3"), str(path.parent / "real" / "all3"))
    (bundles / "all3").symlink_to(path.parent / "real" / "all3")
    with pytest.raises(InputError) as info:
        load_campaign(path)
    assert info.value.rule == "path.containment"


def test_campaign_size_limit_is_a_resource_error(tmp_path: Path) -> None:
    path = _copy_campaign(tmp_path)
    size = len(path.read_bytes()) - 1
    assert load_campaign(path, limits=ReaderLimits(document_bytes=size)).campaign
    with pytest.raises(ResourceError) as info:
        load_campaign(path, limits=ReaderLimits(document_bytes=size - 1))
    assert info.value.rule == "limit.document"


def test_reader_limits_apply_to_the_bundles_of_the_campaign(tmp_path: Path) -> None:
    # The manifest is made larger than the campaign document; a limit that admits the
    # campaign but not the manifest must refuse the manifest (limits reach load_bundle).
    path = _copy_campaign(tmp_path)
    manifest_path = path.parent / "bundles" / "all3" / "manifest.json"
    manifest = parse_document(manifest_path.read_bytes())
    manifest["producer"]["parameters"] = {"padding": "x" * 4000}
    manifest_path.write_bytes(document_bytes(manifest))
    campaign_size = len(path.read_bytes()) - 1
    assert len(manifest_path.read_bytes()) - 1 > campaign_size
    assert load_campaign(path).campaign
    with pytest.raises(ResourceError) as info:
        load_campaign(path, limits=ReaderLimits(document_bytes=campaign_size))
    assert info.value.rule == "limit.document"


def test_campaign_reading_of_a_large_file_stops_after_limit_plus_two(tmp_path: Path) -> None:
    # The size seen by the reader is the bounded read (limit + 2 bytes), not the size of the
    # whole file. Runs before the /dev/zero test so an unbounded reader fails here first.
    path = tmp_path / "campaign.json"
    path.write_bytes(b" " * 3_000_000)
    with pytest.raises(ResourceError) as info:
        load_campaign(path, limits=ReaderLimits(document_bytes=1000))
    assert info.value.rule == "limit.document"
    assert info.value.detail.startswith("1002 bytes,")


@pytest.mark.skipif(not Path("/dev/zero").exists(), reason="needs an endless file (/dev/zero)")
def test_campaign_reading_stops_at_the_document_limit() -> None:
    # An endless input is refused by its size after limit + 2 bytes, not read to the end.
    with pytest.raises(ResourceError) as info:
        load_campaign(Path("/dev/zero"), limits=ReaderLimits(document_bytes=1000))
    assert info.value.rule == "limit.document"


def test_campaign_depth_limit_is_a_resource_error(tmp_path: Path) -> None:
    path = _copy_campaign(tmp_path)
    with pytest.raises(ResourceError) as info:
        load_campaign(path, limits=ReaderLimits(depth=3))
    assert info.value.rule == "limit.depth"


def test_missing_campaign_file_is_an_input_error(tmp_path: Path) -> None:
    with pytest.raises(InputError) as info:
        load_campaign(tmp_path / "absent.json")
    assert info.value.rule == "campaign.file"
