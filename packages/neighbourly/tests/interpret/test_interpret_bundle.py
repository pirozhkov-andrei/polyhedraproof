"""neighbourly.interpret, producer side and verification: bundles, pools, names, tags.

Specification §4.2 and §13.2: producer parameters carry `n`, the map identity, the
layers and the gauge; pools are the order and bracket bits; ``names.tsv`` and ``tags.tsv``
are display exports. Interpretation validates the formula identity by rebuilding it from a
map the caller trusts, and never reads the side files.
"""

from __future__ import annotations

import hashlib
import json
import shutil
from functools import cache
from pathlib import Path
from typing import Any

import pytest

from neighbourly import __version__, corpus12
from neighbourly.cnf import canonical_json, publish_bundle
from neighbourly.data import read_bytes
from neighbourly.encoding import build_encoder
from neighbourly.interpret import (
    BUNDLE_FORMAT,
    PRODUCER_NAME,
    FormulaSpec,
    InterpretError,
    Meaning,
    VariableMap,
    formula_bundle,
    map_sha256,
    read_bundle,
    tag_ranges,
    verify_bundle,
)
from neighbourly.maps import CombinatorialMap

TESTS = Path(__file__).resolve().parents[1]
GOLDENS = TESTS / "cnf" / "goldens_n12.json"


def J(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@cache
def goldens() -> dict[str, Any]:
    data: dict[str, Any] = json.loads(GOLDENS.read_text(encoding="utf-8"))
    assert data["format"] == "neighbourly-goldens-n12-1"
    return data


@cache
def map1_bundle() -> Any:
    return formula_bundle(corpus12.load_map(1), map_name="topology_01")


def csaszar() -> CombinatorialMap:
    text = read_bytes("fixtures", "szilassi", "csaszar_n7.txt").decode("utf-8")
    return CombinatorialMap.from_text(text, "csaszar_n7.txt")


def plain(manifest: Any) -> dict[str, Any]:
    """A manifest as plain, mutable JSON data."""
    copy: dict[str, Any] = json.loads(json.dumps(dict(manifest)))
    return copy


def manifest_copy() -> dict[str, Any]:
    return plain(map1_bundle().files.manifest)


# -- map identity -----------------------------------------------------------------------------


def test_the_map_identity_is_the_hash_of_the_sorted_vertices() -> None:
    cmap = corpus12.load_map(1)
    document = {
        "format": "neighbourly-map-1",
        "n": 12,
        "vertices": [list(t) for t in sorted(cmap.triples)],
    }
    assert map_sha256(cmap) == sha(J(document))
    assert map_sha256(cmap) != map_sha256(corpus12.load_map(2))


def test_relabelling_the_faces_changes_the_map_identity() -> None:
    cmap = csaszar()
    swap = {1: 2, 2: 1}
    relabelled = CombinatorialMap(
        7, [tuple(swap.get(x, x) for x in triple) for triple in cmap.triples]
    )
    assert map_sha256(relabelled) != map_sha256(cmap)


# -- producer metadata ------------------------------------------------------------------------


def test_the_producer_records_n_map_layers_and_gauge() -> None:
    manifest = map1_bundle().files.manifest
    assert manifest["format"] == BUNDLE_FORMAT
    assert manifest["producer"] == {
        "name": PRODUCER_NAME,
        "version": __version__,
        "parameters": {
            "n": 12,
            "map": {"sha256": map_sha256(corpus12.load_map(1)), "name": "topology_01"},
            "layers": "S,H,A,B,I",
            "gauge_face": 1,
        },
    }


def test_the_bundle_formula_is_the_base_formula_of_the_fixture() -> None:
    files = map1_bundle().files
    expected = corpus12.formula_hashes()[1]
    assert files.formula_sha256 == expected.sha256 == sha(files.files["formula.cnf"])
    assert (files.manifest["variables"], files.manifest["clauses"]) == (
        expected.variables,
        expected.clauses,
    )


def test_the_pools_are_the_golden_pools() -> None:
    pools = map1_bundle().files.manifest["pools"]
    assert sorted(pools) == ["brackets", "order"]
    for name, facts in goldens()["pools"]["1"].items():
        values = pools[name]
        assert (len(values), values[0], values[-1]) == (facts["count"], facts["min"], facts["max"])
        assert sha(J(values)) == facts["sha256"], name


def test_the_bundle_is_deterministic() -> None:
    again = formula_bundle(corpus12.load_map(1), map_name="topology_01").files
    assert dict(again.files) == dict(map1_bundle().files.files)


def test_layers_are_canonicalized_and_the_gauge_may_be_absent() -> None:
    produced = formula_bundle(csaszar(), "i, a", None, side_files=False)
    parameters = plain(produced.files.manifest)["producer"]["parameters"]
    assert parameters["layers"] == "S,H,A,B,I"
    assert parameters["gauge_face"] is None
    assert parameters["map"]["name"] is None
    assert produced.files.manifest["side_files"] == []
    assert set(produced.files.files) == {"formula.cnf", "manifest.json"}


@pytest.mark.parametrize("bad", [7, b"x"])
def test_a_map_name_must_be_a_string(bad: Any) -> None:
    with pytest.raises(InterpretError):
        formula_bundle(csaszar(), map_name=bad)


# -- names and tags ---------------------------------------------------------------------------


def parse_tsv(raw: bytes, fields: int) -> list[list[Any]]:
    rows = []
    for line in raw.decode("utf-8").split("\n")[:-1]:
        parts = line.split("\t")
        assert len(parts) == fields
        rows.append([*map(int, parts[:-1]), json.loads(parts[-1])])
    return rows


def test_names_cover_exactly_the_meaningful_variables() -> None:
    produced = map1_bundle()
    rows = parse_tsv(produced.files.files["names.tsv"], 2)
    names = dict(rows)
    vmap = produced.variable_map
    assert names == vmap.names()
    kinds: dict[str, int] = {}
    for meaning in vmap.meanings.values():
        kinds[meaning.kind] = kinds.get(meaning.kind, 0) + 1
    n = 12
    assert kinds == {
        "bracket": 715,
        "order": 66 * 45,
        "cut": 12 * 45,
        "onb": 66 * (n - 4),
        "turn": n * (n - 1),
        "orientation": n,
    }
    assert names[1] == "X(0,1,2,3)"
    assert names[vmap.line_orders[(1, 2)][(3, 4)]] == "o(1,2;3,4)"
    assert names[vmap.cut_orders[(1, 2)][(3, 4)]] == "d(1|2;3,4)"
    assert names[vmap.boundary_bits[(1, 2, 3)]] == "OnB(1,2;3)"
    assert names[vmap.orientation_bits[1]] == "s(1)"


def test_the_tags_file_reproduces_the_golden_clause_tags() -> None:
    produced = map1_bundle()
    rows = parse_tsv(produced.files.files["tags.tsv"], 3)
    clauses = produced.files.manifest["clauses"]
    per_clause: list[list[str] | None] = [None] * clauses
    previous_last = 0
    for first, last, text in rows:
        assert first == previous_last + 1, "ranges are consecutive and do not overlap"
        layer, _, tag = text.partition("/")
        for number in range(first, last + 1):
            per_clause[number - 1] = [layer, tag]
        previous_last = last
    assert previous_last == clauses
    expected = goldens()["map1_tags"]
    assert sha(J(per_clause)) == expected["tags_sha256"]
    assert len({tuple(t) for t in per_clause if t}) == expected["distinct_tags"]


def test_tag_ranges_join_runs_of_equal_tags() -> None:
    tags = [("S", "a"), ("S", "a"), ("S", "b"), ("I", "b"), ("I", "b")]
    assert tag_ranges(tags) == [(1, 2, "S/a"), (3, 3, "S/b"), (4, 5, "I/b")]
    with pytest.raises(InterpretError, match="contains '/'"):
        tag_ranges([("x/y", "t")])


# -- verification -----------------------------------------------------------------------------


def test_verification_rebuilds_the_same_variable_map() -> None:
    produced = map1_bundle()
    verified = verify_bundle(
        produced.files.manifest, corpus12.load_map(1), produced.files.files["formula.cnf"]
    )
    assert verified.formula_sha256 == produced.files.formula_sha256
    assert verified.variable_map == produced.variable_map
    assert verified.spec == FormulaSpec.of(corpus12.load_map(1), map_name="topology_01")
    assert len(verified.clauses) == len(verified.tags) == produced.files.manifest["clauses"]


def test_the_variable_map_is_the_encoders_and_read_only() -> None:
    cmap = csaszar()
    encoder = build_encoder(cmap)
    vmap = VariableMap.from_encoder(encoder, FormulaSpec.of(cmap))
    assert dict(vmap.brackets) == dict(encoder.brackets)
    assert dict(vmap.corner_literals) == dict(encoder.corner_bits)
    corner = next(iter(encoder.corner_bits.items()))
    assert vmap.meaning(-corner[1]) == Meaning("turn", corner[0])
    auxiliaries = [v for v in range(1, vmap.variables + 1) if vmap.meaning(v) is None]
    assert auxiliaries and len(auxiliaries) + len(vmap.meanings) == vmap.variables
    with pytest.raises(TypeError):
        vmap.brackets[(0, 1, 2, 3)] = 5  # type: ignore[index]
    with pytest.raises(InterpretError):
        vmap.meaning(vmap.variables + 1)


def test_an_unbuilt_encoder_has_no_variable_map() -> None:
    from neighbourly.encoding import Encoder

    with pytest.raises(InterpretError, match="not been built"):
        VariableMap.from_encoder(Encoder(csaszar()), FormulaSpec.of(csaszar()))


def tamper(change: Any) -> dict[str, Any]:
    manifest = manifest_copy()
    change(manifest)
    return manifest


def _set(path: list[str], value: Any) -> Any:
    def change(manifest: dict[str, Any]) -> None:
        node = manifest
        for key in path[:-1]:
            node = node[key]
        node[path[-1]] = value

    return change


TAMPERED = {
    "format": (_set(["format"], "cubeproof-bundle-2"), "manifest"),
    "producer": (_set(["producer", "name"], "faces12"), "not produced by"),
    "version": (_set(["producer", "version"], 2), "version"),
    "extra parameter": (_set(["producer", "parameters", "seed"], 1), "exactly the keys"),
    "n": (_set(["producer", "parameters", "n"], 13), "n = 13"),
    "n bool": (_set(["producer", "parameters", "n"], True), "integer"),
    "map hash": (_set(["producer", "parameters", "map", "sha256"], "0" * 64), "map sha256"),
    "map hash case": (_set(["producer", "parameters", "map", "sha256"], "A" * 64), "lowercase"),
    "layers": (_set(["producer", "parameters", "layers"], "S,H,A"), "formula_sha256"),
    "layers spelling": (_set(["producer", "parameters", "layers"], "SHABI"), "not canonical"),
    "gauge": (_set(["producer", "parameters", "gauge_face"], 2), "formula_sha256"),
    "no gauge": (_set(["producer", "parameters", "gauge_face"], None), "formula_sha256"),
    "gauge range": (_set(["producer", "parameters", "gauge_face"], 13), "gauge face"),
    "formula hash": (_set(["formula_sha256"], "0" * 64), "formula_sha256"),
    "variables": (_set(["variables"], 5258), "variables or clauses"),
    "clauses": (_set(["clauses"], 52176), "variables or clauses"),
    "pools": (_set(["pools", "order"], [716]), "pools"),
    "extra pool": (_set(["pools", "aux"], [1]), "pools"),
}


@pytest.mark.parametrize("case", sorted(TAMPERED))
def test_a_tampered_manifest_is_refused(case: str) -> None:
    change, message = TAMPERED[case]
    with pytest.raises(InterpretError, match=message):
        verify_bundle(tamper(change), corpus12.load_map(1))


def test_the_formula_bytes_must_match_the_manifest() -> None:
    formula = bytearray(map1_bundle().files.files["formula.cnf"])
    formula[-3:-2] = b"9" if formula[-3:-2] != b"9" else b"8"
    with pytest.raises(InterpretError, match=r"formula\.cnf"):
        verify_bundle(manifest_copy(), corpus12.load_map(1), bytes(formula))


def test_another_map_is_refused_even_with_the_same_n() -> None:
    with pytest.raises(InterpretError, match="not the map of this bundle"):
        verify_bundle(manifest_copy(), corpus12.load_map(2))
    with pytest.raises(InterpretError, match="n = 12"):
        verify_bundle(manifest_copy(), csaszar())
    with pytest.raises(InterpretError, match="CombinatorialMap"):
        verify_bundle(manifest_copy(), "topology_01")  # type: ignore[arg-type]


def test_a_map_identity_collision_is_still_caught_by_the_rebuild(monkeypatch: Any) -> None:
    """Defence in depth: even if two maps shared an identity, the rebuilt hash differs."""
    from neighbourly import interpret

    monkeypatch.setattr(interpret, "map_sha256", lambda cmap: map_sha256(corpus12.load_map(1)))
    with pytest.raises(InterpretError, match="formula_sha256"):
        verify_bundle(manifest_copy(), corpus12.load_map(2))


# -- bundle directories -----------------------------------------------------------------------


def test_a_published_bundle_reads_back_and_ignores_the_display_names(tmp_path: Path) -> None:
    produced = map1_bundle()
    target = publish_bundle(tmp_path / "map1", produced.files)
    verified = read_bundle(target, corpus12.load_map(1))
    assert verified.variable_map == produced.variable_map
    (target / "names.tsv").write_bytes(b'1\t"o(9,9;9,9)"\n')
    (target / "tags.tsv").unlink()
    assert read_bundle(target, corpus12.load_map(1)).variable_map == produced.variable_map


def test_a_damaged_bundle_directory_is_refused(tmp_path: Path) -> None:
    target = publish_bundle(tmp_path / "map1", map1_bundle().files)
    broken = tmp_path / "broken"
    shutil.copytree(target, broken)
    manifest = json.loads((broken / "manifest.json").read_bytes())
    (broken / "manifest.json").write_text(json.dumps(manifest, indent=1) + "\n")
    with pytest.raises(InterpretError, match="canonical"):
        read_bundle(broken, corpus12.load_map(1))
    (broken / "manifest.json").write_bytes(canonical_json(manifest) + b"\n")
    with open(broken / "formula.cnf", "ab") as handle:
        handle.write(b"1 0\n")
    with pytest.raises(InterpretError, match=r"formula\.cnf"):
        read_bundle(broken, corpus12.load_map(1))
    (broken / "formula.cnf").unlink()
    with pytest.raises(InterpretError):
        read_bundle(broken, corpus12.load_map(1))
    (broken / "manifest.json").write_bytes(b"not json")
    with pytest.raises(InterpretError):
        read_bundle(broken, corpus12.load_map(1))
