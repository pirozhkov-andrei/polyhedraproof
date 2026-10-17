"""Bundle writing and publication against the contract bundle vectors (specification §4.1, §4.2)."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pytest
from cnf_corpus import CAMPAIGNS, bundle_dir, document_bytes, documents, reader

import neighbourly.cnf.bundle as bundle_module
from neighbourly.cnf import (
    BundleFiles,
    CnfError,
    Producer,
    bundle_files,
    canonical_json,
    names_tsv,
    publish_bundle,
    tags_tsv,
)

ALL3 = [
    [1, 2, 3],
    [-1, 2, 3],
    [1, -2, 3],
    [-1, -2, 3],
    [1, 2, -3],
    [-1, 2, -3],
    [1, -2, -3],
    [-1, -2, -3],
]
SAT3 = [[1, 2], [-1, 3], [-2, -3]]
SAT3_NAMES = {3: 'x3 "third"', 1: "x1", 2: "x2"}
SAT3_TAGS = [(2, 2, "middle"), (1, 3, "all")]
E_ACUTE = chr(0xE9)
LINE_SEPARATOR = chr(0x2028)  # not escaped by J, legal inside a TSV field


def producer(formula: str) -> Producer:
    return Producer("spec-vectors", "1", {"formula": formula})


def vector(variables: int, clauses: Any, formula: str, **extra: Any) -> dict[str, Any]:
    arguments = {"variables": variables, "clauses": clauses, "pools": {}}
    return arguments | {"producer": producer(formula)} | extra


#: (campaign, bundle directory) -> the arguments that reproduce it.
VECTORS: dict[tuple[str, str], dict[str, Any]] = {
    ("mixed", "sat3"): vector(3, SAT3, "sat3", names=SAT3_NAMES, tags=SAT3_TAGS),
    ("mixed", "all3"): vector(3, ALL3, "all3"),
    ("all3", "all3"): vector(3, ALL3, "all3", pools={"none": [], "all": {3, 1, 2}}),
    ("pilot", "sat"): vector(1, [[1]], "F_sat"),
    ("unsat", "unsat"): vector(1, [[1], [-1]], "F_unsat"),
    ("zero", "clause"): vector(0, [[]], "F_clause"),
    ("zero", "empty"): vector(0, [], "F_empty"),
}


def make(arguments: dict[str, Any]) -> BundleFiles:
    args = dict(arguments)
    return bundle_files(args.pop("variables"), args.pop("clauses"), **args)


def stored_files(directory: Path) -> dict[str, bytes]:
    return {path.name: path.read_bytes() for path in sorted(directory.iterdir())}


@pytest.mark.parametrize("key", sorted(VECTORS), ids="/".join)
def test_the_files_equal_the_corpus_bundle_byte_for_byte(key: tuple[str, str]) -> None:
    files = make(VECTORS[key])
    assert dict(files.files) == stored_files(bundle_dir(*key))
    order = list(files.files)
    assert order[0] == "formula.cnf" and order[-1] == "manifest.json"


def test_every_corpus_bundle_is_reproduced() -> None:
    stored = {(p.parents[1].name, p.name) for p in CAMPAIGNS.glob("*/bundles/*") if p.is_dir()}
    good = {key for key in stored if key[0] != "bad"}
    assert good == set(VECTORS)


@pytest.mark.parametrize("key", sorted(VECTORS), ids="/".join)
def test_the_independent_reader_accepts_the_published_bundle(
    key: tuple[str, str], tmp_path: Path
) -> None:
    files = make(VECTORS[key])
    target = publish_bundle(tmp_path / "bundle", files)
    contract = reader()
    store = contract.open_store()
    manifest_bytes = (target / "manifest.json").read_bytes()
    formula = (target / "formula.cnf").read_bytes()
    manifest = contract.parse_document(manifest_bytes)
    assert store.errors(manifest, "bundle-manifest.schema.json") == []
    assert contract.manifest_problems(manifest, formula) == []
    variables, clauses = manifest["variables"], manifest["clauses"]
    for artifact in manifest["side_files"]:
        data = (target / artifact["path"]).read_bytes()
        context = {"artifact": artifact, "variables": variables, "clauses": clauses}
        kind = "names-tsv" if artifact["path"] == "names.tsv" else "tags-tsv"
        assert contract.validate_document(store, kind, data, context) == []
    assert files.manifest_sha256 == contract.sha256_hex(manifest_bytes[:-1])
    assert files.formula_sha256 == contract.parse_dimacs(formula).sha256


def test_the_manifest_document_vectors() -> None:
    all3 = make(VECTORS[("all3", "all3")] | {"names": SAT3_NAMES, "tags": SAT3_TAGS})
    assert all3.files["manifest.json"] == document_bytes("manifest-valid")
    empty = make(VECTORS[("zero", "empty")])
    assert empty.files["manifest.json"] == document_bytes("manifest-without-formula")


def test_the_side_file_document_vectors() -> None:
    assert names_tsv(SAT3_NAMES, 3) == document_bytes("names-valid")
    assert names_tsv({}, 3) == document_bytes("names-empty") == b""
    assert names_tsv({1: E_ACUTE}, 3) == document_bytes("names-raw-unicode")
    tags = [(2, 3, "a"), (1, 8, "b"), (1, 8, "all")]
    assert tags_tsv(tags, 8) == document_bytes("tags-valid")
    assert tags_tsv(SAT3_TAGS, 3) == document_bytes("tags-corpus")
    contract, store = reader(), reader().open_store()
    weird = {1: "tab\there", 2: "line\nbreak", 3: LINE_SEPARATOR + " and \\"}
    data = names_tsv(weird, 3)
    assert contract.validate_document(store, "names-tsv", data, {"variables": 3}) == []
    assert documents()["names-escaped-unicode"]["expect"] == {"rule": "names.syntax"}


def test_names_are_sorted_by_numeric_id_not_by_its_decimal_text() -> None:
    """Specification §4.2: names.tsv is sorted by numeric ID; as text, 10 and 100 would precede
    9."""
    names = {100: "c", 10: "a", 9: "b", 1000: "d", 2: "e"}
    data = names_tsv(names, 1000)
    assert data == b'2\t"e"\n9\t"b"\n10\t"a"\n100\t"c"\n1000\t"d"\n'
    contract, store = reader(), reader().open_store()
    assert contract.validate_document(store, "names-tsv", data, {"variables": 1000}) == []
    files = bundle_files(1000, [[9, -10, 100]], pools={}, producer=producer("x"), names=names)
    assert files.files["names.tsv"] == data


def test_tag_ranges_sort_by_the_label_not_by_its_json_text() -> None:
    """Specification §4.2 sorts by (first, last, tag); the JSON escaping must not reorder.

    A line feed sorts before a space as a string, but its JSON text starts with a backslash,
    which sorts after a space.
    """
    data = tags_tsv([(1, 1, " "), (1, 1, "\n"), (1, 1, "A")], 1)
    assert data == b'1\t1\t"\\n"\n1\t1\t" "\n1\t1\t"A"\n'
    contract, store = reader(), reader().open_store()
    assert contract.validate_document(store, "tags-tsv", data, {"clauses": 1}) == []


@pytest.mark.parametrize(
    ("names", "tags"),
    [
        ({0: "a"}, None),
        ({4: "a"}, None),
        ({True: "a"}, None),
        ({1: 5}, None),
        ({1: "\ud800"}, None),
        (None, [(0, 1, "x")]),
        (None, [(1, 9, "x")]),
        (None, [(3, 2, "x")]),
        (None, [(1, 2, "x"), (1, 2, "x")]),
        (None, [(1, 2, 3)]),
    ],
)
def test_bad_side_files_are_refused(names: Any, tags: Any) -> None:
    with pytest.raises(CnfError):
        bundle_files(3, ALL3, pools={}, producer=producer("x"), names=names, tags=tags)


@pytest.mark.parametrize(
    "pools",
    [
        {"Bad": [1]},
        {"": [1]},
        {"a" * 65: [1]},
        {"ok": [0]},
        {"ok": [4]},
        {"ok": [1, 1]},
        {"ok": [True]},
        {1: [1]},
    ],
)
def test_bad_pools_are_refused(pools: Any) -> None:
    with pytest.raises(CnfError):
        bundle_files(3, ALL3, pools=pools, producer=producer("x"))


def test_pools_are_sorted_and_names_may_use_the_full_name_alphabet() -> None:
    files = bundle_files(3, ALL3, pools={"a_b-9": [3, 1], "z" * 64: (2,)}, producer=producer("x"))
    assert files.manifest["pools"] == {"a_b-9": [1, 3], "z" * 64: [2]}


def deep(levels: int) -> Any:
    value: Any = 0
    for _ in range(levels):
        value = [value]
    return value


@pytest.mark.parametrize(
    "parameters",
    [
        {"x": 1.5},
        {"x": float("nan")},
        {"x": 2**63},
        {"x": -(2**63)},
        {"x": {1: "a"}},
        {"x": "\udfff"},
        {"\ud800": 1},
        {"x": b"bytes"},
        {"x": {1, 2}},
        {"x": deep(30)},  # manifest, producer, parameters and 30 lists: 33 levels
    ],
)
def test_parameters_must_obey_the_common_json_rules(parameters: Any) -> None:
    with pytest.raises(CnfError):
        bundle_files(3, ALL3, pools={}, producer=Producer("p", "1", parameters))


def test_parameters_at_the_limits_are_accepted() -> None:
    parameters = {"big": 2**63 - 1, "small": -(2**63 - 1), "deep": deep(29), "t": (1, E_ACUTE)}
    files = bundle_files(3, ALL3, pools={}, producer=Producer("p", "1", parameters))
    manifest = reader().parse_document(files.files["manifest.json"])
    assert manifest["producer"]["parameters"]["t"] == [1, E_ACUTE]
    assert canonical_json({"b": 1, "a": [True, None]}) == b'{"a":[true,null],"b":1}'


def test_bad_clauses_and_producer_are_refused() -> None:
    with pytest.raises(CnfError):
        bundle_files(3, [[4]], pools={}, producer=producer("x"))
    with pytest.raises(CnfError):
        bundle_files(3, ALL3, pools={}, producer=Producer(1, "1"))  # type: ignore[arg-type]


# -- publication ----------------------------------------------------------------------


def test_publication_writes_the_manifest_last_and_syncs_every_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    order: list[str] = []
    synced: list[int] = []
    real_open, real_fsync = open, os.fsync

    def recording_open(path: Any, mode: str = "r", *args: Any, **kwargs: Any) -> Any:
        order.append(Path(path).name)
        return real_open(path, mode, *args, **kwargs)

    def recording_fsync(descriptor: int) -> None:
        synced.append(descriptor)
        real_fsync(descriptor)

    monkeypatch.setattr(bundle_module, "open", recording_open, raising=False)
    monkeypatch.setattr(os, "fsync", recording_fsync)
    files = make(VECTORS[("mixed", "sat3")])
    target = publish_bundle(tmp_path / "sat3", files)
    assert order == ["formula.cnf", "names.tsv", "tags.tsv", "manifest.json"]
    expected_syncs = 4 + (0 if os.name == "nt" else 2)  # files, staging directory, parent
    assert len(synced) == expected_syncs
    assert stored_files(target) == dict(files.files)
    assert sorted(p.name for p in tmp_path.iterdir()) == ["sat3"]  # no staging left


def test_an_existing_target_is_never_overwritten(tmp_path: Path) -> None:
    files = make(VECTORS[("zero", "clause")])
    target = publish_bundle(tmp_path / "b", files)
    before = stored_files(target)
    with pytest.raises(CnfError, match="never overwritten"):
        publish_bundle(target, make(VECTORS[("zero", "empty")]))
    assert stored_files(target) == before
    (tmp_path / "empty-dir").mkdir()
    with pytest.raises(CnfError):
        publish_bundle(tmp_path / "empty-dir", files)
    (tmp_path / "file").write_bytes(b"x")
    with pytest.raises(CnfError):
        publish_bundle(tmp_path / "file", files)
    assert sorted(p.name for p in tmp_path.iterdir()) == ["b", "empty-dir", "file"]


def test_a_failure_before_the_rename_leaves_no_bundle_and_no_staging(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = {"n": 0}
    real_fsync = os.fsync

    def failing_fsync(descriptor: int) -> None:
        calls["n"] += 1
        if calls["n"] == 3:
            raise OSError(5, "simulated I/O error")
        real_fsync(descriptor)

    monkeypatch.setattr(os, "fsync", failing_fsync)
    with pytest.raises(OSError, match="simulated"):
        publish_bundle(tmp_path / "sat3", make(VECTORS[("mixed", "sat3")]))
    assert list(tmp_path.iterdir()) == []


def test_a_target_that_appears_during_publication_is_not_overwritten(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "late"
    real_fsync = os.fsync

    def racing_fsync(descriptor: int) -> None:
        real_fsync(descriptor)
        if not target.exists():
            target.mkdir()
            (target / "manifest.json").write_bytes(b"other\n")

    monkeypatch.setattr(os, "fsync", racing_fsync)
    with pytest.raises(CnfError, match="appeared"):
        publish_bundle(target, make(VECTORS[("zero", "empty")]))
    assert stored_files(target) == {"manifest.json": b"other\n"}
    assert sorted(p.name for p in tmp_path.iterdir()) == ["late"]


def test_files_out_of_order_are_refused(tmp_path: Path) -> None:
    files = make(VECTORS[("zero", "empty")])
    swapped = BundleFiles(
        dict(reversed(list(files.files.items()))), files.formula_sha256, files.manifest
    )
    with pytest.raises(CnfError, match="last"):
        publish_bundle(tmp_path / "x", swapped)
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("name", ["../escape", "/absolute", "sub/names.tsv", "other.tsv", ""])
def test_only_the_bundle_file_names_are_written(tmp_path: Path, name: str) -> None:
    files = make(VECTORS[("zero", "empty")])
    forged = BundleFiles(
        {"formula.cnf": b"p cnf 0 0\n", name: b"x", "manifest.json": files.files["manifest.json"]},
        files.formula_sha256,
        files.manifest,
    )
    target = tmp_path / "inner" / "x"
    target.parent.mkdir()
    with pytest.raises(CnfError, match="only"):
        publish_bundle(target, forged)
    assert list(target.parent.iterdir()) == []
    assert sorted(p.name for p in tmp_path.iterdir()) == ["inner"]


def test_the_bundle_values_are_read_only() -> None:
    files = make(VECTORS[("zero", "empty")])
    with pytest.raises(TypeError):
        files.files["formula.cnf"] = b""  # type: ignore[index]
    with pytest.raises(TypeError):
        files.manifest["format"] = "x"  # type: ignore[index]
