"""neighbourly.corpus12 and the package data: the 59 matrices, the hash fixture, provenance.

The packaged files are copies of the repository data files (``data/`` of the checkout); these
tests pin that they are equal byte for byte, that every packaged file is recorded in
``provenance.json`` with its SHA-256, and that the corpus checks hold on the packaged copy. The
shipped classes and the enumeration document are pinned by recorded SHA-256 goldens. The census
(minutes) and all 59 base formulas (about ten seconds) are in ``test_corpus12_census.py``
(slow).
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from neighbourly import corpus12, data
from neighbourly.enumeration import enumerate_classes
from neighbourly.maps import CombinatorialMap, MapError

PACKAGE_DATA = Path(data.__file__).resolve().parent
TESTS = Path(__file__).resolve().parents[1]
REPO = TESTS.parents[2]
GOLDENS = TESTS / "cnf" / "goldens_n12.json"
#: The data files of the repository (``data/``).
REPOSITORY_DATA = REPO / "data"
#: SHA-256 of J(["dict", [[canonical form, matrix name], ...]]) of
#: ``shipped_classes()``, in its order (form as a list of vertex lists).
SHIPPED_CLASSES_GOLDEN = "b26e20b375dfe022fb61774e68541fc116778078a064fbe115ca222b1df6def1"
#: The enumeration document of ``enumerate_classes(7)``: its keys in order and its SHA-256 (J).
DOCUMENT_7_KEYS_GOLDEN = [
    "format",
    "n",
    "passed",
    "compared_corpus",
    "labelled_count",
    "class_count",
    "orbit_count",
    "arithmetic",
    "problems",
    "classes",
    "corpus_sha256",
]
DOCUMENT_7_SHA256_GOLDEN = "affe32301912ca7a6b4bea3c161dd5b8c0c371341c2bc7cc294b5dceecde7764"


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def J(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def repository_matrix(map_id: int) -> Path:
    return REPOSITORY_DATA / "matrices" / f"topology_{map_id:02d}.txt"


def provenance() -> dict[str, Any]:
    document: dict[str, Any] = json.loads(data.read_bytes("provenance.json"))
    assert document["format"] == "neighbourly-data-provenance-1"
    return document


def test_the_corpus_constants_are_consistent() -> None:
    assert corpus12.N_FACES == 12 and corpus12.N_MAPS == 59
    assert corpus12.N_VERTICES == 44
    assert corpus12.EULER_CHARACTERISTIC == -10
    assert corpus12.GOLDEN_COUNTS == (12144, 59)
    assert (corpus12.BASE_LAYERS, corpus12.BASE_GAUGE_FACE) == ("S,H,A,B,I", 1)
    assert list(corpus12.map_ids()) == list(range(1, 60))


@pytest.mark.parametrize("map_id", [0, 60, -1, True, "1", 1.0])
def test_map_numbers_out_of_range_are_refused(map_id: Any) -> None:
    with pytest.raises(corpus12.CorpusError, match="out of range"):
        corpus12.load_map(map_id)


def test_the_packaged_matrices_are_the_repository_matrices() -> None:
    for map_id in corpus12.map_ids():
        assert corpus12.matrix_bytes(map_id) == repository_matrix(map_id).read_bytes()
    assert (
        data.read_bytes("n12", "matrices", "SHA256SUMS")
        == (REPOSITORY_DATA / "matrices" / "SHA256SUMS").read_bytes()
    )


def test_the_packaged_hash_fixture_is_the_repository_fixture_and_the_goldens() -> None:
    raw = data.read_bytes("n12", "formula_hashes_n12.json")
    assert raw == (REPOSITORY_DATA / "fixtures" / "formula_hashes.json").read_bytes()
    golden = json.loads(GOLDENS.read_text(encoding="utf-8"))["base_formulas"]
    assert golden["fixture_sha256"] == sha(raw)
    hashes = corpus12.formula_hashes()
    assert sorted(hashes) == list(corpus12.map_ids())
    for map_id, entry in hashes.items():
        expected = golden["maps"][str(map_id)]
        assert (entry.variables, entry.clauses, entry.sha256) == (
            expected["variables"],
            expected["clauses"],
            expected["sha256"],
        )


def test_the_matrices_match_their_sums_and_the_corpus_is_well_formed() -> None:
    assert corpus12.matrix_problems() == []
    assert corpus12.corpus_problems() == []
    assert len(corpus12.matrix_sums()) == corpus12.N_MAPS


def test_a_damaged_matrix_is_reported(monkeypatch: pytest.MonkeyPatch) -> None:
    real = data.read_bytes

    def damaged(*parts: str) -> bytes:
        raw = real(*parts)
        return raw.replace(b"1 1 0", b"1 0 1", 1) if parts[-1] == "topology_07.txt" else raw

    monkeypatch.setattr(data, "read_bytes", damaged)
    problems = corpus12.corpus_problems()
    assert any(p.startswith("topology_07.txt: SHA-256") for p in problems)
    assert any(p.startswith("7: ") for p in problems)


def test_an_extra_line_in_the_sums_is_reported(monkeypatch: pytest.MonkeyPatch) -> None:
    real = data.read_bytes
    extra = ("0" * 64 + "  topology_60.txt\n").encode("ascii")

    def lengthened(*parts: str) -> bytes:
        raw = real(*parts)
        return raw + extra if parts[-1] == "SHA256SUMS" else raw

    monkeypatch.setattr(data, "read_bytes", lengthened)
    assert corpus12.matrix_problems() == ["SHA256SUMS lists 60 files, not exactly the 59 matrices"]


def test_a_packaged_matrix_of_another_size_is_reported(monkeypatch: pytest.MonkeyPatch) -> None:
    """A valid orientable map on n = 7 in place of map 5: its size is a problem by itself."""
    real = data.read_bytes

    def replaced(*parts: str) -> bytes:
        if parts[-1] == "topology_05.txt":
            return real("fixtures", "szilassi", "csaszar_n7.txt")
        return real(*parts)

    monkeypatch.setattr(data, "read_bytes", replaced)
    problems = corpus12.corpus_problems()
    assert "5: n=7, V=14, chi=0" in problems
    assert any(p.startswith("topology_05.txt: SHA-256") for p in problems)


def test_a_non_orientable_corpus_map_is_reported(monkeypatch: pytest.MonkeyPatch) -> None:
    """No non-orientable twelve-face map is at hand; the query is replaced, so this tests
    that the corpus check asks it of every map."""
    monkeypatch.setattr(CombinatorialMap, "is_orientable", lambda self: False)
    problems = corpus12.corpus_problems()
    assert problems == [
        f"{m}: non-orientable, so it does not embed in R^3" for m in corpus12.map_ids()
    ]


def test_a_damaged_hash_fixture_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    real = data.read_bytes
    document = json.loads(real("n12", "formula_hashes_n12.json"))
    for change in ({"layers": "S"}, {"gauge_face": 2}, {"format": "x"}):
        broken = json.dumps({**document, **change}).encode()
        monkeypatch.setattr(data, "read_bytes", lambda *parts, b=broken: b)
        with pytest.raises(corpus12.CorpusError):
            corpus12.formula_hashes()
    del document["maps"]["59"]
    short = json.dumps(document).encode()
    monkeypatch.setattr(data, "read_bytes", lambda *parts: short)
    with pytest.raises(corpus12.CorpusError, match="exactly the 59"):
        corpus12.formula_hashes()


def test_missing_package_data_is_a_corpus_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def missing(*parts: str) -> bytes:
        raise FileNotFoundError("/".join(parts))

    monkeypatch.setattr(data, "read_bytes", missing)
    for call in (
        lambda: corpus12.load_map(1),
        corpus12.matrix_sums,
        corpus12.formula_hashes,
    ):
        with pytest.raises(corpus12.CorpusError):
            call()


def test_the_shipped_classes_are_the_pinned_shipped_classes() -> None:
    new = corpus12.shipped_classes()
    pairs = [[[list(vertex) for vertex in form], name] for form, name in new.items()]
    assert sha(J(["dict", pairs])) == SHIPPED_CLASSES_GOLDEN
    assert len(new) == corpus12.N_MAPS


def test_an_isomorphic_pair_in_the_corpus_is_reported(monkeypatch: pytest.MonkeyPatch) -> None:
    real = data.read_bytes

    def duplicated(*parts: str) -> bytes:
        if parts[-1] == "topology_02.txt":
            return real(*parts[:-1], "topology_01.txt")
        return real(*parts)

    monkeypatch.setattr(data, "read_bytes", duplicated)
    with pytest.raises(MapError, match="isomorphic"):
        corpus12.shipped_classes()
    problems = corpus12.corpus_problems()
    assert "58 distinct labelled maps, expected 59" in problems


def test_the_enumeration_document_has_the_pinned_layout() -> None:
    new = corpus12.enumeration_document(enumerate_classes(7))
    assert sha(J(new)) == DOCUMENT_7_SHA256_GOLDEN
    assert list(new) == DOCUMENT_7_KEYS_GOLDEN


def test_provenance_records_every_packaged_file_with_its_hash() -> None:
    files = provenance()["files"]
    recorded = {entry["path"]: entry for entry in files}
    assert len(recorded) == len(files)
    present = {
        path.relative_to(PACKAGE_DATA).as_posix()
        for path in PACKAGE_DATA.rglob("*")
        if path.is_file() and "__pycache__" not in path.parts
    } - {"__init__.py", "provenance.json"}
    assert set(recorded) == present
    for rel, entry in recorded.items():
        assert sha(data.read_bytes(*rel.split("/"))) == entry["sha256"], rel
        assert entry["origin"].startswith(
            ("copy of data/", "generated by tools/", "written for this package: ")
        )


def test_copied_files_equal_their_source_in_the_checkout() -> None:
    root = REPO
    copies = 0
    for entry in provenance()["files"]:
        origin = entry["origin"]
        if not origin.startswith("copy of "):
            continue
        source = origin.removeprefix("copy of ").removesuffix(" of the repository")
        assert (root / source).read_bytes() == data.read_bytes(*entry["path"].split("/"))
        copies += 1
    assert copies == 63
