"""Bundles: manifest, side files, loading with containment, publication and import (specification
§4.2)."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import sys
from pathlib import Path
from typing import Any

import pytest

import cubeproof
from cubeproof.base.canonical_json import document_bytes, parse_document
from cubeproof.base.errors import ContractError, InputError, ResourceError
from cubeproof.base.settings import ReaderLimits
from cubeproof.cnf.bundle import (
    BundleManifest,
    check_manifest_formula,
    import_dimacs,
    load_bundle,
    parse_names_tsv,
    parse_tags_tsv,
    publish_bundle,
    read_side_file,
)
from cubeproof.cnf.dimacs import parse_dimacs
from cubeproof.contracts.values import Artifact

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "contracts"))
import cp_corpus

ALL3_TEXT = cp_corpus.vectors("cnf")["formulas"][4]["text"].encode("ascii")


@pytest.mark.parametrize("entry", cp_corpus.documents("bundle-manifest"), ids=lambda e: e["id"])
def test_manifest_fixtures(entry: dict[str, Any]) -> None:
    data = cp_corpus.fixture_bytes(entry)
    value = parse_document(data)
    kind, expected = cp_corpus.expectation(entry)
    formula_text = entry.get("context", {}).get("formula")

    def run() -> BundleManifest:
        manifest = BundleManifest.from_json(value)
        if formula_text is not None:
            check_manifest_formula(manifest, parse_dimacs(formula_text.encode("utf-8")))
        return manifest

    if kind == "valid":
        manifest = run()
        assert manifest.to_json() == value
        assert document_bytes(manifest.to_json()) == data
        return
    with pytest.raises(ContractError) as info:
        run()
    assert info.value.rule == ("schema" if kind == "schema" else expected)
    if kind == "schema":
        assert info.value.location == expected


def _artifact(context: dict[str, Any]) -> Artifact | None:
    raw = context.get("artifact")
    return None if raw is None else Artifact.from_json(raw)


@pytest.mark.parametrize("entry", cp_corpus.documents("names-tsv"), ids=lambda e: e["id"])
def test_names_fixtures(entry: dict[str, Any]) -> None:
    data = cp_corpus.fixture_bytes(entry)
    context = entry["context"]
    kind, rule = cp_corpus.expectation(entry)
    if kind == "valid":
        names = parse_names_tsv(data, context["variables"], artifact=_artifact(context))
        rendered = "".join(f"{i}\t{json.dumps(n, ensure_ascii=False)}\n" for i, n in names)
        assert rendered.encode("utf-8") == data
        return
    with pytest.raises(ContractError) as info:
        parse_names_tsv(data, context["variables"], artifact=_artifact(context))
    assert info.value.rule == rule


@pytest.mark.parametrize("entry", cp_corpus.documents("tags-tsv"), ids=lambda e: e["id"])
def test_tags_fixtures(entry: dict[str, Any]) -> None:
    data = cp_corpus.fixture_bytes(entry)
    context = entry["context"]
    kind, rule = cp_corpus.expectation(entry)
    if kind == "valid":
        tags = parse_tags_tsv(data, context["clauses"], artifact=_artifact(context))
        rendered = "".join(f"{a}\t{b}\t{json.dumps(t, ensure_ascii=False)}\n" for a, b, t in tags)
        assert rendered.encode("utf-8") == data
        return
    with pytest.raises(ContractError) as info:
        parse_tags_tsv(data, context["clauses"], artifact=_artifact(context))
    assert info.value.rule == rule


def test_tsv_refuses_bad_utf8_and_control_escapes() -> None:
    with pytest.raises(ContractError) as info:
        parse_names_tsv(b'1\t"\xff"\n', 3)
    assert info.value.rule == "names.syntax"
    with pytest.raises(ContractError):
        parse_names_tsv(b'1\t"a\tb"\n', 3)  # J escapes a tab
    assert parse_names_tsv(b'1\t"a\\tb"\n', 3) == ((1, "a\tb"),)
    with pytest.raises(ContractError):
        parse_names_tsv(b'1\t"\\ud800"\n', 3)
    with pytest.raises(ContractError):
        parse_tags_tsv(b'1\t1\t"a"\n', 0)


def _campaign_bundles() -> list[tuple[Path, str]]:
    found = []
    for name in ("all3", "mixed", "pilot", "unsat", "zero"):
        campaign = cp_corpus.load_json(f"campaigns/{name}/campaign.json")
        for entry in campaign["formulas"]:
            found.append((cp_corpus.CORPUS / "campaigns" / name, entry["bundle"]))
    return found


@pytest.mark.parametrize(("root", "relative"), _campaign_bundles(), ids=lambda x: str(x)[-30:])
def test_corpus_bundles_load(root: Path, relative: str) -> None:
    bundle = load_bundle(root, relative)
    raw = (root / relative / "formula.cnf").read_bytes()
    assert bundle.formula.data == raw
    assert bundle.manifest.formula_sha256 == hashlib.sha256(raw).hexdigest()
    assert bundle.facts.variables == bundle.formula.variables
    assert bundle.directory == root / relative
    for side in bundle.manifest.side_files:
        read_side_file(bundle, side.path)


def _copy_all3(tmp_path: Path) -> Path:
    source = cp_corpus.CORPUS / "campaigns" / "all3" / "bundles" / "all3"
    target = tmp_path / "root" / "b"
    shutil.copytree(source, target)
    return tmp_path / "root"


def test_bundle_loading_rules(tmp_path: Path) -> None:
    root = _copy_all3(tmp_path)
    assert load_bundle(root, "b").formula.variables == 3
    (root / "b" / "formula.cnf").write_bytes(b"p cnf 3 1\n1 0\n")
    with pytest.raises(InputError) as info:
        load_bundle(root, "b")
    assert info.value.rule == "bundle.formula_sha256"


def test_manifest_size_limit_is_a_resource_error(tmp_path: Path) -> None:
    root = _copy_all3(tmp_path)
    size = len((root / "b" / "manifest.json").read_bytes()) - 1
    assert load_bundle(root, "b", limits=ReaderLimits(document_bytes=size)).manifest
    with pytest.raises(ResourceError) as info:
        load_bundle(root, "b", limits=ReaderLimits(document_bytes=size - 1))
    assert info.value.rule == "limit.document"
    # A manifest with one more byte than J + LF is refused by its size, not by its syntax.
    with (root / "b" / "manifest.json").open("ab") as stream:
        stream.write(b"\n")
    with pytest.raises(ResourceError) as extra:
        load_bundle(root, "b", limits=ReaderLimits(document_bytes=size))
    assert extra.value.rule == "limit.document"


def test_manifest_reading_is_bounded_by_the_document_limit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A large manifest is refused by its size after limit + 2 bytes, not read to the end.
    root = _copy_all3(tmp_path)
    (root / "b" / "manifest.json").write_bytes(b" " * 5_000_000)
    from cubeproof.base.paths import open_contained as opened

    delivered: dict[str, int] = {}

    class Counting:
        def __init__(self, stream: Any, name: str) -> None:
            self._stream, self._name = stream, name

        def read(self, size: int = -1) -> bytes:
            data: bytes = self._stream.read(size)
            delivered[self._name] = delivered.get(self._name, 0) + len(data)
            return data

        def __enter__(self) -> Counting:
            return self

        def __exit__(self, *exc: object) -> None:
            self._stream.close()

    monkeypatch.setattr(
        "cubeproof.cnf.bundle.open_contained",
        lambda base, relative: Counting(opened(base, relative), relative.rsplit("/", 1)[-1]),
    )
    with pytest.raises(ResourceError) as info:
        load_bundle(root, "b", limits=ReaderLimits(document_bytes=1000))
    assert info.value.rule == "limit.document"
    assert delivered["manifest.json"] == 1002


def test_bundle_with_a_symlink_component_is_refused(tmp_path: Path) -> None:
    root = _copy_all3(tmp_path)
    (root / "alias").symlink_to(root / "b")
    with pytest.raises(InputError) as info:
        load_bundle(root, "alias")
    assert info.value.rule == "path.containment"
    os.replace(root / "b" / "manifest.json", root / "manifest.json")
    (root / "b" / "manifest.json").symlink_to(root / "manifest.json")
    with pytest.raises(InputError) as link:
        load_bundle(root, "b")
    assert link.value.rule == "path.containment"


def test_missing_bundle_files_are_input_errors(tmp_path: Path) -> None:
    root = _copy_all3(tmp_path)
    (root / "b" / "formula.cnf").unlink()
    with pytest.raises(InputError) as info:
        load_bundle(root, "b")
    assert info.value.rule == "bundle.files"
    with pytest.raises(InputError) as missing_dir:
        load_bundle(root, "nothing")
    assert missing_dir.value.rule == "bundle.files"


def test_bundle_formula_that_is_a_directory_is_refused(tmp_path: Path) -> None:
    root = _copy_all3(tmp_path)
    (root / "b" / "formula.cnf").unlink()
    (root / "b" / "formula.cnf").mkdir()
    with pytest.raises(InputError) as info:
        load_bundle(root, "b")
    assert info.value.rule == "path.containment"


def test_publish_bundle_writes_an_immutable_complete_bundle(tmp_path: Path) -> None:
    names = b'1\t"x1"\n3\t"x3"\n'
    tags = b'1\t8\t"all"\n'
    target = tmp_path / "out" / "bundle"
    bundle = publish_bundle(
        target,
        ALL3_TEXT,
        pools={"all": [1, 2, 3], "none": []},
        producer={"name": "test", "version": "1", "parameters": {"seed": 1}},
        side_files={"tags.tsv": tags, "names.tsv": names},
    )
    assert sorted(os.listdir(tmp_path / "out")) == ["bundle"]
    assert sorted(os.listdir(target)) == ["formula.cnf", "manifest.json", "names.tsv", "tags.tsv"]
    assert (target / "formula.cnf").read_bytes() == ALL3_TEXT
    manifest = parse_document((target / "manifest.json").read_bytes())
    assert manifest == {
        "format": "cubeproof-bundle-1",
        "formula_sha256": hashlib.sha256(ALL3_TEXT).hexdigest(),
        "variables": 3,
        "clauses": 8,
        "pools": {"all": [1, 2, 3], "none": []},
        "producer": {"name": "test", "version": "1", "parameters": {"seed": 1}},
        "side_files": [
            {"path": "names.tsv", "sha256": hashlib.sha256(names).hexdigest(), "bytes": 14},
            {"path": "tags.tsv", "sha256": hashlib.sha256(tags).hexdigest(), "bytes": 10},
        ],
    }
    loaded = load_bundle(tmp_path / "out", "bundle")
    assert loaded.manifest == bundle.manifest
    assert read_side_file(loaded, "names.tsv") == ((1, "x1"), (3, "x3"))
    assert read_side_file(loaded, "tags.tsv") == ((1, 8, "all"),)


def test_publish_syncs_every_file_and_writes_the_manifest_last(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Specification §4.2: files are written and synced inside a staging sibling, the manifest last;
    # the staging directory is synced before the atomic rename and the parent after it.
    events: list[tuple[str, str]] = []
    paths: dict[int, str] = {}
    real_open, real_write, real_fsync = os.open, os.write, os.fsync
    real_close, real_rename = os.close, os.rename

    def name_of(path: Any) -> str:
        return os.path.relpath(os.fspath(path), tmp_path)

    def tracing_open(path: Any, flags: int, *args: Any, **kwargs: Any) -> int:
        descriptor = real_open(path, flags, *args, **kwargs)
        paths[descriptor] = name_of(path)
        kind = "create" if flags & os.O_CREAT else "open"
        events.append((kind, paths[descriptor]))
        return descriptor

    def tracing_write(descriptor: int, data: Any) -> int:
        count = real_write(descriptor, data)
        events.append(("write", paths.get(descriptor, "?")))
        return count

    def tracing_fsync(descriptor: int) -> None:
        real_fsync(descriptor)
        events.append(("fsync", paths.get(descriptor, "?")))

    def tracing_close(descriptor: int) -> None:
        events.append(("close", paths.pop(descriptor, "?")))
        real_close(descriptor)

    def tracing_rename(source: Any, target: Any) -> None:
        real_rename(source, target)
        events.append(("rename", f"{name_of(source)} -> {name_of(target)}"))

    monkeypatch.setattr(os, "open", tracing_open)
    monkeypatch.setattr(os, "write", tracing_write)
    monkeypatch.setattr(os, "fsync", tracing_fsync)
    monkeypatch.setattr(os, "close", tracing_close)
    monkeypatch.setattr(os, "rename", tracing_rename)
    publish_bundle(
        tmp_path / "out" / "bundle",
        ALL3_TEXT,
        pools={"all": [1, 2, 3]},
        producer={"name": "t", "version": "1", "parameters": {}},
        side_files={"tags.tsv": b'1\t8\t"all"\n', "names.tsv": b'1\t"x1"\n'},
    )
    monkeypatch.undo()

    renames = [i for i, (kind, _) in enumerate(events) if kind == "rename"]
    assert len(renames) == 1
    rename = renames[0]
    staging, published = events[rename][1].split(" -> ")
    assert published == "out/bundle"
    assert staging.startswith("out/.bundle.staging-")
    created = [(i, name) for i, (kind, name) in enumerate(events) if kind == "create"]
    files = [name for _, name in created]
    assert files == [
        f"{staging}/formula.cnf",
        f"{staging}/names.tsv",
        f"{staging}/tags.tsv",
        f"{staging}/manifest.json",
    ]
    staging_sync = events.index(("fsync", staging))
    for start, name in created:
        writes = [i for i, event in enumerate(events) if event == ("write", name)]
        synced = events.index(("fsync", name))
        closed = events.index(("close", name))
        assert writes, name
        assert start < min(writes) and max(writes) < synced < closed < staging_sync, name
    # The manifest is the last file written: every other file is complete and synced first.
    manifest_start = created[-1][0]
    assert all(events.index(("fsync", name)) < manifest_start for _, name in created[:-1])
    assert staging_sync < rename
    parent_sync = events.index(("fsync", "out"))
    assert rename < parent_sync


def test_publish_refuses_to_overwrite_and_leaves_no_staging(tmp_path: Path) -> None:
    target = tmp_path / "bundle"
    publish_bundle(
        target, ALL3_TEXT, pools={}, producer={"name": "t", "version": "1", "parameters": {}}
    )
    before = (target / "manifest.json").read_bytes()
    with pytest.raises(FileExistsError):
        publish_bundle(
            target,
            b"p cnf 0 0\n",
            pools={},
            producer={"name": "t", "version": "1", "parameters": {}},
        )
    assert (target / "manifest.json").read_bytes() == before
    assert sorted(os.listdir(tmp_path)) == ["bundle"]


def test_publish_refuses_an_existing_target_before_writing_anything(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    producer = {"name": "t", "version": "1", "parameters": {}}
    (tmp_path / "empty").mkdir()
    (tmp_path / "dangling").symlink_to(tmp_path / "missing")

    def no_write(path: Path, data: bytes) -> None:
        raise AssertionError(f"wrote {path}")

    monkeypatch.setattr("cubeproof.cnf.bundle._write_synced", no_write)
    for name in ("empty", "dangling"):
        with pytest.raises(FileExistsError):
            publish_bundle(tmp_path / name, ALL3_TEXT, pools={}, producer=producer)
    assert sorted(os.listdir(tmp_path)) == ["dangling", "empty"]
    assert os.listdir(tmp_path / "empty") == []


def test_publish_never_replaces_a_target_that_appears_during_staging(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # os.rename would silently replace an empty directory; the check before it refuses.
    target = tmp_path / "bundle"
    from cubeproof.cnf.bundle import _sync_directory as real_sync

    def sync_then_appear(path: Path) -> None:
        real_sync(path)
        if path.name.startswith(".bundle.staging-"):
            target.mkdir()

    monkeypatch.setattr("cubeproof.cnf.bundle._sync_directory", sync_then_appear)
    with pytest.raises(FileExistsError):
        publish_bundle(
            target, ALL3_TEXT, pools={}, producer={"name": "t", "version": "1", "parameters": {}}
        )
    assert os.listdir(tmp_path) == ["bundle"]
    assert os.listdir(target) == []


def test_publish_validates_before_writing(tmp_path: Path) -> None:
    target = tmp_path / "bundle"
    producer = {"name": "t", "version": "1", "parameters": {}}
    bad_inputs: list[dict[str, Any]] = [
        {"formula": b"p cnf 1 1\n2 0\n", "pools": {}},
        {"formula": ALL3_TEXT, "pools": {"all": [3, 1]}},
        {"formula": ALL3_TEXT, "pools": {"Bad": [1]}},
        {"formula": ALL3_TEXT, "pools": {}, "side_files": {"other.tsv": b""}},
        {"formula": ALL3_TEXT, "pools": {}, "side_files": {"names.tsv": b'9\t"x"\n'}},
        {"formula": ALL3_TEXT, "pools": {}, "side_files": {"tags.tsv": b'1\t9\t"x"\n'}},
    ]
    for bad in bad_inputs:
        with pytest.raises(ContractError):
            publish_bundle(
                target,
                bad["formula"],
                pools=bad["pools"],
                producer=producer,
                side_files=bad.get("side_files"),
            )
        assert os.listdir(tmp_path) == []


def test_side_file_hash_mismatch(tmp_path: Path) -> None:
    target = tmp_path / "bundle"
    bundle = publish_bundle(
        target,
        ALL3_TEXT,
        pools={},
        producer={"name": "t", "version": "1", "parameters": {}},
        side_files={"names.tsv": b'1\t"a"\n'},
    )
    os.chmod(target / "names.tsv", 0o644)
    (target / "names.tsv").write_bytes(b'1\t"b"\n')
    with pytest.raises(ContractError) as info:
        read_side_file(bundle, "names.tsv")
    assert info.value.rule == "side.artifact"
    with pytest.raises(ContractError):
        read_side_file(bundle, "tags.tsv")


def test_import_dimacs_publishes_a_canonical_bundle(tmp_path: Path) -> None:
    source = tmp_path / "input.cnf"
    raw = b"c external\np cnf 3 2\n1 -3\n 0 2 0\n"
    source.write_bytes(raw)
    target = tmp_path / "imported"
    bundle = import_dimacs(source, target)
    assert (target / "formula.cnf").read_bytes() == b"p cnf 3 2\n1 -3 0\n2 0\n"
    manifest = bundle.manifest.to_json()
    assert manifest["producer"] == {
        "name": "cubeproof-import",
        "version": cubeproof.__version__,
        "parameters": {"source_sha256": hashlib.sha256(raw).hexdigest()},
    }
    assert manifest["pools"] == {}
    assert manifest["side_files"] == []
    assert load_bundle(tmp_path, "imported").formula.sha256 == bundle.formula.sha256
    with pytest.raises(FileExistsError):
        import_dimacs(source, target)


def test_import_dimacs_refuses_bad_input_without_output(tmp_path: Path) -> None:
    source = tmp_path / "input.cnf"
    source.write_bytes(b"p cnf 1 1\n2 0\n")
    with pytest.raises(ContractError) as info:
        import_dimacs(source, tmp_path / "out")
    assert info.value.rule == "dimacs.import"
    assert not (tmp_path / "out").exists()
