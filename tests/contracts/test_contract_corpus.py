"""The corpus is frozen: hashed, tied to the specification and reproducible by its generator.

The corpus metadata freezes the hashes of the specification, of the generator sources and
of the inputs; the generator is independent of the runtime packages and of this test-side
reader (no shared code path).
"""

from __future__ import annotations

import ast
import hashlib
import subprocess
import sys
from pathlib import Path

from contract_reader import CORPUS, REPO, load_json_file

GENERATOR = REPO / "tools" / "spec_vectors"


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def corpus_files() -> set[str]:
    return {
        p.relative_to(CORPUS).as_posix()
        for p in CORPUS.rglob("*")
        if p.is_file() and p.name != "corpus.json"
    }


def test_metadata_freezes_the_specification() -> None:
    meta = load_json_file(CORPUS / "corpus.json")
    assert meta["format"] == "cubeproof-contract-corpus-1"
    assert meta["spec"] == {
        "path": "docs/SPECIFICATION.md",
        "sha256": sha(REPO / "docs" / "SPECIFICATION.md"),
    }
    assert meta["sources"] == [
        {
            "path": "tools/spec_vectors/inputs/prefix-cases-n12.json",
            "sha256": sha(GENERATOR / "inputs" / "prefix-cases-n12.json"),
        }
    ]


def test_metadata_lists_every_file_with_its_hash() -> None:
    meta = load_json_file(CORPUS / "corpus.json")
    listed = {f["path"]: f for f in meta["files"]}
    inputs = {f["path"]: f for f in meta["inputs"]}
    assert not set(listed) & set(inputs)
    assert set(listed) | set(inputs) == corpus_files()
    for path, entry in {**listed, **inputs}.items():
        data = (CORPUS / path).read_bytes()
        assert entry["sha256"] == hashlib.sha256(data).hexdigest(), path
        assert entry["bytes"] == len(data), path


def test_metadata_records_the_generator_sources() -> None:
    meta = load_json_file(CORPUS / "corpus.json")
    sources = {p.relative_to(REPO).as_posix(): sha(p) for p in sorted(GENERATOR.glob("*.py"))}
    assert sources
    assert {g["path"]: g["sha256"] for g in meta["generator"]} == sources


def test_the_generator_reproduces_the_corpus(tmp_path: Path) -> None:
    result = subprocess.run(
        [sys.executable, str(GENERATOR / "generate.py"), "--out", str(tmp_path)],
        capture_output=True,
        text=True,
        check=False,
        cwd=REPO,
    )
    assert result.returncode == 0, result.stderr
    meta = load_json_file(CORPUS / "corpus.json")
    inputs = {f["path"] for f in meta["inputs"]}
    produced = {p.relative_to(tmp_path).as_posix() for p in tmp_path.rglob("*") if p.is_file()}
    assert produced == (corpus_files() | {"corpus.json"}) - inputs
    for path in sorted(produced):
        assert (tmp_path / path).read_bytes() == (CORPUS / path).read_bytes(), path


def test_the_generator_check_mode_accepts_the_committed_corpus() -> None:
    result = subprocess.run(
        [sys.executable, str(GENERATOR / "generate.py"), "--check"],
        capture_output=True,
        text=True,
        check=False,
        cwd=REPO,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def imported(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            names.add(node.module.split(".")[0])
    return names


def test_generator_and_reader_share_no_code() -> None:
    generator_modules = {p.stem for p in GENERATOR.glob("*.py")}
    test_modules = {p.stem for p in (REPO / "tests" / "contracts").glob("*.py")}
    for path in GENERATOR.glob("*.py"):
        found = imported(path)
        assert not found & test_modules, path
        assert not found & {"cubeproof", "neighbourly", "faces12_campaign", "faces12"}, path
    for path in (REPO / "tests" / "contracts").glob("*.py"):
        assert not imported(path) & generator_modules, path
