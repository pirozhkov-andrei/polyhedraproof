"""Specification §3.1, §4.2, §12.1: ``bundle import`` is the explicit door for external DIMACS.

A non-canonical file is normalized (clause and literal order kept), the original bytes' hash is
recorded as provenance, the bundle is published whole or not at all, an existing target is never
overwritten, and an imported bundle is a first-class input of the rest of the chain.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import cp_cli_support as c
import pytest

from cubeproof.base.canonical_json import parse_document
from cubeproof.cnf.bundle import load_bundle

#: unsatisfiable on variables 1..3 (every sign pattern), comments, CRLF, two clauses per line
RAW = (
    b"c an external file\r\np cnf 3 8\r\n"
    b"1 2 3 0 1 2 -3 0\r\n1 -2 3 0\r\n1 -2 -3 0 -1 2 3 0\r\n"
    b"-1 2 -3 0\r\nc between clauses\r\n-1 -2 3 0 -1 -2 -3 0\r\n"
)


def test_an_external_file_becomes_a_canonical_bundle(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    source = tmp_path / "in.cnf"
    source.write_bytes(RAW)
    done = c.cli_main(["bundle", "import", str(source), "-o", str(tmp_path / "b" / "f")], capsys)
    assert done.code == 0, done.err
    document = c.last_json(done.out)
    target = tmp_path / "b" / "f"
    formula = (target / "formula.cnf").read_bytes()
    assert document == {
        "path": str(target.resolve()),
        "formula_sha256": hashlib.sha256(formula).hexdigest(),
        "variables": 3,
        "clauses": 8,
        "source_sha256": hashlib.sha256(RAW).hexdigest(),
    }
    assert formula.startswith(b"p cnf 3 8\n") and b"\r" not in formula and b"c " not in formula
    manifest = parse_document((target / "manifest.json").read_bytes())
    assert manifest["producer"]["parameters"] == {"source_sha256": document["source_sha256"]}
    assert manifest["pools"] == {} and manifest["side_files"] == []
    assert load_bundle(target.parent, "f").formula.clauses == 8
    # the order of clauses and literals is preserved
    assert formula.decode().splitlines()[1:3] == ["1 2 3 0", "1 2 -3 0"]
    assert sorted(p.name for p in target.iterdir()) == ["formula.cnf", "manifest.json"]


def test_an_existing_target_is_never_overwritten(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    source = tmp_path / "in.cnf"
    source.write_bytes(RAW)
    target = tmp_path / "f"
    assert c.cli_main(["bundle", "import", str(source), "-o", str(target)], capsys).code == 0
    before = {p.name: p.read_bytes() for p in target.iterdir()}
    done = c.cli_main(["bundle", "import", str(source), "-o", str(target)], capsys)
    assert done.code == 3 and "[bundle.exists]" in done.err
    assert {p.name: p.read_bytes() for p in target.iterdir()} == before


@pytest.mark.parametrize(
    ("raw", "rule"),
    [
        (b"p cnf 2 1\n1 3 0\n", "dimacs.import"),  # a literal outside 1..V
        (b"1 2 0\n", "dimacs.import"),  # no header
        (b"p cnf 2 2\n1 2 0\n", "dimacs.import"),  # a clause count that is not M
        (b"p cnf 2 1\n1 2\n", "dimacs.import"),  # no terminating 0
    ],
)
def test_malformed_external_dimacs_is_refused_and_leaves_nothing(
    raw: bytes, rule: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    source = tmp_path / "in.cnf"
    source.write_bytes(raw)
    done = c.cli_main(["bundle", "import", str(source), "-o", str(tmp_path / "f")], capsys)
    assert done.code == 3 and f"[{rule}]" in done.err
    assert not (tmp_path / "f").exists()
    assert [p.name for p in tmp_path.iterdir()] == ["in.cnf"]  # not even a staging directory


def test_a_missing_source_is_an_input_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    done = c.cli_main(
        ["bundle", "import", str(tmp_path / "nope.cnf"), "-o", str(tmp_path / "f")], capsys
    )
    assert done.code == 3 and "[input.file]" in done.err


def test_an_imported_bundle_runs_through_the_whole_chain(tmp_path: Path) -> None:
    """import -> campaign create -> run -> certify, all as commands in child processes."""
    source = tmp_path / "in.cnf"
    source.write_bytes(RAW)
    tools = c.t.install(tmp_path / "tools", solver={})
    shop = c.Shop(tmp_path, tools)
    done = c.command("bundle", "import", str(source), "-o", str(tmp_path / "bundles" / "imported"))
    assert done.code == 0, done.err
    created = c.command(*shop.create_args(tmp_path / "bundles" / "imported"))
    assert created.code == 0, created.err
    ran = c.command(*shop.run_args())
    assert ran.code == 0, ran.err
    certified = c.command(
        "certify", "--campaign", str(shop.campaign), "--journals", str(shop.journal)
    )
    assert certified.code == 0 and certified.out.startswith("PROVED")
