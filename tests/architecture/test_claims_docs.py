"""The claims ledger and its generated documents (``tools/checks/claims_docs.py``).

``make lint`` runs ``claims_docs.py --check``; these tests pin what the check finds, so that
a check that silently stopped looking would fail here.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

import claims_docs

ROOT = Path(__file__).resolve().parents[2]

#: Numbers read from ``paper/faces12-en.aux`` after a checked LaTeX build. The parser
#: re-derives them from the source, so a change of document class or counter setup that
#: renumbers the article fails here instead of silently mislabelling the theory map.
NUMBERS_FROM_A_LATEX_BUILD = {
    "prop:euler": "2.5",
    "lem:onereflex": "2.6",
    "thm:59": "3.8",
    "hyp:G": "4.1",
    "lem:plstability": "4.3",
    "conv:genpos": "4.7",
    "thm:order": "5.2",
    "lem:parity": "5.10",
    "thm:chirotope": "6.3",
    "cor:gauge": "8.2",
    "sub:cases": "9.1",
    "prop:cases": "9.5",
    "sec:status": "11",
    "app:numbers": "A",
    "app:software": "B",
}


def test_the_claims_documents_are_consistent() -> None:
    """``claims_docs.py --check``: generated blocks current, every reference resolves."""
    assert claims_docs.check(ROOT) == []


def test_the_statement_numbers_match_a_latex_build() -> None:
    labels = claims_docs.paper_labels(ROOT / claims_docs.PAPER)
    for label, number in NUMBERS_FROM_A_LATEX_BUILD.items():
        assert labels[label].number == number, label


def copy_of_the_ledger(tmp_path: Path) -> Path:
    """The article, the registry and its two documents, released by a small list."""
    root = tmp_path / "root"
    for name in (claims_docs.PAPER, claims_docs.CLAIMS, *(p for p, _ in claims_docs.BLOCKS)):
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(ROOT / name, root / name)
    (root / claims_docs.RELEASE_LIST).write_text(
        "docs/CLAIMS.md\ndocs/THEORY_MAP.md\ndocs/notes.md\npackages/p/src/p/m.py\n",
        encoding="utf-8",
    )
    return root


def test_the_checks_notice_what_they_are_for(tmp_path: Path) -> None:
    root = copy_of_the_ledger(tmp_path)
    source = root / "packages" / "p" / "src" / "p"
    source.mkdir(parents=True)
    (source / "__init__.py").write_text("", encoding="utf-8")
    bogus = "paper" + ": lem:nonexistent"  # assembled, so that this file cites no such label
    (source / "m.py").write_text(f'"""See ({bogus})."""\n\n\ndef f() -> None: ...\n')
    (root / "docs" / "notes.md").write_text("[gone](missing.md) [ok](CLAIMS.md)\n")
    tests = root / "tests"
    tests.mkdir()
    (tests / "test_x.py").write_text(
        "import pytest\n\n\n@pytest.mark.skip\ndef test_skipped() -> None: ...\n"
    )
    claims = (root / claims_docs.CLAIMS).read_text(encoding="utf-8")
    extra = (
        '{"id": "faces12:x", "established": "Tested", "statement": "x", '
        '"code": ["p.m.f", "p.m.g", "p.nowhere.h"], "checks": ['
        '{"test": "tests/test_x.py::test_skipped", "covers": "a"}, '
        '{"test": "tests/test_x.py::test_missing", "covers": "b"}]}, '
    )
    (root / claims_docs.CLAIMS).write_text(claims.replace('"claims": [', '"claims": [' + extra, 1))
    problems = claims_docs.check(root)
    text = "\n".join(problems)
    assert "docs/CLAIMS.md is out of date" in text
    assert "lem:nonexistent" in text and "packages/p/src/p/m.py" in text
    assert "docs/notes.md: link to missing.md is broken" in text
    assert "link to CLAIMS.md" not in text
    assert "faces12:x: code p.m.g does not exist" in text
    assert "faces12:x: code p.nowhere.h does not exist" in text
    assert "code p.m.f does not" not in text
    assert "faces12:x: test tests/test_x.py::test_skipped is skipped or xfail" in text
    assert "faces12:x: test tests/test_x.py::test_missing does not exist" in text
    # writing fixes the generated blocks and nothing else
    assert claims_docs.write(root) == [claims_docs.CLAIMS_PAGE]
    assert claims_docs.write(root) == []
    assert not any("out of date" in p for p in claims_docs.check(root))


def test_every_required_statement_needs_a_claim_and_ids_are_unique(tmp_path: Path) -> None:
    root = copy_of_the_ledger(tmp_path)
    path = root / claims_docs.CLAIMS
    text = path.read_text(encoding="utf-8")
    path.write_text(text.replace('"id": "thm:59"', '"id": "lem:trivalent"', 1), encoding="utf-8")
    problems = claims_docs.check_claims(root)
    assert any("(thm:59) has no entry" in p for p in problems), problems
    assert any("duplicate claim lem:trivalent" in p for p in problems), problems


def test_names_resolve_through_reexports_and_base_classes(tmp_path: Path) -> None:
    package = tmp_path / "packages" / "q" / "src" / "q"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("from .inner import Child\n")
    (package / "inner.py").write_text(
        "class Base:\n    def inherited(self) -> None: ...\n\n\n"
        "class Child(Base):\n    VALUE = 1\n\n"
        "    class Nested:\n        def deep(self) -> None: ...\n"
    )
    resolver = claims_docs._Resolver(tmp_path)
    for name in ("q", "q.inner", "q.Child", "q.Child.inherited", "q.inner.Child.Nested.deep"):
        assert resolver.resolve(name), name
    for name in ("q.Missing", "q.Child.missing", "q.inner.Child.VALUE.x", "r", "q.other"):
        assert not resolver.resolve(name), name


@pytest.mark.parametrize(
    ("path", "markers", "expected"),
    [
        ("packages/p/tests/test_a.py", set(), "`make test-fast`"),
        ("packages/p/tests/test_a.py", {"slow"}, "pytest `--run-slow`"),
        ("packages/p/tests/test_a.py", {"image", "slow"}, "`make test-all` in the test image"),
        ("tests/architecture/test_b.py", {"release_view"}, "`make test-release-view`"),
        ("tests/architecture/test_c.py", set(), "`make test-architecture`"),
        ("tests/release/test_d.py", {"slow"}, "`make test-installed`"),
    ],
)
def test_each_check_names_the_target_that_runs_it(
    path: str, markers: set[str], expected: str
) -> None:
    entry = claims_docs.CatalogueEntry(path, "test_x", frozenset(markers))
    assert claims_docs.how_to_run(entry) == expected


def test_the_command_line_checks_and_writes(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root = copy_of_the_ledger(tmp_path)
    assert claims_docs.main(["--root", str(root), "--check"]) == 1
    assert "out of date" in capsys.readouterr().out
    assert claims_docs.main(["--root", str(root)]) == 0
    assert "wrote docs/CLAIMS.md" in capsys.readouterr().out
    (root / claims_docs.PAPER).unlink()
    assert claims_docs.main(["--root", str(root), "--check"]) == 2
