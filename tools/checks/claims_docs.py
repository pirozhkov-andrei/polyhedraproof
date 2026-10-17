"""The claims ledger: ``docs/claims.json`` rendered into ``docs/CLAIMS.md`` and
``docs/THEORY_MAP.md``, and the checks that keep it honest.

    python3 tools/checks/claims_docs.py [--root DIR] [--check]

Without ``--check`` it rewrites the generated blocks ``claims`` of ``docs/CLAIMS.md`` and
``statements`` of ``docs/THEORY_MAP.md`` (between ``<!-- BEGIN GENERATED: name -->`` and
``<!-- END GENERATED: name -->``). With ``--check`` (``make lint``) it changes nothing and
reports, one sentence per problem:

* a generated block that is out of date;
* a claim that is neither a label of the article nor ``faces12:*``, a duplicate claim, a
  theorem, lemma, proposition or corollary of the article without a claim, an open claim
  that lists checks;
* code named by a claim that does not exist: a dotted name is resolved statically in the
  sources of ``packages/*/src`` and ``tools/checks``, nothing is imported;
* a test named by a claim that does not exist or is unconditionally skipped or expected to
  fail;
* a reference ``(paper: label)`` in a released document or source (tests are left out: they
  build wrong references on purpose) that is not a ``\\label`` of the article;
* a relative link in a released Markdown document that points nowhere.

"Released" means listed in ``RELEASE_FILES.txt``. Standard library only.
"""

from __future__ import annotations

import argparse
import ast
import json
import re
import sys
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PAPER = "paper/faces12-en.tex"
CLAIMS = "docs/claims.json"
FORMAT_CLAIMS = "faces12-claims-1"
CLAIMS_PAGE = "docs/CLAIMS.md"
THEORY_MAP = "docs/THEORY_MAP.md"
#: The generated blocks: ``(file, block name)``.
BLOCKS = ((CLAIMS_PAGE, "claims"), (THEORY_MAP, "statements"))
RELEASE_LIST = "RELEASE_FILES.txt"
#: Where the code named by claims lives (patterns relative to the root).
SOURCE_ROOTS = ("packages/*/src", "tools/checks")
#: Where the tests named by claims live.
TEST_FILES = ("packages/*/tests/**/test_*.py", "tests/**/test_*.py", "tools/**/test_*.py")

#: Label prefixes of the article.
LABEL = r"(?:thm|lem|cor|prop|def|hyp|rem|conv|sec|sub|app):[A-Za-z0-9-]+"
#: ``paper: lem:parity`` or ``paper: lem:onereflex, rem:octants``, in code or prose.
PAPER_REFERENCE = re.compile(rf"paper:\s*({LABEL}(?:\s*,\s*{LABEL})*)")
#: Statements that must each have an entry in the claims registry.
REQUIRED_KINDS = ("thm", "lem", "prop", "cor")
#: The environments that share the theorem counter, and how they are named in print.
THEOREM_KINDS = {
    "theorem": "Theorem",
    "lemma": "Lemma",
    "proposition": "Proposition",
    "corollary": "Corollary",
    "definition": "Definition",
    "hypothesis": "Hypothesis",
    "remark": "Remark",
    "convention": "Convention",
}


class ClaimsError(Exception):
    """The article or the registry cannot be read as this module expects."""


# -- the article --------------------------------------------------------------------------------


@dataclass(frozen=True)
class Statement:
    """One labelled item of the article, numbered as LaTeX numbers it."""

    label: str
    kind: str  # environment or sectioning command
    number: str
    title: str

    @property
    def display(self) -> str:
        suffix = f" ({self.title})" if self.title else ""
        if self.kind in THEOREM_KINDS:
            return f"{THEOREM_KINDS[self.kind]} {self.number}{suffix}"
        if self.kind == "appendix":
            return f"Appendix {self.number}{suffix}"
        return f"Section {self.number}{suffix}"


_BEGIN = re.compile(r"\\begin\{(" + "|".join(THEOREM_KINDS) + r")\}(?:\[([^\]]*)\])?")
_SECTION = re.compile(r"\\(section|subsection)(\*?)\{([^}]*)\}")
_LABEL_DEF = re.compile(r"\\label\{([^}]+)\}")
_TOKEN = re.compile(_SECTION.pattern + "|" + _BEGIN.pattern + "|" + _LABEL_DEF.pattern)


def _plain(title: str) -> str:
    """A LaTeX title as plain text: math shifts and simple commands removed."""
    text = re.sub(r"\\[a-zA-Z]+\{([^}]*)\}", r"\1", title)
    text = text.replace("$", "").replace("\\", "").replace("~", " ")
    return re.sub(r"\s+", " ", text).strip()


def paper_statements(path: Path) -> list[Statement]:
    """Every labelled item of an article source, with the number LaTeX would print.

    amsart numbers sections 1, 2, ... and, after ``\\appendix``, A, B, ...; subsections
    ``section.k``; and every theorem-like environment ``section.k`` on one counter that
    restarts with each section.
    """
    statements: list[Statement] = []
    section, subsection, counter = 0, 0, 0
    appendix = False
    pending: tuple[str, str, str] | None = None  # (kind, number, title) awaiting a label
    for line in path.read_text(encoding="utf-8").splitlines():
        code = re.sub(r"(?<!\\)%.*", "", line)
        if "\\appendix" in code:
            appendix, section = True, 0
        for token in _TOKEN.finditer(code):
            text = token.group(0)
            number = chr(ord("A") + section - 1) if appendix else str(section)
            section_match = _SECTION.match(text)
            begin_match = _BEGIN.match(text)
            if section_match is not None:
                command, star, title = section_match.groups()
                if star:
                    pending = None
                elif command == "section":
                    section, subsection, counter = section + 1, 0, 0
                    number = chr(ord("A") + section - 1) if appendix else str(section)
                    pending = ("appendix" if appendix else "section", number, _plain(title))
                else:
                    subsection += 1
                    pending = ("subsection", f"{number}.{subsection}", _plain(title))
            elif begin_match is not None:
                counter += 1
                title = begin_match.group(2) or ""
                pending = (begin_match.group(1), f"{number}.{counter}", _plain(title))
            else:
                label = text[len("\\label{") : -1]
                if pending is None:
                    raise ClaimsError(f"{PAPER}: label {label} follows nothing numbered")
                kind, numbered, title = pending
                statements.append(Statement(label, kind, numbered, title))
                pending = None
    return statements


def paper_labels(path: Path) -> dict[str, Statement]:
    return {statement.label: statement for statement in paper_statements(path)}


# -- the claims registry ------------------------------------------------------------------------


@dataclass(frozen=True)
class Check:
    test: str
    covers: str


@dataclass(frozen=True)
class Claim:
    id: str
    statement: str
    #: how it is established when not by a proof in the article (a claim outside the article,
    #: or a statement of the article that rests on a cited result)
    established: str = ""
    code: tuple[str, ...] = ()
    checks: tuple[Check, ...] = ()
    limits: str = ""
    open: bool = False

    @property
    def in_paper(self) -> bool:
        return not self.id.startswith("faces12:")


def _string(entry: dict[str, object], key: str, where: str) -> str:
    value = entry.get(key, "")
    if not isinstance(value, str):
        raise ClaimsError(f"{CLAIMS}: {where}: {key} is not a string")
    return value


def load_claims(path: Path) -> list[Claim]:
    document = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict) or document.get("format") != FORMAT_CLAIMS:
        raise ClaimsError(f"{CLAIMS}: expected format {FORMAT_CLAIMS}")
    entries = document.get("claims")
    if not isinstance(entries, list):
        raise ClaimsError(f"{CLAIMS}: claims is not a list")
    claims = []
    for entry in entries:
        if not isinstance(entry, dict):
            raise ClaimsError(f"{CLAIMS}: a claim is not an object")
        where = str(entry.get("id"))
        code = entry.get("code", [])
        checks = entry.get("checks", [])
        if not isinstance(code, list) or not all(isinstance(c, str) for c in code):
            raise ClaimsError(f"{CLAIMS}: {where}: code is not a list of names")
        if not isinstance(checks, list) or not all(isinstance(c, dict) for c in checks):
            raise ClaimsError(f"{CLAIMS}: {where}: checks is not a list of objects")
        claims.append(
            Claim(
                id=_string(entry, "id", where),
                statement=_string(entry, "statement", where),
                established=_string(entry, "established", where),
                code=tuple(code),
                checks=tuple(
                    Check(_string(c, "test", where), _string(c, "covers", where)) for c in checks
                ),
                limits=_string(entry, "limits", where),
                open=entry.get("open", False) is True,
            )
        )
    return claims


# -- tests: existence, markers, and how to run them ---------------------------------------------


@dataclass(frozen=True)
class CatalogueEntry:
    path: str
    name: str
    markers: frozenset[str]

    @property
    def disabled(self) -> bool:
        """Unconditionally skipped or expected to fail."""
        return bool({"skip", "xfail"} & self.markers)


def _marker_names(node: ast.expr) -> Iterator[str]:
    """``pytest.mark.slow`` -> slow; ``pytest.mark.skipif(...)`` -> skipif; lists recurse."""
    if isinstance(node, (ast.List, ast.Tuple)):
        for element in node.elts:
            yield from _marker_names(element)
        return
    target = node.func if isinstance(node, ast.Call) else node
    chain: list[str] = []
    current: ast.expr = target
    while isinstance(current, ast.Attribute):
        chain.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        chain.append(current.id)
    chain.reverse()
    if chain[:2] == ["pytest", "mark"] and len(chain) == 3:
        yield chain[2]


def listed_test_files(root: Path) -> list[Path]:
    found = {
        path
        for pattern in TEST_FILES
        for path in root.glob(pattern)
        if "__pycache__" not in path.parts
    }
    return sorted(found)


def catalogue_tests(root: Path) -> dict[str, CatalogueEntry]:
    """Every module-level test function, keyed ``path::name``."""
    catalogue: dict[str, CatalogueEntry] = {}
    for path in listed_test_files(root):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        module_markers: set[str] = set()
        for node in tree.body:
            if isinstance(node, ast.Assign) and any(
                isinstance(t, ast.Name) and t.id == "pytestmark" for t in node.targets
            ):
                module_markers.update(_marker_names(node.value))
        relative = path.relative_to(root).as_posix()
        for node in tree.body:
            if isinstance(node, ast.FunctionDef) and node.name.startswith("test_"):
                markers = set(module_markers)
                for decorator in node.decorator_list:
                    markers.update(_marker_names(decorator))
                catalogue[f"{relative}::{node.name}"] = CatalogueEntry(
                    relative, node.name, frozenset(markers)
                )
    return catalogue


def how_to_run(entry: CatalogueEntry) -> str:
    """The standard target or opt-in tier that runs a test."""
    if "release_view" in entry.markers:
        return "`make test-release-view`"
    if entry.path.startswith("tests/architecture/"):
        return "`make test-architecture`"
    if "image" in entry.markers:
        return "`make test-all` in the test image"
    if entry.path.startswith("tests/release/"):
        return "`make test-installed`"
    if "slow" in entry.markers:
        return "pytest `--run-slow`"
    return "`make test-fast`"


# -- code: static resolution of dotted names ----------------------------------------------------


def _module_file(root: Path, module: str) -> Path | None:
    parts = module.split(".")
    for pattern in SOURCE_ROOTS:
        for base in sorted(root.glob(pattern)):
            for candidate in (
                base.joinpath(*parts).with_suffix(".py"),
                base.joinpath(*parts) / "__init__.py",
            ):
                if candidate.is_file():
                    return candidate
    return None


def _bindings(body: Sequence[ast.stmt]) -> dict[str, ast.stmt]:
    """Names bound at one level of a module or class body."""
    names: dict[str, ast.stmt] = {}
    for node in body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names[node.name] = node
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    names[target.id] = node
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            names[node.target.id] = node
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                names[(alias.asname or alias.name).split(".")[0]] = node
    return names


class _Resolver:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.trees: dict[Path, ast.Module] = {}

    def tree(self, path: Path) -> ast.Module:
        if path not in self.trees:
            self.trees[path] = ast.parse(path.read_text(encoding="utf-8"))
        return self.trees[path]

    def resolve(self, reference: str) -> bool:
        parts = reference.split(".")
        for cut in range(len(parts), 0, -1):
            path = _module_file(self.root, ".".join(parts[:cut]))
            if path is not None:
                return self._attributes(".".join(parts[:cut]), path, parts[cut:], 0)
        return False

    def _imported(self, module: str, node: ast.ImportFrom, name: str) -> tuple[str, Path] | None:
        """The module a ``from ... import name`` takes ``name`` from, if it is one of ours."""
        if node.level:
            package = module.split(".")
            if not (self._is_package(module)):
                package = package[:-1]
            package = package[: len(package) - (node.level - 1)]
            source = ".".join([*package, *([node.module] if node.module else [])])
        else:
            source = node.module or ""
        submodule = _module_file(self.root, f"{source}.{name}")
        if submodule is not None:
            return f"{source}.{name}", submodule
        path = _module_file(self.root, source)
        return None if path is None else (source, path)

    def _is_package(self, module: str) -> bool:
        path = _module_file(self.root, module)
        return path is not None and path.name == "__init__.py"

    def _attributes(self, module: str, path: Path, rest: list[str], depth: int) -> bool:
        """Whether ``rest`` names something defined in ``module`` (at ``path``)."""
        if not rest:
            return True
        node = _bindings(self.tree(path).body).get(rest[0]) if depth <= 20 else None
        if isinstance(node, ast.ImportFrom):
            return self._through_import(module, node, rest, depth)
        if isinstance(node, ast.ClassDef):
            return self._members(module, path, node, rest[1:], depth)
        return node is not None and len(rest) == 1

    def _through_import(
        self, module: str, node: ast.ImportFrom, rest: list[str], depth: int
    ) -> bool:
        found = self._imported(module, node, rest[0])
        if found is None:
            return False
        source, source_path = found
        if source.endswith("." + rest[0]):  # a submodule
            return self._attributes(source, source_path, rest[1:], depth + 1)
        return self._attributes(source, source_path, rest, depth + 1)

    def _members(
        self, module: str, path: Path, node: ast.ClassDef, rest: list[str], depth: int
    ) -> bool:
        if not rest:
            return True
        members = _bindings(node.body)
        if rest[0] in members:
            member = members[rest[0]]
            if isinstance(member, ast.ClassDef):
                return self._members(module, path, member, rest[1:], depth)
            return len(rest) == 1
        for base in node.bases:  # inherited members, from classes of the same sources
            if isinstance(base, ast.Name) and self._attributes(
                module, path, [base.id, *rest], depth + 1
            ):
                return True
        return False


# -- rendering ----------------------------------------------------------------------------------


def _table(header: Sequence[str], rows: Iterable[Sequence[str]]) -> str:
    lines = ["| " + " | ".join(header) + " |", "|" + "|".join("---" for _ in header) + "|"]
    for row in rows:
        cells = [str(cell).replace("|", "\\|").replace("\n", " ") for cell in row]
        lines.append("| " + " | ".join(cells) + " |")
    return "\n".join(lines)


def _test_link(test: str, up: str) -> str:
    """A link to a test's file from a document ``up`` levels below the root."""
    path, name = test.split("::")
    return f"[`{name}`]({up}{path})"


def render_theory_map(root: Path) -> str:
    """Every numbered statement of the article, with its code and its tests."""
    claims = {claim.id: claim for claim in load_claims(root / CLAIMS)}
    rows = []
    for statement in paper_statements(root / PAPER):
        if statement.kind not in THEOREM_KINDS:
            continue
        claim = claims.get(statement.label)
        code = ", ".join(f"`{c}`" for c in claim.code) if claim else ""
        tests = "<br>".join(_test_link(c.test, "../") for c in claim.checks) if claim else ""
        rows.append([statement.display, f"`{statement.label}`", code or "—", tests or "—"])
    return _table(["Statement", "Label", "Implemented in", "Checked by"], rows)


def _status_of(claim: Claim) -> str:
    """How a claim stands: a proof in the article, a test, a measurement, or open."""
    if claim.open:
        return "**Open**"
    if not claim.in_paper:
        return claim.established or "Stated"
    if claim.established:
        return claim.established + (" + tests" if claim.checks else "")
    kind = claim.id.split(":")[0]
    if kind in REQUIRED_KINDS:
        status = "Proof in the article"
    elif kind == "def":
        status = "Definition"
    elif kind == "rem":
        status = "Remark in the article"
    else:
        status = "Stated in the article"
    return status + (" + tests" if claim.checks else "")


def render_claims_ledger(root: Path) -> str:
    labels = paper_labels(root / PAPER)
    catalogue = catalogue_tests(root)
    rows = []
    for claim in load_claims(root / CLAIMS):
        where = labels[claim.id].display if claim.in_paper and claim.id in labels else "—"
        evidence = []
        for check in claim.checks:
            entry = catalogue.get(check.test)
            run = how_to_run(entry) if entry else "missing"
            evidence.append(f"{check.covers} ({_test_link(check.test, '../')}, {run})")
        if claim.limits:
            evidence.append(f"*Limits:* {claim.limits}")
        rows.append(
            [
                f"`{claim.id}`",
                claim.statement,
                where,
                _status_of(claim),
                "<br>".join(evidence) or "—",
            ]
        )
    return _table(["Claim", "Statement", "In the article", "Status", "Evidence and limits"], rows)


def _render_block(name: str, root: Path) -> str:
    if name == "claims":
        return render_claims_ledger(root)
    if name == "statements":
        return render_theory_map(root)
    raise ClaimsError(f"unknown generated block {name!r}")


def replace_block(text: str, name: str, content: str) -> str:
    begin, end = f"<!-- BEGIN GENERATED: {name} -->", f"<!-- END GENERATED: {name} -->"
    if text.count(begin) != 1 or text.count(end) != 1:
        raise ClaimsError(f"expected one generated block {name!r}")
    head, rest = text.split(begin)
    _, tail = rest.split(end)
    return f"{head}{begin}\n{content}\n{end}{tail}"


def generated(root: Path) -> dict[str, str]:
    """Every generated document's intended content, keyed by its path."""
    return {
        path: replace_block(
            (root / path).read_text(encoding="utf-8"), block, _render_block(block, root)
        )
        for path, block in BLOCKS
    }


def write(root: Path) -> list[str]:
    """Rewrite every generated block that is out of date; returns the documents changed."""
    changed = []
    for path, content in generated(root).items():
        target = root / path
        if target.read_text(encoding="utf-8") != content:
            newline = "\r\n" if b"\r\n" in target.read_bytes() else "\n"  # keep the file's
            target.write_text(content, encoding="utf-8", newline=newline)
            changed.append(path)
    return changed


# -- the checks ---------------------------------------------------------------------------------


def released(root: Path, suffixes: tuple[str, ...]) -> list[Path]:
    """The released files with these suffixes (``RELEASE_FILES.txt``)."""
    listing = root / RELEASE_LIST
    if not listing.is_file():
        return []
    names = listing.read_text(encoding="utf-8").splitlines()
    return sorted(
        root / name for name in names if name.endswith(suffixes) and (root / name).is_file()
    )


def check_claims(root: Path) -> list[str]:
    problems = []
    labels = paper_labels(root / PAPER)
    catalogue = catalogue_tests(root)
    resolver = _Resolver(root)
    seen: set[str] = set()
    for claim in load_claims(root / CLAIMS):
        if claim.id in seen:
            problems.append(f"{CLAIMS}: duplicate claim {claim.id}")
        seen.add(claim.id)
        if claim.in_paper and claim.id not in labels:
            problems.append(f"{CLAIMS}: {claim.id} is neither a label of {PAPER} nor faces12:*")
        for reference in claim.code:
            if not resolver.resolve(reference):
                problems.append(f"{CLAIMS}: {claim.id}: code {reference} does not exist")
        for item in claim.checks:
            entry = catalogue.get(item.test)
            if entry is None:
                problems.append(f"{CLAIMS}: {claim.id}: test {item.test} does not exist")
            elif entry.disabled:
                problems.append(f"{CLAIMS}: {claim.id}: test {item.test} is skipped or xfail")
        if claim.open and claim.checks:
            problems.append(f"{CLAIMS}: {claim.id} is open but lists checks")
    for label, statement in labels.items():
        if label.split(":")[0] in REQUIRED_KINDS and label not in seen:
            problems.append(f"{CLAIMS}: {statement.display} ({label}) has no entry")
    return problems


def check_paper_references(root: Path) -> list[str]:
    labels = paper_labels(root / PAPER)
    problems = []
    sources = [
        path
        for path in released(root, (".py",))
        if not path.relative_to(root).as_posix().startswith(("tests/", "packages/"))
        or "/src/" in path.relative_to(root).as_posix()
    ]
    for path in [*released(root, (".md",)), *sources, root / CLAIMS]:
        for match in PAPER_REFERENCE.finditer(path.read_text(encoding="utf-8")):
            for label in re.findall(LABEL, match.group(1)):
                if label not in labels:
                    where = path.relative_to(root).as_posix()
                    problems.append(f"{where}: `paper: {label}` is not a label of {PAPER}")
    return problems


_LINK = re.compile(r"\[[^\]]*\]\(([^)\s]+)\)")


def check_links(root: Path) -> list[str]:
    problems = []
    for path in released(root, (".md",)):
        where = path.relative_to(root).as_posix()
        for target in _LINK.findall(path.read_text(encoding="utf-8")):
            if re.match(r"[a-z]+:", target) or target.startswith("#"):
                continue
            if not (path.parent / target.split("#")[0]).exists():
                problems.append(f"{where}: link to {target} is broken")
    return problems


def check(root: Path) -> list[str]:
    """Every problem found, as a sentence; empty when the ledger is consistent."""
    problems = [
        f"{path} is out of date: run `python3 tools/checks/claims_docs.py`"
        for path, content in generated(root).items()
        if (root / path).read_text(encoding="utf-8") != content
    ]
    problems += check_claims(root)
    problems += check_paper_references(root)
    problems += check_links(root)
    return problems


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n\n")[0])
    parser.add_argument("--root", type=Path, default=ROOT, help="checkout (default: this one)")
    parser.add_argument("--check", action="store_true", help="change nothing, report problems")
    args = parser.parse_args(argv)
    root = args.root.resolve()
    try:
        if args.check:
            problems = check(root)
            for problem in problems:
                print(problem)
            print(f"claims documents: {len(problems)} problem(s)")
            return 1 if problems else 0
        for path in write(root):
            print(f"wrote {path}")
    except (ClaimsError, OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
