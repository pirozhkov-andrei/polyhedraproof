"""The release list ``RELEASE_FILES.txt`` and the release view built from it.

The list is exactly the files of the checkout, and the view (a copy of the listed files and
nothing else) passes the fast suites of the three packages on its own.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

import release_view
from release_view import build_view

ROOT = Path(__file__).resolve().parents[2]
PACKAGES = ("cubeproof", "neighbourly", "faces12-campaign")
FAST = "not slow and not image"
# Skip reasons of the package fast suites that only mean an optional build tool is absent.
OPTIONAL_BUILD_TOOL_SKIPS = {"no C compiler"}


def test_the_release_list_is_exactly_the_files_of_the_checkout() -> None:
    """Every file listed, every listed file present, the list sorted and without repeats."""
    if release_view.is_checkout(ROOT):
        # the comparison really ran: a checkout whose files git cannot list is a failure
        assert release_view.checkout_files(ROOT), "git listed no file of the checkout"
    found = release_view.problems(ROOT)
    assert found == [], "\n".join(found)


def _tree(root: Path, listed: list[str], present: list[str]) -> None:
    root.mkdir(parents=True, exist_ok=True)
    (root / release_view.LISTING).write_text("".join(f"{n}\n" for n in listed), encoding="utf-8")
    for name in present:
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("x\n", encoding="utf-8")


def test_both_ignore_files_keep_the_hidden_entries_of_the_release() -> None:
    """A hidden root entry of the release list (``.gitignore``, ``.github``, ...) is excepted
    from the rule for hidden root entries in ``.gitignore``, or git would not track it, and in
    ``.dockerignore``, or the source archive built inside the release image would miss it
    (``release.missing``)."""
    hidden = sorted({n.split("/")[0] for n in release_view.listed_files(ROOT) if n[0] == "."})
    assert ".github" in hidden, hidden
    gitignore = (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
    dockerignore = (ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines()
    for name in hidden:
        assert {f"!/{name}", f"!/{name}/"} & set(gitignore), f".gitignore drops {name}"
        assert {f"!{name}", f"!{name}/"} & set(dockerignore), f".dockerignore drops {name}"


def test_a_checkout_that_git_cannot_list_is_a_problem(tmp_path: Path) -> None:
    """A failing git inside a checkout must not pass as "no problem" (e.g. dubious ownership)."""
    _tree(tmp_path, [release_view.LISTING], [])
    (tmp_path / ".git").write_text("gitdir: /nonexistent/release-list\n", encoding="utf-8")
    with pytest.raises(release_view.CheckoutError):
        release_view.checkout_files(tmp_path)
    found = release_view.problems(tmp_path)
    assert any("the files of the checkout cannot be listed" in p for p in found), found


def test_outside_a_checkout_only_the_listed_files_are_checked(tmp_path: Path) -> None:
    _tree(tmp_path, [release_view.LISTING, "src/a.py"], ["src/a.py", "notes.txt"])
    assert release_view.checkout_files(tmp_path) is None
    assert release_view.problems(tmp_path) == []
    (tmp_path / "src" / "a.py").unlink()
    assert release_view.problems(tmp_path) == [
        "RELEASE_FILES.txt lists src/a.py, which is not a file of the tree"
    ]


def test_unlisted_missing_unsorted_and_outside_entries_are_problems(tmp_path: Path) -> None:
    git = shutil.which("git")
    if git is None:
        pytest.skip("git is not installed")
    listed = [release_view.LISTING, "src/gone.py", "src/a.py", "../outside.py"]
    _tree(tmp_path, listed, ["src/a.py", "src/new.py"])
    subprocess.run([git, "init", "-q", str(tmp_path)], check=True, capture_output=True)
    text = "\n".join(release_view.problems(tmp_path))
    assert "RELEASE_FILES.txt is not sorted or lists a file twice" in text
    assert "RELEASE_FILES.txt lists src/gone.py, which is not a file of the tree" in text
    assert "RELEASE_FILES.txt lists ../outside.py, a path outside the tree" in text
    assert "src/new.py is a file of the checkout that RELEASE_FILES.txt does not list" in text
    assert "src/a.py" not in text.replace("src/a.py,", "")


def test_the_view_holds_exactly_the_listed_files(tmp_path: Path) -> None:
    _tree(tmp_path / "tree", [release_view.LISTING, "src/a.py"], ["src/a.py", "notes.txt"])
    view = tmp_path / "view"
    assert build_view(tmp_path / "tree", view) == 2
    assert sorted(p.relative_to(view).as_posix() for p in view.rglob("*") if p.is_file()) == [
        "RELEASE_FILES.txt",
        "src/a.py",
    ]
    (tmp_path / "tree" / "src" / "a.py").unlink()
    with pytest.raises(SystemExit, match=r"lists missing files: src/a\.py"):
        build_view(tmp_path / "tree", tmp_path / "view2")


# Re-runs every package fast suite (minutes): `make test-release-view`; not part of
# `make test-architecture`.
@pytest.mark.release_view
def test_the_source_release_runs_its_own_fast_suites(tmp_path: Path) -> None:
    """The release view (RELEASE_FILES.txt) is self-sufficient: its fast suites pass."""
    view = tmp_path / "view"
    build_view(ROOT, view)
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    suites = [*(f"packages/{name}/tests" for name in PACKAGES), "tests/architecture"]
    # This file is part of the view: without "not release_view" the nested run would start
    # itself again, without end.
    marker = f"{FAST} and not release_view"
    options = ["-m", marker, "-q", "-rs", "-p", "no:cacheprovider"]  # -rs: the skip reasons
    result = subprocess.run(
        [sys.executable, "-m", "pytest", *suites, *options],
        cwd=view,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    # No skip except for an absent optional build tool: the test image has no C compiler
    # by design, so the native-helper tests skip there.
    found = re.search(r"(\d+) skipped", result.stdout.splitlines()[-1])
    skipped = int(found.group(1)) if found else 0
    reasons: dict[str, int] = {}
    for line in result.stdout.splitlines():
        counted = re.match(r"SKIPPED \[(\d+)\] \S+: (.*)$", line)
        if counted:
            reasons[counted.group(2)] = reasons.get(counted.group(2), 0) + int(counted.group(1))
    assert sum(reasons.values()) == skipped, result.stdout
    assert set(reasons) <= OPTIONAL_BUILD_TOOL_SKIPS, reasons
    if shutil.which("cc") is not None:
        assert skipped == 0, reasons
