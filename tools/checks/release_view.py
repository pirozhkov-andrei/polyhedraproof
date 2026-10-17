"""The release list and the release view of the checkout.

    python3 tools/checks/release_view.py [--tree DIR] [--keep] -- COMMAND [ARG...]

``RELEASE_FILES.txt`` lists every file of a release. :func:`problems` compares the list with
the files of a Git checkout: every file of the checkout is listed and every listed file
exists. The release *view* is a temporary copy, outside the checkout, of exactly the listed
files; a command that passes in the view depends on no file outside the list. A listed file
that does not exist is an error.

The command runs inside the view, with bytecode caching disabled; its exit code is returned.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Sequence
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LISTING = "RELEASE_FILES.txt"


class CheckoutError(Exception):
    """The files of a Git checkout cannot be listed."""


def listed_files(tree: Path) -> list[str]:
    listing = tree / LISTING
    names = [line.strip() for line in listing.read_text(encoding="utf-8").splitlines()]
    return [name for name in names if name]


def is_checkout(root: Path) -> bool:
    """A Git checkout: ``.git`` is a directory, or a file in a linked worktree."""
    return (root / ".git").exists()


def checkout_files(root: Path = ROOT) -> list[str] | None:
    """Tracked and untracked-but-not-ignored files of the checkout.

    None only when ``root`` is not a Git checkout (an export or the source release), where
    the comparison does not apply. Inside a checkout a failing ``git`` raises CheckoutError:
    it must never look like a checkout without problems.
    """
    if not is_checkout(root):
        return None
    command = ["git", "-C", str(root), "ls-files", "-z", "--cached", "--others"]
    command.append("--exclude-standard")
    try:
        result = subprocess.run(command, capture_output=True, check=False)
    except OSError as exc:
        raise CheckoutError(f"cannot run git: {exc}") from exc
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", "replace").strip()
        raise CheckoutError(f"git ls-files exited with {result.returncode}: {detail}")
    names = sorted({x.decode("utf-8") for x in result.stdout.split(b"\0") if x})
    return [n for n in names if (root / n).is_file()]


def problems(root: Path = ROOT) -> list[str]:
    """Why ``RELEASE_FILES.txt`` is not exactly the list of the files of ``root``."""
    listed = listed_files(root)
    found = []
    if listed != sorted(set(listed)):
        found.append(f"{LISTING} is not sorted or lists a file twice")
    for name in listed:
        if Path(name).is_absolute() or ".." in Path(name).parts:
            found.append(f"{LISTING} lists {name}, a path outside the tree")
        elif not (root / name).is_file():
            found.append(f"{LISTING} lists {name}, which is not a file of the tree")
    try:
        files = checkout_files(root)
    except CheckoutError as exc:
        return [*found, f"the files of the checkout cannot be listed: {exc}"]
    if files is not None:
        found.extend(
            f"{name} is a file of the checkout that {LISTING} does not list"
            for name in sorted(set(files) - set(listed))
        )
    return found


def build_view(tree: Path, view: Path) -> int:
    """Copy every listed file of ``tree`` into ``view``; return the number of files."""
    missing = []
    count = 0
    for name in listed_files(tree):
        source = tree / name
        if Path(name).is_absolute() or ".." in Path(name).parts:
            raise SystemExit(f"release view: refusing path outside the tree: {name}")
        if not source.is_file():
            missing.append(name)
            continue
        target = view / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
        count += 1
    if missing:
        raise SystemExit(f"release view: {LISTING} lists missing files: " + ", ".join(missing))
    return count


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("--tree", type=Path, default=ROOT, help="checkout (default: this one)")
    parser.add_argument("--keep", action="store_true", help="keep the view and print its path")
    parser.add_argument("command", nargs=argparse.REMAINDER, help="command after --")
    args = parser.parse_args(argv)
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command:
        parser.error("a command is required after --")
    tree = args.tree.resolve()
    base = Path(tempfile.mkdtemp(prefix="release-view-"))
    view = base / "view"
    view.mkdir()
    try:
        count = build_view(tree, view)
        print(f"release view: {count} listed files of {tree} in {view}", flush=True)
        env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        return subprocess.run(command, cwd=view, env=env, check=False).returncode
    finally:
        if args.keep:
            print(f"release view kept: {view}")
        else:
            shutil.rmtree(base, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
