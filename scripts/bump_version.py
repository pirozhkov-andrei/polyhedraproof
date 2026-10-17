"""Change the release version everywhere it is written and regenerate what hashes those files.

The version is declared once per distribution (``pyproject.toml`` and ``__version__`` of each
package, the pins of the meta-package) and repeated in the citation file, the documents, the
default image tag of the wrapper and a few tests; ``tests/architecture`` fails unless the
declarations agree. This script rewrites every file of ``RELEASE_FILES.txt`` that names the old
version as a whole word, except the history (``CHANGELOG.md``), the golden archive test,
whose version is part of its frozen bytes, and the article, which names the release its revision
was published with (a revision changes it, and its PDF with it). A file that records the hash of
a rewritten file is regenerated: the contract corpus (``tools/spec_vectors/generate.py``) records
the hash of ``docs/SPECIFICATION.md``, whose image tag names the version. Run it from a clean tree
and read the diff::

    python3 scripts/bump_version.py 1.0.0
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

root = Path(__file__).resolve().parents[1]
#: The history keeps the versions it describes, the golden archive fixes its own version, the
#: article names the release of its revision, and the examples of this script stay as they are.
KEEP = {
    "CHANGELOG.md",
    "packages/faces12-campaign/tests/test_f12_release.py",
    "paper/faces12-en.tex",
    "scripts/bump_version.py",
}
#: Generators of files that record the hash of a file this script may rewrite: the rewritten
#: file and the generator, run after the rewrite (CONTRIBUTING, "Generated and hash-pinned files").
REGENERATE = {"docs/SPECIFICATION.md": "tools/spec_vectors/generate.py"}
#: PEP 440 release and pre-release versions: 1.0.0, 1.0.1, 1.1.0rc1
VERSION = re.compile(r"\d+\.\d+\.\d+((a|b|rc)\d+)?")

parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
parser.add_argument("version", help="the new version, such as 1.0.0 or 1.1.0rc1")
args = parser.parse_args()
if VERSION.fullmatch(args.version) is None:
    raise SystemExit(f"not a version of the form X.Y.Z or X.Y.ZrcN: {args.version!r}")
project = (root / "packages/cubeproof/pyproject.toml").read_text(encoding="utf-8")
match = re.search(r'^version = "([^"]+)"$', project, re.MULTILINE)
if match is None:
    raise SystemExit("packages/cubeproof/pyproject.toml has no version line")
old, new = match.group(1), args.version
if old == new:
    raise SystemExit(f"the version is already {new}")

# the old version as a whole word: not inside 1.0.0rc1 or 11.0.0, but before a full stop
word = re.compile(rf"(?<![\w.]){re.escape(old)}(?!\w|\.\d)")
listed = (root / "RELEASE_FILES.txt").read_text(encoding="utf-8").splitlines()
changed = []
rewritten = set()
for name in listed:
    if not name or name.startswith("#") or name in KEEP:
        continue
    path = root / name
    try:
        with path.open(encoding="utf-8", newline="") as source:  # keep CRLF files as they are
            text = source.read()
    except (UnicodeDecodeError, FileNotFoundError):
        continue
    replaced, count = word.subn(new, text)
    if count:
        path.write_bytes(replaced.encode("utf-8"))
        changed.append(f"{name}: {count}")
        rewritten.add(name)
print(f"{old} -> {new} in {len(changed)} files")
print("\n".join(changed))
for name, generator in REGENERATE.items():
    if name in rewritten:
        print(f"{name} changed: {generator}", flush=True)  # before the output of the generator
        subprocess.run([sys.executable, str(root / generator)], check=True)
print("Then: update CHANGELOG.md and the date of CITATION.cff, and run make lint test-fast.")
