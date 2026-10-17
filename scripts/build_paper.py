r"""Build an article twice with pdfLaTeX and reject unresolved references or clipped content.

The public article, `paper/faces12-en.tex`, is the default. An explicit source path
can be supplied for a local draft using the same checks; like the article, a draft states its
date as \date{D Month YYYY}, which becomes the date its PDF records. The article declares
`\pdfoutput=1`, as arXiv expects of a pdfLaTeX source, and only pdfTeX builds it: an engine
whose `--version` does not name pdfTeX (XeTeX, LuaTeX, Tectonic) is refused before it runs.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path

root = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser()
parser.add_argument("--engine", default="pdflatex", help="pdflatex: a name on PATH or a path")
parser.add_argument("--source", type=Path, default=root / "paper/faces12-en.tex")
parser.add_argument("--output", type=Path, default=None, help="default: the source with .pdf")
args = parser.parse_args()
source = args.source if args.source.is_absolute() else Path.cwd() / args.source
output = args.output or source.with_suffix(".pdf")
name = source.stem
engine = shutil.which(args.engine)
if engine is None:
    raise SystemExit(f"TeX engine not found: {args.engine}")
try:
    banner = subprocess.run(
        [engine, "--version"], capture_output=True, timeout=60, check=False
    ).stdout.decode(errors="replace")
except (OSError, subprocess.TimeoutExpired) as error:
    raise SystemExit(f"{engine} --version failed: {error}") from error
if "pdfTeX" not in banner.partition("\n")[0]:
    raise SystemExit(f"{engine} is not pdfLaTeX; the article is built with pdfLaTeX only")
# The date the PDF records is the date the article states, \date{17 October 2026}: the day of the
# revision that last changed its PDF.
stated = re.search(r"^\\date\{(\d{1,2} [A-Z][a-z]+ \d{4})\}", source.read_text("utf-8"), re.M)
if stated is None:
    raise SystemExit(f"{source} states no \\date{{D Month YYYY}}, the date its PDF records")
try:
    day = datetime.strptime(stated.group(1), "%d %B %Y").replace(tzinfo=timezone.utc)
except ValueError as error:
    raise SystemExit(f"{source}: \\date{{{stated.group(1)}}} is not a date: {error}") from error
epoch = str(int(day.timestamp()))
environment = dict(os.environ, SOURCE_DATE_EPOCH=epoch, FORCE_SOURCE_DATE="1", TZ="UTC")
with tempfile.TemporaryDirectory(prefix="faces12-paper-") as temporary:
    work = Path(temporary)
    shutil.copyfile(source, work / f"{name}.tex")
    command = [
        engine,
        "-interaction=nonstopmode",
        "-halt-on-error",
        "-no-shell-escape",
        f"{name}.tex",
    ]
    # Two complete builds in the same clean directory: references settle, then bytes repeat.
    digests = []
    for _ in range(2):
        for _pass in range(2):
            result = subprocess.run(
                command, cwd=work, env=environment, capture_output=True, timeout=180, check=False
            )
            if result.returncode:
                raise SystemExit(
                    result.stdout.decode(errors="replace") + result.stderr.decode(errors="replace")
                )
        log = (work / f"{name}.log").read_text(encoding="utf-8", errors="replace")
        bad = re.findall(
            r"^.*(?:Overfull|Missing character:|undefined|multiply defined|Token not allowed).*$",
            log,
            re.M,
        )
        if bad:
            raise SystemExit("Unresolved document defects:\n" + "\n".join(bad))
        digests.append(hashlib.sha256((work / f"{name}.pdf").read_bytes()).hexdigest())
    if len(set(digests)) != 1:
        raise SystemExit(f"PDF bytes differ between repeated builds: {digests}")
    output.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(work / f"{name}.pdf", output)
    shutil.copyfile(work / f"{name}.log", output.with_suffix(".log"))
    print(f"{name}.pdf checked; two identical builds: {digests[0]}")
