"""Refuse to start `make test-all` outside an environment with the pinned tools.

    python3 tools/checks/require_image.py

`make test-all` means "all supported tests in the declared Linux test image"
(`docker/test`). This check fails (exit 2) on a host that is not Linux or lacks the
pinned solver and checker on PATH, so that a default invocation neither launches long work
on the wrong machine nor reports a misleading result.
"""

from __future__ import annotations

import platform
import shutil
import sys

REQUIRED = ("cadical", "cake_lpr")


def main() -> int:
    problems = []
    if platform.system() != "Linux":
        problems.append(f"platform is {platform.system()}, not Linux")
    missing = [name for name in REQUIRED if shutil.which(name) is None]
    if missing:
        problems.append("missing on PATH: " + ", ".join(missing))
    if problems:
        print("make test-all runs only in the declared Linux test image:", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 2
    print("test image prerequisites present: " + ", ".join(REQUIRED))
    return 0


if __name__ == "__main__":
    sys.exit(main())
