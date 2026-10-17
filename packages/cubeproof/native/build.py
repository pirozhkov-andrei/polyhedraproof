#!/usr/bin/env python3
"""Build the native lookahead helper ``cubeproof-look`` with warnings as errors.

    python3 build.py [--cc CC] [--out DIR] [--sanitize]

Writes ``DIR/cubeproof-look`` and ``DIR/cubeproof-look.provenance.json`` (default DIR:
``build`` next to this file). The record has the format ``cubeproof-look-build-1`` and holds the
SHA-256 of the source and of the binary, the compiler's first version line, the exact flags
and the helper's version line; it is canonical JSON (sorted keys, no spaces, one LF) and
contains no timestamp or path, so equal inputs and compiler give equal files. The library
reads it only if its ``binary_sha256`` matches the binary it measured (``split.helper``).

The flags are ``-std=c11 -O2 -Wall -Wextra -Wpedantic -Werror`` (``--sanitize`` replaces
``-O2`` with ``-O1 -g -fsanitize=address,undefined -no-pie``, for tests, not for production).
The sanitized helper is not position-independent: the address sanitizer of older compilers
(GCC 12) cannot always place its shadow memory beside a position-independent executable under a
kernel with high address randomization, and then prints "AddressSanitizer:DEADLYSIGNAL" without
end before ``main``; at a fixed address it starts every time. Standard library only; the
compiler is the one named by ``--cc`` (default ``cc``), never searched in any other way than by
the operating system's PATH lookup of that name.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SOURCE = HERE / "cubeproof-look.c"
BINARY_NAME = "cubeproof-look"
BUILD_FORMAT = "cubeproof-look-build-1"
WARNING_FLAGS = ["-Wall", "-Wextra", "-Wpedantic", "-Werror"]
RELEASE_FLAGS = ["-std=c11", "-O2", *WARNING_FLAGS]
SANITIZE_FLAGS = [
    "-std=c11", "-O1", "-g", "-fsanitize=address,undefined", "-no-pie", *WARNING_FLAGS
]  # fmt: skip
#: Seconds the built helper may take to print its version line.
VERSION_TIMEOUT_S = 60


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def compiler_line(cc: str) -> str:
    result = subprocess.run([cc, "--version"], capture_output=True, text=True, check=True)
    return result.stdout.splitlines()[0].strip()


def build(cc: str, out: Path, flags: list[str]) -> Path:
    """Compile the helper into ``out``; return the path of the record. Raises on any warning."""
    out.mkdir(parents=True, exist_ok=True)
    binary = out / BINARY_NAME
    command = [cc, *flags, "-o", str(binary), str(SOURCE)]
    subprocess.run(command, check=True)
    # Only the version line is read: what the binary writes on stderr is discarded, so a binary
    # whose runtime never starts (a sanitizer that prints without end before main) cannot fill
    # this process's memory, and the timeout ends it. Its stdout, one line, is read whole.
    version = subprocess.run(
        [str(binary), "--version"],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        check=True,
        timeout=VERSION_TIMEOUT_S,
    )
    record = {
        "format": BUILD_FORMAT,
        "binary_sha256": sha256_file(binary),
        "source_sha256": sha256_file(SOURCE),
        "compiler": compiler_line(cc),
        "flags": flags,
        "version": version.stdout.strip(),
    }
    text = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n"
    target = out / (BINARY_NAME + ".provenance.json")
    target.write_bytes(text.encode("utf-8"))
    return target


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--cc", default="cc", help="the C compiler (default: cc)")
    parser.add_argument("--out", type=Path, default=HERE / "build", help="output directory")
    parser.add_argument("--sanitize", action="store_true", help="ASan/UBSan build for tests")
    options = parser.parse_args(argv)
    flags = SANITIZE_FLAGS if options.sanitize else RELEASE_FLAGS
    record = build(options.cc, options.out, list(flags))
    print(f"built {options.out / BINARY_NAME}; record {record}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
