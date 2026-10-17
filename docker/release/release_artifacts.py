"""Build the installable artifacts of the release image (specification §14).

    python3 docker/release/release_artifacts.py --source DIR --out DIR --python PYTHON

Runs in the ``artifacts`` stage of ``docker/release/Dockerfile`` (and on any Linux host with
the pinned build tools of ``constraints/dev.txt`` in the environment of ``PYTHON``). From the
source tree ``DIR`` it writes, below ``--out``:

``sdists/``            one sdist per package, built from a copy of ``packages/<name>`` outside
                       the source tree;
``wheels/``            one wheel per package, built **from that sdist** (``python -m build``
                       without ``--sdist``/``--wheel`` does exactly this), so the installed code
                       is what the source distribution contains;
``source/``            the deterministic source archive of the release list
                       (``faces12-campaign release bundle``), made by the freshly built wheels
                       installed into a scratch virtual environment, never by the checkout's
                       code;
``requirements.txt``   the exact pins ``name==version`` the image installs;
``artifacts.json``     format ``faces12-release-artifacts-1``: version, every file with its
                       SHA-256, the build tools, and which hashes a second build must reproduce
                       (wheels and the source archive) and which it need not (sdists: their
                       gzip header records the build time).

The meta-package: the root ``polyhedraproof`` distribution contains no code and requires
exactly these three distributions at the release version (specification §2.2). The
image installs the three wheels it pins in ``requirements.txt``, which is what the
meta-package would install, so the meta-package is not built here; its wheel and sdist are
built and installed by ``tests/release/test_installed.py``. Standard library only.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

FORMAT = "faces12-release-artifacts-1"
#: The three distributions of the release, in dependency order (specification §2.1).
PACKAGES = ("cubeproof", "neighbourly", "faces12-campaign")
DEFAULT_AUTHOR = "Andrei Pirozhkov"
IGNORE = shutil.ignore_patterns("build", "dist", "*.egg-info", "__pycache__", ".pytest_cache")


class ArtifactError(Exception):
    """A build step failed or produced something unexpected."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def module_name(distribution: str) -> str:
    return distribution.replace("-", "_")


def run(command: Sequence[str | Path], cwd: Path, env: Mapping[str, str]) -> str:
    shown = " ".join(str(c) for c in command)
    print(f"+ {shown}", flush=True)
    result = subprocess.run(
        [str(c) for c in command],
        cwd=cwd,
        env=dict(env),
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        sys.stdout.write(result.stdout[-4000:])
        sys.stderr.write(result.stderr[-4000:])
        raise ArtifactError(f"{shown}: exit {result.returncode}")
    return result.stdout


def clean_env() -> dict[str, str]:
    """The inherited environment without anything that could import from a checkout."""
    env = {
        k: v
        for k, v in os.environ.items()
        if k not in ("PYTHONPATH", "PYTHONHOME", "VIRTUAL_ENV", "PIP_CONSTRAINT")
    }
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["PIP_DISABLE_PIP_VERSION_CHECK"] = "1"
    return env


def package_version(source: Path, distribution: str) -> str:
    text = (source / "packages" / distribution / "pyproject.toml").read_text(encoding="utf-8")
    for line in text.splitlines():
        if line.startswith("version = "):
            return line.split('"')[1]
    raise ArtifactError(f"packages/{distribution}/pyproject.toml has no version line")


def one(directory: Path, pattern: str) -> Path:
    found = sorted(directory.glob(pattern))
    if len(found) != 1:
        raise ArtifactError(f"{directory}: expected one {pattern}, found {[p.name for p in found]}")
    return found[0]


def build_packages(
    source: Path, out: Path, python: Path, work: Path, env: Mapping[str, str]
) -> str:
    """sdist, then the wheel from it, for every package; return the common version."""
    versions = {name: package_version(source, name) for name in PACKAGES}
    if len(set(versions.values())) != 1:
        raise ArtifactError(f"the packages disagree about the release version: {versions}")
    for name in PACKAGES:
        copy = work / "src" / name
        shutil.copytree(source / "packages" / name, copy, ignore=IGNORE)
        built = work / "dist" / name
        run([python, "-m", "build", "--no-isolation", "--outdir", built, copy], work, env)
        sdist = one(built, f"{module_name(name)}-*.tar.gz")
        wheel = one(built, f"{module_name(name)}-*.whl")
        for item, kind in ((sdist, "sdists"), (wheel, "wheels")):
            (out / kind).mkdir(parents=True, exist_ok=True)
            shutil.copyfile(item, out / kind / item.name)
    return next(iter(versions.values()))


def build_source_archive(
    source: Path, out: Path, version: str, work: Path, env: Mapping[str, str], author: str
) -> Path:
    """The release-list archive, made by the built wheels (not the checkout's code)."""
    venv = work / "bundle-env"
    run([sys.executable, "-m", "venv", venv], work, env)
    python = venv / "bin" / "python"
    pins = [f"{name}=={version}" for name in PACKAGES]
    run(
        [python, "-m", "pip", "install", "-q", "--no-index", "--no-compile", "--find-links",
         out / "wheels", *pins],
        work,
        env,
    )  # fmt: skip
    target = out / "source" / f"polyhedraproof-{version}-source.tar.gz"
    target.parent.mkdir(parents=True, exist_ok=True)
    run(
        [python, "-I", "-m", "faces12_campaign", "release", "bundle", "--root", source,
         "--output", target, "--author", author],
        work,
        env,
    )  # fmt: skip
    return target


def build_tools(python: Path, work: Path, env: Mapping[str, str]) -> list[str]:
    text = run([python, "-m", "pip", "list", "--format=freeze"], work, env)
    return sorted((line for line in text.splitlines() if line), key=str.lower)


def manifest(out: Path, version: str, tools: list[str], python: str) -> dict[str, Any]:
    def listing(kind: str) -> dict[str, str]:
        return {p.name: sha256_file(p) for p in sorted((out / kind).iterdir()) if p.is_file()}

    return {
        "format": FORMAT,
        "version": version,
        "packages": list(PACKAGES),
        "requirements": [f"{name}=={version}" for name in PACKAGES],
        "wheels": listing("wheels"),
        "sdists": listing("sdists"),
        "source": listing("source"),
        "build_python": python,
        "build_tools": tools,
        "reproducible": ["wheels", "source"],
        "informational": ["sdists"],
    }


def write_json(path: Path, data: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def build_all(source: Path, out: Path, python: Path, author: str) -> dict[str, Any]:
    source = source.resolve()
    out = out.resolve()
    if out.exists() and any(out.iterdir()):
        raise ArtifactError(f"{out} is not empty")
    if source == out or source in out.parents:
        raise ArtifactError("the output directory must lie outside the source tree")
    env = clean_env()
    with tempfile.TemporaryDirectory(prefix="faces12-artifacts-") as name:
        work = Path(name)
        version = build_packages(source, out, python, work, env)
        build_source_archive(source, out, version, work, env, author)
        tools = build_tools(python, work, env)
        interpreter = run([python, "-c", "import sys; print(sys.version)"], work, env).strip()
    (out / "requirements.txt").write_text(
        "".join(f"{name}=={version}\n" for name in PACKAGES), encoding="utf-8"
    )
    document = manifest(out, version, tools, interpreter)
    write_json(out / "artifacts.json", document)
    return document


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n\n")[0])
    parser.add_argument("--source", type=Path, required=True, help="the source tree")
    parser.add_argument("--out", type=Path, required=True, help="the artifacts directory")
    parser.add_argument("--python", type=Path, required=True, help="Python with build tools")
    parser.add_argument("--author", default=DEFAULT_AUTHOR, help="recorded in the source archive")
    args = parser.parse_args(argv)
    try:
        document = build_all(args.source, args.out, args.python, args.author)
    except (ArtifactError, OSError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    print(json.dumps(document, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
