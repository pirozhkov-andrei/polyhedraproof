"""Test-only helpers of the command-line tests: commands as child processes, worlds of real files.

The fake pinned tools, formulas and campaign builders are those of the lifecycle tests
(``cp_life_tools``); this module adds the command-line side: :func:`command` runs
``python -m cubeproof`` in a child process with a minimal environment, :func:`cli` runs the same
parser in this process, and :class:`Shop` is a directory with bundles, policy, admission file and
tools in which every command of the command line can be exercised through files only.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
LIFECYCLE = HERE.parent / "lifecycle"
if str(LIFECYCLE) not in sys.path:
    sys.path.insert(0, str(LIFECYCLE))

import cp_life_tools as t  # noqa: E402

from cubeproof import cli  # noqa: E402
from cubeproof.base.canonical_json import document_bytes  # noqa: E402
from cubeproof.cnf.bundle import publish_bundle  # noqa: E402
from cubeproof.contracts.campaign import Admit  # noqa: E402
from cubeproof.contracts.identity import node_id, split_id  # noqa: E402
from cubeproof.contracts.policy import Policy  # noqa: E402
from cubeproof.tools.isolation import PinnedBinary  # noqa: E402

__all__ = [
    "DEEP", "SHALLOW", "SRC", "Done", "Shop", "cli_main", "command", "formula_hash", "last_json",
    "made", "prefixes", "shop", "t", "write",
]  # fmt: skip

SRC = t.SRC
#: Eight variables with a five-variable unsatisfiable core: with ``max_free: 3`` the root and
#: four children need a split, sixteen grandchildren are refuted.
DEEP = t.unsat(8, core=5)
SHALLOW = t.unsat(5)


def write(path: Path, document: Any) -> Path:
    """A canonical JSON document file (J plus LF)."""
    path.write_bytes(document_bytes(document))
    return path


def formula_hash(shop: Shop, name: str) -> str:
    """The formula hash of the bundle ``name`` of a shop."""
    return hashlib.sha256((shop.root / "bundles" / name / "formula.cnf").read_bytes()).hexdigest()


def prefixes(entries: Sequence[tuple[str, Sequence[int], Sequence[int]]]) -> dict[str, Any]:
    """A prefixes document sorted by split_id from ``(formula hash, cube, W)`` triples."""
    ordered = sorted(entries, key=lambda e: split_id(node_id(e[0], list(e[1])), list(e[2])))
    splits = [
        {
            "node": {"formula_sha256": f, "cube": list(cube)},
            "variables": list(w),
            "splitter": {"name": "static", "info": {"order": list(w), "prefix": len(w)}},
        }
        for f, cube, w in ordered
    ]
    return {"format": "cubeproof-prefixes-1", "splits": splits}


@dataclass(frozen=True)
class Done:
    code: int
    out: str
    err: str


def command(*args: str, cwd: Path | None = None, timeout: float = 240.0) -> Done:
    """``python -m cubeproof ARGS`` in a child process with a minimal environment."""
    done = subprocess.run(
        [sys.executable, "-m", "cubeproof", *args],
        env={"PYTHONPATH": str(SRC), "PATH": "/usr/bin:/bin"},
        capture_output=True,
        text=True,
        cwd=cwd,
        timeout=timeout,
        check=False,
    )
    return Done(done.returncode, done.stdout, done.stderr)


def cli_main(args: Sequence[str], capsys: Any) -> Done:
    """The parser and handlers in this process: exit code, standard output and error."""
    capsys.readouterr()
    previous = os.environ.get("PYTHONPATH")
    # child processes of an in-process run (the I/O service) must find the package source
    os.environ["PYTHONPATH"] = str(SRC) if not previous else f"{SRC}{os.pathsep}{previous}"
    try:
        code = cli.main(list(args))
    finally:
        if previous is None:
            del os.environ["PYTHONPATH"]
        else:
            os.environ["PYTHONPATH"] = previous
    captured = capsys.readouterr()
    return Done(code, captured.out, captured.err)


def last_json(text: str) -> Any:
    return json.loads(text.strip().splitlines()[-1])


@dataclass
class Shop:
    """Bundles, policy, admit file, tools and a campaign below ``root``."""

    root: Path
    tools: t.Tools

    @property
    def campaign(self) -> Path:
        return self.root / "campaign.json"

    @property
    def results(self) -> Path:
        return self.root / "results"

    @property
    def journal(self) -> Path:
        return self.results / "journal.jsonl"

    def bundle(
        self, name: str, formula: bytes, pools: Mapping[str, Sequence[int]] | None = None
    ) -> Path:
        target = self.root / "bundles" / name
        publish_bundle(
            target,
            formula,
            pools=dict(pools or {}),
            producer={"name": "cli-tests", "version": "1", "parameters": {}},
        )
        return target

    def write_policy(self, policy: Policy | None = None) -> Path:
        path = self.root / "policy.json"
        path.write_bytes(document_bytes((policy or t.split_policy()).to_json()))
        return path

    def write_admit(self) -> Path:
        checker = PinnedBinary.measure(str(self.tools.checker)).sha256
        admit = Admit.from_json({"checker_sha256": [checker], "solvers": None}, "$")
        path = self.root / "admit.json"
        path.write_bytes(document_bytes(admit.to_json()))
        return path

    def create_args(self, *bundles: Path, more: Sequence[str] = ()) -> list[str]:
        return [
            "campaign", "create",
            *(a for b in bundles for a in ("--bundle", str(b))),
            "--policy", str(self.write_policy()),
            "--admit", str(self.write_admit()),
            "--solver", str(self.tools.solver),
            "--solver-argv", '["--lrat"]',
            "--checker", str(self.tools.checker),
            *more,
            "-o", str(self.campaign),
        ]  # fmt: skip

    def run_args(self, *more: str, worker: str = "w1", results: Path | None = None) -> list[str]:
        return [
            "run", "--campaign", str(self.campaign),
            "--results", str(results or self.results),
            "--work", str(self.root / f"work-{worker}"),
            "--worker", worker,
            "--solver", str(self.tools.solver),
            "--checker", str(self.tools.checker),
            *more,
        ]  # fmt: skip


def shop(
    root: Path, formulas: Mapping[str, bytes], *, solver: Mapping[str, Any] | None = None
) -> Shop:
    """Tools and bundles; the campaign file is made by ``campaign create``."""
    root.mkdir(parents=True, exist_ok=True)
    s = Shop(root, t.install(root / "tools", solver=solver))
    for name, data in sorted(formulas.items()):
        s.bundle(name, data)
    return s


def made(
    root: Path, formulas: Mapping[str, bytes], *, solver: Mapping[str, Any] | None = None
) -> Shop:
    """:func:`shop` and the campaign over all of its bundles (through the command)."""
    s = shop(root, formulas, solver=solver)
    done = command(*s.create_args(*(root / "bundles" / n for n in sorted(formulas))))
    assert done.code == 0, done.err
    return s
