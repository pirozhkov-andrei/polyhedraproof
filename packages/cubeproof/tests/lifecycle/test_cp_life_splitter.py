"""Specification §9.1, §9.3, §8.1: the splitter inside the run, with a native helper, a failing one
and none.

The run starts the helper as a supervised process of its own (a splitter task never blocks the
loop); a helper that fails in any way is answered by the lowest eligible variables, recorded in
the split's info (never a verdict, never a stopped run). Without a helper the Python reference
of lookahead-v1 runs in slices.
"""

from __future__ import annotations

import importlib.util
import shutil
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import cp_life_tools as t
import pytest

from cubeproof.base.settings import ToolPaths
from cubeproof.cnf.campaign import load_campaign
from cubeproof.split.choice import Budget, lowest_eligible_choice
from cubeproof.split.lookahead import lookahead

DEEP = t.unsat(8, core=5)
NATIVE = Path(__file__).resolve().parents[2] / "native"


def build_module() -> ModuleType:
    spec = importlib.util.spec_from_file_location("cubeproof_look_build_c20", NATIVE / "build.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def world(tmp_path: Path) -> t.World:
    return t.make_world(tmp_path, {"f": DEEP}, solver={"max_free": 3})


def helper_tools(w: t.World, helper: Path) -> ToolPaths:
    return ToolPaths(solver=str(w.tools.solver), checker=str(w.tools.checker), helper=str(helper))


def fake_helper(directory: Path, behaviour: str) -> Path:
    """An executable that answers ``--version`` like the helper and then does ``behaviour``."""
    path = directory / "cubeproof-look"
    path.write_text(
        f"#!{sys.executable} -I\n"
        "import sys\n"
        "if sys.argv[1:] == ['--version']:\n"
        "    print('cubeproof-look 1 fake')\n"
        "    raise SystemExit(0)\n"
        f"{behaviour}\n",
        encoding="utf-8",
    )
    path.chmod(0o755)
    return path


@pytest.mark.skipif(shutil.which("cc") is None, reason="no C compiler")
def test_the_native_helper_chooses_what_the_reference_chooses(tmp_path: Path) -> None:
    build = build_module()
    out = tmp_path / "helper-build"
    build.build("cc", out, list(build.RELEASE_FLAGS))
    w = world(tmp_path)
    result = w.run(tools=helper_tools(w, out / "cubeproof-look"))
    assert result.exit_code == 0 and w.summary()["verdict"] == "PROVED"
    header = w.records("header")[0]
    assert header["machinery"]["helper"]["algorithm"] == "lookahead-v1"
    splits = w.records("split")
    assert len(splits) == 5
    (bundle,) = load_campaign(w.campaign).bundles.values()
    for record in splits:
        info = record["splitter"]["info"]
        assert info["implementation"] == "helper"
        assert info["helper"]["sha256"] == header["machinery"]["helper"]["sha256"]
        cube = tuple(record["node"]["cube"])
        choice = lookahead(bundle.formula, cube, 2, None, Budget(probe_limit=100_000))
        assert tuple(record["variables"]) == choice.variables


@pytest.mark.parametrize(
    "behaviour",
    [
        "raise SystemExit(3)",
        "print('not a document'); raise SystemExit(0)",
        "print('{}'); raise SystemExit(0)",
        "import os, signal; os.kill(os.getpid(), signal.SIGSEGV)",
    ],
    ids=["bad exit", "not a document", "wrong document", "crash"],
)
def test_a_failing_helper_is_answered_by_the_lowest_eligible_variables(
    tmp_path: Path, behaviour: str
) -> None:
    w = world(tmp_path)
    helper = fake_helper(tmp_path, behaviour)
    result = w.run(tools=helper_tools(w, helper))
    assert result.exit_code == 0 and w.summary()["verdict"] == "PROVED"
    assert w.records("header")[0]["machinery"]["helper"] is not None
    (bundle,) = load_campaign(w.campaign).bundles.values()
    splits = w.records("split")
    assert len(splits) == 5
    for record in splits:
        splitter = record["splitter"]
        assert splitter["name"] == "lowest-eligible"
        info: dict[str, Any] = splitter["info"]
        assert info["implementation"] == "fallback-lowest-eligible"
        assert info["fallback"]["reason"] == "helper_failure"
        assert info["fallback"]["rule"].startswith("split.helper")
        cube = tuple(record["node"]["cube"])
        expected = lowest_eligible_choice(bundle.formula, cube, 2, None, reason="x")
        assert tuple(record["variables"]) == expected.variables
    assert w.work_files() == []  # request files of the helper are removed


def test_an_unusable_helper_is_not_used_and_the_run_says_so(tmp_path: Path) -> None:
    w = world(tmp_path)
    result = w.run(tools=helper_tools(w, tmp_path / "nowhere"))
    assert result.exit_code == 0
    assert w.records("header")[0]["machinery"]["helper"] is None
    assert any(n.startswith("helper not used") for n in result.notes)
    assert {r["splitter"]["info"]["implementation"] for r in w.records("split")} == {
        "python-reference"
    }
