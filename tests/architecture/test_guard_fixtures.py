"""The architecture guard against deliberately invalid packages.

Each case writes a small package tree that breaks exactly one rule and checks that the guard
reports that rule and only the rules the case implies. A valid tree that uses every allowed
edge must produce no finding, so the guard is neither blind nor indiscriminate.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import pytest

from archcheck import (
    LAYER_TABLES,
    SEALED,
    Distribution,
    Violation,
    check_distribution,
    check_standalone,
)

REQUIRES = {
    "cubeproof": frozenset(),
    "neighbourly": frozenset(),
    "faces12_campaign": frozenset({"cubeproof", "neighbourly"}),
}
ROOTS = {
    "cubeproof": {"cubeproof/__init__.py": "", "cubeproof/evidence/__init__.py": ""},
    "neighbourly": {"neighbourly/__init__.py": "", "neighbourly/cnf/__init__.py": ""},
    "faces12_campaign": {"faces12_campaign/__init__.py": ""},
}


@dataclass(frozen=True)
class Case:
    id: str
    top: str
    files: dict[str, str]
    rules: frozenset[str]
    module: str
    mentions: str = ""
    extra: dict[str, str] = field(default_factory=dict)


def check_tree(tmp_path: Path, top: str, files: dict[str, str]) -> list[Violation]:
    src = tmp_path / "src"
    for relative, text in {**ROOTS[top], **files}.items():
        path = src / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    dist = Distribution(
        name=top.replace("_", "-"),
        top=top,
        src=src,
        requires=REQUIRES[top],
        layers=LAYER_TABLES[top],
        sealed=SEALED.get(top, ()),
    )
    return check_distribution(dist)


CASES = [
    Case(
        "cubeproof-imports-neighbourly",
        "cubeproof",
        {"cubeproof/base/__init__.py": "import neighbourly\n"},
        frozenset({"DIST"}),
        "cubeproof.base",
        "neighbourly",
    ),
    Case(
        "third-party-runtime-dependency",
        "neighbourly",
        {"neighbourly/maps.py": "import numpy\n"},
        frozenset({"DIST"}),
        "neighbourly.maps",
        "numpy",
    ),
    Case(
        "application-imports-an-undeclared-distribution",
        "faces12_campaign",
        {"faces12_campaign/campaign.py": "from otherdist.spec import LAYERS\n"},
        frozenset({"DIST"}),
        "faces12_campaign.campaign",
        "otherdist.spec",
    ),
    Case(
        "module-outside-every-layer",
        "cubeproof",
        {"cubeproof/misc.py": "VALUE = 1\n"},
        frozenset({"UNKNOWN"}),
        "cubeproof.misc",
    ),
    Case(
        "contracts-import-tools",
        "cubeproof",
        {
            "cubeproof/contracts/__init__.py": "from cubeproof.tools import run\n",
            "cubeproof/tools/__init__.py": "def run() -> None: ...\n",
        },
        frozenset({"LAYER"}),
        "cubeproof.contracts",
        "cubeproof.tools",
    ),
    Case(
        "relative-import-upward",
        "cubeproof",
        {
            "cubeproof/contracts/__init__.py": "from ..tools import run\n",
            "cubeproof/tools/__init__.py": "def run() -> None: ...\n",
        },
        frozenset({"LAYER"}),
        "cubeproof.contracts",
        "cubeproof.tools",
    ),
    Case(
        "leaf-imports-split-of-the-same-layer",
        "cubeproof",
        {
            "cubeproof/leaf/__init__.py": "from cubeproof.split import plan\n",
            "cubeproof/split/__init__.py": "def plan() -> None: ...\n",
        },
        frozenset({"LAYER"}),
        "cubeproof.leaf",
        "cubeproof.split",
    ),
    Case(
        "certifier-imports-tools",
        "cubeproof",
        {
            "cubeproof/evidence/certify.py": "from cubeproof.tools.checker import accept\n",
            "cubeproof/tools/__init__.py": "",
            "cubeproof/tools/checker.py": "def accept() -> None: ...\n",
        },
        frozenset({"LAYER"}),
        "cubeproof.evidence.certify",
        "cubeproof.tools.checker",
    ),
    Case(
        "certifier-imports-the-coordinator",
        "cubeproof",
        {
            "cubeproof/evidence/certify.py": "import cubeproof.coordinator.cache\n",
            "cubeproof/coordinator/__init__.py": "",
            "cubeproof/coordinator/cache.py": "",
        },
        frozenset({"LAYER"}),
        "cubeproof.evidence.certify",
        "cubeproof.coordinator",
    ),
    Case(
        "certifier-reaches-tools-through-the-package-root",
        "cubeproof",
        {
            "cubeproof/__init__.py": "import cubeproof.tools\n",
            "cubeproof/tools/__init__.py": "",
            "cubeproof/evidence/certify.py": "from cubeproof.evidence.schema import Record\n",
            "cubeproof/evidence/schema.py": "class Record: ...\n",
        },
        # the root's own import is a direct finding; every lower module that runs the root
        # reaches tools transitively
        frozenset({"LAYER", "TRANSITIVE"}),
        "cubeproof.evidence.certify",
        "cubeproof.tools",
    ),
    Case(
        "certifier-reaches-a-process-probe-through-base",
        "cubeproof",
        {
            "cubeproof/evidence/certify.py": "from cubeproof.base.hashing import digest\n",
            "cubeproof/base/__init__.py": "",
            "cubeproof/base/hashing.py": "from cubeproof.base.probe import cpus\n"
            "def digest() -> None: ...\n",
            "cubeproof/base/probe.py": "import subprocess\ndef cpus() -> None: ...\n",
        },
        frozenset({"PURE"}),
        "cubeproof.evidence.certify",
        "subprocess",
    ),
    Case(
        "cnf-starts-a-thread",
        "cubeproof",
        {"cubeproof/cnf/__init__.py": "from threading import Thread\n"},
        frozenset({"PURE"}),
        "cubeproof.cnf",
        "threading",
    ),
    Case(
        "certifier-forks",
        "cubeproof",
        {"cubeproof/evidence/certify.py": "import os\ndef split() -> None:\n    os.fork()\n"},
        frozenset({"PURE"}),
        "cubeproof.evidence.certify",
        "os.fork",
    ),
    Case(
        "cnf-runs-a-shell-command",
        "cubeproof",
        {"cubeproof/cnf/__init__.py": "import os\nos.system('true')\n"},
        frozenset({"PURE"}),
        "cubeproof.cnf",
        "os.system",
    ),
    Case(
        "contracts-keep-a-pipe-opener-under-an-alias",
        "cubeproof",
        {"cubeproof/contracts/__init__.py": "from os import popen\nOPEN = popen\n"},
        frozenset({"PURE"}),
        "cubeproof.contracts",
        "os.popen",
    ),
    Case(
        "journal-signals-a-process",
        "cubeproof",
        {
            "cubeproof/evidence/journal.py": "import os\n"
            "def stop(pid: int) -> None:\n    os.kill(pid, 9)\n"
        },
        frozenset({"PURE"}),
        "cubeproof.evidence.journal",
        "os.kill",
    ),
    Case(
        "certifier-reaches-exec-through-base",
        "cubeproof",
        {
            "cubeproof/evidence/certify.py": "from cubeproof.base.hashing import digest\n",
            "cubeproof/base/__init__.py": "",
            "cubeproof/base/hashing.py": "import os\n"
            "def digest() -> None:\n    os.execv('/bin/true', ['true'])\n",
        },
        frozenset({"PURE"}),
        "cubeproof.evidence.certify",
        "os.execv",
    ),
    Case(
        "leaf-writes-to-stdout",
        "cubeproof",
        {
            "cubeproof/leaf/__init__.py": "import sys\n"
            "def say() -> None:\n    sys.stdout.write('x')\n"
        },
        frozenset({"OUTPUT"}),
        "cubeproof.leaf",
        "sys.stdout.write",
    ),
    Case(
        "maps-write-to-stderr-through-an-alias",
        "neighbourly",
        {
            "neighbourly/maps.py": "from sys import stderr\n"
            "def warn() -> None:\n    stderr.write('x')\n"
        },
        frozenset({"OUTPUT"}),
        "neighbourly.maps",
        "sys.stderr.write",
    ),
    Case(
        "import-cycle",
        "cubeproof",
        {
            "cubeproof/base/__init__.py": "",
            "cubeproof/base/a.py": "from cubeproof.base import b\n",
            "cubeproof/base/b.py": "from cubeproof.base import a\n",
        },
        frozenset({"CYCLE"}),
        "cubeproof.base.a",
        "cubeproof.base.b",
    ),
    Case(
        "import-by-computed-name",
        "cubeproof",
        {
            "cubeproof/base/__init__.py": "import importlib\nNAME = 'x'\n"
            "importlib.import_module(NAME)\n"
        },
        frozenset({"DYNAMIC"}),
        "cubeproof.base",
        "importlib.import_module",
    ),
    Case(
        "import-by-constant-name-cannot-hide-an-upward-edge",
        "cubeproof",
        {
            "cubeproof/contracts/__init__.py": "from importlib import import_module\n"
            "TOOLS = import_module('cubeproof.tools')\n",
            "cubeproof/tools/__init__.py": "",
        },
        frozenset({"LAYER"}),
        "cubeproof.contracts",
        "cubeproof.tools",
    ),
    Case(
        "code-executed-from-a-string",
        "cubeproof",
        {"cubeproof/base/__init__.py": "exec('import subprocess')\n"},
        frozenset({"DYNAMIC"}),
        "cubeproof.base",
        "exec",
    ),
    Case(
        "relative-import-beyond-the-top-level",
        "cubeproof",
        {"cubeproof/base/__init__.py": "from ... import outside\n"},
        frozenset({"IMPORT"}),
        "cubeproof.base",
    ),
    Case(
        "commands-read-the-environment",
        "cubeproof",
        {"cubeproof/commands/__init__.py": "import os\nHOME = os.environ.get('HOME')\n"},
        frozenset({"ENV"}),
        "cubeproof.commands",
        "os.environ",
    ),
    Case(
        "leaf-reads-the-environment-through-an-alias",
        "cubeproof",
        {"cubeproof/leaf/__init__.py": "from os import getenv as ge\nVALUE = ge('X')\n"},
        frozenset({"ENV"}),
        "cubeproof.leaf",
        "os.getenv",
    ),
    Case(
        "api-reads-the-environment",
        "cubeproof",
        {"cubeproof/api/__init__.py": "import os\nVALUE = os.getenv('X')\n"},
        frozenset({"ENV"}),
        "cubeproof.api",
        "os.getenv",
    ),
    Case(
        "coordinator-reads-the-process-arguments",
        "cubeproof",
        {"cubeproof/coordinator/__init__.py": "import sys\nARGS = sys.argv[1:]\n"},
        frozenset({"ENV"}),
        "cubeproof.coordinator",
        "sys.argv",
    ),
    Case(
        "coordinator-prints",
        "cubeproof",
        {"cubeproof/coordinator/__init__.py": "def report() -> None:\n    print('done')\n"},
        frozenset({"OUTPUT"}),
        "cubeproof.coordinator",
        "print",
    ),
    Case(
        "api-exits",
        "cubeproof",
        {"cubeproof/api/__init__.py": "import sys\ndef run() -> None:\n    sys.exit(1)\n"},
        frozenset({"OUTPUT"}),
        "cubeproof.api",
        "sys.exit",
    ),
    Case(
        "library-raises-systemexit",
        "neighbourly",
        {"neighbourly/maps.py": "def load() -> None:\n    raise SystemExit(2)\n"},
        frozenset({"OUTPUT"}),
        "neighbourly.maps",
        "SystemExit",
    ),
    Case(
        "cnf-imports-maps",
        "neighbourly",
        {
            "neighbourly/cnf/builder.py": "from neighbourly.maps import Map\n",
            "neighbourly/maps.py": "class Map: ...\n",
        },
        frozenset({"SEALED"}),
        "neighbourly.cnf.builder",
        "neighbourly.maps",
    ),
    Case(
        "cnf-reaches-maps-through-a-sibling-module",
        "neighbourly",
        {
            "neighbourly/cnf/builder.py": "from neighbourly.cnf import dimacs\n",
            "neighbourly/cnf/dimacs.py": "import neighbourly.maps\n",
            "neighbourly/maps.py": "",
        },
        # dimacs imports maps directly; builder reaches it only through dimacs
        frozenset({"SEALED"}),
        "neighbourly.cnf.builder",
        "reaches neighbourly.maps",
    ),
    Case(
        "cnf-reaches-maps-through-the-package-root",
        "neighbourly",
        {
            "neighbourly/__init__.py": "from neighbourly import maps\n",
            "neighbourly/maps.py": "",
            "neighbourly/cnf/dimacs.py": "import io\n",
        },
        frozenset({"LAYER", "SEALED"}),
        "neighbourly.cnf.dimacs",
        "neighbourly.maps",
    ),
    Case(
        "cnf-imports-cubeproof",
        "neighbourly",
        {"neighbourly/cnf/bundle.py": "import cubeproof\n"},
        frozenset({"DIST"}),
        "neighbourly.cnf.bundle",
        "cubeproof",
    ),
    Case(
        "cnf-reads-package-data",
        "neighbourly",
        {"neighbourly/cnf/encodings.py": "from importlib import resources\n"},
        frozenset({"DATA"}),
        "neighbourly.cnf.encodings",
        "importlib.resources",
    ),
    Case(
        "cnf-locates-files-next-to-itself",
        "neighbourly",
        {"neighbourly/cnf/witness.py": "from pathlib import Path\nHERE = Path(__file__).parent\n"},
        frozenset({"DATA"}),
        "neighbourly.cnf.witness",
        "__file__",
    ),
    Case(
        "generic-encoding-imports-the-corpus",
        "neighbourly",
        {
            "neighbourly/encoding/__init__.py": "from neighbourly.corpus12 import MAPS\n",
            "neighbourly/corpus12.py": "MAPS = ()\n",
        },
        frozenset({"LAYER"}),
        "neighbourly.encoding",
        "neighbourly.corpus12",
    ),
    Case(
        "maps-import-the-encoding-above-them",
        "neighbourly",
        {
            "neighbourly/maps.py": "import neighbourly.encoding.formula\n",
            "neighbourly/encoding/__init__.py": "",
            "neighbourly/encoding/formula.py": "",
        },
        frozenset({"LAYER"}),
        "neighbourly.maps",
        "neighbourly.encoding.formula",
    ),
    Case(
        "adapter-imports-another-adapter",
        "faces12_campaign",
        {
            "faces12_campaign/claim.py": "from faces12_campaign.campaign import create\n",
            "faces12_campaign/campaign.py": "def create() -> None: ...\n",
        },
        frozenset({"LAYER"}),
        "faces12_campaign.claim",
        "faces12_campaign.campaign",
    ),
    Case(
        "adapter-imports-the-commands-above-it",
        "faces12_campaign",
        {
            "faces12_campaign/release.py": "import faces12_campaign.commands\n",
            "faces12_campaign/commands.py": "",
        },
        frozenset({"LAYER"}),
        "faces12_campaign.release",
        "faces12_campaign.commands",
    ),
]


@pytest.mark.parametrize("case", CASES, ids=[c.id for c in CASES])
def test_each_invalid_tree_fails_for_its_intended_reason(tmp_path: Path, case: Case) -> None:
    found = check_tree(tmp_path, case.top, case.files)
    assert {v.rule for v in found} == case.rules, "\n".join(map(str, found))
    primary = [v for v in found if v.module == case.module and v.rule in case.rules]
    assert primary, "\n".join(map(str, found))
    if case.mentions:
        assert any(case.mentions in v.detail for v in primary), "\n".join(map(str, found))


VALID_CUBEPROOF = {
    "cubeproof/__main__.py": "from cubeproof.cli import main\nmain()\n",
    "cubeproof/cli/__init__.py": "import os\nimport sys\nfrom cubeproof.commands import run\n"
    "def main() -> None:\n    print(os.environ.get('HOME'), sys.argv)\n"
    "    sys.stderr.write('x')\n    sys.exit(run())\n",
    "cubeproof/api/__init__.py": "from cubeproof.commands import run\n"
    "from cubeproof.contracts import V\n",
    "cubeproof/commands/__init__.py": "from cubeproof.coordinator import loop\n"
    "from cubeproof.evidence.certify import certify\n"
    "def run() -> int:\n    return 0\n",
    "cubeproof/coordinator/__init__.py": "import threading\nfrom cubeproof.leaf import attempt\n"
    "from cubeproof.split import plan\ndef loop() -> None: ...\n",
    "cubeproof/leaf/__init__.py": "from cubeproof.evidence.journal import append\n"
    "from cubeproof.evidence.schema import Record\nfrom cubeproof.tools import spawn\n"
    "def attempt() -> None: ...\n",
    "cubeproof/leaf/binding.py": "from . import attempt\n",
    "cubeproof/split/__init__.py": "from cubeproof.tools import spawn\ndef plan() -> None: ...\n",
    "cubeproof/evidence/certify/__init__.py": "from cubeproof.evidence.schema import Record\n"
    "from cubeproof.evidence.journal import read\nfrom cubeproof.cnf import Cube\n"
    "from cubeproof.base.hashing import digest\ndef certify() -> None: ...\n",
    "cubeproof/evidence/schema.py": "from cubeproof.contracts import V\nclass Record: ...\n",
    "cubeproof/evidence/journal.py": "import fcntl\nimport os\n"
    "from cubeproof.base.hashing import digest\n"
    "def read() -> None: ...\ndef append() -> None: ...\n",
    "cubeproof/tools/__init__.py": "import subprocess\nfrom cubeproof.base.process import cpus\n"
    "from cubeproof.cnf import Cube\ndef spawn() -> None: ...\n",
    "cubeproof/cnf/__init__.py": "from cubeproof.contracts import V\nclass Cube: ...\n",
    "cubeproof/contracts/__init__.py": "from cubeproof.base.hashing import digest\nV = 1\n",
    "cubeproof/base/__init__.py": "",
    "cubeproof/base/hashing.py": "import hashlib\ndef digest() -> None: ...\n",
    "cubeproof/base/process.py": "import os\nimport resource\nimport subprocess\n"
    "def cpus() -> None: ...\ndef stop(pid: int) -> None:\n    os.kill(pid, 9)\n",
}


def test_a_valid_tree_with_every_layer_has_no_finding(tmp_path: Path) -> None:
    assert check_tree(tmp_path, "cubeproof", VALID_CUBEPROOF) == []


def test_a_valid_neighbourly_tree_has_no_finding(tmp_path: Path) -> None:
    files = {
        "neighbourly/cnf/builder.py": "from neighbourly.cnf import witness\n",
        "neighbourly/cnf/witness.py": "import typing\n",
        "neighbourly/maps.py": "from neighbourly.cnf.builder import witness\n",
        "neighbourly/exact/__init__.py": "from neighbourly.maps import *\n",
        "neighbourly/geometry.py": "from neighbourly.exact import *\n",
        "neighbourly/encoding/__init__.py": "",
        "neighbourly/encoding/formula.py": "from neighbourly.encoding import chirotope\n"
        "from neighbourly.cnf import builder\nfrom neighbourly import maps\n",
        "neighbourly/encoding/chirotope.py": "",
        "neighbourly/corpus12.py": "from importlib import resources\n"
        "from neighbourly.encoding import formula\n",
        "neighbourly/interpret.py": "from neighbourly.encoding import formula\n"
        "from neighbourly.exact import *\n",
    }
    assert check_tree(tmp_path, "neighbourly", files) == []


def test_a_valid_application_tree_has_no_finding(tmp_path: Path) -> None:
    files = {
        "faces12_campaign/cli.py": "import os\nfrom faces12_campaign.commands import run\n"
        "def main() -> None:\n    raise SystemExit(run(os.environ.get('X')))\n",
        "faces12_campaign/commands.py": "from faces12_campaign import campaign, claim\n"
        "def run(x: object) -> int:\n    return 0\n",
        "faces12_campaign/campaign.py": "import cubeproof\nimport neighbourly.cnf\n",
        "faces12_campaign/claim.py": "from cubeproof import api\n",
    }
    assert check_tree(tmp_path, "faces12_campaign", files) == []


def test_the_independent_certifier_may_import_only_the_standard_library(tmp_path: Path) -> None:
    good = tmp_path / "certify_min.py"
    good.write_text("import hashlib\nimport json\n", encoding="utf-8")
    assert check_standalone(good, "tools/certify_min.py") == []
    bad = tmp_path / "bad" / "certify_min.py"
    bad.parent.mkdir()
    bad.write_text("import json\nfrom cubeproof.evidence import certify\n", encoding="utf-8")
    found = check_standalone(bad, "tools/certify_min.py")
    assert {v.rule for v in found} == {"INDEPENDENT"}
    assert "cubeproof.evidence" in found[0].detail


def test_the_spec_vector_generator_may_import_its_own_modules(tmp_path: Path) -> None:
    tool = tmp_path / "spec_vectors"
    tool.mkdir()
    (tool / "__init__.py").write_text("", encoding="utf-8")
    (tool / "hashes.py").write_text("import hashlib\n", encoding="utf-8")
    (tool / "generate.py").write_text(
        "import hashes\nfrom spec_vectors import hashes as h\nfrom . import hashes as g\n",
        encoding="utf-8",
    )
    assert check_standalone(tool, "tools/spec_vectors") == []
    (tool / "leak.py").write_text("import neighbourly.cnf\n", encoding="utf-8")
    found = check_standalone(tool, "tools/spec_vectors")
    assert [(v.rule, v.module) for v in found] == [("INDEPENDENT", "tools/spec_vectors/leak.py")]
