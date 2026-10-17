"""The measured machinery of a header/resume (specification §4.6; writer.machinery).

Binary hashes identify the actual regular files; the source manifest is sorted, has
package-name prefixes, includes runtime source and data and excludes bytecode and caches;
``packages_sha256``/``cubeproof_sha256`` hash J of the manifest and of its cubeproof entries.
The snapshot is checked against the journal schema value (an independent reader).
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

import pytest
from cp_tools_support import (  # noqa: F401 - the two fixtures are registered by import
    fk,
    isolation_fixture,
    linux_only,
    make_binary,
    supervisor_fixture,
)

from cubeproof.base.canonical_json import json_sha256
from cubeproof.base.errors import ToolError
from cubeproof.evidence.schema import values as schema
from cubeproof.tools import machinery as mc
from cubeproof.tools.process import Supervisor


def package(root: Path, name: str, files: dict[str, bytes]) -> Path:
    base = root / name
    for relative, data in files.items():
        target = base / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    return base


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def test_manifest_is_sorted_prefixed_and_excludes_bytecode(tmp_path: Path) -> None:
    cube = package(
        tmp_path / "a",
        "cubeproof",
        {
            "__init__.py": b"",
            "tools/checker.py": b"x = 1\n",
            "tools/__pycache__/checker.cpython-312.pyc": b"\0",
            "stale.pyc": b"\0",
            "old.pyo": b"\0",
            "py.typed": b"",
            "data/table.json": b"{}\n",
        },
    )
    other = package(tmp_path / "b", "neighbourly", {"__init__.py": b"#\n"})
    manifest = mc.source_manifest({"cubeproof": cube, "neighbourly": other})
    assert manifest == (
        {"path": "cubeproof/__init__.py", "sha256": sha(b"")},
        {"path": "cubeproof/data/table.json", "sha256": sha(b"{}\n")},
        {"path": "cubeproof/py.typed", "sha256": sha(b"")},
        {"path": "cubeproof/tools/checker.py", "sha256": sha(b"x = 1\n")},
        {"path": "neighbourly/__init__.py", "sha256": sha(b"#\n")},
    )
    packages, own = mc.manifest_digests(manifest)
    assert packages == json_sha256(list(manifest))
    assert own == json_sha256([e for e in manifest if e["path"].startswith("cubeproof/")])


def test_manifest_order_is_by_path_string(tmp_path: Path) -> None:
    root = package(tmp_path, "cubeproof", {"a_b.py": b"", "a/b.py": b"", "A.py": b""})
    paths = [e["path"] for e in mc.source_manifest({"cubeproof": root})]
    assert paths == sorted(paths) == ["cubeproof/A.py", "cubeproof/a/b.py", "cubeproof/a_b.py"]


@pytest.mark.parametrize(
    "problem", ["symlink", "dirlink", "fifo", "backslash", "name", "unlistable"]
)
def test_manifest_refuses_unusual_entries(tmp_path: Path, problem: str) -> None:
    root = package(tmp_path, "cubeproof", {"__init__.py": b"", "sub/m.py": b""})
    roots = {"cubeproof": root}
    if problem == "symlink":
        (root / "link.py").symlink_to(root / "__init__.py")
    elif problem == "dirlink":  # os.walk would neither descend nor report it
        (root / "linked").symlink_to(root / "sub", target_is_directory=True)
    elif problem == "fifo":
        os.mkfifo(root / "pipe")
    elif problem == "backslash":
        (root / "a\\b.py").write_bytes(b"")
    elif problem == "unlistable":
        (root / "sub").chmod(0)
        if os.access(root / "sub", os.R_OK):
            pytest.skip("running with privileges that ignore directory permissions")
    else:
        roots = {"../x": root}
    try:
        with pytest.raises(ToolError):
            mc.source_manifest(roots)
    finally:
        (root / "sub").chmod(0o755)


def test_manifest_changes_are_detected(tmp_path: Path) -> None:
    root = package(tmp_path, "cubeproof", {"__init__.py": b"", "m.py": b"1\n"})
    manifest = mc.source_manifest({"cubeproof": root})
    mc.verify_manifest(manifest, {"cubeproof": root})
    (root / "m.py").write_bytes(b"2\n")
    with pytest.raises(ToolError) as caught:
        mc.verify_manifest(manifest, {"cubeproof": root})
    assert caught.value.rule == "source_changed"
    (root / "m.py").write_bytes(b"1\n")
    (root / "new.py").write_bytes(b"")
    with pytest.raises(ToolError):
        mc.verify_manifest(manifest, {"cubeproof": root})


def test_the_installed_cubeproof_is_found() -> None:
    root = mc.package_root("cubeproof")
    assert (root / "tools" / "checker.py").is_file()
    manifest = mc.source_manifest({"cubeproof": root})
    assert {"cubeproof/tools/checker.py", "cubeproof/py.typed"} <= {e["path"] for e in manifest}


def test_runtime_info() -> None:
    info = mc.runtime_info(image_digest=None)
    assert set(info) == {"python", "libc", "platform", "image_digest"}
    assert info["python"] and info["libc"] and info["platform"]
    assert info["image_digest"] is None
    assert (
        mc.runtime_info(image_digest="sha256:" + "a" * 64)["image_digest"] == "sha256:" + "a" * 64
    )


@linux_only
def test_snapshot_is_a_valid_journal_machinery(supervisor: Supervisor, tmp_path: Path) -> None:
    _, solver = make_binary(tmp_path, "cadical", [fk.write(fk.STDOUT, "3.0.1\n"), fk.exit_(0)])
    _, checker = make_binary(tmp_path, "cake_lpr", [fk.exit_(0)])
    version = mc.solver_version(supervisor, solver, str(tmp_path))
    assert version == "3.0.1"
    root = package(tmp_path / "src", "cubeproof", {"__init__.py": b"", "m.py": b"1\n"})
    manifest = mc.source_manifest({"cubeproof": root})
    snapshot = mc.snapshot(
        solver=solver,
        solver_argv=("--lrat", "-q"),
        solver_version=version,
        checker=checker,
        helper=None,
        manifest=manifest,
        runtime=mc.runtime_info(image_digest=None),
    )
    parsed = schema.Machinery.from_json(snapshot)
    assert parsed.to_json() == snapshot
    assert snapshot["solver"] == {
        "path": solver.path,
        "sha256": solver.sha256,
        "version": "3.0.1",
        "argv": ["--lrat", "-q"],
    }
    assert snapshot["checker"] == {"path": checker.path, "sha256": checker.sha256}
    assert snapshot["unit_algorithm"] == "unit-v1"
    with_helper = mc.snapshot(
        solver=solver,
        solver_argv=("--lrat",),
        solver_version=version,
        checker=checker,
        helper=("b" * 64, "lookahead-v1"),
        manifest=manifest,
        runtime=mc.runtime_info(image_digest=None),
    )
    assert with_helper["helper"] == {"sha256": "b" * 64, "algorithm": "lookahead-v1"}
    schema.Machinery.from_json(with_helper)


def test_snapshot_refuses_denied_solver_argv(tmp_path: Path) -> None:
    from cubeproof.base.errors import InputError

    tool = fk.make_tool(tmp_path, "cadical", [fk.exit_(0)])
    from cubeproof.tools.isolation import PinnedBinary

    binary = PinnedBinary.measure(str(tool.path))
    with pytest.raises(InputError):
        mc.snapshot(
            solver=binary,
            solver_argv=("--lrat", "-t"),
            solver_version="3.0.1",
            checker=binary,
            helper=None,
            manifest=(),
            runtime=mc.runtime_info(image_digest=None),
        )


@linux_only
@pytest.mark.parametrize(
    "steps",
    [
        [fk.write(fk.STDOUT, "3.0.1\n"), fk.exit_(1)],
        [fk.exit_(0)],
        [fk.write(fk.STDOUT, "\n\n"), fk.exit_(0)],
        [fk.kill_self("SEGV")],
    ],
    ids=["exit1", "empty", "blank", "signal"],
)
def test_a_failing_version_probe_is_a_tool_error(
    supervisor: Supervisor, tmp_path: Path, steps: list[dict[str, object]]
) -> None:
    tool, solver = make_binary(tmp_path, "cadical", steps)
    with pytest.raises(ToolError):
        mc.solver_version(supervisor, solver, str(tmp_path))
    assert tool.calls()[0]["argv"] == ["--version"]
