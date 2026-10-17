"""Work files of one attempt (specification §6.1 stages 1-3, 5): CNF(F, C), unit proofs, sealing."""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest
from cp_leaf_support import SAT, TINY, formula, sha

from cubeproof.cnf.cubecnf import cube_cnf_bytes
from cubeproof.cnf.model import drive
from cubeproof.contracts.identity import node_id
from cubeproof.leaf.files import (
    absent,
    regular_file,
    seal,
    work_paths,
    write_cnf_steps,
    write_new_file,
)


def test_work_paths_name_node_and_attempt(tmp_path: Path) -> None:
    nid = node_id(TINY.sha256, (3,))
    cnf, proof = work_paths(str(tmp_path), nid, "ab" * 16)
    assert cnf == f"{tmp_path}/{nid}-{'ab' * 16}.cnf"
    assert proof == f"{tmp_path}/{nid}-{'ab' * 16}.lrat"


@pytest.mark.parametrize("cube", [(), (3,), (-1, 2, 3)])
@pytest.mark.parametrize("chunk", [1, 7, 4096])
def test_the_cnf_is_exactly_cnf_of_the_node_and_hashed_as_written(
    tmp_path: Path, cube: tuple[int, ...], chunk: int
) -> None:
    path = tmp_path / "n.cnf"
    size, digest = drive(write_cnf_steps(TINY, cube, str(path), chunk=chunk))
    data = cube_cnf_bytes(TINY, cube)
    assert path.read_bytes() == data
    assert (size, digest) == (len(data), sha(data))
    assert stat.S_IMODE(path.stat().st_mode) & 0o222 == 0


def test_the_writer_yields_between_chunks(tmp_path: Path) -> None:
    f = formula(50, [(i, -(i + 1)) for i in range(1, 50)])
    steps = write_cnf_steps(f, (1,), str(tmp_path / "n.cnf"), chunk=16)
    count = 0
    try:
        while True:
            next(steps)
            count += 1
    except StopIteration:
        pass
    assert count >= len(cube_cnf_bytes(f, (1,))) // 16 - 1


@pytest.mark.parametrize("existing", ["file", "symlink", "dangling"])
def test_the_cnf_is_never_written_through_an_existing_name(tmp_path: Path, existing: str) -> None:
    path = tmp_path / "n.cnf"
    target = tmp_path / "target"
    if existing == "file":
        path.write_bytes(b"old")
    else:
        if existing == "symlink":
            target.write_bytes(b"old")
        path.symlink_to(target)
    with pytest.raises(OSError):
        drive(write_cnf_steps(SAT, (), str(path), chunk=4096))
    if existing != "dangling":
        assert (target if existing == "symlink" else path).read_bytes() == b"old"
    else:
        assert not target.exists()


def test_a_small_new_file(tmp_path: Path) -> None:
    path = tmp_path / "p.lrat"
    assert write_new_file(str(path), b"5 0 1 2 0\n") == (10, sha(b"5 0 1 2 0\n"))
    with pytest.raises(OSError):
        write_new_file(str(path), b"x")
    assert path.read_bytes() == b"5 0 1 2 0\n"


def test_sealing_makes_a_regular_file_read_only_and_measures_it(tmp_path: Path) -> None:
    path = tmp_path / "p.lrat"
    path.write_bytes(b"12345")
    os.chmod(path, 0o644)
    assert seal(str(path)) == 5
    assert stat.S_IMODE(path.stat().st_mode) & 0o222 == 0
    assert regular_file(str(path)) and not absent(str(path))


@pytest.mark.parametrize("kind", ["missing", "directory", "symlink", "fifo"])
def test_sealing_refuses_anything_but_a_regular_file(tmp_path: Path, kind: str) -> None:
    path = tmp_path / "p.lrat"
    if kind == "directory":
        path.mkdir()
    elif kind == "symlink":
        (tmp_path / "real").write_bytes(b"x")
        path.symlink_to(tmp_path / "real")
    elif kind == "fifo":
        os.mkfifo(path)
    with pytest.raises(OSError):
        seal(str(path))
    assert not regular_file(str(path))
    assert absent(str(path)) is (kind == "missing")
    if kind == "symlink":
        assert stat.S_IMODE((tmp_path / "real").stat().st_mode) & 0o200
