"""Path containment for relative artifact and bundle paths (specification §4.1, requirement
path.containment)."""

from __future__ import annotations

import io
import os
import sys
from pathlib import Path

import pytest

from cubeproof.base.errors import ContractError
from cubeproof.base.ids import new_id128
from cubeproof.base.paths import (
    contained_file,
    open_contained,
    open_regular_file,
    read_at_most,
    split_relpath,
)

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "contracts"))
import cp_corpus

RELPATHS = cp_corpus.vectors("primitives")["primitives"]["RelPath"]


def _tree(root: Path) -> None:
    (root / "a" / "b").mkdir(parents=True)
    (root / "a" / "b" / "f.txt").write_bytes(b"data")
    (root / "top.txt").write_bytes(b"top")


@pytest.mark.parametrize("text", list(RELPATHS["valid"]))
def test_split_relpath_accepts_valid_relpaths(text: str) -> None:
    assert "/".join(split_relpath(text)) == text


@pytest.mark.parametrize("text", list(RELPATHS["invalid"]), ids=repr)
def test_split_relpath_refuses_invalid_relpaths(text: object) -> None:
    with pytest.raises(ContractError) as info:
        split_relpath(text)  # type: ignore[arg-type]
    assert info.value.rule == "path.containment"


def test_contained_regular_files_are_found(tmp_path: Path) -> None:
    _tree(tmp_path)
    assert contained_file(tmp_path, "a/b/f.txt") == tmp_path / "a" / "b" / "f.txt"
    assert contained_file(tmp_path, "top.txt") == tmp_path / "top.txt"
    with open_contained(tmp_path, "a/b/f.txt") as stream:
        assert stream.read() == b"data"


def test_a_symlinked_directory_component_is_refused(tmp_path: Path) -> None:
    _tree(tmp_path)
    (tmp_path / "link").symlink_to(tmp_path / "a")
    with pytest.raises(ContractError) as info:
        contained_file(tmp_path, "link/b/f.txt")
    assert info.value.rule == "path.containment"
    with pytest.raises(ContractError):
        open_contained(tmp_path, "link/b/f.txt")


def test_a_symlinked_file_is_refused_even_inside_the_root(tmp_path: Path) -> None:
    _tree(tmp_path)
    (tmp_path / "alias.txt").symlink_to(tmp_path / "top.txt")
    for call in (contained_file, open_contained):
        with pytest.raises(ContractError) as info:
            call(tmp_path, "alias.txt")
        assert info.value.rule == "path.containment"


def test_a_symlink_leaving_the_root_is_refused(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret").write_bytes(b"s")
    root = tmp_path / "root"
    root.mkdir()
    (root / "esc").symlink_to(outside)
    with pytest.raises(ContractError):
        contained_file(root, "esc/secret")


def test_non_regular_files_are_refused(tmp_path: Path) -> None:
    _tree(tmp_path)
    with pytest.raises(ContractError) as info:
        contained_file(tmp_path, "a/b")
    assert info.value.rule == "path.containment"
    os.mkfifo(tmp_path / "fifo")
    with pytest.raises(ContractError):
        contained_file(tmp_path, "fifo")
    with pytest.raises(ContractError):
        open_contained(tmp_path, "fifo")


def test_the_opened_descriptor_is_checked_again(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Simulates a regular file replaced by a FIFO between the component check and the open:
    # the descriptor that would be read must itself be a regular file.
    os.mkfifo(tmp_path / "fifo")
    monkeypatch.setattr("cubeproof.base.paths.contained_file", lambda root, rel: root / rel)
    with pytest.raises(ContractError) as info:
        open_contained(tmp_path, "fifo")
    assert info.value.rule == "path.containment"
    # A symlink swapped in at the last moment is not followed (O_NOFOLLOW).
    _tree(tmp_path)
    (tmp_path / "alias.txt").symlink_to(tmp_path / "top.txt")
    with pytest.raises(ContractError):
        open_contained(tmp_path, "alias.txt")


def test_a_file_used_as_a_directory_is_refused(tmp_path: Path) -> None:
    _tree(tmp_path)
    with pytest.raises(ContractError):
        contained_file(tmp_path, "top.txt/x")


def test_missing_files_are_reported_as_missing(tmp_path: Path) -> None:
    _tree(tmp_path)
    with pytest.raises(FileNotFoundError):
        contained_file(tmp_path, "a/missing.txt")
    with pytest.raises(FileNotFoundError):
        contained_file(tmp_path, "nope/f.txt")
    with pytest.raises(FileNotFoundError):
        open_contained(tmp_path, "a/missing.txt")


class _RecordingStream(io.BytesIO):
    """Records the size of every read request; short reads of at most 1000 bytes each."""

    def __init__(self, data: bytes) -> None:
        super().__init__(data)
        self.requests: list[int] = []

    def read(self, size: int | None = -1, /) -> bytes:
        self.requests.append(-1 if size is None else size)
        return super().read(min(1000, size) if size is not None and size >= 0 else 1000)


def test_read_at_most_reads_in_bounded_chunks_and_stops_at_the_count() -> None:
    data = bytes(range(256)) * 20000  # 5 120 000 bytes
    stream = _RecordingStream(data)
    assert read_at_most(stream, 3_000_001) == data[:3_000_001]
    assert stream.tell() == 3_000_001
    assert all(0 < size <= 1 << 20 for size in stream.requests)
    assert read_at_most(_RecordingStream(data), 0) == b""
    assert read_at_most(_RecordingStream(b"abc"), 10) == b"abc"
    assert read_at_most(_RecordingStream(b""), 10) == b""
    with pytest.raises(ValueError):
        read_at_most(_RecordingStream(b"abc"), -1)


def test_new_id128_is_fresh_lowercase_hex() -> None:
    ids = {new_id128() for _ in range(1000)}
    assert len(ids) == 1000
    for value in ids:
        assert len(value) == 32
        assert all(c in "0123456789abcdef" for c in value)


def test_only_a_regular_file_is_opened_and_a_fifo_does_not_block(tmp_path: Path) -> None:
    regular = tmp_path / "file"
    regular.write_bytes(b"data")
    with open_regular_file(regular) as stream:
        assert stream.read() == b"data"
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)  # without O_NONBLOCK the open would wait for a writer
    for path in (fifo, tmp_path, Path("/dev/zero")):
        with pytest.raises(OSError) as caught:
            open_regular_file(path)
        assert path is tmp_path or caught.value.strerror == "not a regular file", path
    with pytest.raises(FileNotFoundError):
        open_regular_file(tmp_path / "missing")
