"""SHA-256 helpers, the hashing writer and the leaf Merkle tree (specification §4.1, §10.5)."""

from __future__ import annotations

import hashlib
import io
import random
import sys
from pathlib import Path
from typing import Any

import pytest

from cubeproof.base.hashing import (
    ZERO_HASH,
    HashingWriter,
    merkle_leaf,
    merkle_root,
    sha256_hex,
)

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "contracts"))
import cp_corpus


def test_sha256_hex_is_lowercase_hex_of_the_bytes() -> None:
    assert sha256_hex(b"") == hashlib.sha256(b"").hexdigest()
    assert sha256_hex(b"abc") == hashlib.sha256(b"abc").hexdigest()
    assert ZERO_HASH == "0" * 64


class _ShortWriter(io.RawIOBase):
    """A raw stream that accepts at most ``step`` bytes per call (short writes)."""

    def __init__(self, step: int) -> None:
        self.step = step
        self.data = bytearray()
        self.calls = 0

    def writable(self) -> bool:
        return True

    def write(self, b: Any) -> int:
        self.calls += 1
        chunk = bytes(b[: self.step])
        self.data += chunk
        return len(chunk)


class _NoneWriter(io.RawIOBase):
    """A nonblocking raw stream that cannot take any byte now."""

    def writable(self) -> bool:
        return True

    def write(self, b: Any) -> int | None:
        return None


def test_hashing_writer_hashes_and_counts_every_byte_written() -> None:
    sink = io.BytesIO()
    writer = HashingWriter(sink)
    writer.write(b"p cnf 1 1\n")
    writer.write(memoryview(b"1 0\n"))
    writer.write(b"")
    assert sink.getvalue() == b"p cnf 1 1\n1 0\n"
    assert writer.bytes_written == 14
    assert writer.hexdigest() == hashlib.sha256(b"p cnf 1 1\n1 0\n").hexdigest()


def test_hashing_writer_completes_short_writes() -> None:
    raw = _ShortWriter(3)
    writer = HashingWriter(raw)
    writer.write(b"0123456789")
    assert bytes(raw.data) == b"0123456789"
    assert raw.calls == 4
    assert writer.bytes_written == 10
    assert writer.hexdigest() == hashlib.sha256(b"0123456789").hexdigest()


def test_hashing_writer_refuses_a_stream_that_writes_nothing() -> None:
    writer = HashingWriter(_NoneWriter())
    with pytest.raises(OSError):
        writer.write(b"x")


class _OverReportingWriter(io.RawIOBase):
    """A broken raw stream that claims one byte more than it was offered."""

    def __init__(self) -> None:
        self.data = bytearray()

    def writable(self) -> bool:
        return True

    def write(self, b: Any) -> int:
        self.data += bytes(b)
        return len(b) + 1


def test_hashing_writer_refuses_a_stream_that_claims_more_than_offered() -> None:
    # The byte count must never describe bytes that were not offered (and so not hashed).
    writer = HashingWriter(_OverReportingWriter())
    with pytest.raises(OSError):
        writer.write(b"abc")
    assert writer.bytes_written == 0
    assert writer.hexdigest() == hashlib.sha256(b"").hexdigest()


@pytest.mark.parametrize("case", cp_corpus.vectors("merkle")["cases"], ids=lambda c: c["name"])
def test_merkle_vectors(case: dict[str, Any]) -> None:
    leaves = [(x["node_id"], x["cnf_sha256"], x["proof_sha256"]) for x in case["leaves"]]
    assert [merkle_leaf(*leaf) for leaf in sorted(leaves)] == case["leaf_hashes"]
    assert merkle_root(leaves) == case["root"]
    shuffled = list(leaves)
    random.Random(7).shuffle(shuffled)
    assert merkle_root(shuffled) == case["root"]
    assert merkle_root(reversed(leaves)) == case["root"]


def _plain_root(leaves: list[tuple[str, str, str]]) -> str | None:
    """Specification §10.5 written out independently: domain tags, pairs, odd element carried."""

    def h(*parts: str) -> str:
        return hashlib.sha256("\0".join(parts).encode("ascii")).hexdigest()

    level = [h("leaf", *leaf) for leaf in sorted(leaves, key=lambda x: x[0])]
    if not level:
        return None
    while len(level) > 1:
        nxt = [h("branch", level[i], level[i + 1]) for i in range(0, len(level) - 1, 2)]
        if len(level) % 2 == 1:
            nxt.append(level[-1])
        level = nxt
    return level[0]


def test_random_trees_agree_with_the_plain_definition() -> None:
    rng = random.Random(1050)
    for count in [*range(0, 18), 31, 32, 33, 100]:
        leaves = [
            tuple(hashlib.sha256(f"{count}-{i}-{k}".encode()).hexdigest() for k in range(3))
            for i in range(count)
        ]
        rng.shuffle(leaves)
        typed = [(a, b, c) for a, b, c in leaves]
        assert merkle_root(typed) == _plain_root(typed)


def test_merkle_leaf_binds_every_field() -> None:
    a, b, c = ("1" * 64, "2" * 64, "3" * 64)
    assert len({merkle_leaf(a, b, c), merkle_leaf(b, a, c), merkle_leaf(a, c, b)}) == 3
