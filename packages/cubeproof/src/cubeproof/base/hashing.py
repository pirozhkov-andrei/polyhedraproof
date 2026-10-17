"""SHA-256 helpers: hex digests, a hashing writer and the leaf Merkle tree (specification §4.1,
§10.5).

A hash is an identifier, never a proof. Hashes are lowercase hexadecimal SHA-256 digests.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from typing import Protocol

#: The ``prev`` of the first journal record and other "no predecessor" values.
ZERO_HASH = "0" * 64


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class _RawWriter(Protocol):
    def write(self, data: memoryview, /) -> int | None: ...


class HashingWriter:
    """Writes every byte to ``stream`` exactly once and hashes exactly what was written.

    ``write`` completes short writes (a raw stream may accept fewer bytes than offered) and
    raises :class:`OSError` if the stream accepts nothing, so the digest and the byte count
    always describe the bytes the stream took.
    """

    def __init__(self, stream: _RawWriter) -> None:
        self._stream = stream
        self._digest = hashlib.sha256()
        self.bytes_written = 0

    def write(self, data: bytes | bytearray | memoryview) -> None:
        view = memoryview(data).cast("B")
        while len(view):
            count = self._stream.write(view)
            if count is None or count <= 0:
                raise OSError("the stream accepted no bytes")
            if count > len(view):
                raise OSError("the stream reported more bytes than offered")
            self._digest.update(view[:count])
            self.bytes_written += count
            view = view[count:]

    def hexdigest(self) -> str:
        return self._digest.hexdigest()


def merkle_leaf(node_id: str, cnf_sha256: str, proof_sha256: str) -> str:
    """``SHA256("leaf" NUL node_id NUL cnf_sha256 NUL proof_sha256)`` (specification §10.5)."""
    text = "\0".join(("leaf", node_id, cnf_sha256, proof_sha256))
    return sha256_hex(text.encode("ascii"))


def _branch(left: str, right: str) -> str:
    return sha256_hex("\0".join(("branch", left, right)).encode("ascii"))


def merkle_root(leaves: Iterable[tuple[str, str, str]]) -> str | None:
    """Root over ``(node_id, cnf_sha256, proof_sha256)`` leaves, in any input order.

    Leaves are sorted by node_id (then the other fields, which only matters for duplicate
    node IDs); adjacent pairs are hashed level by level and an odd last element is carried
    up unchanged. One leaf: the leaf hash. No leaves: None.
    """
    level = [merkle_leaf(*leaf) for leaf in sorted(leaves)]
    if not level:
        return None
    while len(level) > 1:
        paired = [_branch(level[i], level[i + 1]) for i in range(0, len(level) - 1, 2)]
        if len(level) % 2:
            paired.append(level[-1])
        level = paired
    return level[0]
