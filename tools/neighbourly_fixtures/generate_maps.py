"""Generate (or check) the stored n = 15 and n = 16 map fixtures of neighbourly.

    python3 tools/neighbourly_fixtures/generate_maps.py --out DIR   # write fresh fixtures to DIR
    python3 tools/neighbourly_fixtures/generate_maps.py --check     # recompute, compare with data

The fixture of a size is the FIRST map the enumeration finds, computed once, outside the
source tree, then stored and validated. This tool does exactly that and nothing else; the
tests never search, they read the stored fixture.

THE SEARCH is the search of :func:`neighbourly.enumeration.enumerate_oriented`: the same
frame ``link(0) = (1, ..., n-1)``,
the same most-constrained ordered pair, the same increasing third vertex. The only change is
that it stops at the first complete map instead of collecting all of them, which for
``n >= 15`` is the difference between seconds and an unbounded run. ``--check`` and the
``verify_small`` self-check rerun the copy against :func:`enumerate_oriented` on the sizes
where the full enumeration is cheap (n = 4, 7, 10), so a drift of the copy is visible.

Everything stored is then validated by neighbourly itself: the map structure
(:class:`~neighbourly.maps.CombinatorialMap`), orientability, the encoder entry
(:func:`~neighbourly.encoding.check_encodable`), the Euler characteristic, and the identity
of the base-layer formula (``S,H,A,B,I``, gauge face 1), whose size and SHA-256 are stored so
that the tests can show that the build is deterministic.

A stored map is one orientable neighbourly map for that ``n``: a structural fixture. It is not
a census, says nothing about how many maps exist, and no theorem is claimed for these ``n``.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import sys
import time
from collections.abc import Sequence
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
FIXTURES = ROOT / "packages" / "neighbourly" / "src" / "neighbourly" / "data" / "fixtures"
SIZES = (15, 16)
LAYERS = "S,H,A,B,I"
GAUGE_FACE = 1
FORMAT = "neighbourly-map-fixture-1"
#: Hard bound on recursive steps, so that a run that would not finish fails instead.
NODE_LIMIT = 50_000_000

Triple = tuple[int, int, int]


def _import_neighbourly() -> Any:
    """Import neighbourly from the checkout when it is not installed."""
    source = ROOT / "packages" / "neighbourly" / "src"
    if str(source) not in sys.path:
        sys.path.insert(0, str(source))
    import neighbourly  # noqa: PLC0415

    return neighbourly


class SearchLimit(RuntimeError):
    """The search exceeded its node limit without finding a map."""


def first_oriented(
    n: int, node_limit: int = NODE_LIMIT, limit: int = 1
) -> tuple[list[tuple[Triple, ...]], int]:
    """The first `limit` maps of the :func:`enumerate_oriented` search order, and its node count.

    The body is the search of :func:`neighbourly.enumeration.enumerate_oriented`, copied with
    an early exit once `limit` maps are found; with ``limit=0`` it collects every map.
    """
    if type(n) is not int or n < 4:
        raise ValueError("n must be an integer of at least 4")
    if n * (n - 1) % 3:
        return [], 0
    full = (1 << n) - 1
    outgoing = [0] * n
    incoming = [0] * n
    successor = [[-1] * n for _ in range(n)]
    predecessor = [[-1] * n for _ in range(n)]
    degree = [0] * n
    needed = n * (n - 1) // 3
    placed: list[Triple] = []
    found: list[tuple[Triple, ...]] = []
    nodes = 0

    class Done(Exception):
        pass

    def link_ok(v: int, a: int, b: int) -> bool:
        if a == b or successor[v][a] != -1 or predecessor[v][b] != -1:
            return False
        if degree[v] < n - 2:
            x = b
            while x != -1:
                if x == a:
                    return False
                x = successor[v][x]
        return True

    def place(a: int, b: int, c: int) -> bool:
        rotations = ((a, b, c), (b, c, a), (c, a, b))
        for position, (v, p, q) in enumerate(rotations):
            if not link_ok(v, p, q):
                for v2, p2, q2 in rotations[:position]:
                    successor[v2][p2] = -1
                    predecessor[v2][q2] = -1
                    degree[v2] -= 1
                return False
            successor[v][p] = q
            predecessor[v][q] = p
            degree[v] += 1
        outgoing[a] |= 1 << b
        outgoing[b] |= 1 << c
        outgoing[c] |= 1 << a
        incoming[b] |= 1 << a
        incoming[c] |= 1 << b
        incoming[a] |= 1 << c
        placed.append((a, b, c))
        return True

    def unplace(a: int, b: int, c: int) -> None:
        placed.pop()
        outgoing[a] &= ~(1 << b)
        outgoing[b] &= ~(1 << c)
        outgoing[c] &= ~(1 << a)
        incoming[b] &= ~(1 << a)
        incoming[c] &= ~(1 << b)
        incoming[a] &= ~(1 << c)
        for v, p, q in ((c, a, b), (b, c, a), (a, b, c)):
            successor[v][p] = -1
            predecessor[v][q] = -1
            degree[v] -= 1

    def search() -> None:
        nonlocal nodes
        nodes += 1
        if nodes > node_limit:
            raise SearchLimit(f"n = {n}: no map within {node_limit} search nodes")
        if len(placed) == needed:
            found.append(tuple(sorted(_sorted3(t) for t in placed)))
            if limit and len(found) >= limit:
                raise Done
            return
        best = n + 1
        best_a = best_b = -1
        best_mask = 0
        for a in range(n):
            free = full & ~outgoing[a] & ~(1 << a)
            while free:
                b = (free & -free).bit_length() - 1
                free &= free - 1
                mask = full & ~outgoing[b] & ~incoming[a] & ~(1 << a) & ~(1 << b)
                options = mask.bit_count()
                if options < best:
                    best, best_a, best_b, best_mask = options, a, b, mask
                    if options == 0:
                        return
        if best_a < 0:
            return
        while best_mask:
            c = (best_mask & -best_mask).bit_length() - 1
            best_mask &= best_mask - 1
            if place(best_a, best_b, c):
                search()
                unplace(best_a, best_b, c)

    for i in range(1, n - 1):
        if not place(0, i, i + 1):
            return [], nodes
    if not place(0, n - 1, 1):
        return [], nodes
    with contextlib.suppress(Done):
        search()
    return found, nodes


def _sorted3(triple: Sequence[int]) -> Triple:
    a, b, c = sorted(triple)
    return (a, b, c)


def verify_small() -> list[str]:
    """The copied search equals :func:`enumerate_oriented` where enumerating everything is cheap."""
    _import_neighbourly()
    from neighbourly.enumeration import enumerate_oriented  # noqa: PLC0415

    problems = []
    for n in (4, 7, 10):
        everything, _ = first_oriented(n, limit=0)
        reference = enumerate_oriented(n)
        if everything != reference:
            problems.append(f"n = {n}: the copied search differs from enumerate_oriented")
        first, _ = first_oriented(n, limit=1)
        if first != reference[:1]:
            problems.append(f"n = {n}: the first map differs from enumerate_oriented's first")
    return problems


def matrix_text(n: int, triples: Sequence[Triple], nodes: int) -> str:
    """The incidence matrix (one row per vertex, faces 1..n), with a provenance header."""
    lines = [
        f"# An orientable neighbourly map on n = {n} faces: "
        "one row per vertex, one column per face.",
        "# The first map in the search order of neighbourly.enumeration.enumerate_oriented",
        f"# (frame link(0) = (1..{n - 1}), zero-based search, faces shifted to 1..{n}),",
        f"# found after {nodes} search nodes by tools/neighbourly_fixtures/generate_maps.py.",
        "# A structural fixture: it says nothing about how many such maps exist.",
    ]
    for triple in sorted(triples):
        row = ["0"] * n
        for face in triple:
            row[face - 1] = "1"
        lines.append(" ".join(row))
    return "\n".join(lines) + "\n"


def map_document(n: int, text: str, nodes: int) -> dict[str, Any]:
    """Validate the stored map with neighbourly and describe it, its formula and its origin."""
    _import_neighbourly()
    from neighbourly.cnf.dimacs import clause_bytes, formula_digest  # noqa: PLC0415
    from neighbourly.encoding import build_encoder, check_encodable  # noqa: PLC0415
    from neighbourly.interpret import map_sha256  # noqa: PLC0415
    from neighbourly.maps import CombinatorialMap  # noqa: PLC0415

    cmap = CombinatorialMap.from_text(text, f"n{n}.txt")
    if cmap.n != n or not cmap.is_orientable():
        raise ValueError(f"n = {n}: the found map is not an orientable map on {n} faces")
    check_encodable(cmap)
    encoder = build_encoder(cmap, LAYERS, GAUGE_FACE)
    body = clause_bytes(encoder.clauses)
    return {
        "format": FORMAT,
        "n": n,
        "matrix": f"n{n}.txt",
        "matrix_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
        "map_sha256": map_sha256(cmap),
        "vertices": len(cmap.triples),
        "euler_characteristic": cmap.euler_characteristic,
        "orientable": True,
        "base_formula": {
            "layers": LAYERS,
            "gauge_face": GAUGE_FACE,
            "variables": encoder.variables,
            "clauses": len(encoder.clauses),
            "sha256": formula_digest(encoder.variables, body, len(encoder.clauses)),
        },
        "provenance": {
            "generator": "tools/neighbourly_fixtures/generate_maps.py",
            "method": (
                "first map of the enumerate_oriented search order (the search stopped at "
                "the first complete map); validated by CombinatorialMap, is_orientable and "
                "check_encodable"
            ),
            "search_nodes": nodes,
        },
        "scope": (
            "One orientable neighbourly map for this n, used as a structural and per-face "
            "control fixture. Not a census; no existence count or theorem for this n is claimed."
        ),
    }


def fixture_files(n: int) -> dict[str, bytes]:
    """The two files of the fixture of one size (search, validation, description)."""
    maps, nodes = first_oriented(n)
    if not maps:
        raise ValueError(f"n = {n}: the search found no map")
    zero_based = maps[0]
    triples = [(a + 1, b + 1, c + 1) for a, b, c in zero_based]
    text = matrix_text(n, triples, nodes)
    document = map_document(n, text, nodes)
    encoded = json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    return {f"n{n}.txt": text.encode("utf-8"), f"n{n}.json": encoded.encode("utf-8")}


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--out", type=Path, help="write fresh fixtures below this directory")
    group.add_argument("--check", action="store_true", help="compare with the package data")
    parser.add_argument("--sizes", type=int, nargs="+", default=list(SIZES))
    args = parser.parse_args(argv)

    problems = verify_small()
    for problem in problems:
        print(f"FAIL {problem}")
    if not problems:
        print("search copy = enumerate_oriented on n = 4, 7, 10: OK")
    status = 1 if problems else 0
    for n in args.sizes:
        started = time.perf_counter()
        files = fixture_files(n)
        print(f"n = {n}: generated in {time.perf_counter() - started:.1f} s")
        for name, raw in files.items():
            if args.out is not None:
                target = args.out / f"n{n}" / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(raw)
                print(f"  wrote {target} sha256={hashlib.sha256(raw).hexdigest()}")
                continue
            stored = (FIXTURES / f"n{n}" / name).read_bytes()
            same = stored == raw
            print(f"  {'OK' if same else 'DIFFERS'} {name}")
            status |= 0 if same else 1
    return status


if __name__ == "__main__":
    sys.exit(main())
