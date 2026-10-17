"""The stored n = 15 and n = 16 map fixtures: provenance, structure and deterministic builds.

One map of each size was generated ONCE (``tools/neighbourly_fixtures/generate_maps.py``,
outside the source tree) and stored as package data. These tests never search for maps; they
read the stored files, re-validate them (with neighbourly and with an independent structural
check written here), and rebuild their base formulas twice to show that the build is
deterministic and equals the recorded hash. A stored map is a structural fixture, not a
census.
"""

from __future__ import annotations

import hashlib
import importlib.util
import itertools
import json
from functools import cache
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from neighbourly.cnf import clause_bytes, formula_digest
from neighbourly.data import read_bytes
from neighbourly.encoding import ENCODABLE_RESIDUES, build_encoder, check_encodable
from neighbourly.enumeration import enumerate_oriented
from neighbourly.interpret import map_sha256
from neighbourly.maps import CombinatorialMap

REPO = Path(__file__).resolve().parents[4]
GENERATOR = REPO / "tools" / "neighbourly_fixtures" / "generate_maps.py"
SIZES = (15, 16)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@cache
def stored(n: int) -> tuple[bytes, dict[str, Any]]:
    text = read_bytes("fixtures", f"n{n}", f"n{n}.txt")
    document: dict[str, Any] = json.loads(read_bytes("fixtures", f"n{n}", f"n{n}.json"))
    return text, document


def fixture_map(n: int) -> CombinatorialMap:
    return CombinatorialMap.from_text(stored(n)[0].decode("utf-8"), f"n{n}.txt")


@pytest.mark.parametrize("n", SIZES)
def test_the_description_matches_the_stored_matrix(n: int) -> None:
    text, document = stored(n)
    assert document["format"] == "neighbourly-map-fixture-1"
    assert document["n"] == n and document["matrix"] == f"n{n}.txt"
    assert document["matrix_sha256"] == sha(text)
    cmap = fixture_map(n)
    assert document["map_sha256"] == map_sha256(cmap)
    assert document["vertices"] == len(cmap.triples) == n * (n - 1) // 3
    assert document["euler_characteristic"] == cmap.euler_characteristic == n * (7 - n) // 6
    assert document["orientable"] is True
    assert document["provenance"]["generator"] == "tools/neighbourly_fixtures/generate_maps.py"
    assert "Not a census" in document["scope"]


@pytest.mark.parametrize("n", SIZES)
def test_the_stored_map_is_an_encodable_orientable_neighbourly_map(n: int) -> None:
    cmap = fixture_map(n)
    assert cmap.n == n and n % 12 in ENCODABLE_RESIDUES
    assert cmap.is_orientable()
    assert check_encodable(cmap) is cmap


def independent_structure(n: int, triples: list[tuple[int, int, int]]) -> dict[str, Any]:
    """Neighbourliness, links and orientability computed here, without neighbourly.maps."""
    pairs: dict[tuple[int, int], int] = {}
    for triple in triples:
        for pair in itertools.combinations(sorted(triple), 2):
            pairs[pair] = pairs.get(pair, 0) + 1
    single_cycles = True
    for face in range(1, n + 1):
        edges = [tuple(x for x in t if x != face) for t in triples if face in t]
        adjacency: dict[int, list[int]] = {}
        for a, b in edges:
            adjacency.setdefault(a, []).append(b)
            adjacency.setdefault(b, []).append(a)
        start = min(adjacency)
        previous, current, length = start, adjacency[start][0], 1
        while current != start:
            previous, current = current, next(x for x in adjacency[current] if x != previous)
            length += 1
        single_cycles &= length == n - 1 == len(adjacency)
    # orient the triangles coherently: each directed edge must occur once, its reverse once
    oriented: dict[int, tuple[int, int, int]] = {0: triples[0]}
    queue = [0]
    by_pair: dict[tuple[int, int], list[int]] = {}
    for index, triple in enumerate(triples):
        for pair in itertools.combinations(sorted(triple), 2):
            by_pair.setdefault(pair, []).append(index)
    coherent = True
    while queue:
        index = queue.pop()
        a, b, c = oriented[index]
        for x, y in ((a, b), (b, c), (c, a)):
            other = next(i for i in by_pair[(min(x, y), max(x, y))] if i != index)
            p, q, r = triples[other]
            wanted = (y, x)
            rotations = [(p, q, r), (q, r, p), (r, p, q)]
            flipped = [(r, q, p), (q, p, r), (p, r, q)]
            if any(t[:2] == wanted for t in rotations):
                choice = (p, q, r)
            elif any(t[:2] == wanted for t in flipped):
                choice = (r, q, p)
            else:
                choice = None
            if choice is None:
                coherent = False
            elif other in oriented:
                cyc = oriented[other]
                same = {cyc, (cyc[1], cyc[2], cyc[0]), (cyc[2], cyc[0], cyc[1])}
                coherent &= choice in same
            else:
                oriented[other] = choice
                queue.append(other)
    return {
        "pairs_twice": len(pairs) == n * (n - 1) // 2 and set(pairs.values()) == {2},
        "single_cycles": single_cycles,
        "orientable": coherent and len(oriented) == len(triples),
    }


@pytest.mark.parametrize("n", SIZES)
def test_an_independent_structural_check_agrees(n: int) -> None:
    triples = sorted(fixture_map(n).triples)
    assert independent_structure(n, triples) == {
        "pairs_twice": True,
        "single_cycles": True,
        "orientable": True,
    }


def test_the_independent_structural_check_rejects_a_non_orientable_surface() -> None:
    """Its negative control: the 6-vertex real projective plane is neighbourly, not orientable."""
    rp2 = [
        (1, 2, 3), (1, 3, 4), (1, 4, 5), (1, 5, 6), (1, 2, 6),
        (2, 3, 5), (3, 4, 6), (2, 4, 5), (3, 5, 6), (2, 4, 6),
    ]  # fmt: skip
    found = independent_structure(6, rp2)
    assert found["pairs_twice"] and found["single_cycles"]
    assert found["orientable"] is False


@pytest.mark.parametrize("n", SIZES)
def test_the_base_formula_build_is_deterministic_and_recorded(n: int) -> None:
    recorded = stored(n)[1]["base_formula"]
    assert (recorded["layers"], recorded["gauge_face"]) == ("S,H,A,B,I", 1)
    digests = set()
    for _ in range(2):
        encoder = build_encoder(fixture_map(n), recorded["layers"], recorded["gauge_face"])
        body = clause_bytes(encoder.clauses)
        digests.add(formula_digest(encoder.variables, body, len(encoder.clauses)))
        assert (encoder.variables, len(encoder.clauses)) == (
            recorded["variables"],
            recorded["clauses"],
        )
    assert digests == {recorded["sha256"]}


@cache
def generator() -> ModuleType:
    spec = importlib.util.spec_from_file_location("nb_fixture_generator", GENERATOR)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_generators_search_is_the_enumeration_search_where_it_is_cheap() -> None:
    """Checkout only (tools are not package data). No search for n = 15/16 runs here."""
    if not GENERATOR.is_file():
        return
    first_oriented = generator().first_oriented
    for n in (4, 7, 10):
        everything, _ = first_oriented(n, limit=0)
        assert everything == enumerate_oriented(n)
        first, nodes = first_oriented(n, limit=1)
        assert first == everything[:1] and (nodes > 0 or n * (n - 1) % 3)
    assert generator().verify_small() == []


def test_the_stored_matrix_is_the_generators_rendering_of_the_stored_map() -> None:
    """The text file is exactly what ``matrix_text`` writes for the stored vertices."""
    if not GENERATOR.is_file():
        return
    for n in SIZES:
        text, document = stored(n)
        triples = sorted(fixture_map(n).triples)
        nodes = document["provenance"]["search_nodes"]
        assert generator().matrix_text(n, triples, nodes).encode("utf-8") == text
