"""The 59 maps, one by one, against the published list of F. H. Lutz (paper: thm:59).

The Manifold Page lists the triangulations of the orientable surface of genus 6 with twelve
vertices as 59 facet lists (``manifolds_lex_d2_n12_o1_g6.txt``). A neighbourly map on twelve
faces is the dual of such a triangulation: faces become vertices, and the 44 vertices of the
map, triples of faces, become the 44 triangles. ``data/fixtures/lutz_correspondence.json``
names, for every entry of the list, the map of this repository it is and a relabelling of the
twelve faces that carries the map onto the entry.

A relabelling is checked by applying it, so no search for an isomorphism happens here and
nothing depends on the canonical form of the enumeration: the maps of ``data/matrices`` are
relabelled, written in the notation of the list, and the SHA-256 of the result is compared with
the one recorded for the published file without its white space. The file itself is not in the
repository; ``docs/SOURCES.md`` says where it is and how to hash it. Since every map is used
once and the maps are pairwise non-isomorphic (``test_corpus12_data.py``), the equality says
that the two lists are the same 59 isomorphism classes.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any

from neighbourly import corpus12
from neighbourly.enumeration.oriented import canonical

REPO = Path(__file__).resolve().parents[4]
CORRESPONDENCE = REPO / "data" / "fixtures" / "lutz_correspondence.json"
#: SHA-256 of the published file without its white space (``tr -d ' \\n' < FILE | sha256sum``),
#: pinned here as well as in the data file, so that the two cannot be changed together unseen.
PUBLISHED_WITHOUT_WHITESPACE = "eac588cb5d93c8e33ed9a424853ea01745b56a1ec3b75e074848adea7a69cc1e"
#: The automorphism orders of the 59 orientable triangular embeddings of K12 as Ellingham and
#: Stephens state them (Theorem 4 of their article; docs/SOURCES.md): order -> classes.
ORDERS_IN_THE_LITERATURE = {1: 39, 2: 9, 3: 1, 4: 7, 6: 2, 12: 1}

Triangle = tuple[int, int, int]


def correspondence() -> dict[str, Any]:
    document: dict[str, Any] = json.loads(CORRESPONDENCE.read_text(encoding="utf-8"))
    return document


def triangles(map_id: int, relabelling: list[int]) -> list[Triangle]:
    """The vertices of the map as triangles on the relabelled faces, in lexicographic order."""
    image = {face: relabelling[face - 1] for face in range(1, corpus12.N_FACES + 1)}
    found = []
    for triple in corpus12.load_map(map_id).triples:
        a, b, c = sorted(image[face] for face in triple)
        found.append((a, b, c))
    return sorted(found)


def in_the_notation_of_the_list(entries: list[dict[str, Any]]) -> str:
    """The entries as the published file writes them, without white space."""
    return "".join(
        f"manifold_lex_d2_n12_o1_g6_#{entry['lutz']}=["
        + ",".join(f"[{a},{b},{c}]" for a, b, c in triangles(entry["map"], entry["relabelling"]))
        + "]"
        for entry in entries
    )


def sha(text: str) -> str:
    return hashlib.sha256(text.encode("ascii")).hexdigest()


def test_the_published_list_is_the_59_maps_relabelled() -> None:
    document = correspondence()
    entries = document["entries"]
    assert document["format"] == "faces12-lutz-correspondence-1"
    assert [entry["lutz"] for entry in entries] == list(range(1, corpus12.N_MAPS + 1))
    assert sorted(entry["map"] for entry in entries) == list(corpus12.map_ids())  # each map once
    faces = list(range(1, corpus12.N_FACES + 1))
    for entry in entries:
        assert sorted(entry["relabelling"]) == faces, entry["lutz"]  # a bijection of the faces
        assert len(set(triangles(entry["map"], entry["relabelling"]))) == corpus12.N_VERTICES
    assert document["list"]["sha256_without_whitespace"] == PUBLISHED_WITHOUT_WHITESPACE
    assert sha(in_the_notation_of_the_list(entries)) == PUBLISHED_WITHOUT_WHITESPACE


def test_another_map_or_another_relabelling_does_not_give_the_list() -> None:
    """The comparison can fail: two maps exchanged, or two faces exchanged in the relabelling of
    a map without symmetries, give other bytes."""
    document = correspondence()
    recorded = PUBLISHED_WITHOUT_WHITESPACE
    entries = document["entries"]
    first, second = entries[0], entries[1]
    exchanged = [dict(first, map=second["map"]), dict(second, map=first["map"]), *entries[2:]]
    assert sha(in_the_notation_of_the_list(exchanged)) != recorded
    rigid = next(i for i, entry in enumerate(entries) if entry["automorphisms"] == 1)
    relabelling = list(entries[rigid]["relabelling"])
    relabelling[0], relabelling[1] = relabelling[1], relabelling[0]
    moved = [*entries[:rigid], dict(entries[rigid], relabelling=relabelling), *entries[rigid + 1 :]]
    assert sha(in_the_notation_of_the_list(moved)) != recorded


def test_the_automorphism_orders_are_those_of_the_literature() -> None:
    """The order recorded with every entry is the one the enumeration's canonical form counts
    for that map, and the orders are distributed as Ellingham and Stephens state."""
    entries = correspondence()["entries"]
    for entry in entries:
        zero_based = [(a - 1, b - 1, c - 1) for a, b, c in sorted(
            corpus12.load_map(entry["map"]).triples
        )]  # fmt: skip
        _, order = canonical(zero_based, corpus12.N_FACES)
        assert order == entry["automorphisms"], entry["lutz"]
    assert dict(Counter(entry["automorphisms"] for entry in entries)) == ORDERS_IN_THE_LITERATURE
