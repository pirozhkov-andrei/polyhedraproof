"""neighbourly.maps: what a map accepts, what it refuses, and what it derives.

The n-scope of specification §13.2: the map validates its own structural domain for any
integer n >= 4 and no mod-12 rule. What a map derives is pinned by regression goldens on the
shipped maps and the fixtures.
"""

from __future__ import annotations

import hashlib
import itertools
import json
from typing import Any

import pytest

from neighbourly import corpus12
from neighbourly.data import read_bytes
from neighbourly.maps import CombinatorialMap, MapError, sorted_triple

TETRAHEDRON = list(itertools.combinations(range(1, 5), 3))
#: The six-vertex triangulation of the projective plane (dual: a neighbourly map on six
#: faces of a non-orientable surface, Euler characteristic 1).
PROJECTIVE_PLANE = [
    (1, 2, 3),
    (1, 3, 4),
    (1, 4, 5),
    (1, 5, 6),
    (1, 2, 6),
    (2, 3, 5),
    (3, 4, 6),
    (2, 4, 5),
    (3, 5, 6),
    (2, 4, 6),
]
#: SHA-256 of the canonical JSON of ``derived(map)``.
DERIVED_GOLDEN = {
    "1": "d37b5e88e365332f90352e4699f1a145b507f941667b5ace5812607b3879550d",
    "2": "3f5c624ba4787309ee7214b87954c7d2b4375df65f3a615f5123af20c50c35d2",
    "30": "32cccd9fb408bd2f8dd1b641c132254479c9e89fd80d86e6fc0b94874c15e2a4",
    "59": "9c6a5111ec46e7c159172ad1141bbca48c0436da3b0b950e524f66d0555b317a",
    "csaszar": "a77e7d44e1636a87c7962d81857165a32c7ce06a669240f2cc6d1241cef7bfc9",
    "projective": "f444795e09de7729930894a6c6929a8c987b70b03cf1693de87ca7cc2c03db32",
    "tetrahedron": "f65fb019ebd5d18703ac362000c4d35b197c8831563dc10161c621d722056320",
}


def csaszar() -> CombinatorialMap:
    text = read_bytes("fixtures", "szilassi", "csaszar_n7.txt").decode("utf-8")
    return CombinatorialMap.from_text(text, "csaszar_n7.txt")


def test_tetrahedron_is_a_valid_map() -> None:
    cmap = CombinatorialMap(4, TETRAHEDRON)
    assert cmap.n == 4
    assert cmap.faces == (1, 2, 3, 4)
    assert len(cmap.triples) == 4
    assert cmap.is_orientable()
    assert cmap.euler_characteristic == 2


def test_the_packaged_tetrahedron_matrix_is_the_tetrahedron() -> None:
    text = read_bytes("fixtures", "tetrahedron", "tetrahedron.txt").decode("utf-8")
    assert CombinatorialMap.from_text(text).triples == frozenset(TETRAHEDRON)


def test_the_csaszar_map_is_a_torus_on_seven_faces() -> None:
    cmap = csaszar()
    assert (cmap.n, len(cmap.triples), cmap.euler_characteristic) == (7, 14, 0)
    assert cmap.is_orientable()


@pytest.mark.parametrize(
    "rows",
    [
        [*TETRAHEDRON, TETRAHEDRON[0]],  # a repeated vertex
        [(1, 1, 2), *TETRAHEDRON[1:]],  # a repeated face in one vertex
        [(1, 2), *TETRAHEDRON[1:]],  # a vertex that is not a triple
        TETRAHEDRON[:-1],  # a missing vertex
        [(1, 2, 5), *TETRAHEDRON[1:]],  # a face out of range
        [(1, 2, True), *TETRAHEDRON[1:]],  # not an integer face
    ],
)
def test_broken_input_is_not_silently_repaired(rows: list[Any]) -> None:
    with pytest.raises(MapError):
        CombinatorialMap(4, rows)


@pytest.mark.parametrize("n", [3, 0, -4, True, 4.0, "4"])
def test_n_must_be_an_integer_of_at_least_four(n: Any) -> None:
    with pytest.raises(MapError, match="at least 4"):
        CombinatorialMap(n, TETRAHEDRON)


@pytest.mark.parametrize("n", [5, 8, 11, 14])
def test_n_with_3_not_dividing_n_n_minus_1_admits_no_map(n: int) -> None:
    with pytest.raises(MapError, match="3 does not divide"):
        CombinatorialMap(n, [])


def test_a_non_orientable_neighbourly_map_is_a_valid_map() -> None:
    """The structure is generic; orientability is a query, refused only by the encoder."""
    cmap = CombinatorialMap(6, PROJECTIVE_PLANE)
    assert cmap.n % 12 == 6
    assert cmap.euler_characteristic == 1
    assert not cmap.is_orientable()


def test_a_surface_that_is_not_neighbourly_is_refused() -> None:
    # Replacing the vertex (2,4,6) by (1,2,4): the pair {1,2} now has three ends and the
    # pair {4,6} lost one.
    rows = [*PROJECTIVE_PLANE[:-1], (1, 2, 4)]
    with pytest.raises(MapError):
        CombinatorialMap(6, rows)


def test_map_files_load_and_are_the_expected_surfaces() -> None:
    for map_id in (1, corpus12.N_MAPS):
        cmap = corpus12.load_map(map_id)
        assert cmap.n == corpus12.N_FACES
        assert len(cmap.triples) == 44
        assert cmap.euler_characteristic == -10
        assert cmap.is_orientable()


def test_link_cycle_is_deterministic_and_consistent() -> None:
    cmap = corpus12.load_map(1)
    for face in cmap.faces:
        cycle = cmap.link_cycle(face)
        assert cycle == cmap.link_cycle(face)  # cached, and stable
        assert sorted(cycle) == [x for x in cmap.faces if x != face]
        assert cycle[0] == min(cycle)
        successor = cmap.link_successor(face)
        for a, b in zip(cycle, cycle[1:] + cycle[:1]):
            assert successor[a] == b
            # Consecutive in the link implies a real vertex (paper: lem:adjacency).
            assert cmap.is_real(face, a, b)
    cycle = cmap.link_cycle(1)
    cycle.append(99)  # a copy: the cache is not exposed
    assert 99 not in cmap.link_cycle(1)


def test_edges_have_two_ends_and_far_end_is_the_other_one() -> None:
    cmap = corpus12.load_map(1)
    for i, j in itertools.combinations(cmap.faces, 2):
        a, b = cmap.end_pair(i, j)
        assert a < b
        assert cmap.end_pair(j, i) == (a, b)
        assert cmap.is_real(i, j, a) and cmap.is_real(i, j, b)
        assert cmap.far_end(i, j, a) == b
        assert cmap.far_end(i, j, b) == a
    with pytest.raises(MapError):
        cmap.far_end(1, 2, 999)
    with pytest.raises(MapError):
        cmap.end_pair(1, 1)


def test_reading_a_ragged_or_non_binary_matrix_fails() -> None:
    with pytest.raises(MapError):
        CombinatorialMap.from_matrix([[1, 1, 1, 0], [1, 1]])
    with pytest.raises(MapError):
        CombinatorialMap.from_matrix([[2, 1, 1, 0]])
    with pytest.raises(MapError):
        CombinatorialMap.from_matrix([[1, 1, 0, 0]])
    with pytest.raises(MapError):
        CombinatorialMap.from_matrix([])


def test_text_matrices_allow_comments_and_commas_and_name_the_bad_line() -> None:
    text = "# tetrahedron\n1,1,1,0\n1 1 0 1  # second\n\n1 0 1 1\n0 1 1 1\n"
    assert CombinatorialMap.from_text(text).triples == frozenset(TETRAHEDRON)
    with pytest.raises(MapError, match=r"m\.txt:2"):
        CombinatorialMap.from_text("1 1 1 0\n1 x 0 1\n", "m.txt")


def test_from_file_reads_utf8(tmp_path: Any) -> None:
    path = tmp_path / "t.txt"
    path.write_bytes(read_bytes("fixtures", "tetrahedron", "tetrahedron.txt"))
    assert CombinatorialMap.from_file(path).triples == frozenset(TETRAHEDRON)


def test_sorted_triple_has_fixed_width() -> None:
    assert sorted_triple([3, 1, 2]) == (1, 2, 3)
    with pytest.raises(ValueError):
        sorted_triple([1, 2])


# -- derived values against the goldens --------------------------------------------------------


def canon(value: Any) -> Any:
    """The JSON form the golden values are frozen in (dicts keep their order)."""
    if value is None or isinstance(value, (bool, int, str)):
        return value
    if isinstance(value, dict):
        return ["dict", [[canon(k), canon(v)] for k, v in value.items()]]
    if isinstance(value, (list, tuple)):
        return [canon(v) for v in value]
    raise TypeError(f"no canonical form for {type(value)}")


def derived(cmap: CombinatorialMap) -> list[Any]:
    """Everything a map derives: faces, vertices, surface, links, ends and real vertices."""
    out: list[Any] = [cmap.n, cmap.faces, sorted(cmap.triples)]
    out += [cmap.is_orientable(), cmap.euler_characteristic]
    for face in cmap.faces:
        out.append([face, cmap.link_cycle(face), cmap.link_successor(face)])
    for i, j in itertools.combinations(cmap.faces, 2):
        out.append([i, j, cmap.end_pair(i, j), [k for k in cmap.faces if cmap.is_real(i, j, k)]])
    return out


def assert_derives_the_golden(name: str, cmap: CombinatorialMap) -> None:
    text = json.dumps(canon(derived(cmap)), sort_keys=True, separators=(",", ":"))
    assert hashlib.sha256(text.encode("utf-8")).hexdigest() == DERIVED_GOLDEN[name], name


@pytest.mark.parametrize("map_id", [1, 2, 30, 59])
def test_shipped_maps_derive_the_golden_values(map_id: int) -> None:
    assert_derives_the_golden(str(map_id), corpus12.load_map(map_id))


def test_small_maps_derive_the_golden_values() -> None:
    assert_derives_the_golden("tetrahedron", CombinatorialMap(4, TETRAHEDRON))
    assert_derives_the_golden("csaszar", csaszar())
    assert_derives_the_golden("projective", CombinatorialMap(6, PROJECTIVE_PLANE))
