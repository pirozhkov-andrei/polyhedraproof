"""neighbourly.enumeration: the generic search, its classes and its small-n counts.

The n = 12 census is in ``tests/corpus12``. The counts are computations for the n they are run
on, including the zero of n = 10, not generalized. The search results are pinned by regression
goldens (SHA-256 of the canonical JSON: dictionaries in insertion order, tuples as lists).
"""

from __future__ import annotations

import hashlib
import itertools
import json
import random
from typing import Any

import pytest

from neighbourly.enumeration import (
    SMALL_REFERENCE_COUNTS,
    SearchStatistics,
    canonical,
    canonical_map,
    classes_of,
    enumerate_classes,
    enumerate_oriented,
    oriented,
)
from neighbourly.enumeration.oriented import link_cycle
from neighbourly.maps import CombinatorialMap, MapError, Triple, sorted_triple

#: The golden counts of small n: (labelled, classes).
EXPECTED_SMALL_COUNTS = {4: (1, 1), 7: (2, 1), 10: (0, 0)}
#: digest([labelled maps, classes, labelled count, orbit count, automorphism histogram]) of
#: ``enumerate_oriented``/``enumerate_classes``.
SEARCH_GOLDEN = {
    4: "0c6c38f7ae44fdd251e8e0299c74a607dd312174fb3a7f909761a074726b79eb",
    7: "46628ba6df2ac6dfadc7b20b5abcff757c74d95256ab29dfebad16f0e226e1dd",
    10: "98578348fcdc13fa656b898e1282d0ea367cdc6524b290daa7bd8c9bcb664338",
}
#: digest of the [canonical form, link cycle at 0] of every relabelled map below.
RELABELLED_GOLDEN = "0dd85e17c17df2539a1c557213ec887d813104df0d5fa3f5c58d5e9644012ce9"


def canon(value: Any) -> Any:
    """The JSON form the golden values are frozen in (dicts keep their order)."""
    if value is None or isinstance(value, (bool, int, str)):
        return value
    if isinstance(value, dict):
        return ["dict", [[canon(k), canon(v)] for k, v in value.items()]]
    if isinstance(value, (list, tuple)):
        return [canon(v) for v in value]
    raise TypeError(f"no canonical form for {type(value)}")


def digest(value: Any) -> str:
    text = json.dumps(canon(value), sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


@pytest.mark.parametrize("n", [4, 7, 10])
def test_small_enumerations_reproduce_their_reference_counts(n: int) -> None:
    result = enumerate_classes(n, expected=SMALL_REFERENCE_COUNTS[n])
    assert (result.labelled, result.class_count) == SMALL_REFERENCE_COUNTS[n]
    assert result.orbit_identity_holds
    assert result.passed
    assert not result.reference_compared and result.reference_matches is None


def test_the_reference_counts_are_the_golden_counts_for_the_same_n() -> None:
    assert dict(SMALL_REFERENCE_COUNTS) == EXPECTED_SMALL_COUNTS


def test_ten_faces_admit_no_orientable_map_and_the_search_says_so() -> None:
    """n = 10 passes 3 | n(n-1), so the search runs; it finds nothing (n mod 12 = 10).

    The zero is the search's answer, not a residue rule applied before it: the search
    visits nodes.
    """
    assert 10 * 9 % 3 == 0
    statistics = SearchStatistics()
    assert enumerate_oriented(10, statistics) == []
    assert statistics.nodes > 1
    result = enumerate_classes(10)
    assert (result.labelled, result.class_count, result.orbit_count) == (0, 0, 0)
    assert result.search_nodes == statistics.nodes
    assert result.passed


@pytest.mark.parametrize("n", [5, 6, 8, 9])
def test_other_small_n_have_no_orientable_map(n: int) -> None:
    statistics = SearchStatistics()
    assert enumerate_oriented(n, statistics) == []
    # Searched exactly when 3 divides n(n-1): n = 6 and 9, not 5 and 8.
    assert (statistics.nodes > 0) == (n * (n - 1) % 3 == 0)


def test_the_orbit_identity_failing_is_reported(monkeypatch: pytest.MonkeyPatch) -> None:
    """A canonicalization that miscounts automorphisms must not pass silently."""

    def miscounted(triples: list[Triple], n: int) -> tuple[tuple[Triple, ...], int]:
        form, automorphisms = canonical(triples, n)
        return form, automorphisms * 2

    monkeypatch.setattr(oriented, "canonical", miscounted)
    result = enumerate_classes(7, expected=SMALL_REFERENCE_COUNTS[7])
    assert not result.orbit_identity_holds
    assert not result.passed
    assert result.problems == ["the orbit identity sum 2n(n-1)/|Aut| does not reproduce the count"]


@pytest.mark.parametrize("n", [3, 0, True, 7.0, "7"])
def test_n_must_be_an_integer_of_at_least_four(n: Any) -> None:
    with pytest.raises(MapError):
        enumerate_oriented(n)
    with pytest.raises(MapError):
        enumerate_classes(n)


@pytest.mark.parametrize("n", [4, 7, 10])
def test_the_search_is_the_golden_search(n: int) -> None:
    new = enumerate_classes(n)
    found = [
        enumerate_oriented(n),
        new.classes,
        new.labelled,
        new.orbit_count,
        new.automorphism_histogram,
    ]
    assert digest(found) == SEARCH_GOLDEN[n]


def test_wrong_expectations_and_references_are_reported() -> None:
    result = enumerate_classes(7, expected=(3, 1), reference={})
    assert not result.passed
    assert result.reference_compared and result.reference_matches is False
    assert len(result.problems) == 2
    found = enumerate_classes(7)
    same = enumerate_classes(7, reference=dict.fromkeys(found.classes, "x"))
    assert same.passed and same.reference_matches


def test_a_reference_must_equal_the_classes_found(monkeypatch: pytest.MonkeyPatch) -> None:
    """Neither a proper superset nor a proper non-empty subset of the classes passes."""
    found = enumerate_classes(7)
    (form,) = found.classes
    (other,) = enumerate_classes(4).classes
    superset = enumerate_classes(7, reference={form: "found", other: "extra"})
    assert superset.reference_matches is False and not superset.passed

    # Split the one class of n = 7 into its labelled maps (each its own "class", with
    # automorphism group of order 2n(n-1), so the orbit identity still holds).
    def split(triples: list[Triple], n: int) -> tuple[tuple[Triple, ...], int]:
        return tuple(sorted(triples)), 2 * n * (n - 1)

    monkeypatch.setattr(oriented, "canonical", split)
    two = enumerate_classes(7)
    assert two.class_count == 2 and two.passed
    subset = enumerate_classes(7, reference={min(two.classes): "one"})
    assert subset.orbit_identity_holds
    assert subset.reference_matches is False and not subset.passed
    assert subset.problems == [
        "the reference holds 1 maps with n = 7; the search found 2 classes and they do not agree"
    ]


def test_the_orbit_identity_is_checked_per_class() -> None:
    result = enumerate_classes(7)
    framings = 2 * 7 * 6
    for count, automorphisms in result.classes.values():
        assert count == framings // automorphisms


def test_canonical_form_agrees_with_brute_force_relabelling() -> None:
    triples = enumerate_oriented(7)[0]
    form, automorphisms = canonical(list(triples), 7)
    framed = []
    for relabel in itertools.permutations(range(7)):
        image = tuple(sorted(tuple(sorted(relabel[x] for x in t)) for t in triples))
        link = {tuple(sorted(x for x in t if x != 0)) for t in image if 0 in t}
        # The canonical form minimizes among labelings with the prescribed link at 0.
        if link == {(i, i + 1) for i in range(1, 6)} | {(1, 6)}:
            framed.append(image)
    assert form == min(framed)
    assert automorphisms == framed.count(form)


def test_canonical_forms_are_invariant_and_equal_to_the_goldens_on_relabelled_maps() -> None:
    generator = random.Random(20261006)
    seen = []
    for n in (4, 7):
        for triples in enumerate_oriented(n):
            form = canonical(list(triples), n)
            for _ in range(5):
                relabel = list(range(n))
                generator.shuffle(relabel)
                moved = sorted(sorted_triple(relabel[x] for x in t) for t in triples)
                assert canonical(moved, n) == form
                seen.append([canonical(moved, n), link_cycle(moved, 0, n)])
    assert digest(seen) == RELABELLED_GOLDEN


def test_classes_of_names_each_class_once_and_skips_other_n() -> None:
    tetrahedron = CombinatorialMap(4, itertools.combinations(range(1, 5), 3))
    seven = [
        CombinatorialMap(7, [(a + 1, b + 1, c + 1) for a, b, c in t]) for t in enumerate_oriented(7)
    ]
    assert len(seven) == 2
    classes = classes_of([("t", tetrahedron), ("a", seven[0])], 7)
    assert list(classes.values()) == ["a"]
    assert set(classes) == set(enumerate_classes(7).classes)
    assert canonical_map(seven[0]) == canonical_map(seven[1])
    with pytest.raises(MapError, match="isomorphic"):
        classes_of([("a", seven[0]), ("b", seven[1])], 7)


def test_the_summary_lists_the_classes_in_canonical_order() -> None:
    summary = enumerate_classes(7).summary()
    assert summary["class_count"] == 1 and summary["labelled_count"] == 2
    assert summary["arithmetic"] == "exact integers"
    assert summary["classes"][0]["multiplicity"] == 2
