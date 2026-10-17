"""The cut-order census (paper: lem:cutorder, rem:counts) and the octant table
(paper: lem:onereflex, rem:octants), each exhaustive for the sizes it is run on.

The cut-order census (m = 4..6 fast, m = 7 slow), an independent cyclic-triangle computation
(m = 4..6) and the octant table. The results are pinned by regression goldens.
"""

from __future__ import annotations

import dataclasses
import hashlib
import itertools
import json
from math import factorial

import pytest

from neighbourly.enumeration.tournaments import census
from neighbourly.enumeration.vertex_profiles import (
    ADMISSIBLE_PROFILES,
    OCTANTS,
    admissible_profiles,
    at_most_one_reflex_corner,
    profile,
)

#: The golden ``dataclasses.astuple(census(m))``.
CENSUS_GOLDEN = {
    4: (4, 64, 48, 24, 0),
    5: (5, 1024, 384, 120, 0),
    6: (6, 32768, 3840, 720, 0),
}
#: The golden ``admissible_profiles()``.
PROFILES_GOLDEN = {(1, 1, 1): 16, (1, 1, 3): 48}
#: SHA-256 of the JSON list of the ``profile`` of every octant set, in the order below.
OCTANT_PROFILES_GOLDEN = "87c6dfb8759ef1e31d0220862145a8854462fc9afd56d57e36f5dad0169de3ff"


@pytest.mark.parametrize("m", [4, 5, 6])
def test_the_census_reproduces_the_lemma_and_both_counts(m: int) -> None:
    result = census(m)
    assert result.passed
    assert result.mismatches == 0
    assert result.tournaments == 2 ** (m * (m - 1) // 2)
    assert result.satisfying_gp == factorial(m - 1) * 2 ** (m - 1)
    assert result.transitive == factorial(m)
    assert dataclasses.astuple(result) == CENSUS_GOLDEN[m]


@pytest.mark.slow
def test_the_lemma_and_the_counts_on_seven_elements() -> None:
    """Every tournament on seven elements (2^21; about half a minute)."""
    result = census(7)
    assert result.tournaments == 2**21
    assert (result.satisfying_gp, result.transitive, result.mismatches) == (46_080, 5_040, 0)
    assert result.passed


def triangle_check(m: int) -> tuple[int, int, int]:
    """`(mismatches, satisfying GP, transitive)` over every tournament on `m` elements.

    A second computation of lem:cutorder and rem:counts, written as test code from the
    definitions: it shares no code with :func:`census`, and it decides transitivity by looking
    for a cyclic triangle, where :func:`census` compares out-degrees.
    """

    def gp_holds(chi: dict[tuple[int, int], int], c: int, d: int, e: int, f: int) -> bool:
        first = chi[(c, d)] ^ chi[(e, f)]
        second = 1 ^ chi[(c, e)] ^ chi[(d, f)]
        third = chi[(c, f)] ^ chi[(d, e)]
        return not (first == second == third)

    def acyclic(relation: dict[tuple[int, int], int], elements: range) -> bool:
        return all(
            not (relation[(x, y)] and relation[(y, z)] and not relation[(x, z)])
            for x, y, z in itertools.permutations(elements, 3)
        )

    pairs = list(itertools.combinations(range(m), 2))
    mismatches = gp_count = transitive = 0
    for bits in range(1 << len(pairs)):
        chi: dict[tuple[int, int], int] = {}
        for position, (x, y) in enumerate(pairs):
            value = (bits >> position) & 1
            chi[(x, y)], chi[(y, x)] = value, value ^ 1
        gp = all(gp_holds(chi, *subset) for subset in itertools.combinations(range(m), 4))
        cut = {
            (x, y): chi[(x, y)] ^ (chi[(0, x)] if x else 0) ^ (chi[(0, y)] if y else 0)
            for x in range(m)
            for y in range(m)
            if x != y
        }
        mismatches += gp != acyclic(cut, range(m))
        gp_count += gp
        transitive += acyclic(chi, range(m))
    return mismatches, gp_count, transitive


@pytest.mark.parametrize("m", [4, 5, 6])
def test_a_second_computation_by_cyclic_triangles_agrees(m: int) -> None:
    mismatches, gp_count, transitive = triangle_check(m)
    assert mismatches == 0
    assert gp_count == factorial(m - 1) * 2 ** (m - 1)
    assert transitive == factorial(m)
    result = census(m)
    assert (result.mismatches, result.satisfying_gp, result.transitive) == (
        mismatches,
        gp_count,
        transitive,
    )


def test_the_census_needs_four_elements() -> None:
    with pytest.raises(ValueError):
        census(3)


def test_the_vertex_table_admits_only_two_profiles() -> None:
    profiles = admissible_profiles()
    assert set(profiles) == ADMISSIBLE_PROFILES
    assert profiles[(1, 1, 1)] == 16
    assert profiles[(1, 1, 3)] == 48
    assert at_most_one_reflex_corner()
    assert profiles == PROFILES_GOLDEN


def test_every_octant_set_has_the_golden_profile() -> None:
    found = [
        profile(list(chosen))
        for size in range(9)
        for chosen in itertools.combinations(OCTANTS, size)
    ]
    assert len(found) == 2 ** len(OCTANTS)
    text = json.dumps(found, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    assert hashlib.sha256(text.encode("utf-8")).hexdigest() == OCTANT_PROFILES_GOLDEN
