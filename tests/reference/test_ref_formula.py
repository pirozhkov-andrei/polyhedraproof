"""The 59 formulas against a reference written from the article alone.

``ref_paper.py`` was written from the text of ``paper/faces12-en.tex`` before the encoder was
read; it shares no code, no variable numbering, no sign convention and no XOR splitting with
``neighbourly.encoding``. ``ref_adapter.analyse`` takes from the encoder its clauses, the names
of its variables and three choices among alternatives that are all sound (the cut point of
layer A, the pinned corner, the gauge brackets), checks each choice for admissibility, and
shows, for all assignments of the bracket bits at once:

* the substantive clauses are exactly the ones the article prescribes for the map (layers H
  and A, B, the vertex clauses of I, the gauge), compared as sets;
* every other clause belongs to an acyclic list of definitions that forbids no assignment of
  the brackets, and the polynomial over GF(2) of every named variable is the one of the
  article's formula (paper: thm:order, def:onb, lem:turn, lem:sf, lem:parity);
* the gauge brackets are independent (paper: cor:gauge) and the formula without the gauge is
  invariant under the reorientation group (paper: lem:gaugegroup).

``ref_formula_check.work`` adds direct geometry: on random arrangements of twelve planes the
value of every variable equals the predicate computed from points and vectors, and a boundary
clause is violated exactly when two segments cross. A clause the article does not prescribe
is a strengthening and fails here whether or not the golden hashes were updated with it
(paper: thm:necessity; decision 0004).

That the choices are the article's own is required separately: the cut point and the pin by
the reference, the larger end ``z1`` and the gauge brackets by the pinned hash of the bytes.

The fast tests take the maps whose formula bytes the fast tier pins (1, 2 and 59); the slow
test takes all 59.
"""

from __future__ import annotations

import pytest
from ref_formula_check import work
from ref_paper import paper_counts, selftest_dictionary

#: Substantive clauses of a formula with twelve faces, counted from the article
#: (paper: def:formula, app:numbers): H, A (transitivity), B (boundary), I (vertex), gauge.
EXPECTED = {"pred_H": 15840, "pred_A": 2880, "pred_B": 528, "pred_Ivert": 132, "gauge_rank": 13}


def check(map_id: int, arrangements: int) -> None:
    found, sha_ok, sha, problems, info, stats, _seconds = work((map_id, arrangements, 1))
    assert found == map_id
    assert problems == [], problems[:5]
    # choices the adapter reads from the encoder and only checks for admissibility: they must
    # be the article's (the cut point of layer A, the pinned corner)
    assert info["pin_is_paper_choice"] and info.get("notes", []) == [], info.get("notes")
    assert sha_ok, f"map {map_id}: the analysed bytes {sha} are not the pinned formula"
    assert {name: info.get(name) for name in EXPECTED} == EXPECTED
    assert (info["vars"], info["clauses"]) == (5257, 52177)
    assert stats.get("arrangements", 0) == arrangements


@pytest.mark.parametrize("map_id", [1, 2, 59])
def test_the_formula_of_a_map_is_the_formula_of_the_article(map_id: int) -> None:
    check(map_id, 2)


@pytest.mark.slow
@pytest.mark.parametrize("map_id", range(1, 60))
def test_each_of_the_59_formulas_is_the_formula_of_the_article(map_id: int) -> None:
    check(map_id, 3)


def test_the_reference_agrees_with_geometry_on_small_arrangements() -> None:
    """The reference's own dictionary (bracket bits to the order, turn, boundary and cut
    predicates, and their behaviour under reorientation) on random planes with four and seven
    faces, and its count of the article's formula with twelve faces."""
    assert selftest_dictionary(4, 60, 1)["ord"] == 60 * 24
    seven = selftest_dictionary(7, 12, 2)
    assert all(seven[name] > 0 for name in ("ord", "onb", "turn", "Bv", "d", "group")), seven
    counts = paper_counts(12)
    assert (counts["X_vars"], counts["H_clauses"]) == (715, EXPECTED["pred_H"])
    assert (counts["B_vars"], counts["I_vertex_clauses"]) == (528, EXPECTED["pred_Ivert"])
