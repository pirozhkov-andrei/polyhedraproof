"""Genuine realizations satisfy every clause, whatever the labelling and the representative.

The tetrahedron (four faces) and the Szilassi polyhedron (seven) are the known polyhedra with
pairwise adjacent faces. ``ref_realization_check.run`` takes them, verified as embedded
polyhedra by an exact test of its own (``ref_paper.check_realization``), through small
perturbations into general position, mirror images, affine and projective images, sign flips
of the covectors and relabellings of the faces; for each it builds the formula of the
relabelled map with the encoder, moves the realization into gauge geometrically, and requires
every clause to hold and every variable to have the value of its geometric predicate
(paper: thm:necessity, cor:gauge). A clause that a genuine realization violates would make
the formula stronger than the article proves.

The fixture tests of ``neighbourly`` do this for one labelling of one perturbation; here the
labellings and representatives vary. No realization with twelve faces is known, so this
exercises the encoder on small maps only; ``test_ref_formula.py`` covers the formulas with
twelve faces clause by clause.
"""

from __future__ import annotations

import pytest
from ref_realization_check import STATS, run


def test_realizations_with_four_and_seven_faces_satisfy_their_formulas() -> None:
    problems = run(tets=4, npert=1, perm_step=360, seed=3)
    assert problems == [], problems[:5]
    assert STATS["n4_realizations_satisfying_all_clauses"] == 5 * 24
    assert STATS["n7_project_fixture_checked"] == 8  # the packaged planes under every gauge face
    for image in ("perturbed", "mirror", "affine", "projective", "signflip"):
        assert STATS["n7_pool_" + image] == 1, image


@pytest.mark.slow
def test_realizations_in_many_labellings_satisfy_their_formulas() -> None:
    """Every 37th of the 5040 labellings of seven faces, two perturbations with their images,
    and the labellings that carry the polyhedron of the literature onto the packaged map."""
    problems = run(tets=40, npert=2, perm_step=37, seed=3)
    assert problems == [], problems[:5]
    assert STATS["n7_project_map_labelled_realizations"] > 0
