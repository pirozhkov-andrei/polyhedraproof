"""neighbourly.checks.identities: the self-test identity checks, for any encodable map.

For map 1 with the default seed the generic checks give the recorded golden lines exactly
(the corpus line stays with ``neighbourly.corpus12.corpus_problems``); on n = 4, 7, 15, 16
they run on the map given. Negative controls show that each structural check can fail.
"""

from __future__ import annotations

from typing import Any

import pytest

from neighbourly import corpus12
from neighbourly.checks import (
    SEED,
    Check,
    adjacency_check,
    corner_symmetry_check,
    cut_order_check,
    gauge_check,
    identities,
    identity_checks,
    layer_i_check,
    order_bits_check,
    random_planes,
    selftest_planes,
)
from neighbourly.data import read_bytes
from neighbourly.encoding import Encoder, build_encoder
from neighbourly.exact import homogeneous_planes
from neighbourly.geometry import line_coordinate as real
from neighbourly.maps import CombinatorialMap

#: The golden self-test lines of map 1: (name, passed, detail, printed line).
SELFTEST_LINES_GOLDEN = [
    (
        "random planes are in general position",
        True,
        "0 degenerate 4-subsets",
        "  [  OK] random planes are in general position  0 degenerate 4-subsets",
    ),
    (
        "order bits (paper: thm:order): X_0ijk xor X_0ijl xor X_ijkl is the order on L_ij",
        True,
        "200 random quadruples, 0 disagreements",
        (
            "  [  OK] order bits (paper: thm:order): X_0ijk xor X_0ijl xor X_ijkl is the order on "
            "L_ij  200 random quadruples, 0 disagreements"
        ),
    ),
    (
        (
            "cut order (paper: lem:cutorder, rem:counts): rank-2 GP iff the cut order is "
            "transitive, n = 4,5,6, with (n-1)! 2^(n-1) and n! tournaments"
        ),
        True,
        "0 mismatches; 48/24, 384/120, 3840/720",
        (
            "  [  OK] cut order (paper: lem:cutorder, rem:counts): rank-2 GP iff the cut order is "
            "transitive, n = 4,5,6, with (n-1)! 2^(n-1) and n! tournaments  0 mismatches; 48/24, "
            "384/120, 3840/720"
        ),
    ),
    (
        "the shipped maps are neighbourly, orientable and pairwise non-isomorphic",
        True,
        "",
        "  [  OK] the shipped maps are neighbourly, orientable and pairwise non-isomorphic",
    ),
    (
        "gauge (paper: cor:gauge): one representative of each reorientation orbit",
        True,
        "8,192 sign patterns on 13 pinned brackets",
        (
            "  [  OK] gauge (paper: cor:gauge): one representative of each reorientation orbit  "
            "8,192 sign patterns on 13 pinned brackets"
        ),
    ),
    (
        "corner bits (paper: lem:sf): independent of the order the neighbours are named",
        True,
        "132 corners, 0 disagreements",
        (
            "  [  OK] corner bits (paper: lem:sf): independent of the order the neighbours are "
            "named  132 corners, 0 disagreements"
        ),
    ),
    (
        "cyclic adjacency (paper: lem:adjacency): consecutive edges meet at real vertices",
        True,
        "0 mismatches",
        (
            "  [  OK] cyclic adjacency (paper: lem:adjacency): consecutive edges meet at real "
            "vertices  0 mismatches"
        ),
    ),
    (
        "Layer I (paper: lem:I): three clauses at every vertex, one bit per corner",
        True,
        "132 clauses over 44 vertices, 132 corner bits",
        (
            "  [  OK] Layer I (paper: lem:I): three clauses at every vertex, one bit per corner  "
            "132 clauses over 44 vertices, 132 corner bits"
        ),
    ),
    (
        "at most one reflex corner at a vertex (paper: lem:onereflex, rem:octants)",
        True,
        "admissible profiles {(1, 1, 1): 16, (1, 1, 3): 48}",
        (
            "  [  OK] at most one reflex corner at a vertex (paper: lem:onereflex, rem:octants)  "
            "admissible profiles {(1, 1, 1): 16, (1, 1, 3): 48}"
        ),
    ),
]


def load(name: str) -> CombinatorialMap:
    paths = {
        "4": ("tetrahedron", "tetrahedron.txt"),
        "7": ("szilassi", "csaszar_n7.txt"),
        "15": ("n15", "n15.txt"),
        "16": ("n16", "n16.txt"),
    }
    if name == "12":
        return corpus12.load_map(1)
    folder, matrix = paths[name]
    return CombinatorialMap.from_text(read_bytes("fixtures", folder, matrix).decode("utf-8"))


def test_map_1_gives_the_golden_self_test_lines() -> None:
    golden = SELFTEST_LINES_GOLDEN
    corpus = [line for line in golden if line[0].startswith("the shipped maps")]
    assert len(corpus) == 1 and corpus[0][1]
    new = [(c.name, c.passed, c.detail, str(c)) for c in identity_checks(corpus12.load_map(1))]
    assert new == [line for line in golden if line not in corpus]
    assert corpus12.corpus_problems() == []


@pytest.mark.parametrize("name", ["4", "7", "12"])
def test_every_identity_holds_with_the_fixture_planes(name: str) -> None:
    checks = identity_checks(load(name))
    assert len(checks) == 8
    assert all(check.passed for check in checks), [str(c) for c in checks if not c.passed]


@pytest.mark.parametrize("name", ["15", "16"])
def test_every_identity_holds_on_the_stored_fixtures(name: str) -> None:
    cmap = load(name)
    checks = identity_checks(cmap, planes=random_planes(cmap.n, SEED))
    assert len(checks) == 8
    assert all(check.passed for check in checks), [str(c) for c in checks if not c.passed]
    assert f"{1 << (cmap.n + 1):,} sign patterns" in checks[3].detail


def test_a_degenerate_plane_family_stops_after_the_first_line() -> None:
    """With the default seed and coefficients -9..9, sixteen planes are not in general position."""
    checks = identity_checks(load("16"))
    assert [c.passed for c in checks] == [False]
    assert checks[0].detail == "1 degenerate 4-subsets"
    with pytest.raises(ValueError, match="need 16 planes"):
        identity_checks(load("16"), planes=selftest_planes(15))


def test_the_check_line_format() -> None:
    assert str(Check("x", True)) == "  [  OK] x"
    assert str(Check("x", False, "why")) == "  [  **] x  why"


# -- negative controls ------------------------------------------------------------------------


def test_order_bits_are_compared_with_the_affine_order(monkeypatch: Any) -> None:
    rows = homogeneous_planes(random_planes(12, 1))
    assert order_bits_check(rows).passed
    # reverse the geometric direction along every line: every sample must now disagree
    monkeypatch.setattr(identities, "line_coordinate", lambda r, i, j, k: -real(r, i, j, k))
    check = order_bits_check(rows)
    assert not check.passed and check.detail == "200 random quadruples, 200 disagreements"


def test_cut_order_runs_on_the_sizes_asked_for() -> None:
    check = cut_order_check((4,))
    assert check.passed and check.detail == "0 mismatches; 48/24"


def test_a_dependent_gauge_is_caught(monkeypatch: Any) -> None:
    encoder = build_encoder(load("7"))
    targets = encoder.gauge_targets(1)
    monkeypatch.setattr(encoder, "gauge_targets", lambda face=None: [*targets[:-1], targets[0]])
    check = gauge_check(encoder)
    assert not check.passed and "128 sign patterns" in check.detail


class _Uncanonical(Encoder):
    """The corner literal without its link-direction canonicalization (rem:order-matters)."""

    def corner_literal(self, face: int, a: int, b: int) -> int:
        literal = super().corner_literal(face, a, b)
        return literal if self.map.link_successor(face).get(a) == b else -literal


def test_an_uncanonical_corner_literal_is_caught() -> None:
    encoder = _Uncanonical(load("7")).build()
    check = corner_symmetry_check(encoder)
    assert not check.passed and check.detail == "42 corners, 42 disagreements"


def test_a_wrong_reality_test_is_caught(monkeypatch: Any) -> None:
    cmap = load("7")
    assert adjacency_check(cmap).passed
    monkeypatch.setattr(CombinatorialMap, "is_real", lambda self, a, b, c: False)
    check = adjacency_check(cmap)
    assert not check.passed and check.detail == "84 mismatches"


def test_a_missing_vertex_clause_is_caught() -> None:
    encoder = build_encoder(load("7"))
    index = next(i for i, (_, tag) in enumerate(encoder.formula.tags) if tag.startswith("I:"))
    del encoder.formula.tags[index]
    check = layer_i_check(encoder)
    assert not check.passed
    assert check.detail.startswith("41 clauses over 14 vertices")
