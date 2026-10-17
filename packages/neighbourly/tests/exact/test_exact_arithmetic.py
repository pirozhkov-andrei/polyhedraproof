"""neighbourly.exact and neighbourly.geometry: exact values, their errors, and their goldens.

The oracle and the geometry are pinned by regression goldens (SHA-256 of the canonical JSON;
fractions as numerator and denominator).
"""

from __future__ import annotations

import hashlib
import itertools
import json
import random
from fractions import Fraction
from typing import Any

import pytest

from neighbourly.exact import (
    GeometryError,
    bracket,
    determinant,
    homogeneous_planes,
    oracle_from_planes,
)
from neighbourly.geometry import affine_point, line_coordinate

#: digest([signs, degenerate]) of ``oracle_from_planes`` of ``random_planes(seed, 7, 3)``.
ORACLE_GOLDEN = {
    0: "b6c08c0f0102d42dcb6fe35fcb29dee4cca981bec77e9611e6255773af5eaf04",
    1: "555611f29a1e59dcc94188cc583544a213c532bb309c29b3d45cd3b3d97c0685",
    2: "ea106ebc1e28a720a6566d3f77903620e257a8b69e43c1b85eaf280925bd7049",
}
#: digest of the [affine_point, line_coordinate] (or "no point") of every ordered triple.
GEOMETRY_GOLDEN = "fd484545a5bc7d43001c8e556ddb34279e1f93fe70da2cad23693b1de416bcef"


def canon(value: Any) -> Any:
    """The JSON form the golden values are frozen in (dicts keep their order, sets sorted)."""
    if value is None or isinstance(value, (bool, int, str)):
        return value
    if isinstance(value, Fraction):
        return ["fraction", value.numerator, value.denominator]
    if isinstance(value, dict):
        return ["dict", [[canon(k), canon(v)] for k, v in value.items()]]
    if isinstance(value, (list, tuple)):
        return [canon(v) for v in value]
    if isinstance(value, (set, frozenset)):
        return ["set", sorted((canon(v) for v in value), key=_text)]
    raise TypeError(f"no canonical form for {type(value)}")


def _text(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def digest(value: Any) -> str:
    return hashlib.sha256(_text(canon(value)).encode("utf-8")).hexdigest()


def random_planes(seed: int, n: int, span: int = 9) -> list[list[Fraction]]:
    generator = random.Random(seed)
    return [[Fraction(generator.randint(-span, span)) for _ in range(4)] for _ in range(n)]


def test_determinants_of_known_matrices() -> None:
    f = Fraction
    assert determinant([[f(2)]]) == 2
    assert determinant([[f(1), f(2)], [f(3), f(4)]]) == -2
    assert determinant([[f(0), f(1)], [f(1), f(0)]]) == -1  # a row swap changes the sign
    assert determinant([[f(1), f(2)], [f(2), f(4)]]) == 0
    assert determinant([[f(1, 2), f(1, 3)], [f(1, 5), f(1, 7)]]) == f(1, 14) - f(1, 15)
    assert determinant([]) == 1


def test_a_non_square_matrix_is_refused() -> None:
    with pytest.raises(GeometryError):
        determinant([[Fraction(1), Fraction(2)]])


def test_determinant_agrees_with_the_leibniz_formula() -> None:
    generator = random.Random(11)
    for size in (1, 2, 3, 4):
        for _ in range(20):
            matrix = [
                [Fraction(generator.randint(-5, 5)) for _ in range(size)] for _ in range(size)
            ]
            expected = Fraction(0)
            for permutation in itertools.permutations(range(size)):
                inversions = sum(
                    1
                    for a in range(size)
                    for b in range(a + 1, size)
                    if permutation[a] > permutation[b]
                )
                term = Fraction(-1 if inversions % 2 else 1)
                for row, column in enumerate(permutation):
                    term *= matrix[row][column]
                expected += term
            assert determinant(matrix) == expected


def test_the_plane_at_infinity_is_element_zero() -> None:
    rows = homogeneous_planes([[Fraction(x) for x in (1, 2, 3, 4)]])
    assert rows == [[0, 0, 0, 1], [1, 2, 3, 4]]
    assert all(isinstance(x, Fraction) for row in rows for x in row)


@pytest.mark.parametrize("seed", range(3))
def test_the_oracle_is_the_golden_oracle(seed: int) -> None:
    planes = random_planes(seed, 7, span=3)  # small span: some degenerate subsets
    new = oracle_from_planes(planes)
    assert digest([new.signs, new.degenerate]) == ORACLE_GOLDEN[seed]
    rows = homogeneous_planes(planes)
    for subset in itertools.combinations(range(8), 4):
        assert new(subset) == (1 if bracket(rows, subset) < 0 else 0)


def test_orientation_bits_are_attached_not_defaulted() -> None:
    oracle = oracle_from_planes(random_planes(5, 4))
    with pytest.raises(GeometryError, match="orientation bit s_f for face 2"):
        oracle.orientation(2)
    oriented = oracle.with_orientations({1: 3, 2: 0})
    assert (oriented.orientation(1), oriented.orientation(2)) == (1, 0)
    assert oracle.orientations is None
    with pytest.raises(GeometryError):
        oriented.orientation(3)


def test_points_and_line_coordinates_agree_with_the_goldens_and_with_the_planes() -> None:
    planes = random_planes(20261006, 6)
    rows = homogeneous_planes(planes)
    found: list[Any] = []
    for i, j, k in itertools.permutations(range(1, 7), 3):
        try:
            point = affine_point(rows, i, j, k)
        except GeometryError:
            found.append("no point")
            continue
        for plane in (i, j, k):
            assert sum(rows[plane][m] * point[m] for m in range(3)) + rows[plane][3] == 0
        found.append([point, line_coordinate(rows, i, j, k)])
    assert digest(found) == GEOMETRY_GOLDEN


def test_parallel_planes_have_no_point() -> None:
    f = Fraction
    rows = homogeneous_planes(
        [[f(1), f(0), f(0), f(0)], [f(1), f(0), f(0), f(1)], [f(0), f(1), f(0), f(0)]]
    )
    with pytest.raises(GeometryError, match="single point"):
        affine_point(rows, 1, 2, 3)
