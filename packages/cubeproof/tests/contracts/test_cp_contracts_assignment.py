"""Canonical assignment bitsets: padded standard base64, LSB first (specification §4.8)."""

from __future__ import annotations

import base64
import random
from typing import Any

import cp_corpus
import pytest

from cubeproof.base.errors import ContractError
from cubeproof.contracts.assignment import (
    assignment_from_true,
    decode_assignment,
    encode_assignment,
)

VECTORS = cp_corpus.vectors("assignment")


def _values(true: list[int], variables: int) -> tuple[bool, ...]:
    return tuple(i + 1 in set(true) for i in range(variables))


@pytest.mark.parametrize("case", VECTORS["cases"], ids=lambda c: f"{c['variables']}:{c['true']}")
def test_assignment_vectors(case: dict[str, Any]) -> None:
    values = _values(case["true"], case["variables"])
    assert encode_assignment(values) == case["assignment"]
    assert decode_assignment(case["assignment"], case["variables"]) == values
    assert assignment_from_true(case["true"], case["variables"]) == case["assignment"]


@pytest.mark.parametrize("case", VECTORS["invalid"], ids=lambda c: c["why"])
def test_invalid_assignment_vectors(case: dict[str, Any]) -> None:
    with pytest.raises(ContractError) as info:
        decode_assignment(case["assignment"], case["variables"])
    assert info.value.rule == "attempt.assignment"


@pytest.mark.parametrize(
    ("text", "variables"),
    [
        ("BQ==", 2),
        ("EA==", 4),
        ("AAI=", 9),
        ("AA==", 17),
        ("é===", 3),
        ("BQ==\r\n", 3),
        ("\nBQ==", 3),
        ("BQ==BQ==", 3),
        ("B===", 3),
        ("====", 3),
        ("BQ", 3),
        ("AAAAAA==", 24),
    ],
)
def test_more_noncanonical_bitsets(text: str, variables: int) -> None:
    with pytest.raises(ContractError):
        decode_assignment(text, variables)


def test_decode_refuses_foreign_types() -> None:
    for bad in (None, 5, b"AQ==", ["AQ=="]):
        with pytest.raises(ContractError):
            decode_assignment(bad, 1)  # type: ignore[arg-type]
    with pytest.raises(ContractError):
        decode_assignment("AQ==", -1)


def test_assignment_from_true_refuses_out_of_range_variables() -> None:
    for bad in ([0], [4], [-1], [True]):
        with pytest.raises(ContractError):
            assignment_from_true(bad, 3)


def test_random_round_trips_against_an_independent_packing() -> None:
    rng = random.Random(1040)
    for variables in range(0, 70):
        for _ in range(10):
            values = tuple(rng.random() < 0.5 for _ in range(variables))
            raw = bytearray((variables + 7) // 8)
            for i, value in enumerate(values):
                if value:
                    raw[i // 8] |= 1 << (i % 8)
            expected = base64.b64encode(bytes(raw)).decode("ascii")
            assert encode_assignment(values) == expected
            assert decode_assignment(expected, variables) == values
