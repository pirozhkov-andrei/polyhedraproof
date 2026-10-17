"""The gate encodings, checked by exhausting their truth tables.

A gate that is wrong on one signed input pattern would produce a formula that is still well
formed, still solvable, and no longer the formula the article describes. So every gate is
compared with its definition on every assignment, in both directions: no model of the gate's
clauses disagrees with the definition, and no input assignment is lost.
"""

from __future__ import annotations

import itertools
from collections import Counter

import pytest

from neighbourly.cnf import Builder
from neighbourly.cnf.encodings import XOR_CHUNK


def truth(literal: int, values: dict[int, int]) -> int:
    return int(bool(values[abs(literal)]) != (literal < 0))


def build(literals: tuple[int, ...]) -> Builder:
    builder = Builder()
    builder.begin_layer("test")
    for _ in range(max((abs(x) for x in literals), default=0)):
        builder.new_variable()
    return builder


def models(builder: Builder) -> list[dict[int, int]]:
    out = []
    for bits in itertools.product((0, 1), repeat=builder.variables):
        values = dict(enumerate(bits, 1))
        if all(any(truth(x, values) for x in clause) for clause in builder.clauses):
            out.append(values)
    return out


def input_patterns(inputs: int) -> Counter[tuple[int, ...]]:
    return Counter(dict.fromkeys(itertools.product((0, 1), repeat=inputs), 1))


XOR_INPUTS = [
    (1,),
    (-1,),
    (1, -2),
    (1, 1, -2),
    (1, -1),
    (1, -2, 3),
    (1, -2, 3, -4),
    (1, -2, 3, -4, 5),
    (-1, 2, -3, 4, -5, 6),
    (-1, 2, -3, 4, -5, 6, -7),
    (1, 2, 3, 4, 5, 6, 7, 8),
]


@pytest.mark.parametrize("literals", XOR_INPUTS)
def test_define_xor_is_exactly_the_xor_of_its_literals(literals: tuple[int, ...]) -> None:
    builder = build(literals)
    inputs = builder.variables
    output = builder.define_xor(literals)
    extensions: Counter[tuple[int, ...]] = Counter()
    for values in models(builder):
        assert truth(output, values) == sum(truth(x, values) for x in literals) % 2
        extensions[tuple(values[v] for v in range(1, inputs + 1))] += 1
    # No input assignment is lost, and no Tseitin variable is left free.
    assert extensions == input_patterns(inputs)


@pytest.mark.parametrize("literals", [(1, 2), (1, -2), (-1, -2), (1, 1), (1, -1)])
def test_define_and_is_exactly_the_conjunction(literals: tuple[int, int]) -> None:
    builder = build(literals)
    inputs = builder.variables
    output = builder.define_and(*literals)
    extensions: Counter[tuple[int, ...]] = Counter()
    for values in models(builder):
        assert truth(output, values) == int(all(truth(x, values) for x in literals))
        extensions[tuple(values[v] for v in range(1, inputs + 1))] += 1
    assert extensions == input_patterns(inputs)


@pytest.mark.parametrize(
    "literals", [(), (1,), (-1,), (1, -1), (1, -2, 3, -4, 5), (1, 2, -3, 4, 5, -6, 7, 8, 9)]
)
@pytest.mark.parametrize("rhs", [0, 1, 2, 3])
def test_assert_xor_keeps_exactly_the_assignments_with_that_parity(
    literals: tuple[int, ...], rhs: int
) -> None:
    builder = build(literals)
    inputs = builder.variables
    builder.assert_xor(literals, rhs)
    kept: Counter[tuple[int, ...]] = Counter()
    for values in models(builder):
        kept[tuple(values[v] for v in range(1, inputs + 1))] += 1
    expected: Counter[tuple[int, ...]] = Counter()
    for bits in itertools.product((0, 1), repeat=inputs):
        values = dict(enumerate(bits, 1))
        if sum(truth(x, values) for x in literals) % 2 == rhs % 2:
            expected[bits] = 1
    assert kept == expected


def test_the_xor_chunk_is_four_literals() -> None:
    """Chunk size is part of the formula bytes (specification §13.1)."""
    assert XOR_CHUNK == 4
    builder = build((1, 2, 3, 4))
    builder.assert_xor((1, 2, 3, 4), 0, "t")
    assert builder.variables == 4 and len(builder.clauses) == 8
    builder = build((1, 2, 3, 4, 5))
    builder.assert_xor((1, 2, 3, 4, 5), 1, "t")
    # helper 6 = 1^2^3 (8 clauses over 1,2,3,6), then 6^4^5 = 1 (4 clauses)
    assert builder.variables == 6 and len(builder.clauses) == 12
    assert builder.clauses[:2] == [(1, 2, 3, -6), (1, 2, -3, 6)]
    assert builder.clauses[8:] == [(6, 4, 5), (6, -4, -5), (-6, 4, -5), (-6, -4, 5)]


def test_define_and_clause_shape() -> None:
    builder = build((1, 2))
    output = builder.define_and(1, -2, "g")
    assert output == 3
    assert builder.clauses == [(-3, 1), (-3, -2), (3, -1, 2)]
    assert builder.tags == [("test", "g")] * 3


def test_define_xor_allocates_its_output_before_the_chain() -> None:
    builder = build((1, 2, 3, 4, 5))
    output = builder.define_xor((1, 2, 3, 4, 5), "d")
    # output 6 first; the chain [1..5, 6] has six literals: helper 7 = 1^2^3, then 7^4^5^6 = 0
    assert output == 6 and builder.variables == 7
    assert builder.clauses[0] == (1, 2, 3, -7)
    assert builder.clauses[-1] == (-7, -4, -5, 6)  # the odd pattern (1, 1, 1, 0) comes last
