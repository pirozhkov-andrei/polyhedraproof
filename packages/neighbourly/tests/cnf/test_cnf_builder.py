"""The Builder against the frozen reference Formula, operation by operation.

Specification §13.1 fixes allocation, clause order, XOR chunk sizes, Tseitin definitions and tag
order of the emission. Seeded random programs of builder operations (including invalid ones) run
on both classes; every return value, every raised error and the complete state afterwards
(variables, clauses, tags, values, counts, violations) must agree.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest
from cnf_programs import bracket_oracle, program, replay, state
from reference_formula import Formula as ReferenceFormula
from reference_formula import ReferenceFormulaError

from neighbourly.cnf import Builder, CnfError, LayerCounts, OracleWitness


@pytest.mark.parametrize("seed", range(150))
def test_random_programs_without_a_witness_match_the_reference(seed: int) -> None:
    ops = program(seed, 80, oracle=False, invalid=seed % 3 == 0)
    reference, new = ReferenceFormula(), Builder()
    assert replay(new, ops, CnfError) == replay(reference, ops, ReferenceFormulaError)
    assert state(new) == state(reference)


@pytest.mark.parametrize("seed", range(150))
def test_random_programs_with_an_oracle_match_the_reference(seed: int) -> None:
    ops = program(1000 + seed, 80, oracle=True, invalid=seed % 3 == 0)
    oracle = bracket_oracle(seed)
    reference = ReferenceFormula(oracle)
    new = Builder(OracleWitness(oracle), complete=True)
    assert replay(new, ops, CnfError) == replay(reference, ops, ReferenceFormulaError)
    assert state(new) == state(reference)


def test_the_programs_exercise_every_operation_and_violations() -> None:
    """Guard against a vacuous generator: errors, violations and long XOR chains occur."""
    seen: set[str] = set()
    violations = errors = 0
    long_chains = 0
    for seed in range(150):
        ops = program(1000 + seed, 80, oracle=True, invalid=seed % 3 == 0)
        seen |= {name for name, _ in ops}
        long_chains += sum(1 for n, a in ops if n == "assert_xor" and len(a[0]) > 4)
        reference = ReferenceFormula(bracket_oracle(seed))
        errors += sum(1 for r in replay(reference, ops, ReferenceFormulaError) if r[0] != "ok")
        violations += sum(len(v) for v in reference.violations.values())
    assert seen == {
        "begin_layer",
        "bump",
        "new_variable",
        "add_clause",
        "forbid",
        "assert_xor",
        "define_xor",
        "define_and",
    }
    assert violations > 100 and errors > 20 and long_chains > 100


@pytest.mark.parametrize("length", range(10))
@pytest.mark.parametrize("rhs", [0, 1])
def test_xor_chains_have_the_reference_shape(length: int, rhs: int) -> None:
    """Every chain length up to 9: same helpers, same clauses, same order."""
    reference, new = ReferenceFormula(), Builder()
    for builder in (reference, new):
        builder.begin_layer("x")
        for _ in range(length):
            builder.new_variable()
        builder.assert_xor([(-1) ** i * (i + 1) for i in range(length)], rhs, "tag")
    assert state(new) == state(reference)
    helpers = max(0, length - 4 + 1) // 2 if length > 4 else 0
    assert new.variables == length + helpers


@pytest.mark.parametrize("bad", [0, 3, -3, 1.5])
@pytest.mark.parametrize("gate", ["and", "xor", "assert"])
def test_an_invalid_gate_input_with_a_witness_is_a_cnf_error(bad: Any, gate: str) -> None:
    """Deviation from the reference on invalid input only: it raises KeyError from its value
    table."""
    reference = ReferenceFormula(bracket_oracle(0))
    new = Builder(OracleWitness(bracket_oracle(0)), complete=True)
    calls: dict[str, Callable[[Any], object]] = {
        "and": lambda b: b.define_and(1, bad),
        "xor": lambda b: b.define_xor([1, 2, bad]),
        "assert": lambda b: b.assert_xor([bad, 1, 2, 1, 2], 0),
    }
    for builder in (reference, new):
        builder.new_variable(1)
        builder.new_variable(0)
    with pytest.raises(KeyError):
        calls[gate](reference)
    with pytest.raises(CnfError):
        calls[gate](new)
    assert new.clauses == reference.clauses == []


def test_a_single_literal_xor_definition_is_the_literal_itself() -> None:
    builder = Builder()
    builder.new_variable()
    assert builder.define_xor([-1], "t") == -1
    assert builder.clauses == [] and builder.variables == 1


def test_tautologies_are_dropped_and_repeats_collapsed() -> None:
    builder = Builder()
    builder.begin_layer("test")
    builder.new_variable()
    builder.new_variable()
    builder.add_clause((1, -1))
    assert builder.clauses == []
    builder.add_clause((2, 1, 2, 1))
    assert builder.clauses == [(2, 1)]
    builder.add_clause(())
    assert builder.clauses == [(2, 1), ()]
    assert builder.counts["test"] == LayerCounts(variables=2, clauses=2, items=0)


@pytest.mark.parametrize("literal", [0, 3, -3, True, False, 1.0, "1"])
def test_invalid_literals_are_refused(literal: object) -> None:
    builder = Builder()
    builder.new_variable()
    builder.new_variable()
    with pytest.raises(CnfError, match="invalid CNF literal"):
        builder.add_clause([2, literal])  # type: ignore[list-item]
    assert builder.clauses == []


def test_a_value_equal_to_an_earlier_literal_merges_with_it() -> None:
    """The reference de-duplicates with dict.fromkeys, so `True` or `1.0` after `1` is that
    literal."""
    reference, new = ReferenceFormula(), Builder()
    for builder in (reference, new):
        builder.new_variable()
        builder.add_clause([1, True, 1.0])  # type: ignore[list-item]
    assert new.clauses == reference.clauses == [(1,)]
    assert type(new.clauses[0][0]) is int


def test_forbid_needs_one_bit_per_literal() -> None:
    builder = Builder()
    builder.new_variable()
    for literals, values in (([1], []), ([1], [2]), ([], [0])):
        with pytest.raises(CnfError):
            builder.forbid(literals, values)


def test_the_error_class_is_a_hook_for_producers() -> None:
    class ProducerError(CnfError):
        pass

    class Producing(Builder):
        error = ProducerError

    builder = Producing()
    with pytest.raises(ProducerError):
        builder.add_clause([1])
    with pytest.raises(ProducerError):
        builder.forbid([], [1])


def test_reporting_helpers() -> None:
    builder = Builder()
    builder.begin_layer("A")
    builder.new_variable()
    builder.add_clause([1], "a")
    builder.bump(2)
    builder.begin_layer("B")
    builder.add_clause([-1], "b")
    assert builder.layer_of(0) == "A" and builder.layer_of(1) == "B"
    assert builder.counts_table() == [("A", LayerCounts(1, 1, 2)), ("B", LayerCounts(0, 1, 0))]
    assert builder.tags == [("A", "a"), ("B", "b")]
