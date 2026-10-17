"""Witness checking (specification §13.1).

With a witness, every clause whose variable values are all known is checked as it is emitted.
A violated clause is collected with its tag (compatibility mode) or raises (strict mode).
Unknown values never become false; complete mode refuses a variable without a value.
"""

from __future__ import annotations

from collections.abc import Hashable, Sequence

import pytest

from neighbourly.cnf import Builder, CnfError, OracleWitness, WitnessViolation


class Table:
    """A witness that knows some names and nothing else."""

    def __init__(self, known: dict[tuple[Hashable, ...], int | None]) -> None:
        self.known = known
        self.asked: list[tuple[Hashable, ...]] = []

    def __call__(self, name: tuple[Hashable, ...], /) -> int | None:
        self.asked.append(name)
        return self.known.get(name)


def test_named_variables_take_their_value_from_the_witness() -> None:
    witness = Table({("x", 1): 1, ("x", 2): 0})
    builder = Builder(witness)
    a = builder.new_variable(name=("x", 1))
    b = builder.new_variable(name=("x", 2))
    c = builder.new_variable(name=("x", 3))
    assert builder.values == {a: 1, b: 0}
    assert builder.names == {a: ("x", 1), b: ("x", 2), c: ("x", 3)}
    assert witness.asked == [("x", 1), ("x", 2), ("x", 3)]
    assert builder.known_value(-b) == 1 and builder.known_value(c) is None


def test_a_passed_value_takes_precedence_over_the_witness() -> None:
    witness = Table({("x",): 1})
    builder = Builder(witness)
    variable = builder.new_variable(0, ("x",))
    assert builder.values == {variable: 0}
    assert witness.asked == []


def test_a_violated_known_clause_is_collected_with_its_tag() -> None:
    builder = Builder(Table({}))
    builder.begin_layer("L")
    builder.new_variable(0)
    builder.new_variable(1)
    builder.add_clause([1], "first")
    builder.add_clause([1, -2])  # untagged: the clause text is recorded
    builder.add_clause([2], "true")
    builder.begin_layer("M")
    builder.add_clause([], "empty")  # the empty clause is always violated
    assert builder.violations == {"L": ["first", "(1, -2)"], "M": ["empty"]}
    assert len(builder.clauses) == 4  # collecting never drops a clause


def test_unknown_values_never_become_false() -> None:
    builder = Builder(Table({}))
    builder.new_variable(0)
    builder.new_variable()  # unknown
    builder.add_clause([1, 2], "undecided")  # 1 is false, 2 unknown: not checked
    builder.add_clause([2], "unknown")
    builder.add_clause([-1, 2], "satisfied")
    assert builder.violations == {}


def test_strict_mode_raises_on_the_first_violation() -> None:
    builder = Builder(Table({}), strict=True)
    builder.begin_layer("S")
    builder.new_variable(1)
    builder.add_clause([1], "fine")
    with pytest.raises(WitnessViolation) as caught:
        builder.add_clause([-1], "bad")
    assert (caught.value.layer, caught.value.tag, caught.value.clause) == ("S", "bad", (-1,))
    assert isinstance(caught.value, CnfError)
    assert builder.violations == {}


def test_complete_mode_refuses_a_variable_without_a_value() -> None:
    builder = Builder(Table({("y",): 1}), complete=True)
    builder.new_variable(name=("y",))
    with pytest.raises(CnfError, match="needs a value"):
        builder.new_variable(name=("z",))
    with pytest.raises(CnfError, match="needs a value"):
        builder.new_variable()


@pytest.mark.parametrize("value", [2, -1, "1"])
def test_a_value_other_than_zero_or_one_is_refused(value: object) -> None:
    with pytest.raises(CnfError, match="not 0 or 1"):
        Builder(Table({})).new_variable(value)  # type: ignore[arg-type]
    with pytest.raises(CnfError, match="not 0 or 1"):
        Builder(Table({("w",): value})).new_variable(name=("w",))  # type: ignore[dict-item]


def test_without_a_witness_nothing_is_checked_and_values_are_ignored() -> None:
    builder = Builder()
    builder.new_variable(0)
    builder.new_variable(7, ("n",))
    builder.add_clause([1])
    builder.add_clause([])
    assert builder.values == {} and builder.violations == {}
    assert builder.names == {2: ("n",)}
    assert builder.known_value(1) is None
    with pytest.raises(KeyError):
        builder.literal_value(1)


def test_gate_outputs_get_values_in_three_valued_logic() -> None:
    builder = Builder(Table({}))
    t, f, u = builder.new_variable(1), builder.new_variable(0), builder.new_variable()
    assert builder.known_value(builder.define_and(t, -f)) == 1
    assert builder.known_value(builder.define_and(f, u)) == 0  # false AND unknown is false
    assert builder.known_value(builder.define_and(t, u)) is None
    assert builder.known_value(builder.define_xor([t, f, -t])) == 1  # 1 ^ 0 ^ 0
    assert builder.known_value(builder.define_xor([t, -f, f, t])) == 1  # 1 ^ 1 ^ 0 ^ 1
    assert builder.known_value(builder.define_xor([t, u])) is None
    assert builder.violations == {}
    # long chains: every helper gets the XOR of its three inputs
    chain = [builder.new_variable(v) for v in (1, 1, 0, 1, 0, 1, 1)]
    builder.assert_xor(chain, 1, "chain")
    assert builder.violations == {}
    builder.assert_xor(chain, 0, "wrong parity")
    assert builder.violations == {"?": ["wrong parity"]}


def test_the_oracle_witness_answers_for_tuples_of_plane_indices_only() -> None:
    calls: list[Sequence[int]] = []

    def oracle(elements: Sequence[int]) -> int:
        calls.append(tuple(elements))
        return 3  # the low bit is the value

    witness = OracleWitness(oracle)
    assert witness((0, 1, 2, 3)) == 1
    assert witness(("S", 1)) is None
    assert witness((True, 1)) is None
    assert calls == [(0, 1, 2, 3)]
    assert witness.oracle is oracle


def test_the_oracle_adapter_reproduces_the_complete_oracle_mode() -> None:
    builder = Builder(OracleWitness(lambda subset: 0), complete=True)
    builder.begin_layer("test")
    variable = builder.new_variable(0)
    builder.add_clause((variable,), "always false here")
    assert builder.violations["test"] == ["always false here"]
    with pytest.raises(CnfError):
        builder.new_variable()  # oracle mode needs a value for every variable
    bracket = builder.new_variable(name=(0, 1, 2, 3))
    assert builder.values[bracket] == 0
