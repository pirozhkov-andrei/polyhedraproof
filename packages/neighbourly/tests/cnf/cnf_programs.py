"""Seeded random programs of builder operations, replayed on two builders and compared.

Used by the differential tests of ``test_cnf_builder.py`` (Builder against the frozen reference
Formula of ``reference_formula.py``).
"""

from __future__ import annotations

import random
from collections.abc import Callable, Sequence
from typing import Any

Op = tuple[str, tuple[Any, ...]]
LAYERS = ("brackets", "S", "H", "A", "B", "I", "gauge")


def bracket_oracle(seed: int) -> Callable[[Sequence[int]], int]:
    def oracle(elements: Sequence[int]) -> int:
        return (sum(elements) * 7 + seed) % 3 % 2

    return oracle


def literals(rng: random.Random, variables: int, count: int, invalid: bool) -> list[Any]:
    out: list[Any] = []
    for _ in range(count):
        if invalid and rng.random() < 0.03:
            out.append(rng.choice([0, variables + 1, -(variables + 1), True, 1.5]))
        elif variables:
            out.append(rng.choice([1, -1]) * rng.randint(1, variables))
        else:
            out.append(1)  # no variable yet: an invalid literal
    return out


def program(seed: int, steps: int, oracle: bool, invalid: bool) -> list[Op]:
    """A random sequence of operations; values passed to new_variable are 0/1.

    With an oracle, gates get only valid literals: the reference looks an invalid gate input
    up in its value table and raises ``KeyError``, the Builder raises ``CnfError`` (see
    ``test_an_invalid_gate_input_with_a_witness_is_a_cnf_error``).
    """
    rng = random.Random(seed)
    ops: list[Op] = []
    variables = 0
    gate_invalid = invalid and not oracle
    for _ in range(steps):
        kind = rng.choice(
            ["layer", "bump", "var", "var", "clause", "clause", "forbid", "axor", "dxor", "and"]
        )
        if oracle and variables == 0 and kind in ("axor", "dxor", "and"):
            kind = "var"
        if kind == "layer":
            ops.append(("begin_layer", (rng.choice(LAYERS),)))
        elif kind == "bump":
            ops.append(("bump", (rng.randint(1, 3),)))
        elif kind == "var":
            value = rng.randint(0, 1) if oracle else None
            if oracle and invalid and rng.random() < 0.05:
                # Refused in both; the variable is allocated without a value. The reference
                # raises KeyError wherever it is used, the Builder treats it as unknown, so the
                # program ends here (only states reachable without a prior error are compared).
                ops.append(("new_variable", (None,)))
                break
            ops.append(("new_variable", (value,)))
            variables += 1
        elif kind == "clause":
            length = rng.choice([0, 1, 2, 2, 3, 3, 4, 5])
            tag = rng.choice(["", "t", f"c{rng.randint(0, 9)}"])
            ops.append(("add_clause", (literals(rng, variables, length, invalid), tag)))
        elif kind == "forbid":
            length = rng.randint(0, 4)
            lits = literals(rng, variables, length, invalid)
            values = [rng.randint(0, 1) for _ in lits]
            if invalid and rng.random() < 0.05:
                values = values[:-1] if values else [2]
            ops.append(("forbid", (lits, values, "f")))
        elif kind == "axor":
            length = rng.randint(0, 9)
            chain = literals(rng, variables, length, gate_invalid)
            ops.append(("assert_xor", (chain, rng.randint(0, 3), "x")))
        elif kind == "dxor":
            length = rng.randint(0, 7)
            ops.append(("define_xor", (literals(rng, variables, length, gate_invalid), "d")))
        else:
            a, b = literals(rng, variables, 2, gate_invalid)
            ops.append(("define_and", (a, b, "a")))
    return ops


def state(builder: Any) -> dict[str, Any]:
    """Everything a builder holds that both classes expose."""
    counts = {k: (v.variables, v.clauses, v.items) for k, v in builder.counts.items()}
    return {
        "variables": builder.variables,
        "clauses": list(builder.clauses),
        "tags": list(builder.tags),
        "values": dict(builder.values),
        "counts": counts,
        "count_order": list(builder.counts),
        "violations": {k: list(v) for k, v in builder.violations.items()},
        "layer": builder.layer,
    }


def replay(builder: Any, ops: list[Op], error: type[Exception]) -> list[Any]:
    """Run `ops`; record each result or error (messages compared, except new_variable's)."""
    results: list[Any] = []
    for name, args in ops:
        try:
            results.append(("ok", getattr(builder, name)(*args)))
        except error as exc:
            results.append(("error", str(exc) if name != "new_variable" else "missing value"))
        except (KeyError, TypeError) as exc:  # e.g. literal_value of an unknown variable
            results.append(("raised", type(exc).__name__))
    return results
