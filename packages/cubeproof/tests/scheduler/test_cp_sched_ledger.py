"""Reservation ledgers: the remeasurement formula, restaging and no double counting (specification
§8.2-§8.3)."""

from __future__ import annotations

import random

import pytest

from cubeproof.coordinator.ledger import (
    CPU,
    MEMORY,
    Ledger,
    LedgerError,
    Measure,
    Need,
    ResourceBook,
    disk,
)

G = "work"


def book(cpu: int = 4000, memory: int = 1000, work: int = 500) -> ResourceBook:
    return ResourceBook({CPU: cpu, MEMORY: memory, disk(G): work})


def mem(n: int) -> Need:
    return Need(0, n)


def measure(headroom: int | None = None, used: int | None = None) -> dict[str, Measure]:
    return {MEMORY: Measure(headroom, used)}


# -- the formula ------------------------------------------------------------------------------


def test_safe_new_capacity_is_h_minus_the_not_yet_materialized_reservations() -> None:
    ledger = Ledger(MEMORY, 1000)
    ledger.outstanding = 10
    # R = 10, U = 4, H = 20: safe = 20 - (10 - 4) = 14
    assert ledger.safe_new_capacity(Measure(20, 4)) == 14
    assert ledger.refusal(14, Measure(20, 4)) is None
    assert ledger.refusal(15, Measure(20, 4)) == "headroom"


def test_uncertain_used_is_zero() -> None:
    ledger = Ledger(MEMORY, 1000)
    ledger.outstanding = 10
    assert ledger.safe_new_capacity(Measure(20, None)) == 10
    assert ledger.safe_new_capacity(Measure(20, 0)) == 10


def test_used_above_the_reservations_does_not_add_capacity() -> None:
    ledger = Ledger(MEMORY, 1000)
    ledger.outstanding = 10
    assert ledger.safe_new_capacity(Measure(20, 90)) == 20


def test_reservations_are_not_subtracted_twice_from_a_measured_headroom() -> None:
    """R = 60 is fully materialized (U = 60), so the 40 bytes free now are all new capacity.

    A ledger that redefined the budget as free space and then subtracted R again would see
    40 - 60 < 0 and refuse; the formula of specification §8.2 admits exactly 40."""
    ledger = Ledger(MEMORY, 100)
    ledger.outstanding = 60
    assert ledger.safe_new_capacity(Measure(40, 60)) == 40
    assert ledger.refusal(40, Measure(40, 60)) is None
    # the same free space with nothing materialized is already spoken for
    assert ledger.safe_new_capacity(Measure(40, 0)) == 0
    assert ledger.refusal(1, Measure(40, 0)) == "headroom"


def test_the_total_budget_binds_even_with_plenty_of_headroom() -> None:
    ledger = Ledger(MEMORY, 100)
    ledger.outstanding = 60
    assert ledger.refusal(41, Measure(10**9, 60)) == "budget"
    assert ledger.refusal(40, Measure(10**9, 60)) is None


def test_without_a_measured_headroom_only_the_budget_remains() -> None:
    ledger = Ledger(MEMORY, 100)
    ledger.outstanding = 60
    assert ledger.safe_new_capacity(None) == 40
    assert ledger.safe_new_capacity(Measure(None, 5)) == 40


def test_zero_is_always_admitted() -> None:
    ledger = Ledger(MEMORY, 10)
    ledger.outstanding = 50
    assert ledger.refusal(0, Measure(0, 0)) is None


# -- the book ---------------------------------------------------------------------------------


def test_reserve_release_and_the_invariant() -> None:
    b = book()
    first = b.reserve("t1", "solve", Need(1000, 300, ((G, 100),)))
    assert first.need.amounts() == {CPU: 1000, MEMORY: 300, disk(G): 100}
    b.reserve("t2", "check", Need(1000, 200))
    assert (b.outstanding(CPU), b.outstanding(MEMORY), b.outstanding(disk(G))) == (2000, 500, 100)
    b.check()
    b.release("t1")
    assert (b.outstanding(CPU), b.outstanding(MEMORY), b.outstanding(disk(G))) == (1000, 200, 0)
    b.check()
    with pytest.raises(LedgerError) as unknown:
        b.release("t1")
    assert unknown.value.rule == "ledger.unknown"


def test_a_refused_reservation_changes_nothing() -> None:
    b = book(memory=500)
    b.reserve("t1", "solve", mem(400))
    with pytest.raises(LedgerError) as exceeded:
        b.reserve("t2", "solve", Need(1000, 200, ((G, 10),)))
    assert exceeded.value.rule == "ledger.exceeded"
    assert "memory" in str(exceeded.value)
    assert (b.outstanding(CPU), b.outstanding(disk(G))) == (0, 0)
    assert [r.task_id for r in b.reservations()] == ["t1"]


def test_a_task_holds_one_reservation() -> None:
    b = book()
    b.reserve("t1", "solve", mem(10))
    with pytest.raises(LedgerError) as duplicate:
        b.reserve("t1", "solve", mem(10))
    assert duplicate.value.rule == "ledger.duplicate"
    assert b.outstanding(MEMORY) == 10


def test_restaging_asks_only_for_the_increase() -> None:
    """A sealed proof (disk only) becomes a check (cpu, memory, the same disk): the disk bytes
    are the same bytes, not a second reservation."""
    b = book(memory=500, work=300)
    b.reserve("t1", "solve", Need(1000, 400, ((G, 250),)))
    b.restage("t1", "sealed", Need(0, 0, ((G, 120),)))  # the solver exited: shrink
    assert (b.outstanding(CPU), b.outstanding(MEMORY), b.outstanding(disk(G))) == (0, 0, 120)
    b.reserve(
        "t2", "solve", Need(1000, 500, ((G, 180),))
    )  # reuses the freed cpu/ram, fills the disk
    # the check needs 120 disk it already holds: only cpu and memory are new, and memory is full
    with pytest.raises(LedgerError):
        b.restage("t1", "check", Need(1000, 300, ((G, 120),)))
    b.release("t2")
    b.restage("t1", "check", Need(1000, 300, ((G, 120),)))
    assert (b.outstanding(CPU), b.outstanding(MEMORY), b.outstanding(disk(G))) == (1000, 300, 120)
    b.check()


def test_a_refused_restage_leaves_the_old_reservation() -> None:
    b = book(memory=100)
    b.reserve("t1", "sealed", Need(0, 0, ((G, 5),)))
    before = b.reservations()
    with pytest.raises(LedgerError):
        b.restage("t1", "check", Need(1000, 101, ((G, 5),)))
    assert b.reservations() == before
    b.check()


def test_restaging_an_unknown_task_is_refused() -> None:
    with pytest.raises(LedgerError) as unknown:
        book().restage("nobody", "check", mem(1))
    assert unknown.value.rule == "ledger.unknown"


def test_a_decrease_is_never_refused_even_over_a_lowered_ceiling() -> None:
    b = book(memory=100)
    b.reserve("t1", "solve", mem(80))
    b.set_total(MEMORY, 10)
    b.restage("t1", "solve", mem(40))
    assert b.outstanding(MEMORY) == 40


def test_a_lowered_total_never_revokes_work_and_refuses_new_work_until_it_fits() -> None:
    b = book(memory=100)
    b.reserve("t1", "solve", mem(60))
    b.reserve("t2", "solve", mem(30))
    assert b.set_total(MEMORY, 50) == 50
    assert b.deficits() == {MEMORY: 40}
    assert b.outstanding(MEMORY) == 90  # nothing was revoked
    assert not b.fits(mem(1))
    b.release("t1")
    assert b.deficits() == {}
    assert b.fits(mem(20)) and not b.fits(mem(21))


def test_the_total_is_never_raised_above_the_initial_ceiling() -> None:
    b = book(memory=100)
    assert b.set_total(MEMORY, 10**9) == 100
    b.set_total(MEMORY, 30)
    assert b.ledger(MEMORY).ceiling == 100
    assert b.set_total(MEMORY, 70) == 70  # restoring is allowed, up to the ceiling
    assert b.set_total(MEMORY, 10**9) == 100


def test_idle_fit_is_against_the_initial_ceiling_not_a_lowered_total() -> None:
    b = book(memory=100)
    b.set_total(MEMORY, 10)
    assert b.idle_shortfall(mem(100)) is None
    refused = b.idle_shortfall(mem(101))
    assert refused is not None and refused.dimension == MEMORY
    assert b.idle_shortfall(Need(5000, 0)).dimension == CPU  # type: ignore[union-attr]
    assert b.idle_shortfall(Need(0, 0, (("elsewhere", 1),))).dimension == disk("elsewhere")  # type: ignore[union-attr]


def test_disk_amounts_of_one_group_are_one_amount() -> None:
    need = Need(0, 0, ((G, 5), ("other", 1), (G, 7)))
    assert need.disk == (("other", 1), (G, 12))
    assert (Need.of(0, 0, **{G: 3}) + Need.of(0, 0, **{G: 4})).amounts() == {disk(G): 7}
    assert Need(0, 0, ((G, 0),)).empty


def test_shared_storage_competes_for_one_group_budget() -> None:
    """Two paths of one group are one ledger: the second reservation sees the first."""
    b = book(work=100)
    b.reserve("solve", "solve", Need(0, 0, ((G, 70),)))
    with pytest.raises(LedgerError):
        b.reserve("copy", "copy", Need(0, 0, ((G, 40),)))
    b.reserve("copy", "copy", Need(0, 0, ((G, 30),)))


def test_independent_groups_have_independent_budgets() -> None:
    b = ResourceBook({CPU: 1000, MEMORY: 100, disk("a"): 10, disk("b"): 10})
    b.reserve("t1", "solve", Need(0, 0, (("a", 10),)))
    b.reserve("t2", "solve", Need(0, 0, (("b", 10),)))
    assert not b.fits(Need(0, 0, (("a", 1),)))


def test_the_book_needs_cpu_and_memory() -> None:
    with pytest.raises(ValueError):
        ResourceBook({CPU: 1})


def test_stage_totals_for_the_status() -> None:
    b = book()
    b.reserve("t1", "solve", Need(1000, 300, ((G, 100),)))
    b.reserve("t2", "solve", Need(1000, 100))
    b.reserve("t3", "sealed", Need(0, 0, ((G, 40),)))
    assert b.by_stage() == {
        "sealed": {disk(G): 40},
        "solve": {CPU: 2000, MEMORY: 400, disk(G): 100},
    }


def test_negative_or_non_integer_amounts_are_refused() -> None:
    for bad in (-1, 1.5, True):
        with pytest.raises(ValueError):
            Need(bad)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        Measure(-1)


# -- random operation sequences against an independent model ------------------------------------


@pytest.mark.parametrize("seed", range(40))
def test_random_operations_keep_the_ledger_equal_to_its_reservations(seed: int) -> None:
    rng = random.Random(seed)
    totals = {CPU: 6000, MEMORY: 1000, disk(G): 800, disk("b"): 300}
    b = ResourceBook(totals)
    ceiling = dict(totals)
    model: dict[str, dict[str, int]] = {}
    total = dict(totals)

    def measures() -> dict[str, Measure]:
        return {
            d: Measure(
                rng.choice([None, rng.randint(0, 1500)]), rng.choice([None, rng.randint(0, 1200)])
            )
            for d in (MEMORY, disk(G), disk("b"))
        }

    def random_need() -> Need:
        return Need(
            rng.choice([0, 1000, 3000]),
            rng.choice([0, 50, 200, 700]),
            tuple((g, rng.choice([0, 30, 300])) for g in (G, "b") if rng.random() < 0.6),
        )

    def refused_by_the_formula(
        amounts: dict[str, int], old: dict[str, int], at: dict[str, Measure]
    ) -> bool:
        for dimension, amount in amounts.items():
            r = amount - old.get(dimension, 0)
            if r <= 0:
                continue
            outstanding = sum(m.get(dimension, 0) for m in model.values())
            if outstanding + r > total[dimension]:
                return True
            measure = at.get(dimension)
            if measure is not None and measure.headroom is not None:
                used = 0 if measure.used is None else measure.used
                if r > measure.headroom - max(0, outstanding - used):
                    return True
        return False

    for _ in range(120):
        action = rng.choice(["reserve", "reserve", "restage", "release", "lower", "restore"])
        at = measures()
        names = sorted(model)
        if action == "reserve":
            name, need = f"t{rng.randint(0, 9)}", random_need()
            if name in model:
                with pytest.raises(LedgerError):
                    b.reserve(name, "s", need, at)
                continue
            refused = refused_by_the_formula(need.amounts(), {}, at)
            try:
                b.reserve(name, "s", need, at)
            except LedgerError:
                assert refused
            else:
                assert not refused
                model[name] = need.amounts()
        elif action == "restage" and names:
            name, need = rng.choice(names), random_need()
            refused = refused_by_the_formula(need.amounts(), model[name], at)
            try:
                b.restage(name, "s2", need, at)
            except LedgerError:
                assert refused
            else:
                assert not refused
                model[name] = need.amounts()
        elif action == "release" and names:
            name = rng.choice(names)
            b.release(name)
            del model[name]
        elif action in ("lower", "restore"):
            dimension = rng.choice(sorted(totals))
            value = (
                rng.randint(0, 2 * totals[dimension])
                if action == "restore"
                else rng.randint(0, totals[dimension])
            )
            total[dimension] = min(ceiling[dimension], value)
            assert b.set_total(dimension, value) == total[dimension]
        b.check()
        for dimension in totals:
            assert b.outstanding(dimension) == sum(m.get(dimension, 0) for m in model.values())
            assert b.ledger(dimension).total <= ceiling[dimension]
