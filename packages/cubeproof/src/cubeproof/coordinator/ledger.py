"""Reservation ledgers: per-dimension budgets, per-task reservations, safe remeasurement.

Specification §8.2 and §8.3. One :class:`ResourceBook` holds one :class:`Ledger` per resource
dimension: ``cpu`` (milli-CPU), ``memory`` (bytes of scheduling budget) and one
``disk:<group>`` per independent storage group (paths of one backing storage share one group
and therefore one ledger, so the same retained bytes are never reserved in two ledgers). A
task holds exactly one :class:`Reservation` (its current stage and :class:`Need`); moving to
the next stage (:meth:`ResourceBook.restage`) replaces it, so a sealed proof that waits for
its check is the same disk bytes as the solve that produced it, never a second reservation.

For a ledger with outstanding reservations ``R``, measured occupation attributable to them
``U``, measured usable headroom ``H`` (after external costs and the safety reserve) and a
total budget, a new reservation ``r`` is admitted only if::

    r <= safe_new_capacity = max(0, H - max(0, R - U))   and   R + r <= total_budget

Uncertain ``U`` is taken as 0 (conservative) and unmeasured ``H`` leaves only the budget
condition. The total budget is **not** redefined as current free space, so full reservations
are never subtracted from a figure that already excludes them. The total may be lowered
(pressure) and restored, never above the initial ceiling (CLI value or first observation);
existing work is never revoked by a lowered ceiling, only new admissions are refused until
the outstanding amount fits again.

Reservations are accounting, not a guarantee: a reservation of physical memory says that the
scheduler will not start more work than its budget covers, never that the kernel will give
the memory (specification §1.4, §8.2).
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from cubeproof.base.errors import ResourceError

__all__ = [
    "CPU",
    "MEMORY",
    "Ledger",
    "LedgerError",
    "Measure",
    "Need",
    "Reservation",
    "ResourceBook",
    "Shortfall",
    "disk",
]

CPU = "cpu"
MEMORY = "memory"


def disk(group: str) -> str:
    """The dimension name of a storage group's disk ledger."""
    return f"disk:{group}"


class LedgerError(ResourceError):
    """A reservation request the book cannot take (``ledger.*``)."""


def _count(name: str, value: object) -> int:
    if type(value) is not int or value < 0:
        raise ValueError(f"{name} must be a nonnegative integer, not {value!r}")
    return value


@dataclass(frozen=True)
class Measure:
    """``headroom`` is H and ``used`` is U of the module doc; None: not measured."""

    headroom: int | None = None
    used: int | None = None

    def __post_init__(self) -> None:
        for name in ("headroom", "used"):
            value = getattr(self, name)
            if value is not None:
                _count(name, value)


@dataclass(frozen=True)
class Need:
    """What one stage reserves: milli-CPU, memory bytes and disk bytes per storage group."""

    cpu_milli: int = 0
    memory_bytes: int = 0
    disk: tuple[tuple[str, int], ...] = ()

    def __post_init__(self) -> None:
        _count("cpu_milli", self.cpu_milli)
        _count("memory_bytes", self.memory_bytes)
        merged: dict[str, int] = {}
        for group, amount in self.disk:
            if not isinstance(group, str) or not group:
                raise ValueError(f"{group!r} is not a storage group")
            merged[group] = merged.get(group, 0) + _count("disk bytes", amount)
        object.__setattr__(
            self, "disk", tuple((g, merged[g]) for g in sorted(merged) if merged[g] > 0)
        )

    @classmethod
    def of(cls, cpu_milli: int = 0, memory_bytes: int = 0, **disks: int) -> Need:
        """``Need.of(1000, 1 << 30, work=1 << 20)``; group ids that are not identifiers go
        through :meth:`with_disk`."""
        return cls(cpu_milli, memory_bytes, tuple(disks.items()))

    def with_disk(self, group: str, amount: int) -> Need:
        return Need(self.cpu_milli, self.memory_bytes, (*self.disk, (group, amount)))

    def amounts(self) -> dict[str, int]:
        """Nonzero amounts by dimension name (``cpu``, ``memory``, ``disk:<group>``)."""
        found: dict[str, int] = {}
        if self.cpu_milli:
            found[CPU] = self.cpu_milli
        if self.memory_bytes:
            found[MEMORY] = self.memory_bytes
        for group, amount in self.disk:
            found[disk(group)] = amount
        return found

    def __add__(self, other: Need) -> Need:
        return Need(
            self.cpu_milli + other.cpu_milli,
            self.memory_bytes + other.memory_bytes,
            (*self.disk, *other.disk),
        )

    @property
    def empty(self) -> bool:
        return not self.amounts()


@dataclass(frozen=True)
class Reservation:
    task_id: str
    stage: str
    need: Need


@dataclass(frozen=True)
class Shortfall:
    """Why a request does not fit: the first dimension (in name order) that refuses it."""

    dimension: str
    needed: int
    available: int
    total: int
    outstanding: int
    reason: str

    def __str__(self) -> str:
        return (
            f"{self.dimension}: need {self.needed}, available {self.available} "
            f"(total {self.total}, reserved {self.outstanding}; {self.reason})"
        )


class Ledger:
    """One dimension: a total budget under an initial ceiling and the outstanding amount."""

    def __init__(self, name: str, budget: int) -> None:
        self.name = name
        self.ceiling = _count("budget", budget)
        self.total = self.ceiling
        self.outstanding = 0

    @property
    def deficit(self) -> int:
        """How far the outstanding amount exceeds a lowered total (0 when it fits)."""
        return max(0, self.outstanding - self.total)

    def set_total(self, value: int) -> int:
        """Set the total budget, clamped to ``[0, ceiling]``; returns the value in force."""
        self.total = min(self.ceiling, _count("total", value))
        return self.total

    def safe_new_capacity(self, measure: Measure | None) -> int:
        """``max(0, H - max(0, R - U))``; with no usable H only the budget remains."""
        room = max(0, self.total - self.outstanding)
        if measure is None or measure.headroom is None:
            return room
        used = 0 if measure.used is None else measure.used
        return min(room, max(0, measure.headroom - max(0, self.outstanding - used)))

    def refusal(self, r: int, measure: Measure | None) -> str | None:
        """None if a new reservation ``r`` is admitted, otherwise the condition that fails."""
        if r <= 0:
            return None
        if self.outstanding + r > self.total:
            return "budget"
        if r > self.safe_new_capacity(measure):
            return "headroom"
        return None


class ResourceBook:
    """The ledgers of a run and the reservation of every task (module doc)."""

    def __init__(self, budgets: Mapping[str, int]) -> None:
        if CPU not in budgets or MEMORY not in budgets:
            raise ValueError("a resource book needs cpu and memory budgets")
        self._ledgers = {name: Ledger(name, value) for name, value in sorted(budgets.items())}
        self._held: dict[str, Reservation] = {}

    # -- inspection ------------------------------------------------------------------------

    @property
    def dimensions(self) -> tuple[str, ...]:
        return tuple(self._ledgers)

    def ledger(self, dimension: str) -> Ledger:
        try:
            return self._ledgers[dimension]
        except KeyError:
            raise LedgerError("ledger.dimension", f"no ledger {dimension!r}") from None

    def outstanding(self, dimension: str) -> int:
        return self.ledger(dimension).outstanding

    def reservations(self) -> tuple[Reservation, ...]:
        """Every reservation, sorted by task ID."""
        return tuple(self._held[k] for k in sorted(self._held))

    def get(self, task_id: str) -> Reservation | None:
        return self._held.get(task_id)

    def by_stage(self) -> dict[str, dict[str, int]]:
        """Reserved amounts per stage and dimension (status: "per-stage ledgers")."""
        found: dict[str, dict[str, int]] = {}
        for reservation in self._held.values():
            stage = found.setdefault(reservation.stage, {})
            for dimension, amount in reservation.need.amounts().items():
                stage[dimension] = stage.get(dimension, 0) + amount
        return {s: dict(sorted(v.items())) for s, v in sorted(found.items())}

    def check(self) -> None:
        """The ledger invariant: outstanding == sum of reservations, for every dimension."""
        sums: dict[str, int] = dict.fromkeys(self._ledgers, 0)
        for reservation in self._held.values():
            for dimension, amount in reservation.need.amounts().items():
                sums[dimension] += amount
        for name, ledger in self._ledgers.items():
            if ledger.outstanding != sums[name]:
                raise LedgerError(
                    "ledger.invariant", f"{name}: {ledger.outstanding} != {sums[name]}"
                )

    # -- fit -------------------------------------------------------------------------------

    def idle_shortfall(self, need: Need) -> Shortfall | None:
        """Why ``need`` could not run on an idle machine (against the initial ceiling)."""
        for dimension, amount in sorted(need.amounts().items()):
            ledger = self._ledgers.get(dimension)
            if ledger is None:
                return Shortfall(dimension, amount, 0, 0, 0, "no such resource")
            if amount > ledger.ceiling:
                return Shortfall(
                    dimension, amount, ledger.ceiling, ledger.ceiling, 0, "exceeds the capacity"
                )
        return None

    def shortfall(
        self,
        need: Need,
        measures: Mapping[str, Measure] | None = None,
        *,
        replacing: str | None = None,
    ) -> Shortfall | None:
        """Why ``need`` does not fit now, or None. ``replacing`` names a held reservation
        whose amounts are already outstanding: only the increase is asked for."""
        old = self._held[replacing].need.amounts() if replacing in self._held else {}
        for dimension, amount in sorted(need.amounts().items()):
            ledger = self._ledgers.get(dimension)
            if ledger is None:
                return Shortfall(dimension, amount, 0, 0, 0, "no such resource")
            delta = amount - old.get(dimension, 0)
            measure = None if measures is None else measures.get(dimension)
            why = ledger.refusal(delta, measure)
            if why is not None:
                return Shortfall(
                    dimension,
                    delta,
                    ledger.safe_new_capacity(measure),
                    ledger.total,
                    ledger.outstanding,
                    why,
                )
        return None

    def available(self, dimension: str, measures: Mapping[str, Measure] | None = None) -> int:
        """``safe_new_capacity`` of one dimension: the most a new reservation could take."""
        measure = None if measures is None else measures.get(dimension)
        return self.ledger(dimension).safe_new_capacity(measure)

    def fits(
        self,
        need: Need,
        measures: Mapping[str, Measure] | None = None,
        *,
        replacing: str | None = None,
    ) -> bool:
        return self.shortfall(need, measures, replacing=replacing) is None

    # -- changes ---------------------------------------------------------------------------

    def reserve(
        self,
        task_id: str,
        stage: str,
        need: Need,
        measures: Mapping[str, Measure] | None = None,
    ) -> Reservation:
        """Take a reservation for a new task, or raise ``ledger.exceeded`` (nothing changes)."""
        if task_id in self._held:
            raise LedgerError("ledger.duplicate", f"task {task_id} already holds a reservation")
        refused = self.shortfall(need, measures)
        if refused is not None:
            raise LedgerError("ledger.exceeded", str(refused))
        return self._set(task_id, stage, need)

    def restage(
        self,
        task_id: str,
        stage: str,
        need: Need,
        measures: Mapping[str, Measure] | None = None,
    ) -> Reservation:
        """Replace a task's reservation by the next stage's, atomically.

        Only the increase per dimension is admitted (a decrease always succeeds): the
        bytes the task already holds are not asked for again, and nothing changes if any
        dimension refuses.
        """
        if task_id not in self._held:
            raise LedgerError("ledger.unknown", f"task {task_id} holds no reservation")
        refused = self.shortfall(need, measures, replacing=task_id)
        if refused is not None:
            raise LedgerError("ledger.exceeded", str(refused))
        return self._set(task_id, stage, need)

    def release(self, task_id: str) -> Reservation:
        """Give a task's reservation back."""
        held = self._held.pop(task_id, None)
        if held is None:
            raise LedgerError("ledger.unknown", f"task {task_id} holds no reservation")
        for dimension, amount in held.need.amounts().items():
            self._ledgers[dimension].outstanding -= amount
        return held

    def _set(self, task_id: str, stage: str, need: Need) -> Reservation:
        for dimension in need.amounts():
            if dimension not in self._ledgers:
                raise LedgerError("ledger.dimension", f"no ledger {dimension!r}")
        old = self._held.get(task_id)
        if old is not None:
            for dimension, amount in old.need.amounts().items():
                self._ledgers[dimension].outstanding -= amount
        for dimension, amount in need.amounts().items():
            self._ledgers[dimension].outstanding += amount
        reservation = Reservation(task_id, stage, need)
        self._held[task_id] = reservation
        return reservation

    def set_total(self, dimension: str, value: int) -> int:
        """Lower or restore a total budget (clamped to the initial ceiling)."""
        return self.ledger(dimension).set_total(value)

    def deficits(self) -> dict[str, int]:
        """Dimensions whose outstanding amount exceeds a lowered total (existing work runs on)."""
        return {n: ledger.deficit for n, ledger in self._ledgers.items() if ledger.deficit}
