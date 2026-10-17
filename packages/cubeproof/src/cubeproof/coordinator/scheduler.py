"""The launch policy of the coordinator: priorities, check draining, impossible tasks, stalls.

Specification §8.4. After the loop has reaped and classified finished tasks, committed their
records and applied the state transitions, :meth:`Scheduler.plan` decides what to start, in
priority **checks, split work, solves**, and takes the reservation of every task it starts
(a launch decision is a reservation; the caller either starts the task or releases it).

- *Check draining.* The oldest queued check that does not fit now but fits an idle machine
  becomes the **reserved** check: no solve or split starts until it fits, and a younger
  check starts only if it leaves intact, in every dimension it touches, what the reserved
  check still needs. This deliberately may leave CPUs idle. The rule is stateless: the
  next tick recomputes the same oldest check, and since only running tasks release
  resources, the reserved check fits after finitely many completions (liveness argument in
  the tests: every release is monotone and nothing new is admitted that it needs).
- *Impossible tasks.* A task that cannot fit even an idle machine (against the initial
  ceilings) is never waited for: it is reported as :class:`Impossible` with the rule its
  stage applies immediately (a check: EXHAUSTED check memory/stack, handled by the leaf; a
  solve or split: ``node_stop(resource_blocked)``).
- *Stalls.* If nothing runs, nothing could be started and tasks are queued, no task can free
  a resource. After ``stall_patience_ms`` the plan carries a :class:`Stall` with the affected
  nodes and the capacities and requirements; the caller commits
  ``node_stop(resource_blocked)`` for them and exits 1. Never an indefinite spin.
- *Bounded ticks.* A tick examines at most ``max_examined`` candidates per queue and starts at
  most ``max_launches`` tasks, so the cost of a planning step does not grow with a queue of
  millions of frontier nodes. Hashing, copying, unit propagation and the splitter helper are
  never done here: they are leaf-attempt slices, I/O service jobs and helper processes that
  the loop starts as tasks with reservations (specification §8.1).

Reservations are admission accounting; no decision here is a promise of physical RAM.
"""

from __future__ import annotations

import enum
import time
from collections.abc import Callable, Iterable, Iterator, Mapping
from dataclasses import dataclass
from itertools import islice

from cubeproof.base.errors import ResourceError
from cubeproof.contracts.identity import node_id
from cubeproof.coordinator.ledger import Measure, Need, Reservation, ResourceBook, Shortfall

__all__ = [
    "Candidate",
    "Impossible",
    "Launch",
    "Plan",
    "Scheduler",
    "SchedulerError",
    "Stage",
    "Stall",
]

Key = tuple[str, tuple[int, ...]]


class SchedulerError(ResourceError):
    """A misuse of the scheduler (``scheduler.*``)."""


class Stage(str, enum.Enum):
    """Launch stages in priority order (specification §8.4)."""

    CHECK = "check"
    SPLIT = "split"
    SOLVE = "solve"


#: The rule applied at once to a queued task that cannot fit an idle machine (specification §8.4).
RULE_CHECK = "check_exhausted"
RULE_BLOCK = "resource_blocked"


@dataclass(frozen=True)
class Candidate:
    """A queued task: ``seq`` is its queue age (lower is older), ``need`` its full reservation.

    A task that already holds a reservation (a sealed proof waiting for its check holds its
    disk) has ``holds=True``: its launch is a restage that asks only for the increase.
    """

    task_id: str
    stage: Stage
    node: Key | None
    need: Need
    seq: int
    holds: bool = False

    @property
    def order(self) -> tuple[int, str]:
        node = "" if self.node is None else node_id(*self.node)
        return (self.seq, node)


@dataclass(frozen=True)
class Launch:
    """A started task: its candidate and the reservation taken for it."""

    candidate: Candidate
    reservation: Reservation


@dataclass(frozen=True)
class Impossible:
    """A queued task that cannot run on an idle machine, with the rule to apply now."""

    candidate: Candidate
    shortfall: Shortfall
    rule: str


@dataclass(frozen=True)
class Stall:
    """No progress is possible and nothing running can free a resource (specification §8.4)."""

    nodes: tuple[Key, ...]
    requirements: tuple[str, ...]
    capacities: Mapping[str, Mapping[str, int]]
    waited_ms: int


@dataclass(frozen=True)
class Plan:
    """The outcome of one planning step."""

    launches: tuple[Launch, ...]
    impossible: tuple[Impossible, ...]
    reserved_check: Candidate | None
    stall: Stall | None
    halted: bool
    reasons: tuple[str, ...]


class Scheduler:
    """Launch policy over one :class:`ResourceBook` (module doc)."""

    def __init__(
        self,
        book: ResourceBook,
        *,
        clock: Callable[[], int] = time.monotonic_ns,
        max_launches: int = 8,
        max_examined: int = 64,
        stall_patience_ms: int = 30_000,
    ) -> None:
        for name, value in (("max_launches", max_launches), ("max_examined", max_examined)):
            if type(value) is not int or value < 1:
                raise SchedulerError("scheduler.config", f"{name} must be a positive integer")
        if type(stall_patience_ms) is not int or stall_patience_ms < 0:
            raise SchedulerError("scheduler.config", "stall_patience_ms must be nonnegative")
        self.book = book
        self._clock = clock
        self.max_launches = max_launches
        self.max_examined = max_examined
        self.stall_patience_ms = stall_patience_ms
        self._idle_since: int | None = None

    # -- helpers ---------------------------------------------------------------------------

    def _delta(self, candidate: Candidate) -> dict[str, int]:
        held = self.book.get(candidate.task_id) if candidate.holds else None
        old = {} if held is None else held.need.amounts()
        wanted = candidate.need.amounts()
        delta = {d: a - old.get(d, 0) for d, a in wanted.items()}
        return {d: a for d, a in delta.items() if a > 0}

    def _take(
        self, candidate: Candidate, measures: Mapping[str, Measure] | None
    ) -> Launch | Shortfall:
        if candidate.holds and self.book.get(candidate.task_id) is None:
            raise SchedulerError(
                "scheduler.holds", f"{candidate.task_id} claims a reservation it does not hold"
            )
        replacing = candidate.task_id if candidate.holds else None
        refused = self.book.shortfall(candidate.need, measures, replacing=replacing)
        if refused is not None:
            return refused
        if candidate.holds:
            reservation = self.book.restage(
                candidate.task_id, candidate.stage.value, candidate.need, measures
            )
        else:
            reservation = self.book.reserve(
                candidate.task_id, candidate.stage.value, candidate.need, measures
            )
        return Launch(candidate, reservation)

    def _passes(
        self,
        candidate: Candidate,
        blocked: Candidate,
        measures: Mapping[str, Measure] | None,
    ) -> bool:
        """A younger check may start only if the reserved check keeps what it still needs in
        every dimension the younger one touches."""
        wanted = self._delta(blocked)
        for dimension, amount in self._delta(candidate).items():
            if self.book.available(dimension, measures) - amount < wanted.get(dimension, 0):
                return False
        return True

    def _capacities(self) -> dict[str, dict[str, int]]:
        return {
            d: {
                "total": self.book.ledger(d).total,
                "ceiling": self.book.ledger(d).ceiling,
                "outstanding": self.book.outstanding(d),
            }
            for d in self.book.dimensions
        }

    # -- the plan --------------------------------------------------------------------------

    def plan(
        self,
        *,
        checks: Iterable[Candidate] = (),
        splits: Iterable[Candidate] = (),
        solves: Iterable[Candidate] = (),
        measures: Mapping[str, Measure] | None = None,
        active: int = 0,
        halted: bool = False,
    ) -> Plan:
        """Decide what to start now. Queues are in queue order (oldest first); checks and
        splits are verified to be, solves are in the loop's fairness order.

        ``active`` is the number of running tasks (they will release resources); ``halted``
        means new work is stopped (anomaly or machine limit, user stop): nothing is started.
        """
        if halted:
            self._idle_since = None
            return Plan((), (), None, None, True, ("halted: no new work",))
        launches: list[Launch] = []
        impossible: list[Impossible] = []
        queued: list[tuple[Candidate, str]] = []
        reasons: list[str] = []
        blocked: Candidate | None = None
        full = False

        def examine(stage: Stage, queue: Iterable[Candidate]) -> Iterator[Candidate]:
            previous: tuple[int, str] | None = None
            for candidate in islice(queue, self.max_examined):
                if candidate.stage is not stage:
                    raise SchedulerError("scheduler.stage", f"{candidate.task_id} is not {stage}")
                if stage is not Stage.SOLVE:
                    if previous is not None and candidate.order < previous:
                        raise SchedulerError(
                            "scheduler.order", f"{stage.value} queue not oldest first"
                        )
                    previous = candidate.order
                yield candidate

        for candidate in examine(Stage.CHECK, checks):
            if len(launches) >= self.max_launches:
                full = True
                break
            gone = self.book.idle_shortfall(candidate.need)
            if gone is not None:
                impossible.append(Impossible(candidate, gone, RULE_CHECK))
                continue
            if blocked is not None and not self._passes(candidate, blocked, measures):
                queued.append((candidate, f"would delay the reserved check {blocked.task_id}"))
                continue
            taken = self._take(candidate, measures)
            if isinstance(taken, Launch):
                launches.append(taken)
            else:
                queued.append((candidate, str(taken)))
                if blocked is None:
                    blocked = candidate
                    reasons.append(f"draining for check {candidate.task_id}: {taken}")
        if blocked is None and not full:
            for stage, queue in ((Stage.SPLIT, splits), (Stage.SOLVE, solves)):
                for candidate in examine(stage, queue):
                    if len(launches) >= self.max_launches:
                        full = True
                        break
                    gone = self.book.idle_shortfall(candidate.need)
                    if gone is not None:
                        impossible.append(Impossible(candidate, gone, RULE_BLOCK))
                        continue
                    taken = self._take(candidate, measures)
                    if isinstance(taken, Launch):
                        launches.append(taken)
                    else:
                        queued.append((candidate, str(taken)))
                        reasons.append(f"{stage.value} {candidate.task_id} waits: {taken}")
                if full:
                    break
        stall = self._stall(launches, queued, active, full)
        return Plan(tuple(launches), tuple(impossible), blocked, stall, False, tuple(reasons))

    def _stall(
        self, launches: list[Launch], queued: list[tuple[Candidate, str]], active: int, full: bool
    ) -> Stall | None:
        if launches or full or active > 0 or not queued:
            self._idle_since = None
            return None
        now = self._clock()
        if self._idle_since is None:
            self._idle_since = now
        waited = (now - self._idle_since) // 1_000_000
        if waited < self.stall_patience_ms:
            return None
        requirements = tuple(
            f"{c.stage.value} {c.task_id} (needs {_describe(c.need)}): {why}" for c, why in queued
        )
        nodes = tuple(sorted({c.node for c, _ in queued if c.node is not None}))
        return Stall(nodes, requirements, self._capacities(), int(waited))


def _describe(need: Need) -> str:
    return ", ".join(f"{d}={a}" for d, a in sorted(need.amounts().items())) or "nothing"
