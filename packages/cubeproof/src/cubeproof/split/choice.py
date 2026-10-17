"""The common splitter interface (specification §9.1): choices, budgets, eligibility and the
fallback.

``choose(bundle, cube, k, pool, budget) -> SplitChoice`` returns ``{variables, status, info}``
with status ``chosen``, ``no_eligible``, ``budget`` or ``failed``. The variables are distinct,
unassigned variables of the pool (all variables when the pool is None); they are a structural
suggestion that the coordinator validates before it records a split.

Rules of the interface that live here:

- ``k`` is clamped by the caller to the remaining policy depth and to the number of unassigned
  variables (:func:`clamp_k`); at the depth limit the caller records STUCK without invoking
  any splitter, and ``k = 0`` is never a split, so a splitter refuses ``k < 1``.
- A variable is *eligible* if it is in the pool and assigned neither by the parent cube nor by
  unit propagation under it (:func:`eligible`).
- ``no_eligible`` means: no variable of the pool is eligible. Its info says how many
  variables the parent assigned, so the caller can tell a restricted pool without candidates
  (STUCK ``no_eligible_pool``) from a complete conflict-free assignment (the model path).
  ``budget`` and ``failed`` are different conditions (a resource or a failure, never a
  verdict); a parent that propagates to a conflict is a ``failed`` choice with stop
  ``parent_conflict``: the caller must schedule the checked unit route instead.
- :func:`lowest_eligible_choice` is the fallback for a helper that timed out or failed: the
  lowest eligible variables under the validated parent propagation. If that propagation cannot
  fit the resources, the node is blocked (status ``budget``), not the protocol.
"""

from __future__ import annotations

import itertools
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from cubeproof.base.errors import ConfigurationError, ContractError
from cubeproof.cnf.dimacs import Formula
from cubeproof.cnf.unit import UnitIndex, build_index, propagate
from cubeproof.contracts.identity import check_cube, check_split
from cubeproof.contracts.primitives import K_MAX
from cubeproof.contracts.values import JsonObject

CHOSEN = "chosen"
NO_ELIGIBLE = "no_eligible"
BUDGET = "budget"
FAILED = "failed"
STATUSES = (CHOSEN, NO_ELIGIBLE, BUDGET, FAILED)

#: Name recorded for the lowest-eligible fallback.
FALLBACK_ALGORITHM = "lowest-eligible"
#: Value of ``info.stop`` when the parent cube propagates to a conflict.
PARENT_CONFLICT = "parent_conflict"


@dataclass(frozen=True)
class SplitChoice:
    """A splitter's answer: ordered variables, a status and an open info object.

    ``chosen`` carries 1..K_MAX distinct positive variables; every other status carries none.
    """

    variables: tuple[int, ...]
    status: str
    info: JsonObject

    def __post_init__(self) -> None:
        if type(self.variables) is not tuple or any(
            type(v) is not int or v < 1 for v in self.variables
        ):
            raise ContractError("schema", "split choice variables are a tuple of positive ints")
        if self.status not in STATUSES:
            raise ContractError("schema", f"split choice status {self.status!r}")
        if not isinstance(self.info, JsonObject):
            raise ContractError("schema", "split choice info is a JsonObject")
        if len(set(self.variables)) != len(self.variables):
            raise ContractError("split.repeated", f"choice {list(self.variables)!r}")
        if self.status == CHOSEN:
            if not 1 <= len(self.variables) <= K_MAX:
                raise ContractError("split.too_long", f"a chosen split has 1..{K_MAX} variables")
        elif self.variables:
            raise ContractError("schema", f"status {self.status!r} carries no variables")

    @classmethod
    def make(cls, variables: Iterable[int], status: str, info: Mapping[str, Any]) -> SplitChoice:
        """A choice from plain values; ``info`` must be a JSON-able object (specification §4.1 J
        rules)."""
        return cls(tuple(variables), status, JsonObject.from_json(dict(info)))

    def info_dict(self) -> dict[str, Any]:
        return self.info.to_json()

    def to_json(self) -> dict[str, Any]:
        return {
            "variables": list(self.variables),
            "status": self.status,
            "info": self.info.to_json(),
        }


@dataclass(frozen=True)
class Budget:
    """Probe and wall budgets of a dynamic splitter (policy ``split.probe_limit``/``wall_ms``).

    ``probe_limit`` bounds unit-propagation probes deterministically; ``wall_ms`` additionally
    bounds the elapsed monotonic time (None: unlimited, for tests that need the deterministic
    stopping rule only).
    """

    probe_limit: int
    wall_ms: int | None = None

    def __post_init__(self) -> None:
        if type(self.probe_limit) is not int or not 1 <= self.probe_limit < 2**63:
            raise ConfigurationError("split.budget", "probe_limit is a positive integer")
        if self.wall_ms is not None and (
            type(self.wall_ms) is not int or not 1 <= self.wall_ms < 2**63
        ):
            raise ConfigurationError("split.budget", "wall_ms is a positive integer or None")


def check_k(k: int) -> int:
    """``k`` as a valid number of split variables, 1..K_MAX (``k = 0`` is never a split)."""
    if type(k) is not int or not 1 <= k <= K_MAX:
        raise ConfigurationError("split.k", f"k must be an integer in 1..{K_MAX}, not {k!r}")
    return k


def clamp_k(k: int, remaining_depth: int, unassigned: int) -> int:
    """``k`` clamped to the remaining policy depth and the unassigned variables (may be 0).

    A result of 0 means: do not invoke a splitter (STUCK at the depth limit, or nothing left
    to split on).
    """
    for name, value in (("k", k), ("remaining_depth", remaining_depth), ("unassigned", unassigned)):
        if type(value) is not int or value < 0:
            raise ConfigurationError("split.k", f"{name} must be a nonnegative integer")
    return min(k, K_MAX, remaining_depth, unassigned)


def check_pool(pool: Iterable[int] | None, variables: int) -> tuple[int, ...] | None:
    """A pool as a sorted tuple of distinct variables in ``1..V``, or None for all variables."""
    if pool is None:
        return None
    values = tuple(pool)
    if any(type(v) is not int or not 1 <= v <= variables for v in values):
        raise ConfigurationError("split.pool", "pool variables must be integers in 1..V")
    if any(a >= b for a, b in itertools.pairwise(values)):
        raise ConfigurationError("split.pool", "pool variables must be sorted and distinct")
    return values


def eligible(
    variables: int,
    cube: Sequence[int],
    pool: Iterable[int] | None,
    assigned: Iterable[int] = (),
) -> list[int]:
    """The eligible variables in ascending order: in the pool, not in the cube, not assigned.

    ``assigned`` holds the variables assigned by propagation under the parent cube.
    """
    taken = {abs(x) for x in cube}
    taken.update(abs(x) for x in assigned)
    members = range(1, variables + 1) if pool is None else check_pool(pool, variables) or ()
    return [v for v in members if v not in taken]


def validate_choice(
    choice: SplitChoice,
    variables: int,
    cube: Sequence[int],
    pool: Iterable[int] | None,
    k: int,
) -> tuple[int, ...]:
    """The structural check the coordinator makes before it records a chosen split (specification
    §9.1).

    ``W`` must be a well-formed split of ``cube`` in a formula with V = ``variables`` (distinct,
    in range, not in the cube, at most K_MAX; the rules of ``split_problem``), have at most
    ``k`` variables and lie in the pool. Whether a variable is *eligible* in the stronger sense
    (unassigned by propagation) is a heuristic matter: a variable that propagation assigns is
    still a valid split variable, it only wastes depth. A choice that is not ``chosen`` is a
    ``ValueError`` (the caller must handle that status first).
    """
    if choice.status != CHOSEN:
        raise ValueError(f"a {choice.status} choice has no split to validate")
    parent = check_cube(cube, variables)
    check_split(choice.variables, parent, variables)
    if len(choice.variables) > check_k(k):
        raise ContractError("split.too_long", f"{len(choice.variables)} variables for k = {k}")
    members = check_pool(pool, variables)
    if members is not None and not set(choice.variables) <= set(members):
        raise ContractError("split.pool", f"{list(choice.variables)!r} leave the pool")
    return choice.variables


def fallback_info(
    reason: str, *, candidates: int, parent_assigned: int, details: Mapping[str, Any] | None = None
) -> dict[str, Any]:
    """The info object of a lowest-eligible fallback; ``fallback`` records why it was used."""
    return {
        "algorithm": FALLBACK_ALGORITHM,
        "candidates": candidates,
        "parent_assigned": parent_assigned,
        "fallback": {"reason": reason, **(dict(details) if details else {})},
    }


def lowest_eligible_choice(
    formula: Formula,
    cube: Sequence[int],
    k: int,
    pool: Iterable[int] | None,
    *,
    reason: str,
    details: Mapping[str, Any] | None = None,
    index: UnitIndex | None = None,
) -> SplitChoice:
    """The first ``k`` eligible variables under the validated parent propagation.

    Used when a helper timed out or failed; ``reason`` and ``details`` are recorded in the
    splitter info. A parent that propagates to a conflict is ``failed``/``parent_conflict``
    (the checked unit route applies); a parent propagation that does not fit the memory is a
    blocked node, status ``budget``, never a protocol failure.
    """
    check_k(k)
    parent = check_cube(cube, formula.variables)
    members = check_pool(pool, formula.variables)
    try:
        propagation = propagate(index if index is not None else build_index(formula), parent)
    except MemoryError:
        return SplitChoice.make(
            (),
            BUDGET,
            {**fallback_info(reason, candidates=0, parent_assigned=0, details=details)}
            | {"stop": "resources"},
        )
    if propagation.conflict:
        info = fallback_info(reason, candidates=0, parent_assigned=0, details=details)
        return SplitChoice.make((), FAILED, {**info, "stop": PARENT_CONFLICT})
    assigned = propagation.assigned()
    candidates = eligible(formula.variables, parent, members, assigned)
    info = fallback_info(
        reason, candidates=len(candidates), parent_assigned=len(assigned), details=details
    )
    if not candidates:
        return SplitChoice.make((), NO_ELIGIBLE, info)
    return SplitChoice.make(candidates[:k], CHOSEN, info)
