"""Capacity, reservation sizes, the proof-cap clamp and pressure handling (specification §8.2,
§8.3).

- :func:`derive_capacity` turns probe values and the CLI budgets into the **initial ceilings**
  of the ledgers: CPU in milli-CPU (affinity and cgroup quota), a conservative memory
  scheduling budget (host/cgroup headroom minus the 1 GiB system and page-cache reserve, the
  coordinator's RSS and frontier allowance, and the resident cost of the helpers counted
  once) and one disk budget per storage group (free space minus the 2 GiB reserve). A CLI
  value can only lower a ceiling; a request above the observation is clamped and noted.
- The reservation sizes of the specification §8.3 table (:func:`solve_need`, :func:`check_need`,
  ...) use the policy caps plus 64 MiB of overhead per child; the CNF size is the actual size.
  :func:`publish_need` is the disk of a retained/quarantined publication.
- :func:`clamp_proof_cap` lowers the effective proof cap until the predicted initial heap
  is at most the maximum heap, the check fits the idle machine's RAM and one solve's disk
  reservation fits the idle storage; below 1 MiB it fails with a resource diagnostic.
- :class:`Resources` owns the book, remeasures at least every 10 s (specification §8.2) and lowers
  or restores the memory total on pressure; a lowered total never revokes running work.

Reservations are accounting for admission. Nothing here asserts that the kernel will provide
the physical memory a reservation names (specification §1.4).
"""

from __future__ import annotations

import enum
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, replace
from typing import Protocol

from cubeproof.base.errors import ConfigurationError, ResourceError
from cubeproof.base.resources import (
    DEFAULT_ROOTS,
    CpuProbe,
    MemoryProbe,
    Roots,
    StorageGroups,
    StorageProbe,
    group_storage,
    probe_cpu,
    probe_memory,
    probe_storage,
    process_rss_bytes,
)
from cubeproof.cnf.cubecnf import cube_cnf_header
from cubeproof.cnf.dimacs import Formula
from cubeproof.contracts.enums import ProofMode
from cubeproof.contracts.identity import check_cube
from cubeproof.contracts.policy import Policy
from cubeproof.coordinator.ledger import (
    CPU,
    MEMORY,
    Measure,
    Need,
    ResourceBook,
    disk,
)
from cubeproof.evidence.schema import Filesystem, ResourceSnapshot
from cubeproof.leaf.binding import RELAY_MEMORY_BYTES
from cubeproof.leaf.retain import publication_need
from cubeproof.tools import checker as ck

__all__ = [
    "CHILD_OVERHEAD",
    "DISK_RESERVE",
    "MIN_PROOF_CAP",
    "RELAY_CAP",
    "SYSTEM_RESERVE",
    "Capacity",
    "ClampResult",
    "PressureLevel",
    "PressurePolicy",
    "Probes",
    "Remeasure",
    "ResourceConfig",
    "Resources",
    "SystemProbes",
    "check_need",
    "clamp_proof_cap",
    "cnf_size_bound",
    "cnf_size_bytes",
    "derive_capacity",
    "helper_need",
    "idle_fit",
    "io_service_need",
    "preflight",
    "proof_prefix_need",
    "publish_need",
    "sealed_need",
    "solve_need",
    "stream_need",
]

MIB = 1 << 20
GIB = 1 << 30
#: Every new child reserves this much beyond its address-space cap (specification §8.2).
CHILD_OVERHEAD = 64 * MIB
#: Left to the system and the page cache (specification §8.2).
SYSTEM_RESERVE = 1 * GIB
#: Default free space kept per independent storage group (specification §8.2).
DISK_RESERVE = 2 * GIB
#: The relay (specification §8.3: the address-space cap its launch carries) and the I/O buffers.
RELAY_CAP = RELAY_MEMORY_BYTES
IO_BUFFER_CAP = 32 * MIB
#: Lookahead/UP helper address-space cap (specification §8.3) and the scratch of a proof-prefix
#: run.
HELPER_CAP = 256 * MIB
HELPER_SCRATCH = 1 * MIB
PROOF_PREFIX_SCRATCH = 256 * MIB
#: Bounded logs of a leaf: stdout/stderr tails are 16 KiB each; diagnostics are bounded.
LOG_ALLOWANCE = 4 * MIB
#: Coordinator allowance: a floor and a per-frontier-node estimate (specification §8.2).
COORDINATOR_FLOOR = 64 * MIB
FRONTIER_NODE_BYTES = 2048
#: Resident cost of the I/O service when it is not measured.
IO_SERVICE_RESIDENT = 64 * MIB
#: The proof cap is never lowered below this automatically (specification §8.3).
MIN_PROOF_CAP = 1 * MIB
#: A remeasurement is due at least this often (specification §8.2: every 10 s).
MEASURE_INTERVAL_MS = 10_000

CPU_PER_TASK = 1000
CPU_STREAM = 3000


# -- reservation sizes (specification §8.3) --------------------------------------------------------


def _one(group: str, amount: int) -> tuple[tuple[str, int], ...]:
    return ((group, amount),)


def solve_need(policy: Policy, cnf_bytes: int, group: str) -> Need:
    """Solve: solver AS cap + overhead; proof cap + actual CNF + bounded logs of disk."""
    return Need(
        CPU_PER_TASK,
        policy.solver_memory_bytes + CHILD_OVERHEAD,
        _one(group, policy.proof_cap_bytes + cnf_bytes + LOG_ALLOWANCE),
    )


def sealed_need(proof_bytes: int, cnf_bytes: int, group: str) -> Need:
    """A sealed proof waiting for its check: only the disk (CPU and RAM were released)."""
    return Need(0, 0, _one(group, proof_bytes + cnf_bytes + LOG_ALLOWANCE))


def publish_need(proof_bytes: int, cnf_bytes: int, *, source_group: str, target_group: str) -> Need:
    """Publication of a checked proof (retain, quarantine; specification §7.2 steps 1 and 5, §8.3):
    from the start of the copy until the attempt's cleanup. The sealed proof, CNF and logs stay on
    the work group (the source is removed only after the commit) and the copy occupies the
    target group, so one shared group holds the proof twice (``leaf.retain.publication_need``).
    It replaces the sealed reservation of the same task (only the copy is new)."""
    disks = publication_need(proof_bytes, source_group=source_group, target_group=target_group)
    return Need(0, 0, ((source_group, cnf_bytes + LOG_ALLOWANCE), *disks.items()))


def check_need(
    policy: Policy, heap_mib: int, stack_mib: int, proof_bytes: int, cnf_bytes: int, group: str
) -> Need:
    """Check: heap + stack + slack + overhead; the sealed proof, CNF and logs stay on disk."""
    memory = ck.checker_memory_bytes(heap_mib, stack_mib, policy.checker_slack_mib)
    return Need(
        CPU_PER_TASK,
        memory + CHILD_OVERHEAD,
        _one(group, proof_bytes + cnf_bytes + LOG_ALLOWANCE),
    )


def stream_need(
    policy: Policy, cnf_bytes: int, group: str, *, arena: tuple[int, int] | None = None
) -> Need:
    """Stream: solver, checker and relay (three children, three overheads); CNF and logs only.

    ``arena`` is the checker's ``(heap_mib, stack_mib)`` of this attempt (a fresh attempt after
    an arena exhaustion, ``leaf.retry``); by default the policy's first stream arena."""
    heap, stack = (policy.stream_heap_mib, policy.checker_stack_mib) if arena is None else arena
    checker = ck.checker_memory_bytes(heap, stack, policy.checker_slack_mib)
    memory = policy.solver_memory_bytes + checker + RELAY_CAP + 3 * CHILD_OVERHEAD
    return Need(CPU_STREAM, memory, _one(group, cnf_bytes + LOG_ALLOWANCE))


def helper_need(group: str, *, cap: int = HELPER_CAP, scratch: int = HELPER_SCRATCH) -> Need:
    """Lookahead/UP helper: explicit cap + overhead while it is CPU-active; scratch bounds."""
    return Need(CPU_PER_TASK, cap + CHILD_OVERHEAD, _one(group, scratch))


def proof_prefix_need(policy: Policy, cnf_bytes: int, group: str) -> Need:
    """Proof-prefix: solver cap + overhead; 256 MiB proof scratch + CNF + logs."""
    return Need(
        CPU_PER_TASK,
        policy.solver_memory_bytes + CHILD_OVERHEAD,
        _one(group, PROOF_PREFIX_SCRATCH + cnf_bytes + LOG_ALLOWANCE),
    )


def io_service_need(
    group_copies: Mapping[str, int] | None = None, *, resident: int = IO_SERVICE_RESIDENT
) -> Need:
    """I/O service: measured resident + bounded buffers; temporary copies until publication.

    The CPU reservation is taken only while a hash/copy job is active (the caller reserves
    and releases it around the work), never for the idle service."""
    copies = tuple((group_copies or {}).items())
    return Need(CPU_PER_TASK, resident + IO_BUFFER_CAP, copies)


def cnf_size_bytes(formula: Formula, cube: Sequence[int]) -> int:
    """The actual size of CNF(F, C): new header, clause body, one ``l 0`` line per literal."""
    literals = check_cube(cube, formula.variables)
    header = len(cube_cnf_header(formula.variables, formula.clauses, len(literals)))
    return header + len(formula.body) + sum(len(str(x)) + 3 for x in literals)


def cnf_size_bound(formula: Formula, depth: int) -> int:
    """An upper bound of CNF(F, C) over every cube of at most ``depth`` literals."""
    if type(depth) is not int or depth < 0:
        raise ValueError("depth must be a nonnegative integer")
    width = len(str(formula.variables)) + 1  # a sign and the digits of the largest variable
    header = len(cube_cnf_header(formula.variables, formula.clauses, depth))
    return header + len(formula.body) + depth * (width + 3)


# -- capacity ---------------------------------------------------------------------------------


@dataclass(frozen=True)
class ResourceConfig:
    """Requested budgets (CLI ``--jobs``, ``--memory``, ``--disk``) and fixed costs.

    A request can only lower a ceiling. ``helper_resident_bytes`` is the resident cost of the
    I/O service and of the in-memory bundles and indexes, counted once (specification §8.2).
    """

    cpu_milli: int | None = None
    memory_bytes: int | None = None
    disk_bytes: int | None = None
    system_reserve: int = SYSTEM_RESERVE
    disk_reserve: int = DISK_RESERVE
    helper_resident_bytes: int = IO_SERVICE_RESIDENT
    frontier_nodes: int = 0

    def __post_init__(self) -> None:
        for name in ("cpu_milli", "memory_bytes", "disk_bytes"):
            value = getattr(self, name)
            if value is not None and (type(value) is not int or value < 1):
                raise ConfigurationError(f"resources.{name}", f"{value!r} is not positive")
        for name in ("system_reserve", "disk_reserve", "helper_resident_bytes", "frontier_nodes"):
            value = getattr(self, name)
            if type(value) is not int or value < 0:
                raise ConfigurationError(f"resources.{name}", f"{value!r} is negative")

    def coordinator_allowance(self, rss: int | None) -> int:
        """RSS of the coordinator (at least the floor) plus the frontier allowance."""
        return max(rss or 0, COORDINATOR_FLOOR) + self.frontier_nodes * FRONTIER_NODE_BYTES


@dataclass(frozen=True)
class Capacity:
    """The initial ceilings, what was requested and observed, and notes for the status."""

    cpu_milli: int
    memory_budget_bytes: int
    disk_budget_bytes: Mapping[str, int]
    storage: StorageGroups
    requested: Mapping[str, int]
    observed: Mapping[str, int]
    notes: tuple[str, ...] = ()

    def budgets(self) -> dict[str, int]:
        found = {CPU: self.cpu_milli, MEMORY: self.memory_budget_bytes}
        for group, amount in self.disk_budget_bytes.items():
            found[disk(group)] = amount
        return found


def _effective(name: str, observed: int | None, requested: int | None, notes: list[str]) -> int:
    if observed is None:
        if requested is None:
            raise ResourceError(
                f"resources.{name}_unmeasured",
                f"{name} cannot be measured on this host; give an explicit budget",
            )
        notes.append(f"{name}: unmeasured, the requested budget is used without verification")
        return requested
    if requested is None or requested >= observed:
        if requested is not None and requested > observed:
            notes.append(f"{name}: requested {requested} clamped to the observed {observed}")
        return observed
    return requested


def derive_capacity(
    config: ResourceConfig,
    cpu: CpuProbe,
    memory: MemoryProbe,
    rss: int | None,
    storage: StorageGroups,
) -> Capacity:
    """Initial ceilings of the ledgers (module doc)."""
    notes: list[str] = []
    observed: dict[str, int] = {CPU: cpu.milli}
    requested: dict[str, int] = {}
    if config.cpu_milli is not None:
        requested[CPU] = config.cpu_milli
    cpu_milli = _effective("cpu", cpu.milli, config.cpu_milli, notes)

    memory_observed: int | None = None
    if memory.headroom_bytes is not None:
        fixed = config.system_reserve + config.coordinator_allowance(rss)
        fixed += config.helper_resident_bytes
        memory_observed = max(0, memory.headroom_bytes - fixed)
        observed[MEMORY] = memory_observed
    if config.memory_bytes is not None:
        requested[MEMORY] = config.memory_bytes
    memory_budget = _effective("memory", memory_observed, config.memory_bytes, notes)

    disks: dict[str, int] = {}
    for group in storage.groups():
        free = storage.free_bytes[group]
        seen = max(0, free - config.disk_reserve)
        observed[disk(group)] = seen
        if config.disk_bytes is not None:
            requested[disk(group)] = config.disk_bytes
        disks[group] = _effective(f"disk {group}", seen, config.disk_bytes, notes)
        reason = storage.reasons.get(group)
        if reason is not None:
            notes.append(f"storage group {group}: {reason}")
    return Capacity(
        cpu_milli=cpu_milli,
        memory_budget_bytes=memory_budget,
        disk_budget_bytes=dict(sorted(disks.items())),
        storage=storage,
        requested=dict(sorted(requested.items())),
        observed=dict(sorted(observed.items())),
        notes=tuple(notes),
    )


# -- proof cap clamp and preflight (specification §8.3) --------------------------------------------


@dataclass(frozen=True)
class ClampResult:
    """The effective proof cap and, if it was lowered, the first condition that bound it."""

    proof_cap_bytes: int
    requested: int
    limited_by: str | None


def _cap_problem(
    policy: Policy, capacity: Capacity, cap: int, cnf_bytes: int, group: str
) -> str | None:
    heap = ck.initial_heap_mib(cap, policy.heap_fit)
    if heap > policy.checker_max_heap_mib:
        return "heap"
    memory = ck.checker_memory_bytes(heap, policy.checker_stack_mib, policy.checker_slack_mib)
    if memory + CHILD_OVERHEAD > capacity.memory_budget_bytes:
        return "memory"
    if cap + cnf_bytes + LOG_ALLOWANCE > capacity.disk_budget_bytes.get(group, 0):
        return "disk"
    return None


def clamp_proof_cap(
    policy: Policy, capacity: Capacity, *, cnf_bytes: int, group: str
) -> ClampResult:
    """The largest cap <= the policy cap whose predicted initial heap, check memory and solve
    disk reservation fit the idle machine; whole MiB, never below 1 MiB.

    All three conditions are monotone in the cap, so the largest satisfying cap is found by
    bisection. If even 1 MiB (or a smaller configured cap) does not fit, preflight fails with
    the condition and the capacities as its resource diagnostic (specification §8.3).
    """
    requested = policy.proof_cap_bytes
    first = _cap_problem(policy, capacity, requested, cnf_bytes, group)
    if first is None:
        return ClampResult(requested, requested, None)
    floor = min(MIN_PROOF_CAP, requested)
    still = _cap_problem(policy, capacity, floor, cnf_bytes, group)
    if still is not None:
        raise ResourceError(
            "resources.proof_cap",
            f"even a proof cap of {floor} bytes does not fit the idle machine ({still}): "
            f"memory budget {capacity.memory_budget_bytes}, disk budget of {group} "
            f"{capacity.disk_budget_bytes.get(group, 0)}, CNF {cnf_bytes} bytes, "
            f"maximum heap {policy.checker_max_heap_mib} MiB",
        )
    low, high = floor, requested  # low fits, high does not
    while high - low > 1:
        middle = (low + high) // 2
        if _cap_problem(policy, capacity, middle, cnf_bytes, group) is None:
            low = middle
        else:
            high = middle
    cap = max(floor, low // MIB * MIB)
    return ClampResult(cap, requested, first)


def idle_fit(policy: Policy, capacity: Capacity) -> Callable[[int, int], bool]:
    """The ``fits(heap_mib, stack_mib)`` callback of arena retries: does the check fit the
    idle machine's RAM (specification §6.1 step 4, §8.3)? It is a budget check, not a promise of
    RAM."""

    def fits(heap_mib: int, stack_mib: int) -> bool:
        memory = ck.checker_memory_bytes(heap_mib, stack_mib, policy.checker_slack_mib)
        return memory + CHILD_OVERHEAD <= capacity.memory_budget_bytes

    return fits


def preflight(
    policy: Policy, capacity: Capacity, *, cnf_bytes: int, group: str
) -> tuple[Policy, ClampResult, tuple[str, ...]]:
    """Startup checks of specification §8.3/§8.4: the effective policy (clamped cap) and its
    diagnostics.

    Raises :class:`ResourceError` ``resources.preflight`` if a configured task cannot run on
    the idle machine (a stream task is rejected rather than waited for). The effective
    policy is the value to persist in the header/resume before any attempt.
    """
    clamp = clamp_proof_cap(policy, capacity, cnf_bytes=cnf_bytes, group=group)
    effective = replace(policy, proof_cap_bytes=clamp.proof_cap_bytes)
    book = ResourceBook(capacity.budgets())
    notes: list[str] = []
    wanted = [("solve", solve_need(effective, cnf_bytes, group))]
    if effective.proof_mode is ProofMode.STREAM:
        wanted.append(("stream", stream_need(effective, cnf_bytes, group)))
    problems: list[str] = []
    for name, need in wanted:
        shortfall = book.idle_shortfall(need)
        if shortfall is not None:
            problems.append(f"{name}: {shortfall}")
    if problems:
        raise ResourceError(
            "resources.preflight",
            "a configured task cannot run on the idle machine: " + "; ".join(problems),
        )
    if clamp.limited_by is not None:
        notes.append(
            f"proof cap lowered from {clamp.requested} to {clamp.proof_cap_bytes} "
            f"bytes ({clamp.limited_by})"
        )
    return effective, clamp, tuple(notes)


# -- probes -----------------------------------------------------------------------------------


class Probes(Protocol):
    """What :class:`Resources` reads from the host; tests supply scripted implementations."""

    def cpu(self) -> CpuProbe: ...

    def memory(self) -> MemoryProbe: ...

    def rss(self) -> int | None: ...

    def storage(self, paths: Sequence[str]) -> StorageGroups: ...


@dataclass
class SystemProbes:
    """The real probes over (possibly fake) kernel trees (``base.resources``)."""

    roots: Roots = DEFAULT_ROOTS
    cpu_count: Callable[[], int | None] | None = None
    affinity: Callable[[], int | None] | None = None
    storage_probe: Callable[[str], StorageProbe | None] | None = None

    def cpu(self) -> CpuProbe:
        kwargs: dict[str, Callable[[], int | None]] = {}
        if self.cpu_count is not None:
            kwargs["cpu_count"] = self.cpu_count
        if self.affinity is not None:
            kwargs["affinity"] = self.affinity
        return probe_cpu(self.roots, **kwargs)

    def memory(self) -> MemoryProbe:
        return probe_memory(self.roots)

    def rss(self) -> int | None:
        return process_rss_bytes(self.roots)

    def storage(self, paths: Sequence[str]) -> StorageGroups:
        one = self.storage_probe or (lambda p: probe_storage(p, self.roots))
        probes = []
        for path in paths:
            probe = one(path)
            if probe is None:
                raise ResourceError("resources.storage", f"{path} cannot be measured")
            probes.append(probe)
        return group_storage(probes)


# -- pressure and remeasurement -----------------------------------------------------------------


class PressureLevel(str, enum.Enum):
    """The classification of one remeasurement."""

    CALM = "calm"
    MODERATE = "moderate"
    HIGH = "high"


@dataclass(frozen=True)
class PressurePolicy:
    """Thresholds and the response of the memory total (module doc).

    HIGH (pressure averages over 10 s at or above the thresholds, a new OOM kill, or no
    headroom left) lowers the total to ``decrease_percent`` of the outstanding reservations
    (new work is refused until running work releases memory); once ``calm_ticks``
    consecutive remeasurements were not HIGH, each further one restores ``restore_percent``
    of the initial ceiling, never above it (additive increase, multiplicative decrease).
    """

    some_high: float = 20.0
    full_high: float = 5.0
    some_calm: float = 5.0
    full_calm: float = 1.0
    decrease_percent: int = 75
    restore_percent: int = 25
    calm_ticks: int = 3


@dataclass(frozen=True)
class Remeasure:
    """What one remeasurement saw and did (status/diagnostics)."""

    utc_ns: int
    level: PressureLevel
    memory_total: int
    cpu_total: int
    lowered: bool
    restored: bool
    oom_kills: int | None
    notes: tuple[str, ...] = ()


class Resources:
    """Capacity, the book and the periodic remeasurement of one run."""

    def __init__(
        self,
        probes: Probes,
        config: ResourceConfig,
        paths: Mapping[str, str],
        *,
        pressure: PressurePolicy | None = None,
        clock: Callable[[], int] = time.monotonic_ns,
    ) -> None:
        if not paths:
            raise ConfigurationError("resources.paths", "at least one path is needed")
        self.probes = probes
        self.config = config
        self.paths = dict(sorted(paths.items()))
        self.pressure = pressure or PressurePolicy()
        self._clock = clock
        storage = probes.storage(sorted(set(self.paths.values())))
        memory = probes.memory()
        self.capacity = derive_capacity(config, probes.cpu(), memory, probes.rss(), storage)
        self.book = ResourceBook(self.capacity.budgets())
        # The first measurement is part of construction, so H is known before the first plan;
        # OOM kills that happened before the run are not new pressure.
        self._oom: int | None = memory.oom_kills
        self._measures: dict[str, Measure] = self._read(memory, storage, None, None)
        self._last_ns: int | None = clock()
        self._calm = 0

    # -- groups ----------------------------------------------------------------------------

    def group_of(self, role: str) -> str:
        """The storage group of a configured path role (``work``, ``results`` ...)."""
        try:
            return self.capacity.storage.group_of[self.paths[role]]
        except KeyError:
            raise ConfigurationError("resources.paths", f"no path role {role!r}") from None

    # -- measurement -----------------------------------------------------------------------

    def measures(self) -> Mapping[str, Measure]:
        """The latest measures (the first one is taken when the run's resources are built)."""
        return dict(self._measures)

    def due(self) -> bool:
        return (
            self._last_ns is None
            or self._clock() - self._last_ns >= MEASURE_INTERVAL_MS * 1_000_000
        )

    def remeasure(
        self,
        *,
        children_rss: int | None = None,
        disk_used: Mapping[str, int] | None = None,
        force: bool = False,
    ) -> Remeasure | None:
        """Measure H and U of every ledger, classify pressure and lower/restore the memory
        total. Returns None when not yet due (at most one measurement per interval).

        ``children_rss`` is the resident size of the tool children, ``disk_used`` the bytes
        of our files per storage group; both are optional and an absent value is U = 0.
        """
        now = self._clock()
        if not force and not self.due():
            return None
        self._last_ns = now
        notes: list[str] = []
        memory = self.probes.memory()
        storage = self.probes.storage(sorted(set(self.paths.values())))
        measures = self._read(memory, storage, children_rss, disk_used)
        self._measures = measures

        level = self._classify(memory, measures.get(MEMORY))
        lowered = restored = False
        ledger = self.book.ledger(MEMORY)
        if level is PressureLevel.HIGH:
            self._calm = 0
            target = ledger.outstanding * self.pressure.decrease_percent // 100
            if target < ledger.total:
                ledger.set_total(target)
                lowered = True
                notes.append(f"memory total lowered to {ledger.total} on pressure")
        else:
            # CALM or MODERATE: the pressure is not high. A total lowered by a spike must come
            # back, or moderate pressure forever would stall a run that nothing prevents.
            self._calm += 1
            if self._calm >= self.pressure.calm_ticks and ledger.total < ledger.ceiling:
                step = max(1, ledger.ceiling * self.pressure.restore_percent // 100)
                ledger.set_total(ledger.total + step)
                restored = True
        cpu = self.probes.cpu()
        cpu_ledger = self.book.ledger(CPU)
        wanted_cpu = min(cpu_ledger.ceiling, cpu.milli)
        if wanted_cpu != cpu_ledger.total:
            cpu_ledger.set_total(wanted_cpu)
            notes.append(f"cpu total set to {wanted_cpu}")
        return Remeasure(
            utc_ns=now,
            level=level,
            memory_total=ledger.total,
            cpu_total=cpu_ledger.total,
            lowered=lowered,
            restored=restored,
            oom_kills=memory.oom_kills,
            notes=tuple(notes),
        )

    def _read(
        self,
        memory: MemoryProbe,
        storage: StorageGroups,
        children_rss: int | None,
        disk_used: Mapping[str, int] | None,
    ) -> dict[str, Measure]:
        """H and U per dimension from one set of probes (module doc, specification §8.2)."""
        config = self.config
        measures: dict[str, Measure] = {}
        if memory.headroom_bytes is not None:
            # The coordinator's own RSS is already part of the measured usage (it is in H), so
            # only the system reserve and the frontier growth allowance are taken off.
            usable = memory.headroom_bytes - config.system_reserve
            usable -= config.frontier_nodes * FRONTIER_NODE_BYTES
            measures[MEMORY] = Measure(max(0, usable), children_rss)
        for group in storage.groups():
            usable_disk = max(0, storage.free_bytes[group] - config.disk_reserve)
            used = None if disk_used is None else disk_used.get(group)
            measures[disk(group)] = Measure(usable_disk, used)
        return measures

    def _classify(self, memory: MemoryProbe, measure: Measure | None) -> PressureLevel:
        policy = self.pressure
        kills = memory.oom_kills
        new_kills = kills is not None and self._oom is not None and kills > self._oom
        if kills is not None:
            self._oom = kills
        pressure = memory.pressure
        full = None if pressure is None else pressure.full_avg10
        if new_kills or (measure is not None and measure.headroom == 0):
            return PressureLevel.HIGH
        if pressure is not None and (
            pressure.some_avg10 >= policy.some_high
            or (full is not None and full >= policy.full_high)
        ):
            return PressureLevel.HIGH
        if pressure is None or (
            pressure.some_avg10 < policy.some_calm and (full is None or full < policy.full_calm)
        ):
            return PressureLevel.CALM
        return PressureLevel.MODERATE

    # -- journal and status ------------------------------------------------------------------

    def snapshot(self, rss: int | None = None) -> ResourceSnapshot:
        """The ResourceSnapshot of a header/resume record (an observation, specification §4.7)."""
        capacity = self.capacity
        storage = capacity.storage
        filesystems = tuple(
            Filesystem(
                id=group,
                paths=storage.members[group],
                free_bytes=storage.free_bytes[group],
                budget_bytes=capacity.disk_budget_bytes[group],
            )
            for group in storage.groups()
        )
        return ResourceSnapshot(
            cpu_milli=self.book.ledger(CPU).total,
            memory_budget_bytes=self.book.ledger(MEMORY).total,
            filesystems=filesystems,
            coordinator_rss_bytes=(self.probes.rss() or 0) if rss is None else rss,
        )

    def status(self) -> dict[str, object]:
        """Requested and effective budgets, outstanding reservations and notes (specification
        §8.4)."""
        book = self.book
        return {
            "requested": dict(self.capacity.requested),
            "observed": dict(self.capacity.observed),
            "total": {d: book.ledger(d).total for d in book.dimensions},
            "ceiling": {d: book.ledger(d).ceiling for d in book.dimensions},
            "outstanding": {d: book.outstanding(d) for d in book.dimensions},
            "stages": book.by_stage(),
            "coordinator_rss_bytes": self.probes.rss(),
            "measures": {d: [m.headroom, m.used] for d, m in sorted(self._measures.items())},
            "notes": list(self.capacity.notes),
        }
