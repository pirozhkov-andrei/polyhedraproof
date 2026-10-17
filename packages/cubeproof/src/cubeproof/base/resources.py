"""Resource probes of the host: CPU quota, memory headroom and pressure, storage identity.

Specification §8.2. Every probe reads kernel files below an injectable :class:`Roots` (the
real ``/sys/fs/cgroup`` and ``/proc`` by default), so cgroup v1 and v2 layouts, pressure
files and mount tables are testable with plain directory trees. A probe never raises for a
missing or unparsable file: the value it could not measure is ``None`` and the caller
decides (the scheduler treats an unmeasured value conservatively). Nothing here reads the
environment (the entry boundary does) and nothing starts a process.

- CPU capacity respects affinity and the cgroup quota (v2 ``cpu.max``; v1
  ``cpu.cfs_quota_us``/``cpu.cfs_period_us``), the minimum along the cgroup chain, in milli-CPU.
- Memory headroom is the smallest of the kernel's ``MemAvailable`` and, for every cgroup of
  the chain with a limit (v2 ``memory.max``/``memory.high``, v1 ``memory.limit_in_bytes``),
  ``limit - working set`` where the working set is the usage minus ``inactive_file`` (page
  cache that the kernel reclaims is not pressure). It is an observation of this moment, not a
  guarantee that a later allocation succeeds.
- Pressure comes from ``memory.pressure`` (v2) or ``/proc/pressure/memory``; the OOM kill
  counter from ``memory.events`` (v2) or ``memory.oom_control`` (v1).
- Storage: free space by ``statvfs``, identity by ``st_dev`` and the mount table. Paths of
  the same backing storage form one group (they compete for one budget). Independence is
  established only by distinct block-device-backed mounts of a local filesystem; an overlay,
  FUSE, network, tmpfs or unknown mount cannot establish it (a Docker overlay and its volumes
  may sit on one VM disk), so as soon as one path is unestablished **all** paths are one group.
"""

from __future__ import annotations

import os
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field

__all__ = [
    "DEFAULT_ROOTS",
    "ESTABLISHED_FILESYSTEMS",
    "CpuProbe",
    "MemoryProbe",
    "MountIdentity",
    "Pressure",
    "Roots",
    "StorageGroups",
    "StorageProbe",
    "group_storage",
    "mount_of",
    "probe_cpu",
    "probe_memory",
    "probe_storage",
    "process_rss_bytes",
]

#: A probe file is never larger than this (kernel files are tiny; a bigger one is not read).
_MAX_READ = 1 << 20
#: v1 limits at or above this are "no limit" (the kernel reports 2^63 rounded to a page).
_UNLIMITED = 1 << 60
_SHARED_GROUP = "shared"


@dataclass(frozen=True)
class Roots:
    """Where the kernel files are (tests point these at a fake tree)."""

    cgroup: str = "/sys/fs/cgroup"
    proc: str = "/proc"


DEFAULT_ROOTS = Roots()


def _read(path: str) -> str | None:
    try:
        with open(path, "rb") as stream:
            data = stream.read(_MAX_READ + 1)
    except OSError:
        return None
    if len(data) > _MAX_READ:
        return None
    return data.decode("utf-8", "replace")


def _integer(text: str | None) -> int | None:
    if text is None:
        return None
    try:
        return int(text.strip())
    except ValueError:
        return None


def _keyed(text: str | None) -> dict[str, int]:
    """``key value`` lines of ``memory.stat``/``memory.events``/``memory.oom_control``."""
    found: dict[str, int] = {}
    for line in (text or "").splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[1].isdigit():
            found[parts[0]] = int(parts[1])
    return found


def _chain(base: str, path: str) -> list[str]:
    """``base/path`` and every parent up to ``base``, leaf first; only existing directories."""
    parts = [p for p in path.split("/") if p not in ("", ".")]
    if ".." in parts:
        parts = []
    found = []
    for count in range(len(parts), -1, -1):
        directory = "/".join([base.rstrip("/"), *parts[:count]])
        if os.path.isdir(directory):
            found.append(directory)
    return found


@dataclass(frozen=True)
class _Cgroups:
    version: int
    memory: tuple[str, ...]
    cpu: tuple[str, ...]


_V1_CPU_NAMES = ("cpu,cpuacct", "cpu", "cpuacct,cpu")


def _locate(roots: Roots) -> _Cgroups | None:
    own = _read(f"{roots.proc}/self/cgroup") or ""
    entries: list[tuple[str, str]] = []
    for line in own.splitlines():
        parts = line.split(":", 2)
        if len(parts) == 3:
            entries.append((parts[1], parts[2].strip()))
    if os.path.exists(f"{roots.cgroup}/cgroup.controllers"):
        path = next((p for names, p in entries if names == ""), "/")
        chain = tuple(_chain(roots.cgroup, path))
        if not chain and os.path.isdir(roots.cgroup):
            chain = (roots.cgroup,)
        return _Cgroups(2, chain, chain)
    memory: list[str] = []
    cpu: list[str] = []
    for names, path in entries:
        controllers = names.split(",")
        if "memory" in controllers:
            memory = _chain(f"{roots.cgroup}/memory", path) or _chain(f"{roots.cgroup}/memory", "")
        if "cpu" in controllers or "cpuacct" in controllers:
            for name in _V1_CPU_NAMES:
                cpu = _chain(f"{roots.cgroup}/{name}", path) or _chain(f"{roots.cgroup}/{name}", "")
                if cpu:
                    break
    if not entries and os.path.isdir(f"{roots.cgroup}/memory"):
        memory = _chain(f"{roots.cgroup}/memory", "")
    if not memory and not cpu:
        return None
    return _Cgroups(1, tuple(memory), tuple(cpu))


# -- CPU -------------------------------------------------------------------------------------


@dataclass(frozen=True)
class CpuProbe:
    """CPU capacity in milli-CPU and the limits it is the minimum of (``name -> milli``)."""

    milli: int
    limits: Mapping[str, int]


def _affinity() -> int | None:
    try:
        return len(os.sched_getaffinity(0))
    except (AttributeError, OSError):
        return None


def probe_cpu(
    roots: Roots = DEFAULT_ROOTS,
    *,
    cpu_count: Callable[[], int | None] = os.cpu_count,
    affinity: Callable[[], int | None] = _affinity,
) -> CpuProbe:
    """Milli-CPU: the minimum of the host count, the affinity mask and every cgroup quota."""
    limits: dict[str, int] = {}
    count = cpu_count()
    if count:
        limits["host"] = count * 1000
    mask = affinity()
    if mask:
        limits["affinity"] = mask * 1000
    cgroups = _locate(roots)
    if cgroups is not None:
        for index, directory in enumerate(cgroups.cpu):
            quota: int | None = None
            period: int | None = None
            if cgroups.version == 2:
                fields = (_read(f"{directory}/cpu.max") or "").split()
                if len(fields) == 2 and fields[0] != "max":
                    quota, period = _integer(fields[0]), _integer(fields[1])
            else:
                quota = _integer(_read(f"{directory}/cpu.cfs_quota_us"))
                period = _integer(_read(f"{directory}/cpu.cfs_period_us"))
                if quota is not None and quota < 0:
                    quota = None
            if quota is not None and period is not None and period > 0:
                limits[f"cgroup-v{cgroups.version}:{index}"] = quota * 1000 // period
    milli = max(1, min(limits.values())) if limits else 1000
    return CpuProbe(milli, dict(sorted(limits.items())))


# -- memory ----------------------------------------------------------------------------------


@dataclass(frozen=True)
class Pressure:
    """Pressure-stall averages over 10 s in percent; ``full`` is None where the file has none."""

    some_avg10: float
    full_avg10: float | None


def _pressure(text: str | None) -> Pressure | None:
    some: float | None = None
    full: float | None = None
    for line in (text or "").splitlines():
        fields = line.split()
        if not fields or fields[0] not in ("some", "full"):
            continue
        for item in fields[1:]:
            name, _, value = item.partition("=")
            if name == "avg10":
                try:
                    number = float(value)
                except ValueError:
                    return None
                if fields[0] == "some":
                    some = number
                else:
                    full = number
    return None if some is None else Pressure(some, full)


@dataclass(frozen=True)
class MemoryProbe:
    """What the host and the cgroup chain say about memory right now (``None``: unmeasured)."""

    source: str
    host_total: int | None
    host_available: int | None
    limit_bytes: int | None
    usage_bytes: int | None
    headroom_bytes: int | None
    oom_kills: int | None
    pressure: Pressure | None


def _meminfo(roots: Roots) -> tuple[int | None, int | None]:
    total: int | None = None
    available: int | None = None
    for line in (_read(f"{roots.proc}/meminfo") or "").splitlines():
        fields = line.split()
        if len(fields) >= 2 and fields[1].isdigit():
            if fields[0] == "MemTotal:":
                total = int(fields[1]) * 1024
            elif fields[0] == "MemAvailable:":
                available = int(fields[1]) * 1024
    return total, available


def _limited(value: int | None) -> int | None:
    return None if value is None or value >= _UNLIMITED else value


def probe_memory(roots: Roots = DEFAULT_ROOTS) -> MemoryProbe:
    """Memory headroom, pressure and OOM counter (see the module doc for the definition)."""
    total, available = _meminfo(roots)
    cgroups = _locate(roots)
    headroom = available
    limit: int | None = None
    usage: int | None = None
    oom: int | None = None
    source = "host"
    pressure: Pressure | None = None
    if cgroups is not None and cgroups.memory:
        source = f"cgroup-v{cgroups.version}"
        for directory in cgroups.memory:
            if cgroups.version == 2:
                current = _integer(_read(f"{directory}/memory.current"))
                limits = [
                    _limited(_integer(_read(f"{directory}/memory.max"))),
                    _limited(_integer(_read(f"{directory}/memory.high"))),
                ]
                stat = _keyed(_read(f"{directory}/memory.stat"))
                events = _keyed(_read(f"{directory}/memory.events"))
                kills = events.get("oom_kill")
            else:
                current = _integer(_read(f"{directory}/memory.usage_in_bytes"))
                limits = [_limited(_integer(_read(f"{directory}/memory.limit_in_bytes")))]
                stat = _keyed(_read(f"{directory}/memory.stat"))
                kills = _keyed(_read(f"{directory}/memory.oom_control")).get("oom_kill")
            if kills is not None:
                oom = kills if oom is None else max(oom, kills)
            bounds = [x for x in limits if x is not None]
            if current is None or not bounds:
                continue
            cache = stat.get("inactive_file", stat.get("total_inactive_file", 0))
            working = max(0, current - cache)
            room = min(bounds) - working
            if headroom is None or room < headroom:
                headroom, limit, usage = room, min(bounds), working
        leaf = cgroups.memory[0]
        if cgroups.version == 2:
            pressure = _pressure(_read(f"{leaf}/memory.pressure"))
    if pressure is None:
        pressure = _pressure(_read(f"{roots.proc}/pressure/memory"))
    return MemoryProbe(
        source=source,
        host_total=total,
        host_available=available,
        limit_bytes=limit,
        usage_bytes=usage,
        headroom_bytes=None if headroom is None else max(0, headroom),
        oom_kills=oom,
        pressure=pressure,
    )


def process_rss_bytes(roots: Roots = DEFAULT_ROOTS, pid: int | str = "self") -> int | None:
    """Resident set size of a process (``VmRSS`` of its status file), or None."""
    for line in (_read(f"{roots.proc}/{pid}/status") or "").splitlines():
        fields = line.split()
        if len(fields) >= 2 and fields[0] == "VmRSS:" and fields[1].isdigit():
            return int(fields[1]) * 1024
    return None


# -- storage ---------------------------------------------------------------------------------

#: Local filesystems on a block device whose space is its own (an established backing store).
ESTABLISHED_FILESYSTEMS: frozenset[str] = frozenset(
    {"ext2", "ext3", "ext4", "xfs", "btrfs", "f2fs", "jfs", "reiserfs", "zfs", "vfat", "exfat"}
)
_ESCAPE = re.compile(r"\\([0-7]{3})")


@dataclass(frozen=True)
class MountIdentity:
    """The mount a path lives on; ``established`` iff it proves its own backing storage."""

    major_minor: str
    mount_point: str
    fstype: str
    source: str

    @property
    def established(self) -> bool:
        return self.fstype in ESTABLISHED_FILESYSTEMS and self.source.startswith("/dev/")


def _unescape(text: str) -> str:
    return _ESCAPE.sub(lambda m: chr(int(m.group(1), 8)), text)


def mount_of(path: str, mountinfo: str) -> MountIdentity | None:
    """The mount of ``path`` in a ``/proc/self/mountinfo`` text: the longest mount point."""
    best: MountIdentity | None = None
    for line in mountinfo.splitlines():
        before, separator, after = line.partition(" - ")
        fields = before.split()
        tail = after.split()
        if not separator or len(fields) < 5 or len(tail) < 2:
            continue
        point = _unescape(fields[4])
        inside = path == point or path.startswith(point.rstrip("/") + "/")
        if inside and (best is None or len(point) >= len(best.mount_point)):
            best = MountIdentity(fields[2], point, tail[0], _unescape(tail[1]))
    return best


@dataclass(frozen=True)
class StorageProbe:
    """Free space and identity of the filesystem of one path."""

    path: str
    dev: int
    free_bytes: int
    total_bytes: int
    mount: MountIdentity | None


def probe_storage(
    path: str,
    roots: Roots = DEFAULT_ROOTS,
    *,
    stat: Callable[[str], os.stat_result] = os.stat,
    statvfs: Callable[[str], os.statvfs_result] = os.statvfs,
) -> StorageProbe | None:
    """Free bytes (available to an unprivileged writer) and identity of ``path``; None on error."""
    try:
        real = os.path.realpath(path)
        device = stat(real).st_dev
        usage = statvfs(real)
    except OSError:
        return None
    mount = mount_of(real, _read(f"{roots.proc}/self/mountinfo") or "")
    return StorageProbe(
        path=path,
        dev=device,
        free_bytes=usage.f_bavail * usage.f_frsize,
        total_bytes=usage.f_blocks * usage.f_frsize,
        mount=mount,
    )


@dataclass(frozen=True)
class StorageGroups:
    """Paths grouped by backing storage; a group is one budget (specification §8.2).

    ``free_bytes`` of a group is the smallest free space of its members, the conservative
    reading when members of one group are on different filesystems that could not be
    proven independent.
    """

    group_of: Mapping[str, str]
    members: Mapping[str, tuple[str, ...]]
    free_bytes: Mapping[str, int]
    reasons: Mapping[str, str] = field(default_factory=dict)

    def groups(self) -> tuple[str, ...]:
        return tuple(sorted(self.members))


def group_storage(probes: Sequence[StorageProbe]) -> StorageGroups:
    """Group probed paths by backing storage (module doc: one unestablished path merges all)."""
    if not probes:
        return StorageGroups({}, {}, {})
    unestablished = [p for p in probes if p.mount is None or not p.mount.established]
    keys: dict[str, str] = {}
    reasons: dict[str, str] = {}
    if unestablished:
        for probe in probes:
            keys[probe.path] = _SHARED_GROUP
        why = sorted({_why(p) for p in unestablished})
        reasons[_SHARED_GROUP] = "independence not established: " + "; ".join(why)
    else:
        for probe in probes:
            assert probe.mount is not None
            keys[probe.path] = f"dev:{probe.mount.source}"
    members: dict[str, list[str]] = {}
    free: dict[str, int] = {}
    for probe in probes:
        key = keys[probe.path]
        members.setdefault(key, []).append(probe.path)
        free[key] = min(free.get(key, probe.free_bytes), probe.free_bytes)
    return StorageGroups(
        dict(sorted(keys.items())),
        {k: tuple(sorted(v)) for k, v in sorted(members.items())},
        dict(sorted(free.items())),
        dict(sorted(reasons.items())),
    )


def _why(probe: StorageProbe) -> str:
    if probe.mount is None:
        return f"{probe.path}: mount unknown"
    return f"{probe.path}: {probe.mount.fstype} on {probe.mount.source}"
