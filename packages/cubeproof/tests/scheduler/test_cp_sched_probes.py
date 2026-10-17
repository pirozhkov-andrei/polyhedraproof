"""Resource probes on fake cgroup v1/v2 trees, fake proc files and fake mount tables (specification
§8.2)."""

from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path

import pytest

from cubeproof.base.resources import (
    CpuProbe,
    Roots,
    StorageProbe,
    group_storage,
    mount_of,
    probe_cpu,
    probe_memory,
    probe_storage,
    process_rss_bytes,
)

GIB = 1 << 30
MIB = 1 << 20


def tree(base: Path, files: Mapping[str, str]) -> None:
    for name, text in files.items():
        path = base / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)


def meminfo(total_gib: int, available_gib: int) -> str:
    return (
        f"MemTotal: {total_gib * GIB // 1024} kB\nMemAvailable: {available_gib * GIB // 1024} kB\n"
    )


def v2(tmp_path: Path, files: Mapping[str, str], *, path: str = "/app") -> Roots:
    cg, proc = tmp_path / "cg", tmp_path / "proc"
    tree(cg, {"cgroup.controllers": "cpu memory\n", **files})
    tree(proc, {"self/cgroup": f"0::{path}\n"})
    return Roots(str(cg), str(proc))


def v1(tmp_path: Path, files: Mapping[str, str], *, path: str = "/docker/x") -> Roots:
    cg, proc = tmp_path / "cg", tmp_path / "proc"
    tree(cg, files)
    tree(
        proc,
        {"self/cgroup": f"4:memory:{path}\n3:cpu,cpuacct:{path}\n1:name=systemd:/init\n"},
    )
    return Roots(str(cg), str(proc))


def with_meminfo(roots: Roots, total: int = 64, available: int = 48) -> Roots:
    tree(Path(roots.proc), {"meminfo": meminfo(total, available)})
    return roots


def cpu(roots: Roots, *, count: int | None = 64, affinity: int | None = None) -> CpuProbe:
    return probe_cpu(roots, cpu_count=lambda: count, affinity=lambda: affinity)


# -- cpu --------------------------------------------------------------------------------------


def test_cpu_quota_of_a_v2_group_in_milli_cpu(tmp_path: Path) -> None:
    roots = v2(tmp_path, {"app/cpu.max": "250000 100000\n"})
    probe = cpu(roots)
    assert probe.milli == 2500
    assert probe.limits["cgroup-v2:0"] == 2500


def test_no_quota_leaves_the_host_count(tmp_path: Path) -> None:
    assert cpu(v2(tmp_path, {"app/cpu.max": "max 100000\n"})).milli == 64000


def test_affinity_and_quota_take_the_minimum(tmp_path: Path) -> None:
    roots = v2(tmp_path, {"app/cpu.max": "800000 100000\n"})
    assert cpu(roots, affinity=3).milli == 3000
    assert cpu(roots, affinity=16).milli == 8000


def test_a_parent_quota_binds_a_child(tmp_path: Path) -> None:
    roots = v2(
        tmp_path,
        {"app/cpu.max": "max 100000\n", "cpu.max": "150000 100000\n"},
    )
    assert cpu(roots).milli == 1500


def test_a_tiny_quota_is_at_least_one_milli_cpu(tmp_path: Path) -> None:
    roots = v2(tmp_path, {"app/cpu.max": "50 1000000\n"})
    assert cpu(roots).milli == 1


def test_cpu_quota_of_a_v1_group(tmp_path: Path) -> None:
    roots = v1(
        tmp_path,
        {
            "cpu,cpuacct/docker/x/cpu.cfs_quota_us": "300000\n",
            "cpu,cpuacct/docker/x/cpu.cfs_period_us": "100000\n",
        },
    )
    assert cpu(roots).milli == 3000


def test_v1_quota_minus_one_is_no_quota(tmp_path: Path) -> None:
    roots = v1(
        tmp_path,
        {
            "cpu/docker/x/cpu.cfs_quota_us": "-1\n",
            "cpu/docker/x/cpu.cfs_period_us": "100000\n",
        },
    )
    assert cpu(roots, count=8).milli == 8000


def test_a_container_that_sees_only_its_own_v1_group(tmp_path: Path) -> None:
    """The host path in /proc/self/cgroup is absent inside the container's mount."""
    roots = v1(
        tmp_path,
        {
            "cpu,cpuacct/cpu.cfs_quota_us": "100000\n",
            "cpu,cpuacct/cpu.cfs_period_us": "100000\n",
        },
    )
    assert cpu(roots).milli == 1000


def test_unreadable_or_garbled_files_leave_the_other_limits(tmp_path: Path) -> None:
    roots = v2(tmp_path, {"app/cpu.max": "banana\n"})
    assert cpu(roots, count=4).milli == 4000
    assert (
        probe_cpu(
            Roots(str(tmp_path / "none"), str(tmp_path / "none")),
            cpu_count=lambda: 2,
            affinity=lambda: None,
        ).milli
        == 2000
    )


def test_nothing_measurable_defaults_to_one_cpu(tmp_path: Path) -> None:
    nothing = Roots(str(tmp_path / "a"), str(tmp_path / "b"))
    assert probe_cpu(nothing, cpu_count=lambda: None, affinity=lambda: None).milli == 1000


# -- memory -----------------------------------------------------------------------------------


def test_v2_headroom_is_the_limit_minus_the_working_set(tmp_path: Path) -> None:
    roots = with_meminfo(
        v2(
            tmp_path,
            {
                "app/memory.max": str(8 * GIB),
                "app/memory.current": str(5 * GIB),
                "app/memory.stat": f"anon {3 * GIB}\ninactive_file {2 * GIB}\n",
                "app/memory.events": "low 0\nhigh 0\nmax 4\noom 1\noom_kill 1\n",
                "app/memory.pressure": "some avg10=1.50 avg60=0.50 avg300=0.10 total=10\n"
                "full avg10=0.25 avg60=0.00 avg300=0.00 total=2\n",
            },
        )
    )
    probe = probe_memory(roots)
    assert probe.source == "cgroup-v2"
    assert probe.limit_bytes == 8 * GIB
    assert probe.usage_bytes == 3 * GIB  # page cache that the kernel reclaims is not counted
    assert probe.headroom_bytes == 5 * GIB
    assert probe.oom_kills == 1
    assert probe.pressure is not None
    assert (probe.pressure.some_avg10, probe.pressure.full_avg10) == (1.5, 0.25)


def test_headroom_never_exceeds_what_the_host_reports_available(tmp_path: Path) -> None:
    roots = with_meminfo(
        v2(tmp_path, {"app/memory.max": str(64 * GIB), "app/memory.current": str(GIB)}),
        total=64,
        available=7,
    )
    probe = probe_memory(roots)
    assert probe.headroom_bytes == 7 * GIB
    assert probe.host_total == 64 * GIB


def test_an_unlimited_group_leaves_the_host_figure(tmp_path: Path) -> None:
    roots = with_meminfo(v2(tmp_path, {"app/memory.max": "max\n", "app/memory.current": "1"}))
    probe = probe_memory(roots)
    assert probe.limit_bytes is None
    assert probe.headroom_bytes == 48 * GIB


def test_the_tightest_group_of_the_chain_binds(tmp_path: Path) -> None:
    roots = with_meminfo(
        v2(
            tmp_path,
            {
                "app/memory.max": str(16 * GIB),
                "app/memory.current": str(GIB),
                "memory.max": str(4 * GIB),
                "memory.current": str(3 * GIB),
            },
        )
    )
    assert probe_memory(roots).headroom_bytes == GIB


def test_memory_high_is_a_limit_too(tmp_path: Path) -> None:
    roots = with_meminfo(
        v2(
            tmp_path,
            {
                "app/memory.max": "max",
                "app/memory.high": str(2 * GIB),
                "app/memory.current": str(GIB),
            },
        )
    )
    assert probe_memory(roots).headroom_bytes == GIB


def test_usage_above_the_limit_is_zero_headroom(tmp_path: Path) -> None:
    roots = with_meminfo(
        v2(tmp_path, {"app/memory.max": str(GIB), "app/memory.current": str(2 * GIB)})
    )
    assert probe_memory(roots).headroom_bytes == 0


def test_v1_limit_usage_and_oom_counter(tmp_path: Path) -> None:
    roots = with_meminfo(
        v1(
            tmp_path,
            {
                "memory/docker/x/memory.limit_in_bytes": str(4 * GIB),
                "memory/docker/x/memory.usage_in_bytes": str(3 * GIB),
                "memory/docker/x/memory.stat": f"cache {GIB}\ntotal_inactive_file {GIB // 2}\n",
                "memory/docker/x/memory.oom_control": "under_oom 0\noom_kill 7\n",
            },
        )
    )
    probe = probe_memory(roots)
    assert probe.source == "cgroup-v1"
    assert probe.limit_bytes == 4 * GIB
    assert probe.headroom_bytes == 4 * GIB - (3 * GIB - GIB // 2)
    assert probe.oom_kills == 7


def test_v1_unlimited_is_the_host(tmp_path: Path) -> None:
    roots = with_meminfo(
        v1(
            tmp_path,
            {
                "memory/docker/x/memory.limit_in_bytes": "9223372036854771712\n",
                "memory/docker/x/memory.usage_in_bytes": str(GIB),
            },
        ),
        available=30,
    )
    probe = probe_memory(roots)
    assert probe.limit_bytes is None
    assert probe.headroom_bytes == 30 * GIB


def test_an_unlimited_v1_group_without_meminfo_is_unmeasured_not_infinite(tmp_path: Path) -> None:
    roots = v1(
        tmp_path,
        {
            "memory/docker/x/memory.limit_in_bytes": "9223372036854771712\n",
            "memory/docker/x/memory.usage_in_bytes": str(GIB),
        },
    )
    assert probe_memory(roots).headroom_bytes is None


def test_the_oom_counter_is_the_largest_of_the_chain(tmp_path: Path) -> None:
    """memory.events is hierarchical: an ancestor's counter includes its descendants'."""
    roots = with_meminfo(
        v2(
            tmp_path,
            {
                "app/memory.max": "max",
                "app/memory.current": "1",
                "app/memory.events": "oom_kill 2\n",
                "memory.events": "oom_kill 5\n",
            },
        )
    )
    assert probe_memory(roots).oom_kills == 5


def test_proc_pressure_is_the_fallback(tmp_path: Path) -> None:
    roots = with_meminfo(v2(tmp_path, {"app/memory.max": "max", "app/memory.current": "1"}))
    tree(Path(roots.proc), {"pressure/memory": "some avg10=33.00 avg60=1 avg300=1 total=1\n"})
    probe = probe_memory(roots)
    assert probe.pressure is not None
    assert probe.pressure.some_avg10 == 33.0
    assert probe.pressure.full_avg10 is None


def test_a_host_without_cgroups_or_proc_reports_nothing_and_does_not_raise(tmp_path: Path) -> None:
    probe = probe_memory(Roots(str(tmp_path / "x"), str(tmp_path / "y")))
    assert (probe.source, probe.headroom_bytes, probe.pressure, probe.oom_kills) == (
        "host",
        None,
        None,
        None,
    )


def test_garbage_in_a_memory_file_is_unmeasured(tmp_path: Path) -> None:
    roots = with_meminfo(
        v2(tmp_path, {"app/memory.max": "lots", "app/memory.current": "many"}), available=5
    )
    assert probe_memory(roots).headroom_bytes == 5 * GIB


def test_the_coordinator_rss(tmp_path: Path) -> None:
    roots = Roots(str(tmp_path / "cg"), str(tmp_path / "proc"))
    tree(
        Path(roots.proc),
        {
            "self/status": "Name:\tx\nVmRSS:\t   51200 kB\nThreads:\t1\n",
            "42/status": "VmRSS: 8 kB\n",
        },
    )
    assert process_rss_bytes(roots) == 51200 * 1024
    assert process_rss_bytes(roots, 42) == 8 * 1024
    assert process_rss_bytes(roots, 43) is None


# -- storage ----------------------------------------------------------------------------------

MOUNTINFO = (
    "22 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw\n"
    "30 22 8:17 / /data rw shared:2 - xfs /dev/sdb1 rw\n"
    "31 22 8:17 /sub /data/sub rw shared:2 - xfs /dev/sdb1 rw\n"
    "40 22 0:50 / /var/lib/docker/overlay2/x/merged rw - overlay overlay rw,lowerdir=/a\n"
    "41 22 0:51 / /tmp rw - tmpfs tmpfs rw\n"
    "42 22 8:33 / /mnt/with\\040space rw - ext4 /dev/sdc1 rw\n"
    "43 22 0:60 / /mnt/net rw - nfs4 server:/export rw\n"
    "44 22 8:49 / /mnt/ntfs rw - fuseblk /dev/sdd1 rw\n"
)


def test_the_mount_of_a_path_is_the_longest_mount_point() -> None:
    assert mount_of("/data/results", MOUNTINFO).source == "/dev/sdb1"  # type: ignore[union-attr]
    assert mount_of("/data", MOUNTINFO).mount_point == "/data"  # type: ignore[union-attr]
    assert mount_of("/database", MOUNTINFO).mount_point == "/"  # type: ignore[union-attr]
    assert mount_of("/home/u", MOUNTINFO).source == "/dev/sda1"  # type: ignore[union-attr]
    nested = mount_of("/data/sub/x", MOUNTINFO)
    assert nested is not None and nested.mount_point == "/data/sub"
    assert mount_of("/x", "garbage\n") is None


def test_octal_escapes_of_mount_points_are_decoded() -> None:
    mount = mount_of("/mnt/with space/results", MOUNTINFO)
    assert mount is not None and mount.mount_point == "/mnt/with space"


def test_only_block_backed_local_filesystems_establish_independence() -> None:
    established = {
        path: mount_of(path, MOUNTINFO).established  # type: ignore[union-attr]
        for path in (
            "/home",
            "/data/x",
            "/var/lib/docker/overlay2/x/merged/a",
            "/tmp/a",
            "/mnt/net/a",
            "/mnt/ntfs/a",
        )
    }
    assert established == {
        "/mnt/ntfs/a": False,  # a block device, but a FUSE filesystem: not proven independent
        "/home": True,
        "/data/x": True,
        "/var/lib/docker/overlay2/x/merged/a": False,
        "/tmp/a": False,
        "/mnt/net/a": False,
    }


def fake_probe(path: str, free: int, *, mountinfo: str = MOUNTINFO) -> StorageProbe:
    return StorageProbe(path, 1, free, 100 * GIB, mount_of(path, mountinfo))


def test_paths_of_one_device_share_a_group_with_the_smaller_free_space() -> None:
    groups = group_storage(
        [fake_probe("/data/work", 50 * GIB), fake_probe("/data/sub/results", 30 * GIB)]
    )
    assert groups.groups() == ("dev:/dev/sdb1",)
    assert groups.group_of["/data/work"] == groups.group_of["/data/sub/results"]
    assert groups.free_bytes["dev:/dev/sdb1"] == 30 * GIB
    assert groups.members["dev:/dev/sdb1"] == ("/data/sub/results", "/data/work")


def test_separate_block_devices_are_separate_groups() -> None:
    groups = group_storage([fake_probe("/home/a", 10 * GIB), fake_probe("/data/b", 20 * GIB)])
    assert groups.groups() == ("dev:/dev/sda1", "dev:/dev/sdb1")
    assert groups.free_bytes == {"dev:/dev/sda1": 10 * GIB, "dev:/dev/sdb1": 20 * GIB}


@pytest.mark.parametrize(
    "unknown", ["/var/lib/docker/overlay2/x/merged/w", "/tmp/w", "/mnt/net/w", "/nowhere/else"]
)
def test_one_unestablished_path_merges_all_paths_into_one_group(unknown: str) -> None:
    mountinfo = MOUNTINFO if unknown != "/nowhere/else" else "garbage\n"
    probes = [
        fake_probe("/home/a", 10 * GIB, mountinfo=MOUNTINFO),
        fake_probe(unknown, 5 * GIB, mountinfo=mountinfo),
    ]
    groups = group_storage(probes)
    assert groups.groups() == ("shared",)
    assert groups.free_bytes["shared"] == 5 * GIB
    assert "independence not established" in groups.reasons["shared"]


def test_probe_storage_reads_free_space_and_identity(tmp_path: Path) -> None:
    proc = tmp_path / "proc"
    tree(proc, {"self/mountinfo": f"22 1 8:1 / {tmp_path} rw - ext4 /dev/sdz1 rw\n"})
    seen: list[str] = []

    def fake_stat(path: str) -> os.stat_result:
        seen.append(path)
        return os.stat_result((0, 0, 77, 1, 0, 0, 0, 0, 0, 0))

    def fake_statvfs(path: str) -> os.statvfs_result:
        return os.statvfs_result((4096, 4096, 1000, 900, 800, 0, 0, 0, 0, 255))

    probe = probe_storage(
        str(tmp_path / "work"),
        Roots(str(tmp_path), str(proc)),
        stat=fake_stat,
        statvfs=fake_statvfs,
    )
    assert probe is not None
    assert (probe.dev, probe.free_bytes, probe.total_bytes) == (77, 800 * 4096, 1000 * 4096)
    assert probe.mount is not None and probe.mount.source == "/dev/sdz1"


def test_an_unreadable_path_has_no_probe(tmp_path: Path) -> None:
    def failing(path: str) -> os.stat_result:
        raise FileNotFoundError(path)

    assert probe_storage(str(tmp_path), stat=failing) is None


def test_the_real_host_can_be_probed() -> None:
    """Smoke test of the default roots: the values are plausible, nothing raises."""
    assert probe_cpu().milli >= 1
    memory = probe_memory()
    assert memory.headroom_bytes is None or memory.headroom_bytes >= 0
    assert process_rss_bytes() is None or process_rss_bytes() > 0  # type: ignore[operator]
    storage = probe_storage("/tmp")
    assert storage is None or storage.free_bytes >= 0
