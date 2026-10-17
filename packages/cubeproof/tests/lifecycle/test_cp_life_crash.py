"""Specification §7.3, §7.5: kill the process at every named point of the lifecycle and at random
moments.

A crash here is ``SIGKILL`` of the whole run: the process dies where it stands, its tool children
die with it (parent-death signal) and its I/O service ends when its input closes. After each
kill the journal must still certify (a torn suffix is allowed), no process may use the work
directory, the run lock must become free, and the next run must continue from the journal alone
and end exactly where an uninterrupted run ends:

- the certifier's view equals the uninterrupted run's (verdict, per-root summaries with their
  Merkle roots, open list), whatever attempts were repeated on the way;
- no attempt ID occurs twice and no node is verified by two attempts: a committed attempt is
  never solved again, an uncommitted one is pending again (specification §7.5 crash table);
- the journal after the restart starts with exactly the bytes the crashed run left;
- the work directory is empty at the end.

The enumerated points are the hooks the coordinator reports (``Coordinator`` module doc); the
guard test shows that every one of them is reached by the workload. The fast tier runs six
representative points and three random kills; the slow tier (``pytest --run-slow``) runs every
enumerated point, a second crash during the restart, and 50 random kills.
"""

from __future__ import annotations

import random
import signal
import subprocess
import time
from collections import Counter
from pathlib import Path
from typing import Any, NamedTuple

import cp_life_tools as t
import pytest

DEEP = t.unsat(8, core=5)
TOOLS = {"max_free": 3, "sleep": 0.02}
JOBS = 2

#: (hook name, occurrence): the lifecycle of one worker, from the lock to the shutdown.
ENUMERATED: list[tuple[str, int]] = [
    ("startup.locked", 1),
    ("startup.replayed", 1),
    ("startup.reconciled", 1),
    ("startup.measured", 1),
    ("snapshot.submitted", 1),
    ("snapshot.committed", 1),
    ("shard.submitted", 1),
    ("shard.committed", 1),
    ("loop.start", 1),
    ("attempt.started", 1),
    ("attempt.started", 6),
    ("attempt.solve", 1),
    ("attempt.solve", 3),
    ("attempt.seal", 1),
    ("attempt.queued_check", 1),
    ("attempt.check", 1),
    ("attempt.check", 8),
    ("attempt.rehash", 1),
    ("attempt.commit", 1),
    ("attempt.commit", 10),
    ("attempt.cleanup", 1),
    ("attempt.done", 1),
    ("attempt.done", 21),
    ("split.started", 1),
    ("split.submitted", 1),
    ("split.committed", 1),
    ("split.committed", 5),
    ("cache.written", 1),
    ("shutdown", 1),
]
#: Points a restart passes through before it launches work.
RESTART: list[tuple[str, int]] = [
    ("startup.locked", 1),
    ("startup.replayed", 1),
    ("startup.reconciled", 1),
    ("startup.measured", 1),
    ("snapshot.submitted", 1),
    ("snapshot.committed", 1),
    ("loop.start", 1),
    ("attempt.started", 1),
    ("attempt.commit", 1),
]
FAST = [
    ("startup.measured", 1),
    ("shard.submitted", 1),
    ("attempt.solve", 1),
    ("attempt.commit", 3),
    ("split.submitted", 1),
    ("cache.written", 1),
]


def new_world(root: Path) -> t.World:
    return t.make_world(root, {"f": DEEP}, solver=TOOLS)


@pytest.fixture(scope="module")
def reference(tmp_path_factory: pytest.TempPathFactory) -> tuple[dict[str, Any], Counter[str]]:
    """The uninterrupted run: the certifier's view and how often each hook was reported."""
    w = new_world(tmp_path_factory.mktemp("reference"))
    names: Counter[str] = Counter()
    result = w.run(hooks=lambda name: names.update([name]), jobs=JOBS)
    assert result.exit_code == 0
    return w.summary(), names


def check_invariants(w: t.World, before: bytes | None, expected: dict[str, Any]) -> None:
    assert w.summary() == expected
    records = t.journal_records(w.results)
    ids = [r["attempt_id"] for r in records if r["type"] == "attempt"]
    assert len(ids) == len(set(ids)), "an attempt ID was committed twice"
    verified = [
        r["node_id"] for r in records if r["type"] == "attempt" and r["outcome"] == "VERIFIED_UNSAT"
    ]
    assert len(verified) == len(set(verified)), "a node was verified by two attempts"
    if before is not None:
        assert w.journal().read_bytes().startswith(before)
    assert w.work_files() == []
    t.wait_clean(w.results, w.work)


def complete_journal_bytes(w: t.World) -> bytes:
    """What the crashed run durably left: the journal up to its last complete line."""
    if not w.journal().exists():
        return b""
    data = w.journal().read_bytes()
    return data[: data.rfind(b"\n") + 1]


def crash_once(w: t.World, point: tuple[str, int], *, jobs: int = JOBS) -> bool:
    """Run until ``point`` and kill the process there; False if the run ended without it."""
    child = t.spawn_runner(w.spec(jobs=jobs), crash=point)
    code, out, err = t.messages(child)
    if code == -signal.SIGKILL:
        t.wait_clean(w.results, w.work)
        return True
    assert code == 0, (code, out, err)
    return False


def finish(w: t.World, *, jobs: int = JOBS) -> None:
    child = t.spawn_runner(w.spec(jobs=jobs))
    code, out, err = t.messages(child)
    assert code == 0, (code, out, err)


def test_every_enumerated_point_is_reached_by_the_workload(
    reference: tuple[dict[str, Any], Counter[str]],
) -> None:
    _summary, names = reference
    unreachable = [
        (n, k) for n, k in ENUMERATED + RESTART if names[n] < k and n != "attempt.commit"
    ]
    assert unreachable == []
    # the restart passes the same startup hooks again, so their count is what matters there
    assert names["attempt.commit"] >= 10


@pytest.mark.parametrize("point", FAST, ids=lambda p: f"{p[0]}#{p[1]}")
def test_a_crash_at_a_representative_point_is_recovered(
    tmp_path: Path, reference: tuple[dict[str, Any], Counter[str]], point: tuple[str, int]
) -> None:
    summary, _names = reference
    w = new_world(tmp_path)
    assert crash_once(w, point), f"{point} was not reached"
    if w.journal().exists():
        t.summary(w.campaign, w.results)  # the journal certifies after the crash
    before = complete_journal_bytes(w)
    finish(w)
    check_invariants(w, before, summary)


@pytest.mark.slow
@pytest.mark.parametrize("point", ENUMERATED, ids=lambda p: f"{p[0]}#{p[1]}")
def test_a_crash_at_every_enumerated_point_is_recovered(
    tmp_path: Path, reference: tuple[dict[str, Any], Counter[str]], point: tuple[str, int]
) -> None:
    summary, _names = reference
    w = new_world(tmp_path)
    assert crash_once(w, point), f"{point} was not reached"
    if w.journal().exists():
        t.summary(w.campaign, w.results)  # the journal certifies after the crash
    before = complete_journal_bytes(w)
    finish(w)
    check_invariants(w, before, summary)


@pytest.mark.slow
@pytest.mark.parametrize("second", RESTART, ids=lambda p: f"{p[0]}#{p[1]}")
def test_a_crash_during_the_restart_is_recovered_too(
    tmp_path: Path, reference: tuple[dict[str, Any], Counter[str]], second: tuple[str, int]
) -> None:
    summary, _names = reference
    w = new_world(tmp_path)
    assert crash_once(w, ("attempt.commit", 4))
    assert crash_once(w, second), f"{second} was not reached by the restart"
    t.summary(w.campaign, w.results)
    before = complete_journal_bytes(w)
    finish(w)
    check_invariants(w, before, summary)


#: Wall time of one uninterrupted child run of the random-kill workload on an idle machine
#: (measured 2.2-3.4 s). The kill windows are tuned for it and are stretched by
#: ``measured / NOMINAL_RUN_S`` when the machine is slower or loaded: the start-up of every
#: restart (interpreter, imports, replay, I/O service) takes its share of the window, and a window
#: shorter than that start-up would never let the run advance.
NOMINAL_RUN_S = 2.5
#: Consecutive kills that leave the journal unchanged before the next run is left alone.
STALL_LIMIT = 4
#: Kills in one cycle of a campaign; more means the restarts do not converge (a failure).
MAX_KILLS_PER_CYCLE = 150


class RandomKills(NamedTuple):
    landed: Counter[str]  #: where the kills landed (last lifecycle point reported)
    unkilled_after_stall: int  #: runs left alone after STALL_LIMIT kills without progress
    scale: float  #: the factor by which the kill windows were stretched


def random_kill_world(root: Path) -> t.World:
    w = t.make_world(root, {"f": DEEP}, solver=TOOLS | {"sleep": 0.05})
    t.configure(w.tools.checker, sleep=0.05)
    return w


@pytest.fixture(scope="module")
def run_seconds(tmp_path_factory: pytest.TempPathFactory) -> float:
    """Wall time of one uninterrupted child run of the random-kill workload on this machine,
    start-up included (the in-process ``reference`` run does not include it)."""
    w = random_kill_world(tmp_path_factory.mktemp("timing"))
    started = time.monotonic()
    code, out, err = t.messages(t.spawn_runner(w.spec(jobs=1)))
    elapsed = time.monotonic() - started
    assert code == 0, (code, out, err)
    return elapsed


def kill_after(w: t.World, delay_s: float | None, jobs: int, trace: Path) -> str | None:
    """Start a run and kill it after ``delay_s`` seconds. The last lifecycle point the process
    reported before it died (``"-"`` if none), or None if the run ended first. With ``delay_s``
    None the run is not killed and must end by itself."""
    seen = trace.read_text().count("\n") if trace.exists() else 0
    child = t.spawn_runner(w.spec(jobs=jobs), trace=trace)
    if delay_s is None:
        code, text, errors = t.messages(child, timeout_s=600.0)
        assert code == 0, (code, text, errors)
        return None
    try:
        child.wait(timeout=delay_s)
    except subprocess.TimeoutExpired:
        t.kill_and_collect(child, signal.SIGKILL)
        t.wait_clean(w.results, w.work)
        lines = trace.read_text().splitlines()[seen:] if trace.exists() else []
        return lines[-1] if lines else "-"
    out, err = child.communicate()
    assert child.returncode == 0, (child.returncode, out, err)
    return None


def random_kills(
    root: Path,
    expected: dict[str, Any],
    *,
    kills: int,
    seed: int,
    window_s: tuple[float, float],
    run_s: float = NOMINAL_RUN_S,
) -> RandomKills:
    """Cycles of campaigns, each killed at random moments until it completes; where the kills
    landed (the last lifecycle point reported by the process that was killed).

    The loop is bounded. The windows are stretched by the measured duration ``run_s`` of an
    uninterrupted run (never shrunk), so slower machines kill later in the same relative
    moments. If ``STALL_LIMIT`` kills in a row leave the journal unchanged (the window still
    ends before the run can advance), the next run is not killed and finishes the campaign; such
    runs are counted. A cycle with more than ``MAX_KILLS_PER_CYCLE`` kills fails."""
    rng = random.Random(seed)
    scale = max(1.0, run_s / NOMINAL_RUN_S)
    landed: Counter[str] = Counter()
    unkilled_after_stall = 0
    cycle = 0
    while sum(landed.values()) < kills:
        w = random_kill_world(root / f"cycle{cycle}")
        trace = root / f"cycle{cycle}" / "trace.txt"
        cycle += 1
        in_cycle = 0
        stalled = 0
        while True:
            if w.journal().exists():
                t.summary(w.campaign, w.results)
            before = complete_journal_bytes(w)
            delay = rng.uniform(*window_s) * scale
            point = kill_after(w, None if stalled >= STALL_LIMIT else delay, 1, trace)
            if point is None:
                unkilled_after_stall += stalled >= STALL_LIMIT
                break
            landed[point] += 1
            in_cycle += 1
            assert in_cycle <= MAX_KILLS_PER_CYCLE, (
                f"{in_cycle} kills in cycle {cycle - 1} and the campaign is not complete "
                f"(window scale {scale:.2f}, landed {sorted(landed.items())})"
            )
            after = complete_journal_bytes(w)
            stalled = stalled + 1 if after == before else 0
            if before:  # a journal that existed is never rewritten, only continued
                assert w.journal().read_bytes().startswith(before)
        check_invariants(w, None, expected)
    return RandomKills(landed, unkilled_after_stall, scale)


def test_a_few_random_kills_are_recovered(
    tmp_path: Path, reference: tuple[dict[str, Any], Counter[str]], run_seconds: float
) -> None:
    summary, _names = reference
    result = random_kills(
        tmp_path, summary, kills=3, seed=20261007, window_s=(0.3, 1.2), run_s=run_seconds
    )
    print(
        f"run {run_seconds:.2f} s, scale {result.scale:.2f}, stalls {result.unkilled_after_stall}"
    )
    assert sum(result.landed.values()) >= 3


@pytest.mark.slow
def test_fifty_random_kills_are_recovered(
    tmp_path: Path, reference: tuple[dict[str, Any], Counter[str]], run_seconds: float
) -> None:
    summary, _names = reference
    result = random_kills(
        tmp_path, summary, kills=50, seed=7, window_s=(0.05, 2.5), run_s=run_seconds
    )
    landed = result.landed
    print("kills landed after:", sorted(landed.items()))  # evidence for the report
    print(
        f"run {run_seconds:.2f} s, scale {result.scale:.2f}, stalls {result.unkilled_after_stall}"
    )
    assert sum(landed.values()) >= 50
    # the moments are spread over the lifecycle: the startup, the attempts, the splits
    assert len(landed) >= 6
    assert any(name.startswith("attempt.") for name in landed)


def test_a_missing_node_stop_is_derived_again_and_recorded_once(tmp_path: Path) -> None:
    """Specification §7.5: the follow-up of a recorded attempt is re-issued by replay if the crash
    came first."""
    policy = t.split_policy(max_cube_size=1)

    def build(root: Path) -> t.World:
        return t.make_world(root, {"f": DEEP}, solver=TOOLS, policy=policy)

    reference = build(tmp_path / "reference")
    assert reference.run(jobs=JOBS).exit_code == 1
    w = build(tmp_path / "crashed")
    assert crash_once(w, ("stop.submitted", 1))
    assert len(w.records("node_stop")) < 2
    before = complete_journal_bytes(w)
    child = t.spawn_runner(w.spec(jobs=JOBS))
    code, out, err = t.messages(child)
    assert code == 1, (code, out, err)
    stops = [(s["node"]["cube"], s["state"], s["reason"]) for s in w.records("node_stop")]
    wanted = [(s["node"]["cube"], s["state"], s["reason"]) for s in reference.records("node_stop")]
    assert sorted(stops) == sorted(wanted) and len(stops) == 2
    assert w.summary() == reference.summary()
    assert w.journal().read_bytes().startswith(before)
