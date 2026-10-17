"""Stream runs of the coordinator (specification §6.4, §6.5, §7.3, §8.2, §8.3).

Whole runs of one worker in stream mode with the lifecycle test tools (real child processes: the
I/O service, the fake solver and checker under the real isolation wrappers, the real relay
process on real FIFOs). The journal is read back through the package's validators and judged by
the certifier; the scheduling decisions are judged against the replay of the journal prefix that
preceded them: an arena-exhausted stream attempt is followed by a fresh attempt on the same node
whose arena is exactly the one the replay derives, until the maxima, then the node needs a split.
A restart between two attempts takes the same next action as the uninterrupted run.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest

HERE = Path(__file__).resolve().parent
if str(HERE.parent / "lifecycle") not in sys.path:
    sys.path.insert(0, str(HERE.parent / "lifecycle"))

import cp_life_tools as t  # noqa: E402

from cubeproof.cnf.campaign import load_campaign  # noqa: E402
from cubeproof.coordinator.cache import CacheHit, load_cache  # noqa: E402
from cubeproof.coordinator.config import Stop  # noqa: E402
from cubeproof.coordinator.replay import validator_of  # noqa: E402
from cubeproof.coordinator.state import CampaignView, Disposition, ReplayState  # noqa: E402
from cubeproof.evidence.journal import read_journal  # noqa: E402
from cubeproof.evidence.schema import Attempt, Record  # noqa: E402

pytestmark = pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux only")

#: Five variables, a three-variable core: unit propagation decides nothing at the root.
SHALLOW = t.unsat(5)
#: A short arena ladder: 512 -> 1024 -> 2048 MiB, then the maxima (specification §6.4: no infinite
#: ladder).
LADDER = {"stream_heap_mib": 512, "checker_max_heap_mib": 2048, "max_cube_size": 0}
STACK = 16  # cp_life_tools.make_policy


class Replayed:
    """The validated records of a world's journal and folds of its prefixes."""

    def __init__(self, world: t.World) -> None:
        loaded = load_campaign(world.campaign)
        self.view = CampaignView.of(loaded)
        self.records: tuple[Record, ...] = read_journal(
            world.journal(), validator_of(loaded)
        ).records

    def fold(self, count: int | None = None) -> ReplayState:
        """The replay as the coordinator's startup builds it (no judge passed in)."""
        state = ReplayState(self.view)
        state.apply_all(list(self.records if count is None else self.records[:count]))
        return state

    def attempts(self) -> list[tuple[int, Attempt]]:
        return [(r.seq, r.payload) for r in self.records if isinstance(r.payload, Attempt)]


def arenas(world: t.World) -> list[list[tuple[int, int]]]:
    return [[(c["heap_mib"], c["stack_mib"]) for c in a["checks"]] for a in world.attempts()]


def solvers_alive(world: t.World) -> int:
    """Processes running the world's fake solver on its work directory (``/proc``)."""
    solver, work = str(world.tools.solver), str(world.work)
    count = 0
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            words = (entry / "cmdline").read_bytes().split(b"\0")
        except OSError:
            continue
        text = [w.decode("utf-8", "replace") for w in words]
        if solver in text and any(w.startswith(work) for w in text):
            count += 1
    return count


def guard(limit: int) -> Any:
    launches: list[str] = []

    def hook(name: str) -> None:  # a run that never ends fails here, quickly
        if name in ("attempt.started", "split.started"):
            launches.append(name)
            assert len(launches) <= limit, "runaway retries"

    return hook


def test_a_split_stream_campaign_streams_cdcl_leaves_and_checks_unit_proofs_from_files(
    tmp_path: Path,
) -> None:
    w = t.make_world(tmp_path, {"f": SHALLOW}, solver={"max_free": 3})
    result = w.run(proof_mode="stream")
    assert (result.exit_code, result.reason) == (0, Stop.COMPLETE)
    assert w.summary()["verdict"] == "PROVED"
    attempts = w.attempts()
    assert {a["proof_mode"] for a in attempts} == {"stream"}
    # the root ran out of solver memory in the coupled run: a split, not a retry
    assert (attempts[0]["outcome"], attempts[0]["reason"]) == ("EXHAUSTED", "solver_memory")
    assert attempts[0]["relay"] is not None and attempts[0]["route"] == "cdcl"
    verified = [a for a in attempts if a["outcome"] == "VERIFIED_UNSAT"]
    assert verified
    for a in verified:
        # relay non-null iff stream and cdcl; a unit refutation is a checked file (specification
        # §4.8)
        assert (a["relay"] is None) == (a["route"] == "unit")
        if a["route"] == "cdcl":
            relay = a["relay"]
            assert (a["proof_bytes"], a["proof_sha256"]) == (relay["bytes"], relay["sha256"])
    # what the tools used (diagnostics): the three coupled processes of a streamed attempt by
    # role; a unit refutation has no solver and one entry for each of its checks
    for a in attempts:
        usage = a["diagnostics"]["usage"]
        if a["route"] == "cdcl":
            assert set(usage) == {"host_cpu", "solver", "relay", "checker"}
        else:
            assert set(usage) == {"host_cpu", "checks"}
            assert len(usage["checks"]) == len(a["checks"]) >= 1
        for name in set(usage) - {"host_cpu", "checks"}:
            assert set(usage[name]) == {"cpu_ms", "max_rss_kib", "launch_rss_kib"}
    assert w.work_files() == []
    t.wait_clean(w.results, w.work)


def test_arena_exhaustions_take_fresh_attempts_with_the_derived_arena_until_the_maxima(
    tmp_path: Path,
) -> None:
    w = t.make_world(tmp_path, {"f": SHALLOW}, policy=t.split_policy(**LADDER))
    t.configure(w.tools.checker, arena=True)
    result = w.run(proof_mode="stream", hooks=guard(6))
    assert (result.exit_code, result.reason) == (1, Stop.COMPLETE)
    outcomes = [(a["outcome"], a["reason"], a["route"]) for a in w.attempts()]
    assert outcomes == [("EXHAUSTED", "check_memory", "cdcl")] * 3
    assert arenas(w) == [[(512, STACK)], [(1024, STACK)], [(2048, STACK)]]
    # beyond the maxima the node needs a split; at max_cube_size 0 that is STUCK (specification
    # §6.5)
    assert [(s["state"], s["reason"]) for s in w.records("node_stop")] == [("stuck", "max_depth")]
    assert w.work_files() == []
    # every fresh attempt ran with exactly the arena the replay of the preceding journal
    # derives, on a node the replay keeps pending: the live decision is the replayed one
    replayed = Replayed(w)
    for seq, attempt in replayed.attempts():
        before = replayed.fold(seq)
        key = (attempt.node.formula_sha256, attempt.node.cube)
        (node,) = before.open_nodes()
        assert node.disposition is Disposition.PENDING
        last = attempt.checks[-1]
        assert before.stream_arena(key) == (last.heap_mib, last.stack_mib)
    # the state the run cached at its end is the fold of its journal
    hit = load_cache(w.results / "state.cache", replayed.view)
    assert isinstance(hit, CacheHit)
    assert hit.state.digest() == replayed.fold().digest()


def test_the_reservation_holds_the_derived_arena(tmp_path: Path) -> None:
    """Specification §8.3: the fresh attempt reserves the checker with its derived arena. The retry
    was judged when its record was committed (idle budget of that session); a restart with a
    memory budget that holds the first arena's stream (1376 MiB) but not the derived one's
    (1888 MiB) cannot launch it: the node is resource-blocked, never run with less."""
    # the two figures are those of a solver limited to 512 MiB
    policy = t.split_policy(solver_memory_bytes=512 * t.MIB, **LADDER)
    w = t.make_world(tmp_path, {"f": SHALLOW}, policy=policy)
    t.configure(w.tools.checker, arena=True)

    class Crash(Exception):
        pass

    def crash_after_the_first_record(name: str) -> None:
        if name == "attempt.committed":
            raise Crash

    with pytest.raises(Crash):
        w.run(proof_mode="stream", hooks=crash_after_the_first_record)
    t.wait_clean(w.results, w.work)
    result = w.run(proof_mode="stream", memory_bytes=1600 * t.MIB, hooks=guard(6))
    assert result.exit_code == 1
    assert arenas(w) == [[(512, STACK)]]
    stops = [(s["state"], s["reason"]) for s in w.records("node_stop")]
    assert stops == [("resource_blocked", "solve_resources")]
    assert w.work_files() == []


def test_a_stream_leaf_holds_solver_relay_and_checker_slots(tmp_path: Path) -> None:
    """Specification §8.2: a stream leaf reserves 3000 milli-CPU (solver, relay, checker), so on
    3000 at most one leaf runs at a time, although three roots are pending from the start."""
    formulas = {"a": t.unsat(5), "b": t.unsat(6), "c": t.unsat(7)}

    def leaves_at_once(world: t.World, **changes: Any) -> int:
        """The most solver processes of this world alive at any lifecycle point."""
        running: list[int] = [0]

        def hook(name: str) -> None:
            if name.startswith("attempt."):
                running.append(solvers_alive(world))

        result = world.run(probes=t.FixedProbes(milli=3000), hooks=hook, **changes)
        assert (result.exit_code, result.reason) == (0, Stop.COMPLETE)
        assert [a["route"] for a in world.attempts()] == ["cdcl"] * 3
        return max(running)

    w = t.make_world(tmp_path / "stream", formulas, solver={"sleep": 0.3})
    assert leaves_at_once(w, proof_mode="stream") == 1
    # the oracle discriminates: a file mode runs the three leaves side by side on these CPUs
    v = t.make_world(tmp_path / "file", formulas, solver={"sleep": 0.3})
    assert leaves_at_once(v) > 1


def test_a_restart_between_two_stream_attempts_takes_the_same_next_action(
    tmp_path: Path,
) -> None:
    w = t.make_world(tmp_path, {"f": SHALLOW}, policy=t.split_policy(**LADDER))
    t.configure(w.tools.checker, arena=True)

    class Crash(Exception):
        pass

    def crash_after_the_first_record(name: str) -> None:
        if name == "attempt.committed":
            raise Crash

    with pytest.raises(Crash):
        w.run(proof_mode="stream", hooks=crash_after_the_first_record)
    assert arenas(w) == [[(512, STACK)]]
    t.wait_clean(w.results, w.work)
    result = w.run(proof_mode="stream", hooks=guard(6))
    assert result.exit_code == 1
    assert arenas(w) == [[(512, STACK)], [(1024, STACK)], [(2048, STACK)]]
    assert [(s["state"], s["reason"]) for s in w.records("node_stop")] == [("stuck", "max_depth")]
    assert [r["type"] for r in t.journal_records(w.results)].count("resume") == 1
    assert w.work_files() == []
