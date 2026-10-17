"""The first shards of a campaign whose requested roots do not fit one journal line
(specification §4.7, §7.4, §12.1).

A first use without ``--shard`` owns every requested root. When the roots fit one line that is
the single shard ``initial``; otherwise the worker divides them like the shard planner and
commits the parts ``initial-1``, ``initial-2``, ... one record at a time. The campaigns here have
512 requested roots of one formula and a line limit that holds about two hundred of them, so
the expected parts are computed in the test from the limit and the planner's function, not read
back from the run.
"""

from __future__ import annotations

import itertools
from pathlib import Path
from typing import Any

import cp_life_tools as t
import pytest

from cubeproof.base.settings import ReaderLimits
from cubeproof.cnf.campaign import load_campaign
from cubeproof.commands import CampaignRequest, create_campaign
from cubeproof.commands.shard import shards_of
from cubeproof.contracts.campaign import Admit
from cubeproof.contracts.documents import Roots
from cubeproof.contracts.values import Node
from cubeproof.coordinator.run import Coordinator
from cubeproof.tools.isolation import PinnedBinary

SMALL = ReaderLimits(line_bytes=32 * 1024)
PREFIX = 9  # 512 requested roots


def wide_world(root: Path) -> t.World:
    """One unsatisfiable formula of twelve variables with all 2**PREFIX cubes over its first
    variables as requested roots; every root is refuted by the scripted tools at once."""
    tools = t.install(root / "tools")
    path = t.campaign(root, {"f": t.unsat(12)}, tools)  # bundles and a throwaway campaign
    loaded = load_campaign(path)
    (formula,) = loaded.bundles
    cubes = [
        tuple(v if bit else -v for v, bit in zip(range(1, PREFIX + 1), bits, strict=True))
        for bits in itertools.product((0, 1), repeat=PREFIX)
    ]
    nodes = sorted((Node(formula, cube) for cube in cubes), key=lambda n: n.sort_key)
    checker = PinnedBinary.measure(str(tools.checker)).sha256
    path.unlink()
    create_campaign(
        CampaignRequest(
            bundles=[root / "bundles" / "f"],
            policy=t.split_policy(),
            admit=Admit.from_json({"checker_sha256": [checker], "solvers": None}, "$"),
            solver=str(tools.solver),
            solver_argv=["--lrat"],
            checker=str(tools.checker),
            output=path,
            author="lifecycle-tests",
            roots=Roots(tuple(nodes)),
        )
    )
    return t.World(root, path, tools)


def expected_parts(w: t.World, limits: ReaderLimits) -> list[list[list[int]]]:
    """The cubes of each part as the shard planner divides the same nodes for one machine."""
    loaded = load_campaign(w.campaign)
    parts = shards_of(
        loaded.campaign.campaign_id,
        1,
        list(loaded.campaign.roots),
        max_line_bytes=limits.line_bytes,
    )
    return [[list(n.cube) for n in part.nodes] for part in parts]


def recorded_parts(w: t.World) -> list[tuple[str, list[list[int]]]]:
    return [
        (r["shard"]["name"], [n["cube"] for n in r["shard"]["nodes"]]) for r in w.records("shard")
    ]


def test_a_first_use_divides_roots_that_do_not_fit_one_line(tmp_path: Path) -> None:
    w = wide_world(tmp_path)
    expected = expected_parts(w, SMALL)
    assert len(expected) >= 3 and sum(len(part) for part in expected) == 1 << PREFIX
    order: list[str] = []

    def hooks(name: str) -> None:
        if name in ("shard.submitted", "shard.committed"):
            order.append(name)

    done = w.run(limits=SMALL, max_seconds=0.5, hooks=hooks)
    assert done.exit_code in (0, 1)  # the time allocation may end before 512 leaves are done
    # one record at a time: a part is committed before the next is submitted
    assert order == ["shard.submitted", "shard.committed"] * len(expected)
    recorded = recorded_parts(w)
    assert [name for name, _ in recorded] == [f"initial-{i}" for i in range(1, len(expected) + 1)]
    assert [cubes for _, cubes in recorded] == expected
    owned = [tuple(cube) for _, cubes in recorded for cube in cubes]
    assert len(set(owned)) == len(owned) == 1 << PREFIX  # every root once


def test_roots_that_fit_one_line_are_still_the_one_shard_initial(tmp_path: Path) -> None:
    w = wide_world(tmp_path)
    w.run(max_seconds=0.5)  # the default limit of 8 MiB
    ((name, cubes),) = recorded_parts(w)
    assert name == "initial" and len(cubes) == 1 << PREFIX


def test_an_interrupted_first_use_owns_the_remaining_parts_at_its_next_start(
    tmp_path: Path,
) -> None:
    w = wide_world(tmp_path)
    expected = expected_parts(w, SMALL)
    submitted: list[str] = []

    class Interrupted(Exception):
        pass

    def hooks(name: str) -> None:
        if name == "shard.submitted":
            submitted.append(name)
            if len(submitted) == 2:  # the first part is committed, the second is not submitted
                raise Interrupted

    with pytest.raises(Interrupted):
        Coordinator(w.config(limits=SMALL, hooks=hooks)).run()
    t.wait_clean(w.results, w.work)
    assert [name for name, _ in recorded_parts(w)] == ["initial-1"]
    w.run(limits=SMALL, max_seconds=0.5)
    recorded = recorded_parts(w)
    assert [name for name, _ in recorded] == [f"initial-{i}" for i in range(1, len(expected) + 1)]
    assert [cubes for _, cubes in recorded] == expected
    before = recorded_parts(w)
    w.run(limits=SMALL, max_seconds=0.5)  # complete: a third start adds nothing
    assert recorded_parts(w) == before


def test_ownership_is_not_extended_for_a_worker_that_owns_other_shards(tmp_path: Path) -> None:
    """The remaining parts are owned only by a worker whose shards are some of its own first
    parts. Under another line limit the roots divide differently, the accepted shard is none of
    those parts, and nothing is added (specification §12.1: nothing is reconstructed from a
    changed command line); under the first limit the first use is then completed."""
    w = wide_world(tmp_path)
    wider = ReaderLimits(line_bytes=48 * 1024)
    other = expected_parts(w, wider)
    assert len(other) == 2 and other[0] != expected_parts(w, SMALL)[0]  # two parts, not three
    calls: list[str] = []

    class Interrupted(Exception):
        pass

    def hooks(name: str) -> None:
        if name == "shard.submitted":
            calls.append(name)
            if len(calls) == 2:
                raise Interrupted

    with pytest.raises(Interrupted):
        Coordinator(w.config(limits=SMALL, hooks=hooks)).run()
    t.wait_clean(w.results, w.work)
    before = recorded_parts(w)
    assert [name for name, _ in before] == ["initial-1"]
    done: Any = w.run(limits=wider, max_seconds=0.5)
    assert done.exit_code in (0, 1)
    assert recorded_parts(w) == before  # another division: not this worker's first parts
    w.run(limits=SMALL, max_seconds=0.5)
    assert len(recorded_parts(w)) == len(expected_parts(w, SMALL))


def test_a_campaign_near_the_line_limit_is_divided_and_completed_too(tmp_path: Path) -> None:
    """The shortcut that skips the division must not skip a campaign of two parts: 512 roots and
    a limit that holds most of them. (A lower bound of the size of a node cannot prove that the
    roots fit one line; this is the case such a bound gets wrong.)"""
    w = wide_world(tmp_path)
    near = ReaderLimits(line_bytes=56 * 1024)
    expected = expected_parts(w, near)
    assert len(expected) == 2
    calls: list[str] = []

    class Interrupted(Exception):
        pass

    def hooks(name: str) -> None:
        if name == "shard.submitted":
            calls.append(name)
            if len(calls) == 2:
                raise Interrupted

    with pytest.raises(Interrupted):
        Coordinator(w.config(limits=near, hooks=hooks)).run()
    t.wait_clean(w.results, w.work)
    assert [name for name, _ in recorded_parts(w)] == ["initial-1"]
    w.run(limits=near, max_seconds=0.5)
    assert [cubes for _, cubes in recorded_parts(w)] == expected
