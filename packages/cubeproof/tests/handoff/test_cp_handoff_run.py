"""The coordinator with a desk: where it differs from the one without (specification §7.3, §7.4)."""

from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

TESTS = Path(__file__).resolve().parents[1]
if str(TESTS / "lifecycle") not in sys.path:
    sys.path.insert(0, str(TESTS / "lifecycle"))

import cp_life_tools as t  # noqa: E402

from cubeproof.coordinator.config import Stop  # noqa: E402
from cubeproof.coordinator.handoff_run import DeskCoordinator, run_with_desk  # noqa: E402

KEY = ("11" * 32, (1, -2))


def coordinator(tmp_path: Path, **options: Any) -> DeskCoordinator:
    w = t.make_world(tmp_path, {"f": t.unsat(4)})
    return DeskCoordinator(w.config(), **options)


def with_desk(c: DeskCoordinator, **fields: Any) -> DeskCoordinator:
    c.desk = SimpleNamespace(**fields)  # type: ignore[assignment]
    return c


def test_nodes_reserved_for_a_handoff_in_flight_count_as_running(tmp_path: Path) -> None:
    c = with_desk(coordinator(tmp_path), reserved=frozenset({KEY}))
    assert KEY in c._running_keys()
    c._busy.add(("22" * 32, ()))
    assert c._running_keys() == {KEY, ("22" * 32, ())}


@pytest.mark.parametrize("busy", [True, False])
def test_the_run_does_not_end_while_the_desk_has_work(tmp_path: Path, busy: bool) -> None:
    c = with_desk(coordinator(tmp_path), busy=busy)
    c._dirty = False
    assert c._finished() is (not busy)


def test_a_stopped_run_ends_whatever_the_desk_says(tmp_path: Path) -> None:
    c = with_desk(coordinator(tmp_path), busy=True)
    c._stop = Stop.INTERRUPTED
    assert c._finished() is True  # nothing in flight on this side: the stop is not held back


def test_a_command_line_shard_not_yet_offered_keeps_the_run_alive(tmp_path: Path) -> None:
    from cubeproof.contracts.documents import Shard
    from cubeproof.contracts.values import Node

    shard = Shard("ab" * 32, "cli", (Node("11" * 32, ()),))
    c = with_desk(coordinator(tmp_path, shard=shard), busy=False)
    c._dirty = False
    assert c._finished() is False
    c._cli_offered = True
    assert c._finished() is True


def test_the_library_call_runs_a_campaign_to_its_end(tmp_path: Path) -> None:
    w = t.make_world(tmp_path, {"f": t.unsat(4)}, solver={"max_free": 3})
    result = run_with_desk(w.config())
    assert result.exit_code == 0 and result.given_away == 0
    assert result.session["desk.problems"] == 0 and result.session["desk.unpublished"] == 0
    assert not (w.results / "ports.json").exists()  # no inbox, no outbox: the desk is off
