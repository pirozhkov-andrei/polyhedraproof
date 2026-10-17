"""The status document: contract validation, bounds, content and the ETA rule (specification §8.4,
§12.3)."""

from __future__ import annotations

import copy
import dataclasses
import json
import random
from collections.abc import Sequence
from typing import Any

import cp_status_support as sup
import pytest

from cubeproof.base.canonical_json import parse_document
from cubeproof.base.errors import ConfigurationError, ContractError
from cubeproof.contracts.campaign import Admit
from cubeproof.contracts.identity import node_id
from cubeproof.contracts.primitives import INT_MAX
from cubeproof.coordinator.ledger import Need, Reservation
from cubeproof.coordinator.state import ReplayState
from cubeproof.coordinator.status import (
    ROW_LIMIT,
    STALL_LIMIT,
    ActiveTask,
    EtaEstimator,
    ExportInfo,
    StatusTracker,
)
from cubeproof.coordinator.status_coverage import Coverage, closed_coverage
from cubeproof.coordinator.status_format import (
    STATUS_FIELDS,
    render_status,
    status_bytes,
    validate_status,
)

sched = sup.sched
SCHEMA = "status.schema.json"


@pytest.fixture(scope="module")
def store() -> Any:
    return sup.schema_store()


def _journal() -> Any:
    j = sched.Journal({"a": sched.formula_bytes(6)})
    j.shard([("a", ())])
    j.split("a", (), (1, 2))
    j.unsat("a", (-1, -2))
    j.unsat("a", (1, -2))
    j.model("a", (-1, 2))
    j.model("a", (1, 2), outcome="INVALID_MODEL")
    return j


def _document(**changes: Any) -> dict[str, Any]:
    j = _journal()
    state, tracker = sup.folded(j)
    changes.setdefault("coverage", closed_coverage(state))
    return sup.build(state, tracker, **changes)


# -- the contract ----------------------------------------------------------------------------------


@pytest.mark.parametrize("entry", sup.status_documents(), ids=lambda e: e["id"])
def test_the_validator_agrees_with_every_corpus_status_fixture(
    entry: dict[str, Any], store: Any
) -> None:
    value = json.loads(entry["data"]["text"])
    expect = entry["expect"]
    errors = store.errors(value, SCHEMA)
    if expect == "valid":
        assert errors == []
        assert validate_status(value) is value
        assert sup.contract_reader.status_problems(value) == []
        return
    with pytest.raises(ContractError) as caught:
        validate_status(value)
    if "rule" in expect:
        assert errors == []  # a rule violation is schema-valid
        assert caught.value.rule == expect["rule"]
        assert sup.contract_reader.status_problems(value) == [expect["rule"]]
    else:
        assert caught.value.rule == "schema"
        assert caught.value.location == expect["schema"]
        assert caught.value.location in {e.split(": ", 1)[0] for e in errors}


def test_a_built_status_satisfies_the_schema_and_the_reference_rules(store: Any) -> None:
    doc = _document(
        reservations=[
            Reservation("b" * 32, "solve", Need.of(1000, 1 << 30, work=1 << 20)),
            Reservation("a" * 32, "check", Need.of(500, 1 << 20)),
        ],
        active=[ActiveTask("c" * 32, ("0" * 64, (1, 2)), "solve", 90_000)],
        export=ExportInfo("e" * 64, 3, "2026-10-01T00:00:00.000Z", 1234),
    )
    assert store.errors(doc, SCHEMA) == []
    assert sup.contract_reader.status_problems(doc) == []
    assert validate_status(doc) is doc
    assert set(doc) == set(STATUS_FIELDS)
    # the canonical bytes are what is published and read back
    assert parse_document(status_bytes(doc)) == doc


_POOL: list[Any] = [
    None,
    True,
    0,
    1,
    -1,
    INT_MAX,
    "",
    "a",
    "0" * 64,
    "0" * 32,
    "1" * 64,
    "cubeproof-status-2",
    "2026-10-04T12:00:00.000Z",
    "007",
    "9223372036854775808",
    [],
    {},
    [1],
    {"a": 1},
    {"journal": "0" * 64, "seq": 0},
    {"formula_sha256": "0" * 64, "cube": []},
]
_EXTRA = ["extra", "info", "node", "0" * 64, "Bad name"]


def _paths(value: Any, prefix: tuple[Any, ...] = ()) -> list[tuple[Any, ...]]:
    found = [prefix]
    if isinstance(value, dict):
        for key, item in value.items():
            found += _paths(item, (*prefix, key))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            found += _paths(item, (*prefix, index))
    return found


def _get(value: Any, path: tuple[Any, ...]) -> Any:
    for part in path:
        value = value[part]
    return value


def _mutate(seed: Any, rng: random.Random) -> Any:
    value = copy.deepcopy(seed)
    for _ in range(rng.choice([1, 1, 2])):
        path = rng.choice(_paths(value))
        target = _get(value, path)
        op = rng.randrange(6)
        if op == 0 and path:
            _get(value, path[:-1])[path[-1]] = copy.deepcopy(rng.choice(_POOL))
        elif op == 1 and path:
            del _get(value, path[:-1])[path[-1]]
        elif op == 2 and isinstance(target, dict):
            target[rng.choice(_EXTRA)] = copy.deepcopy(rng.choice(_POOL))
        elif op == 3 and isinstance(target, list):
            target.append(copy.deepcopy(rng.choice(target)) if target else rng.choice(_POOL))
        elif op == 4 and isinstance(target, (list, dict)):
            target.clear()
        elif path:
            parent = _get(value, path[:-1])
            if type(target) is int:
                parent[path[-1]] = rng.choice([target - 1, target + 1, 0, INT_MAX])
            else:
                parent[path[-1]] = copy.deepcopy(rng.choice(_POOL))
    return value


def test_random_mutants_get_the_schema_verdict_of_the_shared_validator(store: Any) -> None:
    seeds: list[Any] = [
        json.loads(e["data"]["text"]) for e in sup.status_documents() if e["expect"] == "valid"
    ]
    seeds.append(
        _document(
            reservations=[Reservation("b" * 32, "solve", Need.of(1000, 1 << 30, work=1 << 20))],
            active=[ActiveTask("c" * 32, None, "split", 90_000)],
            export=ExportInfo("e" * 64, 3, "2026-10-01T00:00:00.000Z", 1234),
        )
    )
    rng = random.Random("c22-status")
    rejected = accepted = 0
    for _ in range(800):
        mutant = _mutate(rng.choice(seeds), rng)
        errors = store.errors(mutant, SCHEMA)
        try:
            validate_status(mutant)
            mine: ContractError | None = None
        except ContractError as error:
            mine = error
        if errors:
            rejected += 1
            assert mine is not None and mine.rule == "schema", (mutant, errors, mine)
            assert mine.location in {e.split(": ", 1)[0] for e in errors}, (errors, mine)
        else:
            accepted += 1
            assert mine is None or mine.rule != "schema", (mutant, mine)
            if any(c["denominator_power_two"] > 10_000 for c in mutant["coverage"]):
                continue  # the reference reader computes 2**power: it cannot judge these
            expected = sup.contract_reader.status_problems(mutant)
            assert (mine.rule if mine else None) == (expected[0] if expected else None), (
                mutant,
                expected,
                mine,
            )
    assert rejected > 200 and accepted > 20


@pytest.mark.parametrize(
    ("numerator", "power", "valid"),
    [
        ("0", 0, True),
        ("1", 0, True),
        ("2", 0, False),
        ("1", 1, True),
        ("3", 1, False),  # 3/2
        ("3", 2, True),
        ("5", 2, False),  # 5/4
        ("4", 2, False),  # not reduced
        ("0", 3, False),  # zero is 0/2^0
        ("9223372036854775807", 63, True),
        ("1", 9223372036854775807, True),  # no 2**power is ever computed
        ("3", 9223372036854775807, True),
        ("1" + "0" * 5000, 9223372036854775807, False),  # more digits than are converted
    ],
)
def test_the_coverage_rule_is_exact_and_cheap_for_hostile_numbers(
    numerator: str, power: int, valid: bool
) -> None:
    doc = _document()
    doc["coverage"][0]["closed_numerator"] = numerator
    doc["coverage"][0]["denominator_power_two"] = power
    if valid:
        assert validate_status(doc) is doc
    else:
        with pytest.raises(ContractError) as caught:
            validate_status(doc)
        assert caught.value.rule == "status.coverage"
    if power < 10_000:  # the reference reader computes 2**power
        assert (sup.contract_reader.status_problems(doc) == []) == valid


@pytest.mark.parametrize(
    "name", ["reservations", "node_counts", "active", "models", "anomalies", "coverage"]
)
def test_every_ordered_list_must_be_strictly_increasing(name: str) -> None:
    state, tracker, _ = _many_models(12)
    doc = sup.build(
        state,
        tracker,
        coverage=closed_coverage(state),
        reservations=[
            Reservation("a" * 32, "solve", Need.of(1, 1)),
            Reservation("b" * 32, "check", Need.of(2, 2)),
        ],
        active=[ActiveTask("c" * 32, None, "split", 0), ActiveTask("d" * 32, None, "solve", 0)],
    )
    other = copy.deepcopy(doc["coverage"][0])
    other["node"]["formula_sha256"] = "f" * 64
    doc["coverage"] = sorted(
        [*doc["coverage"], other],
        key=lambda c: (c["node"]["formula_sha256"], node_id(c["node"]["formula_sha256"], [])),
    )
    assert len(doc[name]) >= 2, name
    assert validate_status(doc) is doc  # the unmodified document is valid
    swapped = copy.deepcopy(doc)
    swapped[name][0], swapped[name][1] = swapped[name][1], swapped[name][0]
    duplicated = copy.deepcopy(doc)
    duplicated[name][1] = copy.deepcopy(duplicated[name][0])
    for mutant in (swapped, duplicated):
        with pytest.raises(ContractError) as caught:
            validate_status(mutant)
        assert caught.value.rule == "status.order"
        assert sup.contract_reader.status_problems(mutant) == ["status.order"]


def test_unknown_top_level_fields_and_versions_are_rejected_unknown_diagnostics_are_ignored() -> (
    None
):
    doc = _document()
    with pytest.raises(ContractError):
        validate_status({**doc, "newer": 1})
    with pytest.raises(ContractError):
        validate_status({**doc, "format": "cubeproof-status-2"})
    tolerant = copy.deepcopy(doc)
    tolerant["counters"]["a_counter_from_a_newer_writer"] = 7
    tolerant["info"]["a_note_from_a_newer_writer"] = {"anything": [1, 2]}
    assert validate_status(tolerant) is tolerant


def test_the_text_rendering_never_passes_control_characters_to_a_terminal() -> None:
    doc = _document(
        stalls=["\x1b[2Jcleared\r\nforged line"],
        active=[ActiveTask("a" * 32, None, "st\x07age\x1b[31m", 0)],
        info={"export": {"last_error": "boom\x1b]0;title\x07"}},
    )
    assert validate_status(doc) is doc
    text = render_status(doc)
    assert "\x1b" not in text and "\x07" not in text and "\r" not in text
    assert all(c == "\n" or c.isprintable() for c in text)
    assert "forged line" in text  # the content stays readable, only the controls are gone


def test_the_text_rendering_is_the_same_snapshot() -> None:
    doc = _document(export=ExportInfo("e" * 64, 3, "2026-10-01T00:00:00.000Z", 61_000))
    text = render_status(doc)
    assert doc["utc"] in text and doc["worker"] in text
    assert f"seq {doc['seq']}" in text and doc["head"][:12] in text
    assert "lag 1m01s" in text
    assert "eta: not available" in text
    assert "0 of 1 roots closed, mean closed fraction 0.5000" in text
    assert text.endswith("\n") and render_status(doc) == text  # deterministic


# -- content ---------------------------------------------------------------------------------------


def test_the_state_shows_as_counts_by_state_and_depth() -> None:
    doc = _document()
    assert doc["node_counts"] == [
        {"state": "closed", "depth": 2, "count": 2},
        {"state": "model", "depth": 2, "count": 1},
        {"state": "needs_split", "depth": 2, "count": 1},
    ]
    counters = doc["counters"]
    assert (counters["models"], counters["anomalies"], counters["attempts"]) == (1, 1, 4)
    assert counters["outcome_verified_unsat"] == 2 and counters["records"] == 7
    assert [r["seq"] for r in doc["models"]] == [5] and [r["seq"] for r in doc["anomalies"]] == [6]
    assert all(r["journal"] == doc["journal"] for r in doc["models"] + doc["anomalies"])
    assert doc["info"]["session"] == {"anomalies": 1, "machine_failures": 0}


def test_historical_problems_stay_visible_as_counters() -> None:
    """Attempts the certifier would not admit, splits that are not well formed and nodes given
    away are listed by the state; the status keeps their totals, they never disappear."""
    j = sched.Journal({"a": sched.formula_bytes(6)})
    j.shard([("a", ())])
    j.split("a", (), (1,))
    j.split("a", (1,), (1,))  # the variable is already in the cube: a malformed split
    j.unsat("a", (-1,))
    j.unsat("a", (1,))
    j.handoff([("a", (1,))])
    view = dataclasses.replace(j.view, admit=Admit((sched.OTHER_HASH,), None))
    state = ReplayState(view)
    tracker = StatusTracker()
    for record in j.records:
        state.apply(record)
        tracker.observe(record)
    doc = sup.build(state, tracker)
    assert doc["counters"]["not_admitted"] == 2  # both verified attempts name an unadmitted checker
    assert doc["counters"]["malformed_splits"] == 1
    assert doc["counters"]["given_away"] == 1
    assert doc["counters"]["outcome_verified_unsat"] == 2
    assert not state.closed(j.key("a", (-1,)))  # not admitted: nothing is closed


def test_active_tasks_and_reservations_are_sorted_with_elapsed_times() -> None:
    node = ("0" * 64, (1, 2))
    doc = _document(
        now_ms=100_000,
        active=[
            ActiveTask("b" * 32, node, "check", 99_000),
            ActiveTask("a" * 32, None, "split", 40_000),
        ],
        reservations=[
            Reservation("d" * 32, "solve", Need.of(1000, 5, zeta=3, alpha=2)),
            Reservation("c" * 32, "check", Need.of(0, 7)),
        ],
    )
    assert [a["task_id"] for a in doc["active"]] == ["a" * 32, "b" * 32]
    assert doc["active"][0] == {
        "task_id": "a" * 32,
        "node_id": None,
        "stage": "split",
        "elapsed_ms": 60_000,
    }
    assert doc["active"][1]["node_id"] == node_id(*node) and doc["active"][1]["elapsed_ms"] == 1000
    assert doc["oldest_elapsed_ms"] == 60_000
    assert [r["task_id"] for r in doc["reservations"]] == ["c" * 32, "d" * 32]
    assert doc["reservations"][1]["disk"] == [
        {"id": "alpha", "bytes": 2},
        {"id": "zeta", "bytes": 3},
    ]
    assert _document()["oldest_elapsed_ms"] == 0


def test_a_task_that_started_in_the_future_has_zero_elapsed_time() -> None:
    doc = _document(now_ms=10, active=[ActiveTask("a" * 32, None, "split", 500)])
    assert doc["active"][0]["elapsed_ms"] == 0 and doc["oldest_elapsed_ms"] == 0


def test_stalls_info_and_counters_are_merged_without_clashes() -> None:
    doc = _document(
        stalls=["no task fits: memory"],
        counters={"export_ok": 3},
        info={"export": {"state": "idle"}},
    )
    assert doc["info"]["stalls"] == ["no task fits: memory"]
    assert doc["counters"]["export_ok"] == 3 and doc["info"]["export"] == {"state": "idle"}
    with pytest.raises(ConfigurationError):
        _document(counters={"models": 1})
    with pytest.raises(ConfigurationError):
        _document(info={"session": {}})


def test_a_status_needs_a_state_that_has_applied_its_header() -> None:
    j = _journal()
    with pytest.raises(ConfigurationError):
        sup.build(ReplayState(j.view), StatusTracker())


def test_coverage_is_omitted_and_says_so_when_unavailable() -> None:
    doc = _document(coverage=None)
    assert doc["coverage"] == [] and doc["info"]["coverage"] == {"available": False}


def test_stale_coverage_is_marked() -> None:
    j = _journal()
    state, tracker = sup.folded(j)
    cov = closed_coverage(state)
    doc = sup.build(state, tracker, coverage=cov, coverage_seq=state.seq - 2)
    assert doc["info"]["coverage"]["stale"] is True
    assert doc["info"]["coverage"]["computed_seq"] == state.seq - 2
    fresh = sup.build(state, tracker, coverage=cov)
    assert fresh["info"]["coverage"]["stale"] is False


# -- bounds: no growth with the run ----------------------------------------------------------------


def _many_models(count: int) -> tuple[ReplayState, StatusTracker, Any]:
    j = sched.Journal({"a": sched.formula_bytes(12)})
    j.shard([("a", ())])
    j.split("a", (), (1, 2, 3, 4, 5, 6, 7))
    cubes = sched.children((), (1, 2, 3, 4, 5, 6, 7))
    for index in range(count):
        cube = cubes[index % len(cubes)]
        if index % 2:
            j.model("a", cube)
        else:
            j.model("a", cube, outcome="INVALID_MODEL")
    state, tracker = sup.folded(j)
    return state, tracker, j


def test_models_and_anomalies_are_capped_at_100_with_totals_in_counters() -> None:
    state, tracker, j = _many_models(260)
    doc = sup.build(state, tracker)
    assert len(doc["models"]) == len(doc["anomalies"]) == 100
    assert doc["counters"]["models"] == doc["counters"]["anomalies"] == 130
    assert doc["info"]["truncated"] == {"anomalies": 30, "models": 30}
    assert validate_status(doc) is doc
    # the earliest are kept, so the list does not change while it grows
    assert [r["seq"] for r in doc["models"]] == sorted(r["seq"] for r in doc["models"])
    assert doc["models"][0]["seq"] == 4  # header, shard, split, anomaly, then the first model
    # no model assignment is ever copied into the status
    assignment = next(v["assignment"] for v in j.values if v["type"] == "attempt")
    text = json.dumps(doc)
    assert assignment not in text and "assignment" not in text


def test_the_status_size_does_not_grow_with_the_number_of_records() -> None:
    small_state, small_tracker, _ = _many_models(260)
    large_state, large_tracker, _ = _many_models(800)
    small = len(
        status_bytes(sup.build(small_state, small_tracker, coverage=closed_coverage(small_state)))
    )
    large = len(
        status_bytes(sup.build(large_state, large_tracker, coverage=closed_coverage(large_state)))
    )
    assert large - small < 600  # only a few more digits in the counters and notices


def test_lists_that_depend_on_the_run_are_cut_at_the_row_limit() -> None:
    j = _journal()
    state, tracker = sup.folded(j)
    reservations = [
        Reservation(f"{index:032x}", "solve", Need.of(1, 1, work=1))
        for index in range(ROW_LIMIT + 50)
    ]
    active = [ActiveTask(f"{index:032x}", None, "split", 0) for index in range(ROW_LIMIT + 7)]
    stalls = [f"reason {index}" for index in range(STALL_LIMIT + 5)] + ["x" * 5000]
    doc = sup.build(state, tracker, reservations=reservations, active=active, stalls=stalls)
    assert len(doc["reservations"]) == len(doc["active"]) == ROW_LIMIT
    assert len(doc["info"]["stalls"]) == STALL_LIMIT
    assert doc["info"]["truncated"] == {"active": 7, "reservations": 50, "stalls": 6}
    assert validate_status(doc) is doc
    assert len(status_bytes(doc)) < 1 << 20


def test_a_worst_case_status_stays_well_below_two_mebibytes() -> None:
    """Every capped list full, the deepest allowed node_counts and long coverage numerators."""
    j = sched.Journal({"a": sched.formula_bytes(250)})
    j.shard([("a", ())])
    state, tracker = sup.folded(j)
    reservations = [
        Reservation(f"{i:032x}", "solve" * 4, Need.of(1, 1, **{f"g{n}": 1 for n in range(4)}))
        for i in range(ROW_LIMIT)
    ]
    active = [
        ActiveTask(f"{i:032x}", ("0" * 64, tuple(range(1, 30))), "split", 0)
        for i in range(ROW_LIMIT)
    ]
    cover = [Coverage((f"{i:064x}", (1, 2, 3)), 2**250 - 1, 250) for i in range(ROW_LIMIT)]
    doc = sup.build(
        state,
        tracker,
        reservations=reservations,
        active=active,
        coverage=sorted(cover, key=lambda c: (c.root[0], node_id(*c.root))),
        stalls=["s" * 400] * 30,
    )
    assert len(status_bytes(doc)) < 2 << 20


# -- the ETA rule ----------------------------------------------------------------------------------


def _feed(
    estimator: EtaEstimator,
    times: Sequence[int],
    *,
    closed: Sequence[int],
    pending: int | Sequence[int] = 100,
    needs_split: int | Sequence[int] = 0,
    splits: int | Sequence[int] = 5,
) -> None:
    def at(value: int | Sequence[int], index: int) -> int:
        return value if isinstance(value, int) else value[index]

    for index, now in enumerate(times):
        estimator.observe(
            now,
            closed_leaves=closed[index],
            pending=at(pending, index),
            needs_split=at(needs_split, index),
            splits=at(splits, index),
        )


STEADY_TIMES = [i * 15_000 for i in range(9)]  # 2 minutes
STEADY_CLOSED = [i * 15 for i in range(9)]  # 1 leaf per second


def test_a_steady_stable_frontier_gives_an_estimate_of_pending_over_rate() -> None:
    eta = EtaEstimator()
    _feed(eta, STEADY_TIMES, closed=STEADY_CLOSED)
    assert eta.estimate() == 100_000  # 100 pending at 1 leaf/s


def test_no_estimate_with_too_few_samples_or_too_short_a_span() -> None:
    eta = EtaEstimator()
    _feed(eta, STEADY_TIMES[:5], closed=STEADY_CLOSED[:5])
    assert eta.estimate() is None  # five samples
    quick = EtaEstimator()
    _feed(quick, [i * 1000 for i in range(9)], closed=list(range(9)))
    assert quick.estimate() is None  # eight seconds


def test_no_estimate_while_the_frontier_is_still_branching() -> None:
    growing = EtaEstimator()
    _feed(growing, STEADY_TIMES, closed=STEADY_CLOSED, splits=[5, 5, 5, 5, 6, 6, 6, 6, 6])
    assert growing.estimate() is None  # a split was recorded inside the window
    waiting = EtaEstimator()
    _feed(waiting, STEADY_TIMES, closed=STEADY_CLOSED, needs_split=[0, 0, 0, 0, 0, 0, 0, 0, 3])
    assert waiting.estimate() is None  # nodes wait for a split


def test_no_estimate_when_the_rate_changes_or_stops_or_nothing_is_pending() -> None:
    slowing = EtaEstimator()
    _feed(slowing, STEADY_TIMES, closed=[0, 30, 60, 90, 120, 121, 122, 123, 124])
    assert slowing.estimate() is None  # 2 leaves/s, then 0.07/s
    stalled = EtaEstimator()
    _feed(stalled, STEADY_TIMES, closed=[0, 15, 30, 45, 60, 60, 60, 60, 60])
    assert stalled.estimate() is None
    nothing = EtaEstimator()
    _feed(nothing, STEADY_TIMES, closed=STEADY_CLOSED, pending=0)
    assert nothing.estimate() is None


def test_old_samples_leave_the_window_and_a_backwards_clock_starts_over() -> None:
    eta = EtaEstimator(window_ms=60_000, min_samples=5)
    _feed(eta, STEADY_TIMES, closed=STEADY_CLOSED, splits=[1, 2, 3, 4, 5, 5, 5, 5, 5])
    assert eta.estimate() is not None  # the splits are outside the 60 s window now
    eta.observe(1, closed_leaves=0, pending=10, needs_split=0, splits=5)  # the clock went back
    assert eta.estimate() is None
    # the estimator started over: only the samples taken since count (2 leaves/s here)
    fresh = [1 + i * 15_000 for i in range(9)]
    for index, now in enumerate(fresh[1:], start=1):
        eta.observe(now, closed_leaves=index * 30, pending=10, needs_split=0, splits=5)
    assert eta.estimate() == 5_000


def test_the_status_says_null_for_an_unstable_frontier_and_a_number_when_given_one() -> None:
    assert _document()["eta_ms"] is None
    assert _document(eta_ms=1500)["eta_ms"] == 1500
