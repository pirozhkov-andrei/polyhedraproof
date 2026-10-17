"""Units of the certifier: the closure engine, success fields, admission, import closure."""

from __future__ import annotations

import json
import os
import random
import subprocess
import sys
from typing import Any

import pytest
from cp_certify_support import (
    CHECKER,
    MACHINERY,
    OTHER_HASH,
    SOLVER,
    children,
    corpus_records,
    machinery,
)

from cubeproof.base.errors import ResourceError
from cubeproof.contracts.campaign import Admit, AdmittedSolver
from cubeproof.evidence.certify import (
    EvidenceGraph,
    Leaf,
    admission_reason,
    success_problem,
)
from cubeproof.evidence.schema import Machinery

F = "f" * 64
Key = tuple[str, tuple[int, ...]]


def leaf(journal: str, seq: int) -> Leaf:
    return Leaf(journal, seq, "c" * 64, "d" * 64, "unit")


def k(*cube: int) -> Key:
    return (F, tuple(cube))


# -- closure engine -------------------------------------------------------------------------------


def chain(depth: int, *, last: bool = True, max_nodes: int | None = None) -> EvidenceGraph:
    graph = EvidenceGraph(max_nodes=max_nodes)
    cube: tuple[int, ...] = ()
    for variable in range(1, depth + 1):
        graph.add_split((F, cube), [variable])
        graph.add_verified((F, (*cube, -variable)), leaf("a" * 64, variable))
        cube = (*cube, variable)
    if last:
        graph.add_verified((F, cube), leaf("a" * 64, 0))
    return graph


def test_a_deep_chain_uses_no_recursion() -> None:
    depth = 1500
    assert depth > sys.getrecursionlimit()
    graph = chain(depth)
    assert graph.closed(k())
    leaves, splits = graph.select(k())
    assert (len(leaves), splits) == (depth + 1, depth)
    assert graph.frontier(k()) == []
    open_graph = chain(depth, last=False)
    assert not open_graph.closed(k())
    assert open_graph.frontier(k()) == [(k(*range(1, depth + 1)), "pending", None)]


def test_closure_needs_every_child_and_any_split() -> None:
    graph = EvidenceGraph()
    graph.add_split(k(), [1, 2])
    for child in children((), [1, 2])[:3]:
        graph.add_verified((F, child), leaf("a" * 64, 1))
    assert not graph.closed(k())
    assert graph.frontier(k()) == [((F, children((), [1, 2])[3]), "pending", None)]
    fresh = EvidenceGraph()
    fresh.add_split(k(), [1, 2])
    fresh.add_split(k(), [3])
    for key in [*((F, c) for c in children((), [1, 2])[:3]), k(3), k(-3)]:
        fresh.add_verified(key, leaf("a" * 64, len(key[1])))
    assert fresh.closed(k())
    leaves, splits = fresh.select(k())
    assert splits == 1
    assert {key for key, _ in leaves} == {k(3), k(-3)}


def test_the_smallest_ref_and_the_attempt_before_a_split() -> None:
    graph = EvidenceGraph()
    graph.add_split(k(), [1])
    graph.add_verified(k(1), leaf("a" * 64, 1))
    graph.add_verified(k(-1), leaf("a" * 64, 2))
    graph.add_verified(k(), leaf("b" * 64, 1))
    graph.add_verified(k(), leaf("a" * 64, 9))
    leaves, splits = graph.select(k())
    assert splits == 0
    assert leaves == [(k(), leaf("a" * 64, 9))]


def test_insertion_order_does_not_change_any_result() -> None:
    rng = random.Random(7)
    events: list[tuple[str, Key, Any]] = []
    for cube in [(), (1,), (-1,), (1, 2), (-1, 2), (-1, -2)]:
        for w in ([2], [3], [3, 2]):
            if not {abs(x) for x in cube} & set(w):
                events.append(("split", (F, cube), w))
    for index, cube in enumerate(
        [(1,), (-1, 2), (-1, -2), (2, 3), (-2, 3), (1, 2, 3), (-1, 2, -3), (-1, -2, 3)]
    ):
        events.append(("verified", (F, cube), leaf("a" * 64 if index % 2 else "b" * 64, index)))
    events.append(("model", (F, (1, -2)), None))
    results = set()
    for _ in range(20):
        rng.shuffle(events)
        graph = EvidenceGraph()
        for kind, key, value in events:
            if kind == "split":
                graph.add_split(key, value)
            elif kind == "verified":
                graph.add_verified(key, value)
            else:
                graph.add_model(key)
        starts = [k(), k(1), k(-1), k(-1, 2)]
        closed = tuple(graph.closed(s) for s in starts)
        selected = tuple(
            (tuple(sorted(graph.select(s)[0])), graph.select(s)[1]) if graph.closed(s) else None
            for s in starts
        )
        frontier = tuple(tuple(sorted(graph.frontier(s))) for s in starts)
        results.add((closed, selected, frontier))
    assert len(results) == 1


def labelled(events: list[tuple[str, int, str | None, str]]) -> list[Any]:
    graph = EvidenceGraph()
    for journal, seq, state, reason in events:
        graph.add_label(k(), journal, seq, state, reason)
    return graph.frontier(k())


def test_labels_latest_per_journal_then_smallest_stop() -> None:
    a, b = "a" * 64, "b" * 64
    events: list[tuple[str, int, str | None, str]] = [
        (b, 3, "stuck", "b3"),
        (a, 5, "tool_blocked", "a5"),
        (a, 2, "resource_blocked", "a2"),
    ]
    assert labelled(events) == [(k(), "tool_blocked", "a5")]
    assert labelled(events[::-1]) == [(k(), "tool_blocked", "a5")]
    events.append((a, 7, None, "reopen"))
    assert labelled(events) == [(k(), "stuck", "b3")]
    events.append((b, 4, None, "reopen"))
    assert labelled(events) == [(k(), "pending", None)]
    assert labelled([(b, 4, None, "reopen"), (b, 3, "stuck", "b3")]) == [(k(), "pending", None)]


def test_a_model_node_is_emitted_before_its_splits() -> None:
    graph = EvidenceGraph()
    graph.add_split(k(), [1])
    graph.add_model(k())
    graph.add_label(k(), "a" * 64, 1, "stuck", "x")
    assert graph.frontier(k()) == [(k(), "model", None)]


def test_the_frontier_follows_the_smallest_split_id() -> None:
    from cubeproof.contracts.identity import node_id, split_id

    graph = EvidenceGraph()
    graph.add_split(k(), [1])
    graph.add_split(k(), [2])
    graph.add_verified(k(2), leaf("a" * 64, 1))
    graph.add_verified(k(1), leaf("a" * 64, 2))
    small = min([[1], [2]], key=lambda w: split_id(node_id(F, ()), w))
    expected = sorted((F, c) for c in children((), small) if c not in {(1,), (2,)})
    assert sorted(key for key, _, _ in graph.frontier(k())) == expected


def test_a_node_limit_is_a_resource_error() -> None:
    limited = chain(50, max_nodes=100)
    with pytest.raises(ResourceError):
        limited.closed(k())
    enough = chain(50, max_nodes=101)
    assert enough.closed(k())


def test_selecting_an_open_node_is_refused() -> None:
    graph = EvidenceGraph()
    with pytest.raises(ValueError):
        graph.select(k())


def test_evidence_cannot_be_added_after_a_query() -> None:
    """Memoized results are exact only for complete evidence (specification §10.2)."""
    graph = EvidenceGraph()
    graph.add_split(k(), [1])
    assert not graph.closed(k())
    with pytest.raises(RuntimeError):
        graph.add_verified(k(1), leaf("a" * 64, 1))
    with pytest.raises(RuntimeError):
        graph.add_split(k(1), [2])
    with pytest.raises(RuntimeError):
        graph.add_model(k(1))
    with pytest.raises(RuntimeError):
        graph.add_label(k(1), "a" * 64, 1, None, "x")


# -- success fields and admission ------------------------------------------------------------------


def attempt(**fields: Any) -> dict[str, Any]:
    record = corpus_records("journals/base/w1.jsonl")[2]
    for name in ("format", "seq", "prev", "self", "utc", "type"):
        record.pop(name)
    record.update(fields)
    return record


RELAY = {
    "bytes": 1037,
    "sha256": "b5c0a80b27ce9372ef174b5ef0e34da5559b2bed3859b998f10b19828129ffd7",
}


@pytest.mark.parametrize(
    ("fields", "rule"),
    [
        ({}, None),
        ({"route": "unit", "solver": None}, None),
        ({"proof_bytes": None}, "success.proof"),
        ({"proof_sha256": None}, "success.proof"),
        ({"checks": []}, "success.checks"),
        ({"solver": None}, "success.solver"),
        ({"proof_mode": "stream", "relay": None}, "success.relay"),
        (
            {
                "proof_mode": "stream",
                "relay": RELAY | {"solver_eof": True, "all_written": True, "error": None},
            },
            None,
        ),
        (
            {
                "proof_mode": "stream",
                "relay": RELAY | {"solver_eof": False, "all_written": True, "error": None},
            },
            "success.relay",
        ),
        (
            {
                "proof_mode": "stream",
                "relay": RELAY | {"solver_eof": True, "all_written": False, "error": None},
            },
            "success.relay",
        ),
        (
            {
                "proof_mode": "stream",
                "relay": RELAY | {"solver_eof": True, "all_written": True, "error": "x"},
            },
            "success.relay",
        ),
        (
            {
                "proof_mode": "stream",
                "relay": RELAY
                | {"bytes": 1, "solver_eof": True, "all_written": True, "error": None},
            },
            "success.relay",
        ),
        (
            {
                "proof_mode": "stream",
                "relay": RELAY
                | {"sha256": "0" * 64, "solver_eof": True, "all_written": True, "error": None},
            },
            "success.relay",
        ),
        ({"route": "unit", "solver": None, "proof_mode": "stream", "relay": None}, None),
    ],
)
def test_success_problem(fields: dict[str, Any], rule: str | None) -> None:
    assert success_problem(attempt(**fields)) == rule


def check_result(**fields: Any) -> dict[str, Any]:
    value = attempt()["checks"][0]
    value["result"] = value["result"] | fields
    return dict(value)


@pytest.mark.parametrize(
    "result",
    [
        {"exit": 1},
        {"exit": None, "signal": 9},
        {"signal": 9},  # not a valid process record; the success rule alone refuses it
        {"stdout_bytes": 18},
        {"stdout_truncated": True},
        {"stdout_tail": "s VERIFIED UNSAT"},
        {"stdout_tail": "s VERIFIED UNSAT\n\n", "stdout_bytes": 18},
    ],
)
def test_the_last_check_must_be_the_exact_success(result: dict[str, Any]) -> None:
    good = check_result()
    assert success_problem(attempt(checks=[check_result(**result), good])) is None
    assert success_problem(attempt(checks=[good, check_result(**result)])) == (
        "success.checker_output"
    )


@pytest.mark.parametrize(
    "solver",
    [
        {"started": False, "exit": None},
        {"exit": 10},
        {"exit": None, "signal": 15},
        {"signal": 15},  # exit 20 and a signal: not a valid process record, refused anyway
        {"started": False},  # exit 20 without a start: likewise
    ],
)
def test_a_cdcl_success_needs_solver_exit_20(solver: dict[str, Any]) -> None:
    value = attempt()
    value["solver"] = value["solver"] | solver
    assert success_problem(value) == "success.solver"


def machinery_value(**options: Any) -> Machinery:
    built: Machinery = Machinery.from_json(machinery(**options))
    return built


def test_admission_reason() -> None:
    admit = Admit((CHECKER,), (AdmittedSolver(SOLVER, ("--lrat",)),))
    assert admission_reason(admit, Machinery.from_json(MACHINERY)) is None
    assert admission_reason(admit, machinery_value(checker=OTHER_HASH)) == "checker_not_admitted"
    assert admission_reason(admit, machinery_value(solver_argv=["--lrat", "-q"])) == (
        "solver_not_admitted"
    )
    both = machinery_value(checker=OTHER_HASH, solver_argv=["-q", "--lrat"])
    assert admission_reason(admit, both) == "checker_not_admitted"
    open_solvers = Admit((CHECKER,), None)
    assert admission_reason(open_solvers, machinery_value(solver_argv=["--lrat", "-q"])) is None
    reordered = machinery_value(solver_argv=["--lrat"])
    assert admission_reason(
        Admit((CHECKER,), (AdmittedSolver(OTHER_HASH, ("--lrat",)),)), reordered
    ) == ("solver_not_admitted")


# -- the import closure ------------------------------------------------------------------------


def test_the_certifier_imports_no_tool_coordinator_or_producer_code() -> None:
    program = (
        "import json, sys\n"
        "import cubeproof.evidence.certify\n"
        "print(json.dumps(sorted(sys.modules)))\n"
    )
    env = dict(os.environ, PYTHONPATH=os.pathsep.join(p for p in sys.path if p))
    # -S: without the site hooks of the environment (an editable installation registers a
    # finder that itself imports threading); the package is found through PYTHONPATH.
    output = subprocess.run(
        [sys.executable, "-S", "-c", program], check=True, capture_output=True, text=True, env=env
    ).stdout
    modules = set(json.loads(output))
    own = {m for m in modules if m.startswith("cubeproof")}
    forbidden = {
        m
        for m in own
        if m.startswith(("cubeproof.tools", "cubeproof.coordinator", "cubeproof.leaf"))
        or m in {"cubeproof.cnf.unit", "cubeproof.base.process"}
    }
    assert forbidden == set()
    assert {"subprocess", "multiprocessing", "threading", "socket"} & modules == set()
