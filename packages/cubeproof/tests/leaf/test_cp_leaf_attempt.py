"""The transient file-mode leaf state machine with real processes (specification §6.1-§6.3, §8.1).

Every test runs whole attempts: the CNF is written and hashed, unit propagation decides the
route, the fake solver/checker run under the process supervisor and isolation wrappers, the
I/O service hashes, commits to a real journal and removes the work files. The committed
record is then checked against independent oracles: CNF(F, C) built plainly, the certifier's
success conditions, the journal's own validation (the writer refuses invalid records).
"""

from __future__ import annotations

import os
import signal
import stat
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from cp_leaf_support import (  # noqa: F401 - fixtures are registered by import
    SAT,
    TINY,
    TINY_PROOFS,
    TINY_PROOFS_ROOT,
    UNIT_MODEL,
    Bench,
    expected_cnf_sha256,
    fk,
    formula,
    isolation_fixture,
    make_policy,
    op_trace,
    p,
    sha,
    supervisor_fixture,
    wait_until,
)

from cubeproof.base.errors import ConfigurationError
from cubeproof.base.ids import new_id128
from cubeproof.cnf.cubecnf import CnfDigest, cube_cnf_bytes
from cubeproof.cnf.unit import build_index, refutation
from cubeproof.contracts.assignment import decode_assignment, encode_assignment
from cubeproof.contracts.enums import ProofMode
from cubeproof.contracts.identity import node_id
from cubeproof.contracts.io import Failure, Op, Result
from cubeproof.contracts.policy import HeapFit
from cubeproof.evidence.certify.admission import success_problem
from cubeproof.evidence.schema.rules import attempt_problem
from cubeproof.leaf.attempt import LeafAttempt, Phase
from cubeproof.leaf.binding import fitted_check_time_ms
from cubeproof.leaf.quarantine import QuarantineLedger
from cubeproof.tools.process import Supervisor

pytestmark = pytest.mark.skipif(
    os.uname().sysname != "Linux", reason="tool isolation is Linux-only (specification §6.2)"
)


@pytest.fixture
def make(tmp_path: Path, supervisor: Supervisor) -> Iterator[Any]:
    benches: list[Bench] = []

    def factory(**options: Any) -> Bench:
        bench = Bench(tmp_path / f"b{len(benches)}", supervisor, **options)
        benches.append(bench)
        return bench

    yield factory
    for bench in benches:
        bench.close()


def assert_clean(bench: Bench, attempt: LeafAttempt) -> None:
    """A finished attempt left no work file and no running process."""
    assert attempt.finished
    assert bench.work_files() == []
    assert bench.supervisor.active == []


def assert_valid(record: dict[str, Any], variables: int) -> None:
    assert attempt_problem(record, variables) is None
    assert record["node_id"] == node_id(record["node"]["formula_sha256"], record["node"]["cube"])


# -- unit route ------------------------------------------------------------------------------


def test_a_unit_conflict_is_checked_and_verified_without_a_solver(make: Any) -> None:
    bench = make()
    cube = (1,)
    attempt, record = bench.one(TINY, cube)
    proof = refutation(build_index(TINY), cube)
    assert proof is not None
    assert record["outcome"] == "VERIFIED_UNSAT" and record["route"] == "unit"
    assert record["solver"] is None and record["limits"]["solver_time_ms"] is None
    assert record["cnf_sha256"] == expected_cnf_sha256(TINY, cube)
    assert (record["proof_bytes"], record["proof_sha256"]) == (len(proof), sha(proof))
    assert len(record["checks"]) == 1
    assert success_problem(record) is None
    assert_valid(record, TINY.variables)
    assert bench.solver.calls() == []
    assert len(bench.checker.calls()) == 1
    argv = bench.checker.argv()
    assert argv[-2:] == [attempt.cnf_path, attempt.proof_path]
    assert attempt.phase is Phase.DONE and attempt.committed is not None
    assert_clean(bench, attempt)


def test_a_unit_proof_rejected_by_the_checker_is_check_rejected(make: Any) -> None:
    bench = make(checker=p.checker_reject())
    attempt, record = bench.one(TINY, (1,))
    assert (record["outcome"], record["reason"], record["route"]) == (
        "CHECK_REJECTED",
        "rejected",
        "unit",
    )
    assert record["quarantined"] is None
    assert record["diagnostics"]["quarantine_unavailable"] == "not_supported"
    assert_valid(record, TINY.variables)
    assert_clean(bench, attempt)


def test_a_complete_propagation_is_a_unit_model_without_any_tool(make: Any) -> None:
    bench = make()
    attempt, record = bench.one(UNIT_MODEL)
    assert (record["outcome"], record["route"], record["solver"]) == ("MODEL", "unit", None)
    assert record["assignment"] == encode_assignment([True, True])
    assert record["checks"] == [] and record["proof_sha256"] is None
    assert record["limits"]["check_time_ms"] == bench.policy.checker_time_base_ms
    assert bench.solver.calls() == [] and bench.checker.calls() == []
    assert_valid(record, UNIT_MODEL.variables)
    assert_clean(bench, attempt)


# -- CDCL route: UNSAT ------------------------------------------------------------------------


def test_a_solver_proof_is_sealed_checked_and_verified(make: Any) -> None:
    bench = make(solver=p.solver_unsat(TINY_PROOFS[0]))
    cube = (3,)
    attempt, record = bench.one(TINY, cube)
    assert (record["outcome"], record["route"]) == ("VERIFIED_UNSAT", "cdcl")
    assert record["solver"]["exit"] == 20 and record["solver"]["started"] is True
    assert record["limits"]["solver_time_ms"] == 60_000
    assert record["cnf_sha256"] == expected_cnf_sha256(TINY, cube)
    assert record["proof_sha256"] == sha(TINY_PROOFS[0])
    assert success_problem(record) is None
    assert_valid(record, TINY.variables)
    # one solver, one checker, both on this attempt's files
    assert len(bench.solver.calls()) == 1 and len(bench.checker.calls()) == 1
    assert bench.solver.argv()[-2:] == [attempt.cnf_path, attempt.proof_path]
    assert bench.checker.argv()[-2:] == [attempt.cnf_path, attempt.proof_path]
    assert_clean(bench, attempt)


def test_the_cnf_is_exactly_cnf_of_the_node_and_both_files_are_read_only(make: Any) -> None:
    observed: dict[str, Any] = {}
    bench = make(solver=p.solver_unsat(TINY_PROOFS[0]))
    attempt = bench.attempt(TINY, (3,))
    original = attempt.start_check

    def spy() -> None:
        observed["cnf"] = Path(attempt.cnf_path).read_bytes()
        observed["cnf_mode"] = stat.S_IMODE(os.stat(attempt.cnf_path).st_mode)
        observed["proof_mode"] = stat.S_IMODE(os.stat(attempt.proof_path).st_mode)
        original()

    attempt.start_check = spy
    bench.run(attempt)
    assert observed["cnf"] == cube_cnf_bytes(TINY, (3,))
    assert observed["cnf_mode"] & 0o222 == 0
    assert observed["proof_mode"] & 0o222 == 0


def test_the_job_order_hashes_everything_before_the_single_append(make: Any) -> None:
    """Seal hash, then the final CNF and proof hashes, then exactly one append, then cleanup:
    nothing is appended before the final inputs and verdict are established."""
    bench = make(solver=p.solver_unsat(TINY_PROOFS[0]))
    attempt, _ = bench.one(TINY, (3,))
    cnf = os.path.basename(attempt.cnf_path)
    proof = os.path.basename(attempt.proof_path)
    assert op_trace(bench.io, attempt.attempt_id) == [
        ("hash", proof),
        ("hash", cnf),
        ("hash", proof),
        ("append", "attempt"),
        ("remove", ",".join(sorted([cnf, proof]))),
    ]
    jobs = bench.io.jobs_of(attempt.attempt_id)
    append = next(j for j in jobs if j.op.value == "append")
    assert bench.io.open_at_submit[append.job_id] == frozenset()


def test_unit_route_job_order(make: Any) -> None:
    bench = make()
    attempt, _ = bench.one(TINY, (1,))
    cnf = os.path.basename(attempt.cnf_path)
    proof = os.path.basename(attempt.proof_path)
    assert [op for op, _ in op_trace(bench.io, attempt.attempt_id)] == [
        "hash",
        "hash",
        "hash",
        "append",
        "remove",
    ]
    assert op_trace(bench.io, attempt.attempt_id)[1:3] == [("hash", cnf), ("hash", proof)]


def test_a_deeper_cube_binds_its_node_its_units_and_its_depth(make: Any) -> None:
    """Three cube literals: CNF(F, C) has M+3 clauses with the units in canonical order, the
    node and node_id are those of the canonical cube, the solver time is the depth's."""
    f = formula(5, [(1, 2), (1, -2), (-1, 2), (-1, -2)])
    cube = (3, -4, 5)
    proof = b"8 1 0 1 2 0\n9 0 8 3 4 0\n"
    policy = make_policy(leaf_time_ms={"default": 60_000, "3": 45_000})
    bench = make(solver=p.solver_unsat(proof), policy=policy)
    attempt, record = bench.one(f, cube)
    assert record["outcome"] == "VERIFIED_UNSAT"
    assert record["node"] == {"formula_sha256": f.sha256, "cube": [3, -4, 5]}
    assert record["node_id"] == node_id(f.sha256, cube) == attempt.node_id
    assert record["cnf_sha256"] == expected_cnf_sha256(f, cube)
    assert cube_cnf_bytes(f, cube).endswith(b"3 0\n-4 0\n5 0\n")
    assert record["limits"]["solver_time_ms"] == 45_000
    assert_valid(record, f.variables)


def test_the_empty_cube_root(make: Any) -> None:
    bench = make(solver=p.solver_unsat(TINY_PROOFS_ROOT[1]))
    _, record = bench.one(TINY, ())
    assert record["outcome"] == "VERIFIED_UNSAT"
    assert record["cnf_sha256"] == sha(TINY.data)


# -- CDCL route: models -----------------------------------------------------------------------


def test_a_solver_model_is_evaluated_and_recorded(make: Any) -> None:
    bench = make(solver=p.solver_sat([1, -2, 3]))
    attempt, record = bench.one(SAT)
    assert (record["outcome"], record["reason"], record["route"]) == ("MODEL", None, "cdcl")
    assert record["solver"]["exit"] == 10
    assert decode_assignment(record["assignment"], 3) == (True, False, True)
    assert record["checks"] == [] and record["proof_bytes"] is None
    assert bench.checker.calls() == []
    assert_valid(record, SAT.variables)
    assert_clean(bench, attempt)


def test_a_brute_force_solver_model(make: Any) -> None:
    bench = make(solver=p.solver_brute_force())
    _, record = bench.one(SAT, (-1,))
    assert record["outcome"] == "MODEL"
    values = decode_assignment(record["assignment"], 3)
    assert values[0] is False and values[1] is True


@pytest.mark.parametrize(
    ("stdout", "error", "has_assignment"),
    [
        (b"s SATISFIABLE\nv 1 -2 3 0\n", "violated", True),  # the cube unit 2 is false
        (b"s SATISFIABLE\nv 1 x 0\n", "syntax", False),
        (b"s SATISFIABLE\nv 1 0\n", "missing", False),
        (b"s SATISFIABLE\nv 1 -1 2 -3 0\n", "conflicting", False),
        (b"s SATISFIABLE\nv 1 2 -3 4 0\n", "out_of_range", False),
        (b"v 1 2 -3 0\n", "syntax", False),
        (b"", "syntax", False),
    ],
)
def test_invalid_models_are_recorded_with_their_error(
    make: Any, stdout: bytes, error: str, has_assignment: bool
) -> None:
    bench = make(solver=p.solver_output(stdout, 10))
    attempt, record = bench.one(SAT, (2,))  # unit propagation leaves x1, x3 open
    assert (record["outcome"], record["reason"], record["model_error"]) == (
        "INVALID_MODEL",
        error,
        error,
    )
    assert (record["assignment"] is not None) is has_assignment
    assert record["checks"] == [] and record["proof_sha256"] is None
    assert_valid(record, SAT.variables)
    assert_clean(bench, attempt)


def test_an_overflowing_model_output_is_a_protocol_failure(make: Any) -> None:
    """A SAT exit whose stdout exceeds the model capture is an unrecognized state (TOOL_FAILED
    protocol), never a guessed or truncated model."""
    flood = [fk.write(fk.STDOUT, "c noise\n", size=48 << 20), *p.solver_sat([1, -2, 3])]
    bench = make(solver=flood)
    _, record = bench.one(SAT)
    assert (record["outcome"], record["reason"]) == ("TOOL_FAILED", "protocol")
    assert record["assignment"] is None and record["model_error"] is None
    assert record["solver"]["stdout_truncated"] is True
    assert record["diagnostics"]["model_output"] == "overflow"


# -- CDCL route: limits and failures ----------------------------------------------------------


def test_the_solver_deadline_is_exhausted_time(make: Any) -> None:
    bench = make(
        solver=p.solver_until_terminated(), policy=make_policy(leaf_time_ms={"default": 300})
    )
    attempt, record = bench.one(TINY, (3,))
    assert (record["outcome"], record["reason"]) == ("EXHAUSTED", "time")
    assert record["solver"]["cause"] == "deadline"
    assert record["proof_sha256"] is None and record["checks"] == []
    assert record["limits"]["solver_time_ms"] == 300
    assert bench.checker.calls() == []
    assert_clean(bench, attempt)


def test_the_depth_selects_the_solver_time(make: Any) -> None:
    policy = make_policy(leaf_time_ms={"default": 60_000, "1": 400})
    bench = make(solver=p.solver_until_terminated(), policy=policy)
    _, record = bench.one(TINY, (3,))
    assert record["limits"]["solver_time_ms"] == 400 and record["reason"] == "time"


@pytest.mark.parametrize("size", [1 << 20, 64 << 10])
def test_the_proof_cap_is_exhausted_proof_size(make: Any, size: int) -> None:
    bench = make(
        solver=p.solver_proof_flood(size, chunk=4096), policy=make_policy(proof_cap_bytes=16384)
    )
    attempt, record = bench.one(TINY, (3,))
    assert (record["outcome"], record["reason"]) == ("EXHAUSTED", "proof_size")
    assert record["proof_sha256"] is None and record["checks"] == []
    assert record["limits"]["proof_cap_bytes"] == 16384
    assert_clean(bench, attempt)


def test_the_solver_allocation_failure_is_solver_memory(make: Any) -> None:
    bench = make(solver=p.solver_out_of_memory())
    _, record = bench.one(TINY, (3,))
    assert (record["outcome"], record["reason"]) == ("EXHAUSTED", "solver_memory")
    assert record["solver"]["signal"] == int(signal.SIGABRT)


@pytest.mark.parametrize(
    ("steps", "reason"),
    [
        ([fk.kill_self("SEGV")], "crash"),
        ([fk.kill_self("KILL")], "crash"),
        (p.solver_output(b"s UNSATISFIABLE\n", 20), "protocol"),  # exit 20 without a proof
        (p.solver_output(b"", 0), "protocol"),
        (p.solver_output(b"s UNKNOWN\n", 1), "protocol"),
        (p.solver_partial_proof(TINY_PROOFS[0], 5, then=[fk.kill_self("SEGV")]), "crash"),
    ],
)
def test_solver_failures_are_tool_failed(make: Any, steps: list[Any], reason: str) -> None:
    bench = make(solver=steps)
    attempt, record = bench.one(TINY, (3,))
    assert (record["outcome"], record["reason"]) == ("TOOL_FAILED", reason)
    assert record["proof_sha256"] is None and record["checks"] == []
    assert bench.checker.calls() == []
    assert_valid(record, TINY.variables)
    assert_clean(bench, attempt)


def test_a_changed_solver_binary_is_not_launched(make: Any) -> None:
    bench = make(solver=p.solver_unsat(TINY_PROOFS[0]))
    with open(bench.solver.path, "a", encoding="utf-8") as handle:
        handle.write("\n# changed\n")
    _, record = bench.one(TINY, (3,))
    assert (record["outcome"], record["reason"]) == ("TOOL_FAILED", "binary_changed")
    assert record["solver"]["started"] is False
    assert bench.solver.calls() == []


def test_a_changed_checker_binary_is_not_launched(make: Any) -> None:
    bench = make(solver=p.solver_unsat(TINY_PROOFS[0]))
    with open(bench.checker.path, "a", encoding="utf-8") as handle:
        handle.write("\n# changed\n")
    _, record = bench.one(TINY, (3,))
    assert (record["outcome"], record["reason"]) == ("TOOL_FAILED", "binary_changed")
    assert record["checks"] == []  # no checker ran
    assert record["proof_sha256"] == sha(TINY_PROOFS[0])
    assert bench.checker.calls() == []
    # the proof reached the checker stage: the fitted check time, not the base value
    fitted = fitted_check_time_ms(bench.policy, len(TINY_PROOFS[0]))
    assert fitted != bench.policy.checker_time_base_ms
    assert record["limits"]["check_time_ms"] == fitted


def test_solver_output_pressure_is_drained_and_bounded(make: Any) -> None:
    flood = [
        fk.write(fk.STDOUT, "c progress\n", size=24 << 20, chunk=1 << 16),
        fk.write(fk.STDERR, "c warn\n", size=24 << 20, chunk=1 << 16),
        *p.solver_unsat(TINY_PROOFS[0]),
    ]
    bench = make(solver=flood)
    attempt, record = bench.one(TINY, (3,))
    assert record["outcome"] == "VERIFIED_UNSAT"
    solver = record["solver"]
    assert solver["stdout_truncated"] is True and solver["stdout_bytes"] > 24 << 20
    assert len(solver["stdout_tail"].encode()) <= 16384
    assert len(solver["stderr_tail"].encode()) <= 16384
    assert_clean(bench, attempt)


# -- the checker ----------------------------------------------------------------------------------


def test_checker_arena_exhaustion_retries_only_the_check(make: Any) -> None:
    bench = make(
        solver=p.solver_unsat(TINY_PROOFS[0]),
        checker_cases=[fk.case(p.checker_arena("heap"), invocation=0)],
    )
    attempt, record = bench.one(TINY, (3,))
    assert record["outcome"] == "VERIFIED_UNSAT"
    heap = bench.policy.heap_fit.min_mib
    stack = bench.policy.checker_stack_mib
    assert [(c["heap_mib"], c["stack_mib"]) for c in record["checks"]] == [
        (heap, stack),
        (heap * 2, stack),
    ]
    assert record["checks"][0]["result"]["exit"] == 1
    assert len(bench.solver.calls()) == 1  # the sealed proof is reused, never re-solved
    assert len(bench.checker.calls()) == 2
    assert record["limits"]["check_time_ms"] == fitted_check_time_ms(
        bench.policy, len(TINY_PROOFS[0])
    )
    assert success_problem(record) is None
    assert_clean(bench, attempt)


def test_an_arena_diagnostic_after_a_stderr_flood_is_retried_and_verified(make: Any) -> None:
    """The first check writes more stderr than the tail keeps, then the pinned heap
    diagnostic with its exit code. Specification §6.3 row 5 retries it (the diagnostic is in the
    tail); the binding takes the same earlier check, so the accepted retry is VERIFIED_UNSAT,
    not a TOOL_FAILED that would block the node on every retry."""
    first = [fk.write(fk.STDERR, "c noise\n", size=4 << 20), *p.checker_arena("heap")]
    bench = make(
        solver=p.solver_unsat(TINY_PROOFS[0]),
        checker_cases=[fk.case(first, invocation=0)],
    )
    attempt, record = bench.one(TINY, (3,))
    assert attempt._checks[0].run.stderr_truncated  # the scenario: stderr was cut
    assert (record["outcome"], record["reason"]) == ("VERIFIED_UNSAT", None)
    assert "binding" not in record["diagnostics"]
    heap, stack = bench.policy.heap_fit.min_mib, bench.policy.checker_stack_mib
    assert [(c["heap_mib"], c["stack_mib"]) for c in record["checks"]] == [
        (heap, stack),
        (heap * 2, stack),
    ]
    assert record["checks"][0]["result"]["exit"] == 1
    assert len(bench.solver.calls()) == 1 and len(bench.checker.calls()) == 2
    assert success_problem(record) is None
    assert_valid(record, TINY.variables)
    assert_clean(bench, attempt)


def test_both_arenas_double_together(make: Any) -> None:
    bench = make(
        solver=p.solver_unsat(TINY_PROOFS[0]),
        checker_cases=[
            fk.case(p.checker_arena("both"), invocation=0),
            fk.case(p.checker_arena("stack"), invocation=1),
        ],
    )
    _, record = bench.one(TINY, (3,))
    heap, stack = bench.policy.heap_fit.min_mib, bench.policy.checker_stack_mib
    assert [(c["heap_mib"], c["stack_mib"]) for c in record["checks"]] == [
        (heap, stack),
        (heap * 2, stack * 2),
        (heap * 2, stack * 4),
    ]
    assert record["outcome"] == "VERIFIED_UNSAT"


@pytest.mark.parametrize(
    ("kind", "policy", "reason"),
    [
        ("heap", {"checker_max_heap_mib": 512, "stream_heap_mib": 512}, "check_memory"),
        ("stack", {"checker_max_stack_mib": 256}, "check_stack"),
    ],
)
def test_an_arena_beyond_the_maximum_is_exhausted(
    make: Any, kind: str, policy: dict[str, Any], reason: str
) -> None:
    bench = make(
        solver=p.solver_unsat(TINY_PROOFS[0]),
        checker=p.checker_arena(kind),
        policy=make_policy(**policy),
    )
    attempt, record = bench.one(TINY, (3,))
    assert (record["outcome"], record["reason"]) == ("EXHAUSTED", reason)
    assert len(record["checks"]) == 1
    assert record["proof_sha256"] == sha(TINY_PROOFS[0])
    assert len(bench.checker.calls()) == 1
    assert_clean(bench, attempt)


def test_an_idle_machine_misfit_ends_the_ladder(make: Any) -> None:
    bench = make(solver=p.solver_unsat(TINY_PROOFS[0]), checker=p.checker_arena("heap"))
    asked: list[tuple[int, int]] = []

    def fits(heap: int, stack: int) -> bool:
        asked.append((heap, stack))
        return False

    _, record = bench.one(TINY, (3,), fits=fits)
    assert (record["outcome"], record["reason"]) == ("EXHAUSTED", "check_memory")
    assert asked == [(bench.policy.heap_fit.min_mib * 2, bench.policy.checker_stack_mib)]


def test_the_check_deadline_is_exhausted_check_time(make: Any) -> None:
    bench = make(
        solver=p.solver_unsat(TINY_PROOFS[0]),
        checker=[fk.sleep(60)],
        policy=make_policy(checker_time_base_ms=300, checker_time_per_100mb_ms=300),
    )
    attempt, record = bench.one(TINY, (3,))
    assert (record["outcome"], record["reason"]) == ("EXHAUSTED", "check_time")
    assert record["limits"]["check_time_ms"] == 300
    assert record["checks"][0]["result"]["cause"] == "deadline"
    assert_clean(bench, attempt)


@pytest.mark.parametrize("output", p.WRONG_SUCCESS_OUTPUTS)
def test_a_wrong_success_line_is_a_rejection_never_verified(make: Any, output: bytes) -> None:
    bench = make(solver=p.solver_unsat(TINY_PROOFS[0]), checker=p.checker_output(output, 0))
    _, record = bench.one(TINY, (3,))
    assert (record["outcome"], record["reason"]) == ("CHECK_REJECTED", "rejected")


@pytest.mark.parametrize(
    ("checker", "reason"),
    [
        (p.checker_output(p.CHECKER_SUCCESS, 1), "protocol"),
        (p.checker_output(b"", 7), "protocol"),
        (p.checker_crash("SEGV"), "crash"),
        (p.checker_crash("KILL"), "crash"),
        (p.checker_success_with_arena("heap"), "protocol"),
        (p.checker_flood(4 << 20), "protocol"),
        (p.checker_flood(4 << 20, to=fk.STDERR), "protocol"),
    ],
)
def test_checker_failures_are_never_verified(make: Any, checker: list[Any], reason: str) -> None:
    bench = make(solver=p.solver_unsat(TINY_PROOFS[0]), checker=checker)
    attempt, record = bench.one(TINY, (3,))
    assert (record["outcome"], record["reason"]) == ("TOOL_FAILED", reason)
    assert record["proof_sha256"] == sha(TINY_PROOFS[0])
    assert_valid(record, TINY.variables)
    assert_clean(bench, attempt)


def test_a_checker_rejecting_a_bad_solver_proof(make: Any) -> None:
    bench = make(solver=p.solver_unsat(b"6 0 1 2 0\n"))
    _, record = bench.one(TINY, (3,))
    assert (record["outcome"], record["reason"]) == ("CHECK_REJECTED", "rejected")


# -- file replacement ------------------------------------------------------------------------------


@pytest.mark.parametrize("target", ["cnf", "proof"])
@pytest.mark.parametrize("action", ["append", "flip", "replace", "truncate", "delete"])
@pytest.mark.parametrize("verdict", ["success", "rejection"])
def test_a_file_changed_by_the_checker_is_a_tool_failure_whatever_it_says(
    make: Any, target: str, action: str, verdict: str
) -> None:
    """Read-only modes are no protection (specification §5): the fake makes the file writable first.
    A changed file outranks both a success line and a rejection (specification §6.3 row 1); the
    attempt itself detects it at the re-hash (not only the binding's defence in depth)."""
    victim = fk.arg(-2) if target == "cnf" else fk.arg(-1)
    said = (
        [fk.write(fk.STDOUT, data=p.CHECKER_SUCCESS)]
        if verdict == "success"
        else [fk.write(fk.STDERR, "c Checking failed at line: 1. Reason: x\n")]
    )
    checker = [
        fk.read(fk.arg(-1)),
        fk.alter(victim, "chmod", mode=0o644),
        fk.alter(victim, action),
        *said,
        fk.exit_(0),
    ]
    bench = make(solver=p.solver_unsat(TINY_PROOFS[0]), checker=checker)
    attempt, record = bench.one(TINY, (3,))
    assert (record["outcome"], record["reason"]) == ("TOOL_FAILED", "file_changed")
    assert len(record["checks"]) == 1
    if verdict == "success":
        assert record["checks"][-1]["result"]["stdout_tail"] == "s VERIFIED UNSAT\n"
    diagnostics = record["diagnostics"]
    assert "binding" not in diagnostics
    seen = [
        n
        for n in diagnostics["notes"]
        if n == f"{target}:changed" or n.startswith(f"hash:{target}")
    ]
    assert seen, diagnostics["notes"]
    files = diagnostics["files"][target]
    first, final = ("written", "final") if target == "cnf" else ("sealed", "final")
    assert files[first] != files[final]
    assert record["cnf_sha256"] == expected_cnf_sha256(TINY, (3,))
    assert_clean(bench, attempt)


def test_a_cnf_changed_by_the_solver_is_detected_after_the_check(make: Any) -> None:
    solver = [
        fk.alter(fk.arg(-2), "chmod", mode=0o644),
        fk.alter(fk.arg(-2), "append"),
        *p.solver_unsat(TINY_PROOFS[0]),
    ]
    bench = make(solver=solver, checker=p.checker_accept())
    _, record = bench.one(TINY, (3,))
    assert (record["outcome"], record["reason"]) == ("TOOL_FAILED", "file_changed")


def changing_the_cnf(*then: Any) -> list[Any]:
    """Solver steps: make the CNF writable, append to it, then ``then``."""
    return [fk.alter(fk.arg(-2), "chmod", mode=0o644), fk.alter(fk.arg(-2), "append"), *then]


#: ``(name, solver steps that change the CNF, cube, policy changes)``: each would end in a
#: fixed outcome decided outside the specification §6.3 table (MODEL, INVALID_MODEL, model output
#: overflow, heap fit above the maximum) if the CNF had not changed.
CNF_CHANGED_BEFORE_A_FIXED_OUTCOME: list[tuple[str, list[Any], tuple[int, ...], dict[str, Any]]] = [
    ("model", changing_the_cnf(*p.solver_sat([1, -2, 3])), (), {}),
    (
        "invalid model",
        changing_the_cnf(*p.solver_output(b"s SATISFIABLE\nv 1 -2 3 0\n", 10)),
        (2,),
        {},
    ),
    (
        "model output overflow",
        changing_the_cnf(
            fk.write(fk.STDOUT, "c noise\n", size=48 << 20), *p.solver_sat([1, -2, 3])
        ),
        (),
        {},
    ),
    (
        "heap fit above the maximum",
        changing_the_cnf(*p.solver_unsat(TINY_PROOFS[0])),
        (3,),
        {
            "heap_fit": HeapFit(
                coefficient_milli=10**9, exponent_milli=1000, margin_milli=10**6, min_mib=512
            ),
            "checker_max_heap_mib": 512,
            "stream_heap_mib": 512,
        },
    ),
]


@pytest.mark.parametrize(
    ("name", "solver", "cube", "policy"),
    CNF_CHANGED_BEFORE_A_FIXED_OUTCOME,
    ids=[name for name, *_ in CNF_CHANGED_BEFORE_A_FIXED_OUTCOME],
)
def test_a_changed_cnf_outranks_every_fixed_outcome(
    make: Any, name: str, solver: list[Any], cube: tuple[int, ...], policy: dict[str, Any]
) -> None:
    """Specification §6.3 row 1 (file binding) precedes the model, the overflow and the heap
    fit; the attempt records TOOL_FAILED file_changed, no model. Without the CNF change these
    runs are MODEL/INVALID_MODEL/TOOL_FAILED protocol/EXHAUSTED (tests above)."""
    f = TINY if name == "heap fit above the maximum" else SAT
    bench = make(solver=solver, policy=make_policy(**policy))
    attempt, record = bench.one(f, cube)
    assert (record["outcome"], record["reason"]) == ("TOOL_FAILED", "file_changed"), name
    assert record["route"] == "cdcl"
    assert record["assignment"] is None and record["model_error"] is None
    assert record["checks"] == [] and bench.checker.calls() == []
    diagnostics = record["diagnostics"]
    assert "cnf:changed" in diagnostics["notes"]
    assert "model" not in diagnostics and "binding" not in diagnostics
    cnf = diagnostics["files"]["cnf"]
    assert cnf["written"] != cnf["final"]
    assert record["cnf_sha256"] == expected_cnf_sha256(f, cube)
    assert_valid(record, f.variables)
    assert_clean(bench, attempt)


def test_a_refused_verified_binding_is_recorded_as_tool_failed(
    make: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The table says VERIFIED_UNSAT, but ``bind_verified`` refuses (here its final
    success.* re-check of the built record): the attempt records TOOL_FAILED with the binding's
    reason and rule, never success and never a rejection (no false anomaly)."""
    from cubeproof.leaf import binding

    monkeypatch.setattr(binding, "_success_problem", lambda value: "success.relay")
    bench = make(solver=p.solver_unsat(TINY_PROOFS[0]))
    attempt, record = bench.one(TINY, (3,))
    assert (record["outcome"], record["reason"]) == ("TOOL_FAILED", "protocol")
    refusal = record["diagnostics"]["binding"]
    assert refusal["rule"] == "binding.success" and "success.relay" in refusal["detail"]
    assert "quarantine_unavailable" not in record["diagnostics"]
    assert len(record["checks"]) == 1
    assert record["checks"][0]["result"]["stdout_tail"] == "s VERIFIED UNSAT\n"
    assert record["proof_sha256"] == sha(TINY_PROOFS[0])
    assert record["limits"]["check_time_ms"] == fitted_check_time_ms(
        bench.policy, len(TINY_PROOFS[0])
    )
    assert_valid(record, TINY.variables)
    assert attempt.phase is Phase.DONE
    assert_clean(bench, attempt)


@pytest.mark.parametrize("reason", ["file_changed", "binary_changed", "protocol"])
def test_the_binding_refusal_reason_is_the_recorded_reason(
    make: Any, monkeypatch: pytest.MonkeyPatch, reason: str
) -> None:
    """The recorded reason is the refusal's own, its detail bounded."""
    from cubeproof.leaf import attempt as module
    from cubeproof.leaf.binding import BindingError

    def refuse(*args: Any, **kwargs: Any) -> Any:
        raise BindingError(reason, "binding.injected", "x" * 1000)

    monkeypatch.setattr(module, "bind_verified", refuse)
    bench = make()
    attempt, record = bench.one(TINY, (1,))  # route unit
    assert (record["outcome"], record["reason"], record["route"]) == ("TOOL_FAILED", reason, "unit")
    refusal = record["diagnostics"]["binding"]
    assert refusal["rule"] == "binding.injected"
    assert refusal["detail"] == "x" * 297 + "..."
    assert_valid(record, TINY.variables)
    assert_clean(bench, attempt)


def test_a_wrong_cnf_header_is_caught_before_any_tool(
    make: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    from cubeproof.leaf import files

    def header(variables: int, clauses: int, depth: int) -> bytes:
        return f"p cnf {variables} {clauses}\n".encode()  # M instead of M+d

    monkeypatch.setattr(files, "cube_cnf_header", header)
    bench = make(solver=p.solver_unsat(TINY_PROOFS[0]))
    attempt, record = bench.one(TINY, (3,))
    assert (record["outcome"], record["reason"]) == ("TOOL_FAILED", "file_changed")
    assert record["cnf_sha256"] == expected_cnf_sha256(TINY, (3,))
    assert bench.solver.calls() == [] and bench.checker.calls() == []
    assert_clean(bench, attempt)


# -- identity, concurrency, modes ------------------------------------------------------------


def test_concurrent_attempts_of_one_node_bind_their_own_files(make: Any) -> None:
    bench = make(
        solver_cases=[
            fk.case(p.solver_unsat(TINY_PROOFS[0]), invocation=0),
            fk.case(p.solver_unsat(TINY_PROOFS[1]), invocation=1),
        ],
    )
    first, second = bench.attempt(TINY, (3,)), bench.attempt(TINY, (3,))
    assert first.attempt_id != second.attempt_id
    assert first.cnf_path != second.cnf_path and first.proof_path != second.proof_path
    bench.run(first, second)
    records = {r["attempt_id"]: r for r in bench.io.attempts()}
    assert set(records) == {first.attempt_id, second.attempt_id}
    proofs = {records[a.attempt_id]["proof_sha256"] for a in (first, second)}
    assert proofs == {sha(TINY_PROOFS[0]), sha(TINY_PROOFS[1])}
    for call in bench.checker.calls():
        cnf, proof = call["argv"][-2:]
        assert cnf.rsplit("-", 1)[1][:32] == proof.rsplit("-", 1)[1][:32]
    assert all(r["outcome"] == "VERIFIED_UNSAT" for r in records.values())
    assert bench.work_files() == []


def test_attempt_ids_are_fresh(make: Any) -> None:
    bench = make()
    ids = {bench.attempt(TINY, (1,)).attempt_id for _ in range(50)}
    assert len(ids) == 50


def test_a_stream_attempt_without_the_relay_interpreter_is_refused_up_front(make: Any) -> None:
    """The stream mode is a mode of this leaf (tests/stream/test_cp_stream_leaf.py);
    an attempt that could not run its relay is refused before any file exists."""
    bench = make()
    assert bench.tools.python is None
    with pytest.raises(ConfigurationError) as caught:
        bench.attempt(TINY, (1,), policy=bench.policy.with_proof_mode(ProofMode.STREAM))
    assert caught.value.rule == "leaf.relay_interpreter"
    assert bench.work_files() == []


def test_the_digest_must_belong_to_the_formula(make: Any) -> None:
    bench = make()
    with pytest.raises(ValueError):
        LeafAttempt(
            formula=TINY,
            digest=CnfDigest(SAT),
            cube=(1,),
            policy=bench.policy,
            work_dir=str(bench.work),
            tools=bench.tools,
            supervisor=bench.supervisor,
            io=bench.io,
        )


def test_an_existing_file_at_the_attempt_path_is_never_used(make: Any) -> None:
    bench = make(solver=p.solver_unsat(TINY_PROOFS[0]))
    attempt = bench.attempt(TINY, (3,), attempt_id="ab" * 16)
    Path(attempt.proof_path).write_bytes(TINY_PROOFS[1])
    bench.run(attempt)
    (record,) = bench.io.attempts()
    assert (record["outcome"], record["reason"]) == ("TOOL_FAILED", "io")
    assert bench.solver.calls() == []
    # a file this attempt did not create is not removed by it
    assert Path(attempt.proof_path).read_bytes() == TINY_PROOFS[1]


# -- cancellation ------------------------------------------------------------------------------


def test_cancelling_a_running_solve_records_nothing_and_cleans_up(
    make: Any, tmp_path: Path
) -> None:
    ready = tmp_path / "solver-ready"
    bench = make(solver=p.solver_until_terminated(ready=str(ready)))
    attempt = bench.attempt(TINY, (3,))

    def cancel_when_ready() -> None:
        if ready.exists() and not attempt.cancelled:
            attempt.cancel()

    bench.run(attempt, on_tick=cancel_when_ready)
    assert attempt.phase is Phase.ABANDONED and attempt.abandoned == "cancelled"
    assert bench.io.attempts() == []
    assert_clean(bench, attempt)


def test_a_user_stop_of_the_supervisor_records_nothing(make: Any, tmp_path: Path) -> None:
    ready = tmp_path / "solver-ready"
    bench = make(solver=p.solver_until_terminated(ready=str(ready)))
    attempt = bench.attempt(TINY, (3,))

    def stop_when_ready() -> None:
        if ready.exists() and not bench.supervisor.stopping:
            bench.supervisor.stop(200)

    bench.run(attempt, on_tick=stop_when_ready)
    assert attempt.abandoned == "cancelled"
    assert bench.io.attempts() == []
    assert bench.work_files() == []


def test_cancelling_during_the_check_records_nothing(make: Any, tmp_path: Path) -> None:
    ready = tmp_path / "checker-ready"
    bench = make(
        solver=p.solver_unsat(TINY_PROOFS[0]),
        checker=[fk.touch(str(ready)), fk.sleep(60)],
    )
    attempt = bench.attempt(TINY, (3,))

    def cancel_when_ready() -> None:
        if ready.exists() and not attempt.cancelled:
            attempt.cancel()

    bench.run(attempt, on_tick=cancel_when_ready)
    assert attempt.abandoned == "cancelled"
    assert bench.io.attempts() == []
    assert_clean(bench, attempt)


def test_a_cancellation_during_the_final_hashes_records_nothing(make: Any) -> None:
    """Cancelled before the append: the measurements that still arrive decide nothing."""
    bench = make(solver=p.solver_unsat(TINY_PROOFS[0]))
    attempt = bench.attempt(TINY, (3,))

    def cancel_at_the_final_cnf_hash(job: Any) -> None:
        request = job.request
        if getattr(request, "path", None) == attempt.cnf_path:
            attempt.cancel()

    bench.io.before_run.append(cancel_at_the_final_cnf_hash)
    bench.run(attempt)
    assert attempt.phase is Phase.ABANDONED and attempt.abandoned == "cancelled"
    assert bench.io.attempts() == []
    assert not any(job.op.value == "append" for job in bench.io.jobs)
    assert_clean(bench, attempt)


def test_a_cancellation_after_the_commit_was_submitted_keeps_the_record(make: Any) -> None:
    bench = make(solver=p.solver_unsat(TINY_PROOFS[0]))
    attempt = bench.attempt(TINY, (3,))

    def cancel_at_append(job: Any) -> None:
        if job.op.value == "append":
            attempt.cancel()

    bench.io.before_run.append(cancel_at_append)
    bench.run(attempt)
    assert attempt.phase is Phase.DONE and attempt.committed is not None
    assert [r["outcome"] for r in bench.io.attempts()] == ["VERIFIED_UNSAT"]
    assert_clean(bench, attempt)


# -- cancellation during SOLVE: the solver's proof file ----------------------------------------
#
# CaDiCaL creates its proof file when it starts, long before it exits. A cancelled solve never
# delivers a solver result to the attempt, yet the file at the attempt's proof path is this
# attempt's (PREPARE proved the name free, the path carries the fresh attempt ID): specification
# §6.1 step 7 and §7.5 row 1 make it disposable work that the attempt removes itself, not
# something left for the next startup's reconciliation.


def solver_proof_at_start(ready: Path, *, ignore_term: bool = False) -> list[Any]:
    """Create the proof file first (as CaDiCaL does), signal ``ready``, run until stopped."""
    wait = p.solver_ignoring_term if ignore_term else p.solver_until_terminated
    return [fk.write(fk.arg(-1), data=TINY_PROOFS[0][:6]), *wait(ready=str(ready))]


def phase_of(attempt: LeafAttempt) -> Phase:
    """The phase read afresh (mypy keeps a narrowed ``attempt.phase`` across calls)."""
    return attempt.phase


@pytest.mark.parametrize(
    ("ignore_term", "grace_ms"),
    [(False, None), (False, 1), (True, 50)],
    ids=["stop-grace", "shutdown-grace", "term-ignored-killed"],
)
def test_cancelling_a_solve_removes_the_proof_file_the_solver_created(
    make: Any, tmp_path: Path, ignore_term: bool, grace_ms: int | None
) -> None:
    """External cancellation in SOLVE (a run's drain/shutdown, coordinator/run.py)."""
    ready = tmp_path / "solver-ready"
    bench = make(solver=solver_proof_at_start(ready, ignore_term=ignore_term))
    attempt = bench.attempt(TINY, (3,))
    at_cancel: list[list[str]] = []

    def cancel_when_ready() -> None:
        if ready.exists() and not attempt.cancelled:
            assert attempt.phase is Phase.SOLVE
            at_cancel.append(bench.work_files())
            attempt.cancel(grace_ms)

    bench.run(attempt, on_tick=cancel_when_ready)
    assert os.path.basename(attempt.proof_path) in at_cancel[0]  # the premise of the test
    assert attempt.phase is Phase.ABANDONED and attempt.abandoned == "cancelled"
    assert bench.io.attempts() == []
    assert_clean(bench, attempt)


def test_a_supervisor_stop_during_the_solve_removes_the_proof_file(
    make: Any, tmp_path: Path
) -> None:
    """The attempt cancels itself: the supervisor's stop ends the solver, the attempt sees a
    deliberately cancelled run (no record) and cleans up."""
    ready = tmp_path / "solver-ready"
    bench = make(solver=solver_proof_at_start(ready))
    attempt = bench.attempt(TINY, (3,))

    def stop_when_ready() -> None:
        if ready.exists() and not bench.supervisor.stopping:
            assert os.path.exists(attempt.proof_path)
            bench.supervisor.stop(200)

    bench.run(attempt, on_tick=stop_when_ready)
    assert attempt.cancelled and attempt.abandoned == "cancelled"
    assert bench.io.attempts() == []
    assert_clean(bench, attempt)


def test_a_cancellation_after_the_solver_exited_but_before_its_result_was_taken(
    make: Any,
) -> None:
    """The solver exited 20 with its proof; the attempt is cancelled before it advanced."""
    bench = make(solver=p.solver_unsat(TINY_PROOFS[0]))
    attempt = bench.attempt(TINY, (3,))
    while not (attempt.phase is Phase.SOLVE and attempt.processes):
        attempt.advance()
        for job, result in bench.io.poll():
            attempt.deliver(job, result)

    def solver_reaped() -> bool:
        bench.supervisor.step(5)
        return not attempt.processes

    wait_until(solver_reaped)
    assert attempt.phase is Phase.SOLVE
    assert Path(attempt.proof_path).read_bytes() == TINY_PROOFS[0]
    attempt.cancel()
    bench.run(attempt)
    assert phase_of(attempt) is Phase.ABANDONED and attempt.abandoned == "cancelled"
    assert bench.io.attempts() == []
    assert_clean(bench, attempt)


def test_a_proof_file_created_after_the_cancellation_is_removed(make: Any, tmp_path: Path) -> None:
    """The solver opens its proof only while handling TERM, i.e. after ``cancel()``: the
    attempt looks for its proof file once the solver has ended, not when it is cancelled."""
    ready, written = tmp_path / "solver-ready", tmp_path / "proof-written-on-term"
    on_term = [fk.write(fk.arg(-1), data=TINY_PROOFS[0][:6]), fk.touch(str(written))]
    bench = make(
        solver=[
            fk.trap("TERM", on_term, then="die"),
            fk.touch(str(ready)),
            fk.sleep(60.0),
        ]
    )
    attempt = bench.attempt(TINY, (3,))
    at_cancel: list[bool] = []

    def cancel_when_ready() -> None:
        if ready.exists() and not attempt.cancelled:
            assert attempt.phase is Phase.SOLVE
            at_cancel.append(os.path.lexists(attempt.proof_path))
            attempt.cancel()

    bench.run(attempt, on_tick=cancel_when_ready)
    # The premise: no proof file when cancel() ran; the TERM handler then wrote it.
    assert at_cancel == [False] and written.exists()
    assert phase_of(attempt) is Phase.ABANDONED and attempt.abandoned == "cancelled"
    assert bench.io.attempts() == []
    assert_clean(bench, attempt)


def test_an_unneeded_attempt_cancelled_in_run_removes_its_proof_file(
    make: Any, tmp_path: Path
) -> None:
    """In-run cancellation (specification §6.5, §7.4: a closed node cancels the attempts it makes
    unnecessary): the cancelled attempt's files are gone when it finishes, while the run goes on,
    not at a later stop or startup; the other attempts are not affected."""
    unneeded_id, other_id = new_id128(), new_id128()
    unneeded_ready, other_ready = tmp_path / "unneeded-ready", tmp_path / "other-ready"
    bench = make(
        solver=p.solver_unsat(TINY_PROOFS[0]),
        solver_cases=[
            fk.case(solver_proof_at_start(unneeded_ready), argv_contains=unneeded_id),
            fk.case(p.solver_until_terminated(ready=str(other_ready)), argv_contains=other_id),
        ],
    )
    closing = bench.attempt(TINY, (3,))
    unneeded = bench.attempt(TINY, (-3,), attempt_id=unneeded_id)
    other = bench.attempt(TINY, (3,), attempt_id=other_id)
    in_run: list[list[str]] = []

    def tick() -> None:
        if closing.phase is Phase.DONE and unneeded_ready.exists() and not unneeded.cancelled:
            assert unneeded.phase is Phase.SOLVE and os.path.exists(unneeded.proof_path)
            unneeded.cancel()
        if unneeded.finished and other_ready.exists() and not other.cancelled:
            assert not bench.supervisor.stopping and other.phase is Phase.SOLVE
            in_run.append(bench.work_files())
            other.cancel()

    bench.run(closing, unneeded, other, on_tick=tick)
    assert unneeded.abandoned == "cancelled" and other.abandoned == "cancelled"
    names = {os.path.basename(path) for path in (unneeded.cnf_path, unneeded.proof_path)}
    assert in_run and not names & set(in_run[0])
    assert os.path.basename(other.cnf_path) in in_run[0]  # the run was still going on
    assert [(r["attempt_id"], r["outcome"]) for r in bench.io.attempts()] == [
        (closing.attempt_id, "VERIFIED_UNSAT")
    ]
    assert_clean(bench, unneeded)


# -- nonblocking ------------------------------------------------------------------------------


def test_advance_never_waits_for_a_running_tool(make: Any, tmp_path: Path) -> None:
    import time

    ready = tmp_path / "ready"
    bench = make(solver=p.solver_until_terminated(ready=str(ready)))
    attempt = bench.attempt(TINY, (3,))
    while attempt.phase is not Phase.SOLVE:
        attempt.advance()
        for job, result in bench.io.poll():
            attempt.deliver(job, result)
    wait_until(ready.exists)
    for _ in range(20):
        start = time.monotonic()
        attempt.advance(slice_ms=10)
        assert time.monotonic() - start < 0.5
        assert attempt.phase is Phase.SOLVE
    attempt.cancel()
    bench.run(attempt)
    assert attempt.abandoned == "cancelled"


def test_a_large_cnf_is_written_in_bounded_slices(make: Any) -> None:
    """With a clock that moves 1 ms per reading, one 1 ms slice writes about one chunk."""
    clauses = [(i, -(i + 1), i + 2) for i in range(1, 60_000)]
    big = formula(60_002, clauses)
    size = len(cube_cnf_bytes(big, (1,)))
    now = [0]

    def clock() -> int:
        now[0] += 1_000_000
        return now[0]

    bench = make(solver=p.solver_sat([]))
    attempt = bench.attempt(big, (1,), cnf_chunk=4096, clock=clock)
    slices = 0
    while attempt.phase is Phase.PREPARE:
        attempt.advance(slice_ms=1)
        slices += 1
    assert slices >= size // (2 * 4096)
    assert Path(attempt.cnf_path).read_bytes() == cube_cnf_bytes(big, (1,))
    attempt.cancel()
    bench.run(attempt)
    assert attempt.abandoned == "cancelled"
    assert bench.work_files() == []


def test_a_fitted_heap_above_the_maximum_is_not_checked(make: Any) -> None:
    """Specification §8.3: the startup cap clamp prevents this; if it happens anyway the attempt is
    EXHAUSTED check_memory without starting the checker."""
    policy = make_policy(
        heap_fit=HeapFit(
            coefficient_milli=10**9, exponent_milli=1000, margin_milli=10**6, min_mib=512
        ),
        checker_max_heap_mib=512,
        stream_heap_mib=512,
    )
    bench = make(solver=p.solver_unsat(TINY_PROOFS[0]), policy=policy)
    _, record = bench.one(TINY, (3,))
    assert (record["outcome"], record["reason"]) == ("EXHAUSTED", "check_memory")
    assert record["checks"] == [] and bench.checker.calls() == []
    assert record["limits"]["check_time_ms"] == policy.checker_time_base_ms
    assert record["diagnostics"]["initial_heap_mib"] > 512


# -- retain and quarantine (specification §6.1 steps 6-7, §7.2, §4.8) ---------------------------
#
# Retain: a VERIFIED_UNSAT proof is published durably (the I/O service's single publication)
# **before** its record is appended, and the record binds exactly that artifact. A publication
# that does not complete commits nothing (a VERIFIED_UNSAT without ``retained`` would be a silent
# downgrade).
# Quarantine: a CHECK_REJECTED proof is published under the quota before the record; any miss
# records ``quarantined: null`` plus the reason, and the record is committed in every case.

RETAIN = make_policy(proof_mode=ProofMode.RETAIN)


def published_files(bench: Bench, area: str) -> dict[str, bytes]:
    """The final files below ``results/<area>`` (staging excluded)."""
    folder = bench.results / area
    if not folder.exists():
        return {}
    return {p.name: p.read_bytes() for p in folder.iterdir() if p.is_file()}


def staging_files(bench: Bench) -> list[str]:
    found: list[str] = []
    for area in ("proofs", "quarantine"):
        folder = bench.results / area / "tmp"
        if folder.exists():
            found += sorted(p.name for p in folder.iterdir())
    return found


def publish_failure(kind: str, rule: str) -> Any:
    """Fail every publication with a typed, non-fatal failure (no byte was published)."""

    def fault(job: Any) -> Any:
        if job.op is not Op.PUBLISH:
            return None
        return Result(job.job_id, job.op, job.attempt_id, Failure(kind, rule, "injected", False))

    return fault


def drive_to_publish(bench: Bench, attempt: LeafAttempt) -> None:
    """Run a gated attempt until it asks for its publication grant."""
    for _ in range(4000):
        if attempt.wants_publish:
            return
        attempt.advance()
        if attempt.wants_check:
            attempt.start_check()
        bench.supervisor.step(5)
        for job, result in bench.io.poll():
            attempt.deliver(job, result)
    raise AssertionError(f"no publication requested: {attempt.phase}")


@pytest.mark.parametrize("route", ["cdcl", "unit"])
def test_a_retained_proof_is_published_before_its_record_and_bound_to_it(
    make: Any, route: str
) -> None:
    solver = p.solver_unsat(TINY_PROOFS[0]) if route == "cdcl" else p.solver_brute_force()
    bench = make(solver=solver, policy=RETAIN)
    cube = (3,) if route == "cdcl" else (1,)
    attempt, record = bench.one(TINY, cube)
    assert (record["outcome"], record["route"], record["proof_mode"]) == (
        "VERIFIED_UNSAT",
        route,
        "retain",
    )
    name = f"{attempt.node_id}-{record['proof_sha256']}.lrat"
    assert record["retained"] == {
        "path": f"proofs/{name}",
        "sha256": record["proof_sha256"],
        "bytes": record["proof_bytes"],
    }
    files = published_files(bench, "proofs")
    assert list(files) == [name] and sha(files[name]) == record["proof_sha256"]
    assert staging_files(bench) == []
    assert success_problem(record) is None
    assert_valid(record, TINY.variables)
    assert attempt.published is not None and attempt.published.artifact.path == f"proofs/{name}"
    assert attempt.phase is Phase.DONE
    assert_clean(bench, attempt)


def test_the_retained_publication_precedes_the_append_which_waits_for_its_answer(
    make: Any,
) -> None:
    """Kills "append before publish": the order is hash, hashes, publish, append, remove, and
    the publication had its answer when the single append was submitted (specification §6.1
    step 6)."""
    bench = make(solver=p.solver_unsat(TINY_PROOFS[0]), policy=RETAIN)
    attempt, _ = bench.one(TINY, (3,))
    cnf = os.path.basename(attempt.cnf_path)
    proof = os.path.basename(attempt.proof_path)
    assert op_trace(bench.io, attempt.attempt_id) == [
        ("hash", proof),
        ("hash", cnf),
        ("hash", proof),
        ("publish", ""),
        ("append", "attempt"),
        ("remove", ",".join(sorted([cnf, proof]))),
    ]
    jobs = bench.io.jobs_of(attempt.attempt_id)
    append = next(j for j in jobs if j.op.value == "append")
    publish = next(j for j in jobs if j.op.value == "publish")
    assert bench.io.open_at_submit[append.job_id] == frozenset()
    assert publish.job_id < append.job_id
    assert publish.request.source == attempt.proof_path
    assert publish.request.proof_sha256 == sha(TINY_PROOFS[0])


@pytest.mark.parametrize(
    ("kind", "rule", "exit_code"),
    [
        ("resource", "io.no_space", 1),
        ("integrity", "artifact.conflict", 4),
        ("tool", "io.source_changed", 5),
    ],
)
def test_a_failed_retained_publication_commits_no_record(
    make: Any, kind: str, rule: str, exit_code: int
) -> None:
    """Kills "retain failure commits VERIFIED_UNSAT with retained: null": no record at all, the
    attempt reports the block (the run stops new work with it), the work files are removed."""
    bench = make(solver=p.solver_unsat(TINY_PROOFS[0]), policy=RETAIN)
    bench.io.faults.append(publish_failure(kind, rule))
    attempt = bench.attempt(TINY, (3,))
    bench.run(attempt)
    assert attempt.phase is Phase.ABANDONED and attempt.abandoned == "retain_blocked"
    assert bench.io.attempts() == []
    assert not any(job.op.value == "append" for job in bench.io.jobs)
    blocked = attempt.retain_blocked
    assert blocked is not None
    assert (blocked.kind, blocked.rule, blocked.exit_code) == (kind, rule, exit_code)
    assert attempt.published is None and attempt.committed is None
    assert published_files(bench, "proofs") == {}
    assert_clean(bench, attempt)


def test_a_gated_publication_waits_for_its_reservation(make: Any) -> None:
    """With ``publish_gate`` the coordinator grants the publication (its disk reservation,
    specification §7.2 step 1); nothing is published or appended before the grant."""
    bench = make(solver=p.solver_unsat(TINY_PROOFS[0]), policy=RETAIN)
    attempt = bench.attempt(TINY, (3,), publish_gate=True)
    drive_to_publish(bench, attempt)
    assert attempt.phase is Phase.PUBLISH
    request = attempt.publish_request
    assert request is not None and request.proof_bytes == len(TINY_PROOFS[0])
    for _ in range(5):
        attempt.advance()
        assert bench.io.poll() == []
    assert attempt.wants_publish
    assert not any(job.op.value in ("publish", "append") for job in bench.io.jobs)
    attempt.start_publish()
    assert not attempt.wants_publish
    bench.run(attempt)
    (record,) = bench.io.attempts()
    assert record["outcome"] == "VERIFIED_UNSAT" and record["retained"] is not None
    assert_clean(bench, attempt)


def test_a_refused_retained_reservation_is_retain_full_without_a_record(make: Any) -> None:
    bench = make(solver=p.solver_unsat(TINY_PROOFS[0]), policy=RETAIN)
    attempt = bench.attempt(TINY, (3,), publish_gate=True)
    drive_to_publish(bench, attempt)
    attempt.refuse_publish("disk:results: need 25, available 0")
    bench.run(attempt)
    assert attempt.abandoned == "retain_blocked" and bench.io.attempts() == []
    blocked = attempt.retain_blocked
    assert blocked is not None
    assert (blocked.kind, blocked.rule, blocked.exit_code) == ("resource", "retain.full", 1)
    assert "need 25" in blocked.detail
    assert not any(job.op.value in ("publish", "append") for job in bench.io.jobs)
    assert_clean(bench, attempt)


def test_a_cancellation_while_the_publication_waits_records_nothing(make: Any) -> None:
    bench = make(solver=p.solver_unsat(TINY_PROOFS[0]), policy=RETAIN)
    attempt = bench.attempt(TINY, (3,), publish_gate=True)
    drive_to_publish(bench, attempt)
    attempt.cancel()
    bench.run(attempt)
    assert attempt.abandoned == "cancelled" and bench.io.attempts() == []
    assert not any(job.op.value in ("publish", "append") for job in bench.io.jobs)
    assert_clean(bench, attempt)


def test_a_cancellation_during_the_publication_waits_for_it_and_records_nothing(
    make: Any,
) -> None:
    """Cancelled while the copy runs: its source is not removed before the answer, then
    nothing is appended; the published copy is an orphan of the next startup (specification §7.5
    row 2)."""
    bench = make(solver=p.solver_unsat(TINY_PROOFS[0]), policy=RETAIN)
    attempt = bench.attempt(TINY, (3,))

    def cancel_at_publish(job: Any) -> None:
        if job.op.value == "publish":
            attempt.cancel()

    bench.io.before_run.append(cancel_at_publish)
    bench.run(attempt)
    assert attempt.abandoned == "cancelled" and bench.io.attempts() == []
    assert not any(job.op.value == "append" for job in bench.io.jobs)
    trace = [op for op, _ in op_trace(bench.io, attempt.attempt_id)]
    assert trace.index("publish") < trace.index("remove")
    assert_clean(bench, attempt)


def test_a_cancelled_attempt_keeps_its_source_while_the_publication_is_unanswered(
    make: Any,
) -> None:
    """The copy reads the sealed proof: a cancellation does not submit the removal of the work
    files before the publication's answer has arrived (specification §7.2 steps 1 and 5)."""
    bench = make(solver=p.solver_unsat(TINY_PROOFS[0]), policy=RETAIN)
    attempt = bench.attempt(TINY, (3,), publish_gate=True)
    drive_to_publish(bench, attempt)
    attempt.start_publish()
    attempt.cancel()
    for _ in range(5):
        attempt.advance()
        bench.supervisor.step(1)
    assert [job.op.value for job in bench.io.queue] == ["publish"]
    assert not any(job.op.value in ("remove", "append") for job in bench.io.jobs)
    assert os.path.exists(attempt.proof_path)
    bench.run(attempt)
    assert attempt.abandoned == "cancelled" and bench.io.attempts() == []
    trace = [op for op, _ in op_trace(bench.io, attempt.attempt_id)]
    assert trace.index("publish") < trace.index("remove")
    assert_clean(bench, attempt)


def test_a_refused_retain_binding_publishes_nothing(
    make: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The evidence is judged before the publication: a refusal is TOOL_FAILED, no copy."""
    from cubeproof.leaf import attempt as module
    from cubeproof.leaf.binding import BindingError

    def refuse(*args: Any, **kwargs: Any) -> Any:
        raise BindingError("file_changed", "binding.injected", "refused")

    monkeypatch.setattr(module, "check_verified", refuse)
    bench = make(solver=p.solver_unsat(TINY_PROOFS[0]), policy=RETAIN)
    attempt, record = bench.one(TINY, (3,))
    assert (record["outcome"], record["reason"]) == ("TOOL_FAILED", "file_changed")
    assert record["retained"] is None and record["proof_mode"] == "retain"
    assert record["diagnostics"]["binding"]["rule"] == "binding.injected"
    assert not any(job.op.value == "publish" for job in bench.io.jobs)
    assert published_files(bench, "proofs") == {}
    assert_clean(bench, attempt)


def test_a_transient_verified_proof_is_never_published(make: Any) -> None:
    bench = make(solver=p.solver_unsat(TINY_PROOFS[0]))
    _, record = bench.one(TINY, (3,))
    assert record["retained"] is None and record["proof_mode"] == "transient"
    assert not any(job.op.value == "publish" for job in bench.io.jobs)


def test_an_existing_equal_retained_artifact_is_reused(make: Any) -> None:
    bench = make(solver=p.solver_unsat(TINY_PROOFS[0]), policy=RETAIN)
    first, one = bench.one(TINY, (3,))
    second, two = bench.one(TINY, (3,))
    assert one["retained"] == two["retained"]
    assert first.published is not None and not first.published.reused
    assert second.published is not None and second.published.reused
    assert len(published_files(bench, "proofs")) == 1


@pytest.mark.parametrize("mode", [ProofMode.TRANSIENT, ProofMode.RETAIN])
def test_a_rejected_proof_is_quarantined_before_its_record(make: Any, mode: ProofMode) -> None:
    policy = make_policy(proof_mode=mode)
    bench = make(solver=p.solver_unsat(TINY_PROOFS[0]), checker=p.checker_reject(), policy=policy)
    ledger = QuarantineLedger(1 << 20)
    attempt, record = bench.one(TINY, (3,), quarantine=ledger)
    assert record["outcome"] == "CHECK_REJECTED" and record["retained"] is None
    name = f"{attempt.node_id}-{sha(TINY_PROOFS[0])}.lrat"
    assert record["quarantined"] == {
        "path": f"quarantine/{name}",
        "sha256": sha(TINY_PROOFS[0]),
        "bytes": len(TINY_PROOFS[0]),
    }
    assert "quarantine_unavailable" not in record["diagnostics"]
    assert published_files(bench, "quarantine") == {name: TINY_PROOFS[0]}
    trace = [op for op, _ in op_trace(bench.io, attempt.attempt_id)]
    assert trace == ["hash", "hash", "hash", "publish", "append", "remove"]
    assert ledger.committed_bytes == len(TINY_PROOFS[0])
    assert ledger.pending_bytes == 0 and ledger.orphan_bytes == 0
    assert_valid(record, TINY.variables)
    assert_clean(bench, attempt)


def test_a_quarantine_quota_miss_is_null_plus_reason_without_a_copy(make: Any) -> None:
    bench = make(solver=p.solver_unsat(TINY_PROOFS[0]), checker=p.checker_reject())
    ledger = QuarantineLedger(len(TINY_PROOFS[0]) - 1)
    attempt, record = bench.one(TINY, (3,), quarantine=ledger)
    assert record["outcome"] == "CHECK_REJECTED" and record["quarantined"] is None
    assert record["diagnostics"]["quarantine_unavailable"] == "quota"
    assert not any(job.op.value == "publish" for job in bench.io.jobs)
    assert ledger.used_bytes == 0
    assert_clean(bench, attempt)


def test_a_failed_quarantine_publication_still_commits_the_rejection(make: Any) -> None:
    bench = make(solver=p.solver_unsat(TINY_PROOFS[0]), checker=p.checker_reject())
    bench.io.faults.append(publish_failure("resource", "io.no_space"))
    ledger = QuarantineLedger(1 << 20)
    attempt, record = bench.one(TINY, (3,), quarantine=ledger)
    assert record["outcome"] == "CHECK_REJECTED" and record["quarantined"] is None
    assert record["diagnostics"]["quarantine_unavailable"] == "no_space"
    assert record["diagnostics"]["quarantine_error"]["rule"] == "io.no_space"
    assert ledger.used_bytes == 0
    assert published_files(bench, "quarantine") == {}
    assert_clean(bench, attempt)


def test_a_refused_quarantine_reservation_is_no_space(make: Any) -> None:
    bench = make(solver=p.solver_unsat(TINY_PROOFS[0]), checker=p.checker_reject())
    ledger = QuarantineLedger(1 << 20)
    attempt = bench.attempt(TINY, (3,), quarantine=ledger, publish_gate=True)
    drive_to_publish(bench, attempt)
    assert ledger.pending_bytes == len(TINY_PROOFS[0])
    attempt.refuse_publish("disk: no room")
    bench.run(attempt)
    (record,) = bench.io.attempts()
    assert record["outcome"] == "CHECK_REJECTED" and record["quarantined"] is None
    assert record["diagnostics"]["quarantine_unavailable"] == "no_space"
    assert ledger.used_bytes == 0
    assert_clean(bench, attempt)


def test_a_published_quarantine_copy_without_a_record_stays_counted(make: Any) -> None:
    """Reservation lifetime: the copy is durable but the record was refused; its bytes stay
    counted until the startup reconciliation removes the orphan (specification §7.2 step 5)."""

    def refuse_append(job: Any) -> Any:
        if job.op is not Op.APPEND:
            return None
        return Result(job.job_id, job.op, job.attempt_id, Failure("tool", "x", "refused", False))

    bench = make(solver=p.solver_unsat(TINY_PROOFS[0]), checker=p.checker_reject())
    bench.io.faults.append(refuse_append)
    ledger = QuarantineLedger(1 << 20)
    attempt = bench.attempt(TINY, (3,), quarantine=ledger)
    bench.run(attempt)
    assert attempt.abandoned == "commit_refused"
    assert ledger.committed_bytes == 0 and ledger.pending_bytes == 0
    assert ledger.orphan_bytes == len(TINY_PROOFS[0])


# -- audit attempts (specification §11.2) ---------------------------------------------------------


def test_an_audit_attempt_runs_the_solver_without_a_deadline(make: Any) -> None:
    """A solve longer than the policy's leaf time: a run attempt is EXHAUSTED ``time``, the same
    solve of an audit attempt (``unlimited_solver_time``) completes and is verified with
    ``solver_time_ms`` null; every other part of the record is a run attempt's."""
    slow = [fk.sleep(0.8), *p.solver_unsat(TINY_PROOFS[0])]
    policy = make_policy(leaf_time_ms={"default": 200})
    limited = make(solver=slow, policy=policy)
    _, record = limited.one(TINY, (3,))
    assert (record["outcome"], record["reason"]) == ("EXHAUSTED", "time")
    assert record["limits"]["solver_time_ms"] == 200
    bench = make(solver=slow, policy=policy)
    attempt, audited = bench.one(TINY, (3,), unlimited_solver_time=True)
    assert (audited["outcome"], audited["route"]) == ("VERIFIED_UNSAT", "cdcl")
    assert audited["limits"]["solver_time_ms"] is None
    assert audited["solver"]["elapsed_ms"] >= 800 and audited["solver"]["cause"] is None
    assert audited["proof_sha256"] == sha(TINY_PROOFS[0])
    assert success_problem(audited) is None
    assert_valid(audited, TINY.variables)
    assert_clean(bench, attempt)


def test_an_audit_unit_route_is_the_run_unit_route(make: Any) -> None:
    bench = make()
    _, run = bench.one(TINY, (1,))
    _, audited = bench.one(TINY, (1,), unlimited_solver_time=True)
    assert audited["route"] == run["route"] == "unit"
    assert audited["proof_sha256"] == run["proof_sha256"]
    assert audited["limits"] == run["limits"]


def test_an_audit_attempt_is_refused_for_a_stream_policy_before_any_file(make: Any) -> None:
    from cubeproof.base.errors import ContractError

    bench = make(policy=make_policy(proof_mode=ProofMode.STREAM))
    with pytest.raises(ContractError) as caught:
        bench.attempt(TINY, (3,), unlimited_solver_time=True)
    assert caught.value.rule == "leaf.unlimited"
    assert bench.work_files() == []
    with pytest.raises(ValueError):
        make().attempt(TINY, (3,), unlimited_solver_time="yes")
