"""Each specification §6.3 row with real child processes (the fake tools) through the tool layer.

``attempt`` below is a test-only file-mode driver in the order of specification §6.1 (write CNF,
solve, seal, check with arena retries, re-hash, classify). The trusted binding that records an
attempt is the leaf's; this driver only shows that the supervisor, the checker/solver helpers and
the outcome table produce the right decision for real process behaviour.
"""

from __future__ import annotations

import hashlib
import signal
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest
from cp_tools_support import (  # noqa: F401 - the two fixtures are registered by import
    fixture_files,
    fk,
    isolation_fixture,
    launch,
    linux_only,
    make_binary,
    p,
    run_one,
    supervisor_fixture,
)

from cubeproof.base.process import Cause
from cubeproof.contracts.enums import Outcome
from cubeproof.tools import checker as ck
from cubeproof.tools import solver as sv
from cubeproof.tools.isolation import PinnedBinary
from cubeproof.tools.process import ProcessRun, Supervisor
from cubeproof.tools.process_outcome import (
    Action,
    ArenaLimits,
    CheckFacts,
    Decision,
    Failure,
    SolveFacts,
    classify,
)

pytestmark = linux_only

UNSAT_CNF = fixture_files.fixture("unsat.cnf").read_bytes()
UNSAT_PROOF = fixture_files.fixture("unsat.lrat").read_bytes()
LIMITS = ArenaLimits(max_heap_mib=2048, max_stack_mib=1024)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


@dataclass
class Attempt:
    decision: Decision
    solve: ProcessRun | None
    checks: list[CheckFacts] = field(default_factory=list)


def attempt(
    supervisor: Supervisor,
    work: Path,
    solver: PinnedBinary | None,
    checker: PinnedBinary,
    *,
    argv: Sequence[str] = ("--lrat",),
    proof_cap: int = 1 << 20,
    solver_deadline_ms: int | None = None,
    check_deadline_ms: int | None = None,
    term_grace_ms: int = 300,
    unit_proof: bytes | None = None,
) -> Attempt:
    work.mkdir(parents=True, exist_ok=True)
    cnf = work / "node.cnf"
    proof = work / "node.lrat"
    cnf.write_bytes(UNSAT_CNF)
    cnf_sha = digest(cnf)
    solve_facts: SolveFacts | None = None
    solve_run: ProcessRun | None = None
    if solver is not None:
        spec = launch(
            solver,
            sv.solver_args(argv, str(cnf), str(proof)),
            work,
            file_bytes=proof_cap,
            watch=(str(proof), proof_cap),
            deadline_ms=solver_deadline_ms,
            term_grace_ms=term_grace_ms,
            stdout_capture=1 << 20,
        )
        solve_run = run(supervisor, spec)
        complete = solve_run.result.exit == sv.UNSAT_EXIT and proof.is_file()
        solve_facts = SolveFacts(run=solve_run, proof_complete=complete)
    else:
        assert unit_proof is not None
        proof.write_bytes(unit_proof)
    checks: list[CheckFacts] = []
    decision = classify(solve=solve_facts, checks=checks, limits=LIMITS)
    if decision.action is Action.CHECK:
        proof.chmod(0o444)  # seal
        proof_sha = digest(proof)
        heap, stack = 512, 256
        while True:
            spec = launch(
                checker,
                ck.checker_args(heap, stack, str(cnf), str(proof)),
                work,
                memory_bytes=4 << 30,
                deadline_ms=check_deadline_ms,
                term_grace_ms=term_grace_ms,
            )
            checks.append(CheckFacts(run=run(supervisor, spec), heap_mib=heap, stack_mib=stack))
            decision = classify(solve=solve_facts, checks=checks, limits=LIMITS)
            if decision.action is not Action.RETRY_CHECK:
                break
            assert decision.arena is not None
            heap, stack = decision.arena
        failures = []
        cnf_kept = cnf.is_file() and digest(cnf) == cnf_sha
        proof_kept = proof.is_file() and digest(proof) == proof_sha
        if not (cnf_kept and proof_kept):
            failures.append(Failure.FILE_CHANGED)
        decision = classify(solve=solve_facts, checks=checks, failures=failures, limits=LIMITS)
    return Attempt(decision=decision, solve=solve_run, checks=checks)


def run(supervisor: Supervisor, spec: Any) -> ProcessRun:
    return run_one(supervisor, spec)  # bounded: fails after 60 s instead of hanging


def outcome(result: Attempt) -> tuple[Outcome | None, str | None]:
    assert result.decision.action is Action.RECORD, result.decision
    return result.decision.outcome, result.decision.reason


def tools(
    tmp_path: Path,
    solver_steps: Sequence[dict[str, Any]],
    checker_steps: Sequence[dict[str, Any]],
    **checker: Any,
) -> tuple[PinnedBinary, PinnedBinary, fk.FakeTool, fk.FakeTool]:
    solver_tool, solver = make_binary(tmp_path / "bin", "cadical", solver_steps)
    checker_tool, checker_bin = make_binary(tmp_path / "bin", "cake_lpr", checker_steps, **checker)
    return solver, checker_bin, solver_tool, checker_tool


def test_verified_unsat_end_to_end(supervisor: Supervisor, tmp_path: Path) -> None:
    solver, checker, solver_tool, checker_tool = tools(
        tmp_path, p.solver_unsat(UNSAT_PROOF), p.checker_lrat()
    )
    result = attempt(supervisor, tmp_path / "w", solver, checker)
    assert outcome(result) == (Outcome.VERIFIED_UNSAT, None)
    assert solver_tool.argv(0)[:1] == ["--lrat"]
    assert checker_tool.argv(0)[:2] == ["--CML_HEAP_SIZE=512", "--CML_STACK_SIZE=256"]
    assert ck.accepts(result.checks[-1].run.result)


def test_unit_route_end_to_end(supervisor: Supervisor, tmp_path: Path) -> None:
    _, checker = make_binary(tmp_path, "cake_lpr", p.checker_lrat())
    result = attempt(supervisor, tmp_path / "w", None, checker, unit_proof=UNSAT_PROOF)
    assert outcome(result) == (Outcome.VERIFIED_UNSAT, None)


def test_rejection(supervisor: Supervisor, tmp_path: Path) -> None:
    solver, checker, _, _ = tools(tmp_path, p.solver_unsat(b"9 0 1 0\n"), p.checker_lrat())
    assert outcome(attempt(supervisor, tmp_path / "w", solver, checker)) == (
        Outcome.CHECK_REJECTED,
        "rejected",
    )


@pytest.mark.parametrize("wrong", p.WRONG_SUCCESS_OUTPUTS, ids=repr)
def test_wrong_success_outputs_are_rejections(
    supervisor: Supervisor, tmp_path: Path, wrong: bytes
) -> None:
    solver, checker, _, _ = tools(tmp_path, p.solver_unsat(UNSAT_PROOF), p.checker_output(wrong, 0))
    assert outcome(attempt(supervisor, tmp_path / "w", solver, checker)) == (
        Outcome.CHECK_REJECTED,
        "rejected",
    )


def test_heap_arena_retry_reuses_the_proof(supervisor: Supervisor, tmp_path: Path) -> None:
    solver_tool, solver = make_binary(tmp_path / "bin", "cadical", p.solver_unsat(UNSAT_PROOF))
    checker_tool = fk.make_tool(
        tmp_path / "bin",
        "cake_lpr",
        cases=[
            fk.case(p.checker_arena("heap"), invocation=0),
            fk.case(p.checker_arena("stack"), invocation=1),
            fk.case(p.checker_arena("both"), invocation=2),
        ],
        steps=p.checker_lrat(),
    )
    checker = PinnedBinary.measure(str(checker_tool.path))
    result = attempt(supervisor, tmp_path / "w", solver, checker)
    assert outcome(result) == (Outcome.VERIFIED_UNSAT, None)
    arenas = [(c.heap_mib, c.stack_mib) for c in result.checks]
    assert arenas == [(512, 256), (1024, 256), (1024, 512), (2048, 1024)]
    assert [call["argv"][:2] for call in checker_tool.calls()] == [
        ["--CML_HEAP_SIZE=512", "--CML_STACK_SIZE=256"],
        ["--CML_HEAP_SIZE=1024", "--CML_STACK_SIZE=256"],
        ["--CML_HEAP_SIZE=1024", "--CML_STACK_SIZE=512"],
        ["--CML_HEAP_SIZE=2048", "--CML_STACK_SIZE=1024"],
    ]
    assert len(solver_tool.calls()) == 1  # only the check repeats


@pytest.mark.parametrize(("kind", "reason"), [("heap", "check_memory"), ("stack", "check_stack")])
def test_arena_exhaustion_at_the_maximum(
    supervisor: Supervisor, tmp_path: Path, kind: str, reason: str
) -> None:
    solver, checker, _, checker_tool = tools(
        tmp_path, p.solver_unsat(UNSAT_PROOF), p.checker_arena(kind)
    )
    result = attempt(supervisor, tmp_path / "w", solver, checker)
    assert outcome(result) == (Outcome.EXHAUSTED, reason)
    assert len(checker_tool.calls()) == 3  # bounded ladder: 512..2048 or 256..1024


def test_success_with_arena_diagnostic_is_protocol(supervisor: Supervisor, tmp_path: Path) -> None:
    solver, checker, _, _ = tools(
        tmp_path, p.solver_unsat(UNSAT_PROOF), p.checker_success_with_arena("heap")
    )
    assert outcome(attempt(supervisor, tmp_path / "w", solver, checker)) == (
        Outcome.TOOL_FAILED,
        "protocol",
    )


def test_checker_crash(supervisor: Supervisor, tmp_path: Path) -> None:
    solver, checker, _, _ = tools(tmp_path, p.solver_unsat(UNSAT_PROOF), p.checker_crash("SEGV"))
    assert outcome(attempt(supervisor, tmp_path / "w", solver, checker)) == (
        Outcome.TOOL_FAILED,
        "crash",
    )


def test_checker_flood_is_never_success(supervisor: Supervisor, tmp_path: Path) -> None:
    solver, checker, _, _ = tools(tmp_path, p.solver_unsat(UNSAT_PROOF), p.checker_flood(1 << 20))
    assert outcome(attempt(supervisor, tmp_path / "w", solver, checker)) == (
        Outcome.TOOL_FAILED,
        "protocol",
    )


@pytest.mark.parametrize("target", ["cnf", "proof"])
def test_checker_mutating_its_inputs_is_file_changed(
    supervisor: Supervisor, tmp_path: Path, target: str
) -> None:
    solver, checker, _, _ = tools(
        tmp_path, p.solver_unsat(UNSAT_PROOF), p.checker_alters(target, action="delete")
    )
    assert outcome(attempt(supervisor, tmp_path / "w", solver, checker)) == (
        Outcome.TOOL_FAILED,
        "file_changed",
    )


def test_check_deadline(supervisor: Supervisor, tmp_path: Path) -> None:
    solver, checker, _, _ = tools(
        tmp_path, p.solver_unsat(UNSAT_PROOF), [fk.sleep(60), *p.checker_accept()]
    )
    result = attempt(supervisor, tmp_path / "w", solver, checker, check_deadline_ms=300)
    assert outcome(result) == (Outcome.EXHAUSTED, "check_time")


def test_solver_deadline(supervisor: Supervisor, tmp_path: Path) -> None:
    solver, checker, _, checker_tool = tools(
        tmp_path, p.solver_ignoring_term(60), p.checker_accept()
    )
    result = attempt(supervisor, tmp_path / "w", solver, checker, solver_deadline_ms=300)
    assert outcome(result) == (Outcome.EXHAUSTED, "time")
    assert result.solve is not None and result.solve.result.signal == signal.SIGKILL
    assert checker_tool.calls() == []


def test_proof_size_by_sigxfsz(supervisor: Supervisor, tmp_path: Path) -> None:
    solver, checker, _, _ = tools(tmp_path, p.solver_proof_flood(1 << 20), p.checker_accept())
    result = attempt(supervisor, tmp_path / "w", solver, checker, proof_cap=8192)
    assert outcome(result) == (Outcome.EXHAUSTED, "proof_size")
    assert (tmp_path / "w" / "node.lrat").stat().st_size <= 8192


def test_proof_size_by_cap_event(supervisor: Supervisor, tmp_path: Path) -> None:
    steps = [fk.write(fk.arg(-1), "1 0\n", size=8192), fk.sleep(60)]
    solver, checker, _, _ = tools(tmp_path, steps, p.checker_accept())
    result = attempt(supervisor, tmp_path / "w", solver, checker, proof_cap=8192)
    assert outcome(result) == (Outcome.EXHAUSTED, "proof_size")
    assert result.solve is not None and result.solve.causes[0] is Cause.PROOF_CAP


def test_solver_memory(supervisor: Supervisor, tmp_path: Path) -> None:
    solver, checker, _, _ = tools(tmp_path, p.solver_out_of_memory(), p.checker_accept())
    assert outcome(attempt(supervisor, tmp_path / "w", solver, checker)) == (
        Outcome.EXHAUSTED,
        "solver_memory",
    )


@pytest.mark.parametrize("name", ["SEGV", "KILL", "TERM", "ABRT", "BUS"])
def test_solver_crash_by_signal(supervisor: Supervisor, tmp_path: Path, name: str) -> None:
    solver, checker, _, _ = tools(tmp_path, [fk.kill_self(name)], p.checker_accept())
    assert outcome(attempt(supervisor, tmp_path / "w", solver, checker)) == (
        Outcome.TOOL_FAILED,
        "crash",
    )


@pytest.mark.parametrize(
    "steps",
    [
        p.solver_output(b"s UNKNOWN\n", 0),
        p.solver_output(b"", 1),
        p.solver_output(b"s UNSATISFIABLE\n", 20),  # no proof file at all
    ],
    ids=["exit0", "exit1", "exit20-without-proof"],
)
def test_solver_protocol_failures(
    supervisor: Supervisor, tmp_path: Path, steps: list[dict[str, Any]]
) -> None:
    solver, checker, _, _ = tools(tmp_path, steps, p.checker_accept())
    assert outcome(attempt(supervisor, tmp_path / "w", solver, checker)) == (
        Outcome.TOOL_FAILED,
        "protocol",
    )


def test_sat_goes_to_model_parsing(supervisor: Supervisor, tmp_path: Path) -> None:
    solver, checker, _, checker_tool = tools(tmp_path, p.solver_sat([1, -2]), p.checker_accept())
    result = attempt(supervisor, tmp_path / "w", solver, checker)
    assert result.decision.action is Action.PARSE_MODEL
    assert result.solve is not None and result.solve.stdout == b"s SATISFIABLE\nv 1 -2 0\n"
    assert checker_tool.calls() == []


def test_binary_changed_before_the_solve(supervisor: Supervisor, tmp_path: Path) -> None:
    solver, checker, solver_tool, _ = tools(
        tmp_path, p.solver_unsat(UNSAT_PROOF), p.checker_accept()
    )
    with solver_tool.path.open("a", encoding="utf-8") as handle:
        handle.write("#\n")
    assert outcome(attempt(supervisor, tmp_path / "w", solver, checker)) == (
        Outcome.TOOL_FAILED,
        "binary_changed",
    )
    assert solver_tool.calls() == []


def test_launch_failure(supervisor: Supervisor, tmp_path: Path) -> None:
    solver, _, solver_tool, _ = tools(tmp_path, p.solver_unsat(UNSAT_PROOF), p.checker_accept())
    spec = launch(solver, ["--lrat", "/x/n.cnf", "/x/n.lrat"], tmp_path / "absent")
    result = run(supervisor, spec)
    assert (result.result.started, result.causes) == (False, (Cause.LAUNCH,))
    decision = classify(
        solve=SolveFacts(run=result, proof_complete=False), checks=[], limits=LIMITS
    )
    assert (decision.outcome, decision.reason) == (Outcome.TOOL_FAILED, "launch")
    assert solver_tool.calls() == []
