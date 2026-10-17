"""The stream outcome table (specification §6.3 with the §6.4 stream precedence), pure.

Synthetic runs of the three coupled processes (solver, relay, checker) go through
:func:`cubeproof.leaf.stream.classify_stream`. Named cases pin each precedence rule of specification
§6.4 (cap and arena exhaustion before the EPIPE/termination they cause, checker crash before its
downstream relay errors, early checker success without a complete transfer); the cross
product checks the invariants on every paired tool/relay failure combination.
"""

from __future__ import annotations

import dataclasses
import itertools
import signal
from collections.abc import Sequence
from typing import Any

import pytest
from cp_stream_support import make_policy, run, sha

from cubeproof.base.process import Cause
from cubeproof.contracts.enums import Outcome
from cubeproof.evidence.schema.values import Relay
from cubeproof.leaf.stream import (
    MISSING_REPORT,
    QUARANTINE_DIAGNOSTIC,
    Role,
    StreamDecision,
    StreamFacts,
    StreamLimits,
    classify_stream,
)
from cubeproof.tools import relay as rl
from cubeproof.tools.process import ProcessRun
from cubeproof.tools.process_outcome import Action, Failure

PROOF = b"5 1 0 1 2 0\n6 0 5 3 4 0\n"
SUCCESS = "s VERIFIED UNSAT\n"
HEAP = "CakeML heap space exhausted.\n"
STACK = "CakeML stack space exhausted.\n"
BOTH = "failed to allocate sufficient CakeML heap and stack space.\n"
BAD_ALLOC = "terminate called after throwing an instance of 'std::bad_alloc'\n"
LIMITS = StreamLimits.of(make_policy())
SIGPIPE = int(signal.SIGPIPE)
SIGTERM = int(signal.SIGTERM)
SIGSEGV = int(signal.SIGSEGV)
SIGABRT = int(signal.SIGABRT)


# -- runs of each role ----------------------------------------------------------------------------


def report(
    data: bytes = PROOF,
    *,
    solver_eof: bool = True,
    all_written: bool = True,
    error: str | None = None,
    written: int | None = None,
) -> bytes:
    count = len(data)
    sent = count if written is None else written
    return rl.RelayReport(count, sha(data), solver_eof, all_written, error, sent).to_line()


def relay_run(line: bytes | None, *, exit: int | None = 0, **options: Any) -> ProcessRun:
    capture = b"" if line is None else line
    return run(exit=exit, stdout=capture.decode(), capture=capture, **options)


SOLVER: dict[str, ProcessRun] = {
    "unsat": run(exit=20, stdout="s UNSATISFIABLE\n"),
    "sat": run(exit=10, stdout="s SATISFIABLE\nv 1 -2 0\n"),
    "exit1": run(exit=1),
    "segv": run(signal_number=SIGSEGV),
    "sigpipe": run(signal_number=SIGPIPE),
    "bad_alloc": run(signal_number=SIGABRT, stderr=BAD_ALLOC),
    "memory_event": run(signal_number=9, causes=(Cause.MEMORY_EVENT,)),
    "deadline": run(signal_number=SIGTERM, causes=(Cause.DEADLINE,)),
    "torn": run(signal_number=SIGTERM, causes=(Cause.CANCELLED,)),
    # torn down, but it had already exited by itself with another status
    "torn_exit0": run(exit=0, causes=(Cause.CANCELLED,)),
    "launch": run(started=False, causes=(Cause.LAUNCH,)),
    "binary": run(exit=20, causes=(Cause.BINARY_CHANGED,)),
    "held": run(exit=20, stdout="s UNSATISFIABLE\n", causes=(Cause.HELD_OPEN,)),
}

RELAY: dict[str, ProcessRun] = {
    "complete": relay_run(report()),
    "epipe": relay_run(
        report(all_written=False, error="write: EPIPE", written=10), exit=rl.EXIT_TRANSPORT
    ),
    "cap": relay_run(
        report(solver_eof=False, all_written=False, error=rl.ERROR_CAP, written=0),
        exit=rl.EXIT_CAP,
    ),
    "terminated": relay_run(
        report(solver_eof=False, all_written=False, error=rl.ERROR_TERMINATED, written=0),
        exit=rl.EXIT_TERMINATED,
        causes=(Cause.CANCELLED,),
    ),
    "deadline": relay_run(
        report(solver_eof=False, all_written=False, error=rl.ERROR_TERMINATED, written=0),
        exit=rl.EXIT_TERMINATED,
        causes=(Cause.DEADLINE,),
    ),
    "crash": relay_run(None, exit=None, signal_number=SIGSEGV),
    "no_report": relay_run(None),
    "complete_bad_exit": relay_run(report(), exit=1),
    # a report that claims everything written without the solver's EOF (never complete)
    "no_eof": relay_run(report(solver_eof=False)),
    # torn down after it had completed and reported (a teardown racing the relay's exit)
    "torn_complete": relay_run(report(), causes=(Cause.CANCELLED,)),
    "launch": run(started=False, causes=(Cause.LAUNCH,)),
    "binary": run(started=False, causes=(Cause.BINARY_CHANGED,)),
}

CHECKER: dict[str, ProcessRun] = {
    "accept": run(exit=0, stdout=SUCCESS),
    "reject": run(exit=0, stderr="c Checking failed at line: 1. Reason: x\n"),
    "heap": run(exit=1, stderr=HEAP),
    "stack": run(exit=2, stderr=STACK),
    "both": run(exit=3, stderr=BOTH),
    "crash": run(signal_number=SIGSEGV),
    "torn": run(signal_number=SIGTERM, causes=(Cause.CANCELLED,)),
    "deadline": run(signal_number=SIGTERM, causes=(Cause.DEADLINE,)),
    "exit5": run(exit=5),
    "success_with_arena": run(exit=0, stdout=SUCCESS, stderr=HEAP),
    "heap_with_success": run(exit=1, stdout=SUCCESS, stderr=HEAP),
    "stderr_cut": run(exit=0, stderr="c ...", stderr_truncated=True),
    # torn down after it had reported its heap exhaustion and exited (a racing teardown)
    "torn_heap": run(exit=1, stderr=HEAP, causes=(Cause.CANCELLED,)),
    "launch": run(started=False, causes=(Cause.LAUNCH,)),
}

#: The roles the stream controller itself tore down for each named state (specification §6.4
#: teardown).
TORN = {
    ("relay", "torn_complete"),
    ("checker", "torn_heap"),
    ("solver", "torn"),
    ("solver", "torn_exit0"),
    ("relay", "terminated"),
    ("checker", "torn"),
}


def facts(
    solver: str = "unsat",
    relay: str = "complete",
    checker: str = "accept",
    *,
    torn: Sequence[Role] | None = None,
    cancelled: bool = False,
    heap: int = 1024,
    stack: int = 256,
) -> StreamFacts:
    if torn is None:
        names = {"solver": solver, "relay": relay, "checker": checker}
        torn = [Role(role) for role, name in names.items() if (role, name) in TORN]
    return StreamFacts(
        solver=SOLVER[solver],
        relay=RELAY[relay],
        checker=CHECKER[checker],
        heap_mib=heap,
        stack_mib=stack,
        torn_down=frozenset(torn),
        cancelled=cancelled,
    )


def decide(*args: str, failures: Sequence[Failure] = (), **options: Any) -> StreamDecision:
    return classify_stream(facts(*args, **options), LIMITS, failures=failures)


def outcome(decision: StreamDecision) -> tuple[Any, ...]:
    if decision.action is not Action.RECORD:
        return (decision.action.value,)
    assert decision.outcome is not None
    return (decision.outcome.value, decision.reason)


# -- named rows -------------------------------------------------------------------------------


def test_a_complete_transfer_with_exact_success_is_verified() -> None:
    decision = decide()
    assert outcome(decision) == ("VERIFIED_UNSAT", None)
    assert decision.proof == (len(PROOF), sha(PROOF))
    assert decision.relay == {
        "bytes": len(PROOF),
        "sha256": sha(PROOF),
        "solver_eof": True,
        "all_written": True,
        "error": None,
    }


@pytest.mark.parametrize(
    ("case", "expected"),
    [
        # 0. user cancellation: no record, whatever else happened
        ({"cancelled": True}, ("no_record",)),
        ({"solver": "torn", "torn": ()}, ("no_record",)),  # a supervisor stop, not a teardown
        ({"checker": "torn", "relay": "terminated", "torn": [Role.RELAY]}, ("no_record",)),
        # 1. launch, binary, I/O and file binding, before every other row (also success)
        ({"solver": "launch", "relay": "terminated", "checker": "torn"}, ("TOOL_FAILED", "launch")),
        ({"relay": "launch", "solver": "torn", "checker": "torn"}, ("TOOL_FAILED", "launch")),
        ({"checker": "launch", "relay": "terminated", "solver": "torn"}, ("TOOL_FAILED", "launch")),
        ({"solver": "binary"}, ("TOOL_FAILED", "binary_changed")),
        (
            {"relay": "binary", "solver": "torn", "checker": "torn"},
            ("TOOL_FAILED", "binary_changed"),
        ),
        ({"failures": [Failure.FILE_CHANGED]}, ("TOOL_FAILED", "file_changed")),
        ({"failures": [Failure.IO], "relay": "cap"}, ("TOOL_FAILED", "io")),
        ({"solver": "sat", "failures": [Failure.FILE_CHANGED]}, ("TOOL_FAILED", "file_changed")),
        # a clean SAT exit: the checker only ever saw a partial proof (reading, see module doc)
        ({"solver": "sat", "checker": "reject"}, ("parse_model",)),
        ({"solver": "sat", "checker": "heap", "relay": "epipe"}, ("parse_model",)),
        ({"solver": "sat", "checker": "crash", "relay": "epipe"}, ("parse_model",)),
        ({"solver": "sat", "checker": "torn", "relay": "terminated"}, ("parse_model",)),
        # 2. proof cap outranks the EPIPE/termination it causes, and every later row
        ({"relay": "cap", "solver": "sigpipe", "checker": "reject"}, ("EXHAUSTED", "proof_size")),
        ({"relay": "cap", "solver": "torn", "checker": "accept"}, ("EXHAUSTED", "proof_size")),
        ({"relay": "cap", "solver": "deadline", "checker": "crash"}, ("EXHAUSTED", "proof_size")),
        ({"relay": "cap", "solver": "sigpipe", "checker": "heap"}, ("EXHAUSTED", "proof_size")),
        # 3./4. the coupled deadline: the solver's, else the check's
        ({"solver": "deadline", "relay": "deadline", "checker": "deadline"}, ("EXHAUSTED", "time")),
        ({"solver": "deadline", "relay": "complete", "checker": "heap"}, ("EXHAUSTED", "time")),
        ({"checker": "deadline", "relay": "complete"}, ("EXHAUSTED", "check_time")),
        ({"relay": "deadline", "solver": "torn", "checker": "torn"}, ("EXHAUSTED", "check_time")),
        # 5. arena exhaustion outranks the relay EPIPE and the terminated solver it causes
        ({"checker": "heap", "relay": "epipe", "solver": "sigpipe"}, ("EXHAUSTED", "check_memory")),
        ({"checker": "heap", "relay": "epipe", "solver": "torn"}, ("EXHAUSTED", "check_memory")),
        (
            {"checker": "stack", "relay": "terminated", "solver": "torn"},
            ("EXHAUSTED", "check_stack"),
        ),
        (
            {"checker": "both", "relay": "terminated", "solver": "torn"},
            ("EXHAUSTED", "check_memory"),
        ),
        ({"checker": "heap", "relay": "complete"}, ("EXHAUSTED", "check_memory")),
        # ... but a solver that crashed on its own is upstream of the checker (row U)
        ({"checker": "heap", "relay": "epipe", "solver": "segv"}, ("TOOL_FAILED", "crash")),
        ({"checker": "heap", "relay": "complete", "solver": "exit1"}, ("TOOL_FAILED", "protocol")),
        (
            {"checker": "crash", "relay": "complete", "solver": "bad_alloc"},
            ("EXHAUSTED", "solver_memory"),
        ),
        ({"checker": "success_with_arena"}, ("TOOL_FAILED", "protocol")),
        ({"checker": "heap_with_success", "relay": "epipe"}, ("TOOL_FAILED", "protocol")),
        # 6. solver memory
        ({"solver": "bad_alloc", "checker": "reject"}, ("EXHAUSTED", "solver_memory")),
        (
            {"solver": "memory_event", "checker": "torn", "relay": "terminated"},
            ("EXHAUSTED", "solver_memory"),
        ),
        # 7. a checker crash precedes its downstream relay errors
        ({"checker": "crash", "relay": "epipe", "solver": "sigpipe"}, ("TOOL_FAILED", "crash")),
        ({"checker": "crash", "relay": "epipe", "solver": "torn"}, ("TOOL_FAILED", "crash")),
        ({"solver": "segv", "checker": "reject"}, ("TOOL_FAILED", "crash")),
        ({"solver": "segv", "checker": "torn", "relay": "terminated"}, ("TOOL_FAILED", "crash")),
        ({"relay": "crash", "solver": "sigpipe", "checker": "torn"}, ("TOOL_FAILED", "crash")),
        ({"solver": "held"}, ("TOOL_FAILED", "protocol")),
        ({"relay": "no_report", "checker": "reject"}, ("TOOL_FAILED", "protocol")),
        # broken transport without an earlier classified cause
        ({"relay": "epipe", "solver": "sigpipe", "checker": "reject"}, ("TOOL_FAILED", "relay")),
        ({"relay": "epipe", "solver": "torn", "checker": "accept"}, ("TOOL_FAILED", "relay")),
        ({"relay": "terminated", "solver": "torn", "checker": "accept"}, ("TOOL_FAILED", "relay")),
        ({"relay": "terminated", "solver": "unsat", "checker": "accept"}, ("TOOL_FAILED", "relay")),
        ({"relay": "complete_bad_exit"}, ("TOOL_FAILED", "relay")),
        ({"relay": "no_eof"}, ("TOOL_FAILED", "relay")),
        # a teardown that raced a process's own end does not hide what it reported
        ({"relay": "torn_complete"}, ("VERIFIED_UNSAT", None)),
        (
            {"checker": "torn_heap", "relay": "epipe", "solver": "sigpipe"},
            ("EXHAUSTED", "check_memory"),
        ),
        ({"solver": "exit1", "checker": "reject"}, ("TOOL_FAILED", "protocol")),
        ({"solver": "sigpipe", "checker": "reject"}, ("TOOL_FAILED", "crash")),
        # 9.-11. a complete proof: rejection, success, anything else
        ({"checker": "reject"}, ("CHECK_REJECTED", "rejected")),
        ({"checker": "exit5"}, ("TOOL_FAILED", "protocol")),
        ({"checker": "stderr_cut"}, ("TOOL_FAILED", "protocol")),
        ({"checker": "torn", "relay": "complete"}, ("TOOL_FAILED", "protocol")),
    ],
)
def test_the_stream_rows(case: dict[str, Any], expected: tuple[Any, ...]) -> None:
    options = dict(case)
    failures = options.pop("failures", ())
    names = {k: options.pop(k) for k in ("solver", "relay", "checker") if k in options}
    decision = decide(**names, failures=failures, **options)
    assert outcome(decision) == expected, decision


@pytest.mark.parametrize(
    "stdout",
    [
        "",
        "s VERIFIED UNSAT",
        "s VERIFIED UNSAT\n\n",
        "s VERIFIED UNSAT\r\n",
        " s VERIFIED UNSAT\n",
        "s verified unsat\n",
        "s VERIFIED UNSAT\ns VERIFIED UNSAT\n",
    ],
)
def test_only_the_exact_success_line_verifies(stdout: str) -> None:
    checker = run(exit=0, stdout=stdout)
    value = dataclasses.replace(facts(), checker=checker)
    decision = classify_stream(value, LIMITS)
    assert decision.outcome is not Outcome.VERIFIED_UNSAT


def test_a_rejected_stream_proof_has_metadata_only_quarantine() -> None:
    decision = decide(checker="reject")
    assert outcome(decision) == ("CHECK_REJECTED", "rejected")
    assert decision.proof == (len(PROOF), sha(PROOF))
    assert decision.diagnostics["quarantine_unavailable"] == "stream_not_spooled"
    assert QUARANTINE_DIAGNOSTIC == {"quarantine_unavailable": "stream_not_spooled"}
    for other in (decide(), decide(checker="heap"), decide(solver="sat", checker="reject")):
        assert "quarantine_unavailable" not in other.diagnostics


def test_arena_reasons_follow_the_maxima() -> None:
    """At the maxima the reason is the exhausted arena's (specification §6.3, §6.4: no retry
    beyond)."""
    policy = make_policy(checker_max_heap_mib=1024, checker_max_stack_mib=512)
    limits = StreamLimits.of(policy)
    both_at_stack_max = facts(checker="both", relay="epipe", solver="sigpipe", heap=256, stack=512)
    decision = classify_stream(both_at_stack_max, limits)
    assert outcome(decision) == ("EXHAUSTED", "check_stack")
    both_at_heap_max = facts(checker="both", relay="epipe", solver="sigpipe", heap=1024, stack=256)
    assert outcome(classify_stream(both_at_heap_max, limits)) == ("EXHAUSTED", "check_memory")


def test_secondary_conditions_are_kept() -> None:
    decision = decide(checker="heap", relay="epipe", solver="sigpipe")
    notes = set(decision.secondary)
    # the primary condition is the outcome itself; everything else is kept raw
    assert {"solver:signal:13", "checker:exit:1"} <= notes
    assert "checker:arena:heap" not in notes
    assert any(n.startswith("relay:error:") and "EPIPE" in n for n in notes)
    capped = decide(relay="cap", solver="torn", checker="accept")
    assert "checker:accepted" in capped.secondary
    assert "solver:teardown" in capped.secondary


def test_a_missing_relay_report_is_recorded_as_such() -> None:
    decision = decide(relay="crash", solver="sigpipe", checker="torn")
    assert decision.relay is not None
    assert decision.relay["error"] == MISSING_REPORT
    assert (decision.relay["solver_eof"], decision.relay["all_written"]) == (False, False)
    assert decision.proof is None


def test_proof_fields_only_for_a_complete_transfer_of_a_clean_unsat_solve() -> None:
    assert decide(checker="heap", relay="complete").proof == (len(PROOF), sha(PROOF))
    assert decide(checker="heap", relay="epipe", solver="sigpipe").proof is None
    assert decide(relay="cap", solver="torn", checker="accept").proof is None
    assert decide(solver="exit1", checker="reject").proof is None
    assert decide(solver="sat", checker="reject").proof is None
    assert decide(relay="complete_bad_exit").proof is None


def test_only_an_exit_20_solve_can_be_verified() -> None:
    """A solver that was torn down after it had exited by itself with another status, with a
    complete transfer and an accepting checker, is not a complete proof (exit omitted)."""
    decision = decide(solver="torn_exit0")
    assert outcome(decision) == ("TOOL_FAILED", "protocol")
    assert decision.proof is None


def test_an_unclean_relay_never_reports_a_complete_transfer() -> None:
    """A complete report from a relay that did not end cleanly is not presented as a
    complete transfer in the record."""
    value = decide(relay="complete_bad_exit").relay
    assert value["error"] == "relay_exit:1"
    assert (value["solver_eof"], value["all_written"]) == (True, True)
    assert decide().relay["error"] is None


# -- every combination --------------------------------------------------------------------------


COMBINATIONS = list(itertools.product(sorted(SOLVER), sorted(RELAY), sorted(CHECKER)))


def _clean(value: ProcessRun, code: int, *, torn: bool = False) -> bool:
    """Exit ``code`` without signal or cause (a teardown's cancellation allowed if torn)."""
    result = value.result
    causes = [c for c in value.causes if not (torn and c is Cause.CANCELLED)]
    return result.started and result.exit == code and result.signal is None and not causes


@pytest.mark.parametrize("cancelled", [False, True])
def test_every_paired_failure_combination(cancelled: bool) -> None:
    """Invariants on all solver x relay x checker states (with and without teardown marks)."""
    seen: set[tuple[Any, ...]] = set()
    for solver, relay, checker in COMBINATIONS:
        value = facts(solver, relay, checker, cancelled=cancelled)
        decision = classify_stream(value, LIMITS)
        again = classify_stream(value, LIMITS)
        assert decision == again  # deterministic
        seen.add(outcome(decision))
        label = (solver, relay, checker)
        if cancelled:
            assert decision.action is Action.NO_RECORD, label
            continue
        if decision.outcome is Outcome.VERIFIED_UNSAT:
            assert _clean(value.solver, 20), label
            assert value.report is not None and value.report.complete, label
            assert _clean(value.relay, 0, torn=Role.RELAY in value.torn_down), label
            assert _clean(value.checker, 0), label
            assert value.checker.result.stdout_tail == SUCCESS, label
        if decision.proof is not None:
            assert value.report is not None and value.report.complete, label
            assert decision.proof == (value.report.bytes, value.report.sha256), label
            assert decision.outcome not in (Outcome.MODEL, Outcome.INVALID_MODEL), label
        if decision.relay is not None:
            Relay.from_json(decision.relay)  # schema-valid specification §4.8 relay value
        if decision.action is Action.RECORD:
            assert decision.outcome is not None
            if decision.outcome is not Outcome.VERIFIED_UNSAT:
                assert decision.reason, label
        started = all(v.result.started for v in (value.solver, value.relay, value.checker))
        changed = any(
            Cause.BINARY_CHANGED in v.causes for v in (value.solver, value.relay, value.checker)
        )
        if not started or changed:
            assert decision.outcome is Outcome.TOOL_FAILED, label
            assert decision.reason in ("launch", "binary_changed"), label
        elif relay == "cap" and solver not in ("sat",):
            assert outcome(decision) == ("EXHAUSTED", "proof_size"), label
        elif solver == "sat":
            assert decision.action is Action.PARSE_MODEL, label
    assert ("VERIFIED_UNSAT", None) in seen or cancelled
