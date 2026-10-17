"""The specification §6.3 outcome table on synthetic process runs.

Every row, the precedence between rows, and the rule that a signal alone never stands for a
resource cause: only typed supervisor causes (deadline, proof cap, memory event,
cancellation), the solver's SIGXFSZ and the pinned diagnostics decide EXHAUSTED.
"""

from __future__ import annotations

import signal

import pytest
from cp_tools_support import finished, p, result

from cubeproof.base.process import Cause
from cubeproof.contracts.enums import Outcome
from cubeproof.tools.checker import SUCCESS_STDOUT
from cubeproof.tools.process_outcome import (
    Action,
    ArenaLimits,
    CheckFacts,
    Decision,
    Failure,
    SolveFacts,
    classify,
)

LIMITS = ArenaLimits(max_heap_mib=8192, max_stack_mib=2048)
ALL_SIGNALS = sorted(int(s) for s in signal.valid_signals() if 0 < int(s) < 32)


def solve(
    exit: int | None = 20,
    sig: int | None = None,
    causes: tuple[Cause, ...] = (),
    *,
    complete: bool = True,
    stderr: str = "",
    started: bool = True,
) -> SolveFacts:
    value = result(
        started=started,
        exit=exit if started else None,
        signal=sig if started else None,
        stderr=stderr,
        cause=causes[0].value if causes else None,
    )
    return SolveFacts(run=finished(value, causes), proof_complete=complete)


def check(
    exit: int | None = 0,
    sig: int | None = None,
    stdout: str = SUCCESS_STDOUT,
    stderr: str = "",
    causes: tuple[Cause, ...] = (),
    *,
    heap: int = 512,
    stack: int = 256,
    truncated: bool = False,
    started: bool = True,
) -> CheckFacts:
    value = result(
        started=started,
        exit=exit if started else None,
        signal=sig if started else None,
        stdout=stdout if started else "",
        stderr=stderr,
        truncated=truncated,
        cause=causes[0].value if causes else None,
    )
    return CheckFacts(run=finished(value, causes), heap_mib=heap, stack_mib=stack)


def arena_check(kind: str, heap: int = 512, stack: int = 256) -> CheckFacts:
    code, message = p.ARENA[kind]
    return check(exit=code, stdout="", stderr=message.decode(), heap=heap, stack=stack)


def reject_check() -> CheckFacts:
    return check(stdout="", stderr="c Checking failed at line: 1. Reason: x\n")


def decide(
    solve_facts: SolveFacts | None,
    checks: list[CheckFacts] | None = None,
    failures: tuple[Failure, ...] = (),
    *,
    cancelled: bool = False,
) -> Decision:
    return classify(
        solve=solve_facts,
        checks=checks or [],
        failures=failures,
        limits=LIMITS,
        cancelled=cancelled,
    )


def recorded(decision: Decision) -> tuple[Outcome | None, str | None]:
    assert decision.action is Action.RECORD, decision
    return decision.outcome, decision.reason


# -- the rows in order -------------------------------------------------------------------------


def test_verified_unsat_needs_complete_proof_exact_success_and_no_failure() -> None:
    assert recorded(decide(solve(), [check()])) == (Outcome.VERIFIED_UNSAT, None)


def test_a_completed_solve_asks_for_a_check() -> None:
    assert decide(solve()).action is Action.CHECK
    assert decide(None).action is Action.CHECK  # unit route: the proof is ours and complete


def test_unit_route_uses_the_same_checker_rows() -> None:
    assert recorded(decide(None, [check()])) == (Outcome.VERIFIED_UNSAT, None)
    assert recorded(decide(None, [reject_check()])) == (Outcome.CHECK_REJECTED, "rejected")
    assert decide(None, [arena_check("heap")]).action is Action.RETRY_CHECK


@pytest.mark.parametrize("failure", list(Failure))
def test_row1_binding_and_io_failures_are_tool_failures(failure: Failure) -> None:
    assert recorded(decide(solve(), [check()], (failure,))) == (Outcome.TOOL_FAILED, failure.value)


def test_row1_file_mutation_overrides_checker_success_and_every_later_row() -> None:
    for solve_facts in (
        solve(),
        solve(None, signal.SIGKILL, (Cause.DEADLINE,)),
        solve(None, signal.SIGXFSZ),
    ):
        decision = decide(solve_facts, [check()], (Failure.FILE_CHANGED,))
        assert recorded(decision) == (Outcome.TOOL_FAILED, "file_changed")


def test_row1_the_first_failure_is_primary_and_the_rest_secondary() -> None:
    decision = decide(solve(), [check()], (Failure.IO, Failure.FILE_CHANGED))
    assert recorded(decision) == (Outcome.TOOL_FAILED, "io")
    assert "binding:file_changed" in decision.secondary


def test_row1_launch_and_binary_changes_of_processes() -> None:
    not_started = solve(started=False, causes=(Cause.LAUNCH,))
    assert recorded(decide(not_started)) == (Outcome.TOOL_FAILED, "launch")
    changed = solve(started=False, causes=(Cause.BINARY_CHANGED,))
    assert recorded(decide(changed)) == (Outcome.TOOL_FAILED, "binary_changed")
    after = solve(causes=(Cause.BINARY_CHANGED,))  # the binary changed while it ran
    assert recorded(decide(after, [check()])) == (Outcome.TOOL_FAILED, "binary_changed")
    checker_launch = check(started=False, causes=(Cause.LAUNCH,))
    assert recorded(decide(solve(), [checker_launch])) == (Outcome.TOOL_FAILED, "launch")
    checker_changed = check(causes=(Cause.BINARY_CHANGED,))
    assert recorded(decide(solve(), [checker_changed])) == (
        Outcome.TOOL_FAILED,
        "binary_changed",
    )


def test_row2_proof_cap_and_sigxfsz_are_proof_size() -> None:
    capped = solve(None, signal.SIGTERM, (Cause.PROOF_CAP,), complete=False)
    assert recorded(decide(capped)) == (Outcome.EXHAUSTED, "proof_size")
    xfsz = solve(None, signal.SIGXFSZ, complete=False)
    assert recorded(decide(xfsz)) == (Outcome.EXHAUSTED, "proof_size")
    # a cap event outranks a deadline reached afterwards
    both = solve(None, signal.SIGKILL, (Cause.PROOF_CAP, Cause.DEADLINE), complete=False)
    assert recorded(decide(both)) == (Outcome.EXHAUSTED, "proof_size")
    later = solve(None, signal.SIGKILL, (Cause.DEADLINE, Cause.PROOF_CAP), complete=False)
    assert recorded(decide(later)) == (Outcome.EXHAUSTED, "proof_size")


def test_row2_an_unexpected_exit_without_a_cap_event_is_not_proof_size() -> None:
    # A file exactly at the cap is not evidence by itself (specification §6.3); only the event is.
    assert recorded(decide(solve(1, complete=False))) == (Outcome.TOOL_FAILED, "protocol")


def test_row3_solver_deadline_is_time_whatever_the_end() -> None:
    for exit_code, sig in ((None, signal.SIGTERM), (None, signal.SIGKILL), (20, None), (0, None)):
        decision = decide(solve(exit_code, sig, (Cause.DEADLINE,), complete=exit_code == 20))
        assert recorded(decision) == (Outcome.EXHAUSTED, "time")


def test_row4_check_deadline_outranks_checker_success() -> None:
    late_success = check(causes=(Cause.DEADLINE,))
    assert recorded(decide(solve(), [late_success])) == (Outcome.EXHAUSTED, "check_time")
    killed = check(None, signal.SIGKILL, "", causes=(Cause.DEADLINE,))
    assert recorded(decide(solve(), [killed])) == (Outcome.EXHAUSTED, "check_time")
    arena_late = check(1, None, "", p.ARENA["heap"][1].decode(), (Cause.DEADLINE,))
    assert recorded(decide(solve(), [arena_late])) == (Outcome.EXHAUSTED, "check_time")


@pytest.mark.parametrize(
    ("kind", "arena"),
    [("heap", (1024, 256)), ("stack", (512, 512)), ("both", (1024, 512))],
)
def test_row5_arena_exhaustion_retries_only_the_check(kind: str, arena: tuple[int, int]) -> None:
    decision = decide(solve(), [arena_check(kind)])
    assert decision.action is Action.RETRY_CHECK
    assert decision.arena == arena
    assert decision.outcome is None


@pytest.mark.parametrize(
    ("kind", "heap", "stack", "reason"),
    [
        ("heap", 8192, 256, "check_memory"),
        ("stack", 512, 2048, "check_stack"),
        ("both", 8192, 256, "check_memory"),
        ("both", 512, 2048, "check_stack"),
    ],
)
def test_row5_arena_beyond_the_maxima_is_exhausted(
    kind: str, heap: int, stack: int, reason: str
) -> None:
    decision = decide(solve(), [arena_check(kind, heap, stack)])
    assert recorded(decision) == (Outcome.EXHAUSTED, reason)


def test_row5_a_full_ladder_ends_exhausted() -> None:
    ladder = [arena_check("heap", h) for h in (512, 1024, 2048, 4096, 8192)]
    assert recorded(decide(solve(), ladder)) == (Outcome.EXHAUSTED, "check_memory")
    accepted = [*ladder[:3], check(heap=4096)]
    assert recorded(decide(solve(), accepted)) == (Outcome.VERIFIED_UNSAT, None)


def test_row5_preceding_checks_must_be_the_arena_ladder() -> None:
    with pytest.raises(ValueError):
        decide(solve(), [reject_check(), check()])
    with pytest.raises(ValueError):
        decide(solve(), [arena_check("heap", 512), check(heap=4096)])  # skipped a step
    with pytest.raises(ValueError):
        decide(solve(), [arena_check("stack", 512, 256), check(heap=1024, stack=256)])


def test_row5_success_with_an_arena_diagnostic_is_protocol() -> None:
    for kind in ("heap", "stack", "both"):
        code, message = p.ARENA[kind]
        contradictory = check(code, None, SUCCESS_STDOUT, message.decode())
        decision = decide(solve(), [contradictory])
        assert recorded(decision) == (Outcome.TOOL_FAILED, "protocol")
        exit0 = check(0, None, SUCCESS_STDOUT, message.decode())
        assert recorded(decide(solve(), [exit0])) == (Outcome.TOOL_FAILED, "protocol")


def test_row6_solver_memory_needs_the_pinned_diagnostic_or_an_event() -> None:
    message = p.CADICAL_BAD_ALLOC_STDERR.decode()
    bad_alloc = solve(None, signal.SIGABRT, stderr=message, complete=False)
    assert recorded(decide(bad_alloc)) == (Outcome.EXHAUSTED, "solver_memory")
    event = solve(None, signal.SIGKILL, (Cause.MEMORY_EVENT,), complete=False)
    assert recorded(decide(event)) == (Outcome.EXHAUSTED, "solver_memory")
    plain_abort = solve(None, signal.SIGABRT, complete=False)
    assert recorded(decide(plain_abort)) == (Outcome.TOOL_FAILED, "crash")
    oom_kill = solve(None, signal.SIGKILL, complete=False)
    assert recorded(decide(oom_kill)) == (Outcome.TOOL_FAILED, "crash")


@pytest.mark.parametrize("sig", ALL_SIGNALS)
def test_row7_a_solver_signal_alone_is_a_crash(sig: int) -> None:
    stderr = "CakeML heap space exhausted.\nout of memory\n"
    decision = decide(solve(None, sig, complete=False, stderr=stderr))
    if sig == signal.SIGXFSZ:
        assert recorded(decision) == (Outcome.EXHAUSTED, "proof_size")
    else:
        assert recorded(decision) == (Outcome.TOOL_FAILED, "crash")


@pytest.mark.parametrize("sig", ALL_SIGNALS)
def test_row7_a_checker_signal_is_a_crash_never_memory_or_rejection(sig: int) -> None:
    for stderr in ("", p.ARENA["heap"][1].decode(), p.ARENA["both"][1].decode()):
        for stdout in ("", SUCCESS_STDOUT):
            decision = decide(solve(), [check(None, sig, stdout, stderr)])
            assert recorded(decision) == (Outcome.TOOL_FAILED, "crash")


@pytest.mark.parametrize("code", [0, 1, 2, 3, 11, 30, 124, 127, 255])
def test_row7_unsupported_solver_exits_are_protocol(code: int) -> None:
    assert recorded(decide(solve(code, complete=False))) == (Outcome.TOOL_FAILED, "protocol")


def test_row7_exit_20_without_a_complete_proof_is_protocol() -> None:
    assert recorded(decide(solve(20, complete=False))) == (Outcome.TOOL_FAILED, "protocol")


@pytest.mark.parametrize("code", [1, 2, 3, 4, 5, 70, 255])
def test_row7_checker_exits_other_than_rejection_or_arena_are_protocol(code: int) -> None:
    decision = decide(solve(), [check(code, None, "", "c something\n")])
    assert recorded(decision) == (Outcome.TOOL_FAILED, "protocol")


def test_row7_output_held_open_by_a_descendant_is_protocol() -> None:
    held = check(causes=(Cause.HELD_OPEN,))
    assert recorded(decide(solve(), [held])) == (Outcome.TOOL_FAILED, "protocol")
    solver_held = solve(causes=(Cause.HELD_OPEN,))
    assert recorded(decide(solver_held)) == (Outcome.TOOL_FAILED, "protocol")


def test_row8_exit_10_goes_to_model_parsing() -> None:
    decision = decide(solve(10, complete=False))
    assert decision.action is Action.PARSE_MODEL
    assert decision.outcome is None
    # a model run never has checks
    with pytest.raises(ValueError):
        decide(solve(10, complete=False), [check()])


def test_row9_clean_rejections() -> None:
    assert recorded(decide(solve(), [reject_check()])) == (Outcome.CHECK_REJECTED, "rejected")
    for wrong in p.WRONG_SUCCESS_OUTPUTS:
        text = wrong.decode("utf-8", "replace")
        decision = decide(solve(), [check(0, None, text)])
        assert recorded(decision) == (Outcome.CHECK_REJECTED, "rejected"), wrong


def test_row11_truncated_checker_output_is_never_success_or_rejection() -> None:
    flood = check(0, None, "c noise\n" + SUCCESS_STDOUT, truncated=True)
    assert recorded(decide(solve(), [flood])) == (Outcome.TOOL_FAILED, "protocol")


def test_incomplete_checker_stderr_is_neither_success_nor_rejection() -> None:
    # An arena message could hide in the part of stderr that was not kept.
    for value in (result(stdout=SUCCESS_STDOUT), result(stderr="c Checking failed\n")):
        cut = CheckFacts(run=finished(value, stderr_truncated=True), heap_mib=512, stack_mib=256)
        assert recorded(decide(solve(), [cut])) == (Outcome.TOOL_FAILED, "protocol")


def test_checks_need_a_complete_proof() -> None:
    with pytest.raises(ValueError):
        decide(solve(20, complete=False), [check()])


# -- cancellation --------------------------------------------------------------------------------


def test_user_cancellation_gives_no_record() -> None:
    assert decide(solve(), [check()], cancelled=True).action is Action.NO_RECORD
    cancelled_solve = solve(None, signal.SIGTERM, (Cause.CANCELLED,), complete=False)
    assert decide(cancelled_solve).action is Action.NO_RECORD
    cancelled_check = check(None, signal.SIGKILL, "", causes=(Cause.CANCELLED,))
    assert decide(solve(), [cancelled_check]).action is Action.NO_RECORD
    # even after a supervisor limit or a failure: nothing was committed yet
    late = solve(None, signal.SIGKILL, (Cause.DEADLINE, Cause.CANCELLED), complete=False)
    assert decide(late).action is Action.NO_RECORD
    assert decide(solve(), [check()], (Failure.IO,), cancelled=True).action is Action.NO_RECORD


# -- secondary diagnostics ------------------------------------------------------------------------


def test_secondary_conditions_are_preserved() -> None:
    decision = decide(
        solve(None, signal.SIGKILL, (Cause.PROOF_CAP, Cause.DEADLINE), complete=False)
    )
    assert decision.reason == "proof_size"
    assert "solver:deadline" in decision.secondary
    assert "solver:signal:9" in decision.secondary
    decision = decide(solve(), [check()], (Failure.FILE_CHANGED,))
    assert "checker:accepted" in decision.secondary
    decision = decide(solve(), [check(1, None, SUCCESS_STDOUT, p.ARENA["heap"][1].decode())])
    assert "checker:arena:heap" in decision.secondary
    assert "checker:accepted" not in decision.secondary  # exit 1 is not acceptance


def test_decisions_carry_only_closed_reasons() -> None:
    from cubeproof.contracts.enums import REASONS

    samples = [
        decide(solve(None, signal.SIGXFSZ, complete=False)),
        decide(solve(None, signal.SIGSEGV, complete=False)),
        decide(solve(), [reject_check()]),
        decide(solve(), [arena_check("stack", 512, 2048)]),
        decide(solve(), [check()], (Failure.IO,)),
    ]
    for decision in samples:
        assert decision.outcome is not None
        assert decision.reason in REASONS[decision.outcome]
