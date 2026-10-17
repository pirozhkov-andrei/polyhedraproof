"""Exact checker acceptance, pinned arena diagnostics, heap/time fit and arena retries.

Specification §4.6/§4.8/§6.3: only ``tools.checker.accepts`` recognizes success, from exit 0, no
signal and the **full** stdout exactly ``s VERIFIED UNSAT\\n`` (17 bytes, not truncated).
Specification §6.3: the pinned cake_lpr arena diagnostics (message and exit code, the presets
of ``tests/fakes``) are heap, stack and combined allocation failure; combined doubles both
arenas; success plus a diagnostic is a contradiction. Specification §8.3: heap fit and check
time formulas with conservative rounding.
"""

from __future__ import annotations

import math
import signal

import pytest
from cp_tools_support import p, result

from cubeproof.contracts.policy import HeapFit
from cubeproof.tools import checker as ck
from cubeproof.tools.checker import Arena

SUCCESS = p.CHECKER_SUCCESS.decode()


def as_text(data: bytes) -> str:
    return data.decode("utf-8", "replace")


# -- accepts ---------------------------------------------------------------------------------


def test_the_exact_success_result_is_accepted() -> None:
    assert ck.SUCCESS_STDOUT == SUCCESS == "s VERIFIED UNSAT\n"
    assert ck.accepts(result(stdout=SUCCESS))


@pytest.mark.parametrize("stdout", p.WRONG_SUCCESS_OUTPUTS, ids=repr)
def test_every_wrong_success_output_is_refused(stdout: bytes) -> None:
    assert not ck.accepts(result(stdout=as_text(stdout), stdout_bytes=len(stdout)))


@pytest.mark.parametrize(
    "changes",
    [
        {"exit": 1},
        {"exit": None, "signal": signal.SIGKILL},
        {"started": False, "exit": None},
        {"truncated": True},
        {"stdout_bytes": 18},
        {"stdout_bytes": 16},
        {"stdout_bytes": 17 + 1024 * 1024},
    ],
    ids=repr,
)
def test_success_text_without_the_other_conditions_is_refused(changes: dict[str, object]) -> None:
    assert not ck.accepts(result(stdout=SUCCESS, **changes))  # type: ignore[arg-type]


def test_the_tail_must_equal_the_success_line_even_if_the_count_says_17() -> None:
    # A result read back from elsewhere may be inconsistent; equality, not containment.
    for tail in (
        "c\ns VERIFIED UNSAT\n",
        "s VERIFIED UNSAT\ns VERIFIED UNSAT\n",
        "xs VERIFIED UNSAT\n",
    ):
        assert not ck.accepts(result(stdout=tail, stdout_bytes=17))


def test_success_on_stderr_is_not_success() -> None:
    assert not ck.accepts(result(stdout="", stderr=SUCCESS))


def test_invalid_bytes_that_decode_near_the_success_line_are_refused() -> None:
    for raw in (b"s VERIFIED UNSAT\xff", b"\xffs VERIFIED UNSA\n", b"s VERIFIED UNSAT\n\xff"):
        assert not ck.accepts(result(stdout=as_text(raw), stdout_bytes=len(raw)))


def test_a_cause_does_not_make_a_result_unacceptable_by_itself() -> None:
    # Cause is diagnostic (specification §4.6); precedence over success is decided by the outcome
    # table.
    assert ck.accepts(result(stdout=SUCCESS, cause="deadline"))


# -- arena diagnostics -----------------------------------------------------------------------


@pytest.mark.parametrize("kind", ["heap", "stack", "both"])
def test_pinned_arena_diagnostics_are_recognized(kind: str) -> None:
    code, message = p.ARENA[kind]
    value = result(exit=code, stderr=message.decode())
    assert ck.arena_diagnostic(value) is Arena(kind)
    assert ck.exhausted_arena(message.decode()) is Arena(kind)


@pytest.mark.parametrize(
    ("stderr", "kind"),
    [
        ("CakeML heap space exhausted.\n", Arena.HEAP),
        ("CakeML stack space exhausted.\n", Arena.STACK),
        ("failed to allocate sufficient CakeML heap and stack space.\n", Arena.BOTH),
        ("heap exhausted", Arena.HEAP),
        ("Stack Overflow", Arena.STACK),
        ("heap space exhausted\nstack space exhausted\n", Arena.BOTH),
        ("c Checking failed at line: 3. Reason: pivot must be non-zero\n", None),
        ("", None),
        ("out of memory", None),
    ],
)
def test_the_exhausted_arena_patterns(stderr: str, kind: Arena | None) -> None:
    assert ck.exhausted_arena(stderr) is kind


@pytest.mark.parametrize(
    "value",
    [
        result(exit=2, stderr="CakeML heap space exhausted.\n"),  # code of another arena
        result(exit=0, stderr="CakeML heap space exhausted.\n"),
        result(exit=1, stderr=""),  # pinned exit code without the message
        result(exit=None, signal=signal.SIGSEGV, stderr="CakeML heap space exhausted.\n"),
        result(exit=None, signal=signal.SIGKILL),
        result(exit=None, signal=signal.SIGSEGV),
        result(started=False, exit=None),
    ],
    ids=["code-mismatch", "exit0", "no-message", "segv+message", "kill", "segv", "not-started"],
)
def test_no_arena_without_the_pinned_message_and_exit_code(value: object) -> None:
    assert ck.arena_diagnostic(value) is None  # type: ignore[arg-type]


def test_success_with_an_arena_message_is_a_contradiction() -> None:
    value = result(exit=1, stdout=SUCCESS, stderr="CakeML heap space exhausted.\n")
    assert ck.contradictory_success(value)
    assert ck.contradictory_success(result(exit=1, stdout="x", truncated=True))
    assert ck.contradictory_success(result(exit=1, stdout="c\ns VERIFIED UNSAT\nc\n"))
    assert not ck.contradictory_success(result(exit=1, stderr="CakeML heap space exhausted.\n"))


def test_clean_rejection_is_exit_zero_without_success_or_arena() -> None:
    reject = result(exit=0, stderr="c Checking failed at line: 0. Reason: x\n")
    assert ck.clean_rejection(reject)
    for wrong in p.WRONG_SUCCESS_OUTPUTS:
        assert ck.clean_rejection(result(exit=0, stdout=as_text(wrong), stdout_bytes=len(wrong)))
    assert not ck.clean_rejection(result(stdout=SUCCESS))
    assert not ck.clean_rejection(result(exit=0, stderr="CakeML stack space exhausted.\n"))
    assert not ck.clean_rejection(result(exit=1))
    assert not ck.clean_rejection(result(exit=None, signal=signal.SIGSEGV))
    assert not ck.clean_rejection(result(exit=0, truncated=True, stdout="c x\n"))


# -- command line ------------------------------------------------------------------------------


def test_checker_arguments_and_memory_cap() -> None:
    assert ck.checker_args(1024, 256, "/w/a.cnf", "/w/a.lrat") == (
        "--CML_HEAP_SIZE=1024",
        "--CML_STACK_SIZE=256",
        "/w/a.cnf",
        "/w/a.lrat",
    )
    assert ck.checker_memory_bytes(1024, 256, 256) == (1024 + 256 + 256) << 20
    with pytest.raises(ValueError):
        ck.checker_args(0, 256, "/a", "/b")
    with pytest.raises(ValueError):
        ck.checker_args(1, 256, "relative.cnf", "/b")


# -- heap and time fit (specification §8.3) -------------------------------------------------------

FIT = HeapFit()  # 3230/711/1500 milli, min 512 MiB


def float_estimate(proof_bytes: int, fit: HeapFit = FIT) -> float:
    return float(
        fit.margin_milli
        / 1000
        * fit.coefficient_milli
        / 1000
        * (proof_bytes / 1_000_000) ** (fit.exponent_milli / 1000)
    )


def reference_heap(proof_bytes: int, fit: HeapFit = FIT) -> int:
    """The specification §8.3 formula with exact rational comparison (independent of the module)."""
    m, c, e = fit.margin_milli, fit.coefficient_milli, fit.exponent_milli
    power = 1
    # smallest power of two P with P >= m*c/1e6 * (b/1e6)^(e/1000), i.e.
    # (P * 10^6)^1000 * 10^(6e) >= (m*c)^1000 * b^e
    while (power * 10**6) ** 1000 * 10 ** (6 * e) < (m * c) ** 1000 * proof_bytes**e:
        power *= 2
    return max(fit.min_mib, power)


@pytest.mark.parametrize(
    "proof_bytes",
    [0, 1, 999_999, 1_000_000, 10**7, 10**8, 123_456_789, 10**9, 4 * 2**30, 10**12],
)
def test_initial_heap_matches_the_exact_formula(proof_bytes: int) -> None:
    assert ck.initial_heap_mib(proof_bytes, FIT) == reference_heap(proof_bytes)


def boundary_bytes(power: int, fit: HeapFit) -> int:
    """The largest proof size whose estimate is still <= power (exact search)."""
    low, high = 0, 1
    while reference_heap(high, fit) <= power:
        high *= 2
    while high - low > 1:
        middle = (low + high) // 2
        if reference_heap(middle, fit) <= power:
            low = middle
        else:
            high = middle
    return low


@pytest.mark.parametrize("power", [1024, 2048, 4096, 8192])
def test_power_of_two_boundaries_round_up(power: int) -> None:
    fit = HeapFit(min_mib=1)
    last = boundary_bytes(power, fit)
    assert ck.initial_heap_mib(last, fit) == power
    assert ck.initial_heap_mib(last + 1, fit) == 2 * power
    # The float estimate is within a hair of the boundary there: rounding must not lose it.
    assert math.isclose(float_estimate(last + 1, fit), power, rel_tol=1e-6)


def test_exact_boundary_value_is_not_rounded_up() -> None:
    # margin 1, coefficient 1, exponent 1: estimate = b/1e6 exactly.
    fit = HeapFit(coefficient_milli=1000, exponent_milli=1000, margin_milli=1000, min_mib=1)
    assert ck.initial_heap_mib(1024 * 10**6, fit) == 1024
    assert ck.initial_heap_mib(1024 * 10**6 + 1, fit) == 2048
    assert ck.initial_heap_mib(1, fit) == 1


def test_min_mib_is_a_floor_even_when_not_a_power_of_two() -> None:
    fit = HeapFit(min_mib=700)
    assert ck.initial_heap_mib(0, fit) == 700
    assert ck.initial_heap_mib(10**12, fit) == reference_heap(10**12, fit)


def test_absurd_exponents_stay_finite_and_conservative() -> None:
    fit = HeapFit(exponent_milli=10**9)
    value = ck.initial_heap_mib(10**9, fit)
    assert value >= 2**62
    assert ck.initial_heap_mib(1, fit) == fit.min_mib


def test_heap_fit_refuses_negative_sizes() -> None:
    with pytest.raises(ValueError):
        ck.initial_heap_mib(-1, FIT)


@pytest.mark.parametrize(
    ("proof_bytes", "expected"),
    [
        (0, 600_000),
        (1, 600_000),
        (100_000_000, 600_000),
        (1_000_000_000, 600_000),
        (1_000_000_001, 660_000),
        (2_000_000_000, 1_200_000),
    ],
)
def test_check_time(proof_bytes: int, expected: int) -> None:
    assert ck.check_time_ms(proof_bytes, 600_000, 60_000) == expected


def test_check_time_ceiling_per_100mb() -> None:
    assert ck.check_time_ms(100_000_001, 1, 7) == 14
    assert ck.check_time_ms(200_000_000, 1, 7) == 14


# -- arena retries ---------------------------------------------------------------------------


def test_each_arena_doubles_only_itself() -> None:
    assert ck.next_arena(Arena.HEAP, 512, 256, max_heap_mib=8192, max_stack_mib=2048) == (
        ck.ArenaStep(retry=(1024, 256), reason=None)
    )
    assert ck.next_arena(Arena.STACK, 512, 256, max_heap_mib=8192, max_stack_mib=2048) == (
        ck.ArenaStep(retry=(512, 512), reason=None)
    )
    assert ck.next_arena(Arena.BOTH, 512, 256, max_heap_mib=8192, max_stack_mib=2048) == (
        ck.ArenaStep(retry=(1024, 512), reason=None)
    )


@pytest.mark.parametrize(
    ("arena", "heap", "stack", "reason"),
    [
        (Arena.HEAP, 8192, 256, "check_memory"),
        (Arena.HEAP, 4097, 256, "check_memory"),
        (Arena.STACK, 512, 2048, "check_stack"),
        (Arena.STACK, 512, 1025, "check_stack"),
        (Arena.BOTH, 8192, 256, "check_memory"),
        (Arena.BOTH, 512, 2048, "check_stack"),
        (Arena.BOTH, 8192, 2048, "check_memory"),
    ],
)
def test_no_retry_beyond_the_maxima(arena: Arena, heap: int, stack: int, reason: str) -> None:
    step = ck.next_arena(arena, heap, stack, max_heap_mib=8192, max_stack_mib=2048)
    assert step == ck.ArenaStep(retry=None, reason=reason)


def test_idle_machine_fit_can_refuse_a_retry() -> None:
    def fits(heap: int, stack: int) -> bool:
        return heap + stack <= 1024

    step = ck.next_arena(Arena.HEAP, 512, 256, max_heap_mib=8192, max_stack_mib=2048, fits=fits)
    assert step == ck.ArenaStep(retry=None, reason="check_memory")
    step = ck.next_arena(Arena.STACK, 256, 256, max_heap_mib=8192, max_stack_mib=2048, fits=fits)
    assert step == ck.ArenaStep(retry=(256, 512), reason=None)


def test_the_retry_ladder_is_bounded() -> None:
    heap, stack, steps = 512, 256, 0
    while True:
        step = ck.next_arena(Arena.BOTH, heap, stack, max_heap_mib=8192, max_stack_mib=2048)
        if step.retry is None:
            break
        heap, stack = step.retry
        steps += 1
        assert steps < 64
    # (512,256) -> (1024,512) -> (2048,1024) -> (4096,2048); (8192,4096) exceeds the stack max
    assert (heap, stack, steps) == (4096, 2048, 3)


def test_stream_retry_takes_at_least_the_fit_of_relay_bytes() -> None:
    fit = HeapFit()
    small = ck.next_stream_arena(
        Arena.HEAP, 512, 256, relay_bytes=0, fit=fit, max_heap_mib=8192, max_stack_mib=2048
    )
    assert small == ck.ArenaStep(retry=(1024, 256), reason=None)
    fitted = ck.initial_heap_mib(3 * 10**9, fit)
    assert fitted > 1024
    big = ck.next_stream_arena(
        Arena.HEAP, 512, 256, relay_bytes=3 * 10**9, fit=fit, max_heap_mib=2**20, max_stack_mib=2048
    )
    assert big == ck.ArenaStep(retry=(fitted, 256), reason=None)
    over = ck.next_stream_arena(
        Arena.HEAP, 512, 256, relay_bytes=3 * 10**9, fit=fit, max_heap_mib=1024, max_stack_mib=2048
    )
    assert over == ck.ArenaStep(retry=None, reason="check_memory")
    stack = ck.next_stream_arena(
        Arena.STACK, 512, 256, relay_bytes=3 * 10**9, fit=fit, max_heap_mib=8192, max_stack_mib=2048
    )
    assert stack == ck.ArenaStep(retry=(512, 512), reason=None)


def test_arena_inputs_are_validated() -> None:
    with pytest.raises(ValueError):
        ck.next_arena(Arena.HEAP, 0, 256, max_heap_mib=8192, max_stack_mib=2048)
    with pytest.raises(ValueError):
        ck.next_arena("heap", 512, 256, max_heap_mib=8192, max_stack_mib=2048)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        ck.next_arena(Arena.HEAP, 512, 256, max_heap_mib=0, max_stack_mib=2048)
