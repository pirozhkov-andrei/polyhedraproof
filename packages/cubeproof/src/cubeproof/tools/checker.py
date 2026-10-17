"""The pinned checker cake_lpr: exact success, arena diagnostics, arenas and fit.

Specification §4.6-§4.8, §5, §6.1, §6.3, §6.4 and §8.3.

**Only** :func:`accepts` recognizes checker success (specification §5): the process started, exited
0 without a signal, and its **full** stdout was exactly ``s VERIFIED UNSAT\\n`` (17 bytes,
nothing truncated). Tails are decoded with U+FFFD for invalid bytes, so 17 counted bytes
whose text equals the 17 ASCII characters can only be those bytes.

Arena diagnostics are the pinned cake_lpr's (asserted against the binary by the
image tests): heap ``CakeML heap space exhausted.`` with exit 1, stack ``CakeML stack space
exhausted.`` with exit 2, and the combined up-front allocation failure ``failed to allocate
sufficient CakeML heap and stack space.`` with exit 3. A diagnostic counts only together with the
pinned exit code of its arena and a normal exit (a signal is a crash, never memory; specification
§6.3).

A clean rejection is cake_lpr's documented rejection: exit 0, no arena message, complete
stdout that is not the success line. Other exits are an unsupported exit protocol.

Arena retries (specification §6.1 step 4, §6.3, §6.4): the exhausted arena doubles (both for the
combined diagnostic) while within the configured maxima and the idle-machine fit; otherwise the
attempt is EXHAUSTED ``check_memory`` (heap) or ``check_stack``. Doubling never clamps to the
maximum, so the ladder is finite. Heap fit and check time follow specification §8.3 exactly; the
heap estimate is rounded up with an exact integer comparison at power-of-two boundaries.
"""

from __future__ import annotations

import enum
import math
import re
from collections.abc import Callable
from dataclasses import dataclass

from cubeproof.base.process import ProcessResult
from cubeproof.contracts.policy import HeapFit
from cubeproof.contracts.primitives import SUCCESS_LINE

#: The only checker stdout that authorizes VERIFIED_UNSAT.
SUCCESS_STDOUT = SUCCESS_LINE
SUCCESS_BYTES = len(SUCCESS_LINE.encode("ascii"))
#: cake_lpr rejects a proof with exit 0 and an empty stdout.
REJECTION_EXIT = 0
MIB = 1 << 20


class Arena(str, enum.Enum):
    HEAP = "heap"
    STACK = "stack"
    BOTH = "both"


#: Exit code of the pinned cake_lpr for each arena diagnostic.
ARENA_EXIT: dict[Arena, int] = {Arena.HEAP: 1, Arena.STACK: 2, Arena.BOTH: 3}

_HEAP_EXHAUSTED = re.compile(r"heap(?: space)? exhausted", re.I)
_STACK_EXHAUSTED = re.compile(r"stack(?: space)? exhausted|stack overflow", re.I)
_BOTH_ARENAS = re.compile(r"allocate.*heap and stack", re.I | re.S)
_SUCCESS_MARK = "s VERIFIED UNSAT"


def accepts(result: ProcessResult) -> bool:
    """Exact checker success of one run (specification §4.8 success.checker_output)."""
    return (
        result.started
        and result.exit == 0
        and result.signal is None
        and not result.stdout_truncated
        and result.stdout_bytes == SUCCESS_BYTES
        and result.stdout_tail == SUCCESS_STDOUT
    )


def exhausted_arena(stderr: str) -> Arena | None:
    """Which arena a checker message names, or None."""
    if _BOTH_ARENAS.search(stderr):
        return Arena.BOTH
    heap = _HEAP_EXHAUSTED.search(stderr) is not None
    stack = _STACK_EXHAUSTED.search(stderr) is not None
    if heap and stack:
        return Arena.BOTH
    if stack:
        return Arena.STACK
    if heap:
        return Arena.HEAP
    return None


def arena_diagnostic(result: ProcessResult) -> Arena | None:
    """The pinned arena diagnostic: its message together with its exit code, no signal."""
    if not result.started or result.signal is not None or result.exit is None:
        return None
    arena = exhausted_arena(result.stderr_tail)
    if arena is None or ARENA_EXIT[arena] != result.exit:
        return None
    return arena


def contradictory_success(result: ProcessResult) -> bool:
    """True if stdout may claim success: a success mark, or output not completely known."""
    return result.stdout_truncated or _SUCCESS_MARK in result.stdout_tail


def clean_rejection(result: ProcessResult) -> bool:
    """cake_lpr's normal unsuccessful result: exit 0, known stdout, no success, no arena."""
    return (
        result.started
        and result.exit == REJECTION_EXIT
        and result.signal is None
        and not result.stdout_truncated
        and not accepts(result)
        and exhausted_arena(result.stderr_tail) is None
    )


# -- command line ------------------------------------------------------------------------------


def _arena_value(name: str, value: object) -> int:
    if type(value) is not int or value < 1:
        raise ValueError(f"{name} must be a positive integer, not {value!r}")
    return value


def checker_args(heap_mib: int, stack_mib: int, cnf: str, proof: str) -> tuple[str, ...]:
    """cake_lpr arguments: arenas first, then the CNF and the proof (absolute paths)."""
    heap = _arena_value("heap_mib", heap_mib)
    stack = _arena_value("stack_mib", stack_mib)
    for path in (cnf, proof):
        if not isinstance(path, str) or not path.startswith("/") or "\0" in path:
            raise ValueError(f"checker input {path!r} is not an absolute path")
    return (f"--CML_HEAP_SIZE={heap}", f"--CML_STACK_SIZE={stack}", cnf, proof)


def checker_memory_bytes(heap_mib: int, stack_mib: int, slack_mib: int) -> int:
    """The checker's address-space cap: heap + stack + slack (MiB to bytes)."""
    total = sum(
        _arena_value(n, v)
        for n, v in (("heap", heap_mib), ("stack", stack_mib), ("slack", slack_mib))
    )
    return total * MIB


# -- heap and time fit (specification §8.3) --------------------------------------------------------

#: Beyond this exponent (milli) the exact comparison is too costly; a float bound is used.
_EXACT_EXPONENT_LIMIT = 4000
#: Estimates above 2^62 MiB are reported as 2^62: larger than any configurable heap.
_HEAP_CEILING_LOG2 = 62


def _covers(power: int, proof_bytes: int, fit: HeapFit) -> bool:
    """power >= margin*coefficient*(proof_bytes/1e6)^exponent, decided exactly.

    With m, c, e the milli values: P >= (m c / 10^6) (b / 10^6)^(e/1000)
    <=> (P 10^6)^1000 * 10^(6e) >= (m c)^1000 * b^e  (all integers, both sides >= 0).
    """
    m, c, e = fit.margin_milli, fit.coefficient_milli, fit.exponent_milli
    left: int = (power * 10**6) ** 1000 * 10 ** (6 * e)
    right: int = (m * c) ** 1000 * proof_bytes**e
    return left >= right


def initial_heap_mib(proof_bytes: int, fit: HeapFit) -> int:
    """max(min_mib, smallest power of two >= ceil(margin*coef*(bytes/1e6)^exponent)) MiB."""
    if type(proof_bytes) is not int or proof_bytes < 0:
        raise ValueError(f"proof size {proof_bytes!r} is not a nonnegative integer")
    if proof_bytes == 0:
        return fit.min_mib
    m, c, e = fit.margin_milli, fit.coefficient_milli, fit.exponent_milli
    log2_estimate = math.log2(m * c / 1e6) + (e / 1000) * math.log2(proof_bytes / 1e6)
    if log2_estimate > _HEAP_CEILING_LOG2:
        return max(fit.min_mib, 1 << _HEAP_CEILING_LOG2)
    if log2_estimate < -64:
        return fit.min_mib
    # A power of two P covers the estimate iff P >= estimate (P is an integer, so this is
    # also P >= ceil(estimate)). Start one below the float guess and step up exactly.
    exponent = max(0, math.ceil(log2_estimate) - 1)
    if e <= _EXACT_EXPONENT_LIMIT:
        while not _covers(1 << exponent, proof_bytes, fit):
            exponent += 1
        while exponent > 0 and _covers(1 << (exponent - 1), proof_bytes, fit):
            exponent -= 1
    else:
        # Float only: keep one extra power of two of margin against rounding (conservative).
        exponent = min(_HEAP_CEILING_LOG2, math.ceil(log2_estimate) + 1)
    return max(fit.min_mib, 1 << exponent)


def check_time_ms(proof_bytes: int, base_ms: int, per_100mb_ms: int) -> int:
    """max(base_ms, ceil(proof_bytes / 10^8) * per_100mb_ms) (specification §8.3)."""
    if type(proof_bytes) is not int or proof_bytes < 0:
        raise ValueError(f"proof size {proof_bytes!r} is not a nonnegative integer")
    blocks = -(-proof_bytes // 100_000_000)
    return max(base_ms, blocks * per_100mb_ms)


# -- arena retries ---------------------------------------------------------------------------

Fits = Callable[[int, int], bool]


@dataclass(frozen=True)
class ArenaStep:
    """The next arenas ``(heap_mib, stack_mib)`` to try, or the EXHAUSTED reason."""

    retry: tuple[int, int] | None
    reason: str | None


def _reason(arena: Arena, heap_over: bool, stack_over: bool) -> str:
    if arena is Arena.STACK or (arena is Arena.BOTH and stack_over and not heap_over):
        return "check_stack"
    return "check_memory"


def _step(
    arena: Arena,
    heap: int,
    stack: int,
    max_heap_mib: int,
    max_stack_mib: int,
    fits: Fits | None,
) -> ArenaStep:
    heap_over = heap > max_heap_mib
    stack_over = stack > max_stack_mib
    if heap_over or stack_over:
        return ArenaStep(retry=None, reason=_reason(arena, heap_over, stack_over))
    if fits is not None and not fits(heap, stack):
        return ArenaStep(retry=None, reason=_reason(arena, False, False))
    return ArenaStep(retry=(heap, stack), reason=None)


def _validate(arena: object, heap: int, stack: int, max_heap: int, max_stack: int) -> Arena:
    if not isinstance(arena, Arena):
        raise ValueError(f"{arena!r} is not an Arena")
    for name, value in (
        ("heap_mib", heap),
        ("stack_mib", stack),
        ("max_heap_mib", max_heap),
        ("max_stack_mib", max_stack),
    ):
        _arena_value(name, value)
    return arena


def next_arena(
    arena: Arena,
    heap_mib: int,
    stack_mib: int,
    *,
    max_heap_mib: int,
    max_stack_mib: int,
    fits: Fits | None = None,
) -> ArenaStep:
    """File-mode retry after an arena diagnostic: double the exhausted arena(s)."""
    kind = _validate(arena, heap_mib, stack_mib, max_heap_mib, max_stack_mib)
    heap = heap_mib * 2 if kind in (Arena.HEAP, Arena.BOTH) else heap_mib
    stack = stack_mib * 2 if kind in (Arena.STACK, Arena.BOTH) else stack_mib
    return _step(kind, heap, stack, max_heap_mib, max_stack_mib, fits)


def next_stream_arena(
    arena: Arena,
    heap_mib: int,
    stack_mib: int,
    *,
    relay_bytes: int,
    fit: HeapFit,
    max_heap_mib: int,
    max_stack_mib: int,
    fits: Fits | None = None,
) -> ArenaStep:
    """Stream retry (specification §6.4): at least double, and for heap at least the fit of relay
    bytes."""
    kind = _validate(arena, heap_mib, stack_mib, max_heap_mib, max_stack_mib)
    heap = heap_mib
    if kind in (Arena.HEAP, Arena.BOTH):
        heap = max(heap_mib * 2, initial_heap_mib(relay_bytes, fit))
    stack = stack_mib * 2 if kind in (Arena.STACK, Arena.BOTH) else stack_mib
    return _step(kind, heap, stack, max_heap_mib, max_stack_mib, fits)
