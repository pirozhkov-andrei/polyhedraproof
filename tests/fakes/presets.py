"""Fakes of the pinned solver and checker, with the observable behaviour of the real ones.

The constants below are what the pinned binaries actually print and return (CaDiCaL 3.0.1
at c6073042, cake_lpr at a36874a8, built from docker/test/tools.json); the image tests in
tests/image/test_presets_match_tools.py run the real binaries and compare. Argument
conventions are those of the binaries: the solver gets ``[options..., CNF, PROOF]`` (the
proof path last), the checker ``[--CML_HEAP_SIZE=N, --CML_STACK_SIZE=M, CNF, PROOF]``.

A preset is a list of steps; pass it to ``toolkit.make_tool`` or extend it.

Relay presets stand in for the stream relay (specification §6.4) only as a byte mover with a
test-chosen report: how the real relay receives its endpoints and reports its record is the
stream implementation's contract, not fixed here. ``relay_report`` encodes the fields of
the attempt's ``relay`` record (specification §4.8) for tests that need a report to emit.
"""

from __future__ import annotations

import json
from collections.abc import Sequence

from . import toolkit as fk
from .toolkit import Step, Target

#: The only checker output that may authorise VERIFIED_UNSAT (specification §4.8, §6.3).
CHECKER_SUCCESS = b"s VERIFIED UNSAT\n"
#: cake_lpr's arena diagnostics on stderr and its exit codes (stdout empty).
CAKE_HEAP_EXHAUSTED = (1, b"CakeML heap space exhausted.\n")
CAKE_STACK_EXHAUSTED = (2, b"CakeML stack space exhausted.\n")
CAKE_ALLOCATION_FAILED = (
    3,
    b"failed to allocate sufficient CakeML heap and stack space.\nmalloc: Cannot allocate memory\n",
)
ARENA = {"heap": CAKE_HEAP_EXHAUSTED, "stack": CAKE_STACK_EXHAUSTED, "both": CAKE_ALLOCATION_FAILED}
#: cake_lpr rejecting a proof: exit 0, empty stdout, one ``c`` line on stderr.
CAKE_REJECTION_EXIT = 0
#: CaDiCaL: exit codes, its ``-q`` status lines, its reaction to TERM and to allocation failure.
SOLVER_SAT = 10
SOLVER_UNSAT = 20
CADICAL_UNSAT_STDOUT = b"s UNSATISFIABLE\n"
CADICAL_TERM_STDOUT = b"c UNKNOWN\n"
CADICAL_BAD_ALLOC_STDERR = (
    b"terminate called after throwing an instance of 'std::bad_alloc'\n  what():  std::bad_alloc\n"
)

#: Outputs that resemble success but are not exactly CHECKER_SUCCESS (each with exit 0).
WRONG_SUCCESS_OUTPUTS: tuple[bytes, ...] = (
    b"",
    b"s VERIFIED UNSAT",
    b"s VERIFIED UNSAT\n\n",
    b"s VERIFIED UNSAT\r\n",
    b" s VERIFIED UNSAT\n",
    b"s VERIFIED UNSAT \n",
    b"s  VERIFIED UNSAT\n",
    b"s verified unsat\n",
    b"s VERIFIED SAT\n",
    b"s VERIFIED UNSAT\ns VERIFIED UNSAT\n",
    b"c checking\ns VERIFIED UNSAT\n",
    b"s VERIFIED UNSAT\nc done\n",
    b"s VERIFIED UNSAT\x00\n",
    b"s VERIFIED UNSA\n",
    b"s UNSATISFIABLE\n",
)


def _stdout(data: bytes) -> list[Step]:
    return [fk.write(fk.STDOUT, data=data)] if data else []


def _stderr(data: bytes) -> list[Step]:
    return [fk.write(fk.STDERR, data=data)] if data else []


# -- solver -------------------------------------------------------------------------------


def solver_unsat(proof: bytes, *, proof_target: Target | None = None) -> list[Step]:
    """Write a complete proof, print ``s UNSATISFIABLE``, exit 20."""
    return [
        fk.write(proof_target or fk.arg(-1), data=proof),
        *_stdout(CADICAL_UNSAT_STDOUT),
        fk.exit_(SOLVER_UNSAT),
    ]


def solver_sat(literals: Sequence[int]) -> list[Step]:
    """Print a model (``s``/``v`` lines as CaDiCaL ``-q`` does) and exit 10."""
    text = "s SATISFIABLE\nv " + " ".join([*map(str, literals), "0"]) + "\n"
    return [fk.write(fk.STDOUT, text), fk.exit_(SOLVER_SAT)]


def solver_output(stdout: bytes, code: int, *, stderr: bytes = b"") -> list[Step]:
    """Any status output (also malformed models) with any exit code."""
    return [*_stdout(stdout), *_stderr(stderr), fk.exit_(code)]


def solver_brute_force(cnf: Target | None = None) -> list[Step]:
    """Solve a tiny formula exactly: a model and exit 10, or exit 20 without a proof."""
    return [fk.model(cnf or fk.arg(-2))]


def solver_partial_proof(proof: bytes, keep: int, *, then: Sequence[Step]) -> list[Step]:
    """Write only the first `keep` bytes of `proof`, then do `then` (exit 20, a signal...)."""
    return [fk.write(fk.arg(-1), data=proof[:keep]), *then]


def solver_proof_flood(size: int, *, chunk: int = 1 << 20) -> list[Step]:
    """Write `size` bytes of LRAT-looking text as the proof, then claim UNSAT.

    Under ``prlimit --fsize`` below `size` the fake dies of SIGXFSZ, as CaDiCaL does.
    """
    return [
        fk.write(fk.arg(-1), "1 0 1 0\n", size=size, chunk=chunk),
        *_stdout(CADICAL_UNSAT_STDOUT),
        fk.exit_(SOLVER_UNSAT),
    ]


def solver_out_of_memory() -> list[Step]:
    """CaDiCaL's allocation failure: the C++ runtime message, then SIGABRT."""
    return [*_stderr(CADICAL_BAD_ALLOC_STDERR), fk.kill_self("ABRT")]


def solver_until_terminated(seconds: float = 60.0, *, ready: str | None = None) -> list[Step]:
    """Run until TERM, then print ``c UNKNOWN`` and die of TERM (CaDiCaL ``-q``)."""
    steps = [fk.trap("TERM", _stdout(CADICAL_TERM_STDOUT), then="die")]
    if ready is not None:
        steps.append(fk.touch(ready))
    return [*steps, fk.sleep(seconds)]


def solver_ignoring_term(seconds: float = 60.0, *, ready: str | None = None) -> list[Step]:
    """Ignore TERM (so only KILL ends it) and sleep."""
    steps = [fk.trap("TERM", then="continue")]
    if ready is not None:
        steps.append(fk.touch(ready))
    return [*steps, fk.sleep(seconds)]


def solver_with_grandchild(
    pid_file: str, seconds: float = 60.0, *, setsid: bool = False
) -> list[Step]:
    """Leave a sleeping grandchild behind (its pid in `pid_file`), then sleep."""
    return [fk.spawn([fk.sleep(seconds)], setsid=setsid, pid_file=pid_file), fk.sleep(seconds)]


# -- checker ------------------------------------------------------------------------------


def checker_output(stdout: bytes, code: int = 0, *, stderr: bytes = b"") -> list[Step]:
    """Read the whole proof, then print exactly `stdout`/`stderr` and exit `code`."""
    return [fk.read(fk.arg(-1)), *_stdout(stdout), *_stderr(stderr), fk.exit_(code)]


def checker_accept() -> list[Step]:
    """The exact success line and exit 0, after reading the whole proof."""
    return checker_output(CHECKER_SUCCESS)


def checker_reject(reason: str = "pivot must be non-zero", line: int = 0) -> list[Step]:
    """cake_lpr's rejection: exit 0, nothing on stdout, a ``c Checking failed`` line."""
    message = f"c Checking failed at line: {line}. Reason: {reason}\n".encode()
    return checker_output(b"", CAKE_REJECTION_EXIT, stderr=message)


def checker_arena(kind: str) -> list[Step]:
    """cake_lpr out of its heap, its stack, or unable to allocate both (``both``)."""
    code, message = ARENA[kind]
    return [*_stderr(message), fk.exit_(code)]


def checker_success_with_arena(kind: str = "heap") -> list[Step]:
    """Contradictory: the success line together with an arena diagnostic, exit 0."""
    return checker_output(CHECKER_SUCCESS, 0, stderr=ARENA[kind][1])


def checker_crash(name: str = "SEGV") -> list[Step]:
    return [fk.read(fk.arg(-1)), fk.kill_self(name)]


def checker_alters(target: str, *, action: str = "append") -> list[Step]:
    """Change the CNF (``"cnf"``) or the proof (``"proof"``), then claim success."""
    victim = fk.arg(-2) if target == "cnf" else fk.arg(-1)
    return [fk.read(fk.arg(-1)), fk.alter(victim, action), *_stdout(CHECKER_SUCCESS), fk.exit_(0)]


def checker_stops_reading(after: int, then: Sequence[Step]) -> list[Step]:
    """Read only `after` bytes of the proof (a FIFO in stream mode), close it, do `then`."""
    return [fk.read(fk.arg(-1), limit=after, close=True), *then]


def checker_lrat() -> list[Step]:
    """Check with the independent test validator; answer as cake_lpr would (test-only)."""
    return [fk.lrat_check()]


def checker_flood(size: int, *, to: str = fk.STDOUT) -> list[Step]:
    """Print `size` bytes of noise on stdout (or stderr), then the success line."""
    return [
        fk.read(fk.arg(-1)),
        fk.write(to, "c noise\n", size=size),
        *_stdout(CHECKER_SUCCESS),
        fk.exit_(0),
    ]


# -- relay --------------------------------------------------------------------------------

#: The fields of an attempt's ``relay`` record, in specification §4.8 order.
RELAY_FIELDS = ("bytes", "sha256", "solver_eof", "all_written", "error")


def relay_report(
    count: int, sha256: str, *, solver_eof: bool, all_written: bool, error: str | None = None
) -> bytes:
    """One JSON line with exactly the ``relay`` record fields (specification §4.8).

    A test may emit it truthfully or falsely (``all_written`` without the bytes, a wrong hash);
    the fake does not check it. The transport of the real relay's report is the stream
    implementation's contract.
    """
    if count < 0 or len(sha256) != 64:
        raise ValueError("bytes must be nonnegative and sha256 64 hex digits")
    record = {
        "bytes": count,
        "sha256": sha256,
        "solver_eof": solver_eof,
        "all_written": all_written,
        "error": error,
    }
    return (json.dumps(record, separators=(",", ":")) + "\n").encode()


def relay_copy(
    source: Target = fk.STDIN,
    sink: Target = fk.STDOUT,
    *,
    limit: int | None = None,
    flip_at: int | None = None,
    chunk: int | None = None,
    pause: float | None = None,
    report: bytes = b"",
    report_to: Target = fk.STDERR,
    code: int = 0,
) -> list[Step]:
    """Move bytes from `source` to `sink` until EOF (or `limit` bytes), then report and exit.

    `flip_at` corrupts one byte in transit (the ``pipe`` event hashes the bytes read, before
    the flip); `chunk`/`pause` make a slow relay. `report` bytes go to `report_to` after the
    transfer. A closed sink kills the fake by SIGPIPE, as it would kill a C program.
    """
    return [
        fk.pipe(source, sink, limit=limit, flip_at=flip_at, chunk=chunk, pause=pause),
        *([fk.write(report_to, data=report)] if report else []),
        fk.exit_(code),
    ]


def relay_breaks(
    after: int, then: Sequence[Step], *, source: Target = fk.STDIN, sink: Target = fk.STDOUT
) -> list[Step]:
    """Move only `after` bytes, then do `then` (an exit code, a signal, a hang...)."""
    return [fk.pipe(source, sink, limit=after), *then]
