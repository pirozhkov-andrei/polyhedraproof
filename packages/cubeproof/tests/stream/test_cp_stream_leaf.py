"""The stream leaf wired into the attempt and the binding (specification §4.8, §5, §6.3-§6.5).

A CDCL leaf under a stream policy runs solver -> relay -> checker (``leaf.stream``) inside
:class:`~cubeproof.leaf.attempt.LeafAttempt` and its record is built by ``leaf.binding``, the
only constructor of VERIFIED_UNSAT. A unit refutation under the same policy follows the file
protocol. Every test runs the real attempt with the fake tools under the real supervisor, the
real relay process and the in-process I/O service of the leaf tests with a real journal writer
behind it.

The binding tests take the evidence of a real coupled run and change one fact at a time: only
a complete transfer of a clean exit-20 solve, checked with the exact success line on the
unchanged CNF by the pinned tools and the pinned relay interpreter, binds as VERIFIED_UNSAT.
"""

from __future__ import annotations

import dataclasses
import sys
import time
from collections.abc import Callable, Iterator, Sequence
from pathlib import Path
from typing import Any

import pytest

HERE = Path(__file__).resolve().parent
if str(HERE.parent / "leaf") not in sys.path:
    sys.path.insert(0, str(HERE.parent / "leaf"))

from cp_leaf_support import (  # noqa: E402, F401 - fixtures are registered by import
    SAT,
    TINY,
    TINY_PROOFS,
    Bench,
    isolation_fixture,
    make_policy,
    make_tool,
    op_trace,
    p,
    report_hash,
    sha,
    supervisor_fixture,
)

from cubeproof.base.errors import ConfigurationError  # noqa: E402
from cubeproof.base.ids import new_id128  # noqa: E402
from cubeproof.base.process import Cause  # noqa: E402
from cubeproof.cnf.cube import node_of  # noqa: E402
from cubeproof.cnf.cubecnf import CnfDigest, cube_cnf_bytes  # noqa: E402
from cubeproof.contracts.enums import Outcome, ProofMode, Route  # noqa: E402
from cubeproof.contracts.io import Op  # noqa: E402
from cubeproof.contracts.policy import Policy  # noqa: E402
from cubeproof.evidence.certify.admission import success_problem  # noqa: E402
from cubeproof.leaf.attempt import LeafAttempt, LeafTools, Phase  # noqa: E402
from cubeproof.leaf.binding import (  # noqa: E402
    AttemptIdentity,
    BindingError,
    CheckEvidence,
    FileHash,
    RelayEvidence,
    SolveEvidence,
    StreamEvidence,
    ToolPins,
    bind_outcome,
    bind_stream_verified,
    model_capture_bytes,
)
from cubeproof.leaf.quarantine import QuarantineLedger  # noqa: E402
from cubeproof.leaf.retry import (  # noqa: E402
    RetryAction,
    initial_stream_arena,
    next_stream_attempt,
)
from cubeproof.leaf.stream import (  # noqa: E402
    Role,
    StreamPlan,
    StreamRun,
    StreamTools,
    stream_paths,
)
from cubeproof.tools import relay as rl  # noqa: E402
from cubeproof.tools.isolation import PinnedBinary  # noqa: E402
from cubeproof.tools.process import Supervisor  # noqa: E402

pytestmark = pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux only")

#: The CDCL route: unit propagation of TINY under ``(3,)`` decides nothing.
CDCL_CUBE = (3,)
#: The unit route: ``(1,)`` propagates x2 and -x2, a unit refutation.
UNIT_CUBE = (1,)
STREAM = make_policy(proof_mode=ProofMode.STREAM)
SUCCESS = b"s VERIFIED UNSAT\n"
#: A solver that writes a valid LRAT refutation of TINY under one cube literal and exits 20.
UNSAT_SOLVER = p.solver_unsat(TINY_PROOFS[0])


def python_pin() -> PinnedBinary:
    """The relay interpreter: this test's interpreter, measured like the coordinator does."""
    return PinnedBinary.measure(sys.executable)


@pytest.fixture
def make(tmp_path: Path, supervisor: Supervisor) -> Iterator[Callable[..., Bench]]:
    """A bench in stream mode whose leaf tools carry the pinned relay interpreter."""
    benches: list[Bench] = []

    def factory(**options: Any) -> Bench:
        options.setdefault("policy", STREAM)
        # the brute-force fake solver exits 20 without writing a proof: a CDCL leaf needs one
        options.setdefault("solver", UNSAT_SOLVER)
        bench = Bench(tmp_path / f"b{len(benches)}", supervisor, **options)
        bench.tools = dataclasses.replace(bench.tools, python=python_pin())
        benches.append(bench)
        return bench

    yield factory
    for bench in benches:
        bench.close()


def hashed_names(bench: Bench, attempt: LeafAttempt) -> list[str]:
    return [name for op, name in op_trace(bench.io, attempt.attempt_id) if op == Op.HASH.value]


# -- the attempt -----------------------------------------------------------------------------------


def test_a_cdcl_leaf_under_stream_commits_a_verified_stream_record(make: Any) -> None:
    bench = make()
    attempt, record = bench.one(TINY, CDCL_CUBE)
    assert attempt.phase is Phase.DONE
    assert (record["outcome"], record["reason"]) == ("VERIFIED_UNSAT", None)
    assert (record["route"], record["proof_mode"]) == ("cdcl", "stream")
    relay = record["relay"]
    assert relay is not None
    assert (relay["solver_eof"], relay["all_written"], relay["error"]) == (True, True, None)
    # the relay's count and hash of a complete transfer are the proof fields (specification §4.8,
    # §6.4)
    assert (record["proof_bytes"], record["proof_sha256"]) == (relay["bytes"], relay["sha256"])
    assert relay["bytes"] > 0
    (check,) = record["checks"]
    assert (check["heap_mib"], check["stack_mib"]) == initial_stream_arena(STREAM)
    assert check["result"]["stdout_tail"] == SUCCESS.decode()
    assert record["solver"]["exit"] == 20 and record["solver"]["started"] is True
    # no proof reached a file check: the recorded check time is the policy base value
    assert record["limits"]["check_time_ms"] == STREAM.checker_time_base_ms
    assert record["retained"] is None and record["quarantined"] is None
    assert success_problem(record) is None
    # nothing was spooled: no proof file was ever hashed, only the CNF
    assert all(not name.endswith(".lrat") for name in hashed_names(bench, attempt))
    assert bench.work_files() == []


def test_the_stream_proof_hash_is_the_hash_of_what_the_solver_wrote(make: Any) -> None:
    proof = b"6 1 0 1 2 0\n7 0 6 3 4 0\n"
    bench = make(solver=p.solver_unsat(proof))
    _, record = bench.one(TINY, CDCL_CUBE)
    assert record["outcome"] == "VERIFIED_UNSAT"
    assert (record["proof_bytes"], record["proof_sha256"]) == (len(proof), sha(proof))


def test_a_unit_refutation_under_stream_follows_the_file_protocol(make: Any) -> None:
    bench = make()
    attempt, record = bench.one(TINY, UNIT_CUBE)
    assert (record["outcome"], record["route"]) == ("VERIFIED_UNSAT", "unit")
    assert record["proof_mode"] == "stream"
    assert record["relay"] is None and record["solver"] is None
    # the small unit proof is a sealed file, hashed by the I/O service and checked from disk
    assert f"{attempt.node_id}-{attempt.attempt_id}.lrat" in hashed_names(bench, attempt)
    assert success_problem(record) is None
    assert bench.work_files() == []


def test_a_stream_arena_exhaustion_is_recorded_with_its_raw_results(make: Any) -> None:
    bench = make(checker=p.checker_arena("heap"))
    attempt, record = bench.one(TINY, CDCL_CUBE)
    assert (record["outcome"], record["reason"]) == ("EXHAUSTED", "check_memory")
    (check,) = record["checks"]
    assert (check["heap_mib"], check["stack_mib"]) == initial_stream_arena(STREAM)
    assert "heap" in check["result"]["stderr_tail"]
    assert record["proof_bytes"] is None and record["proof_sha256"] is None
    assert record["relay"] is not None
    assert bench.work_files() == []
    # the record alone calls for a fresh attempt with at least twice the exhausted heap
    assert attempt.record is not None
    heap, stack = initial_stream_arena(STREAM)
    assert next_stream_attempt(attempt.record, STREAM) == RetryAction(2 * heap, stack)


def test_a_fresh_attempt_runs_with_the_derived_arena(make: Any) -> None:
    bench = make()
    heap, stack = initial_stream_arena(STREAM)
    _, record = bench.one(TINY, CDCL_CUBE, stream_arena=(2 * heap, 2 * stack))
    assert record["outcome"] == "VERIFIED_UNSAT"
    (check,) = record["checks"]
    assert (check["heap_mib"], check["stack_mib"]) == (2 * heap, 2 * stack)


@pytest.mark.parametrize("which", ["below_policy", "above_maxima"])
def test_an_arena_outside_the_ladder_is_refused_up_front(make: Any, which: str) -> None:
    bench = make()
    heap, stack = initial_stream_arena(STREAM)
    arena = (
        (heap // 2, stack) if which == "below_policy" else (2 * STREAM.checker_max_heap_mib, stack)
    )
    with pytest.raises(ValueError):
        bench.attempt(TINY, CDCL_CUBE, stream_arena=arena)


def test_a_file_mode_attempt_takes_no_stream_arena(make: Any) -> None:
    bench = make(policy=make_policy())
    with pytest.raises(ValueError):
        bench.attempt(TINY, CDCL_CUBE, stream_arena=initial_stream_arena(STREAM))


def test_a_rejected_stream_has_a_metadata_only_quarantine(make: Any) -> None:
    bench = make(checker=p.checker_reject())
    ledger = QuarantineLedger(STREAM.quarantine_quota_bytes)
    _, record = bench.one(TINY, CDCL_CUBE, quarantine=ledger)
    assert (record["outcome"], record["reason"]) == ("CHECK_REJECTED", "rejected")
    assert record["quarantined"] is None
    assert record["diagnostics"]["quarantine_unavailable"] == "stream_not_spooled"
    relay = record["relay"]
    assert (record["proof_bytes"], record["proof_sha256"]) == (relay["bytes"], relay["sha256"])
    assert not any(job.op is Op.PUBLISH for job in bench.io.jobs)
    assert bench.work_files() == []


def test_a_stream_model_is_parsed_and_carries_the_relay(make: Any) -> None:
    bench = make(solver=p.solver_sat([1, -2, 3]))
    _, record = bench.one(SAT, ())
    assert (record["outcome"], record["route"]) == ("MODEL", "cdcl")
    assert record["model_error"] is None and record["assignment"] is not None
    assert record["relay"] is not None  # relay non-null iff stream and cdcl (specification §4.8)
    assert record["proof_bytes"] is None and record["proof_sha256"] is None
    assert bench.work_files() == []


def test_a_cnf_changed_during_the_stream_outranks_the_success(make: Any) -> None:
    # the CNF is read-only (leaf.files): the checker removes it, then claims success
    bench = make(checker=p.checker_alters("cnf", action="delete"))
    _, record = bench.one(TINY, CDCL_CUBE)
    assert (record["outcome"], record["reason"]) == ("TOOL_FAILED", "file_changed")
    assert bench.work_files() == []


def test_a_cnf_rehash_with_another_hash_is_file_changed(make: Any) -> None:
    bench = make()
    bench.io.faults.append(report_hash(nth=0, suffix=".cnf", sha256="ab" * 32))
    _, record = bench.one(TINY, CDCL_CUBE)
    assert (record["outcome"], record["reason"]) == ("TOOL_FAILED", "file_changed")


def test_cancellation_during_the_stream_records_nothing_and_removes_the_fifos(make: Any) -> None:
    bench = make(solver=p.solver_until_terminated(30.0))
    attempt = bench.attempt(TINY, CDCL_CUBE)

    def cancel_when_streaming() -> None:
        if attempt.phase is Phase.STREAM and len(attempt.processes) == 3:
            attempt.cancel(grace_ms=200)

    started = time.monotonic()
    bench.run(attempt, on_tick=cancel_when_streaming)
    assert time.monotonic() - started < 20
    assert (attempt.phase, attempt.abandoned) == (Phase.ABANDONED, "cancelled")
    assert bench.io.attempts() == []
    assert bench.work_files() == []


def test_a_taken_checker_fifo_name_is_an_io_failure_and_is_left_alone(make: Any) -> None:
    bench = make()
    attempt_id = new_id128()
    attempt = bench.attempt(TINY, CDCL_CUBE, attempt_id=attempt_id)
    taken = bench.work / f"{attempt.node_id}-{attempt_id}.check.lrat"
    bench.work.mkdir(parents=True, exist_ok=True)
    taken.write_bytes(b"not ours")
    bench.run(attempt)
    (record,) = bench.io.attempts()
    assert (record["outcome"], record["reason"]) == ("TOOL_FAILED", "io")
    assert taken.read_bytes() == b"not ours"
    assert bench.work_files() == [taken.name]


def test_a_stream_attempt_needs_the_relay_interpreter(make: Any) -> None:
    bench = make()
    bench.tools = dataclasses.replace(bench.tools, python=None)
    with pytest.raises(ConfigurationError):
        bench.attempt(TINY, CDCL_CUBE)


def test_the_tool_pins_include_the_relay_interpreter(make: Any) -> None:
    bench = make()
    tools: LeafTools = bench.tools
    assert tools.python is not None
    assert tools.pins.python_sha256 == tools.python.sha256


# -- the binding -----------------------------------------------------------------------------------


class Evidence:
    """The evidence of one real coupled run on TINY under ``(3,)`` in its own work directory."""

    def __init__(
        self,
        root: Path,
        supervisor: Supervisor,
        *,
        solver: Sequence[Any] = (),
        checker: Sequence[Any] = (),
        policy: Policy = STREAM,
        arena: tuple[int, int] | None = None,
    ) -> None:
        work = root / "work"
        work.mkdir(parents=True)
        cube = CDCL_CUBE
        attempt_id = new_id128()
        self.identity = AttemptIdentity(
            node=node_of(TINY, cube),
            attempt_id=attempt_id,
            policy=policy,
            route=Route.CDCL,
            work_dir=str(work),
            cnf_sha256=CnfDigest(TINY).cnf_sha256(cube),
        )
        data = cube_cnf_bytes(TINY, cube)
        Path(self.identity.cnf_path).write_bytes(data)
        self.cnf = FileHash(attempt_id, self.identity.cnf_path, len(data), sha(data))
        _, solver_pin = make_tool(root / "tools", "cadical", solver or UNSAT_SOLVER)
        _, checker_pin = make_tool(root / "tools", "cake_lpr", checker or p.checker_lrat())
        python = python_pin()
        tools = StreamTools(solver_pin, ("--lrat",), checker_pin, python)
        self.pins = ToolPins(
            solver_pin.sha256, ("--lrat",), checker_pin.sha256, python_sha256=python.sha256
        )
        paths = stream_paths(str(work), self.identity.node_id, attempt_id)
        assert paths.solver_fifo == self.identity.proof_path
        plan = StreamPlan.of(
            policy,
            paths,
            depth=len(cube),
            arena=arena,
            stdout_capture=model_capture_bytes(TINY.variables),
        )
        run = StreamRun(supervisor, tools, plan)
        run.start()
        deadline = time.monotonic() + 60
        while not run.step():
            assert time.monotonic() < deadline, "the stream run did not end"
            supervisor.step(20)
        facts = run.facts()
        run.cleanup()
        self.report = facts.report
        self.stream = StreamEvidence(
            solve=SolveEvidence(run.launches[Role.SOLVER], facts.solver),
            relay=RelayEvidence(run.launches[Role.RELAY], facts.relay),
            check=CheckEvidence(
                run.launches[Role.CHECKER], facts.checker, plan.heap_mib, plan.stack_mib
            ),
        )

    def bind(self, **changes: Any) -> Any:
        values: dict[str, Any] = {
            "identity": self.identity,
            "pins": self.pins,
            "cnf_written": self.cnf,
            "cnf_final": self.cnf,
            "stream": self.stream,
        }
        values.update(changes)
        identity, pins = values.pop("identity"), values.pop("pins")
        return bind_stream_verified(identity, pins, **values)


@pytest.fixture
def evidence(tmp_path: Path, supervisor: Supervisor) -> Callable[..., Evidence]:
    made: list[Evidence] = []

    def factory(**options: Any) -> Evidence:
        value = Evidence(tmp_path / f"e{len(made)}", supervisor, **options)
        made.append(value)
        return value

    return factory


def relay_with(e: Evidence, **fields: Any) -> RelayEvidence:
    """The relay evidence with a report that differs in ``fields``."""
    assert e.report is not None
    report = dataclasses.replace(e.report, **fields)
    run = dataclasses.replace(e.stream.relay.run, stdout=report.to_line())
    return dataclasses.replace(e.stream.relay, run=run)


def test_a_complete_stream_binds_as_verified(evidence: Any) -> None:
    e = evidence()
    record = e.bind()
    assert e.report is not None and e.report.complete
    value = record.to_json()
    assert (value["outcome"], value["proof_mode"], value["route"]) == (
        "VERIFIED_UNSAT",
        "stream",
        "cdcl",
    )
    assert (value["proof_bytes"], value["proof_sha256"]) == (e.report.bytes, e.report.sha256)
    assert value["relay"] == e.report.record_value()
    assert len(value["checks"]) == 1
    assert success_problem(value) is None


Mutation = Callable[[Evidence], dict[str, Any]]


def _solver_run(e: Evidence, **result: Any) -> dict[str, Any]:
    run = e.stream.solve.run
    changed = dataclasses.replace(run, result=dataclasses.replace(run.result, **result))
    solve = dataclasses.replace(e.stream.solve, run=changed)
    return {"stream": dataclasses.replace(e.stream, solve=solve)}


def _checker_run(e: Evidence, **result: Any) -> dict[str, Any]:
    run = e.stream.check.run
    changed = dataclasses.replace(run, result=dataclasses.replace(run.result, **result))
    check = dataclasses.replace(e.stream.check, run=changed)
    return {"stream": dataclasses.replace(e.stream, check=check)}


def _relay_run(e: Evidence, **result: Any) -> dict[str, Any]:
    run = e.stream.relay.run
    changed = dataclasses.replace(run, result=dataclasses.replace(run.result, **result))
    relay = dataclasses.replace(e.stream.relay, run=changed)
    return {"stream": dataclasses.replace(e.stream, relay=relay)}


def _relay_causes(e: Evidence, *causes: Cause) -> dict[str, Any]:
    return _run_fields(e, "relay", causes=tuple(causes))


def _run_fields(e: Evidence, role: str, **fields: Any) -> dict[str, Any]:
    """The evidence with other ``ProcessRun`` fields (causes, stderr completeness) of a role."""
    part = getattr(e.stream, role)
    changed = dataclasses.replace(part, run=dataclasses.replace(part.run, **fields))
    return {"stream": dataclasses.replace(e.stream, **{role: changed})}


def _launch(e: Evidence, role: str, **fields: Any) -> dict[str, Any]:
    part = getattr(e.stream, role)
    changed = dataclasses.replace(part, launch=dataclasses.replace(part.launch, **fields))
    return {"stream": dataclasses.replace(e.stream, **{role: changed})}


def _arena(e: Evidence, heap: int, stack: int) -> dict[str, Any]:
    check = dataclasses.replace(e.stream.check, heap_mib=heap, stack_mib=stack)
    return {"stream": dataclasses.replace(e.stream, check=check)}


def _other_pins(e: Evidence, **fields: Any) -> dict[str, Any]:
    return {"pins": dataclasses.replace(e.pins, **fields)}


def _other_cnf(e: Evidence, which: str) -> dict[str, Any]:
    return {which: dataclasses.replace(e.cnf, sha256="ab" * 32)}


OTHER = "cd" * 32
REFUSALS: dict[str, tuple[Mutation, str]] = {
    # transport: only a complete transfer (EOF, all written, no error, clean relay exit)
    "no_eof": (
        lambda e: {"stream": dataclasses.replace(e.stream, relay=relay_with(e, solver_eof=False))},
        "protocol",
    ),
    "not_all_written": (
        lambda e: {
            "stream": dataclasses.replace(
                e.stream, relay=relay_with(e, all_written=False, written=0)
            )
        },
        "protocol",
    ),
    "relay_error": (
        lambda e: {
            "stream": dataclasses.replace(e.stream, relay=relay_with(e, error="write: EPIPE"))
        },
        "protocol",
    ),
    "relay_exit": (lambda e: _relay_run(e, exit=rl.EXIT_TRANSPORT), "protocol"),
    "relay_cause": (lambda e: _relay_causes(e, Cause.DEADLINE), "protocol"),
    "relay_signal": (lambda e: _relay_run(e, exit=None, signal=9), "protocol"),
    "no_report": (
        lambda e: {
            "stream": dataclasses.replace(
                e.stream,
                relay=dataclasses.replace(
                    e.stream.relay, run=dataclasses.replace(e.stream.relay.run, stdout=b"")
                ),
            )
        },
        "protocol",
    ),
    # the solver: started, exit 20, no signal
    "solver_exit_0": (lambda e: _solver_run(e, exit=0), "protocol"),
    "solver_exit_10": (lambda e: _solver_run(e, exit=10), "protocol"),
    "solver_signal": (lambda e: _solver_run(e, exit=None, signal=13), "protocol"),
    "solver_cause": (lambda e: _run_fields(e, "solve", causes=(Cause.DEADLINE,)), "protocol"),
    "solver_binary_changed": (
        lambda e: _run_fields(e, "solve", causes=(Cause.BINARY_CHANGED,)),
        "binary_changed",
    ),
    "relay_binary_changed": (
        lambda e: _run_fields(e, "relay", causes=(Cause.BINARY_CHANGED,)),
        "binary_changed",
    ),
    "checker_binary_changed": (
        lambda e: _run_fields(e, "check", causes=(Cause.BINARY_CHANGED,)),
        "binary_changed",
    ),
    # the checker's exact success: no cause, complete stderr, no arena message
    "checker_cause": (lambda e: _run_fields(e, "check", causes=(Cause.DEADLINE,)), "protocol"),
    "checker_stderr_cut": (lambda e: _run_fields(e, "check", stderr_truncated=True), "protocol"),
    "checker_arena_message": (
        lambda e: _checker_run(e, stderr_tail="CakeML heap space exhausted.\n"),
        "protocol",
    ),
    # the checker: the exact success line
    "checker_exit": (lambda e: _checker_run(e, exit=1), "protocol"),
    "checker_stdout": (
        lambda e: _checker_run(e, stdout_tail="s VERIFIED UNSAT \n", stdout_bytes=18),
        "protocol",
    ),
    # binaries: the pinned solver, checker and relay interpreter
    "solver_binary": (lambda e: _other_pins(e, solver_sha256=OTHER), "binary_changed"),
    "checker_binary": (lambda e: _other_pins(e, checker_sha256=OTHER), "binary_changed"),
    "relay_binary": (lambda e: _other_pins(e, python_sha256=OTHER), "binary_changed"),
    "no_relay_pin": (lambda e: _other_pins(e, python_sha256=None), "binary_changed"),
    # files: the attempt's own CNF and FIFOs, the CNF unchanged
    "cnf_written": (lambda e: _other_cnf(e, "cnf_written"), "file_changed"),
    "cnf_final": (lambda e: _other_cnf(e, "cnf_final"), "file_changed"),
    "solver_files": (
        lambda e: _launch(
            e, "solve", args=(*e.stream.solve.launch.args[:-1], e.identity.proof_path + ".x")
        ),
        "file_changed",
    ),
    "checker_files": (
        lambda e: _launch(
            e, "check", args=(*e.stream.check.launch.args[:-1], e.identity.proof_path)
        ),
        "file_changed",
    ),
    "relay_files": (
        lambda e: _launch(
            e,
            "relay",
            args=tuple(
                a if a != e.identity.proof_path else a + ".x" for a in e.stream.relay.launch.args
            ),
        ),
        "file_changed",
    ),
    # limits and arenas
    "relay_cap": (
        lambda e: _launch(
            e,
            "relay",
            args=(*e.stream.relay.launch.args[:-1], str(e.identity.policy.proof_cap_bytes + 1)),
        ),
        "protocol",
    ),
    "solver_memory": (
        lambda e: _launch(e, "solve", memory_bytes=e.identity.policy.solver_memory_bytes + 1),
        "protocol",
    ),
    "solver_spooled": (
        lambda e: _launch(e, "solve", file_bytes=e.identity.policy.proof_cap_bytes),
        "protocol",
    ),
    "checker_beyond_the_paired_deadline": (
        lambda e: _launch(
            e, "check", deadline_ms=e.identity.policy.leaf_time_ms_for_depth(len(CDCL_CUBE)) + 1
        ),
        "protocol",
    ),
    "relay_beyond_the_paired_deadline": (
        lambda e: _launch(
            e, "relay", deadline_ms=e.identity.policy.leaf_time_ms_for_depth(len(CDCL_CUBE)) + 1
        ),
        "protocol",
    ),
    "arena_below_policy": (
        lambda e: _arena(e, initial_stream_arena(e.identity.policy)[0] // 2, 256),
        "protocol",
    ),
}


@pytest.mark.parametrize("name", sorted(REFUSALS))
def test_the_binding_refuses_every_incomplete_or_foreign_stream(evidence: Any, name: str) -> None:
    e = evidence()
    assert e.bind().outcome is Outcome.VERIFIED_UNSAT  # the unchanged evidence binds
    mutation, reason = REFUSALS[name]
    with pytest.raises(BindingError) as refused:
        e.bind(**mutation(e))
    assert refused.value.reason == reason


def test_a_unit_route_identity_cannot_bind_a_stream(evidence: Any) -> None:
    e = evidence()
    unit = dataclasses.replace(e.identity, route=Route.UNIT)
    with pytest.raises(BindingError) as refused:
        e.bind(identity=unit)
    assert refused.value.reason == "protocol"


def test_a_file_mode_identity_cannot_bind_a_stream(evidence: Any) -> None:
    e = evidence()
    transient = dataclasses.replace(e.identity, policy=STREAM.with_proof_mode(ProofMode.TRANSIENT))
    with pytest.raises(BindingError):
        e.bind(identity=transient)


def test_other_stream_outcomes_carry_the_relay_and_never_a_partial_proof(evidence: Any) -> None:
    e = evidence(checker=p.checker_arena("heap"))
    assert e.report is not None
    record = bind_outcome(
        e.identity,
        e.pins,
        outcome=Outcome.EXHAUSTED,
        reason="check_memory",
        stream=e.stream,
        relay=e.report.record_value(),
        cnf_written=e.cnf,
        cnf_final=e.cnf,
    ).to_json()
    assert record["relay"] == e.report.record_value()
    assert record["proof_bytes"] is None and record["proof_sha256"] is None
    (check,) = record["checks"]
    assert (check["heap_mib"], check["stack_mib"]) == initial_stream_arena(STREAM)
    assert record["proof_mode"] == "stream" and record["route"] == "cdcl"


def test_a_stream_outcome_needs_its_stream_evidence(evidence: Any) -> None:
    e = evidence()
    with pytest.raises(BindingError) as refused:
        bind_outcome(e.identity, e.pins, outcome=Outcome.TOOL_FAILED, reason="relay")
    assert refused.value.reason == "protocol"


def test_bind_outcome_never_builds_a_stream_success(evidence: Any) -> None:
    e = evidence()
    assert e.report is not None
    with pytest.raises(ValueError):
        bind_outcome(
            e.identity,
            e.pins,
            outcome=Outcome.VERIFIED_UNSAT,
            reason=None,
            stream=e.stream,
            relay=e.report.record_value(),
        )


def test_proof_fields_of_another_outcome_need_a_complete_transfer(evidence: Any) -> None:
    e = evidence(checker=p.checker_reject())
    assert e.report is not None and e.report.complete
    complete = e.report.record_value()
    record = bind_outcome(
        e.identity,
        e.pins,
        outcome=Outcome.CHECK_REJECTED,
        reason="rejected",
        stream=e.stream,
        relay=complete,
        stream_proof=(e.report.bytes, e.report.sha256),
        cnf_written=e.cnf,
        cnf_final=e.cnf,
    ).to_json()
    assert (record["proof_bytes"], record["proof_sha256"]) == (e.report.bytes, e.report.sha256)
    partial = dict(complete, solver_eof=False)
    with pytest.raises(ValueError):
        bind_outcome(
            e.identity,
            e.pins,
            outcome=Outcome.CHECK_REJECTED,
            reason="rejected",
            stream=e.stream,
            relay=partial,
            stream_proof=(e.report.bytes, e.report.sha256),
        )


def test_the_relay_stdout_is_not_trusted_without_a_clean_exit(evidence: Any) -> None:
    """A complete report from a relay that did not exit cleanly is never a proof."""
    e = evidence()
    changed = _relay_run(e, exit=rl.EXIT_TERMINATED)
    with pytest.raises(BindingError):
        e.bind(**changed)


def test_a_teardown_the_relay_outlived_by_completing_does_not_refuse(evidence: Any) -> None:
    """``leaf.stream``: a teardown racing the relay's clean exit with a complete report (the
    classifier's ``torn_complete`` row) is not a broken transfer; any other cause is."""
    e = evidence()
    record = e.bind(**_relay_causes(e, Cause.CANCELLED)).to_json()
    assert record["outcome"] == "VERIFIED_UNSAT"
    with pytest.raises(BindingError):
        e.bind(**_relay_causes(e, Cause.CANCELLED, Cause.MEMORY_EVENT))


def test_a_relay_value_cannot_claim_a_transfer_the_evidence_lacks(evidence: Any) -> None:
    e = evidence(checker=p.checker_arena("heap"))
    assert e.report is not None and not e.report.complete
    claimed = dict(e.report.record_value(), solver_eof=True, all_written=True, error=None)
    with pytest.raises(ValueError):
        bind_outcome(
            e.identity,
            e.pins,
            outcome=Outcome.EXHAUSTED,
            reason="check_memory",
            stream=e.stream,
            relay=claimed,
        )


def test_a_consistent_run_below_the_stream_arena_does_not_bind(evidence: Any) -> None:
    """S2: launch and evidence agree on an arena below ``stream_heap_mib``: still refused."""
    heap, stack = initial_stream_arena(STREAM)
    e = evidence(arena=(heap // 2, stack))
    assert e.report is not None and e.report.complete
    with pytest.raises(BindingError) as refused:
        e.bind()
    assert (refused.value.reason, refused.value.rule) == ("protocol", "binding.stream_arena")


def test_stream_proof_fields_need_a_clean_unsat_solve(evidence: Any) -> None:
    e = evidence(checker=p.checker_reject())
    assert e.report is not None and e.report.complete
    with pytest.raises(ValueError):
        bind_outcome(
            e.identity,
            e.pins,
            outcome=Outcome.TOOL_FAILED,
            reason="protocol",
            relay=e.report.record_value(),
            stream_proof=(e.report.bytes, e.report.sha256),
            **_solver_run(e, exit=0),
        )
