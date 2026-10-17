"""Coupled solver -> relay -> checker runs with fake tools (specification §6.2, §6.4, §8.3).

Each test runs the real relay process and the fake tools under the real process supervisor and
isolation wrappers, on real FIFOs in a private work directory, then classifies the observed
facts with the stream table. The fakes are test doubles: what they prove is the transport,
teardown and precedence behaviour, not any property of the pinned tools (see the image tier).
"""

from __future__ import annotations

import os
import signal
import stat
import sys
import time
from collections.abc import Iterator, Sequence
from pathlib import Path
from typing import Any

import pytest
from cp_stream_support import (  # noqa: F401 - fixtures are registered by import
    TINY,
    TINY_PROOF,
    fk,
    formula,
    isolation_fixture,
    make_policy,
    make_tool,
    p,
    sha,
    supervisor_fixture,
)

from cubeproof.base.ids import new_id128
from cubeproof.cnf.cubecnf import cube_cnf_bytes
from cubeproof.cnf.dimacs import Formula
from cubeproof.contracts.enums import Outcome, Route
from cubeproof.contracts.identity import node_id
from cubeproof.contracts.policy import Policy
from cubeproof.leaf.stream import (
    RELAY_MEMORY_BYTES,
    RELAY_SCRIPT,
    Role,
    StreamDecision,
    StreamError,
    StreamFacts,
    StreamLimits,
    StreamPlan,
    StreamRun,
    StreamTools,
    classify_stream,
    protocol_for,
    remove_fifos,
    stream_paths,
)
from cubeproof.tools import checker as ck
from cubeproof.tools import relay as rl
from cubeproof.tools import solver as sv
from cubeproof.tools.isolation import PinnedBinary
from cubeproof.tools.process import Supervisor
from cubeproof.tools.process_outcome import Action

pytestmark = pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux only")

MIB = 1 << 20
SUCCESS = b"s VERIFIED UNSAT\n"
SAT = formula(3, [(1, 2), (-1, 3)])


class Coupled:
    """One node's stream run in its own work directory, with fake tools."""

    def __init__(
        self,
        root: Path,
        supervisor: Supervisor,
        *,
        solver: Sequence[Any],
        checker: Sequence[Any],
        policy: Policy | None = None,
        arena: tuple[int, int] | None = None,
        f: Formula = TINY,
        cube: tuple[int, ...] = (),
        python: PinnedBinary | None = None,
    ) -> None:
        self.root = root
        self.supervisor = supervisor
        self.policy = policy or make_policy()
        self.work = root / "work"
        self.work.mkdir(parents=True)
        self.paths = stream_paths(str(self.work), node_id(f.sha256, cube), new_id128())
        Path(self.paths.cnf).write_bytes(cube_cnf_bytes(f, cube))
        self.solver, solver_pin = make_tool(root / "tools", "cadical", solver)
        self.checker, checker_pin = make_tool(root / "tools", "cake_lpr", checker)
        self.tools = StreamTools(
            solver=solver_pin,
            solver_argv=("--lrat",),
            checker=checker_pin,
            python=python or PinnedBinary.measure(sys.executable),
        )
        self.plan = StreamPlan.of(
            self.policy, self.paths, depth=len(cube), arena=arena, stdout_capture=1 << 20
        )
        self.run = StreamRun(supervisor, self.tools, self.plan)
        self.elapsed = 0.0

    def drive(self, timeout: float = 60.0, *, during: Any = None) -> StreamFacts:
        started = time.monotonic()
        if not self.run.prepared:
            self.run.prepare()
        self.run.start()
        while not self.run.step():
            assert time.monotonic() - started < timeout, "the stream run did not end"
            self.supervisor.step(20)
            if during is not None:
                during(self)
        self.elapsed = time.monotonic() - started
        assert not self.run.processes
        assert all(p.run is not None for p in self.run.started.values())
        return self.run.facts()

    def decide(self, timeout: float = 60.0, **options: Any) -> tuple[StreamDecision, StreamFacts]:
        found = self.drive(timeout, **options)
        decision = classify_stream(found, StreamLimits.of(self.policy))
        return decision, found

    def files(self) -> list[str]:
        return sorted(os.listdir(self.work))

    def checker_reads(self) -> list[dict[str, Any]]:
        return [e for e in self.checker.events() if e["op"] == "read"]


@pytest.fixture
def coupled(tmp_path: Path, supervisor: Supervisor) -> Iterator[Any]:
    made: list[Coupled] = []

    def factory(**options: Any) -> Coupled:
        value = Coupled(tmp_path / f"c{len(made)}", supervisor, **options)
        made.append(value)
        return value

    yield factory
    for value in made:
        os.chmod(value.work, 0o700)


def outcome(decision: StreamDecision) -> tuple[Any, ...]:
    if decision.action is not Action.RECORD:
        return (decision.action.value,)
    assert decision.outcome is not None
    return (decision.outcome.value, decision.reason)


def flood(size: int = 8 * MIB) -> list[Any]:
    steps: list[Any] = p.solver_proof_flood(size, chunk=1 << 16)
    return steps


# -- complete transfers -----------------------------------------------------------------------


@pytest.mark.parametrize("checker", ["output", "lrat"])
def test_a_complete_stream_is_verified(coupled: Any, checker: str) -> None:
    steps = p.checker_output(SUCCESS) if checker == "output" else p.checker_lrat()
    c = coupled(solver=p.solver_unsat(TINY_PROOF), checker=steps)
    decision, found = c.decide()
    assert outcome(decision) == ("VERIFIED_UNSAT", None)
    assert decision.proof == (len(TINY_PROOF), sha(TINY_PROOF))
    assert decision.relay == {
        "bytes": len(TINY_PROOF),
        "sha256": sha(TINY_PROOF),
        "solver_eof": True,
        "all_written": True,
        "error": None,
    }
    assert found.torn_down == frozenset()
    if checker == "output":
        (read,) = c.checker_reads()
        assert (read["bytes"], read["sha256"], read["eof"]) == (
            len(TINY_PROOF),
            sha(TINY_PROOF),
            True,
        )
    # the checker read the CNF and the relay's FIFO, the solver wrote its own FIFO
    assert c.checker.argv()[-2:] == [c.paths.cnf, c.paths.checker_fifo]
    assert c.solver.argv()[-2:] == [c.paths.cnf, c.paths.solver_fifo]
    assert sorted(c.run.cleanup()) == sorted([c.paths.solver_fifo, c.paths.checker_fifo])
    assert c.files() == [os.path.basename(c.paths.cnf)]


@pytest.mark.parametrize(("solver_delay", "checker_delay"), [(0.5, 0.0), (0.0, 0.5), (0.4, 0.4)])
def test_open_order_does_not_matter(
    coupled: Any, solver_delay: float, checker_delay: float
) -> None:
    c = coupled(
        solver=[fk.sleep(solver_delay), *p.solver_unsat(TINY_PROOF)],
        checker=[fk.sleep(checker_delay), *p.checker_lrat()],
    )
    decision, _ = c.decide()
    assert outcome(decision) == ("VERIFIED_UNSAT", None)


def test_the_proof_is_never_spooled(coupled: Any) -> None:
    """8 MiB stream through a work directory in which no file can be created (no space
    needed for the proof: the reservation is CNF and logs only, specification §8.3)."""
    c = coupled(solver=flood(), checker=p.checker_output(SUCCESS))
    c.run.prepare()
    os.chmod(c.work, 0o500)
    decision, found = c.decide()
    assert outcome(decision) == ("VERIFIED_UNSAT", None)
    assert found.report is not None and found.report.bytes == 8 * MIB
    (read,) = c.checker_reads()
    assert (read["bytes"], read["sha256"]) == (found.report.bytes, found.report.sha256)
    names = {os.path.basename(x): x for x in (c.paths.solver_fifo, c.paths.checker_fifo)}
    assert set(c.files()) == {os.path.basename(c.paths.cnf), *names}
    for path in names.values():
        info = os.lstat(path)
        assert stat.S_ISFIFO(info.st_mode) and info.st_size == 0
    os.chmod(c.work, 0o700)
    c.run.cleanup()
    assert c.files() == [os.path.basename(c.paths.cnf)]


# -- precedence with real processes -------------------------------------------------------------


@pytest.mark.parametrize("kind", ["heap", "stack"])
def test_arena_exhaustion_outranks_the_epipe_it_causes(coupled: Any, kind: str) -> None:
    c = coupled(solver=flood(), checker=p.checker_stops_reading(1000, p.checker_arena(kind)))
    decision, found = c.decide()
    reason = "check_memory" if kind == "heap" else "check_stack"
    assert outcome(decision) == ("EXHAUSTED", reason)
    assert found.report is not None and not found.report.complete
    assert decision.proof is None
    # the solver was cut off (SIGPIPE) or torn down, never left running
    assert found.solver.result.exit != 20


def test_an_arena_failure_before_the_checker_opens_its_input(coupled: Any) -> None:
    """cake_lpr's up-front allocation failure: the relay can never open its output."""
    c = coupled(solver=flood(), checker=p.checker_arena("both"))
    decision, found = c.decide(timeout=30)
    assert outcome(decision) == ("EXHAUSTED", "check_memory")
    assert Role.RELAY in found.torn_down
    assert c.elapsed < 15


def test_the_cap_outranks_the_epipe_and_the_checker(coupled: Any) -> None:
    c = coupled(
        solver=flood(),
        checker=p.checker_output(SUCCESS),
        policy=make_policy(proof_cap_bytes=MIB),
    )
    decision, found = c.decide()
    assert outcome(decision) == ("EXHAUSTED", "proof_size")
    assert found.report is not None
    assert found.report.error == rl.ERROR_CAP and found.report.bytes <= MIB
    assert decision.proof is None


@pytest.mark.parametrize("then", ["success", "rejection"])
def test_an_early_checker_exit_is_a_relay_failure(coupled: Any, then: str) -> None:
    ending = (
        [fk.write(fk.STDOUT, data=SUCCESS), fk.exit_(0)]
        if then == "success"
        else [fk.write(fk.STDERR, "c Checking failed at line: 1.\n"), fk.exit_(0)]
    )
    c = coupled(solver=flood(), checker=p.checker_stops_reading(1000, ending))
    decision, found = c.decide()
    assert outcome(decision) == ("TOOL_FAILED", "relay")
    assert decision.proof is None
    assert found.report is None or not found.report.complete


def test_a_broken_transfer_does_not_silence_the_checker(coupled: Any) -> None:
    """The checker closed its input and reports its arena exhaustion only a second later:
    the broken transfer ends the solver, never the checker, whose diagnostic is primary."""
    late = p.checker_stops_reading(1000, [fk.sleep(1.0), *p.checker_arena("heap")])
    c = coupled(solver=flood(), checker=late)
    decision, found = c.decide()
    assert outcome(decision) == ("EXHAUSTED", "check_memory")
    assert Role.CHECKER not in found.torn_down
    assert found.report is not None and not found.report.complete


def test_an_unsat_exit_without_opening_the_proof_output_is_an_empty_proof(coupled: Any) -> None:
    """The relay never saw a writer; the solver's end gives it EOF (a nudge), so the run
    ends at once with an empty, complete transfer that the checker rejects."""
    c = coupled(
        solver=[fk.write(fk.STDOUT, "s UNSATISFIABLE\n"), fk.exit_(20)],
        checker=p.checker_lrat(),
    )
    decision, found = c.decide(timeout=30)
    assert found.report is not None and found.report.complete and found.report.bytes == 0
    assert outcome(decision) == ("CHECK_REJECTED", "rejected")
    assert decision.proof == (0, sha(b""))
    assert c.elapsed < 15


def test_a_checker_crash_precedes_the_relay_error(coupled: Any) -> None:
    c = coupled(solver=flood(), checker=p.checker_stops_reading(1000, [fk.kill_self("SEGV")]))
    decision, found = c.decide()
    assert outcome(decision) == ("TOOL_FAILED", "crash")
    assert found.checker.result.signal == int(signal.SIGSEGV)


def test_a_solver_crash_after_a_partial_proof(coupled: Any) -> None:
    solver = p.solver_partial_proof(TINY_PROOF, 10, then=[fk.kill_self("SEGV")])
    c = coupled(solver=solver, checker=p.checker_lrat())
    decision, found = c.decide()
    assert outcome(decision) == ("TOOL_FAILED", "crash")
    assert found.solver.result.signal == int(signal.SIGSEGV)
    assert decision.proof is None


def test_a_sat_solver_that_never_opens_its_proof_output(coupled: Any) -> None:
    c = coupled(solver=p.solver_brute_force(), checker=p.checker_lrat(), f=SAT)
    decision, found = c.decide(timeout=30)
    assert outcome(decision) == ("parse_model",)
    assert found.solver.result.exit == 10
    assert found.solver.stdout is not None and b"s SATISFIABLE" in found.solver.stdout
    assert c.elapsed < 15  # the relay was told the solver is gone: no wait for the deadline


# -- the paired deadline ----------------------------------------------------------------------


def test_the_solver_deadline_is_the_coupled_deadline(coupled: Any) -> None:
    c = coupled(
        solver=p.solver_until_terminated(30),
        checker=p.checker_lrat(),
        policy=make_policy(leaf_time_ms={"default": 1000}),
    )
    decision, _ = c.decide()
    assert outcome(decision) == ("EXHAUSTED", "time")
    assert c.elapsed < 1.0 + 0.5 + 5


def test_a_check_that_outlives_the_coupled_deadline(coupled: Any) -> None:
    """check_time_ms does not extend the stream: the solver's leaf time covers the check."""
    c = coupled(
        solver=p.solver_unsat(TINY_PROOF),
        checker=[fk.read(fk.arg(-1)), fk.sleep(30), fk.exit_(0)],
        policy=make_policy(leaf_time_ms={"default": 1000}, checker_time_base_ms=600_000),
    )
    decision, found = c.decide()
    assert outcome(decision) == ("EXHAUSTED", "check_time")
    assert found.solver.result.exit == 20
    assert c.elapsed < 1.0 + 0.5 + 5


def test_the_three_launches_share_one_deadline(coupled: Any) -> None:
    c = coupled(solver=p.solver_unsat(TINY_PROOF), checker=p.checker_lrat())
    c.drive()
    launches = c.run.launches
    total = c.policy.leaf_time_ms_for_depth(0)
    for role in Role:
        deadline = launches[role].deadline_ms
        assert deadline is not None and total - 5000 <= deadline <= total, role


# -- cancellation and launch failures ----------------------------------------------------------


def test_user_cancellation_records_nothing(coupled: Any) -> None:
    c = coupled(solver=p.solver_until_terminated(30), checker=p.checker_lrat())
    begun = time.monotonic()

    def cancel(value: Coupled) -> None:
        if time.monotonic() - begun > 0.4:
            value.run.cancel(200)

    decision, found = c.decide(during=cancel)
    assert outcome(decision) == ("no_record",)
    assert found.cancelled
    c.run.cleanup()
    assert c.files() == [os.path.basename(c.paths.cnf)]


def test_a_supervisor_stop_records_nothing(coupled: Any, supervisor: Supervisor) -> None:
    c = coupled(solver=p.solver_until_terminated(30), checker=p.checker_lrat())
    begun = time.monotonic()

    def stop(value: Coupled) -> None:
        if time.monotonic() - begun > 0.4 and not supervisor.stopping:
            supervisor.stop(200)

    decision, _ = c.decide(during=stop)
    assert outcome(decision) == ("no_record",)


def test_a_changed_checker_stops_the_others_at_once(coupled: Any) -> None:
    """A launch failure ends the partners at once, not after the relay's grace that follows
    an ended checker (term_grace_ms, here 20 s)."""
    c = coupled(
        solver=p.solver_until_terminated(30),
        checker=p.checker_lrat(),
        policy=make_policy(term_grace_ms=20_000),
    )
    with open(c.checker.path, "a", encoding="utf-8") as stream:
        stream.write("# changed\n")
    decision, found = c.decide(timeout=45)
    assert outcome(decision) == ("TOOL_FAILED", "binary_changed")
    assert not found.checker.result.started
    assert c.elapsed < 10


def test_a_changed_relay_interpreter_is_a_binary_change(coupled: Any) -> None:
    real = PinnedBinary.measure(sys.executable)
    wrong = PinnedBinary(real.path, "00" * 32)
    c = coupled(solver=p.solver_until_terminated(30), checker=p.checker_lrat(), python=wrong)
    decision, found = c.decide(timeout=30)
    assert outcome(decision) == ("TOOL_FAILED", "binary_changed")
    assert not found.relay.result.started
    assert c.elapsed < 15


# -- files ---------------------------------------------------------------------------------


@pytest.mark.parametrize("which", ["solver_fifo", "checker_fifo"])
def test_fifo_paths_are_created_exclusively(
    coupled: Any, supervisor: Supervisor, which: str
) -> None:
    c = coupled(solver=p.solver_unsat(TINY_PROOF), checker=p.checker_lrat())
    taken = Path(getattr(c.paths, which))
    taken.write_bytes(b"not mine")
    with pytest.raises(StreamError) as refused:
        c.run.prepare()
    assert refused.value.rule == "stream.path_exists"
    assert taken.read_bytes() == b"not mine"
    assert set(c.files()) == {os.path.basename(c.paths.cnf), taken.name}
    assert not supervisor.active
    with pytest.raises(StreamError):
        c.run.start()


def test_cleanup_removes_only_fifos(coupled: Any) -> None:
    c = coupled(solver=p.solver_unsat(TINY_PROOF), checker=p.checker_lrat())
    c.drive()
    os.unlink(c.paths.checker_fifo)
    Path(c.paths.checker_fifo).write_bytes(b"someone else's")
    assert remove_fifos(c.paths) == [c.paths.solver_fifo]
    assert Path(c.paths.checker_fifo).read_bytes() == b"someone else's"
    assert os.path.exists(c.paths.cnf)


def test_cleanup_waits_for_the_processes(coupled: Any) -> None:
    c = coupled(solver=p.solver_until_terminated(30), checker=p.checker_lrat())
    c.run.prepare()
    c.run.start()
    with pytest.raises(StreamError) as early:
        c.run.cleanup()
    assert early.value.rule == "stream.running"
    c.run.cancel(100)
    while not c.run.step():
        c.supervisor.step(20)
    c.run.cleanup()


# -- launches and routing ---------------------------------------------------------------------


def test_the_launches(coupled: Any) -> None:
    c = coupled(
        solver=p.solver_unsat(TINY_PROOF),
        checker=p.checker_lrat(),
        arena=(2048, 512),
        policy=make_policy(proof_cap_bytes=3 * MIB),
    )
    c.drive()
    launches = c.run.launches
    solver, relay, checker = launches[Role.SOLVER], launches[Role.RELAY], launches[Role.CHECKER]
    policy = c.policy
    assert solver.binary == c.tools.solver
    assert solver.args == sv.solver_args(("--lrat",), c.paths.cnf, c.paths.solver_fifo)
    assert (solver.memory_bytes, solver.file_bytes, solver.watch) == (
        policy.solver_memory_bytes,
        None,
        None,
    )
    assert solver.stdout_capture == 1 << 20
    assert relay.binary == c.tools.python
    assert relay.args == (
        "-I",
        "-S",
        "-B",
        RELAY_SCRIPT,
        c.paths.solver_fifo,
        c.paths.checker_fifo,
        str(3 * MIB),
    )
    assert relay.memory_bytes == RELAY_MEMORY_BYTES == 128 * MIB
    assert checker.binary == c.tools.checker
    assert checker.args == ck.checker_args(2048, 512, c.paths.cnf, c.paths.checker_fifo)
    assert checker.memory_bytes == ck.checker_memory_bytes(2048, 512, policy.checker_slack_mib)
    assert {launch.cwd for launch in launches.values()} == {str(c.work)}
    assert os.path.isabs(RELAY_SCRIPT) and RELAY_SCRIPT.endswith("cubeproof/tools/relay.py")


def test_the_default_arena_is_the_stream_heap(coupled: Any) -> None:
    c = coupled(solver=p.solver_unsat(TINY_PROOF), checker=p.checker_lrat())
    assert (c.plan.heap_mib, c.plan.stack_mib) == (
        c.policy.stream_heap_mib,
        c.policy.checker_stack_mib,
    )
    assert c.plan.deadline_ms == c.policy.leaf_time_ms_for_depth(0)


def test_a_unit_proof_follows_the_file_protocol_under_a_stream_policy() -> None:
    stream = make_policy()
    assert protocol_for(stream, Route.UNIT) == "file"
    assert protocol_for(stream, Route.CDCL) == "stream"
    for mode in ("transient", "retain"):
        other = make_policy(proof_mode=mode)
        assert protocol_for(other, Route.CDCL) == "file"
        assert protocol_for(other, Route.UNIT) == "file"


def test_paths_are_the_attempts_own() -> None:
    nid, aid = "ab" * 32, "cd" * 16
    paths = stream_paths("/w", nid, aid)
    assert paths.cnf == f"/w/{nid}-{aid}.cnf"
    assert paths.solver_fifo == f"/w/{nid}-{aid}.lrat"
    assert paths.checker_fifo == f"/w/{nid}-{aid}.check.lrat"


def test_a_partial_proof_of_an_unsat_exit_is_rejected_by_the_checker(coupled: Any) -> None:
    """The relay hash is of exactly the bytes the solver wrote; the checker judges them."""
    c = coupled(
        solver=[fk.write(fk.arg(-1), data=TINY_PROOF[:12]), fk.exit_(20)],
        checker=p.checker_lrat(),
    )
    decision, found = c.decide()
    assert found.report is not None and found.report.complete
    assert (found.report.bytes, found.report.sha256) == (12, sha(TINY_PROOF[:12]))
    assert decision.outcome is Outcome.CHECK_REJECTED
    assert decision.proof == (12, sha(TINY_PROOF[:12]))
    assert decision.diagnostics == {"quarantine_unavailable": "stream_not_spooled"}
