"""Coupled runs of the pinned CaDiCaL -> relay -> cake_lpr (``image`` tier).

Real complete stream proofs must hash exactly like the file proof of the same solver on the
same CNF and argv; a real arena exhaustion (cake_lpr closing its input) is EXHAUSTED, not a
relay failure, and the fresh attempt with the arena derived from that record succeeds; a real
cap is ``proof_size``; a real SAT run goes to model parsing. The tools come from
``POLYHEDRAPROOF_TEST_TOOLS`` (the test image or a prefix built by
``docker/test/pinned_tools.py``); an absent prefix fails, never skips.
"""

from __future__ import annotations

import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from cp_stream_support import (  # noqa: F401 - fixtures are registered by import
    Journal,
    cnf_model,
    formula,
    formula_bytes,
    isolation_fixture,
    make_policy,
    sha,
    supervisor_fixture,
)
from cp_stream_support import policy_value as policy

from cubeproof.base.ids import new_id128
from cubeproof.cnf.cubecnf import cube_cnf_bytes
from cubeproof.cnf.dimacs import Formula
from cubeproof.contracts.enums import ProofMode
from cubeproof.contracts.identity import node_id
from cubeproof.contracts.policy import Policy
from cubeproof.evidence.certify.admission import success_problem
from cubeproof.evidence.schema import Attempt
from cubeproof.leaf.attempt import LeafTools
from cubeproof.leaf.retry import next_stream_attempt
from cubeproof.leaf.stream import (
    StreamDecision,
    StreamFacts,
    StreamLimits,
    StreamPlan,
    StreamRun,
    StreamTools,
    classify_stream,
    stream_paths,
)
from cubeproof.tools.isolation import TOOL_ENVIRONMENT, PinnedBinary
from cubeproof.tools.process import Supervisor
from cubeproof.tools.process_outcome import Action
from image.pinned import Pinned, ToolsUnavailable, locate

pytestmark = [
    pytest.mark.image,
    pytest.mark.skipif(not sys.platform.startswith("linux"), reason="pinned tools are Linux"),
]

ARGV = ("-q", "--lrat")
LEAF_TESTS = Path(__file__).resolve().parent.parent / "leaf"


@pytest.fixture(scope="module")
def pinned() -> Pinned:
    try:
        return locate()
    except ToolsUnavailable as error:
        pytest.fail(str(error), pytrace=False)


@pytest.fixture(scope="module")
def tools(pinned: Pinned) -> StreamTools:
    return StreamTools(
        solver=PinnedBinary.measure(str(pinned.cadical)),
        solver_argv=ARGV,
        checker=PinnedBinary.measure(str(pinned.cake_lpr)),
        python=PinnedBinary.measure(sys.executable),
    )


def php(holes: int) -> Formula:
    cnf = cnf_model.pigeonhole(holes)
    return formula(cnf.variables, cnf.clauses)


class Real:
    def __init__(self, root: Path, supervisor: Supervisor, tools: StreamTools) -> None:
        self.root = root
        self.supervisor = supervisor
        self.tools = tools
        self.count = 0

    def stream(
        self,
        f: Formula,
        cube: tuple[int, ...] = (),
        *,
        policy: Policy | None = None,
        arena: tuple[int, int] | None = None,
    ) -> tuple[StreamDecision, StreamFacts, str]:
        self.count += 1
        work = self.root / f"w{self.count}"
        work.mkdir(parents=True)
        effective = policy or make_policy()
        paths = stream_paths(str(work), node_id(f.sha256, cube), new_id128())
        Path(paths.cnf).write_bytes(cube_cnf_bytes(f, cube))
        plan = StreamPlan.of(effective, paths, depth=len(cube), arena=arena, stdout_capture=4 << 20)
        run = StreamRun(self.supervisor, self.tools, plan)
        run.prepare()
        run.start()
        while not run.step():
            self.supervisor.step(20)
        found = run.facts()
        run.cleanup()
        assert sorted(p.name for p in work.iterdir()) == [Path(paths.cnf).name]
        return classify_stream(found, StreamLimits.of(effective)), found, paths.cnf

    def file_proof(self, cnf: str) -> bytes:
        """The proof the same pinned solver writes to a regular file (oracle)."""
        proof = Path(cnf).with_suffix(".file.lrat")
        done = subprocess.run(
            [self.tools.solver.path, *ARGV, cnf, str(proof)],
            capture_output=True,
            env=dict(TOOL_ENVIRONMENT),
            timeout=300,
            check=False,
        )
        assert done.returncode == 20, done
        data = proof.read_bytes()
        proof.unlink()
        return data


@pytest.fixture
def real(tmp_path: Path, supervisor: Supervisor, tools: StreamTools) -> Iterator[Real]:
    yield Real(tmp_path, supervisor, tools)


def outcome(decision: StreamDecision) -> tuple[Any, ...]:
    if decision.action is not Action.RECORD:
        return (decision.action.value,)
    assert decision.outcome is not None
    return (decision.outcome.value, decision.reason)


@pytest.mark.parametrize(
    ("holes", "cube"), [(2, ()), (3, ()), (4, ()), (5, ()), (6, ()), (3, (1, 6))]
)
def test_real_stream_proofs_hash_like_file_proofs(
    real: Real, holes: int, cube: tuple[int, ...]
) -> None:
    decision, found, cnf = real.stream(php(holes), cube)
    assert outcome(decision) == ("VERIFIED_UNSAT", None), found
    expected = real.file_proof(cnf)
    assert decision.proof == (len(expected), sha(expected))
    assert decision.relay is not None and decision.relay["sha256"] == sha(expected)


def _record(decision: StreamDecision, found: StreamFacts, journal: Journal) -> Attempt:
    """The EXHAUSTED record of a real arena exhaustion, as a journal would hold it."""
    assert decision.outcome is not None and decision.reason is not None
    check = {
        "result": found.checker.result.to_json(),
        "heap_mib": found.heap_mib,
        "stack_mib": found.stack_mib,
    }
    seq = journal.failed(
        "f",
        (),
        decision.outcome.value,
        decision.reason,
        route="cdcl",
        solver=found.solver.result.to_json(),
        checks=[check],
        relay=decision.relay,
        proof_bytes=None if decision.proof is None else decision.proof[0],
        proof_sha256=None if decision.proof is None else decision.proof[1],
    )
    record = journal.records[seq].payload
    assert isinstance(record, Attempt)
    return record


def test_real_arena_exhaustion_then_a_fresh_attempt_with_the_derived_arena(real: Real) -> None:
    """cake_lpr out of heap closes the stream: EXHAUSTED(check_memory), the relay's EPIPE and
    the solver's end are secondary; the next attempts use the arena derived from the record
    until the proof is verified (a finite ladder)."""
    fit = {"coefficient_milli": 1, "exponent_milli": 1000, "margin_milli": 1000, "min_mib": 1}
    value = policy(proof_mode="stream", heap_fit=fit)
    journal = Journal({"f": formula_bytes(8, [(1, 2)])}, policy_value=value)
    effective = Policy.from_json(value)
    run_policy = make_policy(heap_fit=effective.heap_fit)
    arena: tuple[int, int] | None = (1, 256)
    seen: list[tuple[Any, ...]] = []
    while arena is not None:
        decision, found, _ = real.stream(php(8), policy=run_policy, arena=arena)
        seen.append((outcome(decision), arena))
        if decision.outcome is not None and decision.outcome.value == "VERIFIED_UNSAT":
            break
        assert outcome(decision) == ("EXHAUSTED", "check_memory"), found
        action = next_stream_attempt(_record(decision, found, journal), effective)
        assert action is not None
        assert action.heap_mib >= 2 * arena[0]
        arena = (action.heap_mib, action.stack_mib)
        assert len(seen) <= 8
    assert seen[0] == (("EXHAUSTED", "check_memory"), (1, 256))
    assert seen[-1][0] == ("VERIFIED_UNSAT", None)


def test_real_proof_cap_is_proof_size(real: Real) -> None:
    decision, found, _ = real.stream(php(6), policy=make_policy(proof_cap_bytes=4096))
    assert outcome(decision) == ("EXHAUSTED", "proof_size"), found
    assert found.report is not None and found.report.bytes <= 4096


def test_real_sat_goes_to_model_parsing(real: Real) -> None:
    sat = formula(3, [(1, 2), (-1, 3)])
    decision, found, _ = real.stream(sat)
    assert outcome(decision) == ("parse_model",)
    assert found.solver.result.exit == 10


@pytest.mark.parametrize(("holes", "cube"), [(4, ()), (5, ()), (6, ())])
def test_real_stream_attempt_records_the_file_proof_hash(
    tmp_path: Path, supervisor: Supervisor, tools: StreamTools, holes: int, cube: tuple[int, ...]
) -> None:
    """The wired attempt: a real CDCL leaf in stream mode commits a VERIFIED_UNSAT record
    whose proof fields are those of the real file-mode attempt on the same node."""
    if str(LEAF_TESTS) not in sys.path:
        sys.path.insert(0, str(LEAF_TESTS))
    from cp_leaf_support import Bench

    f = php(holes)
    records: dict[ProofMode, dict[str, Any]] = {}
    for mode in (ProofMode.TRANSIENT, ProofMode.STREAM):
        bench = Bench(tmp_path / mode.value, supervisor, policy=make_policy(proof_mode=mode))
        bench.tools = LeafTools(tools.solver, ARGV, tools.checker, python=tools.python)
        try:
            _, records[mode] = bench.one(f, cube)
            assert bench.work_files() == []
        finally:
            bench.close()
    file, stream = records[ProofMode.TRANSIENT], records[ProofMode.STREAM]
    assert (file["outcome"], file["route"]) == ("VERIFIED_UNSAT", "cdcl"), file
    assert (stream["outcome"], stream["route"]) == ("VERIFIED_UNSAT", "cdcl"), stream
    assert (stream["proof_bytes"], stream["proof_sha256"]) == (
        file["proof_bytes"],
        file["proof_sha256"],
    )
    relay = stream["relay"]
    assert (relay["solver_eof"], relay["all_written"], relay["error"]) == (True, True, None)
    assert success_problem(stream) is None and success_problem(file) is None
