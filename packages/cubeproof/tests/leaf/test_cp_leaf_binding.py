"""The trusted record binding ``leaf.binding`` (specification §2.3, §4.8, §5, §6.1, §6.3).

Pure tests on synthetic, identity-bound evidence. :func:`bind_verified` is the only
constructor of a VERIFIED_UNSAT attempt: it must refuse unless every input and transport
condition holds (specification §5): CNF written = expected digest = re-hash after the check, sealed
proof = re-hashed proof, every file and run of this attempt only, the pinned binaries, the solver's
exit 20 (route cdcl) or the generated unit-v1 proof (route unit), the arena ladder and a last
check with the exact success status. Each refusal names a TOOL_FAILED reason. Every other
outcome is built by :func:`bind_outcome`, which never builds VERIFIED_UNSAT.
"""

from __future__ import annotations

import dataclasses
import signal
from typing import Any

import pytest
from cp_leaf_support import TINY, cnf_model, make_policy, p, sha

from cubeproof.base.errors import ContractError
from cubeproof.base.process import Cause, ProcessResult
from cubeproof.cnf.cubecnf import CnfDigest, cube_cnf_bytes
from cubeproof.cnf.model import ModelResult
from cubeproof.cnf.unit import build_index, refutation
from cubeproof.contracts.assignment import encode_assignment
from cubeproof.contracts.enums import ModelError, Outcome, ProofMode, Route
from cubeproof.contracts.identity import node_id
from cubeproof.contracts.io import Area, artifact_path
from cubeproof.contracts.policy import HeapFit, Policy
from cubeproof.contracts.values import Artifact, Node
from cubeproof.evidence.certify.admission import success_problem
from cubeproof.evidence.schema import Attempt
from cubeproof.evidence.schema.rules import attempt_problem
from cubeproof.leaf.binding import (
    SOURCE_TOOL_UNAVAILABLE,
    AttemptIdentity,
    BindingError,
    CheckEvidence,
    FileHash,
    SolveEvidence,
    ToolPins,
    attempt_limits,
    bind_not_run,
    bind_outcome,
    bind_verified,
    check_verified,
    fitted_check_time_ms,
    initial_arena,
    model_capture_bytes,
    solver_deadline_ms,
)
from cubeproof.tools import checker as ck
from cubeproof.tools import solver as sv
from cubeproof.tools.isolation import PinnedBinary
from cubeproof.tools.process import Launch, ProcessRun
from cubeproof.tools.process_outcome import Action, ArenaLimits, CheckFacts, SolveFacts, classify

WORK = "/w/work"
A1 = "11" * 16
A2 = "22" * 16
SOLVER = PinnedBinary("/t/cadical", "a" * 64)
CHECKER = PinnedBinary("/t/cake_lpr", "b" * 64)
PINS = ToolPins(solver_sha256=SOLVER.sha256, solver_argv=("--lrat",), checker_sha256=CHECKER.sha256)
POLICY = make_policy()
RETAIN_POLICY = POLICY.with_proof_mode(ProofMode.RETAIN)
CUBE = (3,)
NODE = Node(TINY.sha256, CUBE)
CNF = cube_cnf_bytes(TINY, CUBE)
PROOF = b"6 1 0 1 2 0\n7 0 6 3 4 0\n"
SUCCESS = ck.SUCCESS_STDOUT


def result(
    *,
    exit: int | None = 0,
    signal_number: int | None = None,
    stdout: str = "",
    stderr: str = "",
    stdout_bytes: int | None = None,
    truncated: bool = False,
    started: bool = True,
    cause: str | None = None,
) -> ProcessResult:
    return ProcessResult(
        started=started,
        exit=exit,
        signal=signal_number,
        elapsed_ms=3,
        stdout_tail=stdout,
        stderr_tail=stderr,
        stdout_bytes=len(stdout.encode()) if stdout_bytes is None else stdout_bytes,
        stdout_truncated=truncated,
        cause=cause,
        conflicts=None,
    )


def identity(route: Route = Route.CDCL, attempt_id: str = A1, **changes: Any) -> AttemptIdentity:
    values: dict[str, Any] = {
        "node": NODE,
        "attempt_id": attempt_id,
        "policy": POLICY,
        "route": route,
        "work_dir": WORK,
        "cnf_sha256": CnfDigest(TINY).cnf_sha256(CUBE),
    }
    values.update(changes)
    return AttemptIdentity(**values)


def file_hash(path: str, data: bytes, attempt_id: str = A1) -> FileHash:
    return FileHash(attempt_id=attempt_id, path=path, bytes=len(data), sha256=sha(data))


def solve_evidence(
    ident: AttemptIdentity, run: ProcessRun | None = None, **launch: Any
) -> SolveEvidence:
    policy = ident.policy
    options: dict[str, Any] = {
        "binary": SOLVER,
        "args": sv.solver_args(PINS.solver_argv, ident.cnf_path, ident.proof_path),
        "cwd": WORK,
        "memory_bytes": policy.solver_memory_bytes,
        "file_bytes": policy.proof_cap_bytes,
        "deadline_ms": policy.leaf_time_ms_for_depth(len(ident.node.cube)),
        "term_grace_ms": policy.term_grace_ms,
        "watch": (ident.proof_path, policy.proof_cap_bytes),
        "stdout_capture": model_capture_bytes(TINY.variables),
    }
    options.update(launch)
    if run is None:
        run = ProcessRun(result(exit=20, stdout="s UNSATISFIABLE\n"))
    return SolveEvidence(launch=Launch(**options), run=run)


def check_evidence(
    ident: AttemptIdentity,
    heap: int,
    stack: int,
    run: ProcessRun | None = None,
    *,
    proof_bytes: int = len(PROOF),
    **launch: Any,
) -> CheckEvidence:
    policy = ident.policy
    options: dict[str, Any] = {
        "binary": CHECKER,
        "args": ck.checker_args(heap, stack, ident.cnf_path, ident.proof_path),
        "cwd": WORK,
        "memory_bytes": ck.checker_memory_bytes(heap, stack, policy.checker_slack_mib),
        "deadline_ms": fitted_check_time_ms(policy, proof_bytes),
        "term_grace_ms": policy.term_grace_ms,
    }
    options.update(launch)
    if run is None:
        run = ProcessRun(result(stdout=SUCCESS))
    return CheckEvidence(launch=Launch(**options), run=run, heap_mib=heap, stack_mib=stack)


def arena(kind: str) -> ProcessRun:
    code, message = p.ARENA[kind]
    return ProcessRun(result(exit=code, stderr=message.decode()))


class Case:
    """A complete, valid set of evidence for a VERIFIED_UNSAT; tests change one part."""

    def __init__(self, route: Route = Route.CDCL, proof: bytes = PROOF) -> None:
        self.identity = identity(route)
        self.proof = proof
        ident = self.identity
        heap, stack = initial_arena(POLICY, len(proof))
        self.kwargs: dict[str, Any] = {
            "cnf_written": file_hash(ident.cnf_path, CNF),
            "cnf_final": file_hash(ident.cnf_path, CNF),
            "proof_sealed": file_hash(ident.proof_path, proof),
            "proof_final": file_hash(ident.proof_path, proof),
            "checks": [check_evidence(ident, heap, stack, proof_bytes=len(proof))],
            "solve": solve_evidence(ident) if route is Route.CDCL else None,
            "unit_proof_sha256": sha(proof) if route is Route.UNIT else None,
        }

    def bind(self, **changes: Any) -> Attempt:
        values = dict(self.kwargs)
        values.update(changes)
        return bind_verified(self.identity, PINS, **values)


def assert_refused(case: Case, reason: str, **changes: Any) -> BindingError:
    with pytest.raises(BindingError) as caught:
        case.bind(**changes)
    assert caught.value.reason == reason, caught.value
    return caught.value


# -- identity --------------------------------------------------------------------------------


def test_identity_derives_the_attempt_paths_from_node_and_attempt() -> None:
    ident = identity()
    nid = node_id(TINY.sha256, CUBE)
    assert ident.node_id == nid
    assert ident.cnf_path == f"{WORK}/{nid}-{A1}.cnf"
    assert ident.proof_path == f"{WORK}/{nid}-{A1}.lrat"
    assert identity(attempt_id=A2).cnf_path != ident.cnf_path


def test_a_stream_identity_binds_file_evidence_only_on_the_unit_route() -> None:
    """A unit refutation under a stream policy follows the file protocol (specification §4.8,
    §6.4: relay null); a CDCL proof under stream binds only through ``bind_stream_verified``
    (tests/stream/test_cp_stream_leaf.py), never from file evidence."""
    stream = POLICY.with_proof_mode(ProofMode.STREAM)
    assert identity(policy=stream).policy.proof_mode is ProofMode.STREAM
    unit = Case(Route.UNIT)
    unit.identity = dataclasses.replace(unit.identity, policy=stream)
    value = unit.bind().to_json()
    assert (value["outcome"], value["route"], value["proof_mode"]) == (
        "VERIFIED_UNSAT",
        "unit",
        "stream",
    )
    assert value["relay"] is None and value["retained"] is None
    assert success_problem(value) is None and attempt_problem(value) is None
    cdcl = Case()
    cdcl.identity = dataclasses.replace(cdcl.identity, policy=stream)
    refused = assert_refused(cdcl, "protocol")
    assert refused.rule == "binding.mode"
    with pytest.raises(BindingError) as caught:
        check_verified(cdcl.identity, PINS, **cdcl.kwargs)
    assert caught.value.reason == "protocol"


def test_retain_is_a_file_mode_identity() -> None:
    ident = identity(policy=RETAIN_POLICY)
    assert ident.policy.proof_mode is ProofMode.RETAIN
    assert ident.proof_path == identity().proof_path


@pytest.mark.parametrize(
    "changes",
    [
        {"attempt_id": "x" * 32},
        {"attempt_id": "11" * 15},
        {"work_dir": "relative/work"},
        {"work_dir": "/w/../work"},
        {"work_dir": "/w/work/"},
        {"cnf_sha256": "nothex"},
    ],
)
def test_identity_values_are_validated(changes: dict[str, Any]) -> None:
    with pytest.raises((ContractError, ValueError)):
        identity(**changes)


# -- VERIFIED_UNSAT --------------------------------------------------------------------------


@pytest.mark.parametrize("route", [Route.CDCL, Route.UNIT])
def test_a_complete_binding_gives_the_verified_record(route: Route) -> None:
    case = Case(route)
    attempt = case.bind()
    ident = case.identity
    value = attempt.to_json()
    assert value["outcome"] == "VERIFIED_UNSAT" and value["reason"] is None
    assert value["node"] == {"formula_sha256": TINY.sha256, "cube": [3]}
    assert value["node_id"] == ident.node_id and value["attempt_id"] == A1
    assert value["policy_sha256"] == POLICY.sha256
    assert value["route"] == route.value and value["proof_mode"] == "transient"
    assert value["cnf_sha256"] == sha(CNF)
    assert (value["proof_bytes"], value["proof_sha256"]) == (len(PROOF), sha(PROOF))
    assert value["relay"] is None and value["assignment"] is None
    assert value["retained"] is None and value["quarantined"] is None
    assert len(value["checks"]) == 1
    assert value["checks"][0]["result"]["stdout_tail"] == SUCCESS
    assert value["limits"] == {
        "solver_time_ms": None if route is Route.UNIT else 60_000,
        "proof_cap_bytes": POLICY.proof_cap_bytes,
        "solver_memory_bytes": POLICY.solver_memory_bytes,
        "check_time_ms": fitted_check_time_ms(POLICY, len(PROOF)),
    }
    if route is Route.CDCL:
        assert value["solver"]["exit"] == 20 and value["solver"]["started"] is True
    else:
        assert value["solver"] is None
    files = value["diagnostics"]["files"]
    assert (
        files["cnf"]["written"] == files["cnf"]["final"] == {"bytes": len(CNF), "sha256": sha(CNF)}
    )
    assert (
        files["proof"]["sealed"]
        == files["proof"]["final"]
        == {
            "bytes": len(PROOF),
            "sha256": sha(PROOF),
        }
    )
    # the certifier's own conditions and the field rules hold for what the binding built
    assert success_problem(value) is None
    assert attempt_problem(value, TINY.variables) is None


def test_diagnostics_are_kept_but_cannot_replace_the_file_evidence() -> None:
    case = Case()
    attempt = case.bind(diagnostics={"secondary": ["solver:exit:20"], "files": "forged"})
    value = attempt.to_json()["diagnostics"]
    assert value["secondary"] == ["solver:exit:20"]
    assert value["files"]["cnf"]["final"]["sha256"] == sha(CNF)


def test_the_solver_conflicts_are_recorded_from_its_statistics() -> None:
    case = Case()
    run = ProcessRun(result(exit=20, stdout="c conflicts: 17 x\ns UNSATISFIABLE\n"))
    attempt = case.bind(solve=solve_evidence(case.identity, run))
    assert attempt.to_json()["solver"]["conflicts"] == 17


# -- files: written, final, sealed; attempt and path binding ---------------------------------


def test_the_cnf_must_be_the_expected_digest_when_written() -> None:
    case = Case()
    ident = case.identity
    other = cube_cnf_bytes(TINY, ())
    error = assert_refused(
        case,
        "file_changed",
        cnf_written=file_hash(ident.cnf_path, other),
        cnf_final=file_hash(ident.cnf_path, other),
    )
    assert error.rule == "binding.cnf"


def test_the_cnf_must_be_unchanged_after_the_check() -> None:
    case = Case()
    path = case.identity.cnf_path
    changed = CNF + b"c\n"
    assert_refused(case, "file_changed", cnf_final=file_hash(path, changed))
    flipped = CNF[:-2] + b"4\n"  # same size, other bytes
    assert len(flipped) == len(CNF) and flipped != CNF
    error = assert_refused(case, "file_changed", cnf_final=file_hash(path, flipped))
    assert error.rule == "binding.cnf"


def test_a_wrong_header_is_never_the_expected_cnf() -> None:
    """CNF(F, C) has ``p cnf V (M+d)``; bytes with M in the header are another file."""
    case = Case()
    body = CNF.split(b"\n", 1)[1]
    wrong = f"p cnf {TINY.variables} {TINY.clauses}\n".encode() + body
    assert wrong != CNF
    path = case.identity.cnf_path
    assert_refused(
        case, "file_changed", cnf_written=file_hash(path, wrong), cnf_final=file_hash(path, wrong)
    )


def test_the_expected_digest_is_the_independent_one() -> None:
    """An identity whose cnf_sha256 is not CNF(F, C) of its node cannot be verified."""
    case = Case()
    case.identity = identity(cnf_sha256=sha(cube_cnf_bytes(TINY, ())))
    assert_refused(case, "file_changed")


def test_the_proof_must_be_unchanged_after_the_check() -> None:
    case = Case()
    path = case.identity.proof_path
    other = b"6 2 0 1 3 0\n7 0 6 2 4 0\n"
    assert_refused(case, "file_changed", proof_final=file_hash(path, other))
    same_hash_other_size = FileHash(A1, path, len(PROOF) + 1, sha(PROOF))
    assert_refused(case, "file_changed", proof_final=same_hash_other_size)


@pytest.mark.parametrize("which", ["cnf_written", "cnf_final", "proof_sealed", "proof_final"])
def test_files_of_another_attempt_are_refused(which: str) -> None:
    case = Case()
    other = identity(attempt_id=A2)
    path = other.cnf_path if which.startswith("cnf") else other.proof_path
    data = CNF if which.startswith("cnf") else PROOF
    # the other attempt's path, and this attempt's path reported for the other attempt
    assert_refused(case, "file_changed", **{which: file_hash(path, data, A2)})
    own = case.identity.cnf_path if which.startswith("cnf") else case.identity.proof_path
    assert_refused(case, "file_changed", **{which: file_hash(own, data, A2)})
    assert_refused(case, "file_changed", **{which: file_hash(path, data, A1)})


def test_a_swapped_proof_and_cnf_are_refused() -> None:
    case = Case()
    ident = case.identity
    assert_refused(
        case,
        "file_changed",
        proof_sealed=file_hash(ident.cnf_path, PROOF),
        proof_final=file_hash(ident.cnf_path, PROOF),
    )
    assert_refused(
        case,
        "file_changed",
        cnf_written=file_hash(ident.proof_path, CNF),
        cnf_final=file_hash(ident.proof_path, CNF),
    )


@pytest.mark.parametrize("which", ["cnf_written", "cnf_final", "proof_sealed", "proof_final"])
def test_every_file_measurement_is_required(which: str) -> None:
    case = Case()
    with pytest.raises((BindingError, TypeError, ValueError)):
        case.bind(**{which: None})


def test_the_unit_proof_must_be_the_generated_one() -> None:
    proof = refutation(build_index(TINY), (1,))
    assert proof is not None
    case = Case(Route.UNIT, proof)
    assert case.bind().to_json()["route"] == "unit"
    assert_refused(case, "file_changed", unit_proof_sha256=sha(proof + b"\n"))
    with pytest.raises((BindingError, ValueError)):
        case.bind(unit_proof_sha256=None)


def test_routes_and_solver_evidence_must_agree() -> None:
    cdcl = Case(Route.CDCL)
    with pytest.raises((BindingError, ValueError)):
        cdcl.bind(solve=None)
    unit = Case(Route.UNIT)
    with pytest.raises((BindingError, ValueError)):
        unit.bind(solve=solve_evidence(unit.identity))


# -- the solver ------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "run",
    [
        ProcessRun(result(exit=10, stdout="s SATISFIABLE\n")),
        ProcessRun(result(exit=0)),
        ProcessRun(result(exit=None, signal_number=int(signal.SIGTERM))),
        ProcessRun(result(exit=None, started=False, cause="launch"), (Cause.LAUNCH,)),
        ProcessRun(result(exit=20), (Cause.DEADLINE,)),
        ProcessRun(result(exit=20), (Cause.PROOF_CAP,)),
        ProcessRun(result(exit=20), (Cause.BINARY_CHANGED,)),
        ProcessRun(result(exit=20), (Cause.HELD_OPEN,)),
    ],
)
def test_only_a_clean_solver_exit_20_binds(run: ProcessRun) -> None:
    case = Case()
    expected = (
        ("binary_changed", "binding.solver_binary")
        if Cause.BINARY_CHANGED in run.causes
        else ("protocol", "binding.solver_status")
    )
    with pytest.raises(BindingError) as caught:
        case.bind(solve=solve_evidence(case.identity, run))
    # refused by the solver condition itself, not only by the final success.* re-check
    assert (caught.value.reason, caught.value.rule) == expected


def test_the_solver_must_be_the_pinned_binary_on_this_attempts_files() -> None:
    case = Case()
    ident = case.identity
    other = identity(attempt_id=A2)
    forged = PinnedBinary(SOLVER.path, "c" * 64)
    assert_refused(case, "binary_changed", solve=solve_evidence(ident, binary=forged))
    swapped = sv.solver_args(PINS.solver_argv, other.cnf_path, other.proof_path)
    assert_refused(case, "file_changed", solve=solve_evidence(ident, args=swapped))
    reversed_args = sv.solver_args(PINS.solver_argv, ident.proof_path + ".x", ident.cnf_path)
    assert_refused(case, "file_changed", solve=solve_evidence(ident, args=reversed_args))
    argv = sv.solver_args(("--lrat", "-q"), ident.cnf_path, ident.proof_path)
    assert_refused(case, "protocol", solve=solve_evidence(ident, args=argv))


@pytest.mark.parametrize(
    "launch",
    [
        {"memory_bytes": POLICY.solver_memory_bytes + 1},
        {"file_bytes": None},
        {"file_bytes": POLICY.proof_cap_bytes * 2},
        {"deadline_ms": None},
        {"deadline_ms": 1},
        {"watch": None},
    ],
)
def test_the_solver_ran_under_the_recorded_limits(launch: dict[str, Any]) -> None:
    case = Case()
    assert_refused(case, "protocol", solve=solve_evidence(case.identity, **launch))


# -- the checker ------------------------------------------------------------------------------


def wrong_success_runs() -> list[tuple[str, ProcessRun]]:
    runs: list[tuple[str, ProcessRun]] = []
    for output in p.WRONG_SUCCESS_OUTPUTS:
        text = output.decode("utf-8", "replace")
        runs.append(
            (f"stdout={output!r}", ProcessRun(result(stdout=text, stdout_bytes=len(output))))
        )
    runs += [
        ("exit 1", ProcessRun(result(exit=1, stdout=SUCCESS))),
        ("exit 20", ProcessRun(result(exit=20, stdout=SUCCESS))),
        ("signal", ProcessRun(result(exit=None, signal_number=9, stdout=SUCCESS))),
        ("truncated", ProcessRun(result(stdout=SUCCESS, truncated=True))),
        ("18 bytes", ProcessRun(result(stdout=SUCCESS, stdout_bytes=18))),
        ("stderr cut", ProcessRun(result(stdout=SUCCESS), stderr_truncated=True)),
        ("arena text", ProcessRun(result(stdout=SUCCESS, stderr="CakeML heap space exhausted.\n"))),
        ("deadline", ProcessRun(result(stdout=SUCCESS), (Cause.DEADLINE,))),
        ("cancelled", ProcessRun(result(stdout=SUCCESS), (Cause.CANCELLED,))),
        ("memory", ProcessRun(result(stdout=SUCCESS), (Cause.MEMORY_EVENT,))),
        ("held open", ProcessRun(result(stdout=SUCCESS), (Cause.HELD_OPEN,))),
        (
            "not started",
            ProcessRun(result(exit=None, started=False, cause="launch"), (Cause.LAUNCH,)),
        ),
    ]
    return runs


@pytest.mark.parametrize(
    ("name", "run"), wrong_success_runs(), ids=[n for n, _ in wrong_success_runs()]
)
def test_only_the_exact_checker_status_binds(name: str, run: ProcessRun) -> None:
    case = Case()
    heap, stack = initial_arena(POLICY, len(PROOF))
    with pytest.raises(BindingError) as caught:
        case.bind(checks=[check_evidence(case.identity, heap, stack, run)])
    # refused by the exact-status condition itself, not only by the final success.* re-check
    assert (caught.value.reason, caught.value.rule) == ("protocol", "binding.checker_status"), name


def test_at_least_one_check_is_required() -> None:
    assert_refused(Case(), "protocol", checks=[])


def test_the_checker_must_be_the_pinned_binary_on_this_attempts_files() -> None:
    case = Case()
    ident = case.identity
    other = identity(attempt_id=A2)
    heap, stack = initial_arena(POLICY, len(PROOF))
    forged = PinnedBinary(CHECKER.path, "c" * 64)
    assert_refused(
        case, "binary_changed", checks=[check_evidence(ident, heap, stack, binary=forged)]
    )
    for cnf, proof in [
        (other.cnf_path, other.proof_path),
        (ident.cnf_path, other.proof_path),
        (other.cnf_path, ident.proof_path),
        (ident.proof_path, ident.cnf_path),
    ]:
        args = ck.checker_args(heap, stack, cnf, proof)
        assert_refused(case, "file_changed", checks=[check_evidence(ident, heap, stack, args=args)])


@pytest.mark.parametrize(
    "launch",
    [
        {"deadline_ms": None},
        {"deadline_ms": fitted_check_time_ms(POLICY, len(PROOF)) + 1},
        {"memory_bytes": (1 << 30) + 1},
    ],
)
def test_the_checker_ran_under_the_fitted_limits(launch: dict[str, Any]) -> None:
    case = Case()
    heap, stack = initial_arena(POLICY, len(PROOF))
    assert_refused(case, "protocol", checks=[check_evidence(case.identity, heap, stack, **launch)])


def test_the_arenas_in_the_args_are_the_recorded_arenas() -> None:
    case = Case()
    ident = case.identity
    heap, stack = initial_arena(POLICY, len(PROOF))
    args = ck.checker_args(heap * 2, stack, ident.cnf_path, ident.proof_path)
    assert_refused(case, "protocol", checks=[check_evidence(ident, heap, stack, args=args)])


def test_the_first_check_uses_the_fitted_initial_arena() -> None:
    case = Case()
    heap, stack = initial_arena(POLICY, len(PROOF))
    assert_refused(case, "protocol", checks=[check_evidence(case.identity, heap * 2, stack)])
    assert_refused(case, "protocol", checks=[check_evidence(case.identity, heap, stack * 2)])


def test_checker_only_retries_follow_the_doubling_ladder() -> None:
    case = Case()
    ident = case.identity
    heap, stack = initial_arena(POLICY, len(PROOF))
    ladder = [
        check_evidence(ident, heap, stack, arena("heap")),
        check_evidence(ident, heap * 2, stack, arena("stack")),
        check_evidence(ident, heap * 2, stack * 2, arena("both")),
        check_evidence(ident, heap * 4, stack * 4),
    ]
    value = case.bind(checks=ladder).to_json()
    assert [(c["heap_mib"], c["stack_mib"]) for c in value["checks"]] == [
        (heap, stack),
        (heap * 2, stack),
        (heap * 2, stack * 2),
        (heap * 4, stack * 4),
    ]
    assert success_problem(value) is None
    # not doubled, doubled twice, the wrong arena doubled, a non-arena failure before success
    for bad in (
        [ladder[0], check_evidence(ident, heap, stack)],
        [ladder[0], check_evidence(ident, heap * 4, stack)],
        [ladder[0], check_evidence(ident, heap, stack * 2)],
        [
            check_evidence(ident, heap, stack, ProcessRun(result(exit=1))),
            check_evidence(ident, heap, stack),
        ],
        [check_evidence(ident, heap, stack), check_evidence(ident, heap, stack)],
        [
            check_evidence(
                ident,
                heap,
                stack,
                ProcessRun(result(exit=1, stderr="CakeML heap space exhausted.\n", stdout=SUCCESS)),
            ),
            check_evidence(ident, heap * 2, stack),
        ],
    ):
        assert_refused(case, "protocol", checks=bad)


def test_a_ladder_beyond_the_maxima_is_refused() -> None:
    policy = make_policy(checker_max_heap_mib=512, stream_heap_mib=512)
    case = Case()
    case.identity = identity(policy=policy)
    ident = case.identity
    heap, stack = initial_arena(policy, len(PROOF))
    assert heap == 512
    checks = [
        check_evidence(ident, heap, stack, arena("heap")),
        check_evidence(ident, heap * 2, stack),
    ]
    assert_refused(case, "protocol", checks=checks, solve=solve_evidence(ident))


def earlier_check_runs() -> list[tuple[str, ProcessRun, bool]]:
    """Runs of a first check: ``(name, run, whether specification §6.3 row 5 retries it)``."""
    heap_exit, heap_message = p.ARENA["heap"]
    heap_text = heap_message.decode()
    return [
        ("heap", arena("heap"), True),
        ("stack", arena("stack"), True),
        ("both", arena("both"), True),
        # the diagnostic in the stderr tail after more stderr than the tail keeps
        (
            "heap, stderr cut",
            ProcessRun(result(exit=heap_exit, stderr=heap_text), stderr_truncated=True),
            True,
        ),
        ("heap, other exit", ProcessRun(result(exit=7, stderr=heap_text)), False),
        (
            "heap, success mark",
            ProcessRun(result(exit=heap_exit, stderr=heap_text, stdout=SUCCESS)),
            False,
        ),
        (
            "heap, stdout cut",
            ProcessRun(result(exit=heap_exit, stderr=heap_text, truncated=True)),
            False,
        ),
        (
            "heap, deadline",
            ProcessRun(result(exit=heap_exit, stderr=heap_text), (Cause.DEADLINE,)),
            False,
        ),
        (
            "heap, memory event",
            ProcessRun(result(exit=heap_exit, stderr=heap_text), (Cause.MEMORY_EVENT,)),
            False,
        ),
        ("heap, signal", ProcessRun(result(exit=None, signal_number=9, stderr=heap_text)), False),
        ("rejection", ProcessRun(result(stderr="c Checking failed\n")), False),
    ]


@pytest.mark.parametrize(
    ("name", "run", "retried"),
    earlier_check_runs(),
    ids=[name for name, _, _ in earlier_check_runs()],
)
def test_the_binding_takes_an_earlier_check_exactly_when_the_table_retries_it(
    name: str, run: ProcessRun, retried: bool
) -> None:
    """The state machine's specification §6.3 decision (``classify``) and the binding's
    ladder apply one rule. An earlier check binds iff the table retried it, and then exactly
    with the arena the table chose; otherwise every next arena is refused."""
    case = Case()
    ident = case.identity
    heap, stack = initial_arena(POLICY, len(PROOF))
    decision = classify(
        solve=SolveFacts(run=case.kwargs["solve"].run, proof_complete=True),
        checks=[CheckFacts(run=run, heap_mib=heap, stack_mib=stack)],
        limits=ArenaLimits(
            max_heap_mib=POLICY.checker_max_heap_mib, max_stack_mib=POLICY.checker_max_stack_mib
        ),
    )
    assert (decision.action is Action.RETRY_CHECK) is retried, (name, decision)
    first = check_evidence(ident, heap, stack, run)
    if retried:
        assert decision.arena is not None
        value = case.bind(checks=[first, check_evidence(ident, *decision.arena)]).to_json()
        assert [(c["heap_mib"], c["stack_mib"]) for c in value["checks"]] == [
            (heap, stack),
            decision.arena,
        ]
        assert success_problem(value) is None
        others = {(heap * 2, stack), (heap, stack * 2), (heap * 2, stack * 2), (heap, stack)}
        others.discard(decision.arena)
    else:
        others = {(heap * 2, stack), (heap, stack * 2), (heap * 2, stack * 2), (heap, stack)}
    for following in sorted(others):
        error = assert_refused(case, "protocol", checks=[first, check_evidence(ident, *following)])
        assert error.rule == "binding.ladder", (name, following)


# -- every other outcome ----------------------------------------------------------------------


def test_bind_outcome_never_builds_verified_unsat() -> None:
    case = Case()
    with pytest.raises((BindingError, ValueError)):
        bind_outcome(
            case.identity, PINS, outcome=Outcome.VERIFIED_UNSAT, reason=None, **case.kwargs
        )


def test_rejected_and_exhausted_checks_keep_the_proof_and_the_raw_checks() -> None:
    case = Case()
    ident = case.identity
    heap, stack = initial_arena(POLICY, len(PROOF))
    rejected = check_evidence(ident, heap, stack, ProcessRun(result(stderr="c Checking failed\n")))
    kwargs = dict(case.kwargs, checks=[rejected])
    kwargs.pop("unit_proof_sha256")
    attempt = bind_outcome(ident, PINS, outcome=Outcome.CHECK_REJECTED, reason="rejected", **kwargs)
    value = attempt.to_json()
    assert (value["proof_bytes"], value["proof_sha256"]) == (len(PROOF), sha(PROOF))
    assert value["checks"][0]["result"]["stderr_tail"] == "c Checking failed\n"
    assert value["quarantined"] is None
    assert value["limits"]["check_time_ms"] == fitted_check_time_ms(POLICY, len(PROOF))
    assert attempt_problem(value, TINY.variables) is None


def test_a_solver_limit_has_no_proof_and_the_base_check_time() -> None:
    ident = identity()
    run = ProcessRun(
        result(exit=None, signal_number=int(signal.SIGTERM), cause="deadline"), (Cause.DEADLINE,)
    )
    attempt = bind_outcome(
        ident,
        PINS,
        outcome=Outcome.EXHAUSTED,
        reason="time",
        solve=solve_evidence(ident, run),
        cnf_written=file_hash(ident.cnf_path, CNF),
        cnf_final=file_hash(ident.cnf_path, CNF),
    )
    value = attempt.to_json()
    assert value["proof_bytes"] is None and value["proof_sha256"] is None
    assert value["checks"] == []
    assert value["solver"]["signal"] == int(signal.SIGTERM)
    assert value["limits"]["check_time_ms"] == POLICY.checker_time_base_ms
    assert value["limits"]["solver_time_ms"] == 60_000


def test_models_record_the_assignment_and_no_proof() -> None:
    sat_cube = (3,)
    ident = identity()
    run = ProcessRun(result(exit=10, stdout="s SATISFIABLE\n"))
    model = ModelResult(encode_assignment([True, False, True]), None)
    value = bind_outcome(
        ident,
        PINS,
        outcome=Outcome.MODEL,
        reason=None,
        solve=solve_evidence(ident, run),
        model=model,
        cnf_written=file_hash(ident.cnf_path, cube_cnf_bytes(TINY, sat_cube)),
        cnf_final=file_hash(ident.cnf_path, cube_cnf_bytes(TINY, sat_cube)),
    ).to_json()
    assert value["outcome"] == "MODEL" and value["assignment"] == model.assignment
    assert value["model_error"] is None and value["proof_sha256"] is None
    violated = ModelResult(
        encode_assignment([True, False, True]), ModelError.VIOLATED, "clause 1", 1
    )
    value = bind_outcome(
        ident,
        PINS,
        outcome=Outcome.INVALID_MODEL,
        reason="violated",
        solve=solve_evidence(ident, run),
        model=violated,
    ).to_json()
    assert (value["reason"], value["model_error"]) == ("violated", "violated")
    assert value["diagnostics"]["model"]["violated_clause"] == 1
    syntax = ModelResult(None, ModelError.SYNTAX, "line 2: x")
    value = bind_outcome(
        ident,
        PINS,
        outcome=Outcome.INVALID_MODEL,
        reason="syntax",
        solve=solve_evidence(ident, run),
        model=syntax,
    ).to_json()
    assert value["assignment"] is None and value["model_error"] == "syntax"


def test_a_unit_model_has_no_solver_and_no_solver_time() -> None:
    ident = identity(Route.UNIT)
    model = ModelResult(encode_assignment([True, True, True]), ModelError.VIOLATED, "x", 1)
    value = bind_outcome(
        ident, PINS, outcome=Outcome.INVALID_MODEL, reason="violated", model=model
    ).to_json()
    assert value["solver"] is None and value["route"] == "unit"
    assert value["limits"]["solver_time_ms"] is None


@pytest.mark.parametrize(
    ("outcome", "reason", "model"),
    [
        (Outcome.MODEL, None, None),
        (Outcome.MODEL, "protocol", ModelResult(encode_assignment([True] * 3), None)),
        (Outcome.INVALID_MODEL, "syntax", ModelResult(encode_assignment([True] * 3), None)),
        (Outcome.EXHAUSTED, "rejected", None),
        (Outcome.TOOL_FAILED, "time", None),
        (Outcome.TOOL_FAILED, None, None),
    ],
)
def test_inconsistent_outcomes_are_refused(
    outcome: Outcome, reason: str | None, model: ModelResult | None
) -> None:
    ident = identity()
    run = ProcessRun(result(exit=10, stdout="s SATISFIABLE\n"))
    with pytest.raises((BindingError, ContractError, ValueError)):
        bind_outcome(
            ident,
            PINS,
            outcome=outcome,
            reason=reason,
            solve=solve_evidence(ident, run),
            model=model,
        )


def test_other_outcomes_are_bound_to_this_attempts_runs_and_files() -> None:
    ident = identity()
    other = identity(attempt_id=A2)
    heap, stack = initial_arena(POLICY, len(PROOF))
    swapped = check_evidence(
        ident, heap, stack, args=ck.checker_args(heap, stack, other.cnf_path, other.proof_path)
    )
    with pytest.raises(BindingError):
        bind_outcome(
            ident,
            PINS,
            outcome=Outcome.CHECK_REJECTED,
            reason="rejected",
            solve=solve_evidence(ident),
            proof_sealed=file_hash(ident.proof_path, PROOF),
            checks=[swapped],
        )
    with pytest.raises(BindingError):
        bind_outcome(
            ident,
            PINS,
            outcome=Outcome.TOOL_FAILED,
            reason="protocol",
            solve=solve_evidence(ident),
            cnf_final=file_hash(other.cnf_path, CNF, A2),
        )


def test_a_tool_failure_keeps_the_mismatching_hashes_as_diagnostics() -> None:
    ident = identity()
    changed = CNF + b"c\n"
    value = bind_outcome(
        ident,
        PINS,
        outcome=Outcome.TOOL_FAILED,
        reason="file_changed",
        solve=solve_evidence(ident),
        cnf_written=file_hash(ident.cnf_path, CNF),
        cnf_final=file_hash(ident.cnf_path, changed),
        proof_sealed=file_hash(ident.proof_path, PROOF),
        proof_final=file_hash(ident.proof_path, PROOF),
        checked=True,
    ).to_json()
    assert value["outcome"] == "TOOL_FAILED" and value["reason"] == "file_changed"
    assert value["cnf_sha256"] == sha(CNF)  # the independent digest, not the measured file
    assert value["diagnostics"]["files"]["cnf"]["final"]["sha256"] == sha(changed)
    assert value["limits"]["check_time_ms"] == fitted_check_time_ms(POLICY, len(PROOF))


#: ``(name, outcome, reason, solver run, model)`` of outcomes other than VERIFIED_UNSAT.
OTHER_OUTCOMES: list[tuple[str, Outcome, str | None, ProcessRun, ModelResult | None]] = [
    (
        "model",
        Outcome.MODEL,
        None,
        ProcessRun(result(exit=10, stdout="s SATISFIABLE\n")),
        ModelResult(encode_assignment([True, False, True]), None),
    ),
    (
        "invalid model",
        Outcome.INVALID_MODEL,
        "violated",
        ProcessRun(result(exit=10, stdout="s SATISFIABLE\n")),
        ModelResult(encode_assignment([True, False, True]), ModelError.VIOLATED, "clause 1", 1),
    ),
    (
        "exhausted",
        Outcome.EXHAUSTED,
        "time",
        ProcessRun(
            result(exit=None, signal_number=int(signal.SIGTERM), cause="deadline"),
            (Cause.DEADLINE,),
        ),
        None,
    ),
    ("tool failed", Outcome.TOOL_FAILED, "protocol", ProcessRun(result(exit=0)), None),
]
OTHER_IDS = [name for name, *_ in OTHER_OUTCOMES]


@pytest.mark.parametrize(
    ("name", "outcome", "reason", "run", "model"), OTHER_OUTCOMES, ids=OTHER_IDS
)
def test_other_outcomes_bind_the_solver_launch(
    name: str, outcome: Outcome, reason: str | None, run: ProcessRun, model: ModelResult | None
) -> None:
    """The solve evidence of every other outcome is this attempt's pinned solver
    with the recorded argv on its own files under the recorded limits."""
    ident = identity()
    other = identity(attempt_id=A2)

    def bind(solve: SolveEvidence) -> Attempt:
        return bind_outcome(ident, PINS, outcome=outcome, reason=reason, solve=solve, model=model)

    assert bind(solve_evidence(ident, run)).to_json()["outcome"] == outcome.value
    refusals: list[tuple[str, str, dict[str, Any]]] = [
        (
            "binary_changed",
            "binding.solver_binary",
            {"binary": PinnedBinary(SOLVER.path, "c" * 64)},
        ),
        (
            "file_changed",
            "binding.solver_files",
            {"args": sv.solver_args(PINS.solver_argv, other.cnf_path, other.proof_path)},
        ),
        (
            "protocol",
            "binding.solver_argv",
            {"args": sv.solver_args(("--lrat", "-q"), ident.cnf_path, ident.proof_path)},
        ),
        ("protocol", "binding.solver_limits", {"memory_bytes": POLICY.solver_memory_bytes + 1}),
        ("protocol", "binding.solver_limits", {"deadline_ms": 1}),
    ]
    for expected, rule, launch in refusals:
        with pytest.raises(BindingError) as caught:
            bind(solve_evidence(ident, run, **launch))
        assert (caught.value.reason, caught.value.rule) == (expected, rule), (name, launch)


@pytest.mark.parametrize(
    ("name", "outcome", "reason", "run", "model"), OTHER_OUTCOMES, ids=OTHER_IDS
)
def test_other_outcomes_need_solve_evidence_exactly_on_route_cdcl(
    name: str, outcome: Outcome, reason: str | None, run: ProcessRun, model: ModelResult | None
) -> None:
    """Route cdcl without its solver run, or route unit with one, is refused by the
    binding itself (the journal schema also refuses it at the append)."""
    for ident, solve in (
        (identity(Route.CDCL), None),
        (identity(Route.UNIT), solve_evidence(identity(Route.UNIT), run)),
    ):
        with pytest.raises(BindingError) as caught:
            bind_outcome(ident, PINS, outcome=outcome, reason=reason, solve=solve, model=model)
        assert (caught.value.reason, caught.value.rule) == ("protocol", "binding.route"), name


@pytest.mark.parametrize("name", ["model", "invalid model"])
def test_a_model_record_carries_no_proof_and_no_checks(name: str) -> None:
    """MODEL/INVALID_MODEL have null proof fields and no checks (specification §4.8)."""
    _, outcome, reason, run, model = OTHER_OUTCOMES[OTHER_IDS.index(name)]
    ident = identity()
    heap, stack = initial_arena(POLICY, len(PROOF))
    sealed = file_hash(ident.proof_path, PROOF)
    base: dict[str, Any] = {
        "outcome": outcome,
        "reason": reason,
        "solve": solve_evidence(ident, run),
        "model": model,
    }
    assert bind_outcome(ident, PINS, **base).to_json()["proof_sha256"] is None
    for extra in (
        {"proof_sealed": sealed},
        {"proof_sealed": sealed, "proof_final": sealed},
        {"proof_sealed": sealed, "checks": [check_evidence(ident, heap, stack)]},
    ):
        with pytest.raises(BindingError) as caught:
            bind_outcome(ident, PINS, **base, **extra)
        assert (caught.value.reason, caught.value.rule) == ("protocol", "binding.model"), extra


# -- limits and sizes ------------------------------------------------------------------------


def test_limits_follow_the_policy_and_the_route() -> None:
    policy = make_policy(leaf_time_ms={"default": 1000, "1": 2000})
    assert attempt_limits(policy, Route.CDCL, 1).to_json()["solver_time_ms"] == 2000
    assert attempt_limits(policy, Route.CDCL, 2).to_json()["solver_time_ms"] == 1000
    assert attempt_limits(policy, Route.UNIT, 1).to_json()["solver_time_ms"] is None
    fitted = attempt_limits(policy, Route.CDCL, 1, 777).to_json()
    assert fitted["check_time_ms"] == 777
    assert (
        attempt_limits(policy, Route.CDCL, 1).to_json()["check_time_ms"]
        == policy.checker_time_base_ms
    )


def test_fitted_values_are_the_tools_layer_formulas() -> None:
    policy = make_policy(heap_fit=HeapFit(min_mib=1), checker_time_base_ms=10)
    for size in (0, 1, 10**6, 3 * 10**8 + 1):
        assert fitted_check_time_ms(policy, size) == ck.check_time_ms(
            size, 10, policy.checker_time_per_100mb_ms
        )
        assert initial_arena(policy, size) == (
            ck.initial_heap_mib(size, policy.heap_fit),
            policy.checker_stack_mib,
        )


@pytest.mark.parametrize("variables", [0, 1, 9, 10, 99, 1000, 123_457])
def test_the_model_capture_holds_a_complete_cadical_model(variables: int) -> None:
    """CaDiCaL prints every variable in ``v`` lines of at most 78 columns; the capture holds
    such an output plus 1 MiB for banners and statistics."""
    literals = [-v if v % 3 else v for v in range(1, variables + 1)]
    for width in (78, 4):
        output = cnf_model.model_lines(literals, width)
        assert model_capture_bytes(variables) >= len(output) + (1 << 20)


def test_the_stream_policy_cannot_bind_file_evidence_of_a_cdcl_proof() -> None:
    """A stream policy with file evidence of a CDCL proof is a refused file binding (route cdcl);
    every other outcome of a stream CDCL leaf needs its stream evidence (no relay value
    could be recorded without it: specification §4.8 ``relay`` non-null iff stream and cdcl)."""
    stream = dataclasses.replace(POLICY, proof_mode=ProofMode.STREAM)
    assert isinstance(stream, Policy)
    case = Case()
    case.identity = dataclasses.replace(case.identity, policy=stream)
    assert assert_refused(case, "protocol").rule == "binding.mode"
    with pytest.raises(BindingError) as caught:
        bind_outcome(
            case.identity,
            PINS,
            outcome=Outcome.TOOL_FAILED,
            reason="crash",
            solve=case.kwargs["solve"],
        )
    assert caught.value.reason == "protocol"


# -- retain and quarantine (specification §4.8, §6.1 step 6, §7.2) -------------------------------


def retained(data: bytes = PROOF, *, area: Area = Area.PROOFS, node: str | None = None) -> Artifact:
    """The artifact of ``data`` below ``area`` for the test node (or ``node``)."""
    name = node_id(TINY.sha256, CUBE) if node is None else node
    return Artifact(artifact_path(area, name, sha(data)), sha(data), len(data))


class RetainCase(Case):
    def __init__(self, route: Route = Route.CDCL, proof: bytes = PROOF) -> None:
        super().__init__(route, proof)
        self.identity = dataclasses.replace(self.identity, policy=RETAIN_POLICY)


@pytest.mark.parametrize("route", [Route.CDCL, Route.UNIT])
def test_a_retained_verified_record_binds_the_published_proof(route: Route) -> None:
    case = RetainCase(route)
    value = case.bind(retained=retained()).to_json()
    assert value["outcome"] == "VERIFIED_UNSAT" and value["proof_mode"] == "retain"
    assert value["retained"] == retained().to_json()
    assert value["retained"]["path"] == f"proofs/{case.identity.node_id}-{sha(PROOF)}.lrat"
    assert value["quarantined"] is None and value["relay"] is None
    assert success_problem(value) is None
    assert attempt_problem(value, TINY.variables) is None


def test_a_retain_mode_verified_record_without_its_reference_is_refused() -> None:
    """No silent downgrade (specification §7.2): retain never builds a VERIFIED_UNSAT with retained
    null."""
    error = assert_refused(RetainCase(), "protocol")
    assert error.rule == "binding.retained"
    error = assert_refused(RetainCase(), "protocol", retained=None)
    assert error.rule == "binding.retained"


@pytest.mark.parametrize(
    "artifact",
    [
        retained(PROOF + b"c\n"),  # another proof
        retained(node="ab" * 32),  # another node's name
        retained(area=Area.QUARANTINE),  # not the retained area
        Artifact(retained().path, sha(PROOF), len(PROOF) + 1),  # another size
        Artifact(retained().path, sha(b"x"), len(PROOF)),  # another hash under the name
    ],
    ids=["proof", "node", "area", "size", "hash"],
)
def test_a_retained_reference_must_be_exactly_the_checked_proof(artifact: Artifact) -> None:
    error = assert_refused(RetainCase(), "file_changed", retained=artifact)
    assert error.rule == "binding.retained"


def test_a_transient_record_never_carries_a_retained_reference() -> None:
    error = assert_refused(Case(), "protocol", retained=retained())
    assert error.rule == "binding.retained"


def test_check_verified_gives_the_sealed_proof_and_refuses_like_the_binding() -> None:
    """The evidence is judged before anything is published (specification §6.1 step 6):
    ``check_verified`` applies every condition of ``bind_verified`` but builds no record."""
    case = RetainCase()
    sealed = check_verified(case.identity, PINS, **case.kwargs)
    assert sealed == case.kwargs["proof_sealed"]
    changed = file_hash(case.identity.proof_path, PROOF + b"c\n")
    with pytest.raises(BindingError) as caught:
        check_verified(case.identity, PINS, **dict(case.kwargs, proof_final=changed))
    assert caught.value.reason == "file_changed"
    with pytest.raises(BindingError) as caught:
        check_verified(case.identity, PINS, **dict(case.kwargs, checks=[]))
    assert caught.value.reason == "protocol"


def test_the_success_recheck_refuses_a_retained_record_without_its_reference(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The final specification §4.8 success re-check also covers the retained field (defence in
    depth)."""
    from cubeproof.leaf import binding

    value = RetainCase().bind(retained=retained()).to_json()
    assert binding._success_problem(value) is None
    assert binding._success_problem(dict(value, retained=None)) == "success.retained"
    other = dict(value, retained=retained(node="ab" * 32).to_json())
    assert binding._success_problem(other) == "success.retained"
    transient = Case().bind().to_json()
    assert binding._success_problem(transient) is None
    assert binding._success_problem(dict(transient, retained=retained().to_json())) == (
        "success.retained"
    )
    assert binding._success_problem(dict(value, proof_mode="stream")) == "success.relay"


def rejected_kwargs(case: Case) -> dict[str, Any]:
    ident = case.identity
    heap, stack = initial_arena(ident.policy, len(PROOF))
    check = check_evidence(ident, heap, stack, ProcessRun(result(stderr="c Checking failed\n")))
    kwargs = dict(case.kwargs, checks=[check])
    kwargs.pop("unit_proof_sha256")
    return kwargs


@pytest.mark.parametrize("case_type", [Case, RetainCase], ids=["transient", "retain"])
def test_a_rejected_proof_binds_its_quarantined_copy(case_type: type[Case]) -> None:
    case = case_type()
    copy = retained(area=Area.QUARANTINE)
    value = bind_outcome(
        case.identity,
        PINS,
        outcome=Outcome.CHECK_REJECTED,
        reason="rejected",
        quarantined=copy,
        **rejected_kwargs(case),
    ).to_json()
    assert value["quarantined"] == copy.to_json() and value["retained"] is None
    assert value["proof_mode"] == case.identity.policy.proof_mode.value
    assert attempt_problem(value, TINY.variables) is None


@pytest.mark.parametrize(
    "copy",
    [
        retained(PROOF + b"c\n", area=Area.QUARANTINE),
        retained(area=Area.QUARANTINE, node="ab" * 32),
        retained(),  # the retained area
    ],
    ids=["proof", "node", "area"],
)
def test_a_quarantined_reference_must_be_the_rejected_proof(copy: Artifact) -> None:
    case = Case()
    with pytest.raises(ValueError):
        bind_outcome(
            case.identity,
            PINS,
            outcome=Outcome.CHECK_REJECTED,
            reason="rejected",
            quarantined=copy,
            **rejected_kwargs(case),
        )


def test_only_a_rejected_proof_is_quarantined() -> None:
    case = Case()
    kwargs = rejected_kwargs(case)
    with pytest.raises(ValueError):
        bind_outcome(
            case.identity,
            PINS,
            outcome=Outcome.TOOL_FAILED,
            reason="protocol",
            quarantined=retained(area=Area.QUARANTINE),
            **kwargs,
        )


def test_every_other_retain_mode_outcome_is_recorded_in_retain_mode_without_reference() -> None:
    case = RetainCase()
    value = bind_outcome(
        case.identity, PINS, outcome=Outcome.CHECK_REJECTED, reason="rejected",
        **rejected_kwargs(case),
    ).to_json()  # fmt: skip
    assert value["proof_mode"] == "retain"
    assert value["retained"] is None and value["quarantined"] is None
    assert attempt_problem(value, TINY.variables) is None


# -- audit attempts: no solver time limit (specification §11.2) ----------------------------------


class AuditCase(Case):
    """A complete VERIFIED_UNSAT of an audit identity: the solver ran without a deadline."""

    def __init__(self, route: Route = Route.CDCL) -> None:
        super().__init__(route)
        self.identity = dataclasses.replace(self.identity, unlimited_solver_time=True)
        if route is Route.CDCL:
            self.kwargs["solve"] = solve_evidence(self.identity, deadline_ms=None)


def test_a_run_identity_is_not_an_audit_identity() -> None:
    assert identity().unlimited_solver_time is False
    assert solver_deadline_ms(identity()) == 60_000
    assert solver_deadline_ms(identity(unlimited_solver_time=True)) is None


@pytest.mark.parametrize("route", [Route.CDCL, Route.UNIT])
def test_an_audit_attempt_records_no_solver_time_limit(route: Route) -> None:
    case = AuditCase(route)
    value = case.bind().to_json()
    assert value["outcome"] == "VERIFIED_UNSAT"
    assert value["limits"]["solver_time_ms"] is None
    # every other limit is the policy's, as for a run attempt
    assert value["limits"] == {**Case(route).bind().to_json()["limits"], "solver_time_ms": None}
    assert success_problem(value) is None and attempt_problem(value, TINY.variables) is None
    check_verified(case.identity, PINS, **case.kwargs)


def test_an_audit_solve_must_have_run_without_a_deadline() -> None:
    case = AuditCase()
    for deadline in (60_000, 1):
        error = assert_refused(
            case, "protocol", solve=solve_evidence(case.identity, deadline_ms=deadline)
        )
        assert error.rule == "binding.solver_limits"
    with pytest.raises(BindingError):
        check_verified(
            case.identity, PINS, **{**case.kwargs, "solve": solve_evidence(case.identity)}
        )


def test_a_run_solve_without_a_deadline_is_never_bound() -> None:
    """The pairing holds in the other direction too: a run attempt cannot drop its limit."""
    case = Case()
    error = assert_refused(case, "protocol", solve=solve_evidence(case.identity, deadline_ms=None))
    assert error.rule == "binding.solver_limits"


def test_audit_limits_are_null_for_every_outcome() -> None:
    ident = identity(unlimited_solver_time=True)
    run = ProcessRun(result(exit=None, signal_number=int(signal.SIGABRT)), ())
    value = bind_outcome(
        ident,
        PINS,
        outcome=Outcome.EXHAUSTED,
        reason="solver_memory",
        solve=solve_evidence(ident, run, deadline_ms=None),
        cnf_written=file_hash(ident.cnf_path, CNF),
        cnf_final=file_hash(ident.cnf_path, CNF),
    ).to_json()
    assert value["limits"]["solver_time_ms"] is None
    assert attempt_problem(value, TINY.variables) is None
    assert attempt_limits(POLICY, Route.CDCL, 1, unlimited_solver_time=True).solver_time_ms is None
    assert attempt_limits(POLICY, Route.CDCL, 1).solver_time_ms == 60_000


def test_an_audit_attempt_never_streams() -> None:
    stream = POLICY.with_proof_mode(ProofMode.STREAM)
    with pytest.raises(ContractError) as caught:
        identity(policy=stream, unlimited_solver_time=True)
    assert caught.value.rule == "leaf.unlimited"
    with pytest.raises(ContractError):
        identity(unlimited_solver_time=1)
    assert identity(policy=RETAIN_POLICY, unlimited_solver_time=True).unlimited_solver_time


def test_a_target_that_was_not_run_has_an_honest_placeholder_record() -> None:
    ident = identity(unlimited_solver_time=True)
    value = bind_not_run(ident, detail="strict audit: source solver aaaa not configured").to_json()
    assert (value["outcome"], value["reason"], value["route"]) == ("TOOL_FAILED", "launch", "cdcl")
    solver = value["solver"]
    assert solver["started"] is False and solver["exit"] is None and solver["signal"] is None
    assert solver["cause"] == SOURCE_TOOL_UNAVAILABLE == "source_tool_unavailable"
    assert value["checks"] == [] and value["proof_sha256"] is None and value["proof_bytes"] is None
    assert value["retained"] is None and value["quarantined"] is None
    assert value["limits"]["solver_time_ms"] is None
    assert value["cnf_sha256"] == ident.cnf_sha256 and value["attempt_id"] == A1
    assert value["diagnostics"]["not_run"].startswith("strict audit")
    files = value["diagnostics"]["files"]
    assert files["cnf"]["written"] is None and files["proof"]["sealed"] is None
    assert attempt_problem(value, TINY.variables) is None
    long = bind_not_run(ident, detail="x" * 1000).to_json()["diagnostics"]["not_run"]
    assert len(long) == 300 and long.endswith("...")


@pytest.mark.parametrize(
    "ident",
    [identity(), identity(Route.UNIT, unlimited_solver_time=True)],
    ids=["run_identity", "unit_route"],
)
def test_only_a_cdcl_audit_identity_can_be_not_run(ident: AttemptIdentity) -> None:
    with pytest.raises(ValueError):
        bind_not_run(ident, detail="x")
