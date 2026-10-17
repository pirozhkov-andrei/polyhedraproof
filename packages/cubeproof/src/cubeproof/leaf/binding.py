"""The trusted binding of one attempt's evidence to its journal record (specification §2.3, §4.8,
§5, §6).

Only :func:`bind_verified` (and, for a stream CDCL proof, :func:`bind_stream_verified`, below)
constructs a VERIFIED_UNSAT attempt (specification §5: "only leaf.binding may
construct a VERIFIED_UNSAT record after also satisfying all input and transport checks").
It is pure: it judges evidence values that the state machine collected and never performs
I/O. It refuses (:class:`BindingError` with a TOOL_FAILED reason) unless **all** hold:

1. Identity. Every file measurement (:class:`FileHash`) names this attempt's ID and its own
   path ``<work>/<node_id>-<attempt_id>.cnf``/``.lrat``; every launch ran the pinned binary
   (its SHA-256 is the machinery's) on exactly these two paths, in this order.
2. CNF. The bytes written and the bytes re-hashed after the last check both have the
   independently computed ``cnf_sha256`` of CNF(F, C) (and the same size).
3. Proof. The sealed proof and the proof re-hashed after the last check have the same size
   and hash; the record's proof fields are those. Route unit: the sealed proof is the
   generated unit-v1 proof (its hash). Route cdcl: the solver run is clean (started, exit 20,
   no signal, no supervisor cause) under the recorded limits and solver argv.
4. Checks. At least one; the first uses the fitted initial arena (specification §8.3); each earlier
   check is a pinned arena diagnostic (no success claim, no cause; the specification §6.3 row 5
   retry condition of ``classify``, whether or not its stderr was cut) followed by exactly the
   doubled arena within the maxima (specification §6.1 step 4, §6.3); every check had the fitted
   check time and its memory cap; the last one is the exact success (``tools.checker.accepts``: exit
   0, no signal, full stdout exactly ``s VERIFIED UNSAT\\n``), with complete stderr, no arena
   message and no supervisor cause.

The built record is then checked once more against the certifier's success conditions
(specification §4.8 success.*). Refusal reasons: ``file_changed`` (a file or path binding fails),
``binary_changed`` (another binary), ``protocol`` (any status, ladder or limit condition).

Stream mode (specification §4.8, §6.4). A unit refutation under a stream policy is a small
file checked through the file protocol: it binds through :func:`bind_verified` like a file
mode (record ``relay`` null). A CDCL proof under a stream policy is never a file: it binds
only through :func:`bind_stream_verified` (and :func:`bind_verified`/:func:`check_verified`
refuse it, ``binding.mode``), which requires, besides the CNF conditions 1-2 above:

S1. Launches. The solver, the relay (the pinned interpreter, :data:`RELAY_ARGS`, the package's
    relay script :data:`RELAY_SCRIPT`) and the checker ran the pinned binaries (the relay
    interpreter's hash is ``ToolPins.python_sha256``) on exactly the attempt's CNF and its two
    FIFOs ``<node_id>-<attempt_id>.lrat`` (solver side) and ``.check.lrat`` (checker side), with
    the recorded solver argv, the policy proof cap as the relay's cap, the solver memory cap
    (no file cap, no watch: nothing is spooled), the relay cap :data:`RELAY_MEMORY_BYTES`, the
    checker's arenas and AS cap, and each a deadline within the paired ``leaf_time_ms``.
S2. Arenas. Heap and stack within ``[stream_heap_mib, checker_max_heap_mib]`` and
    ``[checker_stack_mib, checker_max_stack_mib]`` (a fresh attempt's derived arena is the
    coordinator's choice; any arena of that range checks the same proof).
S3. Runs. The solver run is clean (started, exit 20, no signal, no cause); the relay ended
    cleanly (exit 0, no signal, no cause except a teardown that it outlived by completing)
    and its complete stdout is exactly one report line of a complete transfer (solver EOF,
    all written, no error) within the cap; the checker's result is the exact success with
    complete stderr, no arena message and no cause.

The record's proof fields are the relay's count and hash of that complete transfer, its
``relay`` value is the report's, ``limits.check_time_ms`` the policy base value (no proof
reached a file check; the paired deadline bounds the check). :func:`bind_outcome` builds the
other stream outcomes from the same evidence (:class:`StreamEvidence`, required for a stream
CDCL record because specification §4.8 requires its ``relay`` value): proof fields only for a
complete transfer that the evidence itself shows, never a partial count; no quarantine copy
(specification §6.4: metadata-only, the attempt records the reason).

File modes (specification §4.8, §6.1, §7.2): transient and retain.
In retain mode a VERIFIED_UNSAT record exists only with its ``retained`` reference: exactly
``proofs/<node_id>-<proof_sha256>.lrat`` with the sealed proof's size and hash, published
before the record (specification §6.1 step 6). Without it, or with any other artifact, the binding
refuses (``binding.retained``): a retain-mode VERIFIED_UNSAT with ``retained: null`` would be a
silent downgrade to transient. :func:`check_verified` applies conditions 1-4 without building a
record, so that the attempt judges the evidence **before** it publishes anything;
:func:`bind_verified` applies them again (it is pure and the evidence is immutable) together with
the reference.

:func:`bind_outcome` builds every other outcome; it refuses VERIFIED_UNSAT, still requires the
identity binding of all evidence it is given and records mismatching hashes as diagnostics.
It records the attempt's proof mode, never a retained reference, and a ``quarantined``
reference only for CHECK_REJECTED and only as the ``quarantine/`` name of the rejected proof.
Record diagnostics always carry the measured hashes under ``files`` (written by the binding
itself, never by the caller).

Audit attempts (specification §11.2). An identity with ``unlimited_solver_time`` is an
audit attempt: its CDCL solver runs with **no deadline** and its record has
``limits.solver_time_ms: null``. The pairing is exact in both directions: the launch of such an
identity has ``deadline_ms`` None and the launch of any other identity the policy's
``leaf_time_ms`` (``binding.solver_limits`` otherwise), so a run attempt can neither drop its
limit nor be presented as an unlimited one. The flag is refused for a stream policy (the coupled
stream deadline of specification §6.4 has no unlimited form; audits run a file mode).
:func:`bind_not_run` builds the one record of an audit target whose source solver is unavailable in
a strict audit: TOOL_FAILED ``launch`` with a solver result that was never started and the cause
:data:`SOURCE_TOOL_UNAVAILABLE`, no check, no proof; only an audit identity may carry it.

Obligation of the caller: :class:`ToolPins` must come from the **measured
machinery snapshot** recorded in the journal header/resume (specification §4.6), not from whatever
binary is at hand. Within ``leaf.attempt.LeafAttempt`` the pins are derived from the same
``PinnedBinary`` objects that launch the tools, so the binary-hash comparison holds there by
construction; the specification §5 requirement "the checked binary's hash matches the measured
machinery" therefore rests on the coordinator building ``LeafTools`` from that snapshot, together
with the supervisor's re-hash of the binary before each spawn (``BINARY_CHANGED``).
"""

from __future__ import annotations

import os
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from cubeproof.base.errors import ContractError, ToolError
from cubeproof.base.process import Cause
from cubeproof.base.process import ProcessResult as RunResult
from cubeproof.cnf.model import ModelResult
from cubeproof.contracts.enums import Outcome, ProofMode, Route
from cubeproof.contracts.identity import node_id as compute_node_id
from cubeproof.contracts.io import Area, absolute_path_problem, artifact_path
from cubeproof.contracts.policy import Policy
from cubeproof.contracts.primitives import SUCCESS_LINE, is_hash, is_id128
from cubeproof.contracts.values import Artifact, JsonObject, Node
from cubeproof.evidence.schema import Attempt
from cubeproof.evidence.schema.values import CheckerCheck, Limits, ProcessResult, Relay
from cubeproof.leaf.retry import initial_stream_arena
from cubeproof.tools import checker as ck
from cubeproof.tools import relay as rl
from cubeproof.tools import solver as sv
from cubeproof.tools.isolation import PinnedBinary
from cubeproof.tools.process import Launch, ProcessRun

__all__ = [
    "BINARY_CHANGED",
    "FILE_CHANGED",
    "PROTOCOL",
    "RELAY_ARGS",
    "RELAY_MEMORY_BYTES",
    "RELAY_SCRIPT",
    "SOURCE_TOOL_UNAVAILABLE",
    "AttemptIdentity",
    "BindingError",
    "CheckEvidence",
    "FileHash",
    "RelayEvidence",
    "SolveEvidence",
    "StreamEvidence",
    "ToolPins",
    "attempt_limits",
    "attempt_paths",
    "bind_not_run",
    "bind_outcome",
    "bind_stream_verified",
    "bind_verified",
    "check_verified",
    "checker_launch",
    "fitted_check_time_ms",
    "initial_arena",
    "model_capture_bytes",
    "solver_deadline_ms",
    "solver_launch",
]

FILE_CHANGED = "file_changed"
BINARY_CHANGED = "binary_changed"
PROTOCOL = "protocol"
#: Bytes of solver stdout kept beyond the model's own size: banners and statistics.
_CAPTURE_SLACK = 4 << 20
_SUCCESS_BYTES = len(SUCCESS_LINE.encode("ascii"))
#: The file modes (specification §6.1); a unit proof under stream also follows the file protocol.
_FILE_MODES = (ProofMode.TRANSIENT, ProofMode.RETAIN)
#: The relay's address-space cap (specification §8.3: relay cap 128 MiB).
RELAY_MEMORY_BYTES = 128 << 20
#: The relay script of this package, run by the pinned interpreter: isolated, no
#: site-packages, no bytecode (its bytes are part of the measured source manifest).
RELAY_SCRIPT = os.path.abspath(rl.__file__)
RELAY_ARGS = ("-I", "-S", "-B")
#: The solver cause of an audit placeholder attempt: the source tool was not run.
SOURCE_TOOL_UNAVAILABLE = "source_tool_unavailable"


class BindingError(ToolError):
    """The evidence does not bind; ``reason`` is the TOOL_FAILED reason to record."""

    def __init__(self, reason: str, rule: str, detail: str = "") -> None:
        super().__init__(rule, detail)
        self.reason = reason


def _require(condition: bool, reason: str, rule: str, detail: str) -> None:
    if not condition:
        raise BindingError(reason, rule, detail)


def attempt_paths(work_dir: str, node_id: str, attempt_id: str) -> tuple[str, str]:
    """``(<work>/<node_id>-<attempt_id>.cnf, <work>/<node_id>-<attempt_id>.lrat)`` (specification
    §6.1)."""
    if not is_hash(node_id) or not is_id128(attempt_id):
        raise ContractError("schema", "work paths need a node ID and an attempt ID")
    stem = f"{work_dir}/{node_id}-{attempt_id}"
    return f"{stem}.cnf", f"{stem}.lrat"


@dataclass(frozen=True)
class AttemptIdentity:
    """What one attempt is: node, fresh attempt ID, effective policy, route, work directory
    and the independently computed ``cnf_sha256`` of CNF(F, C) (specification §3.2, §4.8).

    ``unlimited_solver_time`` marks an audit attempt (specification §11.2, module doc): no solver
    deadline, ``solver_time_ms`` null; never with a stream policy."""

    node: Node
    attempt_id: str
    policy: Policy
    route: Route
    work_dir: str
    cnf_sha256: str
    unlimited_solver_time: bool = False

    def __post_init__(self) -> None:
        if type(self.unlimited_solver_time) is not bool:
            raise ContractError("schema", "unlimited_solver_time is a bool")
        streams = isinstance(self.policy, Policy) and self.policy.proof_mode is ProofMode.STREAM
        if self.unlimited_solver_time and streams:
            raise ContractError(
                "leaf.unlimited",
                "an audit attempt without solver time limit runs a file mode, not stream",
            )
        if not isinstance(self.node, Node):
            raise ContractError("schema", "an attempt identity needs a Node")
        if not is_id128(self.attempt_id):
            raise ContractError("schema", f"{self.attempt_id!r} is not an Id128")
        if not isinstance(self.policy, Policy):
            raise ContractError("schema", "an attempt identity needs a Policy")
        if not isinstance(self.route, Route):
            raise ContractError("schema", f"{self.route!r} is not a Route")
        problem = absolute_path_problem(self.work_dir)
        if problem is not None:
            raise ContractError("leaf.work_dir", f"{self.work_dir!r}: {problem}")
        if not is_hash(self.cnf_sha256):
            raise ContractError("schema", f"{self.cnf_sha256!r} is not a Hash")

    @property
    def node_id(self) -> str:
        """Recomputed from the node (never a cached or supplied value)."""
        return compute_node_id(self.node.formula_sha256, self.node.cube)

    @property
    def depth(self) -> int:
        return len(self.node.cube)

    @property
    def cnf_path(self) -> str:
        return attempt_paths(self.work_dir, self.node_id, self.attempt_id)[0]

    @property
    def proof_path(self) -> str:
        """The proof file; in stream mode (route cdcl) the solver side FIFO."""
        return attempt_paths(self.work_dir, self.node_id, self.attempt_id)[1]

    @property
    def checker_fifo_path(self) -> str:
        """The checker side FIFO of a stream attempt: ``<node_id>-<attempt_id>.check.lrat``."""
        return self.proof_path.removesuffix(".lrat") + ".check.lrat"

    @property
    def streams(self) -> bool:
        """A CDCL leaf under a stream policy (specification §6.4); a unit proof follows the file
        protocol."""
        return self.policy.proof_mode is ProofMode.STREAM and self.route is Route.CDCL


@dataclass(frozen=True)
class ToolPins:
    """The measured machinery an attempt binds to: solver hash and argv, checker hash and, for
    the stream mode, the hash of the interpreter that runs the relay (None: no relay)."""

    solver_sha256: str
    solver_argv: tuple[str, ...]
    checker_sha256: str
    python_sha256: str | None = None

    def __post_init__(self) -> None:
        if not is_hash(self.solver_sha256) or not is_hash(self.checker_sha256):
            raise ContractError("schema", "tool pins are SHA-256 hashes")
        if self.python_sha256 is not None and not is_hash(self.python_sha256):
            raise ContractError("schema", "the relay interpreter pin is a SHA-256 hash")
        if type(self.solver_argv) is not tuple:
            raise ContractError("schema", "the solver argv is a tuple")
        sv.check_argv(self.solver_argv)


@dataclass(frozen=True)
class FileHash:
    """Size and SHA-256 of one work file, measured for one attempt (an I/O service result
    the attempt accepted for its own job on that path, or the hash of the bytes it wrote)."""

    attempt_id: str
    path: str
    bytes: int
    sha256: str

    def __post_init__(self) -> None:
        if not is_id128(self.attempt_id) or not is_hash(self.sha256):
            raise ContractError("schema", "a file hash names an attempt ID and a Hash")
        if absolute_path_problem(self.path) is not None:
            raise ContractError("schema", f"{self.path!r} is not an absolute path")
        if type(self.bytes) is not int or self.bytes < 0:
            raise ContractError("schema", f"{self.bytes!r} is not a size")

    def to_json(self) -> dict[str, Any]:
        return {"bytes": self.bytes, "sha256": self.sha256}


@dataclass(frozen=True)
class SolveEvidence:
    """The solver launch exactly as given to the supervisor, and its finished run."""

    launch: Launch
    run: ProcessRun


@dataclass(frozen=True)
class CheckEvidence:
    """One checker launch, its finished run and the arenas it was given."""

    launch: Launch
    run: ProcessRun
    heap_mib: int
    stack_mib: int


@dataclass(frozen=True)
class RelayEvidence:
    """The relay launch exactly as given to the supervisor, and its finished run (its
    captured stdout holds the report)."""

    launch: Launch
    run: ProcessRun


@dataclass(frozen=True)
class StreamEvidence:
    """The three runs of one coupled stream run (``leaf.stream``)."""

    solve: SolveEvidence
    relay: RelayEvidence
    check: CheckEvidence

    def __post_init__(self) -> None:
        if not (
            isinstance(self.solve, SolveEvidence)
            and isinstance(self.relay, RelayEvidence)
            and isinstance(self.check, CheckEvidence)
        ):
            raise ValueError("stream evidence is a solve, a relay and a check")


# -- limits, arenas and launches -----------------------------------------------------------------


def fitted_check_time_ms(policy: Policy, proof_bytes: int) -> int:
    """Specification §8.3: ``max(base_ms, ceil(proof_bytes / 10^8) * per_100mb_ms)``."""
    return ck.check_time_ms(
        proof_bytes, policy.checker_time_base_ms, policy.checker_time_per_100mb_ms
    )


def initial_arena(policy: Policy, proof_bytes: int) -> tuple[int, int]:
    """The first check's ``(heap_mib, stack_mib)``: the fitted heap and the policy stack."""
    return ck.initial_heap_mib(proof_bytes, policy.heap_fit), policy.checker_stack_mib


def model_capture_bytes(variables: int) -> int:
    """Solver stdout kept for model parsing: a complete model of V variables in any line
    layout (at most ``digits+2`` bytes per value plus 3 bytes of line overhead per value),
    the status line and 4 MiB for banners and statistics."""
    if type(variables) is not int or variables < 0:
        raise ValueError(f"{variables!r} is not a variable count")
    return _CAPTURE_SLACK + variables * (len(str(variables)) + 5) + 64


def attempt_limits(
    policy: Policy,
    route: Route,
    depth: int,
    check_time_ms: int | None = None,
    *,
    unlimited_solver_time: bool = False,
) -> Limits:
    """The record's ``limits`` (specification §4.8): solver time only for route cdcl and never for
    an audit attempt (``unlimited_solver_time``, specification §11.2); the fitted check time if the
    proof reached the checker stage, otherwise the policy base value."""
    limited = route is Route.CDCL and not unlimited_solver_time
    solver_time = policy.leaf_time_ms_for_depth(depth) if limited else None
    return Limits(
        solver_time_ms=solver_time,
        proof_cap_bytes=policy.proof_cap_bytes,
        solver_memory_bytes=policy.solver_memory_bytes,
        check_time_ms=policy.checker_time_base_ms if check_time_ms is None else check_time_ms,
    )


def solver_deadline_ms(identity: AttemptIdentity) -> int | None:
    """The solver deadline of a file-mode attempt: the policy's ``leaf_time_ms`` for its depth,
    or None for an audit attempt (``unlimited_solver_time``, specification §11.2)."""
    if identity.unlimited_solver_time:
        return None
    return identity.policy.leaf_time_ms_for_depth(identity.depth)


def _limits(identity: AttemptIdentity, check_time_ms: int | None) -> Limits:
    return attempt_limits(
        identity.policy,
        identity.route,
        identity.depth,
        check_time_ms,
        unlimited_solver_time=identity.unlimited_solver_time,
    )


def solver_launch(
    identity: AttemptIdentity, binary: PinnedBinary, argv: Sequence[str], *, stdout_capture: int
) -> Launch:
    """The one solver run of an attempt (specification §6.1 step 2, §6.2): pinned binary, recorded
    argv, the attempt's CNF and proof paths, AS cap, proof file cap (fsize and watched), deadline
    (none for an audit attempt, :func:`solver_deadline_ms`)."""
    policy = identity.policy
    cap = policy.proof_cap_bytes
    return Launch(
        binary=binary,
        args=sv.solver_args(tuple(argv), identity.cnf_path, identity.proof_path),
        cwd=identity.work_dir,
        memory_bytes=policy.solver_memory_bytes,
        file_bytes=cap,
        deadline_ms=solver_deadline_ms(identity),
        term_grace_ms=policy.term_grace_ms,
        watch=(identity.proof_path, cap),
        stdout_capture=stdout_capture,
    )


def checker_launch(
    identity: AttemptIdentity, binary: PinnedBinary, heap_mib: int, stack_mib: int, proof_bytes: int
) -> Launch:
    """One check of the sealed proof (specification §6.1 step 4): arenas, AS cap heap+stack+slack,
    the fitted check time; the same CNF and proof for every arena retry."""
    policy = identity.policy
    return Launch(
        binary=binary,
        args=ck.checker_args(heap_mib, stack_mib, identity.cnf_path, identity.proof_path),
        cwd=identity.work_dir,
        memory_bytes=ck.checker_memory_bytes(heap_mib, stack_mib, policy.checker_slack_mib),
        deadline_ms=fitted_check_time_ms(policy, proof_bytes),
        term_grace_ms=policy.term_grace_ms,
    )


# -- evidence checks ---------------------------------------------------------------------------


def _file(identity: AttemptIdentity, value: Any, path: str, name: str) -> FileHash:
    _require(isinstance(value, FileHash), PROTOCOL, "binding.missing", f"{name} is required")
    assert isinstance(value, FileHash)
    _require(
        value.attempt_id == identity.attempt_id and value.path == path,
        FILE_CHANGED,
        "binding.attempt",
        f"{name} measured {value.path} for attempt {value.attempt_id}, not {path}",
    )
    return value


def _optional_file(identity: AttemptIdentity, value: Any, path: str, name: str) -> FileHash | None:
    return None if value is None else _file(identity, value, path, name)


def _check_solver_launch(identity: AttemptIdentity, pins: ToolPins, solve: SolveEvidence) -> None:
    launch = solve.launch
    _require(
        launch.binary.sha256 == pins.solver_sha256,
        BINARY_CHANGED,
        "binding.solver_binary",
        f"the solver run used {launch.binary.sha256}, the machinery pins {pins.solver_sha256}",
    )
    args = launch.args
    _require(
        args[-2:] == (identity.cnf_path, identity.proof_path),
        FILE_CHANGED,
        "binding.solver_files",
        f"the solver ran on {args[-2:]!r}",
    )
    _require(
        args == sv.solver_args(pins.solver_argv, identity.cnf_path, identity.proof_path),
        PROTOCOL,
        "binding.solver_argv",
        f"the solver argv {args[:-2]!r} is not {pins.solver_argv!r}",
    )
    policy = identity.policy
    cap = policy.proof_cap_bytes
    _require(
        launch.memory_bytes == policy.solver_memory_bytes
        and launch.file_bytes == cap
        and launch.deadline_ms == solver_deadline_ms(identity)
        and launch.watch == (identity.proof_path, cap),
        PROTOCOL,
        "binding.solver_limits",
        "the solver did not run under the recorded limits",
    )


def _check_checker_launch(
    identity: AttemptIdentity, pins: ToolPins, check: CheckEvidence, proof_bytes: int
) -> None:
    launch = check.launch
    _require(
        launch.binary.sha256 == pins.checker_sha256,
        BINARY_CHANGED,
        "binding.checker_binary",
        f"the check used {launch.binary.sha256}, the machinery pins {pins.checker_sha256}",
    )
    args = launch.args
    _require(
        args[-2:] == (identity.cnf_path, identity.proof_path),
        FILE_CHANGED,
        "binding.checker_files",
        f"the checker ran on {args[-2:]!r}",
    )
    heap, stack = check.heap_mib, check.stack_mib
    _require(
        args == ck.checker_args(heap, stack, identity.cnf_path, identity.proof_path),
        PROTOCOL,
        "binding.checker_args",
        f"checker arguments {args[:-2]!r} are not the recorded arenas {heap}/{stack}",
    )
    policy = identity.policy
    _require(
        launch.memory_bytes == ck.checker_memory_bytes(heap, stack, policy.checker_slack_mib)
        and launch.deadline_ms == fitted_check_time_ms(policy, proof_bytes),
        PROTOCOL,
        "binding.checker_limits",
        "the check did not run under the fitted limits",
    )


def _clean_solve(solve: SolveEvidence) -> None:
    run = solve.run
    _require(
        Cause.BINARY_CHANGED not in run.causes,
        BINARY_CHANGED,
        "binding.solver_binary",
        "the solver binary changed",
    )
    result = run.result
    _require(
        not run.causes
        and result.started
        and result.exit == sv.UNSAT_EXIT
        and result.signal is None,
        PROTOCOL,
        "binding.solver_status",
        f"solver: started {result.started}, exit {result.exit}, signal {result.signal}, "
        f"causes {[c.value for c in run.causes]}",
    )


def _arena_step(identity: AttemptIdentity, check: CheckEvidence) -> tuple[int, int]:
    """The next arena after an earlier check, which must be a clean pinned arena failure.

    This is exactly the specification §6.3 row 5 retry condition of
    ``tools.process_outcome.classify`` (pinned diagnostic with its exit code, no supervisor cause,
    no contradictory success), so the state machine retries a check iff the binding accepts it as an
    earlier check. Stderr completeness is deliberately **not** required here: the diagnostic is read
    from the stderr tail, a cut earlier stderr does not make the retry less justified, and the
    record does not carry ``stderr_truncated`` (the certifier could not apply it). Only the
    accepting check must have complete stderr (:func:`_exact_success`)."""
    run = check.run
    result = run.result
    arena = ck.arena_diagnostic(result)
    _require(
        arena is not None and not run.causes and not ck.contradictory_success(result),
        PROTOCOL,
        "binding.ladder",
        "only clean arena exhaustions may precede the accepting check",
    )
    assert arena is not None
    policy = identity.policy
    step = ck.next_arena(
        arena,
        check.heap_mib,
        check.stack_mib,
        max_heap_mib=policy.checker_max_heap_mib,
        max_stack_mib=policy.checker_max_stack_mib,
    )
    _require(step.retry is not None, PROTOCOL, "binding.ladder", "a retry beyond the maxima")
    assert step.retry is not None
    return step.retry


def _exact_success(check: CheckEvidence) -> None:
    run = check.run
    result = run.result
    _require(
        not run.causes
        and not run.stderr_truncated
        and ck.accepts(result)
        and ck.exhausted_arena(result.stderr_tail) is None,
        PROTOCOL,
        "binding.checker_status",
        f"checker: exit {result.exit}, signal {result.signal}, stdout_bytes "
        f"{result.stdout_bytes}, truncated {result.stdout_truncated}, causes "
        f"{[c.value for c in run.causes]}",
    )


def _paired(identity: AttemptIdentity, launch: Launch) -> bool:
    """A deadline within the coupled stream deadline, the solver's ``leaf_time_ms`` (specification
    §6.4)."""
    deadline = launch.deadline_ms
    limit = identity.policy.leaf_time_ms_for_depth(identity.depth)
    return type(deadline) is int and 1 <= deadline <= limit


def _check_stream_launches(
    identity: AttemptIdentity, pins: ToolPins, stream: StreamEvidence
) -> None:
    """S1 and S2 of the module doc: binaries, files, arguments, limits and arenas."""
    solver, relay, checker = stream.solve.launch, stream.relay.launch, stream.check.launch
    _require(
        solver.binary.sha256 == pins.solver_sha256,
        BINARY_CHANGED,
        "binding.solver_binary",
        f"the solver run used {solver.binary.sha256}, the machinery pins {pins.solver_sha256}",
    )
    _require(
        pins.python_sha256 is not None and relay.binary.sha256 == pins.python_sha256,
        BINARY_CHANGED,
        "binding.relay_binary",
        f"the relay ran under {relay.binary.sha256}, the pinned interpreter is "
        f"{pins.python_sha256}",
    )
    _require(
        checker.binary.sha256 == pins.checker_sha256,
        BINARY_CHANGED,
        "binding.checker_binary",
        f"the check used {checker.binary.sha256}, the machinery pins {pins.checker_sha256}",
    )
    cnf, source, sink = identity.cnf_path, identity.proof_path, identity.checker_fifo_path
    for name, found, wanted in (
        ("solver", solver.args[-2:], (cnf, source)),
        ("relay", relay.args[-3:-1], (source, sink)),
        ("checker", checker.args[-2:], (cnf, sink)),
    ):
        _require(
            found == wanted,
            FILE_CHANGED,
            f"binding.{name}_files",
            f"the {name} ran on {found!r}, not {wanted!r}",
        )
    policy = identity.policy
    heap, stack = stream.check.heap_mib, stream.check.stack_mib
    _require(
        solver.args == sv.solver_args(pins.solver_argv, cnf, source),
        PROTOCOL,
        "binding.solver_argv",
        f"the solver argv {solver.args[:-2]!r} is not {pins.solver_argv!r}",
    )
    _require(
        relay.args == (*RELAY_ARGS, RELAY_SCRIPT, source, sink, str(policy.proof_cap_bytes)),
        PROTOCOL,
        "binding.relay_args",
        f"the relay arguments {relay.args!r} are not the relay script with the policy cap",
    )
    _require(
        checker.args == ck.checker_args(heap, stack, cnf, sink),
        PROTOCOL,
        "binding.checker_args",
        f"checker arguments {checker.args[:-2]!r} are not the recorded arenas {heap}/{stack}",
    )
    _require(
        solver.memory_bytes == policy.solver_memory_bytes
        and solver.file_bytes is None
        and solver.watch is None
        and _paired(identity, solver),
        PROTOCOL,
        "binding.solver_limits",
        "the solver did not run under the recorded stream limits",
    )
    _require(
        relay.memory_bytes == RELAY_MEMORY_BYTES and _paired(identity, relay),
        PROTOCOL,
        "binding.relay_limits",
        "the relay did not run under the relay cap and the paired deadline",
    )
    _require(
        checker.memory_bytes == ck.checker_memory_bytes(heap, stack, policy.checker_slack_mib)
        and _paired(identity, checker),
        PROTOCOL,
        "binding.checker_limits",
        "the checker did not run under its arenas and the paired deadline",
    )
    first_heap, first_stack = initial_stream_arena(policy)
    _require(
        first_heap <= heap <= policy.checker_max_heap_mib
        and first_stack <= stack <= policy.checker_max_stack_mib,
        PROTOCOL,
        "binding.stream_arena",
        f"the arena {heap}/{stack} is outside the policy's stream arenas",
    )


def _uncancelled(run: ProcessRun) -> tuple[Cause, ...]:
    """The run's supervisor causes other than a cancellation."""
    return tuple(cause for cause in run.causes if cause is not Cause.CANCELLED)


def _transfer(identity: AttemptIdentity, relay: RelayEvidence) -> rl.RelayReport | None:
    """The report of a relay that ended cleanly with a complete transfer within the cap, else
    None (S3 of the module doc). A termination that the relay outlived by completing its
    transfer (exit 0 with a complete report: the teardown raced its exit, ``leaf.stream``)
    does not change what it transferred; any other supervisor cause does."""
    run = relay.run
    result = run.result
    if _uncancelled(run) or not (
        result.started and result.exit == rl.EXIT_COMPLETE and result.signal is None
    ):
        return None
    report = rl.parse_report(run.stdout)
    if report is None or not report.complete:
        return None
    return report if report.bytes <= identity.policy.proof_cap_bytes else None


def _record_value(result: RunResult, *, conflicts: bool = False) -> ProcessResult:
    value = result.to_json()
    if conflicts and value["conflicts"] is None:
        value["conflicts"] = sv.parse_conflicts(result.stdout_tail)
    record: ProcessResult = ProcessResult.from_json(value)
    return record


def _check_value(check: CheckEvidence) -> CheckerCheck:
    value: CheckerCheck = CheckerCheck.from_json(
        {
            "result": check.run.result.to_json(),
            "heap_mib": check.heap_mib,
            "stack_mib": check.stack_mib,
        }
    )
    return value


def _diagnostics(
    identity: AttemptIdentity,
    extra: Mapping[str, Any] | None,
    files: Mapping[str, FileHash | None],
    model: ModelResult | None = None,
) -> JsonObject:
    value: dict[str, Any] = dict(extra or {})

    def measured(name: str) -> dict[str, Any] | None:
        found = files.get(name)
        return None if found is None else found.to_json()

    value["files"] = {
        "cnf": {
            "name": os.path.basename(identity.cnf_path),
            "written": measured("cnf_written"),
            "final": measured("cnf_final"),
        },
        "proof": {
            "name": os.path.basename(identity.proof_path),
            "sealed": measured("proof_sealed"),
            "final": measured("proof_final"),
        },
    }
    if model is not None:
        value["model"] = {"detail": model.detail, "violated_clause": model.violated_clause}
    return JsonObject.from_json(value)


def _success_problem(value: Mapping[str, Any]) -> str | None:
    """Specification §4.8 success.* of the built record (the certifier checks the same
    independently)."""
    if value["proof_bytes"] is None or value["proof_sha256"] is None:
        return "success.proof"
    if not value["checks"]:
        return "success.checks"
    last = value["checks"][-1]["result"]
    if not (
        last["exit"] == 0
        and last["signal"] is None
        and last["stdout_bytes"] == _SUCCESS_BYTES
        and last["stdout_truncated"] is False
        and last["stdout_tail"] == SUCCESS_LINE
    ):
        return "success.checker_output"
    solver = value["solver"]
    if value["route"] == Route.CDCL.value and (
        solver is None
        or solver["started"] is not True
        or solver["exit"] != sv.UNSAT_EXIT
        or solver["signal"] is not None
    ):
        return "success.solver"
    return _mode_problem(value)


def _mode_problem(value: Mapping[str, Any]) -> str | None:
    """A file mode or a stream unit proof without relay; in retain mode exactly the published
    checked proof; a stream CDCL proof with the complete transfer whose counters it carries."""
    mode = value["proof_mode"]
    if mode == ProofMode.STREAM.value:
        relay = value["relay"]
        if value["route"] == Route.UNIT.value:
            problem = None if relay is None else "success.relay"
        elif relay is None or not (
            relay["solver_eof"] is True
            and relay["all_written"] is True
            and relay["error"] is None
            and relay["bytes"] == value["proof_bytes"]
            and relay["sha256"] == value["proof_sha256"]
        ):
            problem = "success.relay"
        else:
            problem = None
        if problem is None and value["retained"] is not None:
            problem = "success.retained"
        return problem
    if value["relay"] is not None or mode not in (m.value for m in _FILE_MODES):
        return "success.relay"
    wanted = None
    if mode == ProofMode.RETAIN.value:
        path = artifact_path(Area.PROOFS, value["node_id"], value["proof_sha256"])
        wanted = {"path": path, "sha256": value["proof_sha256"], "bytes": value["proof_bytes"]}
    if value["retained"] != wanted:
        return "success.retained"
    return None


def _expected_artifact(area: Area, identity: AttemptIdentity, proof: FileHash) -> Artifact:
    """``<area>/<node_id>-<proof_sha256>.lrat`` with the proof's size and hash (specification
    §7.2)."""
    return Artifact(artifact_path(area, identity.node_id, proof.sha256), proof.sha256, proof.bytes)


# -- binding -------------------------------------------------------------------------------------


def _cnf_files(
    identity: AttemptIdentity, cnf_written: Any, cnf_final: Any
) -> tuple[FileHash, FileHash]:
    """Conditions 1-2 for the CNF: this attempt's file, CNF(F, C) before and after."""
    written = _file(identity, cnf_written, identity.cnf_path, "cnf_written")
    final = _file(identity, cnf_final, identity.cnf_path, "cnf_final")
    for name, value in (("written", written), ("final", final)):
        _require(
            value.sha256 == identity.cnf_sha256,
            FILE_CHANGED,
            "binding.cnf",
            f"the {name} CNF has {value.sha256}, CNF(F, C) is {identity.cnf_sha256}",
        )
    _require(written.bytes == final.bytes, FILE_CHANGED, "binding.cnf", "the CNF size changed")
    return written, final


def _no_binary_change(run: ProcessRun, role: str) -> None:
    _require(
        Cause.BINARY_CHANGED not in run.causes,
        BINARY_CHANGED,
        f"binding.{role}_binary",
        f"the {role} binary changed",
    )


def _stream_identity(identity: AttemptIdentity, pins: ToolPins) -> None:
    if not isinstance(identity, AttemptIdentity) or not isinstance(pins, ToolPins):
        raise ValueError("a stream binding needs an AttemptIdentity and ToolPins")
    _require(
        identity.streams,
        PROTOCOL,
        "binding.mode",
        f"a {identity.policy.proof_mode.value} {identity.route.value} attempt has no stream",
    )


def bind_stream_verified(
    identity: AttemptIdentity,
    pins: ToolPins,
    *,
    cnf_written: FileHash,
    cnf_final: FileHash,
    stream: StreamEvidence,
    diagnostics: Mapping[str, Any] | None = None,
) -> Attempt:
    """The VERIFIED_UNSAT record of a coupled stream run, or :class:`BindingError` (S1-S3 of
    the module doc together with the CNF conditions 1-2)."""
    _stream_identity(identity, pins)
    _require(isinstance(stream, StreamEvidence), PROTOCOL, "binding.stream", "the stream evidence")
    written, final = _cnf_files(identity, cnf_written, cnf_final)
    _check_stream_launches(identity, pins, stream)
    # S3: a clean exit-20 solve, a complete transfer, the exact checker success
    _clean_solve(stream.solve)
    _no_binary_change(stream.relay.run, "relay")
    report = _transfer(identity, stream.relay)
    _require(
        report is not None,
        PROTOCOL,
        "binding.relay",
        "the relay did not end cleanly with one report of a complete transfer within the cap",
    )
    assert report is not None
    _no_binary_change(stream.check.run, "checker")
    _exact_success(stream.check)
    files = {"cnf_written": written, "cnf_final": final}
    attempt = Attempt(
        node=identity.node,
        node_id=identity.node_id,
        attempt_id=identity.attempt_id,
        policy_sha256=identity.policy.sha256,
        route=Route.CDCL,
        proof_mode=ProofMode.STREAM,
        outcome=Outcome.VERIFIED_UNSAT,
        reason=None,
        cnf_sha256=identity.cnf_sha256,
        limits=attempt_limits(identity.policy, Route.CDCL, identity.depth, None),
        solver=_record_value(stream.solve.run.result, conflicts=True),
        checks=(_check_value(stream.check),),
        proof_bytes=report.bytes,
        proof_sha256=report.sha256,
        relay=_relay_record(report.record_value()),
        assignment=None,
        model_error=None,
        retained=None,
        quarantined=None,
        diagnostics=_diagnostics(identity, diagnostics, files),
    )
    problem = _success_problem(attempt.to_json())
    _require(problem is None, PROTOCOL, "binding.success", f"the built record violates {problem}")
    return attempt


def _relay_record(value: Mapping[str, Any]) -> Relay:
    try:
        relay: Relay = Relay.from_json(dict(value))
    except ContractError as error:
        raise ValueError(f"{value!r} is not a relay value: {error}") from None
    return relay


def _complete(value: Mapping[str, Any]) -> bool:
    return (
        value.get("solver_eof") is True
        and value.get("all_written") is True
        and value.get("error") is None
    )


def _stream_parts(
    identity: AttemptIdentity,
    pins: ToolPins,
    stream: Any,
    relay: Any,
    stream_proof: Any,
    *,
    modelled: bool,
) -> tuple[Relay, tuple[int, str] | None]:
    """The ``relay`` value and proof fields of a stream CDCL record of another outcome (module
    doc): the evidence is this attempt's; a complete transfer or proof is never claimed unless
    the evidence itself shows a clean relay with exactly that complete transfer."""
    _require(
        isinstance(stream, StreamEvidence) and relay is not None,
        PROTOCOL,
        "binding.stream",
        "a stream CDCL record needs its stream evidence and relay value",
    )
    assert isinstance(stream, StreamEvidence)
    _check_stream_launches(identity, pins, stream)
    value = _relay_record(relay)
    report = _transfer(identity, stream.relay)
    if _complete(value.to_json()) and (
        report is None or (report.bytes, report.sha256) != (value.bytes, value.sha256)
    ):
        raise ValueError("the relay value claims a complete transfer the evidence does not show")
    if stream_proof is None:
        return value, None
    if modelled:
        raise ValueError("a model has no proof")
    proof = tuple(stream_proof)
    solve = stream.solve.run
    clean = (
        not _uncancelled(solve)
        and solve.result.started
        and solve.result.exit == sv.UNSAT_EXIT
        and solve.result.signal is None
    )
    if not (
        clean
        and _complete(value.to_json())
        and proof == (value.bytes, value.sha256)
        and report is not None
    ):
        raise ValueError("stream proof fields need a clean exit-20 solve and a complete transfer")
    return value, (value.bytes, value.sha256)


def _verified_files(
    identity: AttemptIdentity,
    pins: ToolPins,
    *,
    cnf_written: FileHash,
    cnf_final: FileHash,
    proof_sealed: FileHash,
    proof_final: FileHash,
    checks: Sequence[CheckEvidence],
    solve: SolveEvidence | None,
    unit_proof_sha256: str | None,
) -> dict[str, FileHash]:
    """Conditions 1-4 of the module doc; the measured files, or :class:`BindingError`."""
    if not isinstance(identity, AttemptIdentity) or not isinstance(pins, ToolPins):
        raise ValueError("a verified binding needs an AttemptIdentity and ToolPins")
    _require(
        not identity.streams,
        PROTOCOL,
        "binding.mode",
        "a CDCL proof under the stream mode is never a file: it binds only through "
        "bind_stream_verified",
    )
    # 1-2: files of this attempt; the CNF is the expected one before and after
    written, final = _cnf_files(identity, cnf_written, cnf_final)
    # 3: the sealed proof is the checked proof
    sealed = _file(identity, proof_sealed, identity.proof_path, "proof_sealed")
    after = _file(identity, proof_final, identity.proof_path, "proof_final")
    _require(
        (sealed.bytes, sealed.sha256) == (after.bytes, after.sha256),
        FILE_CHANGED,
        "binding.proof",
        f"the sealed proof {sealed.bytes}/{sealed.sha256} became {after.bytes}/{after.sha256}",
    )
    if identity.route is Route.UNIT:
        _require(solve is None, PROTOCOL, "binding.route", "route unit has no solver run")
        _require(unit_proof_sha256 is not None, PROTOCOL, "binding.route", "the unit proof hash")
        _require(
            sealed.sha256 == unit_proof_sha256,
            FILE_CHANGED,
            "binding.unit_proof",
            "the sealed proof is not the generated unit-v1 proof",
        )
    else:
        _require(
            isinstance(solve, SolveEvidence), PROTOCOL, "binding.route", "route cdcl needs a solve"
        )
        assert solve is not None
        _require(
            unit_proof_sha256 is None, PROTOCOL, "binding.route", "route cdcl has no unit proof"
        )
        _check_solver_launch(identity, pins, solve)
        _clean_solve(solve)
    # 4: the checks
    _require(len(checks) >= 1, PROTOCOL, "binding.checks", "no check")
    expected = initial_arena(identity.policy, sealed.bytes)
    for index, check in enumerate(checks):
        _require(
            isinstance(check, CheckEvidence), PROTOCOL, "binding.checks", "a check is evidence"
        )
        _check_checker_launch(identity, pins, check, sealed.bytes)
        _require(
            (check.heap_mib, check.stack_mib) == expected,
            PROTOCOL,
            "binding.ladder",
            f"check {index} used {check.heap_mib}/{check.stack_mib}, expected {expected}",
        )
        if index < len(checks) - 1:
            expected = _arena_step(identity, check)
    _exact_success(checks[-1])
    return {
        "cnf_written": written,
        "cnf_final": final,
        "proof_sealed": sealed,
        "proof_final": after,
    }


def check_verified(
    identity: AttemptIdentity,
    pins: ToolPins,
    *,
    cnf_written: FileHash,
    cnf_final: FileHash,
    proof_sealed: FileHash,
    proof_final: FileHash,
    checks: Sequence[CheckEvidence],
    solve: SolveEvidence | None = None,
    unit_proof_sha256: str | None = None,
) -> FileHash:
    """The checked proof a VERIFIED_UNSAT record of this evidence would carry, or
    :class:`BindingError`: every evidence condition of :func:`bind_verified`, no record.

    Retain publishes exactly this proof before it binds the record (specification §6.1 step 6)."""
    files = _verified_files(
        identity,
        pins,
        cnf_written=cnf_written,
        cnf_final=cnf_final,
        proof_sealed=proof_sealed,
        proof_final=proof_final,
        checks=checks,
        solve=solve,
        unit_proof_sha256=unit_proof_sha256,
    )
    return files["proof_sealed"]


def bind_verified(
    identity: AttemptIdentity,
    pins: ToolPins,
    *,
    cnf_written: FileHash,
    cnf_final: FileHash,
    proof_sealed: FileHash,
    proof_final: FileHash,
    checks: Sequence[CheckEvidence],
    solve: SolveEvidence | None = None,
    unit_proof_sha256: str | None = None,
    retained: Artifact | None = None,
    diagnostics: Mapping[str, Any] | None = None,
) -> Attempt:
    """The VERIFIED_UNSAT record of an attempt, or :class:`BindingError` (module doc).

    ``retained`` is the published proof in retain mode (required there, refused otherwise)."""
    files = _verified_files(
        identity,
        pins,
        cnf_written=cnf_written,
        cnf_final=cnf_final,
        proof_sealed=proof_sealed,
        proof_final=proof_final,
        checks=checks,
        solve=solve,
        unit_proof_sha256=unit_proof_sha256,
    )
    sealed = files["proof_sealed"]
    mode = identity.policy.proof_mode
    if mode is ProofMode.RETAIN:
        _require(
            retained is not None,
            PROTOCOL,
            "binding.retained",
            "a retain-mode VERIFIED_UNSAT needs its published proof (no silent downgrade)",
        )
        _require(
            retained == _expected_artifact(Area.PROOFS, identity, sealed),
            FILE_CHANGED,
            "binding.retained",
            f"the retained artifact {retained!r} is not the checked proof "
            f"{sealed.bytes}/{sealed.sha256} of node {identity.node_id}",
        )
    else:
        _require(
            retained is None,
            PROTOCOL,
            "binding.retained",
            f"a {mode.value} record has no retained proof",
        )
    attempt = Attempt(
        node=identity.node,
        node_id=identity.node_id,
        attempt_id=identity.attempt_id,
        policy_sha256=identity.policy.sha256,
        route=identity.route,
        proof_mode=mode,
        outcome=Outcome.VERIFIED_UNSAT,
        reason=None,
        cnf_sha256=identity.cnf_sha256,
        limits=_limits(identity, fitted_check_time_ms(identity.policy, sealed.bytes)),
        solver=None if solve is None else _record_value(solve.run.result, conflicts=True),
        checks=tuple(_check_value(check) for check in checks),
        proof_bytes=sealed.bytes,
        proof_sha256=sealed.sha256,
        relay=None,
        assignment=None,
        model_error=None,
        retained=retained,
        quarantined=None,
        diagnostics=_diagnostics(identity, diagnostics, files),
    )
    problem = _success_problem(attempt.to_json())
    _require(problem is None, PROTOCOL, "binding.success", f"the built record violates {problem}")
    return attempt


def bind_outcome(
    identity: AttemptIdentity,
    pins: ToolPins,
    *,
    outcome: Outcome,
    reason: str | None,
    solve: SolveEvidence | None = None,
    checks: Sequence[CheckEvidence] = (),
    cnf_written: FileHash | None = None,
    cnf_final: FileHash | None = None,
    proof_sealed: FileHash | None = None,
    proof_final: FileHash | None = None,
    model: ModelResult | None = None,
    checked: bool | None = None,
    unit_proof_sha256: str | None = None,
    quarantined: Artifact | None = None,
    diagnostics: Mapping[str, Any] | None = None,
    stream: StreamEvidence | None = None,
    relay: Mapping[str, Any] | None = None,
    stream_proof: tuple[int, str] | None = None,
) -> Attempt:
    """Every outcome other than VERIFIED_UNSAT (module doc).

    A stream CDCL attempt (``identity.streams``) is described by ``stream`` (its three runs) and
    ``relay`` (the record's relay value, ``leaf.stream.relay_value``) instead of ``solve``,
    ``checks`` and the proof files; ``stream_proof`` are the proof fields of a complete
    transfer of a clean exit-20 solve (ValueError unless the evidence shows exactly that).
    A model records no check (specification §4.8 attempt.model_shape: the checker only saw a partial
    proof).

    ``checked`` says whether the sealed proof reached the checker stage (a check launch was
    attempted); it decides the recorded check time (specification §4.8). By default: any check
    evidence. Only started checks are recorded (specification §4.8: checks are empty when no checker
    ran). ``quarantined`` is the published copy of a rejected proof (CHECK_REJECTED only, exactly
    ``quarantine/<node_id>-<proof_sha256>.lrat`` of the sealed proof; ValueError otherwise).
    """
    if not isinstance(identity, AttemptIdentity) or not isinstance(pins, ToolPins):
        raise ValueError("bind_outcome needs an AttemptIdentity and ToolPins")
    outcome = Outcome(outcome)
    if outcome is Outcome.VERIFIED_UNSAT:
        raise ValueError("only bind_verified builds a VERIFIED_UNSAT record")
    if identity.streams:
        _require(
            solve is None
            and not checks
            and proof_sealed is None
            and proof_final is None
            and unit_proof_sha256 is None,
            PROTOCOL,
            "binding.stream",
            "a stream CDCL record is bound from its stream evidence, never from file evidence",
        )
        return _stream_outcome(
            identity,
            pins,
            outcome=outcome,
            reason=reason,
            stream=stream,
            relay=relay,
            stream_proof=stream_proof,
            cnf_written=cnf_written,
            cnf_final=cnf_final,
            model=model,
            quarantined=quarantined,
            diagnostics=diagnostics,
        )
    if stream is not None or relay is not None or stream_proof is not None:
        raise ValueError(
            f"a {identity.policy.proof_mode.value} {identity.route.value} record has no stream"
        )
    files = {
        "cnf_written": _optional_file(identity, cnf_written, identity.cnf_path, "cnf_written"),
        "cnf_final": _optional_file(identity, cnf_final, identity.cnf_path, "cnf_final"),
        "proof_sealed": _optional_file(identity, proof_sealed, identity.proof_path, "proof_sealed"),
        "proof_final": _optional_file(identity, proof_final, identity.proof_path, "proof_final"),
    }
    if identity.route is Route.UNIT:
        _require(solve is None, PROTOCOL, "binding.route", "route unit has no solver run")
    else:
        _require(
            isinstance(solve, SolveEvidence), PROTOCOL, "binding.route", "route cdcl needs a solve"
        )
        assert solve is not None
        _check_solver_launch(identity, pins, solve)
    sealed = files["proof_sealed"]
    if checks:
        _require(sealed is not None, PROTOCOL, "binding.checks", "checks need a sealed proof")
    for check in checks:
        _require(
            isinstance(check, CheckEvidence), PROTOCOL, "binding.checks", "a check is evidence"
        )
        assert sealed is not None
        _check_checker_launch(identity, pins, check, sealed.bytes)
    reached = bool(checks) if checked is None else checked
    check_time = (
        fitted_check_time_ms(identity.policy, sealed.bytes)
        if reached and sealed is not None
        else None
    )
    modelled = outcome in (Outcome.MODEL, Outcome.INVALID_MODEL)
    if modelled:
        if not isinstance(model, ModelResult) or model.outcome is not outcome:
            raise ValueError(f"{outcome.value} needs its model result")
        _require(
            sealed is None and not checks, PROTOCOL, "binding.model", "a model has no proof/checks"
        )
        if model.reason != reason:
            raise ValueError(f"{outcome.value} has reason {model.reason!r}, not {reason!r}")
    elif model is not None:
        raise ValueError(f"{outcome.value} carries no model")
    if quarantined is not None:
        if outcome is not Outcome.CHECK_REJECTED or sealed is None:
            raise ValueError(f"{outcome.value} has no quarantined proof (CHECK_REJECTED only)")
        if quarantined != _expected_artifact(Area.QUARANTINE, identity, sealed):
            raise ValueError(f"{quarantined!r} is not the quarantine copy of the rejected proof")
    extra = dict(diagnostics or {})
    if unit_proof_sha256 is not None:
        extra["unit_proof_sha256"] = unit_proof_sha256
    return Attempt(
        node=identity.node,
        node_id=identity.node_id,
        attempt_id=identity.attempt_id,
        policy_sha256=identity.policy.sha256,
        route=identity.route,
        proof_mode=identity.policy.proof_mode,
        outcome=outcome,
        reason=reason,
        cnf_sha256=identity.cnf_sha256,
        limits=_limits(identity, check_time),
        solver=None if solve is None else _record_value(solve.run.result, conflicts=True),
        checks=tuple(_check_value(c) for c in checks if c.run.result.started),
        proof_bytes=None if sealed is None else sealed.bytes,
        proof_sha256=None if sealed is None else sealed.sha256,
        relay=None,
        assignment=model.assignment if modelled and model is not None else None,
        model_error=model.model_error if modelled and model is not None else None,
        retained=None,
        quarantined=quarantined,
        diagnostics=_diagnostics(identity, extra, files, model if modelled else None),
    )


def bind_not_run(identity: AttemptIdentity, *, detail: str) -> Attempt:
    """The placeholder record of an audit target that was not run (module doc).

    A strict audit runs a CDCL target only with its source solver; without it the target is
    NOT_COMPARABLE, and this record is what its ``audit_result`` refers to. It states that
    nothing ran: TOOL_FAILED ``launch``, route cdcl with a solver result that was never started
    (cause :data:`SOURCE_TOOL_UNAVAILABLE`), no check, no proof, no files, no solver time
    limit. ValueError unless ``identity`` is an audit identity on route cdcl (a run attempt
    never carries it)."""
    if not isinstance(identity, AttemptIdentity):
        raise ValueError("bind_not_run needs an AttemptIdentity")
    if not identity.unlimited_solver_time or identity.route is not Route.CDCL:
        raise ValueError("only a CDCL audit attempt (unlimited_solver_time) can be not run")
    if not isinstance(detail, str):
        raise ValueError("the detail is a string")
    solver = ProcessResult.from_json(
        {
            "started": False,
            "exit": None,
            "signal": None,
            "elapsed_ms": 0,
            "stdout_tail": "",
            "stderr_tail": "",
            "stdout_bytes": 0,
            "stdout_truncated": False,
            "cause": SOURCE_TOOL_UNAVAILABLE,
            "conflicts": None,
        }
    )
    return Attempt(
        node=identity.node,
        node_id=identity.node_id,
        attempt_id=identity.attempt_id,
        policy_sha256=identity.policy.sha256,
        route=Route.CDCL,
        proof_mode=identity.policy.proof_mode,
        outcome=Outcome.TOOL_FAILED,
        reason="launch",
        cnf_sha256=identity.cnf_sha256,
        limits=_limits(identity, None),
        solver=solver,
        checks=(),
        proof_bytes=None,
        proof_sha256=None,
        relay=None,
        assignment=None,
        model_error=None,
        retained=None,
        quarantined=None,
        diagnostics=_diagnostics(identity, {"not_run": _text(detail)}, {}),
    )


def _text(detail: str) -> str:
    return detail if len(detail) <= 300 else detail[:297] + "..."


def _stream_outcome(
    identity: AttemptIdentity,
    pins: ToolPins,
    *,
    outcome: Outcome,
    reason: str | None,
    stream: StreamEvidence | None,
    relay: Mapping[str, Any] | None,
    stream_proof: tuple[int, str] | None,
    cnf_written: FileHash | None,
    cnf_final: FileHash | None,
    model: ModelResult | None,
    quarantined: Artifact | None,
    diagnostics: Mapping[str, Any] | None,
) -> Attempt:
    """:func:`bind_outcome` of a stream CDCL attempt (module doc)."""
    files = {
        "cnf_written": _optional_file(identity, cnf_written, identity.cnf_path, "cnf_written"),
        "cnf_final": _optional_file(identity, cnf_final, identity.cnf_path, "cnf_final"),
    }
    modelled = outcome in (Outcome.MODEL, Outcome.INVALID_MODEL)
    value, proof = _stream_parts(identity, pins, stream, relay, stream_proof, modelled=modelled)
    assert stream is not None
    if modelled:
        if not isinstance(model, ModelResult) or model.outcome is not outcome:
            raise ValueError(f"{outcome.value} needs its model result")
        if model.reason != reason:
            raise ValueError(f"{outcome.value} has reason {model.reason!r}, not {reason!r}")
    elif model is not None:
        raise ValueError(f"{outcome.value} carries no model")
    if quarantined is not None:
        raise ValueError("stream quarantine is metadata-only: no quarantined artifact")
    check = stream.check
    checks = () if modelled or not check.run.result.started else (_check_value(check),)
    return Attempt(
        node=identity.node,
        node_id=identity.node_id,
        attempt_id=identity.attempt_id,
        policy_sha256=identity.policy.sha256,
        route=Route.CDCL,
        proof_mode=ProofMode.STREAM,
        outcome=outcome,
        reason=reason,
        cnf_sha256=identity.cnf_sha256,
        limits=attempt_limits(identity.policy, Route.CDCL, identity.depth, None),
        solver=_record_value(stream.solve.run.result, conflicts=True),
        checks=checks,
        proof_bytes=None if proof is None else proof[0],
        proof_sha256=None if proof is None else proof[1],
        relay=value,
        assignment=model.assignment if modelled and model is not None else None,
        model_error=model.model_error if modelled and model is not None else None,
        retained=None,
        quarantined=None,
        diagnostics=_diagnostics(identity, diagnostics, files, model if modelled else None),
    )
