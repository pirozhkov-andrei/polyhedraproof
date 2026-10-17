"""The optional native helper ``cubeproof-look``, its supervised execution and the fallbacks.

The helper is an optional, separately built executable located explicitly in the
configuration (``ToolPaths.helper``, specification §14): nothing is searched on PATH.
:func:`discover_helper` measures the file (:class:`~cubeproof.tools.isolation.PinnedBinary`), runs
``--version`` and reads the build record ``<path>.provenance.json`` written by ``native/build.py``
(compiler, flags, source and binary SHA-256), which is used only if its binary hash matches the
measured binary. A missing or unusable helper is not an error: the splitter then uses the Python
reference with a visible warning and identical semantics (specification §14, §9.3).

:class:`LookaheadSplitter` implements the common interface ``choose(bundle, cube, k, pool,
budget)`` (specification §9.1):

- helper present: one supervised run with the request document of :mod:`cubeproof.split.protocol`
  (own session, parent-death signal, address-space cap, deadline). The result is validated; a
  valid ``budget`` or ``no_eligible`` answer is returned as it is;
- helper timeout, crash, bad exit, binary change, held-open output or invalid output: the
  **lowest eligible variables** under the validated parent propagation, with the failure
  recorded in ``info.fallback`` (specification §9.1). These are operational failures, never proof
  verdicts;
- helper absent: the Python reference, ``info.implementation = "python-reference"``.

``choose`` blocks its thread while it steps the supervisor; the coordinator drives
:func:`start_helper` / :meth:`HelperJob.result` from its own event loop instead (the lookahead
Python reference has a step-generator form, :func:`~cubeproof.split.lookahead.lookahead_steps`).
Reserving the memory of an active helper (default 256 MiB plus overhead, specification §8.3) is the
scheduler's business.
"""

from __future__ import annotations

import os
import time
import uuid
import warnings
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cubeproof.base.canonical_json import parse_document
from cubeproof.base.errors import ConfigurationError, CubeproofError, ToolError
from cubeproof.cnf.bundle import Bundle
from cubeproof.cnf.unit import UnitIndex, build_index
from cubeproof.contracts.identity import check_cube, node_id
from cubeproof.split.choice import (
    Budget,
    SplitChoice,
    check_k,
    check_pool,
    lowest_eligible_choice,
)
from cubeproof.split.lookahead import Engine, build_engine, lookahead
from cubeproof.split.protocol import parse_result, request_document
from cubeproof.tools.isolation import PinnedBinary
from cubeproof.tools.process import Launch, Process, Supervisor
from cubeproof.tools.solver import probe_version

HELPER_NAME = "cubeproof-look"
VERSION_PREFIX = "cubeproof-look 1 "
BUILD_FORMAT = "cubeproof-look-build-1"
PROVENANCE_SUFFIX = ".provenance.json"
#: Default address-space cap of a helper run (specification §8.3: 256 MiB plus overhead).
DEFAULT_MEMORY_BYTES = 256 << 20
#: Wall time allowed for reading the formula and starting, on top of ``wall_ms``.
DEFAULT_SLACK_MS = 60_000
#: Deadline of a helper run without a wall budget.
DEFAULT_DEADLINE_MS = 3_600_000
RESULT_CAPTURE_BYTES = 64 * 1024
_PROVENANCE_LIMIT = 1 << 20
_FAILED_RULE = "split.helper_failed"


@dataclass(frozen=True)
class Helper:
    """A measured helper binary with its version line and (matching) build record."""

    binary: PinnedBinary
    version: str
    provenance: dict[str, Any] = field(default_factory=dict)

    def record(self) -> dict[str, Any]:
        """The provenance recorded in the splitter info: hashes first, then the build record."""
        return {"sha256": self.binary.sha256, "version": self.version, **self.provenance}


@dataclass(frozen=True)
class HelperDiscovery:
    """The result of :func:`discover_helper`: the helper, or why there is none."""

    helper: Helper | None
    problem: str | None = None


def _read_provenance(path: str, binary_sha256: str) -> dict[str, Any]:
    """The build record next to the binary, only if it describes exactly this binary."""
    try:
        with open(path + PROVENANCE_SUFFIX, "rb") as stream:
            data = stream.read(_PROVENANCE_LIMIT + 1)
    except OSError:
        return {}
    if len(data) > _PROVENANCE_LIMIT:
        return {}
    try:
        value = parse_document(data)
    except CubeproofError:
        return {}
    if (
        not isinstance(value, dict)
        or value.get("format") != BUILD_FORMAT
        or value.get("binary_sha256") != binary_sha256
    ):
        return {}
    return {k: v for k, v in value.items() if k not in ("format", "binary_sha256")}


def discover_helper(path: str | None, supervisor: Supervisor, cwd: str) -> HelperDiscovery:
    """Measure and probe the configured helper; absence or failure is a reason, not an error.

    ``path`` is the explicit absolute path of ``ToolPaths.helper`` (None: not configured).
    """
    if path is None:
        return HelperDiscovery(None, "no helper path is configured")
    if not isinstance(path, str) or not path.startswith("/") or "\0" in path:
        raise ConfigurationError("tools.helper", f"{path!r} is not an absolute local path")
    try:
        binary = PinnedBinary.measure(path)
    except ToolError as error:
        return HelperDiscovery(None, f"{path}: {error.rule}")
    try:
        version = probe_version(supervisor, binary, cwd)
    except ToolError as error:
        return HelperDiscovery(None, f"{path}: {error.rule}: {error.detail[:200]}")
    if not version.startswith(VERSION_PREFIX):
        return HelperDiscovery(None, f"{path} reports {version[:80]!r}, not {HELPER_NAME}")
    return HelperDiscovery(Helper(binary, version, _read_provenance(path, binary.sha256)))


@dataclass(frozen=True)
class HelperRequest:
    """One lookahead request: everything the helper and the result validation need."""

    formula_path: str
    formula_sha256: str
    variables: int
    cube: tuple[int, ...]
    k: int
    pool: tuple[int, ...] | None
    probe_limit: int
    wall_ms: int | None

    @property
    def node(self) -> str:
        return node_id(self.formula_sha256, self.cube)

    def document(self) -> bytes:
        return request_document(
            formula_path=self.formula_path,
            formula_sha256=self.formula_sha256,
            variables=self.variables,
            cube=self.cube,
            k=self.k,
            pool=self.pool,
            probe_limit=self.probe_limit,
            wall_ms=self.wall_ms,
        )


class HelperJob:
    """A started helper run; :meth:`result` interprets the finished process."""

    def __init__(self, process: Process, request: HelperRequest, request_path: Path) -> None:
        self.process = process
        self.request = request
        self.request_path = request_path

    @property
    def finished(self) -> bool:
        return self.process.run is not None

    def result(self) -> SplitChoice:
        """The validated choice of a finished run; ``ToolError`` on any helper failure."""
        run = self.process.run
        if run is None:
            raise RuntimeError("the helper has not finished")
        self.request_path.unlink(missing_ok=True)
        outcome = run.result
        if run.causes or outcome.exit != 0:
            causes = [c.value for c in run.causes]
            raise ToolError(
                _FAILED_RULE,
                f"exit {outcome.exit}, signal {outcome.signal}, causes {causes}, "
                f"stderr {outcome.stderr_tail[-300:]!r}",
            )
        if run.stdout is None:
            raise ToolError("split.helper_protocol", "the result exceeds its capture bound")
        request = self.request
        return parse_result(
            run.stdout,
            node=request.node,
            variables=request.variables,
            cube=request.cube,
            k=request.k,
            pool=request.pool,
            probe_limit=request.probe_limit,
            wall_ms=request.wall_ms,
        )


def start_helper(
    supervisor: Supervisor,
    helper: Helper,
    request: HelperRequest,
    workdir: Path,
    *,
    memory_bytes: int = DEFAULT_MEMORY_BYTES,
    deadline_ms: int | None = None,
) -> HelperJob:
    """Write the request into ``workdir`` and start the helper on ``supervisor``."""
    directory = Path(workdir).resolve()
    request_path = directory / f"look-{uuid.uuid4().hex}.request"
    descriptor = os.open(request_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(request.document())
    if deadline_ms is None:
        deadline_ms = (
            DEFAULT_DEADLINE_MS if request.wall_ms is None else request.wall_ms + DEFAULT_SLACK_MS
        )
    process = supervisor.start(
        Launch(
            binary=helper.binary,
            args=(str(request_path),),
            cwd=str(directory),
            memory_bytes=memory_bytes,
            deadline_ms=deadline_ms,
            term_grace_ms=1000,
            stdout_capture=RESULT_CAPTURE_BYTES,
        )
    )
    return HelperJob(process, request, request_path)


def run_helper(
    supervisor: Supervisor,
    helper: Helper,
    request: HelperRequest,
    workdir: Path,
    *,
    memory_bytes: int = DEFAULT_MEMORY_BYTES,
    deadline_ms: int | None = None,
) -> SplitChoice:
    """:func:`start_helper`, wait for the run on this thread, and validate its result."""
    job = start_helper(
        supervisor, helper, request, workdir, memory_bytes=memory_bytes, deadline_ms=deadline_ms
    )
    while not job.finished:
        supervisor.step(50)
    return job.result()


def _default_warn(message: str) -> None:
    warnings.warn(message, RuntimeWarning, stacklevel=4)


class LookaheadSplitter:
    """``lookahead-v1`` with the native helper, its fallbacks and the Python reference."""

    name = "lookahead-v1"

    def __init__(
        self,
        *,
        helper: Helper | None = None,
        absent_reason: str | None = None,
        supervisor: Supervisor | None = None,
        workdir: Path | None = None,
        memory_bytes: int = DEFAULT_MEMORY_BYTES,
        deadline_ms: int | None = None,
        clock: Callable[[], int] = time.monotonic_ns,
        warn: Callable[[str], None] = _default_warn,
    ) -> None:
        if helper is not None and (supervisor is None or workdir is None):
            raise ValueError("a helper needs a supervisor and a work directory")
        self.helper = helper
        self.absent_reason = absent_reason
        self._supervisor = supervisor
        self._workdir = workdir
        self._memory_bytes = memory_bytes
        self._deadline_ms = deadline_ms
        self._clock = clock
        self._warn = warn
        self._warned = False
        self._engine: Engine | None = None
        self._unit_index: UnitIndex | None = None

    def _reference_engine(self, bundle: Bundle) -> Engine:
        engine = self._engine
        if engine is None or engine.formula_sha256 != bundle.formula.sha256:
            engine = self._engine = build_engine(bundle.formula)
        return engine

    def _tag(self, choice: SplitChoice, implementation: str, **more: Any) -> SplitChoice:
        info = choice.info_dict()
        info["implementation"] = implementation
        info.update(more)
        return SplitChoice.make(choice.variables, choice.status, info)

    def choose(
        self,
        bundle: Bundle,
        cube: Sequence[int],
        k: int,
        pool: Iterable[int] | None,
        budget: Budget,
    ) -> SplitChoice:
        """Choose up to ``k`` variables at ``cube`` (specification §9.1); see the module
        docstring."""
        formula = bundle.formula
        check_k(k)
        parent = check_cube(cube, formula.variables)
        members = check_pool(pool, formula.variables)
        if self.helper is None:
            if not self._warned:
                self._warned = True
                reason = self.absent_reason or "no helper is configured"
                self._warn(
                    f"{HELPER_NAME} is not available ({reason}); using the Python reference "
                    "of lookahead-v1 with the same semantics"
                )
            choice = lookahead(
                formula,
                parent,
                k,
                members,
                budget,
                engine=self._reference_engine(bundle),
                clock=self._clock,
            )
            return self._tag(choice, "python-reference")
        assert self._supervisor is not None and self._workdir is not None
        request = HelperRequest(
            formula_path=str((Path(bundle.directory) / "formula.cnf").resolve()),
            formula_sha256=formula.sha256,
            variables=formula.variables,
            cube=parent,
            k=k,
            pool=members,
            probe_limit=budget.probe_limit,
            wall_ms=budget.wall_ms,
        )
        try:
            choice = run_helper(
                self._supervisor,
                self.helper,
                request,
                self._workdir,
                memory_bytes=self._memory_bytes,
                deadline_ms=self._deadline_ms,
            )
        except ToolError as error:
            return self.fallback(bundle, parent, k, members, error)
        return self._tag(choice, "helper", helper=self.helper.record())

    def fallback(
        self,
        bundle: Bundle,
        cube: Sequence[int],
        k: int,
        pool: Iterable[int] | None,
        error: ToolError,
    ) -> SplitChoice:
        """The lowest eligible variables after a helper failure, with the failure recorded."""
        details: dict[str, Any] = {"rule": error.rule, "detail": error.detail[:300]}
        if self.helper is not None:
            details["helper_sha256"] = self.helper.binary.sha256
        cached = self._unit_index
        if cached is None or cached.formula_sha256 != bundle.formula.sha256:
            try:
                cached = self._unit_index = build_index(bundle.formula)
            except MemoryError:
                cached = None
        choice = lowest_eligible_choice(
            bundle.formula, cube, k, pool, reason="helper_failure", details=details, index=cached
        )
        return self._tag(choice, "fallback-lowest-eligible")
