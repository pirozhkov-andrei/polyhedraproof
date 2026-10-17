"""The run lifecycle of one worker: startup, the event loop, stop and restart (specification §6.5,
§7.3, §8, §12.2).

:class:`Coordinator` runs one worker on one results/work directory pair, single-threaded and
nonblocking (specification §8.1). This module wires its pieces:

- **Startup** (specification §7.3, in this order): campaign and bundles, the two directories, the
  exclusive nonblocking ``run.lock`` (a second worker on the same directory is refused, exit 3), a
  check that no process of an older run still uses the work directory, the comparison of the
  journal with its export (``_before_replay``, a monitored run), validation and replay of the
  journal (a torn suffix repaired, a damaged line an IntegrityError, a wrong campaign or worker
  refused) with the derived cache as a verified shortcut, validation of every committed
  artifact reference and removal of orphans and of the old work files, measurement of the
  machinery and resources and the effective policy, the I/O service process (which creates the
  journal for a new worker), the committed **resume** (or the header) before anything else, the
  explicitly requested ``node_reopen`` records, the initial shard, and the ``node_stop``
  follow-ups the rules imply but a crash may have lost.
- **The loop**: reap and classify, commit, apply every committed record to the scheduling state
  (the records are read back from the journal and validated, so the state is a fold of
  validated records), then launch in the priority of specification §8.4 under the reservation
  ledgers. A result belongs to the attempt that submitted the job or to this module's own jobs;
  anything else stops the run. Tasks that are no longer open work are cancelled without records.
- **Stop**: SIGINT/SIGTERM, the time allocation, the anomaly limit or the machine failure
  limit stop new work; running attempts are cancelled (no record before the terminal commit),
  an attempt already committing finishes; a second signal kills. The exit code follows specification
  §12.2.
- **Restart**: nothing is trusted that the journal does not say. An attempt without a
  committed record is pending again; a committed one is never solved again; missing follow-up
  events are derived by replay; work files are removed.

Resource reservations are admission accounting (specification §8.2); they are restaged per phase of
an attempt (solve, sealed proof, check) so that a sealed proof's disk is never reserved twice.

Retain and quarantine (specification §6.1 steps 6-7, §7.2, §7.3, §8.3):

- The startup recovery (:func:`cubeproof.leaf.retain.recover`) binds every committed record to
  its references first (from the records alone: a retain-mode VERIFIED_UNSAT without its
  ``retained`` artifact, or one naming another file, is an IntegrityError), then lets the artifact
  reconciliation validate every referenced file and only then remove orphans. The records are
  re-read from the journal prefix the replay validated, under the same run lock; their
  references must equal the replay's.
- Every attempt asks for its publication (``publish_gate``): the coordinator restages the
  attempt's reservation to :func:`~cubeproof.coordinator.resources.publish_need` (the copy on
  the results group, twice on a shared group) through :func:`publication_admission`. While a
  publication waits for disk no new solve or split is launched, so freed disk goes to it.
  A refused retained publication is retain-full; any retained publication that does not
  complete stops new work and, after the drain, ends the run with the block's error
  (``retain.blocked``, exit code by kind, specification §12.2). Nothing is recorded for that
  attempt.
- Rejected proofs are quarantined under the policy quota with one
  :class:`~cubeproof.leaf.quarantine.QuarantineLedger` per session, seeded from the
  validated committed quarantine files.

Stream (specification §6.4, §8.2, §8.3): a leaf reserves the stream need (solver, checker with the
node's next arena and relay; 3000 milli-CPU, so an idle machine with fewer slots fails preflight)
and runs with the arena :meth:`~cubeproof.coordinator.state.ReplayState.stream_arena` derives from
the journal. Whether an arena-exhausted stream record keeps its node pending for a fresh attempt
is the replay's decision (``ReplayState.stream_retry``), so a live run and a restart take the
same next action; beyond the maxima or the idle machine the node needs a split.

Named points of the lifecycle are reported to ``RunConfig.hooks`` (``startup.locked``,
``startup.replayed``, ``startup.reconciled``, ``startup.measured``, ``snapshot.submitted``,
``snapshot.committed``, ``shard.submitted``, ``shard.committed``, ``loop.start``,
``attempt.<phase>``, ``attempt.published`` (a durable copy whose record is not yet submitted),
``attempt.committed`` (an acknowledged record whose work files are not yet removed),
``split.started``, ``split.submitted``, ``split.committed``, ``stop.submitted``,
``stop.committed``, ``reopen.committed``, ``drain.begin``, ``shutdown``, ``cache.written``):
the crash tests kill the process at chosen occurrences of them.
"""

from __future__ import annotations

import contextlib
import errno
import json
import os
import signal
import stat
import time
from collections import Counter, deque
from collections.abc import Collection, Iterator, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from types import FrameType
from typing import Any

from cubeproof.base.canonical_json import document_bytes
from cubeproof.base.errors import ConfigurationError, CubeproofError, IntegrityError, ToolError
from cubeproof.base.ids import new_id128
from cubeproof.base.settings import ReaderLimits
from cubeproof.cnf.campaign import LoadedCampaign, load_campaign
from cubeproof.cnf.cubecnf import CnfDigest
from cubeproof.cnf.dimacs import Formula
from cubeproof.contracts.documents import Shard
from cubeproof.contracts.enums import ProofMode, StopState
from cubeproof.contracts.identity import node_id, split_children
from cubeproof.contracts.io import (
    AppendRequest,
    AppendValue,
    Area,
    Failure,
    Job,
    Op,
    PublishValue,
    Result,
    artifact_area,
)
from cubeproof.contracts.values import Artifact, Node
from cubeproof.coordinator.cache import write_cache
from cubeproof.coordinator.config import RunConfig, RunResult, Stop
from cubeproof.coordinator.export import ExportDescriptor, exported_records
from cubeproof.coordinator.indexes import EngineCache, IndexCache, SlicedCache
from cubeproof.coordinator.layout import (
    WORK_LOCK_NAME,
    Layout,
    clear_work,
    wait_for_survivors,
)
from cubeproof.coordinator.ledger import Measure, Need, ResourceBook
from cubeproof.coordinator.measure import (
    Measured,
    check_code_continuity,
    check_policy_continuity,
    measure,
    resolve_policy,
)
from cubeproof.coordinator.ownership import RECORD_OVERHEAD, chunk_nodes
from cubeproof.coordinator.replay import Replayed, check_owner, replay_journal, validator_of
from cubeproof.coordinator.resources import (
    Resources,
    cnf_size_bytes,
    helper_need,
    idle_fit,
    publish_need,
    sealed_need,
    solve_need,
    stream_need,
)
from cubeproof.coordinator.scheduler import Candidate, Impossible, Scheduler, Stage
from cubeproof.coordinator.scheduler_loop import TickStats
from cubeproof.coordinator.scheduler_select import (
    RootRotation,
    SplitAction,
    SplitDecision,
    Work,
    check_candidate,
    decide_split,
    next_work,
    split_k,
)
from cubeproof.coordinator.splits import SplitTask
from cubeproof.coordinator.state import (
    CampaignView,
    Disposition,
    Followup,
    Key,
    ReplayState,
    key_of,
)
from cubeproof.coordinator.tail import JournalTail
from cubeproof.evidence.journal import Anchor, RunLock
from cubeproof.evidence.journal.chain import ChainState
from cubeproof.evidence.schema import (
    Attempt,
    NodeReopen,
    NodeStop,
    Record,
    SplitRecord,
    parse_record,
)
from cubeproof.leaf.attempt import LeafAttempt, LeafError, Phase
from cubeproof.leaf.quarantine import QuarantineLedger
from cubeproof.leaf.retain import (
    RetainBlocked,
    committed_references,
    may_reference,
    recover,
    reference_problem,
)
from cubeproof.split.choice import Budget, SplitChoice, lowest_eligible_choice
from cubeproof.tools.io_service_client import IoClient

__all__ = [
    "Coordinator",
    "check_exported_tail",
    "lock_descriptor",
    "publication_admission",
    "run_worker",
]

#: Reasons of the node stops this module commits itself (the rules' own follow-ups carry the
#: reasons of :mod:`cubeproof.coordinator.state`).
REASON_CHECK_EXHAUSTED = "check_exhausted"
REASON_STALLED = "stalled"
REASON_UNIT_ROUTE = "unit_route_exhausted"
_PLAN_INTERVAL_NS = 250_000_000
_CPU_PHASES = frozenset({Phase.PREPARE, Phase.UNIT, Phase.MODEL})
_DRAIN_EXTRA_S = 60.0
#: CPU time the tasks may use per tick (specification §8.1: ticks stay short; the rest waits for
#: events).
_TICK_BUDGET_NS = 25_000_000


def lock_descriptor(lock: RunLock) -> int:
    """The descriptor of the run lock, to be passed to the I/O service so that it holds the
    same lock (``RunLock`` has no public accessor; the same open file description is needed:
    a second ``flock`` from this process on another descriptor would conflict)."""
    descriptor = lock._fd
    if descriptor is None:
        raise ConfigurationError("run.lock", "the run lock is not held")
    return descriptor


def publication_admission(
    book: ResourceBook,
    task_id: str,
    need: Need,
    measures: Mapping[str, Measure] | None,
    *,
    stuck: Collection[str] = (),
) -> tuple[str, str]:
    """Admit the publication of ``task_id`` (specification §7.2 step 1, §8.3): ``("grant", "")``
    after its reservation was restaged to ``need``; ``("wait", why)`` while another reservation that
    is not itself waiting for a publication (``stuck``) holds the refusing dimension and can
    free it; otherwise ``("refuse", why)``: the copy cannot be reserved (retain-full).

    Only the increase over the task's held reservation is asked for (``ResourceBook.restage``).
    """
    idle = book.idle_shortfall(need)
    if idle is not None:
        return "refuse", str(idle)
    short = book.shortfall(need, measures, replacing=task_id)
    if short is None:
        book.restage(task_id, "publish", need, measures)
        return "grant", ""
    can_free = any(
        held.task_id != task_id
        and held.task_id not in stuck
        and held.need.amounts().get(short.dimension, 0) > 0
        for held in book.reservations()
    )
    return ("wait" if can_free else "refuse"), str(short)


def _referencing_attempts(path: Path, replayed: Replayed, limits: ReaderLimits) -> list[Attempt]:
    """The committed attempts that can carry or require an artifact reference, re-read from the
    journal prefix the replay validated (``may_reference`` selects the lines to parse)."""
    if replayed.tail is None:
        return []
    end = replayed.tail.chain.offset
    found: list[Attempt] = []
    read = 0
    with path.open("rb") as stream:
        while read < end:
            line = stream.readline(min(limits.line_bytes + 1, end - read))
            read += len(line)
            if not line.endswith(b"\n"):
                raise IntegrityError(
                    "run.tail", f"{path} changed after its validation (offset {read} of {end})"
                )
            body = line[:-1]
            if not may_reference(body):
                continue
            try:
                payload = parse_record(body, limits=limits).payload
            except CubeproofError as error:
                raise IntegrityError(
                    "run.tail", f"{path} changed after its validation: {error.rule}"
                ) from None
            if isinstance(payload, Attempt):
                found.append(payload)
    return found


def _present(results: Path, artifact: Artifact) -> bool:
    """Whether the referenced file is a regular file of the recorded size (its hash is checked
    by the startup recovery, like every committed reference)."""
    try:
        info = os.lstat(results / artifact.path)
    except OSError:
        return False
    return stat.S_ISREG(info.st_mode) and info.st_size == artifact.bytes


def check_exported_tail(
    export: Path,
    descriptor: ExportDescriptor,
    anchor: Anchor,
    *,
    loaded: LoadedCampaign,
    results: Path,
    limits: ReaderLimits,
) -> None:
    """Whether the exported records after the journal's ``anchor`` may be appended to the journal
    (specification §7.5; the ``inspect`` of :func:`~cubeproof.coordinator.export.
    restore_from_export`): raises otherwise, having changed nothing.

    The whole published prefix is read through the replay's validator (schema, rules, chain, the
    descriptor's end). Every attempt after the anchor must bind its artifact references, and the
    referenced retained or quarantined files must be in ``results``: a record whose file was
    lost with the results would make the journal fail its own startup recovery.
    """
    missing, first = 0, ""
    try:
        for record in exported_records(export, descriptor, validator_of(loaded), limits=limits):
            payload = record.payload
            if record.seq <= anchor.seq or not isinstance(payload, Attempt):
                continue
            problem = reference_problem(payload)
            if problem is not None:
                raise IntegrityError(problem, f"the exported attempt {payload.attempt_id}")
            for artifact in (payload.retained, payload.quarantined):
                if artifact is not None and not _present(results, artifact):
                    missing, first = missing + 1, first or artifact.path
    except OSError as error:
        raise IntegrityError("export.prefix", f"{export}: {error}") from error
    if missing:
        raise IntegrityError(
            "artifact.missing",
            f"{missing} retained or quarantined files that the exported records reference are "
            f"not in the results directory (the first: {first})",
        )


class _Interrupted(Exception):
    """A signal arrived while starting up: end quietly with exit code 130."""


@dataclass
class _Own:
    """A job of this module (not of an attempt): what it was for."""

    kind: str
    key: Key | None = None


@dataclass
class _AttemptTask:
    attempt: LeafAttempt
    key: Key
    cnf_bytes: int
    group: str
    seq: int = -1
    seen: Phase | None = None


@dataclass
class _SplitTask:
    task: SplitTask
    key: Key
    k: int


class Coordinator:
    """One run of one worker (module doc). :meth:`run` does everything."""

    loaded: LoadedCampaign
    view: CampaignView
    campaign_id: str
    layout: Layout
    resources: Resources
    book: ResourceBook
    scheduler: Scheduler
    rotation: RootRotation
    indexes: IndexCache
    engines: EngineCache

    def __init__(self, config: RunConfig) -> None:
        self.config = config
        self._clock = config.clock
        self._stop: Stop | None = None
        self._signals = 0
        self._error: CubeproofError | None = None
        self._notes: list[str] = []
        self._counts: Counter[str] = Counter()
        # resources acquired by startup, released by shutdown
        self.lock: RunLock | None = None
        self.work_lock: RunLock | None = None
        self.io: IoClient | None = None
        self.measured: Measured | None = None
        self.tail: JournalTail | None = None
        self.state: ReplayState | None = None
        self._cache_status = "absent"
        self._replayed_records = 0
        # tasks and what is in flight
        self._attempts: dict[str, _AttemptTask] = {}
        self._splits: dict[str, _SplitTask] = {}
        self._own: dict[int, _Own] = {}
        self._busy: set[Key] = set()
        self._selfs: dict[int, str] = {}
        self._forced: set[Key] = set()
        self._forced_runs: Counter[Key] = Counter()
        self._digests: dict[str, CnfDigest] = {}
        self._retired: deque[LeafAttempt] = deque(maxlen=256)
        self._ticks = TickStats()
        self._turn = 0
        self._ready_now: dict[tuple[int, str], bool] = {}
        self._dirty = True
        self._next_plan = 0
        self._queued = 0
        self._check_seq = 0
        self._drained = False
        self._drain_deadline: float | None = None
        self._deadline_ns: int | None = None
        # retain and quarantine
        self._quarantined: tuple[Artifact, ...] = ()
        self.quarantine: QuarantineLedger | None = None
        self._blocked: RetainBlocked | None = None
        self._publish_waiting = False

    # -- helpers ---------------------------------------------------------------------------

    def _hook(self, name: str) -> None:
        if self.config.hooks is not None:
            self.config.hooks(name)

    @contextlib.contextmanager
    def _signal_scope(self) -> Iterator[None]:
        if not self.config.handle_signals:
            yield
            return
        previous: dict[signal.Signals, Any] = {}

        def handler(signum: int, frame: FrameType | None) -> None:
            del signum, frame
            self._signals += 1

        try:
            for number in (signal.SIGINT, signal.SIGTERM):
                previous[number] = signal.signal(number, handler)
        except ValueError:  # not the main thread: the caller owns signal handling
            for restored, old in previous.items():
                signal.signal(restored, old)
            previous.clear()
        try:
            yield
        finally:
            for restored, old in previous.items():
                signal.signal(restored, old)

    # -- the whole run -----------------------------------------------------------------------

    def run(self) -> RunResult:
        """Start up, run until nothing is left to do or a stop, shut down, and report.

        A CubeproofError (configuration, integrity, tool, I/O) is raised after an orderly
        shutdown; :func:`~cubeproof.coordinator.config.exit_code_of` maps it to an exit code.
        """
        # The handlers stay installed through the shutdown and the report: a stop signal while
        # the run shuts down (cancel, supervisor grace, clean-stop export, final status) is
        # counted, not the default action that would kill the process mid-shutdown.
        with self._signal_scope():
            try:
                try:
                    self._startup()
                    self._loop()
                except _Interrupted:
                    self._stop = Stop.INTERRUPTED
            except CubeproofError as error:
                self._error = error
                raise
            except OSError as error:
                # An I/O error that no layer classified: access problems are configuration (the
                # user fixes them), anything else (a full or failing disk) is an I/O failure.
                self._error = _classify_os_error(error)
                raise self._error from error
            finally:
                self._shutdown()
            return self._result()

    # -- startup (specification §7.3) --------------------------------------------------------------

    def _startup(self) -> None:
        config = self.config
        self.loaded = load_campaign(config.campaign, limits=config.limits)
        self.view = CampaignView.of(self.loaded)
        self.campaign_id = self.loaded.campaign.campaign_id
        self.layout = Layout.of(config.results, config.work)
        self.layout.prepare()
        # 1. exclusive ownership of the results directory
        self.lock = RunLock.acquire(self.layout.lock)
        try:
            self.work_lock = RunLock.acquire(self.layout.work_lock)
        except ConfigurationError as error:
            if error.rule != "run.locked":
                raise
            raise ConfigurationError(
                "run.work_locked", f"{self.layout.work} is the work directory of another worker"
            ) from None
        self._hook("startup.locked")
        alive = wait_for_survivors(self.layout.work, wait_ms=config.survivor_wait_ms)
        if alive:
            raise ConfigurationError(
                "run.work_in_use", f"processes {alive} still use {self.layout.work}"
            )
        # 2.-3. validate the journal, repair a torn suffix, rebuild the state
        check_owner(self.layout.journal, self.view, config.worker, config.limits)
        self._before_replay()
        self._interruption_point()
        replayed = replay_journal(
            self.layout.journal,
            self.loaded,
            self.view,
            limits=config.limits,
            cache_path=self.layout.cache if config.cache else None,
            lock=self.lock,
            worker=config.worker,
        )
        self.state = replayed.state
        self.tail = replayed.tail
        self._cache_status = replayed.cache if config.cache else "disabled"
        self._replayed_records = replayed.records
        if replayed.repaired:
            self._notes.append(f"repaired a torn tail of {replayed.repaired} bytes")
        self.state.check_antichain()
        self._interruption_point()
        self._hook("startup.replayed")
        # 4. artifacts first (nothing is removed unless every reference is intact), then work
        self._reconcile(replayed)
        self._interruption_point()
        self._hook("startup.reconciled")
        # 5. machinery, resources, effective policy
        check_policy_continuity(self.state.policy, config, resolve_policy(self.loaded, config))
        self.measured = measure(
            config,
            self.loaded,
            self.layout.work,
            self.layout.results,
            frontier_nodes=len(self.state.open_nodes()),
        )
        self._interruption_point()
        code_note = check_code_continuity(self.state.machinery, config, self.measured.machinery)
        if code_note is not None:
            self._notes.append(code_note)
        self._notes.extend(self.measured.notes)
        if self.measured.helper_note is not None and config.tools.helper is not None:
            self._notes.append(f"helper not used: {self.measured.helper_note}")
        self._hook("startup.measured")
        self.resources = self.measured.resources
        self.book = self.resources.book
        self.scheduler = Scheduler(
            self.book, clock=config.clock, stall_patience_ms=config.stall_patience_ms
        )
        self.rotation = RootRotation()
        self.indexes = IndexCache(clock=config.clock)
        self.engines = EngineCache(clock=config.clock)
        self.fits = idle_fit(self.measured.policy, self.resources.capacity)
        self.quarantine = QuarantineLedger(
            self.measured.policy.quarantine_quota_bytes, self._quarantined
        )
        self._begin_session(replayed)
        if config.max_seconds is not None:
            self._deadline_ns = self._clock() + int(config.max_seconds * 1e9)

    def _before_replay(self) -> None:
        """Under the run lock, before the journal is validated, repaired or appended to: the
        point at which a monitored run compares the journal with its export (specification §7.3
        step 2, :mod:`cubeproof.commands.monitored`). Nothing to do here."""

    def _interruption_point(self) -> None:
        """A signal that arrived during a long startup step ends the startup here (exit 130)."""
        if self._signals:
            raise _Interrupted

    def _reconcile(self, replayed: Replayed) -> None:
        """Startup recovery of the artifact areas (module doc), then the old work files."""
        attempts = _referencing_attempts(self.layout.journal, replayed, self.config.limits)
        # every record binds its references (IntegrityError otherwise), before any file
        references = committed_references(attempts)
        if set(references) != set(replayed.committed):
            raise IntegrityError(
                "retain.reference",
                "the references of the re-read records differ from the replayed journal's",
            )
        recover(str(self.layout.results), attempts)
        self._quarantined = tuple(a for a in references if artifact_area(a.path) is Area.QUARANTINE)
        with contextlib.suppress(OSError):
            self.layout.cache.with_name(self.layout.cache.name + ".tmp").unlink()
        removed = clear_work(self.layout.work, keep=(WORK_LOCK_NAME,))
        if removed:
            self._notes.append(f"removed {removed} files left in the work directory")

    def _begin_session(self, replayed: Replayed) -> None:
        """Commit the header (new worker) or the resume, then reopens, shard and follow-ups."""
        assert self.measured is not None and self.state is not None
        measured, state = self.measured, self.state
        snapshot = {
            "machinery": measured.machinery.to_json(),
            "policy": measured.policy.to_json(),
            "resources": measured.resources.snapshot().to_json(),
        }
        self._hook("snapshot.submitted")
        if replayed.header is None:
            header = {
                "type": "header",
                "worker": self.config.worker,
                "campaign": self.campaign_id,
                "purpose": "run",
                **snapshot,
            }
            self._spawn_service(header)
            self._sync()
            self._check_position()
        else:
            self._spawn_service(None)
            self._check_position()
            self._submit_own({"type": "resume", **snapshot}, _Own("resume"))
            self._wait_own()
        self._hook("snapshot.committed")
        if self.config.reopen_blocked:
            self._reopen_blocked()
        if not state.shards():
            self._initial_shard()
        else:
            self._finish_initial_shards(state.shards())
        self._followups()
        self._wait_own()

    def _check_position(self) -> None:
        """The service starts exactly at the end of the journal this run validated."""
        assert self.tail is not None and self.io is not None
        hello = self.io.hello
        if hello is None or (hello.seq, hello.head) != (self.tail.seq, self.tail.head):
            raise IntegrityError(
                "run.tail", "the journal changed between its validation and the service start"
            )

    # -- the I/O service ---------------------------------------------------------------------

    def _spawn_service(self, header: dict[str, Any] | None) -> None:
        assert self.lock is not None
        config = self.config
        if not config.service_argv:
            raise ConfigurationError("run.service", "no I/O service command is configured")
        variables = {sha: b.formula.variables for sha, b in self.loaded.bundles.items()}
        descriptor = lock_descriptor(self.lock)
        argv = [
            *config.service_argv,
            "--results",
            str(self.layout.results),
            "--work",
            str(self.layout.work),
            "--journal",
            str(self.layout.journal),
            "--lock",
            str(self.lock.path),
            "--lock-fd",
            str(descriptor),
            "--campaign",
            self.campaign_id,
            "--variables",
            json.dumps(variables, sort_keys=True),
        ]
        header_path: Path | None = None
        if header is not None:
            header_path = self.layout.work / "header.json"
            header_path.write_bytes(document_bytes(header))
            argv += ["--header-file", str(header_path)]
        self.io = IoClient.spawn(
            argv, cwd=str(self.layout.results), pass_fds=(descriptor,), env=config.service_env
        )
        while self.io.hello is None and self.io.failure is None:
            self.io.poll(0.05)
            if self._signals:
                raise _Interrupted
        if self.io.failure is not None:
            raise ToolError(
                "io.service_failed", f"the I/O service did not start: {self.io.failure}"
            )
        if header_path is not None:
            with contextlib.suppress(OSError):
                header_path.unlink()
            self.tail = JournalTail(
                self.layout.journal,
                ChainState(name=self.layout.journal.name, limits=config.limits),
                validator_of(self.loaded),
                limits=config.limits,
            )

    # -- committed records ---------------------------------------------------------------------

    def _sync(self) -> list[Record]:
        """Read, validate and apply every record the service has appended since last time."""
        assert self.tail is not None and self.state is not None
        records = self.tail.poll()
        for record in records:
            self.state.apply(record)
            self._selfs[record.seq] = record.self_hash
            self._on_record(record)
        if records:
            self._dirty = True
        return records

    def _on_record(self, record: Record) -> None:
        payload = record.payload
        if isinstance(payload, Attempt):
            key = key_of(payload.node)
            self._counts["attempts"] += 1
            self._counts[f"outcome:{payload.outcome.value}"] += 1
            self._forced.discard(key)
        elif isinstance(payload, SplitRecord):
            self._counts["splits"] += 1
            self._busy.discard(key_of(payload.node))
        elif isinstance(payload, NodeStop):
            self._counts["stops"] += 1
            self._busy.discard(key_of(payload.node))
        elif isinstance(payload, NodeReopen):
            self._counts["reopens"] += 1
            self._busy.discard(key_of(payload.node))
        else:
            self._counts[payload.TYPE.value] += 1

    def _acknowledge(self, value: AppendValue) -> None:
        """The service's committed position must be a record the journal holds."""
        if value.seq not in self._selfs:
            self._sync()
        held = self._selfs.pop(value.seq, None)
        if held != value.head:
            raise IntegrityError(
                "run.tail",
                f"the service reported seq {value.seq} head {value.head}; the journal differs",
            )

    # -- own jobs ------------------------------------------------------------------------------

    def _submit_own(self, payload: dict[str, Any], own: _Own) -> None:
        assert self.io is not None
        job = self.io.submit(AppendRequest.of(payload))
        self._own[job.job_id] = own

    def _wait_own(self) -> None:
        """Wait (startup only) until every own job has its result."""
        assert self.io is not None
        while self._own:
            self._take_results(self.io.poll(0.05))
            if self.io.failure is not None:
                raise ToolError("io.service_failed", f"{self.io.failure}")
            if self._signals:
                raise _Interrupted

    def _take_results(self, results: list[tuple[Job, Result]]) -> None:
        for job, result in results:
            own = self._own.pop(job.job_id, None)
            outcome = result.outcome
            if isinstance(outcome, AppendValue):
                self._acknowledge(outcome)
            if own is not None:
                if isinstance(outcome, Failure):
                    raise IntegrityError(
                        "run.refused",
                        f"the journal refused this run's {own.kind} record: "
                        f"{outcome.rule}: {outcome.detail}",
                    )
                self._hook(f"{own.kind}.committed")
                self._dirty = True
                continue
            owner = next(
                (t.attempt for t in self._attempts.values() if t.attempt.owns(job)),
                next((a for a in self._retired if a.owns(job)), None),
            )
            if owner is None:
                raise ToolError("io.unknown_job", f"a result for job {job.job_id} of no task")
            if job.op is Op.APPEND and isinstance(outcome, AppendValue):
                # the record is durable and its work files are not yet asked to be removed
                # (specification §6.1 step 7: the attempt submits the removal when this ack is
                # delivered)
                self._hook("attempt.committed")
            owner.deliver(job, result)
            if job.op is Op.PUBLISH and isinstance(outcome, PublishValue):
                self._hook("attempt.published")  # durable copy; its append is not yet submitted
            self._dirty = True

    def _stop_node(self, key: Key, state: StopState, reason: str) -> None:
        assert self.state is not None and self.state.policy is not None
        if key in self._busy:
            return
        self._busy.add(key)
        self._hook("stop.submitted")
        self._submit_own(
            {
                "type": "node_stop",
                "node": Node(*key).to_json(),
                "state": state.value,
                "reason": reason,
                "policy_sha256": self.state.policy.sha256,
            },
            _Own("stop", key),
        )

    def _followups(self) -> None:
        """Persist the stops the rules imply and the journal lacks, before scheduling them."""
        assert self.state is not None
        for item in self.state.followups():
            self._submit_followup(item)

    def _submit_followup(self, item: Followup) -> None:
        self._stop_node(item.key, item.state, item.reason)

    def _reopen_blocked(self) -> None:
        assert self.state is not None and self.state.policy is not None
        for node in self.state.open_nodes():
            if node.disposition is Disposition.STOPPED:
                self._busy.add(node.key)
                self._submit_own(
                    {
                        "type": "node_reopen",
                        "node": Node(*node.key).to_json(),
                        "reason": "reopen_blocked",
                        "policy_sha256": self.state.policy.sha256,
                    },
                    _Own("reopen", node.key),
                )
        self._wait_own()

    def _initial_shards(self) -> list[Shard]:
        """The requested roots, expanded through direct root splits (specification §12.1), as the
        shards a first use owns: one shard named ``initial``, or, when the nodes do not fit a
        journal line, the parts ``initial-1``, ``initial-2``, ... of
        :func:`cubeproof.coordinator.ownership.chunk_nodes`. The division depends on the
        campaign alone, so a later session computes the same shards."""
        campaign = self.loaded.campaign
        nodes: dict[tuple[str, str], Node] = {}
        splits = {(s.node.formula_sha256, s.node.cube): s for s in campaign.root_splits}
        for root in campaign.roots:
            direct = splits.get((root.formula_sha256, root.cube))
            if direct is None:
                nodes[root.sort_key] = root
                continue
            for cube in split_children(root.cube, direct.variables):
                child = Node(root.formula_sha256, cube)
                nodes[child.sort_key] = child
        chunks = chunk_nodes(
            self.campaign_id,
            [nodes[k] for k in sorted(nodes)],
            max_line_bytes=self.config.limits.line_bytes,
        )
        if len(chunks) == 1:
            return [Shard(self.campaign_id, "initial", tuple(chunks[0]))]
        return [
            Shard(self.campaign_id, f"initial-{index}", tuple(chunk))
            for index, chunk in enumerate(chunks, 1)
        ]

    def _initial_shard(self) -> None:
        """First use: own the requested roots (:meth:`_initial_shards`). Every shard is persisted
        before any node of it runs (specification §7.4), one record at a time: together the
        records of a large campaign exceed what the I/O service queues."""
        self._submit_shards(self._initial_shards())

    def _submit_shards(self, shards: Sequence[Shard]) -> None:
        for shard in shards:
            self._hook("shard.submitted")
            self._submit_own(
                {"type": "shard", "shard": shard.to_json(), "shard_sha256": shard.shard_id},
                _Own("shard"),
            )
            self._wait_own()

    def _one_initial_shard(self) -> bool:
        """True if the requested roots certainly fit one shard record, decided without building
        them: an upper bound of what the nodes cost. A node entry is its cube and the formula
        hash; a literal is at most the digits of the largest variable, a sign and a comma, the
        rest of the entry at most 110 bytes. Campaigns above the bound are divided by
        :meth:`_initial_shards` to find out."""
        campaign = self.loaded.campaign
        splits = {(s.node.formula_sha256, s.node.cube): s for s in campaign.root_splits}
        count = longest = 0
        for root in campaign.roots:
            direct = splits.get((root.formula_sha256, root.cube))
            width = 0 if direct is None else len(direct.variables)
            count += 1 << width
            longest = max(longest, len(root.cube) + width)
        digits = max(len(str(b.formula.variables)) for b in self.loaded.bundles.values())
        budget = self.config.limits.line_bytes - 2 * RECORD_OVERHEAD
        return count * (110 + (digits + 2) * longest) < budget

    def _finish_initial_shards(self, accepted: Sequence[str]) -> None:
        """A first use that was interrupted between the parts of its own shards owns the rest.

        Only then: the accepted shards must be some, not all, of the ``initial-K`` parts and
        nothing else. A worker that was given shards, or that owns all the parts, gets nothing
        from here; ownership is never reconstructed from a changed command line
        (specification §12.1)."""
        if self._one_initial_shard():
            return
        parts = self._initial_shards()
        have = set(accepted)
        if len(parts) > 1 and have < {s.shard_id for s in parts}:
            self._submit_shards([s for s in parts if s.shard_id not in have])

    # -- the loop ------------------------------------------------------------------------------

    def _loop(self) -> None:
        assert self.state is not None and self.io is not None and self.measured is not None
        self._hook("loop.start")
        supervisor = self.measured.supervisor
        while True:
            tick_started = self._clock()
            self._check_stop()
            if self._stop is not None and not self._drained:
                self._begin_drain()
            busy = self._advance()
            self._reap()
            self._observe()
            self._stage_reservations()
            self._publications()
            if self._stop is None:
                self._derived()
                self._plan()
                if self.resources.remeasure() is not None:
                    self._dirty = True
            self._ticks.record(max(0, self._clock() - tick_started))
            if self._finished():
                break
            timeout_ms = 0 if busy else self.config.tick_ms
            if supervisor.active:
                supervisor.step(timeout_ms)
                self._take_results(self.io.poll(0.0))
            else:
                self._take_results(self.io.poll(timeout_ms / 1000))
            self._service_check()
        if self._blocked is not None:
            # retain-full or another incomplete retained publication: the run stopped new work
            # and drained; it ends with the block's diagnostic and exit code (specification §7.2,
            # §12.2)
            raise self._blocked.error()
        if self._stop is None:
            self._stop = Stop.COMPLETE

    def _check_stop(self) -> None:
        assert self.state is not None
        if self._stop is not None:
            if self._signals >= 2 and self.measured is not None:
                self.measured.supervisor.stop(1)  # a second signal: no more grace
            return
        if self._signals:
            self._stop = Stop.INTERRUPTED
        elif self._deadline_ns is not None and self._clock() >= self._deadline_ns:
            self._stop = Stop.TIME
        elif self.state.machine_halt:
            self._stop = Stop.MACHINE
        elif self.state.anomaly_halt:
            self._stop = Stop.ANOMALY

    def _service_check(self) -> None:
        assert self.io is not None
        failure = self.io.failure
        if failure is None:
            return
        if self._stop is None:
            self._stop = Stop.SERVICE
            self._notes.append(f"the I/O service failed: {failure}")
        for task in self._attempts.values():
            task.attempt.io_failed(str(failure))
        self._own.clear()

    def _begin_drain(self) -> None:
        """Stop new work: cancel what has no committed record, let a commit in flight finish."""
        assert self.measured is not None
        self._drained = True
        self._hook("drain.begin")
        policy = self.measured.policy
        self.measured.supervisor.stop(policy.stop_grace_ms)
        for task in self._attempts.values():
            task.attempt.cancel()
        for split in self._splits.values():
            split.task.cancel(policy.stop_grace_ms)
        self._drain_deadline = time.monotonic() + policy.stop_grace_ms / 1000 + _DRAIN_EXTRA_S

    def _finished(self) -> bool:
        if self._stop is not None:
            idle = not self._attempts and not self._splits and not self._own
            expired = self._drain_deadline is not None and time.monotonic() > self._drain_deadline
            return idle or expired
        return (
            not self._dirty
            and not self._attempts
            and not self._splits
            and not self._own
            and not self._busy
            and self._queued == 0
        )

    # -- attempts and splits -------------------------------------------------------------------

    def _advance(self) -> bool:
        """Advance the tasks; True if some task has CPU work left (the loop must not sleep).

        A task waiting for a process or for the I/O service is polled once (its ``advance``
        returns at once); tasks with CPU work (writing a CNF, unit propagation, a model, the
        Python lookahead) share a time budget in slices of 5 ms, round-robin, and the budget
        is not spent on tasks that have nothing to do (no busy waiting).
        """
        cpu: list[LeafAttempt | SplitTask] = []
        for task in self._attempts.values():
            if task.attempt.finished:
                continue
            if task.attempt.phase in _CPU_PHASES:
                cpu.append(task.attempt)
            else:
                task.attempt.advance(1)
        helper = self.measured is not None and self.measured.helper is not None
        for split in self._splits.values():
            if split.task.finished:
                continue
            if helper:
                split.task.advance(1)
            else:
                cpu.append(split.task)
        end = self._clock() + _TICK_BUDGET_NS
        while cpu and self._clock() < end:
            ready = [t for t in cpu if not t.finished and _cpu_bound(t)]
            if not ready:
                break
            turn = self._turn % len(ready)
            self._turn += 1
            for worker in ready[turn:] + ready[:turn]:
                worker.advance(5)
                if self._clock() >= end:
                    break
        return (
            any(not t.finished and _cpu_bound(t) for t in cpu)
            or self.indexes.pending
            or self.engines.pending
        )

    def _reap(self) -> None:
        for task_id, task in list(self._attempts.items()):
            if not task.attempt.finished:
                continue
            self.book.release(task_id)
            del self._attempts[task_id]
            self._dirty = True
            self._attempt_ended(task)
        for task_id, split in list(self._splits.items()):
            if split.task.finished:
                self.book.release(task_id)
                del self._splits[task_id]
                self._dirty = True
                if not split.task.cancelled:
                    self._split_done(split)

    def _attempt_ended(self, task: _AttemptTask) -> None:
        attempt = task.attempt
        self._hook(f"attempt.{attempt.phase.value}")
        if attempt.phase is Phase.DONE:
            if attempt.cleanup_error:
                self._notes.append(
                    f"cleanup of attempt {attempt.attempt_id}: {attempt.cleanup_error}"
                )
            return
        reason = attempt.abandoned
        if reason == "cancelled":
            return
        self._retired.append(attempt)  # its late results are recognized and absorbed
        if reason == "retain_blocked":
            blocked = attempt.retain_blocked
            assert blocked is not None
            self._notes.append(f"attempt {attempt.attempt_id}: {blocked.note}")
            if self._blocked is None:
                self._blocked = blocked
            if self._stop is None:
                # stop new work and drain like a service stop; the run then raises the
                # block's error instead of reporting this stop (module doc)
                self._stop = Stop.SERVICE
            return
        if reason == "commit_refused":
            raise IntegrityError(
                "run.refused", f"the journal refused the record of attempt {attempt.attempt_id}"
            )
        if reason == "io_mismatch":
            raise LeafError("leaf.io_mismatch", f"attempt {attempt.attempt_id} was stopped")
        if self._stop is None:
            self._stop = Stop.SERVICE
        self._notes.append(f"attempt {attempt.attempt_id} abandoned: {reason}")

    def _observe(self) -> None:
        """Hooks at the phase changes of the attempts (crash tests inject faults here), and the
        queue age of a sealed proof waiting for its check."""
        for task in self._attempts.values():
            phase = task.attempt.phase
            if phase is not task.seen:
                task.seen = phase
                self._hook(f"attempt.{phase.value}")
            if phase is Phase.QUEUED_CHECK and task.seq < 0:
                self._check_seq += 1
                task.seq = self._check_seq

    def _stage_reservations(self) -> None:
        """Shrink each attempt's reservation as its phases free CPU and RAM (specification §8.3)."""
        for task_id, task in self._attempts.items():
            attempt = task.attempt
            phase = attempt.phase
            held = self.book.get(task_id)
            if held is None:
                continue
            want: Need | None = None
            if phase is Phase.SEAL or phase in (
                Phase.REHASH,
                Phase.PUBLISH,
                Phase.COMMIT,
                Phase.CLEANUP,
            ):
                want = Need(0, 0, held.need.disk)
            elif phase is Phase.QUEUED_CHECK:
                request = attempt.check_request
                if request is not None:
                    want = sealed_need(request.proof_bytes, task.cnf_bytes, task.group)
            if want is not None and want != held.need and _shrinks(held.need, want):
                self.book.restage(task_id, phase.value, want, None)
                self._dirty = True

    def _publications(self) -> None:
        """Grant, hold or refuse the publications the attempts ask for (module doc)."""
        waiting = {t for t, task in self._attempts.items() if task.attempt.wants_publish}
        if not waiting:
            self._publish_waiting = False
            return
        target = self.resources.group_of("results")
        measures = self.resources.measures()
        for task_id in sorted(waiting):
            task = self._attempts[task_id]
            request = task.attempt.publish_request
            assert request is not None
            need = publish_need(
                request.proof_bytes, task.cnf_bytes, source_group=task.group, target_group=target
            )
            verdict, why = publication_admission(self.book, task_id, need, measures, stuck=waiting)
            if verdict == "grant":
                task.attempt.start_publish()
            elif verdict == "refuse":
                task.attempt.refuse_publish(why)
            else:
                continue
            waiting.discard(task_id)
            self._dirty = True
        self._publish_waiting = bool(waiting)

    # -- derived actions ------------------------------------------------------------------------

    def _running_keys(self) -> set[Key]:
        keys = {t.key for t in self._attempts.values()}
        keys.update(s.key for s in self._splits.values())
        keys.update(self._busy)
        return keys

    def _derived(self) -> None:
        """State-derived work: stops the rules imply, and tasks that are no longer needed."""
        assert self.state is not None and self.measured is not None
        if not self._dirty:
            return
        self._followups()
        running = {t.key for t in self._attempts.values()} | {s.key for s in self._splits.values()}
        for key in self.state.unneeded(sorted(running)):
            for task in self._attempts.values():
                if task.key == key:
                    task.attempt.cancel()
            for split in self._splits.values():
                if split.key == key:
                    split.task.cancel(self.measured.policy.stop_grace_ms)

    # -- planning --------------------------------------------------------------------------------

    def _plan(self) -> None:
        assert self.state is not None and self.measured is not None
        now = self._clock()
        if not self._dirty and now < self._next_plan:
            return
        self._dirty = False
        self._ready_now = {}
        self._next_plan = now + _PLAN_INTERVAL_NS
        state = self.state
        halted = state.anomaly_halt or state.machine_halt
        group = self.resources.group_of("work")
        checks = self._check_candidates()
        solves: list[Candidate] = []
        splits: list[Candidate] = []
        works: dict[str, Work] = {}
        waiting = deferred = 0
        # The Python reference of the lookahead shares one engine per formula whose trail is
        # not reentrant: at most one reference split runs at a time (a helper has no such limit).
        reference_busy = self.measured.helper is None and bool(self._splits)
        if not halted:
            limit = max(16, 4 * (len(self._attempts) + 1))
            for work in next_work(
                state, running=self._running_keys(), rotation=self.rotation, limit=limit
            ):
                if (
                    work.stage is Stage.SPLIT
                    and work.node.key not in self._forced
                    and self.measured.helper is None
                ):
                    if reference_busy:
                        deferred += 1  # replanned when the running split ends
                        continue
                    reference_busy = True
                candidate = self._candidate(work, group, len(works))
                if candidate is None:
                    waiting += 1
                    continue
                works[candidate.task_id] = work
                (splits if candidate.stage is Stage.SPLIT else solves).append(candidate)
        self._queued = len(checks) + len(solves) + len(splits) + waiting + deferred
        if waiting:
            self._dirty = True  # an index or engine is being built: plan again next tick
        active = sum(
            1 for t in self._attempts.values() if t.attempt.phase is not Phase.QUEUED_CHECK
        ) + len(self._splits)
        if self._publish_waiting:
            # a publication waits for disk: freed disk goes to it, not to new work (module doc)
            solves, splits = [], []
            self._dirty = True
        plan = self.scheduler.plan(
            checks=checks,
            splits=splits,
            solves=solves,
            measures=self.resources.measures(),
            active=active,
            halted=halted,
        )
        for item in plan.impossible:
            self._impossible(item)
        if plan.stall is not None:
            self._stalled(plan.stall.nodes, plan.stall.requirements)
        for launch in plan.launches:
            candidate = launch.candidate
            try:
                if candidate.stage is Stage.CHECK:
                    self._attempts[candidate.task_id].attempt.start_check()
                elif candidate.stage is Stage.SOLVE:
                    self._start_attempt(candidate, works[candidate.task_id])
                else:
                    self._start_split(candidate, works[candidate.task_id])
            except BaseException:
                started = candidate.task_id in self._attempts or candidate.task_id in self._splits
                held = self.book.get(candidate.task_id) is not None
                if candidate.stage is not Stage.CHECK and not started and held:
                    self.book.release(candidate.task_id)
                raise
        if plan.launches:
            self._dirty = True

    def _check_candidates(self) -> list[Candidate]:
        waiting = [
            t
            for t in self._attempts.values()
            if t.attempt.phase is Phase.QUEUED_CHECK and not t.attempt.cancelled
        ]
        out: list[Candidate] = []
        for task in sorted(waiting, key=lambda t: (t.seq, node_id(*t.key))):
            request = task.attempt.check_request
            if request is None:
                continue
            out.append(
                check_candidate(
                    request,
                    task_id=task.attempt.attempt_id,
                    node=task.key,
                    cnf_bytes=task.cnf_bytes,
                    group=task.group,
                    seq=task.seq,
                )
            )
        return out

    def _candidate(self, work: Work, group: str, seq: int) -> Candidate | None:
        """The scheduler's view of a node to start (None while its index is being built)."""
        assert self.state is not None and self.measured is not None
        policy = self.state.policy
        assert policy is not None
        key = work.node.key
        formula = self.loaded.formula(key[0])
        stage = work.stage
        if stage is Stage.SPLIT and key in self._forced:
            if self._forced_runs[key] > policy.tool_retries + 1:
                self._stop_node(key, StopState.RESOURCE_BLOCKED, REASON_UNIT_ROUTE)
                return None
            stage = Stage.SOLVE
        if stage is Stage.SOLVE:
            if not self._ready(self.indexes, formula):
                return None
            cnf_bytes = cnf_size_bytes(formula, key[1])
            if policy.proof_mode is ProofMode.STREAM:
                # solver, checker with the node's next arena and relay (specification §8.3); a unit
                # route later shrinks it like a file-mode attempt
                arena = self.state.stream_arena(key)
                need = stream_need(policy, cnf_bytes, group, arena=arena)
            else:
                need = solve_need(policy, cnf_bytes, group)
        else:
            if self.measured.helper is None and not self._ready(self.engines, formula):
                return None
            need = helper_need(group)
        return Candidate(new_id128(), stage, key, need, seq)

    def _ready(self, cache: SlicedCache[Any], formula: Formula) -> bool:
        """Whether the shared index of ``formula`` is built; asking advances a pending build by
        one slice, at most once per planning step (a tick stays short while it is built)."""
        found = self._ready_now.get((id(cache), formula.sha256))
        if found is None:
            found = cache.get(formula) is not None
            self._ready_now[(id(cache), formula.sha256)] = found
        return found

    def _impossible(self, item: Impossible) -> None:
        """A task that cannot run on an idle machine: apply its exhaustion rule now (specification
        §8.4)."""
        candidate = item.candidate
        key = candidate.node
        assert key is not None
        if candidate.stage is Stage.CHECK:
            task = self._attempts.get(candidate.task_id)
            if task is not None:
                task.attempt.cancel()
            self._stop_node(key, StopState.RESOURCE_BLOCKED, REASON_CHECK_EXHAUSTED)
            return
        self._stop_node(key, StopState.RESOURCE_BLOCKED, f"{candidate.stage.value}_resources")

    def _stalled(self, nodes: tuple[Key, ...], requirements: tuple[str, ...]) -> None:
        """Nothing runs, nothing fits and nothing can free a resource: block the nodes."""
        self._notes.append("stalled: " + "; ".join(requirements)[:600])
        for key in nodes:
            for task in self._attempts.values():
                if task.key == key:
                    task.attempt.cancel()
            self._stop_node(key, StopState.RESOURCE_BLOCKED, REASON_STALLED)

    def _start_attempt(self, candidate: Candidate, work: Work) -> None:
        assert self.state is not None and self.measured is not None and self.io is not None
        policy = self.state.policy
        assert policy is not None
        key = work.node.key
        formula: Formula = self.loaded.formula(key[0])
        digest = self._digests.setdefault(formula.sha256, CnfDigest(formula))
        index = self.indexes.get(formula)
        assert index is not None
        if key in self._forced:
            self._forced_runs[key] += 1
        # the arena the replay derives for this node (specification §6.4: live = replay)
        streaming = policy.proof_mode is ProofMode.STREAM
        arena = self.state.stream_arena(key) if streaming else None
        attempt = LeafAttempt(
            formula=formula,
            digest=digest,
            cube=key[1],
            policy=policy,
            work_dir=str(self.layout.work),
            tools=self.measured.tools,
            supervisor=self.measured.supervisor,
            io=self.io,
            attempt_id=candidate.task_id,
            unit_index=index,
            fits=self.fits,
            clock=self.config.clock,
            quarantine=self.quarantine,
            publish_gate=True,
            stream_arena=arena,
        )
        self._attempts[candidate.task_id] = _AttemptTask(
            attempt, key, cnf_size_bytes(formula, key[1]), self.resources.group_of("work")
        )
        self._hook("attempt.started")

    def _start_split(self, candidate: Candidate, work: Work) -> None:
        assert self.state is not None and self.measured is not None
        policy = self.state.policy
        assert policy is not None
        key = work.node.key
        bundle = self.loaded.bundles[key[0]]
        k = split_k(policy, key[1], bundle.formula.variables)
        pool: tuple[int, ...] | None = None
        if policy.split.pool is not None:
            found = bundle.manifest.pools.get(policy.split.pool)
            if found is None:
                raise ConfigurationError(
                    "run.pool", f"the bundle has no variable pool {policy.split.pool!r}"
                )
            pool = tuple(found)
        task = SplitTask(
            bundle=bundle,
            cube=key[1],
            k=k,
            pool=pool,
            budget=Budget(policy.split.probe_limit, policy.split.wall_ms),
            engines=self.engines,
            supervisor=self.measured.supervisor,
            helper=self.measured.helper,
            work=self.layout.work,
            clock=self.config.clock,
        )
        self._splits[candidate.task_id] = _SplitTask(task, key, k)
        self._hook("split.started")

    def _split_done(self, split: _SplitTask) -> None:
        """The splitter's answer becomes an action (specification §9.1)."""
        choice = split.task.choice
        assert choice is not None
        formula = split.task.bundle.formula
        decision = decide_split(
            choice,
            variables=formula.variables,
            cube=split.key[1],
            pool=split.task.pool,
            k=split.k,
        )
        if decision.action is SplitAction.FALLBACK:
            fallback = lowest_eligible_choice(
                formula,
                split.key[1],
                split.k,
                split.task.pool,
                reason=decision.reason or "helper_failure",
                index=self.indexes.get(formula),
            )
            choice = fallback
            decision = decide_split(
                fallback,
                variables=formula.variables,
                cube=split.key[1],
                pool=split.task.pool,
                k=split.k,
                fallback=True,
            )
        self._act(split.key, choice, decision)

    def _act(self, key: Key, choice: SplitChoice, decision: SplitDecision) -> None:
        if decision.action is SplitAction.SPLIT:
            info = choice.info_dict()
            self._hook("split.submitted")
            self._busy.add(key)  # the node is busy until its split record is applied
            self._submit_own(
                {
                    "type": "split",
                    "node": Node(*key).to_json(),
                    "variables": list(decision.variables),
                    "splitter": {"name": str(info.get("algorithm", "lookahead-v1")), "info": info},
                },
                _Own("split", key),
            )
        elif decision.action is SplitAction.SOLVE:
            self._forced.add(key)
        else:
            self._stop_node(key, decision.stop_state or StopState.STUCK, decision.reason)

    # -- shutdown --------------------------------------------------------------------------------

    def _shutdown(self) -> None:
        """Cancel what is left, close the service, write the cache, release the lock."""
        self._hook("shutdown")
        measured = self.measured
        for task in self._attempts.values():
            task.attempt.cancel(grace_ms=1)
        for split in self._splits.values():
            split.task.cancel(1)
        if measured is not None:
            try:
                measured.supervisor.shutdown(grace_ms=min(measured.policy.stop_grace_ms, 5000))
            except ToolError as error:
                self._notes.append(f"shutdown: {error}")
        if self.io is not None:
            self.io.close(timeout=30.0)
        self._final_sync_and_cache()
        if self.tail is not None:
            self.tail.close()
        if self.work_lock is not None:
            self.work_lock.release()
        if self.lock is not None:
            self.lock.release()

    def _final_sync_and_cache(self) -> None:
        state = self.state
        if state is None or self.tail is None:
            return
        try:
            self._sync()
        except CubeproofError as error:
            if self._error is None:
                self._error = error
            return
        if self.config.cache and self._error is None and state.journal_id is not None:
            try:
                write_cache(self.layout.cache, state, self.campaign_id)
                self._hook("cache.written")
            except OSError as error:
                self._notes.append(f"the state cache was not written: {error}")

    # -- the report -----------------------------------------------------------------------------

    def _exit_code(self) -> int:
        """Specification §12.2: 4 > 5 > 2 > 6 > 1 > 0 for completed work, 130 for a deliberate
        interruption (an integrity error that was already diagnosed is raised, not returned)."""
        assert self.state is not None
        stop = self._stop
        if stop is Stop.INTERRUPTED:
            return 130
        nodes = self.state.open_nodes()
        conditions = (
            (
                5,
                stop in (Stop.MACHINE, Stop.SERVICE)
                or self.state.machine_halt
                or any(n.stop_state is StopState.TOOL_BLOCKED for n in nodes),
            ),
            (2, any(n.disposition is Disposition.MODEL for n in nodes)),
            (6, self.state.session.anomalies > 0 or stop is Stop.ANOMALY),
            (1, bool(nodes) or stop is Stop.TIME),
        )
        return next((code for code, holds in conditions if holds), 0)

    def _result(self) -> RunResult:
        state = self.state
        assert state is not None and self._stop is not None
        nodes = state.open_nodes()
        return RunResult(
            exit_code=self._exit_code(),
            reason=self._stop,
            campaign=self.campaign_id,
            worker=self.config.worker,
            journal=state.journal_id,
            seq=state.seq,
            head=state.head,
            open={f"{s}:{d}": c for (s, d), c in state.counts().items()},
            session=dict(sorted(self._counts.items())),
            anomalies=state.session.anomalies,
            models=sum(1 for n in nodes if n.disposition is Disposition.MODEL),
            given_away=len(state.given_away()),
            cache=self._cache_status,
            replayed_records=self._replayed_records,
            ticks=self._ticks.report(),
            notes=tuple(self._notes),
        )


_ACCESS_ERRORS = frozenset(
    {errno.EACCES, errno.EPERM, errno.ENOENT, errno.ENOTDIR, errno.EISDIR, errno.EROFS}
)


def _classify_os_error(error: OSError) -> CubeproofError:
    where = f"{error.filename}: " if error.filename else ""
    detail = f"{where}{error.strerror or error}"
    if error.errno in _ACCESS_ERRORS:
        return ConfigurationError("run.access", detail)
    return ToolError("run.io", detail)


def _cpu_bound(task: LeafAttempt | SplitTask) -> bool:
    """Whether the task has CPU work to do now (an attempt in a computing phase, a reference
    split), as opposed to waiting for a process or the I/O service."""
    return task.phase in _CPU_PHASES if isinstance(task, LeafAttempt) else True


def _shrinks(old: Need, new: Need) -> bool:
    """``new`` asks for nothing more than ``old`` in any dimension (a decrease always fits)."""
    before, after = old.amounts(), new.amounts()
    return all(d in before and a <= before[d] for d, a in after.items())


def run_worker(config: RunConfig) -> RunResult:
    """``cubeproof run`` as a library call: one :class:`Coordinator` run."""
    return Coordinator(config).run()
