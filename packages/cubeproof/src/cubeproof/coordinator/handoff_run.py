"""A run with a handoff desk: ``run --shard FILE --inbox DIR --outbox DIR`` (specification §7.3,
§7.4, §12.1).

:class:`DeskCoordinator` is the :class:`~cubeproof.coordinator.run.Coordinator` plus a
:class:`~cubeproof.coordinator.handoff.HandoffDesk`. It changes the run in five places and nowhere
else:

* ``_begin_session``: the desk is built from the replayed journal and **started before the
  resume** is committed (specification §7.3 step 4: republish missing handoff outputs, finish the
  moves of accepted inbox files, remove interrupted temporary files), then the base startup goes on;
* ``_initial_shard``: first use. An explicit ``--shard`` is offered to the desk and waited for;
  else a shard that waits in the inbox is the first shard (the desk accepts it in its first
  tick); else the worker makes the all-roots shard of specification §12.1 itself. Later runs offer a
  ``--shard`` once as well: an identical shard is harmless, a new one is validated under
  specification §7.4 and a rejected one is a ConfigurationError (exit 3) with the diagnostic;
  nothing is reconstructed from a changed command line;
* ``_on_record``: every committed record is observed by the desk;
* ``_derived``: one ``desk.tick`` per loop iteration, after the committed records are applied
  (and the one-time offer of a ``--shard`` to a worker that already owns shards);
* ``_running_keys``/``_finished``: the nodes reserved for a handoff in flight count as running,
  and the run does not end while the desk has a record in flight or owes its first scan or a
  publication.

The result carries the desk's counters (``session["desk.<name>"]``) and its visible problems
(``notes``): an unpublished output, a request waiting behind a foreign file, an unreadable inbox
file. A run never claims that what it gave away is closed (``given_away`` is reported separately).
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any

from cubeproof.base.errors import ConfigurationError
from cubeproof.contracts.documents import Shard
from cubeproof.coordinator.config import RunConfig, RunResult
from cubeproof.coordinator.handoff import DeskConfig, HandoffDesk
from cubeproof.coordinator.ownership import Ownership, Verdict
from cubeproof.coordinator.replay import Replayed
from cubeproof.coordinator.run import Coordinator, _Own
from cubeproof.coordinator.state import Key
from cubeproof.evidence.schema import Record

__all__ = ["DeskCoordinator", "run_with_desk"]


class DeskCoordinator(Coordinator):
    """A :class:`Coordinator` with a handoff desk (module doc)."""

    def __init__(
        self,
        config: RunConfig,
        *,
        inbox: Path | None = None,
        outbox: Path | None = None,
        shard: Shard | None = None,
        scan_interval_ns: int = 250_000_000,
    ) -> None:
        super().__init__(config)
        self._inbox = inbox
        self._outbox = outbox
        self._cli_shard = shard
        self._cli_offered = False
        self._scan_interval_ns = scan_interval_ns
        self.desk: HandoffDesk

    # -- startup -------------------------------------------------------------------------------

    def _begin_session(self, replayed: Replayed) -> None:
        variables = {sha: b.formula.variables for sha, b in self.loaded.bundles.items()}
        ownership = (
            Ownership(self.campaign_id, variables)
            if replayed.header is None
            else Ownership.from_journal(
                self.layout.journal, campaign=self.campaign_id, variables=variables, verify=False
            )
        )
        self.desk = HandoffDesk(
            DeskConfig(
                campaign=self.campaign_id,
                variables=variables,
                results=self.layout.results,
                inbox=self._inbox,
                outbox=self._outbox,
                limits=self.config.limits,
                scan_interval_ns=self._scan_interval_ns,
                clock=self.config.clock,
                hook=self._hook,
            ),
            ownership,
            self._append_for_desk,
        )
        self.desk.start()
        super()._begin_session(replayed)

    def _append_for_desk(self, payload: dict[str, Any]) -> None:
        self._submit_own(payload, _Own("desk"))

    def _initial_shard(self) -> None:
        """First use (module doc): ``--shard``, else a shard in the inbox, else all roots."""
        if self._cli_shard is not None:
            self._offer_cli_shard()
            self._wait_own()
        elif not self.desk.inbox_offers():
            super()._initial_shard()

    def _offer_cli_shard(self) -> None:
        shard = self._cli_shard
        if shard is None or self._cli_offered:
            return
        self._cli_offered = True
        judgement = self.desk.offer(shard)
        if judgement.verdict is Verdict.REJECT:
            raise ConfigurationError(judgement.rule or "shard", judgement.detail)

    # -- the loop ------------------------------------------------------------------------------

    def _on_record(self, record: Record) -> None:
        super()._on_record(record)
        self.desk.observe(record)

    def _derived(self) -> None:
        super()._derived()
        assert self.state is not None
        if not self._cli_offered and not self.desk.busy:
            self._offer_cli_shard()  # a later run: an identical shard is a no-op, a new one counts
        self.desk.tick(self.state, self._running_keys())

    def _running_keys(self) -> set[Key]:
        return super()._running_keys() | set(self.desk.reserved)

    def _finished(self) -> bool:
        done = super()._finished()
        if self._stop is not None:
            return done
        return done and not self.desk.busy and (self._cli_shard is None or self._cli_offered)

    # -- the report ----------------------------------------------------------------------------

    def _result(self) -> RunResult:
        result = super()._result()
        if not hasattr(self, "desk"):
            return result
        session = {**result.session, **{f"desk.{k}": v for k, v in self.desk.summary().items()}}
        notes = (
            *result.notes,
            *(f"handoff {k}: {v}" for k, v in sorted(self.desk.problems.items())),
        )
        return replace(result, session=dict(sorted(session.items())), notes=notes)


def run_with_desk(
    config: RunConfig,
    *,
    inbox: Path | None = None,
    outbox: Path | None = None,
    shard: Shard | None = None,
) -> RunResult:
    """``cubeproof run`` with ``--inbox``/``--outbox``/``--shard`` as a library call."""
    return DeskCoordinator(config, inbox=inbox, outbox=outbox, shard=shard).run()
