"""The coordinator: scheduling state and resources, and the run lifecycle.

Scheduling (specification §6.5, §7.3, §8):

- :mod:`.state`: deterministic replay of one journal, the open frontier and follow-ups;
- :mod:`.ledger`: reservation ledgers (per dimension and storage group), safe remeasurement;
- :mod:`.resources`: capacity, reservation sizes, the proof-cap clamp, pressure handling;
- :mod:`.scheduler`: launch priorities, check draining, impossible tasks and stalls;
- :mod:`.scheduler_select`: root fairness, split decisions, tools of a machinery snapshot;
- :mod:`.scheduler_loop`: fair slicing under a per-tick budget and tick-latency statistics.

Lifecycle (specification §7.3, §7.5, §12.2):

- :mod:`.run`: the :class:`~cubeproof.coordinator.run.Coordinator`: startup sequence, event loop,
  stop and shutdown; :mod:`.config` its configuration, result and exit codes;
- :mod:`.layout`, :mod:`.replay`, :mod:`.measure`, :mod:`.tail`, :mod:`.cache`: directories and
  survivors, journal validation and replay, machinery and policy measurement, following the
  journal the service writes, the derived state cache;
- :mod:`.service`: the I/O service process (the journal writer behind the service protocol);
- :mod:`.splits`, :mod:`.indexes`: the splitter as a nonblocking task, shared propagation indexes.

Only :mod:`.run`, :mod:`.service` and :mod:`.splits` start processes; the modules of the first
group have no clock beyond an injected one and start none.
"""
