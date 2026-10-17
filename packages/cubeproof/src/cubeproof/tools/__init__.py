"""External tools as supervised processes (specification §2.3, §4.6, §6.2, §6.3, §8.3).

- ``tools.isolation``: the util-linux wrappers (``setpriv --pdeathsig KILL``, ``prlimit``)
  and pinned binaries identified by the SHA-256 of the actual regular file.
- ``tools.process``: the nonblocking supervisor: own sessions/groups, caps, monotonic
  deadlines, TERM then KILL, cancellation, bounded draining, reaping, typed causes.
- ``tools.checker``: the only recognizer of exact checker success, pinned cake_lpr arena
  diagnostics, arena retry values, heap and check-time fit.
- ``tools.solver``: solver argv rules (campaign.argv, the deny list), solver command line,
  pinned CaDiCaL diagnostics.
- ``tools.process_outcome``: the specification §6.3 outcome table from typed causes and process
  results.
- ``tools.machinery``: the measured machinery of a header/resume (specification §4.6).

This package root imports nothing, so importing one tool module does not start the others.
"""
