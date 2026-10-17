"""The leaf protocol: one attempt on one node, and the trusted record binding (specification §5,
§6).

- :mod:`cubeproof.leaf.binding` is the only constructor of a VERIFIED_UNSAT attempt record
  (specification §2.3, §5): pure checks of identity-bound evidence (file hashes, tool runs,
  launches).
- :mod:`cubeproof.leaf.files` writes and seals the work files of one attempt.
- :mod:`cubeproof.leaf.attempt` is the nonblocking state machine of one attempt: the file
  modes (transient and retain), with the publication step before the record (specification §6.1 step
  6), and the stream mode (specification §6.4).
- :mod:`cubeproof.leaf.stream` runs and classifies the coupled solver -> relay -> checker run
  of a CDCL leaf under a stream policy; :mod:`cubeproof.leaf.retry` derives the bounded fresh
  attempt after a stream arena exhaustion from the committed record alone.
- :mod:`cubeproof.leaf.retain` decides retained publications and validates committed
  references at restart; :mod:`cubeproof.leaf.quarantine` keeps rejected proofs under the
  quota. Both use the single publication/reconciliation implementation of
  :mod:`cubeproof.tools.artifacts`.
- :mod:`cubeproof.leaf.driver` runs attempts to their end (tests, simple entry points).

A unit refutation under a stream policy follows the file protocol (specification §4.8). A stream
attempt without the pinned relay interpreter is refused with ``ConfigurationError
leaf.relay_interpreter`` before any file is written.
"""
