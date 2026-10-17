"""Split selection (specification §9): static, proof-prefix-v1 and lookahead-v1.

A splitter chooses an ordered list W of distinct unassigned variables for a node; it is a
heuristic, never an authority (specification §5, §9.1): the coordinator validates a choice, records
the split with its ordered variables, and certification reads the recorded W without running a
splitter again. Every sign child of the recorded split must exist, so nothing here ever
drops a child or adds an implied assumption to one.

- ``split.choice``: :class:`SplitChoice`, :class:`Budget`, eligibility, clamping of k and the
  lowest-eligible fallback.
- ``split.static``: an explicitly supplied ordered W, its prefixes and case indexing (specification
  §9.2).
- ``split.proof_prefix``: ``proof-prefix-v1``, the proof-prefix algorithm (specification §9.2).
- ``split.lookahead``: the Python reference of ``lookahead-v1`` (specification §9.3).
- ``split.protocol``: the ``cubeproof-look-request-1`` / ``cubeproof-look-result-1`` documents.
- ``split.helper``: the optional native helper ``cubeproof-look``, its supervised execution
  and the fallbacks.

This package root imports nothing.
"""
