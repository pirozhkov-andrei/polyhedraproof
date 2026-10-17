"""Evidence of cubeproof: the journal record codec, the journal and its durable storage.

- :mod:`cubeproof.evidence.schema`: the ``cubeproof-journal-1`` record values, their schema
  and the record rules that need no other record (specification §4.7, §4.8).
- :mod:`cubeproof.evidence.journal`: reading and validating journals (specification §7.1), anchors,
  durable append, locks and torn-tail repair (specification §7.1, §7.3, §7.5).

This package root imports nothing of its own (architecture rule for package roots).
"""
