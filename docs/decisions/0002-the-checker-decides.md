# 0002. Only the verified checker closes a case

## Context

Checked refutations allow the result to be assessed without trusting the solver.
The checker's formal guarantee has execution assumptions; the reduction, encoder
and exhaustive coverage remain separate obligations ([TRUST](../TRUST.md)).

## Decision

The unit of closure is a leaf attempt of a cube. An attempt is recorded as verified only
when cake_lpr exits 0 without a signal and its complete, untruncated standard output is
exactly `s VERIFIED UNSAT` and a line feed; where a relay carries the proof, the relay
must also report a complete transfer without error. CaDiCaL proposes proofs; its own
UNSAT answer is insufficient. Unit-propagation refutations use the same checker.

## Consequences

How a proof reaches the checker is a policy choice among three proof modes
([0011](0011-three-proof-modes.md)): the default `transient` mode seals a proof file,
checks it and deletes it, `stream` couples solver and checker through a relay, and
`retain` keeps the checked proof. Proofs are therefore not stored by default. A record
names the proof it accepted by its hash, and an audit recomputes the leaf and compares
([0013](0013-admission-and-guarantees.md)).
