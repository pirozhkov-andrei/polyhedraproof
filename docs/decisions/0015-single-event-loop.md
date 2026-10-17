# 0015. One coordinator event loop with supervised, bounded helper processes

## Context

A single loop has no shared-state races and makes ordering (reap, classify, commit, then
launch) explicit and replayable. A blocking fsync must not stall draining of child output,
timers or cancellation, so slow I/O lives in a separate process instead of threads. One
process for all I/O, rather than one per chunk or append, keeps the cost bounded and the
trust boundary small and nameable.

## Decision

Each worker has one coordinator running a single-threaded, nonblocking event loop. There
is no pool of workers per case. Solver, checker, splitter helper and stream relay are
subprocesses with explicit lifetimes (own process groups, parent-death signal, address
space and file size limits), reaped and classified by the loop.

Large hashing, copying, fsync and journal appends run in one long-lived supervised I/O
service process. It is the sole journal writer, works in chunks of at most 8 MiB, gives
journal commits priority between chunks and answers typed results tagged with job and
attempt IDs. It cannot construct a VERIFIED_UNSAT record: the coordinator supplies validated
record values. Unit propagation and native lookahead also run bounded or yield, so arbitrary
CNF cannot block the loop.

CPU, memory and disk are reserved through ledgers before any task starts; a task that does
not fit is not started.

## Consequences

- The I/O service is part of the binding and durability trust boundary and is reviewed as
  such; a failed service or a mismatched job or attempt ID stops new work, and replay
  resolves uncertain commits.
- The responsiveness requirement of the loop is an ordinary tick latency p99 of at most
  100 ms and an observed maximum of at most 1 s (SPECIFICATION §8.1); delays never
  authorize skipped checks or early records.
- Memory budgets account for child overheads and resident helper costs, because child
  address-space caps do not bound total physical memory.
