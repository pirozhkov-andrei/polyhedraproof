"""``proof-prefix-v1``: the proof-prefix partition algorithm (specification §9.2, decision 0012).

The algorithm is fixed, so that a recorded prefix can be recomputed and compared. Everything
that affects the result is part of its definition:

- sampling: the first variable is ranked from one bounded run at the root; every later layer
  samples ``samples`` cases of the prefix chosen so far, drawing one polarity per chosen
  variable from ``random.Random(seed).random() < 0.5`` (True: positive), in chosen order, for
  every sample, and no draw at all while nothing is chosen;
- the **heuristic scratch files**: the formula's header ``p cnf V M+u``, its clause body
  byte for byte, then the ``u`` sampled unit clauses *in chosen order* (not canonical order),
  solved with ``<options> -q -c <conflicts> --lrat --no-binary <cnf> <lrat>``. These files
  are not evidence CNFs: every leaf attempt of a campaign uses the canonical CNF bytes
  (specification §3.1);
- counting: the first ``steps`` clause-*addition* lines of the LRAT text file (deletions are
  skipped), every literal up to the first ``0`` of a line contributes its variable, variables
  already chosen are skipped;
- exclusion: a candidate must be in the pool and not excluded; the exclusion set starts with
  the variables assigned by unit propagation of the formula alone and grows, after each
  choice ``v``, by the variables propagation forces under ``v`` and under ``-v`` taken
  *separately* (single-literal exclusion: a variable forced by one polarity only is excluded
  too; a polarity that conflicts excludes ``v`` itself). Every chosen literal is propagated
  on its own;
- ties: the first variable with the highest count in the order the counter was filled
  (first occurrence in the first sample's proof, then later samples' new variables).

Defaults: samples 2, steps 100000, conflicts 90000, seed 5, pool ``order``. Running the
solver is the caller's operation: :func:`choose_prefix` takes a ``run_solver`` callable;
:func:`supervised_solver` builds one on the process supervisor. A solver that fails is a
:class:`~cubeproof.base.errors.ToolError` (an operational failure, never a verdict); the
selected prefix is recorded as a campaign root split with :func:`proof_prefix_splitter`.

A candidate variable above V (a solver extension variable) is ignored. The pinned solver with
these options adds none.
"""

from __future__ import annotations

import os
import random
from collections import Counter
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cubeproof.base.errors import ConfigurationError, ToolError
from cubeproof.cnf.dimacs import Formula
from cubeproof.cnf.unit import UnitIndex, build_index, propagate
from cubeproof.contracts.values import JsonObject, Node, Split, Splitter
from cubeproof.tools.isolation import PinnedBinary
from cubeproof.tools.process import Launch, Supervisor

PROOF_PREFIX_NAME = "proof-prefix-v1"
DEFAULT_SAMPLES = 2
DEFAULT_STEPS = 100_000
DEFAULT_CONFLICTS = 90_000
DEFAULT_SEED = 5
DEFAULT_POOL = "order"

#: A partition solver run is a heuristic, not evidence; it gets a generous but finite cap.
SOLVER_TIMEOUT_SECONDS = 3600
LRAT_CAP_BYTES = 256 << 20
SOLVER_MEMORY_BYTES = 2048 << 20
#: Accepted solver exit codes (unknown, satisfiable, unsatisfiable).
SOLVER_EXITS = (0, 10, 20)

#: ``(cnf_path, lrat_path, conflicts)``: run the partition solver once; raise ToolError on failure.
SolverRun = Callable[[Path, Path, int], None]
#: Reports a chosen variable: ``(position, variable, occurrences)``.
Progress = Callable[[int, int, int], None]


@dataclass(frozen=True)
class ProofPrefixParams:
    """The parameters of a proof-prefix-v1 run (the defaults of the algorithm)."""

    samples: int = DEFAULT_SAMPLES
    steps: int = DEFAULT_STEPS
    conflicts: int = DEFAULT_CONFLICTS
    seed: int = DEFAULT_SEED
    pool: str = DEFAULT_POOL
    solver_options: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        for name, value, minimum in (
            ("samples", self.samples, 1),
            ("steps", self.steps, 1),
            ("conflicts", self.conflicts, 1),
        ):
            if type(value) is not int or value < minimum:
                raise ConfigurationError(
                    "split.proof_prefix", f"{name} must be an integer >= {minimum}"
                )
        if type(self.seed) is not int:
            raise ConfigurationError("split.proof_prefix", "seed must be an integer")
        if not isinstance(self.pool, str) or not self.pool:
            raise ConfigurationError("split.proof_prefix", "pool must be a nonempty name")
        if not isinstance(self.solver_options, tuple) or not all(
            isinstance(o, str) and "\0" not in o for o in self.solver_options
        ):
            raise ConfigurationError(
                "split.proof_prefix", "solver_options must be a tuple of strings"
            )


@dataclass(frozen=True)
class ProofPrefix:
    """The chosen variables in order and the occurrence count that ranked each."""

    variables: tuple[int, ...]
    occurrences: tuple[int, ...]


def count_prefix(path: Path, steps: int, skip: set[int]) -> Counter[int]:
    """Variable occurrences in the first ``steps`` clause-ADDITION lines of an LRAT file."""
    occurrences: Counter[int] = Counter()
    seen = 0
    with open(path, "rb") as stream:
        for raw in stream:
            parts = raw.split()
            if len(parts) < 2 or parts[1] == b"d":  # a deletion is not a derivation
                continue
            seen += 1
            if seen > steps:
                break
            for token in parts[1:]:
                literal = int(token)
                if literal == 0:  # literals end, hints follow
                    break
                if abs(literal) not in skip:
                    occurrences[abs(literal)] += 1
    return occurrences


def scratch_bytes(formula: Formula, units: Sequence[int]) -> bytes:
    """The heuristic scratch file: header with ``M + len(units)``, the body, then the units.

    The units are written in the order given (the chosen order, with sampled signs), one
    ``<literal> 0`` line each.
    """
    header = f"p cnf {formula.variables} {formula.clauses + len(units)}\n".encode("ascii")
    tail = "".join(f"{literal} 0\n" for literal in units).encode("ascii")
    return header + formula.body + tail


def implied(index: UnitIndex, literals: Iterable[int]) -> set[int]:
    """Variables propagation forces once any ONE of ``literals`` is assumed (one-sided test).

    A literal whose propagation conflicts forces its own variable; otherwise every other
    variable on the trail is forced. Over-excluding costs nothing: there are thousands of
    candidates, and the alternative is spending partition depth on the partition's own
    consequences.
    """
    forced: set[int] = set()
    for literal in literals:
        propagation = propagate(index, (literal,))
        if propagation.conflict:
            forced.add(abs(literal))
            continue
        forced.update(abs(x) for x in propagation.trail if abs(x) != abs(literal))
    return forced


def choose_prefix(
    formula: Formula,
    count: int,
    pool: Iterable[int] | None,
    params: ProofPrefixParams,
    run_solver: SolverRun,
    workdir: Path,
    *,
    progress: Progress | None = None,
) -> ProofPrefix:
    """Choose up to ``count`` splitting variables in the order they were chosen.

    ``pool`` is the set of variables that may be chosen (None: every variable). Fewer than
    ``count`` variables are returned when no candidate is left. Scratch files live in
    ``workdir`` and are removed afterwards.
    """
    if type(count) is not int or count < 0:
        raise ConfigurationError("split.proof_prefix", "count must be an integer >= 0")
    allowed = None if pool is None else frozenset(pool)
    workdir.mkdir(parents=True, exist_ok=True)
    generator = random.Random(params.seed)
    pid = os.getpid()
    cnf = workdir / f"proof-prefix-{pid}.cnf"
    lrat = workdir / f"proof-prefix-{pid}.lrat"
    index = build_index(formula)
    excluded = {abs(literal) for literal in propagate(index, ()).trail}
    chosen: list[int] = []
    counts: list[int] = []
    try:
        for _ in range(count):
            occurrences: Counter[int] = Counter()
            # The first layer has no partition to sample from, so one prefix at the root
            # is all there is; every later layer samples `samples` cases of what is built.
            for _sample in range(params.samples if chosen else 1):
                units = [v if generator.random() < 0.5 else -v for v in chosen]
                cnf.write_bytes(scratch_bytes(formula, units))
                lrat.unlink(missing_ok=True)
                run_solver(cnf, lrat, params.conflicts)
                occurrences += count_prefix(lrat, params.steps, set(chosen))
            occurrences = Counter(
                {
                    variable: seen
                    for variable, seen in occurrences.items()
                    if (
                        1 <= variable <= formula.variables
                        if allowed is None
                        else variable in allowed
                    )
                    and variable not in excluded
                }
            )
            if not occurrences:
                break
            variable, seen = occurrences.most_common(1)[0]
            chosen.append(variable)
            counts.append(seen)
            excluded.update(implied(index, (variable, -variable)))
            if progress is not None:
                progress(len(chosen), variable, seen)
    finally:
        for path in (cnf, lrat):
            path.unlink(missing_ok=True)
    return ProofPrefix(tuple(chosen), tuple(counts))


def supervised_solver(
    supervisor: Supervisor,
    binary: PinnedBinary,
    params: ProofPrefixParams,
    cwd: Path,
    *,
    memory_bytes: int = SOLVER_MEMORY_BYTES,
    timeout_s: int = SOLVER_TIMEOUT_SECONDS,
    lrat_cap: int = LRAT_CAP_BYTES,
) -> SolverRun:
    """A :class:`SolverRun` that runs the pinned solver on the process supervisor.

    The command is ``<options> -q -c N --lrat --no-binary <cnf> <lrat>``. The run
    has a wall deadline and caps the LRAT file; exits other than 0/10/20, a signal, a cap, a
    deadline or a missing LRAT file raise ``ToolError`` ``split.proof_prefix_solver``.
    """
    directory = str(Path(cwd).resolve())

    def run(cnf: Path, lrat: Path, conflicts: int) -> None:
        args = (
            *params.solver_options,
            "-q",
            "-c",
            str(conflicts),
            "--lrat",
            "--no-binary",
            str(cnf),
            str(lrat),
        )
        process = supervisor.start(
            Launch(
                binary=binary,
                args=args,
                cwd=directory,
                memory_bytes=memory_bytes,
                file_bytes=lrat_cap + (64 << 20),
                deadline_ms=timeout_s * 1000,
                watch=(str(lrat), lrat_cap),
            )
        )
        while process.run is None:
            supervisor.step(100)
        outcome = process.run
        result = outcome.result
        if outcome.causes or result.exit not in SOLVER_EXITS or not lrat.is_file():
            causes = [c.value for c in outcome.causes]
            raise ToolError(
                "split.proof_prefix_solver",
                f"partition solver failed (exit {result.exit}, signal {result.signal}, "
                f"causes {causes}): {result.stderr_tail[-1000:]}",
            )

    return run


def proof_prefix_splitter(
    params: ProofPrefixParams,
    *,
    solver_sha256: str,
    occurrences: Sequence[int] = (),
    **provenance: Any,
) -> Splitter:
    """The ``splitter`` value recorded with the root split: parameters and tool provenance."""
    info: dict[str, Any] = {
        "algorithm": PROOF_PREFIX_NAME,
        "samples": params.samples,
        "steps": params.steps,
        "conflicts": params.conflicts,
        "seed": params.seed,
        "pool": params.pool,
        "rng": "python-random-below-0.5-positive",
        "solver": {"sha256": solver_sha256, "options": list(params.solver_options)},
        "occurrences": list(occurrences),
        **provenance,
    }
    return Splitter(PROOF_PREFIX_NAME, JsonObject.from_json(info))


def proof_prefix_root_split(
    formula_sha256: str,
    prefix: ProofPrefix,
    params: ProofPrefixParams,
    *,
    solver_sha256: str,
    **more: Any,
) -> Split:
    """The campaign root split (empty cube) for a chosen prefix, with its provenance."""
    splitter = proof_prefix_splitter(
        params, solver_sha256=solver_sha256, occurrences=prefix.occurrences, **more
    )
    return Split(Node(formula_sha256, ()), prefix.variables, splitter)
