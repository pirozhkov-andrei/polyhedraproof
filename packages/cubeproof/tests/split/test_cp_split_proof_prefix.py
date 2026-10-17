"""proof-prefix-v1 against its recorded goldens (specification §9.2, decision 0012).

The algorithm is fixed: with the same solver output it must produce the same scratch bytes
(header, clause body, units in chosen order with the seeded signs), the same RNG consumption,
the same counting, exclusion and tie order. The solver is a deterministic fake (a function of
the scratch bytes), so every deviation from the definition shows up as a different choice or
scratch file.

The goldens are what the algorithm produces on exactly these inputs: the choices, the progress
lines, and the SHA-256 of the canonical JSON of the scratch files, counts and exclusions
(bytes by their SHA-256, sets sorted, pairs as lists).
"""

from __future__ import annotations

import hashlib
import json
import random
from collections import Counter
from collections.abc import Callable, Iterable, Iterator
from pathlib import Path
from typing import Any

import pytest
from cp_split_support import (
    fake_lrat,
    make_formula,
    read_log,
    write_fake_solver,
)

from cubeproof.base.errors import ConfigurationError, ContractError, ToolError
from cubeproof.cnf.dimacs import Formula
from cubeproof.cnf.unit import build_index
from cubeproof.split import proof_prefix as lp
from cubeproof.split.proof_prefix import (
    PROOF_PREFIX_NAME,
    ProofPrefixParams,
    choose_prefix,
    count_prefix,
    implied,
    proof_prefix_root_split,
    proof_prefix_splitter,
    scratch_bytes,
    supervised_solver,
)
from cubeproof.tools.isolation import Isolation, PinnedBinary
from cubeproof.tools.process import Supervisor

LrattFn = Callable[[bytes], bytes]

#: The goldens of the twelve random cases below: the chosen variables, the progress lines
#: ``(layer, variable, occurrences)`` and the scratch files.
PREFIX_CASES_GOLDEN: list[dict[str, Any]] = [
    {
        "variables": [2, 21, 10, 3, 7],
        "progress": [[1, 2, 1], [2, 21, 1], [3, 10, 2], [4, 3, 2], [5, 7, 1]],
        "scratch": "28f82c9b7084ff76048cdcdf971e0c1094e8e7dc15f39ed6bee07bd98be2d1b1",
    },
    {
        "variables": [8, 13, 10, 7],
        "progress": [[1, 8, 2], [2, 13, 2], [3, 10, 1], [4, 7, 1]],
        "scratch": "1c6ae17c103cf57a5eac1ca6ec6d1703b66af89a78e18ab7cb7a61f5505577d6",
    },
    {
        "variables": [14, 9, 19, 18, 11],
        "progress": [[1, 14, 3], [2, 9, 3], [3, 19, 3], [4, 18, 2], [5, 11, 3]],
        "scratch": "ed8b3d2f24765afedc9de6ab7795066a41b41dba07d3e8f1cd4a6f912291678c",
    },
    {
        "variables": [9, 18, 11, 7],
        "progress": [[1, 9, 2], [2, 18, 3], [3, 11, 2], [4, 7, 3]],
        "scratch": "a73db2a85c93613b831fca725a84310315d88205a968970a6273c8d771dcd989",
    },
    {
        "variables": [14, 8, 12, 22, 15, 21],
        "progress": [[1, 14, 2], [2, 8, 6], [3, 12, 2], [4, 22, 5], [5, 15, 3], [6, 21, 2]],
        "scratch": "3af983d600136834d42be33e58ba48a8d0184dcb2404af430488f2eca1e5444f",
    },
    {
        "variables": [10, 5, 9, 17],
        "progress": [[1, 10, 5], [2, 5, 4], [3, 9, 3], [4, 17, 2]],
        "scratch": "0dc7aea455988ca9d3a22082485973c09acf4622f4814853e5a09c4d4a3da4d0",
    },
    {
        "variables": [7, 14, 4],
        "progress": [[1, 7, 12], [2, 14, 27], [3, 4, 26]],
        "scratch": "dac9d1d350e45f8db8586a8fe80254ea40195e5095a4d3d077b1133bcd3051ef",
    },
    {
        "variables": [14, 11, 7, 10],
        "progress": [[1, 14, 2], [2, 11, 5], [3, 7, 6], [4, 10, 7]],
        "scratch": "1d4cd96c2bc92cffb457d24b7f80814a67513ba9e2ab537d3ea16fcdd09bedda",
    },
    {
        "variables": [7],
        "progress": [[1, 7, 5]],
        "scratch": "d1b6ba71487143f955076f7af180505cc0665d0a43a897a754a0d77d86533f98",
    },
    {
        "variables": [11, 7, 13, 10, 9],
        "progress": [[1, 11, 7], [2, 7, 18], [3, 13, 15], [4, 10, 15], [5, 9, 13]],
        "scratch": "963374a72496fbe1ec8acb2a6354ca16f020dc7e8fe829caf721c3484bf7ad7b",
    },
    {
        "variables": [5, 12, 6, 2, 13],
        "progress": [[1, 5, 4], [2, 12, 6], [3, 6, 12], [4, 2, 4], [5, 13, 7]],
        "scratch": "fdbd354af57c07c51febaac8590383a07423f61c5327f74ad9af46776fd8db2d",
    },
    {
        "variables": [15, 13, 22, 12, 6, 8, 3],
        "progress": [
            [1, 15, 7],
            [2, 13, 18],
            [3, 22, 13],
            [4, 12, 10],
            [5, 6, 12],
            [6, 8, 11],
            [7, 3, 13],
        ],
        "scratch": "054c39434d947d3cfb972872898a358f9c75bd4a34ae50df4e8f2a3c4b21b739",
    },
]
#: The scratch files of the 30 random formulas below.
SCRATCH_GOLDEN = "80fec158b0d873b635130c17cd0c182845b6bbe0236a80d447f218d26542fe2d"
#: The ``count_prefix`` items, in insertion order, of 25 random proofs x 3 step caps.
COUNTING_GOLDEN = "88c31f0600499c16f1c274417847458b21004ff4f47d782a0f4da68ad87bfb02"
#: ``implied`` of (v, -v) and (v,) for every variable of 25 formulas.
EXCLUSION_GOLDEN = "3d856accd30b9dea39e58e406bd4d6336f9be3037a1e86dabfa727bfba32ba48"
#: The choice when every candidate ties (the flat proof).
TIES_GOLDEN = [3, 9, 5, 6]
#: The choice and progress with the pool {2, 5, 6}.
POOL_GOLDEN: dict[str, Any] = {
    "variables": [5, 6, 2],
    "progress": [[1, 5, 13], [2, 6, 26], [3, 2, 18]],
}
#: The run through a real (fake-tool) solver process: choice, scratch files and argv.
SUPERVISED_GOLDEN: dict[str, Any] = {
    "variables": [9, 7, 4],
    "cnfs": 5,
    "cnfs_sha256": "ef33201a7579b3f9d29ad4a66e85dda2fbd49b7d776b58e96c93e73fc0243c73",
    "argv": ["--seed=1\n-q\n-c\n77\n--lrat\n--no-binary"] * 5,
}


def J(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def files_digest(files: Iterable[bytes]) -> str:
    """The frozen form of a list of byte strings: each by its SHA-256."""
    return sha(J([["bytes", sha(data)] for data in files]))


def set_form(values: set[int]) -> list[Any]:
    """The frozen form of a set of integers: sorted by their JSON text."""
    return ["set", sorted(values, key=str)]


def implication_formula(rng: random.Random, variables: int) -> Formula:
    """Binary implications with a few units and wider clauses: exclusion has work to do."""
    clauses = []
    for _ in range(rng.randint(variables // 2, variables * 2)):
        width = rng.choice([1, 2, 2, 2, 3, 3, 4])
        clauses.append([rng.choice([-1, 1]) * rng.randint(1, variables) for _ in range(width)])
    return make_formula(variables, clauses)


def random_lrat(data: bytes) -> bytes:
    return fake_lrat(data, "random")


def flat_lrat(data: bytes) -> bytes:
    return fake_lrat(data, "flat")


def ranked(order: list[int]) -> LrattFn:
    """A solver output that ranks the variables in ``order`` (one single-literal addition each)."""
    text = "".join(f"{100 + i} {v} 0 1 0\n" for i, v in enumerate(order)).encode()
    return lambda data: text


def new_run(lrat_fn: LrattFn) -> tuple[Callable[[Path, Path, int], None], list[bytes]]:
    seen: list[bytes] = []

    def run(cnf: Path, lrat: Path, conflicts: int) -> None:
        data = Path(cnf).read_bytes()
        seen.append(data)
        Path(lrat).write_bytes(lrat_fn(data))

    return run, seen


Progress = list[tuple[int, int, int]]


def choose(
    tmp_path: Path,
    formula: Formula,
    count: int,
    pool: set[int] | None,
    lrat_fn: LrattFn = random_lrat,
    **params: Any,
) -> tuple[lp.ProofPrefix, Progress, list[bytes]]:
    """proof_prefix on one input: choice, progress, scratch."""
    run, seen = new_run(lrat_fn)
    progress: Progress = []
    result = choose_prefix(
        formula,
        count,
        None if pool is None else sorted(pool),
        ProofPrefixParams(**params),
        run,
        tmp_path,
        progress=lambda *a: progress.append(a),
    )
    return result, progress, seen


def test_choices_scratch_bytes_and_progress_equal_the_goldens_on_random_formulas(
    tmp_path: Path,
) -> None:
    rng = random.Random(1717)
    long_prefixes = 0
    for case in range(12):
        formula = implication_formula(rng, rng.randint(10, 24))
        pool = None if rng.random() < 0.4 else set(rng.sample(range(1, formula.variables + 1), 8))
        params: dict[str, Any] = {
            "samples": rng.randint(1, 3),
            "steps": rng.choice([3, 10, 100_000]),
            "conflicts": rng.randint(1, 90_000),
            "seed": rng.randint(0, 100),
        }
        new, progress, seen = choose(
            tmp_path / str(case), formula, rng.randint(1, 7), pool, **params
        )
        expected = PREFIX_CASES_GOLDEN[case]
        assert list(new.variables) == expected["variables"], f"case {case}"
        assert [list(p) for p in progress] == expected["progress"]
        assert files_digest(seen) == expected["scratch"], "the scratch files differ"
        assert list(new.occurrences) == [count for _, _, count in progress]
        long_prefixes += len(new.variables) >= 3
    assert long_prefixes >= 6  # the comparison is not vacuous


def test_defaults_are_the_specified_defaults() -> None:
    params = ProofPrefixParams()
    assert (params.samples, params.steps, params.conflicts, params.seed, params.pool) == (
        2,
        100_000,
        90_000,
        5,
        "order",
    )
    assert PROOF_PREFIX_NAME == "proof-prefix-v1"


def test_the_seeded_signs_follow_the_python_random_stream(tmp_path: Path) -> None:
    formula = make_formula(8, [[1, 2, 3, 4, 5, 6, 7, 8]])
    run, seen = new_run(random_lrat)
    result = choose_prefix(formula, 3, None, ProofPrefixParams(seed=5), run, tmp_path)
    assert len(result.variables) == 3
    # 1 root file; then 2 samples with 1 chosen variable and 2 samples with 2 chosen
    assert len(seen) == 1 + 2 + 2
    generator = random.Random(5)
    first, second = result.variables[:1], result.variables[:2]
    for data, chosen in zip(seen, [(), first, first, second, second], strict=True):
        units = [v if generator.random() < 0.5 else -v for v in chosen]
        lines = data.decode().splitlines()
        assert lines[0] == f"p cnf 8 {1 + len(units)}"
        assert lines[1] == "1 2 3 4 5 6 7 8 0"
        assert lines[2:] == [f"{u} 0" for u in units]  # chosen order, not canonical order


def test_the_first_layer_draws_nothing_and_later_layers_sample(tmp_path: Path) -> None:
    formula = make_formula(5, [[1, 2, 3, 4, 5]])
    run, seen = new_run(random_lrat)
    choose_prefix(formula, 1, None, ProofPrefixParams(samples=4), run, tmp_path)
    assert len(seen) == 1  # no partition yet: one root run regardless of samples
    run2, seen2 = new_run(random_lrat)
    choose_prefix(formula, 2, None, ProofPrefixParams(samples=4), run2, tmp_path)
    assert len(seen2) == 1 + 4


def test_scratch_bytes_are_the_golden_dimacs_bytes() -> None:
    """The case-file layout: the clause count includes the units, which follow the body in
    chosen order; the bytes equal the recorded golden."""
    rng = random.Random(4)
    found = []
    for _ in range(30):
        variables = rng.randint(1, 12)
        clauses = [
            [rng.choice([-1, 1]) * rng.randint(1, variables) for _ in range(rng.randint(0, 4))]
            for _ in range(rng.randint(0, 9))
        ]
        formula = make_formula(variables, clauses)
        sample = rng.sample(range(1, variables + 1), min(variables, 3))
        units = [rng.choice([-1, 1]) * v for v in sample]
        data = scratch_bytes(formula, units)
        header = f"p cnf {variables} {formula.clauses + len(units)}\n".encode()
        body = formula.data.split(b"\n", 1)[1]
        assert data == header + body + b"".join(f"{u} 0\n".encode() for u in units)
        assert scratch_bytes(formula, []) == formula.data  # no units: the canonical bytes
        found.append(data)
    assert files_digest(found) == SCRATCH_GOLDEN


def test_counting_equals_the_goldens(tmp_path: Path) -> None:
    rng = random.Random(6)
    found = []
    for case in range(25):
        lines = []
        for i in range(rng.randint(0, 30)):
            kind = rng.random()
            if kind < 0.15:
                lines.append(f"{i + 9} d 1 2 0")
            elif kind < 0.2:
                lines.append("7")  # a stray short line is skipped
            else:
                width = rng.randint(0, 4)
                literals = " ".join(
                    str(rng.choice([-1, 1]) * rng.randint(1, 9)) for _ in range(width)
                )
                lines.append(f"{i + 9} {literals} 0 {rng.randint(1, 5)} {rng.randint(1, 5)} 0")
        path = tmp_path / f"{case}.lrat"
        path.write_text("\n".join(lines) + "\n")
        skip = set(rng.sample(range(1, 10), rng.randint(0, 3)))
        for steps in (1, 3, 100_000):
            # the insertion order decides ties, so the items are compared in order
            found.append([list(item) for item in count_prefix(path, steps, skip).items()])
    assert sha(J(found)) == COUNTING_GOLDEN


def test_a_hint_list_and_deletions_are_not_counted(tmp_path: Path) -> None:
    path = tmp_path / "x.lrat"
    path.write_text("10 3 -4 0 1 2 0\n11 d 3 4 0\n12 -3 0 5 6 0\n")
    assert count_prefix(path, 100, set()) == Counter({3: 2, 4: 1})
    assert count_prefix(path, 1, set()) == Counter({3: 1, 4: 1})  # steps count additions only
    assert count_prefix(path, 100, {3}) == Counter({4: 1})


def test_exclusion_equals_the_goldens_for_every_variable() -> None:
    rng = random.Random(21)
    found = []
    for _ in range(25):
        formula = implication_formula(rng, rng.randint(6, 16))
        index = build_index(formula)
        for v in range(1, formula.variables + 1):
            found.append([set_form(implied(index, (v, -v))), set_form(implied(index, (v,)))])
    assert sha(J(found)) == EXCLUSION_GOLDEN


# The expected choices of the next tests are recorded goldens of the same input.


def test_exclusion_is_single_literal(tmp_path: Path) -> None:
    # +1 forces 2 but -1 forces nothing: 2 is excluded after choosing 1 (one-sided exclusion)
    formula = make_formula(4, [[-1, 2]])
    new, *_ = choose(tmp_path, formula, 3, None, ranked([1, 2, 3, 4]))
    assert new.variables == (1, 3, 4)


def test_two_choices_together_exclude_nothing(tmp_path: Path) -> None:
    # 1 and 2 together force 3, but neither alone does: 3 stays a candidate of proof-prefix-v1
    formula = make_formula(4, [[-1, -2, 3]])
    new, *_ = choose(tmp_path, formula, 4, None, ranked([1, 2, 3, 4]))
    assert new.variables == (1, 2, 3, 4)


def test_root_propagation_excludes_assigned_variables(tmp_path: Path) -> None:
    formula = make_formula(5, [[2], [-2, 4]])
    new, *_ = choose(tmp_path, formula, 5, None, ranked([2, 4, 5, 3, 1]))
    assert new.variables == (5, 3, 1)


def test_a_conflicting_polarity_excludes_its_variable() -> None:
    # -2 would force 3 and -3 through (2 3) and (2 -3): the single-literal test excludes variable 2
    formula = make_formula(4, [[2, 3], [2, -3]])
    index = build_index(formula)
    assert implied(index, (2, -2)) == {2}


def test_ties_are_decided_by_counting_order_not_by_variable_number(tmp_path: Path) -> None:
    formula = make_formula(10, [[1, 2, 3, 4, 5, 6, 7, 8, 9, 10]])
    new, *_ = choose(tmp_path, formula, 4, None, flat_lrat)
    assert list(new.variables) == TIES_GOLDEN
    first_literal = int(fake_lrat(formula.data, "flat").splitlines()[0].split()[1])
    assert new.variables[0] == first_literal
    # every candidate ties in every layer (one root run, then two samples): only the order decides
    assert new.occurrences == (1, 2, 2, 2)


def test_pool_restricts_the_candidates_and_the_prefix_can_end_early(tmp_path: Path) -> None:
    formula = make_formula(8, [[1, 2, 3, 4, 5, 6, 7, 8]])
    new, progress, _ = choose(tmp_path, formula, 6, {2, 5, 6})
    assert list(new.variables) == POOL_GOLDEN["variables"] and len(new.variables) <= 3
    assert set(new.variables) <= {2, 5, 6}
    assert [list(p) for p in progress] == POOL_GOLDEN["progress"]


def test_an_empty_pool_gives_an_empty_prefix(tmp_path: Path) -> None:
    formula = make_formula(4, [[1, 2, 3, 4]])
    run, seen = new_run(random_lrat)
    result = choose_prefix(formula, 3, [], ProofPrefixParams(), run, tmp_path)
    assert result.variables == () and len(seen) == 1


def test_count_zero_runs_nothing(tmp_path: Path) -> None:
    run, seen = new_run(random_lrat)
    assert (
        choose_prefix(make_formula(2, []), 0, None, ProofPrefixParams(), run, tmp_path).variables
        == ()
    )
    assert seen == []


def test_scratch_files_are_removed_also_after_a_failure(tmp_path: Path) -> None:
    def failing(cnf: Path, lrat: Path, conflicts: int) -> None:
        raise ToolError("split.proof_prefix_solver", "boom")

    formula = make_formula(3, [[1, 2, 3]])
    with pytest.raises(ToolError):
        choose_prefix(formula, 2, None, ProofPrefixParams(), failing, tmp_path / "w")
    assert list((tmp_path / "w").iterdir()) == []
    run, _ = new_run(random_lrat)
    choose_prefix(formula, 2, None, ProofPrefixParams(), run, tmp_path / "w2")
    assert list((tmp_path / "w2").iterdir()) == []


def test_parameters_are_validated() -> None:
    for kwargs in (
        {"samples": 0},
        {"steps": 0},
        {"conflicts": 0},
        {"samples": 1.5},
        {"seed": 1.5},
        {"pool": ""},
        {"solver_options": ["-x"]},
        {"solver_options": ("a\0",)},
    ):
        with pytest.raises(ConfigurationError):
            ProofPrefixParams(**kwargs)
    with pytest.raises(ConfigurationError):
        choose_prefix(
            make_formula(2, []), -1, None, ProofPrefixParams(), lambda *a: None, Path("/tmp")
        )


def test_a_candidate_beyond_v_is_ignored(tmp_path: Path) -> None:
    formula = make_formula(3, [[1, 2, 3]])
    run, _ = new_run(ranked([9, 2, 1]))
    result = choose_prefix(formula, 2, None, ProofPrefixParams(), run, tmp_path)
    assert result.variables[0] == 2  # 9 would be an extension variable of the solver


# -- recording ----------------------------------------------------------------------------------


def test_the_splitter_record_carries_parameters_and_tool_provenance() -> None:
    params = ProofPrefixParams(solver_options=("--quiet",))
    splitter = proof_prefix_splitter(
        params, solver_sha256="cd" * 32, occurrences=[5, 4], version="3.0.1"
    )
    assert splitter.name == PROOF_PREFIX_NAME
    assert splitter.info.to_json() == {
        "algorithm": "proof-prefix-v1",
        "samples": 2,
        "steps": 100_000,
        "conflicts": 90_000,
        "seed": 5,
        "pool": "order",
        "rng": "python-random-below-0.5-positive",
        "solver": {"sha256": "cd" * 32, "options": ["--quiet"]},
        "occurrences": [5, 4],
        "version": "3.0.1",
    }


def test_the_root_split_is_a_campaign_split_at_the_empty_cube() -> None:
    prefix = lp.ProofPrefix((4, 2, 9), (7, 6, 5))
    split = proof_prefix_root_split("ab" * 32, prefix, ProofPrefixParams(), solver_sha256="cd" * 32)
    assert split.node.cube == () and split.variables == (4, 2, 9)
    assert split.splitter.info.to_json()["occurrences"] == [7, 6, 5]
    too_long = lp.ProofPrefix(tuple(range(1, 22)), (1,) * 21)
    with pytest.raises(ContractError) as error:
        proof_prefix_root_split("ab" * 32, too_long, ProofPrefixParams(), solver_sha256="cd" * 32)
    assert error.value.rule == "split.too_long"  # depth 22 is not one split (specification §3.2)


# -- the supervised solver (real processes, fake tool) -----------------------------------------


@pytest.fixture(scope="module")
def supervisor() -> Iterator[Supervisor]:
    sup = Supervisor(Isolation.probe())
    try:
        yield sup
    finally:
        sup.shutdown(grace_ms=200)


def test_supervised_command_line_and_scratch_equal_the_goldens_with_a_real_process(
    tmp_path: Path, supervisor: Supervisor
) -> None:
    formula = make_formula(9, [[1, 2, 3], [-1, 4], [5, 6, 7, 8, 9]])
    new_log = tmp_path / "new-log"
    new_solver = write_fake_solver(tmp_path / "new-solver", new_log)
    options = ("--seed=1",)
    params = ProofPrefixParams(steps=50, conflicts=77, seed=9, solver_options=options)
    binary = PinnedBinary.measure(str(new_solver))
    result = choose_prefix(
        formula,
        3,
        None,
        params,
        supervised_solver(supervisor, binary, params, tmp_path / "new"),
        tmp_path / "new",
    )
    assert list(result.variables) == SUPERVISED_GOLDEN["variables"]
    new_cnfs, new_argv = read_log(new_log)
    assert len(new_cnfs) == 1 + 2 + 2 == SUPERVISED_GOLDEN["cnfs"]
    assert files_digest(new_cnfs) == SUPERVISED_GOLDEN["cnfs_sha256"]
    assert new_argv == SUPERVISED_GOLDEN["argv"]
    assert new_argv[0].split("\n") == ["--seed=1", "-q", "-c", "77", "--lrat", "--no-binary"]


def shell_solver(tmp_path: Path, body: str) -> PinnedBinary:
    script = tmp_path / "solver"
    script.write_text(f"#!/bin/sh\n{body}\n")
    script.chmod(0o755)
    return PinnedBinary.measure(str(script))


LAST_ARGUMENT = '"$(eval echo \\${$#})"'  # the LRAT path, the solver's last argument


@pytest.mark.parametrize(
    ("body", "kwargs"),
    [
        ("exit 1", {}),
        (f"echo '9 1 0 1 0' > {LAST_ARGUMENT}; exit 1", {}),  # a proof file, but a bad exit
        ("exit 0", {}),  # exit 0 but no LRAT file
        ("kill -SEGV $$", {}),
        ("sleep 30", {"timeout_s": 1}),
        (f"head -c 3000000 /dev/zero > {LAST_ARGUMENT}; sleep 30", {"lrat_cap": 1 << 20}),
    ],
)
def test_a_failing_partition_solver_is_a_tool_error_not_a_verdict(
    tmp_path: Path, supervisor: Supervisor, body: str, kwargs: dict[str, Any]
) -> None:
    binary = shell_solver(tmp_path, body)
    run = supervised_solver(supervisor, binary, ProofPrefixParams(), tmp_path, **kwargs)
    cnf = tmp_path / "x.cnf"
    cnf.write_bytes(b"p cnf 1 0\n")
    with pytest.raises(ToolError) as error:
        run(cnf, tmp_path / "x.lrat", 10)
    assert error.value.rule == "split.proof_prefix_solver"


@pytest.mark.parametrize("code", [0, 10, 20])
def test_accepted_solver_exits_are_unknown_sat_and_unsat(
    tmp_path: Path, supervisor: Supervisor, code: int
) -> None:
    binary = shell_solver(tmp_path, f'echo "9 1 0 1 0" > {LAST_ARGUMENT}; exit {code}')
    run = supervised_solver(supervisor, binary, ProofPrefixParams(), tmp_path)
    cnf = tmp_path / "y.cnf"
    cnf.write_bytes(b"p cnf 1 0\n")
    lrat = tmp_path / "y.lrat"
    run(cnf, lrat, 10)
    assert lrat.read_text() == "9 1 0 1 0\n"
