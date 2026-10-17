"""Solver argv rules, command line and pinned CaDiCaL diagnostics (specification §4.4, §6.1, §6.3).

campaign.argv: the exact element ``--lrat`` and only option elements.
writer.argv_deny_list: options of the pinned CaDiCaL 3.0.1 that disable or
change proof production, set a competing termination limit, read or write other files,
turn off the witness or do not solve are refused. Single-dash options are an allow list.
Specification §6.3: solver memory exhaustion is recognized only from the pinned bad_alloc abort.
"""

from __future__ import annotations

import signal

import pytest
from cp_tools_support import p, result

from cubeproof.base.errors import InputError
from cubeproof.tools import solver as sv

ALLOWED = [
    ["--lrat"],
    ["--lrat", "--no-binary"],
    ["-q", "--lrat"],
    ["--lrat", "--binary=false"],
    ["--lrat", "--binary"],
    ["--lrat", "--elim=false", "--seed=7", "--unsat", "--plain"],
    ["--lrat", "-v", "-vv", "--verbose=2", "--stats", "--report=true"],
    ["--lrat", "-L5", "-O2", "-P1", "--checkproof=0", "--witness", "--colors"],
]

DENIED = [
    # proof production disabled or changed
    ["--lrat", "--no-lrat"],
    ["--lrat", "--lrat=false"],
    ["--lrat", "--lrat=0"],
    ["--lrat", "--lrat=true"],
    ["--lrat", "--frat=1"],
    ["--lrat", "--frat"],
    ["--lrat", "--idrup"],
    ["--lrat", "--lidrup=1"],
    ["--lrat", "--veripb=2"],
    ["--lrat", "--no-idrup"],
    # competing termination limits
    ["--lrat", "-t"],
    ["--lrat", "-t10"],
    ["--lrat", "-c"],
    ["--lrat", "-c1000"],
    ["--lrat", "-d"],
    ["--lrat", "--conflicts=10"],
    ["--lrat", "--decisions=10"],
    ["--lrat", "--time=10"],
    ["--lrat", "--seconds=10"],
    # other files
    ["--lrat", "-o"],
    ["--lrat", "-e"],
    ["--lrat", "-w"],
    ["--lrat", "-r"],
    # no witness
    ["--lrat", "-n"],
    ["--lrat", "--no-witness"],
    ["--lrat", "--witness=false"],
    ["--lrat", "--witness=0"],
    # not solving
    ["--lrat", "-h"],
    ["--lrat", "--help"],
    ["--lrat", "--version"],
    ["--lrat", "--build"],
    ["--lrat", "--copyright"],
    ["--lrat", "-"],
    ["--lrat", "--"],
    # unknown single-dash options
    ["--lrat", "-f"],
    ["--lrat", "-x"],
    ["--lrat", "-qv"],
    ["--lrat", "-L"],
]


@pytest.mark.parametrize("argv", ALLOWED, ids=repr)
def test_allowed_argv(argv: list[str]) -> None:
    sv.check_argv(argv)


@pytest.mark.parametrize("argv", DENIED, ids=repr)
def test_denied_argv(argv: list[str]) -> None:
    with pytest.raises(InputError) as caught:
        sv.check_argv(argv)
    assert caught.value.rule == "writer.argv_deny_list"
    assert argv[-1] in caught.value.detail


@pytest.mark.parametrize(
    "argv",
    [[], ["-q"], ["--LRAT"], ["--lrat", "file.cnf"], ["--lrat", ""], ["--lrat", 3], "--lrat"],
    ids=repr,
)
def test_campaign_argv_rules(argv: object) -> None:
    with pytest.raises(InputError) as caught:
        sv.check_argv(argv)  # type: ignore[arg-type]
    assert caught.value.rule == "campaign.argv"


def test_solver_arguments_put_the_paths_last() -> None:
    assert sv.solver_args(["--lrat", "-q"], "/w/n.cnf", "/w/n.lrat") == (
        "--lrat",
        "-q",
        "/w/n.cnf",
        "/w/n.lrat",
    )


@pytest.mark.parametrize(
    ("cnf", "proof"),
    [
        ("n.cnf", "/w/n.lrat"),
        ("/w/n.cnf", "-"),
        ("/w/n.cnf.gz", "/w/n.lrat"),
        ("/w/n.cnf", "/w/n.lrat.xz"),
        ("/w/n.cnf", "/w/n.lrat.bz2"),
        ("/w/n.cnf", "/w/n.LRAT.7Z"),
        ("/w/n.cnf", "/w/n.lrat.zst"),
        ("/w/n\0.cnf", "/w/n.lrat"),
    ],
)
def test_solver_paths_are_absolute_and_never_compressed(cnf: str, proof: str) -> None:
    with pytest.raises(ValueError):
        sv.solver_args(["--lrat"], cnf, proof)


def test_solver_arguments_check_the_argv() -> None:
    with pytest.raises(InputError):
        sv.solver_args(["--lrat", "-t"], "/w/n.cnf", "/w/n.lrat")


@pytest.mark.parametrize(
    ("tail", "expected"),
    [
        ("c conflicts:                 12345        4.56    per second\n", 12345),
        ("c conflicts: 1\nc conflicts: 2\n", 2),
        ("s UNSATISFIABLE\n", None),
        ("", None),
        ("c conflicts: many\n", None),
        ("x c conflicts: 5\n", None),
    ],
)
def test_conflicts_are_read_from_the_statistics(tail: str, expected: int | None) -> None:
    assert sv.parse_conflicts(tail) == expected


def test_only_the_pinned_bad_alloc_abort_is_solver_memory() -> None:
    message = p.CADICAL_BAD_ALLOC_STDERR.decode()
    assert sv.allocation_failure(result(exit=None, signal=signal.SIGABRT, stderr=message))
    # the same signal without the message, the message with another end: not memory
    assert not sv.allocation_failure(result(exit=None, signal=signal.SIGABRT))
    assert not sv.allocation_failure(result(exit=None, signal=signal.SIGKILL, stderr=message))
    assert not sv.allocation_failure(result(exit=None, signal=signal.SIGSEGV, stderr=message))
    assert not sv.allocation_failure(result(exit=1, stderr=message))
    assert not sv.allocation_failure(result(exit=None, signal=signal.SIGABRT, stderr="bad_alloc"))


def test_exit_codes() -> None:
    assert (sv.SAT_EXIT, sv.UNSAT_EXIT) == (p.SOLVER_SAT, p.SOLVER_UNSAT) == (10, 20)
