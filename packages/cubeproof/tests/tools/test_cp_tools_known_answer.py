"""The known-answer control of the checker (``cubeproof.tools.known_answer``).

Oracles that do not come from the module under test: the four questions are judged by a brute
force over all assignments (is the formula satisfiable?) and by the independent test validator
``fakes.lrat_check`` (is the proof a refutation?); the fake checkers are scripted to accept
everything, reject everything, crash, or really check. The pinned cake_lpr answers the same
questions in ``test_cp_tools_image.py`` (image tier).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from cp_tools_support import fk, isolation_fixture, linux_only, make_binary, p, supervisor_fixture

from cubeproof.base.errors import ToolError
from cubeproof.tools.known_answer import CASES, check_checker
from cubeproof.tools.process import Supervisor
from fakes.cnf_model import brute_force_model, parse_dimacs
from fakes.lrat_check import check

__all__ = ["isolation_fixture", "supervisor_fixture"]

pytestmark = linux_only


def test_the_known_answers_are_the_true_ones() -> None:
    """Exactly one question has the answer yes, and every answer is the independent one."""
    assert [case.accept for case in CASES] == [True, False, False, False]
    for case in CASES:
        cnf = parse_dimacs(case.cnf)
        satisfiable = brute_force_model(cnf) is not None
        refutes = check(cnf, case.proof).verified
        assert refutes is case.accept, case.name
        assert not (satisfiable and refutes), case.name
    assert brute_force_model(parse_dimacs(CASES[1].cnf)) is not None


def test_a_checker_that_checks_passes_and_leaves_nothing(
    supervisor: Supervisor, tmp_path: Path
) -> None:
    tool, pinned = make_binary(tmp_path / "bin", "cake_lpr", p.checker_lrat())
    work = tmp_path / "work"
    work.mkdir()
    check_checker(supervisor, pinned, str(work))
    assert len(tool.calls()) == len(CASES)
    assert list(work.iterdir()) == []  # the inputs of the control are removed
    for call in tool.calls():  # the argument form of a leaf check: arenas, CNF, proof
        heap, stack, cnf, proof = call["argv"]
        assert heap.startswith("--CML_HEAP_SIZE=") and stack.startswith("--CML_STACK_SIZE=")
        assert cnf.startswith(str(work)) and proof.startswith(str(work))


@pytest.mark.parametrize(
    ("steps", "question", "what"),
    [
        (p.checker_accept(), CASES[1].name, "was ACCEPTED"),
        (p.checker_reject(), CASES[0].name, "was not accepted"),
        (p.checker_crash(), CASES[0].name, "was not accepted"),
        (p.checker_output(b"s VERIFIED UNSAT\nmore\n"), CASES[0].name, "was not accepted"),
    ],
    ids=["accepts everything", "rejects everything", "crashes", "loose success line"],
)
def test_a_wrong_checker_is_stopped(
    steps: list[dict[str, Any]],
    question: str,
    what: str,
    supervisor: Supervisor,
    tmp_path: Path,
) -> None:
    tool, pinned = make_binary(tmp_path / "bin", "cake_lpr", steps)
    work = tmp_path / "work"
    work.mkdir()
    with pytest.raises(ToolError) as caught:
        check_checker(supervisor, pinned, str(work))
    assert caught.value.rule == "tool.known_answer"
    assert question in caught.value.detail and what in caught.value.detail
    assert pinned.sha256 in caught.value.detail
    assert list(work.iterdir()) == []
    assert tool.calls()  # it was really asked


def test_a_checker_that_accepts_only_wrong_proofs_is_stopped_at_the_first_question(
    supervisor: Supervisor, tmp_path: Path
) -> None:
    """Rejecting the true refutation is as wrong as accepting a false one."""
    steps = [fk.case(p.checker_reject(), invocation=0)]
    tool, pinned = make_binary(tmp_path / "bin", "cake_lpr", p.checker_accept(), cases=steps)
    work = tmp_path / "work"
    work.mkdir()
    with pytest.raises(ToolError, match="was not accepted"):
        check_checker(supervisor, pinned, str(work))
    assert len(tool.calls()) == 1


def test_a_rejection_that_is_not_the_checker_s_clean_one_is_a_failure(
    supervisor: Supervisor, tmp_path: Path
) -> None:
    """cake_lpr rejects with exit 0 and no success line; a program that answers a wrong proof
    with another exit code did not say "rejected" in the checker's way and is not trusted."""
    cases = [fk.case(p.checker_lrat(), invocation=0)]  # the true refutation: really checked
    _, pinned = make_binary(tmp_path / "bin", "cake_lpr", p.checker_output(b"", 3), cases=cases)
    work = tmp_path / "work"
    work.mkdir()
    with pytest.raises(ToolError) as caught:
        check_checker(supervisor, pinned, str(work))
    assert CASES[1].name in caught.value.detail
    assert "was not rejected cleanly" in caught.value.detail and "exit 3" in caught.value.detail


def test_a_checker_that_does_not_answer_is_a_failure(
    supervisor: Supervisor, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("cubeproof.tools.known_answer._TIMEOUT_MS", 300)
    _, pinned = make_binary(tmp_path / "bin", "cake_lpr", [fk.sleep(30)])
    work = tmp_path / "work"
    work.mkdir()
    with pytest.raises(ToolError) as caught:
        check_checker(supervisor, pinned, str(work))
    assert "could not be asked" in caught.value.detail and CASES[0].name in caught.value.detail
