"""Specification §12.1, §12.2: the command table, the parser and the generated reference agree.

The command line is data (``cubeproof.cli.spec``): the parser is built from it and
``docs/cubeproof/cli-reference.md`` is rendered from it. These tests regenerate the document and
compare it with the file in the repository, check that every row of the table is a parser
argument and vice versa, and that the exit-code table is specification §12.2 (the ``ExitCode``
values of the contracts layer).
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path

import pytest

from cubeproof.cli import spec
from cubeproof.cli.parser import build_parser, command_of
from cubeproof.cli.reference import render_reference
from cubeproof.contracts.enums import ExitCode

REPO = Path(__file__).resolve().parents[4]
REFERENCE = REPO / "docs" / "cubeproof" / "cli-reference.md"

#: Specification §12.1, transcribed: the commands of the synopsis and their first words.
SYNOPSIS = {
    ("bundle", "import"),
    ("campaign", "create"),
    ("shard",),
    ("run",),
    ("handoff",),
    ("status",),
    ("certify",),
    ("audit",),
    ("verify-retained",),
    ("journal", "verify"),
    ("journal", "repair"),
}


def test_the_reference_in_the_repository_is_the_generated_one() -> None:
    assert REFERENCE.read_text(encoding="utf-8") == render_reference(), (
        "docs/cubeproof/cli-reference.md is stale: run "
        "`python -m cubeproof.cli.reference > docs/cubeproof/cli-reference.md`"
    )


def test_the_reference_is_deterministic_and_plain() -> None:
    text = render_reference()
    assert text == render_reference()
    assert text.endswith("\n") and not text.endswith("\n\n")
    assert "\r" not in text and "\t" not in text
    assert all(not line.endswith(" ") for line in text.splitlines())
    assert "io-service" not in text  # the hidden command is not documented


def test_the_table_has_every_command_of_the_synopsis_and_the_additions() -> None:
    words = {c.words for c in spec.COMMANDS if not c.hidden}
    assert words >= SYNOPSIS
    assert words - SYNOPSIS == {("evidence", "package")}
    assert [c.words for c in spec.COMMANDS if c.hidden] == [("io-service",)]
    assert len({c.words for c in spec.COMMANDS}) == len(spec.COMMANDS)


def test_the_exit_code_table_is_specification_12_2() -> None:
    assert set(spec.EXIT_MEANING) == {int(c) for c in ExitCode}
    assert {int(c) for c in ExitCode} == {0, 1, 2, 3, 4, 5, 6, 130}
    for command in spec.COMMANDS:
        for code, meaning in command.exits:
            assert code in spec.EXIT_MEANING and meaning, (command.name, code)
        assert [code for code, _ in command.exits] == sorted(code for code, _ in command.exits)
    # the section of the reference lists exactly the documented codes
    section = render_reference().split("## Exit codes", 1)[1].split("##", 1)[0]
    assert set(map(int, re.findall(r"^\| (\d+) \|", section, re.MULTILINE))) == set(
        spec.EXIT_MEANING
    )


def _leaf(parser: argparse.ArgumentParser, words: tuple[str, ...]) -> argparse.ArgumentParser:
    current = parser
    for word in words:
        actions = [a for a in current._actions if isinstance(a, argparse._SubParsersAction)]
        assert len(actions) == 1
        current = actions[0].choices[word]
    return current


@pytest.mark.parametrize("command", spec.COMMANDS, ids=lambda c: c.name)
def test_every_row_of_the_table_is_a_parser_argument_and_nothing_else_is(
    command: spec.Command,
) -> None:
    leaf = _leaf(build_parser(hidden=command.hidden), command.words)
    parsed = {
        tuple(a.option_strings) or (a.dest,): a
        for a in leaf._actions
        if not isinstance(a, argparse._HelpAction)
    }
    declared = {arg.flags for arg in command.args}
    assert set(parsed) == declared
    for arg in command.args:
        action = parsed[arg.flags]
        assert action.required == (arg.required or arg.positional), arg.flags
        assert (action.choices is not None) == bool(arg.choices), arg.flags


def test_command_of_selects_the_table_row() -> None:
    parser = build_parser()
    args = parser.parse_args(["journal", "verify", "j", "--campaign", "c"])
    assert command_of(args).words == ("journal", "verify")
    assert command_of(parser.parse_args(["status", "--results", "r"])).words == ("status",)


def test_each_command_documents_what_it_prints_and_when_it_fails() -> None:
    for command in spec.COMMANDS:
        if command.hidden:
            continue
        assert command.summary and command.exits, command.name
        assert command.output or not command.available, command.name
    unavailable = {c.name for c in spec.COMMANDS if not c.available}
    assert unavailable == set()  # every command of the table is available


def test_the_contract_page_names_the_documents_and_commands_it_describes() -> None:
    page = (REPO / "docs" / "cubeproof" / "commands.md").read_text(encoding="utf-8")
    for name in (
        "cubeproof-roots-1",
        "cubeproof-prefixes-1",
        "cubeproof-weights-1",
        "cubeproof-shard-1",
        "cubeproof-evidence-1",
        "proof-prefix-v1",
        "cli-reference.md",
        "cubeproof-audit-report-1",
        "cubeproof-verify-retained-report-1",
    ):
        assert name in page, name
    for command in spec.COMMANDS:
        if not command.hidden:
            assert f"cubeproof {command.name}" in page or command.name in page, command.name
    assert (REPO / "docs" / "cubeproof" / "cli-reference.md").exists()


def test_every_command_of_the_table_has_a_handler_and_nothing_else_has() -> None:
    from cubeproof.cli.handlers import HANDLERS

    assert set(HANDLERS) == {command.words for command in spec.COMMANDS}
