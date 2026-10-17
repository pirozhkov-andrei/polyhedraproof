"""The ``argparse`` parser, built from the table of :mod:`cubeproof.cli.spec`.

A parse error is a usage error (exit code 3 of specification §12.2), not argparse's 2: the parser
raises :class:`~cubeproof.base.errors.ConfigurationError` ``usage`` and the boundary reports it.
``-h`` prints the help and ``--version`` prints ``cubeproof VERSION``; both end the parse
(argparse's own exit with status 0), and :func:`cubeproof.cli.main` turns that into a return
value.
"""

from __future__ import annotations

import argparse
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any, NoReturn

from cubeproof import __version__
from cubeproof.base.errors import ConfigurationError
from cubeproof.cli.spec import COMMANDS, Arg, Command

__all__ = ["build_parser", "command_of", "parse"]

PROGRAM = "cubeproof"
SERVICE = "io-service"

_TYPES: dict[str, Callable[[str], Any]] = {"path": Path, "int": int, "float": float, "str": str}


class _Parser(argparse.ArgumentParser):
    """Argument errors are configuration errors (exit code 3), not argparse's 2; option names
    are exact (no abbreviations)."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        kwargs.setdefault("allow_abbrev", False)
        super().__init__(*args, **kwargs)

    def error(self, message: str) -> NoReturn:
        raise ConfigurationError("usage", message)


def _add(parser: argparse.ArgumentParser, arg: Arg) -> None:
    options: dict[str, Any] = {"help": arg.help}
    if arg.kind == "flag":
        parser.add_argument(*arg.flags, action="store_true", **options)
        return
    options["type"] = _TYPES[arg.kind]
    if arg.choices:
        options["choices"] = arg.choices
    if arg.metavar is not None:
        options["metavar"] = arg.metavar
    if arg.positional:
        parser.add_argument(*arg.flags, **options)
        return
    options["required"] = arg.required
    if arg.repeat:
        options["action"] = "append"
        options["default"] = []
    elif arg.many:
        options["nargs"] = "+"
        options["action"] = "extend"  # --journals A B and --journals A --journals B agree
    if arg.default is not None:
        options["default"] = arg.default
    parser.add_argument(*arg.flags, **options)


def build_parser(*, hidden: bool = False) -> argparse.ArgumentParser:
    """The parser of the public commands of the table (``hidden``: of the internal ones only,
    which no help lists)."""
    parser = _Parser(prog=PROGRAM, description="cube-tree refutation campaigns")
    if not hidden:
        parser.add_argument("--version", action="version", version=f"{PROGRAM} {__version__}")
    commands = parser.add_subparsers(
        dest="command", required=True, parser_class=_Parser, metavar="COMMAND"
    )
    groups: dict[str, Any] = {}
    for command in COMMANDS:
        if command.hidden != hidden:
            continue
        head, *rest = command.words
        if not rest:
            leaf = commands.add_parser(head, help=command.summary, description=command.summary)
        else:
            if head not in groups:
                group = commands.add_parser(head, help=f"{head} commands")
                groups[head] = group.add_subparsers(
                    dest="action", required=True, parser_class=_Parser, metavar="ACTION"
                )
            leaf = groups[head].add_parser(
                rest[0], help=command.summary, description=command.summary
            )
        for arg in command.args:
            _add(leaf, arg)
    return parser


def parse(argv: Sequence[str]) -> argparse.Namespace:
    """Parse ``argv``; the internal service command is recognised by its first word."""
    return build_parser(hidden=bool(argv) and argv[0] == SERVICE).parse_args(list(argv))


def command_of(args: argparse.Namespace) -> Command:
    """The table entry a parsed namespace selected."""
    words = (
        (args.command,) if getattr(args, "action", None) is None else (args.command, args.action)
    )
    for command in COMMANDS:
        if command.words == words:
            return command
    raise ConfigurationError("usage", f"unknown command {' '.join(words)}")
