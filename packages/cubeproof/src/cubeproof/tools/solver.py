"""The pinned solver CaDiCaL: argv rules, command line and diagnostics (specification §4.4, §6.1,
§6.3).

Argv rules, checked by :func:`check_argv` before any solver run and when the machinery is
measured:

- campaign.argv: a list of strings containing the exact element ``--lrat``; every
  element starts with ``-`` (paths are supervisor inputs, never argv).
- writer.argv_deny_list (for the pinned CaDiCaL 3.0.1; its ``--help``
  is the source). Refused are options that

  * disable or change proof production: any ``--lrat`` form other than the exact element,
    ``frat``, ``idrup``, ``lidrup``, ``veripb`` (any value or ``--no-`` form);
  * set a competing termination limit: ``-t``, ``-c``, ``-d`` (with or without a value),
    ``conflicts``, ``decisions``, ``time``, ``seconds``, ``terminate``;
  * read or write other files: ``-o``, ``-e``, ``-w``, ``-r``;
  * suppress the witness needed for SAT models: ``-n``, ``--no-witness``, any
    ``--witness=`` value (the plain ``--witness`` is the default and allowed);
  * do not solve: ``-h``, ``--help``, ``--version``, ``--build``, ``--copyright``, ``-``
    (stdin input) and ``--`` (end of options).

  Single-dash options are an allow list: ``-q``, ``-v`` (repeatable as ``-vv``...),
  ``-L<n>``, ``-O<n>``, ``-P<n>``. Other long options (``--name``, ``--no-name``,
  ``--name=value``) are allowed; the solver itself rejects unknown ones (a protocol failure).
  Options embedded in DIMACS comments cannot occur (canonical DIMACS has no comments) and
  ``CADICAL_*`` environment options cannot reach the solver (tools get a fixed environment).

Command line: ``<argv...> <cnf> <proof>`` with absolute paths; a path whose suffix would
make CaDiCaL (de)compress through an external program is refused.

Diagnostics (specification §6.3): exit 10 SAT, exit 20 UNSAT; memory exhaustion only from the pinned
C++ runtime abort (SIGABRT with the ``std::bad_alloc`` message), never from a
signal alone; conflicts from the ``c conflicts:`` statistics line when present.
"""

from __future__ import annotations

import re
import signal
from collections.abc import Sequence

from cubeproof.base.errors import InputError, ToolError
from cubeproof.base.process import ProcessResult
from cubeproof.tools.isolation import PinnedBinary
from cubeproof.tools.process import Launch, Supervisor

SAT_EXIT = 10
UNSAT_EXIT = 20
#: The C++ runtime's message when CaDiCaL's allocation fails (then SIGABRT).
BAD_ALLOC_MESSAGE = "terminate called after throwing an instance of 'std::bad_alloc'"
REQUIRED_OPTION = "--lrat"

#: Long option names refused in every form (``--name``, ``--no-name``, ``--name=value``).
DENIED_NAMES = frozenset(
    {
        "lrat",
        "frat",
        "idrup",
        "lidrup",
        "veripb",
        "conflicts",
        "decisions",
        "time",
        "seconds",
        "terminate",
        "help",
        "version",
        "build",
        "copyright",
    }
)
_SHORT_ALLOWED = re.compile(r"-(?:q|v+|[LOP][0-9]+)")
_LONG = re.compile(r"--(no-)?([^=]+)(=.*)?", re.S)
_COMPRESSED = (".gz", ".bz2", ".xz", ".7z", ".lzma", ".zst", ".zip", ".z")
_CONFLICTS = re.compile(r"^c conflicts:\s+([0-9]+)", re.M)
_VERSION_TIMEOUT_MS = 30_000


def _denied(element: str) -> bool:
    if element == REQUIRED_OPTION:
        return False
    if element in ("-", "--"):
        return True
    if not element.startswith("--"):
        return _SHORT_ALLOWED.fullmatch(element) is None
    match = _LONG.fullmatch(element)
    if match is None:
        return True
    negated, name, value = match.group(1), match.group(2), match.group(3)
    if name in DENIED_NAMES:
        return True
    return name == "witness" and (negated is not None or value is not None)


def check_argv(argv: Sequence[str]) -> None:
    """campaign.argv, then the deny list; InputError naming the first offending element."""
    if isinstance(argv, str) or not isinstance(argv, Sequence):
        raise InputError("campaign.argv", f"{argv!r} is not a list of strings")
    for element in argv:
        if not isinstance(element, str) or not element.startswith("-"):
            raise InputError("campaign.argv", f"{element!r} is not an option element")
    if REQUIRED_OPTION not in argv:
        raise InputError("campaign.argv", "the exact element '--lrat' is missing")
    for element in argv:
        if _denied(element):
            raise InputError("writer.argv_deny_list", f"solver option {element!r} is refused")


def _solver_path(path: str) -> str:
    if not isinstance(path, str) or not path.startswith("/") or "\0" in path:
        raise ValueError(f"solver path {path!r} is not an absolute path")
    if path.lower().endswith(_COMPRESSED):
        raise ValueError(f"solver path {path!r} would be (de)compressed by the solver")
    return path


def solver_args(argv: Sequence[str], cnf: str, proof: str) -> tuple[str, ...]:
    """The solver arguments: the checked argv, then the CNF path and the proof path."""
    check_argv(argv)
    return (*argv, _solver_path(cnf), _solver_path(proof))


def parse_conflicts(stdout_tail: str) -> int | None:
    """The last ``c conflicts: N`` statistics value, or None."""
    found = _CONFLICTS.findall(stdout_tail)
    return int(found[-1]) if found else None


def allocation_failure(result: ProcessResult) -> bool:
    """The pinned solver's explicit allocation failure: SIGABRT with the bad_alloc message."""
    return (
        result.started
        and result.signal == signal.SIGABRT
        and BAD_ALLOC_MESSAGE in result.stderr_tail
    )


def probe_version(supervisor: Supervisor, binary: PinnedBinary, cwd: str) -> str:
    """``<solver> --version``: the first output line; ToolError unless a clean exit 0."""
    process = supervisor.start(
        Launch(
            binary=binary,
            args=("--version",),
            cwd=cwd,
            memory_bytes=1 << 30,
            file_bytes=1 << 20,
            deadline_ms=_VERSION_TIMEOUT_MS,
            term_grace_ms=1000,
            stdout_capture=4096,
        )
    )
    while process.run is None:
        supervisor.step(100)
    run = process.run
    lines = (run.stdout or b"").decode("utf-8", "replace").strip().splitlines()
    if run.causes or run.result.exit != 0 or not lines or not lines[0].strip():
        raise ToolError(
            "tool.version",
            f"{binary.path} --version: exit {run.result.exit}, signal {run.result.signal}, "
            f"causes {[c.value for c in run.causes]}, stdout {run.result.stdout_tail[:200]!r}",
        )
    return lines[0].strip()
