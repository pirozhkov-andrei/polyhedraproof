"""The command line (specification §12.1, §12.2): the only place that reads the arguments and
prints.

The commands and their arguments are the table of :mod:`cubeproof.cli.spec` (the generated
reference ``docs/cubeproof/cli-reference.md`` is rendered from it)::

    cubeproof bundle import INPUT.cnf -o BUNDLE
    cubeproof campaign create --bundle B... --policy P --admit A --solver PATH --solver-argv JSON
                              --checker PATH [--roots F] [--root-split SPEC] -o campaign.json
    cubeproof shard (--campaign F | --evidence M) --machines N [--formula KEY ...] [--weights F]
                    [--from-open CERT --journals J... [--scope S]] -o DIR
    cubeproof run (--campaign F | --evidence M) --results D --work D --worker NAME ...
    cubeproof handoff / status / certify / evidence package / journal verify|repair

Result documents go to standard output, notes and the run log to standard error. Every error is
reported as ``cubeproof: error [rule] detail`` on standard error and mapped to an exit code of
specification §12.2: usage, configuration and lock conflicts 3, integrity 4, tools and the I/O
service 5, a resource block 1, an interruption 130. The hidden command ``io-service`` is the I/O
service process of a run (its standard input and output are the job protocol): it must print nothing
else.
"""

from __future__ import annotations

import errno
import sys
import traceback
from collections.abc import Sequence

from cubeproof.base.errors import CubeproofError
from cubeproof.cli.handlers import HANDLERS, report_note
from cubeproof.cli.parser import command_of, parse
from cubeproof.contracts.enums import ExitCode
from cubeproof.coordinator.config import exit_code_of

__all__ = ["main"]

_ACCESS = frozenset(
    {errno.EACCES, errno.EPERM, errno.ENOENT, errno.ENOTDIR, errno.EISDIR, errno.EROFS}
)


def _report(error: CubeproofError) -> int:
    detail = f" {error.detail}" if error.detail else ""
    location = f" ({error.location})" if error.location else ""
    report_note(f"cubeproof: error [{error.rule}]{detail}{location}")
    return exit_code_of(error)


def main(argv: Sequence[str] | None = None) -> int:
    """Run a command; the return value is the process exit code (specification §12.2)."""
    try:
        args = parse(sys.argv[1:] if argv is None else list(argv))
        return HANDLERS[command_of(args).words](args)
    except SystemExit as stop:  # argparse: -h printed the help
        return stop.code if isinstance(stop.code, int) else int(ExitCode.SUCCESS)
    except CubeproofError as error:
        return _report(error)
    except KeyboardInterrupt:
        report_note("cubeproof: interrupted")
        return int(ExitCode.INTERRUPTED)
    except OSError as error:
        where = f"{error.filename}: " if error.filename else ""
        report_note(f"cubeproof: error [io.error] {where}{error.strerror or error}")
        return int(ExitCode.USAGE if error.errno in _ACCESS else ExitCode.TOOL)
    except Exception:
        report_note("cubeproof: internal error")
        report_note(traceback.format_exc().rstrip())
        return int(ExitCode.INTEGRITY)
