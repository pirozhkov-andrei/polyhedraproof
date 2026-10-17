"""The command line of the application (specification §13.3): the only place that reads the
arguments, prints and chooses the exit code.

::

    faces12-campaign formulas (-o DIR [--check] | --check) [--maps M]
    faces12-campaign campaign init --formulas DIR [--maps M | --root MAP:CASE ...]
                     --solver PATH --solver-argv JSON --checker PATH --author NAME
                     [--admit F] [--policy F] [--proof-mode M] [--prefix K] [--prefixes F]
                     [--unpinned-checker] -o campaign.json
    faces12-campaign campaign prefixes --campaign F -o FILE
    faces12-campaign run|shard|handoff|certify|audit|status ...   (cubeproof, unchanged)
    faces12-campaign claim --evidence MANIFEST --review REVIEW --article ARTICLE
                     [--accept-checker SHA256 ...]
    faces12-campaign model (--evidence MANIFEST | --campaign F --journals J...)
    faces12-campaign maps [-o FILE]
    faces12-campaign selftest [--maps M]
    faces12-campaign release bundle|verify|provenance|docs ...

Result documents go to standard output as one JSON line (the last line); statements and
notes precede it; errors are ``faces12-campaign: error [rule] detail`` on standard error.
"""

from __future__ import annotations

import argparse
import errno
import json
import sys
import time
import traceback
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any, Final

from cubeproof import cli as cubeproof_cli
from cubeproof.base.errors import CubeproofError
from cubeproof.coordinator.config import exit_code_of
from faces12_campaign import __version__, commands, release
from faces12_campaign.campaign import DEFAULT_PREFIX, DEFAULT_PROOF_MODE, PilotRoot
from faces12_campaign.claim import ClaimRefused
from faces12_campaign.formulas import parse_maps

__all__ = ["DELEGATED", "EXIT_CODES", "PROGRAM", "build_parser", "command_line", "main"]

PROGRAM: Final = "faces12-campaign"
#: Commands handed to ``cubeproof`` unchanged (specification §13.3: thin adapters).
DELEGATED: Final = ("run", "shard", "handoff", "certify", "audit", "status")
#: Specification §12.2 as the application uses it.
EXIT_CODES: Final = (
    (0, "success; `claim`: the unconditional article conclusion"),
    (1, "open work; `claim`: conditional support with outstanding obligations, or an OPEN "
        "certificate"),
    (2, "a valid model (`model`: unless INCONSISTENT); `claim` refused for MODEL_FOUND"),
    (3, "usage, configuration or input error"),
    (4, "integrity failure or inconsistency (`claim`, `model`: an INCONSISTENT certificate); "
        "a refused claim; a failed self-test or check"),
    (5, "missing or failing tool, retry exhaustion, I/O service failure"),
    (6, "`run`: an anomaly without a higher-priority condition"),
    (130, "interrupted by the user"),
)  # fmt: skip
_ACCESS = frozenset(
    {errno.EACCES, errno.EPERM, errno.ENOENT, errno.ENOTDIR, errno.EISDIR, errno.EROFS}
)

Handler = Callable[[argparse.Namespace], int]


def _note(text: str) -> None:
    print(text, file=sys.stderr)


def _emit(document: Any) -> None:
    print(json.dumps(document, sort_keys=True, ensure_ascii=False, separators=(",", ":")))


def _path(text: str) -> Path:
    return Path(text)


def _maps(text: str) -> tuple[int, ...]:
    try:
        return parse_maps(text)
    except CubeproofError as error:
        raise argparse.ArgumentTypeError(error.detail) from None


def _argv(text: str) -> tuple[str, ...]:
    try:
        value = json.loads(text)
    except ValueError:
        raise argparse.ArgumentTypeError("not JSON") from None
    if not isinstance(value, list) or not all(isinstance(x, str) for x in value):
        raise argparse.ArgumentTypeError("a JSON list of strings")
    return tuple(value)


def _pilot(text: str) -> PilotRoot:
    try:
        return PilotRoot.parse(text)
    except CubeproofError as error:
        raise argparse.ArgumentTypeError(error.detail) from None


# -- handlers ------------------------------------------------------------------------------------


def _formulas(args: argparse.Namespace) -> int:
    maps = None if args.maps is None else list(args.maps)
    report = commands.formulas(args.output, maps, check=args.check)
    _emit(report.to_json())
    return 0


def _campaign_init(args: argparse.Namespace) -> int:
    absolute = str(Path(args.solver).resolve()), str(Path(args.checker).resolve())
    result = commands.campaign_init(
        commands.InitCommand(
            formulas=args.formulas,
            output=args.output,
            solver=absolute[0],
            solver_argv=args.solver_argv,
            checker=absolute[1],
            author=args.author,
            maps=None if args.maps is None else list(args.maps),
            pilots=tuple(args.root or ()),
            admit=args.admit,
            policy=args.policy,
            proof_mode=args.proof_mode,
            prefix=args.prefix,
            prefixes=args.prefixes,
            unpinned_checker=args.unpinned_checker,
        )
    )
    _emit(result.to_json())
    return 0


def _campaign_prefixes(args: argparse.Namespace) -> int:
    document = commands.campaign_prefixes(args.campaign, args.output)
    _emit({"output": str(args.output), "splits": len(document["splits"])})
    return 0


def _claim(args: argparse.Namespace) -> int:
    result = commands.claim(
        args.evidence, args.review, args.article, accept_checkers=tuple(args.accept_checker or ())
    )
    print(result.statement())
    _emit(result.to_json())
    return result.exit_code


def _model(args: argparse.Namespace) -> int:
    result = commands.models(
        evidence=args.evidence, campaign=args.campaign, journals=tuple(args.journals or ())
    )
    for report in result.models:
        state = (
            "uninterpreted"
            if report.interpretation is None
            else (
                "satisfies its formula" if report.interpretation.satisfies else "violates clauses"
            )
        )
        _note(f"model of {report.key} at {report.record}: {state}")
    if result.verdict == "INCONSISTENT":
        _note(
            "the certificate is INCONSISTENT: a formula is both proved and modelled; the "
            "computation contradicts itself (integrity failure)"
        )
    _emit(result.to_json())
    # Specification §12.2: inconsistency (4) outranks a valid model (2)
    if result.verdict == "INCONSISTENT":
        return 4
    return 2 if result.models else 0


def _maps_command(args: argparse.Namespace) -> int:
    passed, document = commands.census()
    if args.output is not None:
        commands.write_document(args.output, document)
    _emit(document)
    return 0 if passed else 4


def _selftest(args: argparse.Namespace) -> int:
    checks = commands.selftest(list(args.maps))
    for check in checks:
        print(str(check))
    failed = [c for c in checks if not c.passed]
    print(f"  {len(checks) - len(failed)} of {len(checks)} checks hold")
    return 4 if failed else 0


def _release_bundle(args: argparse.Namespace) -> int:
    digest = release.build_bundle(args.root, args.output, args.author)
    print(f"{digest}  {args.output}")
    return 0


def _release_verify(args: argparse.Namespace) -> int:
    count = release.verify_bundle(args.directory)
    print(f"verified {count} bundled files")
    return 0


def _release_provenance(args: argparse.Namespace) -> int:
    document = release.provenance_document(
        recorded_ms=time.time_ns() // 1_000_000,
        root=args.root,
        solver=args.solver,
        checker=args.checker,
    )
    if args.output is not None:
        commands.write_document(args.output, document)
    _emit(document)
    return 0


def _release_docs(args: argparse.Namespace) -> int:
    cli = command_line()
    if args.check:
        problems = release.check(cli, args.root)
        for problem in problems:
            print(f"  {problem}")
        print(f"  {len(problems)} problem(s)" if problems else "  the documentation is consistent")
        return 4 if problems else 0
    for path in release.write(cli, args.root) or ["(every generated document is current)"]:
        print(f"  {path}")
    return 0


def _delegated(args: argparse.Namespace) -> int:  # pragma: no cover - main() delegates first
    return cubeproof_cli.main([args.command, *args.arguments])


# -- the parser ----------------------------------------------------------------------------------


def _parser(
    sub: Any, name: str, help_text: str, handler: Handler | None
) -> argparse.ArgumentParser:
    parser: argparse.ArgumentParser = sub.add_parser(
        name, help=help_text, description=help_text, allow_abbrev=False
    )
    if handler is not None:
        parser.set_defaults(handler=handler)
    return parser


def build_parser() -> argparse.ArgumentParser:
    """The argument parser of every command."""
    parser = argparse.ArgumentParser(
        prog=PROGRAM,
        description="The twelve-faces campaign on cubeproof and neighbourly.",
        allow_abbrev=False,
    )
    parser.add_argument("--version", action="version", version=f"{PROGRAM} {__version__}")
    sub = parser.add_subparsers(dest="command", required=True, metavar="COMMAND")

    p = _parser(
        sub, "formulas", "write or verify the bundles of the 59 published formulas", _formulas
    )
    p.add_argument("-o", "--output", type=_path, metavar="DIR", help="the bundles directory")
    p.add_argument("--maps", type=_maps, metavar="M", help="maps, e.g. 1,2,10-12 (default all)")
    p.add_argument(
        "--check",
        action="store_true",
        help="verify instead of writing: the bundles of DIR, or without -o the hashes",
    )

    group = _parser(sub, "campaign", "create a campaign of the published formulas", None)
    steps = group.add_subparsers(dest="step", required=True, metavar="STEP")
    p = _parser(
        steps, "init", "create the default, a restricted or a pilot campaign", _campaign_init
    )
    p.add_argument(
        "--formulas", type=_path, required=True, metavar="DIR", help="written by `formulas`"
    )
    p.add_argument("--maps", type=_maps, metavar="M", help="restrict to these maps (default all)")
    p.add_argument(
        "--root", type=_pilot, action="append", metavar="MAP:CASE",
        help="a pilot root: a case of the proof-prefix split `proof-prefix-v1` "
        "(repeatable)",
    )  # fmt: skip
    p.add_argument("--solver", required=True, metavar="PATH", help="the pinned solver binary")
    p.add_argument(
        "--solver-argv", type=_argv, required=True, metavar="JSON",
        help='solver options as a JSON list; the campaign of the 59 formulas uses ["-q", "--lrat"]',
    )  # fmt: skip
    p.add_argument("--checker", required=True, metavar="PATH", help="the pinned checker binary")
    p.add_argument(
        "--unpinned-checker", action="store_true",
        help="allow a checker that is not the cake_lpr binary of this release",
    )  # fmt: skip
    p.add_argument("--author", required=True, metavar="NAME", help="recorded in the campaign")
    p.add_argument("--admit", type=_path, metavar="FILE", help="admission (default: the checker)")
    p.add_argument("--policy", type=_path, metavar="FILE", help="a complete policy document")
    p.add_argument(
        "--proof-mode", default=DEFAULT_PROOF_MODE, choices=("transient", "retain", "stream"),
        help="proof mode of the default policy",
    )  # fmt: skip
    p.add_argument(
        "--prefix", type=int, default=DEFAULT_PREFIX, metavar="K",
        help="proof-prefix variables, 0 for none (fully dynamic)",
    )  # fmt: skip
    p.add_argument("--prefixes", type=_path, metavar="FILE", help="reuse stored prefixes")
    p.add_argument(
        "-o", "--output", type=_path, required=True, metavar="FILE", help="campaign.json"
    )
    p = _parser(
        steps, "prefixes", "export a campaign's stored prefixes for reuse", _campaign_prefixes
    )
    p.add_argument("--campaign", type=_path, required=True, metavar="FILE", help="a campaign")
    p.add_argument("-o", "--output", type=_path, required=True, metavar="FILE", help="new file")

    for name in DELEGATED:
        p = _parser(sub, name, f"hand the arguments to `cubeproof {name}`", _delegated)
        p.add_argument("arguments", nargs=argparse.REMAINDER, metavar="ARGS")

    p = _parser(
        sub, "claim", "the claim gate: recertify, check the publication and the review", _claim
    )
    p.add_argument(
        "--evidence", type=_path, required=True, metavar="MANIFEST", help="evidence.json"
    )
    p.add_argument("--review", type=_path, required=True, metavar="REVIEW", help="the review")
    p.add_argument("--article", type=_path, required=True, metavar="ARTICLE", help="the article")
    p.add_argument(
        "--accept-checker", action="append", metavar="SHA256",
        help="accept an admitted checker that is not the cake_lpr binary of this release "
        "(repeatable)",
    )  # fmt: skip

    p = _parser(sub, "model", "describe the models of a recomputed certificate", _model)
    p.add_argument("--evidence", type=_path, metavar="MANIFEST", help="an evidence directory")
    p.add_argument("--campaign", type=_path, metavar="FILE", help="a campaign file")
    p.add_argument(
        "--journals", type=_path, nargs="+", action="extend", metavar="JOURNAL", help="journals"
    )

    p = _parser(sub, "maps", "the census of the maps with twelve faces (minutes)", _maps_command)
    p.add_argument("-o", "--output", type=_path, metavar="FILE", help="write the census here")

    p = _parser(sub, "selftest", "identities, corpus and base formula checks", _selftest)
    p.add_argument("--maps", type=_maps, default="1", metavar="M", help="maps to check")

    group = _parser(sub, "release", "source archive, provenance and generated documents", None)
    steps = group.add_subparsers(dest="step", required=True, metavar="STEP")
    p = _parser(steps, "bundle", "build the deterministic source archive", _release_bundle)
    p.add_argument("--output", type=_path, required=True, metavar="FILE", help="the new archive")
    p.add_argument("--author", default="", help="recorded in the archive manifest")
    p.add_argument("--root", type=_path, default=Path("."), metavar="DIR", help="source root")
    p = _parser(steps, "verify", "check an unpacked archive against its manifest", _release_verify)
    p.add_argument("--directory", type=_path, required=True, metavar="DIR", help="unpacked")
    p = _parser(steps, "provenance", "record what this installation is", _release_provenance)
    p.add_argument("--output", type=_path, metavar="FILE", help="also write it here")
    p.add_argument("--root", type=_path, metavar="DIR", help="a source root to hash")
    p.add_argument("--solver", type=_path, metavar="PATH", help="the solver binary to hash")
    p.add_argument("--checker", type=_path, metavar="PATH", help="the checker binary to hash")
    p = _parser(steps, "docs", "regenerate the generated reference, or check it", _release_docs)
    p.add_argument("--check", action="store_true", help="change nothing; exit 4 on a problem")
    p.add_argument("--root", type=_path, default=Path("."), metavar="DIR", help="source root")
    return parser


def command_line() -> release.CommandLine:
    """The parser and exit codes, as the reference generator needs them."""
    return release.CommandLine(build_parser(), EXIT_CODES, DELEGATED)


def _validate(args: argparse.Namespace) -> str | None:
    if args.command == "model":
        if (args.evidence is None) == (args.campaign is None):
            return "give --evidence or --campaign with --journals"
        if args.campaign is not None and not args.journals:
            return "--campaign needs --journals"
        if args.evidence is not None and args.journals:
            return "--evidence is the exclusive alternative to --campaign/--journals"
    if args.command == "formulas" and args.output is None and not args.check:
        return "formulas needs -o DIR, or --check"
    return None


def main(argv: Sequence[str] | None = None) -> int:  # noqa: PLR0911 - one return per outcome
    """Run a command; the return value is the process exit code (specification §12.2)."""
    words = list(sys.argv[1:] if argv is None else argv)
    if words and words[0] in DELEGATED:
        return cubeproof_cli.main(words)
    try:
        args = build_parser().parse_args(words)
        problem = _validate(args)
        if problem is not None:
            _note(f"{PROGRAM}: error [usage] {problem}")
            return 3
        handler: Handler = args.handler
        return handler(args)
    except SystemExit as stop:  # argparse: usage error (2 -> 3) or -h/--version (0)
        code = stop.code if isinstance(stop.code, int) else 0
        return 3 if code else 0
    except ClaimRefused as error:
        _note(f"{PROGRAM}: claim refused [{error.rule}] {error.detail}")
        return error.exit_code
    except CubeproofError as error:
        location = f" ({error.location})" if error.location else ""
        _note(f"{PROGRAM}: error [{error.rule}] {error.detail}{location}")
        return exit_code_of(error)
    except KeyboardInterrupt:
        _note(f"{PROGRAM}: interrupted")
        return 130
    except OSError as error:
        where = f"{error.filename}: " if error.filename else ""
        _note(f"{PROGRAM}: error [io.error] {where}{error.strerror or error}")
        return 3 if error.errno in _ACCESS else 5
    except Exception:
        _note(f"{PROGRAM}: internal error")
        _note(traceback.format_exc().rstrip())
        return 4
