"""The command line as data (specification §12.1, §12.2): one table builds the parser and the
reference.

``COMMANDS`` lists every command with its arguments, what it prints and the exit codes it uses.
:mod:`cubeproof.cli.parser` builds the ``argparse`` parser from it and
:mod:`cubeproof.cli.reference` renders ``docs/cubeproof/cli-reference.md`` from it, so the
generated reference cannot drift from the parser (a test regenerates and compares it). Rules that
involve several arguments (exclusive alternatives, required combinations) are stated in each
command's ``rules`` and enforced in :mod:`cubeproof.cli.handlers`.

``audit`` and ``verify-retained`` (specification §11, §12.1) add the arguments of their execution
environment to the synopsis, as ``run`` does: the work directory, the local tool paths and the
resource budgets. ``available=False`` marks a command a build specifies but does not implement
(it then reports ``command.unavailable``, exit 3); every command of this build is available.
"""

from __future__ import annotations

from dataclasses import dataclass

__all__ = ["COMMANDS", "EXIT_MEANING", "Arg", "Command", "find"]


@dataclass(frozen=True)
class Arg:
    """One argument. Positional when the first flag does not start with ``-``."""

    flags: tuple[str, ...]
    help: str
    #: "path", "int", "float", "str" or "flag" (a boolean switch)
    kind: str = "str"
    required: bool = False
    repeat: bool = False  # --x A --x B (append)
    many: bool = False  # --x A B C (one or more values)
    choices: tuple[str, ...] = ()
    default: str | int | float | None = None
    metavar: str | None = None

    @property
    def positional(self) -> bool:
        return not self.flags[0].startswith("-")

    @property
    def name(self) -> str:
        return self.flags[-1].lstrip("-").replace("-", "_")


@dataclass(frozen=True)
class Command:
    """A command: its words (``("campaign", "create")``), arguments, output and exit codes."""

    words: tuple[str, ...]
    summary: str
    args: tuple[Arg, ...] = ()
    #: what standard output carries
    output: str = ""
    #: the exit codes this command uses (subset of :data:`EXIT_MEANING`) and what they mean here
    exits: tuple[tuple[int, str], ...] = ()
    #: rules over several arguments, enforced at the boundary (exit code 3 when violated)
    rules: tuple[str, ...] = ()
    available: bool = True
    hidden: bool = False

    @property
    def name(self) -> str:
        return " ".join(self.words)


#: The meaning of every exit code (specification §12.2).
EXIT_MEANING: dict[int, str] = {
    0: "success: run: all still-owned requested regions closed, no model, anomaly or block; "
    "certify: PROVED; audit: all selected strict matches; other commands: completed",
    1: "open work, resource block or time allocation ended; certify OPEN; audit incomplete, "
    "not comparable or reproved only; a pending handoff after its wait",
    2: "a valid model was found; certify MODEL_FOUND",
    3: "usage, configuration or lock conflict (including a request the inputs cannot satisfy)",
    4: "integrity failure, inconsistency or strict audit mismatch",
    5: "missing or failing tool, retry exhaustion or I/O service failure",
    6: "the run recorded an anomaly (without a higher-priority condition)",
    130: "explicit user signal interruption, after clean handling",
}

_JOURNALS = Arg(("--journals",), "journal files to use (explicit; no search)", "path", many=True)
_CAMPAIGN = Arg(("--campaign",), "the campaign file", "path")
_EVIDENCE = Arg(
    ("--evidence",),
    "an evidence manifest (portable directory): the exclusive alternative to the "
    "campaign/journal path arguments",
    "path",
    metavar="MANIFEST",
)

COMMANDS: tuple[Command, ...] = (
    Command(
        ("bundle", "import"),
        "normalize external DIMACS into an immutable bundle",
        (
            Arg(("input",), "the external DIMACS file", "path", metavar="INPUT.cnf"),
            Arg(("-o", "--output"), "the new bundle directory (must not exist)", "path", True),
        ),
        "the bundle document (path, formula_sha256, variables, clauses, source_sha256) as JSON",
        ((0, "the bundle was published"), (3, "usage, unreadable input or existing target")),
    ),
    Command(
        ("campaign", "create"),
        "create a campaign file from bundles, a policy and admission lists",
        (
            Arg(
                ("--bundle",), "a bundle directory below the campaign directory", "path", True, True
            ),
            Arg(("--policy",), "the policy file (a complete policy object)", "path", True),
            Arg(("--admit",), "the admission file {checker_sha256, solvers}", "path", True),
            Arg(("--solver",), "the local path of the pinned solver", "str", True),
            Arg(
                ("--solver-argv",),
                "JSON list of the solver's options (no executable, no paths)",
                "str",
                True,
                metavar="JSON",
            ),
            Arg(("--checker",), "the local path of the pinned checker", "str", True),
            Arg(
                ("--roots",),
                "a cubeproof-roots-1 file (default: the empty cube per formula)",
                "path",
            ),
            Arg(
                ("--root-split",),
                "none, static:FILE (a cubeproof-prefixes-1 file) or proof-prefix-v1:K",
                "str",
                default="none",
                metavar="SPEC",
            ),
            Arg(("--author",), "the author recorded in the campaign", "str", default="cubeproof"),
            Arg(("-o", "--output"), "the campaign file (must not exist)", "path", True),
        ),
        "one line: the campaign ID and the file",
        (
            (0, "the campaign was published"),
            (3, "usage or invalid input"),
            (5, "a tool is unusable"),
        ),
        (
            "the campaign file is published beside its bundles (their paths stay inside its "
            "directory)",
            "the tools' hashes are measured from the given local paths and recorded",
        ),
    ),
    Command(
        ("shard",),
        "plan shards of the work for independent machines",
        (
            _CAMPAIGN,
            _EVIDENCE,
            Arg(("--machines",), "number of machines", "int", True),
            Arg(
                ("--formula",),
                "plan only the nodes of this formula of the campaign (default: all formulas)",
                "str",
                metavar="KEY",
                repeat=True,
            ),
            Arg(("--weights",), "a cubeproof-weights-1 file (cost per planned node ID)", "path"),
            Arg(
                ("--from-open",),
                "plan the open frontier of this certificate (recomputed from the journals)",
                "path",
                metavar="CERT",
            ),
            _JOURNALS,
            Arg(
                ("--scope",),
                "the frontier to plan: campaign (certificate.open) or formulas (formula_open)",
                "str",
                choices=("campaign", "formulas"),
            ),
            Arg(
                ("-o", "--output"),
                "the output directory for the `shard-K.json` files",
                "path",
                True,
            ),
        ),
        "the plan (shards, node counts, costs, hashes, empty machines, the formulas of "
        "--formula) as JSON",
        ((0, "the shards were written"), (3, "usage or invalid input"), (4, "integrity failure")),
        (
            "exactly one of --campaign and --evidence",
            "--from-open needs --journals and --campaign; --journals and --scope belong to a "
            "frontier plan",
            "--evidence plans the frontier of the manifest's certificate, recomputed from its "
            "journals",
            "a frontier containing a model node is refused, and so is a certificate that does "
            "not match its journals",
        ),
    ),
    Command(
        ("run",),
        "run one worker",
        (
            _CAMPAIGN,
            _EVIDENCE,
            Arg(("--results",), "the worker's results directory", "path", True),
            Arg(("--work",), "the worker's disposable work directory", "path", True),
            Arg(("--worker",), "the worker name (a-z, 0-9, _ and -)", "str", True),
            Arg(("--solver",), "the local path of the pinned solver", "str", True),
            Arg(("--checker",), "the local path of the pinned checker", "str", True),
            Arg(("--helper",), "the local path of the splitter helper (optional)", "str"),
            Arg(("--shard",), "a cubeproof-shard-1 file to own (first use or later)", "path"),
            Arg(("--jobs",), "CPU slots", "int"),
            Arg(("--memory",), "memory budget (512, 64MiB, 2G)", "str", metavar="SIZE"),
            Arg(("--disk",), "disk budget (512, 64MiB, 2G)", "str", metavar="SIZE"),
            Arg(("--max-hours",), "time allocation in hours", "float", metavar="H"),
            Arg(
                ("--policy-override",),
                "override a policy field for this run",
                "str",
                repeat=True,
                metavar="KEY=JSON_VALUE",
            ),
            Arg(
                ("--proof-mode",),
                "how proofs are kept",
                "str",
                choices=("transient", "retain", "stream"),
            ),
            Arg(("--inbox",), "the directory this worker accepts shards from", "path"),
            Arg(("--outbox",), "the directory this worker publishes handoffs into", "path"),
            Arg(("--export",), "the directory of the periodic journal export", "path"),
            Arg(("--reopen-blocked",), "commit a node_reopen for every blocked node first", "flag"),
            Arg(
                ("--campaign-policy",),
                "return to the campaign's policy for the fields the session before had changed "
                "and this command line does not name",
                "flag",
            ),
            Arg(
                ("--accept-code-change",),
                "continue a journal whose session before ran other cubeproof sources",
                "flag",
            ),
            Arg(("--no-cache",), "ignore and rewrite the derived state cache", "flag"),
            Arg(
                ("--no-known-answer",),
                "skip the known-answer control of the checker (only for scripted test tools)",
                "flag",
            ),
            Arg(("-v", "--verbose"), "also log debug events", "flag"),
            Arg(("-q", "--quiet"), "log warnings and errors only", "flag"),
        ),
        "the run result (exit_code, reason, open work by state, session counters, given_away, "
        "notes) as one JSON line; the log (progress each minute) and notes go to standard error",
        (
            (0, "all still-owned requested regions closed"),
            (1, "open work, a resource block or the time allocation ended"),
            (2, "a valid model was found"),
            (3, "usage, configuration or a lock conflict"),
            (4, "integrity failure"),
            (5, "a tool or the I/O service failed, or retries were exhausted"),
            (6, "an anomaly was recorded"),
            (130, "interrupted by SIGINT/SIGTERM after clean handling"),
        ),
        (
            "exactly one of --campaign and --evidence",
            "-v and -q exclude each other",
            "the first use without --shard owns all requested roots (expanded by root splits); "
            "a later run never reconstructs ownership from a changed command line",
            "the result never claims that handed-off regions are closed (given_away is separate)",
            "status.json and status.txt are published into the results directory",
        ),
    ),
    Command(
        ("handoff",),
        "ask a worker to give nodes away, and follow the answer",
        (
            Arg(("--results",), "the results directory of the giving worker", "path", True),
            Arg(("--nodes",), "number of nodes to give", "int", True),
            Arg(
                ("--output-name",),
                "the name of the output file in the worker's outbox",
                "str",
                True,
            ),
            Arg(
                ("--wait-ms",),
                "wait this long for the completion (0: do not wait)",
                "int",
                default=0,
            ),
        ),
        "the outcome (state, request, response, output) as JSON",
        (
            (0, "completed, or the request is durable and no wait was asked"),
            (1, "pending, publishing or blocked after the wait"),
            (3, "usage, no inbox, a taken output name or a rejected request"),
        ),
    ),
    Command(
        ("status",),
        "show the monitor a worker publishes",
        (
            Arg(("--results",), "the worker's results directory", "path", True),
            Arg(("--json",), "print the validated status document as JSON", "flag"),
        ),
        "the human rendering of status.json (a stale status is marked), or with --json the "
        "document",
        ((0, "the status was read and is valid"), (3, "no status or an invalid status")),
        ("status is a derived monitor, never evidence",),
    ),
    Command(
        ("certify",),
        "certify journals against a campaign",
        (
            _CAMPAIGN,
            _JOURNALS,
            _EVIDENCE,
            Arg(("-o", "--output"), "write the certificate here (must not exist)", "path"),
        ),
        "the verdict and the certificate file",
        (
            (0, "PROVED"),
            (1, "OPEN"),
            (2, "MODEL_FOUND"),
            (3, "usage or an unreadable campaign"),
            (4, "integrity failure or INCONSISTENT"),
        ),
        (
            "--campaign with --journals, or --evidence alone",
            "--evidence recomputes the certificate and requires it to equal the packaged one",
        ),
    ),
    Command(
        ("evidence", "package"),
        "publish a portable evidence directory",
        (
            Arg(("--campaign",), "the campaign file", "path", True),
            Arg(("--journals",), "journal files to certify and snapshot", "path", True, many=True),
            Arg(("-o", "--output"), "the evidence directory (must not exist)", "path", True),
        ),
        "the package (manifest and certificate hashes, verdict, counts) as JSON",
        ((0, "the package was published"), (3, "usage or invalid input"), (4, "integrity failure")),
        (
            "the campaign, bundle files and certified journal prefixes are copied before the "
            "certificate, which is recomputed from the copies, and the manifest comes last",
            "exit 0 whatever the verdict: certify maps the verdict",
        ),
    ),
    Command(
        ("journal", "verify"),
        "validate every complete record of a journal",
        (
            Arg(("journal",), "the journal file", "path", metavar="JOURNAL"),
            Arg(("--campaign",), "the campaign the journal belongs to", "path", True),
        ),
        "the journal's identity, extent and torn tail as JSON",
        (
            (0, "the journal validates (a torn tail is reported)"),
            (3, "usage or an unreadable campaign"),
            (4, "integrity failure, or a journal that cannot be read"),
        ),
    ),
    Command(
        ("journal", "repair"),
        "remove a torn tail of a journal",
        (
            Arg(("journal",), "the journal file", "path", metavar="JOURNAL"),
            Arg(("--campaign",), "the campaign the journal belongs to", "path", True),
        ),
        "what was removed, and the journal verified again, as JSON",
        (
            (0, "repaired, or nothing to repair"),
            (3, "usage, or the results directory is locked by a live worker"),
            (4, "any damage other than a torn tail: the file is left unchanged"),
        ),
        ("takes the containing results directory's run.lock without waiting",),
    ),
    Command(
        ("audit",),
        "recompute audit of certified leaves: strict reproduction or independent reproof",
        (
            _CAMPAIGN,
            Arg(
                ("--certificate",),
                "the certificate to audit (bound to its exact journal prefixes and recomputed)",
                "path",
                metavar="CERT",
            ),
            _JOURNALS,
            _EVIDENCE,
            Arg(("--sample",), "audit the N smallest by seeded hash (N > 0)", "int", metavar="N"),
            Arg(("--all",), "audit every used attempt", "flag"),
            Arg(
                ("--seed",),
                "sampling seed, 64 hex digits (default: SHA-256 of the certificate)",
                "str",
                metavar="HEX64",
            ),
            Arg(
                ("--comparison",),
                "strict (historical proof hash) or reprove (a new proof, a different guarantee)",
                "str",
                choices=("strict", "reprove"),
                default="strict",
            ),
            Arg(
                ("--results",), "the audit's own results directory (journal, report)", "path", True
            ),
            Arg(("--work",), "the audit's disposable work directory", "path", True),
            Arg(("--worker",), "the audit's worker name (a-z, 0-9, _ and -)", "str", True),
            Arg(("--solver",), "the local path of the pinned solver", "str", True),
            Arg(("--checker",), "the local path of the pinned checker", "str", True),
            Arg(
                ("--helper",),
                "the local path of the splitter helper (recorded only: an audit never splits)",
                "str",
            ),
            Arg(("--memory",), "memory budget (512, 64MiB, 2G)", "str", metavar="SIZE"),
            Arg(("--disk",), "disk budget (512, 64MiB, 2G)", "str", metavar="SIZE"),
            Arg(
                ("--proof-cap",),
                "proof cap (default: the larger of the policy cap and the largest selected "
                "reference proof), clamped to the budgets",
                "str",
                metavar="SIZE",
            ),
            Arg(
                ("--no-known-answer",),
                "skip the known-answer control of the checker (only for scripted test tools)",
                "flag",
            ),
        ),
        "the outcome (exit_code, reason, journal position, pending targets, the report file and "
        "its summary: comparison, population, selected, seed, counts) as one JSON line; the "
        "report cubeproof-audit-report-1 is <results>/audit-report.json",
        (
            (0, "every selected target of a strict audit matched its historical proof hash"),
            (
                1,
                "open, not comparable or reproved only, pending targets, an empty population, "
                "or a reprove comparison",
            ),
            (3, "usage, configuration or a lock conflict"),
            (
                4,
                "integrity failure: the certificate or plan disagrees with the evidence, a "
                "mismatch, a model of a used target or a rejected new proof",
            ),
            (5, "a missing or failing tool, or the I/O service failed"),
            (130, "interrupted by SIGINT/SIGTERM after clean handling"),
        ),
        (
            "--sample N or --all, not both",
            "--evidence alone, or --campaign with --certificate and --journals",
            "the certificate is recomputed from snapshots of its exact journal prefixes before "
            "any target is chosen; records appended later are not used",
            "the solver runs without a time limit; --memory, --disk and --proof-cap bound it",
            "a strict audit runs only the source solver: a target without it is NOT_COMPARABLE",
            "a restart continues the plan in the same results directory; another selection "
            "there is refused",
        ),
    ),
    Command(
        ("verify-retained",),
        "re-check every committed retained proof with the admitted checker, without a solver",
        (
            _CAMPAIGN,
            _JOURNALS,
            _EVIDENCE,
            Arg(("--proofs-root",), "the results directory holding proofs/", "path", True),
            Arg(("--results",), "the verification's own results directory", "path", True),
            Arg(("--work",), "the directory of the private proof copies", "path", True),
            Arg(("--worker",), "the verification's worker name", "str", True),
            Arg(("--checker",), "the local path of the admitted checker", "str", True),
            Arg(("--memory",), "memory cap of each check (512, 64MiB, 2G)", "str", metavar="SIZE"),
        ),
        "the counts (expected, found, verified, missing, corrupt, rejected, exhausted, failed, "
        "unretained) and the report file as one JSON line; the report is "
        "<results>/verify-retained.json",
        (
            (0, "every expected retained proof was verified (and at least one was expected)"),
            (1, "a check was exhausted, or nothing was expected"),
            (3, "usage, configuration or a lock conflict"),
            (4, "a proof is missing, corrupt or rejected, or an input fails integrity"),
            (5, "the checker is missing, unusable, not admitted or failed"),
        ),
        (
            "--evidence alone, or --campaign with --journals",
            "every committed retained reference of the journals is expected; none is skipped",
            "the evidence is only read; the results and work directories are separate from it",
        ),
    ),
    Command(
        ("io-service",),
        "the I/O service process of a run (internal)",
        (
            Arg(("--results",), "results directory", "str", True),
            Arg(("--work",), "work directory", "str", True),
            Arg(("--journal",), "journal path", "str", True),
            Arg(("--lock",), "run lock path", "str", True),
            Arg(("--lock-fd",), "inherited lock descriptor", "int", True),
            Arg(("--campaign",), "campaign ID", "str", True),
            Arg(("--variables",), "JSON map formula hash -> variables", "str", True),
            Arg(("--header-file",), "header payload file", "str"),
        ),
        "",
        (),
        hidden=True,
    ),
)


def find(*words: str) -> Command:
    """The command named by ``words`` (KeyError if there is none)."""
    for command in COMMANDS:
        if command.words == words:
            return command
    raise KeyError(" ".join(words))
