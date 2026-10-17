"""``run``: the command entry point of one worker (specification §12.1, §12.2).

The command layer completes a :class:`~cubeproof.coordinator.config.RunConfig` (the command of
the I/O service process: this interpreter running ``cubeproof io-service``) and runs the
coordinator. It neither prints nor exits; the CLI reports the :class:`RunResult` and maps its
``exit_code`` or an error's :func:`~cubeproof.coordinator.config.exit_code_of`.

:class:`RunOptions` are the run arguments that are not the coordinator's own configuration: the
handoff desk (``--inbox``, ``--outbox``, ``--shard FILE``) and the monitor (``--export DIR``, the
log sink and level). A run is always monitored (``status.json``, ``status.txt``); it has a desk
only when one of the three desk options is given, otherwise it is exactly the plain coordinator.
The scheduler is the coordinator's: nothing here decides what runs next.
"""

from __future__ import annotations

import json
import re
import sys
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from cubeproof.base.canonical_json import parse_json
from cubeproof.base.errors import ConfigurationError, CubeproofError
from cubeproof.commands.monitored import (
    MonitoredCoordinator,
    MonitoredDeskCoordinator,
    Monitoring,
)
from cubeproof.coordinator.config import RunConfig, RunResult
from cubeproof.coordinator.service import ServiceArgs, run_service

__all__ = [
    "SERVICE_COMMAND",
    "RunOptions",
    "parse_policy_overrides",
    "parse_size",
    "run_command",
    "service_command",
    "service_main",
]

#: The I/O service process: this interpreter, the ``cubeproof`` entry point, its hidden command.
SERVICE_COMMAND: tuple[str, ...] = (sys.executable, "-m", "cubeproof", "io-service")

_SIZE = re.compile(r"([0-9]+)([KMGT]i?B?|B)?", re.IGNORECASE)
_UNITS = {
    "": 1,
    "B": 1,
    "K": 1024,
    "M": 1024**2,
    "G": 1024**3,
    "T": 1024**4,
}


def parse_size(text: str) -> int:
    """``512``, ``64M``, ``2GiB`` ... as a positive number of bytes (binary multiples)."""
    match = _SIZE.fullmatch(text.strip())
    if match is None:
        raise ConfigurationError("run.size", f"{text!r} is not a size such as 512, 64MiB or 2G")
    number, unit = match.groups()
    value = int(number) * _UNITS[(unit or "").upper().removesuffix("IB").removesuffix("B")]
    if value < 1:
        raise ConfigurationError("run.size", f"{text!r} is not positive")
    return value


def parse_policy_overrides(items: Sequence[str]) -> dict[str, Any]:
    """``KEY=JSON_VALUE`` strings (``--policy-override``) as a mapping of dotted keys to values."""
    found: dict[str, Any] = {}
    for item in items:
        key, separator, text = item.partition("=")
        if not separator or not key:
            raise ConfigurationError("run.policy_override", f"{item!r} is not KEY=JSON_VALUE")
        try:
            found[key] = parse_json(text.encode("utf-8"))
        except CubeproofError:
            raise ConfigurationError(
                "run.policy_override", f"{item!r}: the value is not a JSON value"
            ) from None
    return found


@dataclass(frozen=True)
class RunOptions:
    """The run arguments beyond :class:`RunConfig` (module doc)."""

    inbox: Path | None = None
    outbox: Path | None = None
    #: a ``cubeproof-shard-1`` file offered as the worker's shard (specification §7.4, §12.1)
    shard: Path | None = None
    #: the directory of the periodic journal export (specification §7.5)
    export: Path | None = None
    #: receives the human log lines (progress each minute, events); None: no log
    log_sink: Callable[[str], None] | None = None
    log_level: str = "info"

    def __post_init__(self) -> None:
        if self.log_level not in ("debug", "info", "warn", "error"):
            raise ConfigurationError("run.log_level", f"{self.log_level!r} is not a log level")

    @property
    def desk(self) -> bool:
        return self.inbox is not None or self.outbox is not None or self.shard is not None


def run_command(config: RunConfig, options: RunOptions = RunOptions()) -> RunResult:  # noqa: B008
    """Run one worker; ``config`` without a service command gets the standard one."""
    if not config.service_argv:
        config = replace(config, service_argv=SERVICE_COMMAND)
    monitoring = Monitoring(options.export, options.log_sink, options.log_level)
    if not options.desk:
        return MonitoredCoordinator(config, monitoring).run()
    return MonitoredDeskCoordinator(
        config,
        monitoring,
        inbox=None if options.inbox is None else Path(options.inbox).resolve(),
        outbox=None if options.outbox is None else Path(options.outbox).resolve(),
        shard_file=options.shard,
    ).run()


def service_command(
    *,
    results: str,
    work: str,
    journal: str,
    lock: str,
    lock_fd: int,
    campaign: str,
    variables: str,
    header_file: str | None,
) -> int:
    """The hidden ``io-service`` command: parse the values the coordinator passed and serve."""
    try:
        counts: Mapping[str, Any] = json.loads(variables)
    except ValueError:
        raise ConfigurationError("io.service_args", "--variables is not JSON") from None
    if not isinstance(counts, dict) or not all(type(v) is int for v in counts.values()):
        raise ConfigurationError("io.service_args", "--variables maps formula hashes to counts")
    return service_main(
        ServiceArgs(
            results=results,
            work=work,
            journal=journal,
            lock=lock,
            lock_fd=lock_fd,
            campaign=campaign,
            variables={str(k): int(v) for k, v in counts.items()},
            header_file=header_file,
        )
    )


def service_main(args: ServiceArgs) -> int:
    """Serve on standard input/output (descriptors 0 and 1, which the coordinator owns)."""
    return run_service(args)
