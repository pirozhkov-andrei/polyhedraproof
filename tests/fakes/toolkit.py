"""Build fake tools for tests: executables that misbehave exactly as scripted.

    from fakes import toolkit as fk

    tool = fk.make_tool(tmp_path, "cadical", [fk.write(fk.arg(-1), "3 0 1 2 0\\n"),
                                             fk.write(fk.STDOUT, "s UNSATISFIABLE\\n"),
                                             fk.exit_(20)])
    subprocess.run([str(tool.path), "formula.cnf", "proof.lrat"])
    tool.calls()[0]["argv"]   # what the code under test passed

Each step helper returns one step of the script language of ``fakes.fake_tool`` (documented
there); ``fakes.presets`` composes them into stand-ins for the pinned solver and checker.
A script is validated when the tool is made, so a typo fails in the test, not in the child.
Fakes are test doubles: no production result may rest on them.

The first ``make_tool`` of a process starts the log collector: a daemon thread listening on
a Linux abstract Unix socket. Fakes send their call and event records to it and it appends
them to the tool's ``.calls.jsonl``/``.events.jsonl``, so the fakes' bookkeeping is outside
their own resource limits (``fakes.fake_tool``). It accepts records only for tools made by
this process. Code under test that calls ``os.fork`` without exec (``subprocess`` is not
affected) gets a child without the collector thread, which is harmless; only a fork taken
while the collector is appending a record leaves that tool's log lock held by the child
until the child exits or execs.
"""

from __future__ import annotations

import contextlib
import json
import os
import secrets
import signal
import socket
import sys
import threading
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import fake_tool

Step = dict[str, Any]
Target = Any

STDIN = "stdin"
STDOUT = "stdout"
STDERR = "stderr"
ENGINE = Path(fake_tool.__file__).resolve()
LIB = ENGINE.parents[1]
#: Linux reads at most 255 bytes of a ``#!`` line (BINPRM_BUF_SIZE 256, kernel 5.1+).
SHEBANG_LIMIT = 255


def arg(index: int) -> dict[str, int]:
    """The path given as argument `index` (Python indexing; argv[0] excluded)."""
    return {"arg": index}


def path(value: str | os.PathLike[str]) -> dict[str, str]:
    return {"path": os.fspath(value)}


def fd(number: int) -> dict[str, int]:
    return {"fd": number}


def _optional(step: Step, **values: Any) -> Step:
    step.update({k: v for k, v in values.items() if v is not None})
    return step


def write(
    to: Target,
    text: str | None = None,
    *,
    data: bytes | None = None,
    file: str | os.PathLike[str] | None = None,
    repeat: int | None = None,
    size: int | None = None,
    chunk: int | None = None,
    pause: float | None = None,
    append: bool | None = None,
    fsync: bool | None = None,
) -> Step:
    """Write text (UTF-8), raw `data` or a file's bytes to a target."""
    step: Step = {"op": "write", "to": to}
    if text is not None:
        step["text"] = text
    if data is not None:
        step["hex"] = data.hex()
    if file is not None:
        step["file"] = os.fspath(file)
    return _optional(
        step, repeat=repeat, size=size, chunk=chunk, pause=pause, append=append, fsync=fsync
    )


def read(source: Target, *, limit: int | None = None, close: bool | None = None) -> Step:
    return _optional({"op": "read", "source": source}, limit=limit, close=close)


def pipe(
    source: Target,
    to: Target,
    *,
    limit: int | None = None,
    flip_at: int | None = None,
    chunk: int | None = None,
    pause: float | None = None,
) -> Step:
    return _optional(
        {"op": "pipe", "source": source, "to": to},
        limit=limit,
        flip_at=flip_at,
        chunk=chunk,
        pause=pause,
    )


def sleep(seconds: float) -> Step:
    return {"op": "sleep", "seconds": seconds}


def wait_for(target: str | os.PathLike[str], timeout: float = 30.0) -> Step:
    return {"op": "wait_for", "path": os.fspath(target), "timeout": timeout}


def touch(target: str | os.PathLike[str]) -> Step:
    return {"op": "touch", "path": os.fspath(target)}


def close(number: int) -> Step:
    return {"op": "close", "fd": number}


def kill_self(name: str) -> Step:
    return {"op": "kill_self", "signal": name}


def trap(name: str, steps: Sequence[Step] = (), *, then: str = "die", code: int = 0) -> Step:
    return {"op": "trap", "signal": name, "steps": list(steps), "then": then, "code": code}


def spawn(
    steps: Sequence[Step],
    *,
    setsid: bool = False,
    pid_file: str | os.PathLike[str] | None = None,
    wait: bool = False,
) -> Step:
    step: Step = {"op": "spawn", "steps": list(steps), "setsid": setsid}
    if pid_file is not None:
        step["pid_file"] = os.fspath(pid_file)
    if wait:
        step["wait"] = True
    return step


def exit_(code: int) -> Step:
    return {"op": "exit", "code": code}


def alter(
    target: Target,
    action: str,
    *,
    text: str | None = None,
    size: int | None = None,
    offset: int | None = None,
    mode: int | None = None,
) -> Step:
    return _optional(
        {"op": "alter", "target": target, "action": action},
        text=text,
        size=size,
        offset=offset,
        mode=mode,
    )


def lrat_check(cnf: Target | None = None, proof: Target | None = None) -> Step:
    return {"op": "lrat_check", "cnf": cnf or arg(-2), "proof": proof or arg(-1)}


def model(cnf: Target | None = None) -> Step:
    return {"op": "model", "cnf": cnf or arg(-1)}


def exec_(argv: Sequence[str], *, pass_args: bool = False) -> Step:
    return {"op": "exec", "argv": list(argv), "pass_args": pass_args}


def case(
    steps: Sequence[Step], *, invocation: int | None = None, argv_contains: str | None = None
) -> dict[str, Any]:
    return _optional({"steps": list(steps)}, invocation=invocation, argv_contains=argv_contains)


class LogError(AssertionError):
    """A fake's log holds an incomplete record or misses a record the fake could not write."""


def _lost(tool: Path, kind: str) -> list[str]:
    """Names of the loss markers of `tool`'s `kind` log (fake_tool.lost_marker)."""
    prefix = f"{tool.name}.{kind}.lost."
    try:
        names = os.listdir(tool.parent)
    except FileNotFoundError:
        return []
    return sorted(name for name in names if name.startswith(prefix))


def _records(tool: Path, kind: str) -> list[dict[str, Any]]:
    lost = _lost(tool, kind)
    if lost:
        raise LogError(
            f"{tool}: {len(lost)} {kind} record(s) lost by the fake itself (written without "
            f"the collector): {', '.join(lost)}"
        )
    return _lines(fake_tool.log_path(tool, kind))


def _lines(path: Path) -> list[dict[str, Any]]:
    try:
        data = path.read_bytes()
    except FileNotFoundError:
        return []
    records = []
    for number, line in enumerate(data.split(b"\n")[:-1], 1):
        try:
            record = json.loads(line)
        except ValueError:
            record = None
        if not isinstance(record, dict):
            raise LogError(f"{path}: line {number} is not a complete record")
        records.append(record)
    if not data.endswith(b"\n") and data:
        raise LogError(
            f"{path}: the last record is truncated (written by the fake itself, without the "
            "collector, under a file size limit?)"
        )
    return records


class _Collector:
    """Receives the fakes' records and appends them to the logs of this process's tools."""

    def __init__(self) -> None:
        self.pid = os.getpid()
        self.address = f"@polyhedraproof-fakes-{self.pid}-{secrets.token_hex(8)}"
        self.tools: set[str] = set()
        self.server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.server.bind(fake_tool.collector_address(self.address))
        self.server.listen(128)
        threading.Thread(target=self._serve, name="fake-tool-log-collector", daemon=True).start()

    def _serve(self) -> None:
        while True:
            try:
                connection, _ = self.server.accept()
            except OSError:
                return
            threading.Thread(target=self._handle, args=(connection,), daemon=True).start()

    def _handle(self, connection: socket.socket) -> None:
        with connection, contextlib.suppress(OSError):
            connection.settimeout(fake_tool.COLLECTOR_TIMEOUT)
            chunks = []
            while chunk := connection.recv(fake_tool.BLOCK):
                chunks.append(chunk)
            connection.sendall(json.dumps(self.answer(b"".join(chunks))).encode())

    def answer(self, data: bytes) -> dict[str, Any]:
        try:
            request = json.loads(data)
            tool = request["tool"]
            kind = request["kind"]
            record = request["record"]
            if tool not in self.tools:
                return {"ok": False, "error": f"not a tool of this process: {tool!r}"}
            if kind not in fake_tool.LOG_KINDS or not isinstance(record, dict):
                return {"ok": False, "error": "bad request"}
            stored = fake_tool.append_record(Path(tool), kind, record)
        except fake_tool.LogLost as lost:
            return {"ok": False, "error": f"log write failed: {lost.error}"}
        except (OSError, ValueError, KeyError, TypeError) as error:
            return {"ok": False, "error": f"bad request: {error}"}
        return {"ok": True, "record": stored}


_COLLECTORS: dict[int, _Collector] = {}
_COLLECTOR_LOCK = threading.Lock()


def collector() -> _Collector:
    """The log collector of this process, started on first use (again after a fork)."""
    with _COLLECTOR_LOCK:
        pid = os.getpid()
        if pid not in _COLLECTORS:
            _COLLECTORS[pid] = _Collector()
        return _COLLECTORS[pid]


@dataclass(frozen=True)
class FakeTool:
    """An executable fake and its logs."""

    path: Path

    @property
    def script_path(self) -> Path:
        return self.path.with_name(self.path.name + ".json")

    def calls(self) -> list[dict[str, Any]]:
        """One record per invocation, in invocation order (fake_tool.describe).

        Raises LogError if a record is incomplete or was lost.
        """
        return _records(self.path, "calls")

    def events(self) -> list[dict[str, Any]]:
        """The event records of all invocations; LogError as for calls()."""
        return _records(self.path, "events")

    def assert_logs_complete(self) -> None:
        """Raise LogError unless every record of every run reached both logs intact."""
        for kind in fake_tool.LOG_KINDS:
            _records(self.path, kind)

    def argv(self, invocation: int = -1) -> list[str]:
        return list(self.calls()[invocation]["argv"])

    def __str__(self) -> str:
        return str(self.path)


def make_tool(
    directory: str | os.PathLike[str],
    name: str,
    steps: Sequence[Step] = (),
    *,
    cases: Sequence[dict[str, Any]] = (),
    record_env: Sequence[str] = (),
    python_signals: bool = False,
    interpreter: str | None = None,
    use_collector: bool = True,
) -> FakeTool:
    """Write ``directory/name`` (executable) and its script; return the tool.

    `use_collector=False` makes the fake write its logs itself (only for testing that
    fallback: such logs are subject to the fake's file size limit).
    """
    target = Path(directory).resolve() / name
    script: dict[str, Any] = {
        "steps": list(steps),
        "cases": list(cases),
        "record_env": list(record_env),
        "python_signals": python_signals,
        "lib": str(LIB),
    }
    if use_collector:
        logs = collector()
        logs.tools.add(str(target))
        script["log"] = logs.address
    fake_tool.validate(json.loads(json.dumps(script)))
    python = interpreter or sys.executable
    shebang = f"#!{python} -IS\n"
    if len(shebang) > SHEBANG_LIMIT or " " in python:
        raise ValueError(f"interpreter path unusable in a #! line: {python!r}")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.with_name(name + ".json").write_text(json.dumps(script, indent=1), encoding="utf-8")
    target.write_text(shebang + ENGINE.read_text(encoding="utf-8"), encoding="utf-8")
    target.chmod(0o755)
    return FakeTool(target)


def signal_name(returncode: int) -> str | None:
    """``SEGV`` for -11 and so on; None for a normal exit."""
    if returncode >= 0:
        return None
    return signal.Signals(-returncode).name.removeprefix("SIG")
