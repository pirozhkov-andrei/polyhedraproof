"""Engine of the fake tools: one program that does exactly what its script says.

A fake tool is a copy of this file made executable with a ``#!<python> -IS`` line, next to
its script ``<tool>.json`` (``fakes.toolkit.make_tool`` writes both). It is a real process:
it can be exec'd directly, limited by ``prlimit``, given a parent-death signal by ``setpriv``,
signalled and reaped like the pinned solver and checker, and it can misbehave in every way the
process layer must survive: emit models, complete or partial proofs, exact or wrong success
lines, arena diagnostics, oversized output and files, sleep, ignore TERM, kill itself with a
signal, change its input files, close its pipes, leave a grandchild behind.

Every run records one call before doing anything else: the invocation number, argv, cwd,
pid/ppid/pgid/sid, the recorded environment variables, the soft resource limits, the
parent-death signal and the open file descriptors. Steps that observe data (``read``,
``pipe``, ``spawn``, ``alter``, signals, errors) record events. The records end up as JSON
lines in ``<tool>.calls.jsonl`` and ``<tool>.events.jsonl``.

The fake does not write those files itself. It sends each record over a Unix socket to the
log collector of the test process that made the tool (``fakes.toolkit``), waits for the
confirmation and only then continues. So the fake's own bookkeeping writes no regular file
and is not subject to its ``RLIMIT_FSIZE`` (``prlimit --fsize``): under any file size limit,
including 0, only the scripted steps write files, and a SIGXFSZ comes from a scripted write
as it would come from CaDiCaL's proof. Only when the collector cannot be reached (no ``log``
address in the script, or the test process is gone) does the fake append the record itself,
with SIGXFSZ ignored during that write so the log never decides the exit. A record that
cannot be written completely leaves an empty marker file ``<tool>.<kind>.lost.<pid>.<errno>``
(creating an empty file is not limited by ``RLIMIT_FSIZE``) and possibly a truncated line;
either makes ``FakeTool.calls()``/``events()``/``assert_logs_complete()`` raise
``LogError``, while the scripted stdout/stderr stay exactly as scripted. Only if even the
marker cannot be created (unusable tool directory) is the loss reported on stderr
(``fake tool: ... log record lost``). A calls record that could not be counted gets the
invocation number -1. If the collector wrote a record but its confirmation was lost (30 s
timeout), the direct fallback can duplicate it.

Script (JSON object):

``steps``           list of steps, run when no case matches
``cases``           list of ``{"steps", "invocation"?, "argv_contains"?}``; the first case
                    whose matchers all hold is run instead (invocations count from 0)
``record_env``      names of environment variables to record
``python_signals``  keep Python's SIGPIPE/SIGXFSZ/SIGINT handling (default: the default
                    dispositions of a C program, so a closed pipe or a file size limit kills
                    the fake by signal as it kills CaDiCaL)
``lib``             directory that contains the ``fakes`` package (for ``lrat_check`` and
                    ``model``)
``log``             address of the log collector (``@name``: Linux abstract socket)

Targets: ``"stdout"``, ``"stderr"``, ``"stdin"``, ``{"fd": n}``, ``{"arg": i}`` (the path in
argv[i], Python indexing over the arguments without argv[0]), ``{"path": p}``.

Steps (``op`` and its keys):

``write``     to, text | hex | file, repeat, size (exact byte count, cycling the data),
              chunk, pause (seconds between chunks), append, fsync
``read``      source, limit (bytes, default all), close (close the source afterwards)
``pipe``      source, to, limit, flip_at (xor one byte at this offset), chunk, pause
``sleep``     seconds
``wait_for``  path, timeout: poll until the path exists, else exit 98
``touch``     path: create it atomically, containing this process's pid
``close``     fd
``kill_self`` signal (name such as ``"SEGV"``): default disposition, no core file, kill
``trap``      signal, steps, then (``"die"`` | ``"continue"`` | ``"exit"``), code
``spawn``     steps, setsid, pid_file, wait: fork a child that runs the steps and exits
              (97 on a script error, 75 on any other failure); with ``wait`` the parent
              waits for it and records its ``returncode`` (negative: killed by that signal)
              in the spawn event
``exit``      code
``alter``     target, action (``append`` data | ``truncate`` size | ``flip`` offset |
              ``delete`` | ``replace`` text | ``chmod`` mode)
``lrat_check`` cnf, proof: check with fakes.lrat_check and answer as cake_lpr does
``model``     cnf: brute-force the formula; print a model and exit 10, or exit 20
``exec``      argv, pass_args: replace this process

Exit codes of the engine itself: 97 bad script, 98 wait_for timed out, 75 I/O error of a
step (unless a default signal disposition killed the process first). Scripted files
(``pid_file``, ``touch``) are steps and, like any step, subject to the process's limits.
"""

from __future__ import annotations

import contextlib
import errno
import fcntl
import hashlib
import json
import os
import resource
import signal
import socket
import sys
import time
from collections.abc import Iterator, Mapping, Sequence
from pathlib import Path
from typing import Any

BAD_SCRIPT = 97
WAIT_TIMEOUT = 98
IO_ERROR = 75
BLOCK = 1 << 20
LOG_KINDS = ("calls", "events")
#: Invocation number of a run whose calls record could not be logged (no case matches it).
UNKNOWN_INVOCATION = -1
#: Seconds the fake waits for the collector's confirmation of one record.
COLLECTOR_TIMEOUT = 30.0

_TARGET = {"to", "source", "cnf", "proof", "target"}
OPS: dict[str, frozenset[str]] = {
    "write": frozenset(
        {"to", "text", "hex", "file", "repeat", "size", "chunk", "pause", "append", "fsync"}
    ),
    "read": frozenset({"source", "limit", "close"}),
    "pipe": frozenset({"source", "to", "limit", "flip_at", "chunk", "pause"}),
    "sleep": frozenset({"seconds"}),
    "wait_for": frozenset({"path", "timeout"}),
    "touch": frozenset({"path"}),
    "close": frozenset({"fd"}),
    "kill_self": frozenset({"signal"}),
    "trap": frozenset({"signal", "steps", "then", "code"}),
    "spawn": frozenset({"steps", "setsid", "pid_file", "wait"}),
    "exit": frozenset({"code"}),
    "alter": frozenset({"target", "action", "text", "size", "offset", "mode"}),
    "lrat_check": frozenset({"cnf", "proof"}),
    "model": frozenset({"cnf"}),
    "exec": frozenset({"argv", "pass_args"}),
}
REQUIRED: dict[str, frozenset[str]] = {
    "write": frozenset({"to"}),
    "read": frozenset({"source"}),
    "pipe": frozenset({"source", "to"}),
    "sleep": frozenset({"seconds"}),
    "wait_for": frozenset({"path"}),
    "touch": frozenset({"path"}),
    "close": frozenset({"fd"}),
    "kill_self": frozenset({"signal"}),
    "trap": frozenset({"signal"}),
    "spawn": frozenset({"steps"}),
    "exit": frozenset({"code"}),
    "alter": frozenset({"target", "action"}),
    "lrat_check": frozenset({"cnf", "proof"}),
    "model": frozenset({"cnf"}),
    "exec": frozenset({"argv"}),
}
ALTER_ACTIONS = ("append", "truncate", "flip", "delete", "replace", "chmod")
SCRIPT_KEYS = frozenset({"steps", "cases", "record_env", "python_signals", "lib", "log"})
CASE_KEYS = frozenset({"steps", "invocation", "argv_contains"})


class ScriptError(ValueError):
    """The script asks for something the engine does not do."""


def signal_number(name: str) -> int:
    try:
        return int(getattr(signal, "SIG" + name.removeprefix("SIG")))
    except AttributeError as error:
        raise ScriptError(f"unknown signal {name!r}") from error


def _validate_target(value: Any, where: str) -> None:
    if value in ("stdout", "stderr", "stdin"):
        return
    if isinstance(value, dict) and len(value) == 1:
        ((key, item),) = value.items()
        if key == "fd" and isinstance(item, int) and item >= 0:
            return
        if key == "arg" and isinstance(item, int):
            return
        if key == "path" and isinstance(item, str) and item:
            return
    raise ScriptError(f"{where}: bad target {value!r}")


def validate_steps(steps: Any, where: str = "steps") -> None:
    if not isinstance(steps, list):
        raise ScriptError(f"{where}: not a list")
    for index, step in enumerate(steps):
        here = f"{where}[{index}]"
        if not isinstance(step, dict) or step.get("op") not in OPS:
            raise ScriptError(f"{here}: unknown step {step!r}")
        op = step["op"]
        keys = set(step) - {"op"}
        if not keys <= OPS[op]:
            raise ScriptError(f"{here}: {op} does not take {sorted(keys - OPS[op])}")
        if not REQUIRED[op] <= keys:
            raise ScriptError(f"{here}: {op} needs {sorted(REQUIRED[op] - keys)}")
        for key in keys & _TARGET:
            _validate_target(step[key], f"{here}.{key}")
        if op == "write" and sum(k in step for k in ("text", "hex", "file")) != 1:
            raise ScriptError(f"{here}: write needs exactly one of text, hex, file")
        if op in ("kill_self", "trap"):
            signal_number(step["signal"])
        if op == "trap" and step.get("then", "die") not in ("die", "continue", "exit"):
            raise ScriptError(f"{here}: trap then must be die, continue or exit")
        if op == "alter" and step["action"] not in ALTER_ACTIONS:
            raise ScriptError(f"{here}: unknown alter action {step['action']!r}")
        if op in ("trap", "spawn"):
            validate_steps(step.get("steps", []), f"{here}.steps")
        if op == "exec" and not (
            isinstance(step["argv"], list)
            and step["argv"]
            and all(isinstance(a, str) for a in step["argv"])
        ):
            raise ScriptError(f"{here}: exec argv must be a nonempty list of strings")


def validate(script: Any) -> None:
    if not isinstance(script, dict):
        raise ScriptError("script is not an object")
    if not set(script) <= SCRIPT_KEYS:
        raise ScriptError(f"unknown script keys {sorted(set(script) - SCRIPT_KEYS)}")
    if "log" in script and not (isinstance(script["log"], str) and script["log"]):
        raise ScriptError("log: not a collector address")
    validate_steps(script.get("steps", []))
    cases = script.get("cases", [])
    if not isinstance(cases, list):
        raise ScriptError("cases: not a list")
    for index, case in enumerate(cases):
        if not isinstance(case, dict) or not set(case) <= CASE_KEYS or "steps" not in case:
            raise ScriptError(f"cases[{index}]: bad case {case!r}")
        validate_steps(case["steps"], f"cases[{index}].steps")


def choose(script: Mapping[str, Any], invocation: int, argv: Sequence[str]) -> list[Any]:
    for case in script.get("cases", []):
        if "invocation" in case and case["invocation"] != invocation:
            continue
        if "argv_contains" in case and not any(case["argv_contains"] in a for a in argv):
            continue
        return list(case["steps"])
    return list(script.get("steps", []))


class LogLost(Exception):
    """A log record could not be written completely (the line may be truncated)."""

    def __init__(self, record: Mapping[str, Any], error: OSError) -> None:
        super().__init__(f"{error}")
        self.record = dict(record)
        self.error = error


def log_path(tool: Path, kind: str) -> Path:
    if kind not in LOG_KINDS:
        raise ValueError(f"unknown log {kind!r}")
    return tool.with_name(f"{tool.name}.{kind}.jsonl")


def append_record(tool: Path, kind: str, record: Mapping[str, Any]) -> dict[str, Any]:
    """Append `record` to the tool's `kind` log under the tool's lock; return it as stored.

    A calls record gets the next invocation number (the number of earlier lines). Used by
    the collector of ``fakes.toolkit`` and, without a collector, by the fake itself. Raises
    ``LogLost`` (carrying the record; invocation ``UNKNOWN_INVOCATION`` if the log could not
    be counted) if the line could not be written completely.
    """
    target = log_path(tool, kind)
    stored = dict(record)
    if kind == "calls":
        stored["invocation"] = UNKNOWN_INVOCATION
    try:
        lock = os.open(tool.with_name(tool.name + ".lock"), os.O_RDWR | os.O_CREAT, 0o644)
    except OSError as error:
        raise LogLost(stored, error) from error
    try:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if kind == "calls":
            try:
                with open(target, "rb") as stream:
                    stored["invocation"] = sum(1 for _ in stream)
            except FileNotFoundError:
                stored["invocation"] = 0
            except OSError as error:
                raise LogLost(stored, error) from error
        line = memoryview((json.dumps(stored, sort_keys=True) + "\n").encode())
        try:
            fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
            try:
                while line:
                    line = line[os.write(fd, line) :]
            finally:
                os.close(fd)
        except OSError as error:
            raise LogLost(stored, error) from error
    finally:
        os.close(lock)
    return stored


def lost_marker(tool: Path, kind: str, pid: int, error: OSError) -> Path:
    """The empty file that records a `kind` record the fake ``pid`` could not log."""
    if kind not in LOG_KINDS:
        raise ValueError(f"unknown log {kind!r}")
    name = errno.errorcode.get(error.errno or 0, "unknown")
    return tool.with_name(f"{tool.name}.{kind}.lost.{pid}.{name}")


def mark_lost(tool: Path, kind: str, error: OSError) -> bool:
    """Create the loss marker of this process; False if even that was impossible.

    The marker is an empty file: creating it writes no data, so no file size limit
    (``RLIMIT_FSIZE`` 0 included) prevents it.
    """
    try:
        os.close(os.open(lost_marker(tool, kind, os.getpid(), error), os.O_WRONLY | os.O_CREAT))
    except OSError:
        return False
    return True


def collector_address(address: str) -> str:
    """``@name`` is the Linux abstract socket ``\\0name``; anything else a socket path."""
    return "\0" + address[1:] if address.startswith("@") else address


def ask_collector(address: str, request: Mapping[str, Any]) -> dict[str, Any] | None:
    """Send one request to the collector; its reply if it confirmed, else None."""
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(COLLECTOR_TIMEOUT)
            connection.connect(collector_address(address))
            # MSG_NOSIGNAL: a vanished collector must not kill the fake by SIGPIPE.
            connection.sendall(json.dumps(request, sort_keys=True).encode(), socket.MSG_NOSIGNAL)
            connection.shutdown(socket.SHUT_WR)
            chunks = []
            while chunk := connection.recv(BLOCK):
                chunks.append(chunk)
        reply = json.loads(b"".join(chunks))
    except (OSError, ValueError):
        return None
    if not isinstance(reply, dict) or reply.get("ok") is not True:
        return None
    return reply


def _say(text: str) -> None:
    with contextlib.suppress(OSError):
        os.write(2, text.encode())


class Log:
    """Records of one fake process: through the collector, else written directly."""

    def __init__(self, tool: Path, address: str | None) -> None:
        self.tool = tool
        self.address = address

    def record(self, kind: str, record: Mapping[str, Any]) -> dict[str, Any]:
        if self.address:
            reply = ask_collector(
                self.address, {"tool": str(self.tool), "kind": kind, "record": dict(record)}
            )
            if reply is not None and isinstance(reply.get("record"), dict):
                return dict(reply["record"])
        return self.direct(kind, record)

    def direct(self, kind: str, record: Mapping[str, Any]) -> dict[str, Any]:
        """Append the record from this process, never killed by its own file size limit.

        A record that cannot be written is marked by an empty file next to the tool
        (``lost_marker``); the scripted stdout/stderr stay untouched. Only if even the
        marker cannot be created (the tool's directory is unusable) is the loss reported
        on stderr, the one channel left.
        """
        previous = signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
        try:
            return append_record(self.tool, kind, record)
        except LogLost as lost:
            if not mark_lost(self.tool, kind, lost.error):
                _say(f"fake tool: {kind} log record lost: {lost.error}\n")
            return lost.record
        finally:
            signal.signal(signal.SIGXFSZ, previous)


def _soft_limit(kind: int) -> int:
    soft = resource.getrlimit(kind)[0]
    return -1 if soft == resource.RLIM_INFINITY else soft


def _pdeathsig() -> int | None:
    try:
        import ctypes

        libc = ctypes.CDLL(None, use_errno=True)
        value = ctypes.c_int(0)
        if libc.prctl(2, ctypes.byref(value), 0, 0, 0) != 0:  # PR_GET_PDEATHSIG
            return None
        return value.value
    except (OSError, AttributeError):
        return None


def _open_fds() -> list[int]:
    try:
        names = os.listdir("/proc/self/fd")
    except OSError:
        return []
    fds = []
    for name in names:
        try:
            os.fstat(int(name))
        except OSError:
            continue  # the descriptor of the listing itself, already closed
        fds.append(int(name))
    return sorted(fds)


def describe(argv: Sequence[str], record_env: Sequence[str]) -> dict[str, Any]:
    """The calls record of this process, without its invocation number."""
    return {
        "argv": list(argv),
        "cwd": os.getcwd(),
        "pid": os.getpid(),
        "ppid": os.getppid(),
        "pgid": os.getpgid(0),
        "sid": os.getsid(0),
        "env": {name: os.environ.get(name) for name in record_env},
        "rlimits": {
            "as": _soft_limit(resource.RLIMIT_AS),
            "fsize": _soft_limit(resource.RLIMIT_FSIZE),
            "core": _soft_limit(resource.RLIMIT_CORE),
            "nofile": _soft_limit(resource.RLIMIT_NOFILE),
        },
        "pdeathsig": _pdeathsig(),
        "fds": _open_fds(),
    }


def register(log: Log, argv: Sequence[str], record_env: Sequence[str]) -> int:
    """Record this run in the calls log; return its invocation number."""
    return int(log.record("calls", describe(argv, record_env))["invocation"])


class Runner:
    """Executes steps for one invocation of a fake tool."""

    def __init__(
        self, log: Log, script: Mapping[str, Any], argv: Sequence[str], invocation: int
    ) -> None:
        self.log = log
        self.script = script
        self.argv = list(argv)
        self.invocation = invocation

    # -- helpers --------------------------------------------------------------------------

    def event(self, op: str, **data: Any) -> None:
        self.log.record("events", {"invocation": self.invocation, "op": op, **data})

    def path_of(self, target: Any) -> str:
        if isinstance(target, dict) and "arg" in target:
            try:
                return self.argv[target["arg"]]
            except IndexError as error:
                raise ScriptError(f"no argument {target['arg']} in {self.argv}") from error
        if isinstance(target, dict) and "path" in target:
            return str(target["path"])
        raise ScriptError(f"{target!r} is not a file target")

    def fd_of(self, target: Any) -> int | None:
        if target in ("stdin", "stdout", "stderr"):
            return {"stdin": 0, "stdout": 1, "stderr": 2}[target]
        if isinstance(target, dict) and "fd" in target:
            return int(target["fd"])
        return None

    def open_for_write(self, target: Any, append: bool) -> tuple[int, bool]:
        fd = self.fd_of(target)
        if fd is not None:
            return fd, False
        flags = os.O_WRONLY | os.O_CREAT | (os.O_APPEND if append else os.O_TRUNC)
        return os.open(self.path_of(target), flags, 0o644), True

    def open_for_read(self, target: Any) -> tuple[int, bool]:
        fd = self.fd_of(target)
        if fd is not None:
            return fd, False
        return os.open(self.path_of(target), os.O_RDONLY), True

    def lib(self) -> None:
        lib = self.script.get("lib")
        if not lib:
            raise ScriptError("this step needs the script's lib directory")
        if lib not in sys.path:
            sys.path.insert(0, lib)

    @staticmethod
    def write_all(fd: int, data: bytes) -> None:
        view = memoryview(data)
        while view:
            view = view[os.write(fd, view) :]

    def payload(self, step: Mapping[str, Any]) -> Iterator[bytes]:
        if "text" in step:
            data = str(step["text"]).encode()
        elif "hex" in step:
            data = bytes.fromhex(step["hex"])
        else:
            data = Path(step["file"]).read_bytes()
        chunk = int(step.get("chunk", BLOCK))
        if "size" in step:
            total = int(step["size"])
            if total and not data:
                raise ScriptError("write size needs nonempty data")
        else:
            total = len(data) * int(step.get("repeat", 1))
        if not data:
            return
        sent = 0
        while sent < total:
            count = min(chunk, total - sent)
            start = sent % len(data)
            repeated = data[start:] + data * (count // len(data) + 1)
            yield repeated[:count]
            sent += count

    def run(self, steps: Sequence[Any]) -> None:
        for step in steps:
            getattr(self, "op_" + step["op"])(step)

    # -- steps ----------------------------------------------------------------------------

    def op_write(self, step: Mapping[str, Any]) -> None:
        fd, owned = self.open_for_write(step["to"], bool(step.get("append", False)))
        pause = float(step.get("pause", 0))
        try:
            for index, block in enumerate(self.payload(step)):
                if index and pause:
                    time.sleep(pause)
                self.write_all(fd, block)
            if step.get("fsync"):
                os.fsync(fd)
        finally:
            if owned:
                os.close(fd)

    def op_read(self, step: Mapping[str, Any]) -> None:
        fd, owned = self.open_for_read(step["source"])
        limit = step.get("limit")
        digest = hashlib.sha256()
        count = 0
        eof = False
        while limit is None or count < limit:
            want = BLOCK if limit is None else min(BLOCK, limit - count)
            block = os.read(fd, want)
            if not block:
                eof = True
                break
            digest.update(block)
            count += len(block)
        if owned or step.get("close"):
            os.close(fd)
        self.event("read", bytes=count, sha256=digest.hexdigest(), eof=eof)

    def op_pipe(self, step: Mapping[str, Any]) -> None:
        source, owned_source = self.open_for_read(step["source"])
        sink, owned_sink = self.open_for_write(step["to"], False)
        limit = step.get("limit")
        flip_at = step.get("flip_at")
        chunk = int(step.get("chunk", BLOCK))
        pause = float(step.get("pause", 0))
        digest = hashlib.sha256()
        count = 0
        eof = False
        try:
            while limit is None or count < limit:
                want = chunk if limit is None else min(chunk, limit - count)
                block = os.read(source, want)
                if not block:
                    eof = True
                    break
                digest.update(block)
                if flip_at is not None and count <= flip_at < count + len(block):
                    mutable = bytearray(block)
                    mutable[flip_at - count] ^= 0x01
                    block = bytes(mutable)
                if count and pause:
                    time.sleep(pause)
                self.write_all(sink, block)
                count += len(block)
        finally:
            if owned_source:
                os.close(source)
            if owned_sink:
                os.close(sink)
        self.event("pipe", bytes=count, sha256=digest.hexdigest(), eof=eof)

    def op_sleep(self, step: Mapping[str, Any]) -> None:
        time.sleep(float(step["seconds"]))

    def op_wait_for(self, step: Mapping[str, Any]) -> None:
        deadline = time.monotonic() + float(step.get("timeout", 30))
        while not os.path.exists(step["path"]):
            if time.monotonic() > deadline:
                os.write(2, f"fake tool: timed out waiting for {step['path']}\n".encode())
                raise SystemExit(WAIT_TIMEOUT)
            time.sleep(0.01)

    def op_touch(self, step: Mapping[str, Any]) -> None:
        path = Path(step["path"])
        temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
        temporary.write_text(str(os.getpid()), encoding="ascii")
        os.replace(temporary, path)

    def op_close(self, step: Mapping[str, Any]) -> None:
        os.close(int(step["fd"]))

    def op_kill_self(self, step: Mapping[str, Any]) -> None:
        number = signal_number(step["signal"])
        resource.setrlimit(resource.RLIMIT_CORE, (0, resource.getrlimit(resource.RLIMIT_CORE)[1]))
        if number not in (signal.SIGKILL, signal.SIGSTOP):
            signal.signal(number, signal.SIG_DFL)
            signal.pthread_sigmask(signal.SIG_UNBLOCK, {number})
        os.kill(os.getpid(), number)
        time.sleep(1)
        os.write(2, f"fake tool: still alive after SIG{step['signal']}\n".encode())
        raise SystemExit(BAD_SCRIPT)

    def op_trap(self, step: Mapping[str, Any]) -> None:
        number = signal_number(step["signal"])
        steps = list(step.get("steps", []))
        then = step.get("then", "die")
        code = int(step.get("code", 0))

        def handler(signum: int, frame: object) -> None:
            self.event("signal", signal=signum)
            self.run(steps)
            if then == "die":
                signal.signal(signum, signal.SIG_DFL)
                os.kill(os.getpid(), signum)
            elif then == "exit":
                os._exit(code)

        signal.signal(number, handler)

    def op_spawn(self, step: Mapping[str, Any]) -> None:
        pid = os.fork()
        if pid == 0:
            code = 0
            try:
                if step.get("setsid"):
                    os.setsid()
                self.run(step["steps"])
            except SystemExit as stop:
                code = stop.code if isinstance(stop.code, int) else 1
            except ScriptError as error:
                _say(f"fake tool: bad script: {error}\n")
                code = BAD_SCRIPT
            except BaseException:  # the child must never return into the parent's steps
                code = IO_ERROR
            os._exit(code)
        if step.get("pid_file"):
            path = Path(step["pid_file"])
            temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
            temporary.write_text(str(pid), encoding="ascii")
            os.replace(temporary, path)
        if step.get("wait"):
            _, status = os.waitpid(pid, 0)
            self.event("spawn", pid=pid, returncode=os.waitstatus_to_exitcode(status))
        else:
            self.event("spawn", pid=pid)

    def op_exit(self, step: Mapping[str, Any]) -> None:
        raise SystemExit(int(step["code"]))

    def op_alter(self, step: Mapping[str, Any]) -> None:
        path = Path(self.path_of(step["target"]))
        action = step["action"]
        if action == "append":
            with open(path, "ab") as stream:
                stream.write(str(step.get("text", "c altered\n")).encode())
        elif action == "truncate":
            os.truncate(path, int(step.get("size", 0)))
        elif action == "flip":
            offset = int(step.get("offset", 0))
            with open(path, "r+b") as stream:
                stream.seek(offset)
                byte = stream.read(1)
                if not byte:
                    raise ScriptError(f"{path} has no byte at offset {offset}")
                stream.seek(offset)
                stream.write(bytes([byte[0] ^ 0x01]))
        elif action == "delete":
            path.unlink()
        elif action == "replace":
            temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
            temporary.write_bytes(str(step.get("text", "")).encode())
            os.replace(temporary, path)
        else:
            path.chmod(int(step.get("mode", 0o600)))
        self.event("alter", path=str(path), action=action)

    def op_lrat_check(self, step: Mapping[str, Any]) -> None:
        self.lib()
        from fakes.lrat_check import SUCCESS, check_files

        result = check_files(Path(self.path_of(step["cnf"])), Path(self.path_of(step["proof"])))
        if result.verified:
            self.write_all(1, SUCCESS)
        else:
            self.write_all(2, f"c Checking failed: {result.reason}\n".encode())
        raise SystemExit(0)

    def op_model(self, step: Mapping[str, Any]) -> None:
        self.lib()
        from fakes.cnf_model import (
            brute_force_model,
            literals_of,
            model_lines,
            parse_dimacs,
        )

        cnf = parse_dimacs(Path(self.path_of(step["cnf"])).read_bytes())
        model = brute_force_model(cnf)
        if model is None:
            self.write_all(1, b"s UNSATISFIABLE\n")
            raise SystemExit(20)
        self.write_all(1, model_lines(literals_of(model)))
        raise SystemExit(10)

    def op_exec(self, step: Mapping[str, Any]) -> None:
        argv = list(step["argv"]) + (self.argv if step.get("pass_args") else [])
        os.execv(argv[0], argv)


def main() -> int:
    # Importing fakes.* for lrat_check/model must not write .pyc files: under a file size
    # limit such a write would be the fake's, not the script's.
    sys.dont_write_bytecode = True
    tool = Path(__file__).resolve()
    argv = sys.argv[1:]
    try:
        script = json.loads(tool.with_name(tool.name + ".json").read_text(encoding="utf-8"))
        validate(script)
    except (OSError, ValueError) as error:
        os.write(2, f"fake tool: bad script: {error}\n".encode())
        return BAD_SCRIPT
    if not script.get("python_signals"):
        for number in (signal.SIGPIPE, signal.SIGXFSZ, signal.SIGINT):
            signal.signal(number, signal.SIG_DFL)
    log = Log(tool, script.get("log"))
    invocation = register(log, argv, list(script.get("record_env", [])))
    runner = Runner(log, script, argv, invocation)
    try:
        runner.run(choose(script, invocation, argv))
    except ScriptError as error:
        os.write(2, f"fake tool: bad script: {error}\n".encode())
        return BAD_SCRIPT
    except OSError as error:
        runner.event("error", error=str(error), errno=error.errno)
        os.write(2, f"fake tool: {error}\n".encode())
        return IO_ERROR
    return 0


if __name__ == "__main__":
    sys.exit(main())
