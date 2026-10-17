"""The fake-tool engine does exactly what its script says, as a real process."""

from __future__ import annotations

import contextlib
import errno
import hashlib
import json
import os
import resource
import shutil
import signal
import stat
import subprocess
import sys
import time
from collections.abc import Callable, Iterator, Mapping
from pathlib import Path

import pytest

from fakes import fake_tool
from fakes import toolkit as fk
from fakes.fixture_files import fixture

TIMEOUT = 30


def run(
    tool: fk.FakeTool,
    *args: str | Path,
    data: bytes | None = None,
    env: Mapping[str, str] | None = None,
    cwd: Path | None = None,
    preexec_fn: Callable[[], None] | None = None,
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [str(tool.path), *map(str, args)],
        input=data,
        capture_output=True,
        timeout=TIMEOUT,
        check=False,
        env=env,
        cwd=cwd,
        preexec_fn=preexec_fn,
    )


def wait_until(predicate: object, timeout: float = 10.0) -> None:
    assert callable(predicate)
    deadline = time.monotonic() + timeout
    while not predicate():
        if time.monotonic() > deadline:
            raise AssertionError("condition not reached")
        time.sleep(0.01)


def alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


@pytest.fixture
def reap_pids() -> Iterator[list[int]]:
    """Pids of grandchildren a test leaves behind; killed at the end."""
    pids: list[int] = []
    yield pids
    for pid in pids:
        with contextlib.suppress(ProcessLookupError):
            os.kill(pid, signal.SIGKILL)


# -- scripts --------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "steps",
    [
        [{"op": "nonsense"}],
        [{"op": "write", "to": "stdout"}],
        [{"op": "write", "to": "stdout", "text": "a", "hex": "62"}],
        [{"op": "write", "to": "printer", "text": "a"}],
        [{"op": "write", "to": {"arg": "x"}, "text": "a"}],
        [{"op": "sleep"}],
        [{"op": "sleep", "seconds": 1, "extra": 2}],
        [{"op": "kill_self", "signal": "NOPE"}],
        [{"op": "trap", "signal": "TERM", "then": "dance"}],
        [{"op": "alter", "target": {"arg": 0}, "action": "burn"}],
        [{"op": "spawn", "steps": [{"op": "nonsense"}]}],
        [{"op": "exec", "argv": []}],
        "not a list",
    ],
)
def test_bad_scripts_are_rejected_when_the_tool_is_made(tmp_path: Path, steps: object) -> None:
    with pytest.raises(fake_tool.ScriptError):
        fk.make_tool(tmp_path, "tool", steps)  # type: ignore[arg-type]


def test_bad_script_structure_is_rejected() -> None:
    with pytest.raises(fake_tool.ScriptError):
        fake_tool.validate([])
    with pytest.raises(fake_tool.ScriptError):
        fake_tool.validate({"steps": [], "colour": "red"})
    with pytest.raises(fake_tool.ScriptError):
        fake_tool.validate({"cases": [{"invocation": 1}]})
    with pytest.raises(fake_tool.ScriptError):
        fake_tool.validate({"cases": "x"})


def test_a_script_broken_after_creation_exits_97(tmp_path: Path) -> None:
    tool = fk.make_tool(tmp_path, "tool", [fk.exit_(0)])
    tool.script_path.write_text('{"steps": [{"op": "nonsense"}]}', encoding="utf-8")
    result = run(tool)
    assert result.returncode == fake_tool.BAD_SCRIPT
    assert b"bad script" in result.stderr
    tool.script_path.unlink()
    assert run(tool).returncode == fake_tool.BAD_SCRIPT


def test_a_missing_argument_is_a_script_error(tmp_path: Path) -> None:
    tool = fk.make_tool(tmp_path, "tool", [fk.write(fk.arg(3), "x")])
    result = run(tool, "only-one")
    assert result.returncode == fake_tool.BAD_SCRIPT
    assert b"no argument 3" in result.stderr


def test_an_unusable_interpreter_path_is_refused(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="interpreter"):
        fk.make_tool(tmp_path, "tool", [], interpreter="/x" * 200)
    with pytest.raises(ValueError, match="interpreter"):
        fk.make_tool(tmp_path, "tool", [], interpreter="/with space/python")


# -- the calls log ------------------------------------------------------------------------


def test_every_run_is_recorded(tmp_path: Path) -> None:
    tool = fk.make_tool(tmp_path, "tool", [fk.exit_(3)], record_env=["FAKE_MARK", "ABSENT"])
    env = {**os.environ, "FAKE_MARK": "hello"}
    work = tmp_path / "cwd"
    work.mkdir()
    first = run(tool, "a b", "--x=1", env=env, cwd=work)
    second = run(tool, env=env)
    assert (first.returncode, second.returncode) == (3, 3)
    calls = tool.calls()
    assert [c["invocation"] for c in calls] == [0, 1]
    assert calls[0]["argv"] == ["a b", "--x=1"]
    assert tool.argv(0) == ["a b", "--x=1"]
    assert calls[1]["argv"] == []
    assert calls[0]["cwd"] == str(work)
    assert calls[0]["env"] == {"FAKE_MARK": "hello", "ABSENT": None}
    assert calls[0]["ppid"] == os.getpid()
    assert {0, 1, 2} <= set(calls[0]["fds"])
    assert set(calls[0]["rlimits"]) == {"as", "fsize", "core", "nofile"}


def test_the_record_shows_limits_sessions_and_leaked_descriptors(tmp_path: Path) -> None:
    tool = fk.make_tool(tmp_path, "tool", [])
    reader, writer = os.pipe()
    os.set_inheritable(writer, True)

    def limit() -> None:
        resource.setrlimit(resource.RLIMIT_FSIZE, (12345, resource.RLIM_INFINITY))

    try:
        subprocess.run(
            [str(tool.path)],
            preexec_fn=limit,
            start_new_session=True,
            pass_fds=(writer,),
            timeout=TIMEOUT,
            check=True,
        )
    finally:
        os.close(reader)
        os.close(writer)
    call = tool.calls()[0]
    assert call["rlimits"]["fsize"] == 12345
    assert call["sid"] == call["pid"] == call["pgid"]
    assert writer in call["fds"]


@pytest.mark.skipif(shutil.which("setpriv") is None, reason="needs util-linux setpriv")
def test_the_record_shows_the_parent_death_signal(tmp_path: Path) -> None:
    tool = fk.make_tool(tmp_path, "tool", [])
    setpriv = shutil.which("setpriv")
    assert setpriv is not None
    subprocess.run(
        [setpriv, "--pdeathsig", "KILL", "--", str(tool.path)], timeout=TIMEOUT, check=True
    )
    subprocess.run([str(tool.path)], timeout=TIMEOUT, check=True)
    calls = tool.calls()
    assert calls[0]["pdeathsig"] == signal.SIGKILL
    assert calls[1]["pdeathsig"] == 0


def test_concurrent_runs_get_distinct_invocation_numbers(tmp_path: Path) -> None:
    tool = fk.make_tool(tmp_path, "tool", [fk.sleep(0.05)])
    children = [subprocess.Popen([str(tool.path), str(i)]) for i in range(8)]
    for child in children:
        assert child.wait(timeout=TIMEOUT) == 0
    calls = tool.calls()
    assert sorted(c["invocation"] for c in calls) == list(range(8))
    assert sorted(c["argv"][0] for c in calls) == [str(i) for i in range(8)]


# -- output and files -----------------------------------------------------------------------


def test_exact_bytes_on_stdout_and_stderr(tmp_path: Path) -> None:
    tool = fk.make_tool(
        tmp_path,
        "tool",
        [
            fk.write(fk.STDOUT, "s VERIFIED UNSAT\n"),
            fk.write(fk.STDERR, data=b"\x00\xff"),
            fk.write(fk.fd(1), "x", repeat=3),
        ],
    )
    result = run(tool)
    assert (result.returncode, result.stdout, result.stderr) == (
        0,
        b"s VERIFIED UNSAT\nxxx",
        b"\x00\xff",
    )


def test_oversized_output_has_the_exact_size(tmp_path: Path) -> None:
    size = (3 << 20) + 7
    tool = fk.make_tool(tmp_path, "tool", [fk.write(fk.STDOUT, "abc", size=size, chunk=65536)])
    result = run(tool)
    assert len(result.stdout) == size
    assert result.stdout[:7] == b"abcabca"
    assert result.stdout == (b"abc" * (size // 3 + 1))[:size]


def test_files_named_in_argv_or_by_path(tmp_path: Path) -> None:
    source = tmp_path / "source.bin"
    source.write_bytes(b"0123")
    other = tmp_path / "other.txt"
    tool = fk.make_tool(
        tmp_path,
        "tool",
        [
            fk.write(fk.arg(-1), "first\n"),
            fk.write(fk.arg(-1), "second\n", append=True, fsync=True),
            fk.write(fk.path(other), file=source),
            fk.write(fk.arg(0), "", size=0),
        ],
    )
    assert run(tool, tmp_path / "zero", tmp_path / "proof").returncode == 0
    assert (tmp_path / "proof").read_bytes() == b"first\nsecond\n"
    assert other.read_bytes() == b"0123"
    assert (tmp_path / "zero").read_bytes() == b""


def test_slow_output_comes_in_chunks(tmp_path: Path) -> None:
    tool = fk.make_tool(tmp_path, "tool", [fk.write(fk.STDOUT, "ab", size=8, chunk=2, pause=0.1)])
    child = subprocess.Popen([str(tool.path)], stdout=subprocess.PIPE)
    assert child.stdout is not None
    started = time.monotonic()
    first = child.stdout.read(2)
    rest = child.stdout.read()
    child.wait(timeout=TIMEOUT)
    assert first + rest == b"abababab"
    assert time.monotonic() - started >= 0.25


def test_a_closed_pipe_kills_the_fake_by_sigpipe(tmp_path: Path) -> None:
    tool = fk.make_tool(tmp_path, "tool", [fk.write(fk.STDOUT, "x", size=1 << 24)])
    child = subprocess.Popen([str(tool.path)], stdout=subprocess.PIPE)
    assert child.stdout is not None
    child.stdout.read(10)
    child.stdout.close()
    assert child.wait(timeout=TIMEOUT) == -signal.SIGPIPE


def test_with_python_signals_a_closed_pipe_is_an_io_error(tmp_path: Path) -> None:
    tool = fk.make_tool(
        tmp_path, "tool", [fk.write(fk.STDOUT, "x", size=1 << 24)], python_signals=True
    )
    child = subprocess.Popen([str(tool.path)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    assert child.stdout is not None and child.stderr is not None
    child.stdout.read(10)
    child.stdout.close()
    assert child.wait(timeout=TIMEOUT) == fake_tool.IO_ERROR
    assert b"Broken pipe" in child.stderr.read()
    assert tool.events()[-1]["errno"] == errno.EPIPE


def test_a_file_size_limit_kills_the_fake_by_sigxfsz(tmp_path: Path) -> None:
    tool = fk.make_tool(tmp_path, "tool", [fk.write(fk.arg(-1), "1 0 1 0\n", size=1 << 20)])

    def limit() -> None:
        resource.setrlimit(resource.RLIMIT_FSIZE, (4096, resource.RLIM_INFINITY))

    result = run(tool, tmp_path / "proof", preexec_fn=limit)
    assert result.returncode == -signal.SIGXFSZ
    assert (tmp_path / "proof").stat().st_size == 4096


def _fsize(cap: int) -> Callable[[], None]:
    def limit() -> None:  # as `prlimit --fsize=cap`: soft and hard limit
        resource.setrlimit(resource.RLIMIT_FSIZE, (cap, cap))

    return limit


PROOF = b"1 2 0\n0\n"


def _proof_tool(tmp_path: Path, *, use_collector: bool = True) -> fk.FakeTool:
    return fk.make_tool(
        tmp_path,
        "solver",
        [
            fk.read(fk.STDIN),  # an event before the proof
            fk.write(fk.arg(-1), data=PROOF),
            fk.write(fk.STDOUT, "s UNSATISFIABLE\n"),
            fk.exit_(20),
        ],
        use_collector=use_collector,
    )


@pytest.mark.parametrize("cap", [0, 1, len(PROOF), 50, 1000])
def test_the_proof_step_not_the_logs_decides_under_a_file_size_limit(
    tmp_path: Path, cap: int
) -> None:
    # Below one log line (0, 1, 8, 50 bytes) and below several (1000): the records are
    # complete and the outcome is the proof write's, run after run.
    tool = _proof_tool(tmp_path)
    runs = 6
    for number in range(runs):
        proof = tmp_path / f"proof-{number}"
        result = run(tool, tmp_path / "formula", proof, data=b"", preexec_fn=_fsize(cap))
        if cap >= len(PROOF):
            assert (result.returncode, result.stdout) == (20, b"s UNSATISFIABLE\n")
            assert proof.read_bytes() == PROOF
        else:
            assert result.returncode == -signal.SIGXFSZ
            assert proof.read_bytes() == PROOF[:cap]
        assert result.stderr == b""
    calls = tool.calls()
    assert [c["invocation"] for c in calls] == list(range(runs))
    assert {c["rlimits"]["fsize"] for c in calls} == {cap}
    assert [(e["invocation"], e["op"]) for e in tool.events()] == [(n, "read") for n in range(runs)]
    assert len(fake_tool.log_path(tool.path, "calls").read_bytes()) > max(cap, 1000)


def test_the_built_in_checker_writes_no_file_under_a_zero_file_size_limit(tmp_path: Path) -> None:
    tool = fk.make_tool(tmp_path, "checker", [fk.lrat_check()])
    result = run(tool, fixture("unsat.cnf"), fixture("unsat.lrat"), preexec_fn=_fsize(0))
    assert (result.returncode, result.stdout) == (0, b"s VERIFIED UNSAT\n")
    assert tool.calls()[0]["rlimits"]["fsize"] == 0


def test_without_the_collector_a_log_that_does_not_fit_is_reported_not_fatal(
    tmp_path: Path,
) -> None:
    tool = _proof_tool(tmp_path / "unlimited", use_collector=False)
    assert "log" not in json.loads(tool.script_path.read_text(encoding="utf-8"))
    assert run(tool, "f", tmp_path / "p0", data=b"").returncode == 20
    assert [c["invocation"] for c in tool.calls()] == [0]  # direct logging works unlimited
    tool.assert_logs_complete()

    tool = _proof_tool(tmp_path / "limited", use_collector=False)
    for number in range(3):
        proof = tmp_path / f"proof-{number}"
        result = run(tool, "f", proof, data=b"", preexec_fn=_fsize(50))
        assert result.returncode == 20  # the log write did not kill the fake
        assert proof.read_bytes() == PROOF
        assert (result.stdout, result.stderr) == (b"s UNSATISFIABLE\n", b"")  # as scripted
    markers = sorted(p.name for p in tool.path.parent.iterdir() if ".lost." in p.name)
    assert markers and all(p.endswith(".EFBIG") for p in markers)
    assert all(p.startswith(("solver.calls.lost.", "solver.events.lost.")) for p in markers)
    with pytest.raises(fk.LogError, match=r"calls record.* lost"):
        tool.calls()
    with pytest.raises(fk.LogError, match=r"events record.* lost"):
        tool.events()
    with pytest.raises(fk.LogError, match="lost"):
        tool.assert_logs_complete()


def test_a_record_lost_without_a_trace_in_the_log_is_still_reported(tmp_path: Path) -> None:
    # The events log cannot be opened at all (it is a directory): nothing truncated shows
    # the loss, only the marker does.
    tool = fk.FakeTool(tmp_path / "tool")
    fake_tool.log_path(tool.path, "events").mkdir()
    log = fake_tool.Log(tool.path, None)
    assert log.direct("calls", {"argv": []})["invocation"] == 0
    assert log.direct("events", {"op": "x"}) == {"op": "x"}
    assert [c["invocation"] for c in tool.calls()] == [0]
    with pytest.raises(fk.LogError, match="1 events record"):
        tool.events()
    marker = fake_tool.lost_marker(tool.path, "events", os.getpid(), OSError(errno.EISDIR, ""))
    assert marker.exists() and marker.stat().st_size == 0


def test_stderr_reports_a_loss_only_when_no_marker_can_be_made(
    tmp_path: Path, capfd: pytest.CaptureFixture[str]
) -> None:
    log = fake_tool.Log(tmp_path / "gone" / "tool", None)  # the tool's directory is missing
    record = log.direct("calls", {"argv": []})
    assert record["invocation"] == fake_tool.UNKNOWN_INVOCATION
    assert "fake tool: calls log record lost" in capfd.readouterr().err


def test_an_unreachable_collector_falls_back_to_direct_logging(tmp_path: Path) -> None:
    tool = _proof_tool(tmp_path)
    script = json.loads(tool.script_path.read_text(encoding="utf-8"))
    script["log"] = "@polyhedraproof-fakes-nobody-listens"
    tool.script_path.write_text(json.dumps(script), encoding="utf-8")
    assert run(tool, "f", tmp_path / "proof", data=b"").returncode == 20
    assert [c["invocation"] for c in tool.calls()] == [0]
    assert [e["op"] for e in tool.events()] == ["read"]


def test_the_collector_accepts_records_only_for_tools_of_this_process(tmp_path: Path) -> None:
    tool = fk.make_tool(tmp_path, "tool", [])
    address = fk.collector().address
    stranger = tmp_path / "stranger"
    assert (
        fake_tool.ask_collector(address, {"tool": str(stranger), "kind": "calls", "record": {}})
        is None
    )
    assert not fake_tool.log_path(stranger, "calls").exists()
    bad_kind = {"tool": str(tool.path), "kind": "secrets", "record": {}}
    assert fake_tool.ask_collector(address, bad_kind) is None
    assert fk.collector().answer(b"not json")["ok"] is False
    assert fk.collector().answer(b'{"tool": 1}')["ok"] is False
    reply = fake_tool.ask_collector(
        address, {"tool": str(tool.path), "kind": "events", "record": {"op": "x"}}
    )
    assert reply == {"ok": True, "record": {"op": "x"}}
    assert tool.events() == [{"op": "x"}]
    assert tool.calls() == []


def test_closing_stdout_makes_later_writes_fail(tmp_path: Path) -> None:
    tool = fk.make_tool(tmp_path, "tool", [fk.close(1), fk.write(fk.STDOUT, "late")])
    result = run(tool)
    assert result.returncode == fake_tool.IO_ERROR
    assert result.stdout == b""
    assert tool.events()[-1]["errno"] == errno.EBADF


# -- input ------------------------------------------------------------------------------------


def test_reading_stdin_is_recorded(tmp_path: Path) -> None:
    tool = fk.make_tool(tmp_path, "tool", [fk.read(fk.STDIN)])
    data = os.urandom(300_000)
    assert run(tool, data=data).returncode == 0
    (event,) = tool.events()
    assert event == {
        "invocation": 0,
        "op": "read",
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "eof": True,
    }


def test_a_reader_that_stops_early_breaks_the_writers_pipe(tmp_path: Path) -> None:
    tool = fk.make_tool(tmp_path, "tool", [fk.read(fk.STDIN, limit=10, close=True), fk.sleep(5)])
    child = subprocess.Popen([str(tool.path)], stdin=subprocess.PIPE)
    assert child.stdin is not None
    with pytest.raises(BrokenPipeError):
        for _ in range(1000):
            child.stdin.write(b"x" * 65536)
            child.stdin.flush()
    # The fake logs its read after closing stdin, so the writer may see EPIPE first.
    wait_until(tool.events)
    child.kill()
    child.wait(timeout=TIMEOUT)
    with contextlib.suppress(BrokenPipeError):
        child.stdin.close()
    assert tool.events()[0]["bytes"] == 10
    assert tool.events()[0]["eof"] is False


def test_a_proof_can_be_read_from_a_fifo(tmp_path: Path) -> None:
    fifo = tmp_path / "proof.fifo"
    os.mkfifo(fifo)
    tool = fk.make_tool(tmp_path, "checker", [fk.read(fk.arg(-1)), fk.write(fk.STDOUT, "done\n")])
    child = subprocess.Popen([str(tool.path), "f.cnf", str(fifo)], stdout=subprocess.PIPE)
    data = b"3 0 1 2 0\n" * 1000
    with open(fifo, "wb") as stream:
        stream.write(data)
    out, _ = child.communicate(timeout=TIMEOUT)
    assert out == b"done\n"
    assert tool.events()[0]["sha256"] == hashlib.sha256(data).hexdigest()


def test_pipe_copies_flips_and_limits(tmp_path: Path) -> None:
    tool = fk.make_tool(
        tmp_path, "relay", [fk.pipe(fk.STDIN, fk.arg(-1), limit=100, flip_at=5, chunk=7)]
    )
    data = bytes(range(256))
    assert run(tool, tmp_path / "out", data=data).returncode == 0
    out = (tmp_path / "out").read_bytes()
    assert len(out) == 100
    assert out[5] == data[5] ^ 1
    assert out[:5] + out[6:] == data[:5] + data[6:100]
    event = tool.events()[0]
    assert (event["bytes"], event["eof"]) == (100, False)
    assert event["sha256"] == hashlib.sha256(data[:100]).hexdigest()


# -- control flow and signals ----------------------------------------------------------------


@pytest.mark.parametrize("name", ["SEGV", "ABRT", "KILL", "BUS"])
def test_kill_self(tmp_path: Path, name: str) -> None:
    tool = fk.make_tool(tmp_path, "tool", [fk.kill_self(name)])
    work = tmp_path / "work"
    work.mkdir()
    result = run(tool, cwd=work)
    assert result.returncode == -signal.Signals["SIG" + name]
    assert fk.signal_name(result.returncode) == name
    assert list(work.iterdir()) == []  # no core file


def test_signal_name_of_a_normal_exit() -> None:
    assert fk.signal_name(0) is None
    assert fk.signal_name(20) is None


def test_a_trapped_term_prints_and_dies(tmp_path: Path) -> None:
    ready = tmp_path / "ready"
    tool = fk.make_tool(
        tmp_path,
        "tool",
        [fk.trap("TERM", [fk.write(fk.STDOUT, "c UNKNOWN\n")]), fk.touch(ready), fk.sleep(30)],
    )
    child = subprocess.Popen([str(tool.path)], stdout=subprocess.PIPE)
    wait_until(ready.exists)
    assert int(ready.read_text()) == child.pid
    child.terminate()
    out, _ = child.communicate(timeout=TIMEOUT)
    assert (child.returncode, out) == (-signal.SIGTERM, b"c UNKNOWN\n")
    assert tool.events()[0]["op"] == "signal"


def test_an_ignored_term_needs_kill(tmp_path: Path) -> None:
    ready = tmp_path / "ready"
    tool = fk.make_tool(
        tmp_path, "tool", [fk.trap("TERM", then="continue"), fk.touch(ready), fk.sleep(30)]
    )
    child = subprocess.Popen([str(tool.path)])
    wait_until(ready.exists)
    child.terminate()
    with pytest.raises(subprocess.TimeoutExpired):
        child.wait(timeout=0.5)
    child.kill()
    assert child.wait(timeout=TIMEOUT) == -signal.SIGKILL


def test_a_trap_can_exit_with_a_code(tmp_path: Path) -> None:
    ready = tmp_path / "ready"
    tool = fk.make_tool(
        tmp_path, "tool", [fk.trap("INT", then="exit", code=7), fk.touch(ready), fk.sleep(30)]
    )
    child = subprocess.Popen([str(tool.path)])
    wait_until(ready.exists)
    child.send_signal(signal.SIGINT)
    assert child.wait(timeout=TIMEOUT) == 7


def test_an_untrapped_interrupt_kills_like_a_c_program(tmp_path: Path) -> None:
    ready = tmp_path / "ready"
    tool = fk.make_tool(tmp_path, "tool", [fk.touch(ready), fk.sleep(30)])
    child = subprocess.Popen([str(tool.path)], stderr=subprocess.PIPE)
    wait_until(ready.exists)
    child.send_signal(signal.SIGINT)
    _, err = child.communicate(timeout=TIMEOUT)
    assert child.returncode == -signal.SIGINT
    assert b"KeyboardInterrupt" not in err


def test_wait_for_proceeds_or_times_out(tmp_path: Path) -> None:
    go = tmp_path / "go"
    tool = fk.make_tool(tmp_path, "tool", [fk.wait_for(go, timeout=10), fk.exit_(5)])
    child = subprocess.Popen([str(tool.path)])
    time.sleep(0.2)
    assert child.poll() is None
    go.write_text("")
    assert child.wait(timeout=TIMEOUT) == 5
    late = fk.make_tool(tmp_path, "late", [fk.wait_for(tmp_path / "never", timeout=0.2)])
    result = run(late)
    assert result.returncode == fake_tool.WAIT_TIMEOUT
    assert b"timed out" in result.stderr


def test_cases_select_by_invocation_and_argv(tmp_path: Path) -> None:
    tool = fk.make_tool(
        tmp_path,
        "checker",
        [fk.exit_(9)],
        cases=[
            fk.case([fk.exit_(1)], invocation=0),
            fk.case([fk.exit_(0)], argv_contains="--CML_HEAP_SIZE=2048"),
        ],
    )
    assert run(tool, "--CML_HEAP_SIZE=2048").returncode == 1  # invocation 0 wins
    assert run(tool, "--CML_HEAP_SIZE=1024").returncode == 9
    assert run(tool, "--CML_HEAP_SIZE=2048").returncode == 0


def test_spawn_leaves_a_grandchild(tmp_path: Path, reap_pids: list[int]) -> None:
    pid_file = tmp_path / "grandchild"
    tool = fk.make_tool(tmp_path, "tool", [fk.spawn([fk.sleep(30)], pid_file=pid_file)])
    # Not captured: the grandchild inherits stdout/stderr and would hold the pipes open.
    result = subprocess.run([str(tool.path)], timeout=TIMEOUT, check=False)
    assert result.returncode == 0
    grandchild = int(pid_file.read_text())
    reap_pids.append(grandchild)
    assert alive(grandchild)
    assert tool.events()[0] == {"invocation": 0, "op": "spawn", "pid": grandchild}
    assert os.getpgid(grandchild) == tool.calls()[0]["pgid"]


def test_a_grandchild_keeps_the_output_pipe_open(tmp_path: Path, reap_pids: list[int]) -> None:
    pid_file = tmp_path / "grandchild"
    tool = fk.make_tool(tmp_path, "tool", [fk.spawn([fk.sleep(30)], pid_file=pid_file)])
    child = subprocess.Popen([str(tool.path)], stdout=subprocess.PIPE)
    assert child.wait(timeout=TIMEOUT) == 0
    grandchild = int(pid_file.read_text())
    reap_pids.append(grandchild)
    assert child.stdout is not None
    os.set_blocking(child.stdout.fileno(), False)
    assert child.stdout.read() is None  # no EOF: the grandchild still holds the write end
    os.kill(grandchild, signal.SIGKILL)
    os.set_blocking(child.stdout.fileno(), True)
    assert child.stdout.read() == b""
    child.stdout.close()


def test_spawn_with_setsid_escapes_the_process_group(tmp_path: Path, reap_pids: list[int]) -> None:
    pid_file = tmp_path / "grandchild"
    tool = fk.make_tool(
        tmp_path, "tool", [fk.spawn([fk.sleep(30)], setsid=True, pid_file=pid_file), fk.sleep(30)]
    )
    child = subprocess.Popen([str(tool.path)], start_new_session=True)
    wait_until(pid_file.exists)
    grandchild = int(pid_file.read_text())
    reap_pids.append(grandchild)
    wait_until(lambda: os.getsid(grandchild) == grandchild)
    os.killpg(child.pid, signal.SIGKILL)
    assert child.wait(timeout=TIMEOUT) == -signal.SIGKILL
    assert alive(grandchild)


def test_a_spawned_child_runs_its_own_steps(tmp_path: Path) -> None:
    marker = tmp_path / "marker"
    tool = fk.make_tool(
        tmp_path,
        "tool",
        [fk.spawn([fk.write(fk.path(marker), "child"), fk.exit_(3)]), fk.wait_for(marker)],
    )
    assert run(tool).returncode == 0
    assert marker.read_text() == "child"


def test_a_waited_child_reports_its_exit_and_script_errors_exit_97(tmp_path: Path) -> None:
    tool = fk.make_tool(
        tmp_path,
        "tool",
        [
            fk.spawn([fk.exit_(4)], wait=True),
            fk.spawn([fk.write(fk.arg(5), "x")], wait=True),  # no argument 5: script error
            fk.spawn([fk.close(1000)], wait=True),  # EBADF: an I/O error of a step
            fk.spawn([fk.kill_self("TERM")], wait=True),
        ],
    )
    result = run(tool)
    assert result.returncode == 0
    assert [e["returncode"] for e in tool.events()] == [
        4,
        fake_tool.BAD_SCRIPT,
        fake_tool.IO_ERROR,
        -signal.SIGTERM,
    ]
    assert b"bad script: no argument 5" in result.stderr


# -- altering files --------------------------------------------------------------------------


def test_alter_actions(tmp_path: Path) -> None:
    files = {name: tmp_path / name for name in ("a", "t", "f", "d", "r", "c")}
    for path in files.values():
        path.write_bytes(b"0123456789")
    inode = files["r"].stat().st_ino
    tool = fk.make_tool(
        tmp_path,
        "tool",
        [
            fk.alter(fk.path(files["a"]), "append", text="+"),
            fk.alter(fk.path(files["t"]), "truncate", size=4),
            fk.alter(fk.path(files["f"]), "flip", offset=2),
            fk.alter(fk.path(files["d"]), "delete"),
            fk.alter(fk.path(files["r"]), "replace", text="new"),
            fk.alter(fk.path(files["c"]), "chmod", mode=0o400),
        ],
    )
    assert run(tool).returncode == 0
    assert files["a"].read_bytes() == b"0123456789+"
    assert files["t"].read_bytes() == b"0123"
    assert files["f"].read_bytes() == b"0133456789"  # "2" is 0x32, flipped to 0x33
    assert not files["d"].exists()
    assert files["r"].read_bytes() == b"new"
    assert files["r"].stat().st_ino != inode
    assert stat.S_IMODE(files["c"].stat().st_mode) == 0o400
    assert [e["action"] for e in tool.events()] == [
        "append",
        "truncate",
        "flip",
        "delete",
        "replace",
        "chmod",
    ]


def test_flipping_beyond_the_end_is_a_script_error(tmp_path: Path) -> None:
    (tmp_path / "short").write_bytes(b"x")
    tool = fk.make_tool(tmp_path, "tool", [fk.alter(fk.arg(0), "flip", offset=5)])
    assert run(tool, tmp_path / "short").returncode == fake_tool.BAD_SCRIPT


# -- built-in checker, solver and exec ---------------------------------------------------------


def test_lrat_check_answers_like_cake_lpr(tmp_path: Path) -> None:
    tool = fk.make_tool(tmp_path, "checker", [fk.lrat_check()])
    good = run(tool, "--CML_HEAP_SIZE=64", fixture("unsat.cnf"), fixture("unsat.lrat"))
    assert (good.returncode, good.stdout, good.stderr) == (0, b"s VERIFIED UNSAT\n", b"")
    bad = run(tool, fixture("unsat.cnf"), fixture("bad-hint.lrat"))
    assert (bad.returncode, bad.stdout) == (0, b"")
    assert bad.stderr.startswith(b"c Checking failed: ")


def test_model_brute_forces_tiny_formulas(tmp_path: Path) -> None:
    tool = fk.make_tool(tmp_path, "solver", [fk.model(fk.arg(0))])
    sat = run(tool, fixture("sat.cnf"))
    assert (sat.returncode, sat.stdout) == (10, b"s SATISFIABLE\nv -1 2 3 0\n")
    unsat = run(tool, fixture("unsat.cnf"))
    assert (unsat.returncode, unsat.stdout) == (20, b"s UNSATISFIABLE\n")


def test_exec_replaces_the_process(tmp_path: Path) -> None:
    inner = fk.make_tool(tmp_path, "inner", [fk.exit_(4)])
    outer = fk.make_tool(
        tmp_path, "outer", [fk.exec_([str(inner.path), "--from-outer"], pass_args=True)]
    )
    assert run(outer, "x").returncode == 4
    assert inner.calls()[0]["argv"] == ["--from-outer", "x"]
    assert inner.calls()[0]["pid"] == outer.calls()[0]["pid"]


def test_the_engine_is_stdlib_only_and_runs_isolated(tmp_path: Path) -> None:
    tool = fk.make_tool(tmp_path, "tool", [fk.write(fk.STDOUT, "ok")])
    first_line = tool.path.read_text(encoding="utf-8").splitlines()[0]
    assert first_line == f"#!{sys.executable} -IS"
    env = {"PATH": os.environ.get("PATH", ""), "PYTHONPATH": "/nonexistent"}
    assert run(tool, env=env).stdout == b"ok"
    script = json.loads(tool.script_path.read_text(encoding="utf-8"))
    assert Path(script["lib"]) == Path(fake_tool.__file__).resolve().parents[1]
