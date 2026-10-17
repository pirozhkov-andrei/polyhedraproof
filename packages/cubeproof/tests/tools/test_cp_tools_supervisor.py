"""The process supervisor with real child processes (the fake tools): specification §6.2, §4.6.

Observed from inside the child (the fake logs it): own session and process group, the
parent-death signal KILL, the address-space/file-size/core limits, a minimal environment,
the working directory, stdin from /dev/null and no inherited descriptors. Observed from
outside: monotonic deadlines with TERM then KILL after the grace, user cancellation,
bounded draining of floods, typed causes, reaping, killing of descendants, output held open
by an escaped descendant, the death of the tool with its coordinator, binary changes.
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import textwrap
import time
from pathlib import Path

import pytest
from cp_tools_support import (  # noqa: F401 - the two fixtures are registered by import
    FAKE_MEMORY,
    REPO,
    alive,
    assert_fds_return_to,
    fk,
    isolation_fixture,
    launch,
    linux_only,
    make_binary,
    open_fds,
    p,
    pid_of,
    run_one,
    supervisor_fixture,
    wait_until,
)

from cubeproof.base.errors import ToolError
from cubeproof.base.process import TAIL_BYTES, Cause
from cubeproof.tools.isolation import Isolation, PinnedBinary
from cubeproof.tools.process import Launch, Supervisor

pytestmark = linux_only


def test_the_child_runs_isolated(supervisor: Supervisor, tmp_path: Path) -> None:
    tool, binary = make_binary(
        tmp_path,
        "tool",
        [fk.read(fk.STDIN), fk.exit_(0)],
        record_env=["PATH", "HOME", "LC_ALL", "CADICAL_ELIM", "PYTHONPATH"],
    )
    work = tmp_path / "work"
    work.mkdir()
    spec = launch(binary, ["--x", "a b"], work, memory_bytes=3 << 30, file_bytes=1 << 20)
    run = run_one(supervisor, spec)
    assert run.result.exit == 0 and run.result.started
    call = tool.calls()[0]
    assert call["argv"] == ["--x", "a b"]  # the fake records argv without argv[0]
    assert call["cwd"] == str(work)
    assert call["pgid"] == call["pid"] == call["sid"]
    assert call["pdeathsig"] == signal.SIGKILL
    assert call["rlimits"]["as"] == 3 << 30
    assert call["rlimits"]["fsize"] == 1 << 20
    assert call["rlimits"]["core"] == 0
    assert call["env"] == {
        "PATH": None,
        "HOME": None,
        "LC_ALL": "C",
        "CADICAL_ELIM": None,
        "PYTHONPATH": None,
    }
    assert call["fds"] == [0, 1, 2]
    # stdin was /dev/null: the read ended at once
    reads = [e for e in tool.events() if e["op"] == "read"]
    assert reads and reads[0]["bytes"] == 0


def test_without_a_file_cap_the_file_size_is_unlimited(
    supervisor: Supervisor, tmp_path: Path
) -> None:
    tool, binary = make_binary(tmp_path, "tool", [fk.exit_(0)])
    run_one(supervisor, launch(binary, [], tmp_path))
    assert tool.calls()[0]["rlimits"]["fsize"] == -1


def test_exit_status_tails_and_counts(supervisor: Supervisor, tmp_path: Path) -> None:
    _, binary = make_binary(
        tmp_path,
        "tool",
        [fk.write(fk.STDOUT, "out\n"), fk.write(fk.STDERR, "err\n"), fk.exit_(7)],
    )
    run = run_one(supervisor, launch(binary, [], tmp_path))
    value = run.result
    assert (value.exit, value.signal, value.stdout_tail, value.stderr_tail) == (
        7,
        None,
        "out\n",
        "err\n",
    )
    assert (value.stdout_bytes, value.stdout_truncated, value.cause) == (4, False, None)
    assert run.causes == ()
    assert value.elapsed_ms >= 0


def test_the_usage_of_a_reaped_process_is_what_the_kernel_reports(
    supervisor: Supervisor, tmp_path: Path
) -> None:
    """Processor time and peak resident memory come from ``wait4`` and count from the fork, so
    a peak is not far below what this process had resident at the launch (``launch_rss_kib``).
    Oracles that follow the size of the test process: a child that fills 300 MiB more than
    this process holds peaks above that, far above a child that exits at once; a child that
    computes for half a second of its own processor time used at least that much more."""
    python = PinnedBinary.measure(os.path.realpath(sys.executable))
    spin = "import time\nt = time.process_time()\nwhile time.process_time() - t < 0.5: pass\n"
    with open("/proc/self/statm", encoding="ascii") as stream:
        here_mib = int(stream.read().split()[1]) * os.sysconf("SC_PAGE_SIZE") >> 20
    fill_mib = here_mib + 300  # clearly above the floor, whatever this test process holds
    fill = f"x = bytearray(b'\\x01') * ({fill_mib} << 20)\n"
    quick = run_one(supervisor, launch(python, ["-I", "-c", "raise SystemExit(0)"], tmp_path))
    busy = run_one(
        supervisor, launch(python, ["-I", "-c", spin + fill + "raise SystemExit(3)"], tmp_path)
    )
    for run in (quick, busy):
        assert run.cpu_ms is not None and run.max_rss_kib is not None
        assert run.launch_rss_kib is not None and run.launch_rss_kib > 1024
        # the floor: most of the parent's pages are the child's at the fork (not the file pages)
        assert run.max_rss_kib >= run.launch_rss_kib // 2
    assert quick.max_rss_kib is not None and busy.max_rss_kib is not None
    assert busy.max_rss_kib > fill_mib * 1024  # the tool's own peak, above the floor
    assert busy.max_rss_kib > quick.max_rss_kib + 200 * 1024
    assert quick.max_rss_kib < (here_mib + 100) * 1024  # the quick child stays at the floor
    assert quick.cpu_ms is not None and busy.cpu_ms is not None
    assert busy.cpu_ms >= quick.cpu_ms + 400
    assert (quick.result.exit, busy.result.exit, busy.result.signal) == (0, 3, None)
    killed = run_one(
        supervisor,
        launch(
            python,
            ["-I", "-c", "import os, signal\nos.kill(os.getpid(), signal.SIGKILL)"],
            tmp_path,
        ),
    )
    assert (killed.result.exit, killed.result.signal) == (None, signal.SIGKILL)
    assert killed.cpu_ms is not None  # a signal death is reaped and measured like an exit


def test_the_reaped_status_is_handed_to_the_process_object(
    supervisor: Supervisor, tmp_path: Path
) -> None:
    """The supervisor reaps with ``wait4``; the ``Popen`` object must know the status, or it
    would wait for a child that is gone and report 0."""
    python = PinnedBinary.measure(os.path.realpath(sys.executable))
    process = supervisor.start(launch(python, ["-I", "-c", "raise SystemExit(7)"], tmp_path))
    while process.run is None:
        supervisor.step(50)
    assert process.run.result.exit == 7
    assert process._popen is not None and process._popen.returncode == 7
    assert process._popen.poll() == 7 and process._popen.wait() == 7


def test_a_signal_death_is_reported_as_a_signal(supervisor: Supervisor, tmp_path: Path) -> None:
    _, binary = make_binary(tmp_path, "tool", [fk.kill_self("SEGV")])
    run = run_one(supervisor, launch(binary, [], tmp_path))
    assert (run.result.exit, run.result.signal, run.causes) == (None, signal.SIGSEGV, ())


def test_the_deadline_sends_term_and_records_the_cause(
    supervisor: Supervisor, tmp_path: Path
) -> None:
    _, binary = make_binary(tmp_path, "solver", p.solver_until_terminated(60))
    started = time.monotonic()
    spec = launch(binary, [], tmp_path, deadline_ms=400, term_grace_ms=5000)
    run = run_one(supervisor, spec)
    assert time.monotonic() - started < 5
    assert run.result.signal == signal.SIGTERM
    assert run.causes == (Cause.DEADLINE,)
    assert run.result.cause == "deadline"
    assert run.result.stdout_tail == p.CADICAL_TERM_STDOUT.decode()
    assert run.result.elapsed_ms >= 400


def test_term_is_followed_by_kill_after_the_grace(supervisor: Supervisor, tmp_path: Path) -> None:
    ready = tmp_path / "ready"
    _, binary = make_binary(tmp_path, "solver", p.solver_ignoring_term(60, ready=str(ready)))
    spec = launch(binary, [], tmp_path, deadline_ms=300, term_grace_ms=300)
    run = run_one(supervisor, spec)
    assert ready.exists()
    assert run.result.signal == signal.SIGKILL
    assert run.causes == (Cause.DEADLINE,)
    assert run.result.elapsed_ms >= 600


def test_user_cancellation_is_a_typed_cause(supervisor: Supervisor, tmp_path: Path) -> None:
    ready = tmp_path / "ready"
    _, binary = make_binary(tmp_path, "solver", p.solver_ignoring_term(60, ready=str(ready)))
    process = supervisor.start(launch(binary, [], tmp_path))
    wait_until(ready.exists)
    supervisor.cancel(process, grace_ms=200)
    while process.run is None:
        supervisor.step(50)
    assert process.run.causes == (Cause.CANCELLED,)
    assert process.run.result.signal == signal.SIGKILL
    assert not supervisor.stopping  # cancelling one process is not a user stop


def test_a_stopping_supervisor_launches_nothing(supervisor: Supervisor, tmp_path: Path) -> None:
    _, binary = make_binary(tmp_path, "tool", [fk.exit_(0)])
    supervisor.stop(grace_ms=100)
    process = supervisor.start(launch(binary, [], tmp_path))
    assert process.run is not None
    assert not process.run.result.started
    assert process.run.causes == (Cause.CANCELLED,)


def test_floods_are_drained_and_bounded(supervisor: Supervisor, tmp_path: Path) -> None:
    size = 8 << 20
    _, binary = make_binary(tmp_path, "checker", p.checker_flood(size), python_signals=False)
    proof = tmp_path / "proof"
    proof.write_bytes(b"x")
    run = run_one(supervisor, launch(binary, ["cnf", str(proof)], tmp_path))
    value = run.result
    assert value.exit == 0
    assert value.stdout_bytes == size + len(p.CHECKER_SUCCESS)
    assert value.stdout_truncated
    assert value.stdout_tail.endswith(p.CHECKER_SUCCESS.decode())
    assert len(value.stdout_tail.encode()) <= TAIL_BYTES
    assert run.stdout is None  # nothing captured beyond the bound


def test_stderr_flood_is_bounded(supervisor: Supervisor, tmp_path: Path) -> None:
    _, binary = make_binary(tmp_path, "tool", [fk.write(fk.STDERR, "e", size=1 << 20), fk.exit_(0)])
    run = run_one(supervisor, launch(binary, [], tmp_path))
    assert len(run.result.stderr_tail.encode()) <= TAIL_BYTES
    assert run.stderr_truncated
    assert run.result.stdout_bytes == 0


def test_stdout_capture_for_models(supervisor: Supervisor, tmp_path: Path) -> None:
    _, binary = make_binary(tmp_path, "solver", p.solver_sat([1, -2, 3]))
    run = run_one(supervisor, launch(binary, [], tmp_path, stdout_capture=1 << 20))
    assert run.result.exit == 10
    assert run.stdout == b"s SATISFIABLE\nv 1 -2 3 0\n"


def test_descendants_in_the_group_die_with_the_leader(
    supervisor: Supervisor, tmp_path: Path
) -> None:
    pid_file = tmp_path / "grandchild.pid"
    _, binary = make_binary(
        tmp_path, "tool", [fk.spawn([fk.sleep(60)], pid_file=str(pid_file)), fk.exit_(0)]
    )
    run = run_one(supervisor, launch(binary, [], tmp_path, eof_grace_ms=5000))
    assert run.result.exit == 0
    grandchild = pid_of(pid_file)
    wait_until(lambda: not alive(grandchild), 10)
    assert Cause.HELD_OPEN not in run.causes


def test_descendants_die_on_deadline(supervisor: Supervisor, tmp_path: Path) -> None:
    pid_file = tmp_path / "grandchild.pid"
    _, binary = make_binary(tmp_path, "solver", p.solver_with_grandchild(str(pid_file), 60))
    spec = launch(binary, [], tmp_path, deadline_ms=500, term_grace_ms=300)
    run = run_one(supervisor, spec)
    assert run.causes[0] is Cause.DEADLINE
    grandchild = pid_of(pid_file)
    wait_until(lambda: not alive(grandchild), 10)


def test_an_escaped_descendant_holding_the_output_is_reported(
    supervisor: Supervisor, tmp_path: Path
) -> None:
    pid_file = tmp_path / "escaped.pid"
    _, binary = make_binary(
        tmp_path,
        "tool",
        [fk.spawn([fk.sleep(60)], setsid=True, pid_file=str(pid_file)), fk.exit_(0)],
    )
    try:
        run = run_one(supervisor, launch(binary, [], tmp_path, eof_grace_ms=300))
        assert run.result.exit == 0
        assert Cause.HELD_OPEN in run.causes
    finally:
        if pid_file.exists():
            escaped = pid_of(pid_file)
            if alive(escaped):
                os.kill(escaped, signal.SIGKILL)


def test_every_child_is_reaped(supervisor: Supervisor, tmp_path: Path) -> None:
    _, binary = make_binary(tmp_path, "tool", [fk.exit_(3)])
    process = supervisor.start(launch(binary, [], tmp_path))
    pid = process.pid
    assert pid is not None
    while process.run is None:
        supervisor.step(50)
    with pytest.raises(ChildProcessError):
        os.waitpid(pid, os.WNOHANG)
    assert not Path(f"/proc/{pid}").exists() or not alive(pid)


def test_several_processes_at_once(supervisor: Supervisor, tmp_path: Path) -> None:
    processes = []
    for code in (0, 1, 2):
        _, binary = make_binary(
            tmp_path / str(code),
            "tool",
            [fk.sleep(0.1 * code), fk.write(fk.STDOUT, "x"), fk.exit_(code)],
        )
        processes.append(supervisor.start(launch(binary, [], tmp_path)))
    deadline = time.monotonic() + 30
    while any(proc.run is None for proc in processes):
        assert time.monotonic() < deadline
        supervisor.step(50)
    assert [proc.run.result.exit for proc in processes if proc.run] == [0, 1, 2]
    assert not supervisor.active


def test_the_proof_cap_is_observed_while_running(supervisor: Supervisor, tmp_path: Path) -> None:
    proof = tmp_path / "proof.lrat"
    _, binary = make_binary(
        tmp_path, "solver", [fk.write(fk.arg(-1), "1 0\n", size=64 * 1024), fk.sleep(60)]
    )
    spec = launch(binary, [str(proof)], tmp_path, watch=(str(proof), 64 * 1024), term_grace_ms=200)
    run = run_one(supervisor, spec)
    assert run.causes[0] is Cause.PROOF_CAP
    assert run.result.cause == "proof_cap"
    assert run.result.signal in (signal.SIGTERM, signal.SIGKILL)


def test_a_small_file_does_not_trigger_the_cap(supervisor: Supervisor, tmp_path: Path) -> None:
    proof = tmp_path / "proof.lrat"
    _, binary = make_binary(tmp_path, "solver", p.solver_unsat(b"1 0 1 0\n"))
    run = run_one(supervisor, launch(binary, [str(proof)], tmp_path, watch=(str(proof), 9)))
    assert (run.result.exit, run.causes) == (20, ())


def test_the_file_size_limit_kills_by_sigxfsz(supervisor: Supervisor, tmp_path: Path) -> None:
    proof = tmp_path / "proof.lrat"
    _, binary = make_binary(tmp_path, "solver", p.solver_proof_flood(1 << 20))
    run = run_one(supervisor, launch(binary, [str(proof)], tmp_path, file_bytes=4096))
    assert run.result.signal == signal.SIGXFSZ
    assert proof.stat().st_size == 4096


def test_a_binary_changed_before_the_spawn_is_not_started(
    supervisor: Supervisor, tmp_path: Path
) -> None:
    tool, binary = make_binary(tmp_path, "tool", [fk.exit_(0)])
    with tool.path.open("a", encoding="utf-8") as handle:
        handle.write("# changed\n")
    run = run_one(supervisor, launch(binary, [], tmp_path))
    assert not run.result.started
    assert run.causes == (Cause.BINARY_CHANGED,)
    assert tool.calls() == []


def test_a_missing_binary_is_a_binary_change(supervisor: Supervisor, tmp_path: Path) -> None:
    tool, binary = make_binary(tmp_path, "tool", [fk.exit_(0)])
    tool.path.unlink()
    run = run_one(supervisor, launch(binary, [], tmp_path))
    assert (run.result.started, run.causes) == (False, (Cause.BINARY_CHANGED,))


def test_a_binary_changed_during_the_run_is_detected_after_exit(
    supervisor: Supervisor, tmp_path: Path
) -> None:
    target = tmp_path / "tool"
    _, binary = make_binary(tmp_path, "tool", [fk.alter(fk.path(target), "append"), fk.exit_(0)])
    run = run_one(supervisor, launch(binary, [], tmp_path))
    assert run.result.started and run.result.exit == 0
    assert Cause.BINARY_CHANGED in run.causes


def test_a_launch_failure_is_typed(supervisor: Supervisor, tmp_path: Path) -> None:
    _, binary = make_binary(tmp_path, "tool", [fk.exit_(0)])
    run = run_one(supervisor, launch(binary, [], tmp_path / "missing-directory"))
    assert not run.result.started
    assert run.causes == (Cause.LAUNCH,)
    assert run.result.exit is None and run.result.signal is None


def test_failed_launches_and_finished_runs_leak_no_descriptors(
    supervisor: Supervisor, tmp_path: Path
) -> None:
    """A missing binary or a failed spawn leaves no pipe open."""
    _, binary = make_binary(tmp_path, "tool", [fk.write(fk.STDOUT, "x"), fk.exit_(0)])
    run_one(supervisor, launch(binary, [], tmp_path))  # warm up lazily opened descriptors
    before = open_fds()
    for _ in range(3):
        run_one(supervisor, launch(binary, [], tmp_path / "missing"))  # Popen fails
        run_one(supervisor, launch(binary, [], tmp_path))  # a normal run
    missing, missing_binary = make_binary(tmp_path / "gone", "tool", [fk.exit_(0)])
    missing.path.unlink()
    run_one(supervisor, launch(missing_binary, [], tmp_path))
    # The fakes' log collector may hold a connection for a moment; a leak would stay.
    assert_fds_return_to(before)


def test_a_memory_event_reported_by_the_coordinator_is_kept(
    supervisor: Supervisor, tmp_path: Path
) -> None:
    ready = tmp_path / "ready"
    _, binary = make_binary(tmp_path, "solver", p.solver_until_terminated(60, ready=str(ready)))
    process = supervisor.start(launch(binary, [], tmp_path))
    wait_until(ready.exists)
    supervisor.note(process, Cause.MEMORY_EVENT)
    assert process.pid is not None
    os.kill(process.pid, signal.SIGKILL)  # what the OOM killer would do
    while process.run is None:
        supervisor.step(50)
    assert process.run.causes == (Cause.MEMORY_EVENT,)
    assert process.run.result.signal == signal.SIGKILL


def test_deadlines_follow_the_supervisor_clock(isolation: Isolation, tmp_path: Path) -> None:
    now = [10**12]
    supervisor = Supervisor(isolation, clock=lambda: now[0])
    try:
        ready = tmp_path / "ready"
        _, binary = make_binary(tmp_path, "solver", p.solver_until_terminated(60, ready=str(ready)))
        process = supervisor.start(launch(binary, [], tmp_path, deadline_ms=1000))
        wait_until(ready.exists)
        for _ in range(5):
            supervisor.step(20)
        assert process.run is None  # wall time passes, the injected clock does not
        now[0] += 1000 * 10**6
        while process.run is None:
            supervisor.step(50)
        assert process.run.causes == (Cause.DEADLINE,)
        assert process.run.result.elapsed_ms == 1000
    finally:
        supervisor.shutdown(grace_ms=100)


def zombie(pid: int) -> bool:
    try:
        with open(f"/proc/{pid}/stat", encoding="ascii") as handle:
            return handle.read().rsplit(")", 1)[1].split()[0] == "Z"
    except (FileNotFoundError, ProcessLookupError):
        return False


def test_an_exit_noticed_late_is_not_charged_with_limits(
    isolation: Isolation, tmp_path: Path
) -> None:
    """The coordinator was busy past the deadline; the tool had already finished."""
    now = [10**12]
    supervisor = Supervisor(isolation, clock=lambda: now[0])
    try:
        proof = tmp_path / "proof"
        _, binary = make_binary(tmp_path, "tool", [fk.write(fk.arg(-1), "x" * 64), fk.exit_(0)])
        spec = launch(binary, [str(proof)], tmp_path, deadline_ms=1000, watch=(str(proof), 64))
        process = supervisor.start(spec)
        assert process.pid is not None
        pid = process.pid
        wait_until(lambda: zombie(pid))
        now[0] += 5000 * 10**6
        while process.run is None:
            supervisor.step(50)
        assert process.run.causes == ()
        assert process.run.result.exit == 0
    finally:
        supervisor.shutdown(grace_ms=100)


def test_a_status_lost_to_another_reaper_is_unknown(supervisor: Supervisor, tmp_path: Path) -> None:
    """Popen reports 0 for a child it cannot wait for; that must not become exit 0."""
    _, binary = make_binary(tmp_path, "checker", [*p.checker_output(p.CHECKER_SUCCESS)[1:]])
    process = supervisor.start(launch(binary, ["/c", "/p"], tmp_path))
    assert process.pid is not None
    pid = process.pid
    wait_until(lambda: zombie(pid))
    os.waitpid(pid, 0)  # someone else reaps our child
    while process.run is None:
        supervisor.step(50)
    value = process.run.result
    assert value.started
    assert (value.exit, value.signal) == (None, None)
    assert value.stdout_tail == p.CHECKER_SUCCESS.decode()
    from cubeproof.tools.checker import accepts

    assert not accepts(value)


def test_the_default_clock_is_monotonic(isolation: Isolation) -> None:
    supervisor = Supervisor(isolation)
    assert supervisor.clock is time.monotonic_ns
    supervisor.shutdown(grace_ms=10)


def test_shutdown_kills_and_reaps_everything(isolation: Isolation, tmp_path: Path) -> None:
    ready = tmp_path / "ready"
    _, binary = make_binary(tmp_path, "solver", p.solver_ignoring_term(60, ready=str(ready)))
    before = open_fds()
    supervisor = Supervisor(isolation)
    process = supervisor.start(launch(binary, [], tmp_path))
    wait_until(ready.exists)
    pid = process.pid
    assert pid is not None
    supervisor.shutdown(grace_ms=100)
    assert process.run is not None
    assert process.run.causes == (Cause.CANCELLED,)
    assert not alive(pid)
    # pipes, pidfd and the selector itself are released (collector sockets may linger briefly)
    assert_fds_return_to(before)
    assert supervisor.step(10) == []
    late = supervisor.start(launch(binary, [], tmp_path))
    assert late.run is not None and late.run.causes == (Cause.CANCELLED,)


def test_launch_values_are_validated(tmp_path: Path) -> None:
    _, binary = make_binary(tmp_path, "tool", [fk.exit_(0)])
    for changes in (
        {"cwd": "relative"},
        {"memory_bytes": 0},
        {"file_bytes": 0},
        {"deadline_ms": 0},
        {"term_grace_ms": 0},
        {"stdout_capture": -1},
        {"tail_bytes": 0},
        {"watch": ("relative", 5)},
        {"watch": ("/abs", 0)},
        {"args": ("ok", "nul\0")},
    ):
        values = {"binary": binary, "args": (), "cwd": str(tmp_path), "memory_bytes": FAKE_MEMORY}
        values.update(changes)
        with pytest.raises(ValueError):
            Launch(**values)  # type: ignore[arg-type]


# -- the coordinator dies -----------------------------------------------------------------------

COORDINATOR = textwrap.dedent(
    """
    import sys, time
    sys.path.insert(0, {src!r})
    from cubeproof.tools.isolation import Isolation, PinnedBinary
    from cubeproof.tools.process import Launch, Supervisor
    supervisor = Supervisor(Isolation.probe())
    binary = PinnedBinary.measure({tool!r})
    supervisor.start(Launch(binary=binary, args=(), cwd={cwd!r}, memory_bytes={memory}))
    while True:
        supervisor.step(100)
    """
)


def test_the_tool_dies_with_its_coordinator(tmp_path: Path) -> None:
    ready = tmp_path / "ready"
    tool, _ = make_binary(tmp_path, "solver", p.solver_ignoring_term(120, ready=str(ready)))
    script = tmp_path / "coordinator.py"
    script.write_text(
        COORDINATOR.format(
            src=str(REPO / "packages" / "cubeproof" / "src"),
            tool=str(tool.path),
            cwd=str(tmp_path),
            memory=FAKE_MEMORY,
        ),
        encoding="utf-8",
    )
    coordinator = subprocess.Popen([sys.executable, "-I", str(script)])
    try:
        wait_until(ready.exists, 30)
        tool_pid = pid_of(ready)
        assert alive(tool_pid)
        coordinator.kill()  # SIGKILL: no Python cleanup runs in the coordinator
        coordinator.wait(timeout=30)
        wait_until(lambda: not alive(tool_pid), 10)
    finally:
        if coordinator.poll() is None:
            coordinator.kill()
            coordinator.wait()


LAUNCHING_COORDINATOR = textwrap.dedent(
    """
    import sys, time
    sys.path.insert(0, {src!r})
    from cubeproof.tools.isolation import Isolation, PinnedBinary
    from cubeproof.tools.process import Launch, Supervisor
    supervisor = Supervisor(Isolation({setpriv!r}, Isolation.probe().prlimit))
    binary = PinnedBinary.measure({tool!r})
    process = supervisor.start(Launch(binary=binary, args=(), cwd={cwd!r}, memory_bytes={memory}))
    print(process.pid, flush=True)
    while True:
        supervisor.step(100)
    """
)

SLOW_SETPRIV = (
    '#!/bin/sh\n: > {entered}\nwhile [ ! -e {go} ]; do sleep 0.02; done\nexec {setpriv} "$@"\n'
)


def test_the_tool_dies_with_a_coordinator_killed_while_it_launches(tmp_path: Path) -> None:
    """The coordinator dies after the fork of a tool and before ``setpriv`` has set the
    parent-death signal (here ``setpriv`` waits for a file, so the window is as long as the
    test needs; in a run it is the start of ``setpriv``, well under a millisecond per launch).
    ``setpriv`` sets the signal without looking at its parent, so by itself it leaves the
    tool running without a supervisor: the forked child must have set the signal and checked
    its parent before."""
    ready, entered, go = tmp_path / "ready", tmp_path / "entered", tmp_path / "go"
    tool, _ = make_binary(tmp_path, "solver", p.solver_ignoring_term(120, ready=str(ready)))
    slow = tmp_path / "slow-setpriv"
    slow.write_text(
        SLOW_SETPRIV.format(entered=entered, go=go, setpriv=Isolation.probe().setpriv),
        encoding="utf-8",
    )
    slow.chmod(0o755)
    script = tmp_path / "coordinator.py"
    script.write_text(
        LAUNCHING_COORDINATOR.format(
            src=str(REPO / "packages" / "cubeproof" / "src"),
            setpriv=str(slow),
            tool=str(tool.path),
            cwd=str(tmp_path),
            memory=FAKE_MEMORY,
        ),
        encoding="utf-8",
    )
    coordinator = subprocess.Popen(
        [sys.executable, "-I", str(script)], stdout=subprocess.PIPE, start_new_session=True
    )
    tool_pid = None
    try:
        assert coordinator.stdout is not None
        tool_pid = int(coordinator.stdout.readline())
        wait_until(entered.exists, 30)  # the child runs the wrapper chain: the fork is over
        assert alive(tool_pid) and not ready.exists()
        # a crash of the whole run, as the end-to-end tests do it; the tool has its own group
        os.killpg(coordinator.pid, signal.SIGKILL)
        coordinator.wait(timeout=30)
        go.touch()  # setpriv may start now: its parent is dead already
        wait_until(lambda: not alive(tool_pid), 10)
        assert not ready.exists()  # the tool itself never ran
    finally:
        go.touch()
        if coordinator.poll() is None:
            coordinator.kill()
            coordinator.wait()
        if tool_pid is not None and alive(tool_pid):
            os.killpg(tool_pid, signal.SIGKILL)


def test_a_child_whose_parent_is_not_its_supervisor_executes_nothing(tmp_path: Path) -> None:
    """The other half of the launch window: the supervisor died before the forked child set
    the parent-death signal, so the kernel will never send it. The child then has another
    parent (init or a subreaper) than the process that forked it; here the guard is given a
    process ID that is not the parent's, and the child must end before it executes anything."""
    from cubeproof.tools.process import _parent_death_guard

    marker = tmp_path / "executed"
    command = ["/bin/sh", "-c", f": > {marker}"]
    stranger = _parent_death_guard(1)  # this test is not process 1
    assert stranger is not None
    with pytest.raises(subprocess.SubprocessError):
        subprocess.Popen(command, preexec_fn=stranger)  # noqa: PLW1509 - the guard under test
    assert not marker.exists()
    mine = _parent_death_guard(os.getpid())
    assert mine is not None
    assert subprocess.run(command, preexec_fn=mine, check=False).returncode == 0
    assert marker.exists()


# -- pinned binaries and the isolation probe ---------------------------------------------------


def test_isolation_wraps_with_setpriv_and_prlimit(isolation: Isolation) -> None:
    wrapped = isolation.wrap("/opt/t/cadical", ("--lrat", "a"), memory_bytes=1 << 30, file_bytes=99)
    assert wrapped == [
        isolation.setpriv,
        "--pdeathsig",
        "KILL",
        "--",
        isolation.prlimit,
        f"--as={1 << 30}",
        "--fsize=99",
        "--core=0",
        "--",
        "/opt/t/cadical",
        "--lrat",
        "a",
    ]
    no_fsize = isolation.wrap("/opt/t/x", (), memory_bytes=5, file_bytes=None)
    assert "--fsize=99" not in no_fsize and not any(a.startswith("--fsize") for a in no_fsize)
    assert os.path.isabs(isolation.setpriv) and os.path.isabs(isolation.prlimit)


def test_isolation_probe_refuses_missing_or_broken_wrappers(tmp_path: Path) -> None:
    with pytest.raises(ToolError):
        Isolation.probe(setpriv=str(tmp_path / "no-setpriv"))
    broken = fk.make_tool(
        tmp_path, "setpriv", [fk.write(fk.STDERR, "unknown option\n"), fk.exit_(1)]
    )
    with pytest.raises(ToolError):
        Isolation.probe(setpriv=str(broken.path))
    with pytest.raises(ToolError):
        Isolation.probe(prlimit=str(tmp_path / "no-prlimit"))


def test_pinned_binaries_are_measured_regular_files(tmp_path: Path) -> None:
    import hashlib

    tool = fk.make_tool(tmp_path, "tool", [fk.exit_(0)])
    binary = PinnedBinary.measure(str(tool.path))
    assert binary.sha256 == hashlib.sha256(tool.path.read_bytes()).hexdigest()
    assert binary.path == str(tool.path)
    link = tmp_path / "link"
    link.symlink_to(tool.path)
    assert PinnedBinary.measure(str(link)) == binary  # the actual regular file (specification §4.6)
    binary.verify()
    assert PinnedBinary.pinned(str(tool.path), binary.sha256) == binary
    with pytest.raises(ToolError) as caught:
        PinnedBinary.pinned(str(tool.path), "0" * 64)
    assert caught.value.rule == "tool.hash_mismatch"


@pytest.mark.parametrize("problem", ["missing", "directory", "not_executable", "fifo"])
def test_unusable_binaries_are_tool_errors(tmp_path: Path, problem: str) -> None:
    target = tmp_path / "tool"
    if problem == "directory":
        target.mkdir()
    elif problem == "not_executable":
        target.write_bytes(b"#!/bin/sh\n")
        target.chmod(0o644)
    elif problem == "fifo":
        os.mkfifo(target)
    with pytest.raises(ToolError):
        PinnedBinary.measure(str(target))


def test_relative_binary_paths_are_configuration_errors() -> None:
    from cubeproof.base.errors import ConfigurationError

    with pytest.raises(ConfigurationError):
        PinnedBinary.measure("cadical")


def test_verify_detects_changes(tmp_path: Path) -> None:
    tool = fk.make_tool(tmp_path, "tool", [fk.exit_(0)])
    binary = PinnedBinary.measure(str(tool.path))
    replacement = tmp_path / "new"
    replacement.write_bytes(tool.path.read_bytes() + b"\n")
    replacement.chmod(0o755)
    os.replace(replacement, tool.path)
    with pytest.raises(ToolError) as caught:
        binary.verify()
    assert caught.value.rule == "binary_changed"
    assert binary.changed()
