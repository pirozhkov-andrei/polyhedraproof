"""The solver, checker and relay presets produce exactly the outputs their names promise."""

from __future__ import annotations

import hashlib
import json
import os
import resource
import signal
import subprocess
import time
from collections.abc import Callable
from pathlib import Path

import pytest

from fakes import presets as p
from fakes import toolkit as fk
from fakes.cnf_model import ModelError, parse_dimacs, parse_model
from fakes.fixture_files import fixture

TIMEOUT = 30


def run(
    tool: fk.FakeTool, *args: str | Path, preexec_fn: Callable[[], None] | None = None
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [str(tool.path), *map(str, args)],
        capture_output=True,
        timeout=TIMEOUT,
        check=False,
        preexec_fn=preexec_fn,
    )


def checker_args(tmp_path: Path, proof: bytes = b"3 0 1 2 0\n") -> list[str | Path]:
    (tmp_path / "f.cnf").write_bytes(fixture("unsat.cnf").read_bytes())
    (tmp_path / "f.lrat").write_bytes(proof)
    return [
        "--CML_HEAP_SIZE=1024",
        "--CML_STACK_SIZE=1024",
        tmp_path / "f.cnf",
        tmp_path / "f.lrat",
    ]


def wait_until(path: Path) -> None:
    deadline = time.monotonic() + 10
    while not path.exists():
        assert time.monotonic() < deadline
        time.sleep(0.01)


# -- checker ----------------------------------------------------------------------------------


def test_accept_prints_exactly_the_success_line(tmp_path: Path) -> None:
    tool = fk.make_tool(tmp_path, "cake_lpr", p.checker_accept())
    result = run(tool, *checker_args(tmp_path))
    assert (result.returncode, result.stdout, result.stderr) == (0, p.CHECKER_SUCCESS, b"")
    assert tool.events()[0]["bytes"] == len(b"3 0 1 2 0\n")


def test_no_wrong_success_output_is_the_success_line() -> None:
    assert p.CHECKER_SUCCESS not in p.WRONG_SUCCESS_OUTPUTS
    assert len(set(p.WRONG_SUCCESS_OUTPUTS)) == len(p.WRONG_SUCCESS_OUTPUTS)


@pytest.mark.parametrize("output", p.WRONG_SUCCESS_OUTPUTS)
def test_wrong_success_outputs_are_emitted_byte_for_byte(tmp_path: Path, output: bytes) -> None:
    tool = fk.make_tool(tmp_path, "cake_lpr", p.checker_output(output))
    result = run(tool, *checker_args(tmp_path))
    assert (result.returncode, result.stdout) == (0, output)


def test_the_success_line_with_a_failing_exit(tmp_path: Path) -> None:
    tool = fk.make_tool(tmp_path, "cake_lpr", p.checker_output(p.CHECKER_SUCCESS, 1))
    result = run(tool, *checker_args(tmp_path))
    assert (result.returncode, result.stdout) == (1, p.CHECKER_SUCCESS)


def test_reject_looks_like_cake_lpr(tmp_path: Path) -> None:
    tool = fk.make_tool(tmp_path, "cake_lpr", p.checker_reject())
    result = run(tool, *checker_args(tmp_path))
    assert (result.returncode, result.stdout) == (0, b"")
    assert result.stderr == b"c Checking failed at line: 0. Reason: pivot must be non-zero\n"


@pytest.mark.parametrize("kind", ["heap", "stack", "both"])
def test_arena_exhaustion(tmp_path: Path, kind: str) -> None:
    tool = fk.make_tool(tmp_path, "cake_lpr", p.checker_arena(kind))
    result = run(tool, *checker_args(tmp_path))
    assert (result.returncode, result.stdout, result.stderr) == (
        *p.ARENA[kind][:1],
        b"",
        p.ARENA[kind][1],
    )


def test_the_arena_codes_and_messages_are_distinct() -> None:
    codes = {code for code, _ in p.ARENA.values()}
    messages = {message for _, message in p.ARENA.values()}
    assert len(codes) == len(messages) == 3
    assert 0 not in codes


def test_success_together_with_an_arena_diagnostic(tmp_path: Path) -> None:
    tool = fk.make_tool(tmp_path, "cake_lpr", p.checker_success_with_arena("stack"))
    result = run(tool, *checker_args(tmp_path))
    assert (result.returncode, result.stdout, result.stderr) == (
        0,
        p.CHECKER_SUCCESS,
        p.CAKE_STACK_EXHAUSTED[1],
    )


@pytest.mark.parametrize("name", ["SEGV", "KILL"])
def test_checker_crash(tmp_path: Path, name: str) -> None:
    tool = fk.make_tool(tmp_path, "cake_lpr", p.checker_crash(name))
    result = run(tool, *checker_args(tmp_path))
    assert result.returncode == -signal.Signals["SIG" + name]
    assert result.stdout == b""


@pytest.mark.parametrize("target", ["cnf", "proof"])
def test_a_checker_that_changes_its_input_still_claims_success(tmp_path: Path, target: str) -> None:
    args = checker_args(tmp_path)
    victim = Path(args[2] if target == "cnf" else args[3])
    before = victim.read_bytes()
    tool = fk.make_tool(tmp_path, "cake_lpr", p.checker_alters(target))
    result = run(tool, *args)
    assert (result.returncode, result.stdout) == (0, p.CHECKER_SUCCESS)
    assert victim.read_bytes() != before


def test_a_checker_that_stops_reading_a_stream(tmp_path: Path) -> None:
    fifo = tmp_path / "proof.fifo"
    os.mkfifo(fifo)
    tool = fk.make_tool(tmp_path, "cake_lpr", p.checker_stops_reading(100, p.checker_arena("heap")))
    child = subprocess.Popen(
        [str(tool.path), "--CML_HEAP_SIZE=1", "f.cnf", str(fifo)], stderr=subprocess.PIPE
    )
    written = 0
    with pytest.raises(BrokenPipeError), open(fifo, "wb", buffering=0) as stream:
        for _ in range(10_000):
            written += stream.write(b"x" * 4096)
    _, err = child.communicate(timeout=TIMEOUT)
    assert (child.returncode, err) == p.CAKE_HEAP_EXHAUSTED
    assert written >= 100
    assert tool.events()[0]["bytes"] == 100


def test_the_lrat_checker_preset_checks_for_real(tmp_path: Path) -> None:
    tool = fk.make_tool(tmp_path, "checker", p.checker_lrat())
    good = run(tool, *checker_args(tmp_path))
    assert good.stdout == p.CHECKER_SUCCESS
    bad = run(tool, *checker_args(tmp_path, b"3 0 1 0\n"))
    assert (bad.returncode, bad.stdout) == (0, b"")


def test_checker_flood(tmp_path: Path) -> None:
    tool = fk.make_tool(tmp_path, "cake_lpr", p.checker_flood(1 << 20, to=fk.STDERR))
    result = run(tool, *checker_args(tmp_path))
    assert len(result.stderr) == 1 << 20
    assert result.stdout == p.CHECKER_SUCCESS


# -- solver -----------------------------------------------------------------------------------


def test_unsat_writes_the_complete_proof(tmp_path: Path) -> None:
    proof = fixture("unsat.blrat").read_bytes()
    tool = fk.make_tool(tmp_path, "cadical", p.solver_unsat(proof))
    result = run(tool, "-q", "--lrat", fixture("unsat.cnf"), tmp_path / "out.lrat")
    assert (result.returncode, result.stdout) == (20, p.CADICAL_UNSAT_STDOUT)
    assert (tmp_path / "out.lrat").read_bytes() == proof
    assert tool.argv() == ["-q", "--lrat", str(fixture("unsat.cnf")), str(tmp_path / "out.lrat")]


def test_sat_prints_a_model_that_parses(tmp_path: Path) -> None:
    tool = fk.make_tool(tmp_path, "cadical", p.solver_sat([1, 2, 3]))
    result = run(tool, fixture("sat.cnf"))
    assert result.returncode == p.SOLVER_SAT
    cnf = parse_dimacs(fixture("sat.cnf").read_bytes())
    assert parse_model(result.stdout, cnf) == {1: True, 2: True, 3: True}


def test_malformed_models(tmp_path: Path) -> None:
    cnf = parse_dimacs(fixture("sat.cnf").read_bytes())
    tool = fk.make_tool(tmp_path, "cadical", p.solver_output(b"s SATISFIABLE\nv 1 2 0\n", 10))
    result = run(tool, fixture("sat.cnf"))
    assert result.returncode == 10
    with pytest.raises(ModelError) as caught:
        parse_model(result.stdout, cnf)
    assert caught.value.kind == "missing"


def test_brute_force_solver(tmp_path: Path) -> None:
    tool = fk.make_tool(tmp_path, "cadical", p.solver_brute_force())
    sat = run(tool, fixture("sat.cnf"), tmp_path / "proof")
    assert sat.returncode == 10
    unsat = run(tool, fixture("unsat.cnf"), tmp_path / "proof")
    assert unsat.returncode == 20
    assert not (tmp_path / "proof").exists()  # exit 20 without a proof: protocol failure


def test_partial_proof_then_exit_20(tmp_path: Path) -> None:
    proof = b"5 1 0 1 2 0\n6 0 5 3 4 0\n"
    tool = fk.make_tool(tmp_path, "cadical", p.solver_partial_proof(proof, 12, then=[fk.exit_(20)]))
    assert run(tool, "f.cnf", tmp_path / "proof").returncode == 20
    assert (tmp_path / "proof").read_bytes() == proof[:12]


def test_proof_flood_under_a_file_size_limit_dies_of_sigxfsz(tmp_path: Path) -> None:
    tool = fk.make_tool(tmp_path, "cadical", p.solver_proof_flood(1 << 20, chunk=4096))

    def limit() -> None:
        resource.setrlimit(resource.RLIMIT_FSIZE, (65536, resource.RLIM_INFINITY))

    limited = run(tool, "f.cnf", tmp_path / "capped", preexec_fn=limit)
    assert limited.returncode == -signal.SIGXFSZ
    assert (tmp_path / "capped").stat().st_size == 65536
    free = run(tool, "f.cnf", tmp_path / "full")
    assert (free.returncode, (tmp_path / "full").stat().st_size) == (20, 1 << 20)


def test_out_of_memory_aborts_with_the_cxx_message(tmp_path: Path) -> None:
    tool = fk.make_tool(tmp_path, "cadical", p.solver_out_of_memory())
    result = run(tool)
    assert result.returncode == -signal.SIGABRT
    assert result.stderr == p.CADICAL_BAD_ALLOC_STDERR


def test_terminated_solver_prints_unknown(tmp_path: Path) -> None:
    ready = tmp_path / "ready"
    tool = fk.make_tool(tmp_path, "cadical", p.solver_until_terminated(ready=str(ready)))
    child = subprocess.Popen([str(tool.path)], stdout=subprocess.PIPE)
    wait_until(ready)
    child.terminate()
    out, _ = child.communicate(timeout=TIMEOUT)
    assert (child.returncode, out) == (-signal.SIGTERM, p.CADICAL_TERM_STDOUT)


def test_solver_ignoring_term(tmp_path: Path) -> None:
    ready = tmp_path / "ready"
    tool = fk.make_tool(tmp_path, "cadical", p.solver_ignoring_term(ready=str(ready)))
    child = subprocess.Popen([str(tool.path)])
    wait_until(ready)
    child.terminate()
    time.sleep(0.3)
    assert child.poll() is None
    child.kill()
    assert child.wait(timeout=TIMEOUT) == -signal.SIGKILL


def test_solver_with_grandchild(tmp_path: Path) -> None:
    pid_file = tmp_path / "pid"
    tool = fk.make_tool(tmp_path, "cadical", p.solver_with_grandchild(str(pid_file), 30))
    child = subprocess.Popen([str(tool.path)], start_new_session=True)
    wait_until(pid_file)
    grandchild = int(pid_file.read_text())
    try:
        assert os.getpgid(grandchild) == child.pid
    finally:
        os.killpg(child.pid, signal.SIGKILL)
        child.wait(timeout=TIMEOUT)


# -- relay ------------------------------------------------------------------------------------


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def test_relay_report_has_exactly_the_record_fields() -> None:
    line = p.relay_report(5, "0" * 64, solver_eof=True, all_written=False, error="EPIPE")
    assert line.endswith(b"\n") and line.count(b"\n") == 1
    record = json.loads(line)
    assert tuple(record) == p.RELAY_FIELDS
    assert record == {
        "bytes": 5,
        "sha256": "0" * 64,
        "solver_eof": True,
        "all_written": False,
        "error": "EPIPE",
    }
    with pytest.raises(ValueError):
        p.relay_report(-1, "0" * 64, solver_eof=True, all_written=True)
    with pytest.raises(ValueError):
        p.relay_report(0, "abc", solver_eof=True, all_written=True)


def test_relay_copies_exactly_and_reports(tmp_path: Path) -> None:
    data = os.urandom(200_000)
    report = p.relay_report(len(data), sha256(data), solver_eof=True, all_written=True)
    tool = fk.make_tool(tmp_path, "relay", p.relay_copy(chunk=4096, report=report))
    result = subprocess.run(
        [str(tool.path)], input=data, capture_output=True, timeout=TIMEOUT, check=False
    )
    assert (result.returncode, result.stdout, result.stderr) == (0, data, report)
    (event,) = tool.events()
    assert (event["op"], event["bytes"], event["sha256"], event["eof"]) == (
        "pipe",
        len(data),
        sha256(data),
        True,
    )


def test_relay_corrupts_one_byte_in_transit(tmp_path: Path) -> None:
    data = bytes(range(256)) * 4
    tool = fk.make_tool(tmp_path, "relay", p.relay_copy(flip_at=300, code=0))
    result = subprocess.run(
        [str(tool.path)], input=data, capture_output=True, timeout=TIMEOUT, check=False
    )
    assert result.returncode == 0
    assert len(result.stdout) == len(data)
    assert [i for i in range(len(data)) if result.stdout[i] != data[i]] == [300]
    assert tool.events()[0]["sha256"] == sha256(data)  # what it read, not what it wrote


def test_relay_that_breaks_off_after_some_bytes(tmp_path: Path) -> None:
    tool = fk.make_tool(tmp_path, "relay", p.relay_breaks(100, [fk.exit_(3)]))
    data = b"x" * 1_000_000
    result = subprocess.run(
        [str(tool.path)], input=data, capture_output=True, timeout=TIMEOUT, check=False
    )
    assert (result.returncode, result.stdout) == (3, data[:100])
    event = tool.events()[0]
    assert (event["bytes"], event["eof"]) == (100, False)


def test_relay_with_a_closed_sink_dies_of_sigpipe(tmp_path: Path) -> None:
    tool = fk.make_tool(tmp_path, "relay", p.relay_copy())
    reader, writer = os.pipe()
    os.close(reader)
    try:
        result = subprocess.run(
            [str(tool.path)],
            input=b"y" * 100_000,
            stdout=writer,
            stderr=subprocess.PIPE,
            timeout=TIMEOUT,
            check=False,
        )
    finally:
        os.close(writer)
    assert result.returncode == -signal.SIGPIPE


def test_solver_relay_checker_through_fifos(tmp_path: Path) -> None:
    """The stream topology with fakes: solver -> FIFO -> relay -> FIFO -> checker."""
    proof = fixture("unsat.lrat").read_bytes()
    cnf = fixture("unsat.cnf")
    solver_out, checker_in = tmp_path / "solver.fifo", tmp_path / "checker.fifo"
    os.mkfifo(solver_out)
    os.mkfifo(checker_in)
    solver = fk.make_tool(tmp_path, "cadical", p.solver_unsat(proof))
    relay = fk.make_tool(tmp_path, "relay", p.relay_copy(fk.arg(0), fk.arg(1)))
    checker = fk.make_tool(tmp_path, "cake_lpr", p.checker_lrat())
    commands = {
        "checker": [str(checker.path), str(cnf), str(checker_in)],
        "relay": [str(relay.path), str(solver_out), str(checker_in)],
        "solver": [str(solver.path), "-q", "--lrat", str(cnf), str(solver_out)],
    }
    children = {
        name: subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        for name, argv in commands.items()
    }
    outputs = {name: child.communicate(timeout=TIMEOUT) for name, child in children.items()}
    codes = {name: child.returncode for name, child in children.items()}
    assert codes == {"checker": 0, "relay": 0, "solver": p.SOLVER_UNSAT}
    assert outputs["solver"][0] == p.CADICAL_UNSAT_STDOUT
    assert outputs["checker"] == (p.CHECKER_SUCCESS, b"")
    event = relay.events()[0]
    assert (event["bytes"], event["sha256"], event["eof"]) == (len(proof), sha256(proof), True)
