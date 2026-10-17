"""Specification §12.2: every row of the exit-code table, at the command line.

Runs use the fake pinned tools of the lifecycle tests (real coordinator, real child processes).
Each test names the table row it exercises: 0 success, 1 open work, 2 model, 3 usage, 4 integrity,
5 tools, 6 anomaly, 130 interruption; the priority 4 > 5 > 2 > 6 > 1 > 0 is checked on the
combinations a command line can reach.
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import cp_cli_support as c
import pytest

from cubeproof import cli
from cubeproof.cli import handlers
from cubeproof.contracts.enums import ExitCode

SPLITTING = {"max_free": 3}
#: a scripted checker that is faulty from its first call would be stopped by the known-answer
#: control; these tests are about what a session does with a checker that fails later
FAULTY = "--no-known-answer"


def run(shop: c.Shop, capsys: pytest.CaptureFixture[str], *more: str, worker: str = "w1") -> c.Done:
    return c.cli_main(shop.run_args(*more, worker=worker), capsys)


def certify(shop: c.Shop, capsys: pytest.CaptureFixture[str]) -> c.Done:
    return c.cli_main(
        ["certify", "--campaign", str(shop.campaign), "--journals", str(shop.journal)], capsys
    )


def test_exit_0_a_proved_run_and_its_certificate(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    shop = c.made(tmp_path, {"f": c.SHALLOW}, solver=SPLITTING)
    done = run(shop, capsys, "--jobs", "2")
    assert done.code == 0, done.err
    document = c.last_json(done.out)
    assert (document["exit_code"], document["reason"], document["open"]) == (0, "complete", {})
    proved = certify(shop, capsys)
    assert proved.code == 0 and proved.out.startswith("PROVED")


def test_exit_1_open_work_when_the_time_allocation_ends_and_certify_open(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    shop = c.made(tmp_path, {"f": c.DEEP}, solver={**SPLITTING, "sleep": 0.4})
    done = run(shop, capsys, "--max-hours", "0.00001")
    assert done.code == 1, done.err
    document = c.last_json(done.out)
    assert document["reason"] == "time" and document["open"]
    open_certificate = certify(shop, capsys)
    assert open_certificate.code == 1 and open_certificate.out.startswith("OPEN")
    # the work is not lost: the next run finishes it
    c.t.configure(shop.tools.solver, **SPLITTING)
    assert run(shop, capsys).code == 0
    assert certify(shop, capsys).code == 0


def test_exit_1_a_resource_block_before_any_work(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    shop = c.made(tmp_path, {"f": c.SHALLOW}, solver=SPLITTING)
    done = run(shop, capsys, "--proof-mode", "stream", "--jobs", "2")  # a stream task needs 3 slots
    assert done.code == 1
    assert "[resources.preflight]" in done.err
    assert not shop.journal.exists()


def test_exit_2_a_valid_model_in_run_and_in_certify(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    shop = c.made(tmp_path, {"f": c.t.sat(5)}, solver={})
    done = run(shop, capsys)
    assert done.code == 2, done.err
    assert c.last_json(done.out)["models"] == 1
    certified = certify(shop, capsys)
    assert certified.code == 2 and certified.out.startswith("MODEL_FOUND")


def test_exit_3_usage_configuration_and_lock_conflicts(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    shop = c.made(tmp_path, {"f": c.SHALLOW}, solver=SPLITTING)
    assert run(shop, capsys, "--memory", "12x").code == 3  # a malformed size
    assert run(shop, capsys, "--policy-override", "no_such=1").code == 3
    missing = shop.run_args()
    missing[missing.index("--campaign") + 1] = str(tmp_path / "nope.json")
    done = c.cli_main(missing, capsys)
    assert done.code == 3 and "[campaign.file]" in done.err
    # a second worker on the same results directory: a lock conflict (specification §7.3)
    from cubeproof.evidence.journal import RunLock

    shop.results.mkdir(exist_ok=True)
    with RunLock.acquire(shop.results / "run.lock"):
        done = run(shop, capsys)
    assert done.code == 3 and "[run.locked]" in done.err
    # another worker name in the same directory, once a journal exists
    assert run(shop, capsys).code == 0
    done = run(shop, capsys, worker="w2")
    assert done.code == 3 and "[run.worker]" in done.err


def test_exit_4_a_damaged_journal_in_every_command_that_reads_it(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    shop = c.made(tmp_path, {"f": c.SHALLOW}, solver=SPLITTING)
    assert run(shop, capsys).code == 0
    data = bytearray(shop.journal.read_bytes())
    lines = bytes(data).split(b"\n")
    lines[2] = lines[2].replace(b'"seq"', b'"sEq"', 1)  # a complete invalid line in the middle
    shop.journal.write_bytes(b"\n".join(lines))
    damaged = shop.journal.read_bytes()
    assert certify(shop, capsys).code == 4
    verify = c.cli_main(
        ["journal", "verify", str(shop.journal), "--campaign", str(shop.campaign)], capsys
    )
    assert verify.code == 4
    again = run(shop, capsys)
    assert again.code == 4 and "cubeproof: error [" in again.err
    repair = c.cli_main(
        ["journal", "repair", str(shop.journal), "--campaign", str(shop.campaign)], capsys
    )
    assert repair.code == 4
    assert shop.journal.read_bytes() == damaged  # nothing was repaired, appended or removed


def test_exit_5_a_tool_that_is_not_the_pinned_one_and_a_crashing_tool(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    shop = c.made(tmp_path, {"f": c.SHALLOW}, solver=SPLITTING)
    other = tmp_path / "other"
    other.write_text("#!/bin/sh\nexit 0\n")
    other.chmod(0o755)
    args = shop.run_args()
    args[args.index("--checker") + 1] = str(other)
    done = c.cli_main(args, capsys)
    assert done.code == 5 and "[tool.hash_mismatch]" in done.err
    assert not shop.journal.exists()
    missing = shop.run_args()
    missing[missing.index("--solver") + 1] = str(tmp_path / "gone")
    assert c.cli_main(missing, capsys).code == 5
    # a checker that dies on every proof is stopped by the known-answer control at the start:
    # no record at all, and no header
    c.t.configure(shop.tools.checker, crash=True)
    done = run(shop, capsys)
    assert done.code == 5 and "[tool.known_answer]" in done.err, done.err
    assert not shop.journal.exists()
    # without the control: retries are exhausted, the node is tool-blocked
    done = run(shop, capsys, FAULTY)
    assert done.code == 5 and "[tool.known_answer]" not in done.err, done.err
    assert certify(shop, capsys).code == 1  # nothing was proved


def test_exit_6_an_anomaly_and_the_priority_of_the_conditions(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    shop = c.made(tmp_path / "anomaly", {"f": c.SHALLOW}, solver=SPLITTING)
    c.t.configure(shop.tools.checker, reject=True)  # the checker rejects an honest proof
    done = run(shop, capsys, FAULTY)
    assert done.code == 6, done.err
    assert c.last_json(done.out)["anomalies"] >= 1
    # 2 beats 6: a model and an anomaly
    both = c.made(tmp_path / "both", {"a": c.SHALLOW, "b": c.t.sat(5)}, solver={})
    c.t.configure(both.tools.checker, reject=True)
    done = run(both, capsys, FAULTY)
    assert done.code == 2, done.err
    assert c.last_json(done.out)["anomalies"] >= 1
    # 5 beats 2: a model and a node blocked by a crashing tool
    mixed = c.made(tmp_path / "mixed", {"a": c.SHALLOW, "b": c.t.sat(5)}, solver={})
    c.t.configure(mixed.tools.checker, crash=True)
    done = run(mixed, capsys, FAULTY)
    assert done.code == 5, done.err
    assert c.last_json(done.out)["models"] == 1


@pytest.mark.parametrize("signal_number", [signal.SIGINT, signal.SIGTERM])
def test_exit_130_an_interruption_after_clean_handling(signal_number: int, tmp_path: Path) -> None:
    ready = tmp_path / "ready"
    shop = c.made(tmp_path, {"f": c.DEEP}, solver={**SPLITTING, "sleep": 20.0, "ready": str(ready)})
    child = subprocess.Popen(
        [sys.executable, "-m", "cubeproof", *shop.run_args("--jobs", "1")],
        env={"PYTHONPATH": str(c.SRC), "PATH": "/usr/bin:/bin"},
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    deadline = time.monotonic() + 90
    while not ready.exists():
        assert time.monotonic() < deadline and child.poll() is None, "the solver did not start"
        time.sleep(0.02)
    os.kill(child.pid, signal_number)
    out, err = child.communicate(timeout=120)
    assert child.returncode == 130, (out, err)
    document = json.loads(out.strip().splitlines()[-1])
    assert document["reason"] == "interrupted" and document["exit_code"] == 130
    c.t.wait_clean(shop.results, tmp_path / "work-w1")
    # a restart continues from the journal and finishes
    c.t.configure(shop.tools.solver, **SPLITTING)
    resumed = c.command(*shop.run_args())
    assert resumed.code == 0, resumed.err


def test_exit_130_for_an_interruption_of_any_other_command(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def interrupted(args: object) -> int:
        raise KeyboardInterrupt

    monkeypatch.setitem(handlers.HANDLERS, ("status",), interrupted)
    done = c.cli_main(["status", "--results", "r"], capsys)
    assert done.code == 130 == int(ExitCode.INTERRUPTED)
    assert "interrupted" in done.err


def test_unclassified_failures_are_internal_errors_with_a_traceback_not_exit_1(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def broken(args: object) -> int:
        raise RuntimeError("boom")

    monkeypatch.setitem(handlers.HANDLERS, ("status",), broken)
    done = c.cli_main(["status", "--results", "r"], capsys)
    assert done.code == 4  # never 1: that is "open work"
    assert "internal error" in done.err and "RuntimeError: boom" in done.err


@pytest.mark.parametrize(
    ("failure", "code"),
    [
        (PermissionError(13, "Permission denied", "/x"), 3),
        (OSError(5, "Input/output error", "/x"), 5),
    ],
)
def test_operating_system_errors_are_classified_like_the_run(
    failure: OSError, code: int, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def failing(args: object) -> int:
        raise failure

    monkeypatch.setitem(handlers.HANDLERS, ("status",), failing)
    done = c.cli_main(["status", "--results", "r"], capsys)
    assert done.code == code and "[io.error]" in done.err and "/x" in done.err
    assert cli.main is not None
