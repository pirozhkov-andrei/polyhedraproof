"""Specification §7.4, §8.4, §12.1, §12.3: ``run`` with the status monitor, export, shards, inbox,
outbox, policy overrides and reopening, and ``status``/``handoff`` beside it.

The run is the coordinator wired by the command layer; these tests check the wiring
and the observable behavior at the command line, not the coordinator's internals.
"""

from __future__ import annotations

import json
import os
import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import cp_cli_support as c
import pytest

from cubeproof import api
from cubeproof.base.canonical_json import document_bytes, parse_document
from cubeproof.coordinator.status_format import validate_status
from cubeproof.coordinator.status_monitor import RunMonitor

SPLITTING = {"max_free": 3}


def run(shop: c.Shop, capsys: pytest.CaptureFixture[str], *more: str, **kw: Any) -> c.Done:
    return c.cli_main(shop.run_args(*more, **kw), capsys)


def journal_lines(shop: c.Shop, results: Path | None = None) -> list[dict[str, Any]]:
    path = (results or shop.results) / "journal.jsonl"
    return [json.loads(line) for line in path.read_bytes().split(b"\n") if line]


# -- the result document --------------------------------------------------------------------------


def test_the_run_result_is_one_json_line_of_exact_types(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    shop = c.made(tmp_path, {"f": c.DEEP}, solver=SPLITTING)
    done = run(shop, capsys, "--jobs", "2")
    assert done.code == 0, done.err
    assert len(done.out.strip().splitlines()) == 1
    document = c.last_json(done.out)
    assert set(document) == {
        "exit_code", "reason", "campaign", "worker", "journal", "seq", "head", "open", "session",
        "anomalies", "models", "given_away", "cache", "replayed_records", "ticks", "notes",
    }  # fmt: skip
    ints = ("exit_code", "seq", "anomalies", "models", "given_away", "replayed_records")
    assert all(type(document[k]) is int for k in ints)
    assert all(
        type(document[k]) is str
        for k in ("reason", "campaign", "worker", "journal", "head", "cache")
    )
    assert type(document["open"]) is dict and type(document["notes"]) is list
    assert all(type(v) is int for v in document["session"].values())
    assert all(type(v) is float or type(v) is int for v in document["ticks"].values())
    assert (document["worker"], document["reason"], document["cache"]) == (
        "w1",
        "complete",
        "absent",
    )
    header = journal_lines(shop)[0]
    assert document["journal"] == header["self"] and document["campaign"] == header["campaign"]
    assert document["head"] == journal_lines(shop)[-1]["self"]
    assert document["seq"] == len(journal_lines(shop)) - 1


# -- the monitor, the export and the log ----------------------------------------------------------


def test_a_run_publishes_status_exports_its_journal_and_logs_progress(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    shop = c.made(tmp_path, {"f": c.DEEP}, solver=SPLITTING)
    export = tmp_path / "export"
    done = run(shop, capsys, "--jobs", "2", "--export", str(export))
    assert done.code == 0, done.err
    status = parse_document((shop.results / "status.json").read_bytes())
    assert validate_status(status) == status
    assert status["lifecycle"] == "stopped" and status["worker"] == "w1"
    lines = journal_lines(shop)
    assert status["seq"] == len(lines) - 1 and status["head"] == lines[-1]["self"]
    assert status["journal"] == lines[0]["self"] and status["campaign"] == lines[0]["campaign"]
    assert status["counters"]["records"] == len(lines)  # every record was observed, from seq 0
    assert status["counters"]["attempts"] == sum(1 for r in lines if r["type"] == "attempt")
    assert status["export"] is not None and status["export"]["seq"] == status["seq"]
    assert [(e["state"], e["depth"], e["count"]) for e in status["node_counts"]] == [
        ("closed", 4, 16)
    ]
    assert status["coverage"][0]["closed_numerator"] == "1"
    text = (shop.results / "status.txt").read_text(encoding="utf-8")
    assert "worker w1" in text and "stopped" in text
    # the export is a copy of the journal at the clean stop, with its descriptor
    assert sorted(p.name for p in export.iterdir()) == ["export.json", "journal.1.jsonl"]
    assert (export / "journal.1.jsonl").read_bytes() == shop.journal.read_bytes()
    # the log goes to standard error, the result to standard output
    assert "INFO progress" in done.err and "export.ok" in done.err
    assert "progress" not in done.out


def test_quiet_and_verbose_select_the_log_level(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    shop = c.made(tmp_path, {"f": c.SHALLOW}, solver=SPLITTING)
    quiet = run(shop, capsys, "-q", "--export", str(tmp_path / "e1"))
    assert quiet.code == 0 and "INFO" not in quiet.err
    loud = run(shop, capsys, "-v", "--export", str(tmp_path / "e2"))
    assert loud.code == 0 and "INFO" in loud.err


def test_status_after_a_run_in_text_and_json(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    shop = c.made(tmp_path, {"f": c.SHALLOW}, solver=SPLITTING)
    assert run(shop, capsys).code == 0
    text = c.cli_main(["status", "--results", str(shop.results)], capsys)
    assert text.code == 0 and text.out.startswith("cubeproof status") and "worker w1" in text.out
    as_json = c.cli_main(["status", "--results", str(shop.results), "--json"], capsys)
    document = c.last_json(as_json.out)
    assert as_json.code == 0
    assert document == parse_document((shop.results / "status.json").read_bytes())
    assert as_json.err == ""  # a stopped worker is not stale


def test_status_marks_a_stale_monitor_and_refuses_what_is_not_one(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    shop = c.made(tmp_path, {"f": c.SHALLOW}, solver=SPLITTING)
    assert run(shop, capsys).code == 0
    path = shop.results / "status.json"
    document = parse_document(path.read_bytes())
    old = (datetime.now(timezone.utc) - timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    path.write_bytes(document_bytes({**document, "lifecycle": "running", "utc": old}))
    stale = c.cli_main(["status", "--results", str(shop.results)], capsys)
    assert stale.code == 0 and "WARNING: the last status is" in stale.out
    as_json = c.cli_main(["status", "--results", str(shop.results), "--json"], capsys)
    assert as_json.code == 0 and "stale" in as_json.err
    path.write_bytes(b'{"format":"cubeproof-status-1"}\n')
    invalid = c.cli_main(["status", "--results", str(shop.results)], capsys)
    assert invalid.code == 3 and "[status.invalid]" in invalid.err
    path.unlink()
    absent = c.cli_main(["status", "--results", str(shop.results)], capsys)
    assert absent.code == 3 and "[status.absent]" in absent.err


def test_a_resumed_run_counts_the_records_of_the_runs_before_it(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The tracker is fed the records the replay validated, so models and anomalies of an earlier
    run still appear in the status of a later one."""
    shop = c.made(tmp_path, {"f": c.SHALLOW}, solver=SPLITTING)
    c.t.configure(shop.tools.checker, reject=True)
    first = run(shop, capsys, "--no-known-answer")  # a checker that turns faulty, not a wrong one
    assert first.code == 6
    c.t.configure(shop.tools.checker)
    second = run(shop, capsys)
    assert second.code == 0, second.err
    status = parse_document((shop.results / "status.json").read_bytes())
    lines = journal_lines(shop)
    rejected = [
        r["seq"] for r in lines if r["type"] == "attempt" and r["outcome"] == "CHECK_REJECTED"
    ]
    assert rejected  # the first run's anomalies, which this run did not see happen
    assert status["counters"]["records"] == len(lines)
    assert status["counters"]["anomalies"] == len(rejected)
    assert [a["seq"] for a in status["anomalies"]] == rejected
    assert status["counters"]["type_resume"] == 1 and status["counters"]["type_header"] == 1


def test_a_monitor_that_cannot_write_never_stops_the_run(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    shop = c.made(tmp_path, {"f": c.SHALLOW}, solver=SPLITTING)
    shop.results.mkdir()
    (shop.results / "status.json").mkdir()  # nothing can be renamed over a directory
    done = run(shop, capsys)
    assert done.code == 0, done.err
    assert c.last_json(done.out)["open"] == {}
    assert api.certify(shop.campaign, [shop.journal])["verdict"] == "PROVED"


def test_a_monitor_that_fails_is_switched_off_with_a_note_and_the_run_goes_on(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    shop = c.made(tmp_path, {"f": c.DEEP}, solver=SPLITTING)

    def broken(*args: Any, **kwargs: Any) -> None:
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(RunMonitor, "tick", broken)
    done = run(shop, capsys, "--jobs", "2")
    assert done.code == 0, done.err
    document = c.last_json(done.out)
    assert document["open"] == {} and document["reason"] == "complete"
    assert len([n for n in document["notes"] if n.startswith("the status monitor stopped")]) == 1
    assert api.certify(shop.campaign, [shop.journal])["verdict"] == "PROVED"


# -- options of the run ---------------------------------------------------------------------------


def test_policy_overrides_and_proof_mode_are_part_of_the_persisted_effective_policy(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    shop = c.made(tmp_path, {"f": c.SHALLOW}, solver=SPLITTING)
    done = run(shop, capsys, "--policy-override", "max_cube_size=7", "--proof-mode", "retain")
    assert done.code == 0, done.err
    policy = journal_lines(shop)[0]["policy"]
    assert policy["max_cube_size"] == 7 and policy["proof_mode"] == "retain"
    assert run(shop, capsys, "--policy-override", "max_cube_size=nine").code == 3
    assert run(shop, capsys, "--policy-override", "no.such.key=1").code == 3
    # a later session without those options would silently run another policy: refused
    lines = journal_lines(shop)
    dropped = run(shop, capsys)
    assert dropped.code == 3 and "[run.policy_changed]" in dropped.err, dropped.err
    assert "max_cube_size=7" in dropped.err and 'proof_mode="retain"' in dropped.err
    assert journal_lines(shop) == lines
    again = run(shop, capsys, "--policy-override", "max_cube_size=7", "--proof-mode", "retain")
    assert again.code == 0, again.err
    back = run(shop, capsys, "--campaign-policy")  # on purpose
    assert back.code == 0, back.err
    assert journal_lines(shop)[-1]["policy"]["proof_mode"] == "transient"


def test_the_state_cache_can_be_ignored(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    shop = c.made(tmp_path, {"f": c.SHALLOW}, solver=SPLITTING)
    assert run(shop, capsys).code == 0
    assert c.last_json(run(shop, capsys).out)["cache"] == "used"
    assert c.last_json(run(shop, capsys, "--no-cache").out)["cache"] == "disabled"


def test_reopening_blocked_nodes_needs_the_flag(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    shop = c.made(tmp_path, {"f": c.SHALLOW}, solver={"crash_if_free_le": 99})
    first = run(shop, capsys)
    assert first.code == 5
    assert "tool_blocked:0" in c.last_json(first.out)["open"]
    attempts = sum(1 for r in journal_lines(shop) if r["type"] == "attempt")
    c.t.configure(shop.tools.solver, **SPLITTING)  # the tool is repaired ...
    again = run(shop, capsys)
    assert (
        again.code == 5
        and sum(1 for r in journal_lines(shop) if r["type"] == "attempt") == attempts
    )
    assert [r for r in journal_lines(shop) if r["type"] == "node_reopen"] == []  # ... not enough
    reopened = run(shop, capsys, "--reopen-blocked")
    assert reopened.code == 0, reopened.err
    assert [r["reason"] for r in journal_lines(shop) if r["type"] == "node_reopen"] == [
        "reopen_blocked"
    ]
    certified = c.cli_main(
        ["certify", "--campaign", str(shop.campaign), "--journals", str(shop.journal)], capsys
    )
    assert certified.code == 0 and certified.out.startswith("PROVED")


# -- shards, inbox, outbox, handoff ---------------------------------------------------------------


def two_nodes(
    root: Path, capsys: pytest.CaptureFixture[str], **solver: Any
) -> tuple[c.Shop, dict[str, Any]]:
    shop = c.made(root, {"a": c.t.unsat(8, core=5), "b": c.SHALLOW}, solver={**SPLITTING, **solver})
    done = c.cli_main(
        ["shard", "--campaign", str(shop.campaign), "--machines", "2", "-o", str(root / "shards")],
        capsys,
    )
    assert done.code == 0, done.err
    return shop, c.last_json(done.out)


def test_a_worker_runs_only_the_shard_it_was_given(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    shop, plan = two_nodes(tmp_path, capsys)
    first, second = (e["path"] for e in plan["shards"])
    done = run(shop, capsys, "--shard", first)
    assert done.code == 0, done.err
    shards = [r for r in journal_lines(shop) if r["type"] == "shard"]
    assert [r["shard_sha256"] for r in shards] == [plan["shards"][0]["shard_sha256"]]
    worked = {r["node"]["formula_sha256"] for r in journal_lines(shop) if r["type"] == "attempt"}
    assert len(worked) == 1  # one of the two formulas; the other is the other machine's
    certified = c.cli_main(
        ["certify", "--campaign", str(shop.campaign), "--journals", str(shop.journal)], capsys
    )
    assert certified.code == 1 and certified.out.startswith("OPEN")  # half of the campaign
    # the same shard again is harmless; the other machine finishes the rest
    assert run(shop, capsys, "--shard", first).code == 0
    assert len([r for r in journal_lines(shop) if r["type"] == "shard"]) == 1
    other = run(shop, capsys, "--shard", second, worker="w2", results=tmp_path / "results-2")
    assert other.code == 0, other.err
    second_journal = str(tmp_path / "results-2" / "journal.jsonl")
    both = c.cli_main(
        [
            "certify",
            "--campaign",
            str(shop.campaign),
            "--journals",
            str(shop.journal),
            second_journal,
        ],
        capsys,
    )
    assert both.code == 0 and both.out.startswith("PROVED")
    # the option may be repeated: every occurrence counts, none replaces another
    repeated = c.cli_main(
        [
            *["certify", "--campaign", str(shop.campaign)],
            *["--journals", str(shop.journal), "--journals", second_journal],
        ],
        capsys,
    )
    assert repeated.code == 0 and repeated.out.startswith("PROVED")


def test_a_shard_that_cannot_be_accepted_is_refused_before_anything_is_written(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    shop, plan = two_nodes(tmp_path, capsys)
    first = Path(plan["shards"][0]["path"])
    document = json.loads(first.read_bytes())
    cases = {
        "another campaign": {**document, "campaign": "0" * 64},
        "a node of no formula of the campaign": {
            **document,
            "nodes": [{"formula_sha256": "1" * 64, "cube": []}],
        },
        "a literal beyond V": {**document, "nodes": [{**document["nodes"][0], "cube": [99]}]},
        "no nodes": {**document, "nodes": []},
        "a name that is not a name": {**document, "name": "Bad Name"},
    }
    for name, value in cases.items():
        path = tmp_path / f"bad-{len(name)}.json"
        path.write_bytes(document_bytes(value))
        done = run(shop, capsys, "--shard", str(path))
        assert done.code == 3, (name, done.err)
        assert not (shop.results / "journal.jsonl").exists(), name
    missing = run(shop, capsys, "--shard", str(tmp_path / "nope.json"))
    assert missing.code == 3 and "[input.file]" in missing.err
    assert not (shop.results / "journal.jsonl").exists()
    # a shard that overlaps accepted work is rejected whole; the same file again is a no-op
    assert run(shop, capsys, "--shard", str(first)).code == 0

    def shard_records() -> int:
        return sum(1 for r in journal_lines(shop) if r["type"] == "shard")

    accepted = shard_records()
    renamed = tmp_path / "renamed.json"
    renamed.write_bytes(document_bytes({**document, "name": "renamed"}))
    again = run(shop, capsys, "--shard", str(renamed))  # the same nodes under another name
    assert again.code == 3 and "[shard.overlap]" in again.err and shard_records() == accepted
    child = {
        **document,
        "name": "child",
        "nodes": [{"formula_sha256": document["nodes"][0]["formula_sha256"], "cube": [1]}],
    }
    (tmp_path / "child.json").write_bytes(document_bytes(child))
    overlapping = run(shop, capsys, "--shard", str(tmp_path / "child.json"))
    assert overlapping.code == 3 and "[shard.overlap]" in overlapping.err
    assert shard_records() == accepted


def test_handoff_gives_work_away_and_the_receiver_finishes_it(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """give/receive end to end through the commands: request, serve, deliver, run, certify."""
    shop = c.made(tmp_path, {"f": c.DEEP}, solver={**SPLITTING, "sleep": 0.3})
    inbox, outbox = tmp_path / "inbox", tmp_path / "outbox"
    ports = ("--inbox", str(inbox), "--outbox", str(outbox))
    stopped = run(shop, capsys, *ports, "--max-hours", "0.00001")
    assert stopped.code == 1 and (shop.results / "ports.json").exists()
    # the request is durable even though no worker is running
    asked = c.cli_main(
        ["handoff", "--results", str(shop.results), "--nodes", "1", "--output-name", "out1"], capsys
    )
    document = c.last_json(asked.out)
    assert asked.code == 0 and document["state"] == "pending" and document["response"] is None
    assert (inbox / "out1.request.json").exists()
    # repeating the request finds the same request; another count under the name is refused
    twice = c.cli_main(
        ["handoff", "--results", str(shop.results), "--nodes", "1", "--output-name", "out1"], capsys
    )
    assert c.last_json(twice.out)["request"] == document["request"]
    other = c.cli_main(
        ["handoff", "--results", str(shop.results), "--nodes", "2", "--output-name", "out1"], capsys
    )
    assert other.code == 3 and "[handoff.name_taken]" in other.err
    waited = c.cli_main(
        [
            "handoff",
            "--results",
            str(shop.results),
            "--nodes",
            "1",
            "--output-name",
            "out1",
            "--wait-ms",
            "50",
        ],
        capsys,
    )
    assert (
        waited.code == 1 and c.last_json(waited.out)["state"] == "pending"
    )  # a timeout is open work
    # the worker serves it at its next run and gives the one pending node away
    c.t.configure(shop.tools.solver, **SPLITTING)
    served = run(shop, capsys, *ports)
    result = c.last_json(served.out)
    assert result["given_away"] == 1 and served.code in (0, 1), served.err
    status = parse_document((shop.results / "status.json").read_bytes())
    assert validate_status(status) == status  # the desk's counters travel in the monitor
    assert status["counters"]["desk_handoffs"] == 1 and status["counters"]["given_away"] == 1
    done = c.cli_main(
        ["handoff", "--results", str(shop.results), "--nodes", "1", "--output-name", "out1"], capsys
    )
    final = c.last_json(done.out)
    assert done.code == 0 and final["state"] == "completed"
    assert final["output"] == str((outbox / "out1.json").resolve())
    assert final["response"]["nodes"] == 1 and final["response"]["output_name"] == "out1"
    # delivery is the user's: copy the file to the receiver, which runs it
    delivered = tmp_path / "delivered" / "out1.json"
    delivered.parent.mkdir()
    shutil.copyfile(outbox / "out1.json", delivered)
    receiver = run(shop, capsys, "--shard", str(delivered), worker="w2", results=tmp_path / "r2")
    assert receiver.code == 0, receiver.err
    both = c.cli_main(
        ["certify", "--campaign", str(shop.campaign), "--journals", str(shop.journal),
         str(tmp_path / "r2" / "journal.jsonl")], capsys,
    )  # fmt: skip
    assert both.code == 0 and both.out.startswith("PROVED")


def test_handoff_without_an_inbox_or_a_worker_is_a_usage_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    shop = c.made(tmp_path, {"f": c.SHALLOW}, solver=SPLITTING)
    no_ports = c.cli_main(
        ["handoff", "--results", str(tmp_path / "nowhere"), "--nodes", "1", "--output-name", "o"],
        capsys,
    )
    assert no_ports.out == ""
    assert no_ports.code == 3 and "[handoff.ports]" in no_ports.err
    assert run(shop, capsys).code == 0  # a run without --inbox and --outbox
    done = c.cli_main(
        ["handoff", "--results", str(shop.results), "--nodes", "1", "--output-name", "o"], capsys
    )
    assert done.code == 3 and "[handoff.ports]" in done.err
    only_outbox = c.made(tmp_path / "other", {"f": c.SHALLOW}, solver=SPLITTING)
    assert run(only_outbox, capsys, "--outbox", str(tmp_path / "ob")).code == 0
    done = c.cli_main(
        ["handoff", "--results", str(only_outbox.results), "--nodes", "1", "--output-name", "o"],
        capsys,
    )
    assert done.code == 3 and "[handoff.no_inbox]" in done.err


# -- a restored backup that is older than the export (RUNNING: Stop, resume and recovery) ---------


def _restore_walkthrough(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> tuple[c.Shop, Path, bytes, bytes]:
    """Run, back the results up, run to the end with exports, lose the results, restore the
    backup: ``(shop, export directory, the journal of the backup, the exported journal)``."""
    shop = c.made(tmp_path, {"f": c.DEEP}, solver={**SPLITTING, "sleep": 0.3})
    export = tmp_path / "export"
    first = run(shop, capsys, "--export", str(export), "--max-hours", "0.00001")
    assert first.code == 1, first.err
    backup = tmp_path / "backup"
    shutil.copytree(shop.results, backup)
    second = run(shop, capsys, "--jobs", "2", "--export", str(export))
    assert second.code == 0, second.err
    exported = (export / "journal.1.jsonl").read_bytes()
    assert exported == shop.journal.read_bytes()
    old = (backup / "journal.jsonl").read_bytes()
    assert exported.startswith(old) and len(old) < len(exported)
    shutil.rmtree(shop.results)  # the results volume is lost ...
    shutil.copytree(backup, shop.results)  # ... and the older backup restored into an empty one
    return shop, export, old, exported


def test_a_restored_older_backup_is_completed_from_the_export_before_the_run_resumes(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The walkthrough: the export directory holds a longer history of the same journal than the
    restored backup. The run appends the exported records the backup lacks (nothing committed
    before the last export is lost or solved again), resumes after them and goes on exporting
    into the same directory: one history, no fork."""
    shop, export, _, exported = _restore_walkthrough(tmp_path, capsys)
    third = run(shop, capsys, "--jobs", "2", "--export", str(export))
    assert third.code == 0, third.err
    assert "export.failed" not in third.err and "export.ok" in third.err
    assert "journal.restored" in third.err
    document = c.last_json(third.out)
    assert any("from the export" in note for note in document["notes"])
    journal = shop.journal.read_bytes()
    # the exported history is a prefix of the journal again; this session added only its resume
    assert journal.startswith(exported)
    new = [json.loads(line) for line in journal[len(exported) :].splitlines()]
    assert [r["type"] for r in new] == ["resume"]
    # the export was extended in place (same generation) and equals the journal at the stop
    assert sorted(p.name for p in export.iterdir()) == ["export.json", "journal.1.jsonl"]
    assert (export / "journal.1.jsonl").read_bytes() == journal
    status = parse_document((shop.results / "status.json").read_bytes())
    assert status["export"]["seq"] == status["seq"] == document["seq"]
    assert status["info"]["export"]["consecutive_failures"] == 0
    certified = c.cli_main(
        ["certify", "--campaign", str(shop.campaign), "--journals", str(shop.journal)], capsys
    )
    assert certified.code == 0, certified.err


def test_a_restored_journal_that_went_on_without_its_export_is_refused_before_any_record(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The restored worker ran with another export directory: its journal and the first export
    are now two continuations of one journal. A run given the first directory again stops at
    once (exit 4), names the way out and changes neither history."""
    shop, export, old, exported = _restore_walkthrough(tmp_path, capsys)
    elsewhere = run(shop, capsys, "--jobs", "2", "--export", str(tmp_path / "export2"))
    assert elsewhere.code == 0, elsewhere.err
    forked = shop.journal.read_bytes()
    assert forked.startswith(old) and not forked.startswith(exported)
    refused = run(shop, capsys, "--export", str(export))
    assert refused.code == 4 and "[export.diverged]" in refused.err
    assert "move the export directory aside" in refused.err
    assert shop.journal.read_bytes() == forked
    assert (export / "journal.1.jsonl").read_bytes() == exported
    # each history alone is a valid journal; together they are a fork (specification §10.1)
    certify = ["certify", "--campaign", str(shop.campaign), "--journals"]
    for journal in (shop.journal, export / "journal.1.jsonl"):
        alone = c.cli_main([*certify, str(journal)], capsys)
        assert alone.code == 0, alone.err
    both = c.cli_main([*certify, str(shop.journal), str(export / "journal.1.jsonl")], capsys)
    assert both.code == 4, both.err


def test_a_new_journal_is_never_started_beside_the_export_of_another(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Results lost and nothing restored: a launch with the old export directory would create a
    second journal under the same worker name and an export that fails for the whole run. It
    stops before the journal is created (exit 3)."""
    shop = c.made(tmp_path, {"f": c.SHALLOW}, solver=SPLITTING)
    export = tmp_path / "export"
    assert run(shop, capsys, "--export", str(export)).code == 0
    exported = (export / "journal.1.jsonl").read_bytes()
    shutil.rmtree(shop.results)
    refused = run(shop, capsys, "--export", str(export))
    assert refused.code == 3 and "[export.foreign]" in refused.err
    assert "holds no journal" in refused.err
    assert not shop.journal.exists()
    assert (export / "journal.1.jsonl").read_bytes() == exported
    # another worker's journal in the same directory: also before any work
    other = run(shop, capsys, "--export", str(export), worker="w2", results=tmp_path / "r2")
    assert other.code == 3 and "[export.foreign]" in other.err
    # with its own directory the worker starts
    assert run(shop, capsys, "--export", str(tmp_path / "export-new")).code == 0


def test_exported_records_whose_retained_proofs_are_lost_are_not_restored(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Retain mode: the records after the backup reference proof files that were lost with the
    results. Appending them would leave a journal that fails its own startup check, so the run
    refuses (exit 4) and the restored journal stays as the backup left it."""
    shop = c.made(tmp_path, {"f": c.DEEP}, solver={**SPLITTING, "sleep": 0.3})
    export = tmp_path / "export"
    mode = ("--proof-mode", "retain", "--export", str(export))
    assert run(shop, capsys, *mode, "--max-hours", "0.00001").code == 1
    backup = tmp_path / "backup"
    shutil.copytree(shop.results, backup)
    assert run(shop, capsys, *mode, "--jobs", "2").code == 0
    exported = (export / "journal.1.jsonl").read_bytes()
    assert any(p.is_file() for p in (shop.results / "proofs").iterdir())
    kept = tmp_path / "kept"
    shutil.move(str(shop.results), kept)
    shutil.copytree(backup, shop.results)
    old = shop.journal.read_bytes()
    refused = run(shop, capsys, *mode)
    assert refused.code == 4 and "[export.regressed]" in refused.err
    assert "artifact.missing" in refused.err and "move the export directory aside" in refused.err
    assert shop.journal.read_bytes() == old
    assert (export / "journal.1.jsonl").read_bytes() == exported
    # with the proof files back (a backup that has them) the same start restores the records
    shutil.copytree(kept / "proofs", shop.results / "proofs", dirs_exist_ok=True)
    resumed = run(shop, capsys, *mode)
    assert resumed.code == 0, resumed.err
    assert shop.journal.read_bytes().startswith(exported)


def test_a_failed_final_export_is_a_note_of_the_result_and_not_an_exit_code(
    tmp_path: Path,
) -> None:
    """The exit code describes the journal (specification §12.2). An export that fails after the
    start (here: the directory is replaced by another journal's export during the run) is
    reported in the log, in the status and as a note of the result.

    The replacement follows every successful export: ``export.ok`` is logged when the
    coordinator collects a finished export and before it starts the next one, so the final
    export always finds the other journal. (Replacing at the first progress line raced with the
    first export, which runs in its own thread and could overwrite the copy.)"""
    shop = c.made(tmp_path / "a", {"f": c.SHALLOW}, solver=SPLITTING)
    donor = c.made(tmp_path / "donor", {"f": c.SHALLOW}, solver=SPLITTING)
    foreign = tmp_path / "foreign"
    given = api.run(
        c.t.config(donor.root, donor.campaign, donor.tools), api.RunOptions(export=foreign)
    )
    assert given.exit_code == 0
    export = tmp_path / "export"
    lines: list[str] = []

    def sink(line: str) -> None:
        lines.append(line)
        if " export.ok " in line:  # the startup comparison has passed; no export is running
            for data in foreign.iterdir():
                if data.name != "export.json":
                    shutil.copy2(data, export / data.name)
            shutil.copy2(foreign / "export.json", export / "export.json.tmp")
            os.replace(export / "export.json.tmp", export / "export.json")  # the descriptor last

    result = api.run(
        c.t.config(shop.root, shop.campaign, shop.tools),
        api.RunOptions(export=export, log_sink=sink, log_level="debug"),
    )
    assert result.exit_code == 0
    assert any("the final export failed (export.foreign" in note for note in result.notes)
    assert any("export.failed" in line for line in lines)
    status = parse_document((shop.results / "status.json").read_bytes())
    assert status["info"]["export"]["consecutive_failures"] >= 1
