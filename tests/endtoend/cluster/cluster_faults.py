"""Fault corpus: the deterministic durable boundaries of specification §7.5, as files.

Each function builds the state that a crash at one boundary of the crash table leaves on disk
(specification §7.1-§7.5), from a real campaign of the fake tools, and then restarts the
worker through the command line and checks the recovery the table prescribes. A journal
prefix that ends at a record boundary is exactly what a crash between two appends leaves
(every append is durable before the next one starts, specification §7.1); the files around it
are put in the state the protocol order implies at that point (specification §6.1 step 6-7,
§7.2, §7.4):

======================================  =========================================================
specification §7.5 crash point          state built here
======================================  =========================================================
during CNF/solve/seal/check             SIGKILL of the process group while the solver runs
                                        (the fake solver announces its start in a file)
artifact published, attempt not         retain: journal cut before the last attempt with a
committed                               retained proof, the published proof kept; plus a
                                        partial copy in ``proofs/tmp/``
attempt committed, cleanup missing      journal cut after the last verified attempt; its work
                                        files (named in its diagnostics) put back
shard committed, inbox move missing     receiver journal cut after the accepted shard record;
                                        the shard file back in ``inbox/``
handoff committed, output missing       giver journal cut after the handoff record; output
                                        removed, the request back in ``inbox/``
node_stop / split follow-up missing     journal cut after the attempt that implies it (two
                                        failed attempts with ``tool_retries`` 1; EXHAUSTED)
full last line corrupt                  one hexadecimal digit of the last ``self`` changed
last suffix lacks LF                    a partial record appended without LF
======================================  =========================================================

Every function returns a JSON record whose ``problems`` list is empty when the recovery is
the one specification §7.5 requires.
"""

from __future__ import annotations

import hashlib
import json
import shutil
from collections.abc import Callable, Mapping
from dataclasses import replace
from pathlib import Path
from typing import Any

import cluster_harness as h

e2e = h.e2e

#: one campaign for every row: two unsatisfiable formulas, statically split once and split
#: again by the dynamic splitter (the fake solver runs out of memory above eight free variables)
WORKLOAD = h.fake_workloads()["php"]


def write_prefix(worker: h.Worker, keep: Callable[[dict[str, Any]], bool]) -> bytes:
    """Rewrite the worker's journal as the prefix of its complete records while ``keep``
    holds. Its export directory goes too: an export never holds more than the journal, so a
    crash cannot leave one that is ahead of it. The state cache stays, although it is ahead of
    the cut journal: stricter than a crash state, it must be detected and replaced by a full
    replay (specification §7.3)."""
    kept = bytearray()
    for line in e2e.complete_lines(worker.journal).splitlines(keepends=True):
        if not keep(json.loads(line)):
            break
        kept += line
    worker.journal.write_bytes(bytes(kept))
    shutil.rmtree(worker.export, ignore_errors=True)
    return bytes(kept)


def single(root: Path, tools: e2e.Tools, mode: str, workload: h.Workload = WORKLOAD) -> h.Worker:
    """One worker that owns every root (no shard), run to the end."""
    campaign = h.make_campaign(root, workload, tools, mode)
    worker = h.Worker("w1", root / "w1", campaign, tools, mode, None, 3)
    end = worker.run()
    if end.code not in h.DONE:
        raise AssertionError(f"base run exit {end.code}: {end.err_tail}")
    return worker


def pair(root: Path, tools: e2e.Tools, mode: str) -> tuple[h.Worker, h.Worker, list[Path]]:
    """Two finished workers of a planned campaign: the giver was stopped, asked for work,
    restarted (it served the request at once) and finished; the receiver accepted its shard
    and the delivered one and finished. No crash."""
    campaign = h.make_campaign(root, WORKLOAD, tools, mode)
    shards = h.plan_shards(campaign, 2, root / "shards")
    giver = h.Worker("wa", root / "wa", campaign, tools, mode, shards[0], 3)
    receiver = h.Worker("wb", root / "wb", campaign, tools, mode, shards[1], 3)
    live = giver.start()
    if live.until(lambda: any(r["type"] == "attempt" for r in giver.records())):
        live.send("SIGINT")
    live.wait()
    giver.handoff(2, "gift", 0)
    for worker in (giver, receiver):
        if worker is receiver and h.deliver(giver, receiver) is None:
            raise AssertionError("the giver published no shard")
        end = worker.run()
        if end.code not in h.DONE:
            raise AssertionError(f"base {worker.name} exit {end.code}: {end.err_tail}")
    return giver, receiver, shards


def _restart(
    worker: h.Worker, record: dict[str, Any], expect: tuple[int, ...] = h.DONE
) -> h.RunEnd:
    end = worker.run()
    record["restart"] = end.to_json()
    if end.code not in expect:
        record["problems"].append(f"restart exit {end.code}: {end.err_tail}")
    return end


def _certify(
    campaign: Path, journals: list[Path], out: Path, record: dict[str, Any], verdict: str = "PROVED"
) -> e2e.Certified:
    certified = e2e.certify_both(campaign, journals, out)
    record["problems"] += [f"certify: {p}" for p in certified.problems()]
    if certified.main_bytes is None or certified.verdict != verdict:
        record["problems"].append(
            f"certify: verdict {certified.verdict if certified.main_bytes else None} != {verdict}"
        )
    return certified


def _differ(final: e2e.Certified, reference: e2e.Certified) -> bool:
    """Both certificates exist and their run-independent content differs."""
    if final.main_bytes is None or reference.main_bytes is None:
        return False
    return bool(e2e.semantic(final.certificate) != e2e.semantic(reference.certificate))


def _base_record(row: str, mode: str) -> dict[str, Any]:
    return {"scenario": "boundary", "row": row, "mode": mode, "problems": []}


def _journal_checks(worker: h.Worker, prefix: bytes, record: dict[str, Any]) -> None:
    data = e2e.complete_lines(worker.journal)
    if not data.startswith(prefix):
        record["problems"].append("the restarted journal does not extend the crash prefix")
    record["problems"] += list(e2e.resume_invariants(b"", worker.journal, worker.starts - 1))
    if worker.work_files():
        record["problems"].append(f"work files left: {worker.work_files()}")


def during_solve(root: Path, tools: e2e.Tools, mode: str = "transient") -> dict[str, Any]:
    """Crash while the solver runs, before any terminal record of that attempt: the startup
    removes the unreferenced work files and the node is pending again (specification §7.5
    row 1)."""
    record = _base_record("during CNF/solve/seal/check, before terminal append", mode)
    campaign = h.make_campaign(root, WORKLOAD, tools, mode)
    ready = root / "solver-started"
    tools.configure_fake(**{**WORKLOAD.fake_solver, "sleep": 30, "ready": str(ready)})
    worker = h.Worker("w1", root / "w1", campaign, tools, mode, None, 3)
    live = worker.start()
    landed = live.until(ready.exists, 60.0)
    attempts_before = len(e2e.attempts(worker.journal))
    live.send("SIGKILL")
    live.wait()
    record["landed"] = landed
    record["attempts_at_crash"] = attempts_before
    record["work_files_after_crash"] = worker.work_files()
    if not landed:
        record["problems"].append("the solver never started before the crash")
    if len(e2e.attempts(worker.journal)) != attempts_before:
        record["problems"].append("a terminal record appeared for the killed attempt")
    if not worker.work_files():
        record["problems"].append("the crash left no work file (nothing to recover)")
    prefix = e2e.complete_lines(worker.journal)
    tools.configure_fake(**WORKLOAD.fake_solver)
    end = _restart(worker, record)
    if not any(
        "removed" in n and "work directory" in n for n in (end.document or {}).get("notes", [])
    ):
        record["problems"].append("the restart did not report the removed work files")
    _journal_checks(worker, prefix, record)
    _certify(campaign, [worker.journal], root / "certify", record)
    return record


def published_not_committed(root: Path, tools: e2e.Tools) -> dict[str, Any]:
    """Retain: a crash after the proof was published (specification §7.2 step 3) and before its
    attempt was appended (step 4). The startup removes the unreferenced published file and a
    partial temporary copy; the node is solved again; every committed retained proof stays."""
    record = _base_record("artifact published, attempt not committed", "retain")
    worker = single(root, tools, "retain")
    reference = e2e.certify_both(worker.campaign, [worker.journal], root / "certify-reference")
    retained = [a for a in e2e.attempts(worker.journal) if a.get("retained")]
    last = retained[-1]
    published = worker.results / last["retained"]["path"]
    prefix = write_prefix(worker, lambda r: r["seq"] < last["seq"])
    tmp = worker.results / "proofs" / "tmp" / "00000000000000000000000000000000.lrat"
    tmp.parent.mkdir(parents=True, exist_ok=True)
    tmp.write_bytes(published.read_bytes()[: max(1, published.stat().st_size // 2)])
    record["cut_before_seq"] = last["seq"]
    record["orphans_before_restart"] = h.orphan_proofs(worker)
    if not published.exists() or not record["orphans_before_restart"]:
        record["problems"].append("the constructed state has no published uncommitted proof")
    _restart(worker, record)
    again = [
        a
        for a in e2e.attempts(worker.journal)
        if a["node_id"] == last["node_id"] and a["seq"] >= last["seq"]
    ]
    if not any(a["outcome"] == "VERIFIED_UNSAT" for a in again):
        record["problems"].append("the node of the uncommitted attempt was not solved again")
    if tmp.exists():
        record["problems"].append("the partial temporary copy survived the restart")
    record["orphans_after_restart"] = h.orphan_proofs(worker)
    if record["orphans_after_restart"]:
        record["problems"].append(
            f"unreferenced proofs after the restart: {record['orphans_after_restart']}"
        )
    missing, count = h.retained_problems(worker)
    record["problems"] += missing
    record["retained"] = count
    done, document = h.verify_retained(
        worker.campaign, [worker.journal], worker.results, root / "verify", tools
    )
    record["verify_retained"] = document
    if done.code != 0 or document is None or document["verified"] != count:
        record["problems"].append(f"verify-retained exit {done.code}: {document}")
    _journal_checks(worker, prefix, record)
    final = _certify(worker.campaign, [worker.journal], root / "certify", record)
    if _differ(final, reference):
        record["problems"].append("the recovered certificate differs from the uncut run")
    return record


def committed_cleanup_missing(
    root: Path, tools: e2e.Tools, mode: str = "transient"
) -> dict[str, Any]:
    """A crash after the attempt was appended but before its work files were deleted: the
    startup removes them and the committed attempt is not solved again (specification §7.5
    row 3)."""
    record = _base_record("attempt committed, acknowledgement/cleanup missing", mode)
    worker = single(root, tools, mode)
    last = [a for a in e2e.attempts(worker.journal) if a["outcome"] == "VERIFIED_UNSAT"][-1]
    prefix = write_prefix(worker, lambda r: r["seq"] <= last["seq"])
    worker.work.mkdir(parents=True, exist_ok=True)
    names = [f["name"] for f in last["diagnostics"].get("files", {}).values() if f.get("name")]
    for name in names:
        (worker.work / name).write_bytes(b"left behind by the crash\n")
    record["cut_after_seq"] = last["seq"]
    record["work_files_put_back"] = names
    if not names:
        record["problems"].append("the attempt names no work file")
    _restart(worker, record)
    again = [a for a in e2e.attempts(worker.journal) if a["node_id"] == last["node_id"]]
    if len(again) != 1:
        record["problems"].append(f"the committed attempt's node has {len(again)} attempts")
    _journal_checks(worker, prefix, record)
    _certify(worker.campaign, [worker.journal], root / "certify", record)
    return record


def shard_move_missing(root: Path, tools: e2e.Tools, mode: str = "transient") -> dict[str, Any]:
    """A crash after the receiver committed a delivered shard and before it moved the file to
    ``accepted/``: the restart recognizes the shard hash, finishes the move, accepts nothing
    twice and works on the shard (specification §7.5 row 4)."""
    record = _base_record("shard committed, inbox move missing", mode)
    giver, receiver, _ = pair(root, tools, mode)
    gift = giver.handoffs()[0]
    accepted = receiver.inbox / "accepted" / "gift.json"
    shutil.move(accepted, receiver.inbox / "gift.json")
    shard_seq = next(
        r["seq"]
        for r in receiver.records()
        if r["type"] == "shard" and r["shard_sha256"] == gift["shard_sha256"]
    )
    prefix = write_prefix(receiver, lambda r: r["seq"] <= shard_seq)
    record["cut_after_seq"] = shard_seq
    _restart(receiver, record)
    if (receiver.inbox / "gift.json").exists() or not accepted.exists():
        record["problems"].append("the inbox move was not finished")
    if receiver.shard_hashes().count(str(gift["shard_sha256"])) != 1:
        record["problems"].append("the delivered shard was accepted more than once")
    _journal_checks(receiver, prefix, record)
    _certify(giver.campaign, [giver.journal, receiver.journal], root / "certify", record)
    return record


def handoff_output_missing(root: Path, tools: e2e.Tools, mode: str = "transient") -> dict[str, Any]:
    """A crash after the giver committed the handoff and before it published the output: the
    restart recreates the same bytes from the record, keeps the given nodes excluded and marks
    the request processed (specification §7.5 row 5)."""
    record = _base_record("handoff committed, output missing", mode)
    giver, receiver, shards = pair(root, tools, mode)
    gift = giver.handoffs()[0]
    output = giver.outbox / "gift.json"
    original = output.read_bytes()
    output.unlink()
    shutil.move(giver.inbox / "processed" / "gift.request.json", giver.inbox / "gift.request.json")
    prefix = write_prefix(giver, lambda r: r["seq"] <= gift["seq"])
    record["cut_after_seq"] = gift["seq"]
    _restart(giver, record)
    if not output.exists() or output.read_bytes() != original:
        record["problems"].append("the output was not recreated with the same bytes")
    if len(giver.handoffs()) != 1:
        record["problems"].append("a second handoff was committed")
    if not (giver.inbox / "processed" / "gift.request.json").exists():
        record["problems"].append("the request was not marked processed")
    record["problems"] += h.exclusion_problems(
        giver, receiver, [*h.shard_nodes(shards[1]), *h.nodes_of(gift["shard"])]
    )
    _journal_checks(giver, prefix, record)
    _certify(giver.campaign, [giver.journal, receiver.journal], root / "certify", record)
    return record


def split_follow_up_missing(
    root: Path, tools: e2e.Tools, mode: str = "transient"
) -> dict[str, Any]:
    """A crash after an EXHAUSTED attempt and before its split: the replay issues the split
    once before that node is scheduled again (specification §7.3, §7.5 row 6)."""
    record = _base_record("split follow-up missing", mode)
    worker = single(root, tools, mode)
    reference = e2e.certify_both(worker.campaign, [worker.journal], root / "certify-reference")
    exhausted = [a for a in e2e.attempts(worker.journal) if a["outcome"] == "EXHAUSTED"][-1]
    prefix = write_prefix(worker, lambda r: r["seq"] <= exhausted["seq"])
    record["cut_after_seq"] = exhausted["seq"]
    _restart(worker, record)
    key = h.node_key(exhausted)
    splits = [r for r in worker.records() if r["type"] == "split" and h.node_key(r) == key]
    attempts = [a for a in e2e.attempts(worker.journal) if h.node_key(a) == key]
    if len(splits) != 1 or len(attempts) != 1:
        record["problems"].append(
            f"{len(splits)} splits and {len(attempts)} attempts of the exhausted node"
        )
    _journal_checks(worker, prefix, record)
    final = _certify(worker.campaign, [worker.journal], root / "certify", record)
    if _differ(final, reference):
        record["problems"].append("the recovered certificate differs from the uncut run")
    return record


def node_stop_follow_up_missing(
    root: Path, tools: e2e.Tools, mode: str = "transient"
) -> dict[str, Any]:
    """Leaves whose solver crashes: two TOOL_FAILED attempts (``tool_retries`` 1) and then
    ``node_stop(tool_blocked)``. A crash after the second failure and before the stop: the
    replay derives and persists the stop before that node is scheduled (specification §6.5,
    §7.5 row 6)."""
    record = _base_record("node_stop follow-up missing", mode)
    workload = replace(
        WORKLOAD,
        fake_solver={**WORKLOAD.fake_solver, "crash_if_free_le": 8},
        policy_changes={"machine_failure_limit": 1000},
    )
    campaign = h.make_campaign(root, workload, tools, mode)
    worker = h.Worker("w1", root / "w1", campaign, tools, mode, None, 3)
    first = worker.run()
    record["base_exit"] = first.code
    stops = [r for r in worker.records() if r["type"] == "node_stop"]
    if not stops:
        record["problems"].append("the base run recorded no node_stop")
        return record
    stop = stops[0]
    key = h.node_key(stop)
    failed = [a for a in e2e.attempts(worker.journal) if h.node_key(a) == key]
    record["failed_attempts_before_stop"] = [a["outcome"] for a in failed]
    prefix = write_prefix(worker, lambda r: r["seq"] < stop["seq"])
    record["cut_before_seq"] = stop["seq"]
    _restart(worker, record, (first.code,))
    again = [r for r in worker.records() if r["type"] == "node_stop" and h.node_key(r) == key]
    attempts = [a for a in e2e.attempts(worker.journal) if h.node_key(a) == key]
    if len(again) != 1 or again[0]["state"] != "tool_blocked":
        record["problems"].append(f"{len(again)} node_stop records of the blocked node")
    if len(attempts) != len(failed):
        record["problems"].append("the blocked node was attempted again before its stop")
    _journal_checks(worker, prefix, record)
    _certify(campaign, [worker.journal], root / "certify", record, "OPEN")
    return record


def last_line_corrupt(root: Path, tools: e2e.Tools, mode: str = "transient") -> dict[str, Any]:
    """A complete last line whose ``self`` is wrong: an integrity error for run, verify,
    repair and both certifiers; nothing truncates or rewrites the journal (specification §7.1,
    §7.5 row 7)."""
    record = _base_record("full last line corrupt", mode)
    worker = single(root, tools, mode)
    data = worker.journal.read_bytes()
    lines = data.splitlines(keepends=True)
    last = json.loads(lines[-1])
    digit = "0" if last["self"][-1] != "0" else "1"
    lines[-1] = lines[-1].replace(last["self"].encode(), (last["self"][:-1] + digit).encode())
    damaged = b"".join(lines)
    worker.journal.write_bytes(damaged)
    codes: dict[str, Any] = {}
    end = worker.run()
    codes["run"] = end.code
    for action in ("verify", "repair"):
        done = e2e.execute(
            e2e.cubeproof(
                "journal", action, "--campaign", str(worker.campaign), str(worker.journal)
            )
        )
        codes[f"journal {action}"] = done.code
    certified = e2e.certify_both(worker.campaign, [worker.journal], root / "certify")
    codes["certify"] = [certified.main.code, certified.independent.code]
    record["exit_codes"] = codes
    if end.code != 4 or codes["journal verify"] != 4 or codes["journal repair"] == 0:
        record["problems"].append(f"exit codes {codes}")
    if certified.main.code != 4 or certified.independent.code != 4:
        record["problems"].append(f"certifiers: {codes['certify']}")
    if certified.main_bytes is not None or certified.independent_bytes is not None:
        record["problems"].append("a certificate was written for a damaged journal")
    if worker.journal.read_bytes() != damaged:
        record["problems"].append("the damaged journal was changed")
    return record


def torn_tail(root: Path, tools: e2e.Tools, mode: str = "transient") -> dict[str, Any]:
    """A last suffix without LF: both certifiers ignore it and agree; ``journal repair`` (on a
    copy) and the next run remove only that suffix and record the repair (specification §7.1,
    §7.5 row 8)."""
    record = _base_record("last suffix lacks LF", mode)
    campaign = h.make_campaign(root, WORKLOAD, tools, mode)
    worker = h.Worker("w1", root / "w1", campaign, tools, mode, None, 3)
    live = worker.start()
    if live.until(lambda: len(e2e.attempts(worker.journal)) >= 6):
        live.send("SIGINT")
    record["stopped"] = live.wait().to_json()
    prefix = e2e.complete_lines(worker.journal)
    tail = b'{"format":"cubeproof-journal-1","prev":"'
    worker.journal.write_bytes(prefix + tail)
    torn = _certify(campaign, [worker.journal], root / "certify-torn", record, "OPEN")
    if torn.main_bytes is not None:
        record["torn_ignored"] = True
    copy = root / "copy" / "journal.jsonl"
    copy.parent.mkdir(parents=True)
    shutil.copyfile(worker.journal, copy)
    repaired = e2e.execute(
        e2e.cubeproof("journal", "repair", "--campaign", str(campaign), str(copy))
    )
    verified = e2e.execute(
        e2e.cubeproof("journal", "verify", "--campaign", str(campaign), str(copy))
    )
    record["journal_repair"] = [repaired.code, verified.code]
    if repaired.code != 0 or verified.code != 0 or not copy.read_bytes().startswith(prefix):
        record["problems"].append(f"journal repair/verify on the copy: {record['journal_repair']}")
    _restart(worker, record)
    repairs = [r for r in worker.records() if r["type"] == "repair"]
    expected = {"removed_bytes": len(tail), "removed_sha256": hashlib.sha256(tail).hexdigest()}
    if len(repairs) != 1 or {k: repairs[0][k] for k in expected} != expected:
        record["problems"].append(f"repair records: {repairs}")
    _journal_checks(worker, prefix, record)
    _certify(campaign, [worker.journal], root / "certify", record)
    return record


ROWS: Mapping[str, Callable[[Path, e2e.Tools], dict[str, Any]]] = {
    "during-solve": during_solve,
    "published-not-committed": published_not_committed,
    "committed-cleanup-missing": committed_cleanup_missing,
    "shard-move-missing": shard_move_missing,
    "handoff-output-missing": handoff_output_missing,
    "split-follow-up-missing": split_follow_up_missing,
    "node-stop-follow-up-missing": node_stop_follow_up_missing,
    "last-line-corrupt": last_line_corrupt,
    "torn-tail": torn_tail,
}

#: the rows that run in any proof mode (the published-artifact row is retain by definition)
MODE_ROWS: Mapping[str, Callable[[Path, e2e.Tools, str], dict[str, Any]]] = {
    "during-solve": during_solve,
    "committed-cleanup-missing": committed_cleanup_missing,
    "shard-move-missing": shard_move_missing,
    "handoff-output-missing": handoff_output_missing,
    "split-follow-up-missing": split_follow_up_missing,
    "node-stop-follow-up-missing": node_stop_follow_up_missing,
    "last-line-corrupt": last_line_corrupt,
    "torn-tail": torn_tail,
}
