"""Specification §7.1, §12.1: ``journal verify`` and ``journal repair``.

Both validate with the campaign's context (the certifier's record rules). ``repair`` removes only
a torn tail, records the removal, takes the results directory's run lock without waiting and
leaves any other damage untouched.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import cp_cli_support as c
import pytest

from cubeproof.evidence.journal import RunLock


def finished(root: Path, capsys: pytest.CaptureFixture[str]) -> c.Shop:
    shop = c.made(root, {"f": c.SHALLOW}, solver={"max_free": 3})
    assert c.cli_main(shop.run_args("--jobs", "2"), capsys).code == 0
    return shop


def verify(shop: c.Shop, capsys: pytest.CaptureFixture[str], journal: Path | None = None) -> c.Done:
    return c.cli_main(
        ["journal", "verify", str(journal or shop.journal), "--campaign", str(shop.campaign)],
        capsys,
    )


def repair(shop: c.Shop, capsys: pytest.CaptureFixture[str]) -> c.Done:
    return c.cli_main(
        ["journal", "repair", str(shop.journal), "--campaign", str(shop.campaign)], capsys
    )


def test_verify_reports_the_identity_and_extent_of_a_valid_journal(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    shop = finished(tmp_path, capsys)
    done = verify(shop, capsys)
    assert done.code == 0, done.err
    report = c.last_json(done.out)
    data = shop.journal.read_bytes()
    lines = data.split(b"\n")[:-1]
    assert set(report) == {
        "path",
        "id",
        "worker",
        "purpose",
        "records",
        "bytes",
        "head",
        "torn_tail_bytes",
    }
    assert report["path"] == str(shop.journal)
    assert (report["worker"], report["purpose"], report["records"]) == ("w1", "run", len(lines))
    assert report["bytes"] == len(data) and report["torn_tail_bytes"] == 0
    header, last = json.loads(lines[0]), json.loads(lines[-1])
    assert report["id"] == header["self"] and report["head"] == last["self"]
    assert done.err == ""


def test_verify_refuses_a_journal_of_another_campaign_and_a_missing_file(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    shop = finished(tmp_path / "one", capsys)
    other = c.made(tmp_path / "two", {"g": c.t.unsat(6)}, solver={"max_free": 3})
    wrong = c.cli_main(
        ["journal", "verify", str(shop.journal), "--campaign", str(other.campaign)], capsys
    )
    assert wrong.code == 4 and "[journal.campaign]" in wrong.err
    gone = verify(shop, capsys, tmp_path / "nope.jsonl")
    assert gone.code == 4 and "[journal.file]" in gone.err  # as in certify: unreadable journal
    directory = verify(shop, capsys, tmp_path)
    assert directory.code == 4 and "[journal.file]" in directory.err


def test_a_torn_tail_is_reported_by_verify_and_removed_and_recorded_by_repair(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    shop = finished(tmp_path, capsys)
    clean = shop.journal.read_bytes()
    tail = b'{"seq":999,"type":"att'
    with shop.journal.open("ab") as stream:
        stream.write(tail)
    reported = verify(shop, capsys)
    assert reported.code == 0
    assert c.last_json(reported.out)["torn_tail_bytes"] == len(tail)
    assert "torn tail" in reported.err
    done = repair(shop, capsys)
    assert done.code == 0, done.err
    report = c.last_json(done.out)
    assert set(report) == {"path", "removed_bytes", "removed_sha256", "verified"}
    assert report["removed_bytes"] == len(tail)
    assert report["removed_sha256"] == hashlib.sha256(tail).hexdigest()
    assert report["verified"]["torn_tail_bytes"] == 0
    assert report["verified"]["records"] == len(clean.split(b"\n")[:-1]) + 1  # the repair record
    repaired = shop.journal.read_bytes()
    assert repaired.startswith(clean)
    record = json.loads(repaired[len(clean) :].splitlines()[0])
    assert record["type"] == "repair" and record["removed_bytes"] == len(tail)
    certified = c.cli_main(
        ["certify", "--campaign", str(shop.campaign), "--journals", str(shop.journal)], capsys
    )
    assert certified.code == 0 and certified.out.startswith("PROVED")
    # nothing left to repair: nothing is appended
    again = repair(shop, capsys)
    assert again.code == 0 and c.last_json(again.out)["removed_bytes"] == 0
    assert c.last_json(again.out)["removed_sha256"] is None
    assert shop.journal.read_bytes() == repaired


def test_repair_refuses_a_directory_held_by_a_live_worker_and_waits_for_nobody(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    shop = finished(tmp_path, capsys)
    with shop.journal.open("ab") as stream:
        stream.write(b"torn")
    before = shop.journal.read_bytes()
    with RunLock.acquire(shop.results / "run.lock"):
        done = repair(shop, capsys)
    assert done.code == 3 and "[run.locked]" in done.err
    assert shop.journal.read_bytes() == before
    assert repair(shop, capsys).code == 0  # once the lock is free


def test_repair_leaves_every_other_kind_of_damage_to_restoration(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    shop = finished(tmp_path, capsys)
    lines = shop.journal.read_bytes().split(b"\n")
    lines[2] = lines[2].replace(b'"type"', b'"tYpe"', 1)
    shop.journal.write_bytes(b"\n".join(lines) + b"torn")  # a damaged line and a torn tail
    before = shop.journal.read_bytes()
    done = repair(shop, capsys)
    assert done.code == 4, done.err
    assert shop.journal.read_bytes() == before
    assert verify(shop, capsys).code == 4
    # a journal without a header cannot be repaired from a campaign alone
    empty = tmp_path / "empty" / "journal.jsonl"
    empty.parent.mkdir()
    empty.write_bytes(b"")
    nothing = c.cli_main(
        ["journal", "repair", str(empty), "--campaign", str(shop.campaign)], capsys
    )
    assert nothing.code in (3, 4) and "[journal.no_header]" in nothing.err
    assert empty.read_bytes() == b""
