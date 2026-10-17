"""Reading the inbox and moving its files (specification §7.4, §7.5): kinds, caching, repeatable
moves."""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from cp_handoff_support import (
    VARIABLES,
    Crash,
    CrashCalls,
    Gate,
    drop_request,
    drop_shard,
    publish,
    request_of,
    shard_of,
)

from cubeproof.base.canonical_json import document_bytes
from cubeproof.base.errors import IntegrityError
from cubeproof.base.settings import ReaderLimits
from cubeproof.coordinator.inbox import (
    ACCEPTED,
    InboxFile,
    Kind,
    move_into,
    read_file,
    scan,
    write_reason,
)
from cubeproof.coordinator.outbox import clean_staging


def kinds(directory: Path, **options: object) -> dict[str, Kind]:
    known: dict[str, InboxFile] = {}
    found = scan(directory, known, variables=VARIABLES, **options)  # type: ignore[arg-type]
    return {f.name: f.kind for f in found}


def test_files_are_classified_by_their_content(tmp_path: Path) -> None:
    shard = shard_of([("a", (1,)), ("a", (-1,))])
    drop_shard(tmp_path, shard, "one.json")
    drop_request(tmp_path, request_of("out", 3), "req.json")
    publish(tmp_path / "other.json", document_bytes({"format": "something-else"}))
    publish(tmp_path / "list.json", document_bytes([1, 2]))
    assert kinds(tmp_path) == {
        "one.json": Kind.SHARD,
        "req.json": Kind.REQUEST,
        "other.json": Kind.INVALID,
        "list.json": Kind.INVALID,
    }
    known: dict[str, InboxFile] = {}
    by_name = {f.name: f for f in scan(tmp_path, known, variables=VARIABLES)}
    assert by_name["one.json"].shard == shard
    assert by_name["req.json"].request == request_of("out", 3)
    assert by_name["other.json"].rule == "inbox.format"
    assert (
        by_name["one.json"].sha256
        == __import__("hashlib").sha256((tmp_path / "one.json").read_bytes()).hexdigest()
    )


def test_a_canonical_document_that_is_not_a_valid_shard_is_invalid_not_unreadable(
    tmp_path: Path,
) -> None:
    good = shard_of([("a", (1,)), ("a", (-1,))]).to_json()
    overlapping = {**good, "nodes": [good["nodes"][0], good["nodes"][0]]}
    publish(tmp_path / "overlap.json", document_bytes(overlapping))
    foreign = shard_of([("a", (1,))]).to_json()
    foreign["nodes"][0]["formula_sha256"] = "cd" * 32
    publish(tmp_path / "foreign.json", document_bytes(foreign))
    assert kinds(tmp_path) == {"overlap.json": Kind.INVALID, "foreign.json": Kind.INVALID}
    known: dict[str, InboxFile] = {}
    rules = {f.name: f.rule for f in scan(tmp_path, known, variables=VARIABLES)}
    assert rules == {"overlap.json": "shard.nodes", "foreign.json": "record.formula"}


def test_files_that_may_still_be_in_transit_are_unreadable_and_stay(tmp_path: Path) -> None:
    (tmp_path / "half.json").write_bytes(b'{"format":"cubeproof-shard-1","campa')
    (tmp_path / "empty.json").write_bytes(b"")
    (tmp_path / "pretty.json").write_bytes(b'{ "format": "x" }\n')
    (tmp_path / "bom.json").write_bytes(b"\xef\xbb\xbf{}\n")
    assert set(kinds(tmp_path).values()) == {Kind.UNREADABLE}
    assert len(kinds(tmp_path)) == 4


def test_names_of_files_being_written_and_directories_are_ignored(tmp_path: Path) -> None:
    for name in (".hidden", "x.json.tmp", "y.part"):
        (tmp_path / name).write_bytes(b"{}")
    (tmp_path / "accepted").mkdir()
    (tmp_path / "accepted" / "inner.json").write_bytes(b"{}")
    assert kinds(tmp_path) == {}


def test_a_link_is_not_followed(tmp_path: Path) -> None:
    target = tmp_path / "elsewhere.json"
    drop_shard(tmp_path / "other", shard_of([("a", ())]), "real.json")
    os.symlink(tmp_path / "other" / "real.json", tmp_path / "inbox.json")
    assert target.exists() is False
    known: dict[str, InboxFile] = {}
    (item,) = scan(tmp_path, known, variables=VARIABLES)
    assert item.kind is Kind.UNREADABLE and item.rule == "io.not_regular"


def test_a_document_over_the_limit_is_unreadable(tmp_path: Path) -> None:
    drop_shard(tmp_path, shard_of([("a", (1,)), ("a", (-1,))]), "big.json")
    limits = ReaderLimits(document_bytes=50)
    known: dict[str, InboxFile] = {}
    (item,) = scan(tmp_path, known, limits=limits, variables=VARIABLES)
    assert (item.kind, item.rule) == (Kind.UNREADABLE, "limit.document")


def test_a_file_is_read_again_only_when_it_changes(tmp_path: Path) -> None:
    path = drop_shard(tmp_path, shard_of([("a", ())]), "s.json")
    known: dict[str, InboxFile] = {}
    (first,) = scan(tmp_path, known, variables=VARIABLES)
    (second,) = scan(tmp_path, known, variables=VARIABLES)
    assert second is first
    publish(path, document_bytes(shard_of([("a", (1,))]).to_json()))
    (third,) = scan(tmp_path, known, variables=VARIABLES)
    assert third is not first and third.shard == shard_of([("a", (1,))])
    path.unlink()
    assert scan(tmp_path, known, variables=VARIABLES) == [] and known == {}


def test_a_half_written_file_becomes_a_shard_when_it_is_complete(tmp_path: Path) -> None:
    data = document_bytes(shard_of([("a", ())]).to_json())
    path = tmp_path / "s.json"
    path.write_bytes(data[:20])
    known: dict[str, InboxFile] = {}
    assert scan(tmp_path, known, variables=VARIABLES)[0].kind is Kind.UNREADABLE
    path.write_bytes(data)
    assert scan(tmp_path, known, variables=VARIABLES)[0].kind is Kind.SHARD


def test_a_missing_directory_is_empty(tmp_path: Path) -> None:
    assert scan(tmp_path / "nowhere", {}, variables=VARIABLES) == []


def test_read_file_reports_a_vanished_file(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        read_file(tmp_path / "gone.json", (0, 0, 0))


# -- moves -------------------------------------------------------------------------------------


def digest(path: Path) -> str:
    import hashlib

    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_a_move_puts_the_file_into_the_folder_and_removes_it_from_the_inbox(tmp_path: Path) -> None:
    path = drop_shard(tmp_path, shard_of([("a", ())]), "s.json")
    data = path.read_bytes()
    target = move_into(path, tmp_path / ACCEPTED, digest(path))
    assert target == tmp_path / ACCEPTED / "s.json" and target.read_bytes() == data
    assert not path.exists()


def test_a_move_can_be_repeated_after_every_step(tmp_path: Path) -> None:
    """Crash after each call of a move: the rerun finishes it, whatever state it finds."""
    data = document_bytes(shard_of([("a", ())]).to_json())
    outcomes = set()
    for point in range(1, 40):
        inbox = tmp_path / f"run{point}"
        path = publish(inbox / "s.json", data)
        gate = Gate(point)
        try:
            move_into(path, inbox / ACCEPTED, digest(path), CrashCalls(gate))
        except Crash:
            pass
        else:
            assert gate.fired is None
            break
        # whatever the state: only the inbox file, both, or only the target
        assert path.exists() or (inbox / ACCEPTED / "s.json").exists()
        if path.exists() and (inbox / ACCEPTED / "s.json").exists():
            assert path.read_bytes() == (inbox / ACCEPTED / "s.json").read_bytes()
        move_into(path, inbox / ACCEPTED, digest_of(data))
        assert not path.exists() and (inbox / ACCEPTED / "s.json").read_bytes() == data
        outcomes.add(point)
    assert len(outcomes) >= 6  # the move has several crash points


def digest_of(data: bytes) -> str:
    import hashlib

    return hashlib.sha256(data).hexdigest()


def test_a_name_taken_by_other_bytes_gets_the_hash_suffix(tmp_path: Path) -> None:
    folder = tmp_path / ACCEPTED
    folder.mkdir()
    (folder / "s.json").write_bytes(b"older\n")
    path = drop_shard(tmp_path, shard_of([("a", ())]), "s.json")
    code = digest(path)
    target = move_into(path, folder, code)
    assert target.name == f"s.json.{code[:16]}" and (folder / "s.json").read_bytes() == b"older\n"
    # the same file again (a second copy with the same bytes) joins the first one
    again = drop_shard(tmp_path, shard_of([("a", ())]), "s.json")
    assert move_into(again, folder, code) == target
    (folder / f"s.json.{code[:16]}").write_bytes(b"x")
    third = drop_shard(tmp_path, shard_of([("a", ())]), "s.json")
    with pytest.raises(IntegrityError) as caught:
        move_into(third, folder, code)
    assert caught.value.rule == "inbox.move"
    assert third.exists()  # nothing was lost


def test_a_reason_is_written_once_and_kept(tmp_path: Path) -> None:
    write_reason(tmp_path, "bad.json", "shard.overlap", "first words")
    write_reason(tmp_path, "bad.json", "shard.overlap", "other words")
    assert (tmp_path / "bad.json.reason.txt").read_text() == "shard.overlap: first words\n"
    write_reason(tmp_path, "plain.json", "inbox.format", "")
    assert (tmp_path / "plain.json.reason.txt").read_text() == "inbox.format\n"


def test_staging_files_of_interrupted_publications_are_cleaned(tmp_path: Path) -> None:
    keep = tmp_path / "out.json"
    keep.write_bytes(b"{}\n")
    stale = tmp_path / (".out.json." + "ab" * 16 + ".tmp")
    stale.write_bytes(b"half")
    (tmp_path / ".other").write_bytes(b"not ours")
    (tmp_path / ("x" + "ab" * 16 + ".tmp")).write_bytes(b"no dot")
    assert clean_staging(tmp_path) == 1
    assert not stale.exists() and keep.exists() and (tmp_path / ".other").exists()
    assert clean_staging(tmp_path) == 0
    assert clean_staging(tmp_path / "missing") == 0


def test_a_change_is_seen_whatever_part_of_the_signature_it_changes(tmp_path: Path) -> None:
    first = shard_of([("a", (1,))])
    second = shard_of([("a", (2,))])  # same size
    assert len(document_bytes(first.to_json())) == len(document_bytes(second.to_json()))
    path = drop_shard(tmp_path, first, "s.json")
    known: dict[str, InboxFile] = {}
    (before,) = scan(tmp_path, known, variables=VARIABLES)
    stat = path.stat()
    # same size, same inode, only the modification time moves
    with path.open("r+b") as stream:
        stream.write(document_bytes(second.to_json()))
    os.utime(path, ns=(stat.st_atime_ns, stat.st_mtime_ns + 5_000_000))
    (after,) = scan(tmp_path, known, variables=VARIABLES)
    assert before.shard == first and after.shard == second
    # same size, same modification time, only the file (inode) is another
    now = path.stat()
    replacement = tmp_path / "other.tmp"
    replacement.write_bytes(document_bytes(first.to_json()))
    os.utime(replacement, ns=(now.st_atime_ns, now.st_mtime_ns))
    os.replace(replacement, path)
    (again,) = scan(tmp_path, known, variables=VARIABLES)
    assert again.shard == first


def test_a_file_replaced_after_it_was_read_is_not_moved(tmp_path: Path) -> None:
    path = drop_shard(tmp_path, shard_of([("a", (1,))]), "s.json")
    code = digest(path)
    drop_shard(tmp_path, shard_of([("a", (2,))]), "s.json")  # a new version, published meanwhile
    with pytest.raises(IntegrityError) as caught:
        move_into(path, tmp_path / ACCEPTED, code)
    assert caught.value.rule == "inbox.changed" and path.exists()
    assert not (tmp_path / ACCEPTED).exists() or not list((tmp_path / ACCEPTED).iterdir())
