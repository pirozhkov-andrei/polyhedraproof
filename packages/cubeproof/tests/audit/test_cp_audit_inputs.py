"""A certificate bound to the exact journal prefixes it certified (specification §11.1, §4.9).

The certificate is a claim. Binding copies the certified prefix of every journal into a
read-only snapshot, re-runs the certifier on the snapshots and requires the claim to be the
recomputed certificate before any target is chosen. Covered here: source journal
appended after the certificate, wrong head, tampered used list, restart with preserved
snapshots.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

import cp_audit_support as s

from cubeproof.base.canonical_json import json_sha256
from cubeproof.base.errors import InputError, IntegrityError
from cubeproof.base.settings import ReaderLimits
from cubeproof.cnf.campaign import load_campaign
from cubeproof.commands.audit_inputs import bind_certified_inputs, read_certificate
from cubeproof.evidence.certify.run import certify_campaign


def bind(files: s.CaseFiles, *, journals: Any = None, snapshots: Path | None = None) -> Any:
    return bind_certified_inputs(
        files.campaign,
        files.journals if journals is None else journals,
        files.certificate,
        snapshots or files.root / "snapshots",
    )


def edit_certificate(files: s.CaseFiles, change: Any) -> None:
    value = s.load(files.certificate)
    change(value)
    s.write_document(files.certificate, value)


def test_a_certificate_binds_to_snapshots_of_its_journals(tmp_path: Path) -> None:
    files = s.corpus_case(tmp_path, "alternatives")
    bound = bind(files)
    claim = s.load(files.certificate)
    assert bound.recertified.certificate == claim
    assert bound.certificate.sha256 == json_sha256(claim)
    assert [p.name for p in bound.snapshots] == [f"{j['id']}.jsonl" for j in claim["journals"]]
    for snapshot in bound.snapshots:
        assert os.stat(snapshot).st_mode & 0o222 == 0  # read-only
        source = next(j for j in files.journals if j.read_bytes() == snapshot.read_bytes())
        assert source.exists()


def test_records_appended_after_the_certificate_are_not_incorporated(tmp_path: Path) -> None:
    files = s.corpus_case(tmp_path, "base")
    [journal] = files.journals
    full = journal.read_bytes()
    prefix = b"".join(line + b"\n" for line in full.split(b"\n")[:3])  # header, split, attempt
    journal.write_bytes(prefix)
    campaign = load_campaign(files.campaign)
    early = certify_campaign(campaign, [journal]).certificate
    s.write_document(files.certificate, early)
    journal.write_bytes(full)  # the worker appended two attempts after certification
    bound = bind(files)
    assert bound.snapshots[0].read_bytes() == prefix
    assert bound.recertified.certificate == early
    assert len(early["used_attempts"]) < len(
        certify_campaign(campaign, [journal]).certificate["used_attempts"]
    )


def test_a_torn_tail_of_the_source_is_not_part_of_the_prefix(tmp_path: Path) -> None:
    files = s.corpus_case(tmp_path, "torn_tail")
    bound = bind(files)
    claim = s.load(files.certificate)
    assert claim["journals"][0]["torn_tail_bytes"] > 0
    assert bound.snapshots[0].stat().st_size == claim["journals"][0]["bytes"]
    assert bound.recertified.certificate["journals"][0]["torn_tail_bytes"] == 0


def test_a_wrong_head_is_an_integrity_error(tmp_path: Path) -> None:
    files = s.corpus_case(tmp_path, "base")
    edit_certificate(files, lambda v: v["journals"][0].update(head="ab" * 32))
    with pytest.raises(IntegrityError) as caught:
        bind(files)
    assert caught.value.rule == "journal.anchor"
    assert not list((files.root / "snapshots").glob("*.jsonl"))


@pytest.mark.parametrize(("field", "delta"), [("bytes", 1), ("bytes", -1), ("records", 1)])
def test_a_wrong_prefix_size_is_an_integrity_error(tmp_path: Path, field: str, delta: int) -> None:
    files = s.corpus_case(tmp_path, "base")
    edit_certificate(
        files, lambda v: v["journals"][0].update({field: v["journals"][0][field] + delta})
    )
    with pytest.raises(IntegrityError) as caught:
        bind(files)
    assert caught.value.rule == "journal.anchor"


def _drop_used(value: dict[str, Any]) -> None:
    value["used_attempts"].pop()


def _other_proof(value: dict[str, Any]) -> None:
    value["used_attempts"][0]["proof_sha256"] = "cd" * 32


def _other_record(value: dict[str, Any]) -> None:
    value["used_attempts"][0]["record"]["seq"] += 1


def _verdict(value: dict[str, Any]) -> None:
    value["verdict"] = "OPEN"


@pytest.mark.parametrize("tamper", [_drop_used, _other_proof, _other_record, _verdict])
def test_a_tampered_certificate_is_an_integrity_error(tmp_path: Path, tamper: Any) -> None:
    files = s.corpus_case(tmp_path, "base")
    edit_certificate(files, tamper)
    with pytest.raises(IntegrityError) as caught:
        bind(files)
    assert caught.value.rule == "audit.certificate"


def test_the_certificate_must_be_of_the_campaign(tmp_path: Path) -> None:
    files = s.corpus_case(tmp_path, "base")
    edit_certificate(files, lambda v: v.update(campaign="ef" * 32))
    with pytest.raises(IntegrityError) as caught:
        bind(files)
    assert caught.value.rule == "audit.certificate"


def test_every_journal_must_be_named_by_the_certificate(tmp_path: Path) -> None:
    files = s.corpus_case(tmp_path, "alternatives")
    stranger = s.corpus_case(tmp_path / "other", "split_full").journals[0]
    with pytest.raises(Exception) as caught:
        bind(files, journals=[*files.journals, stranger])
    assert getattr(caught.value, "rule", None) in ("audit.journals", "journal.campaign")
    with pytest.raises(IntegrityError) as missing:
        bind(files, journals=files.journals[:1])
    assert missing.value.rule == "audit.journals"


def test_a_copy_of_a_journal_is_reported_and_not_used(tmp_path: Path) -> None:
    files = s.corpus_case(tmp_path, "duplicates")
    bound = bind(files)
    assert bound.recertified.certificate == s.load(files.certificate)
    assert bound.copies_ignored  # the shorter or torn copies of w1


def test_existing_snapshots_are_revalidated_on_restart(tmp_path: Path) -> None:
    files = s.corpus_case(tmp_path, "base")
    first = bind(files)
    before = first.snapshots[0].read_bytes()
    [journal] = files.journals
    journal.unlink()  # the restart needs only the preserved snapshot
    again = bind(files, journals=[])
    assert again.snapshots[0].read_bytes() == before
    snapshot = again.snapshots[0]
    os.chmod(snapshot, 0o644)
    snapshot.write_bytes(before[:-1] + b" ")
    with pytest.raises(IntegrityError) as caught:
        bind(files, journals=[])
    assert caught.value.rule == "audit.snapshot"


def test_a_certificate_has_no_document_size_limit(tmp_path: Path) -> None:
    # Specification §4.1: the document limit is for campaigns and shards, not certificates
    # (a campaign of 59 formulas at its start has a certificate of about 130 MB).
    files = s.corpus_case(tmp_path, "alternatives")
    size = len(files.certificate.read_bytes())
    below = ReaderLimits(document_bytes=size - 2)  # the document (J without its LF) is size - 1
    assert read_certificate(files.certificate, limits=below).document == s.load(files.certificate)
    bound = bind_certified_inputs(
        files.campaign, files.journals, files.certificate, files.root / "snapshots", limits=below
    )
    assert bound.recertified.certificate == s.load(files.certificate)
    fifo = tmp_path / "fifo.json"
    os.mkfifo(fifo)  # refused without waiting for a writer
    for unusable in (tmp_path, Path("/dev/zero"), fifo):  # read whole only if it is a regular file
        with pytest.raises(InputError) as caught:
            read_certificate(unusable)
        assert caught.value.rule == "audit.certificate_file", unusable


def test_an_unusable_certificate_file_is_an_input_error(tmp_path: Path) -> None:
    files = s.corpus_case(tmp_path, "base")
    files.certificate.write_bytes(b'{"format":"cubeproof-certificate-1"}\n')
    with pytest.raises(InputError) as caught:
        read_certificate(files.certificate)
    assert caught.value.rule == "audit.certificate_file"
    files.certificate.write_bytes(b"not json")
    with pytest.raises(InputError):
        bind(files)
