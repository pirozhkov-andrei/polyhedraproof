"""Specification §4.9, §12.1: portable evidence packages and the manifest ``cubeproof-evidence-1``.

A package holds the campaign, the bundle files, one snapshot per used journal, the certificate
recomputed from those copies and a manifest, published in that dependency order and renamed into
place whole. Readers verify every listed file; the certificate in a package is a claim that is
recomputed, never an input to trust.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import shutil
import stat
from pathlib import Path
from typing import Any

import cp_cli_support as c
import pytest

from cubeproof import api
from cubeproof.base.canonical_json import document_bytes, parse_document
from cubeproof.base.errors import ContractError
from cubeproof.commands import EvidenceManifest, load_evidence, package
from cubeproof.evidence.certify.run import certify, certify_campaign

TWO = {"a": c.t.unsat(8, core=5), "b": c.SHALLOW}


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build(root: Path, capsys: pytest.CaptureFixture[str], *, two_workers: bool = False) -> c.Shop:
    """A campaign over two formulas and its finished run(s)."""
    shop = c.made(root, TWO, solver={"max_free": 3})
    if not two_workers:
        assert c.cli_main(shop.run_args("--jobs", "2"), capsys).code == 0
        return shop
    plan = c.last_json(
        c.cli_main(
            ["shard", "--campaign", str(shop.campaign), "--machines", "2", "-o", str(root / "s")],
            capsys,
        ).out
    )
    for index, entry in enumerate(plan["shards"], 1):
        results = shop.results if index == 1 else root / "results-2"
        done = c.cli_main(
            shop.run_args(
                "--shard", entry["path"], "--jobs", "2", worker=f"w{index}", results=results
            ),
            capsys,
        )
        assert done.code == 0, done.err
    return shop


def journals(shop: c.Shop) -> list[Path]:
    found = [shop.journal]
    second = shop.root / "results-2" / "journal.jsonl"
    return found + ([second] if second.exists() else [])


def package_args(shop: c.Shop, out: Path) -> list[str]:
    return [
        "evidence", "package", "--campaign", str(shop.campaign),
        "--journals", *(str(j) for j in journals(shop)), "-o", str(out),
    ]  # fmt: skip


def packaged(shop: c.Shop, capsys: pytest.CaptureFixture[str], out: Path | None = None) -> Path:
    out = out or shop.root / "package"
    done = c.cli_main(package_args(shop, out), capsys)
    assert done.code == 0, done.err
    return out


# -- the package ----------------------------------------------------------------------------------


def test_a_package_is_the_dependencies_the_certificate_and_a_manifest_of_their_hashes(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    shop = build(tmp_path, capsys, two_workers=True)
    out = tmp_path / "package"
    done = c.cli_main(package_args(shop, out), capsys)
    assert done.code == 0, done.err
    document = c.last_json(done.out)
    assert set(document) == {
        "output", "manifest", "manifest_sha256", "certificate_file_sha256", "campaign", "verdict",
        "bundles", "journals", "duplicates",
    }  # fmt: skip
    assert document["verdict"] == "PROVED" and (document["bundles"], document["journals"]) == (2, 2)
    assert document["duplicates"] == []
    assert document["manifest"] == str(out.resolve() / "evidence.json")
    assert document["manifest_sha256"] == sha(out / "evidence.json")
    # the hashes of the two files as written (what sha256sum prints and the manifest lists);
    # ``certificate_sha256`` is the name of the document hash of audits (specification §4.1,
    # §11.2: J(certificate) without the final LF), which is another number
    certificate_bytes = (out / "certificate.json").read_bytes()
    assert document["certificate_file_sha256"] == sha(out / "certificate.json")
    assert certificate_bytes.endswith(b"\n")
    assert document["certificate_file_sha256"] != hashlib.sha256(certificate_bytes[:-1]).hexdigest()
    assert sorted(str(p.relative_to(out)) for p in out.rglob("*") if p.is_file()) == [
        "bundles/a/formula.cnf", "bundles/a/manifest.json", "bundles/b/formula.cnf",
        "bundles/b/manifest.json", "campaign.json", "certificate.json", "evidence.json",
        "journals/w1.jsonl", "journals/w2.jsonl",
    ]  # fmt: skip
    manifest = parse_document((out / "evidence.json").read_bytes())
    assert set(manifest) == {"format", "campaign", "bundles", "journals", "certificate"}
    assert manifest["format"] == "cubeproof-evidence-1"
    listed = [manifest["campaign"], manifest["certificate"], *manifest["journals"]]
    for bundle in manifest["bundles"]:
        listed += [bundle["manifest"], bundle["formula"]]
    for artifact in listed:
        assert set(artifact) == {"path", "sha256", "bytes"}
        file = out / artifact["path"]
        assert not os.path.isabs(artifact["path"]) and ".." not in artifact["path"].split("/")
        assert sha(file) == artifact["sha256"] and file.stat().st_size == artifact["bytes"]
    assert [j["path"] for j in manifest["journals"]] == ["journals/w1.jsonl", "journals/w2.jsonl"]
    assert [b["manifest"]["path"] for b in manifest["bundles"]] == [
        "bundles/a/manifest.json",
        "bundles/b/manifest.json",
    ]
    # immutable: nothing in the package is writable
    assert all(
        not p.stat().st_mode & (stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH)
        for p in out.rglob("*")
        if p.is_file()
    )
    # the packaged campaign is the campaign (byte for byte), the journals are the journals
    assert (out / "campaign.json").read_bytes() == shop.campaign.read_bytes()
    for copy, source in zip(sorted((out / "journals").iterdir()), journals(shop), strict=True):
        assert copy.read_bytes() == source.read_bytes()
    # the packaged certificate is the certificate of the original inputs
    expected = certify(shop.campaign, journals(shop)).certificate
    assert parse_document((out / "certificate.json").read_bytes()) == expected
    assert not [p for p in tmp_path.iterdir() if p.name.startswith(".")]  # no staging left


def test_a_package_is_portable_and_certifies_without_the_original_files(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    shop = build(tmp_path / "origin", capsys, two_workers=True)
    out = packaged(shop, capsys)
    moved = tmp_path / "elsewhere" / "deep" / "moved"
    moved.parent.mkdir(parents=True)
    shutil.copytree(out, moved)
    shutil.rmtree(tmp_path / "origin")  # the campaign, the bundles and the journals are gone
    done = c.command(
        "certify", "--evidence", str(moved / "evidence.json"), "-o", str(tmp_path / "again.json")
    )
    assert done.code == 0, done.err
    assert done.out.startswith("PROVED")
    assert (tmp_path / "again.json").read_bytes() == (moved / "certificate.json").read_bytes()
    # the same directory under another working directory and a relative manifest path
    relative = c.command("certify", "--evidence", "evidence.json", cwd=moved)
    assert relative.code == 0 and relative.out.startswith("PROVED")


def test_the_dependencies_are_published_before_the_certificate_and_the_manifest_last(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    shop = build(tmp_path, capsys, two_workers=True)
    order: list[str] = []
    write, copy = package._write_bytes, package._copy_prefix

    def logged_write(path: Path, data: bytes) -> None:
        order.append(path.name)
        write(path, data)

    def logged_copy(source: Path, target: Path, count: int) -> None:
        order.append(f"journal:{target.name}")
        copy(source, target, count)

    monkeypatch.setattr(package, "_write_bytes", logged_write)
    monkeypatch.setattr(package, "_copy_prefix", logged_copy)
    packaged(shop, capsys)
    assert order[0] == "campaign.json"
    assert order[-2:] == ["certificate.json", "evidence.json"]
    assert sorted(order[1:-2]) == sorted(
        [
            "manifest.json",
            "formula.cnf",
            "manifest.json",
            "formula.cnf",
            "journal:w1.jsonl",
            "journal:w2.jsonl",
        ]
    )
    assert order.index("journal:w1.jsonl") < order.index("certificate.json")


@pytest.mark.parametrize(
    "fail_at",
    ["campaign.json", "formula.cnf", "journal:w1.jsonl", "certificate.json", "evidence.json"],
)
def test_a_failure_while_packaging_publishes_nothing(
    fail_at: str,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    shop = build(tmp_path, capsys)
    write, copy = package._write_bytes, package._copy_prefix

    def failing_write(path: Path, data: bytes) -> None:
        if path.name == fail_at:
            raise OSError(28, "No space left on device")
        write(path, data)

    def failing_copy(source: Path, target: Path, count: int) -> None:
        if f"journal:{target.name}" == fail_at:
            raise OSError(28, "No space left on device")
        copy(source, target, count)

    monkeypatch.setattr(package, "_write_bytes", failing_write)
    monkeypatch.setattr(package, "_copy_prefix", failing_copy)
    out = tmp_path / "package"
    done = c.cli_main(package_args(shop, out), capsys)
    assert done.code == 5 and "[io.error]" in done.err
    assert not out.exists()
    assert not [
        p for p in tmp_path.iterdir() if p.name.startswith(".")
    ]  # the staging directory is gone
    monkeypatch.undo()
    assert c.cli_main(package_args(shop, out), capsys).code == 0  # and a retry works


def test_snapshots_are_the_certified_prefix_not_a_torn_tail_nor_later_records(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    shop = build(tmp_path, capsys)
    clean = shop.journal.read_bytes()
    with shop.journal.open("ab") as stream:
        stream.write(b'{"torn": tr')  # a write that was cut: no terminating LF
    out = packaged(shop, capsys)
    copy = (out / "journals" / "w1.jsonl").read_bytes()
    assert copy == clean
    certificate = parse_document((out / "certificate.json").read_bytes())
    assert [j["torn_tail_bytes"] for j in certificate["journals"]] == [0]
    # a journal that grows between the certification and the copy is cut at the certified bytes
    calls: list[int] = []

    def growing(*args: Any, **kwargs: Any) -> Any:
        result = certify_campaign(*args, **kwargs)
        if not calls:
            with shop.journal.open("ab") as stream:
                stream.write(b"not a record\n")  # a complete but invalid line appended meanwhile
        calls.append(1)
        return result

    monkeypatch.setattr(package, "certify_campaign", growing)
    out2 = tmp_path / "package2"
    done = c.cli_main(package_args(shop, out2), capsys)
    assert done.code == 0, done.err
    assert (out2 / "journals" / "w1.jsonl").read_bytes() == clean


def test_a_certificate_of_the_copies_that_differs_from_the_inputs_publishes_nothing(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The package is certified twice, from the inputs and from the copies; the two must agree."""
    shop = build(tmp_path, capsys)
    calls: list[int] = []

    def disagreeing(*args: Any, **kwargs: Any) -> Any:
        result = certify_campaign(*args, **kwargs)
        calls.append(1)
        if len(calls) == 2:  # the certification of the copies
            return dataclasses.replace(
                result, certificate={**result.certificate, "verdict": "OPEN"}
            )
        return result

    monkeypatch.setattr(package, "certify_campaign", disagreeing)
    out = tmp_path / "package"
    done = c.cli_main(package_args(shop, out), capsys)
    assert done.code == 4 and "[evidence.package]" in done.err
    assert len(calls) == 2
    assert not out.exists() and not [p for p in tmp_path.iterdir() if p.name.startswith(".")]


def test_two_copies_of_one_journal_are_packaged_once_and_reported(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    shop = build(tmp_path, capsys)
    twin = tmp_path / "copy.jsonl"
    shutil.copyfile(shop.journal, twin)
    done = c.cli_main(
        [
            "evidence",
            "package",
            "--campaign",
            str(shop.campaign),
            "--journals",
            str(shop.journal),
            str(twin),
            "-o",
            str(tmp_path / "p"),
        ],
        capsys,
    )
    document = c.last_json(done.out)
    assert done.code == 0 and document["journals"] == 1 and len(document["duplicates"]) == 1
    assert "is a copy of a journal already used" in done.err
    assert [p.name for p in (tmp_path / "p" / "journals").iterdir()] == ["w1.jsonl"]


def test_an_open_pilot_is_packaged_with_its_open_verdict(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    shop = c.made(tmp_path, {"f": c.DEEP}, solver={"max_free": 3, "sleep": 0.4})
    assert c.cli_main(shop.run_args("--max-hours", "0.00001"), capsys).code == 1
    out = tmp_path / "package"
    done = c.cli_main(package_args(shop, out), capsys)
    assert done.code == 0 and c.last_json(done.out)["verdict"] == "OPEN"  # packaging succeeded
    certified = c.cli_main(["certify", "--evidence", str(out / "evidence.json")], capsys)
    assert certified.code == 1 and certified.out.startswith("OPEN")  # certify maps the verdict


def test_packaging_refuses_bad_inputs_and_existing_targets(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    shop = build(tmp_path, capsys)
    out = packaged(shop, capsys)
    before = sorted(str(p) for p in out.rglob("*"))
    again = c.cli_main(package_args(shop, out), capsys)
    assert again.code == 3 and "[evidence.exists]" in again.err
    assert sorted(str(p) for p in out.rglob("*")) == before
    bad = shop.root / "bad.jsonl"
    data = shop.journal.read_bytes().split(b"\n")
    data[1] = data[1][:-3] + b"x}"
    bad.write_bytes(b"\n".join(data))
    refused = c.cli_main(
        [
            "evidence",
            "package",
            "--campaign",
            str(shop.campaign),
            "--journals",
            str(bad),
            "-o",
            str(tmp_path / "q"),
        ],
        capsys,
    )
    assert refused.code == 4
    assert not (tmp_path / "q").exists()
    missing = c.cli_main(
        [
            "evidence",
            "package",
            "--campaign",
            str(tmp_path / "nope.json"),
            "--journals",
            str(shop.journal),
            "-o",
            str(tmp_path / "r"),
        ],
        capsys,
    )
    assert missing.code == 3 and not (tmp_path / "r").exists()


# -- reading a package ----------------------------------------------------------------------------


def copy_of(out: Path, name: str) -> Path:
    """A writable copy of a package to damage."""
    target = out.parent / name
    shutil.copytree(out, target)
    for path in target.rglob("*"):
        path.chmod(0o755 if path.is_dir() else 0o644)
    return target


def rewrite_manifest(target: Path, edit: Any) -> None:
    manifest = json.loads((target / "evidence.json").read_bytes())
    edit(manifest)
    (target / "evidence.json").write_bytes(document_bytes(manifest))


def refresh(target: Path, relative: str) -> None:
    """Make the manifest agree with a changed file (a forger who also fixes the manifest)."""

    def edit(manifest: dict[str, Any]) -> None:
        items = [manifest["campaign"], manifest["certificate"], *manifest["journals"]]
        for bundle in manifest["bundles"]:
            items += [bundle["manifest"], bundle["formula"]]
        for item in items:
            if item["path"] == relative:
                data = (target / relative).read_bytes()
                item["sha256"], item["bytes"] = hashlib.sha256(data).hexdigest(), len(data)

    rewrite_manifest(target, edit)


def test_every_listed_file_is_verified_before_use(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    shop = build(tmp_path, capsys, two_workers=True)
    out = packaged(shop, capsys)
    cases: dict[str, Any] = {
        "a flipped journal byte": lambda t: (t / "journals/w1.jsonl").write_bytes(
            bytes([(t / "journals/w1.jsonl").read_bytes()[100] ^ 1]).join(
                [
                    (t / "journals/w1.jsonl").read_bytes()[:100],
                    (t / "journals/w1.jsonl").read_bytes()[101:],
                ]
            )
        ),
        "a truncated journal": lambda t: (t / "journals/w2.jsonl").write_bytes(
            (t / "journals/w2.jsonl").read_bytes()[:-5]
        ),
        "an extended journal": lambda t: (t / "journals/w2.jsonl").open("ab").write(b"x\n"),
        "a removed formula": lambda t: (t / "bundles/a/formula.cnf").unlink(),
        "a removed journal": lambda t: (t / "journals/w1.jsonl").unlink(),
        "another campaign": lambda t: (t / "campaign.json").write_bytes(b"{}\n"),
        "another certificate": lambda t: (t / "certificate.json").write_bytes(b"{}\n"),
        "a symlinked journal": lambda t: (
            shutil.move(t / "journals/w1.jsonl", t / "real.jsonl"),
            (t / "journals/w1.jsonl").symlink_to(t / "real.jsonl"),
        ),
        "a directory instead of a file": lambda t: (
            (t / "bundles/b/formula.cnf").unlink(),
            (t / "bundles/b/formula.cnf").mkdir(),
        ),
    }
    for name, damage in cases.items():
        target = copy_of(out, f"damaged-{len(name)}")
        damage(target)
        done = c.cli_main(["certify", "--evidence", str(target / "evidence.json")], capsys)
        assert done.code == 4, (name, done.err)
        assert "cubeproof: error [evidence." in done.err, (name, done.err)
        assert done.out == ""
        shutil.rmtree(target)


def test_a_certificate_in_a_package_is_recomputed_never_trusted(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A forger who edits the certificate and also fixes the manifest's hash gets exit 4."""
    shop = build(tmp_path, capsys)
    out = packaged(shop, capsys)
    target = copy_of(out, "forged")
    document = json.loads((target / "certificate.json").read_bytes())
    document["open"] = []
    document["verdict"] = "OPEN"
    (target / "certificate.json").write_bytes(document_bytes(document))
    refresh(target, "certificate.json")
    assert load_evidence(target / "evidence.json")  # the manifest is consistent ...
    done = c.cli_main(["certify", "--evidence", str(target / "evidence.json")], capsys)
    assert done.code == 4 and "[evidence.certificate]" in done.err  # ... the certificate is not
    # a plan from the forged certificate is refused too
    plan = c.cli_main(
        [
            "shard",
            "--evidence",
            str(target / "evidence.json"),
            "--machines",
            "2",
            "-o",
            str(tmp_path / "x"),
        ],
        capsys,
    )
    assert plan.code == 3 and "[shard.certificate]" in plan.err
    # a forger who edits a journal and fixes the manifest is caught by the journal's own chain
    other = copy_of(out, "forged-journal")
    path = other / "journals" / "w1.jsonl"
    lines = path.read_bytes().split(b"\n")
    lines[3] = lines[3].replace(b'"seq"', b'"sEq"', 1)
    path.write_bytes(b"\n".join(lines))
    refresh(other, "journals/w1.jsonl")
    done = c.cli_main(["certify", "--evidence", str(other / "evidence.json")], capsys)
    assert done.code == 4


def test_unlisted_files_are_never_read(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    shop = build(tmp_path, capsys)
    out = packaged(shop, capsys)
    target = copy_of(out, "noisy")
    (target / "journals" / "stray.jsonl").write_bytes(b"garbage that is not a journal\n")
    (target / "bundles" / "c").mkdir()
    (target / "old-certificate.json").write_bytes(b"{}\n")
    done = c.cli_main(["certify", "--evidence", str(target / "evidence.json")], capsys)
    assert done.code == 0 and done.out.startswith("PROVED"), done.err


def test_a_malformed_manifest_is_an_input_error_naming_its_rule(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    shop = build(tmp_path, capsys, two_workers=True)
    out = packaged(shop, capsys)

    def swap(m: dict[str, Any]) -> None:
        m["journals"].reverse()

    def traverse(m: dict[str, Any]) -> None:
        m["journals"][0]["path"] = "../w1.jsonl"

    def absolute(m: dict[str, Any]) -> None:
        m["campaign"]["path"] = "/etc/passwd"

    def twice(m: dict[str, Any]) -> None:
        m["certificate"]["path"] = m["campaign"]["path"]

    def stranger(m: dict[str, Any]) -> None:
        del m["bundles"][1]

    def unknown(m: dict[str, Any]) -> None:
        m["extra"] = 1

    def format_(m: dict[str, Any]) -> None:
        m["format"] = "cubeproof-evidence-2"

    def renamed(m: dict[str, Any]) -> None:
        m["bundles"][0]["formula"]["path"] = "bundles/a/other.cnf"  # same bytes, not formula.cnf

    cases = [
        ("evidence.order", swap, 3),
        ("schema", traverse, 3),
        ("schema", absolute, 3),
        ("evidence.duplicate", twice, 3),
        ("evidence.bundles", stranger, 4),
        ("schema", unknown, 3),
        ("schema", format_, 3),
        ("evidence.bundles", renamed, 3),
    ]
    for rule, edit, code in cases:
        target = copy_of(out, f"bad-{rule}-{edit.__name__}")
        shutil.copyfile(target / "bundles/a/formula.cnf", target / "bundles/a/other.cnf")
        rewrite_manifest(target, edit)
        done = c.cli_main(["certify", "--evidence", str(target / "evidence.json")], capsys)
        assert done.code == code and f"[{rule}]" in done.err, (edit.__name__, done.err)
    target = copy_of(out, "not-canonical")
    (target / "evidence.json").write_bytes(
        json.dumps(json.loads((target / "evidence.json").read_bytes()), indent=1).encode()
    )
    assert c.cli_main(["certify", "--evidence", str(target / "evidence.json")], capsys).code == 3
    gone = c.cli_main(["certify", "--evidence", str(tmp_path / "nope" / "evidence.json")], capsys)
    assert gone.code == 3 and "[evidence.file]" in gone.err


def test_the_evidence_alternative_is_exclusive_in_every_consuming_command(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    shop = build(tmp_path, capsys)
    out = packaged(shop, capsys)
    manifest = str(out / "evidence.json")
    for command in (
        ["certify", "--journals", str(shop.journal)],
        ["certify", "--campaign", str(shop.campaign)],
        ["shard", "--machines", "2", "-o", str(tmp_path / "o"), "--campaign", str(shop.campaign)],
        shop.run_args(),
    ):
        done = c.cli_main([*command, "--evidence", manifest], capsys)
        assert done.code == 3 and "[usage]" in done.err, command


def test_commands_run_from_the_evidence_alone(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """certify, shard and run take their inputs from a manifest (specification §12.1)."""
    shop = c.made(tmp_path / "origin", {"f": c.DEEP}, solver={"max_free": 3, "sleep": 0.4})
    assert c.cli_main(shop.run_args("--max-hours", "0.00001"), capsys).code == 1  # an open pilot
    out = packaged(shop, capsys, tmp_path / "package")
    manifest = str(out / "evidence.json")
    planned = c.cli_main(
        ["shard", "--evidence", manifest, "--machines", "2", "-o", str(tmp_path / "plan")], capsys
    )
    assert planned.code == 0, planned.err
    document = c.last_json(planned.out)
    assert document["source"] == "open" and document["nodes"] >= 1
    by_key = ["shard", "--evidence", manifest, "--machines", "2", "--formula"]
    one = c.cli_main([*by_key, "f", "-o", str(tmp_path / "plan-f")], capsys)
    assert c.last_json(one.out)["formulas"] == ["f"]
    assert c.last_json(one.out)["nodes"] == document["nodes"]
    other = c.cli_main([*by_key, "g", "-o", str(tmp_path / "plan-g")], capsys)
    assert other.code == 3 and "[shard.formula]" in other.err
    explicit_args = ["shard", "--campaign", str(shop.campaign), "--machines", "2"]
    explicit_args += ["-o", str(tmp_path / "plan2"), "--from-open", str(out / "certificate.json")]
    explicit_args += ["--journals", str(out / "journals" / "w1.jsonl")]
    explicit = c.cli_main(explicit_args, capsys)
    again = c.last_json(explicit.out)
    for key in ("campaign", "nodes", "source", "scope", "machines", "stopped", "empty_machines"):
        assert again[key] == document[key]
    assert [s["shard_sha256"] for s in again["shards"]] == [
        s["shard_sha256"] for s in document["shards"]
    ]
    # a run that takes its campaign from the evidence finishes the work in a new results directory
    c.t.configure(shop.tools.solver, max_free=3)
    args = ["run", "--evidence", manifest, "--results", str(tmp_path / "r2")]
    args += ["--work", str(tmp_path / "w2"), "--worker", "w2"]
    args += ["--solver", str(shop.tools.solver), "--checker", str(shop.tools.checker)]
    ran = c.cli_main(args, capsys)
    assert ran.code == 0, ran.err
    assert (
        api.certify(out / "campaign.json", [tmp_path / "r2" / "journal.jsonl"])["verdict"]
        == "PROVED"
    )


# -- the manifest against the frozen corpus -------------------------------------------------------


def test_the_manifest_reader_agrees_with_the_contract_corpus() -> None:
    import sys

    tests = Path(__file__).resolve().parents[1] / "contracts"
    if str(tests) not in sys.path:
        sys.path.insert(0, str(tests))
    import cp_corpus

    entries = cp_corpus.documents("evidence-manifest")
    assert len(entries) >= 10
    for entry in entries:
        data = cp_corpus.fixture_bytes(entry)
        value = parse_document(data)
        kind, expected = cp_corpus.expectation(entry)
        if kind == "valid":
            manifest = EvidenceManifest.from_json(value)
            assert manifest.to_json() == value
            assert document_bytes(manifest.to_json()) == data
            continue
        with pytest.raises(ContractError) as info:
            EvidenceManifest.from_json(value)
        assert info.value.rule == ("schema" if kind == "schema" else expected), entry["id"]
        if kind == "schema":
            assert info.value.location == expected, entry["id"]


def test_the_rebuilt_certificate_must_equal_the_original_except_for_the_dropped_torn_tail() -> None:
    original: dict[str, Any] = {
        "verdict": "PROVED",
        "journals": [
            {"id": "a" * 64, "records": 3, "bytes": 10, "torn_tail_bytes": 4},
            {"id": "b" * 64, "records": 5, "bytes": 20, "torn_tail_bytes": 0},
        ],
        "open": [],
    }
    rebuilt = json.loads(json.dumps(original))
    for entry in rebuilt["journals"]:
        entry["torn_tail_bytes"] = 0
    same = package._same_but_torn_tail
    assert same(original, rebuilt)
    edits: list[Any] = [
        lambda d: d.update(verdict="OPEN"),
        lambda d: d["journals"][0].update(bytes=11),
        lambda d: d["journals"][1].update(records=6),
        lambda d: d["journals"].pop(),
        lambda d: d.update(open=[{"node": 1}]),
        lambda d: d["journals"][0].update(torn_tail_bytes=1),  # a torn tail must be gone
    ]
    for edit in edits:
        changed = json.loads(json.dumps(rebuilt))
        edit(changed)
        assert not same(original, changed)
    assert original["journals"][0]["torn_tail_bytes"] == 4  # the original is not modified
