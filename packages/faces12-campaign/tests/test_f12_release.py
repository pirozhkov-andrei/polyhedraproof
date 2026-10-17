"""``release bundle|verify|provenance|docs``: the release functions.

The obligations of the source archive (allowlist, escape, determinism, exclusive creation,
verification) are checked on the adapter. The archive format is pinned by a recorded golden
archive of a small source tree: the verifier accepts it, and the archive built from the same
tree has its layout, header for header.
"""

from __future__ import annotations

import base64
import gzip
import json
import os
import platform
import tarfile
from pathlib import Path

import pytest
from f12_support import REPO, sha, tools

import faces12_campaign
from cubeproof.base.errors import ConfigurationError, InputError, IntegrityError
from faces12_campaign import cli, release
from faces12_campaign.release.bundle import MANIFEST_NAME, release_payloads
from faces12_campaign.release.docs import REFERENCE, render_reference

VERSION = faces12_campaign.__version__
#: The golden archive of ``source_root(...)`` (version 1.0.0, no author), base64, and its
#: SHA-256.
GOLDEN_ARCHIVE = (
    "H4sIAAAAAAAC/+3WXYubQBQGYK+F/Q/ideOeM59O70LrwsJuC5v2OswnadnEoElpKfvfO2YhLGkvu4E250HUGfUI"
    "ynt02z/+WMUw2O3Q92mGDTRw/dDN3993zToUfwVkSojDNjvdZvrFfp5HphGKCooz2I87O+TbF5dpiDasY1mQy7T9"
    "c/7vuvmiW97c3nWLZvd998r5l3iSf4GaU/7P4djqr8rf3vpVGXo/XtvDUYrK5eR/8fHzw7tueT//cHvTLT41X8d+"
    "84r5l0Ke5l8xpPyfw8+yqu1+t+qH+m1V12/yMPXD2u6mYbI+jshmY78ffJy5/SY8xhkeznqeW44ry6TKJ+dCVX3s"
    "JtPVAEFLJ1ErJ1rvvcZg0HmPQTsDybOWgWDGocorrVPAIJPwMvgYRVJhus1U8qQrTaWFYdLqaGOAkMCYvBjB22Q4"
    "WCtAYwIwDI3SmmsU3EvteP7TCcKlhNY9lz52t6lkqwVrk5eMtcADR1Ayaucj9wl4ikJLMEpxjDKCdi5oCylEBV74"
    "xKTXdVk9Tc/lWxzGL/1mKnkIU10+lf9a/o8P5lz//+wk/xxRUf7PwdKHnRBCCCGEEEIIIYQQQggh5L/yC4vW1W4A"
    "KAAA"
)
GOLDEN_ARCHIVE_SHA256 = "0568d9723154d233053070a9e2db9fd0239cecb8b5dd40381a41f9354c580a14"
GOLDEN_VERSION = "1.0.0"


def source_root(root: Path, *, listing: str | None = None) -> Path:
    (root / "docs").mkdir(parents=True)
    (root / "README.md").write_text("readme\n", encoding="utf-8")
    (root / "docs" / "a.md").write_text("a\n", encoding="utf-8")
    (root / "stray.txt").write_text("not released\n", encoding="utf-8")
    text = listing if listing is not None else "README.md\r\nRELEASE_FILES.txt\r\ndocs/a.md\r\n"
    (root / "RELEASE_FILES.txt").write_text(text, encoding="utf-8", newline="")
    return root


def members(archive: Path) -> dict[str, bytes]:
    with tarfile.open(archive, "r:gz") as opened:
        return {
            m.name: opened.extractfile(m).read()  # type: ignore[union-attr]
            for m in opened.getmembers()
        }


def unpack(archive: Path, target: Path) -> Path:
    for name, data in members(archive).items():
        path = target / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    return target / f"polyhedraproof-{VERSION}"


def test_the_archive_is_the_allowlist_and_byte_reproducible(tmp_path: Path) -> None:
    root = source_root(tmp_path / "src")
    first = release.build_bundle(root, tmp_path / "one.tar.gz", "A. Author")
    second = release.build_bundle(root, tmp_path / "two.tar.gz", "A. Author")
    assert first == second == sha((tmp_path / "one.tar.gz").read_bytes())
    found = members(tmp_path / "one.tar.gz")
    prefix = f"polyhedraproof-{VERSION}/"
    assert sorted(found) == sorted(
        prefix + n for n in (MANIFEST_NAME, "README.md", "RELEASE_FILES.txt", "docs/a.md")
    )
    assert list(found) == sorted(found)  # written in a fixed order
    manifest = json.loads(found[prefix + MANIFEST_NAME])
    assert manifest["format"] == "faces12-source-bundle-1"
    assert (manifest["version"], manifest["author"]) == (VERSION, "A. Author")
    assert manifest["source_sha256"]["docs/a.md"] == sha(b"a\n")
    with tarfile.open(tmp_path / "one.tar.gz", "r:gz") as opened:
        for member in opened.getmembers():
            assert (member.mtime, member.mode, member.uid, member.gid) == (0, 0o644, 0, 0)
    with gzip.open(tmp_path / "one.tar.gz") as raw:
        assert raw.read()  # a plain gzip stream
    assert (tmp_path / "one.tar.gz").read_bytes()[4:8] == b"\0\0\0\0"  # gzip mtime 0


def test_an_archive_is_never_replaced(tmp_path: Path) -> None:
    root = source_root(tmp_path / "src")
    target = tmp_path / "out.tar.gz"
    target.write_bytes(b"cited")
    with pytest.raises(ConfigurationError):
        release.build_bundle(root, target)
    assert target.read_bytes() == b"cited"


@pytest.mark.parametrize(
    "listing",
    [
        "README.md\nREADME.md\nRELEASE_FILES.txt\n",
        "README.md\n",
        "README.md\nRELEASE_FILES.txt\n../escape.txt\n",
        "README.md\nRELEASE_FILES.txt\n/etc/hostname\n",
        "README.md\nRELEASE_FILES.txt\nmissing.md\n",
        "README.md\nRELEASE_FILES.txt\nlink.md\n",
    ],
    ids=["duplicate", "omits-itself", "escape", "absolute", "missing", "symlink"],
)
def test_the_allowlist_refuses_bad_entries(tmp_path: Path, listing: str) -> None:
    root = source_root(tmp_path / "src", listing=listing)
    os.symlink(root / "README.md", root / "link.md")
    with pytest.raises(InputError):
        release_payloads(root)
    with pytest.raises(InputError):
        release_payloads(tmp_path)  # no RELEASE_FILES.txt at all


@pytest.mark.parametrize(
    ("damage", "rule"),
    [
        ("extra", "release.files"),
        ("changed", "release.checksum"),
        ("missing", "release.files"),
        ("symlink", "release.symlink"),
        ("inner-symlink", "release.symlink"),
        ("format", "release.manifest"),
    ],
)
def test_verification_of_an_unpacked_archive(tmp_path: Path, damage: str, rule: str) -> None:
    root = source_root(tmp_path / "src")
    if damage == "inner-symlink":  # two listed files with equal bytes: only the link is wrong
        (root / "README.md").write_text("a\n", encoding="utf-8")
    release.build_bundle(root, tmp_path / "a.tar.gz")
    unpacked = unpack(tmp_path / "a.tar.gz", tmp_path / "unpacked")
    assert release.verify_bundle(unpacked) == 3
    if damage == "extra":
        (unpacked / "docs" / "b.md").write_text("b\n")
    elif damage == "changed":
        (unpacked / "docs" / "a.md").write_text("A\n")
    elif damage == "missing":
        (unpacked / "docs" / "a.md").unlink()
    elif damage == "symlink":
        (unpacked / "docs" / "a.md").unlink()
        os.symlink(root / "docs" / "a.md", unpacked / "docs" / "a.md")
    elif damage == "inner-symlink":
        (unpacked / "docs" / "a.md").unlink()
        os.symlink(Path("..") / "README.md", unpacked / "docs" / "a.md")
    else:
        manifest = json.loads((unpacked / MANIFEST_NAME).read_text())
        manifest["format"] = "faces12-source-bundle-0"
        (unpacked / MANIFEST_NAME).write_text(json.dumps(manifest))
    with pytest.raises(IntegrityError) as caught:
        release.verify_bundle(unpacked)
    assert caught.value.rule == rule


def headers(archive: Path) -> list[tuple[object, ...]]:
    """Every member header without the top directory (it names the version)."""
    with tarfile.open(archive, "r:gz") as opened:
        return [
            (
                m.name.split("/", 1)[1],
                m.size,
                m.mode,
                m.uid,
                m.gid,
                m.uname,
                m.gname,
                m.mtime,
                m.type,
            )
            for m in opened.getmembers()
        ]


def test_the_archive_format_is_the_golden_one_in_both_directions(tmp_path: Path) -> None:
    raw = base64.b64decode("".join(GOLDEN_ARCHIVE))
    assert sha(raw) == GOLDEN_ARCHIVE_SHA256
    golden = tmp_path / "golden.tar.gz"
    golden.write_bytes(raw)
    # the verifier accepts the golden archive
    for name, data in members(golden).items():
        path = tmp_path / "o" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    (top,) = list((tmp_path / "o").iterdir())
    assert top.name == f"polyhedraproof-{GOLDEN_VERSION}"
    assert release.verify_bundle(top) == 3
    # the archive built from the same tree has the golden layout, header for header, and its
    # manifest is the golden manifest byte for byte after substituting the version it records,
    # which is equal today
    root = source_root(tmp_path / "src")
    release.build_bundle(root, tmp_path / "built.tar.gz")
    built = tmp_path / "built.tar.gz"
    assert [h[0] for h in headers(built)] == [h[0] for h in headers(golden)]
    golden_manifest = members(golden)[f"polyhedraproof-{GOLDEN_VERSION}/{MANIFEST_NAME}"]
    built_manifest = members(built)[f"polyhedraproof-{VERSION}/{MANIFEST_NAME}"]
    version_line = '"version": "{}"'
    assert (
        built_manifest.replace(
            version_line.format(VERSION).encode(), version_line.format(GOLDEN_VERSION).encode()
        )
        == golden_manifest
    )
    assert [h for h in headers(built) if h[0] != MANIFEST_NAME] == [
        h for h in headers(golden) if h[0] != MANIFEST_NAME
    ]
    for archive in (golden, built):
        data = archive.read_bytes()
        assert data[:4] == b"\x1f\x8b\x08\x00" and data[4:8] == b"\0\0\0\0"  # gzip, mtime 0


def test_provenance_names_the_packages_tools_and_sources(tmp_path: Path) -> None:
    pinned = tools(tmp_path / "tools")
    root = source_root(tmp_path / "src")
    document = release.provenance_document(
        recorded_ms=0, root=root, solver=pinned.solver, checker=pinned.checker
    )
    assert document["format"] == "faces12-provenance-1"
    assert document["recorded_utc"] == "1970-01-01T00:00:00.000Z"
    assert set(document["packages"]) == {"cubeproof", "neighbourly", "faces12-campaign"}
    assert {p["version"] for p in document["packages"].values()} == {VERSION}
    assert all(p["files"] > 0 and len(p["sha256"]) == 64 for p in document["packages"].values())
    assert document["binaries"]["solver"]["sha256"] == pinned.solver_sha256
    assert document["binaries"]["checker"]["sha256"] == pinned.checker_sha256
    assert document["source_sha256"] == {
        "README.md": sha(b"readme\n"),
        "RELEASE_FILES.txt": sha((root / "RELEASE_FILES.txt").read_bytes()),
        "docs/a.md": sha(b"a\n"),
    }
    bare = release.provenance_document(recorded_ms=1)
    assert bare["binaries"] == {} and bare["source_sha256"] is None
    with pytest.raises(ConfigurationError):
        release.provenance_document(recorded_ms=1, solver=tmp_path / "absent")
    assert set(document) == {
        "format",
        "recorded_utc",
        "packages",
        "python",
        "implementation",
        "platform",
        "libc",
        "binaries",
        "source_sha256",
    }


def test_provenance_records_the_build_environment_not_the_host(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Two hosts that build the same image record the same document: no kernel release, no
    host name, no user, and only the time of recording differs."""
    kernel = "6.18.33.2-microsoft-standard-WSL2"
    monkeypatch.setattr(platform, "release", lambda: kernel)
    monkeypatch.setattr(platform, "version", lambda: "#1 SMP PREEMPT_DYNAMIC host-specific")
    monkeypatch.setattr(platform, "node", lambda: "build-host-17")
    monkeypatch.setattr(
        platform, "platform", lambda *a, **k: f"Linux-{kernel}-x86_64-with-glibc2.36"
    )
    monkeypatch.setattr(platform, "system", lambda: "Linux")
    monkeypatch.setattr(platform, "machine", lambda: "x86_64")
    monkeypatch.setattr(platform, "libc_ver", lambda *a, **k: ("glibc", "2.36"))
    document = release.provenance_document(recorded_ms=0)
    assert document["platform"] == "linux-x86_64"
    assert document["libc"] == "glibc 2.36"
    text = json.dumps(document)
    for host_specific in (kernel, "microsoft", "WSL", "build-host-17", "host-specific"):
        assert host_specific not in text
    later = release.provenance_document(recorded_ms=86_400_000)
    assert {k: v for k, v in later.items() if k != "recorded_utc"} == {
        k: v for k, v in document.items() if k != "recorded_utc"
    }
    monkeypatch.setattr(platform, "libc_ver", lambda *a, **k: ("", ""))
    assert release.provenance_document(recorded_ms=0)["libc"] == "unknown"


def test_the_committed_reference_is_the_generated_one() -> None:
    expected = render_reference(cli.command_line())
    assert (REPO / REFERENCE).read_text(encoding="utf-8") == expected
    assert release.check(cli.command_line(), REPO) == []


def docs_root(tmp_path: Path) -> Path:
    root = tmp_path / "root"
    (root / "docs" / "faces12").mkdir(parents=True)
    (root / "docs" / "cubeproof").mkdir(parents=True)
    (root / "docs" / "cubeproof" / "cli-reference.md").write_text("x\n")
    for linked in ("SPECIFICATION.md", "RELEASE.md"):
        (root / "docs" / linked).write_text("x\n")
    (root / "paper").mkdir()
    (root / "paper" / "faces12-en.tex").write_bytes(
        (REPO / "paper" / "faces12-en.tex").read_bytes()
    )
    for name in ("application.md", "cli-reference.md"):
        source = REPO / "docs" / "faces12" / name
        (root / "docs" / "faces12" / name).write_bytes(source.read_bytes())
    return root


def test_the_documentation_check_finds_stale_references_labels_and_links(tmp_path: Path) -> None:
    root = docs_root(tmp_path)
    command_line = cli.command_line()
    assert release.check(command_line, root) == []
    guide = root / "docs" / "faces12" / "application.md"
    guide.write_text(
        guide.read_text() + "\n(paper: lem:nothing) [gone](missing.md)\n", encoding="utf-8"
    )
    reference = root / REFERENCE
    reference.write_text(reference.read_text() + "edited\n", encoding="utf-8")
    problems = release.check(command_line, root)
    assert any("out of date" in p for p in problems)
    assert any("lem:nothing" in p for p in problems)
    assert any("missing.md" in p for p in problems)
    assert release.write(command_line, root) == [REFERENCE]
    assert release.write(command_line, root) == []
    assert len(release.check(command_line, root)) == 2


def test_the_release_commands(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    root = source_root(tmp_path / "src")
    archive = tmp_path / "a.tar.gz"
    args = ["release", "bundle", "--root", str(root), "--output", str(archive)]
    assert cli.main(args) == 0
    assert capsys.readouterr().out.split()[0] == sha(archive.read_bytes())
    assert cli.main(args) == 3  # never replaced
    unpacked = unpack(archive, tmp_path / "u")
    assert cli.main(["release", "verify", "--directory", str(unpacked)]) == 0
    (unpacked / "README.md").write_text("changed\n")
    assert cli.main(["release", "verify", "--directory", str(unpacked)]) == 4
    out = tmp_path / "provenance.json"
    assert cli.main(["release", "provenance", "--output", str(out)]) == 0
    assert json.loads(out.read_text())["format"] == "faces12-provenance-1"
    assert cli.main(["release", "docs", "--check", "--root", str(REPO)]) == 0
    stale = docs_root(tmp_path)
    (stale / REFERENCE).write_text("old\n")
    assert cli.main(["release", "docs", "--check", "--root", str(stale)]) == 4


def test_io_reading_is_contained(tmp_path: Path) -> None:
    """A listed path through a symlinked directory is refused like an escape."""
    root = source_root(tmp_path / "src", listing="README.md\nRELEASE_FILES.txt\nout/x.md\n")
    (tmp_path / "outside").mkdir()
    (tmp_path / "outside" / "x.md").write_text("x\n")
    os.symlink(tmp_path / "outside", root / "out")
    with pytest.raises(InputError):
        release_payloads(root)
