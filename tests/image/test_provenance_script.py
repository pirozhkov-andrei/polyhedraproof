"""docker/test/pinned_tools.py records, verifies and compares builds; ``locate`` trusts no
unrecorded binary. Runs anywhere: the builds here are small stand-ins, not the real tools."""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

from image.pinned import VARIABLE, Pinned, ToolsUnavailable, locate, pinned_tools


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def fake_build(prefix: Path, manifest: dict[str, Any] | None = None) -> Path:
    """A prefix as `build` leaves it, with stand-in binaries."""
    record_tools = {}
    for name in pinned_tools.BINARIES:
        binary = prefix / "bin" / name
        binary.parent.mkdir(parents=True, exist_ok=True)
        binary.write_bytes(f"stand-in {name}\n".encode())
        record_tools[name] = {"binary": f"bin/{name}", "sha256": sha256(binary.read_bytes())}
    record = {
        "format": pinned_tools.PROVENANCE_FORMAT,
        "manifest": manifest or pinned_tools.load_manifest(pinned_tools.MANIFEST),
        "tools": record_tools,
    }
    pinned_tools.write_json(prefix / "provenance" / "tools.json", record)
    return prefix


def test_the_manifest_loader_checks_the_format(tmp_path: Path) -> None:
    manifest = pinned_tools.load_manifest(pinned_tools.MANIFEST)
    assert manifest["format"] == pinned_tools.MANIFEST_FORMAT
    (tmp_path / "other.json").write_text('{"format": "other"}', encoding="utf-8")
    with pytest.raises(pinned_tools.BuildError):
        pinned_tools.load_manifest(tmp_path / "other.json")


def test_the_build_environment_adds_the_pins() -> None:
    env = pinned_tools.build_environment({"build_environment": {"SOURCE_DATE_EPOCH": 7}})
    assert env["SOURCE_DATE_EPOCH"] == "7"
    assert "PATH" in env


def test_verify_accepts_the_recorded_binaries_only(tmp_path: Path) -> None:
    prefix = fake_build(tmp_path / "prefix")
    assert pinned_tools.verify(prefix) == []
    (prefix / "bin" / "cake_lpr").write_bytes(b"another checker\n")
    assert pinned_tools.verify(prefix) == [
        f"cake_lpr: {prefix}/bin/cake_lpr sha256 differs from the recorded build"
    ]
    (prefix / "bin" / "cadical").unlink()
    assert f"cadical: {prefix}/bin/cadical is missing" in pinned_tools.verify(prefix)


def test_verify_rejects_a_foreign_or_incomplete_record(tmp_path: Path) -> None:
    prefix = fake_build(tmp_path / "prefix")
    record_path = prefix / "provenance" / "tools.json"
    record = json.loads(record_path.read_text(encoding="utf-8"))
    del record["tools"]["cadical"]
    pinned_tools.write_json(record_path, record)
    assert pinned_tools.verify(prefix) == ["cadical: not recorded"]
    pinned_tools.write_json(record_path, {"format": "something else"})
    assert "not a polyhedraproof-test-provenance-1 record" in pinned_tools.verify(prefix)[0]


def test_compare_lists_every_difference_by_key(tmp_path: Path) -> None:
    first, second = tmp_path / "a", tmp_path / "b"
    for directory in (first, second):
        pinned_tools.write_json(directory / "tools.json", {"tools": {"x": {"sha256": "1"}}})
    assert pinned_tools.compare(first, second) == []
    pinned_tools.write_json(second / "tools.json", {"tools": {"x": {"sha256": "2"}, "y": []}})
    assert pinned_tools.compare(first, second) == [
        "tools.json: tools.x.sha256: '1' != '2'",
        "tools.json: tools.y: '<absent>' != []",
    ]
    pinned_tools.write_json(first / "environment.json", {"python": "3"})
    assert pinned_tools.compare(first, second)[-1] == f"environment.json: missing in {second}"
    (second / "tools.json").unlink()
    assert f"tools.json: missing in {second}" in pinned_tools.compare(first, second)


def test_flatten() -> None:
    assert pinned_tools.flatten({"a": [1, {"b": None}], "c": {}, "d": []}) == {
        "a[0]": 1,
        "a[1].b": None,
        "c": {},
        "d": [],
    }


def test_the_environment_record_has_no_timestamps() -> None:
    record = pinned_tools.environment()
    assert record["format"] == pinned_tools.ENVIRONMENT_FORMAT
    assert set(record) == {
        "format",
        "python",
        "platform",
        "distributions",
        "debian_packages",
        "utilities",
    }
    assert record["distributions"] == sorted(record["distributions"], key=str.lower)


def test_the_command_line_exit_codes(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    prefix = fake_build(tmp_path / "prefix")
    assert pinned_tools.main(["verify", "--prefix", str(prefix)]) == 0
    assert "binaries: identical" in capsys.readouterr().out
    (prefix / "bin" / "cadical").write_bytes(b"changed")
    assert pinned_tools.main(["verify", "--prefix", str(prefix)]) == 1
    assert "binaries: 1 differences" in capsys.readouterr().out
    provenance = prefix / "provenance"
    assert pinned_tools.main(["compare", str(provenance), str(provenance)]) == 0
    assert pinned_tools.main(["verify", "--prefix", str(tmp_path / "absent")]) == 2
    output = tmp_path / "environment.json"
    assert pinned_tools.main(["environment", "--output", str(output)]) == 0
    assert (
        json.loads(output.read_text(encoding="utf-8"))["format"]
        == "polyhedraproof-test-environment-1"
    )


@pytest.mark.skipif(shutil.which("git") is None, reason="needs git")
def test_the_build_refuses_cake_lpr_sources_with_other_checksums(tmp_path: Path) -> None:
    """A moved or substituted checker source never reaches the compiler."""
    repository = tmp_path / "upstream"
    repository.mkdir()
    for name in ("basis_ffi.c", "cake_lpr.S"):
        (repository / name).write_text(f"/* not the pinned {name} */\n", encoding="ascii")

    def git(*args: str) -> str:
        return subprocess.run(
            ["git", "-C", str(repository), *args], capture_output=True, text=True, check=True
        ).stdout.strip()

    git("init", "-q")
    git("add", ".")
    identity = ("-c", "user.name=t", "-c", "user.email=t@example.org", "-c", "commit.gpgsign=false")
    git(*identity, "commit", "-q", "-m", "x")
    pin = dict(pinned_tools.load_manifest(pinned_tools.MANIFEST)["tools"]["cake_lpr"])
    pin.update(repository=str(repository), commit=git("rev-parse", "HEAD"))
    with pytest.raises(pinned_tools.BuildError, match="checksum mismatch"):
        pinned_tools.build_cake_lpr(pin, tmp_path / "work", tmp_path / "prefix", {})
    assert not (tmp_path / "prefix" / "bin" / "cake_lpr").exists()
    pin["commit"] = "0" * 40
    with pytest.raises(pinned_tools.BuildError):
        pinned_tools.build_cake_lpr(pin, tmp_path / "work2", tmp_path / "prefix", {})


# -- locate -------------------------------------------------------------------------------


def test_locate_needs_the_variable() -> None:
    with pytest.raises(ToolsUnavailable, match=VARIABLE):
        locate({})


def test_locate_accepts_a_verified_build_of_this_manifest(tmp_path: Path) -> None:
    prefix = fake_build(tmp_path / "prefix")
    found = locate({VARIABLE: str(prefix)})
    assert isinstance(found, Pinned)
    assert found.cadical == prefix.resolve() / "bin" / "cadical"
    assert found.cake_lpr == prefix.resolve() / "bin" / "cake_lpr"
    assert (
        found.pin("cake_lpr")["commit"] == found.record["manifest"]["tools"]["cake_lpr"]["commit"]
    )


def test_locate_refuses_changed_binaries_stale_pins_and_missing_records(tmp_path: Path) -> None:
    prefix = fake_build(tmp_path / "prefix")
    (prefix / "bin" / "cadical").write_bytes(b"another solver\n")
    with pytest.raises(ToolsUnavailable, match="differs from the recorded build"):
        locate({VARIABLE: str(prefix)})
    other = dict(pinned_tools.load_manifest(pinned_tools.MANIFEST), apt_snapshot="other")
    stale = fake_build(tmp_path / "stale", other)
    with pytest.raises(ToolsUnavailable, match="rebuild the image"):
        locate({VARIABLE: str(stale)})
    with pytest.raises(ToolsUnavailable, match=r"tools\.json"):
        locate({VARIABLE: str(tmp_path / "nothing")})
