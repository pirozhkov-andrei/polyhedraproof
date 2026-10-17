"""The host wrapper ``pipeline/faces12-worker.sh`` (specification §14).

The fast tests run the wrapper against a fake ``docker`` on ``PATH`` that records every call
and keeps a minimal container/volume state; they check the names, the explicit ``/io`` and
volume paths, quoting of host paths with spaces, the stop/start/recreate sequence, and that
no call can delete a volume.

The tests marked ``image`` drive a real release image named by ``POLYHEDRAPROOF_RELEASE_IMAGE``
through the documented procedure: example campaign, launch, stop, start, recreate, completion,
backup, loss of both volumes and restore, with host paths containing spaces.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
import uuid
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
BASH_WRAPPER = ROOT / "pipeline" / "faces12-worker.sh"
IMAGE_VARIABLE = "POLYHEDRAPROOF_RELEASE_IMAGE"
WRAPPER_IMAGE_VARIABLE = "POLYHEDRAPROOF_IMAGE"
needs_posix = pytest.mark.skipif(os.name != "posix", reason="the fake docker is a POSIX script")

FAKE_DOCKER = r"""#!/usr/bin/env bash
# A fake docker for the wrapper tests: records each call (arguments separated by \x1f) and
# keeps one container ("NAME STATE" in $state/container) and a set of volumes.
state=${FAKE_DOCKER_STATE:?}
mkdir -p "$state/volumes"
{ printf '%s\x1f' "$@"; printf '\n'; } >> "$state/calls"
case "$1" in
  container)
    if [ -f "$state/container" ]; then cut -d' ' -f2 "$state/container"; exit 0; fi
    echo; echo "Error: No such container" >&2; exit 1 ;;
  ps) [ -f "$state/container" ] && cat "$state/container"; exit 0 ;;
  volume)
    case "$2" in
      inspect) [ -e "$state/volumes/$3" ]; exit $? ;;
      ls) ls "$state/volumes"; exit 0 ;;
      create) touch "$state/volumes/${*: -1}"; echo "${*: -1}"; exit 0 ;;
      *) echo "fake docker: volume $2 is not allowed" >&2; exit 97 ;;
    esac ;;
  run)
    shift; detached=0; name=
    while [ $# -gt 0 ]; do
      case "$1" in -d) detached=1 ;; --name) name=$2; shift ;; esac
      shift
    done
    if [ "$detached" = 1 ]; then echo "$name running" > "$state/container"; echo 0123cafe; fi
    exit 0 ;;
  stop) sed -i 's/ .*/ exited/' "$state/container"; echo "${*: -1}"; exit 0 ;;
  start) sed -i 's/ .*/ running/' "$state/container"; echo "${*: -1}"; exit 0 ;;
  rm)
    case "$2" in -*) echo "fake docker: rm $2 is not allowed" >&2; exit 97 ;; esac
    rm -f "$state/container"; echo "$2"; exit 0 ;;
  exec|logs) exit 0 ;;
esac
echo "fake docker: $1 is not expected" >&2
exit 98
"""


@dataclass
class Fake:
    """A fake docker installation and a host /io directory with spaces in its path."""

    state: Path
    env: dict[str, str]
    io: Path

    def calls(self) -> list[list[str]]:
        path = self.state / "calls"
        if not path.exists():
            return []
        text = path.read_text(encoding="utf-8")
        return [line.split("\x1f")[:-1] for line in text.splitlines()]

    def mutations(self) -> list[list[str]]:
        """The calls that change something (not the queries)."""
        changing = ("run", "stop", "start", "rm")
        return [c for c in self.calls() if c[0] in changing or c[:2] == ["volume", "create"]]

    def reset_calls(self) -> None:
        (self.state / "calls").unlink(missing_ok=True)

    def set_container(self, text: str | None) -> None:
        path = self.state / "container"
        if text is None:
            path.unlink(missing_ok=True)
        else:
            path.write_text(text + "\n", encoding="utf-8")


@pytest.fixture
def fake(tmp_path: Path) -> Fake:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    docker = bin_dir / "docker"
    docker.write_text(FAKE_DOCKER, encoding="utf-8")
    docker.chmod(0o755)
    state = tmp_path / "state"
    state.mkdir()
    host_io = tmp_path / "host dir with spaces" / "io"
    host_io.mkdir(parents=True)
    (host_io / "campaign.json").write_text("{}\n", encoding="utf-8")
    (host_io / "shards").mkdir()
    (host_io / "shards" / "s1.json").write_text("{}\n", encoding="utf-8")
    env = {k: v for k, v in os.environ.items() if k != WRAPPER_IMAGE_VARIABLE}
    env["PATH"] = f"{bin_dir}{os.pathsep}{env.get('PATH', '')}"
    env["FAKE_DOCKER_STATE"] = str(state)
    return Fake(state, env, host_io)


def bash(fake: Fake, *words: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", str(BASH_WRAPPER), *words],
        env=fake.env, capture_output=True, text=True, check=False, timeout=60,
    )  # fmt: skip


def launched(fake: Fake) -> None:
    result = bash(fake, "launch", "--worker", "w1", "--io", str(fake.io), "--user", "1:1")
    assert result.returncode == 0, result.stderr


def detached_run(fake: Fake) -> list[str]:
    runs = [c for c in fake.calls() if c[:2] == ["run", "-d"]]
    assert len(runs) == 1, fake.calls()
    return runs[0]


def no_deletion(calls: Sequence[Sequence[str]]) -> None:
    """No call removes, prunes or overwrites a volume."""
    for call in calls:
        assert call[:2] not in (["volume", "rm"], ["volume", "prune"]), call
        assert call[:2] != ["system", "prune"], call
        if call and call[0] == "rm":
            assert not any(w in ("-v", "--volumes", "-f", "--force") for w in call), call
        if call[:2] == ["run", "-d"]:
            assert "--rm" not in call, call


def expected_run(io: Path, worker: str, user: str) -> list[str]:
    return [
        "run", "-d", "--name", f"faces12-{worker}", "--init", "--network", "none",
        "--user", user,
        "--label", f"org.polyhedraproof.worker={worker}",
        "--label", f"org.polyhedraproof.io={io}",
        "-v", f"faces12-results-{worker}:/work/results",
        "-v", f"faces12-work-{worker}:/work/scratch",
        "-v", f"{io}:/io",
        "faces12-campaign:1.0.0rc1",
        "run", "--campaign", "/io/campaign.json",
        "--results", "/work/results", "--work", "/work/scratch", "--worker", worker,
        "--inbox", "/io/inbox", "--outbox", "/io/outbox", "--export", "/io/export",
    ]  # fmt: skip


# -- the wrapper against a fake docker -----------------------------------------------------------


def test_the_wrapper_script_parses() -> None:
    result = subprocess.run(["bash", "-n", str(BASH_WRAPPER)], capture_output=True, check=False)
    assert result.returncode == 0, result.stderr


def test_the_wrapper_cannot_delete_a_volume() -> None:
    code = "\n".join(
        line
        for line in BASH_WRAPPER.read_text(encoding="utf-8").splitlines()
        if not line.lstrip().startswith("#")
    ).lower()
    for forbidden in ("volume rm", "prune", "rm -v", "--volumes", "rm -f"):
        assert forbidden not in code, forbidden
    assert "stop -t 120" in code


@needs_posix
def test_names_are_deterministic(fake: Fake) -> None:
    result = bash(fake, "names", "--worker", "w-01")
    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines() == [
        "container faces12-w-01",
        "results faces12-results-w-01",
        "work faces12-work-w-01",
    ]
    assert fake.calls() == []
    other = bash(fake, "names", "--worker", "w-01", "--prefix", "lab2")
    assert "container lab2-w-01" in other.stdout


@needs_posix
def test_launch_mounts_explicit_paths_and_quotes_a_host_path_with_spaces(fake: Fake) -> None:
    result = bash(fake, "launch", "--worker", "w1", "--io", str(fake.io), "--user", "1234:1234",
                  "--", "--jobs", "2", "--memory", "1G")  # fmt: skip
    assert result.returncode == 0, result.stderr
    calls = fake.mutations()
    assert calls[0][:2] == calls[1][:2] == ["volume", "create"]
    assert calls[0][-1] == "faces12-results-w1" and calls[1][-1] == "faces12-work-w1"
    init = calls[2]
    assert init[:8] == ["run", "--rm", "--init", "--network", "none", "--user", "0:0", "-v"]
    assert init[-2:] == ["init-volumes", "1234:1234"]
    run = detached_run(fake)
    assert run == [*expected_run(fake.io, "w1", "1234:1234"), "--jobs", "2", "--memory", "1G"]
    for name in ("inbox", "outbox", "export"):
        assert (fake.io / name).is_dir()
    no_deletion(fake.calls())


@needs_posix
def test_launch_passes_a_shard_and_relative_exchange_directories(fake: Fake) -> None:
    result = bash(fake, "launch", "--worker", "w1", "--io", str(fake.io), "--user", "1000:1000",
                  "--shard", "shards/s1.json", "--inbox", "x/in", "--export", "exp")  # fmt: skip
    assert result.returncode == 0, result.stderr
    run = detached_run(fake)
    assert run[run.index("--shard") + 1] == "/io/shards/s1.json"
    assert run[run.index("--inbox") + 1] == "/io/x/in"
    assert run[run.index("--export") + 1] == "/io/exp"


@needs_posix
def test_the_default_user_is_the_callers(fake: Fake) -> None:
    result = bash(fake, "launch", "--worker", "w1", "--io", str(fake.io))
    if os.getuid() == 0:
        assert result.returncode == 2 and "never runs as root" in result.stderr
        return
    assert result.returncode == 0, result.stderr
    run = detached_run(fake)
    assert run[run.index("--user") + 1] == f"{os.getuid()}:{os.getgid()}"


@needs_posix
@pytest.mark.parametrize(
    ("words", "message"),
    [
        (["--user", "0:0"], "never runs as root"),
        (["--user", "00:1000"], "never runs as root"),
        (["--user", "1000"], "UID:GID"),
        (["--campaign", "../campaign.json"], "below --io"),
        (["--campaign", "/etc/passwd"], "below --io"),
        (["--campaign", "missing.json"], "no campaign file"),
        (["--shard", "../s.json"], "below --io"),
        (["--inbox", "a/../../b"], "below --io"),
        (["--prefix", "UPPER"], "--prefix"),
        (["--bogus", "x"], "unexpected"),
    ],
)
def test_launch_refuses_bad_options_before_calling_docker(
    fake: Fake, words: list[str], message: str
) -> None:
    base = ["launch", "--worker", "w1", "--io", str(fake.io)]
    if "--user" not in words:
        base += ["--user", "1000:1000"]
    result = bash(fake, *base, *words)
    assert result.returncode == 2, result.stdout + result.stderr
    assert message in result.stderr
    assert fake.mutations() == []


@needs_posix
@pytest.mark.parametrize("worker", ["", "W1", "-w", "a" * 49, "w 1", "w/1", "w:1"])
def test_worker_names_are_restricted(fake: Fake, worker: str) -> None:
    result = bash(fake, "launch", "--worker", worker, "--io", str(fake.io), "--user", "1:1")
    assert result.returncode == 2
    assert fake.calls() == []


@needs_posix
def test_launch_refuses_an_existing_container(fake: Fake) -> None:
    fake.set_container("faces12-w1 exited")
    result = bash(fake, "launch", "--worker", "w1", "--io", str(fake.io), "--user", "1:1")
    assert result.returncode == 2
    assert "exists (exited): use start, or recreate" in result.stderr
    assert fake.mutations() == []


@needs_posix
def test_stop_start_and_recreate_keep_the_volumes(fake: Fake) -> None:
    launched(fake)
    fake.reset_calls()
    assert bash(fake, "stop", "--worker", "w1").returncode == 0
    assert fake.mutations() == [["stop", "-t", "120", "faces12-w1"]]
    fake.reset_calls()
    assert bash(fake, "start", "--worker", "w1").returncode == 0
    assert fake.mutations() == [["start", "faces12-w1"]]
    fake.reset_calls()
    result = bash(fake, "recreate", "--worker", "w1", "--io", str(fake.io), "--user", "1:1")
    assert result.returncode == 0, result.stderr
    assert "volumes kept" in result.stdout
    calls = fake.mutations()
    assert calls[0] == ["stop", "-t", "120", "faces12-w1"]
    assert calls[1] == ["rm", "faces12-w1"]
    assert not any(c[:2] == ["volume", "create"] for c in calls)  # the volumes exist
    assert calls[2][-2:] == ["init-volumes", "1:1"]
    assert detached_run(fake) == expected_run(fake.io, "w1", "1:1")
    assert sorted(p.name for p in (fake.state / "volumes").iterdir()) == [
        "faces12-results-w1",
        "faces12-work-w1",
    ]
    no_deletion(fake.calls())


@needs_posix
def test_recreate_after_a_lost_container_launches_again(fake: Fake) -> None:
    result = bash(fake, "recreate", "--worker", "w1", "--io", str(fake.io), "--user", "1:1")
    assert result.returncode == 0, result.stderr
    assert "removed container" not in result.stdout
    assert detached_run(fake) == expected_run(fake.io, "w1", "1:1")


@needs_posix
def test_commands_that_start_no_container_need_no_user(fake: Fake) -> None:
    for words in (["names"], ["stop"], ["logs"]):
        result = bash(fake, *words, "--worker", "w1", "--user", "0:0")
        assert result.returncode == 0, result.stderr


@needs_posix
def test_start_without_a_container_points_to_launch(fake: Fake) -> None:
    result = bash(fake, "start", "--worker", "w1")
    assert result.returncode == 2 and "use launch or recreate" in result.stderr


@needs_posix
def test_status_of_a_stopped_worker_reads_the_results_volume_read_only(fake: Fake) -> None:
    launched(fake)
    fake.set_container("faces12-w1 exited")
    fake.reset_calls()
    result = bash(fake, "status", "--worker", "w1", "--user", "1:1", "--", "--json")
    assert result.returncode == 0, result.stderr
    run = fake.mutations()[0]
    assert "faces12-results-w1:/work/results:ro" in run
    assert run[-4:] == ["status", "--results", "/work/results", "--json"]
    fake.set_container("faces12-w1 running")
    fake.reset_calls()
    assert bash(fake, "status", "--worker", "w1").returncode == 0
    assert any(c[0] == "exec" and c[-2:] == ["--results", "/work/results"] for c in fake.calls())


@needs_posix
def test_capacity_and_backup_need_existing_volumes(fake: Fake, tmp_path: Path) -> None:
    result = bash(fake, "capacity", "--worker", "w1", "--user", "1:1")
    assert result.returncode == 2 and "no volume" in result.stderr
    target = tmp_path / "backup dir"
    target.mkdir()
    result = bash(fake, "backup", "--worker", "w1", "--to", str(target), "--user", "1:1")
    assert result.returncode == 2 and "no volume" in result.stderr
    assert fake.mutations() == []


@needs_posix
def test_backup_and_restore_refuse_a_running_worker(fake: Fake, tmp_path: Path) -> None:
    fake.set_container("faces12-w1 running")
    archive = tmp_path / "a b.tar"
    archive.write_bytes(b"")
    for words in (["backup", "--to", str(tmp_path)], ["restore", "--from", str(archive)]):
        result = bash(fake, *words, "--worker", "w1", "--user", "1:1")
        assert result.returncode == 2 and "stop the worker" in result.stderr
    assert fake.mutations() == []


@needs_posix
def test_backup_and_restore_mount_host_directories_with_spaces(fake: Fake, tmp_path: Path) -> None:
    launched(fake)
    fake.set_container("faces12-w1 exited")
    target = tmp_path / "backup dir"
    target.mkdir()
    fake.reset_calls()
    result = bash(fake, "backup", "--worker", "w1", "--to", str(target), "--user", "1:1")
    assert result.returncode == 0, result.stderr
    run = fake.mutations()[0]
    assert "faces12-results-w1:/work/results:ro" in run
    assert f"{target}:/backup" in run
    assert run[-3:-1] == ["backup-results", "/backup"]
    assert run[-1].startswith("faces12-results-w1-") and run[-1].endswith(".tar")
    archive = target / "faces12-results-w1-1.tar"
    archive.write_bytes(b"")
    fake.reset_calls()
    result = bash(fake, "restore", "--worker", "w1", "--from", str(archive), "--user", "1:1")
    assert result.returncode == 0, result.stderr
    run = fake.mutations()[-1]
    assert f"{target}:/backup:ro" in run
    assert run[-2:] == ["restore-results", "/backup/faces12-results-w1-1.tar"]
    no_deletion(fake.calls())


# -- the documented procedure against a real image -----------------------------------------------


def release_image() -> str:
    image = os.environ.get(IMAGE_VARIABLE, "")
    if not image:
        pytest.skip(f"set {IMAGE_VARIABLE} to a built release image (docker/release/validate.sh)")
    assert shutil.which("docker"), f"{IMAGE_VARIABLE} is set but docker is not on PATH"
    return image


@dataclass
class Host:
    """The wrapper driving a real Docker daemon, with its own worker name."""

    worker: str
    image: str
    io: Path
    backups: Path

    def run(self, command: str, *more: str, extra: Sequence[str] = ()) -> str:
        env = dict(os.environ)
        env[WRAPPER_IMAGE_VARIABLE] = self.image
        words = ["bash", str(BASH_WRAPPER), command, "--worker", self.worker, *more]
        if extra:
            words += ["--", *extra]
        result = subprocess.run(
            words, env=env, capture_output=True, text=True, check=False, timeout=900
        )
        assert result.returncode == 0, (words, result.stdout, result.stderr)
        return result.stdout

    def status(self) -> dict[str, Any]:
        out = self.run("status", extra=["--json"])
        document: dict[str, Any] = json.loads(out.strip().splitlines()[-1])
        return document

    def state(self) -> str:
        return subprocess.run(
            ["docker", "container", "inspect", "--format", "{{.State.Status}}",
             f"faces12-{self.worker}"],
            capture_output=True, text=True, check=True,
        ).stdout.strip()  # fmt: skip

    def wait_until_exited(self, seconds: float) -> None:
        deadline = time.monotonic() + seconds
        while self.state() == "running":
            assert time.monotonic() < deadline, f"faces12-{self.worker} still running"
            time.sleep(2)

    def remove_everything(self) -> None:
        """Test cleanup (and the simulated loss of a disk): container and both volumes."""
        subprocess.run(["docker", "rm", "-f", f"faces12-{self.worker}"],
                       capture_output=True, check=False)  # fmt: skip
        subprocess.run(
            ["docker", "volume", "rm", f"faces12-results-{self.worker}",
             f"faces12-work-{self.worker}"],
            capture_output=True, check=False,
        )  # fmt: skip


@pytest.fixture
def host(tmp_path: Path) -> Iterator[Host]:
    image = release_image()
    base = tmp_path / "host dir with spaces"
    io_dir, backups = base / "io", base / "back ups"
    io_dir.mkdir(parents=True)
    backups.mkdir()
    worker = f"tsh-{uuid.uuid4().hex[:10]}"
    box = Host(worker, image, io_dir, backups)
    try:
        yield box
    finally:
        box.remove_everything()


def complete(status: dict[str, Any]) -> bool:
    return bool(status["coverage"]) and all(
        root["closed_numerator"] == "1" and root["denominator_power_two"] == 0
        for root in status["coverage"]
    )


@pytest.mark.slow
@pytest.mark.image
def test_the_procedure_keeps_the_results_through_stop_start_recreate_and_restore(
    host: Host,
) -> None:
    host.run("example", "--io", str(host.io))
    assert (host.io / "campaign.json").is_file()
    host.run("launch", "--io", str(host.io), extra=["--jobs", "2"])
    time.sleep(8)
    host.run("stop")
    assert host.state() == "exited"
    stopped = host.status()
    assert stopped["lifecycle"] == "stopped" and stopped["seq"] > 0
    host.run("start")
    assert host.state() == "running"
    time.sleep(4)
    out = host.run("recreate", "--io", str(host.io), extra=["--jobs", "2"])
    assert "volumes kept" in out
    host.wait_until_exited(900)
    final = host.status()
    assert final["journal"] == stopped["journal"], "recreation started a new journal"
    assert final["seq"] > stopped["seq"]
    assert final["counters"].get("type_resume", 0) >= 1
    assert complete(final), final["coverage"]
    exports = list((host.io / "export").iterdir())
    assert exports, "the journal export reached the host"
    host.run("backup", "--to", str(host.backups))
    archives = sorted(host.backups.glob("*.tar"))
    assert len(archives) == 1 and archives[0].with_name(archives[0].name + ".sha256").is_file()
    host.remove_everything()  # the disk is lost: container and both volumes
    host.run("restore", "--from", str(archives[0]))
    restored = host.status()
    assert (restored["journal"], restored["seq"], restored["head"]) == (
        final["journal"],
        final["seq"],
        final["head"],
    )
