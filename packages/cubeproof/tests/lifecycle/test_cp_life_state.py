"""Specification §7.3: the pieces of the startup: layout, survivors, tail, derived cache and replay.

The journals here are real ones, written by runs of the coordinator with fake tools and read
back through the package's own validators. The cache is judged against the fold it is derived
from: restoring a cache and applying the later records must end in exactly the state of the
fold of all records, at every prefix; any damage to the cache file must be a miss that names its
reason, never an error and never a state that differs from the fold.
"""

from __future__ import annotations

import contextlib
import os
import shutil
import signal
import subprocess
import sys
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import cp_life_tools as t
import pytest

from cubeproof.base.canonical_json import document_bytes, json_sha256, parse_document
from cubeproof.base.errors import (
    ConfigurationError,
    CubeproofError,
    InputError,
    IntegrityError,
    ResourceError,
    ToolError,
)
from cubeproof.base.settings import ReaderLimits, ToolPaths
from cubeproof.cnf.campaign import LoadedCampaign, load_campaign
from cubeproof.coordinator.cache import CACHE_FORMAT, CacheHit, CacheMiss, load_cache, write_cache
from cubeproof.coordinator.config import RunConfig, exit_code_of
from cubeproof.coordinator.layout import (
    Layout,
    ancestors,
    clear_work,
    survivors,
    wait_for_survivors,
)
from cubeproof.coordinator.replay import peek_header, validator_of
from cubeproof.coordinator.state import CampaignView, ReplayState
from cubeproof.coordinator.tail import JournalTail
from cubeproof.evidence.journal import read_journal
from cubeproof.evidence.journal.chain import ChainState
from cubeproof.evidence.schema import Record

DEEP = t.unsat(8, core=5)


class Finished:
    """A completed run and what the startup sees of it."""

    def __init__(self, root: Path) -> None:
        self.world = t.make_world(root, {"f": DEEP}, solver={"max_free": 3})
        assert self.world.run().exit_code == 0
        self.loaded: LoadedCampaign = load_campaign(self.world.campaign)
        self.view = CampaignView.of(self.loaded)
        self.records: tuple[Record, ...] = read_journal(
            self.world.journal(), validator_of(self.loaded)
        ).records

    @property
    def cache(self) -> Path:
        return self.world.results / "state.cache"

    def fold(self, records: tuple[Record, ...] | list[Record]) -> ReplayState:
        state = ReplayState(self.view)
        state.apply_all(list(records))
        return state


@pytest.fixture(scope="module")
def finished(tmp_path_factory: pytest.TempPathFactory) -> Finished:
    return Finished(tmp_path_factory.mktemp("finished"))


# -- layout, work files, survivors ----------------------------------------------------------------


def test_results_and_work_may_not_contain_each_other(tmp_path: Path) -> None:
    for results, work in [
        (tmp_path / "a", tmp_path / "a"),
        (tmp_path / "a", tmp_path / "a" / "w"),
        (tmp_path / "a" / "r", tmp_path / "a"),
    ]:
        with pytest.raises(ConfigurationError) as error:
            Layout.of(results, work)
        assert error.value.rule == "run.layout"
    layout = Layout.of(tmp_path / "r", tmp_path / "w")
    layout.prepare()
    assert layout.results.is_dir() and layout.work.is_dir()
    assert layout.journal.name == "journal.jsonl" and layout.lock.name == "run.lock"


def test_clear_work_removes_everything_below_and_never_follows_links(tmp_path: Path) -> None:
    work = tmp_path / "work"
    outside = tmp_path / "outside"
    (outside / "inner").mkdir(parents=True)
    (outside / "inner" / "file").write_text("keep")
    (work / "a" / "b").mkdir(parents=True)
    (work / "a" / "b" / "c").write_text("x")
    (work / "top").write_text("x")
    os.symlink(outside, work / "link-to-dir")
    os.symlink(outside / "inner" / "file", work / "a" / "link-to-file")
    os.symlink(work / "nowhere", work / "dangling")
    removed = clear_work(work)
    assert removed >= 7
    assert work.is_dir() and list(work.iterdir()) == []
    assert (outside / "inner" / "file").read_text() == "keep"
    assert clear_work(work) == 0
    (work / ".run.lock").write_text("")
    (work / "other").write_text("x")
    assert clear_work(work, keep=(".run.lock",)) == 1  # the work lock stays
    assert [p.name for p in work.iterdir()] == [".run.lock"]


def test_survivors_are_the_other_processes_that_use_the_directory(tmp_path: Path) -> None:
    work = tmp_path / "work"
    work.mkdir()
    code = "import time; time.sleep(60)"
    in_cwd = subprocess.Popen([sys.executable, "-c", code], cwd=work)
    holder = subprocess.Popen(
        [sys.executable, "-c", f"f = open({str(work / 'held')!r}, 'w'); {code}"], cwd=tmp_path
    )
    elsewhere = subprocess.Popen([sys.executable, "-c", code], cwd=tmp_path)
    try:
        deadline = time.monotonic() + 10
        while not (work / "held").exists():
            assert time.monotonic() < deadline
            time.sleep(0.01)
        time.sleep(0.1)
        found = survivors(work.resolve())
        assert in_cwd.pid in found and holder.pid in found and elsewhere.pid not in found
        assert os.getpid() not in found
    finally:
        for process in (in_cwd, holder, elsewhere):
            process.kill()
            process.wait()
    assert wait_for_survivors(work.resolve(), wait_ms=2000) == []


def test_the_shell_that_started_this_process_is_not_a_survivor(tmp_path: Path) -> None:
    """A user who runs the command from inside the work directory is not an old process."""
    work = tmp_path / "work"
    work.mkdir()
    code = (
        "import subprocess, sys; "
        "sleeper = [sys.executable, '-c', 'import time; time.sleep(60)']; "
        "p = subprocess.Popen(sleeper, cwd=sys.argv[1]); "
        "print(p.pid, flush=True); p.wait()"
    )
    parent = subprocess.Popen(
        [sys.executable, "-c", code, str(tmp_path)], cwd=work, stdout=subprocess.PIPE, text=True
    )
    try:
        assert parent.stdout is not None
        child = int(parent.stdout.readline())
        assert ancestors(child) == [parent.pid, *ancestors(parent.pid)]
        assert os.getppid() in ancestors(os.getpid())
        assert survivors(work.resolve(), own=child) == []  # the parent sits in work: an ancestor
        assert survivors(work.resolve()) == [parent.pid]  # but it is a survivor of this process
    finally:
        parent.kill()
        parent.wait()
        with contextlib.suppress(OSError):
            os.kill(child, signal.SIGKILL)


def test_waiting_for_survivors_ends_when_they_exit(tmp_path: Path) -> None:
    work = tmp_path / "work"
    work.mkdir()
    short = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(0.4)"], cwd=work)
    started = time.monotonic()
    assert wait_for_survivors(work.resolve(), wait_ms=10_000) == []
    assert time.monotonic() - started < 5
    short.wait()
    stubborn = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"], cwd=work)
    try:
        assert wait_for_survivors(work.resolve(), wait_ms=200) == [stubborn.pid]
    finally:
        stubborn.kill()
        stubborn.wait()


# -- the tail -------------------------------------------------------------------------------------


def test_the_tail_reads_exactly_the_complete_validated_lines(
    tmp_path: Path, finished: Finished
) -> None:
    data = finished.world.journal().read_bytes()
    path = tmp_path / "journal.jsonl"
    path.write_bytes(b"")
    tail = JournalTail(path, ChainState(name=path.name), validator_of(finished.loaded))
    seen: list[Record] = []
    step = 37
    for end in range(0, len(data) + step, step):
        path.write_bytes(data[: min(end, len(data))])
        seen += tail.poll()
        complete = data[: min(end, len(data))].count(b"\n")
        assert len(seen) == complete  # a partial line is held back, never parsed
    assert [r.self_hash for r in seen] == [r.self_hash for r in finished.records]
    assert tail.seq == len(seen) - 1 and tail.head == seen[-1].self_hash
    assert tail.poll() == []
    tail.close()


def test_the_tail_follows_a_journal_that_does_not_exist_yet(
    tmp_path: Path, finished: Finished
) -> None:
    path = tmp_path / "journal.jsonl"
    tail = JournalTail(path, ChainState(name=path.name), validator_of(finished.loaded))
    assert tail.poll() == [] and tail.seq == -1 and tail.head is None
    shutil.copy(finished.world.journal(), path)
    assert len(tail.poll()) == len(finished.records)


def test_the_tail_rejects_a_line_the_reader_would_reject(
    tmp_path: Path, finished: Finished
) -> None:
    lines = finished.world.journal().read_bytes().split(b"\n")[:-1]
    lines[2] = lines[2].replace(b'"seq":2', b'"seq":3')
    path = tmp_path / "journal.jsonl"
    path.write_bytes(b"\n".join(lines) + b"\n")
    tail = JournalTail(path, ChainState(name=path.name), validator_of(finished.loaded))
    with pytest.raises(CubeproofError) as error:
        tail.poll()
    assert error.value.location is not None and error.value.location.endswith(":3")


@pytest.mark.parametrize("ending", [b"", b"\n"], ids=["without end", "complete"])
def test_the_tail_bounds_a_line(tmp_path: Path, finished: Finished, ending: bytes) -> None:
    path = tmp_path / "journal.jsonl"
    path.write_bytes(b"x" * 5000 + ending)
    limits = ReaderLimits(line_bytes=1000)
    tail = JournalTail(
        path,
        ChainState(name=path.name, limits=limits),
        validator_of(finished.loaded),
        limits=limits,
    )
    with pytest.raises(ResourceError) as error:
        tail.poll()
    assert error.value.rule == "limit.line"


# -- the header peek ------------------------------------------------------------------------------


def test_peek_header_reads_the_owner_without_validating(tmp_path: Path, finished: Finished) -> None:
    limits = ReaderLimits()
    path = tmp_path / "j.jsonl"
    path.write_bytes(finished.world.journal().read_bytes())
    peeked = peek_header(path, limits)
    assert peeked is not None and peeked[0] == "w1" and peeked[2] == "run"
    assert peeked[1] == finished.view.campaign_id
    for data in (b"", b"no newline", b"not json\n", b'{"type":"resume"}\n', b'{"type":"header"}\n'):
        path.write_bytes(data)
        assert peek_header(path, limits) is None
    assert peek_header(tmp_path / "missing", limits) is None


# -- the cache ------------------------------------------------------------------------------------


def test_the_cache_a_run_writes_restores_the_state_of_the_fold(finished: Finished) -> None:
    hit = load_cache(finished.cache, finished.view)
    assert isinstance(hit, CacheHit)
    folded = finished.fold(finished.records)
    assert (hit.seq, hit.head) == (folded.seq, folded.head)
    assert hit.state.digest() == folded.digest()
    assert hit.journal == folded.journal_id


def test_a_restored_state_continues_like_the_fold_at_every_prefix(finished: Finished) -> None:
    folded = finished.fold(finished.records).digest()
    for cut in range(1, len(finished.records)):
        prefix = finished.fold(finished.records[:cut])
        restored = ReplayState(finished.view)
        restored.restore(prefix.export())
        assert restored.digest() == prefix.digest()
        restored.apply_all(list(finished.records[cut:]))
        assert restored.digest() == folded, f"restored at {cut}"


def alter(path: Path, change: Callable[[dict[str, Any]], None], *, rehash: bool = False) -> None:
    value = parse_document(path.read_bytes())
    change(value)
    if rehash:
        value["sha256"] = json_sha256(value["state"])
    path.write_bytes(document_bytes(value))


def copy_cache(finished: Finished, tmp_path: Path) -> Path:
    target = tmp_path / "state.cache"
    shutil.copy(finished.cache, target)
    return target


def set_field(name: str, value: Any, *, rehash: bool = False) -> Callable[[Path], None]:
    def change(path: Path) -> None:
        alter(path, lambda doc: doc.__setitem__(name, value), rehash=rehash)

    return change


def set_state(name: str, value: Any) -> Callable[[Path], None]:
    def change(path: Path) -> None:
        alter(path, lambda doc: doc["state"].__setitem__(name, value), rehash=True)

    return change


def drop_node(path: Path) -> None:
    def change(doc: dict[str, Any]) -> None:
        doc["state"]["nodes"][0][2]["attempts"] = "many"

    alter(path, change, rehash=True)


def reorder(path: Path) -> None:
    def change(doc: dict[str, Any]) -> None:
        doc["state"]["nodes"].reverse()

    alter(path, change, rehash=True)


def garble(path: Path) -> None:
    data = bytearray(path.read_bytes())
    data[len(data) // 2] ^= 0x55
    path.write_bytes(bytes(data))


def pretty(path: Path) -> None:
    import json

    path.write_text(json.dumps(parse_document(path.read_bytes()), indent=2))


#: The reason is None where the damage may land in several checks (any miss is right).
def delete(path: Path) -> None:
    path.unlink()


def empty(path: Path) -> None:
    path.write_bytes(b"")


def noise(path: Path) -> None:
    path.write_bytes(b"\x00\xff" * 50)


def truncate(path: Path) -> None:
    path.write_bytes(path.read_bytes()[:-9])


def directory(path: Path) -> None:
    path.unlink()
    path.mkdir()


MISSES: list[tuple[str, Callable[[Path], None], str | None]] = [
    ("deleted", delete, "absent"),
    ("empty", empty, "not_canonical"),
    ("garbage", noise, "not_canonical"),
    ("truncated", truncate, "not_canonical"),
    ("pretty printed", pretty, "not_canonical"),
    ("flipped byte", garble, None),
    ("a directory", directory, "unreadable"),
    ("other version", set_field("format", "cubeproof-state-cache-2"), "format"),
    ("other campaign", set_field("campaign", "ab" * 32), "campaign"),
    ("extra field", set_field("extra", 1), "schema"),
    ("checksum", set_field("sha256", "cd" * 32), "checksum"),
    ("seq not an integer", set_field("seq", "7", rehash=True), "schema"),
    ("negative seq", set_field("seq", -1, rehash=True), "schema"),
    ("seq and state disagree", set_field("seq", 1, rehash=True), "position"),
    ("head and state disagree", set_field("head", "ef" * 32, rehash=True), "position"),
    ("other journal", set_field("journal", "ef" * 32, rehash=True), "position"),
    ("state changed, checksum stale", set_field("state", {}), "checksum"),
    ("state without fields", set_field("state", {}, rehash=True), "state"),
    ("a node fact of the wrong type", drop_node, "state"),
    ("nodes out of order", reorder, "state"),
    ("unknown formula", set_state("nodes", [["ab" * 32, [], {}]]), "state"),
]


@pytest.mark.parametrize(
    ("damage", "reason"), [(m[1], m[2]) for m in MISSES], ids=[m[0] for m in MISSES]
)
def test_a_damaged_cache_is_a_miss_with_its_reason(
    tmp_path: Path, finished: Finished, damage: Callable[[Path], None], reason: str | None
) -> None:
    path = copy_cache(finished, tmp_path)
    damage(path)
    miss = load_cache(path, finished.view)
    assert isinstance(miss, CacheMiss)
    assert reason is None or miss.reason == reason


def test_the_cache_format_name_is_the_documented_one() -> None:
    assert CACHE_FORMAT == "cubeproof-state-cache-1"


def test_a_cache_without_state_cannot_be_written(finished: Finished) -> None:
    with pytest.raises(ValueError, match="no committed state"):
        write_cache(Path("/nonexistent/state.cache"), ReplayState(finished.view), "0" * 64)


def test_writing_the_cache_is_atomic_and_leaves_no_temporary_file(
    tmp_path: Path, finished: Finished
) -> None:
    state = finished.fold(finished.records)
    target = tmp_path / "state.cache"
    write_cache(target, state, finished.view.campaign_id)
    assert sorted(p.name for p in tmp_path.iterdir()) == ["state.cache"]
    hit = load_cache(target, finished.view)
    assert isinstance(hit, CacheHit) and hit.state.digest() == state.digest()
    # an unwritable target is an OSError for the caller to report, and removes the temporary
    with pytest.raises(OSError):
        write_cache(tmp_path / "missing-dir" / "state.cache", state, finished.view.campaign_id)


# -- the cache against the journal at startup -----------------------------------------------------


def test_a_cache_of_another_journal_is_not_used_but_the_run_is_unaffected(
    tmp_path: Path,
) -> None:
    a = t.make_world(tmp_path / "a", {"f": DEEP}, solver={"max_free": 3})
    assert a.run().exit_code == 0
    other_results = tmp_path / "b" / "results"
    b_config = a.config(results=other_results, work=tmp_path / "b" / "work")
    from cubeproof import api

    assert api.run(b_config).exit_code == 0
    shutil.copy(other_results / "state.cache", a.results / "state.cache")
    folded = a.run(cache=False)
    shutil.copy(other_results / "state.cache", a.results / "state.cache")
    result = a.run()
    assert result.cache == "fallback:position"
    assert (result.exit_code, result.seq) == (0, folded.seq + 1)
    assert result.replayed_records == folded.replayed_records + 1
    # the next cache is the right one again
    assert a.run().cache == "used"


#: The damages that are also run end to end (the others are judged by ``load_cache`` alone).
RUN_WITH = frozenset(
    {"deleted", "garbage", "checksum", "head and state disagree", "a directory", "unknown formula"}
)


def test_every_kind_of_damaged_cache_leaves_the_run_with_the_fold_result(
    tmp_path: Path,
) -> None:
    w = t.make_world(tmp_path, {"f": DEEP}, solver={"max_free": 3})
    assert w.run().exit_code == 0
    cache = w.results / "state.cache"
    uncached = w.run(cache=False)
    assert uncached.cache == "disabled"
    for name, damage, reason in MISSES:
        if name not in RUN_WITH:
            continue
        if not cache.exists():
            w.run()  # rewrites the cache
        valid = cache.read_bytes()
        damage(cache)
        result = w.run()
        if reason is None:
            assert result.cache.startswith("fallback:")
        else:
            assert result.cache == ("absent" if reason == "absent" else f"fallback:{reason}")
        assert result.exit_code == 0 and result.open == {}
        if cache.is_dir():
            cache.rmdir()
        cache.write_bytes(valid)
    assert w.run().cache == "used"


def test_a_cache_that_is_ahead_of_the_journal_is_a_fallback(tmp_path: Path) -> None:
    w = t.make_world(tmp_path, {"f": t.unsat(5)}, solver={"max_free": 3})
    assert w.run().exit_code == 0
    cache = w.results / "state.cache"
    data = w.journal().read_bytes()
    lines = data.split(b"\n")
    # a journal that lost its last complete records (restored from an older backup)
    w.journal().write_bytes(b"\n".join(lines[:-3]) + b"\n")
    result = w.run()
    assert result.cache == "fallback:position"
    assert result.exit_code == 0
    assert cache.exists()


# -- configuration values and exit codes ----------------------------------------------------------


def test_run_config_rejects_what_cannot_run(tmp_path: Path) -> None:
    base = {
        "campaign": tmp_path / "c.json",
        "results": tmp_path / "r",
        "work": tmp_path / "w",
        "worker": "w1",
        "tools": ToolPaths(),
    }
    RunConfig(**base)  # type: ignore[arg-type]
    for bad in (
        {"worker": "Upper"},
        {"worker": ""},
        {"jobs": 0},
        {"memory_bytes": -1},
        {"max_seconds": 0},
        {"policy_overrides": {"Bad Key": 1}},
        {"proof_mode": "everything"},
        {"tick_ms": -1},
    ):
        with pytest.raises(ConfigurationError):
            RunConfig(**{**base, **bad})  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("error", "code"),
    [
        (ConfigurationError("run.locked"), 3),
        (InputError("campaign.file"), 3),
        (InputError("bundle.files"), 3),
        (InputError("journal.no_header"), 4),
        (IntegrityError("journal.self"), 4),
        (ResourceError("limit.line"), 4),
        (ResourceError("certify.memory"), 4),
        (ResourceError("resources.preflight"), 1),
        (ToolError("tool.missing"), 5),
        (CubeproofError("other"), 4),
        (RuntimeError("bug"), 4),
    ],
)
def test_errors_map_to_the_exit_codes_of_the_specification(error: BaseException, code: int) -> None:
    assert exit_code_of(error) == code
