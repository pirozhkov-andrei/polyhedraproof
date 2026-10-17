"""Acceptance decisions and the fold of ownership records (specification §4.5, §7.4)."""

from __future__ import annotations

import itertools
import random
from pathlib import Path

import pytest
from cp_handoff_support import (
    CAMPAIGN,
    FORMULAS,
    HASH,
    VARIABLES,
    key,
    node,
    shard_of,
)
from cp_sched_support import Journal
from cp_sched_support import j as encode

from cubeproof.base.errors import IntegrityError, ResourceError
from cubeproof.base.settings import ReaderLimits
from cubeproof.contracts.documents import Shard
from cubeproof.contracts.identity import compatible, split_id
from cubeproof.contracts.values import Node
from cubeproof.coordinator.ownership import (
    RECORD_OVERHEAD,
    Ownership,
    Verdict,
    _cross_pairs,
    _overlap_in_formula,
    first_overlap,
)
from cubeproof.coordinator.state import ReplayState

# -- overlap -----------------------------------------------------------------------------------


def nodes_of(name: str, *cubes: tuple[int, ...]) -> list[Node]:
    return [node(name, c) for c in cubes]


@pytest.mark.parametrize(
    ("offered", "held", "overlaps"),
    [
        (((),), ((),), True),  # the same node
        (((1,),), ((),), True),  # a descendant of a held node
        (((),), ((1, 2),), True),  # an ancestor of a held node
        (((1, 2),), ((1, 3),), True),  # compatible, neither contains the other
        (((1,),), ((-1,),), False),  # contradicting literals
        (((1, 2),), ((-1, 2), (1, -2)), False),  # each contradicts on one variable
        (((1, 2),), ((-1, 2), (1, -2), (1, 2, 3)), True),  # a descendant among others
        (((2,), (1, -2)), ((-1, -2),), False),
    ],
)
def test_overlap_is_compatibility_of_cubes(
    offered: tuple[tuple[int, ...], ...], held: tuple[tuple[int, ...], ...], overlaps: bool
) -> None:
    found = first_overlap(nodes_of("a", *held), nodes_of("a", *offered))
    assert (found is not None) is overlaps
    if found is not None:
        new, old = found
        assert new.cube in offered and old.cube in held
        assert compatible(new.cube, old.cube)


def test_nodes_of_different_formulas_never_overlap() -> None:
    assert first_overlap([node("a")], [node("b")]) is None


def random_antichain(rng: random.Random, variables: int, leaves: int) -> list[tuple[int, ...]]:
    """The leaves of a random split tree: pairwise incompatible cubes."""
    frontier: list[tuple[int, ...]] = [()]
    while len(frontier) < leaves:
        cube = frontier.pop(rng.randrange(len(frontier)))
        free = [v for v in range(1, variables + 1) if v not in {abs(x) for x in cube}]
        if not free:
            frontier.append(cube)
            break
        v = rng.choice(free)
        frontier += [tuple(sorted((*cube, s * v), key=abs)) for s in (1, -1)]
    return frontier


@pytest.mark.parametrize("seed", range(40))
def test_overlap_agrees_with_the_pairwise_definition(seed: int) -> None:
    rng = random.Random(seed)
    held = random_antichain(rng, 6, rng.randrange(1, 12))
    offered = random_antichain(rng, 6, rng.randrange(1, 12))
    expected = any(compatible(a, b) for a in held for b in offered)
    found = first_overlap(nodes_of("a", *held), nodes_of("a", *offered))
    assert (found is not None) is expected
    if found is not None:
        assert compatible(found[0].cube, found[1].cube)


@pytest.mark.parametrize("seed", range(25))
def test_the_pairwise_fallback_decides_like_the_refinement(seed: int) -> None:
    rng = random.Random(1000 + seed)
    held = random_antichain(rng, 7, rng.randrange(1, 20))
    offered = random_antichain(rng, 7, rng.randrange(1, 20))
    cubes = [frozenset(c) for c in (*offered, *held)]
    side = [0] * len(offered) + [1] * len(held)
    fast, plain = _overlap_in_formula(cubes, side), _cross_pairs(cubes, side)
    assert (fast is None) is (plain is None)
    if fast is not None:
        i, j = fast
        assert side[i] == 0 and side[j] == 1 and compatible(sorted(cubes[i]), sorted(cubes[j]))


def test_a_large_split_tree_is_checked_in_near_linear_time() -> None:
    held = [
        tuple(sorted((*c, 1), key=abs)) for c in itertools.product(*[(v, -v) for v in range(2, 13)])
    ]
    other = [
        tuple(sorted((*c, -1), key=abs))
        for c in itertools.product(*[(v, -v) for v in range(2, 13)])
    ]
    assert first_overlap(nodes_of("a", *held), nodes_of("a", *other)) is None  # 4096 x 4096


# -- the decision ------------------------------------------------------------------------------


def ownership_of(journal: Journal) -> Ownership:
    owned = Ownership(CAMPAIGN, VARIABLES)
    for record in journal.records:
        owned.observe(record)
    return owned


def journal_with(*steps: str) -> Journal:
    j = Journal(FORMULAS)
    for step in steps:
        if step == "root":
            j.shard([("a", ()), ("b", ())], name="first")
        elif step == "split":
            j.split("a", (), (1, 2))
        elif step == "give":
            j.handoff([("a", (1, 2))], request="7", name="out")
    return j


def test_a_new_disjoint_shard_is_accepted() -> None:
    owned = ownership_of(journal_with("root"))
    inside = Shard(CAMPAIGN, "x", (node("b", (1,)),))
    assert owned.judge(inside).verdict is Verdict.REJECT  # inside the accepted root of b
    owned = ownership_of(Journal(FORMULAS))
    assert owned.judge(shard_of([("a", (1,)), ("a", (-1,))])).verdict is Verdict.ACCEPT


def test_an_identical_shard_hash_is_a_no_op() -> None:
    j = journal_with("root")
    owned = ownership_of(j)
    again = shard_of([("a", ()), ("b", ())], name="first")
    assert owned.judge(again).verdict is Verdict.DUPLICATE
    renamed = shard_of([("a", ()), ("b", ())], name="second")
    judged = owned.judge(renamed)
    assert judged.verdict is Verdict.REJECT and judged.rule == "shard.overlap"


@pytest.mark.parametrize(
    "offered",
    [
        [("a", ())],  # the accepted root itself
        [("a", (1, 2))],  # inside an accepted root
        [("a", (3,)), ("a", (-3,))],  # unrelated cubes that cover parts of the root
    ],
)
def test_a_shard_meeting_an_accepted_region_is_rejected_whole(
    offered: list[tuple[str, tuple[int, ...]]],
) -> None:
    owned = ownership_of(journal_with("root"))
    judged = owned.judge(shard_of(offered))
    assert judged.verdict is Verdict.REJECT and judged.rule == "shard.overlap"
    assert "accepted" in judged.detail and "new worker" in judged.detail


def test_a_partly_overlapping_shard_is_not_partially_accepted() -> None:
    j = Journal(FORMULAS)
    j.shard([("a", (1,))], name="first")
    owned = ownership_of(j)
    mixed = shard_of([("a", (-1,)), ("a", (1, 2))])
    assert owned.judge(mixed).verdict is Verdict.REJECT
    assert owned.judge(shard_of([("a", (-1,))])).verdict is Verdict.ACCEPT


def test_what_was_given_away_is_never_taken_back_by_this_worker() -> None:
    j = journal_with("root", "split", "give")
    owned = ownership_of(j)
    gone = shard_of([("a", (1, 2))], name="again")
    judged = owned.judge(gone)
    assert judged.verdict is Verdict.REJECT and "given-away" in judged.detail
    below = shard_of([("a", (1, 2, 3))], name="below")
    assert owned.judge(below).verdict is Verdict.REJECT
    # the shard that was handed off is a different document (its name is the output name)
    assert owned.judge(shard_of([("a", (1, 2))], name="out")).verdict is Verdict.REJECT


def test_the_decision_does_not_depend_on_how_often_it_is_asked() -> None:
    owned = ownership_of(journal_with("root", "split", "give"))
    offered = shard_of([("a", (1, 2))], name="x")
    assert [owned.judge(offered) for _ in range(3)] == [owned.judge(offered)] * 3


def test_a_shard_of_another_campaign_is_rejected() -> None:
    owned = ownership_of(Journal(FORMULAS))
    foreign = Shard("ab" * 32, "x", (node("a"),))
    judged = owned.judge(foreign)
    assert (judged.verdict, judged.rule) == (Verdict.REJECT, "shard.campaign")


def test_unknown_formulas_and_cube_ranges_are_rejected() -> None:
    owned = ownership_of(Journal(FORMULAS))
    unknown = Shard(CAMPAIGN, "x", (Node("cd" * 32, ()),))
    assert owned.judge(unknown).rule == "record.formula"
    outside = Shard(CAMPAIGN, "x", (node("b", (7,)),))  # formula b has 4 variables
    assert owned.judge(outside).rule == "cube.range"


def test_a_shard_that_cannot_be_recorded_in_one_line_is_rejected() -> None:
    owned = ownership_of(Journal(FORMULAS))
    shard = shard_of([("a", (1,)), ("a", (-1,))])
    assert owned.judge(shard, max_line_bytes=10_000).verdict is Verdict.ACCEPT
    small = owned.judge(shard, max_line_bytes=RECORD_OVERHEAD + 20)
    assert (small.verdict, small.rule) == (Verdict.REJECT, "shard.size")


# -- the fold ----------------------------------------------------------------------------------


def test_the_fold_agrees_with_the_replay_state() -> None:
    j = journal_with("root", "split", "give")
    j.handoff([], request="8", name="none")  # zero nodes
    owned = ownership_of(j)
    state = ReplayState(j.view)
    state.apply_all(j.records)
    assert {(n.formula_sha256, n.cube) for n in owned.given_nodes} == set(state.given_away())
    assert sorted(owned.shards) == state.shards()
    assert set(owned.handoffs) == {"0" * 31 + "7", "0" * 31 + "8"}
    assert owned.handoffs["0" * 31 + "8"].shard is None
    rooted = {(n.formula_sha256, n.cube) for n in owned.accepted_roots}
    assert rooted == {key("a"), key("b")}
    assert owned.prior("0" * 31 + "9") is None
    assert owned.output_owner("out") is owned.handoffs["0" * 31 + "7"]
    assert owned.output_owner("zzz") is None


def test_the_entry_positions_are_the_shard_and_the_split_records() -> None:
    j = journal_with("root", "split")
    owned = ownership_of(j)
    assert owned.root_seq(key("a")) == 1  # the header is seq 0, the shard record seq 1
    assert owned.root_seq(key("a", (1,))) == -1  # not an accepted root
    split = next(r for r in j.records if r.type.value == "split")
    assert owned.split_seq(key("a"), split_id(node("a").node_id, (1, 2))) == split.seq
    assert owned.split_seq(key("a"), "0" * 64) == -1


def test_records_must_follow_each_other_and_a_request_is_handed_off_once() -> None:
    j = journal_with("root")
    owned = Ownership(CAMPAIGN, VARIABLES)
    with pytest.raises(IntegrityError):
        owned.observe(j.records[1])
    j2 = journal_with("root", "split", "give")
    owned2 = ownership_of(j2)
    j2.handoff([("a", (-1, 2))], request="7", name="out2")  # the journal rules refuse a repeat
    with pytest.raises(IntegrityError) as repeated:
        owned2.observe(j2.records[-1])
    assert repeated.value.rule == "handoff.request_unique"


# -- reading the journal file ------------------------------------------------------------------


def write_journal(path: Path, j: Journal, *, torn: bytes = b"") -> None:
    path.write_bytes(b"".join(encode(v) + b"\n" for v in j.values) + torn)


def test_the_file_reader_matches_the_fold_and_ignores_a_torn_tail(tmp_path: Path) -> None:
    j = journal_with("root", "split", "give")
    write_journal(tmp_path / "j", j, torn=b'{"format":"cubeproof-jour')
    owned = Ownership.from_journal(tmp_path / "j", campaign=CAMPAIGN, variables=VARIABLES)
    assert owned.seq == len(j.values) - 1
    assert set(owned.handoffs) == {"0" * 31 + "7"}
    # unverified reading (a caller that has just validated the file) finds the same
    quick = Ownership.from_journal(
        tmp_path / "j", campaign=CAMPAIGN, variables=VARIABLES, verify=False
    )
    assert quick.handoffs == owned.handoffs and quick.shards == owned.shards


def test_the_file_reader_follows_a_growing_journal(tmp_path: Path) -> None:
    j = journal_with("root", "split")
    write_journal(tmp_path / "j", j)
    owned = Ownership.from_journal(tmp_path / "j", campaign=CAMPAIGN, variables=VARIABLES)
    assert owned.refresh(tmp_path / "j") == 0
    j.handoff([("a", (1, 2))], request="7", name="out")
    write_journal(tmp_path / "j", j, torn=b"{")
    assert owned.refresh(tmp_path / "j") == 1
    assert "0" * 31 + "7" in owned.handoffs
    write_journal(tmp_path / "j", j)
    assert owned.refresh(tmp_path / "j") == 0


@pytest.mark.parametrize("damage", ["chain", "self", "self_unparsed", "campaign", "noncanonical"])
def test_the_file_reader_refuses_a_damaged_journal(tmp_path: Path, damage: str) -> None:
    j = journal_with("root", "split")
    j.stop("a", (1, 2), "stuck", "because")  # a record the file reader does not parse
    lines = [encode(v) + b"\n" for v in j.values]
    if damage == "self_unparsed":
        lines[-1] = lines[-1].replace(b'"reason":"because"', b'"reason":"becausx"')
    if damage == "chain":
        lines.pop(1)
    elif damage == "self":
        lines[1] = lines[1].replace(b'"name":"first"', b'"name":"firsx"')
    elif damage == "noncanonical":
        lines[1] = lines[1].replace(b'"seq":1,', b'"seq": 1,')
    (tmp_path / "j").write_bytes(b"".join(lines))
    if damage == "campaign":
        with pytest.raises(IntegrityError):
            Ownership.from_journal(tmp_path / "j", campaign="ab" * 32, variables=VARIABLES)
        return
    with pytest.raises(Exception) as caught:
        Ownership.from_journal(tmp_path / "j", campaign=CAMPAIGN, variables=VARIABLES)
    assert getattr(caught.value, "rule", "").startswith(("journal.", "json."))


def test_a_file_without_a_complete_header_is_refused(tmp_path: Path) -> None:
    (tmp_path / "j").write_bytes(b'{"format"')
    with pytest.raises(IntegrityError) as caught:
        Ownership.from_journal(tmp_path / "j")
    assert caught.value.rule == "journal.no_header"
    assert HASH["a"]


def test_a_followed_file_must_stay_the_journal_of_its_campaign(tmp_path: Path) -> None:
    j = journal_with("root")
    write_journal(tmp_path / "j", j)
    owned = Ownership("ab" * 32, VARIABLES)  # follows a journal of another campaign
    with pytest.raises(IntegrityError) as caught:
        owned.refresh(tmp_path / "j")
    assert caught.value.rule == "journal.header"


def test_the_file_reader_reads_a_line_at_a_time_and_bounds_it(tmp_path: Path) -> None:
    j = journal_with("root", "split")
    write_journal(tmp_path / "j", j)
    longest = max(len(encode(v)) for v in j.values)
    ok = ReaderLimits(line_bytes=longest)
    owned = Ownership.from_journal(
        tmp_path / "j", campaign=CAMPAIGN, variables=VARIABLES, limits=ok
    )
    assert owned.seq == len(j.values) - 1
    too_small = ReaderLimits(line_bytes=longest - 1)
    with pytest.raises(ResourceError) as caught:
        Ownership.from_journal(
            tmp_path / "j", campaign=CAMPAIGN, variables=VARIABLES, limits=too_small
        )
    assert caught.value.rule == "limit.line"
    # an unfinished line that is already longer than any line may be is a limit, not a torn tail
    write_journal(tmp_path / "k", j, torn=b"x" * (longest + 5))
    with pytest.raises(ResourceError):
        Ownership.from_journal(tmp_path / "k", campaign=CAMPAIGN, variables=VARIABLES, limits=ok)


def test_a_complete_line_over_the_limit_is_refused_even_when_it_is_not_parsed(
    tmp_path: Path,
) -> None:
    """Unverified reading skips lines that are no shard, handoff or split: still bounded."""
    j = journal_with("root")
    j.stop("a", (1,), "stuck", "x" * 20_000)
    write_journal(tmp_path / "j", j)
    long_line = max(len(encode(v)) for v in j.values)
    assert long_line == len(encode(j.values[-1]))
    limits = ReaderLimits(line_bytes=long_line - 1)
    with pytest.raises(ResourceError) as caught:
        Ownership.from_journal(
            tmp_path / "j", campaign=CAMPAIGN, variables=VARIABLES, limits=limits, verify=False
        )
    assert caught.value.rule == "limit.line"
