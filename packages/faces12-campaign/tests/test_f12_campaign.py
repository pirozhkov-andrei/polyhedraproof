"""``campaign init``: the default and restricted campaigns, proof prefixes and pilot roots.

Specification §13.3, §9.2, §4.4. Expected values come from the specification and from frozen
inputs, not from the adapter: the policy defaults of specification §4.3, the recorded prefixes of
maps 1 and 2 (specification §9.2, the prefix-case corpus) and the cubes and node IDs of its cases.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from f12_support import (
    PREFIX_CASES,
    World,
    cs,
    fixture_prefix,
    make_world,
    stored_prefixes,
    write_json,
)

from cubeproof.base.errors import ConfigurationError, InputError
from cubeproof.contracts.campaign import Admit
from cubeproof.contracts.policy import default_policy
from cubeproof.contracts.values import Node, Split, Splitter
from cubeproof.evidence.certify.run import certify
from faces12_campaign import campaign as campaign_adapter
from faces12_campaign import cli, commands, pins
from faces12_campaign.campaign import PilotRoot, prefix_cube

#: Specification §9.2: the proof prefixes expected for maps 1 and 2.
SPEC_PREFIX = {
    1: [1398, 858, 775, 994, 1262, 811, 1213, 947, 945, 1215, 3156, 853],
    2: [853, 1354, 992, 1305, 1399, 1260, 1216, 1259, 1533, 1488, 946, 743],
}


@pytest.fixture
def world(tmp_path: Path) -> World:
    return make_world(tmp_path, [1, 2])


def document(path: Path) -> dict[str, Any]:
    value: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    return value


def prefixes_file(world: World, maps: tuple[int, ...] = (1, 2), **changes: Any) -> Path:
    from neighbourly import corpus12

    hashes = corpus12.formula_hashes()
    entries = [(hashes[m].sha256, fixture_prefix(m)) for m in maps]
    return write_json(
        world.root / "prefixes.json",
        stored_prefixes(entries, world.tools.solver_sha256, **changes),
    )


def test_the_fixture_prefixes_are_the_specified_ones() -> None:
    assert {m: fixture_prefix(m) for m in (1, 2)} == SPEC_PREFIX


def test_prefix_zero_is_fully_dynamic(world: World) -> None:
    doc = document(world.init(prefix=0))
    from neighbourly import corpus12

    hashes = corpus12.formula_hashes()
    assert [(f["key"], f["formula_sha256"]) for f in doc["formulas"]] == [
        ("map01", hashes[1].sha256), ("map02", hashes[2].sha256),
    ]  # fmt: skip
    assert [f["bundle"] for f in doc["formulas"]] == ["formulas/map01", "formulas/map02"]
    roots = sorted((hashes[m].sha256, cs.node_id(hashes[m].sha256, [])) for m in (1, 2))
    assert doc["roots"] == [{"formula_sha256": f, "cube": []} for f, _ in roots]
    assert doc["root_splits"] == []
    assert doc["policy"] == default_policy("transient").to_json()
    assert doc["policy"]["split"] == {
        "method": "lookahead-v1", "vars": 4, "pool": None, "probe_limit": 100000, "wall_ms": 1000,
    }  # fmt: skip
    assert doc["tools"]["solver"] == {
        "name": "cadical", "sha256": world.tools.solver_sha256, "argv": ["--lrat"],
    }  # fmt: skip
    assert doc["admit"] == {"checker_sha256": [world.tools.checker_sha256], "solvers": None}


def test_the_default_prefix_reuses_validated_stored_prefixes(world: World) -> None:
    doc = document(world.init(prefix=12, prefixes=prefixes_file(world)))
    from neighbourly import corpus12

    hashes = corpus12.formula_hashes()
    splits = {s["node"]["formula_sha256"]: s for s in doc["root_splits"]}
    assert set(splits) == {hashes[1].sha256, hashes[2].sha256}
    for map_id in (1, 2):
        split = splits[hashes[map_id].sha256]
        assert split["node"]["cube"] == []
        assert split["variables"] == SPEC_PREFIX[map_id]
        assert split["splitter"]["name"] == "proof-prefix-v1"
        assert split["splitter"]["info"]["solver"]["sha256"] == world.tools.solver_sha256
    ids = [cs.split_id(s["node"]["formula_sha256"], [], s["variables"]) for s in doc["root_splits"]]
    assert ids == sorted(ids)
    assert doc["policy"]["leaf_time_ms"] == {"12": 900000, "default": 300000}


def test_without_a_prefix_file_the_proof_prefix_is_computed(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[Any] = []

    def recorder(request: Any) -> Any:
        seen.append(request)
        raise ConfigurationError("test.stop", "recorded")

    monkeypatch.setattr(campaign_adapter, "create_campaign", recorder)
    for prefix in (12, 4):
        with pytest.raises(ConfigurationError, match="recorded"):
            world.init(prefix=prefix, name=f"c{prefix}.json")
    assert [(r.root_split.kind, r.root_split.count) for r in seen] == [
        ("proof-prefix-v1", 12), ("proof-prefix-v1", 4),
    ]  # fmt: skip
    assert seen[0].roots is None
    assert not (world.root / "c12.json").exists()


def test_the_default_is_the_proof_prefix_12_then_lookahead_4(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No prefix option given: proof-prefix-v1 with 12 variables, the default policy."""
    seen: list[Any] = []

    def recorder(request: Any) -> Any:
        seen.append(request)
        raise ConfigurationError("test.stop", "recorded")

    monkeypatch.setattr(campaign_adapter, "create_campaign", recorder)
    command = commands.InitCommand(
        formulas=world.bundles,
        output=world.root / "campaign.json",
        solver=str(world.tools.solver),
        solver_argv=("--lrat",),
        checker=str(world.tools.checker),
        author="faces12 tests",
        maps=[1, 2],
        unpinned_checker=True,
    )
    with pytest.raises(ConfigurationError, match="recorded"):
        commands.campaign_init(command)
    (request,) = seen
    assert (request.root_split.kind, request.root_split.count) == ("proof-prefix-v1", 12)
    assert request.policy == default_policy("transient")
    assert (request.policy.split.method, request.policy.split.vars) == ("lookahead-v1", 4)
    assert request.roots is None  # every requested root is the empty cube
    parsed = cli.build_parser().parse_args(
        ["campaign", "init", "--formulas", "F", "--solver", "s", "--solver-argv", "[]",
         "--checker", "c", "--author", "a", "-o", "x"]
    )  # fmt: skip
    assert (parsed.prefix, parsed.prefixes, parsed.maps, parsed.proof_mode) == (
        12, None, None, "transient",
    )  # fmt: skip


def test_another_depth_needs_prefixes_of_that_length(world: World) -> None:
    from neighbourly import corpus12

    hashes = corpus12.formula_hashes()
    entries = [(hashes[m].sha256, fixture_prefix(m)[:4]) for m in (1, 2)]
    four = write_json(world.root / "four.json", stored_prefixes(entries, world.tools.solver_sha256))
    doc = document(world.init(prefix=4, prefixes=four))
    assert sorted(len(s["variables"]) for s in doc["root_splits"]) == [4, 4]
    with pytest.raises(InputError) as caught:
        world.init(prefix=12, prefixes=four, name="other.json")
    assert caught.value.rule == "campaign.prefix_count"


@pytest.mark.parametrize(
    ("change", "rule"),
    [
        ({"seed": 6}, "campaign.prefix_provenance"),
        ({"steps": 10000}, "campaign.prefix_provenance"),
        ({"conflicts": 1000}, "campaign.prefix_provenance"),
        ({"pool": "brackets"}, "campaign.prefix_provenance"),
        ({"rng": "other"}, "campaign.prefix_provenance"),
        ({"algorithm": "lookahead-v1"}, "campaign.prefix_provenance"),
        ({"solver": {"sha256": "ab" * 32, "options": []}}, "campaign.prefix_provenance"),
        ({"solver": None}, "campaign.prefix_provenance"),
        ({"solver_options": ["--x"]}, "campaign.prefix_provenance"),
        ({"name": "static"}, "campaign.prefix_provenance"),
        ({"cube": [5]}, "campaign.prefix_cube"),
    ],
)
def test_stored_prefixes_are_refused_unless_their_provenance_validates(
    world: World, change: dict[str, Any], rule: str
) -> None:
    from neighbourly import corpus12

    hashes = corpus12.formula_hashes()
    change = dict(change)
    name = change.pop("name", "proof-prefix-v1")
    cube = change.pop("cube", [])
    if "solver_options" in change:  # the pinned solver, but another configuration of it
        options = change.pop("solver_options")
        change["solver"] = {"sha256": world.tools.solver_sha256, "options": options}
    entries = [(hashes[m].sha256, fixture_prefix(m)) for m in (1, 2)]
    path = write_json(
        world.root / "bad.json",
        stored_prefixes(entries, world.tools.solver_sha256, name=name, cube=cube, **change),
    )
    with pytest.raises(InputError) as caught:
        world.init(prefix=12, prefixes=path)
    assert caught.value.rule == rule
    assert not world.campaign.exists()


def test_stored_prefixes_must_be_order_variables_of_every_campaign_formula(world: World) -> None:
    from neighbourly import corpus12

    hashes = corpus12.formula_hashes()
    manifest = document(world.bundles / "map01" / "manifest.json")
    bracket = manifest["pools"]["brackets"][0]
    wrong = [*fixture_prefix(1)[:11], bracket]
    path = write_json(
        world.root / "pool.json",
        stored_prefixes(
            [(hashes[1].sha256, wrong), (hashes[2].sha256, fixture_prefix(2))],
            world.tools.solver_sha256,
        ),
    )
    with pytest.raises(InputError) as caught:
        world.init(prefix=12, prefixes=path)
    assert caught.value.rule == "campaign.prefix_pool"
    only_one = prefixes_file(world, (1,))
    with pytest.raises(InputError) as missing:
        world.init(prefix=12, prefixes=only_one, name="c2.json")
    assert missing.value.rule == "campaign.prefix_missing"
    # entries of formulas outside the campaign are ignored (a file may cover all 59)
    extra = write_json(
        world.root / "extra.json",
        stored_prefixes(
            [(hashes[m].sha256, fixture_prefix(min(m, 2))) for m in (1, 2, 3)],
            world.tools.solver_sha256,
        ),
    )
    assert len(document(world.init(prefix=12, prefixes=extra, name="c3.json"))["root_splits"]) == 2


def test_two_stored_prefixes_of_one_formula_are_refused(world: World) -> None:
    """Both prefixes of map 1 validate on their own (pinned provenance, order variables); the
    file is still refused rather than letting one of them win silently."""
    from neighbourly import corpus12

    hashes = corpus12.formula_hashes()
    first = fixture_prefix(1)
    second = list(reversed(first))
    path = write_json(
        world.root / "two.json",
        stored_prefixes(
            [
                (hashes[1].sha256, first),
                (hashes[1].sha256, second),
                (hashes[2].sha256, fixture_prefix(2)),
            ],
            world.tools.solver_sha256,
        ),
    )
    with pytest.raises(InputError) as caught:
        world.init(prefix=12, prefixes=path)
    assert caught.value.rule == "campaign.prefix_duplicate"
    assert not world.campaign.exists()


def test_prefix_cases_map_to_their_cubes() -> None:
    for case in json.loads(PREFIX_CASES.read_text(encoding="utf-8"))["cases"]:
        cube = prefix_cube(case["prefix_variables"], case["index"])
        assert list(cube) == case["cube"]
        assert (
            cs.node_id(
                json.loads(PREFIX_CASES.read_text())["bases"][case["map"] - 1]["formula_sha256"],
                list(cube),
            )
            == case["node_id"]
        )
    with pytest.raises(ConfigurationError):
        prefix_cube([1, 2], 4)
    with pytest.raises(ConfigurationError):
        prefix_cube([], 0)


def test_a_pilot_root_is_its_prefix_cube_below_the_stored_prefix(world: World) -> None:
    case = next(
        c
        for c in json.loads(PREFIX_CASES.read_text(encoding="utf-8"))["cases"]
        if (c["map"], c["index"]) == (2, 3077)
    )
    doc = document(
        world.init(
            prefix=12, prefixes=prefixes_file(world), maps=None, pilots=(PilotRoot(2, 3077),)
        )
    )
    from neighbourly import corpus12

    f2 = corpus12.formula_hashes()[2].sha256
    assert [f["key"] for f in doc["formulas"]] == ["map02"]
    assert doc["roots"] == [{"formula_sha256": f2, "cube": case["cube"]}]
    assert cs.node_id(f2, doc["roots"][0]["cube"]) == case["node_id"]
    assert len(doc["roots"][0]["cube"]) == 12  # its 12 literals, not appended a second time
    (split,) = doc["root_splits"]
    assert split["node"] == {"formula_sha256": f2, "cube": []}
    assert split["variables"] == SPEC_PREFIX[2]
    stored = Split(Node(f2, ()), tuple(split["variables"]), Splitter.from_json(split["splitter"]))
    assert stored.children()[3077] == Node(f2, tuple(case["cube"]))


def test_a_closed_pilot_root_is_not_a_proof_of_its_map(world: World) -> None:
    world.init(prefix=12, prefixes=prefixes_file(world), maps=None, pilots=(PilotRoot(2, 3077),))
    case_cube = document(world.campaign)["roots"][0]["cube"]
    builder = world.journal()
    builder.unsat("map02", case_cube)
    journal = builder.write("w1.jsonl")
    certificate = certify(world.campaign, [journal]).certificate
    (formula,) = certificate["formulas"]
    assert formula["roots"][0]["closed"] is True
    assert formula["proved"] is False
    assert certificate["verdict"] == "OPEN"
    assert len(certificate["formula_open"]) == 4095  # the other children of the prefix


def test_pilot_and_selection_errors(world: World) -> None:
    with pytest.raises(ConfigurationError) as no_prefix:
        world.init(prefix=12, maps=None, pilots=(PilotRoot(2, 3077),))
    assert no_prefix.value.rule == "campaign.root"
    with pytest.raises(ConfigurationError) as both:
        world.init(prefix=12, prefixes=prefixes_file(world), pilots=(PilotRoot(2, 1),))
    assert both.value.rule == "usage"
    with pytest.raises(ConfigurationError):
        world.init(prefix=21)
    with pytest.raises(ConfigurationError):
        world.init(prefix=0, prefixes=prefixes_file(world))
    with pytest.raises(ConfigurationError):
        PilotRoot.parse("2-3077")
    with pytest.raises(ConfigurationError):
        world.init(
            prefix=12, prefixes=prefixes_file(world), maps=None, pilots=(PilotRoot(2, 4096),)
        )


def test_a_campaign_is_never_overwritten_and_its_prefixes_can_be_reused(world: World) -> None:
    first = world.init(prefix=12, prefixes=prefixes_file(world))
    before = first.read_bytes()
    with pytest.raises(ConfigurationError) as caught:
        world.init(prefix=0, name="campaign.json")
    assert caught.value.rule == "campaign.exists"
    assert first.read_bytes() == before
    exported = world.root / "exported.json"
    commands.campaign_prefixes(first, exported)
    again = document(world.init(prefix=12, prefixes=exported, name="again.json"))
    assert again["root_splits"] == json.loads(before)["root_splits"]


def test_bundles_are_verified_before_a_campaign_is_made(world: World) -> None:
    from cubeproof.base.errors import IntegrityError

    data = bytearray((world.bundles / "map02" / "formula.cnf").read_bytes())
    data[-3] = ord("1") if data[-3] != ord("1") else ord("2")
    (world.bundles / "map02" / "formula.cnf").write_bytes(bytes(data))
    with pytest.raises(IntegrityError):
        world.init(prefix=0)
    assert not (world.root / "campaign.json").exists()


# -- the checker of a campaign (specification §13.3) ---------------------------------------------


def test_init_refuses_a_checker_that_is_not_the_release_binary(tmp_path: Path) -> None:
    """Oracle: the release hash of faces12_campaign.pins; the stand-in tools of these tests are
    other files, so a campaign needs the explicit flag and reports what it holds."""
    world = make_world(tmp_path, [1])
    with pytest.raises(ConfigurationError) as caught:
        world.init(prefix=0, unpinned_checker=False)
    assert caught.value.rule == "campaign.checker"
    assert world.tools.checker_sha256 in caught.value.detail
    assert pins.RELEASE_CHECKER_SHA256 in caught.value.detail
    assert not (tmp_path / "campaign.json").exists()
    result = commands.campaign_init(
        commands.InitCommand(
            formulas=world.bundles,
            output=tmp_path / "campaign.json",
            solver=str(world.tools.solver),
            solver_argv=("--lrat",),
            checker=str(world.tools.checker),
            author="faces12 tests",
            maps=[1],
            prefix=0,
            unpinned_checker=True,
        )
    )
    assert result.to_json()["tools"] == {
        "solver_sha256": world.tools.solver_sha256,
        "checker_sha256": world.tools.checker_sha256,
        "admitted_checkers": [world.tools.checker_sha256],
        "release_checker": False,
        "release_solver": False,
    }


def test_init_judges_every_admitted_checker(tmp_path: Path) -> None:
    world = make_world(tmp_path, [1])
    release = pins.RELEASE_CHECKER_SHA256
    admit = write_json(tmp_path / "admit.json", {"checker_sha256": [release], "solvers": None})
    with pytest.raises(ConfigurationError) as caught:  # the configured checker is still foreign
        world.init(prefix=0, admit=admit, unpinned_checker=False)
    assert caught.value.rule == "campaign.checker" and release in caught.value.detail


def test_the_release_checker_needs_no_flag() -> None:
    """The gate of ``campaign init`` in isolation: only the release hash passes without the flag."""
    release = pins.RELEASE_CHECKER_SHA256
    assert pins.unpinned([release]) == []
    assert pins.unpinned(["ab" * 32, release, "ab" * 32]) == ["ab" * 32]
    admit = Admit.from_json({"checker_sha256": [release], "solvers": None}, "$")
    assert campaign_adapter._release_checker(release, admit, unpinned_checker=False) is True
    both = Admit.from_json({"checker_sha256": sorted([release, "ab" * 32]), "solvers": None}, "$")
    with pytest.raises(ConfigurationError):
        campaign_adapter._release_checker(release, both, unpinned_checker=False)
    assert campaign_adapter._release_checker(release, both, unpinned_checker=True) is False
