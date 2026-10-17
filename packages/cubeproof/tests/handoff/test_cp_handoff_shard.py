"""``shard``: planning for independent machines, from roots and open coverage (specification §4.5,
§10.3)."""

from __future__ import annotations

import io
import json
import os
import sys
from pathlib import Path
from typing import Any

import pytest

TESTS = Path(__file__).resolve().parents[1]
if str(TESTS / "lifecycle") not in sys.path:
    sys.path.insert(0, str(TESTS / "lifecycle"))

import cp_life_tools as t  # noqa: E402

from cubeproof.base.canonical_json import document_bytes  # noqa: E402
from cubeproof.base.errors import ConfigurationError, InputError, ResourceError  # noqa: E402
from cubeproof.base.settings import ReaderLimits  # noqa: E402
from cubeproof.cnf.campaign import load_campaign  # noqa: E402
from cubeproof.commands import CampaignRequest, certify_command, create_campaign  # noqa: E402
from cubeproof.commands.shard import (  # noqa: E402
    ShardRequest,
    _holds_exactly,
    campaign_nodes,
    deal_round_robin,
    deal_weighted,
    read_shard_file,
    shard_command,
    shards_of,
)
from cubeproof.contracts.campaign import Admit  # noqa: E402
from cubeproof.contracts.documents import Roots, Shard, Weights  # noqa: E402
from cubeproof.contracts.identity import node_id, pairwise_incompatible  # noqa: E402
from cubeproof.contracts.values import Node  # noqa: E402
from cubeproof.coordinator.handoff_run import DeskCoordinator  # noqa: E402
from cubeproof.coordinator.ownership import RECORD_OVERHEAD  # noqa: E402
from cubeproof.tools.isolation import PinnedBinary  # noqa: E402

SPLITTING = {"max_free": 3}
DEEP = t.unsat(8, core=5)


def world(tmp_path: Path, formulas: dict[str, bytes], **options: Any) -> t.World:
    return t.make_world(tmp_path, formulas, **options)


def read_shards(result: Any) -> dict[str, Shard]:
    found = {}
    for planned in result.shards:
        data = Path(planned.path).read_bytes()
        shard = Shard.from_json(json.loads(data))
        assert data == document_bytes(shard.to_json())
        assert shard.shard_id == planned.shard_sha256
        found[planned.name] = shard
    return found


def all_nodes(shards: dict[str, Shard]) -> list[Node]:
    return [n for s in shards.values() for n in s.nodes]


def plan(w: t.World, machines: int, out: str = "plan", **options: Any) -> Any:
    return shard_command(ShardRequest(w.campaign, machines, w.root / out, **options))


# -- the default plan --------------------------------------------------------------------------


def test_requested_roots_are_dealt_round_robin_by_node_id(tmp_path: Path) -> None:
    w = world(tmp_path, {"a": t.unsat(4), "b": t.unsat(5), "c": t.unsat(6)})
    result = plan(w, 2)
    roots = sorted(load_campaign(w.campaign).campaign.roots, key=lambda n: n.node_id)
    shards = read_shards(result)
    assert sorted(shards) == ["shard-1", "shard-2"]
    assert {n.node_id for n in shards["shard-1"].nodes} == {roots[0].node_id, roots[2].node_id}
    assert {n.node_id for n in shards["shard-2"].nodes} == {roots[1].node_id}
    assert result.nodes == 3 and result.empty_machines == () and result.source == "roots"
    assert [p.nodes for p in result.shards] == [2, 1]
    for shard in shards.values():  # nodes sorted (formula, node_id), no root twice
        assert [n.sort_key for n in shard.nodes] == sorted(n.sort_key for n in shard.nodes)
    ids = [n.node_id for n in all_nodes(shards)]
    assert len(ids) == len(set(ids)) == 3


def test_a_machine_without_nodes_gets_no_file(tmp_path: Path) -> None:
    w = world(tmp_path, {"a": t.unsat(4)})
    result = plan(w, 3)
    assert [p.name for p in result.shards] == ["shard-1"] and result.empty_machines == (2, 3)
    assert sorted(p.name for p in (w.root / "plan").iterdir()) == ["shard-1.json"]
    assert result.to_json()["empty_machines"] == [2, 3] and json.dumps(result.to_json())


def split_campaign(w: t.World, formula: str, variables: list[int]) -> Path:
    """The campaign of ``w`` with a direct root split of one formula's empty cube."""
    document = json.loads(w.campaign.read_text())
    entry = next(f for f in document["formulas"] if f["key"] == formula)
    document["root_splits"] = [
        {
            "node": {"formula_sha256": entry["formula_sha256"], "cube": []},
            "variables": variables,
            "splitter": {"name": "static", "info": {}},
        }
    ]
    path = Path(w.root) / "split-campaign.json"
    path.write_bytes(document_bytes(document))
    return path


def test_roots_are_expanded_through_a_direct_root_split(tmp_path: Path) -> None:
    w = world(tmp_path, {"a": t.unsat(4), "b": t.unsat(5)})
    path = split_campaign(w, "a", [1, 2])
    result = shard_command(ShardRequest(path, 2, w.root / "plan"))
    loaded = load_campaign(path)
    shards = read_shards(result)
    nodes = all_nodes(shards)
    assert len(nodes) == 5 and result.nodes == 5
    a = next(f.formula_sha256 for f in loaded.campaign.formulas if f.key == "a")
    cubes = sorted(n.cube for n in nodes if n.formula_sha256 == a)
    assert cubes == sorted([(-1, -2), (-1, 2), (1, -2), (1, 2)])
    assert pairwise_incompatible([n.cube for n in nodes if n.formula_sha256 == a])
    ordered = sorted(nodes, key=lambda n: n.node_id)
    assert {n.node_id for n in shards["shard-1"].nodes} == {n.node_id for n in ordered[0::2]}
    assert {n.node_id for n in shards["shard-2"].nodes} == {n.node_id for n in ordered[1::2]}


def test_one_machine_gets_everything_and_counts_are_checked(tmp_path: Path) -> None:
    w = world(tmp_path, {"a": t.unsat(4), "b": t.unsat(5)})
    assert plan(w, 1).shards[0].nodes == 2
    for bad in (0, -1):
        with pytest.raises(ConfigurationError) as caught:
            plan(w, bad, out=f"bad{bad}")
        assert caught.value.rule == "shard.machines"


def test_the_plan_is_repeatable_and_never_overwrites(tmp_path: Path) -> None:
    w = world(tmp_path, {"a": t.unsat(4), "b": t.unsat(5)})
    first = plan(w, 2)
    again = plan(w, 2)
    assert [p.file_sha256 for p in first.shards] == [p.file_sha256 for p in again.shards]
    with pytest.raises(ConfigurationError) as caught:
        plan(w, 1)  # another plan into the same directory
    assert caught.value.rule == "shard.exists"
    assert sorted(p.name for p in (w.root / "plan").iterdir()) == ["shard-1.json", "shard-2.json"]


def test_a_journal_option_without_from_open_is_refused(tmp_path: Path) -> None:
    w = world(tmp_path, {"a": t.unsat(4)})
    with pytest.raises(ConfigurationError):
        plan(w, 2, journals=[w.journal()])
    with pytest.raises(ConfigurationError):
        plan(w, 2, scope="formulas")


# -- weights -----------------------------------------------------------------------------------


def weights_file(w: t.World, costs: dict[str, int], campaign: str | None = None) -> Path:
    loaded = load_campaign(w.campaign)
    path = Path(w.root) / "weights.json"
    path.write_bytes(
        document_bytes(
            {
                "format": "cubeproof-weights-1",
                "campaign": campaign or loaded.campaign.campaign_id,
                "costs": costs,
            }
        )
    )
    return path


def test_weights_deal_the_largest_first_to_the_lightest_machine(tmp_path: Path) -> None:
    w = world(tmp_path, {"a": t.unsat(4), "b": t.unsat(5), "c": t.unsat(6), "d": t.unsat(7)})
    path = split_campaign(w, "a", [1, 2])
    loaded = load_campaign(path)
    nodes = campaign_nodes(loaded)  # 3 more nodes from "a": 7 in all
    ids = sorted(n.node_id for n in nodes)
    costs = {ids[0]: 10, ids[1]: 7, ids[2]: 7, ids[3]: 3}
    document = {
        "format": "cubeproof-weights-1",
        "campaign": loaded.campaign.campaign_id,
        "costs": costs,
    }
    (w.root / "w.json").write_bytes(document_bytes(document))
    result = shard_command(ShardRequest(path, 3, w.root / "plan", weights=w.root / "w.json"))
    # the oracle: the rule of specification §12.1 written out
    cost = {n.node_id: costs.get(n.node_id, 1) for n in nodes}
    order = sorted(cost, key=lambda i: (-cost[i], i))
    load = [0, 0, 0]
    lanes: list[set[str]] = [set(), set(), set()]
    for ident in order:
        machine = min(range(3), key=lambda m: (load[m], m))
        lanes[machine].add(ident)
        load[machine] += cost[ident]
    shards = read_shards(result)
    for index, lane in enumerate(lanes, 1):
        assert {n.node_id for n in shards[f"shard-{index}"].nodes} == lane
    assert [p.cost for p in result.shards] == load


def test_weights_with_unknown_nodes_or_another_campaign_are_refused(tmp_path: Path) -> None:
    w = world(tmp_path, {"a": t.unsat(4), "b": t.unsat(5)})
    with pytest.raises(InputError) as unknown:
        plan(w, 2, weights=weights_file(w, {"ab" * 32: 5}))
    assert unknown.value.rule == "weights.unknown"
    other = weights_file(w, {}, campaign="cd" * 32)
    with pytest.raises(InputError) as foreign:
        plan(w, 2, out="p2", weights=other)
    assert foreign.value.rule == "shard.weights"
    with pytest.raises(InputError):
        plan(w, 2, out="p3", weights=weights_file(w, {node_id("0" * 64, ()): 0}))


def test_the_dealing_rules_on_plain_nodes() -> None:
    nodes = [Node("11" * 32, (i,)) for i in range(1, 8)]
    lanes = deal_round_robin(nodes, 3)
    assert sorted(len(lane) for lane in lanes) == [2, 2, 3]
    assert {n.cube for lane in lanes for n in lane} == {n.cube for n in nodes}
    ordered = sorted(nodes, key=lambda n: n.node_id)
    assert lanes[0] == ordered[0::3] and lanes[1] == ordered[1::3]
    weights = Weights("22" * 32, {n.node_id: 5 for n in nodes[:2]})
    heavy = deal_weighted(nodes, 2, weights)
    assert {n.cube for n in heavy[0][:1]} | {n.cube for n in heavy[1][:1]} == {
        n.cube for n in nodes[:2]
    }
    assert deal_weighted([], 2, weights) == [[], []]


# -- large node lists --------------------------------------------------------------------------


def test_a_machine_with_more_nodes_than_one_record_holds_gets_several_shards() -> None:
    nodes = [Node("11" * 32, tuple(sorted((*c, 1), key=abs))) for c in _grid(6)]
    cap = RECORD_OVERHEAD + 512 + 1500
    shards = shards_of("22" * 32, 4, nodes, max_line_bytes=cap)
    assert len(shards) > 1
    assert [s.name for s in shards] == [f"shard-4-{i}" for i in range(1, len(shards) + 1)]
    assert sorted(n.node_id for s in shards for n in s.nodes) == sorted(n.node_id for n in nodes)
    for shard in shards:
        assert len(document_bytes(shard.to_json())) + RECORD_OVERHEAD <= cap
    single = shards_of("22" * 32, 4, nodes[:2], max_line_bytes=cap)
    assert [s.name for s in single] == ["shard-4"] and shards_of(
        "22" * 32, 1, [], max_line_bytes=cap
    ) == []
    with pytest.raises(ResourceError):
        shards_of("22" * 32, 1, nodes, max_line_bytes=RECORD_OVERHEAD + 512 + 20)


def _grid(variables: int) -> list[tuple[int, ...]]:
    import itertools

    return [tuple(c) for c in itertools.product(*[(v, -v) for v in range(2, variables + 2)])]


def test_a_plan_over_the_limit_divides_the_node_list(tmp_path: Path) -> None:
    w = world(tmp_path, {"a": t.unsat(4), "b": t.unsat(5), "c": t.unsat(6)})
    limits = ReaderLimits(line_bytes=RECORD_OVERHEAD + 512 + 400)
    result = shard_command(ShardRequest(w.campaign, 1, w.root / "plan", limits=limits))
    assert len(result.shards) >= 2 and {p.machine for p in result.shards} == {1}
    assert [p.name for p in result.shards] == [
        f"shard-1-{i}" for i in range(1, len(result.shards) + 1)
    ]
    assert sum(p.nodes for p in result.shards) == result.nodes == 3


# -- reading a shard file ----------------------------------------------------------------------


def test_a_shard_file_is_read_for_the_formulas_of_the_campaign(tmp_path: Path) -> None:
    w = world(tmp_path, {"a": t.unsat(4)})
    result = plan(w, 1)
    loaded = load_campaign(w.campaign)
    variables = {sha: b.formula.variables for sha, b in loaded.bundles.items()}
    shard = read_shard_file(Path(result.shards[0].path), variables=variables)
    assert shard.name == "shard-1"
    with pytest.raises(InputError):
        read_shard_file(Path(result.shards[0].path), variables={})
    (w.root / "bad.json").write_bytes(b"{}")
    with pytest.raises(InputError):
        read_shard_file(w.root / "bad.json", variables=variables)
    with pytest.raises(InputError):
        read_shard_file(w.root / "absent.json", variables=variables)


# -- some formulas of the campaign -------------------------------------------------------------


def keys_of(nodes: list[Node]) -> set[tuple[str, tuple[int, ...]]]:
    return {(n.formula_sha256, n.cube) for n in nodes}


def test_a_plan_of_one_formula_holds_its_nodes_and_nothing_else(tmp_path: Path) -> None:
    """``--formula`` restricts what is dealt: the plan of formula a and the plan of the others are
    disjoint and together the plan of the campaign."""
    w = world(tmp_path, {"a": t.unsat(4), "b": t.unsat(5), "c": t.unsat(6)})
    path = split_campaign(w, "a", [1, 2])
    sha = {f.key: f.formula_sha256 for f in load_campaign(path).campaign.formulas}
    whole = shard_command(ShardRequest(path, 1, w.root / "whole"))
    assert whole.formulas == () and whole.to_json()["formulas"] == []
    one = shard_command(ShardRequest(path, 2, w.root / "one", formulas=("a",)))
    nodes = all_nodes(read_shards(one))
    assert keys_of(nodes) == {(sha["a"], c) for c in [(-1, -2), (-1, 2), (1, -2), (1, 2)]}
    assert one.nodes == 4 and one.formulas == ("a",) and one.to_json()["formulas"] == ["a"]
    # dealt round robin among the planned nodes, not among those of the campaign
    ordered = sorted(nodes, key=lambda n: n.node_id)
    shards = read_shards(one)
    assert {n.node_id for n in shards["shard-1"].nodes} == {n.node_id for n in ordered[0::2]}
    assert {n.node_id for n in shards["shard-2"].nodes} == {n.node_id for n in ordered[1::2]}
    rest = shard_command(ShardRequest(path, 2, w.root / "rest", formulas=("c", "b", "c")))
    assert rest.formulas == ("b", "c") and rest.nodes == 2
    others = all_nodes(read_shards(rest))
    assert keys_of(others) == {(sha["b"], ()), (sha["c"], ())}
    assert keys_of(nodes) | keys_of(others) == keys_of(all_nodes(read_shards(whole)))


def test_a_formula_the_campaign_does_not_have_is_refused_and_nothing_is_written(
    tmp_path: Path,
) -> None:
    w = world(tmp_path, {"a": t.unsat(4), "b": t.unsat(5)})
    (a,) = [f.formula_sha256 for f in load_campaign(w.campaign).campaign.formulas if f.key == "a"]
    for keys in (("z",), ("a", "z"), (a,)):  # a formula is named by its key, not by its hash
        with pytest.raises(ConfigurationError) as caught:
            plan(w, 2, formulas=keys)
        assert caught.value.rule == "shard.formula"
        assert keys[-1] in caught.value.detail and "a, b" in caught.value.detail
    assert not (w.root / "plan").exists()
    # the key is judged before a certificate is read or recomputed
    with pytest.raises(ConfigurationError) as early:
        plan(w, 2, formulas=("z",), from_open=w.root / "none.json", journals=[w.root / "none"])
    assert early.value.rule == "shard.formula"


def test_weights_of_a_plan_of_one_formula_name_its_nodes_only(tmp_path: Path) -> None:
    w = world(tmp_path, {"a": t.unsat(4), "b": t.unsat(5)})
    loaded = load_campaign(w.campaign)
    ids = {f.key: Node(f.formula_sha256, ()).node_id for f in loaded.campaign.formulas}
    campaign_id = loaded.campaign.campaign_id

    def weights(name: str, costs: dict[str, int]) -> Path:
        path = Path(w.root) / name
        document = {"format": "cubeproof-weights-1", "campaign": campaign_id, "costs": costs}
        path.write_bytes(document_bytes(document))
        return path

    good = plan(w, 1, formulas=("a",), weights=weights("wa.json", {ids["a"]: 7}))
    assert [p.cost for p in good.shards] == [7]
    with pytest.raises(InputError):  # the node of b is not planned
        plan(w, 1, out="p2", formulas=("a",), weights=weights("wb.json", {ids["b"]: 7}))
    assert not (w.root / "p2").exists()


def test_a_worker_with_the_shard_of_one_formula_proves_it_in_the_campaign_of_all(
    tmp_path: Path,
) -> None:
    """One formula of a campaign computed first: the worker owns the planned nodes only, its
    journal is a journal of the whole campaign, and the certificate says which formula is proved
    and that the campaign is open."""
    w = world(tmp_path, {"a": DEEP, "b": t.unsat(5)}, solver=SPLITTING)
    result = plan(w, 1, formulas=("a",))
    (shard,) = read_shards(result).values()
    desk = DeskCoordinator(
        w.config(), inbox=w.root / "inbox", outbox=w.root / "outbox", shard=shard
    )
    assert desk.run().exit_code == 0  # its work is done
    _, certificate = certificate_of(w, w.journal(), "one.json")
    assert certificate["verdict"] == "OPEN"
    assert {f["key"]: f["proved"] for f in certificate["formulas"]} == {"a": True, "b": False}
    sha = {f.key: f.formula_sha256 for f in load_campaign(w.campaign).campaign.formulas}
    assert [e["node"] for e in certificate["open"]] == [{"formula_sha256": sha["b"], "cube": []}]
    assert {a["node"]["formula_sha256"] for a in w.attempts()} == {sha["a"]}  # b was not touched
    # the rest is planned from that certificate, and for one formula of it
    cert_path = Path(w.root) / "one.json"
    rest = plan(w, 1, out="rest", from_open=cert_path, journals=[w.journal()], formulas=("b",))
    assert keys_of(all_nodes(read_shards(rest))) == {(sha["b"], ())}
    none = plan(w, 1, out="none", from_open=cert_path, journals=[w.journal()], formulas=("a",))
    assert none.nodes == 0 and none.shards == () and none.formulas == ("a",)


# -- from open coverage ------------------------------------------------------------------------


def prefix_journal(w: t.World, attempts: int, name: str = "prefix.jsonl") -> Path:
    """The journal of a finished run cut after the n-th VERIFIED_UNSAT attempt (a valid journal)."""
    lines = w.journal().read_bytes().splitlines(keepends=True)
    kept, seen = [], 0
    for line in lines:
        kept.append(line)
        if b'"outcome":"VERIFIED_UNSAT"' in line:
            seen += 1
            if seen == attempts:
                break
    path = Path(w.root) / name
    path.write_bytes(b"".join(kept))
    return path


def certificate_of(w: t.World, journal: Path, name: str) -> tuple[Path, dict[str, Any]]:
    path = Path(w.root) / name
    result = certify_command(w.campaign, [journal], path)
    return path, result.certificate


def open_set(certificate: dict[str, Any], field: str = "open") -> set[str]:
    return {e["node_id"] for e in certificate[field]}


def test_the_remaining_work_is_planned_from_a_certificate_without_expanding_it(
    tmp_path: Path,
) -> None:
    w = world(tmp_path, {"f": DEEP}, solver=SPLITTING)
    assert w.run().exit_code == 0
    journal = prefix_journal(w, 6)
    cert_path, certificate = certificate_of(w, journal, "open.json")
    assert certificate["verdict"] == "OPEN" and 0 < len(certificate["open"]) < 16
    result = plan(w, 3, from_open=cert_path, journals=[journal])
    shards = read_shards(result)
    nodes = all_nodes(shards)
    assert {n.node_id for n in nodes} == open_set(certificate)
    assert len(nodes) == len(open_set(certificate)) == result.nodes and result.source == "open"
    assert result.scope == "campaign" and result.stopped == {}


def test_a_closed_campaign_has_nothing_to_plan(tmp_path: Path) -> None:
    w = world(tmp_path, {"f": DEEP}, solver=SPLITTING)
    assert w.run().exit_code == 0
    cert_path, certificate = certificate_of(w, w.journal(), "done.json")
    assert certificate["verdict"] == "PROVED"
    result = plan(w, 2, from_open=cert_path, journals=[w.journal()])
    assert result.nodes == 0 and result.shards == () and result.empty_machines == (1, 2)


def test_a_pilot_does_not_schedule_the_rest_of_the_formula_unless_asked(tmp_path: Path) -> None:
    tools = t.install(tmp_path / "tools", solver=SPLITTING)
    bundle_root = tmp_path
    formulas = {"f": t.unsat(5)}
    # a campaign whose only requested root is the half-space [1]
    from cubeproof.cnf.bundle import publish_bundle

    publish_bundle(
        bundle_root / "bundles" / "f",
        formulas["f"],
        pools={},
        producer={"name": "t", "version": "1", "parameters": {}},
    )
    from cubeproof.cnf.bundle import load_bundle

    sha = load_bundle(bundle_root, "bundles/f").manifest.formula_sha256
    checker = PinnedBinary.measure(str(tools.checker)).sha256
    campaign = bundle_root / "campaign.json"
    create_campaign(
        CampaignRequest(
            bundles=[bundle_root / "bundles" / "f"],
            policy=t.split_policy(),
            admit=Admit.from_json({"checker_sha256": [checker], "solvers": None}, "$"),
            solver=str(tools.solver),
            solver_argv=["--lrat"],
            checker=str(tools.checker),
            output=campaign,
            author="tests",
            roots=Roots((Node(sha, (1,)),)),
        )
    )
    w = t.World(tmp_path, campaign, tools)
    w.run()
    cert_path, certificate = certificate_of(w, w.journal(), "pilot.json")
    assert certificate["verdict"] == "OPEN"
    assert open_set(certificate) == set()  # the requested root is closed
    assert certificate["formula_open"], "the rest of the formula is open"
    default = shard_command(
        ShardRequest(campaign, 1, tmp_path / "p1", from_open=cert_path, journals=[w.journal()])
    )
    assert default.nodes == 0 and default.scope == "campaign"
    wide = shard_command(
        ShardRequest(
            campaign,
            1,
            tmp_path / "p2",
            from_open=cert_path,
            journals=[w.journal()],
            scope="formulas",
        )
    )
    assert wide.scope == "formulas" and wide.nodes == len(certificate["formula_open"])
    # formula_open is computed from the empty cube: the whole formula is still one open node
    assert [n.cube for n in all_nodes(read_shards(wide))] == [()]


def test_stopped_nodes_are_planned_and_counted(tmp_path: Path) -> None:
    w = world(tmp_path, {"f": t.unsat(5)}, solver={"crash_if_free_le": 99})
    w.run()  # tool failures: the root is blocked
    cert_path, certificate = certificate_of(w, w.journal(), "blocked.json")
    assert [e["state"] for e in certificate["open"]] == ["tool_blocked"]
    result = plan(w, 2, from_open=cert_path, journals=[w.journal()])
    assert result.nodes == 1 and result.stopped == {"tool_blocked": 1}


def test_stopped_nodes_are_counted_for_the_planned_formulas_only(tmp_path: Path) -> None:
    w = world(tmp_path, {"f": t.unsat(5), "g": t.unsat(6)}, solver={"crash_if_free_le": 5})
    w.run()  # the tools fail on f only: its root is blocked, g is proved
    cert_path, certificate = certificate_of(w, w.journal(), "blocked.json")
    assert [e["state"] for e in certificate["open"]] == ["tool_blocked"]
    journals = [w.journal()]
    assert plan(w, 1, from_open=cert_path, journals=journals).stopped == {"tool_blocked": 1}
    f = plan(w, 1, out="f", from_open=cert_path, journals=journals, formulas=("f",))
    assert f.nodes == 1 and f.stopped == {"tool_blocked": 1}
    g = plan(w, 1, out="g", from_open=cert_path, journals=journals, formulas=("g",))
    assert g.nodes == 0 and g.stopped == {} and g.shards == ()


def test_a_certificate_is_compared_as_bytes_without_a_size_limit(tmp_path: Path) -> None:
    # Specification §4.1: certificates have no document limit; the campaign of 59 formulas has a
    # certificate of about 130 MB at its start, twice the default limit of 64 MiB.
    w = world(tmp_path, {"f": DEEP}, solver=SPLITTING)
    w.run()
    journal = prefix_journal(w, 6)
    cert_path, certificate = certificate_of(w, journal, "cert.json")
    data = cert_path.read_bytes()
    below = ReaderLimits(document_bytes=len(data) - 2)  # J(certificate) is len(data) - 1 bytes
    assert len(w.campaign.read_bytes()) - 1 <= below.document_bytes
    result = plan(w, 2, from_open=cert_path, journals=[journal], limits=below)
    assert result.nodes == len(certificate["open"]) > 0
    for name, changed in {
        "spaced": data.replace(b",", b", ", 1),  # the same value, other bytes
        "truncated": data[:-1],
        "extended": data + b"\n",
        "edited": data.replace(b'"OPEN"', b'"OPEX"', 1),  # the same length
    }.items():
        assert changed != data, name
        other = Path(w.root) / f"{name}.json"
        other.write_bytes(changed)
        with pytest.raises(InputError) as caught:
            plan(w, 2, out=f"p-{name}", from_open=other, journals=[journal])
        assert caught.value.rule == "shard.certificate", name
    fifo = Path(w.root) / "fifo.json"
    os.mkfifo(fifo)  # refused at once: neither the open nor the comparison waits for a writer
    for unusable in (Path(w.root), fifo):
        with pytest.raises(InputError) as unreadable:
            plan(w, 2, out="p-bad", from_open=unusable, journals=[journal])
        assert unreadable.value.rule == "input.file", unusable


def test_a_file_holds_a_document_only_with_exactly_its_bytes() -> None:
    expected = bytes(range(256)) * 9000  # more than two chunks of 1 MiB
    assert _holds_exactly(io.BytesIO(expected), expected)
    late = bytearray(expected)
    late[(1 << 20) + 5] ^= 1  # a difference after the first chunk
    for other in (bytes(late), expected[:-1], expected + b"x", b""):
        assert not _holds_exactly(io.BytesIO(other), expected)


def test_a_model_is_never_planned(tmp_path: Path) -> None:
    w = world(tmp_path, {"f": t.sat(5)})
    assert w.run().exit_code == 2
    cert_path, certificate = certificate_of(w, w.journal(), "model.json")
    assert certificate["verdict"] == "MODEL_FOUND"
    with pytest.raises(InputError) as caught:
        plan(w, 2, from_open=cert_path, journals=[w.journal()])
    assert caught.value.rule == "shard.model"
    assert not (w.root / "plan").exists() or list((w.root / "plan").iterdir()) == []


def test_a_certificate_that_is_not_the_journals_is_refused(tmp_path: Path) -> None:
    w = world(tmp_path, {"f": DEEP}, solver=SPLITTING)
    w.run()
    journal = prefix_journal(w, 6)
    other = prefix_journal(w, 9, "other.jsonl")
    cert_path, _ = certificate_of(w, other, "cert.json")
    with pytest.raises(InputError) as caught:
        plan(w, 2, from_open=cert_path, journals=[journal])
    assert caught.value.rule == "shard.certificate"
    with pytest.raises(ConfigurationError) as missing:
        plan(w, 2, out="p2", from_open=cert_path)
    assert missing.value.rule == "shard.journals"
    with pytest.raises(ConfigurationError):
        plan(w, 2, out="p3", from_open=cert_path, journals=[journal], scope="elsewhere")
    assert not (w.root / "plan").exists()


def test_the_planned_nodes_are_exactly_what_a_new_worker_must_still_prove(tmp_path: Path) -> None:
    """Re-sharding from open, whole: the pieces cover the open frontier and nothing else."""
    w = world(tmp_path, {"f": DEEP}, solver=SPLITTING)
    w.run()
    journal = prefix_journal(w, 4)
    cert_path, certificate = certificate_of(w, journal, "open.json")
    result = plan(w, 4, from_open=cert_path, journals=[journal])
    shards = read_shards(result)
    planned = {(n.formula_sha256, n.cube) for n in all_nodes(shards)}
    declared = {
        (e["node"]["formula_sha256"], tuple(e["node"]["cube"])) for e in certificate["open"]
    }
    assert planned == declared
    # the pieces are disjoint from each other: no region is planned twice
    by_formula: dict[str, list[tuple[int, ...]]] = {}
    for formula, cube in planned:
        by_formula.setdefault(formula, []).append(cube)
    assert all(pairwise_incompatible(cubes) for cubes in by_formula.values())
