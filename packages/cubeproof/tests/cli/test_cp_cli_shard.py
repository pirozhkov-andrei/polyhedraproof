"""Specification §10.3, §12.1: the shard planner at the command line.

Oracles are transcribed from the specification (node identity and child numbering §3.2, round
robin and weighted dealing §12.1), not taken from the code under test. The properties:
every plan covers exactly the expected nodes, the shards of a plan are pairwise disjoint, the
default plan is round robin by node_id, a weighted plan is "largest cost first to the least loaded
machine, lowest index on ties", a plan from a certificate uses its frontier as it is, the scope
decides which frontier, and a certificate that its journals do not produce is never used.
"""

from __future__ import annotations

import hashlib
import json
import random
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Any

import cp_cli_support as c
import pytest
from cp_cli_support import formula_hash, prefixes, write

Cube = tuple[int, ...]
Node = tuple[str, Cube]


def node_id_of(formula: str, cube: Sequence[int]) -> str:
    """Specification §3.2: SHA256 of "node" NUL formula NUL the cube's space-separated literals."""
    data = b"node\0" + formula.encode() + b"\0" + " ".join(str(x) for x in cube).encode()
    return hashlib.sha256(data).hexdigest()


def children(cube: Sequence[int], variables: Sequence[int]) -> list[Cube]:
    """Specification §3.2: child t assigns +W[j] when bit j of t is 1, -W[j] otherwise; in
    canonical order."""
    found = []
    for t in range(1 << len(variables)):
        signed = [v if t >> j & 1 else -v for j, v in enumerate(variables)]
        found.append(tuple(sorted((*cube, *signed), key=abs)))
    return found


def incompatible(a: Cube, b: Cube) -> bool:
    return any(-x in set(b) for x in a)


def read_shards(plan: dict[str, Any]) -> dict[int, list[Node]]:
    """Machine -> its nodes, from the shard files the plan lists."""
    found: dict[int, list[Node]] = {}
    for shard in plan["shards"]:
        document = json.loads(Path(shard["path"]).read_bytes())
        assert (
            document["format"] == "cubeproof-shard-1" and document["campaign"] == plan["campaign"]
        )
        found.setdefault(shard["machine"], []).extend(
            (n["formula_sha256"], tuple(n["cube"])) for n in document["nodes"]
        )
    return found


def assert_disjoint(per_machine: dict[int, list[Node]]) -> None:
    every = [n for nodes in per_machine.values() for n in nodes]
    assert len(set(every)) == len(every)
    for i, (fa, ca) in enumerate(every):
        for fb, cb in every[i + 1 :]:
            assert fa != fb or incompatible(ca, cb), (ca, cb)


def plan(shop: c.Shop, capsys: pytest.CaptureFixture[str], out: Path, *more: str) -> c.Done:
    return c.cli_main(["shard", "--campaign", str(shop.campaign), "-o", str(out), *more], capsys)


def split_world(root: Path, capsys: pytest.CaptureFixture[str]) -> tuple[c.Shop, str, str]:
    """Formulas a (root split on 1,2,3: eight nodes) and b (one root): nine planned nodes."""
    shop = c.shop(root, {"a": c.t.unsat(8, core=5), "b": c.SHALLOW})
    a, b = formula_hash(shop, "a"), formula_hash(shop, "b")
    file = write(root / "prefix.json", prefixes([(a, [], [1, 2, 3])]))
    done = c.cli_main(
        shop.create_args(
            root / "bundles" / "a", root / "bundles" / "b", more=["--root-split", f"static:{file}"]
        ),
        capsys,
    )
    assert done.code == 0, done.err
    return shop, a, b


def expected_nodes(a: str, b: str) -> list[Node]:
    return [(a, cube) for cube in children((), [1, 2, 3])] + [(b, ())]


def test_the_default_plan_is_round_robin_by_node_id_over_the_expanded_roots(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    shop, a, b = split_world(tmp_path, capsys)
    done = plan(shop, capsys, tmp_path / "out", "--machines", "4")
    assert done.code == 0, done.err
    document = c.last_json(done.out)
    nodes = expected_nodes(a, b)
    ordered = sorted(nodes, key=lambda n: node_id_of(*n))
    expected = {m: [n for i, n in enumerate(ordered) if i % 4 == m - 1] for m in range(1, 5)}
    got = read_shards(document)
    assert {m: sorted(v) for m, v in got.items()} == {m: sorted(v) for m, v in expected.items()}
    assert_disjoint(got)
    assert sorted(n for v in got.values() for n in v) == sorted(nodes)  # nothing missing or twice
    assert set(document) == {
        "campaign", "machines", "scope", "source", "nodes", "shards", "empty_machines", "stopped",
        "formulas",
    }  # fmt: skip
    assert document["formulas"] == []
    assert (document["machines"], document["scope"], document["source"], document["nodes"]) == (
        4,
        "campaign",
        "roots",
        9,
    )
    assert document["empty_machines"] == [] and document["stopped"] == {}
    for entry in document["shards"]:
        assert set(entry) == {
            "machine",
            "name",
            "path",
            "nodes",
            "cost",
            "shard_sha256",
            "file_sha256",
        }
        data = Path(entry["path"]).read_bytes()
        assert hashlib.sha256(data).hexdigest() == entry["file_sha256"]
        assert hashlib.sha256(data[:-1]).hexdigest() == entry["shard_sha256"]  # the shard's ID
        assert entry["cost"] == entry["nodes"]  # every node costs 1 without weights
        shard_nodes = json.loads(data)["nodes"]
        keys = [
            (n["formula_sha256"], node_id_of(n["formula_sha256"], n["cube"])) for n in shard_nodes
        ]
        assert keys == sorted(keys)  # sorted (formula_sha256, node_id)


def test_the_formula_option_plans_the_named_formulas_and_refuses_an_unknown_key(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    shop, a, b = split_world(tmp_path, capsys)
    done = plan(shop, capsys, tmp_path / "a", "--machines", "2", "--formula", "a")
    assert done.code == 0, done.err
    document = c.last_json(done.out)
    got = read_shards(document)
    assert sorted(n for v in got.values() for n in v) == sorted(expected_nodes(a, b)[:8])
    assert document["nodes"] == 8 and document["formulas"] == ["a"]
    both = plan(
        shop, capsys, tmp_path / "ab", "--machines", "1", "--formula", "b", "--formula", "a"
    )
    assert c.last_json(both.out)["nodes"] == 9 and c.last_json(both.out)["formulas"] == ["a", "b"]
    bad = plan(shop, capsys, tmp_path / "bad", "--machines", "2", "--formula", "map01")
    assert bad.code == 3 and "[shard.formula]" in bad.err and "map01" in bad.err
    assert not (tmp_path / "bad").exists()


def test_more_machines_than_nodes_leave_machines_without_a_file(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    shop, a, b = split_world(tmp_path, capsys)
    done = plan(shop, capsys, tmp_path / "out", "--machines", "12")
    document = c.last_json(done.out)
    assert done.code == 0 and document["nodes"] == 9
    assert len(document["empty_machines"]) == 3 and len(document["shards"]) == 9
    assert sorted(p.name for p in (tmp_path / "out").iterdir()) == sorted(
        s["name"] + ".json" for s in document["shards"]
    )
    assert_disjoint(read_shards(document))
    one = plan(shop, capsys, tmp_path / "one", "--machines", "1")
    assert sorted(read_shards(c.last_json(one.out))[1]) == sorted(expected_nodes(a, b))


def deal_weighted_oracle(
    nodes: Iterable[Node], machines: int, weights: dict[str, int]
) -> dict[int, set[Node]]:
    """Specification §12.1: largest cost first (ties by node_id), each to the least loaded machine
    (lowest index on ties)."""
    load = [0] * machines
    lanes: dict[int, set[Node]] = {m: set() for m in range(1, machines + 1)}
    for node in sorted(nodes, key=lambda n: (-weights.get(node_id_of(*n), 1), node_id_of(*n))):
        target = min(range(machines), key=lambda m: (load[m], m))
        lanes[target + 1].add(node)
        load[target] += weights.get(node_id_of(*node), 1)
    return lanes


@pytest.mark.parametrize("seed", range(12))
def test_weighted_plans_follow_the_dealing_rule_and_are_disjoint(
    seed: int, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    shop, a, b = split_world(tmp_path, capsys)
    rng = random.Random(seed)
    nodes = expected_nodes(a, b)
    machines = rng.randint(1, 5)
    weights = {
        node_id_of(*n): rng.choice([1, 2, 3, 10, 1000])
        for n in rng.sample(nodes, rng.randint(0, len(nodes)))
    }  # the rest cost 1
    probe = c.last_json(plan(shop, capsys, tmp_path / "probe", "--machines", "1").out)
    document = {"format": "cubeproof-weights-1", "campaign": probe["campaign"], "costs": weights}
    path = write(tmp_path / "weights.json", document)
    done = plan(shop, capsys, tmp_path / "out", "--machines", str(machines), "--weights", str(path))
    assert done.code == 0, done.err
    result = c.last_json(done.out)
    got = read_shards(result)
    oracle = deal_weighted_oracle(nodes, machines, weights)
    assert {m: set(v) for m, v in got.items()} == {m: v for m, v in oracle.items() if v}
    assert_disjoint(got)
    assert sorted(n for v in got.values() for n in v) == sorted(nodes)
    per_machine = {m: sum(weights.get(node_id_of(*n), 1) for n in v) for m, v in got.items()}
    reported: dict[int, int] = {}
    for shard in result["shards"]:
        reported[shard["machine"]] = reported.get(shard["machine"], 0) + shard["cost"]
    assert reported == per_machine
    # the plan is deterministic: planning again into another directory gives the same sets
    again = c.last_json(
        plan(
            shop, capsys, tmp_path / "again", "--machines", str(machines), "--weights", str(path)
        ).out
    )
    assert {m: sorted(v) for m, v in read_shards(again).items()} == {
        m: sorted(v) for m, v in got.items()
    }


def test_invalid_weights_are_refused_before_anything_is_written(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    shop, _a, b = split_world(tmp_path, capsys)
    probe = c.last_json(plan(shop, capsys, tmp_path / "probe", "--machines", "1").out)
    known = node_id_of(b, ())

    def attempt(document: dict[str, Any]) -> c.Done:
        path = tmp_path / "w.json"  # raw JSON: the document writer refuses a float
        path.write_text(json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n")
        return plan(shop, capsys, tmp_path / "out", "--machines", "2", "--weights", str(path))

    base = {"format": "cubeproof-weights-1", "campaign": probe["campaign"]}
    assert attempt({**base, "costs": {known: 3}}).code == 0
    (tmp_path / "out" / "shard-1.json").unlink()
    (tmp_path / "out" / "shard-2.json").unlink()
    cases = [
        ("weights.unknown", {**base, "costs": {"1" * 64: 3}}),  # an unplanned node ID
        ("schema", {**base, "costs": {known: 0}}),  # not positive
        ("json.number", {**base, "costs": {known: 1.5}}),
        ("schema", {**base, "costs": {"not-a-hash": 2}}),
        ("shard.weights", {**base, "campaign": "0" * 64, "costs": {known: 3}}),  # another campaign
        ("schema", {"format": "cubeproof-weights-2", "campaign": probe["campaign"], "costs": {}}),
    ]
    for rule, document in cases:
        done = attempt(document)
        assert done.code == 3 and f"[{rule}]" in done.err, (rule, done.err)
        assert list((tmp_path / "out").iterdir()) == []
    missing = plan(
        shop, capsys, tmp_path / "out", "--machines", "2", "--weights", str(tmp_path / "nope.json")
    )
    assert missing.code == 3 and "[input.file]" in missing.err


def test_a_plan_is_never_overwritten_with_other_content(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    shop, *_ = split_world(tmp_path, capsys)
    first = plan(shop, capsys, tmp_path / "out", "--machines", "2")
    assert first.code == 0
    again = plan(shop, capsys, tmp_path / "out", "--machines", "2")  # identical plan: harmless
    assert again.code == 0 and c.last_json(again.out) == c.last_json(first.out)
    before = (tmp_path / "out" / "shard-1.json").read_bytes()
    other = plan(shop, capsys, tmp_path / "out", "--machines", "3")
    assert other.code == 3 and "[shard.exists]" in other.err
    assert (tmp_path / "out" / "shard-1.json").read_bytes() == before


# -- plans from a certificate ---------------------------------------------------------------------


def pilot_world(root: Path, capsys: pytest.CaptureFixture[str]) -> tuple[c.Shop, str]:
    """One formula, a pilot root (1) and a root split on variable 1 of the empty cube: the root's
    sibling (-1) is outside the campaign scope but inside the formula's."""
    shop = c.shop(root, {"f": c.t.unsat(8, core=5)}, solver={"max_free": 3})
    f = formula_hash(shop, "f")
    roots = write(
        root / "roots.json",
        {"format": "cubeproof-roots-1", "roots": [{"formula_sha256": f, "cube": [1]}]},
    )
    file = write(root / "prefix.json", prefixes([(f, [], [1])]))
    done = c.cli_main(
        shop.create_args(
            root / "bundles" / "f",
            more=["--roots", str(roots), "--root-split", f"static:{file}"],
        ),
        capsys,
    )
    assert done.code == 0, done.err
    ran = c.cli_main(shop.run_args("--jobs", "2"), capsys)
    assert ran.code == 0, ran.err  # the pilot root is closed ...
    certificate = root / "certificate.json"
    certified = c.cli_main(
        [
            "certify",
            "--campaign",
            str(shop.campaign),
            "--journals",
            str(shop.journal),
            "-o",
            str(certificate),
        ],
        capsys,
    )
    assert certified.code == 1 and certified.out.startswith("OPEN")  # ... the formula is not
    return shop, f


def from_open(shop: c.Shop, capsys: pytest.CaptureFixture[str], out: Path, *more: str) -> c.Done:
    return plan(
        shop, capsys, out, "--machines", "2",
        "--from-open", str(shop.root / "certificate.json"), "--journals", str(shop.journal), *more,
    )  # fmt: skip


def test_scope_campaign_plans_only_the_requested_roots_and_formulas_plans_the_rest(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    shop, f = pilot_world(tmp_path, capsys)
    scoped = from_open(shop, capsys, tmp_path / "campaign-scope")
    document = c.last_json(scoped.out)
    assert scoped.code == 0, scoped.err
    assert (document["source"], document["scope"], document["nodes"]) == ("open", "campaign", 0)
    assert document["shards"] == [] and document["empty_machines"] == [1, 2]
    assert not list((tmp_path / "campaign-scope").iterdir())  # a pilot never schedules the rest
    explicit = from_open(shop, capsys, tmp_path / "explicit", "--scope", "campaign")
    assert c.last_json(explicit.out)["nodes"] == 0
    rest = from_open(shop, capsys, tmp_path / "formulas-scope", "--scope", "formulas")
    document = c.last_json(rest.out)
    assert rest.code == 0, rest.err
    assert (document["source"], document["scope"], document["nodes"]) == ("open", "formulas", 1)
    got = read_shards(document)
    assert [n for v in got.values() for n in v] == [(f, (-1,))]  # exactly the sibling, not expanded


def test_a_pilot_and_the_rest_of_its_formula_prove_it_together(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    shop, *_ = pilot_world(tmp_path, capsys)
    rest = from_open(shop, capsys, tmp_path / "rest", "--scope", "formulas")
    shard_file = c.last_json(rest.out)["shards"][0]["path"]
    second = c.cli_main(
        shop.run_args(
            "--shard", shard_file, "--jobs", "2", worker="w2", results=tmp_path / "results-2"
        ),
        capsys,
    )
    assert second.code == 0, second.err
    both = c.cli_main(
        ["certify", "--campaign", str(shop.campaign), "--journals", str(shop.journal),
         str(tmp_path / "results-2" / "journal.jsonl")], capsys,
    )  # fmt: skip
    assert both.code == 0 and both.out.startswith("PROVED")


def test_a_certificate_the_journals_do_not_produce_is_never_used(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    shop, *_ = pilot_world(tmp_path, capsys)
    certificate = tmp_path / "certificate.json"
    document = json.loads(certificate.read_bytes())
    forged = {
        **document,
        "open": [{**document["formula_open"][0]}] if document["formula_open"] else [],
    }
    for name, value in {
        "open entry": forged,
        "verdict": {**document, "verdict": "PROVED"},
    }.items():
        bad = write(tmp_path / f"{name.split()[0]}.json", value)
        done = plan(
            shop, capsys, tmp_path / f"out-{name.split()[0]}", "--machines", "2",
            "--from-open", str(bad), "--journals", str(shop.journal),
        )  # fmt: skip
        assert done.code == 3 and "[shard.certificate]" in done.err, (name, done.err)
        assert not (tmp_path / f"out-{name.split()[0]}").exists()
    missing = plan(
        shop, capsys, tmp_path / "out-missing", "--machines", "2",
        "--from-open", str(tmp_path / "gone.json"), "--journals", str(shop.journal),
    )  # fmt: skip
    assert missing.code == 3 and "[input.file]" in missing.err


def test_a_model_in_the_certificate_blocks_a_plan(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    shop = c.made(tmp_path, {"f": c.t.sat(5)}, solver={})
    assert c.cli_main(shop.run_args(), capsys).code == 2
    certificate = tmp_path / "certificate.json"
    assert (
        c.cli_main(
            [
                "certify",
                "--campaign",
                str(shop.campaign),
                "--journals",
                str(shop.journal),
                "-o",
                str(certificate),
            ],
            capsys,
        ).code
        == 2
    )
    done = from_open(shop, capsys, tmp_path / "out")
    assert done.code == 3 and "[shard.model]" in done.err
    assert not (tmp_path / "out").exists()


def test_stopped_nodes_are_planned_like_the_others_and_counted(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    shop = c.made(tmp_path, {"f": c.SHALLOW}, solver={"crash_if_free_le": 99})
    assert (
        c.cli_main(shop.run_args(), capsys).code == 5
    )  # the solver dies: the node is tool-blocked
    certificate = tmp_path / "certificate.json"
    assert (
        c.cli_main(
            [
                "certify",
                "--campaign",
                str(shop.campaign),
                "--journals",
                str(shop.journal),
                "-o",
                str(certificate),
            ],
            capsys,
        ).code
        == 1
    )
    done = from_open(shop, capsys, tmp_path / "out")
    document = c.last_json(done.out)
    assert done.code == 0 and document["nodes"] == 1
    assert document["stopped"] == {"tool_blocked": 1}
    assert_disjoint(read_shards(document))
    # a worker that runs the planned node from a fresh results directory tries it again, with no
    # reopen flag: the stop belongs to the first worker's journal, not to the node
    c.t.configure(shop.tools.solver, max_free=3)
    second = c.cli_main(
        shop.run_args(
            "--shard",
            document["shards"][0]["path"],
            worker="w2",
            results=tmp_path / "results-2",
        ),
        capsys,
    )
    assert second.code == 0, second.err
    both = c.cli_main(
        [
            "certify",
            "--campaign",
            str(shop.campaign),
            "--journals",
            str(shop.journal),
            str(tmp_path / "results-2" / "journal.jsonl"),
        ],
        capsys,
    )
    assert both.code == 0 and both.out.startswith("PROVED")
