"""Specification §4.4, §9.2, §12.1: ``campaign create`` with roots, root splits, a validated policy
and tools.

The campaign is validated exactly as every reader validates it before it is published; a published
campaign is never replaced; roots and root splits are explicit inputs with the constraints of
specification §4.4; ``proof-prefix-v1:K`` records the prefix and its provenance as a root split.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import cp_cli_support as c
import pytest
from cp_cli_support import formula_hash, prefixes, write

from cubeproof.base.canonical_json import parse_document
from cubeproof.cnf.campaign import load_campaign
from cubeproof.commands import RootSplitSpec
from cubeproof.contracts.identity import node_id, split_id

TWO = {"a": c.DEEP, "b": c.SHALLOW}


def create(
    shop: c.Shop, names: list[str], *more: str, capsys: pytest.CaptureFixture[str]
) -> c.Done:
    bundles = [shop.root / "bundles" / n for n in names]
    return c.cli_main(shop.create_args(*bundles, more=more), capsys)


def test_the_default_campaign_has_one_empty_root_per_formula(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    shop = c.shop(tmp_path, TWO)
    done = create(shop, ["a", "b"], capsys=capsys)
    assert done.code == 0, done.err
    data = shop.campaign.read_bytes()
    document = parse_document(data)
    campaign_id = hashlib.sha256(data[:-1]).hexdigest()
    assert done.out == f"campaign {campaign_id} written to {shop.campaign}\n"
    assert document["format"] == "cubeproof-campaign-1" and document["root_splits"] == []
    assert document["author"] == "cubeproof"
    assert [f["key"] for f in document["formulas"]] == ["a", "b"]
    assert [r["cube"] for r in document["roots"]] == [[], []]
    assert document["tools"]["solver"]["argv"] == ["--lrat"]
    assert load_campaign(shop.campaign).campaign.campaign_id == campaign_id
    assert shop.campaign.stat().st_mode & 0o222  # a plain published file


def test_a_published_campaign_is_never_replaced(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    shop = c.shop(tmp_path, TWO)
    assert create(shop, ["a"], capsys=capsys).code == 0
    before = shop.campaign.read_bytes()
    done = create(shop, ["a", "b"], capsys=capsys)
    assert done.code == 3 and "[campaign.exists]" in done.err
    assert shop.campaign.read_bytes() == before
    assert not [p for p in tmp_path.iterdir() if p.name.startswith(".")]


def test_pilot_roots_are_an_explicit_input_with_the_constraints_of_specification_4_4(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    shop = c.shop(tmp_path, TWO)
    a, b = formula_hash(shop, "a"), formula_hash(shop, "b")

    made_files: list[Path] = []

    def roots(*nodes: tuple[str, list[int]]) -> Path:
        made_files.append(tmp_path / f"roots-{len(made_files)}.json")
        return write(
            made_files[-1],
            {
                "format": "cubeproof-roots-1",
                "roots": [{"formula_sha256": f, "cube": cube} for f, cube in nodes],
            },
        )

    pilot = roots((a, [1, 2]), (b, []))  # a nonempty root alone proves nothing: certify says so
    assert create(shop, ["a", "b"], "--roots", str(pilot), capsys=capsys).code == 0
    campaign = parse_document(shop.campaign.read_bytes())
    assert {(r["formula_sha256"], tuple(r["cube"])) for r in campaign["roots"]} == {
        (a, (1, 2)),
        (b, ()),
    }
    # every violation is an input error that names its rule, and nothing is published
    cases = {
        "roots.nodes": roots((a, [1]), (a, [1, 2]), (b, [])),  # compatible roots of one formula
        "campaign.roots_per_formula": roots((a, [1, 2])),  # formula b has no root
        "cube.range": roots((a, [99]), (b, [])),
        "schema": write(tmp_path / "r.json", {"format": "cubeproof-roots-1"}),
    }
    for rule, path in cases.items():
        shop.campaign.unlink(missing_ok=True)
        done = create(shop, ["a", "b"], "--roots", str(path), capsys=capsys)
        assert done.code == 3 and f"[{rule}]" in done.err, (rule, done.err)
        assert not shop.campaign.exists()


def test_a_static_root_split_is_recorded_sorted_and_provenance_kept(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    shop = c.shop(tmp_path, TWO)
    a, b = formula_hash(shop, "a"), formula_hash(shop, "b")
    file = write(tmp_path / "prefix.json", prefixes([(a, [], [1, 2, 3]), (b, [], [2, 1])]))
    done = create(shop, ["a", "b"], "--root-split", f"static:{file}", capsys=capsys)
    assert done.code == 0, done.err
    splits = parse_document(shop.campaign.read_bytes())["root_splits"]
    assert [s["variables"] for s in splits] == [
        s["variables"] for s in parse_document(file.read_bytes())["splits"]
    ]
    assert {s["node"]["formula_sha256"] for s in splits} == {a, b}
    assert all(s["splitter"]["name"] == "static" for s in splits)
    ids = [
        split_id(node_id(s["node"]["formula_sha256"], s["node"]["cube"]), s["variables"])
        for s in splits
    ]
    assert ids == sorted(ids)
    # the first shard of a run is those roots expanded through the split (2^3 + 2^2 nodes)
    plan = c.cli_main(
        ["shard", "--campaign", str(shop.campaign), "--machines", "1", "-o", str(tmp_path / "s")],
        capsys,
    )
    assert plan.code == 0 and c.last_json(plan.out)["nodes"] == 12


@pytest.mark.parametrize(
    ("entries", "rule"),
    [
        ([("a", [], [1, 1])], "split.repeated"),
        ([("a", [], [99])], "split.out_of_range"),
        ([("a", [], [])], "split.empty"),
        ([("a", [], list(range(1, 22)))], "split.too_long"),
        ([("a", [2], [2])], "split.in_cube"),
        ([("zz", [], [1])], "campaign.node_formula"),
    ],
)
def test_a_malformed_static_root_split_is_refused_with_its_rule(
    entries: list[tuple[str, list[int], list[int]]],
    rule: str,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    shop = c.shop(tmp_path, {"a": c.t.unsat(30, core=3)})
    a = formula_hash(shop, "a")
    triples = [(a if f == "a" else "1" * 64, cube, w) for f, cube, w in entries]
    document = prefixes(triples)
    file = write(tmp_path / "prefix.json", document)
    done = create(shop, ["a"], "--root-split", f"static:{file}", capsys=capsys)
    assert done.code == 3 and f"[{rule}]" in done.err, done.err
    assert not shop.campaign.exists()


def test_a_split_below_a_requested_root_must_be_on_that_root(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    shop = c.shop(tmp_path, {"a": c.DEEP})
    a = formula_hash(shop, "a")
    roots = write(
        tmp_path / "roots.json",
        {"format": "cubeproof-roots-1", "roots": [{"formula_sha256": a, "cube": [1]}]},
    )
    below = write(tmp_path / "prefix.json", prefixes([(a, [1, 2], [3])]))
    done = create(
        shop, ["a"], "--roots", str(roots), "--root-split", f"static:{below}", capsys=capsys
    )
    assert done.code == 3 and "[campaign.root_split_node]" in done.err
    on_root = write(tmp_path / "prefix2.json", prefixes([(a, [1], [3])]))
    assert (
        create(
            shop, ["a"], "--roots", str(roots), "--root-split", f"static:{on_root}", capsys=capsys
        ).code
        == 0
    )


def test_a_prefixes_file_that_is_not_one_is_an_input_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    shop = c.shop(tmp_path, {"a": c.DEEP})
    missing = create(shop, ["a"], "--root-split", f"static:{tmp_path / 'nope.json'}", capsys=capsys)
    assert missing.code == 3 and "[input.file]" in missing.err
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    assert create(shop, ["a"], "--root-split", f"static:{bad}", capsys=capsys).code == 3


@pytest.mark.parametrize(
    ("text", "kind", "count"),
    [
        ("none", "none", None),
        ("static:x.json", "static", None),
        ("proof-prefix-v1:7", "proof-prefix-v1", 7),
    ],
)
def test_the_root_split_spec_parses(text: str, kind: str, count: int | None) -> None:
    spec = RootSplitSpec.parse(text)
    assert (spec.kind, spec.count) == (kind, count)


@pytest.mark.parametrize(
    "text",
    ["", "None", "static", "static:", "lookahead-v1:3"]
    + [f"proof-prefix-v1{suffix}" for suffix in ("", ":", ":0", ":21", ":-1", ":1.5", ":x")],
)
def test_malformed_root_split_specs_are_usage_errors(text: str) -> None:
    from cubeproof.base.errors import ConfigurationError

    with pytest.raises(ConfigurationError) as info:
        RootSplitSpec.parse(text)
    assert info.value.rule == "campaign.root_split"


def test_proof_prefix_is_computed_with_the_pinned_solver_and_recorded(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The prefix algorithm end to end with the fake solver: the prefix, its parameters and the
    solver hash are the root split; the heuristic scratch files are gone afterwards; the result
    is deterministic (seeded)."""
    results = []
    for index in (1, 2):
        root = tmp_path / f"w{index}"
        shop = c.shop(root, {})
        shop.bundle("a", c.t.unsat(8, core=5), pools={"order": list(range(1, 9))})
        done = create(shop, ["a"], "--root-split", "proof-prefix-v1:2", capsys=capsys)
        assert done.code == 0, done.err
        document = parse_document(shop.campaign.read_bytes())
        (split,) = document["root_splits"]
        assert split["node"]["cube"] == [] and 1 <= len(split["variables"]) <= 2
        assert set(split["variables"]) <= set(range(1, 9))
        info = split["splitter"]["info"]
        assert split["splitter"]["name"] == "proof-prefix-v1"
        assert (info["samples"], info["steps"], info["conflicts"], info["seed"], info["pool"]) == (
            2,
            100000,
            90000,
            5,
            "order",
        )
        assert info["solver"]["sha256"] == document["tools"]["solver"]["sha256"]
        assert info["occurrences"] and len(info["occurrences"]) == len(split["variables"])
        assert not [p for p in root.iterdir() if p.name.startswith(".")]
        results.append(split["variables"])
    assert results[0] == results[1]


def test_proof_prefix_runs_the_algorithm_with_the_documented_defaults_per_formula(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Specification §9.2: samples 2, steps 100000, conflicts 90000, seed 5, pool ``order``; K
    variables from the bundle's pool of every formula; what the algorithm returns is what is
    recorded."""
    from cubeproof.commands import rootsplit
    from cubeproof.split.proof_prefix import ProofPrefix, ProofPrefixParams

    shop = c.shop(tmp_path, {})
    pool = [2, 4, 6, 8]  # a pool that is not every variable
    shop.bundle("a", c.t.unsat(8, core=5), pools={"order": pool})
    shop.bundle("b", c.t.unsat(6, core=4), pools={"order": [1, 3, 5]})
    calls: list[tuple[int, int, tuple[int, ...], ProofPrefixParams]] = []

    def chosen(formula: Any, count: int, given: Any, params: Any, run: Any, work: Path) -> Any:
        calls.append((formula.variables, count, tuple(given), params))
        assert work.is_dir() and callable(run)
        return ProofPrefix((3, 1), (7, 5))

    monkeypatch.setattr(rootsplit, "choose_prefix", chosen)
    done = create(shop, ["a", "b"], "--root-split", "proof-prefix-v1:2", capsys=capsys)
    assert done.code == 0, done.err
    assert sorted((v, k, p) for v, k, p, _ in calls) == [
        (6, 2, (1, 3, 5)),
        (8, 2, tuple(pool)),
    ]
    assert all(params == ProofPrefixParams() for *_, params in calls)
    splits = parse_document(shop.campaign.read_bytes())["root_splits"]
    assert len(splits) == 2 and all(s["variables"] == [3, 1] for s in splits)
    assert all(s["splitter"]["info"]["occurrences"] == [7, 5] for s in splits)


def test_a_failing_partition_solver_publishes_no_campaign_and_leaves_no_scratch(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    shop = c.shop(tmp_path, {}, solver={"crash_if_free_le": 99})
    shop.bundle("a", c.t.unsat(8, core=5), pools={"order": list(range(1, 9))})
    done = create(shop, ["a"], "--root-split", "proof-prefix-v1:2", capsys=capsys)
    assert done.code == 5 and "[split.proof_prefix_solver]" in done.err
    assert not shop.campaign.exists()
    assert not [p for p in tmp_path.iterdir() if p.name.startswith(".")]


def test_proof_prefix_needs_the_order_pool_and_whole_formula_roots(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    shop = c.shop(tmp_path, {"a": c.DEEP})  # no pools
    done = create(shop, ["a"], "--root-split", "proof-prefix-v1:2", capsys=capsys)
    assert done.code == 3 and "[campaign.pool]" in done.err and "order" in done.err
    assert not shop.campaign.exists()
    shop.bundle("p", c.DEEP, pools={"order": list(range(1, 9))})
    a = formula_hash(shop, "p")
    roots = write(
        tmp_path / "roots.json",
        {"format": "cubeproof-roots-1", "roots": [{"formula_sha256": a, "cube": [1]}]},
    )
    done = create(
        shop, ["p"], "--roots", str(roots), "--root-split", "proof-prefix-v1:2", capsys=capsys
    )
    assert done.code == 3 and "[campaign.root_split]" in done.err


def test_the_policy_and_admission_files_are_validated(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    shop = c.shop(tmp_path, {"a": c.DEEP})
    bundle = shop.root / "bundles" / "a"
    base = shop.create_args(bundle)
    policy_path = Path(base[base.index("--policy") + 1])
    policy = json.loads(policy_path.read_bytes())
    admit_path = Path(base[base.index("--admit") + 1])
    admit = json.loads(admit_path.read_bytes())

    def attempt(name: str, document: Any, target: Path) -> c.Done:
        edited = tmp_path / name
        write(edited, document)
        args = [str(edited) if a == str(target) else a for a in base]
        return c.cli_main(args, capsys)

    assert attempt("p1.json", {**policy, "proof_cap_bytes": 0}, policy_path).code == 3
    assert attempt("p2.json", {**policy, "unknown": 1}, policy_path).code == 3
    assert (
        attempt("p3.json", {k: v for k, v in policy.items() if k != "split"}, policy_path).code == 3
    )
    done = attempt("a1.json", {**admit, "checker_sha256": ["0" * 64]}, admit_path)
    assert done.code == 3 and "[campaign.tools_admitted]" in done.err
    done = attempt("a2.json", {**admit, "solvers": []}, admit_path)
    assert done.code == 3
    assert not shop.campaign.exists()
    # the unchanged files are accepted
    assert c.cli_main(base, capsys).code == 0


def test_bundles_must_lie_below_the_campaign_directory_and_be_named_like_formulas(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    shop = c.shop(tmp_path / "shop", {"a": c.DEEP})
    outside = c.t.install(tmp_path / "t2")
    other = c.Shop(tmp_path / "elsewhere", outside)
    other.root.mkdir()
    foreign = other.bundle("x", c.DEEP)
    args = shop.create_args(foreign)
    done = c.cli_main(args, capsys)
    assert done.code == 3 and "[campaign.bundle_path]" in done.err
    odd = shop.bundle("Bad.Name", c.SHALLOW)
    done = c.cli_main(shop.create_args(odd), capsys)
    assert done.code == 3 and "[campaign.key]" in done.err
    missing = c.cli_main(shop.create_args(shop.root / "bundles" / "nope"), capsys)
    assert missing.code == 3 and "bundle.files" in missing.err


def test_tools_are_measured_from_local_paths_and_a_bad_path_is_a_tool_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    shop = c.shop(tmp_path, {"a": c.DEEP})
    args = shop.create_args(shop.root / "bundles" / "a")
    solver_at = args.index("--solver") + 1
    ok = c.cli_main(args, capsys)
    assert ok.code == 0
    document = parse_document(shop.campaign.read_bytes())
    solver_hash = hashlib.sha256(Path(args[solver_at]).read_bytes()).hexdigest()
    assert document["tools"]["solver"]["sha256"] == solver_hash
    shop.campaign.unlink()
    args[solver_at] = str(tmp_path / "no-such-solver")
    done = c.cli_main(args, capsys)
    assert done.code == 5 and "[tool." in done.err
    assert not shop.campaign.exists()
    # a relative tool path is made absolute at the command line
    shop.campaign.unlink(missing_ok=True)
    args[solver_at] = str(Path(shop.tools.solver).relative_to(tmp_path))
    done = c.command(*args, cwd=tmp_path)
    assert done.code == 0, done.err
