"""Differential test: the hand-written validators agree with the JSON Schemas.

Every valid corpus fixture is mutated at random (field removed, added, replaced by a value of
another type or range, list emptied or extended). The contract ``SchemaStore`` (an independent
implementation of the frozen schemas) decides whether the mutant is schema-valid. The runtime
validator must then report rule ``schema`` exactly when the schema rejects the mutant, at one
of the locations the schema names; when the schema accepts it, the validator may only report a
semantic rule (or accept).
"""

from __future__ import annotations

import copy
import random
from collections.abc import Callable
from typing import Any

import cp_corpus
import pytest

from cubeproof.base.canonical_json import parse_document
from cubeproof.base.errors import ContractError
from cubeproof.cnf.bundle import BundleManifest
from cubeproof.contracts.campaign import Campaign
from cubeproof.contracts.documents import HandoffRequest, Prefixes, Roots, Shard, Weights
from cubeproof.contracts.policy import Policy
from cubeproof.contracts.primitives import INT_MAX

KINDS: dict[str, tuple[str, Callable[[Any], object]]] = {
    "policy": ("policy.schema.json", Policy.from_json),
    "bundle-manifest": ("bundle-manifest.schema.json", BundleManifest.from_json),
    "shard": ("shard.schema.json", Shard.from_json),
    "handoff-request": ("handoff-request.schema.json", HandoffRequest.from_json),
    "roots": ("roots.schema.json", Roots.from_json),
    "prefixes": ("prefixes.schema.json", Prefixes.from_json),
    "weights": ("weights.schema.json", Weights.from_json),
    "campaign": ("campaign.schema.json", Campaign.from_json),
}

POOL: list[Any] = [
    None,
    True,
    False,
    0,
    1,
    -1,
    2,
    20,
    21,
    511,
    512,
    INT_MAX,
    -INT_MAX,
    "",
    "a",
    "A",
    "a" * 65,
    "0" * 64,
    "0" * 63,
    "0" * 32,
    "default",
    "01",
    "12",
    "lookahead-v1",
    "transient",
    "stream",
    "cadical",
    "cake_lpr",
    "--lrat",
    "names.tsv",
    "tags.tsv",
    "a/../b",
    "a\\b",
    "C:x",
    "2026-10-04T12:00:00.000Z",
    "2026-10-04T12:00:00Z",
    "cubeproof-shard-1",
    [],
    {},
    [1],
    [0],
    [-1, 2],
    ["--lrat"],
    {"a": 1},
    {"name": "x", "info": {}},
    {"formula_sha256": "0" * 64, "cube": []},
]
EXTRA_KEYS = ["extra", "default", "7", "Bad", "0" * 64, "info", "name"]


def _seeds(kind: str) -> list[Any]:
    if kind == "campaign":
        names = ["all3", "mixed", "pilot", "unsat", "zero"]
        return [cp_corpus.load_json(f"campaigns/{n}/campaign.json") for n in names]
    return [
        parse_document(cp_corpus.fixture_bytes(e))
        for e in cp_corpus.documents(kind)
        if e["expect"] == "valid"
    ]


def _paths(value: Any, prefix: tuple[Any, ...] = ()) -> list[tuple[Any, ...]]:
    found = [prefix]
    if isinstance(value, dict):
        for key, item in value.items():
            found += _paths(item, (*prefix, key))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            found += _paths(item, (*prefix, index))
    return found


def _get(value: Any, path: tuple[Any, ...]) -> Any:
    for part in path:
        value = value[part]
    return value


def _mutate(seed: Any, rng: random.Random) -> Any:
    value = copy.deepcopy(seed)
    for _ in range(rng.choice([1, 1, 1, 2])):
        paths = _paths(value)
        path = rng.choice(paths)
        target = _get(value, path)
        op = rng.randrange(6)
        if op == 0 and path:
            parent = _get(value, path[:-1])
            parent[path[-1]] = copy.deepcopy(rng.choice(POOL))
        elif op == 1 and path:
            parent = _get(value, path[:-1])
            del parent[path[-1]]
        elif op == 2 and isinstance(target, dict):
            target[rng.choice(EXTRA_KEYS)] = copy.deepcopy(rng.choice(POOL))
        elif op == 3 and isinstance(target, list):
            if target and rng.random() < 0.5:
                target.append(copy.deepcopy(rng.choice(target)))
            else:
                target.append(copy.deepcopy(rng.choice(POOL)))
        elif op == 4 and isinstance(target, (list, dict)):
            target.clear()
        elif path:
            parent = _get(value, path[:-1])
            if isinstance(target, int) and not isinstance(target, bool):
                parent[path[-1]] = rng.choice([target - 1, target + 1, -target, 0, INT_MAX])
            else:
                parent[path[-1]] = copy.deepcopy(rng.choice(POOL))
    return value


@pytest.fixture(scope="module")
def store() -> Any:
    return cp_corpus.schema_store()


@pytest.mark.parametrize("kind", sorted(KINDS))
def test_valid_seeds_are_valid_for_both(kind: str, store: Any) -> None:
    schema, parse = KINDS[kind]
    for seed in _seeds(kind):
        assert store.errors(seed, schema) == []
        parse(seed)


@pytest.mark.parametrize("kind", sorted(KINDS))
def test_mutants_agree_with_the_schema(kind: str, store: Any) -> None:
    schema, parse = KINDS[kind]
    seeds = _seeds(kind)
    rng = random.Random(f"c10-schema-{kind}")
    rejected = accepted = 0
    for _ in range(600):
        mutant = _mutate(rng.choice(seeds), rng)
        errors = store.errors(mutant, schema)
        try:
            parse(mutant)
            mine: ContractError | None = None
        except ContractError as error:
            mine = error
        if errors:
            rejected += 1
            assert mine is not None, (mutant, errors)
            assert mine.rule == "schema", (mutant, errors, mine)
            assert mine.location in cp_corpus.schema_locations(errors), (mutant, errors, mine)
        else:
            accepted += 1
            assert mine is None or mine.rule != "schema", (mutant, mine)
    assert rejected > 100
    assert accepted > 10
