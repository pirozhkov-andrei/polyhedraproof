"""The complete Policy object (specification §4.3) against the corpus vectors and fixtures."""

from __future__ import annotations

import dataclasses
import hashlib
from typing import Any

import cp_corpus
import pytest

from cubeproof.base.canonical_json import encode, parse_document
from cubeproof.base.errors import ContractError
from cubeproof.contracts.enums import ProofMode
from cubeproof.contracts.policy import Policy, default_policy

VECTORS = cp_corpus.vectors("policy")


def test_default_policy_matches_the_vectors() -> None:
    policy = default_policy(ProofMode.TRANSIENT)
    assert policy.to_json() == VECTORS["default_transient"]
    assert policy.sha256 == VECTORS["policy_sha256"]
    for mode, digest in VECTORS["variants"].items():
        assert default_policy(ProofMode(mode)).sha256 == digest
        assert default_policy(mode).sha256 == digest
    assert policy.sha256 == hashlib.sha256(encode(VECTORS["default_transient"])).hexdigest()


def test_default_policy_requires_a_mode() -> None:
    with pytest.raises(ContractError):
        default_policy("fast")


@pytest.mark.parametrize("entry", cp_corpus.documents("policy"), ids=lambda e: e["id"])
def test_policy_fixtures(entry: dict[str, Any]) -> None:
    data = cp_corpus.fixture_bytes(entry)
    value = parse_document(data)
    kind, expected = cp_corpus.expectation(entry)
    if kind == "valid":
        policy = Policy.from_json(value)
        assert policy.to_json() == value
        assert encode(policy.to_json()) + b"\n" == data
        assert policy.sha256 == hashlib.sha256(data[:-1]).hexdigest()
        return
    with pytest.raises(ContractError) as info:
        Policy.from_json(value)
    assert info.value.rule == ("schema" if kind == "schema" else expected)
    if kind == "schema":
        assert info.value.location == expected


def test_leaf_time_lookup_is_exact_depth_then_default() -> None:
    value = dict(VECTORS["default_transient"])
    value["leaf_time_ms"] = {"0": 5, "12": 900000, "default": 300000}
    policy = Policy.from_json(value)
    assert policy.leaf_time_ms_for_depth(12) == 900000
    assert policy.leaf_time_ms_for_depth(0) == 5
    assert policy.leaf_time_ms_for_depth(11) == 300000
    assert policy.leaf_time_ms_for_depth(120) == 300000
    with pytest.raises(ValueError):
        policy.leaf_time_ms_for_depth(-1)


def test_policy_is_immutable_and_hashable() -> None:
    policy = default_policy("retain")
    with pytest.raises(dataclasses.FrozenInstanceError):
        policy.tool_retries = 9  # type: ignore[misc]
    assert hash(policy) == hash(default_policy("retain"))
    assert policy == default_policy("retain")
    assert policy != default_policy("stream")
    assert policy.proof_mode is ProofMode.RETAIN
    assert policy.split.method == "lookahead-v1"
    assert policy.heap_fit.coefficient_milli == 3230


def test_with_proof_mode_returns_a_new_validated_policy() -> None:
    policy = default_policy("transient")
    stream = policy.with_proof_mode(ProofMode.STREAM)
    assert stream.sha256 == VECTORS["variants"]["stream"]
    assert policy.sha256 == VECTORS["variants"]["transient"]


def test_cross_field_rules_are_inclusive_at_the_boundary() -> None:
    value = dict(VECTORS["default_transient"])
    value["checker_max_stack_mib"] = value["checker_stack_mib"]
    value["stream_heap_mib"] = value["checker_max_heap_mib"]
    policy = Policy.from_json(value)
    assert policy.checker_max_stack_mib == policy.checker_stack_mib
    value["checker_max_stack_mib"] = value["checker_stack_mib"] - 1
    with pytest.raises(ContractError) as stack:
        Policy.from_json(value)
    assert stack.value.rule == "policy.stack"
    value["checker_max_stack_mib"] = value["checker_stack_mib"]
    value["stream_heap_mib"] = value["checker_max_heap_mib"] + 1
    with pytest.raises(ContractError) as heap:
        Policy.from_json(value)
    assert heap.value.rule == "policy.stream_heap"


def test_semantic_rules_come_after_the_schema() -> None:
    value = dict(VECTORS["default_transient"])
    value["checker_max_stack_mib"] = 100  # violates policy.stack
    value["stream_heap_mib"] = 9000  # violates policy.stream_heap
    with pytest.raises(ContractError) as info:
        Policy.from_json(value)
    assert info.value.rule == "policy.stack"
    value["checker_max_stack_mib"] = 2048
    with pytest.raises(ContractError) as heap:
        Policy.from_json(value)
    assert heap.value.rule == "policy.stream_heap"
    value["tool_retries"] = True
    with pytest.raises(ContractError) as schema:
        Policy.from_json(value)
    assert schema.value.rule == "schema"
    assert schema.value.location == "$.tool_retries"
