"""Record codec (evidence.schema): corpus record fixtures, vectors, schema agreement, building.

A journal-record document is one journal line: J(record) + LF. Reading it checks canonical
bytes, the schema of the record's type, ``self`` and the record rules that need no other
record (specification §4.7, §4.8, §7.1). Admission-dependent ``success.*`` rules belong to the
certifier and the binding; the codec accepts such records as structurally valid.
"""

from __future__ import annotations

import copy
import hashlib
import json
import random
from typing import Any

import cp_journal_support as sup
import pytest

from cubeproof.base.errors import ContractError, IntegrityError, ResourceError
from cubeproof.base.settings import ReaderLimits
from cubeproof.contracts.enums import ModelError, Outcome, RecordType
from cubeproof.contracts.primitives import INT_MAX
from cubeproof.contracts.values import Artifact, Node
from cubeproof.evidence.schema import (
    JOURNAL_FORMAT,
    Attempt,
    Header,
    ProcessResult,
    Record,
    Repair,
    Resume,
    build_record,
    check_record_schema,
    parse_record,
    read_record,
    record_problem,
    record_self,
)

RECORD_FIXTURES = sup.documents("journal-record")
_IDS = [e["id"] for e in RECORD_FIXTURES]


def _context_variables(entry: dict[str, Any], data: bytes) -> dict[str, int] | None:
    context = entry.get("context") or {}
    if "variables" not in context:
        return None
    return sup.variables_for(data, context["variables"])


def _fixture(entry_id: str) -> tuple[dict[str, Any], bytes]:
    entry = next(e for e in RECORD_FIXTURES if e["id"] == entry_id)
    return entry, sup.fixture_bytes(entry)


@pytest.mark.parametrize("entry", RECORD_FIXTURES, ids=_IDS)
def test_record_fixtures(entry: dict[str, Any]) -> None:
    data = sup.fixture_bytes(entry)
    variables = _context_variables(entry, data)
    expect = entry["expect"]
    delegated = isinstance(expect, dict) and expect.get("rule") in sup.DELEGATED_RULES
    if expect == "valid" or delegated:
        # success.* needs admission: structurally the record is valid.
        record = read_record(data, variables=variables)
        assert record.to_json() == json.loads(data)
        assert record.line + b"\n" == data
        assert (
            record.self_hash
            == hashlib.sha256(
                sup.j({k: v for k, v in json.loads(data).items() if k != "self"})
            ).hexdigest()
        )
        return
    with pytest.raises(ContractError) as info:
        read_record(data, variables=variables)
    # A standalone record document is a plain rejection, not an input/integrity verdict.
    assert type(info.value) is ContractError
    if "schema" in expect:
        assert info.value.rule == "schema"
        assert info.value.location == expect["schema"]
    else:
        assert info.value.rule == expect["rule"]


def test_every_record_type_has_a_valid_fixture() -> None:
    seen = set()
    for entry in RECORD_FIXTURES:
        if entry["expect"] == "valid":
            data = sup.fixture_bytes(entry)
            seen.add(read_record(data, variables=_context_variables(entry, data)).type)
    assert seen == set(RecordType)


def test_parse_record_takes_the_line_without_its_lf() -> None:
    _, data = _fixture("record-repair")
    assert parse_record(data[:-1]).line == data[:-1]
    with pytest.raises(ContractError) as info:
        parse_record(data)
    assert info.value.rule == "json.canonical"


def test_line_limit_is_a_resource_error() -> None:
    _, data = _fixture("record-repair")
    line = data[:-1]
    assert parse_record(line, limits=ReaderLimits(line_bytes=len(line))).line == line
    with pytest.raises(ResourceError) as info:
        parse_record(line, limits=ReaderLimits(line_bytes=len(line) - 1))
    assert info.value.rule == "limit.line"


def test_validation_order_is_bytes_schema_self_rules() -> None:
    _, data = _fixture("record-node-stop")
    value = json.loads(data)
    # A record rule violation with a broken self: self is reported first (specification §7.1).
    bad_cube = {**value, "node": {**value["node"], "cube": [2, 1]}}
    with pytest.raises(ContractError) as info:
        parse_record(sup.j(bad_cube))
    assert info.value.rule == "journal.self"
    with pytest.raises(ContractError) as info:
        parse_record(sup.j(sup.sign(bad_cube)))
    assert info.value.rule == "cube.canonical"
    # A schema violation with a broken self: schema first.
    with pytest.raises(ContractError) as info:
        parse_record(sup.j({**value, "state": "lost"}))
    assert info.value.rule == "schema"
    # Non-canonical bytes before anything else.
    with pytest.raises(ContractError) as info:
        parse_record(json.dumps(value).encode())
    assert info.value.rule == "json.canonical"


def test_journal_vectors() -> None:
    vectors = sup.load_json("vectors/journal.json")
    assert vectors["format"] == "cubeproof-vectors-journal-1"
    data = sup.corpus_bytes(vectors["file"])
    lines = sup.lines_of(data)
    prev = sup.ZERO
    for entry, line in zip(vectors["records"], lines, strict=True):
        unsigned = entry["unsigned_text"].encode("utf-8")
        assert hashlib.sha256(unsigned).hexdigest() == entry["self"]
        record = parse_record(line)
        assert record.self_hash == entry["self"] == record_self(record.to_json())
        assert record.prev == entry["prev"] == prev
        assert record.seq == entry["seq"]
        prev = record.self_hash
    assert parse_record(lines[0]).self_hash == vectors["id"]
    assert prev == vectors["head"]


def test_record_self_ignores_only_self() -> None:
    _, data = _fixture("record-repair")
    value = json.loads(data)
    assert record_self(value) == value["self"]
    assert record_self({**value, "self": "f" * 64}) == value["self"]
    assert record_self({**value, "removed_bytes": 2}) != value["self"]


# -- schema agreement with the JSON Schemas --------------------------------------------------------

POOL: list[Any] = [
    None,
    True,
    False,
    0,
    1,
    -1,
    10,
    20,
    255,
    256,
    INT_MAX,
    -INT_MAX,
    "",
    "a",
    "A",
    "0" * 64,
    "0" * 63,
    "0" * 32,
    "unit",
    "cdcl",
    "stream",
    "retain",
    "transient",
    "VERIFIED_UNSAT",
    "MODEL",
    "violated",
    "rejected",
    "time",
    "header",
    "attempt",
    "run",
    "audit",
    "stuck",
    "unit-v1",
    "cubeproof-journal-1",
    "cubeproof-shard-1",
    "2026-10-04T12:00:00.000Z",
    "2026-10-04T12:00:00Z",
    "AAA=",
    "AA",
    "a/../b",
    [],
    {},
    [1],
    [0],
    [-1, 2],
    {"a": 1},
    {"formula_sha256": "0" * 64, "cube": []},
    {"journal": "0" * 64, "seq": 0},
    {"path": "p", "sha256": "0" * 64, "bytes": 0},
]
EXTRA_KEYS = ["extra", "self", "type", "seq", "info", "name", "node"]


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
            _get(value, path[:-1])[path[-1]] = copy.deepcopy(rng.choice(POOL))
        elif op == 1 and path:
            del _get(value, path[:-1])[path[-1]]
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
    return sup.schema_store()


def _seeds() -> list[Any]:
    return [json.loads(sup.fixture_bytes(e)) for e in RECORD_FIXTURES if e["expect"] == "valid"]


def test_valid_seeds_are_schema_valid_for_both(store: Any) -> None:
    for seed in _seeds():
        assert sup.record_schema_errors(store, seed) == []
        check_record_schema(seed)


def test_schema_mutants_agree_with_the_shared_schema(store: Any) -> None:
    seeds = _seeds()
    rng = random.Random("c11-record-schema")
    rejected = accepted = 0
    for _ in range(3000):
        mutant = _mutate(rng.choice(seeds), rng)
        errors = sup.record_schema_errors(store, mutant)
        try:
            check_record_schema(mutant)
            mine: ContractError | None = None
        except ContractError as error:
            mine = error
        if errors:
            rejected += 1
            assert mine is not None, (mutant, errors)
            assert mine.rule == "schema", (mutant, errors, mine)
            assert mine.location in sup.schema_locations(errors), (mutant, errors, mine)
        else:
            accepted += 1
            assert mine is None, (mutant, mine)
    assert rejected > 1000
    assert accepted > 100


def test_schema_root_cases() -> None:
    roots: list[Any] = [None, [], "header", 0, {}, {"type": "nothing"}, {"type": 3}]
    for value in roots:
        with pytest.raises(ContractError) as info:
            check_record_schema(value)
        assert (info.value.rule, info.value.location) == ("schema", "$")


# -- context-free record rules -------------------------------------------------------------------


def _attempt_value(entry_id: str = "attempt-exhausted_time") -> dict[str, Any]:
    _, data = _fixture(entry_id)
    value: dict[str, Any] = json.loads(data)
    return value


def test_tail_size_counts_utf8_bytes_of_the_decoded_text() -> None:
    value = _attempt_value("attempt-exhausted_time")
    solver = value["solver"]
    assert solver is not None
    limit = 16 * 1024
    for tail, ok in (
        ("x" * limit, True),
        ("x" * (limit + 1), False),
        ("é" * (limit // 2), True),
        ("é" * (limit // 2) + "x", False),
    ):
        for field in ("stdout_tail", "stderr_tail"):
            changed = {**value, "solver": {**solver, field: tail}}
            problem = record_problem(changed)
            assert (problem is None) == ok, (field, len(tail), problem)
            if not ok:
                assert problem == "process.tail_size"


def test_variables_enable_range_assignment_and_formula_rules() -> None:
    value = _attempt_value("attempt-model_cdcl")
    formula = value["node"]["formula_sha256"]
    assert record_problem(value) is None
    assert record_problem(value, {formula: 3}) is None
    assert record_problem(value, {formula: 9}) == "attempt.assignment"
    assert record_problem(value, {"f" * 64: 3}) == "record.formula"
    deep = {**value, "node": {**value["node"], "cube": [-3]}}
    assert record_problem(deep, {formula: 2}) == "cube.range"


def test_rule_order_within_an_attempt() -> None:
    value = _attempt_value("attempt-exhausted_time")
    # Several violations: the reported one is the first in the specification §4.8 matrix order.
    broken = {
        **value,
        "reason": None,
        "proof_bytes": 5,
        "node_id": "f" * 64,
    }
    assert record_problem(broken) == "record.node_id"
    broken["node_id"] = value["node_id"]
    assert record_problem(broken) == "attempt.reason"
    broken["reason"] = "time"
    assert record_problem(broken) == "attempt.proof_pair"


def test_utc_calendar_comes_before_payload_rules() -> None:
    value = _attempt_value("attempt-exhausted_time")
    broken = {**value, "utc": "2026-02-30T00:00:00.000Z", "reason": None}
    assert record_problem(broken) == "utc.calendar"


# -- building records ------------------------------------------------------------------------------


def _valid_records() -> list[Record]:
    records = []
    for entry in RECORD_FIXTURES:
        if entry["expect"] == "valid":
            data = sup.fixture_bytes(entry)
            records.append(read_record(data, variables=_context_variables(entry, data)))
    return records


def test_building_reproduces_every_valid_fixture() -> None:
    for record in _valid_records():
        built = build_record(record.payload, seq=record.seq, prev=record.prev, utc=record.utc)
        assert built == record
        assert built.line == record.line
        assert built.self_hash == record.self_hash
        assert built.to_json()["format"] == JOURNAL_FORMAT


def test_payload_constructors_validate_like_the_reader() -> None:
    record = read_record(sup.fixture_bytes(_fixture("attempt-exhausted_time")[0]))
    attempt = record.payload
    assert isinstance(attempt, Attempt)
    assert attempt.outcome is Outcome.EXHAUSTED
    fields = {name: getattr(attempt, name) for name in attempt.__dataclass_fields__}
    assert Attempt(**fields) == attempt
    with pytest.raises(ContractError) as info:
        Attempt(**{**fields, "reason": None})
    assert info.value.rule == "attempt.reason"
    with pytest.raises(ContractError) as info:
        Attempt(**{**fields, "reason": "rejected"})
    assert info.value.rule == "attempt.reason"
    with pytest.raises(ContractError) as info:
        Attempt(**{**fields, "proof_bytes": True})
    assert info.value.rule == "schema"
    with pytest.raises(ContractError) as info:
        Attempt(**{**fields, "node_id": "f" * 64})
    assert info.value.rule == "record.node_id"
    with pytest.raises(ContractError) as info:
        Attempt(**{**fields, "model_error": ModelError.SYNTAX})
    assert info.value.rule in {"attempt.model_error"}


# -- attempt.retained: nonnull only for VERIFIED_UNSAT in retain mode (specification §4.8) --------


def _with_retained(value: dict[str, Any], **changes: Any) -> dict[str, Any]:
    """``value`` with ``changes`` and a retained artifact matching its proof."""
    changed = {**value, **changes}
    changed["retained"] = {
        "bytes": changed["proof_bytes"],
        "path": "proofs/x.lrat",
        "sha256": changed["proof_sha256"],
    }
    return changed


_NOT_RETAIN_MODE = [
    "attempt-vu_cdcl",
    "attempt-vu_unit",
    "attempt-vu_cdcl-stream",
    "attempt-vu_unit-stream",
]


@pytest.mark.parametrize("entry_id", _NOT_RETAIN_MODE)
def test_retained_needs_retain_mode(entry_id: str) -> None:
    value = _attempt_value(entry_id)
    assert value["outcome"] == "VERIFIED_UNSAT"
    assert value["proof_mode"] in ("transient", "stream")
    assert value["proof_sha256"] is not None
    assert record_problem(value) is None
    assert record_problem(_with_retained(value)) == "attempt.retained"


@pytest.mark.parametrize("entry_id", ["attempt-vu_cdcl-retain", "attempt-vu_unit-retain"])
def test_a_retain_mode_attempt_moved_to_transient_loses_its_retained(entry_id: str) -> None:
    value = _attempt_value(entry_id)
    assert value["retained"] is not None
    assert record_problem(value) is None
    assert record_problem({**value, "proof_mode": "transient"}) == "attempt.retained"
    if value["route"] == "unit":  # a unit attempt has no relay in any mode
        assert record_problem({**value, "proof_mode": "stream"}) == "attempt.retained"


@pytest.mark.parametrize(
    "entry_id", ["attempt-exhausted_check_memory-retain", "attempt-rejected-retain"]
)
def test_retained_needs_verified_unsat(entry_id: str) -> None:
    value = _attempt_value(entry_id)
    assert value["proof_mode"] == "retain"
    assert value["outcome"] != "VERIFIED_UNSAT"
    assert value["proof_sha256"] is not None
    assert record_problem(value) is None
    assert record_problem(_with_retained(value)) == "attempt.retained"


@pytest.mark.parametrize("entry_id", _NOT_RETAIN_MODE)
def test_attempt_constructor_refuses_retained_outside_retain_mode(entry_id: str) -> None:
    record = read_record(sup.fixture_bytes(_fixture(entry_id)[0]))
    attempt = record.payload
    assert isinstance(attempt, Attempt)
    assert attempt.proof_sha256 is not None and attempt.proof_bytes is not None
    fields = {name: getattr(attempt, name) for name in attempt.__dataclass_fields__}
    artifact = Artifact("proofs/x.lrat", attempt.proof_sha256, attempt.proof_bytes)
    with pytest.raises(ContractError) as info:
        Attempt(**{**fields, "retained": artifact})
    assert info.value.rule == "attempt.retained"
    retain = Attempt(**{**fields, "proof_mode": "retain", "relay": None, "retained": artifact})
    assert retain.retained == artifact


def test_process_result_constructor_rules() -> None:
    base: dict[str, Any] = {
        "started": True,
        "exit": 0,
        "signal": None,
        "elapsed_ms": 1,
        "stdout_tail": "",
        "stderr_tail": "",
        "stdout_bytes": 0,
        "stdout_truncated": False,
        "cause": None,
        "conflicts": None,
    }
    assert ProcessResult(**base).to_json() == base
    with pytest.raises(ContractError) as info:
        ProcessResult(**{**base, "signal": 9})
    assert info.value.rule == "process.exit_signal"
    with pytest.raises(ContractError) as info:
        ProcessResult(**{**base, "started": False})
    assert info.value.rule == "process.not_started"
    with pytest.raises(ContractError) as info:
        ProcessResult(**{**base, "exit": 256})
    assert info.value.rule == "schema"


def test_build_record_checks_the_envelope() -> None:
    payload = Repair(removed_bytes=3, removed_sha256="a" * 64)
    record = build_record(payload, seq=4, prev="b" * 64, utc="2026-10-01T00:00:00.000Z")
    assert record.type is RecordType.REPAIR
    assert record.seq == 4
    assert record_self(record.to_json()) == record.self_hash
    for bad in (
        {"seq": -1, "prev": "b" * 64, "utc": "2026-10-01T00:00:00.000Z"},
        {"seq": True, "prev": "b" * 64, "utc": "2026-10-01T00:00:00.000Z"},
        {"seq": 1, "prev": "B" * 64, "utc": "2026-10-01T00:00:00.000Z"},
        {"seq": 1, "prev": "b" * 64, "utc": "2026-10-01T00:00:00Z"},
    ):
        with pytest.raises(ContractError) as info:
            build_record(payload, **bad)  # type: ignore[arg-type]
        assert info.value.rule == "schema"
    with pytest.raises(ContractError) as info:
        build_record(payload, seq=1, prev="b" * 64, utc="2026-13-01T00:00:00.000Z")
    assert info.value.rule == "utc.calendar"
    with pytest.raises(ContractError) as info:
        Repair(removed_bytes=0, removed_sha256="a" * 64)
    assert info.value.rule == "schema"


def test_header_and_resume_share_the_snapshot_fields() -> None:
    header = read_record(sup.fixture_bytes(_fixture("record-header")[0])).payload
    assert isinstance(header, Header)
    resume = Resume(machinery=header.machinery, policy=header.policy, resources=header.resources)
    assert resume.policy.sha256 == header.policy.sha256
    with pytest.raises(ContractError) as info:
        Header(**{**{n: getattr(header, n) for n in header.__dataclass_fields__}, "worker": "W"})
    assert info.value.rule == "schema"


def test_nodes_in_records_are_values() -> None:
    record = read_record(sup.fixture_bytes(_fixture("attempt-exhausted_time")[0]))
    attempt = record.payload
    assert isinstance(attempt, Attempt)
    assert isinstance(attempt.node, Node)
    assert attempt.node.node_id == attempt.node_id


def test_codec_errors_become_integrity_errors_only_in_a_journal() -> None:
    # The codec itself raises plain ContractError; the journal reader converts (see reader tests).
    _, data = _fixture("record-cube-order")
    with pytest.raises(ContractError) as info:
        read_record(data, variables=sup.variables_for(data, 3))
    assert not isinstance(info.value, IntegrityError)
