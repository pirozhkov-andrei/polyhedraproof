"""Byte and hash vectors of specification §3, §4.1, §4.3, §4.8, §4.10, §10.5 and §11.1.

Each expectation here is built from literal preimage bytes written by hand from the text,
not from the generator's code: SHA-256 of a hand-written byte string is the only shared
primitive. The corpus vector files must agree with these and with the reference reader.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

import pytest
from contract_reader import (
    CORPUS,
    cube_cnf,
    cube_problem,
    decode_assignment,
    j_bytes,
    load_json_file,
    merkle_root,
    node_id,
    parse_dimacs,
    split_children,
    split_id,
    split_problem,
)

F_SAT = b"p cnf 1 1\n1 0\n"
F_UNSAT = b"p cnf 1 2\n1 0\n-1 0\n"
F_EMPTY = b"p cnf 0 0\n"
F_CLAUSE = b"p cnf 0 1\n 0\n"
ALL3 = (
    b"p cnf 3 8\n1 2 3 0\n-1 2 3 0\n1 -2 3 0\n-1 -2 3 0\n"
    b"1 2 -3 0\n-1 2 -3 0\n1 -2 -3 0\n-1 -2 -3 0\n"
)
SAT3 = b"p cnf 3 3\n1 2 0\n-1 3 0\n-2 -3 0\n"
FORMULAS = {
    "F_sat": F_SAT,
    "F_unsat": F_UNSAT,
    "F_empty": F_EMPTY,
    "F_clause": F_CLAUSE,
    "all3": ALL3,
    "sat3": SAT3,
}


def h(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def vectors(name: str) -> Any:
    data = load_json_file(CORPUS / "vectors" / f"{name}.json")
    assert data["format"] == f"cubeproof-vectors-{name}-1"
    return data


def test_normative_example_strings_of_a_4_10() -> None:
    cnf = vectors("cnf")
    by_name = {f["name"]: f for f in cnf["formulas"]}
    assert set(by_name) == set(FORMULAS)
    for name, data in FORMULAS.items():
        entry = by_name[name]
        assert entry["text"].encode() == data
        assert entry["sha256"] == h(data)
        assert (entry["variables"], entry["clauses"]) == (
            int(data.split(b"\n")[0].split()[2]),
            int(data.split(b"\n")[0].split()[3]),
        )


def test_cnf_of_f_sat_and_minus_one_is_f_unsat() -> None:
    """Specification §4.10: CNF(F_sat, [-1]) = "p cnf 1 2\\n1 0\\n-1 0\\n"."""
    assert cube_cnf(parse_dimacs(F_SAT), [-1]) == F_UNSAT
    entry = next(
        n for n in vectors("cnf")["nodes"] if n["formula"] == "F_sat" and n["cube"] == [-1]
    )
    assert entry["cnf_text"].encode() == F_UNSAT
    assert entry["cnf_sha256"] == h(F_UNSAT)


def test_node_ids_from_hand_written_preimages() -> None:
    sat = h(F_SAT)
    hand = {
        ("F_sat", ()): h(b"node\x00" + sat.encode() + b"\x00"),
        ("F_sat", (-1,)): h(b"node\x00" + sat.encode() + b"\x00-1"),
        ("F_sat", (1,)): h(b"node\x00" + sat.encode() + b"\x001"),
        ("all3", (-1, 2, -3)): h(b"node\x00" + h(ALL3).encode() + b"\x00-1 2 -3"),
        ("F_empty", ()): h(b"node\x00" + h(F_EMPTY).encode() + b"\x00"),
    }
    corpus = {(n["formula"], tuple(n["cube"])): n for n in vectors("cnf")["nodes"]}
    for key, expected in hand.items():
        assert corpus[key]["node_id"] == expected, key
        assert node_id(h(FORMULAS[key[0]]), key[1]) == expected


def test_cube_cnf_bytes_from_hand_written_strings() -> None:
    hand = {
        ("F_unsat", (1,)): b"p cnf 1 3\n1 0\n-1 0\n1 0\n",
        ("F_clause", ()): b"p cnf 0 1\n 0\n",
        ("F_empty", ()): b"p cnf 0 0\n",
        ("all3", (-1, 2, -3)): b"p cnf 3 11\n" + ALL3.split(b"\n", 1)[1] + b"-1 0\n2 0\n-3 0\n",
        ("sat3", (1,)): b"p cnf 3 4\n1 2 0\n-1 3 0\n-2 -3 0\n1 0\n",
    }
    corpus = {(n["formula"], tuple(n["cube"])): n for n in vectors("cnf")["nodes"]}
    for key, data in hand.items():
        assert corpus[key]["cnf_text"].encode() == data, key
        assert corpus[key]["cnf_sha256"] == h(data), key


def test_every_node_vector_agrees_with_the_reader() -> None:
    cnf = vectors("cnf")
    for entry in cnf["nodes"]:
        formula = parse_dimacs(FORMULAS[entry["formula"]])
        assert entry["node_id"] == node_id(formula.sha256, entry["cube"])
        data = cube_cnf(formula, entry["cube"])
        assert entry["cnf_text"].encode() == data
        assert entry["cnf_sha256"] == h(data)


def test_split_of_f_unsat_on_one_has_children_minus_one_then_one() -> None:
    """Specification §3.2: bit j of child t gives +W[j] if 1, otherwise -W[j]."""
    unsat = h(F_UNSAT)
    root = h(b"node\x00" + unsat.encode() + b"\x00")
    entry = next(
        s
        for s in vectors("cnf")["splits"]
        if s["formula"] == "F_unsat" and s["cube"] == [] and s["variables"] == [1]
    )
    assert entry["node_id"] == root
    assert entry["split_id"] == h(b'{"node_id":"' + root.encode() + b'","variables":[1]}')
    assert [c["cube"] for c in entry["children"]] == [[-1], [1]]
    assert [c["node_id"] for c in entry["children"]] == [
        h(b"node\x00" + unsat.encode() + b"\x00-1"),
        h(b"node\x00" + unsat.encode() + b"\x001"),
    ]


def test_split_children_order_for_two_variables_and_a_parent_cube() -> None:
    entry = next(
        s
        for s in vectors("cnf")["splits"]
        if s["formula"] == "all3" and s["cube"] == [2] and s["variables"] == [3, 1]
    )
    assert [c["cube"] for c in entry["children"]] == [
        [-1, 2, -3],
        [-1, 2, 3],
        [1, 2, -3],
        [1, 2, 3],
    ]
    root = node_id(h(ALL3), [2])
    assert entry["split_id"] == h(b'{"node_id":"' + root.encode() + b'","variables":[3,1]}')


def test_every_split_vector_agrees_with_the_reader() -> None:
    for entry in vectors("cnf")["splits"]:
        sha = h(FORMULAS[entry["formula"]])
        assert entry["node_id"] == node_id(sha, entry["cube"])
        assert entry["split_id"] == split_id(entry["node_id"], entry["variables"])
        children = split_children(entry["cube"], entry["variables"])
        assert [c["cube"] for c in entry["children"]] == [list(c) for c in children]
        assert [c["node_id"] for c in entry["children"]] == [node_id(sha, c) for c in children]


def test_cube_and_split_problem_vectors() -> None:
    cnf = vectors("cnf")
    rules = {e["expect"] for e in cnf["cubes"]}
    assert rules == {None, "cube.canonical", "cube.range"}
    for entry in cnf["cubes"]:
        assert cube_problem(entry["cube"], entry["variables"]) == entry["expect"], entry
    problems = {e["expect"] for e in cnf["split_problems"]}
    assert problems == {
        None,
        "split.empty",
        "split.too_long",
        "split.repeated",
        "split.out_of_range",
        "split.in_cube",
    }
    for entry in cnf["split_problems"]:
        found = split_problem(entry["split"], entry["cube"], entry["variables"])
        assert found == entry["expect"], entry


def test_split_problem_order_is_the_specified_one() -> None:
    assert split_problem([], [1], 3) == "split.empty"
    assert split_problem([9] * 21, [1], 3) == "split.too_long"
    assert split_problem([1, 1, 9], [1], 3) == "split.repeated"
    assert split_problem([1, 9], [1], 3) == "split.out_of_range"
    assert split_problem([1, 2], [-1], 3) == "split.in_cube"
    assert split_problem([2, 3], [-1], 3) is None


def leaf(n: str, c: str, p: str) -> str:
    return h(b"leaf\x00" + n.encode() + b"\x00" + c.encode() + b"\x00" + p.encode())


def branch(a: str, b: str) -> str:
    return h(b"branch\x00" + a.encode() + b"\x00" + b.encode())


def test_merkle_vectors_from_hand_written_preimages() -> None:
    cases = {c["name"]: c for c in vectors("merkle")["cases"]}
    assert set(cases) >= {"empty", "one", "two", "three", "five"}
    assert cases["empty"]["leaves"] == [] and cases["empty"]["root"] is None
    for case in cases.values():
        leaves = [(x["node_id"], x["cnf_sha256"], x["proof_sha256"]) for x in case["leaves"]]
        assert [x[0] for x in leaves] == sorted(x[0] for x in leaves)
        hashes = [leaf(*x) for x in leaves]
        assert case["leaf_hashes"] == hashes
        assert case["root"] == merkle_root(reversed(leaves))
        if case["name"] == "one":
            assert case["root"] == hashes[0]
        if case["name"] == "two":
            assert case["root"] == branch(hashes[0], hashes[1])
        if case["name"] == "three":
            assert case["root"] == branch(branch(hashes[0], hashes[1]), hashes[2])
        if case["name"] == "five":
            left = branch(branch(hashes[0], hashes[1]), branch(hashes[2], hashes[3]))
            assert case["root"] == branch(left, hashes[4])


def test_assignment_bitsets_from_hand_written_cases() -> None:
    hand = {
        (0, ()): "",
        (3, (1, 3)): "BQ==",
        (8, (8,)): "gA==",
        (9, (9,)): "AAE=",
        (1, ()): "AA==",
    }
    cases = vectors("assignment")["cases"]
    corpus = {(c["variables"], tuple(c["true"])): c["assignment"] for c in cases}
    for key, text in hand.items():
        assert corpus[key] == text
    for (variables, true), text in corpus.items():
        values = decode_assignment(text, variables)
        assert values is not None
        assert [i + 1 for i, v in enumerate(values) if v] == list(true)
    for bad in vectors("assignment")["invalid"]:
        assert decode_assignment(bad["assignment"], bad["variables"]) is None, bad
    bad_cases = [(3, "Bw"), (3, "CA=="), (3, "BR=="), (9, "AA=="), (3, "BQ==\n"), (3, "-w==")]
    for variables, text in bad_cases:
        assert decode_assignment(text, variables) is None, text


#: e acute, LINE SEPARATOR, DEL and a slash: none of them is escaped by J (specification §4.1).
RAW = chr(0xE9) + chr(0x2028) + chr(0x7F) + "/"


def test_j_encoding_vectors() -> None:
    hand = [
        ({"b": 1, "a": [True, None, "x"]}, '{"a":[true,null,"x"],"b":1}'),
        ({"e": RAW}, '{"e":"' + RAW + '"}'),
        ({"c": '\x01\n\t"\\'}, '{"c":"\\u0001\\n\\t\\"\\\\"}'),
        ({"z": {"y": [], "x": {}}}, '{"z":{"x":{},"y":[]}}'),
        ([-(2**63 - 1), 2**63 - 1, 0], "[-9223372036854775807,9223372036854775807,0]"),
    ]
    corpus = vectors("json")["encode"]
    for value, text in hand:
        assert j_bytes(value).decode("utf-8") == text
        assert any(e["text"] == text and e["value"] == value for e in corpus), text
    for entry in corpus:
        assert j_bytes(entry["value"]).decode("utf-8") == entry["text"]
        assert entry["sha256"] == h(entry["text"].encode("utf-8"))


DEFAULT_POLICY = {
    "leaf_time_ms": {"12": 900000, "default": 300000},
    "proof_cap_bytes": 4294967296,
    "solver_memory_bytes": 1073741824,
    "checker_max_heap_mib": 8192,
    "checker_stack_mib": 256,
    "checker_max_stack_mib": 2048,
    "checker_slack_mib": 256,
    "checker_time_base_ms": 600000,
    "checker_time_per_100mb_ms": 60000,
    "heap_fit": {
        "coefficient_milli": 3230,
        "exponent_milli": 711,
        "margin_milli": 1500,
        "min_mib": 512,
    },
    "split": {
        "method": "lookahead-v1",
        "vars": 4,
        "pool": None,
        "probe_limit": 100000,
        "wall_ms": 1000,
    },
    "max_cube_size": 60,
    "proof_mode": "transient",
    "stream_heap_mib": 1024,
    "quarantine_quota_bytes": 21474836480,
    "tool_retries": 3,
    "machine_failure_limit": 5,
    "anomaly_limit": 3,
    "term_grace_ms": 10000,
    "stop_grace_ms": 30000,
}


def test_default_policy_and_its_hash() -> None:
    """Specification §4.3 defaults; proof_mode has no default and is fixed to transient here."""
    policy = vectors("policy")
    assert policy["default_transient"] == DEFAULT_POLICY
    assert policy["policy_sha256"] == h(
        json.dumps(DEFAULT_POLICY, sort_keys=True, separators=(",", ":")).encode()
    )


def test_audit_sample_selection_and_targets_hash() -> None:
    """Specification §11.1: N smallest (SHA256(seed NUL node_id), node_id), then ordered by
    node_id."""
    selection = vectors("selection")
    sample = selection["audit_sample"]
    seed = sample["seed"]
    ranked = sorted((h(seed.encode() + b"\x00" + n.encode()), n) for n in sample["population"])
    chosen = sorted(n for _, n in ranked[: sample["n"]])
    assert sample["selected"] == chosen
    assert 0 < sample["n"] < len(sample["population"])
    targets = selection["targets"]
    joined = b"".join(j_bytes(t) + b"\n" for t in targets["targets"])
    assert targets["targets_sha256"] == h(joined)
    assert targets["targets"], "at least one target"


def test_self_chained_journal_vector() -> None:
    """Specification §7.1: self = SHA256(J(record without self)); prev chains; seq contiguous."""
    journal = vectors("journal")
    data = (CORPUS / journal["file"]).read_bytes()
    lines = data.split(b"\n")
    assert lines[-1] == b""
    previous = "0" * 64
    for seq, (line, expected) in enumerate(zip(lines[:-1], journal["records"], strict=True)):
        record = json.loads(line)
        unsigned = {k: v for k, v in record.items() if k != "self"}
        text = json.dumps(unsigned, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        assert expected["unsigned_text"] == text
        assert record["self"] == expected["self"] == h(text.encode("utf-8"))
        assert record["prev"] == expected["prev"] == previous
        assert record["seq"] == seq
        previous = record["self"]
    assert journal["id"] == journal["records"][0]["self"]
    assert journal["head"] == previous


@pytest.mark.parametrize("name", ["cnf", "merkle", "assignment", "json", "policy", "selection"])
def test_vector_files_are_pretty_utf8_json(name: str) -> None:
    text = (CORPUS / "vectors" / f"{name}.json").read_text(encoding="utf-8")
    assert text.endswith("\n")
    assert json.loads(text)["format"] == f"cubeproof-vectors-{name}-1"
