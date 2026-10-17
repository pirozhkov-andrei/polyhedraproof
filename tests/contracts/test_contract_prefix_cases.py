"""Prefix-order and cube case bytes of maps 1 and 2 (specification §3.3).

The base formulas are stored compressed. A case CNF with its units in prefix order and the
cube CNF, which sorts them by variable, are two byte strings of one region. Both are rebuilt
here from the base bytes and compared with the frozen hashes; the 59-formula fixture
independently confirms the base hashes.
"""

from __future__ import annotations

import hashlib
import json
import lzma
from typing import Any

from contract_reader import CORPUS, REPO, load_json_file, node_id


def h(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def prefix_cases() -> dict[str, Any]:
    data: dict[str, Any] = load_json_file(CORPUS / "prefix_cases" / "cases.json")
    assert data["format"] == "cubeproof-vectors-prefix-cases-1"
    return data


def test_base_formulas_match_the_59_formula_fixture() -> None:
    fixture = json.loads((REPO / "data" / "fixtures" / "formula_hashes.json").read_text())
    bases = prefix_cases()["bases"]
    assert {b["map"] for b in bases} == {1, 2}
    for base in bases:
        data = lzma.decompress((CORPUS / base["file"]).read_bytes())
        expected = fixture["maps"][str(base["map"])]
        assert h(data) == base["formula_sha256"] == expected["sha256"]
        header = f"p cnf {expected['variables']} {expected['clauses']}\n".encode()
        assert data.startswith(header)
        assert (base["variables"], base["clauses"]) == (expected["variables"], expected["clauses"])


def test_prefix_order_and_cube_case_bytes() -> None:
    data = prefix_cases()
    bases = {b["map"]: b for b in data["bases"]}
    raw = {m: lzma.decompress((CORPUS / b["file"]).read_bytes()) for m, b in bases.items()}
    cases = data["cases"]
    assert len(cases) == 11
    assert {(c["map"], c["index"]) for c in cases} >= {(2, 3077), (1, 0), (2, 4095)}
    for case in cases:
        base = bases[case["map"]]
        body = raw[case["map"]].split(b"\n", 1)[1]
        units = case["prefix_units"]
        assert [abs(u) for u in units] == case["prefix_variables"]
        header = f"p cnf {base['variables']} {base['clauses'] + len(units)}\n".encode()
        prefix_order_bytes = header + body + b"".join(f"{u} 0\n".encode() for u in units)
        assert h(prefix_order_bytes) == case["prefix_order_cnf_sha256"]
        assert len(prefix_order_bytes) == case["prefix_order_cnf_bytes"]
        cube = sorted(units, key=abs)
        assert case["cube"] == cube
        cube_bytes = header + body + b"".join(f"{u} 0\n".encode() for u in cube)
        assert h(cube_bytes) == case["cube_cnf_sha256"]
        assert len(cube_bytes) == case["cube_cnf_bytes"]
        assert case["node_id"] == node_id(base["formula_sha256"], cube)
        assert prefix_order_bytes != cube_bytes
        index = sum(1 << j for j, u in enumerate(units) if u > 0)
        assert index == case["index"]


def test_a_pinned_case_of_map_2() -> None:
    case = next(c for c in prefix_cases()["cases"] if (c["map"], c["index"]) == (2, 3077))
    units = [853, -1354, 992, -1305, -1399, -1260, -1216, -1259, -1533, -1488, 946, 743]
    assert case["prefix_units"] == units
    digest = "c8bdb5e86c946edfd1aa7ed77dc437d53405a65942ca6674118bc820986215f2"
    assert case["prefix_order_cnf_sha256"] == digest
