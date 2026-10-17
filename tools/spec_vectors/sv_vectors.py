"""Byte/hash vectors (specification §3, §4.1, §4.3, §4.8, §4.10, §7.1, §10.5, §11.1) and
prefix case bytes (specification §3.3).
"""

from __future__ import annotations

import json
import lzma
from pathlib import Path
from typing import Any

from sv_cases import ALL3, F_SAT, FORMULAS, pretty
from sv_records import DEFAULT_POLICY, M_OK, P_RETAIN, P_STREAM, P_TRANSIENT, Journal
from sv_spec import (
    bitset,
    canonical_cube,
    children,
    jbytes,
    jsha,
    merkle,
    merkle_levels,
    node,
    node_id,
    sha,
    split_id,
    w_problem,
)


def vector(name: str, body: dict[str, Any]) -> bytes:
    return pretty({"format": f"cubeproof-vectors-{name}-1"} | body)


def cnf_vectors() -> bytes:
    by_name = {f.name: f for f in FORMULAS}
    nodes = [
        ("F_sat", []),
        ("F_sat", [-1]),
        ("F_sat", [1]),
        ("F_unsat", []),
        ("F_unsat", [1]),
        ("F_unsat", [-1]),
        ("F_empty", []),
        ("F_clause", []),
        ("all3", []),
        ("all3", [1]),
        ("all3", [-1, 2, -3]),
        ("sat3", []),
        ("sat3", [1]),
        ("sat3", [-1, 2]),
    ]
    splits = [
        ("F_unsat", [], [1]),
        ("F_sat", [], [1]),
        ("all3", [], [1]),
        ("all3", [], [2]),
        ("all3", [1], [2, 3]),
        ("all3", [2], [3, 1]),
        ("sat3", [], [1]),
    ]
    cubes = [
        (3, [], None),
        (3, [-1, 2, -3], None),
        (3, [3], None),
        (3, [2, 1], "cube.canonical"),
        (3, [1, 1], "cube.canonical"),
        (3, [1, -1], "cube.canonical"),
        (3, [-2, -1], "cube.canonical"),
        (3, [4], "cube.range"),
        (3, [1, -4], "cube.range"),
        (0, [], None),
        (0, [1], "cube.range"),
    ]
    problems = [
        (3, [1], [], "split.empty"),
        (3, [1], [9] * 21, "split.too_long"),
        (3, [1], list(range(2, 23)), "split.too_long"),
        (3, [1], [2, 2], "split.repeated"),
        (3, [1], [1, 1], "split.repeated"),
        (3, [1], [4], "split.out_of_range"),
        (3, [], [3, 4], "split.out_of_range"),
        (3, [1], [2, 1], "split.in_cube"),
        (3, [-1], [1], "split.in_cube"),
        (3, [-1], [3, 2], None),
        (3, [], [1, 2, 3], None),
        (20, [], list(range(1, 21)), None),
    ]
    return vector(
        "cnf",
        {
            "note": "CNF(F,C) = header(V, M+len(C)) + clause body + one 'l 0' line per cube "
            "literal (SPECIFICATION §3.2).",
            "formulas": [
                {
                    "name": f.name,
                    "text": f.data.decode("ascii"),
                    "sha256": f.sha256,
                    "variables": f.variables,
                    "clauses": len(f.clauses),
                }
                for f in FORMULAS
            ],
            "nodes": [
                {
                    "formula": name,
                    "formula_sha256": by_name[name].sha256,
                    "cube": cube,
                    "node_id": node_id(by_name[name].sha256, cube),
                    "cnf_text": by_name[name].cube_cnf(cube).decode("ascii"),
                    "cnf_sha256": by_name[name].cube_sha256(cube),
                }
                for name, cube in nodes
            ],
            "splits": [
                {
                    "formula": name,
                    "cube": cube,
                    "variables": w,
                    "node_id": node_id(by_name[name].sha256, cube),
                    "split_id": split_id(node_id(by_name[name].sha256, cube), w),
                    "split_id_preimage": jbytes(
                        {"node_id": node_id(by_name[name].sha256, cube), "variables": w}
                    ).decode("ascii"),
                    "children": [
                        {"index": i, "cube": c, "node_id": node_id(by_name[name].sha256, c)}
                        for i, c in enumerate(children(cube, w))
                    ],
                }
                for name, cube, w in splits
            ],
            "cubes": [{"variables": v, "cube": c, "expect": e} for v, c, e in cubes],
            "split_problems": [
                {"variables": v, "cube": c, "split": w, "expect": e} for v, c, w, e in problems
            ],
        },
    )


def check_split_problems() -> None:
    """The generator's own reading must agree with its vector expectations."""
    data = json.loads(cnf_vectors())
    for entry in data["split_problems"]:
        found = w_problem(entry["split"], entry["cube"], entry["variables"])
        expected = entry["expect"]
        if (None if found is None else "split." + found) != expected:
            raise AssertionError(entry)


def merkle_vectors() -> bytes:
    cases = []
    for name, count in (("empty", 0), ("one", 1), ("two", 2), ("three", 3), ("five", 5)):
        leaves = sorted(
            (sha(f"node {name} {i}"), sha(f"cnf {name} {i}"), sha(f"proof {name} {i}"))
            for i in range(count)
        )
        levels = merkle_levels(leaves) if leaves else []
        cases.append(
            {
                "name": name,
                "leaves": [
                    {"node_id": n, "cnf_sha256": c, "proof_sha256": p} for n, c, p in leaves
                ],
                "leaf_hashes": levels[0] if levels else [],
                "levels": levels,
                "root": merkle(leaves),
            }
        )
    return vector(
        "merkle",
        {
            "note": "leaf = SHA256('leaf' NUL node_id NUL cnf_sha256 NUL proof_sha256); branch = "
            "SHA256('branch' NUL left NUL right); an odd last element is carried "
            "(SPECIFICATION §10.5).",
            "cases": cases,
        },
    )


def assignment_vectors() -> bytes:
    cases = [
        (0, []),
        (1, []),
        (1, [1]),
        (3, [1, 3]),
        (3, [2]),
        (3, []),
        (8, [8]),
        (8, list(range(1, 9))),
        (9, [9]),
        (9, [1, 9]),
        (16, []),
        (17, [17]),
    ]
    invalid = [
        (3, "Bw", "missing padding"),
        (3, "CA==", "unused high bit set"),
        (3, "BR==", "nonzero padding bits"),
        (9, "AA==", "one byte for V=9"),
        (0, "AA==", "one byte for V=0"),
        (3, "BQ==\n", "trailing newline"),
        (3, "-w==", "not the standard alphabet"),
        (3, "BQ=", "bad padding"),
        (3, "B Q==", "space"),
        (8, "gA", "missing padding"),
    ]
    return vector(
        "assignment",
        {
            "note": "Padded standard base64 of ceil(V/8) bytes; variable i is bit (i-1)%8 of byte "
            "(i-1)//8, LSB first; unused high bits are zero (SPECIFICATION §4.8).",
            "cases": [{"variables": v, "true": t, "assignment": bitset(v, t)} for v, t in cases],
            "invalid": [{"variables": v, "assignment": a, "why": why} for v, a, why in invalid],
        },
    )


def json_vectors() -> bytes:
    values: list[Any] = [
        {"b": 1, "a": [True, None, "x"]},
        {"e": "\u00e9\u2028\u007f/"},
        {"c": '\x01\n\t"\\'},
        {"z": {"y": [], "x": {}}},
        [-(2**63 - 1), 2**63 - 1, 0],
        {"\u00e9": 1, "e": 2, "E": 3},
        "",
        {},
    ]
    return vector(
        "json",
        {
            "note": "J(x) = UTF-8 of json.dumps(x, sort_keys=True, separators=(',', ':'), "
            "ensure_ascii=False, allow_nan=False) (SPECIFICATION §4.1). Keys sort by code point.",
            "encode": [
                {"value": v, "text": jbytes(v).decode("utf-8"), "sha256": jsha(v)} for v in values
            ],
        },
    )


def policy_vectors() -> bytes:
    return vector(
        "policy",
        {
            "note": "SPECIFICATION §4.3 defaults. proof_mode has no default; default_transient "
            "fixes it to transient. policy_sha256 = SHA256(J(policy)).",
            "default_transient": DEFAULT_POLICY,
            "policy_sha256": jsha(P_TRANSIENT),
            "variants": {
                "transient": jsha(P_TRANSIENT),
                "retain": jsha(P_RETAIN),
                "stream": jsha(P_STREAM),
            },
        },
    )


def selection_vectors(modes_w1: Journal) -> bytes:
    population = sorted(
        node_id(ALL3.sha256, canonical_cube([a, b]))
        for x, y in ((1, 2), (1, 3), (2, 3))
        for a in (x, -x)
        for b in (y, -y)
    )
    seed = sha("specification vectors audit sample seed")
    ranked = sorted((sha(f"{seed}\x00{n}"), n) for n in population)
    count = 5
    targets = []
    for seq in (2, 4):
        record = modes_w1.records[seq]
        targets.append(
            {
                "node": record["node"],
                "node_id": record["node_id"],
                "source": {"journal": modes_w1.id, "seq": seq},
                "cnf_sha256": record["cnf_sha256"],
                "proof_sha256": record["proof_sha256"],
                "route": record["route"],
                "machinery": M_OK,
            }
        )
    targets.sort(key=lambda t: t["node_id"])
    return vector(
        "selection",
        {
            "audit_sample": {
                "note": "--sample N --seed S: the N smallest (SHA256(S NUL node_id), node_id), "
                "then ordered by node_id (SPECIFICATION §11.1).",
                "seed": seed,
                "population": population,
                "n": count,
                "ranked": [{"key": k, "node_id": n} for k, n in ranked],
                "selected": sorted(n for _, n in ranked[:count]),
            },
            "targets": {
                "note": "targets_sha256 = SHA256 of concatenated J(target)+LF in target order; a "
                "target's identity hash is SHA256(J(target)) (SPECIFICATION §11.1).",
                "targets": targets,
                "target_hashes": [jsha(t) for t in targets],
                "targets_sha256": sha(b"".join(jbytes(t) + b"\n" for t in targets)),
            },
        },
    )


def journal_vector(pilot: Journal, path: str) -> bytes:
    records = []
    for record in pilot.records:
        unsigned = {k: v for k, v in record.items() if k != "self"}
        records.append(
            {
                "seq": record["seq"],
                "prev": record["prev"],
                "unsigned_text": jbytes(unsigned).decode("utf-8"),
                "self": record["self"],
            }
        )
    return vector(
        "journal",
        {
            "note": "self = SHA256(J(record without self)); prev = previous self or 64 zeros; "
            "a line is J(record) + LF; journal ID = header self; head = last self "
            "(SPECIFICATION §7.1).",
            "file": path,
            "id": pilot.id,
            "head": pilot.records[-1]["self"],
            "records": records,
        },
    )


def primitive_vectors() -> bytes:
    nonneg_max = 2**63 - 1
    hash0 = "0" * 64
    primitives: dict[str, dict[str, list[Any]]] = {
        "Hash": {
            "valid": [hash0, "f" * 64, sha("x")],
            "invalid": ["F" * 64, "0" * 63, "0" * 65, "g" * 64, "", 0, None],
        },
        "Id128": {
            "valid": ["0" * 32, "abcdef" + "0" * 26],
            "invalid": ["0" * 31, "0" * 33, "A" * 32, 1],
        },
        "Name": {
            "valid": ["a", "0", "w1", "a-b_c", "a" * 64],
            "invalid": ["", "-a", "_a", "A", "a" * 65, "a b", "a.b", "\u00e9", "a\n", 1],
        },
        "RelPath": {
            "valid": ["a", "a/b", "a/b.c", "..a", "a..", ".a", "a/.b", "ab:c", "a b", "\u00e9"],
            "invalid": [
                "",
                ".",
                "..",
                "./a",
                "a/.",
                "a/./b",
                "a/..",
                "../a",
                "a//b",
                "/a",
                "a/",
                "a\\b",
                "\\a",
                "C:a",
                "c:/a",
                "Z:",
                "a\u0000b",
                1,
            ],
        },
        "UTC": {
            "valid": [
                "2026-10-04T12:00:00.000Z",
                "2024-02-29T23:59:59.999Z",
                "2000-02-29T00:00:00.000Z",
                "0000-01-01T00:00:00.000Z",
                "9999-12-31T23:59:59.999Z",
            ],
            "invalid": [
                "2023-02-29T00:00:00.000Z",
                "1900-02-29T00:00:00.000Z",
                "2026-04-31T00:00:00.000Z",
                "2026-00-10T00:00:00.000Z",
                "2026-13-01T00:00:00.000Z",
                "2026-10-00T00:00:00.000Z",
                "2026-10-04T24:00:00.000Z",
                "2026-10-04T23:60:00.000Z",
                "2026-10-04T23:59:60.000Z",
                "2026-10-04T12:00:00Z",
                "2026-10-04T12:00:00.0000Z",
                "2026-10-04T12:00:00.000+00:00",
                "2026-10-04T12:00:00.000z",
                "2026-10-04 12:00:00.000Z",
                "\u0662026-10-04T12:00:00.000Z",
                0,
            ],
        },
        "Int64": {
            "valid": [0, 1, -1, nonneg_max, -nonneg_max],
            "invalid": [nonneg_max + 1, -nonneg_max - 1, True, "1", None],
        },
        "NonNegative": {"valid": [0, 1, nonneg_max], "invalid": [-1, nonneg_max + 1, False]},
        "Positive": {"valid": [1, nonneg_max], "invalid": [0, -1, True]},
        "Literal": {
            "valid": [1, -1, nonneg_max, -nonneg_max],
            "invalid": [0, True, nonneg_max + 1],
        },
        "Cube": {"valid": [[], [1, -2], [2, 1]], "invalid": [[0], [True], "1", None]},
        "Node": {
            "valid": [node(F_SAT, []), node(ALL3, [-1, 2])],
            "invalid": [
                {"formula_sha256": hash0},
                {"formula_sha256": hash0, "cube": [], "x": 1},
                {"formula_sha256": "X", "cube": []},
            ],
        },
        "Ref": {
            "valid": [{"journal": hash0, "seq": 0}],
            "invalid": [
                {"journal": hash0, "seq": -1},
                {"journal": hash0},
                {"journal": hash0, "seq": True},
            ],
        },
        "Artifact": {
            "valid": [{"path": "proofs/a.lrat", "sha256": hash0, "bytes": 0}],
            "invalid": [
                {"path": "../a", "sha256": hash0, "bytes": 0},
                {"path": "a", "sha256": hash0, "bytes": -1},
                {"path": "a", "sha256": hash0},
            ],
        },
    }
    return vector("primitives", {"primitives": primitives})


def prefix_case_vectors(root: Path, expected: dict[str, Any], inputs: dict[int, str]) -> bytes:
    """Prefix-order and canonical cube case bytes of maps 1 and 2, recomputed here and
    compared with the expected values of the input document."""
    fixture_maps = expected["base_formulas"]["maps"]
    bases = []
    raw = {}
    for map_id, path in sorted(inputs.items()):
        data = lzma.decompress((root / path).read_bytes())
        base = fixture_maps[str(map_id)]
        if sha(data) != base["sha256"]:
            raise AssertionError(f"map {map_id}: base hash differs from the expected one")
        header, body = data.split(b"\n", 1)
        variables, clauses = (int(x) for x in header.split()[2:4])
        if (variables, clauses) != (base["variables"], base["clauses"]):
            raise AssertionError(f"map {map_id}: header differs from the expected one")
        raw[map_id] = (variables, clauses, body)
        bases.append(
            {
                "map": map_id,
                "file": path,
                "formula_sha256": base["sha256"],
                "variables": variables,
                "clauses": clauses,
            }
        )
    cases = []
    for case in expected["cases"]:
        variables, clauses, body = raw[case["map"]]
        units = case["prefix_units"]
        header = f"p cnf {variables} {clauses + len(units)}\n".encode()
        prefix_order = header + body + b"".join(f"{u} 0\n".encode() for u in units)
        cube = canonical_cube(units)
        canonical = header + body + b"".join(f"{u} 0\n".encode() for u in cube)
        checks = (
            (sha(prefix_order), case["prefix_order_cnf_sha256"]),
            (len(prefix_order), case["prefix_order_cnf_bytes"]),
            (cube, case["cube"]),
            (sha(canonical), case["cube_cnf_sha256"]),
        )
        for found, wanted in checks:
            if found != wanted:
                raise AssertionError(
                    f"prefix case {case['map']}/{case['index']}: {found} != {wanted}"
                )
        formula_sha = bases[[b["map"] for b in bases].index(case["map"])]["formula_sha256"]
        cases.append(
            {
                "map": case["map"],
                "index": case["index"],
                "depth": case["depth"],
                "prefix_variables": case["prefix_variables"],
                "prefix_units": units,
                "prefix_order_cnf_sha256": sha(prefix_order),
                "prefix_order_cnf_bytes": len(prefix_order),
                "cube": cube,
                "node_id": node_id(formula_sha, cube),
                "cube_cnf_sha256": sha(canonical),
                "cube_cnf_bytes": len(canonical),
            }
        )
    return vector(
        "prefix-cases",
        {
            "note": "A case CNF with the prefix units in prefix order and the cube CNF, which "
            "sorts the units by variable, are different byte strings of the same region, so "
            "their hashes differ while the base formula bytes are the same (SPECIFICATION "
            "§3.3). Index bit j is the sign of the j-th prefix unit.",
            "provenance": {
                "expected": "tools/spec_vectors/inputs/prefix-cases-n12.json",
                "base_formulas": "compressed bytes of the base formulas (layers S,H,A,B,I, "
                "gauge face 1), equal to data/fixtures/formula_hashes.json",
            },
            "bases": bases,
            "cases": cases,
        },
    )
