"""neighbourly.encoding emits the pinned formulas: bytes, numbering, tags, pools, values.

Specification §3.3: every formula byte is fixed. What the encoder emits is compared with
golden values:

- the goldens of ``tests/cnf/goldens_n12.json``: the layer variants, map-1 tags, pools, the
  base formulas of maps 1, 2, 59 (all 59 in ``tests/corpus12``, slow) and the prefix cases;
- frozen emission digests: for every case below, the SHA-256 of the canonical JSON of
  everything the encoder exposes (``state``; dictionaries in insertion order, tuples as
  lists, sets sorted), and the DIMACS writer on 300 random formulas.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import random
from fractions import Fraction
from functools import cache
from pathlib import Path
from typing import Any

import pytest

from neighbourly import corpus12
from neighbourly.cnf.dimacs import checked_clause_bytes, clause_bytes, formula_digest, header_bytes
from neighbourly.data import read_bytes
from neighbourly.encoding import Encoder, build_encoder
from neighbourly.exact import oracle_from_planes
from neighbourly.maps import CombinatorialMap

TESTS = Path(__file__).resolve().parents[1]
REPO = TESTS.parents[2]
GOLDENS = TESTS / "cnf" / "goldens_n12.json"
#: The prefix cases as the contract corpus generator reads them (the same cases, a second record).
PREFIX_CASES = REPO / "tools" / "spec_vectors" / "inputs" / "prefix-cases-n12.json"
#: The fields of a prefix case that both records hold.
CASE_KEYS = (
    "map",
    "depth",
    "index",
    "formula_sha256",
    "prefix_units",
    "prefix_order_cnf_bytes",
    "prefix_order_cnf_sha256",
)

#: digest(state(encoder)) of the case ``map|layers|gauge``.
EMISSION_GOLDEN = {
    "1|B|2": "84221907e52a8a3fa10b71070ab74d62da5f26124e777ef3d511a621485da2b0",
    "1|I|None": "f50fd289231c94a6a235a56ece6da0b327c8971027c63efa05c190f0950553fb",
    "1|S,H,A,B,I|1": "d9ec7c7f2009ad785fc09c47a04aa1eb91e0d44fbf5a4e90d25538b71caf0627",
    "1|S,H,A|3": "e3d7653bddf3567ecb9840b1dd2a95a29f808243653ffe543ce51af286b2c1ab",
    "1|S|None": "3ac159c6c8eb907b43d258518bc1e11575bfbf8cf6b541e375a0af82aef9f01c",
    "2|B|2": "956905f6c7fe754a06162fa19dbf64be35bde0af266f2bde5fb933e9a88060fa",
    "2|I|None": "c6308f4feab82ad9d8899a50812eb8c6435bcf800fdfef38f04b83827ac4074a",
    "2|S,H,A,B,I|1": "1d7a7fbe35e18b96482483843342351c91ec9b51271a95d3d98600a1bc0159a7",
    "2|S,H,A|3": "e3d7653bddf3567ecb9840b1dd2a95a29f808243653ffe543ce51af286b2c1ab",
    "2|S|None": "3ac159c6c8eb907b43d258518bc1e11575bfbf8cf6b541e375a0af82aef9f01c",
    "59|B|2": "a41f9492b30d24070ec77ad7ad5da47511858a99ad083363cff326828aad8b26",
    "59|I|None": "d802ead02b33ec738cd8b2503c37571c32e1bf243816e0729a5b9dd3a4cfbd7b",
    "59|S,H,A,B,I|1": "bf4cef364f9210b4a90a9755d94cb627b760a95c47ef78ce69570b2964f915c8",
    "59|S,H,A|3": "e3d7653bddf3567ecb9840b1dd2a95a29f808243653ffe543ce51af286b2c1ab",
    "59|S|None": "3ac159c6c8eb907b43d258518bc1e11575bfbf8cf6b541e375a0af82aef9f01c",
    "csaszar|B|2": "0f41d09f479407bee496f5846901ed2f7465fdadf9ad46ab6f7b6dce41a45742",
    "csaszar|I|None": "70874822d52eb16dbeaaf72bf0f4896a3d4c07aa94412653ac5ab4e4157c28bd",
    "csaszar|S,H,A,B,I|1": "e50e45a380f7bfac7d82532bb8b2166f326f6db2bb4762d9aa0326b9fce04dbf",
    "csaszar|S,H,A|3": "9fede7b41af986e6891f9e9d371b2d438fb7bb3d23b0f6da3e7082921377dd56",
    "csaszar|S|None": "9837f9ab6f418562455f4c133e9ccfea64ed29a79d933f6cad31395d05efa7e1",
    "tetrahedron|B|2": "a3fb138f4904056e434f80c89ae2418af1092dca528ae95d998fcbffa14e2d6a",
    "tetrahedron|I|None": "dafd750b7613e2eeeeed97b8f7cad8e31d0cd550e7b0b26a12eda1df681d90f4",
    "tetrahedron|S,H,A,B,I|1": "2c1058acfdd9d52dec7c298038eceffaa9d2d22cf963408b2ba5bdc69d395389",
    "tetrahedron|S,H,A|3": "05a07d95d33af459392cdc433c7ecd05242e4322143aa557166f192ca795bed1",
    "tetrahedron|S|None": "8afc29c5b9312cdc0cf2f0c00f0abb67d25fd85d8363ef009ab629edaf640973",
}
#: digest(state(encoder in ground-truth mode)) on the random planes below.
GROUND_TRUTH_GOLDEN = {
    "1": "383aaa55fb52a9db8f41a84d91789c1a9b2f53abb8240ea27067fe1bb6f16821",
    "59": "d5d2ef1d9aa35e03e6106bd37bccbf2c772922ac84983212f741eff6c87e249c",
    "csaszar": "bb68c3a567d8c0de501bf03f3150e656c0f48a0c0c69b774297027546c912bfe",
}
#: The same on Szilassi's planes with their recorded orientation bits.
SZILASSI_GOLDEN = "7d9ebe286788933abcfa85c55f01b38cb260dc1a0dfcefec8fa1d34a995ff95f"
#: digest of [clause bytes, header bytes, formula digest] of the writer, 300 formulas.
WRITER_GOLDEN = "4aa013e3be74814608ad2331c9757c64e9744333db29f53e965d4ff6cd37dddb"


def J(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canon(value: Any) -> Any:
    """The JSON form the golden values are frozen in: dict order kept, tuples as lists."""
    result: Any
    if value is None or isinstance(value, (bool, int, str)):
        result = value
    elif isinstance(value, Fraction):
        result = ["fraction", value.numerator, value.denominator]
    elif isinstance(value, float):
        result = ["float", repr(value)]
    elif isinstance(value, (bytes, bytearray)):
        result = ["bytes", sha(bytes(value))]
    elif isinstance(value, dict):
        result = ["dict", [[canon(k), canon(v)] for k, v in value.items()]]
    elif isinstance(value, (list, tuple)):
        result = [canon(v) for v in value]
    elif isinstance(value, (set, frozenset)):
        result = ["set", sorted((canon(v) for v in value), key=J)]
    elif dataclasses.is_dataclass(value) and not isinstance(value, type):
        result = canon(dataclasses.astuple(value))
    else:
        raise TypeError(f"no canonical form for {type(value)}")
    return result


def digest(value: Any) -> str:
    return sha(J(canon(value)))


def test_the_canonical_form_keeps_order_and_types_apart() -> None:
    assert digest({1: 2, 3: 4}) != digest({3: 4, 1: 2})
    assert digest([1, 2]) == digest((1, 2)) != digest({1, 2})
    assert digest(True) != digest(1)
    assert digest(Fraction(1, 2)) != digest(0.5)
    assert digest({2, 1}) == digest({1, 2})
    with pytest.raises(TypeError):
        canon(object())


@cache
def goldens() -> dict[str, Any]:
    data: dict[str, Any] = json.loads(GOLDENS.read_text(encoding="utf-8"))
    assert data["format"] == "neighbourly-goldens-n12-1"
    return data


def test_the_goldens_agree_with_the_inputs_of_the_contract_corpus() -> None:
    """Two records of the same prefix cases and base formulas: this package's goldens and
    the input of ``tools/spec_vectors`` (from which the contract corpus is generated)."""
    data = json.loads(PREFIX_CASES.read_text(encoding="utf-8"))
    assert data["format"] == "prefix-cases-n12-1"
    own = goldens()
    for map_id, facts in data["base_formulas"]["maps"].items():
        assert own["base_formulas"]["maps"][map_id] == facts
    assert (data["base_formulas"]["layers"], data["base_formulas"]["gauge_face"]) == (
        own["base_formulas"]["layers"],
        own["base_formulas"]["gauge_face"],
    )
    cases = [{k: c[k] for k in CASE_KEYS if k != "formula_sha256"} for c in data["cases"]]
    assert cases == [
        {k: c[k] for k in CASE_KEYS if k != "formula_sha256"} for c in own["prefix_cases"]
    ]
    for case, mine in zip(data["cases"], own["prefix_cases"]):
        assert mine["formula_sha256"] == own["base_formulas"]["maps"][str(case["map"])]["sha256"]
        tail = "".join(f"{u} 0\n" for u in case["prefix_units"])
        assert mine["prefix_unit_tail"] == tail
        assert case["cube"] == sorted(case["prefix_units"], key=abs)


def small_map(name: str) -> CombinatorialMap:
    path = {"tetrahedron": "tetrahedron/tetrahedron.txt", "csaszar": "szilassi/csaszar_n7.txt"}
    text = read_bytes("fixtures", *path[name].split("/")).decode("utf-8")
    return CombinatorialMap.from_text(text, name)


def any_map(name: str) -> CombinatorialMap:
    return corpus12.load_map(int(name)) if name.isdigit() else small_map(name)


def state(encoder: Any) -> dict[str, Any]:
    """Everything an encoder exposes."""
    formula = encoder.formula
    return {
        "n": encoder.n,
        "elements": encoder.elements,
        "selection": encoder.selection,
        "variables": formula.variables,
        "clauses": list(formula.clauses),
        "tags": list(formula.tags),
        "values": dict(formula.values),
        "counts": {k: (v.variables, v.clauses, v.items) for k, v in formula.counts.items()},
        "count_order": list(formula.counts),
        "violations": {k: list(v) for k, v in formula.violations.items()},
        "layer": formula.layer,
        "brackets": dict(encoder.brackets),
        "line_orders": {k: dict(v) for k, v in encoder.line_orders.items()},
        "cut_orders": {k: dict(v) for k, v in encoder.cut_orders.items()},
        "boundary_bits": dict(encoder.boundary_bits),
        "corner_bits": dict(encoder.corner_bits),
        "face_orientation_bits": dict(encoder.face_orientation_bits),
        "pools": {name: sorted(encoder.pool(name)) for name in ("order", "brackets")},
    }


CASES = [
    (name, layers, gauge)
    for name in ("tetrahedron", "csaszar", "1", "2", "59")
    for layers, gauge in (("S,H,A,B,I", 1), ("S", None), ("S,H,A", 3), ("B", 2), ("I", None))
]


def test_every_case_has_a_frozen_emission() -> None:
    assert sorted(EMISSION_GOLDEN) == sorted(f"{n}|{layers}|{g}" for n, layers, g in CASES)


@pytest.mark.parametrize(("name", "layers", "gauge"), CASES)
def test_the_emission_is_the_frozen_emission(name: str, layers: str, gauge: int | None) -> None:
    new = Encoder(any_map(name)).build(layers, gauge)
    assert digest(state(new)) == EMISSION_GOLDEN[f"{name}|{layers}|{gauge}"]


def random_oracle(seed: int, cmap: CombinatorialMap) -> Any:
    """Random rational planes in general position with s_f = 0."""
    generator = random.Random(seed)
    while True:
        planes = [[Fraction(generator.randint(-40, 40)) for _ in range(4)] for _ in range(cmap.n)]
        oracle = oracle_from_planes(planes)
        if oracle.in_general_position:
            return oracle.with_orientations(dict.fromkeys(cmap.faces, 0))


@pytest.mark.parametrize("name", ["1", "59", "csaszar"])
def test_ground_truth_mode_gives_the_frozen_values_and_violations(name: str) -> None:
    """Random planes satisfy S, H, A but not B, I: the violation lists are compared too."""
    cmap = any_map(name)
    new = Encoder(cmap, oracle=random_oracle(20261006, cmap)).build("S,H,A,B,I", None)
    found = state(new)
    assert digest(found) == GROUND_TRUTH_GOLDEN[name]
    assert len(found["values"]) == found["variables"]
    assert found["violations"] and set(found["violations"]) <= {"B", "I"}


def test_ground_truth_on_the_szilassi_planes_gives_the_frozen_values_and_no_violation() -> None:
    cmap = small_map("csaszar")
    document = json.loads(read_bytes("fixtures", "szilassi", "szilassi.json"))
    planes = [[Fraction(x) for x in p] for p in document["planes"]]
    orientation = {int(k): v for k, v in document["verification"]["orientation"].items()}
    oracle = oracle_from_planes(planes).with_orientations(orientation)
    new = Encoder(cmap, oracle=oracle).build("S,H,A,B,I", None)  # planes not moved into gauge
    assert digest(state(new)) == SZILASSI_GOLDEN
    assert not new.formula.violations


def test_the_writer_gives_the_frozen_writer_bytes() -> None:
    """Clause bytes, header bytes and formula digest, by their frozen digest."""
    rng = random.Random(20261006)
    found = []
    for _ in range(300):
        variables = rng.randint(0, 40)
        clauses = [
            tuple(rng.choice([1, -1]) * rng.randint(1, variables) for _ in range(rng.randint(0, 6)))
            if variables
            else ()
            for _ in range(rng.randint(0, 12))
        ]
        count = len(clauses)
        body = clause_bytes(clauses)
        assert body == checked_clause_bytes(variables, clauses)
        found.append([body, header_bytes(variables, count), formula_digest(variables, body, count)])
    assert digest(found) == WRITER_GOLDEN
    assert clause_bytes([()]) == b" 0\n"


# -- goldens of goldens_n12.json ------------------------------------------------------------------


VARIANTS = [(m, layers) for m in ("1", "2", "59") for layers in ("S", "S,H,A", "S,H,A,B,I")]


@pytest.mark.parametrize(("map_id", "layers"), VARIANTS)
def test_the_layer_variant_goldens(map_id: str, layers: str) -> None:
    expected = goldens()["layer_variants"][map_id][layers]
    encoder = build_encoder(corpus12.load_map(int(map_id)), layers, 1)
    assert encoder.selection == expected["selection"]
    assert (encoder.variables, len(encoder.clauses)) == (expected["variables"], expected["clauses"])
    body = clause_bytes(encoder.clauses)
    assert formula_digest(encoder.variables, body, len(encoder.clauses)) == expected["sha256"]
    counts = {
        name: {"clauses": c.clauses, "variables": c.variables, "items": c.items}
        for name, c in encoder.formula.counts_table()
    }
    assert counts == expected["layer_counts"]
    assert [name for name, _ in encoder.formula.counts_table()] == expected["layer_order"]


@pytest.mark.parametrize("map_id", [1, 2, 59])
def test_the_base_formula_goldens(map_id: int) -> None:
    expected = goldens()["base_formulas"]["maps"][str(map_id)]
    encoder = corpus12.base_encoder(map_id)
    body = clause_bytes(encoder.clauses)
    assert len(body) == expected["body_bytes"]
    found = corpus12.base_formula(map_id)
    assert (found.variables, found.clauses, found.sha256) == (
        expected["variables"],
        expected["clauses"],
        expected["sha256"],
    )
    assert found == corpus12.formula_hashes()[map_id]


def test_the_map_1_tag_goldens() -> None:
    expected = goldens()["map1_tags"]
    encoder = corpus12.base_encoder(1)
    tags = [[layer, tag] for layer, tag in encoder.formula.tags]
    assert encoder.selection == expected["selection"]
    assert len(tags) == expected["clauses"]
    assert len({tuple(t) for t in tags}) == expected["distinct_tags"]
    assert sha(J(tags)) == expected["tags_sha256"]
    for layer, facts in expected["per_layer"].items():
        subset = [t for t in tags if t[0] == layer]
        assert sha(J(subset)) == facts["sha256"], layer
        assert (subset[0][1], subset[-1][1], len(subset)) == (
            facts["first"],
            facts["last"],
            facts["clauses"],
        )


@pytest.mark.parametrize("position", range(11))
def test_the_prefix_case_goldens(position: int) -> None:
    """The prefix case files: the base emission with the units in prefix order."""
    case = goldens()["prefix_cases"][position]
    encoder = corpus12.base_encoder(case["map"])
    body = clause_bytes(encoder.clauses)
    variables, count = encoder.variables, len(encoder.clauses)
    assert formula_digest(variables, body, count) == case["formula_sha256"]
    units = case["prefix_units"]
    assert len(units) == case["depth"]
    tail = b"".join(f"{u} 0\n".encode("ascii") for u in units)
    data = header_bytes(variables, count + len(units)) + body + tail
    assert len(data) == case["prefix_order_cnf_bytes"]
    assert sha(data) == case["prefix_order_cnf_sha256"]
    assert data.endswith(case["prefix_unit_tail"].encode("ascii"))


@pytest.mark.parametrize("map_id", ["1", "2", "59"])
def test_the_pool_goldens(map_id: str) -> None:
    encoder = corpus12.base_encoder(int(map_id))
    for name, facts in goldens()["pools"][map_id].items():
        values = sorted(encoder.pool(name))
        assert (len(values), values[0], values[-1]) == (facts["count"], facts["min"], facts["max"])
        assert sha(J(values)) == facts["sha256"], name
