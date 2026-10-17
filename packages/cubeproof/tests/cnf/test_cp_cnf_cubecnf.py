"""CNF(F, C): exact bytes, streamed writing and the cached-header/body digest (specification
§3.2)."""

from __future__ import annotations

import hashlib
import io
import lzma
import random
import sys
from pathlib import Path
from typing import Any

import pytest

from cubeproof.base.errors import ContractError
from cubeproof.cnf.cube import child_nodes, cube_units, node_of
from cubeproof.cnf.cubecnf import (
    CnfDigest,
    cube_cnf_bytes,
    cube_cnf_header,
    write_cube_cnf,
)
from cubeproof.cnf.dimacs import Formula, parse_dimacs
from cubeproof.contracts.identity import canonical_cube, node_id, split_children

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "contracts"))
import cp_corpus

CNF = cp_corpus.vectors("cnf")
FORMULAS = {f["name"]: parse_dimacs(f["text"].encode("ascii")) for f in CNF["formulas"]}


def _plain_cube_cnf(text: bytes, cube: list[int]) -> bytes:
    """Specification §3.2 written out independently: a new header, one unit line per literal."""
    header, _, body = text.partition(b"\n")
    _, _, v, m = header.split(b" ")
    new_header = b"p cnf %d %d\n" % (int(v), int(m) + len(cube))
    return new_header + body + b"".join(b"%d 0\n" % x for x in cube)


def _random_case(rng: random.Random) -> tuple[bytes, list[list[int]]]:
    variables = rng.choice([0, 1, 2, 5, 9, 10, 11, 99, 100, 101, 1000])
    lines = [f"p cnf {variables} "]
    clauses = []
    for _ in range(rng.randrange(0, 40)):
        if variables == 0 or rng.random() < 0.05:
            clauses.append(" 0\n")
        else:
            width = rng.randrange(1, 5)
            lits = [rng.randint(1, variables) * rng.choice((1, -1)) for _ in range(width)]
            clauses.append(" ".join(map(str, lits)) + " 0\n")
    text = (lines[0] + f"{len(clauses)}\n" + "".join(clauses)).encode("ascii")
    cubes: list[list[int]] = []
    for _ in range(12):
        size = rng.randint(0, min(variables, 15))
        chosen = rng.sample(range(1, variables + 1), size)
        cubes.append(sorted((v if rng.random() < 0.5 else -v for v in chosen), key=abs))
    return text, cubes


class _ShortWriter(io.RawIOBase):
    def __init__(self) -> None:
        self.data = bytearray()

    def writable(self) -> bool:
        return True

    def write(self, b: Any) -> int:
        chunk = bytes(b[:7])
        self.data += chunk
        return len(chunk)


@pytest.mark.parametrize("case", CNF["nodes"], ids=lambda c: f"{c['formula']}{c['cube']}")
def test_node_vectors(case: dict[str, Any]) -> None:
    formula = FORMULAS[case["formula"]]
    expected = case["cnf_text"].encode("ascii")
    assert cube_cnf_bytes(formula, case["cube"]) == expected
    assert CnfDigest(formula).cnf_sha256(case["cube"]) == case["cnf_sha256"]
    sink = io.BytesIO()
    result = write_cube_cnf(formula, case["cube"], sink)
    assert sink.getvalue() == expected
    assert (result.sha256, result.bytes) == (case["cnf_sha256"], len(expected))
    assert node_of(formula, case["cube"]).node_id == case["node_id"]


def test_the_normative_example() -> None:
    formula = parse_dimacs(b"p cnf 1 1\n1 0\n")
    assert cube_cnf_bytes(formula, [-1]) == b"p cnf 1 2\n1 0\n-1 0\n"
    assert cube_cnf_header(1, 1, 1) == b"p cnf 1 2\n"
    assert cube_units([-1, 2]) == b"-1 0\n2 0\n"
    assert cube_units([]) == b""


def test_v0_and_empty_clause_formulas() -> None:
    empty = parse_dimacs(b"p cnf 0 0\n")
    clause = parse_dimacs(b"p cnf 0 1\n 0\n")
    assert cube_cnf_bytes(empty, []) == b"p cnf 0 0\n"
    assert cube_cnf_bytes(clause, []) == b"p cnf 0 1\n 0\n"
    assert CnfDigest(empty).cnf_sha256([]) == hashlib.sha256(b"p cnf 0 0\n").hexdigest()
    with pytest.raises(ContractError) as info:
        CnfDigest(empty).cnf_sha256([1])
    assert info.value.rule == "cube.range"


def test_cubes_are_validated_against_the_formula() -> None:
    formula = FORMULAS["all3"]
    digest = CnfDigest(formula)
    for call in (
        lambda c: cube_cnf_bytes(formula, c),
        digest.cnf_sha256,
        lambda c: write_cube_cnf(formula, c, io.BytesIO()),
        lambda c: node_of(formula, c),
    ):
        with pytest.raises(ContractError) as canonical:
            call([2, 1])
        assert canonical.value.rule == "cube.canonical"
        with pytest.raises(ContractError) as rng_error:
            call([4])
        assert rng_error.value.rule == "cube.range"


def test_random_digests_equal_the_plain_construction() -> None:
    rng = random.Random(1070)
    for _ in range(300):
        text, cubes = _random_case(rng)
        formula = parse_dimacs(text)
        digest = CnfDigest(formula)
        # Repeated depths, interleaved: the cached state must be copied, never consumed.
        for cube in cubes + cubes[::-1]:
            plain = _plain_cube_cnf(text, cube)
            assert digest.cnf_sha256(cube) == hashlib.sha256(plain).hexdigest()
            assert cube_cnf_bytes(formula, cube) == plain
            sink = io.BytesIO()
            result = write_cube_cnf(formula, cube, sink, chunk_size=rng.choice([1, 3, 64]))
            assert sink.getvalue() == plain
            assert (result.sha256, result.bytes) == (hashlib.sha256(plain).hexdigest(), len(plain))


def test_digest_cache_depends_on_the_depth_header() -> None:
    formula = FORMULAS["all3"]
    digest = CnfDigest(formula)
    shallow = digest.cnf_sha256([1])
    deep = digest.cnf_sha256([1, 2])
    again = digest.cnf_sha256([2])
    text = CNF["formulas"][4]["text"].encode("ascii")
    assert shallow == hashlib.sha256(_plain_cube_cnf(text, [1])).hexdigest()
    assert deep == hashlib.sha256(_plain_cube_cnf(text, [1, 2])).hexdigest()
    assert again == hashlib.sha256(_plain_cube_cnf(text, [2])).hexdigest()
    assert len({shallow, deep, again}) == 3


def test_same_body_different_header_gives_different_digests() -> None:
    a = parse_dimacs(b"p cnf 2 1\n1 0\n")
    b = parse_dimacs(b"p cnf 3 1\n1 0\n")
    assert CnfDigest(a).cnf_sha256([2]) != CnfDigest(b).cnf_sha256([2])
    assert CnfDigest(a).cnf_sha256([2]) == hashlib.sha256(b"p cnf 2 2\n1 0\n2 0\n").hexdigest()


def test_digests_of_two_formulas_do_not_share_a_cache() -> None:
    a = parse_dimacs(b"p cnf 2 1\n1 0\n")
    b = parse_dimacs(b"p cnf 2 1\n2 0\n")
    da, db = CnfDigest(a), CnfDigest(b)
    assert da.cnf_sha256([1]) == hashlib.sha256(b"p cnf 2 2\n1 0\n1 0\n").hexdigest()
    assert db.cnf_sha256([1]) == hashlib.sha256(b"p cnf 2 2\n2 0\n1 0\n").hexdigest()


def test_streamed_writer_completes_short_writes() -> None:
    formula = FORMULAS["all3"]
    raw = _ShortWriter()
    result = write_cube_cnf(formula, [-1, 3], raw, chunk_size=5)
    expected = cube_cnf_bytes(formula, [-1, 3])
    assert bytes(raw.data) == expected
    assert result.bytes == len(expected)


def test_child_nodes_follow_the_bit_numbering() -> None:
    formula = FORMULAS["all3"]
    parent = node_of(formula, [2])
    children = child_nodes(formula, parent, [3, 1])
    assert [c.cube for c in children] == [(-1, 2, -3), (-1, 2, 3), (1, 2, -3), (1, 2, 3)]
    with pytest.raises(ContractError) as info:
        child_nodes(formula, parent, [4])
    assert info.value.rule == "split.out_of_range"
    other = node_of(FORMULAS["sat3"], [2])
    with pytest.raises(ContractError):
        child_nodes(formula, other, [1])


def _prefix_case_bases() -> dict[int, tuple[dict[str, Any], bytes]]:
    data = cp_corpus.load_json("prefix_cases/cases.json")
    return {
        base["map"]: (base, lzma.decompress((cp_corpus.CORPUS / base["file"]).read_bytes()))
        for base in data["bases"]
    }


def test_prefix_cases_map_to_the_expected_cubes_and_hashes() -> None:
    """Frozen vectors: cube bytes from the base formulas of maps 1 and 2 (specification §3.3)."""
    bases = _prefix_case_bases()
    formulas: dict[int, Formula] = {}
    for number, (base, text) in bases.items():
        formula = parse_dimacs(text)
        assert formula.sha256 == base["formula_sha256"]
        assert (formula.variables, formula.clauses) == (base["variables"], base["clauses"])
        formulas[number] = formula
    digests = {number: CnfDigest(formula) for number, formula in formulas.items()}
    cases = cp_corpus.load_json("prefix_cases/cases.json")["cases"]
    assert len(cases) >= 10
    for case in cases:
        formula = formulas[case["map"]]
        text = bases[case["map"]][1]
        prefix = case["prefix_variables"]
        # Index bit j is the sign of the j-th prefix variable (depth 22 exceeds K_MAX, so
        # it is not one split; depth 12 is also checked against the split children).
        signed = [v if (case["index"] >> j) & 1 else -v for j, v in enumerate(prefix)]
        cube = list(canonical_cube(signed))
        assert cube == case["cube"]
        if len(prefix) <= 20:
            assert list(split_children([], prefix)[case["index"]]) == cube
        assert node_id(formula.sha256, cube) == case["node_id"]
        assert digests[case["map"]].cnf_sha256(cube) == case["cube_cnf_sha256"]
        assert len(cube_cnf_bytes(formula, cube)) == case["cube_cnf_bytes"]
        # The same units in prefix order: same region, other hash.
        prefix_order = _plain_cube_cnf(text, case["prefix_units"])
        assert hashlib.sha256(prefix_order).hexdigest() == case["prefix_order_cnf_sha256"]
        assert len(prefix_order) == case["prefix_order_cnf_bytes"]
        assert sorted(case["prefix_units"], key=abs) == cube
