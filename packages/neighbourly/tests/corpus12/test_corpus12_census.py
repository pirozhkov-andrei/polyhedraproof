"""The long n = 12 computations (slow): all 59 base formulas, and the census.

- specification §3.3: the 59 base formula hashes equal the packaged fixture, the
  repository fixture (``data/fixtures/formula_hashes.json``) and the goldens (bytes,
  counts and SHA-256), emitted by neighbourly.encoding.
- paper: thm:59: the exhaustive search for n = 12 finds 12144 labelled maps in 59 classes,
  and the classes are exactly those of the 59 shipped matrices, whose classes are pinned
  in ``test_corpus12_data.py`` (several minutes). This is the computation for n = 12
  only.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from neighbourly import corpus12
from neighbourly.cnf.dimacs import clause_bytes, formula_digest

TESTS = Path(__file__).resolve().parents[1]
GOLDENS = TESTS / "cnf" / "goldens_n12.json"
#: The 59-formula fixture of the repository (``data/fixtures``).
REPOSITORY_FIXTURE = TESTS.parents[2] / "data" / "fixtures" / "formula_hashes.json"


@pytest.mark.slow
def test_all_59_base_formulas_keep_their_bytes() -> None:
    golden = json.loads(GOLDENS.read_text(encoding="utf-8"))["base_formulas"]
    fixture = json.loads(REPOSITORY_FIXTURE.read_text(encoding="utf-8"))
    packaged = corpus12.formula_hashes()
    for map_id in corpus12.map_ids():
        encoder = corpus12.base_encoder(map_id)
        body = clause_bytes(encoder.clauses)
        count = len(encoder.clauses)
        digest = formula_digest(encoder.variables, body, count)
        expected = golden["maps"][str(map_id)]
        assert (encoder.variables, count, len(body), digest) == (
            expected["variables"],
            expected["clauses"],
            expected["body_bytes"],
            expected["sha256"],
        ), map_id
        assert fixture["maps"][str(map_id)]["sha256"] == digest, map_id
        assert packaged[map_id].sha256 == digest, map_id


@pytest.mark.slow
def test_the_twelve_face_census_reproduces_the_corpus() -> None:
    result = corpus12.enumerate_corpus()
    assert (result.labelled, result.class_count) == corpus12.GOLDEN_COUNTS
    assert result.reference_matches
    assert result.orbit_identity_holds
    assert result.passed
    assert set(result.classes) == set(corpus12.shipped_classes())
    document = corpus12.enumeration_document(result)
    assert document["format"] == corpus12.FORMAT_ENUMERATION
    assert len(document["classes"]) == corpus12.N_MAPS
    assert sum(entry["multiplicity"] for entry in document["classes"]) == 12144
    assert document["corpus_sha256"] == corpus12.matrix_sums()
    for name, digest in document["corpus_sha256"].items():
        map_id = int(name.removeprefix("topology_").removesuffix(".txt"))
        assert hashlib.sha256(corpus12.matrix_bytes(map_id)).hexdigest() == digest
