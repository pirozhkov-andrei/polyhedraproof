"""``model``: models of a recomputed certificate in the article's terms.

Specification §13.2, §13.3. The golden: the application's path (bitset of specification §4.8 ->
rebuilt formula -> description) gives the golden description of map 1 on the pinned assignment.
The model path end to end uses Szilassi's realization (n = 7): a real model, so the certifier
accepts the MODEL record; it is still reported as a candidate, not as a realization
(paper: rem:noconverse).
"""

from __future__ import annotations

import hashlib
import json
from fractions import Fraction
from pathlib import Path
from typing import Any

import pytest
from f12_support import (
    REPO,
    STAND_IN_CHECKER,
    World,
    certificate_file_sha256,
    cs,
    make_world,
    raw_campaign,
    review,
    sha,
    tools,
    write_json,
)

from cubeproof.base.canonical_json import document_bytes
from cubeproof.base.errors import IntegrityError
from cubeproof.contracts.assignment import encode_assignment
from faces12_campaign import cli
from faces12_campaign.claim import ClaimRefused, Publication, PublishedFormula, claim
from faces12_campaign.formulas import bundle_key
from faces12_campaign.model import corpus_maps, interpret_assignment, interpret_models
from neighbourly import corpus12
from neighbourly.cnf import publish_bundle
from neighbourly.data import read_bytes
from neighbourly.encoding import Encoder
from neighbourly.exact import oracle_from_planes
from neighbourly.interpret import formula_bundle
from neighbourly.maps import CombinatorialMap

GOLDEN = REPO / "packages" / "neighbourly" / "tests" / "interpret" / "golden_model_map1.json"
#: The ``description_sha256`` and ``assignment_ones`` of the golden (map 1, S,H,A,B,I, gauge 1).
DESCRIPTION_SHA256 = "4689bfd8bba3d87b8a36f8b38b7b5d900f8f4f2f8d0670534afd2f1e7dc41dfc"
ASSIGNMENT_ONES = 2626
ARTICLE = REPO / "paper" / "faces12-en.tex"


def J(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def test_the_golden_assignment_gets_the_golden_description(tmp_path: Path) -> None:
    """The digests are pinned here and the full golden document is compared."""
    world = make_world(tmp_path, [1])
    bundle = world.bundles / bundle_key(1)
    variables = json.loads((bundle / "manifest.json").read_text())["variables"]
    values = [
        hashlib.sha256(f"k12-s00-model-1:{v}".encode("ascii")).digest()[0] & 1 == 1
        for v in range(1, variables + 1)
    ]
    assert sum(values) == ASSIGNMENT_ONES
    result = interpret_assignment(bundle, corpus12.load_map(1), encode_assignment(values))
    assert hashlib.sha256(J(dict(result.description))).hexdigest() == DESCRIPTION_SHA256
    assert result.formula_sha256 == corpus12.formula_hashes()[1].sha256
    assert not result.satisfies  # a pinned pseudo-random assignment, not a model
    golden = json.loads(GOLDEN.read_text(encoding="utf-8"))
    assert (golden["map"], golden["layers"], golden["gauge_face"]) == (1, "S,H,A,B,I", 1)
    assert golden["description_sha256"] == DESCRIPTION_SHA256
    assert golden["assignment_ones"] == ASSIGNMENT_ONES
    assert golden["formula_sha256"] == result.formula_sha256
    assert dict(result.description) == golden["description"]
    with pytest.raises(IntegrityError) as wrong_map:
        interpret_assignment(bundle, corpus12.load_map(2), encode_assignment(values))
    assert wrong_map.value.rule == "model.bundle"
    with pytest.raises(IntegrityError) as short:
        interpret_assignment(bundle, corpus12.load_map(1), encode_assignment(values[:-8]))
    assert short.value.rule == "model.assignment"


def test_the_corpus_maps_are_keyed_by_the_published_hashes() -> None:
    maps = corpus_maps()
    fixture = corpus12.formula_hashes()
    assert sorted(maps) == sorted(b.sha256 for b in fixture.values())
    label, load = maps[fixture[2].sha256]
    assert label == "topology_02" and load().triples == corpus12.load_map(2).triples


def szilassi() -> tuple[CombinatorialMap, dict[int, int], dict[str, Any]]:
    cmap = CombinatorialMap.from_text(
        read_bytes("fixtures", "szilassi", "csaszar_n7.txt").decode("utf-8")
    )
    document = json.loads(read_bytes("fixtures", "szilassi", "szilassi.json"))
    planes = [[Fraction(x) for x in row] for row in document["planes"]]
    orientation = {int(k): v for k, v in document["verification"]["orientation"].items()}
    truth = Encoder(cmap, oracle=oracle_from_planes(planes).with_orientations(orientation))
    truth.build("S,H,A,B,I", None)
    return cmap, dict(truth.formula.values), document


Modelled = tuple[World, Path, Path, Publication]


def szilassi_evidence(root: Path, *, also_unsat: bool) -> Modelled:
    """A campaign of Szilassi's formula with a MODEL attestation of its realization and, when
    ``also_unsat``, a fabricated UNSAT attestation of the same empty cube (INCONSISTENT)."""
    cmap, values, _ = szilassi()
    world = World(root, (), tools(root / "tools"))
    produced = formula_bundle(cmap, "S,H,A,B,I", None, map_name="szilassi")
    world.bundles.mkdir()
    publish_bundle(world.bundles / "szilassi", produced.files)
    raw_campaign(world)
    variables = produced.variable_map.variables
    bits = encode_assignment([values[v] == 1 for v in range(1, variables + 1)])
    builder = world.journal()
    builder.attempt(
        "szilassi", [], outcome="MODEL", reason=None, model_error=None, assignment=bits,
        route="cdcl", solver=cs.solver_result(10), checks=[], proof_bytes=None, proof_sha256=None,
    )  # fmt: skip
    if also_unsat:
        builder.unsat("szilassi", [])
    journal = builder.write("w1.jsonl")
    manifest = world.package([journal])
    sha = produced.files.formula_sha256
    publication = Publication(
        "szilassi",
        {sha: PublishedFormula(sha, "szilassi", "S,H,A,B,I", None, lambda: cmap)},
        frozenset({STAND_IN_CHECKER}),
    )
    return world, journal, manifest, publication


@pytest.fixture(scope="module")
def modelled(tmp_path_factory: pytest.TempPathFactory) -> Modelled:
    """A campaign of Szilassi's formula with a MODEL attestation of its realization."""
    return szilassi_evidence(tmp_path_factory.mktemp("model"), also_unsat=False)


@pytest.fixture(scope="module")
def inconsistent(tmp_path_factory: pytest.TempPathFactory) -> Modelled:
    """The same valid model plus an UNSAT attestation of the same root: the certificate is
    INCONSISTENT (a soundness failure somewhere in the chain, specification §10.4)."""
    return szilassi_evidence(tmp_path_factory.mktemp("inconsistent"), also_unsat=True)


def test_a_model_is_described_and_not_called_a_realization(
    modelled: tuple[World, Path, Path, Publication],
) -> None:
    world, journal, manifest, publication = modelled
    _, _, document = szilassi()
    sources = {sha: (f.label, f.load_map) for sha, f in publication.formulas.items()}
    for result in (
        interpret_models(campaign=world.campaign, journals=[journal], maps=sources),
        interpret_models(evidence=manifest, maps=sources),
    ):
        assert result.verdict == "MODEL_FOUND"
        (report,) = result.models
        assert report.key == "szilassi" and report.label == "szilassi"
        assert report.interpretation is not None and report.interpretation.satisfies
        reflex = {int(k): v for k, v in document["verification"]["reflex"].items()}
        assert dict(report.interpretation.reflex_corners) == reflex
        summary = result.to_json()
        assert "not a geometric realization" in summary["note"]
        assert "not a geometric realization" in summary["models"][0]["interpretation"]["note"]
    # without a trusted map the model is reported, uninterpreted
    (bare,) = interpret_models(campaign=world.campaign, journals=[journal]).models
    assert bare.interpretation is None and bare.label is None


def test_a_model_certificate_is_no_claim(
    modelled: tuple[World, Path, Path, Publication], tmp_path: Path
) -> None:
    _, _, manifest, publication = modelled
    path = review(
        tmp_path / "review.json", certificate_file_sha256=certificate_file_sha256(manifest)
    )
    with pytest.raises(ClaimRefused) as caught:
        claim(manifest, path, ARTICLE, publication=publication)
    assert (caught.value.rule, caught.value.exit_code) == ("claim.model", 2)


def test_the_model_command_exits_2_with_a_model(
    modelled: tuple[World, Path, Path, Publication], capsys: Any
) -> None:
    world, journal, manifest, _ = modelled
    assert cli.main(["model", "--evidence", str(manifest)]) == 2
    out = capsys.readouterr().out
    assert json.loads(out.strip().splitlines()[-1])["verdict"] == "MODEL_FOUND"
    assert cli.main(["model", "--evidence", str(manifest), "--journals", str(journal)]) == 3
    assert cli.main(["model", "--campaign", str(world.campaign)]) == 3


def test_an_inconsistent_certificate_is_no_claim(
    inconsistent: Modelled, tmp_path: Path, capsys: Any
) -> None:
    """A formula both proved and modelled: the claim refuses with exit 4 (specification §12.2: 4 =
    inconsistency), from the function and from the command line (default publication: the
    verdict is refused before the formulas are compared)."""
    _, _, manifest, publication = inconsistent
    certificate = json.loads((manifest.parent / "certificate.json").read_text(encoding="utf-8"))
    assert certificate["verdict"] == "INCONSISTENT"
    path = review(
        tmp_path / "review.json", certificate_file_sha256=certificate_file_sha256(manifest)
    )
    with pytest.raises(ClaimRefused) as caught:
        claim(manifest, path, ARTICLE, publication=publication)
    assert (caught.value.rule, caught.value.exit_code) == ("claim.inconsistent", 4)
    args = ["claim", "--evidence", str(manifest), "--review", str(path), "--article", str(ARTICLE)]
    assert cli.main(args) == 4
    captured = capsys.readouterr()
    assert "claim refused [claim.inconsistent]" in captured.err
    assert captured.out == ""  # no statement of any kind


def test_the_model_command_exits_4_for_an_inconsistent_certificate(
    inconsistent: Modelled, capsys: Any
) -> None:
    """INCONSISTENT outranks a valid model (specification §12.2 priority 4 > 2); the model is still
    listed."""
    world, journal, manifest, publication = inconsistent
    sources = {sha: (f.label, f.load_map) for sha, f in publication.formulas.items()}
    result = interpret_models(evidence=manifest, maps=sources)
    assert result.verdict == "INCONSISTENT" and len(result.models) == 1
    assert cli.main(["model", "--evidence", str(manifest)]) == 4
    captured = capsys.readouterr()
    assert json.loads(captured.out.strip().splitlines()[-1])["verdict"] == "INCONSISTENT"
    assert "INCONSISTENT" in captured.err
    command = ["model", "--campaign", str(world.campaign), "--journals", str(journal)]
    assert cli.main(command) == 4


def test_the_model_command_compares_the_packaged_certificate(
    modelled: Modelled, tmp_path: Path
) -> None:
    """A certificate swapped in the evidence directory (manifest updated to match) is refused:
    models are taken only from the recomputed certificate."""
    import shutil

    _, _, manifest, publication = modelled
    copy = tmp_path / "forged"
    shutil.copytree(manifest.parent, copy)
    for path in copy.rglob("*"):
        path.chmod(0o755 if path.is_dir() else 0o644)
    certificate = json.loads((copy / "certificate.json").read_text(encoding="utf-8"))
    certificate["models"] = []
    certificate["verdict"] = "OPEN"
    data = document_bytes(certificate)
    (copy / "certificate.json").write_bytes(data)
    document = json.loads((copy / "evidence.json").read_text(encoding="utf-8"))
    document["certificate"].update(sha256=sha(data), bytes=len(data))
    write_json(copy / "evidence.json", document)
    sources = {s: (f.label, f.load_map) for s, f in publication.formulas.items()}
    with pytest.raises(IntegrityError) as caught:
        interpret_models(evidence=copy / "evidence.json", maps=sources)
    assert caught.value.rule == "evidence.certificate"
    assert cli.main(["model", "--evidence", str(copy / "evidence.json")]) == 4
