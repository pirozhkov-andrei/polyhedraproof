"""``claim``: no claim for a missing, extra or wrong formula, an OPEN or model certificate, a
forged certificate or unresolved anomalies; a conditional statement while the mathematical
obligations are outstanding (specification §13.3, §10.4, §4.9).

The fast tests use the publication of maps 1 and 2 (the gate's logic is the same for any
publication); one slow test runs the gate on all 59 published formulas. Every certificate is
recomputed by the gate from fabricated journal attestations (f12_support), never read.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from f12_support import (
    REPO,
    STAND_IN_CHECKER,
    World,
    artifact,
    certificate_file_sha256,
    make_world,
    raw_campaign,
    review,
    sha,
    write_json,
)

from cubeproof.base.canonical_json import document_bytes
from cubeproof.base.errors import CubeproofError, InputError, IntegrityError
from faces12_campaign import cli, pins
from faces12_campaign.claim import ClaimRefused, ClaimResult, Publication, claim

ARTICLE = REPO / "paper" / "faces12-en.tex"
TWO = Publication.corpus12([1, 2], checkers=[STAND_IN_CHECKER])
SRC = [
    REPO / "packages" / name / "src" for name in ("cubeproof", "neighbourly", "faces12-campaign")
]


@pytest.fixture(scope="module")
def base(tmp_path_factory: pytest.TempPathFactory) -> World:
    world = make_world(tmp_path_factory.mktemp("claim"), [1, 2])
    world.init(prefix=0)
    return world


@pytest.fixture(scope="module")
def proved(base: World) -> Path:
    """The evidence manifest of a PROVED certificate for maps 1 and 2."""
    return base.package([base.proved_journal()], "proved")


def run_claim(
    manifest: Path,
    tmp_path: Path,
    *,
    publication: Publication = TWO,
    **review_options: Any,
) -> ClaimResult:
    path = review(
        tmp_path / "review.json",
        certificate_file_sha256=review_options.pop(
            "certificate_file_sha256", certificate_file_sha256(manifest)
        ),
        **review_options,
    )
    return claim(manifest, path, ARTICLE, publication=publication)


def refused(call: Callable[[], object]) -> ClaimRefused:
    with pytest.raises(ClaimRefused) as caught:
        call()
    return caught.value


def test_a_proved_certificate_gives_conditional_support(proved: Path, tmp_path: Path) -> None:
    result = run_claim(proved, tmp_path)
    assert result.exit_code == 1 and not result.unconditional
    assert result.outstanding == ("encoding", "enumeration", "reduction")
    text = result.statement()
    assert text.startswith("CONDITIONAL computational support.")
    assert "NOT established" in text and "paper: cor:conditional" in text
    document = result.to_json()
    assert document["conclusion"] == "conditional"
    assert document["certificate_file_sha256"] == certificate_file_sha256(proved)
    certificate = (proved.parent / "certificate.json").read_bytes()
    assert document["certificate_id"] == sha(certificate[:-1])
    assert document["campaign"] == json.loads(certificate)["campaign"]
    assert [f["key"] for f in document["formulas"]] == ["map01", "map02"]
    assert document["reviewer"] == "A. Reviewer"


def obligations(root: Path, **overrides: dict[str, Any]) -> list[dict[str, Any]]:
    found = []
    for name in ("encoding", "enumeration", "reduction"):
        entry = {
            "name": name,
            "status": "reviewed",
            "evidence": artifact(root, f"review/{name}.md", f"{name} review\n".encode()),
            "note": f"{name} checked",
        }
        entry.update(overrides.get(name, {}))
        found.append(entry)
    return found


def test_the_conclusion_is_unconditional_only_with_every_obligation_reviewed(
    proved: Path, tmp_path: Path
) -> None:
    result = run_claim(proved, tmp_path, obligations=obligations(tmp_path))
    assert result.exit_code == 0 and result.unconditional and result.outstanding == ()
    headline = result.statement().split(". ")[0]
    assert headline.startswith("ARTICLE CONCLUSION, given the attested journals")
    assert "(paper: rem:attestation)" in headline
    assert "there is no neighbourly polyhedron" in headline
    for override in ({"status": "outstanding"}, {"evidence": None}):
        partial = run_claim(proved, tmp_path, obligations=obligations(tmp_path, reduction=override))
        assert partial.exit_code == 1 and partial.outstanding == ("reduction",)


@pytest.mark.parametrize(
    "damage", ["content", "size", "declared size", "missing", "symlink", "escape"]
)
def test_review_artifacts_are_verified(proved: Path, tmp_path: Path, damage: str) -> None:
    entries = obligations(tmp_path)
    target = tmp_path / "review" / "encoding.md"
    if damage == "content":
        target.write_bytes(b"Encoding review\n")
    elif damage == "size":
        target.write_bytes(b"encoding review\n\n")
    elif damage == "declared size":
        entries[0]["evidence"]["bytes"] += 1  # the right hash with the wrong size
    elif damage == "missing":
        target.unlink()
    elif damage == "symlink":
        (tmp_path / "elsewhere.md").write_bytes(target.read_bytes())
        target.unlink()
        os.symlink(tmp_path / "elsewhere.md", target)
    else:
        entries[0]["evidence"]["path"] = "../outside.md"
    if damage == "escape":
        with pytest.raises(InputError):
            run_claim(proved, tmp_path, obligations=entries)
        return
    error = refused(lambda: run_claim(proved, tmp_path, obligations=entries))
    assert error.rule == "claim.review_artifact" and error.exit_code == 4


def test_an_open_certificate_is_no_claim(base: World, tmp_path: Path) -> None:
    manifest = base.package([base.proved_journal(["map01"], worker="w2")], "open")
    error = refused(lambda: run_claim(manifest, tmp_path))
    assert (error.rule, error.exit_code) == ("claim.open", 1)


def test_a_missing_or_extra_formula_is_no_claim(proved: Path, tmp_path: Path) -> None:
    error = refused(
        lambda: run_claim(proved, tmp_path, publication=Publication.corpus12([1, 2, 3]))
    )
    assert (error.rule, error.exit_code) == ("claim.formulas_missing", 4)
    error = refused(lambda: run_claim(proved, tmp_path, publication=Publication.corpus12([1])))
    assert (error.rule, error.exit_code) == ("claim.formulas_extra", 4)


@pytest.mark.parametrize(
    "lie",
    [
        lambda p: p["map"].update(sha256=p["map"]["sha256"][::-1]),
        lambda p: p.update(layers="S,H,A,B"),
        lambda p: p.update(gauge_face=None),
        lambda p: p.update(n=13),
    ],
    ids=["map", "layers", "gauge", "n"],
)
def test_a_formula_whose_parameters_do_not_rebuild_it_is_no_claim(
    tmp_path: Path, lie: Callable[[dict[str, Any]], None]
) -> None:
    """The published hash with lying producer parameters: cubeproof accepts the bundle (its
    parameters are open), the claim rebuilds the formula from them and refuses."""
    world = make_world(tmp_path, [1, 2])
    manifest_path = world.bundles / "map01" / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    lie(manifest["producer"]["parameters"])
    manifest_path.write_bytes(document_bytes(manifest))
    raw_campaign(world)  # `campaign init` would refuse this bundle; cubeproof does not
    error = refused(lambda: run_claim(world.package([world.proved_journal()]), tmp_path))
    assert (error.rule, error.exit_code) == ("claim.bundle", 4)


def test_the_published_layers_and_gauge_are_compared(proved: Path, tmp_path: Path) -> None:
    """A publication that declares other parameters for the same hash is not this claim."""
    from dataclasses import replace

    for change in ({"layers": "S,H,A"}, {"gauge_face": None}):
        entries = {sha: replace(f, **change) for sha, f in TWO.formulas.items()}
        other = Publication("declared otherwise", entries, TWO.checkers)
        with pytest.raises(ClaimRefused) as caught:
            run_claim(proved, tmp_path, publication=other)
        assert (caught.value.rule, caught.value.exit_code) == ("claim.parameters", 4)


def test_a_wrong_formula_is_no_claim(tmp_path: Path) -> None:
    """Map 1 encoded with another gauge is another formula: not the published one."""
    from neighbourly import corpus12
    from neighbourly.cnf import publish_bundle
    from neighbourly.interpret import formula_bundle

    world = make_world(tmp_path, [2])
    other = formula_bundle(corpus12.load_map(1), corpus12.BASE_LAYERS, None)
    publish_bundle(world.bundles / "map01", other.files)
    raw_campaign(world)
    error = refused(lambda: run_claim(world.package([world.proved_journal()]), tmp_path))
    assert (error.rule, error.exit_code) == ("claim.formulas_missing", 4)


def test_a_forged_certificate_is_no_claim(base: World, proved: Path, tmp_path: Path) -> None:
    import shutil

    copy = tmp_path / "forged"
    shutil.copytree(proved.parent, copy)
    for path in copy.rglob("*"):
        path.chmod(0o755 if path.is_dir() else 0o644)
    certificate = json.loads((copy / "certificate.json").read_text(encoding="utf-8"))
    certificate["formulas"][0]["summary"]["leaves"] = 2
    data = document_bytes(certificate)
    (copy / "certificate.json").write_bytes(data)
    # without fixing the manifest the evidence itself is damaged
    with pytest.raises(IntegrityError):
        run_claim(copy / "evidence.json", tmp_path, certificate_file_sha256=sha(data))
    manifest = json.loads((copy / "evidence.json").read_text(encoding="utf-8"))
    manifest["certificate"].update(sha256=sha(data), bytes=len(data))
    write_json(copy / "evidence.json", manifest)
    error = refused(
        lambda: run_claim(copy / "evidence.json", tmp_path, certificate_file_sha256=sha(data))
    )
    assert (error.rule, error.exit_code) == ("claim.certificate", 4)


def test_a_bare_certificate_is_not_claim_input(proved: Path, tmp_path: Path) -> None:
    path = review(tmp_path / "review.json", certificate_file_sha256=certificate_file_sha256(proved))
    with pytest.raises(CubeproofError):
        claim(proved.parent / "certificate.json", path, ARTICLE, publication=TWO)


def test_the_review_is_bound_to_the_certificate_and_the_article(
    proved: Path, tmp_path: Path
) -> None:
    error = refused(lambda: run_claim(proved, tmp_path, certificate_file_sha256="ab" * 32))
    assert error.rule == "claim.review_certificate"
    error = refused(lambda: run_claim(proved, tmp_path, article_sha256="cd" * 32))
    assert error.rule == "claim.review_article"


def anomalous(base: World) -> Path:
    builder = base.journal("w3")
    builder.failed("map01", [5], "CHECK_REJECTED", "rejected")
    builder.unsat("map01", [])
    builder.unsat("map02", [])
    return base.package([builder.write("w3.jsonl")], "anomalous")


def test_every_anomaly_needs_a_resolution(base: World, tmp_path: Path) -> None:
    manifest = anomalous(base)
    certificate = json.loads((manifest.parent / "certificate.json").read_text(encoding="utf-8"))
    assert certificate["verdict"] == "PROVED"
    (anomaly,) = certificate["anomalies"]
    record, code = anomaly["record"], anomaly["code"]
    error = refused(lambda: run_claim(manifest, tmp_path))
    assert (error.rule, error.exit_code) == ("claim.anomaly_unresolved", 4)
    blank = [{"record": record, "code": code, "resolution": "  "}]
    assert refused(lambda: run_claim(manifest, tmp_path, dispositions=blank)).rule == (
        "claim.anomaly_unresolved"
    )
    done = [{"record": record, "code": code, "resolution": "rejected proof, leaf re-proved"}]
    assert run_claim(manifest, tmp_path, dispositions=done).anomalies == 1
    stray = [
        *done,
        {"record": {**record, "seq": record["seq"] + 1}, "code": code, "resolution": "x"},
    ]
    assert refused(lambda: run_claim(manifest, tmp_path, dispositions=stray)).rule == (
        "claim.anomaly_unknown"
    )
    # the same anomaly twice (blank, then resolved) is ambiguous: refused, never "last wins"
    twice = [*blank, *done]
    with pytest.raises(InputError) as duplicate:
        run_claim(manifest, tmp_path, dispositions=twice)
    assert duplicate.value.rule == "review.dispositions"


@pytest.mark.parametrize(
    "transform",
    [
        lambda d: d["obligations"].reverse(),
        lambda d: d["obligations"].pop(),
        lambda d: d["obligations"][0].update(name="article"),
        lambda d: d["obligations"][0].update(status="done"),
        lambda d: d.update(utc="2026-10-09T12:00:00Z"),
        lambda d: d.update(reviewer=""),
        lambda d: d.update(format="faces12-claim-review-2"),
        lambda d: d.update(extra=1),
        lambda d: d.update(
            anomaly_dispositions=[
                {"record": {"journal": "b" * 64, "seq": 1}, "code": "x", "resolution": "r"},
                {"record": {"journal": "a" * 64, "seq": 1}, "code": "x", "resolution": "r"},
            ]
        ),
        lambda d: d.update(
            anomaly_dispositions=[
                {"record": {"journal": "a" * 64, "seq": 1}, "code": "x", "resolution": ""},
                {"record": {"journal": "a" * 64, "seq": 1}, "code": "x", "resolution": "r"},
            ]
        ),
    ],
)
def test_a_malformed_review_is_an_input_error(
    proved: Path, tmp_path: Path, transform: Callable[[dict[str, Any]], None]
) -> None:
    with pytest.raises(InputError):
        run_claim(proved, tmp_path, transform=transform)


def test_a_noncanonical_review_is_an_input_error(proved: Path, tmp_path: Path) -> None:
    path = review(tmp_path / "review.json", certificate_file_sha256=certificate_file_sha256(proved))
    path.write_text(json.dumps(json.loads(path.read_text()), indent=1), encoding="utf-8")
    with pytest.raises(InputError):
        claim(proved, path, ARTICLE, publication=TWO)


def test_the_command_line_reports_and_exits(proved: Path, tmp_path: Path, capsys: Any) -> None:
    path = review(tmp_path / "review.json", certificate_file_sha256=certificate_file_sha256(proved))
    args = ["claim", "--evidence", str(proved), "--review", str(path), "--article", str(ARTICLE)]
    # the default publication is all 59 formulas: two of them are a missing-formula refusal
    assert cli.main(args) == 4
    assert "claim refused [claim.formulas_missing]" in capsys.readouterr().err
    bad = tmp_path / "bad.json"
    bad.write_text("{}\n", encoding="utf-8")
    assert cli.main([*args[:3], "--review", str(bad), "--article", str(ARTICLE)]) == 3


def test_the_command_line_exits_1_for_an_open_certificate(
    base: World, tmp_path: Path, capsys: Any
) -> None:
    manifest = base.package([base.proved_journal(["map02"], worker="w4")], "open-cli")
    path = review(
        tmp_path / "review.json", certificate_file_sha256=certificate_file_sha256(manifest)
    )
    args = ["claim", "--evidence", str(manifest), "--review", str(path), "--article", str(ARTICLE)]
    assert cli.main(args) == 1
    assert "claim refused [claim.open]" in capsys.readouterr().err


def test_the_default_publication_is_the_59_published_formulas(proved: Path, tmp_path: Path) -> None:
    """Fast guard of the default (the slow test below runs it end to end). Oracle: the
    repository fixture ``data/fixtures/formula_hashes.json``, not the packaged copy."""
    fixture = json.loads((REPO / "data" / "fixtures" / "formula_hashes.json").read_text())
    published = {int(k): v["sha256"] for k, v in fixture["maps"].items()}
    assert sorted(published) == list(range(1, 60))
    default = Publication.corpus12()
    assert set(default.formulas) == set(published.values())
    expected = (fixture["layers"], fixture["gauge_face"])
    assert expected == ("S,H,A,B,I", 1)
    assert {(f.layers, f.gauge_face) for f in default.formulas.values()} == {expected}
    assert len({f.label for f in default.formulas.values()}) == 59
    # claim() without a publication uses exactly this default: a maps-1-and-2 campaign misses
    # precisely the 57 other published formulas
    path = review(tmp_path / "review.json", certificate_file_sha256=certificate_file_sha256(proved))
    error = refused(lambda: claim(proved, path, ARTICLE))
    assert error.rule == "claim.formulas_missing"
    # and its checker is the cake_lpr binary of the release, nothing else
    assert default.checkers == {pins.RELEASE_CHECKER_SHA256}
    named = {h for h in published.values() if h in error.detail}
    assert named == {published[m] for m in range(3, 60)}


@pytest.mark.slow
def test_the_59_published_formulas_give_conditional_support(tmp_path: Path) -> None:
    """The default publication end to end: export, campaign, attestations of all 59 empty
    roots, evidence, and the command in a child process."""
    world = make_world(tmp_path, list(range(1, 60)))
    world.init(prefix=0)
    manifest = world.package([world.proved_journal()])
    path = review(
        tmp_path / "review.json", certificate_file_sha256=certificate_file_sha256(manifest)
    )
    env = {"PYTHONPATH": os.pathsep.join(str(s) for s in SRC), "PATH": "/usr/bin:/bin"}
    done = subprocess.run(
        [sys.executable, "-m", "faces12_campaign", "claim", "--evidence", str(manifest),
         "--review", str(path), "--article", str(ARTICLE)],
        env=env, capture_output=True, text=True, timeout=600, check=False,
    )  # fmt: skip
    # the campaign of this test names a stand-in as its checker: the gate refuses it ...
    assert done.returncode == 4, done.stdout
    assert "claim refused [claim.checker]" in done.stderr and STAND_IN_CHECKER in done.stderr
    assert "CONDITIONAL" not in done.stdout and "ARTICLE CONCLUSION" not in done.stdout
    # ... and with the operator's explicit acceptance says in the statement what it accepted
    done = subprocess.run(
        [sys.executable, "-m", "faces12_campaign", "claim", "--evidence", str(manifest),
         "--review", str(path), "--article", str(ARTICLE), "--accept-checker", STAND_IN_CHECKER],
        env=env, capture_output=True, text=True, timeout=600, check=False,
    )  # fmt: skip
    assert done.returncode == 1, done.stderr
    assert done.stdout.startswith("CONDITIONAL computational support.")
    assert f"{STAND_IN_CHECKER} (NOT the release binary" in done.stdout
    result = json.loads(done.stdout.strip().splitlines()[-1])
    assert result["publication"] == "corpus12" and len(result["formulas"]) == 59
    assert result["outstanding"] == ["encoding", "enumeration", "reduction"]


# -- the checker (specification §13.3): the gate says which program checked ---------------------


def test_the_statement_names_the_checker_and_the_solver(proved: Path, tmp_path: Path) -> None:
    result = run_claim(proved, tmp_path)
    assert result.checkers == ((STAND_IN_CHECKER, True),)
    text = result.statement()
    assert f"{STAND_IN_CHECKER} (the cake_lpr binary of this release)" in text
    tools = result.to_json()["tools"]
    assert tools["admitted_checkers"] == [{"sha256": STAND_IN_CHECKER, "release_checker": True}]
    # what the used records name comes from the certificate's machinery, not from the campaign
    certificate = json.loads((proved.parent / "certificate.json").read_bytes())
    snapshots = [entry["machinery"] for entry in certificate["machinery"]]
    assert snapshots
    assert tools["used_checkers"] == sorted({s["checker"]["sha256"] for s in snapshots})
    assert tools["used_checkers"] == [STAND_IN_CHECKER]
    (solver,) = tools["used_solvers"]
    assert solver == {
        "sha256": snapshots[0]["solver"]["sha256"],
        "argv": snapshots[0]["solver"]["argv"],
    }
    assert f"The records this certificate uses name the checker {STAND_IN_CHECKER}" in text
    assert solver["sha256"] in text
    sources = sorted({s["cubeproof_sha256"] for s in snapshots})
    assert tools["used_cubeproof_sha256"] == sources and len(sources) == 1
    assert f"written by the cubeproof sources {sources[0]}." in text


def test_a_checker_that_is_not_the_release_binary_is_no_claim(proved: Path, tmp_path: Path) -> None:
    """The campaign of these tests admits a stand-in that never checks anything. Against the
    release checker it certifies PROVED and is refused; accepted explicitly, the statement says
    what was accepted. Oracle: the hash of the stand-in's bytes, computed in f12_support."""
    release = Publication.corpus12([1, 2])
    assert release.checkers == {pins.RELEASE_CHECKER_SHA256} != {STAND_IN_CHECKER}
    error = refused(lambda: run_claim(proved, tmp_path, publication=release))
    assert error.rule == "claim.checker" and error.exit_code == 4
    assert STAND_IN_CHECKER in error.detail and pins.RELEASE_CHECKER_SHA256 in error.detail
    path = review(
        tmp_path / "accepted.json", certificate_file_sha256=certificate_file_sha256(proved)
    )
    accepted = claim(proved, path, ARTICLE, publication=release, accept_checkers=[STAND_IN_CHECKER])
    assert accepted.checkers == ((STAND_IN_CHECKER, False),)
    assert f"{STAND_IN_CHECKER} (NOT the release binary" in accepted.statement()
    assert accepted.to_json()["tools"]["admitted_checkers"][0]["release_checker"] is False
    assert f"name the checker {STAND_IN_CHECKER} (NOT the release binary)" in accepted.statement()


def test_an_acceptance_names_only_foreign_admitted_checkers(proved: Path, tmp_path: Path) -> None:
    path = review(tmp_path / "review.json", certificate_file_sha256=certificate_file_sha256(proved))
    for accepted in (["ab" * 32], [STAND_IN_CHECKER]):  # not admitted; already the release one
        with pytest.raises(ClaimRefused) as caught:
            claim(proved, path, ARTICLE, publication=TWO, accept_checkers=accepted)
        assert caught.value.rule == "claim.checker_unknown"


def test_the_review_names_exactly_the_admitted_checkers(proved: Path, tmp_path: Path) -> None:
    other = "cd" * 32
    for named in ([other], sorted([other, STAND_IN_CHECKER])):
        with pytest.raises(ClaimRefused) as caught:
            run_claim(proved, tmp_path, checker_sha256=named)
        assert caught.value.rule == "claim.review_checker"
    unsorted = sorted([other, STAND_IN_CHECKER])[::-1]
    for bad in ([], [STAND_IN_CHECKER, STAND_IN_CHECKER], ["xyz"], unsorted):
        with pytest.raises(InputError):
            run_claim(proved, tmp_path, checker_sha256=bad)


def test_an_admitted_second_checker_is_judged_too(base: World, tmp_path: Path) -> None:
    """A campaign may admit more checkers than the one it runs; the certificate believes all of
    them, so all of them are named and judged."""
    world = make_world(tmp_path / "w", [1, 2])
    other = "ef" * 32
    admit = write_json(
        tmp_path / "admit.json",
        {"checker_sha256": sorted([other, STAND_IN_CHECKER]), "solvers": None},
    )
    world.init(prefix=0, admit=admit)
    manifest = world.package([world.proved_journal()])
    both = sorted([other, STAND_IN_CHECKER])
    error = refused(lambda: run_claim(manifest, tmp_path))  # the review names only one
    assert error.rule == "claim.review_checker"
    error = refused(lambda: run_claim(manifest, tmp_path, checker_sha256=both))
    assert error.rule == "claim.checker" and other in error.detail
    path = review(
        tmp_path / "both.json",
        certificate_file_sha256=certificate_file_sha256(manifest),
        checker_sha256=both,
    )
    result = claim(manifest, path, ARTICLE, publication=TWO, accept_checkers=[other])
    assert dict(result.checkers) == {other: False, STAND_IN_CHECKER: True}
    # the statement separates what the campaign admits from what the used records name: every
    # journal of this world was written with the stand-in, none with the other checker
    assert result.used_checkers == (STAND_IN_CHECKER,)
    text = result.statement()
    admits, uses = text.split("The records this certificate uses name the checker ")
    assert other in admits and STAND_IN_CHECKER in admits
    assert STAND_IN_CHECKER in uses and other not in uses
