"""The claim gate: what the computation supports, and what it does not (specification §13.3).

``claim --evidence MANIFEST --review REVIEW --article ARTICLE`` never trusts a certificate
file. In this order it

1. reads the review attestation ``faces12-claim-review-1`` (canonical JSON, exact fields);
2. verifies the evidence directory (:func:`cubeproof.commands.load_evidence`: every listed
   file by size and SHA-256) and **re-runs the certifier** on its campaign and journal
   snapshots; the packaged certificate must be byte for byte the recomputed one;
3. requires the verdict ``PROVED`` (OPEN and MODEL_FOUND are not claims; INCONSISTENT is an
   integrity failure);
4. binds the review: its ``certificate_file_sha256`` is the SHA-256 of the certificate file the
   evidence manifest lists, its ``article_sha256`` the SHA-256 of the article given;
5. requires the campaign formulas to be **exactly** the published formulas (no missing, no
   extra formula) and each of them proved at its empty cube;
6. requires a nonempty resolution for every anomaly of the certificate and no disposition
   for an anomaly the certificate does not have;
7. verifies every evidence artifact named by the review (relative to the review file's
   directory, no symlinks) by size and SHA-256;
8. rebuilds every formula from the packaged map (:func:`neighbourly.interpret.read_bundle`)
   and requires the published layers and gauge: a hash alone is not the formula's meaning;
9. requires the review to name exactly the checkers the campaign admits
   (``checker_sha256``), and every one of them to be the cake_lpr binary of this release
   (:mod:`faces12_campaign.pins`) or accepted explicitly (``--accept-checker``). A certificate
   believes whatever checker its campaign admits, so the gate is the place that says which
   program that was; the result names the admitted checkers and, from the machinery of the
   records the certificate uses, the checkers and solvers those records name and the cubeproof
   sources (``cubeproof_sha256``) that wrote them.

The result is a **conditional** computational-support statement while any of the obligations
``enumeration``, ``encoding`` and ``reduction`` is outstanding or has no evidence artifact,
and the unconditional article conclusion (paper: cor:conditional) only when all three are
reviewed with verified artifacts. The review file is a human attestation, not a signature:
creating it does not replace the mathematical review, and the result names the reviewer and
the artifacts so that the attestation can be traced. The certificate itself is an attestation
of the journals (paper: rem:attestation).
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from itertools import pairwise
from pathlib import Path
from typing import Any, Final

from cubeproof.base.canonical_json import json_sha256, parse_document
from cubeproof.base.errors import ContractError, CubeproofError, InputError
from cubeproof.base.paths import open_contained
from cubeproof.commands import load_evidence, read_json_file
from cubeproof.contracts import fields as f
from cubeproof.contracts.campaign import Campaign
from cubeproof.contracts.primitives import is_hash, is_utc
from cubeproof.contracts.values import Artifact, Ref
from cubeproof.evidence.certify.run import certify
from faces12_campaign import pins
from neighbourly import corpus12
from neighbourly.interpret import InterpretError, read_bundle
from neighbourly.maps import CombinatorialMap

__all__ = [
    "FORMAT_CLAIM",
    "FORMAT_REVIEW",
    "OBLIGATIONS",
    "ClaimRefused",
    "ClaimResult",
    "Disposition",
    "Obligation",
    "Publication",
    "PublishedFormula",
    "Review",
    "claim",
    "read_review",
]

FORMAT_REVIEW: Final = "faces12-claim-review-1"
FORMAT_CLAIM: Final = "faces12-claim-1"
#: The mathematical obligations outside the computation, sorted by name.
OBLIGATIONS: Final = ("encoding", "enumeration", "reduction")
_STATUSES: Final = ("reviewed", "outstanding")
_CHUNK: Final = 1 << 20

_ACCEPTED: Final = "NOT the release binary; accepted by the operator with --accept-checker"
_WHAT: Final = {
    "enumeration": "the census of the 59 maps is complete (paper: thm:59)",
    "encoding": "the formulas encode necessary conditions (paper: thm:necessity)",
    "reduction": "a polyhedron induces one of the maps and realizes it (paper: lem:bridge)",
}


class ClaimRefused(CubeproofError):
    """The evidence does not support the claim; ``exit_code`` follows specification §12.2."""

    def __init__(self, rule: str, detail: str = "", *, exit_code: int = 4) -> None:
        super().__init__(rule, detail)
        self.exit_code = exit_code


# -- the review attestation ----------------------------------------------------------------------


@dataclass(frozen=True)
class Obligation:
    name: str
    status: str
    evidence: Artifact | None
    note: str

    @classmethod
    def from_json(cls, value: Any, at: str) -> Obligation:
        f.obj(value, at, ("name", "status", "evidence", "note"))
        name = f.string(value["name"], f.member(at, "name"))
        if name not in OBLIGATIONS:
            raise ContractError("review.obligation", f"{name!r} is not one of {OBLIGATIONS}")
        status = f.string(value["status"], f.member(at, "status"))
        if status not in _STATUSES:
            raise ContractError("review.obligation", f"status {status!r} is not one of {_STATUSES}")
        evidence = value["evidence"]
        artifact = (
            None if evidence is None else Artifact.from_json(evidence, f.member(at, "evidence"))
        )
        return cls(name, status, artifact, f.string(value["note"], f.member(at, "note")))

    @property
    def established(self) -> bool:
        """Reviewed and backed by an evidence artifact (verified by :func:`claim`)."""
        return self.status == "reviewed" and self.evidence is not None

    def to_json(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status,
            "evidence": None if self.evidence is None else self.evidence.to_json(),
            "note": self.note,
        }


@dataclass(frozen=True)
class Disposition:
    record: Ref
    code: str
    resolution: str

    @classmethod
    def from_json(cls, value: Any, at: str) -> Disposition:
        f.obj(value, at, ("record", "code", "resolution"))
        return cls(
            Ref.from_json(value["record"], f.member(at, "record")),
            f.string(value["code"], f.member(at, "code")),
            f.string(value["resolution"], f.member(at, "resolution")),
        )

    @property
    def key(self) -> tuple[str, int, str]:
        return (self.record.journal, self.record.seq, self.code)


@dataclass(frozen=True)
class Review:
    """``faces12-claim-review-1`` (specification §13.3)."""

    certificate_file_sha256: str
    article_sha256: str
    checker_sha256: tuple[str, ...]
    reviewer: str
    utc: str
    obligations: tuple[Obligation, ...]
    dispositions: tuple[Disposition, ...]

    @classmethod
    def from_json(cls, value: Any, at: str = "$") -> Review:
        keys = ("format", "certificate_file_sha256", "article_sha256", "checker_sha256")
        f.obj(value, at, (*keys, "reviewer", "utc", "obligations", "anomaly_dispositions"))
        m = f.member
        f.const(value["format"], m(at, "format"), FORMAT_REVIEW)
        certificate = f.matching(
            value["certificate_file_sha256"], m(at, "certificate_file_sha256"), is_hash, "Hash"
        )
        article = f.matching(value["article_sha256"], m(at, "article_sha256"), is_hash, "Hash")
        checkers = tuple(
            f.items(
                value["checker_sha256"],
                m(at, "checker_sha256"),
                lambda v, where: f.matching(v, where, is_hash, "Hash"),
                min_items=1,
            )
        )
        if any(a >= b for a, b in pairwise(checkers)):
            raise ContractError(
                "review.checkers", "checker_sha256 is not strictly sorted (no hash twice)"
            )
        reviewer = f.string(value["reviewer"], m(at, "reviewer"), min_length=1)
        utc = f.matching(value["utc"], m(at, "utc"), is_utc, "UTC")
        obligations = tuple(
            f.items(value["obligations"], m(at, "obligations"), Obligation.from_json)
        )
        if tuple(o.name for o in obligations) != OBLIGATIONS:
            raise ContractError(
                "review.obligations",
                f"exactly one obligation per name, sorted: {list(OBLIGATIONS)}",
            )
        dispositions = tuple(
            f.items(
                value["anomaly_dispositions"], m(at, "anomaly_dispositions"), Disposition.from_json
            )
        )
        keys_in_order = [d.key for d in dispositions]
        if any(a >= b for a, b in pairwise(keys_in_order)):
            raise ContractError(
                "review.dispositions", "anomaly dispositions are not strictly sorted by Ref/code"
            )
        return cls(certificate, article, checkers, reviewer, utc, obligations, dispositions)


def read_review(path: Path) -> Review:
    """The review file (canonical J plus LF); InputError naming the rule otherwise."""
    value = read_json_file(Path(path))
    try:
        return Review.from_json(value)
    except CubeproofError as error:
        raise InputError(error.rule, f"{path}: {error.detail}", location=error.location) from None


# -- the publication -------------------------------------------------------------------------------


@dataclass(frozen=True)
class PublishedFormula:
    """One published formula: its hash, label, the trusted map and the published parameters."""

    formula_sha256: str
    label: str
    layers: str
    gauge_face: int | None
    load_map: Callable[[], CombinatorialMap]


@dataclass(frozen=True)
class Publication:
    """The formulas a claim is about, each with the trusted source of its map."""

    name: str
    formulas: Mapping[str, PublishedFormula]
    checkers: frozenset[str] = frozenset({pins.RELEASE_CHECKER_SHA256})

    @classmethod
    def corpus12(
        cls, maps: Iterable[int] | None = None, checkers: Iterable[str] | None = None
    ) -> Publication:
        """The 59 base formulas of :mod:`neighbourly.corpus12` with the release checker.

        A subset of the maps, or other checker binaries, only for tests.
        """
        fixture = corpus12.formula_hashes()
        chosen = sorted(fixture) if maps is None else sorted(set(maps))
        entries = {}
        for map_id in chosen:
            sha = fixture[map_id].sha256
            entries[sha] = PublishedFormula(
                sha,
                corpus12.matrix_name(map_id).removesuffix(".txt"),
                corpus12.BASE_LAYERS,
                corpus12.BASE_GAUGE_FACE,
                _loader(map_id),
            )
        name = "corpus12" if maps is None else f"corpus12 maps {chosen}"
        if checkers is None:
            return cls(name, entries)
        return cls(name, entries, frozenset(checkers))


def _loader(map_id: int) -> Callable[[], CombinatorialMap]:
    return lambda: corpus12.load_map(map_id)


# -- the gate --------------------------------------------------------------------------------


@dataclass(frozen=True)
class ClaimResult:
    """What the evidence and the review support (module doc)."""

    campaign_id: str
    certificate_file_sha256: str
    certificate_id: str
    article_sha256: str
    reviewer: str
    review_utc: str
    publication: str
    formulas: tuple[tuple[str, str, str], ...]  # (campaign key, formula hash, label)
    anomalies: int
    obligations: tuple[Obligation, ...]
    checkers: tuple[tuple[str, bool], ...]  # (admitted checker hash, is the release binary)
    used_checkers: tuple[str, ...]  # the checkers named by the records the certificate uses
    used_solvers: tuple[tuple[str, tuple[str, ...]], ...]  # (hash, argv) of those records
    used_sources: tuple[str, ...] = ()  # the cubeproof_sha256 of the sessions that wrote them

    @property
    def unconditional(self) -> bool:
        return all(o.established for o in self.obligations)

    @property
    def outstanding(self) -> tuple[str, ...]:
        return tuple(o.name for o in self.obligations if not o.established)

    @property
    def exit_code(self) -> int:
        """0 for the unconditional conclusion, 1 while obligations are open (open work)."""
        return 0 if self.unconditional else 1

    def statement(self) -> str:
        """The text the command prints."""
        count = len(self.formulas)
        support = (
            f"The certificate {self.certificate_file_sha256} of campaign {self.campaign_id} is "
            f"PROVED, recomputed from its journals, for exactly the {count} published formulas "
            f"({self.publication}); each formula was rebuilt from its map with the published "
            "layers and gauge. Under the attestation model of the journals "
            "(paper: rem:attestation) this supports the hypothesis of the conditional "
            "corollary (paper: cor:conditional). " + self._tools()
        )
        if not self.unconditional:
            missing = "; ".join(f"{n}: {_WHAT[n]}" for n in self.outstanding)
            return (
                "CONDITIONAL computational support. "
                + support
                + f" The article conclusion is NOT established: outstanding obligations: {missing}."
            )
        return (
            "ARTICLE CONCLUSION, given the attested journals (paper: rem:attestation) and the "
            "reviewed obligations: there is no neighbourly polyhedron with twelve faces satisfying "
            "(H1)-(H3) (paper: cor:conditional). "
            + support
            + f" The obligations enumeration, encoding and reduction were reviewed by "
            f"{self.reviewer} at {self.review_utc} with the artifacts listed in the review."
        )

    def _tools(self) -> str:
        """Which programs the attested checks name: the gate's own statement of its anchor."""
        kinds = dict(self.checkers)
        admitted = "; ".join(
            f"{sha} ({'the cake_lpr binary of this release' if release else _ACCEPTED})"
            for sha, release in self.checkers
        )
        used = "; ".join(
            f"{sha} ({'the release binary' if kinds[sha] else 'NOT the release binary'})"
            for sha in self.used_checkers
        )
        solvers = "; ".join(f"{sha} with options {list(argv)}" for sha, argv in self.used_solvers)
        sources = "; ".join(self.used_sources)
        return (
            f"The campaign admits the checker {admitted}. The records this certificate uses "
            f"name the checker {used} and the solver {solvers}, and were written by the "
            f"cubeproof sources {sources}."
        )

    def to_json(self) -> dict[str, Any]:
        return {
            "format": FORMAT_CLAIM,
            "conclusion": "unconditional" if self.unconditional else "conditional",
            "campaign": self.campaign_id,
            "certificate_file_sha256": self.certificate_file_sha256,
            "certificate_id": self.certificate_id,
            "article_sha256": self.article_sha256,
            "reviewer": self.reviewer,
            "review_utc": self.review_utc,
            "publication": self.publication,
            "formulas": [
                {"key": key, "formula_sha256": sha, "label": label}
                for key, sha, label in self.formulas
            ],
            "anomalies_resolved": self.anomalies,
            "tools": {
                "admitted_checkers": [
                    {"sha256": sha, "release_checker": release} for sha, release in self.checkers
                ],
                "used_checkers": list(self.used_checkers),
                "used_solvers": [
                    {"sha256": sha, "argv": list(argv)} for sha, argv in self.used_solvers
                ],
                "used_cubeproof_sha256": list(self.used_sources),
            },
            "obligations": [o.to_json() for o in self.obligations],
            "outstanding": list(self.outstanding),
            "statement": self.statement(),
        }


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        while chunk := stream.read(_CHUNK):
            digest.update(chunk)
    return digest.hexdigest()


def _verify_artifact(root: Path, artifact: Artifact, name: str) -> None:
    digest = hashlib.sha256()
    size = 0
    try:
        with open_contained(root, artifact.path) as stream:
            while chunk := stream.read(_CHUNK):
                digest.update(chunk)
                size += len(chunk)
    except FileNotFoundError:
        raise ClaimRefused("claim.review_artifact", f"{name}: {artifact.path} is absent") from None
    except ContractError as error:
        raise ClaimRefused("claim.review_artifact", f"{name}: {error.detail}") from None
    if size != artifact.bytes or digest.hexdigest() != artifact.sha256:
        raise ClaimRefused(
            "claim.review_artifact", f"{name}: {artifact.path} differs from its size or SHA-256"
        )


def _verdict(certificate: Mapping[str, Any]) -> None:
    verdict = certificate["verdict"]
    if verdict == "PROVED":
        return
    if verdict == "OPEN":
        raise ClaimRefused("claim.open", "the certificate is OPEN: no claim", exit_code=1)
    if verdict == "MODEL_FOUND":
        raise ClaimRefused(
            "claim.model",
            "the certificate has a valid model: no claim (a model is a candidate to be examined, "
            "not a realization; paper: rem:noconverse)",
            exit_code=2,
        )
    raise ClaimRefused("claim.inconsistent", f"the certificate verdict is {verdict}")


def _formulas(
    certificate: Mapping[str, Any], publication: Publication
) -> tuple[tuple[str, str, str], ...]:
    entries = {item["formula_sha256"]: item for item in certificate["formulas"]}
    missing = sorted(set(publication.formulas) - set(entries))
    extra = sorted(set(entries) - set(publication.formulas))
    if missing:
        raise ClaimRefused(
            "claim.formulas_missing", f"published formulas absent from the campaign: {missing}"
        )
    if extra:
        raise ClaimRefused("claim.formulas_extra", f"campaign formulas not published: {extra}")
    unproved = sorted(sha for sha, entry in entries.items() if entry["proved"] is not True)
    if unproved:
        raise ClaimRefused("claim.unproved", f"formulas not proved at the empty cube: {unproved}")
    return tuple(
        sorted(
            (entry["key"], sha, publication.formulas[sha].label) for sha, entry in entries.items()
        )
    )


def _anomalies(certificate: Mapping[str, Any], review: Review) -> int:
    expected = {
        (a["record"]["journal"], a["record"]["seq"], a["code"]) for a in certificate["anomalies"]
    }
    given = {d.key: d for d in review.dispositions}
    unknown = sorted(set(given) - expected)
    if unknown:
        raise ClaimRefused(
            "claim.anomaly_unknown", f"dispositions for anomalies the certificate lacks: {unknown}"
        )
    unresolved = sorted(k for k in expected if k not in given or not given[k].resolution.strip())
    if unresolved:
        raise ClaimRefused(
            "claim.anomaly_unresolved",
            f"{len(unresolved)} certificate anomalies have no resolution: {unresolved[:5]}",
        )
    return len(expected)


def _campaign(campaign_path: Path) -> Campaign:
    try:
        return Campaign.from_json(parse_document(campaign_path.read_bytes()))
    except CubeproofError as error:  # verified by the certifier already; defensive
        raise ClaimRefused("claim.campaign", f"{campaign_path}: {error.detail}") from None


def _checkers(
    campaign: Campaign, review: Review, publication: Publication, accepted: Iterable[str]
) -> tuple[tuple[str, bool], ...]:
    """The admitted checkers, each marked as the release binary or not (module doc, step 9).

    The certifier admits the records of every checker in ``admit`` (specification §10.1) and
    cannot know what program a hash stands for. The gate therefore requires the review to name
    exactly those hashes, and each of them to be a release checker of the publication unless
    the operator accepted it by its hash.
    """
    admitted = sorted({campaign.tools.checker_sha256, *campaign.admit.checker_sha256})
    if list(review.checker_sha256) != admitted:
        raise ClaimRefused(
            "claim.review_checker",
            f"the review names the checkers {list(review.checker_sha256)}, the campaign admits "
            f"{admitted}",
        )
    accepted_set = set(accepted)
    unknown = sorted(accepted_set - set(admitted))
    if unknown:
        raise ClaimRefused(
            "claim.checker_unknown", f"--accept-checker for checkers the campaign lacks: {unknown}"
        )
    release = set(publication.checkers)
    foreign = [sha for sha in pins.unpinned(admitted, release) if sha not in accepted_set]
    if foreign:
        raise ClaimRefused(
            "claim.checker",
            f"the campaign admits the checker {', '.join(foreign)}, which is not the cake_lpr "
            f"binary of this release ({', '.join(sorted(release))}); a certificate of such a "
            "campaign says nothing until that program is known to be a correct checker "
            "(--accept-checker SHA256 states that it is)",
        )
    redundant = sorted(accepted_set & release)
    if redundant:
        raise ClaimRefused(
            "claim.checker_unknown",
            f"--accept-checker for a checker that is the release binary: {redundant}",
        )
    return tuple((sha, sha in release) for sha in admitted)


def _used_tools(
    certificate: Mapping[str, Any], checkers: tuple[tuple[str, bool], ...]
) -> tuple[tuple[str, ...], tuple[tuple[str, tuple[str, ...]], ...], tuple[str, ...]]:
    """The checkers, solvers and cubeproof sources named by the records the certificate uses
    (its ``machinery``): a defect found later in one release names the leaves to recheck.

    ``admit`` says what a campaign would believe; the machinery snapshots of the used records
    say what was written. The certifier admitted those records, so every such checker is one of
    the judged ones; anything else is a defect of the certificate, not of the campaign.
    """
    snapshots = [entry["machinery"] for entry in certificate["machinery"]]
    used = tuple(sorted({snapshot["checker"]["sha256"] for snapshot in snapshots}))
    stray = sorted(set(used) - {sha for sha, _ in checkers})
    if stray:
        raise ClaimRefused(
            "claim.checker", f"records of the certificate name checkers never admitted: {stray}"
        )
    solvers = {
        (snapshot["solver"]["sha256"], tuple(snapshot["solver"]["argv"])) for snapshot in snapshots
    }
    sources = tuple(sorted({snapshot["cubeproof_sha256"] for snapshot in snapshots}))
    return used, tuple(sorted(solvers)), sources


def _rebuild(campaign: Campaign, campaign_path: Path, publication: Publication) -> None:
    root = campaign_path.parent
    for entry in campaign.formulas:
        published = publication.formulas[entry.formula_sha256]
        try:
            verified = read_bundle(root / entry.bundle, published.load_map())
        except InterpretError as error:
            raise ClaimRefused("claim.bundle", f"{entry.key}: {error}") from None
        spec = verified.spec
        if (verified.formula_sha256, spec.layers, spec.gauge_face) != (
            published.formula_sha256,
            published.layers,
            published.gauge_face,
        ):
            raise ClaimRefused(
                "claim.parameters",
                f"{entry.key}: layers {spec.layers!r}, gauge {spec.gauge_face!r} are not the "
                f"published {published.layers!r}, gauge {published.gauge_face!r}",
            )


def claim(
    evidence: Path,
    review: Path,
    article: Path,
    *,
    publication: Publication | None = None,
    accept_checkers: Iterable[str] = (),
) -> ClaimResult:
    """Run the gate (module doc); :class:`ClaimRefused` or a cubeproof error when it refuses."""
    published = publication if publication is not None else Publication.corpus12()
    attestation = read_review(review)
    verified = load_evidence(Path(evidence))
    result = certify(verified.campaign, verified.journals)
    if result.document != verified.certificate.read_bytes():
        raise ClaimRefused(
            "claim.certificate",
            f"{evidence}: the packaged certificate is not the certificate of its campaign and "
            "journals",
        )
    certificate = result.certificate
    _verdict(certificate)
    certificate_file_sha256 = verified.manifest.certificate.sha256
    if attestation.certificate_file_sha256 != certificate_file_sha256:
        raise ClaimRefused(
            "claim.review_certificate",
            f"the review attests certificate {attestation.certificate_file_sha256}, "
            f"the evidence holds {certificate_file_sha256}",
        )
    try:
        article_sha256 = _file_sha256(Path(article))
    except OSError as error:
        raise InputError("claim.article", f"{article}: {error.strerror or error}") from None
    if attestation.article_sha256 != article_sha256:
        raise ClaimRefused(
            "claim.review_article",
            f"the review attests article {attestation.article_sha256}, {article} is "
            f"{article_sha256}",
        )
    formulas = _formulas(certificate, published)
    anomalies = _anomalies(certificate, attestation)
    root = Path(review).resolve().parent
    for obligation in attestation.obligations:
        if obligation.evidence is not None:
            _verify_artifact(root, obligation.evidence, obligation.name)
    campaign = _campaign(verified.campaign)
    checkers = _checkers(campaign, attestation, published, accept_checkers)
    used_checkers, used_solvers, used_sources = _used_tools(certificate, checkers)
    _rebuild(campaign, verified.campaign, published)
    return ClaimResult(
        campaign_id=certificate["campaign"],
        certificate_file_sha256=certificate_file_sha256,
        certificate_id=json_sha256(certificate),
        article_sha256=article_sha256,
        reviewer=attestation.reviewer,
        review_utc=attestation.utc,
        publication=published.name,
        formulas=formulas,
        anomalies=anomalies,
        obligations=attestation.obligations,
        checkers=checkers,
        used_checkers=used_checkers,
        used_solvers=used_solvers,
        used_sources=used_sources,
    )
