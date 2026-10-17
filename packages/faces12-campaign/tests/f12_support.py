"""Test-only helpers of the faces12-campaign tests: worlds of real files.

- :func:`tools` writes two distinct executable files as the pinned solver and checker: the
  application tests never run a solver; campaigns only hash these files.
- :class:`World` is a directory with the bundles of some maps (written by the application's
  own ``formulas`` export), a campaign made by ``campaign init``, journals fabricated with the
  plain builder of the certifier tests (``cp_certify_support``: J, node IDs, CNF bytes and
  the hash chain transcribed from the specification without the certifier), and an evidence
  directory packaged by cubeproof. Fabricated VERIFIED_UNSAT records are attestations, which
  is exactly what a certificate rests on (paper: rem:attestation); no proof is checked here.
- :func:`review` writes a ``faces12-claim-review-1`` document.

Nothing here is imported by runtime code.
"""

from __future__ import annotations

import hashlib
import json
import sys
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
CERTIFY_TESTS = REPO / "packages" / "cubeproof" / "tests" / "certify"
if str(CERTIFY_TESTS) not in sys.path:
    sys.path.insert(0, str(CERTIFY_TESTS))

import cp_certify_support as cs  # noqa: E402

from cubeproof import api as cubeproof_api  # noqa: E402
from cubeproof.base.canonical_json import document_bytes  # noqa: E402
from cubeproof.commands import CampaignRequest, PackageRequest, create_campaign  # noqa: E402
from cubeproof.contracts.campaign import Admit  # noqa: E402
from cubeproof.contracts.policy import default_policy  # noqa: E402
from faces12_campaign import commands  # noqa: E402
from faces12_campaign.campaign import PROOF_PREFIX_RNG  # noqa: E402
from faces12_campaign.formulas import export_formulas  # noqa: E402

__all__ = [
    "PREFIX_CASES",
    "REPO",
    "Tools",
    "World",
    "artifact",
    "certificate_file_sha256",
    "cs",
    "fixture_prefix",
    "make_world",
    "proof_prefix_splitter_info",
    "raw_campaign",
    "review",
    "sha",
    "stored_prefixes",
    "tools",
    "write_json",
]

PREFIX_CASES = REPO / "tests" / "contracts" / "corpus" / "prefix_cases" / "cases.json"
ARTICLE = REPO / "paper" / "faces12-en.tex"


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def write_json(path: Path, document: Any) -> Path:
    """A canonical document file (J plus LF)."""
    path.write_bytes(document_bytes(document))
    return path


@dataclass(frozen=True)
class Tools:
    solver: Path
    checker: Path

    @property
    def solver_sha256(self) -> str:
        return sha(self.solver.read_bytes())

    @property
    def checker_sha256(self) -> str:
        return sha(self.checker.read_bytes())


def _stand_in(name: str) -> str:
    return f"#!/bin/sh\n# {name} stand-in: never run by these tests\nexit 1\n"


#: The hash of the checker stand-in: not the release cake_lpr, so campaigns of these tests are
#: created with ``unpinned_checker`` and claimed against a publication that names this hash.
STAND_IN_CHECKER: Final = hashlib.sha256(_stand_in("cake_lpr").encode()).hexdigest()


def tools(directory: Path) -> Tools:
    """Two executable files with different contents, standing for the pinned tools."""
    directory.mkdir(parents=True, exist_ok=True)
    found = []
    for name in ("cadical", "cake_lpr"):
        path = directory / name
        path.write_text(_stand_in(name))
        path.chmod(0o755)
        found.append(path)
    return Tools(found[0], found[1])


def proof_prefix_splitter_info(solver_sha256: str, count: int, **changes: Any) -> dict[str, Any]:
    """The splitter info ``proof-prefix-v1`` records (cubeproof.split.proof_prefix)."""
    info: dict[str, Any] = {
        "algorithm": "proof-prefix-v1",
        "samples": 2,
        "steps": 100000,
        "conflicts": 90000,
        "seed": 5,
        "pool": "order",
        "rng": PROOF_PREFIX_RNG,
        "solver": {"sha256": solver_sha256, "options": []},
        "occurrences": [1] * count,
    }
    info.update(changes)
    return info


def fixture_prefix(map_id: int) -> list[int]:
    """The 12 proof-prefix variables of map 1 or 2 from the frozen prefix-case corpus."""
    cases = json.loads(PREFIX_CASES.read_text(encoding="utf-8"))["cases"]
    variables: list[int] = next(c for c in cases if c["map"] == map_id)["prefix_variables"]
    return variables[:12]


def stored_prefixes(
    entries: Sequence[tuple[str, Sequence[int]]],
    solver_sha256: str,
    *,
    name: str = "proof-prefix-v1",
    cube: Sequence[int] = (),
    **info_changes: Any,
) -> dict[str, Any]:
    """A ``cubeproof-prefixes-1`` document of proof prefixes ``(formula hash, W)``."""
    ordered = sorted(entries, key=lambda e: cs.split_id(e[0], list(cube), list(e[1])))
    return {
        "format": "cubeproof-prefixes-1",
        "splits": [
            {
                "node": {"formula_sha256": formula, "cube": list(cube)},
                "variables": list(w),
                "splitter": {
                    "name": name,
                    "info": proof_prefix_splitter_info(solver_sha256, len(w), **info_changes),
                },
            }
            for formula, w in ordered
        ],
    }


class _Facts:
    """What cp_certify_support's builder records for its oracle (unused here)."""

    def __init__(self) -> None:
        self.verified: dict[Any, Any] = {}
        self.models: set[Any] = set()

    def add_split(self, key: Any, variables: Sequence[int]) -> None:
        return None


@dataclass
class World:
    """Bundles, tools, a campaign, fabricated journals and an evidence package below ``root``."""

    root: Path
    maps: tuple[int, ...]
    tools: Tools
    campaign: Path = field(init=False)
    formulas: dict[str, bytes] = field(init=False)
    hashes: dict[str, str] = field(init=False)
    campaign_id: str = field(init=False)
    facts: _Facts = field(init=False, default_factory=_Facts)

    @property
    def bundles(self) -> Path:
        return self.root / "formulas"

    def init(self, **choices: Any) -> Path:
        """``campaign init`` of this world's maps (prefix 0 unless chosen) -> campaign.json."""
        self.campaign = self.root / choices.pop("name", "campaign.json")
        values: dict[str, Any] = {
            "formulas": self.bundles,
            "output": self.campaign,
            "solver": str(self.tools.solver),
            "solver_argv": ("--lrat",),
            "checker": str(self.tools.checker),
            "author": "faces12 tests",
            "maps": list(self.maps),
            "prefix": 0,
            "unpinned_checker": True,
        }
        values.update(choices)
        commands.campaign_init(commands.InitCommand(**values))
        self.load()
        return self.campaign

    def load(self) -> None:
        """Read the campaign: formula keys, hashes and bytes, its ID."""
        data = self.campaign.read_bytes()
        document = json.loads(data)
        self.campaign_id = sha(data[:-1])
        self.hashes = {e["key"]: e["formula_sha256"] for e in document["formulas"]}
        self.formulas = {
            e["key"]: (self.campaign.parent / e["bundle"] / "formula.cnf").read_bytes()
            for e in document["formulas"]
        }

    # the duck-typed scenario of cp_certify_support.JournalBuilder
    def sha(self, key: str) -> str:
        return self.hashes[key]

    def path(self, name: str) -> Path:
        return self.root / name

    def journal(self, worker: str = "w1") -> Any:
        """A journal builder whose header machinery uses this world's checker (admitted)."""
        machinery = cs.machinery(checker=self.tools.checker_sha256)
        return cs.JournalBuilder(self, worker, machinery=machinery)  # type: ignore[arg-type]

    def proved_journal(self, keys: Sequence[str] | None = None, worker: str = "w1") -> Path:
        """One VERIFIED_UNSAT attestation at the empty cube of each formula of ``keys``."""
        builder = self.journal(worker)
        for key in sorted(self.hashes) if keys is None else keys:
            builder.unsat(key, [])
        written: Path = builder.write(f"{worker}.jsonl")
        return written

    def package(self, journals: Sequence[Path], name: str = "evidence") -> Path:
        """The evidence directory of the journals (cubeproof ``evidence package``)."""
        output = self.root / name
        cubeproof_api.package(PackageRequest(self.campaign, list(journals), output))
        return output / "evidence.json"


def raw_campaign(world: World) -> None:
    """A campaign over every bundle of the world made by cubeproof directly (no application
    check), as somebody could make one."""
    world.campaign = world.root / "campaign.json"
    admit = {"checker_sha256": [world.tools.checker_sha256], "solvers": None}
    create_campaign(
        CampaignRequest(
            bundles=sorted(world.bundles.iterdir()),
            policy=default_policy("transient"),
            admit=Admit.from_json(admit, "$"),
            solver=str(world.tools.solver),
            solver_argv=["--lrat"],
            checker=str(world.tools.checker),
            output=world.campaign,
            author="faces12 tests",
        )
    )
    world.load()


def make_world(root: Path, maps: Sequence[int]) -> World:
    """Tools and the bundles of ``maps`` below ``root`` (no campaign yet)."""
    world = World(root, tuple(maps), tools(root / "tools"))
    export_formulas(world.bundles, maps)
    return world


def review(
    path: Path,
    *,
    certificate_file_sha256: str,
    article_sha256: str | None = None,
    checker_sha256: Sequence[str] = (STAND_IN_CHECKER,),
    obligations: Sequence[Mapping[str, Any]] | None = None,
    dispositions: Sequence[Mapping[str, Any]] = (),
    reviewer: str = "A. Reviewer",
    utc: str = "2026-10-09T12:00:00.000Z",
    transform: Callable[[dict[str, Any]], None] | None = None,
) -> Path:
    """A canonical review attestation (all obligations outstanding unless given)."""
    document: dict[str, Any] = {
        "format": "faces12-claim-review-1",
        "certificate_file_sha256": certificate_file_sha256,
        "article_sha256": article_sha256 or sha(ARTICLE.read_bytes()),
        "checker_sha256": list(checker_sha256),
        "reviewer": reviewer,
        "utc": utc,
        "obligations": list(obligations)
        if obligations is not None
        else [
            {"name": n, "status": "outstanding", "evidence": None, "note": ""}
            for n in ("encoding", "enumeration", "reduction")
        ],
        "anomaly_dispositions": list(dispositions),
    }
    if transform is not None:
        transform(document)
    return write_json(path, document)


def artifact(root: Path, relative: str, content: bytes) -> dict[str, Any]:
    """Write ``root/relative`` and return its Artifact descriptor."""
    target = root / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(content)
    return {"path": relative, "sha256": sha(content), "bytes": len(content)}


def certificate_file_sha256(manifest: Path) -> str:
    """The certificate Artifact hash of an evidence manifest."""
    value: str = json.loads(manifest.read_text(encoding="utf-8"))["certificate"]["sha256"]
    return value
