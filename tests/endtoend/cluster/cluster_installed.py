"""The installed multi-worker run: the RELEASE image and its documented wrapper.

    python3 tests/endtoend/cluster/cluster_installed.py IMAGE OUT_DIR

Two workers of one campaign run in containers of the release image (specification §14),
started, stopped, crashed and recreated only through ``pipeline/faces12-worker.sh`` and
``docker kill``:

1. The campaign (pigeonhole 7->6 and 8->7 split statically by three variables, pigeonhole
   11->10 by one; 1 s leaves, so the pigeonhole 11->10 halves split further) is created and
   planned for two machines **inside the image** (``cubeproof bundle import``, ``campaign
   create``, ``shard``) with the image's admitted tools; the second machine gets a byte copy
   of the immutable inputs.
2. Worker A (transient) is launched with shard 1; a handoff request is answered while it runs
   (``docker exec ... cubeproof handoff --wait-ms``); then A is crashed (``docker kill``, i.e.
   SIGKILL of the container's process tree) and started again.
3. The published shard is delivered into B's inbox (the user's file transfer); worker B
   (retain mode) is launched with shard 2, crashed after it accepted both shards, started again.
4. A is stopped cleanly (``stop``, ``docker stop -t 120``) and started; B's container is
   recreated (its volumes kept). Both run to the end.
5. The exported journals (the clean-stop exports below each ``--io``) must equal the journals
   in the results volumes; the installed certifier (in the image) and the checkout's main and
   independent certifiers must write byte-identical PROVED certificates; the strict recompute
   audit of every used leaf and ``verify-retained`` of B's proofs run in the image.

Host paths contain spaces on purpose. Everything goes below OUT_DIR: ``transcript.log`` (every
command, its output and exit code) and ``result.json`` (facts and ``problems``; exit 0 when
empty). Only the containers and volumes of its own two workers (``e2e-installed-a-TAG``,
``e2e-installed-b-TAG``) are removed, before and after the run (``E2E_CLUSTER_KEEP_WORKERS=1``
keeps them afterwards). Duration on an 8-core host: about five minutes. Not a performance
measurement.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
for _path in (HERE.parent / "single", REPO / "tests", REPO / "packages" / "cubeproof" / "src"):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

import e2e_harness as e2e  # noqa: E402

from cubeproof.base.canonical_json import document_bytes  # noqa: E402
from cubeproof.contracts.identity import node_id, split_id  # noqa: E402

WRAPPER = REPO / "pipeline" / "faces12-worker.sh"
ENTRY = ("/opt/faces12/venv/bin/python", "-I", "/opt/faces12/entrypoint.py")
SOLVER_ARGV = ["-q", "--lrat"]
FORMULAS = {"php6": 6, "php7": 7, "php10": 10}
SPLIT = {"php6": [1, 2, 3], "php7": [1, 2, 3], "php10": [1]}


class Run:
    """One installed run: its directories, transcript, facts and problems."""

    def __init__(self, image: str, out: Path) -> None:
        self.image = image
        self.out = out
        tag = hashlib.sha256(str(out).encode()).hexdigest()[:6]
        self.a, self.b = f"e2e-installed-a-{tag}", f"e2e-installed-b-{tag}"
        self.io = {self.a: out / "worker a io", self.b: out / "worker b io"}
        self.log = out / "transcript.log"
        self.problems: list[str] = []
        self.facts: dict[str, Any] = {"image": image, "workers": [self.a, self.b]}
        self.env = {**os.environ, "POLYHEDRAPROOF_IMAGE": image}

    # -- commands ------------------------------------------------------------------------------

    def sh(
        self, *argv: str, check: bool = False, timeout: float = 1800.0
    ) -> subprocess.CompletedProcess[str]:
        started = time.monotonic()
        done = subprocess.run(
            list(argv), capture_output=True, text=True, timeout=timeout, check=False, env=self.env
        )
        with open(self.log, "a", encoding="utf-8") as log:
            log.write(f"\n$ {' '.join(argv)}\n{done.stdout[-6000:]}{done.stderr[-3000:]}")
            log.write(f"# exit={done.returncode} seconds={time.monotonic() - started:.1f}\n")
        if check and done.returncode != 0:
            self.problems.append(f"{' '.join(argv[:5])} ...: exit {done.returncode}")
        return done

    def note(self, text: str) -> None:
        with open(self.log, "a", encoding="utf-8") as log:
            log.write(f"\n# {text}\n")

    def wrapper(self, command: str, worker: str, *more: str) -> subprocess.CompletedProcess[str]:
        return self.sh(
            "bash", str(WRAPPER), command, "--worker", worker, *more, check=command != "status"
        )

    def in_image(
        self, *args: str, mounts: Sequence[tuple[str, str]] = ()
    ) -> subprocess.CompletedProcess[str]:
        user = f"{os.getuid()}:{os.getgid()}"
        argv = ["docker", "run", "--rm", "--init", "--network", "none", "--user", user]
        for source, target in mounts:
            argv += ["-v", f"{source}:{target}"]
        return self.sh(*argv, self.image, *args)

    def state(self, worker: str) -> str:
        done = subprocess.run(
            ["docker", "container", "inspect", "--format", "{{.State.Status}} {{.State.ExitCode}}",
             f"faces12-{worker}"],
            capture_output=True, text=True, check=False,
        )  # fmt: skip
        return done.stdout.strip() or "absent"

    def records(self, worker: str) -> list[dict[str, Any]]:
        """The complete records of a worker's journal, read from its results volume."""
        done = subprocess.run(
            ["docker", "run", "--rm", "--network", "none", "--entrypoint", "cat", "-v",
             f"faces12-results-{worker}:/work/results:ro", self.image,
             "/work/results/journal.jsonl"],
            capture_output=True, check=False,
        )  # fmt: skip
        data = done.stdout[: done.stdout.rfind(b"\n") + 1]
        return [json.loads(line) for line in data.splitlines()]

    def wait_records(
        self, worker: str, condition: Callable[[list[dict[str, Any]]], bool], timeout: float = 900.0
    ) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if condition(self.records(worker)):
                return True
            if not self.state(worker).startswith("running"):
                return False
            time.sleep(1.0)
        return False

    def wait_exit(self, worker: str, timeout: float = 3600.0) -> str:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            current = self.state(worker)
            if not current.startswith("running"):
                self.note(f"{worker}: {current}")
                return current
            time.sleep(2.0)
        self.problems.append(f"{worker} still running after {timeout:.0f} s")
        return self.state(worker)

    def cleanup(self) -> None:
        for worker in (self.a, self.b):
            subprocess.run(
                ["docker", "rm", "-f", f"faces12-{worker}"], capture_output=True, check=False
            )
            subprocess.run(
                ["docker", "volume", "rm", f"faces12-results-{worker}", f"faces12-work-{worker}"],
                capture_output=True, check=False,
            )  # fmt: skip

    # -- the run -------------------------------------------------------------------------------

    def campaign(self) -> bool:
        """Inputs on the host, bundles/campaign/shards inside the image, copy for machine B."""
        tools = self.sh(
            "docker", "run", "--rm", "--network", "none", "--entrypoint", "sha256sum", self.image,
            "/opt/faces12/bin/cadical", "/opt/faces12/bin/cake_lpr", check=True,
        ).stdout.split()  # fmt: skip
        if len(tools) < 4:
            return False
        solver, checker = tools[0], tools[2]
        self.facts["tools"] = {"cadical": solver, "cake_lpr": checker}
        io = self.io[self.a]
        inputs = io / "inputs"
        inputs.mkdir(parents=True)
        entries = []
        for key, holes in FORMULAS.items():
            data = e2e.pigeonhole_formula(holes)
            (inputs / f"{key}.cnf").write_bytes(data)
            entries.append((hashlib.sha256(data).hexdigest(), SPLIT[key]))
        entries.sort(key=lambda e: split_id(node_id(e[0], []), e[1]))
        policy = e2e.pinned_policy(2, leaf_default_ms=1000).to_json()
        (inputs / "policy.json").write_bytes(document_bytes(policy))
        admit = {"checker_sha256": [checker], "solvers": [{"sha256": solver, "argv": SOLVER_ARGV}]}
        (inputs / "admit.json").write_bytes(document_bytes(admit))
        splits = [
            {
                "node": {"formula_sha256": formula, "cube": []},
                "variables": variables,
                "splitter": {
                    "name": "static",
                    "info": {"order": variables, "prefix": len(variables)},
                },
            }
            for formula, variables in entries
        ]
        prefixes = {"format": "cubeproof-prefixes-1", "splits": splits}
        (inputs / "prefixes.json").write_bytes(document_bytes(prefixes))
        mount = [(str(io), "/io")]
        bundles: list[str] = []
        for key in FORMULAS:
            done = self.in_image(
                "cubeproof", "bundle", "import", f"/io/inputs/{key}.cnf",
                "-o", f"/io/bundles/{key}", mounts=mount,
            )  # fmt: skip
            if done.returncode != 0:
                self.problems.append(f"bundle import {key}: exit {done.returncode}")
                return False
            bundles += ["--bundle", f"/io/bundles/{key}"]
        created = self.in_image(
            "cubeproof", "campaign", "create", *bundles, "--policy", "/io/inputs/policy.json",
            "--admit", "/io/inputs/admit.json", "--solver-argv", json.dumps(SOLVER_ARGV),
            "--root-split", "static:/io/inputs/prefixes.json", "--author", "e2e-installed",
            "-o", "/io/campaign.json", mounts=mount,
        )  # fmt: skip
        planned = self.in_image(
            "cubeproof", "shard", "--campaign", "/io/campaign.json", "--machines", "2",
            "-o", "/io/shards", mounts=mount,
        )  # fmt: skip
        if created.returncode != 0 or planned.returncode != 0:
            self.problems.append(
                f"campaign create {created.returncode}, shard {planned.returncode}"
            )
            return False
        for name in ("campaign.json", "bundles", "shards"):
            source, target = io / name, self.io[self.b] / name
            if source.is_dir():
                shutil.copytree(source, target)
            else:
                shutil.copyfile(source, target)
        self.facts["campaign_sha256"] = hashlib.sha256(
            (io / "campaign.json").read_bytes()
        ).hexdigest()
        return True

    def workers(self) -> None:
        a, b = self.a, self.b
        self.wrapper(
            "launch",
            a,
            "--io",
            str(self.io[a]),
            "--shard",
            "shards/shard-1.json",
            "--",
            "--jobs",
            "3",
        )
        if not self.wait_records(a, lambda rows: sum(r["type"] == "attempt" for r in rows) >= 3):
            self.problems.append("worker A made no progress")
        asked = self.sh(
            "docker", "exec", f"faces12-{a}", *ENTRY, "cubeproof", "handoff", "--results",
            "/work/results", "--nodes", "3", "--output-name", "gift", "--wait-ms", "120000",
        )  # fmt: skip
        answer = e2e._document(asked.stdout) or {}
        self.facts["handoff"] = {
            "exit": asked.returncode,
            "state": answer.get("state"),
            "response": answer.get("response"),
        }
        if asked.returncode != 0 or answer.get("state") != "completed":
            self.problems.append(f"handoff: exit {asked.returncode}, state {answer.get('state')}")
        self.note("crash of worker A: docker kill (SIGKILL of the container's process tree)")
        self.sh("docker", "kill", f"faces12-{a}", check=True)
        self.facts["a_after_kill"] = self.state(a)
        self.wrapper("start", a)
        gift = self.io[a] / "outbox" / "gift.json"
        inbox = self.io[b] / "inbox"
        inbox.mkdir(parents=True, exist_ok=True)
        if gift.exists():
            shutil.copyfile(gift, inbox / ".gift.json.part")
            os.replace(inbox / ".gift.json.part", inbox / "gift.json")
        else:
            self.problems.append("no handoff output to deliver")
        run_b = ("--", "--jobs", "3", "--proof-mode", "retain")
        self.wrapper("launch", b, "--io", str(self.io[b]), "--shard", "shards/shard-2.json", *run_b)
        accepted = self.wait_records(
            b,
            lambda rows: (
                sum(r["type"] == "shard" for r in rows) >= 2
                and sum(r["type"] == "attempt" for r in rows) >= 2
            ),
        )
        if not accepted:
            self.problems.append("worker B did not accept the delivered shard while running")
        self.note("crash of worker B: docker kill")
        self.sh("docker", "kill", f"faces12-{b}", check=True)
        self.facts["b_after_kill"] = self.state(b)
        self.wrapper("start", b)
        time.sleep(5.0)
        self.note("clean stop and start of worker A; recreation of worker B's container")
        self.facts["a_before_stop"] = self.state(a)
        self.facts["b_before_recreate"] = self.state(b)
        if not self.facts["a_before_stop"].startswith("running"):
            self.problems.append("worker A had ended before the clean stop")
        self.wrapper("stop", a)
        self.facts["a_after_stop"] = self.state(a)
        self.wrapper("start", a)
        self.wrapper(
            "recreate", b, "--io", str(self.io[b]), "--shard", "shards/shard-2.json", *run_b
        )
        ends = {w: self.wait_exit(w) for w in (a, b)}
        self.facts["final_state"] = ends
        self.problems += [f"{w} ended {e}" for w, e in ends.items() if e != "exited 0"]
        self.wrapper("status", a)
        self.wrapper("status", b)
        self.sh("docker", "volume", "ls", "--filter", f"label=org.polyhedraproof.worker={b}")

    def evidence(self) -> None:
        a, b = self.a, self.b
        journals: dict[str, Path] = {}
        for worker in (a, b):
            descriptor = json.loads((self.io[worker] / "export" / "export.json").read_text())
            journals[worker] = self.io[worker] / "export" / str(descriptor["file"])
            live = self.records(worker)
            exported = [json.loads(x) for x in journals[worker].read_bytes().splitlines()]
            if exported != live:
                self.problems.append(f"{worker}: the export is not the whole journal")
            kinds = sorted({str(r["type"]) for r in live})
            self.facts[f"records_{worker}"] = {k: sum(r["type"] == k for r in live) for k in kinds}
        both = [(str(self.io[a]), "/io"), (str(self.io[b]), "/iob")]
        names = [f"/io/export/{journals[a].name}", f"/iob/export/{journals[b].name}"]
        installed = self.in_image(
            "cubeproof", "certify", "--campaign", "/io/campaign.json", "--journals", *names,
            "-o", "/io/certificate-installed.json", mounts=both,
        )  # fmt: skip
        host = e2e.certify_both(
            self.io[a] / "campaign.json", [journals[a], journals[b]], self.out / "certify-host"
        )
        path = self.io[a] / "certificate-installed.json"
        installed_bytes = path.read_bytes() if path.exists() else None
        self.facts["certify"] = {
            "installed_exit": installed.returncode,
            "host_exits": [host.main.code, host.independent.code],
            "installed_sha256": e2e._digest(installed_bytes),
            "host_main_sha256": e2e._digest(host.main_bytes),
            "host_min_sha256": e2e._digest(host.independent_bytes),
            "verdict": host.verdict if host.main_bytes is not None else None,
        }
        self.problems += [f"host certifiers: {p}" for p in host.problems()]
        if (
            installed_bytes is None
            or installed_bytes != host.main_bytes
            or installed.returncode != 0
        ):
            self.problems.append(
                "the installed certifier's certificate differs from the checkout's"
            )
        if host.main_bytes is None or host.verdict != "PROVED":
            self.problems.append("the campaign is not PROVED")
        else:
            self.facts["summaries"] = {f["key"]: f["summary"] for f in host.certificate["formulas"]}
        audited = self.in_image(
            "cubeproof", "audit", "--campaign", "/io/campaign.json", "--certificate",
            "/io/certificate-installed.json", "--journals", *names, "--all", "--comparison",
            "strict", "--results", "/io/audit/results", "--work", "/io/audit/work",
            "--worker", "audit", mounts=both,
        )  # fmt: skip
        summary = (e2e._document(audited.stdout) or {}).get("summary") or {}
        self.facts["audit"] = {"exit": audited.returncode, "summary": summary}
        if audited.returncode != 0 or not summary.get("strict_success"):
            self.problems.append(f"strict audit: exit {audited.returncode}")
        verified = self.in_image(
            "cubeproof", "verify-retained", "--campaign", "/io/campaign.json", "--journals",
            f"/io/export/{journals[b].name}", "--proofs-root", "/work/results", "--results",
            "/io/verify/results", "--work", "/io/verify/work", "--worker", "verify",
            mounts=[(str(self.io[b]), "/io"), (f"faces12-results-{b}", "/work/results:ro")],
        )  # fmt: skip
        document = e2e._document(verified.stdout) or {}
        self.facts["verify_retained"] = document
        if verified.returncode != 0 or not document.get("verified") or document.get("missing"):
            self.problems.append(f"verify-retained: exit {verified.returncode}")

    def main(self) -> int:
        if self.out.exists():
            shutil.rmtree(self.out)
        for io in self.io.values():
            io.mkdir(parents=True)
        commit = subprocess.run(
            ["git", "-C", str(REPO), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            check=False,
        ).stdout.strip()
        utc = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        self.log.write_text(
            f"# installed run utc={utc} checkout={REPO} commit={commit}\n", encoding="utf-8"
        )
        self.facts["commit"] = commit
        self.cleanup()
        self.facts["image_id"] = self.sh(
            "docker", "image", "inspect", "--format", "{{.Id}}", self.image, check=True
        ).stdout.strip()
        self.sh(
            "docker", "version", "--format", "{{.Server.Version}} {{.Server.Os}}/{{.Server.Arch}}"
        )
        self.sh("uname", "-srm")
        self.sh("nproc")
        try:
            if self.campaign():
                self.workers()
                self.evidence()
        finally:
            if os.environ.get("E2E_CLUSTER_KEEP_WORKERS") != "1":
                self.cleanup()
        result = {**self.facts, "problems": self.problems}
        (self.out / "result.json").write_text(json.dumps(result, indent=1, sort_keys=True) + "\n")
        print(
            json.dumps({"problems": self.problems, "certify": self.facts.get("certify")}, indent=1)
        )
        return 1 if self.problems else 0


def main(argv: Sequence[str]) -> int:
    if len(argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    return Run(argv[0], Path(argv[1]).resolve()).main()


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
