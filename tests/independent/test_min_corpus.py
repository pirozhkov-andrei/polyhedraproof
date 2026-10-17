"""The frozen evidence cases of the contract corpus with their expected certificates or errors.

Specification §10; reading 6 of ``schemas/cubeproof/v1/requirements.json`` fixes the error
kinds.

Each case is run through the API and through the command line. A valid case must produce the
expected certificate byte for byte and its exit code; a failing case must exit 4, name the
expected error kind and rule, and leave no certificate behind.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from support import CORPUS, TOOL, corpus_json, load_tool

tool = load_tool()
CASES = corpus_json("cases.json")["cases"]


def paths(case: dict) -> tuple[Path, list[Path]]:
    return CORPUS / case["campaign"], [CORPUS / p for p in case["journals"]]


class CorpusApi(unittest.TestCase):
    def test_case_count(self) -> None:
        self.assertGreaterEqual(len(CASES), 90)

    def test_cases(self) -> None:
        for case in CASES:
            with self.subTest(id=case["id"]):
                campaign, journals = paths(case)
                expect = case["expect"]
                if "certificate" in expect:
                    result = tool.certify(campaign, journals)
                    wanted = (CORPUS / expect["certificate"]).read_bytes()
                    self.assertEqual(result.certificate_bytes, wanted, case["id"])
                    self.assertEqual(result.exit_code, expect["exit"], case["id"])
                else:
                    with self.assertRaises(tool.CertifyError) as caught:
                        tool.certify(campaign, journals)
                    error = caught.exception
                    self.assertEqual(
                        (error.kind, error.rule),
                        (expect["error"]["kind"], expect["error"]["rule"]),
                        case["id"],
                    )
                    self.assertEqual(error.exit_code, 4)

    def test_input_order_has_no_effect(self) -> None:
        for case in CASES:
            if "certificate" not in case["expect"] or len(case["journals"]) < 2:
                continue
            campaign, journals = paths(case)
            forward = tool.certify(campaign, journals).certificate_bytes
            backward = tool.certify(campaign, list(reversed(journals))).certificate_bytes
            self.assertEqual(forward, backward, case["id"])

    def test_failing_cases_in_any_order(self) -> None:
        for case in CASES:
            if "error" not in case["expect"] or len(case["journals"]) < 2:
                continue
            campaign, journals = paths(case)
            with self.assertRaises(tool.CertifyError) as caught:
                tool.certify(campaign, list(reversed(journals)))
            self.assertEqual(caught.exception.rule, case["expect"]["error"]["rule"], case["id"])

    def test_duplicate_inputs_are_reported(self) -> None:
        case = next(c for c in CASES if c["id"] == "duplicates")
        campaign, journals = paths(case)
        result = tool.certify(campaign, journals)
        reported = {Path(d["path"]).name for d in result.duplicates}
        self.assertEqual(reported, {"w1-prefix.jsonl", "w1-torn.jsonl"})
        self.assertTrue(all(d["used"].endswith("duplicates/w1.jsonl") for d in result.duplicates))

    def test_the_same_file_twice_counts_once(self) -> None:
        case = next(c for c in CASES if c["id"] == "base")
        campaign, journals = paths(case)
        result = tool.certify(campaign, journals + journals)
        self.assertEqual(
            result.certificate_bytes, (CORPUS / case["expect"]["certificate"]).read_bytes()
        )


class CorpusCli(unittest.TestCase):
    def run_cli(self, case: dict, out: Path) -> subprocess.CompletedProcess[str]:
        campaign, journals = paths(case)
        argv = [sys.executable, str(TOOL), "certify", "--campaign", str(campaign)]
        if journals:
            argv += ["--journals", *map(str, journals)]
        argv += ["-o", str(out)]
        return subprocess.run(argv, capture_output=True, text=True, check=False)

    def test_cases(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            for case in CASES:
                with self.subTest(id=case["id"]):
                    out = Path(tmp) / (case["id"] + ".json")
                    done = self.run_cli(case, out)
                    expect = case["expect"]
                    self.assertEqual(done.returncode, expect["exit"], done.stderr)
                    report = json.loads(done.stdout)
                    if "certificate" in expect:
                        wanted = (CORPUS / expect["certificate"]).read_bytes()
                        self.assertEqual(out.read_bytes(), wanted)
                        self.assertEqual(report["verdict"], json.loads(wanted)["verdict"])
                        self.assertIsNone(report["error"])
                    else:
                        self.assertFalse(out.exists())
                        self.assertEqual(report["error"]["kind"], expect["error"]["kind"])
                        self.assertEqual(report["error"]["rule"], expect["error"]["rule"])

    def test_usage_errors_exit_3(self) -> None:
        done = subprocess.run(
            [sys.executable, str(TOOL), "certify", "--campaign"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(done.returncode, 3)

    def test_missing_campaign_is_an_input_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "c.json"
            done = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "certify",
                    "--campaign",
                    str(Path(tmp) / "none.json"),
                    "-o",
                    str(out),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(done.returncode, 4)
            self.assertEqual(json.loads(done.stdout)["error"]["kind"], "input")
            self.assertFalse(out.exists())


class Compare(unittest.TestCase):
    """The comparison driver reports agreement field by field (specification §10.5)."""

    def test_identical(self) -> None:
        cert = CORPUS / "certificates" / "base.json"
        self.assertEqual(tool.compare_certificates(cert.read_bytes(), cert.read_bytes()), [])

    def test_differences_are_named(self) -> None:
        a = json.loads((CORPUS / "certificates" / "frontier.json").read_bytes())
        b = json.loads((CORPUS / "certificates" / "frontier.json").read_bytes())
        b["open"] = b["open"][:-1]
        b["verdict"] = "PROVED"
        found = tool.compare_certificates(
            tool.canonical_json(a) + b"\n", tool.canonical_json(b) + b"\n"
        )
        self.assertEqual(sorted(d["field"] for d in found), ["open", "verdict"])

    def test_cli_against_the_corpus(self) -> None:
        done = subprocess.run(
            [sys.executable, str(TOOL), "corpus", "--corpus", str(CORPUS)],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        summary = json.loads(done.stdout)
        self.assertEqual(summary["failed"], [])
        self.assertEqual(summary["passed"], len(CASES))


if __name__ == "__main__":
    unittest.main()
