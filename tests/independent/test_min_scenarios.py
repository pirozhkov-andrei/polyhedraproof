"""Synthetic evidence for rules the frozen corpus exercises only partly.

Specification §7.1 and §10.1-§10.5.

Expected values are derived here from the text of the specification with the plain oracle
constructions of support.py; where the answer depends on a hash order, the test computes it.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from support import (
    JournalWriter,
    Scenario,
    cnf_text,
    j,
    load_tool,
    merkle,
    node_id,
    sha,
    split_id,
    write_document,
)

tool = load_tool()


def certificate(result) -> dict:
    return json.loads(result.certificate_bytes)


class Base(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def scenario(self, name: str = "all3") -> Scenario:
        return Scenario(self.root, name)


class Selection(Base):
    def test_smallest_closed_split_and_its_subtree(self) -> None:
        s = self.scenario()
        f = s.formula
        records = [s.split([-1], [2, 3]), s.split([], [2]), s.verified([1])]
        children = [[-1, -2, -3], [-1, 2, -3], [-1, -2, 3], [-1, 2, 3]]
        records += [s.verified(c) for c in children]
        records += [s.verified([-2]), s.verified([2])]
        path = s.journal("w1.jsonl", records)
        cert = certificate(tool.certify(s.campaign_path, [path]))
        by_one = split_id(node_id(f, []), [1]) < split_id(node_id(f, []), [2])
        leaves = [[1], *children] if by_one else [[-2], [2]]
        att = {tuple(r["node"]["cube"]): r for r in records if r["type"] == "attempt"}
        expected = merkle(
            [
                (node_id(f, c), att[tuple(c)]["cnf_sha256"], att[tuple(c)]["proof_sha256"])
                for c in leaves
            ]
        )
        summary = cert["formulas"][0]["summary"]
        if by_one:
            self.assertEqual(
                (summary["leaves"], summary["splits"], summary["max_cube_size"]), (5, 2, 3)
            )
        else:
            self.assertEqual(
                (summary["leaves"], summary["splits"], summary["max_cube_size"]), (2, 1, 1)
            )
        self.assertEqual(summary["leaf_merkle_root"], expected)
        self.assertEqual(cert["verdict"], "PROVED")
        used = sorted(u["node_id"] for u in cert["used_attempts"])
        self.assertEqual(used, sorted(node_id(f, c) for c in leaves))
        self.assertEqual(tool.certify(s.campaign_path, [path]).exit_code, 0)

    def test_an_attempt_is_preferred_to_a_closed_split(self) -> None:
        s = self.scenario()
        records = [s.verified([1]), s.verified([-1]), s.verified([])]
        cert = certificate(tool.certify(s.campaign_path, [s.journal("w1.jsonl", records)]))
        summary = cert["formulas"][0]["summary"]
        self.assertEqual(
            (summary["leaves"], summary["splits"], summary["max_cube_size"]), (1, 0, 0)
        )
        self.assertEqual([u["node"]["cube"] for u in cert["used_attempts"]], [[]])
        self.assertEqual([u["record"]["seq"] for u in cert["used_attempts"]], [3])

    def test_smallest_closed_split_at_a_nested_node(self) -> None:
        """Specification §10.2: the smallest closed split_id is chosen at every node of the
        selected tree, not only at the queried one."""
        s = self.scenario()
        f = s.formula
        records = [s.split([], [1]), s.split([1], [2]), s.split([1], [3])]
        cubes = [[-1], [1, -2], [1, 2], [1, -3], [1, 3]]
        records += [s.verified(c) for c in cubes]
        path = s.journal("w1.jsonl", records)
        cert = certificate(tool.certify(s.campaign_path, [path]))
        nested = node_id(f, [1])
        w = 2 if split_id(nested, [2]) < split_id(nested, [3]) else 3
        leaves = [[-1], [1, -w], [1, w]]
        att = {tuple(r["node"]["cube"]): r for r in records if r["type"] == "attempt"}
        seq = {  # the header is seq 0
            tuple(r["node"]["cube"]): i + 1 for i, r in enumerate(records) if r["type"] == "attempt"
        }
        self.assertEqual(cert["verdict"], "PROVED")
        ordered = sorted(leaves, key=lambda c: node_id(f, c))
        self.assertEqual(
            [(u["node_id"], u["record"]["seq"]) for u in cert["used_attempts"]],
            [(node_id(f, c), seq[tuple(c)]) for c in ordered],
        )
        summary = cert["formulas"][0]["summary"]
        self.assertEqual(
            (summary["leaves"], summary["splits"], summary["max_cube_size"]), (3, 2, 2)
        )
        expected = merkle(
            [
                (node_id(f, c), att[tuple(c)]["cnf_sha256"], att[tuple(c)]["proof_sha256"])
                for c in leaves
            ]
        )
        self.assertEqual(summary["leaf_merkle_root"], expected)

    def test_smallest_ref_orders_by_journal_before_seq(self) -> None:
        """Specification §10.2: the smallest admitted verified Ref is ordered by (journal ID,
        seq); the journal with the smaller ID wins even with a larger seq."""
        s = self.scenario()
        ids = {}
        for worker in ("w1", "w2"):
            writer = JournalWriter()
            writer.add(s.header(worker))
            ids[worker] = writer.id
        small, large = sorted(ids, key=lambda w: ids[w])
        late = s.verified([])
        early = s.verified([])
        paths = [
            s.journal("small.jsonl", [s.verified([1]), s.verified([-1]), late], worker=small),
            s.journal("large.jsonl", [early], worker=large),
        ]
        for order in (paths, list(reversed(paths))):
            cert = certificate(tool.certify(s.campaign_path, order))
            self.assertEqual(cert["verdict"], "PROVED")
            [used] = cert["used_attempts"]
            self.assertEqual((used["record"]["journal"], used["record"]["seq"]), (ids[small], 3))
            self.assertEqual(used["proof_sha256"], late["proof_sha256"])
            self.assertEqual(
                cert["formulas"][0]["summary"]["leaf_merkle_root"],
                merkle([(node_id(s.formula, []), late["cnf_sha256"], late["proof_sha256"])]),
            )

    def test_an_open_child_known_from_another_split_keeps_a_split_open(self) -> None:
        """Specification §10.2: a split closes only if all children are closed, also when an
        open child was already decided through another split."""
        s = self.scenario()
        f = s.formula
        records = [s.split([], [1, 2]), s.split([], [2, 1])]
        records += [s.verified(c) for c in ([1, 2], [-1, 2], [1, -2])]
        path = s.journal("w1.jsonl", records)
        result = tool.certify(s.campaign_path, [path])
        cert = certificate(result)
        self.assertEqual(cert["verdict"], "OPEN")
        self.assertEqual(result.exit_code, 1)
        self.assertFalse(cert["formulas"][0]["proved"])
        self.assertEqual(cert["used_attempts"], [])
        root = node_id(f, [])
        smallest = min((split_id(root, w), w) for w in ([1], [1, 2], [2, 1]))[1]
        frontier = [[-1], [1]] if smallest == [1] else [[-1, -2]]
        self.assertEqual(
            [o["node_id"] for o in cert["open"]], sorted(node_id(f, c) for c in frontier)
        )

    def test_an_open_node_shared_by_two_subtrees(self) -> None:
        """The diamond: [-1,-2] is open and reachable through [-1] and through [-2]; neither
        root split closes."""
        s = self.scenario()
        f = s.formula
        records = [s.split([], [1]), s.split([], [2]), s.split([-1], [2]), s.split([-2], [1])]
        records += [s.verified(c) for c in ([1], [2], [-1, 2], [1, -2])]
        path = s.journal("w1.jsonl", records)
        result = tool.certify(s.campaign_path, [path])
        cert = certificate(result)
        self.assertEqual(cert["verdict"], "OPEN")
        self.assertEqual(result.exit_code, 1)
        self.assertFalse(cert["formulas"][0]["proved"])
        self.assertEqual(cert["used_attempts"], [])
        self.assertEqual([o["node_id"] for o in cert["open"]], [node_id(f, [-1, -2])])
        self.assertEqual(cert["open"][0]["state"], "pending")

    def test_closure_is_literal_for_requested_roots(self) -> None:
        """Routine reading 8 of requirements.json: a closed ancestor does not close a requested
        root."""
        s = self.scenario("pilot")
        f = s.formula
        path = s.journal("w1.jsonl", [s.verified([])])
        result = tool.certify(s.campaign_path, [path])
        cert = certificate(result)
        formula = cert["formulas"][0]
        self.assertTrue(formula["proved"])
        self.assertEqual(formula["summary"]["leaves"], 1)
        self.assertEqual(formula["roots"][0]["cube"], [-1])
        self.assertFalse(formula["roots"][0]["closed"])
        self.assertEqual(formula["roots"][0]["summary"]["leaf_merkle_root"], None)
        self.assertEqual([o["node"]["cube"] for o in cert["open"]], [[-1]])
        self.assertEqual(cert["open"][0]["node_id"], node_id(f, [-1]))
        self.assertEqual(cert["formula_open"], [])
        self.assertEqual(cert["verdict"], "PROVED")
        self.assertEqual(result.exit_code, 0)


class MalformedSplits(Base):
    def test_every_w_problem_is_an_anomaly_and_ignored(self) -> None:
        s = self.scenario()
        bad = {
            "empty": [],
            "too_long": [2] * 21,
            "repeated": [2, 2],
            "out_of_range": [4],
            "in_cube": [1],
        }
        records = [s.verified([1])] + [s.split([-1], w) for w in bad.values()]
        path = s.journal("w1.jsonl", records)
        result = tool.certify(s.campaign_path, [path])
        cert = certificate(result)
        found = [(a["record"]["seq"], a["code"], a["info"]) for a in cert["anomalies"]]
        expected = [(i + 2, "malformed_split", {"problem": p}) for i, p in enumerate(bad)]
        self.assertEqual(found, expected)
        self.assertEqual([o["node"]["cube"] for o in cert["open"]], [[-1]])
        self.assertEqual(cert["open"][0]["state"], "pending")
        self.assertEqual(cert["verdict"], "OPEN")
        self.assertEqual(result.exit_code, 1)

    def test_a_malformed_split_with_an_invalid_parent_is_an_error(self) -> None:
        s = self.scenario()
        path = s.journal("w1.jsonl", [s.split([-1, 1], [])])
        with self.assertRaises(tool.CertifyError) as caught:
            tool.certify(s.campaign_path, [path])
        self.assertEqual(
            (caught.exception.kind, caught.exception.rule), ("integrity", "cube.canonical")
        )


class Admission(Base):
    def test_a_resume_changes_the_snapshot(self) -> None:
        s = self.scenario()
        resume = {
            "type": "resume",
            "utc": "2026-10-01T00:00:05.000Z",
            "machinery": dict(s.template[0]["machinery"]),
            "policy": s.template[0]["policy"],
            "resources": s.template[0]["resources"],
        }
        resume["machinery"]["checker"] = {"path": "/x/cake_lpr", "sha256": "ab" * 32}
        records = [s.verified([1]), resume, s.verified([-1])]
        path = s.journal("w1.jsonl", records)
        cert = certificate(tool.certify(s.campaign_path, [path]))
        self.assertEqual(
            [(x["record"]["seq"], x["reason"]) for x in cert["not_admitted"]],
            [(3, "checker_not_admitted")],
        )
        # Specification §4.9: machinery lists the snapshots of used records only, and
        # used_attempts are those in a reported closed summary. The root stays open, so the
        # admitted attempt on [1] is not used (frozen corpus: certificates/split_incomplete.json).
        self.assertEqual(cert["used_attempts"], [])
        self.assertEqual(cert["machinery"], [])
        self.assertEqual([o["node"]["cube"] for o in cert["open"]], [[-1]])
        self.assertEqual(cert["verdict"], "OPEN")

    def test_policy_hash_follows_the_latest_snapshot(self) -> None:
        s = self.scenario()
        policy = dict(s.template[0]["policy"], tool_retries=7)
        resume = {
            "type": "resume",
            "utc": "2026-10-01T00:00:05.000Z",
            "machinery": s.template[0]["machinery"],
            "policy": policy,
            "resources": s.template[0]["resources"],
        }
        good = s.verified([-1])
        good["policy_sha256"] = sha(j(policy))
        path = s.journal("w1.jsonl", [s.verified([1]), resume, good])
        self.assertEqual(certificate(tool.certify(s.campaign_path, [path]))["verdict"], "PROVED")
        stale = s.verified([-1])
        path = s.journal("w2.jsonl", [s.verified([1]), resume, stale])
        with self.assertRaises(tool.CertifyError) as caught:
            tool.certify(s.campaign_path, [path])
        self.assertEqual(caught.exception.rule, "attempt.policy_sha256")


class Journals(Base):
    def test_line_limit_is_a_resource_error(self) -> None:
        s = self.scenario()
        big = s.verified([1])
        big["diagnostics"] = {"pad": "x" * (8 * 1024 * 1024)}
        path = s.journal("w1.jsonl", [big])
        with self.assertRaises(tool.CertifyError) as caught:
            tool.certify(s.campaign_path, [path])
        self.assertEqual((caught.exception.kind, caught.exception.rule), ("resource", "limit.line"))

    def test_torn_tail_after_the_header(self) -> None:
        s = self.scenario()
        path = s.journal("w1.jsonl", [])
        data = path.read_bytes()
        path.write_bytes(data + b'{"assignment":null,')
        cert = certificate(tool.certify(s.campaign_path, [path]))
        [entry] = cert["journals"]
        self.assertEqual(
            (entry["records"], entry["bytes"], entry["torn_tail_bytes"]), (1, len(data), 19)
        )
        self.assertEqual(cert["verdict"], "OPEN")

    def test_a_prefix_copy_with_a_different_torn_tail_is_compatible(self) -> None:
        s = self.scenario()
        full = s.journal("w1.jsonl", [s.verified([1]), s.verified([-1])])
        lines = full.read_bytes().splitlines(keepends=True)
        copy = self.root / "copy.jsonl"
        copy.write_bytes(b"".join(lines[:2]) + lines[2][:10])
        result = tool.certify(s.campaign_path, [copy, full])
        cert = certificate(result)
        self.assertEqual(cert["journals"][0]["records"], 3)
        self.assertEqual(cert["journals"][0]["torn_tail_bytes"], 0)
        self.assertEqual(cert["verdict"], "PROVED")
        # a copy that diverges inside its complete records is a fork
        other = JournalWriter()
        for record in [s.header(), s.verified([1]), s.verified([-1])]:
            other.add(record)
        fork = other.write(self.root / "fork.jsonl")
        with self.assertRaises(tool.CertifyError) as caught:
            tool.certify(s.campaign_path, [full, fork])
        self.assertEqual(caught.exception.rule, "journal.fork")

    def test_a_symlinked_bundle_is_rejected(self) -> None:
        s = self.scenario()
        bundle = s.root / "campaign" / "bundles" / "all3"
        moved = s.root / "elsewhere"
        bundle.rename(moved)
        os.symlink(moved, bundle)
        with self.assertRaises(tool.CertifyError) as caught:
            tool.certify(s.campaign_path, [])
        self.assertEqual(
            (caught.exception.kind, caught.exception.rule), ("input", "path.containment")
        )


class WideSplit(Base):
    """A root split of 10 variables: 1024 children, Merkle over an even/odd mix, open lists."""

    def build(self, skip: list[int] | None) -> tuple[Scenario, Path, list[list[int]], list[dict]]:
        s = self.scenario()
        text = b"p cnf 10 2\n1 2 3 0\n-1 -2 -3 0\n"
        bundle = s.root / "campaign" / "bundles" / "all3"
        (bundle / "formula.cnf").write_bytes(text)
        f = sha(text)
        manifest = {
            "format": "cubeproof-bundle-1",
            "formula_sha256": f,
            "variables": 10,
            "clauses": 2,
            "pools": {},
            "producer": {"name": "test", "version": "1", "parameters": {}},
            "side_files": [],
        }
        write_document(bundle / "manifest.json", manifest)
        s.formula_text = {f: text}
        s.campaign["formulas"][0]["formula_sha256"] = f
        s.campaign["roots"] = [{"formula_sha256": f, "cube": []}]
        s.campaign["root_splits"] = [
            {
                "node": {"formula_sha256": f, "cube": []},
                "variables": list(range(1, 11)),
                "splitter": {"name": "static", "info": {}},
            }
        ]
        s.save_campaign()
        children = []
        for t in range(1024):
            cube = [(v if (t >> (v - 1)) & 1 else -v) for v in range(1, 11)]
            children.append(cube)
        records = [s.verified(c, f) for i, c in enumerate(children) if not skip or i not in skip]
        return s, s.journal("w1.jsonl", records), children, records

    def test_all_children_closed(self) -> None:
        s, path, _, records = self.build(None)
        cert = certificate(tool.certify(s.campaign_path, [path]))
        leaves = [(r["node_id"], r["cnf_sha256"], r["proof_sha256"]) for r in records]
        summary = cert["formulas"][0]["summary"]
        self.assertEqual(
            (summary["leaves"], summary["splits"], summary["max_cube_size"]), (1024, 1, 10)
        )
        self.assertEqual(summary["leaf_merkle_root"], merkle(leaves))
        self.assertEqual(len(cert["used_attempts"]), 1024)
        ids = [u["node_id"] for u in cert["used_attempts"]]
        self.assertEqual(ids, sorted(ids))

    def test_open_children_in_order(self) -> None:
        skip = [3, 1000, 517]
        s, path, children, _ = self.build(skip)
        cert = certificate(tool.certify(s.campaign_path, [path]))
        f = next(iter(s.formula_text))
        expected = sorted((f, node_id(f, children[i])) for i in skip)
        self.assertEqual(
            [(o["node"]["formula_sha256"], o["node_id"]) for o in cert["open"]], expected
        )
        self.assertEqual(cert["verdict"], "OPEN")
        self.assertEqual(cert["used_attempts"], [])

    def test_cnf_oracle(self) -> None:
        s, _, children, records = self.build(None)
        text = next(iter(s.formula_text.values()))
        self.assertEqual(records[5]["cnf_sha256"], sha(cnf_text(text, children[5])))


# Malformed inputs and unexpected failures end in an error report and exit 4 (specification
# §4.9, §12.2). Exit codes 0, 1 and 2 are verdicts (PROVED, OPEN, MODEL_FOUND); a crash must
# never be read as one of them, and no certificate may be written.

HUGE = b"1" * 5000  # beyond CPython's default int/str conversion limit of 4300 digits


class ErrorBase(Base):
    def setUp(self) -> None:
        super().setUp()
        self.output = self.root / "cert.json"

    def run_main(self, argv: list[str]) -> tuple[int, dict]:
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = tool.main(argv)
        return code, json.loads(out.getvalue())

    def certify_main(self, s: Scenario, journals: list[Path] | None = None) -> tuple[int, dict]:
        argv = ["certify", "--campaign", str(s.campaign_path), "-o", str(self.output)]
        if journals:
            argv += ["--journals", *(str(p) for p in journals)]
        return self.run_main(argv)

    def assert_error(self, code: int, report: dict, kind: str, rule: str | None = None) -> None:
        self.assertEqual(code, 4)
        self.assertEqual(report["verdict"], None)
        self.assertEqual(report["certificate_sha256"], None)
        self.assertEqual(report["error"]["kind"], kind)
        if rule is not None:
            self.assertEqual(report["error"]["rule"], rule)
        self.assertFalse(self.output.exists())


class DimacsLimits(unittest.TestCase):
    def test_huge_decimals_are_rule_violations(self) -> None:
        cases = {
            b"p cnf " + HUGE + b" 0\n": "dimacs.header",
            b"p cnf 1 " + HUGE + b"\n": "dimacs.header",
            b"p cnf 9223372036854775808 0\n": "dimacs.header",
            b"p cnf 1 1\n" + HUGE + b" 0\n": "dimacs.range",
            b"p cnf 1 1\n-" + HUGE + b" 0\n": "dimacs.range",
            b"p cnf 1 1\n1 " + HUGE + b" 0\n": "dimacs.range",
            b"p cnf 1 1\n99999999999999999999 0\n": "dimacs.range",
        }
        for data, rule in cases.items():
            with self.subTest(data=data[:40]):
                self.assertEqual(tool.check_document("dimacs", data), [rule])

    def test_the_largest_header_value_is_accepted(self) -> None:
        self.assertEqual(tool.check_document("dimacs", b"p cnf 9223372036854775807 0\n"), [])


class BundleErrors(ErrorBase):
    def test_a_huge_dimacs_header_in_a_bundle(self) -> None:
        s = self.scenario()
        (self.root / "campaign" / "bundles" / "all3" / "formula.cnf").write_bytes(
            b"p cnf " + HUGE + b" 0\n"
        )
        with self.assertRaises(tool.CertifyError) as caught:
            tool.certify(s.campaign_path, [])
        self.assertEqual((caught.exception.kind, caught.exception.rule), ("input", "dimacs.header"))
        self.assert_error(*self.certify_main(s), "input", "dimacs.header")

    def test_a_bundle_path_through_a_regular_file(self) -> None:
        s = self.scenario()
        s.campaign["formulas"][0]["bundle"] += "/manifest.json/x"
        s.save_campaign()
        with self.assertRaises(tool.CertifyError) as caught:
            tool.certify(s.campaign_path, [])
        self.assertEqual((caught.exception.kind, caught.exception.rule), ("input", "bundle.files"))
        self.assert_error(*self.certify_main(s), "input", "bundle.files")

    def test_a_bundle_that_cannot_be_inspected(self) -> None:
        s = self.scenario()
        bundle = self.root / "campaign" / "bundles" / "all3"
        real = os.lstat

        def lstat(path, *args, **kwargs):
            if Path(path) == bundle:
                raise PermissionError(13, "Permission denied", str(path))
            return real(path, *args, **kwargs)

        with mock.patch.object(tool.os, "lstat", lstat):
            with self.assertRaises(tool.CertifyError) as caught:
                tool.certify(s.campaign_path, [])
            self.assertEqual(
                (caught.exception.kind, caught.exception.rule), ("input", "bundle.files")
            )
            self.assert_error(*self.certify_main(s), "input", "bundle.files")

    def test_an_unsearchable_bundle_parent(self) -> None:
        if os.geteuid() == 0:
            self.skipTest("root ignores directory permissions; covered by the lstat mock test")
        s = self.scenario()
        parent = self.root / "campaign" / "bundles"
        parent.chmod(0)
        try:
            code, report = self.certify_main(s)
        finally:
            parent.chmod(0o755)
        self.assert_error(code, report, "input", "bundle.files")


class LastResort(ErrorBase):
    def test_an_unexpected_exception_is_an_internal_error(self) -> None:
        s = self.scenario()
        for exc in (
            RuntimeError("boom"),
            AssertionError("selecting an open node"),
            ValueError("x"),
            RecursionError(),
        ):
            with self.subTest(exc=type(exc).__name__):
                with mock.patch.object(tool, "build_certificate", side_effect=exc):
                    code, report = self.certify_main(s)
                self.assert_error(code, report, "internal")
                self.assertIn(type(exc).__name__, report["error"]["detail"])

    def test_an_unwritable_output_is_an_error(self) -> None:
        s = self.scenario()
        self.output = self.root / "missing" / "cert.json"
        self.assert_error(*self.certify_main(s), "internal")
        self.assertEqual(list(self.root.glob("**/*.tmp")), [])

    def test_compare_of_non_object_documents(self) -> None:
        left, right = self.root / "a.json", self.root / "b.json"
        left.write_bytes(b"[1]\n")
        right.write_bytes(b"[2]\n")
        code, report = self.run_main(["compare", str(left), str(right)])
        self.assertEqual(code, 4)
        self.assertIn("error", report)


if __name__ == "__main__":
    unittest.main()
