"""Frozen contract vectors against the independent certifier's primitives.

Specification §3, §4.1, §4.8 and §10.5.
"""

from __future__ import annotations

import lzma
import unittest

from support import CORPUS, cnf_text, corpus_json, load_tool, sha

tool = load_tool()


class JsonVectors(unittest.TestCase):
    def test_encode(self) -> None:
        for case in corpus_json("vectors/json.json")["encode"]:
            data = tool.canonical_json(case["value"])
            self.assertEqual(data.decode("utf-8"), case["text"])
            self.assertEqual(sha(data), case["sha256"])
            self.assertEqual(tool.parse_json(data), case["value"])


class PrimitiveVectors(unittest.TestCase):
    def test_schema_definitions(self) -> None:
        primitives = corpus_json("vectors/primitives.json")["primitives"]
        for name, sets in primitives.items():
            for value in sets["valid"]:
                with self.subTest(name=name, value=value):
                    self.assertEqual(tool.schema_problems("common", name, value), [])
            for value in sets["invalid"]:
                with self.subTest(name=name, value=value):
                    problems = tool.schema_problems("common", name, value)
                    if name == "UTC" and isinstance(value, str) and not problems:
                        # the pattern accepts it; the calendar rule must reject it
                        self.assertFalse(tool.utc_valid(value), value)
                    else:
                        self.assertNotEqual(problems, [])
            if name == "UTC":
                for value in sets["valid"]:
                    self.assertTrue(tool.utc_valid(value), value)


class CnfVectors(unittest.TestCase):
    def setUp(self) -> None:
        self.data = corpus_json("vectors/cnf.json")
        self.formulas = {f["name"]: f for f in self.data["formulas"]}

    def test_formulas(self) -> None:
        for f in self.data["formulas"]:
            parsed = tool.parse_dimacs(f["text"].encode("ascii"))
            self.assertEqual(
                (parsed.variables, len(parsed.clauses)), (f["variables"], f["clauses"])
            )
            self.assertEqual(parsed.sha256, f["sha256"])

    def test_nodes_ids_and_cnf_digests(self) -> None:
        for n in self.data["nodes"]:
            text = self.formulas[n["formula"]]["text"].encode("ascii")
            formula = tool.parse_dimacs(text)
            self.assertEqual(tool.node_id(n["formula_sha256"], n["cube"]), n["node_id"])
            self.assertEqual(tool.cube_cnf(formula, n["cube"]), n["cnf_text"].encode("ascii"))
            self.assertEqual(formula.cnf_sha256(n["cube"]), n["cnf_sha256"])
            # the cached-state digest equals the plain construction (independent oracle)
            self.assertEqual(sha(cnf_text(text, n["cube"])), n["cnf_sha256"])

    def test_cube_rules(self) -> None:
        for c in self.data["cubes"]:
            with self.subTest(case=c):
                self.assertEqual(tool.cube_problem(c["cube"], c["variables"]), c["expect"])

    def test_split_rules(self) -> None:
        for c in self.data["split_problems"]:
            with self.subTest(case=c):
                found = tool.split_problem(c["split"], c["cube"], c["variables"])
                self.assertEqual(found, c["expect"])

    def test_splits_and_children(self) -> None:
        for s in self.data["splits"]:
            formula = self.formulas[s["formula"]]["sha256"]
            self.assertEqual(tool.node_id(formula, s["cube"]), s["node_id"])
            self.assertEqual(tool.split_id(s["node_id"], s["variables"]), s["split_id"])
            children = tool.split_children(s["cube"], s["variables"])
            self.assertEqual([list(c) for c in children], [c["cube"] for c in s["children"]])
            for child in s["children"]:
                self.assertEqual(tool.node_id(formula, child["cube"]), child["node_id"])


class AssignmentVectors(unittest.TestCase):
    def test_valid(self) -> None:
        data = corpus_json("vectors/assignment.json")
        for case in data["cases"]:
            values = tool.decode_assignment(case["assignment"], case["variables"])
            true = [i + 1 for i, v in enumerate(values) if v]
            self.assertEqual(true, case["true"])
            self.assertEqual(len(values), case["variables"])

    def test_invalid(self) -> None:
        data = corpus_json("vectors/assignment.json")
        for case in data["invalid"]:
            with self.subTest(case=case):
                with self.assertRaises(tool.Failure) as caught:
                    tool.decode_assignment(case["assignment"], case["variables"])
                self.assertEqual(caught.exception.rule, "attempt.assignment")


class MerkleVectors(unittest.TestCase):
    def test_cases(self) -> None:
        for case in corpus_json("vectors/merkle.json")["cases"]:
            leaves = [(x["node_id"], x["cnf_sha256"], x["proof_sha256"]) for x in case["leaves"]]
            self.assertEqual([tool.leaf_hash(*x) for x in leaves], case["leaf_hashes"])
            self.assertEqual(tool.merkle_root(leaves), case["root"], case["name"])
            # the root does not depend on the order in which leaves are given
            self.assertEqual(tool.merkle_root(list(reversed(leaves))), case["root"], case["name"])


class JournalVector(unittest.TestCase):
    def test_chain(self) -> None:
        data = corpus_json("vectors/journal.json")
        records = tool.read_journal_bytes((CORPUS / data["file"]).read_bytes())
        self.assertEqual(records.id, data["id"])
        self.assertEqual(records.head, data["head"])
        for expect, line in zip(data["records"], records.lines, strict=True):
            self.assertEqual(line.record["self"], expect["self"])
            unsigned = {k: v for k, v in line.record.items() if k != "self"}
            self.assertEqual(tool.canonical_json(unsigned).decode(), expect["unsigned_text"])


class PrefixCaseBytes(unittest.TestCase):
    """Real map formulas: strict reader, node IDs and cached-state digests (specification §3.2,
    §3.3)."""

    def test_maps(self) -> None:
        data = corpus_json("prefix_cases/cases.json")
        bases = {b["map"]: b for b in data["bases"]}
        formulas = {}
        for number, base in bases.items():
            raw = lzma.decompress((CORPUS / base["file"]).read_bytes())
            formula = tool.parse_dimacs(raw)
            self.assertEqual(formula.sha256, base["formula_sha256"])
            self.assertEqual(
                (formula.variables, len(formula.clauses)), (base["variables"], base["clauses"])
            )
            formulas[number] = (formula, raw)
        for case in data["cases"]:
            formula, raw = formulas[case["map"]]
            cube = case["cube"]
            self.assertIsNone(tool.cube_problem(cube, formula.variables))
            self.assertEqual(tool.node_id(formula.sha256, cube), case["node_id"])
            self.assertEqual(formula.cnf_sha256(cube), case["cube_cnf_sha256"])
            self.assertEqual(sha(cnf_text(raw, cube)), case["cube_cnf_sha256"])


if __name__ == "__main__":
    unittest.main()
