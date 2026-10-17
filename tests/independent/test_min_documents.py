"""Single-document fixtures of the contract corpus for the document types a certifier reads.

Every fixture of these types names its expectation: valid, exactly one requirement, or a schema
rejection. The independent certifier must agree; a schema rejection is reported as "schema"
(its location is not compared). Types that only other components read (status, weights, look
requests, audit reports, ...) are out of the certifier's scope.
"""

from __future__ import annotations

import base64
import unittest

from support import corpus_json, load_tool

tool = load_tool()

CERTIFIER_TYPES = {
    "json",
    "dimacs",
    "bundle-manifest",
    "policy",
    "shard",
    "handoff-request",
    "journal-record",
}


def fixture(entry: dict) -> bytes:
    data = entry["data"]
    if "text" in data:
        return data["text"].encode("utf-8", "surrogatepass")
    return base64.b64decode(data["base64"])


def expected(entry: dict) -> list[str]:
    expect = entry["expect"]
    if expect == "valid":
        return []
    if "rule" in expect:
        return [expect["rule"]]
    return ["schema"]


class Documents(unittest.TestCase):
    def test_fixtures(self) -> None:
        entries = [
            e for e in corpus_json("documents.json")["documents"] if e["type"] in CERTIFIER_TYPES
        ]
        self.assertGreater(len(entries), 250)
        for entry in entries:
            with self.subTest(id=entry["id"]):
                found = tool.check_document(entry["type"], fixture(entry), entry.get("context"))
                self.assertEqual(found, expected(entry), entry["id"])


if __name__ == "__main__":
    unittest.main()
