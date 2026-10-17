"""Closure over wide splits, and the verdict of a campaign of several formulas.

Specification §10.2 and §10.5. The frozen corpus has splits of one and two variables, the
scenarios one wide split whose children are all open, and campaigns in which the formulas share
their fate; the campaign of the 59 formulas has splits of twelve and of four variables with
closed children and is proved only when every formula is. The oracle of the closure is written
here: its own enumeration of the children of a split and a plain recursion. For a closed node
the selected leaves must be a partition of the node's cube.
"""

from __future__ import annotations

import itertools
import json
import random
import tempfile
import unittest
from pathlib import Path

from support import Scenario, load_tool

tool = load_tool()

Cube = tuple[int, ...]
F = "ab" * 32
JOURNAL = "cd" * 32


def children_of(cube: Cube, variables: list[int]) -> list[Cube]:
    found = []
    for index in range(2 ** len(variables)):
        literals = list(cube)
        literals += [v if (index >> j) & 1 else -v for j, v in enumerate(variables)]
        found.append(tuple(sorted(literals, key=abs)))
    return found


def evidence_of(splits: dict[Cube, list[list[int]]], verified: set[Cube]):
    evidence = tool.Evidence()
    for cube, lists in splits.items():
        for variables in lists:
            evidence.add_split((F, cube), list(variables))
    for seq, cube in enumerate(sorted(verified)):
        evidence.add_verified((F, cube), tool.Leaf((JOURNAL, seq), {}, 0))
    return evidence


def naive(cube: Cube, splits, verified: set[Cube], memo: dict[Cube, bool]) -> bool:
    if cube not in memo:
        memo[cube] = cube in verified or any(
            all(naive(child, splits, verified, memo) for child in children_of(cube, variables))
            for variables in splits.get(cube, [])
        )
    return memo[cube]


def history(rng: random.Random):
    total = rng.randint(3, 8)
    splits: dict[Cube, list[list[int]]] = {}
    nodes: list[Cube] = [()]
    frontier: list[Cube] = [()]
    for _ in range(rng.randint(1, 6)):
        if not frontier:
            break
        cube = frontier.pop(rng.randrange(len(frontier)))
        free = [v for v in range(1, total + 1) if v not in {abs(x) for x in cube}]
        if not free:
            continue
        for _ in range(rng.randint(1, 2)):
            variables = rng.sample(free, rng.randint(1, min(len(free), 6)))
            splits.setdefault(cube, []).append(variables)
            children = children_of(cube, variables)
            nodes.extend(children)
            frontier.extend(rng.sample(children, min(len(children), 3)))
    verified: set[Cube] = set()
    mode = rng.random()
    for cube, lists in splits.items():
        for variables in lists:
            children = children_of(cube, variables)
            if mode < 0.4:
                skipped: set[int] = set()
            elif mode < 0.8:
                skipped = {rng.randrange(len(children))}
            else:
                skipped = set(rng.sample(range(len(children)), rng.randint(0, len(children))))
            verified.update(child for i, child in enumerate(children) if i not in skipped)
    for cube in sorted(verified):
        if cube in splits and rng.random() < 0.7:
            verified.discard(cube)
    return total, splits, verified, list(dict.fromkeys(nodes))


class WideSplits(unittest.TestCase):
    def test_one_open_child_of_a_wide_split_keeps_the_node_open(self) -> None:
        for width in (3, 4, 12):
            variables = list(range(1, width + 1))
            children = children_of((), variables)
            count = len(children)
            self.assertEqual(len(set(children)), 2**width)
            for position in sorted({0, 3, 4, 5, count // 2, count - 2, count - 1}):
                with self.subTest(width=width, position=position):
                    verified = set(children) - {children[position]}
                    evidence = evidence_of({(): [variables]}, verified)
                    self.assertFalse(evidence.closed((F, ())))
                    self.assertFalse(evidence.closed((F, children[position])))
                    # the same when every child was asked, and remembered, before the parent
                    asked = evidence_of({(): [variables]}, verified)
                    self.assertEqual(
                        [asked.closed((F, child)) for child in children].count(False), 1
                    )
                    self.assertFalse(asked.closed((F, ())))
            whole = evidence_of({(): [variables]}, set(children))
            self.assertTrue(whole.closed((F, ())))
            selected = whole.select((F, ()))
            self.assertEqual(selected.splits, 1)
            self.assertEqual(sorted(key[1] for key in selected.leaves), sorted(children))

    def test_closure_on_random_graphs_with_wide_splits(self) -> None:
        late = 0
        for seed in range(150):
            total, splits, verified, nodes = history(random.Random(seed))
            evidence = evidence_of(splits, verified)
            memo: dict[Cube, bool] = {}
            for cube in nodes:
                with self.subTest(seed=seed, cube=cube):
                    expected = naive(cube, splits, verified, memo)
                    self.assertIs(evidence.closed((F, cube)), expected)
                    if expected:
                        self.partition(evidence, total, cube)
            for cube, lists in splits.items():
                for variables in lists:
                    state = [naive(c, splits, verified, memo) for c in children_of(cube, variables)]
                    late += len(variables) >= 3 and state.count(False) == 1 and all(state[:4])
        self.assertGreaterEqual(late, 10)  # the case a short look at the children gets wrong

    def partition(self, evidence, total: int, cube: Cube) -> None:
        """The selected leaves of a closed node are pairwise incompatible and every total
        assignment below the node lies in exactly one of them."""
        leaves = [set(key[1]) for key in evidence.select((F, cube)).leaves]
        for a, b in itertools.combinations(leaves, 2):
            self.assertTrue(any(-literal in b for literal in a))
        free = [v for v in range(1, total + 1) if v not in {abs(x) for x in cube}]
        for bits in itertools.product((False, True), repeat=len(free)):
            assignment = set(cube) | {v if bit else -v for v, bit in zip(free, bits)}
            self.assertEqual(sum(leaf <= assignment for leaf in leaves), 1)


class SeveralFormulas(unittest.TestCase):
    """A campaign is proved when every formula is (specification §10.5)."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.scenario = Scenario(Path(self.tmp.name), "mixed")
        entries = self.scenario.campaign["formulas"]
        self.first, self.second = (entry["formula_sha256"] for entry in entries)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def certify(self, records: list[dict]) -> tuple[int, dict]:
        path = self.scenario.journal("w1.jsonl", records)
        result = tool.certify(self.scenario.campaign_path, [path])
        return result.exit_code, json.loads(result.certificate_bytes)

    def proved(self, certificate: dict) -> dict[str, bool]:
        return {f["formula_sha256"]: f["proved"] for f in certificate["formulas"]}

    def test_one_proved_formula_does_not_prove_the_campaign(self) -> None:
        s = self.scenario
        for done, other in ((self.first, self.second), (self.second, self.first)):
            with self.subTest(done=done):
                code, certificate = self.certify([s.verified([], formula=done)])
                self.assertEqual(self.proved(certificate), {done: True, other: False})
                self.assertEqual((certificate["verdict"], code), ("OPEN", 1))
                self.assertEqual(
                    [entry["node"]["formula_sha256"] for entry in certificate["open"]], [other]
                )

    def test_every_formula_proved_proves_the_campaign(self) -> None:
        s = self.scenario
        records = [s.verified([], formula=self.first), s.verified([], formula=self.second)]
        code, certificate = self.certify(records)
        self.assertEqual(self.proved(certificate), {self.first: True, self.second: True})
        self.assertEqual((certificate["verdict"], code), ("PROVED", 0))

    def test_a_wide_split_of_one_formula_with_one_open_child(self) -> None:
        """Three variables, eight children: the formula is proved only with all eight."""
        s = self.scenario
        children = [list(c) for c in children_of((), [1, 2, 3])]
        whole = [s.split([], [1, 2, 3], formula=self.first)]
        whole += [s.verified(c, formula=self.first) for c in children]
        whole.append(s.verified([], formula=self.second))
        code, certificate = self.certify(whole)
        self.assertEqual((certificate["verdict"], code), ("PROVED", 0))
        for position in (0, 4, 7):
            with self.subTest(position=position):
                records = [r for i, r in enumerate(whole) if i != position + 1]
                code, certificate = self.certify(records)
                self.assertEqual((certificate["verdict"], code), ("OPEN", 1))
                self.assertFalse(self.proved(certificate)[self.first])
                self.assertEqual(
                    [entry["node"]["cube"] for entry in certificate["open"]], [children[position]]
                )


if __name__ == "__main__":
    unittest.main()
