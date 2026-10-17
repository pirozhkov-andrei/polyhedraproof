"""Generate (or check) the frozen cubeproof v1 contract corpus.

    python3 tools/spec_vectors/generate.py            # rewrite tests/contracts/corpus
    python3 tools/spec_vectors/generate.py --check    # exit 1 if the corpus differs
    python3 tools/spec_vectors/generate.py --out DIR  # write a fresh copy elsewhere

Standard library only and independent of the runtime packages and of the test-side reader;
the contract tests in tests/contracts verify everything it writes with an independent
reading. The corpus records the hashes of the specification, of this generator and of its
inputs. Frozen inputs (the compressed base formulas of maps 1 and 2) are read, never
rewritten.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
CORPUS = ROOT / "tests" / "contracts" / "corpus"
SPECIFICATION = "docs/SPECIFICATION.md"
PREFIX_CASES = "tools/spec_vectors/inputs/prefix-cases-n12.json"
INPUTS = {1: "prefix_cases/map1-base.cnf.xz", 2: "prefix_cases/map2-base.cnf.xz"}
INPUT_PROVENANCE = (
    "map {map} base formula bytes (layers S,H,A,B,I, gauge face 1), compressed with xz; "
    "SHA-256 of the bytes equals data/fixtures/formula_hashes.json"
)

sys.path.insert(0, str(HERE))

import sv_cases  # noqa: E402
import sv_documents  # noqa: E402
import sv_vectors  # noqa: E402
from sv_spec import sha  # noqa: E402


def file_entry(path: str, data: bytes) -> dict[str, Any]:
    return {"path": path, "sha256": sha(data), "bytes": len(data)}


def generate(inputs_root: Path) -> dict[str, bytes]:
    """Every generated corpus file by relative path (inputs excluded)."""
    files = sv_cases.Files()
    cases, keep = sv_cases.build(files)
    sv_vectors.check_split_problems()
    certificates = {
        c["id"]: json.loads(files.files[c["expect"]["certificate"]])
        for c in cases.cases
        if "certificate" in c["expect"]
    }
    files.put("documents.json", sv_documents.build(certificates))
    files.put("vectors/cnf.json", sv_vectors.cnf_vectors())
    files.put("vectors/merkle.json", sv_vectors.merkle_vectors())
    files.put("vectors/assignment.json", sv_vectors.assignment_vectors())
    files.put("vectors/json.json", sv_vectors.json_vectors())
    files.put("vectors/policy.json", sv_vectors.policy_vectors())
    files.put("vectors/selection.json", sv_vectors.selection_vectors(keep["modes_w1"]))
    files.put(
        "vectors/journal.json",
        sv_vectors.journal_vector(keep["pilot_root"], "journals/pilot_root/w1.jsonl"),
    )
    files.put("vectors/primitives.json", sv_vectors.primitive_vectors())
    expected = json.loads((ROOT / PREFIX_CASES).read_text(encoding="utf-8"))
    files.put(
        "prefix_cases/cases.json", sv_vectors.prefix_case_vectors(inputs_root, expected, INPUTS)
    )

    spec = {"path": SPECIFICATION, "sha256": sha((ROOT / SPECIFICATION).read_bytes())}
    metadata = {
        "format": "cubeproof-contract-corpus-1",
        "description": "Frozen contract corpus of cubeproof v1. Schemas and the "
        "requirement matrix are in schemas/cubeproof/v1; tests/contracts verifies this corpus "
        "with an independent reader.",
        "spec": spec,
        "generator": [
            {"path": p.relative_to(ROOT).as_posix(), "sha256": sha(p.read_bytes())}
            for p in sorted(HERE.glob("*.py"))
        ],
        "sources": [{"path": PREFIX_CASES, "sha256": sha((ROOT / PREFIX_CASES).read_bytes())}],
        "inputs": [
            file_entry(path, (inputs_root / path).read_bytes())
            | {"provenance": INPUT_PROVENANCE.format(map=m)}
            for m, path in sorted(INPUTS.items())
        ],
        "files": [file_entry(p, d) for p, d in sorted(files.files.items())],
    }
    files.put("corpus.json", sv_cases.pretty(metadata))
    return files.files


def write(target: Path, generated: dict[str, bytes]) -> None:
    keep = set(generated) | set(INPUTS.values())
    if target.exists():
        for path in sorted(target.rglob("*"), reverse=True):
            relative = path.relative_to(target).as_posix()
            if path.is_file() and relative not in keep:
                path.unlink()
            elif path.is_dir() and not any(path.iterdir()):
                path.rmdir()
    for relative, data in generated.items():
        path = target / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists() or path.read_bytes() != data:
            path.write_bytes(data)


def differences(target: Path, generated: dict[str, bytes]) -> list[str]:
    found = []
    present = {p.relative_to(target).as_posix() for p in target.rglob("*") if p.is_file()} - set(
        INPUTS.values()
    )
    for path in sorted(present - set(generated)):
        found.append(f"unexpected file {path}")
    for path, data in sorted(generated.items()):
        file = target / path
        if not file.is_file():
            found.append(f"missing file {path}")
        elif file.read_bytes() != data:
            found.append(f"differs {path}")
    return found


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--check", action="store_true", help="compare with the committed corpus")
    group.add_argument("--out", type=Path, help="write a fresh corpus to this directory")
    args = parser.parse_args(argv)
    generated = generate(CORPUS)
    if args.check:
        found = differences(CORPUS, generated)
        for line in found:
            print(line)
        print(f"{len(generated)} generated files, {len(found)} differences")
        return 1 if found else 0
    if args.out is not None:
        write(args.out, generated)
        print(f"wrote {len(generated)} files to {args.out}")
        return 0
    write(CORPUS, generated)
    print(f"wrote {len(generated)} files to {CORPUS}")
    digest = hashlib.sha256(generated["corpus.json"]).hexdigest()
    print(f"corpus.json sha256 {digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
