"""The native helper ``cubeproof-look`` against the Python reference (specification §9.3, §14).

The helper is compiled here with the project's flags (warnings are errors) into a temporary
directory. Equality means byte equality of the result documents: with the same integer
probe limit and no wall budget the helper and the reference must agree on every field.
"""

from __future__ import annotations

import hashlib
import random
import resource
import shutil
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from cp_split_support import (
    NATIVE,
    load_build_module,
    make_formula,
    oracle_lookahead,
    random_cube,
    random_formula,
    random_pool,
    summary,
)

from cubeproof.base.canonical_json import document_bytes, parse_document
from cubeproof.base.errors import ConfigurationError, ToolError
from cubeproof.cnf.bundle import publish_bundle
from cubeproof.cnf.dimacs import Formula
from cubeproof.contracts.identity import node_id
from cubeproof.split.choice import Budget
from cubeproof.split.helper import (
    BUILD_FORMAT,
    PROVENANCE_SUFFIX,
    Helper,
    HelperRequest,
    LookaheadSplitter,
    discover_helper,
    run_helper,
    start_helper,
)
from cubeproof.split.lookahead import build_engine, lookahead
from cubeproof.split.protocol import parse_result, request_document, result_document
from cubeproof.tools.isolation import Isolation, PinnedBinary
from cubeproof.tools.process import Supervisor

pytestmark = pytest.mark.skipif(shutil.which("cc") is None, reason="no C compiler")

BUILD = load_build_module()


@pytest.fixture(scope="module")
def built(tmp_path_factory: pytest.TempPathFactory) -> Path:
    out = tmp_path_factory.mktemp("look-build")
    BUILD.build("cc", out, list(BUILD.RELEASE_FLAGS))
    return out


@pytest.fixture(scope="module")
def binary(built: Path) -> Path:
    return built / "cubeproof-look"


@pytest.fixture(scope="module")
def supervisor() -> Iterator[Supervisor]:
    sup = Supervisor(Isolation.probe())
    try:
        yield sup
    finally:
        sup.shutdown(grace_ms=200)


def write_request(
    directory: Path,
    formula: Formula,
    cube: tuple[int, ...],
    k: int,
    pool: list[int] | None,
    limit: int,
    wall_ms: int | None = None,
    *,
    formula_bytes: bytes | None = None,
) -> Path:
    path = directory / "formula.cnf"
    path.write_bytes(formula.data if formula_bytes is None else formula_bytes)
    request = directory / "request.json"
    request.write_bytes(
        request_document(
            formula_path=str(path),
            formula_sha256=formula.sha256,
            variables=formula.variables,
            cube=cube,
            k=k,
            pool=pool,
            probe_limit=limit,
            wall_ms=wall_ms,
        )
    )
    return request


def run_direct(
    binary: Path,
    directory: Path,
    formula: Formula,
    cube: tuple[int, ...],
    k: int,
    pool: list[int] | None,
    limit: int,
    wall_ms: int | None = None,
    *,
    formula_bytes: bytes | None = None,
) -> subprocess.CompletedProcess[bytes]:
    request = write_request(
        directory, formula, cube, k, pool, limit, wall_ms, formula_bytes=formula_bytes
    )
    return subprocess.run([str(binary), str(request)], capture_output=True, check=False)


#: What the address sanitizer runtime of some compilers prints, without end, when the kernel's
#: address randomization leaves it no room for its shadow memory. It happens at random before
#: ``main`` and says nothing about the helper: a finding is a report that names an ``ERROR``.
SANITIZER_START_FAILURE = b"AddressSanitizer:DEADLYSIGNAL"
SANITIZER_STARTS = 50
SANITIZER_STDERR_LIMIT = 1 << 20


def run_sanitized(
    binary: Path,
    directory: Path,
    formula: Formula,
    cube: tuple[int, ...],
    k: int,
    pool: list[int] | None,
    limit: int,
) -> subprocess.CompletedProcess[bytes]:
    """One run of the sanitized helper: bounded in time and output, started again only when the
    sanitizer runtime itself failed to start (never when it reported a finding)."""
    request = write_request(directory, formula, cube, k, pool, limit)
    errors = directory / "stderr.txt"

    def bound() -> None:
        resource.setrlimit(resource.RLIMIT_FSIZE, (SANITIZER_STDERR_LIMIT,) * 2)

    for _ in range(SANITIZER_STARTS):
        with errors.open("wb") as stream:
            ran = subprocess.run(
                [str(binary), str(request)],
                stdout=subprocess.PIPE,
                stderr=stream,
                check=False,
                timeout=120,
                preexec_fn=bound,
            )
        stderr = errors.read_bytes()
        done = subprocess.CompletedProcess(ran.args, ran.returncode, ran.stdout, stderr)
        started = not stderr.startswith(SANITIZER_START_FAILURE) or b"ERROR" in stderr
        if ran.returncode == 0 or ran.stdout or started:
            return done
    pytest.fail(f"the sanitizer runtime did not start in {SANITIZER_STARTS} attempts")


# -- the build ----------------------------------------------------------------------------------


def test_the_build_record_describes_source_binary_compiler_and_flags(built: Path) -> None:
    record = parse_document((built / ("cubeproof-look" + PROVENANCE_SUFFIX)).read_bytes())
    assert record["format"] == BUILD_FORMAT
    assert (
        record["binary_sha256"]
        == hashlib.sha256((built / "cubeproof-look").read_bytes()).hexdigest()
    )
    assert (
        record["source_sha256"]
        == hashlib.sha256((NATIVE / "cubeproof-look.c").read_bytes()).hexdigest()
    )
    assert {"-Wall", "-Wextra", "-Wpedantic", "-Werror"} <= set(record["flags"])
    assert record["compiler"] and record["version"] == "cubeproof-look 1 lookahead-v1"
    assert set(record) == {
        "format",
        "binary_sha256",
        "source_sha256",
        "compiler",
        "flags",
        "version",
    }


def test_warnings_are_errors(tmp_path: Path) -> None:
    defective = tmp_path / "defective.c"
    defective.write_text("static int unused_variable;\nint main(void) { return 0; }\n")
    flags = ["cc", *BUILD.RELEASE_FLAGS]
    bad = subprocess.run([*flags, "-o", str(tmp_path / "x"), str(defective)], check=False)
    assert bad.returncode != 0
    clean = tmp_path / "clean.c"
    clean.write_text("int main(void) { return 0; }\n")
    good = subprocess.run([*flags, "-o", str(tmp_path / "y"), str(clean)], check=False)
    assert good.returncode == 0
    assert "-Werror" in BUILD.RELEASE_FLAGS and "-Wall" in BUILD.RELEASE_FLAGS


#: A build in a child process whose address space (1 GiB) and processor time (20 s, inherited by
#: the program it starts) are bounded: a version probe that kept the output of a binary printing
#: without end fails there with MemoryError, and one without a timeout ends when the program's
#: processor time runs out, instead of exhausting the machine or leaving the program running.
BOUNDED_BUILD = """
import importlib.util, pathlib, resource, subprocess, sys
resource.setrlimit(resource.RLIMIT_AS, (1 << 30, 1 << 30))
resource.setrlimit(resource.RLIMIT_CPU, (20, 30))
spec = importlib.util.spec_from_file_location("bounded_build", sys.argv[1])
build = importlib.util.module_from_spec(spec)
spec.loader.exec_module(build)
build.VERSION_TIMEOUT_S = 2
try:
    build.build(sys.argv[2], pathlib.Path(sys.argv[3]), [])
except subprocess.TimeoutExpired:
    print("timed out")
"""


def test_a_helper_that_never_starts_cannot_fill_the_memory_of_the_build(tmp_path: Path) -> None:
    """A sanitized binary whose runtime does not start prints without end before ``main``; the
    version probe of ``build.py`` discards that output and gives up after its timeout."""
    compiler = tmp_path / "flooding-cc"
    compiler.write_text(
        "#!/bin/sh\n"
        "# cc ... -o OUT SOURCE: OUT becomes a program that writes to stderr without end\n"
        'while [ "$1" != "-o" ]; do shift; done\n'
        'printf "#!/bin/sh\\nexec yes AddressSanitizer:DEADLYSIGNAL >&2\\n" > "$2"\n'
        'chmod +x "$2"\n',
        encoding="utf-8",
    )
    compiler.chmod(0o755)
    done = subprocess.run(
        [sys.executable, "-c", BOUNDED_BUILD, str(NATIVE / "build.py"), str(compiler),
         str(tmp_path / "out")],
        capture_output=True, text=True, check=False, timeout=120,
    )  # fmt: skip
    assert done.stdout.strip() == "timed out", done.stdout + done.stderr[-2000:]


def test_the_sanitized_helper_starts_every_time(tmp_path: Path) -> None:
    """The sanitized build is not position-independent: under the test image's compiler (GCC 12)
    and a kernel with high address randomization, a position-independent one failed to start in
    about a quarter of the runs; this one starts every time. Elsewhere the test passes either
    way."""
    out = tmp_path / "san"
    BUILD.build("cc", out, list(BUILD.SANITIZE_FLAGS))
    errors = tmp_path / "stderr.txt"

    def bound() -> None:
        resource.setrlimit(resource.RLIMIT_FSIZE, (SANITIZER_STDERR_LIMIT,) * 2)

    for attempt in range(40):
        with errors.open("wb") as stream:
            ran = subprocess.run(
                [str(out / "cubeproof-look"), "--version"],
                stdout=subprocess.PIPE, stderr=stream, check=False, timeout=30, preexec_fn=bound,
            )  # fmt: skip
        assert ran.returncode == 0, (attempt, errors.read_bytes()[:200])
        assert ran.stdout.startswith(b"cubeproof-look "), (attempt, ran.stdout[:200])


def test_the_build_is_deterministic(built: Path, tmp_path: Path) -> None:
    BUILD.build("cc", tmp_path / "again", list(BUILD.RELEASE_FLAGS))
    for name in ("cubeproof-look", "cubeproof-look" + PROVENANCE_SUFFIX):
        assert (tmp_path / "again" / name).read_bytes() == (built / name).read_bytes()


def test_version_line(binary: Path) -> None:
    done = subprocess.run([str(binary), "--version"], capture_output=True, check=True)
    assert done.stdout == b"cubeproof-look 1 lookahead-v1\n" and done.stderr == b""


def test_usage_errors(binary: Path) -> None:
    for argv in ([], ["a", "b"], ["--version", "x"]):
        done = subprocess.run([str(binary), *argv], capture_output=True, check=False)
        assert done.returncode == 2 and done.stdout == b""


# -- equality with the reference ------------------------------------------------------------------


def random_inputs(
    seed: int, n: int
) -> Iterator[tuple[Formula, tuple[int, ...], int, list[int] | None, int]]:
    rng = random.Random(seed)
    for _ in range(n):
        formula = random_formula(rng)
        yield (
            formula,
            random_cube(rng, formula),
            rng.randint(1, 10),
            random_pool(rng, formula),
            rng.choice([1, 2, 3, 7, 20, 60, 200, 5000, 10**6, 10**6, 10**6]),
        )


def test_the_helper_and_the_reference_write_the_same_bytes_on_150_inputs(
    binary: Path, tmp_path: Path
) -> None:
    outcomes: set[tuple[str, str]] = set()
    sampled = 0
    for formula, cube, k, pool, limit in random_inputs(11235, 150):
        done = run_direct(binary, tmp_path, formula, cube, k, pool, limit)
        choice = lookahead(formula, cube, k, pool, Budget(limit))
        expected = result_document(node_id(formula.sha256, cube), choice)
        assert done.returncode == 0 and done.stderr == b""
        assert done.stdout == expected
        outcomes.add((choice.status, choice.info_dict()["stop"]))
        sampled += len(choice.variables) >= 6  # rounds 6.. sample 16 of 2^5.. children
    assert sampled >= 5
    assert {
        ("chosen", "k"),
        ("chosen", "probe_limit"),
        ("chosen", "candidates"),
        ("budget", "probe_limit"),
        ("no_eligible", "candidates"),
        ("failed", "parent_conflict"),
    } <= outcomes


def test_the_helper_agrees_with_the_literal_oracle(binary: Path, tmp_path: Path) -> None:
    for formula, cube, k, pool, limit in random_inputs(31415, 40):
        done = run_direct(binary, tmp_path, formula, cube, k, pool, limit)
        node = node_id(formula.sha256, cube)
        choice = parse_result(
            done.stdout,
            node=node,
            variables=formula.variables,
            cube=cube,
            k=k,
            pool=pool,
            probe_limit=limit,
            wall_ms=None,
        )
        assert summary(choice) == oracle_lookahead(formula, cube, k, pool, limit)


def test_deep_rounds_with_sampling_agree(binary: Path, tmp_path: Path) -> None:
    """k = 12 on a formula with many free variables: rounds 6 to 12 sample 16 of 32..2048."""
    rng = random.Random(5)
    clauses = [[-rng.randint(1, 18), rng.randint(1, 18)] for _ in range(14)]
    clauses += [[rng.randint(1, 20) for _ in range(3)] for _ in range(8)]
    formula = make_formula(20, clauses)
    for cube in ((), (3,), (-2, 5)):
        done = run_direct(binary, tmp_path, formula, cube, 12, None, 10**7)
        choice = lookahead(formula, cube, 12, None, Budget(10**7), engine=build_engine(formula))
        assert done.stdout == result_document(node_id(formula.sha256, cube), choice)
        assert len(choice.variables) == 12 and choice.info_dict()["stop"] == "k"


def test_the_largest_split_samples_up_to_two_to_the_nineteenth_children(
    binary: Path, tmp_path: Path
) -> None:
    """k = 20: round 20 samples 16 of the 2^19 sign vectors (about half a million hashes)."""
    rng = random.Random(20)
    clauses = [[-rng.randint(1, 26), rng.randint(1, 26)] for _ in range(12)]
    clauses += [[rng.choice([-1, 1]) * rng.randint(1, 26) for _ in range(3)] for _ in range(6)]
    formula = make_formula(26, clauses)
    done = run_direct(binary, tmp_path, formula, (), 20, None, 10**9)
    choice = lookahead(formula, (), 20, None, Budget(10**9), engine=build_engine(formula))
    assert len(choice.variables) == 20 and choice.info_dict()["stop"] == "k"
    assert done.stdout == result_document(node_id(formula.sha256, ()), choice)


def test_a_generous_wall_budget_changes_nothing(binary: Path, tmp_path: Path) -> None:
    formula = make_formula(10, [[-1, 2], [-2, 3], [4, 5, 6], [-6, 7]])
    without = run_direct(binary, tmp_path, formula, (), 4, None, 10**6)
    with_wall = run_direct(binary, tmp_path, formula, (), 4, None, 10**6, wall_ms=600_000)
    assert without.stdout == with_wall.stdout and without.returncode == 0


def test_an_expired_wall_budget_is_a_valid_budget_answer(binary: Path, tmp_path: Path) -> None:
    rng = random.Random(1)
    clauses = [
        [rng.choice([-1, 1]) * rng.randint(1, 40000) for _ in range(3)] for _ in range(150000)
    ]
    formula = make_formula(40000, clauses)
    done = run_direct(binary, tmp_path, formula, (), 4, None, 10**9, wall_ms=1)
    choice = parse_result(
        done.stdout,
        node=node_id(formula.sha256, ()),
        variables=formula.variables,
        cube=(),
        k=4,
        pool=None,
        probe_limit=10**9,
        wall_ms=1,
    )
    assert done.returncode == 0
    assert (choice.status, choice.info_dict()["stop"]) == (
        "budget",
        "wall_ms",
    )  # loading took > 1 ms


def test_sanitizers_find_nothing_on_a_sample(tmp_path: Path) -> None:
    out = tmp_path / "san"
    try:
        BUILD.build("cc", out, list(BUILD.SANITIZE_FLAGS))
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        pytest.fail(f"the sanitizer build failed: {error}")
    for formula, cube, k, pool, limit in random_inputs(2718, 40):
        done = run_sanitized(out / "cubeproof-look", tmp_path, formula, cube, k, pool, limit)
        assert done.returncode == 0, done.stderr.decode()[:500]
        choice = lookahead(formula, cube, k, pool, Budget(limit))
        assert done.stdout == result_document(node_id(formula.sha256, cube), choice)
    # every probe limit of a small run: the budget ends in the parent, in a round's children,
    # in a candidate, or not at all (every allocation of the run is freed on each path)
    chain = make_formula(6, [[-1, 2], [-1, 3], [-2, -3, 4], [5, 6]])
    for limit in range(1, 80):
        done = run_sanitized(out / "cubeproof-look", tmp_path, chain, (), 4, None, limit)
        assert done.returncode == 0, (limit, done.stderr.decode()[:500])
        choice = lookahead(chain, (), 4, None, Budget(limit))
        assert done.stdout == result_document(node_id(chain.sha256, ()), choice)


# -- helper failures: exit codes, no stdout, bounded stderr -------------------------------------


def request_for(formula: Formula, path: Path, **overrides: Any) -> dict[str, Any]:
    value: dict[str, Any] = {
        "format": "cubeproof-look-request-1",
        "formula_path": str(path),
        "formula_sha256": formula.sha256,
        "cube": [],
        "k": 2,
        "pool": None,
        "probe_limit": 1000,
        "wall_ms": None,
    }
    value.update(overrides)
    return value


def run_request(
    binary: Path, directory: Path, request: Any, raw: bytes | None = None
) -> subprocess.CompletedProcess[bytes]:
    path = directory / "r.json"
    path.write_bytes(document_bytes(request) if raw is None else raw)
    return subprocess.run([str(binary), str(path)], capture_output=True, check=False)


def assert_failure(done: subprocess.CompletedProcess[bytes], code: int) -> None:
    assert done.returncode == code, done.stderr
    assert done.stdout == b""  # stdout carries nothing but a valid result
    assert done.stderr.startswith(b"cubeproof-look: ") and done.stderr.count(b"\n") == 1
    assert len(done.stderr) < 300


def test_a_hash_mismatch_is_a_formula_error(binary: Path, tmp_path: Path) -> None:
    formula = make_formula(4, [[1, 2]])
    other = make_formula(4, [[1, 3]])
    done = run_direct(binary, tmp_path, formula, (), 1, None, 100, formula_bytes=other.data)
    assert_failure(done, 3)


def test_a_missing_formula_is_a_formula_error(binary: Path, tmp_path: Path) -> None:
    formula = make_formula(4, [[1, 2]])
    done = run_request(binary, tmp_path, request_for(formula, tmp_path / "absent.cnf"))
    assert_failure(done, 3)


@pytest.mark.parametrize(
    "data",
    [
        b"p cnf 2 1\r\n1 2 0\r\n",
        b"p cnf 2 1\n1 2 0",  # no final LF
        b"p cnf 2 2\n1 0\n",  # fewer clauses than declared
        b"p cnf 2 1\n1 3 0\n",  # literal out of range
        b"c comment\np cnf 2 1\n1 2 0\n",
        b"p cnf 2 1\n1  2 0\n",
        b"",
    ],
)
def test_a_formula_that_is_not_canonical_dimacs_is_refused(
    binary: Path, tmp_path: Path, data: bytes
) -> None:
    path = tmp_path / "f.cnf"
    path.write_bytes(data)
    digest = hashlib.sha256(data).hexdigest()
    request = {
        "format": "cubeproof-look-request-1",
        "formula_path": str(path),
        "formula_sha256": digest,
        "cube": [],
        "k": 1,
        "pool": None,
        "probe_limit": 10,
        "wall_ms": None,
    }
    assert_failure(run_request(binary, tmp_path, request), 3)


def test_too_many_variables_is_a_resource_limit(binary: Path, tmp_path: Path) -> None:
    data = b"p cnf 999999999 0\n"
    path = tmp_path / "f.cnf"
    path.write_bytes(data)
    request = {
        "format": "cubeproof-look-request-1",
        "formula_path": str(path),
        "formula_sha256": hashlib.sha256(data).hexdigest(),
        "cube": [],
        "k": 1,
        "pool": None,
        "probe_limit": 10,
        "wall_ms": None,
    }
    assert_failure(run_request(binary, tmp_path, request), 4)


def test_an_allocation_failure_is_a_resource_exit_not_a_crash(binary: Path, tmp_path: Path) -> None:
    data = b"p cnf 200000000 0\n"
    path = tmp_path / "f.cnf"
    path.write_bytes(data)
    request = {
        "format": "cubeproof-look-request-1",
        "formula_path": str(path),
        "formula_sha256": hashlib.sha256(data).hexdigest(),
        "cube": [],
        "k": 1,
        "pool": None,
        "probe_limit": 10,
        "wall_ms": None,
    }
    (tmp_path / "r.json").write_bytes(document_bytes(request))

    def limit() -> None:
        resource.setrlimit(resource.RLIMIT_AS, (200 << 20, 200 << 20))

    done = subprocess.run(
        [str(binary), str(tmp_path / "r.json")], capture_output=True, check=False, preexec_fn=limit
    )
    assert_failure(done, 4)


@pytest.mark.parametrize(
    "change",
    [
        {"format": "cubeproof-look-request-2"},
        {"k": 0},
        {"k": 21},
        {"k": "3"},
        {"cube": [2, 1]},
        {"cube": [0]},
        {"cube": [1, -1]},
        {"cube": [5]},  # out of range for V=4
        {"pool": [2, 1]},
        {"pool": [5]},
        {"pool": [1, 1]},
        {"probe_limit": 0},
        {"probe_limit": -3},
        {"probe_limit": None},
        {"wall_ms": 0},
        {"wall_ms": "1"},
        {"formula_sha256": "A" * 64},
        {"formula_sha256": "ab" * 31},
        {"formula_path": "relative.cnf"},
        {"extra": 1},
    ],
)
def test_a_bad_request_is_refused_before_any_work(
    binary: Path, tmp_path: Path, change: dict[str, Any]
) -> None:
    formula = make_formula(4, [[1, 2]])
    path = tmp_path / "f.cnf"
    path.write_bytes(formula.data)
    request = request_for(formula, path, **change)
    assert_failure(run_request(binary, tmp_path, request), 2)


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"not json",
        b"[]",
        b"{",
        b'{"format":"cubeproof-look-request-1"}',  # fields missing
        b'{"format":"cubeproof-look-request-1","format":"cubeproof-look-request-1"}',
        b'{"k":1} trailing',
        b'{"format":"cubeproof-look-request-1","k":1.5}',
        b'{"format":"cubeproof-look-request-1","k":1e0}',
        b'{"format":"cubeproof-look-request-1","k":01}',
        b'{"format":"cubeproof-look-request-1","cube":[1,,2]}',
        b'{"format":"cubeproof-look-request-1","formula_path":"/a\\ud800"}',
    ],
)
def test_a_malformed_request_document_is_refused(binary: Path, tmp_path: Path, raw: bytes) -> None:
    assert_failure(run_request(binary, tmp_path, None, raw=raw), 2)


def test_a_missing_request_file_is_refused(binary: Path, tmp_path: Path) -> None:
    done = subprocess.run([str(binary), str(tmp_path / "absent")], capture_output=True, check=False)
    assert_failure(done, 2)


def test_clause_forms_in_the_formula_are_handled(binary: Path, tmp_path: Path) -> None:
    formula = make_formula(
        6, [[1, 1], [2, -2, 3], [-1, -1, 4], [5, 5, 5, 6], [], [4, -4]]
    )  # empty clause: every parent conflicts
    done = run_direct(binary, tmp_path, formula, (), 2, None, 100)
    assert done.stdout == result_document(
        node_id(formula.sha256, ()), lookahead(formula, (), 2, None, Budget(100))
    )
    assert b'"status":"failed"' in done.stdout
    noempty = make_formula(6, [[1, 1], [2, -2, 3], [-1, -1, 4], [5, 5, 5, 6], [4, -4], [1, -1, 2]])
    done = run_direct(binary, tmp_path, noempty, (), 2, None, 100)
    choice = lookahead(noempty, (), 2, None, Budget(100))
    assert done.stdout == result_document(node_id(noempty.sha256, ()), choice)
    assert choice.info_dict()["parent_assigned"] == 2  # 1 and 4: units survive the repeats


# -- supervised execution, validation, fallbacks, absence --------------------------------------


def publish(tmp_path: Path, formula: Formula, name: str = "bundle") -> Any:
    return publish_bundle(
        tmp_path / name,
        formula.data,
        pools={},
        producer={"name": "test", "version": "1", "parameters": {}},
    )


def helper_for(binary: Path, version: str = "cubeproof-look 1 lookahead-v1") -> Helper:
    return Helper(PinnedBinary.measure(str(binary)), version, {"source_sha256": "aa" * 32})


def splitter_for(
    helper: Helper | None, supervisor: Supervisor, workdir: Path, **kwargs: Any
) -> LookaheadSplitter:
    workdir.mkdir(exist_ok=True)
    return LookaheadSplitter(helper=helper, supervisor=supervisor, workdir=workdir, **kwargs)


FORMULA = make_formula(8, [[-1, 2], [-2, 3], [-2, 4], [4, 5, 6], [-6, 7, 8]])


def test_the_supervised_helper_gives_the_reference_choice(
    binary: Path, supervisor: Supervisor, tmp_path: Path
) -> None:
    bundle = publish(tmp_path, FORMULA)
    splitter = splitter_for(helper_for(binary), supervisor, tmp_path / "work")
    for cube, k, pool, limit in (((), 3, None, 10**6), ((-5,), 4, [1, 2, 3, 4, 6, 7], 40)):
        choice = splitter.choose(bundle, cube, k, pool, Budget(limit))
        reference = lookahead(FORMULA, cube, k, pool, Budget(limit))
        info = choice.info_dict()
        record = info.pop("helper")
        assert info.pop("implementation") == "helper"
        assert (choice.status, choice.variables) == (reference.status, reference.variables)
        assert info == reference.info_dict()
        assert record["source_sha256"] == "aa" * 32 and len(record["sha256"]) == 64
    assert list((tmp_path / "work").iterdir()) == []  # request files are removed


def test_requests_run_under_the_supervisor_limits(
    binary: Path, supervisor: Supervisor, tmp_path: Path
) -> None:
    helper = helper_for(binary)
    request = HelperRequest(
        formula_path=str(tmp_path / "f.cnf"),
        formula_sha256=FORMULA.sha256,
        variables=FORMULA.variables,
        cube=(),
        k=2,
        pool=None,
        probe_limit=1000,
        wall_ms=None,
    )
    (tmp_path / "f.cnf").write_bytes(FORMULA.data)
    work = tmp_path / "work"
    work.mkdir()
    job = start_helper(supervisor, helper, request, work)
    while not job.finished:
        supervisor.step(50)
    assert job.result() == lookahead(FORMULA, (), 2, None, Budget(1000))
    assert job.process.run is not None and job.process.run.result.exit == 0
    assert run_helper(supervisor, helper, request, work) == lookahead(
        FORMULA, (), 2, None, Budget(1000)
    )


def test_the_address_space_cap_makes_a_big_formula_an_operational_failure(
    binary: Path, supervisor: Supervisor, tmp_path: Path
) -> None:
    big = make_formula(3_000_000, [])  # about 70 MB of arrays are needed for 3 million variables
    (tmp_path / "f.cnf").write_bytes(big.data)
    request = HelperRequest(
        formula_path=str(tmp_path / "f.cnf"),
        formula_sha256=big.sha256,
        variables=big.variables,
        cube=(),
        k=1,
        pool=None,
        probe_limit=10,
        wall_ms=None,
    )
    work = tmp_path / "work"
    work.mkdir()
    helper = helper_for(binary)
    tight = start_helper(supervisor, helper, request, work, memory_bytes=32 << 20)
    while not tight.finished:
        supervisor.step(50)
    assert tight.process.run is not None and tight.process.run.result.exit == 4
    with pytest.raises(ToolError) as error:
        tight.result()
    assert error.value.rule == "split.helper_failed" and "out of memory" in error.value.detail
    roomy = start_helper(supervisor, helper, request, work, memory_bytes=1 << 30)
    while not roomy.finished:
        supervisor.step(50)
    assert roomy.result().status == "chosen"


def fake_helper(tmp_path: Path, name: str, body: str) -> Helper:
    script = tmp_path / name
    script.write_text(f"#!/bin/sh\n{body}\n")
    script.chmod(0o755)
    return Helper(PinnedBinary.measure(str(script)), "cubeproof-look 1 fake")


@pytest.mark.parametrize(
    ("body", "rule"),
    [
        ("echo broken >&2; exit 3", "split.helper_failed"),
        ("exit 1", "split.helper_failed"),
        ("kill -SEGV $$", "split.helper_failed"),
        ("kill -KILL $$", "split.helper_failed"),
        ("sleep 30", "split.helper_failed"),  # the deadline
        ("echo hello", "split.helper_protocol"),
        ("exit 0", "split.helper_protocol"),
        ("head -c 200000 /dev/zero | tr '\\0' x", "split.helper_protocol"),  # beyond the capture
    ],
)
def test_helper_failures_fall_back_to_the_lowest_eligible_variables(
    tmp_path: Path, supervisor: Supervisor, body: str, rule: str
) -> None:
    bundle = publish(tmp_path, FORMULA)
    helper = fake_helper(tmp_path, "helper", body)
    splitter = splitter_for(helper, supervisor, tmp_path / "work", deadline_ms=700)
    choice = splitter.choose(bundle, (-5,), 3, None, Budget(1000))
    assert choice.status == "chosen" and choice.variables == (1, 2, 3)  # nothing assigned yet
    info = choice.info_dict()
    assert info["implementation"] == "fallback-lowest-eligible"
    assert info["algorithm"] == "lowest-eligible"
    assert info["fallback"]["reason"] == "helper_failure"
    assert info["fallback"]["rule"] == rule
    assert info["fallback"]["helper_sha256"] == helper.binary.sha256


def test_the_fallback_uses_the_validated_parent_propagation(
    tmp_path: Path, supervisor: Supervisor
) -> None:
    formula = make_formula(6, [[1], [-1, 2], [4, 5, 6]])
    bundle = publish(tmp_path, formula)
    splitter = splitter_for(fake_helper(tmp_path, "h", "exit 1"), supervisor, tmp_path / "work")
    choice = splitter.choose(bundle, (-3,), 2, None, Budget(10))
    assert choice.variables == (4, 5)  # 1, 2 propagated, 3 in the cube
    assert choice.info_dict()["parent_assigned"] == 3


def test_a_fallback_after_a_parent_conflict_is_not_a_split(
    tmp_path: Path, supervisor: Supervisor
) -> None:
    bundle = publish(tmp_path, make_formula(3, [[1], [-1]]))
    splitter = splitter_for(fake_helper(tmp_path, "h", "exit 1"), supervisor, tmp_path / "work")
    choice = splitter.choose(bundle, (), 2, None, Budget(10))
    assert (choice.status, choice.variables) == ("failed", ())
    assert choice.info_dict()["stop"] == "parent_conflict"


def test_a_result_that_names_another_node_or_an_assigned_variable_falls_back(
    tmp_path: Path, supervisor: Supervisor
) -> None:
    bundle = publish(tmp_path, FORMULA)
    node = node_id(FORMULA.sha256, (-5,))
    good = lookahead(FORMULA, (-5,), 2, None, Budget(1000))
    for forged in (
        result_document(node_id(FORMULA.sha256, ()), good),  # another node
        result_document(node, good).replace(
            b'"variables":[', b'"variables":[5,'
        ),  # a cube variable
    ):
        script = tmp_path / "forged.bin"
        script.write_bytes(forged)
        helper = fake_helper(tmp_path, "forger", f"cat {script}")
        splitter = splitter_for(helper, supervisor, tmp_path / "work")
        choice = splitter.choose(bundle, (-5,), 2, None, Budget(1000))
        assert choice.info_dict()["implementation"] == "fallback-lowest-eligible"
        assert choice.info_dict()["fallback"]["rule"] == "split.helper_protocol"


def test_a_valid_helper_answer_is_used_as_it_is(tmp_path: Path, supervisor: Supervisor) -> None:
    bundle = publish(tmp_path, FORMULA)
    node = node_id(FORMULA.sha256, (-5,))
    choice = lookahead(FORMULA, (-5,), 2, None, Budget(1000))
    canned = tmp_path / "canned"
    canned.write_bytes(result_document(node, choice))
    splitter = splitter_for(
        fake_helper(tmp_path, "canned-helper", f"cat {canned}"), supervisor, tmp_path / "work"
    )
    answer = splitter.choose(bundle, (-5,), 2, None, Budget(1000))
    assert answer.variables == choice.variables
    assert answer.info_dict()["implementation"] == "helper"


def test_a_budget_answer_is_returned_not_replaced_by_a_fallback(
    binary: Path, supervisor: Supervisor, tmp_path: Path
) -> None:
    bundle = publish(tmp_path, FORMULA)
    splitter = splitter_for(helper_for(binary), supervisor, tmp_path / "work")
    choice = splitter.choose(bundle, (), 3, None, Budget(2))
    assert (choice.status, choice.variables) == ("budget", ())
    assert choice.info_dict()["implementation"] == "helper"


def test_an_absent_helper_uses_the_python_reference_with_a_visible_warning(tmp_path: Path) -> None:
    bundle = publish(tmp_path, FORMULA)
    messages: list[str] = []
    splitter = LookaheadSplitter(absent_reason="not installed", warn=messages.append)
    first = splitter.choose(bundle, (), 3, None, Budget(10**6))
    second = splitter.choose(bundle, (-5,), 2, None, Budget(10**6))
    assert (
        len(messages) == 1 and "not installed" in messages[0] and "Python reference" in messages[0]
    )
    info = first.info_dict()
    assert info.pop("implementation") == "python-reference"
    assert first.variables == lookahead(FORMULA, (), 3, None, Budget(10**6)).variables
    assert info == lookahead(FORMULA, (), 3, None, Budget(10**6)).info_dict()
    assert second.info_dict()["implementation"] == "python-reference"


def test_the_default_warning_is_a_runtime_warning(tmp_path: Path) -> None:
    bundle = publish(tmp_path, FORMULA)
    with pytest.warns(RuntimeWarning, match="cubeproof-look is not available"):
        LookaheadSplitter().choose(bundle, (), 1, None, Budget(100))


def test_a_helper_needs_a_supervisor_and_a_work_directory(binary: Path) -> None:
    with pytest.raises(ValueError):
        LookaheadSplitter(helper=helper_for(binary))


def test_choose_validates_its_arguments(tmp_path: Path) -> None:
    bundle = publish(tmp_path, FORMULA)
    splitter = LookaheadSplitter(warn=lambda message: None)
    for args in ((0, None), (21, None), (1, [9]), (1, [2, 1])):
        with pytest.raises(Exception) as error:
            splitter.choose(bundle, (), args[0], args[1], Budget(10))
        assert getattr(error.value, "rule", "").startswith("split.")
    with pytest.raises(Exception) as cube_error:
        splitter.choose(bundle, (3, 2), 1, None, Budget(10))
    assert getattr(cube_error.value, "rule", "") == "cube.canonical"


# -- install and discovery ----------------------------------------------------------------------


def install(tmp_path: Path) -> Path:
    source = tmp_path / "native"
    shutil.copytree(NATIVE, source, ignore=shutil.ignore_patterns("build", "__pycache__"))
    prefix = tmp_path / "prefix"
    subprocess.run(
        ["make", "-C", str(source), "install", f"PREFIX={prefix}", f"PYTHON={sys.executable}"],
        check=True,
        capture_output=True,
    )
    return prefix / "bin" / "cubeproof-look"


def test_make_install_places_the_helper_and_its_record_where_discovery_finds_them(
    tmp_path: Path, supervisor: Supervisor
) -> None:
    if shutil.which("make") is None:
        pytest.fail("make is required for the install test")
    installed = install(tmp_path)
    found = discover_helper(str(installed), supervisor, str(tmp_path))
    assert found.problem is None and found.helper is not None
    helper = found.helper
    assert helper.version == "cubeproof-look 1 lookahead-v1"
    record = helper.record()
    assert record["sha256"] == hashlib.sha256(installed.read_bytes()).hexdigest()
    assert (
        record["source_sha256"]
        == hashlib.sha256((NATIVE / "cubeproof-look.c").read_bytes()).hexdigest()
    )
    assert "-Werror" in record["flags"] and record["compiler"]
    # the installed helper works through the supervisor
    bundle = publish(tmp_path, FORMULA)
    splitter = splitter_for(helper, supervisor, tmp_path / "work")
    assert (
        splitter.choose(bundle, (), 2, None, Budget(1000)).info_dict()["implementation"] == "helper"
    )


def test_a_build_record_of_another_binary_is_not_used(
    tmp_path: Path, supervisor: Supervisor
) -> None:
    installed = install(tmp_path)
    with open(installed, "ab") as stream:
        stream.write(b"\0")  # a different binary now: the record no longer describes it
    found = discover_helper(str(installed), supervisor, str(tmp_path))
    assert found.helper is not None and found.helper.provenance == {}
    assert found.helper.record()["sha256"] == hashlib.sha256(installed.read_bytes()).hexdigest()


def test_discovery_reports_absence_and_unusable_helpers_without_raising(
    tmp_path: Path, supervisor: Supervisor
) -> None:
    assert discover_helper(None, supervisor, str(tmp_path)).helper is None
    missing = discover_helper(str(tmp_path / "absent"), supervisor, str(tmp_path))
    assert missing.helper is None and "absent" in (missing.problem or "")
    plain = tmp_path / "plain"
    plain.write_text("x")
    not_executable = discover_helper(str(plain), supervisor, str(tmp_path))
    assert not_executable.helper is None and not_executable.problem
    wrong = tmp_path / "wrong"
    wrong.write_text("#!/bin/sh\necho 'some other tool 3'\n")
    wrong.chmod(0o755)
    other = discover_helper(str(wrong), supervisor, str(tmp_path))
    assert other.helper is None and "not cubeproof-look" in (other.problem or "")
    broken = tmp_path / "broken"
    broken.write_text("#!/bin/sh\nexit 4\n")
    broken.chmod(0o755)
    failing = discover_helper(str(broken), supervisor, str(tmp_path))
    assert failing.helper is None and failing.problem


def test_paths_are_never_searched(tmp_path: Path, supervisor: Supervisor) -> None:
    with pytest.raises(ConfigurationError):  # a bare name is not an absolute configured path
        discover_helper("cubeproof-look", supervisor, str(tmp_path))
