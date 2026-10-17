"""Single-document fixtures: tests/contracts/corpus/documents.json.

Each entry holds exact bytes, a document type, an optional context and an expectation:
"valid", {"rule": id} (exactly that requirement fails) or {"schema": location} (the schema
fails, only at that location; locations use $.field[index] and $.object<key> for keys).
"""

from __future__ import annotations

import base64
import copy
import json
from collections.abc import Callable
from typing import Any

from sv_cases import (
    ALL3,
    F_CLAUSE,
    F_EMPTY,
    F_SAT,
    F_UNSAT,
    NAMES_TSV,
    SAT3,
    TAGS_TSV,
    entry_split_id,
    manifest,
)
from sv_records import (
    CHECK_HEAP,
    CHECK_OK,
    M_OK,
    MANIFEST,
    NOT_STARTED,
    P_RETAIN,
    P_STREAM,
    P_TRANSIENT,
    PRESETS,
    RESOURCES,
    SOLVER_CRASH,
    SOLVER_SAT,
    SOLVER_TIMEOUT,
    attempt_fields,
    check,
    ident,
    machinery,
    out,
    policy,
    sign,
)
from sv_spec import Formula, document, jbytes, jsha, node, node_id, sha

Expect = Any

# A source manifest with a path that starts with "cubeproof" but whose first path component
# is "cubeproofx" (routine reading 6); still sorted by code point ("/" < "x").
MANIFEST_X = sorted(
    [*MANIFEST, {"path": "cubeproofx/__init__.py", "sha256": sha("cubeproofx/__init__.py")}],
    key=lambda e: e["path"],
)
# A source manifest with an entry named exactly "cubeproof": its first path component is
# "cubeproof", so it is a cubeproof entry (routine reading 6); "cubeproof" sorts before
# "cubeproof/".
# The rule is a string rule on paths; readers do not check that the paths could coexist on disk.
MANIFEST_BARE = sorted(
    [*MANIFEST, {"path": "cubeproof", "sha256": sha("cubeproof")}],
    key=lambda e: e["path"],
)


class Documents:
    def __init__(self) -> None:
        self.entries: list[dict[str, Any]] = []

    def add(
        self,
        ident_: str,
        kind: str,
        data: bytes,
        expect: Expect = "valid",
        context: dict[str, Any] | None = None,
    ) -> None:
        try:
            payload: dict[str, str] = {"text": data.decode("utf-8")}
            if "\r" in payload["text"]:
                raise UnicodeDecodeError("utf-8", data, 0, 1, "keep CR visible as base64")
        except UnicodeDecodeError:
            payload = {"base64": base64.b64encode(data).decode("ascii")}
        entry: dict[str, Any] = {"id": ident_, "type": kind, "data": payload, "expect": expect}
        if context:
            entry["context"] = context
        if any(e["id"] == ident_ for e in self.entries):
            raise ValueError(f"duplicate document id {ident_}")
        self.entries.append(entry)

    def doc(
        self,
        ident_: str,
        kind: str,
        value: Any,
        expect: Expect = "valid",
        context: dict[str, Any] | None = None,
    ) -> None:
        self.add(ident_, kind, document(value), expect, context)


def rule(name: str) -> dict[str, str]:
    return {"rule": name}


def at(location: str) -> dict[str, str]:
    return {"schema": location}


def mutate(value: dict[str, Any], change: Callable[[dict[str, Any]], Any]) -> dict[str, Any]:
    result = copy.deepcopy(value)
    change(result)
    return result


# -- JSON and text formats ----------------------------------------------------------------------


def json_documents(d: Documents) -> None:
    deep_ok: Any = []
    for _ in range(31):
        deep_ok = [deep_ok]
    deep_bad = [deep_ok]
    d.add("json-object", "json", b'{"a":1}\n')
    d.add("json-array", "json", b"[]\n")
    d.add("json-control-escape", "json", b'{"a":"\\u001f\\n"}\n')
    d.add("json-raw-unicode", "json", '{"a":"\u00e9\u2028\u007f/"}\n'.encode())
    d.add("json-depth-32", "json", document(deep_ok))
    d.add("json-bom", "json", b'\xef\xbb\xbf{"a":1}\n', rule("json.bom"))
    d.add("json-invalid-byte", "json", b'{"a":"\xff"}\n', rule("json.utf8"))
    d.add("json-encoded-surrogate", "json", b'{"a":"\xed\xa0\x80"}\n', rule("json.utf8"))
    d.add("json-overlong", "json", b'{"a":"\xc0\xaf"}\n', rule("json.utf8"))
    d.add("json-truncated", "json", b'{"a":1\n', rule("json.syntax"))
    d.add("json-two-values", "json", b'{"a":1}{"b":2}\n', rule("json.syntax"))
    d.add("json-single-quotes", "json", b"{'a':1}\n", rule("json.syntax"))
    d.add("json-duplicate-key", "json", b'{"a":1,"a":1}\n', rule("json.duplicate_key"))
    d.add("json-nested-duplicate-key", "json", b'{"a":{"b":1,"b":2}}\n', rule("json.duplicate_key"))
    d.add("json-fraction", "json", b'{"a":1.0}\n', rule("json.number"))
    d.add("json-exponent", "json", b'{"a":1e2}\n', rule("json.number"))
    d.add("json-nan", "json", b'{"a":NaN}\n', rule("json.number"))
    d.add("json-infinity", "json", b'{"a":-Infinity}\n', rule("json.number"))
    d.add("json-too-large", "json", b'{"a":9223372036854775808}\n', rule("json.integer_range"))
    d.add("json-too-small", "json", b'{"a":-9223372036854775808}\n', rule("json.integer_range"))
    d.add("json-int64-bounds", "json", b'{"a":[-9223372036854775807,9223372036854775807]}\n')
    d.add("json-lone-surrogate", "json", b'{"a":"\\ud800"}\n', rule("json.surrogate"))
    d.add("json-lone-surrogate-key", "json", b'{"\\udc00":1}\n', rule("json.surrogate"))
    d.add("json-spaces", "json", b'{"a": 1}\n', rule("json.canonical"))
    d.add("json-key-order", "json", b'{"b":1,"a":2}\n', rule("json.canonical"))
    d.add("json-no-final-lf", "json", b'{"a":1}', rule("json.canonical"))
    d.add("json-two-lf", "json", b'{"a":1}\n\n', rule("json.canonical"))
    d.add("json-crlf", "json", b'{"a":1}\r\n', rule("json.canonical"))
    d.add("json-leading-space", "json", b' {"a":1}\n', rule("json.canonical"))
    d.add("json-minus-zero", "json", b'{"a":-0}\n', rule("json.canonical"))
    d.add("json-escaped-non-ascii", "json", b'{"a":"\\u00e9"}\n', rule("json.canonical"))
    d.add("json-escaped-slash", "json", b'{"a":"\\/"}\n', rule("json.canonical"))
    d.add("json-depth-33", "json", document(deep_bad), rule("limit.depth"))


def dimacs_documents(d: Documents) -> None:
    for formula in (F_SAT, F_UNSAT, F_EMPTY, F_CLAUSE, ALL3, SAT3):
        d.add(f"dimacs-{formula.name}", "dimacs", formula.data)
    d.add("dimacs-duplicates-and-tautology", "dimacs", b"p cnf 2 3\n1 1 0\n1 -1 0\n1 1 0\n")
    d.add("dimacs-unsorted-literals-unused-variables", "dimacs", b"p cnf 5 1\n-5 3 0\n")
    bad = {
        "empty-file": (b"", "dimacs.header"),
        "header-no-lf": (b"p cnf 0 0", "dimacs.header"),
        "header-leading-zero": (b"p cnf 01 1\n1 0\n", "dimacs.header"),
        "header-two-spaces": (b"p  cnf 1 1\n1 0\n", "dimacs.header"),
        "header-comment-first": (b"c x\np cnf 1 1\n1 0\n", "dimacs.header"),
        "header-missing-count": (b"p cnf 1\n", "dimacs.header"),
        "header-negative": (b"p cnf -1 0\n", "dimacs.header"),
        "header-trailing-space": (b"p cnf 1 1 \n1 0\n", "dimacs.header"),
        "header-capital": (b"P cnf 0 0\n", "dimacs.header"),
        "header-crlf": (b"p cnf 1 1\r\n1 0\n", "dimacs.header"),
        "clause-plus": (b"p cnf 1 1\n+1 0\n", "dimacs.clause"),
        "clause-leading-zero": (b"p cnf 1 1\n01 0\n", "dimacs.clause"),
        "clause-minus-zero": (b"p cnf 1 1\n-0 1 0\n", "dimacs.clause"),
        "clause-two-spaces": (b"p cnf 1 1\n1  0\n", "dimacs.clause"),
        "clause-trailing-space": (b"p cnf 1 1\n1 0 \n", "dimacs.clause"),
        "clause-empty-without-space": (b"p cnf 0 1\n0\n", "dimacs.clause"),
        "clause-blank-line": (b"p cnf 1 2\n1 0\n\n", "dimacs.clause"),
        "clause-crlf": (b"p cnf 1 1\n1 0\r\n", "dimacs.clause"),
        "clause-tab": (b"p cnf 1 1\n1\t0\n", "dimacs.clause"),
        "clause-no-final-lf": (b"p cnf 1 1\n1 0", "dimacs.clause"),
        "clause-comment": (b"p cnf 1 1\nc x\n", "dimacs.clause"),
        "clause-two-terminators": (b"p cnf 2 1\n1 2 0 0\n", "dimacs.clause"),
        "count-too-few": (b"p cnf 1 2\n1 0\n", "dimacs.count"),
        "count-too-many": (b"p cnf 1 0\n1 0\n", "dimacs.count"),
        "range": (b"p cnf 1 1\n2 0\n", "dimacs.range"),
        "range-zero-variables": (b"p cnf 0 1\n-1 0\n", "dimacs.range"),
    }
    for name, (data, which) in bad.items():
        d.add(f"dimacs-{name}", "dimacs", data, rule(which))


def side_file_documents(d: Documents) -> None:
    names = {"variables": 3}
    d.add("names-valid", "names-tsv", NAMES_TSV, context=names)
    d.add("names-empty", "names-tsv", b"", context=names)
    d.add("names-raw-unicode", "names-tsv", '1\t"\u00e9"\n'.encode(), context=names)
    d.add(
        "names-artifact",
        "names-tsv",
        NAMES_TSV,
        context=names
        | {"artifact": {"path": "names.tsv", "sha256": sha(NAMES_TSV), "bytes": len(NAMES_TSV)}},
    )
    d.add(
        "names-artifact-mismatch",
        "names-tsv",
        NAMES_TSV,
        rule("side.artifact"),
        names | {"artifact": {"path": "names.tsv", "sha256": sha(b"x"), "bytes": len(NAMES_TSV)}},
    )
    for name, data in {
        "not-json": b"1\ta\n",
        "escaped-unicode": b'1\t"\\u00e9"\n',
        "leading-zero": b'01\t"a"\n',
        "space": b'1 "a"\n',
        "no-final-lf": b'1\t"a"',
        "number-label": b"1\t1\n",
        "extra-column": b'1\t"a"\t"b"\n',
        "zero-id": b'0\t"a"\n',
    }.items():
        d.add(f"names-{name}", "names-tsv", data, rule("names.syntax"), names)
    d.add("names-unsorted", "names-tsv", b'2\t"b"\n1\t"a"\n', rule("names.order"), names)
    d.add("names-duplicate-id", "names-tsv", b'1\t"a"\n1\t"b"\n', rule("names.order"), names)
    d.add("names-out-of-range", "names-tsv", b'4\t"d"\n', rule("names.range"), names)
    tags = {"clauses": 8}
    d.add("tags-valid", "tags-tsv", b'1\t8\t"all"\n1\t8\t"b"\n2\t3\t"a"\n', context=tags)
    d.add("tags-corpus", "tags-tsv", TAGS_TSV, context={"clauses": 3})
    d.add("tags-two-columns", "tags-tsv", b'1\t"a"\n', rule("tags.syntax"), tags)
    d.add("tags-number-label", "tags-tsv", b"1\t2\t3\n", rule("tags.syntax"), tags)
    d.add("tags-unsorted", "tags-tsv", b'2\t3\t"a"\n1\t8\t"b"\n', rule("tags.order"), tags)
    d.add("tags-duplicate-line", "tags-tsv", b'1\t2\t"a"\n1\t2\t"a"\n', rule("tags.order"), tags)
    d.add("tags-first-after-last", "tags-tsv", b'3\t2\t"x"\n', rule("tags.range"), tags)
    d.add("tags-beyond-m", "tags-tsv", b'1\t9\t"x"\n', rule("tags.range"), tags)


# -- documents with schemas ---------------------------------------------------------------------


def manifest_documents(d: Documents) -> None:
    side = {"names.tsv": NAMES_TSV, "tags.tsv": TAGS_TSV}
    good = manifest(ALL3, {"all": [1, 2, 3], "none": []}, side)
    context = {"formula": ALL3.data.decode()}
    d.doc("manifest-valid", "bundle-manifest", good, context=context)
    d.doc("manifest-without-formula", "bundle-manifest", manifest(F_EMPTY, {}, {}))
    d.doc("manifest-unknown-field", "bundle-manifest", good | {"extra": 1}, at("$.extra"), context)
    d.doc(
        "manifest-side-name",
        "bundle-manifest",
        mutate(good, lambda v: v["side_files"][0].update(path="other.tsv")),
        at("$.side_files[0].path"),
        context,
    )
    d.doc(
        "manifest-pool-name",
        "bundle-manifest",
        mutate(good, lambda v: v["pools"].update(Bad=[1])),
        at("$.pools<Bad>"),
        context,
    )
    d.doc(
        "manifest-pool-zero",
        "bundle-manifest",
        mutate(good, lambda v: v["pools"].update(all=[0, 1])),
        at("$.pools.all[0]"),
        context,
    )
    d.doc(
        "manifest-negative-variables",
        "bundle-manifest",
        good | {"variables": -1},
        at("$.variables"),
        context,
    )
    d.doc(
        "manifest-format",
        "bundle-manifest",
        good | {"format": "cubeproof-bundle-2"},
        at("$.format"),
        context,
    )
    d.doc(
        "manifest-hash",
        "bundle-manifest",
        good | {"formula_sha256": SAT3.sha256},
        rule("bundle.formula_sha256"),
        context,
    )
    d.doc(
        "manifest-counts", "bundle-manifest", good | {"clauses": 7}, rule("bundle.counts"), context
    )
    d.doc(
        "manifest-pool-unsorted",
        "bundle-manifest",
        mutate(good, lambda v: v["pools"].update(all=[2, 1])),
        rule("bundle.pools"),
        context,
    )
    d.doc(
        "manifest-pool-duplicate",
        "bundle-manifest",
        mutate(good, lambda v: v["pools"].update(all=[1, 1])),
        rule("bundle.pools"),
        context,
    )
    d.doc(
        "manifest-pool-range",
        "bundle-manifest",
        mutate(good, lambda v: v["pools"].update(all=[4])),
        rule("bundle.pools"),
        context,
    )
    d.doc(
        "manifest-side-order",
        "bundle-manifest",
        mutate(good, lambda v: v["side_files"].reverse()),
        rule("bundle.side_files"),
        context,
    )


def policy_documents(d: Documents) -> None:
    d.doc("policy-default-transient", "policy", P_TRANSIENT)
    d.doc("policy-retain", "policy", P_RETAIN)
    d.doc("policy-stream", "policy", P_STREAM)
    d.doc("policy-pool", "policy", policy(split=P_TRANSIENT["split"] | {"pool": "all"}))
    d.doc("policy-default-key-only", "policy", policy(leaf_time_ms={"default": 1}))
    d.doc("policy-depth-keys", "policy", policy(leaf_time_ms={"0": 5, "100": 3, "default": 1}))
    d.doc(
        "policy-boundaries",
        "policy",
        policy(
            checker_max_heap_mib=512,
            stream_heap_mib=512,
            checker_max_stack_mib=256,
            max_cube_size=0,
            tool_retries=0,
        ),
    )
    missing = {k: v for k, v in P_TRANSIENT.items() if k != "anomaly_limit"}
    d.doc("policy-missing-field", "policy", missing, at("$"))
    d.doc("policy-unknown-field", "policy", P_TRANSIENT | {"extra": 1}, at("$.extra"))
    d.doc("policy-no-default", "policy", policy(leaf_time_ms={"12": 1}), at("$.leaf_time_ms"))
    d.doc(
        "policy-depth-leading-zero",
        "policy",
        policy(leaf_time_ms={"012": 1, "default": 1}),
        at("$.leaf_time_ms<012>"),
    )
    d.doc(
        "policy-depth-negative",
        "policy",
        policy(leaf_time_ms={"-1": 1, "default": 1}),
        at("$.leaf_time_ms<-1>"),
    )
    d.doc(
        "policy-leaf-time-zero",
        "policy",
        policy(leaf_time_ms={"default": 0}),
        at("$.leaf_time_ms.default"),
    )
    d.doc(
        "policy-method",
        "policy",
        policy(split=P_TRANSIENT["split"] | {"method": "static"}),
        at("$.split.method"),
    )
    d.doc(
        "policy-vars-21",
        "policy",
        policy(split=P_TRANSIENT["split"] | {"vars": 21}),
        at("$.split.vars"),
    )
    d.doc(
        "policy-vars-0",
        "policy",
        policy(split=P_TRANSIENT["split"] | {"vars": 0}),
        at("$.split.vars"),
    )
    d.doc(
        "policy-pool-name",
        "policy",
        policy(split=P_TRANSIENT["split"] | {"pool": "Bad"}),
        at("$.split.pool"),
    )
    d.doc(
        "policy-heap-511", "policy", policy(checker_max_heap_mib=511), at("$.checker_max_heap_mib")
    )
    d.doc("policy-stream-heap-511", "policy", policy(stream_heap_mib=511), at("$.stream_heap_mib"))
    d.doc("policy-mode", "policy", policy(proof_mode="keep"), at("$.proof_mode"))
    d.doc("policy-negative-cube-size", "policy", policy(max_cube_size=-1), at("$.max_cube_size"))
    d.doc("policy-boolean", "policy", policy(tool_retries=True), at("$.tool_retries"))
    d.doc("policy-zero-cap", "policy", policy(proof_cap_bytes=0), at("$.proof_cap_bytes"))
    d.doc(
        "policy-heap-fit-field",
        "policy",
        policy(heap_fit=P_TRANSIENT["heap_fit"] | {"extra": 1}),
        at("$.heap_fit.extra"),
    )
    d.doc("policy-stack", "policy", policy(checker_max_stack_mib=128), rule("policy.stack"))
    d.doc("policy-stream-heap", "policy", policy(stream_heap_mib=9000), rule("policy.stream_heap"))


def shard_value(*cubes: list[int]) -> dict[str, Any]:
    nodes = sorted(
        (node(ALL3, c) for c in cubes), key=lambda n: node_id(n["formula_sha256"], n["cube"])
    )
    return {
        "format": "cubeproof-shard-1",
        "campaign": sha("campaign"),
        "name": "s1",
        "nodes": nodes,
    }


def shard_documents(d: Documents) -> None:
    v3 = {"variables": 3}
    good = shard_value([1], [-1, 2], [-1, -2])
    d.doc("shard-valid", "shard", good, context=v3)
    d.doc("shard-empty-cube", "shard", shard_value([]), context=v3)
    d.doc("shard-no-nodes", "shard", good | {"nodes": []}, at("$.nodes"))
    d.doc("shard-name", "shard", good | {"name": "S1"}, at("$.name"))
    d.doc("shard-campaign", "shard", good | {"campaign": "X"}, at("$.campaign"))
    d.doc("shard-format", "shard", good | {"format": "cubeproof-shard-2"}, at("$.format"))
    d.doc(
        "shard-unsorted",
        "shard",
        mutate(good, lambda v: v["nodes"].reverse()),
        rule("shard.nodes"),
        v3,
    )
    d.doc("shard-overlap", "shard", shard_value([1], [1, 2]), rule("shard.nodes"), v3)
    d.doc(
        "shard-duplicate",
        "shard",
        mutate(shard_value([1]), lambda v: v["nodes"].append(v["nodes"][0])),
        rule("shard.nodes"),
        v3,
    )
    d.doc(
        "shard-cube-order",
        "shard",
        mutate(good, lambda v: v["nodes"][0].update(cube=[2, 1])),
        rule("cube.canonical"),
        v3,
    )
    d.doc("shard-cube-range", "shard", shard_value([4]), rule("cube.range"), v3)
    request = {
        "format": "cubeproof-handoff-request-1",
        "campaign": sha("campaign"),
        "request_id": ident("request"),
        "node_count": 3,
        "output_name": "to-b",
    }
    d.doc("request-valid", "handoff-request", request)
    d.doc("request-zero-nodes", "handoff-request", request | {"node_count": 0}, at("$.node_count"))
    d.doc(
        "request-short-id",
        "handoff-request",
        request | {"request_id": "0" * 31},
        at("$.request_id"),
    )
    d.doc(
        "request-path-name",
        "handoff-request",
        request | {"output_name": "a/b"},
        at("$.output_name"),
    )
    d.doc("request-unknown-field", "handoff-request", request | {"path": "x"}, at("$.path"))


# -- journal records ----------------------------------------------------------------------------


def record(kind: str, **payload: Any) -> dict[str, Any]:
    base = {
        "format": "cubeproof-journal-1",
        "seq": 7,
        "prev": sha("previous record"),
        "type": kind,
        "utc": "2026-10-01T00:00:07.000Z",
    }
    return sign(base | payload)


def line(value: dict[str, Any]) -> bytes:
    return jbytes(value) + b"\n"


def attempt(
    cube: list[int], preset: str, formula: Formula = ALL3, **changes: Any
) -> dict[str, Any]:
    fields = attempt_fields(
        formula,
        cube,
        preset,
        jsha(P_TRANSIENT),
        f"doc:{preset}:{cube}:{sorted(changes)}",
        **changes,
    )
    return record("attempt", **fields)


def resign(value: dict[str, Any], **changes: Any) -> dict[str, Any]:
    return sign({k: v for k, v in value.items() if k != "self"} | changes)


def record_documents(d: Documents) -> None:
    v3 = {"variables": 3}
    ok = v3 | {"admitted": True}
    header = record(
        "header",
        worker="w1",
        campaign=sha("campaign"),
        purpose="run",
        machinery=M_OK,
        policy=P_TRANSIENT,
        resources=RESOURCES,
    )
    d.add("record-header", "journal-record", line(header))
    d.add(
        "record-header-cubeproof-prefix",
        "journal-record",
        line(resign(header, machinery=machinery(manifest=MANIFEST_X))),
    )
    d.add(
        "record-header-cubeproof-bare",
        "journal-record",
        line(resign(header, machinery=machinery(manifest=MANIFEST_BARE))),
    )
    d.add(
        "record-resume",
        "journal-record",
        line(record("resume", machinery=M_OK, policy=P_STREAM, resources=RESOURCES)),
    )
    shard = shard_value([1], [-1])
    d.add(
        "record-shard",
        "journal-record",
        line(record("shard", shard=shard, shard_sha256=jsha(shard))),
        context=v3,
    )
    d.add(
        "record-split",
        "journal-record",
        line(
            record(
                "split",
                node=node(ALL3, [1]),
                variables=[3, 2],
                splitter={"name": "lookahead-v1", "info": {}},
            )
        ),
        context=v3,
    )
    d.add(
        "record-split-malformed-w",
        "journal-record",
        line(
            record(
                "split", node=node(ALL3, [1]), variables=[1, 1], splitter={"name": "x", "info": {}}
            )
        ),
        context=v3,
    )
    d.add(
        "record-node-stop",
        "journal-record",
        line(
            record(
                "node_stop",
                node=node(ALL3, [1]),
                state="stuck",
                reason="max_depth",
                policy_sha256=jsha(P_TRANSIENT),
            )
        ),
        context=v3,
    )
    d.add(
        "record-node-reopen",
        "journal-record",
        line(
            record("node_reopen", node=node(ALL3, [1]), reason="", policy_sha256=jsha(P_TRANSIENT))
        ),
        context=v3,
    )
    request = {
        "format": "cubeproof-handoff-request-1",
        "campaign": sha("campaign"),
        "request_id": ident("h"),
        "node_count": 2,
        "output_name": "o",
    }
    d.add(
        "record-handoff-empty",
        "journal-record",
        line(record("handoff", request=request, shard=None, shard_sha256=None)),
    )
    d.add(
        "record-handoff",
        "journal-record",
        line(record("handoff", request=request, shard=shard, shard_sha256=jsha(shard))),
        context=v3,
    )
    d.add(
        "record-repair",
        "journal-record",
        line(record("repair", removed_bytes=3, removed_sha256=sha(b"abc"))),
    )
    source = attempt([1], "vu_cdcl")
    target = {
        "node": source["node"],
        "node_id": source["node_id"],
        "source": {"journal": sha("j"), "seq": 7},
        "cnf_sha256": source["cnf_sha256"],
        "proof_sha256": source["proof_sha256"],
        "route": "cdcl",
        "machinery": M_OK,
    }
    targets = sha(jbytes(target) + b"\n")
    d.add(
        "record-audit-begin",
        "journal-record",
        line(
            record(
                "audit_begin",
                certificate_sha256=sha("c"),
                sample_count=1,
                seed=sha("s"),
                targets_sha256=targets,
                target_count=1,
                comparison="reprove",
            )
        ),
    )
    d.add(
        "record-audit-target",
        "journal-record",
        line(record("audit_target", target=target, ordinal=0)),
        context=v3,
    )
    d.add(
        "record-audit-ready",
        "journal-record",
        line(record("audit_ready", targets_sha256=targets, target_count=1)),
    )
    d.add(
        "record-audit-result",
        "journal-record",
        line(
            record(
                "audit_result",
                target=target,
                attempt={"journal": sha("j"), "seq": 9},
                status="REPROVED_UNSAT",
                reason="different profile",
            )
        ),
        context=v3,
    )

    for preset in PRESETS:
        if preset == "failed_relay":
            continue
        true = (
            [1]
            if preset in ("invalid_violated",)
            else ([1, 3] if preset.startswith("model") else None)
        )
        cube = [] if preset.startswith("model") else [1]
        formula = SAT3 if preset.startswith("model") else ALL3
        extra = {"true": true} if true is not None else {}
        d.add(
            f"attempt-{preset}",
            "journal-record",
            line(attempt(cube, preset, formula, **extra)),
            context=ok if preset.startswith("vu") else v3,
        )
    for mode in ("retain", "stream"):
        for preset in (
            "vu_cdcl",
            "vu_unit",
            "exhausted_time",
            "exhausted_check_memory",
            "rejected",
            "failed_crash",
            "failed_io",
        ):
            d.add(
                f"attempt-{preset}-{mode}",
                "journal-record",
                line(attempt([1], preset, mode=mode)),
                context=ok if preset.startswith("vu") else v3,
            )
    d.add(
        "attempt-failed_relay-stream",
        "journal-record",
        line(attempt([1], "failed_relay", mode="stream")),
        context=v3,
    )
    d.add(
        "attempt-model_cdcl-stream",
        "journal-record",
        line(attempt([], "model_cdcl", SAT3, mode="stream", true=[1, 3])),
        context=v3,
    )
    d.add(
        "attempt-model-zero-variables",
        "journal-record",
        line(attempt([], "model_unit", F_EMPTY, true=[])),
        context={"variables": 0},
    )
    d.add(
        "attempt-arena-retry",
        "journal-record",
        line(attempt([1], "vu_cdcl", checks=[check(CHECK_HEAP), check(CHECK_OK, 1024, 256)])),
        context=ok,
    )
    d.add(
        "attempt-audit-unlimited",
        "journal-record",
        line(
            attempt(
                [1],
                "vu_cdcl",
                limits={
                    "solver_time_ms": None,
                    "proof_cap_bytes": 1,
                    "solver_memory_bytes": 1,
                    "check_time_ms": 1,
                },
            )
        ),
        context=ok,
    )
    d.add(
        "attempt-tail-16k",
        "journal-record",
        line(attempt([1], "failed_crash", solver=SOLVER_CRASH | {"stderr_tail": "x" * 16384})),
        context=v3,
    )
    d.add(
        "attempt-not-admitted-bad-output",
        "journal-record",
        line(attempt([1], "vu_cdcl", checks=[check(out("s VERIFIED UNSAT"))])),
        context=v3 | {"admitted": False},
    )

    vu = attempt([1], "vu_cdcl")
    bad: list[tuple[str, dict[str, Any] | bytes, Any, dict[str, Any] | None]] = [
        ("unknown-type", record("note", text="x"), at("$"), None),
        ("unknown-field", resign(vu, extra=1), at("$.extra"), None),
        (
            "missing-field",
            sign({k: v for k, v in vu.items() if k not in ("self", "diagnostics")}),
            at("$"),
            None,
        ),
        ("boolean-integer", resign(vu, proof_bytes=True), at("$.proof_bytes"), None),
        (
            "zero-literal",
            resign(vu, node={"formula_sha256": ALL3.sha256, "cube": [0]}),
            at("$.node.cube[0]"),
            None,
        ),
        ("uppercase-hash", resign(vu, node_id=vu["node_id"].upper()), at("$.node_id"), None),
        ("exit-256", resign(vu, solver=vu["solver"] | {"exit": 256}), at("$.solver"), None),
        (
            "signal-0",
            resign(vu, solver=vu["solver"] | {"exit": None, "signal": 0}),
            at("$.solver"),
            None,
        ),
        ("null-check", resign(vu, checks=[None]), at("$.checks[0]"), None),
        ("outcome", resign(vu, outcome="UNSAT"), at("$.outcome"), None),
        (
            "reason-unknown",
            resign(attempt([1], "exhausted_time"), reason="oom"),
            at("$.reason"),
            None,
        ),
        ("reason-empty", resign(attempt([1], "exhausted_time"), reason=""), at("$.reason"), None),
        (
            "assignment-unpadded",
            resign(attempt([1], "invalid_violated", true=[1]), assignment="Ag"),
            at("$.assignment"),
            None,
        ),
        ("format", resign(vu, format="cubeproof-journal-2"), at("$.format"), None),
        ("negative-seq", resign(vu, seq=-1), at("$.seq"), None),
        ("utc-format", resign(vu, utc="2026-10-01"), at("$.utc"), None),
        ("purpose", resign(header, purpose="debug"), at("$.purpose"), None),
        (
            "stop-state",
            record(
                "node_stop",
                node=node(ALL3, [1]),
                state="model",
                reason="",
                policy_sha256=jsha(P_TRANSIENT),
            ),
            at("$.state"),
            None,
        ),
        ("worker-name", resign(header, worker="W1"), at("$.worker"), None),
        # a header names no machine: a field for one is an unknown field
        ("header-host", resign(header, host="unknown"), at("$.host"), None),
        (
            "relay-field",
            resign(attempt([1], "vu_cdcl", mode="stream"), relay={"bytes": 1}),
            at("$.relay"),
            None,
        ),
        (
            "machinery-unit",
            resign(header, machinery=M_OK | {"unit_algorithm": "unit-v2"}),
            at("$.machinery.unit_algorithm"),
            None,
        ),
        (
            "manifest-path",
            resign(header, machinery=machinery(manifest=[{"path": "../x", "sha256": sha("x")}])),
            at("$.machinery.source_manifest[0].path"),
            None,
        ),
        (
            "repair-zero",
            record("repair", removed_bytes=0, removed_sha256=sha(b"")),
            at("$.removed_bytes"),
            None,
        ),
        ("utc-calendar", resign(vu, utc="2026-02-30T00:00:00.000Z"), rule("utc.calendar"), v3),
        (
            "manifest-order",
            resign(header, machinery=machinery(manifest=list(reversed(MANIFEST)))),
            rule("machinery.manifest_order"),
            None,
        ),
        (
            "packages-hash",
            resign(header, machinery=M_OK | {"packages_sha256": sha("x")}),
            rule("machinery.packages_sha256"),
            None,
        ),
        (
            "cubeproof-hash",
            resign(header, machinery=M_OK | {"cubeproof_sha256": jsha(MANIFEST)}),
            rule("machinery.cubeproof_sha256"),
            None,
        ),
        (
            # routine reading 6: "cubeproofx/..." is not under the first path component "cubeproof"
            "cubeproof-hash-prefix",
            resign(
                header,
                machinery=machinery(manifest=MANIFEST_X)
                | {
                    "cubeproof_sha256": jsha(
                        [e for e in MANIFEST_X if e["path"].startswith("cubeproof")]
                    )
                },
            ),
            rule("machinery.cubeproof_sha256"),
            None,
        ),
        (
            # routine reading 6: the entry "cubeproof" itself is a cubeproof entry; this hash leaves
            # it out (prefix "cubeproof/")
            "cubeproof-hash-bare",
            resign(
                header,
                machinery=machinery(manifest=MANIFEST_BARE)
                | {
                    "cubeproof_sha256": jsha(
                        [e for e in MANIFEST_BARE if e["path"].startswith("cubeproof/")]
                    )
                },
            ),
            rule("machinery.cubeproof_sha256"),
            None,
        ),
        (
            "policy-stack",
            resign(header, policy=policy(checker_max_stack_mib=1)),
            rule("policy.stack"),
            None,
        ),
        (
            "policy-stream-heap",
            resign(header, policy=policy(stream_heap_mib=8193)),
            rule("policy.stream_heap"),
            None,
        ),
        (
            "exit-and-signal",
            attempt([1], "failed_crash", solver=SOLVER_CRASH | {"exit": 1}),
            rule("process.exit_signal"),
            v3,
        ),
        (
            "not-started-exit",
            attempt([1], "failed_launch", solver=NOT_STARTED | {"exit": 2}),
            rule("process.not_started"),
            v3,
        ),
        (
            "tail-bytes",
            attempt([1], "failed_crash", solver=SOLVER_CRASH | {"stderr_tail": "x" * 16385}),
            rule("process.tail_size"),
            v3,
        ),
        (
            "tail-multibyte",
            attempt(
                [1],
                "failed_crash",
                solver=SOLVER_CRASH | {"stdout_tail": "\u00e9" * 8193, "stdout_bytes": 16386},
            ),
            rule("process.tail_size"),
            v3,
        ),
        (
            "node-id",
            attempt([1], "vu_cdcl", node_id=node_id(ALL3.sha256, [-1])),
            rule("record.node_id"),
            v3,
        ),
        ("cube-order", attempt([2, 1], "vu_cdcl"), rule("cube.canonical"), v3),
        (
            "cube-contradictory",
            record(
                "node_stop",
                node=node(ALL3, [1, -1]),
                state="stuck",
                reason="",
                policy_sha256=jsha(P_TRANSIENT),
            ),
            rule("cube.canonical"),
            v3,
        ),
        ("cube-range", attempt([4], "vu_cdcl"), rule("cube.range"), v3),
        ("reason-on-verified", attempt([1], "vu_cdcl", reason="time"), rule("attempt.reason"), v3),
        (
            "reason-wrong-outcome",
            attempt([1], "exhausted_time", reason="crash"),
            rule("attempt.reason"),
            v3,
        ),
        (
            "reason-rejected",
            attempt([1], "rejected", reason="protocol"),
            rule("attempt.reason"),
            v3,
        ),
        (
            "reason-tool-failed",
            attempt([1], "failed_crash", reason="rejected"),
            rule("attempt.reason"),
            v3,
        ),
        (
            "reason-model",
            attempt([], "model_cdcl", SAT3, true=[1, 3], reason="violated"),
            rule("attempt.reason"),
            v3,
        ),
        (
            "reason-invalid-model",
            attempt([1], "invalid_syntax", reason="missing"),
            rule("attempt.reason"),
            v3,
        ),
        (
            "unit-with-solver",
            attempt([1, 2], "vu_unit", solver=vu["solver"]),
            rule("attempt.solver"),
            v3,
        ),
        (
            "cdcl-without-solver",
            attempt([1], "exhausted_time", solver=None),
            rule("attempt.solver"),
            v3,
        ),
        (
            "stream-without-relay",
            attempt([1], "vu_cdcl", mode="stream", relay=None),
            rule("attempt.relay"),
            v3,
        ),
        (
            "file-mode-relay",
            attempt(
                [1],
                "exhausted_time",
                relay={
                    "bytes": 1,
                    "sha256": sha("r"),
                    "solver_eof": False,
                    "all_written": False,
                    "error": None,
                },
            ),
            rule("attempt.relay"),
            v3,
        ),
        (
            "proof-pair",
            attempt([1], "exhausted_check_time", proof_sha256=None),
            rule("attempt.proof_pair"),
            v3,
        ),
        (
            "stream-partial-proof",
            attempt(
                [1],
                "exhausted_check_memory",
                mode="stream",
                proof_bytes=4096,
                proof_sha256=sha("p"),
            ),
            rule("attempt.stream_proof"),
            v3,
        ),
        (
            "stream-proof-mismatch",
            attempt([1], "failed_file_changed", mode="stream", proof_bytes=1),
            rule("attempt.stream_proof"),
            v3,
        ),
        *(
            (
                f"stream-proof-{name}",
                attempt(
                    [1],
                    "vu_cdcl",
                    mode="stream",
                    proof=sha("p"),
                    relay={
                        "bytes": 1037,
                        "sha256": sha("p"),
                        "solver_eof": True,
                        "all_written": True,
                        "error": None,
                    }
                    | change,
                ),
                rule("attempt.stream_proof"),
                v3,
            )
            for name, change in (
                ("no-solver-eof", {"solver_eof": False}),
                ("not-all-written", {"all_written": False}),
                ("relay-error", {"error": "EPIPE"}),
            )
        ),
        (
            "model-with-proof",
            attempt([], "model_cdcl", SAT3, true=[1, 3], proof_bytes=1, proof_sha256=sha("p")),
            rule("attempt.model_shape"),
            v3,
        ),
        (
            "model-with-checks",
            attempt([], "model_cdcl", SAT3, true=[1, 3], checks=[check(CHECK_OK)]),
            rule("attempt.model_shape"),
            v3,
        ),
        (
            "model-exit-20",
            attempt([], "model_cdcl", SAT3, true=[1, 3], solver=vu["solver"]),
            rule("attempt.model_shape"),
            v3,
        ),
        (
            "model-with-error",
            attempt([], "model_cdcl", SAT3, true=[1, 3], model_error="violated"),
            rule("attempt.model_error"),
            v3,
        ),
        (
            "model-without-assignment",
            attempt([], "model_cdcl", SAT3),
            rule("attempt.model_error"),
            v3,
        ),
        (
            "parse-error-with-assignment",
            attempt([1], "invalid_syntax", true=[1]),
            rule("attempt.model_error"),
            v3,
        ),
        (
            "violated-without-assignment",
            attempt([1], "invalid_violated"),
            rule("attempt.model_error"),
            v3,
        ),
        (
            "exhausted-with-assignment",
            attempt([1], "exhausted_time", true=[1]),
            rule("attempt.model_error"),
            v3,
        ),
        (
            "assignment-length",
            attempt([1], "invalid_violated", assignment="AAA="),
            rule("attempt.assignment"),
            v3,
        ),
        (
            "assignment-unused-bit",
            attempt([1], "invalid_violated", assignment="CA=="),
            rule("attempt.assignment"),
            v3,
        ),
        (
            "assignment-noncanonical",
            attempt([1], "invalid_violated", assignment="BR=="),
            rule("attempt.assignment"),
            v3,
        ),
        (
            "assignment-zero-variables",
            attempt([], "model_unit", F_EMPTY, assignment="AA=="),
            rule("attempt.assignment"),
            {"variables": 0},
        ),
        (
            "retained-transient",
            attempt(
                [1],
                "vu_cdcl",
                retained={"path": "proofs/x.lrat", "sha256": sha("proof|x"), "bytes": 1},
            ),
            rule("attempt.retained"),
            v3,
        ),
        (
            "retained-other-proof",
            attempt(
                [1],
                "vu_cdcl",
                mode="retain",
                proof=sha("a"),
                retained={"path": "proofs/x.lrat", "sha256": sha("b"), "bytes": 1037},
            ),
            rule("attempt.retained"),
            v3,
        ),
        (
            "retained-rejected",
            attempt(
                [1],
                "rejected",
                mode="retain",
                retained={"path": "proofs/x.lrat", "sha256": sha("proof|x"), "bytes": 1037},
            ),
            rule("attempt.retained"),
            v3,
        ),
        (
            "quarantined-stream",
            attempt(
                [1],
                "rejected",
                mode="stream",
                quarantined={"path": "quarantine/x.lrat", "sha256": sha("q"), "bytes": 1},
            ),
            rule("attempt.quarantined"),
            v3,
        ),
        (
            "quarantined-verified",
            attempt(
                [1],
                "vu_cdcl",
                quarantined={"path": "quarantine/x.lrat", "sha256": sha("q"), "bytes": 1},
            ),
            rule("attempt.quarantined"),
            v3,
        ),
        (
            "success-no-proof",
            attempt([1, 2], "vu_unit", proof_bytes=None, proof_sha256=None),
            rule("success.proof"),
            ok,
        ),
        ("success-no-checks", attempt([1], "vu_cdcl", checks=[]), rule("success.checks"), ok),
        (
            "success-exit-1",
            attempt([1], "vu_cdcl", checks=[check(out("s VERIFIED UNSAT\n", exit=1))]),
            rule("success.checker_output"),
            ok,
        ),
        (
            "success-no-lf",
            attempt([1], "vu_cdcl", checks=[check(out("s VERIFIED UNSAT"))]),
            rule("success.checker_output"),
            ok,
        ),
        (
            "success-truncated",
            attempt(
                [1], "vu_cdcl", checks=[check(out("s VERIFIED UNSAT\n", stdout_truncated=True))]
            ),
            rule("success.checker_output"),
            ok,
        ),
        (
            "success-other-line",
            attempt([1], "vu_cdcl", checks=[check(out("s VERIFIED unsat\n"))]),
            rule("success.checker_output"),
            ok,
        ),
        (
            "success-more-output",
            attempt([1], "vu_cdcl", checks=[check(out("s VERIFIED UNSAT\n", stdout_bytes=18))]),
            rule("success.checker_output"),
            ok,
        ),
        (
            "success-signal",
            attempt([1], "vu_cdcl", checks=[check(out("s VERIFIED UNSAT\n", exit=None, signal=9))]),
            rule("success.checker_output"),
            ok,
        ),
        (
            "success-last-check-arena",
            attempt([1], "vu_cdcl", checks=[check(CHECK_OK), check(CHECK_HEAP)]),
            rule("success.checker_output"),
            ok,
        ),
        (
            "success-solver-exit-10",
            attempt([1], "vu_cdcl", solver=SOLVER_SAT),
            rule("success.solver"),
            ok,
        ),
        (
            "success-solver-signal",
            attempt([1], "vu_cdcl", solver=SOLVER_TIMEOUT),
            rule("success.solver"),
            ok,
        ),
        (
            "success-solver-not-started",
            attempt([1], "vu_cdcl", solver=NOT_STARTED),
            rule("success.solver"),
            ok,
        ),
        (
            "shard-unsorted",
            record(
                "shard",
                shard=mutate(shard, lambda v: v["nodes"].reverse()),
                shard_sha256=jsha(mutate(shard, lambda v: v["nodes"].reverse())),
            ),
            rule("shard.nodes"),
            v3,
        ),
        ("shard-hash", record("shard", shard=shard, shard_sha256=sha("x")), rule("shard.hash"), v3),
        (
            "handoff-pair",
            record("handoff", request=request, shard=None, shard_sha256=sha("x")),
            rule("handoff.pair"),
            None,
        ),
        (
            "handoff-hash",
            record("handoff", request=request, shard=shard, shard_sha256=sha("x")),
            rule("shard.hash"),
            v3,
        ),
        (
            "handoff-count",
            record(
                "handoff",
                request=request | {"node_count": 1},
                shard=shard,
                shard_sha256=jsha(shard),
            ),
            rule("handoff.count"),
            v3,
        ),
        (
            "audit-target-node-id",
            record("audit_target", target=target | {"node_id": sha("x")}, ordinal=0),
            rule("record.node_id"),
            v3,
        ),
        ("no-final-lf", jbytes(vu), rule("json.canonical"), v3),
        (
            "spaces",
            json.dumps(vu, sort_keys=True, separators=(", ", ": ")).encode() + b"\n",
            rule("json.canonical"),
            v3,
        ),
    ]
    for name, value, expect, context in bad:
        data = value if isinstance(value, bytes) else line(value)
        d.add(f"record-{name}", "journal-record", data, expect, context)


# -- certificate, evidence manifest, audit report, status and small inputs ---------------------


def certificate_documents(d: Documents, certificates: dict[str, dict[str, Any]]) -> None:
    pilot = certificates["pilot_root"]
    d.doc("certificate-pilot-root", "certificate", pilot)
    d.doc("certificate-catalogue", "certificate", certificates["catalogue"])
    d.doc("certificate-duplicates", "certificate", certificates["duplicates"])
    incomplete = certificates["split_incomplete"]
    d.doc("certificate-split-incomplete", "certificate", incomplete)
    d.doc("certificate-unknown-field", "certificate", pilot | {"extra": 1}, at("$.extra"))
    d.doc("certificate-verdict", "certificate", pilot | {"verdict": "UNKNOWN"}, at("$.verdict"))
    d.doc(
        "certificate-open-state",
        "certificate",
        mutate(incomplete, lambda v: v["open"][0].update(state="done")),
        at("$.open[0].state"),
    )
    d.doc(
        "certificate-anomaly-code",
        "certificate",
        mutate(certificates["catalogue"], lambda v: v["anomalies"][0].update(code="other")),
        at("$.anomalies[0].code"),
    )
    d.doc(
        "certificate-journal-order",
        "certificate",
        mutate(certificates["duplicates"], lambda v: v["journals"].reverse()),
        rule("certificate.order"),
    )
    d.doc(
        "certificate-anomaly-order",
        "certificate",
        mutate(certificates["catalogue"], lambda v: v["anomalies"].reverse()),
        rule("certificate.order"),
    )
    d.doc(
        "certificate-open-summary",
        "certificate",
        mutate(incomplete, lambda v: v["formulas"][0]["roots"][0]["summary"].update(leaves=1)),
        rule("certificate.summary"),
    )
    d.doc(
        "certificate-closed-without-root",
        "certificate",
        mutate(
            pilot, lambda v: v["formulas"][0]["roots"][0]["summary"].update(leaf_merkle_root=None)
        ),
        rule("certificate.summary"),
    )
    d.doc(
        "certificate-node-id",
        "certificate",
        mutate(pilot, lambda v: v["used_attempts"][0].update(node_id=sha("x"))),
        rule("record.node_id"),
    )


def artifact(path: str, data: bytes = b"x") -> dict[str, Any]:
    return {"path": path, "sha256": sha(data), "bytes": len(data)}


def evidence_documents(d: Documents) -> None:
    good: dict[str, Any] = {
        "format": "cubeproof-evidence-1",
        "campaign": artifact("campaign.json"),
        "bundles": [
            {
                "manifest": artifact("bundles/all3/manifest.json"),
                "formula": artifact("bundles/all3/formula.cnf"),
            },
            {
                "manifest": artifact("bundles/sat3/manifest.json"),
                "formula": artifact("bundles/sat3/formula.cnf"),
            },
        ],
        "journals": [artifact("journals/w1.jsonl"), artifact("journals/w2.jsonl")],
        "certificate": artifact("certificate.json"),
    }
    d.doc("evidence-valid", "evidence-manifest", good)
    d.doc(
        "evidence-journal-order",
        "evidence-manifest",
        mutate(good, lambda v: v["journals"].reverse()),
        rule("evidence.order"),
    )
    d.doc(
        "evidence-bundle-order",
        "evidence-manifest",
        mutate(good, lambda v: v["bundles"].reverse()),
        rule("evidence.order"),
    )
    for name, path in {
        "parent": "../w1.jsonl",
        "dot": "./w1.jsonl",
        "absolute": "/w1.jsonl",
        "backslash": "journals\\w1.jsonl",
        "drive": "C:w1.jsonl",
        "empty-component": "journals//w1.jsonl",
        "trailing-slash": "journals/",
        "nul": "w1\u0000.jsonl",
    }.items():
        changed = copy.deepcopy(good)
        changed["journals"][0]["path"] = path
        d.doc(f"evidence-path-{name}", "evidence-manifest", changed, at("$.journals[0].path"))


def audit_report_documents(d: Documents) -> None:
    target = {
        "node": node(ALL3, [1]),
        "node_id": node_id(ALL3.sha256, [1]),
        "source": {"journal": sha("j"), "seq": 3},
        "cnf_sha256": ALL3.cube_sha256([1]),
        "proof_sha256": sha("p"),
        "route": "cdcl",
        "machinery": M_OK,
    }
    statuses = ["HASH_MATCHED", "REPROVED_UNSAT", "MISMATCH", "NOT_COMPARABLE", "FAILED", "OPEN"]
    good = {
        "format": "cubeproof-audit-report-1",
        "campaign": sha("campaign"),
        "certificate_sha256": sha("certificate"),
        "targets_sha256": sha(jbytes(target) + b"\n"),
        "comparison": "strict",
        "population": 3,
        "selected": 2,
        "seed": sha("seed"),
        "counts": dict.fromkeys(statuses, 0) | {"HASH_MATCHED": 1},
        "results": [
            {
                "target": target,
                "record": {"journal": sha("a"), "seq": 5},
                "status": "HASH_MATCHED",
                "reason": "",
            }
        ],
        "pending": [node_id(ALL3.sha256, [-1])],
    }
    d.doc("audit-report-valid", "audit-report", good)
    d.doc(
        "audit-report-counts",
        "audit-report",
        mutate(good, lambda v: v["counts"].update(HASH_MATCHED=0)),
        rule("audit_report.counts"),
    )
    d.doc(
        "audit-report-selected",
        "audit-report",
        good | {"selected": 3},
        rule("audit_report.selected"),
    )
    d.doc(
        "audit-report-population",
        "audit-report",
        good | {"population": 1},
        rule("audit_report.selected"),
    )
    d.doc(
        "audit-report-missing-status",
        "audit-report",
        mutate(good, lambda v: v["counts"].pop("OPEN")),
        at("$.counts"),
    )
    d.doc(
        "audit-report-extra-status",
        "audit-report",
        mutate(good, lambda v: v["counts"].update(OK=0)),
        at("$.counts.OK"),
    )
    d.doc(
        "audit-report-comparison",
        "audit-report",
        good | {"comparison": "loose"},
        at("$.comparison"),
    )


def status_documents(d: Documents) -> None:
    good = {
        "format": "cubeproof-status-1",
        "campaign": sha("campaign"),
        "journal": sha("journal"),
        "head": sha("head"),
        "policy_sha256": jsha(P_TRANSIENT),
        "worker": "w1",
        "seq": 12,
        "utc": "2026-10-01T00:01:00.000Z",
        "lifecycle": "running",
        "resources": RESOURCES,
        "reservations": sorted(
            [
                {
                    "task_id": ident("t1"),
                    "stage": "solve",
                    "cpu_milli": 1000,
                    "memory_bytes": 1,
                    "disk": [{"id": "results", "bytes": 5}],
                },
                {
                    "task_id": ident("t2"),
                    "stage": "check",
                    "cpu_milli": 1000,
                    "memory_bytes": 2,
                    "disk": [],
                },
            ],
            key=lambda r: str(r["task_id"]),
        ),
        "node_counts": [
            {"state": "closed", "depth": 1, "count": 2},
            {"state": "pending", "depth": 1, "count": 1},
        ],
        "active": [{"task_id": ident("t1"), "node_id": None, "stage": "solve", "elapsed_ms": 10}],
        "oldest_elapsed_ms": 10,
        "counters": {"attempts": 3, "models total": 0},
        "export": {
            "head": sha("head"),
            "seq": 11,
            "utc": "2026-10-01T00:00:30.000Z",
            "lag_ms": 30000,
        },
        "models": [],
        "anomalies": [{"journal": sha("journal"), "seq": 4}],
        "coverage": [{"node": node(ALL3, []), "closed_numerator": "3", "denominator_power_two": 2}],
        "eta_ms": None,
        "info": {"stall": None},
    }
    d.doc("status-valid", "status", good)
    d.doc(
        "status-full-coverage",
        "status",
        good
        | {
            "coverage": [
                {"node": node(ALL3, []), "closed_numerator": "1", "denominator_power_two": 0}
            ],
            "export": None,
        },
    )
    d.doc(
        "status-order",
        "status",
        mutate(good, lambda v: v["reservations"].reverse()),
        rule("status.order"),
    )
    d.doc(
        "status-not-reduced",
        "status",
        mutate(good, lambda v: v["coverage"][0].update(closed_numerator="2")),
        rule("status.coverage"),
    )
    d.doc(
        "status-above-one",
        "status",
        mutate(
            good, lambda v: v["coverage"][0].update(closed_numerator="3", denominator_power_two=1)
        ),
        rule("status.coverage"),
    )
    d.doc("status-utc", "status", good | {"utc": "2026-02-30T00:00:00.000Z"}, rule("utc.calendar"))
    d.doc(
        "status-too-many-models",
        "status",
        good | {"models": [{"journal": sha("j"), "seq": i} for i in range(101)]},
        at("$.models"),
    )
    d.doc("status-lifecycle", "status", good | {"lifecycle": "paused"}, at("$.lifecycle"))
    d.doc(
        "status-numerator",
        "status",
        mutate(good, lambda v: v["coverage"][0].update(closed_numerator="03")),
        at("$.coverage[0].closed_numerator"),
    )
    d.doc(
        "status-counter-name",
        "status",
        mutate(good, lambda v: v["counters"].update({"caf\u00e9": 1})),
        at("$.counters<caf\u00e9>"),
    )


def small_documents(d: Documents) -> None:
    planned = [node_id(ALL3.sha256, [1]), node_id(ALL3.sha256, [-1])]
    weights = {
        "format": "cubeproof-weights-1",
        "campaign": sha("campaign"),
        "costs": {planned[0]: 5, planned[1]: 1},
    }
    context = {"planned": planned}
    d.doc("weights-valid", "weights", weights, context=context)
    d.doc(
        "weights-unknown",
        "weights",
        mutate(weights, lambda v: v["costs"].update({sha("other"): 1})),
        rule("weights.unknown"),
        context,
    )
    d.doc(
        "weights-zero",
        "weights",
        mutate(weights, lambda v: v["costs"].update({planned[0]: 0})),
        at(f"$.costs.{planned[0]}"),
        context,
    )
    d.doc(
        "weights-key",
        "weights",
        mutate(weights, lambda v: v["costs"].update(abc=1)),
        at("$.costs<abc>"),
        context,
    )
    roots = {"format": "cubeproof-roots-1", "roots": shard_value([1], [-1, 2])["nodes"]}
    d.doc("roots-valid", "roots", roots)
    d.doc(
        "roots-overlap",
        "roots",
        {"format": "cubeproof-roots-1", "roots": shard_value([1], [1, 2])["nodes"]},
        rule("roots.nodes"),
    )
    d.doc("roots-empty", "roots", {"format": "cubeproof-roots-1", "roots": []}, at("$.roots"))
    d.doc(
        "roots-cube",
        "roots",
        {"format": "cubeproof-roots-1", "roots": [node(ALL3, [3, 1])]},
        rule("cube.canonical"),
    )
    entries: list[dict[str, Any]] = [
        {
            "node": node(ALL3, cube),
            "variables": w,
            "splitter": {"name": "proof-prefix-v1", "info": {"seed": 5}},
        }
        for cube, w in (([], [1, 2]), ([-1], [3]))
    ]
    entries.sort(key=entry_split_id)
    prefixes = {"format": "cubeproof-prefixes-1", "splits": entries}
    v = {"formulas": {ALL3.sha256: 3}}
    d.doc("prefixes-valid", "prefixes", prefixes, context=v)
    d.doc("prefixes-empty", "prefixes", {"format": "cubeproof-prefixes-1", "splits": []})
    d.doc(
        "prefixes-order",
        "prefixes",
        mutate(prefixes, lambda x: x["splits"].reverse()),
        rule("prefixes.order"),
        v,
    )
    d.doc(
        "prefixes-repeated",
        "prefixes",
        {
            "format": "cubeproof-prefixes-1",
            "splits": [
                {
                    "node": node(ALL3, []),
                    "variables": [2, 2],
                    "splitter": {"name": "static", "info": {}},
                }
            ],
        },
        rule("split.repeated"),
        v,
    )
    d.doc(
        "prefixes-out-of-range",
        "prefixes",
        {
            "format": "cubeproof-prefixes-1",
            "splits": [
                {
                    "node": node(ALL3, []),
                    "variables": [4],
                    "splitter": {"name": "static", "info": {}},
                }
            ],
        },
        rule("split.out_of_range"),
        v,
    )
    d.doc(
        "prefixes-in-cube",
        "prefixes",
        {
            "format": "cubeproof-prefixes-1",
            "splits": [
                {
                    "node": node(ALL3, [1]),
                    "variables": [1],
                    "splitter": {"name": "static", "info": {}},
                }
            ],
        },
        rule("split.in_cube"),
        v,
    )
    d.doc(
        "prefixes-empty-w",
        "prefixes",
        {
            "format": "cubeproof-prefixes-1",
            "splits": [
                {
                    "node": node(ALL3, []),
                    "variables": [],
                    "splitter": {"name": "static", "info": {}},
                }
            ],
        },
        rule("split.empty"),
        v,
    )
    d.doc(
        "prefixes-long-w",
        "prefixes",
        {
            "format": "cubeproof-prefixes-1",
            "splits": [
                {
                    "node": node(ALL3, []),
                    "variables": list(range(1, 22)),
                    "splitter": {"name": "static", "info": {}},
                }
            ],
        },
        rule("split.too_long"),
        v,
    )
    d.doc(
        "prefixes-zero",
        "prefixes",
        {
            "format": "cubeproof-prefixes-1",
            "splits": [
                {
                    "node": node(ALL3, []),
                    "variables": [0],
                    "splitter": {"name": "static", "info": {}},
                }
            ],
        },
        at("$.splits[0].variables[0]"),
        v,
    )
    request = {
        "format": "cubeproof-look-request-1",
        "formula_path": "/work/scratch/formula.cnf",
        "formula_sha256": ALL3.sha256,
        "cube": [-1],
        "k": 2,
        "pool": [2, 3],
        "probe_limit": 100000,
        "wall_ms": None,
    }
    d.doc("look-request-valid", "look-request", request)
    d.doc("look-request-no-pool", "look-request", request | {"pool": None, "wall_ms": 1000})
    d.doc("look-request-pool-order", "look-request", request | {"pool": [3, 2]}, rule("look.pool"))
    d.doc("look-request-cube", "look-request", request | {"cube": [2, -1]}, rule("cube.canonical"))
    d.doc("look-request-k-0", "look-request", request | {"k": 0}, at("$.k"))
    d.doc("look-request-k-21", "look-request", request | {"k": 21}, at("$.k"))
    d.doc("look-request-wall-0", "look-request", request | {"wall_ms": 0}, at("$.wall_ms"))
    d.doc("look-request-field", "look-request", request | {"seed": 1}, at("$.seed"))
    result = {
        "format": "cubeproof-look-result-1",
        "node_id": node_id(ALL3.sha256, [-1]),
        "variables": [3, 2],
        "status": "chosen",
        "info": {"probes": 40},
    }
    d.doc("look-result-valid", "look-result", result)
    d.doc("look-result-empty", "look-result", result | {"variables": [], "status": "no_eligible"})
    d.doc(
        "look-result-repeated",
        "look-result",
        result | {"variables": [2, 2]},
        rule("look.variables"),
    )
    d.doc("look-result-status", "look-result", result | {"status": "ok"}, at("$.status"))
    d.doc(
        "look-result-too-many",
        "look-result",
        result | {"variables": list(range(1, 22))},
        at("$.variables"),
    )


def build(certificates: dict[str, dict[str, Any]]) -> bytes:
    d = Documents()
    json_documents(d)
    dimacs_documents(d)
    side_file_documents(d)
    manifest_documents(d)
    policy_documents(d)
    shard_documents(d)
    record_documents(d)
    certificate_documents(d, certificates)
    evidence_documents(d)
    audit_report_documents(d)
    status_documents(d)
    small_documents(d)
    value = {"format": "cubeproof-contract-documents-1", "documents": d.entries}
    return (json.dumps(value, indent=1, sort_keys=True, ensure_ascii=False) + "\n").encode()
