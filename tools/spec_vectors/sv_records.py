"""Records of the corpus: tools, machinery, policies, journals and attempts.

Specification §4.3-§4.8 and §7.1.

Builders produce complete, consistent records; tests and cases derive invalid variants by
changing exactly one thing. Identifiers are deterministic (derived from labels), so the
corpus is reproducible byte for byte.
"""

from __future__ import annotations

import copy
from collections.abc import Sequence
from typing import Any

from sv_spec import VERIFIED, ZERO, Formula, bitset, jbytes, jsha, node, node_id, sha, utc

CHECKER = sha("cake_lpr admitted test binary")
CHECKER_BAD = sha("cake_lpr unadmitted test binary")
SOLVER = sha("cadical admitted test binary")
ARGV = ["--lrat"]
ARGV_SEED = ["--lrat", "--seed=1"]

DEFAULT_POLICY: dict[str, Any] = {
    "leaf_time_ms": {"12": 900000, "default": 300000},
    "proof_cap_bytes": 4294967296,
    "solver_memory_bytes": 1073741824,
    "checker_max_heap_mib": 8192,
    "checker_stack_mib": 256,
    "checker_max_stack_mib": 2048,
    "checker_slack_mib": 256,
    "checker_time_base_ms": 600000,
    "checker_time_per_100mb_ms": 60000,
    "heap_fit": {
        "coefficient_milli": 3230,
        "exponent_milli": 711,
        "margin_milli": 1500,
        "min_mib": 512,
    },
    "split": {
        "method": "lookahead-v1",
        "vars": 4,
        "pool": None,
        "probe_limit": 100000,
        "wall_ms": 1000,
    },
    "max_cube_size": 60,
    "proof_mode": "transient",
    "stream_heap_mib": 1024,
    "quarantine_quota_bytes": 21474836480,
    "tool_retries": 3,
    "machine_failure_limit": 5,
    "anomaly_limit": 3,
    "term_grace_ms": 10000,
    "stop_grace_ms": 30000,
}


def policy(mode: str = "transient", **changes: Any) -> dict[str, Any]:
    value = copy.deepcopy(DEFAULT_POLICY) | {"proof_mode": mode}
    return value | changes


P_TRANSIENT = policy("transient")
P_RETAIN = policy("retain")
P_STREAM = policy("stream")

RESOURCES: dict[str, Any] = {
    "cpu_milli": 8000,
    "memory_budget_bytes": 17179869184,
    "filesystems": [
        {
            "id": "results",
            "paths": ["/work/results", "/work/scratch"],
            "free_bytes": 107374182400,
            "budget_bytes": 53687091200,
        }
    ],
    "coordinator_rss_bytes": 52428800,
}

MANIFEST = [
    {"path": "cubeproof/__init__.py", "sha256": sha("cubeproof/__init__.py")},
    {"path": "cubeproof/evidence/certify.py", "sha256": sha("cubeproof/evidence/certify.py")},
    {"path": "faces12_campaign/__init__.py", "sha256": sha("faces12_campaign/__init__.py")},
    {"path": "neighbourly/__init__.py", "sha256": sha("neighbourly/__init__.py")},
]


def machinery(
    checker: str = CHECKER,
    solver: str = SOLVER,
    argv: Sequence[str] = ARGV,
    manifest: Sequence[dict[str, str]] = MANIFEST,
) -> dict[str, Any]:
    entries = [dict(e) for e in manifest]
    return {
        "solver": {
            "path": "/opt/tools/bin/cadical",
            "sha256": solver,
            "version": "1.9.5",
            "argv": list(argv),
        },
        "checker": {"path": "/opt/tools/bin/cake_lpr", "sha256": checker},
        "helper": None,
        "runtime": {
            "python": "3.12.3",
            "libc": "glibc 2.39",
            "platform": "linux-x86_64",
            "image_digest": None,
        },
        "source_manifest": entries,
        "packages_sha256": jsha(entries),
        "cubeproof_sha256": jsha([e for e in entries if e["path"].split("/")[0] == "cubeproof"]),
        "unit_algorithm": "unit-v1",
    }


M_OK = machinery()
M_BAD_CHECKER = machinery(checker=CHECKER_BAD)
M_SEED = machinery(argv=ARGV_SEED)


def ident(label: str) -> str:
    """A deterministic Id128 for a label (fixtures only; real ones come from OS randomness)."""
    return sha("id128:" + label)[:32]


def sign(record: dict[str, Any]) -> dict[str, Any]:
    """Set self = SHA256(J(record without self)) (specification §7.1)."""
    unsigned = {k: v for k, v in record.items() if k != "self"}
    return unsigned | {"self": jsha(unsigned)}


class Journal:
    """A journal under construction; ``records`` are complete signed records."""

    def __init__(
        self,
        worker: str,
        campaign: str,
        *,
        purpose: str = "run",
        mach: dict[str, Any] | None = None,
        pol: dict[str, Any] | None = None,
        clock: int = 0,
    ) -> None:
        self.worker = worker
        self.campaign = campaign
        self.clock = clock
        self.records: list[dict[str, Any]] = []
        self.policy = pol if pol is not None else P_TRANSIENT
        self.add(
            "header",
            worker=worker,
            campaign=campaign,
            purpose=purpose,
            machinery=mach if mach is not None else M_OK,
            policy=self.policy,
            resources=RESOURCES,
        )

    @property
    def id(self) -> str:
        return str(self.records[0]["self"])

    @property
    def seq(self) -> int:
        return len(self.records)

    @property
    def policy_sha256(self) -> str:
        return jsha(self.policy)

    def add(self, kind: str, **payload: Any) -> dict[str, Any]:
        seq = len(self.records)
        record = {
            "format": "cubeproof-journal-1",
            "seq": seq,
            "prev": self.records[-1]["self"] if self.records else ZERO,
            "type": kind,
            "utc": utc(self.clock + seq),
        } | payload
        record = sign(record)
        self.records.append(record)
        return record

    def resume(self, pol: dict[str, Any], mach: dict[str, Any] | None = None) -> dict[str, Any]:
        self.policy = pol
        return self.add(
            "resume", machinery=mach if mach is not None else M_OK, policy=pol, resources=RESOURCES
        )

    def split(self, formula: Formula, cube: Sequence[int], variables: Sequence[int]) -> None:
        self.add(
            "split",
            node=node(formula, cube),
            variables=list(variables),
            splitter={"name": "lookahead-v1", "info": {"probes": 12}},
        )

    def stop(self, formula: Formula, cube: Sequence[int], state: str, reason: str) -> None:
        self.add(
            "node_stop",
            node=node(formula, cube),
            state=state,
            reason=reason,
            policy_sha256=self.policy_sha256,
        )

    def reopen(self, formula: Formula, cube: Sequence[int], reason: str) -> None:
        self.add(
            "node_reopen", node=node(formula, cube), reason=reason, policy_sha256=self.policy_sha256
        )

    def attempt(self, formula: Formula, cube: Sequence[int], preset: str, **changes: Any) -> None:
        fields = attempt_fields(
            formula, cube, preset, self.policy_sha256, f"{self.worker}:{self.seq}", **changes
        )
        self.add("attempt", **fields)

    def data(self) -> bytes:
        return b"".join(jbytes(r) + b"\n" for r in self.records)


# -- process results ----------------------------------------------------------------------------


def process(**changes: Any) -> dict[str, Any]:
    base = {
        "started": True,
        "exit": 0,
        "signal": None,
        "elapsed_ms": 12,
        "stdout_tail": "",
        "stderr_tail": "",
        "stdout_bytes": 0,
        "stdout_truncated": False,
        "cause": None,
        "conflicts": None,
    }
    return base | changes


def out(text: str, **changes: Any) -> dict[str, Any]:
    fields = {"stdout_tail": text, "stdout_bytes": len(text.encode("utf-8"))} | changes
    return process(**fields)


SOLVER_UNSAT = out("s UNSATISFIABLE\n", exit=20, conflicts=7)
SOLVER_SAT = out("s SATISFIABLE\nv 1 -2 3 0\n", exit=10, conflicts=3)
SOLVER_TIMEOUT = process(exit=None, signal=15, cause="solver_deadline", conflicts=None)
SOLVER_CAPPED = process(exit=None, signal=25, cause="proof_cap")
SOLVER_NOMEM = process(exit=1, stderr_tail="c allocation failed\n", cause="solver_memory")
SOLVER_CRASH = process(exit=None, signal=11, cause=None)
NOT_STARTED = process(started=False, exit=None, elapsed_ms=0, cause="launch")
CHECK_OK = out(VERIFIED)
CHECK_REJECT = out("s NOT VERIFIED\n", exit=1)
CHECK_HEAP = process(exit=1, stderr_tail="CakeML heap space exhausted.\n", cause="arena_heap")
CHECK_STACK = process(exit=1, stderr_tail="CakeML stack space exhausted.\n", cause="arena_stack")
CHECK_TIMEOUT = process(exit=None, signal=9, cause="check_deadline")


def check(result: dict[str, Any], heap: int = 512, stack: int = 256) -> dict[str, Any]:
    return {"result": result, "heap_mib": heap, "stack_mib": stack}


# -- attempts -----------------------------------------------------------------------------------

PRESETS = (
    "vu_unit",
    "vu_cdcl",
    "model_unit",
    "model_cdcl",
    "exhausted_proof_size",
    "exhausted_time",
    "exhausted_check_time",
    "exhausted_check_memory",
    "exhausted_check_stack",
    "exhausted_solver_memory",
    "failed_launch",
    "failed_binary_changed",
    "failed_io",
    "failed_file_changed",
    "failed_crash",
    "failed_protocol",
    "failed_relay",
    "rejected",
    "invalid_missing",
    "invalid_conflicting",
    "invalid_out_of_range",
    "invalid_syntax",
    "invalid_violated",
)


def attempt_fields(
    formula: Formula,
    cube: Sequence[int],
    preset: str,
    policy_hash: str,
    label: str,
    **changes: Any,
) -> dict[str, Any]:
    """Complete attempt payload of a preset; ``changes`` override fields afterwards.

    Change keys: ``mode`` (proof mode), ``assignment`` (true variables or a raw string via
    ``assignment_text``), ``proof`` (proof hash) and any attempt field name.
    """
    mode = changes.pop("mode", "transient")
    identity = node_id(formula.sha256, cube)
    proof = changes.pop("proof", sha("proof|" + label))
    proof_bytes = 1000 + len(cube) * 37
    unit = preset in ("vu_unit", "model_unit")
    route = "unit" if unit else "cdcl"
    stream = mode == "stream" and route == "cdcl"
    limits = {
        "solver_time_ms": None if unit else 300000,
        "proof_cap_bytes": 4294967296,
        "solver_memory_bytes": 1073741824,
        "check_time_ms": 600000,
    }
    fields: dict[str, Any] = {
        "node": node(formula, cube),
        "node_id": identity,
        "attempt_id": changes.pop("attempt_id", sha("attempt|" + label)[:32]),
        "policy_sha256": policy_hash,
        "route": route,
        "proof_mode": mode,
        "outcome": "VERIFIED_UNSAT",
        "reason": None,
        "cnf_sha256": formula.cube_sha256(cube),
        "limits": limits,
        "solver": None if unit else SOLVER_UNSAT,
        "checks": [check(CHECK_OK)],
        "proof_bytes": proof_bytes,
        "proof_sha256": proof,
        "relay": None,
        "assignment": None,
        "model_error": None,
        "retained": None,
        "quarantined": None,
        "diagnostics": {},
    }
    complete_relay = {
        "bytes": proof_bytes,
        "sha256": proof,
        "solver_eof": True,
        "all_written": True,
        "error": None,
    }
    partial_relay = {
        "bytes": 4096,
        "sha256": sha("partial relay|" + label),
        "solver_eof": False,
        "all_written": False,
        "error": None,
    }
    no_proof: dict[str, Any] = {"proof_bytes": None, "proof_sha256": None, "checks": []}
    kind, _, detail = preset.partition("_")
    if kind == "vu":
        if stream:
            fields["relay"] = complete_relay
        if mode == "retain":
            fields["retained"] = {
                "path": f"proofs/{identity}-{proof}.lrat",
                "sha256": proof,
                "bytes": proof_bytes,
            }
    elif kind == "model":
        fields |= no_proof | {"outcome": "MODEL", "solver": None if unit else SOLVER_SAT}
        if stream:
            fields["relay"] = partial_relay | {"bytes": 0, "sha256": sha(b"")}
    elif kind == "exhausted":
        fields |= {"outcome": "EXHAUSTED", "reason": detail}
        fields |= _exhausted(detail, no_proof, stream, complete_relay, partial_relay, fields)
    elif kind == "failed":
        fields |= {"outcome": "TOOL_FAILED", "reason": detail}
        fields |= _failed(detail, no_proof, stream, complete_relay, partial_relay)
    elif kind == "rejected":
        fields |= {
            "outcome": "CHECK_REJECTED",
            "reason": "rejected",
            "checks": [check(CHECK_REJECT)],
        }
        if stream:
            fields["relay"] = complete_relay
            fields["diagnostics"] = {"quarantine_unavailable": "stream_not_spooled"}
        else:
            fields["quarantined"] = {
                "path": f"quarantine/{identity}-{proof}.lrat",
                "sha256": proof,
                "bytes": proof_bytes,
            }
    elif kind == "invalid":
        error = preset.removeprefix("invalid_")
        fields |= no_proof | {
            "outcome": "INVALID_MODEL",
            "reason": error,
            "model_error": error,
            "solver": SOLVER_SAT,
        }
        if stream:
            fields["relay"] = partial_relay | {"bytes": 0, "sha256": sha(b"")}
        fields["diagnostics"] = {"model_text": "v 1 -1 0" if error == "conflicting" else "v ?"}
    else:
        raise ValueError(preset)
    true_vars = changes.pop("true", None)
    if true_vars is not None:
        fields["assignment"] = bitset(formula.variables, true_vars)
    return fields | changes


def _exhausted(
    detail: str,
    no_proof: dict[str, Any],
    stream: bool,
    complete_relay: dict[str, Any],
    partial_relay: dict[str, Any],
    fields: dict[str, Any],
) -> dict[str, Any]:
    if detail == "proof_size":
        return no_proof | {"solver": SOLVER_CAPPED} | _relay(stream, partial_relay)
    if detail == "time":
        return no_proof | {"solver": SOLVER_TIMEOUT} | _relay(stream, partial_relay)
    if detail == "solver_memory":
        return no_proof | {"solver": SOLVER_NOMEM} | _relay(stream, partial_relay)
    arena = {
        "check_time": CHECK_TIMEOUT,
        "check_memory": CHECK_HEAP,
        "check_stack": CHECK_STACK,
    }[detail]
    if stream:
        return no_proof | {"checks": [check(arena)], "relay": partial_relay}
    first = [check(arena)] if detail == "check_time" else [check(arena), check(arena, 1024, 512)]
    return {"checks": first}


def _relay(stream: bool, partial_relay: dict[str, Any]) -> dict[str, Any]:
    return {"relay": partial_relay} if stream else {}


def _failed(
    detail: str,
    no_proof: dict[str, Any],
    stream: bool,
    complete_relay: dict[str, Any],
    partial_relay: dict[str, Any],
) -> dict[str, Any]:
    if detail in ("launch", "binary_changed"):
        return (
            no_proof | {"solver": NOT_STARTED | {"cause": detail}} | _relay(stream, partial_relay)
        )
    if detail == "io":
        return no_proof | _relay(stream, partial_relay)
    if detail == "file_changed":
        return {"diagnostics": {"rehash": "proof changed after check"}} | (
            {"relay": complete_relay} if stream else {}
        )
    if detail == "crash":
        return no_proof | {"solver": SOLVER_CRASH} | _relay(stream, partial_relay)
    if detail == "protocol":
        return no_proof | _relay(stream, partial_relay)
    if detail == "relay":
        relay = partial_relay | {"error": "EPIPE"}
        return no_proof | {"relay": relay if stream else None}
    raise ValueError(detail)
