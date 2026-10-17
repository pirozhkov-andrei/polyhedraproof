"""The complete Policy object of specification §4.3 and its identity ``policy_sha256 =
SHA256(J(policy))``.

A policy has exactly the fields of the table; there is no partial policy and no default
proof mode (the effective policy always names one). Defaults are provisional operational
choices, not measured optima. Cross-field rules: ``checker_max_stack_mib >=
checker_stack_mib`` (policy.stack) and ``stream_heap_mib <= checker_max_heap_mib``
(policy.stream_heap); ``leaf_time_ms`` has key ``default`` and canonical decimal depth keys
(policy.leaf_time_keys, a schema-level rule).
"""

from __future__ import annotations

import functools
import re
from collections.abc import Mapping
from dataclasses import dataclass, replace
from types import MappingProxyType
from typing import Any

from cubeproof.base.canonical_json import json_sha256
from cubeproof.base.errors import ContractError
from cubeproof.contracts import fields as f
from cubeproof.contracts.enums import ProofMode
from cubeproof.contracts.primitives import INT_MAX, is_name

_DEPTH_KEY = re.compile(r"default|0|[1-9][0-9]*")

POLICY_FIELDS: tuple[str, ...] = (
    "leaf_time_ms",
    "proof_cap_bytes",
    "solver_memory_bytes",
    "checker_max_heap_mib",
    "checker_stack_mib",
    "checker_max_stack_mib",
    "checker_slack_mib",
    "checker_time_base_ms",
    "checker_time_per_100mb_ms",
    "heap_fit",
    "split",
    "max_cube_size",
    "proof_mode",
    "stream_heap_mib",
    "quarantine_quota_bytes",
    "tool_retries",
    "machine_failure_limit",
    "anomaly_limit",
    "term_grace_ms",
    "stop_grace_ms",
)


def _depth_key(name: object) -> bool:
    return isinstance(name, str) and _DEPTH_KEY.fullmatch(name) is not None


@dataclass(frozen=True)
class HeapFit:
    """Checker heap fit parameters (milli-units; specification §4.3, §8.3)."""

    coefficient_milli: int = 3230
    exponent_milli: int = 711
    margin_milli: int = 1500
    min_mib: int = 512

    @classmethod
    def from_json(cls, value: Any, at: str) -> HeapFit:
        names = ("coefficient_milli", "exponent_milli", "margin_milli", "min_mib")
        f.obj(value, at, names)
        return cls(*(f.positive(value[n], f.member(at, n)) for n in names))

    def to_json(self) -> dict[str, Any]:
        return {
            "coefficient_milli": self.coefficient_milli,
            "exponent_milli": self.exponent_milli,
            "margin_milli": self.margin_milli,
            "min_mib": self.min_mib,
        }


@dataclass(frozen=True)
class SplitPolicy:
    """The dynamic split method: ``lookahead-v1`` with its budgets (specification §4.3, §9.3)."""

    method: str = "lookahead-v1"
    vars: int = 4
    pool: str | None = None
    probe_limit: int = 100000
    wall_ms: int = 1000

    @classmethod
    def from_json(cls, value: Any, at: str) -> SplitPolicy:
        f.obj(value, at, ("method", "vars", "pool", "probe_limit", "wall_ms"))
        return cls(
            method=f.const(value["method"], f.member(at, "method"), "lookahead-v1"),
            vars=f.integer(value["vars"], f.member(at, "vars"), 1, 20),
            pool=f.nullable(
                value["pool"],
                f.member(at, "pool"),
                lambda v, where: f.matching(v, where, is_name, "Name"),
            ),
            probe_limit=f.positive(value["probe_limit"], f.member(at, "probe_limit")),
            wall_ms=f.positive(value["wall_ms"], f.member(at, "wall_ms")),
        )

    def to_json(self) -> dict[str, Any]:
        return {
            "method": self.method,
            "vars": self.vars,
            "pool": self.pool,
            "probe_limit": self.probe_limit,
            "wall_ms": self.wall_ms,
        }


@dataclass(frozen=True)
class Policy:
    """A complete, validated policy. Build it with :meth:`from_json` or :func:`default_policy`."""

    leaf_time_ms: Mapping[str, int]
    proof_cap_bytes: int
    solver_memory_bytes: int
    checker_max_heap_mib: int
    checker_stack_mib: int
    checker_max_stack_mib: int
    checker_slack_mib: int
    checker_time_base_ms: int
    checker_time_per_100mb_ms: int
    heap_fit: HeapFit
    split: SplitPolicy
    max_cube_size: int
    proof_mode: ProofMode
    stream_heap_mib: int
    quarantine_quota_bytes: int
    tool_retries: int
    machine_failure_limit: int
    anomaly_limit: int
    term_grace_ms: int
    stop_grace_ms: int

    def __post_init__(self) -> None:
        # Every constructor path gets the same rules: freeze the mapping, then re-validate
        # the JSON form (schema level and cross-field rules).
        if not isinstance(self.leaf_time_ms, Mapping):
            raise ContractError(
                "schema", "leaf_time_ms is not a mapping", location="$.leaf_time_ms"
            )
        frozen = MappingProxyType(dict(sorted(self.leaf_time_ms.items(), key=lambda x: str(x[0]))))
        object.__setattr__(self, "leaf_time_ms", frozen)
        if isinstance(self.proof_mode, str) and not isinstance(self.proof_mode, ProofMode):
            mode = self.proof_mode
            if mode not in {m.value for m in ProofMode}:
                raise ContractError(
                    "schema", f"{mode!r} is not a proof mode", location="$.proof_mode"
                )
            object.__setattr__(self, "proof_mode", ProofMode(mode))
        self.parse_schema(self.to_json())
        self.check_rules()

    def __hash__(self) -> int:
        return hash(self.sha256)

    @staticmethod
    def parse_schema(value: Any, at: str = "$") -> dict[str, Any]:
        """Schema level of a policy object; returns keyword arguments of :class:`Policy`."""
        f.obj(value, at, POLICY_FIELDS)
        m = functools.partial(f.member, at)
        leaf = f.obj(value["leaf_time_ms"], m("leaf_time_ms"), ("default",), closed=False)
        f.property_names(leaf, m("leaf_time_ms"), _depth_key)
        times = {k: f.positive(v, f.member(m("leaf_time_ms"), k)) for k, v in leaf.items()}
        return {
            "leaf_time_ms": MappingProxyType(dict(sorted(times.items()))),
            "proof_cap_bytes": f.positive(value["proof_cap_bytes"], m("proof_cap_bytes")),
            "solver_memory_bytes": f.positive(
                value["solver_memory_bytes"], m("solver_memory_bytes")
            ),
            "checker_max_heap_mib": f.integer(
                value["checker_max_heap_mib"], m("checker_max_heap_mib"), 512, INT_MAX
            ),
            "checker_stack_mib": f.positive(value["checker_stack_mib"], m("checker_stack_mib")),
            "checker_max_stack_mib": f.positive(
                value["checker_max_stack_mib"], m("checker_max_stack_mib")
            ),
            "checker_slack_mib": f.positive(value["checker_slack_mib"], m("checker_slack_mib")),
            "checker_time_base_ms": f.positive(
                value["checker_time_base_ms"], m("checker_time_base_ms")
            ),
            "checker_time_per_100mb_ms": f.positive(
                value["checker_time_per_100mb_ms"], m("checker_time_per_100mb_ms")
            ),
            "heap_fit": HeapFit.from_json(value["heap_fit"], m("heap_fit")),
            "split": SplitPolicy.from_json(value["split"], m("split")),
            "max_cube_size": f.nonnegative(value["max_cube_size"], m("max_cube_size")),
            "proof_mode": ProofMode(
                f.choice(value["proof_mode"], m("proof_mode"), [x.value for x in ProofMode])
            ),
            "stream_heap_mib": f.integer(
                value["stream_heap_mib"], m("stream_heap_mib"), 512, INT_MAX
            ),
            "quarantine_quota_bytes": f.nonnegative(
                value["quarantine_quota_bytes"], m("quarantine_quota_bytes")
            ),
            "tool_retries": f.nonnegative(value["tool_retries"], m("tool_retries")),
            "machine_failure_limit": f.positive(
                value["machine_failure_limit"], m("machine_failure_limit")
            ),
            "anomaly_limit": f.positive(value["anomaly_limit"], m("anomaly_limit")),
            "term_grace_ms": f.positive(value["term_grace_ms"], m("term_grace_ms")),
            "stop_grace_ms": f.positive(value["stop_grace_ms"], m("stop_grace_ms")),
        }

    def check_rules(self) -> None:
        """The cross-field rules, in the order policy.stack, policy.stream_heap."""
        if self.checker_max_stack_mib < self.checker_stack_mib:
            raise ContractError(
                "policy.stack",
                f"checker_max_stack_mib {self.checker_max_stack_mib} < "
                f"checker_stack_mib {self.checker_stack_mib}",
            )
        if self.stream_heap_mib > self.checker_max_heap_mib:
            raise ContractError(
                "policy.stream_heap",
                f"stream_heap_mib {self.stream_heap_mib} > "
                f"checker_max_heap_mib {self.checker_max_heap_mib}",
            )

    @classmethod
    def from_json(cls, value: Any, at: str = "$") -> Policy:
        """A policy object: schema level first, then the cross-field rules."""
        return cls(**cls.parse_schema(value, at))

    def to_json(self) -> dict[str, Any]:
        return {
            "leaf_time_ms": dict(self.leaf_time_ms),
            "proof_cap_bytes": self.proof_cap_bytes,
            "solver_memory_bytes": self.solver_memory_bytes,
            "checker_max_heap_mib": self.checker_max_heap_mib,
            "checker_stack_mib": self.checker_stack_mib,
            "checker_max_stack_mib": self.checker_max_stack_mib,
            "checker_slack_mib": self.checker_slack_mib,
            "checker_time_base_ms": self.checker_time_base_ms,
            "checker_time_per_100mb_ms": self.checker_time_per_100mb_ms,
            "heap_fit": self.heap_fit.to_json() if isinstance(self.heap_fit, HeapFit) else None,
            "split": self.split.to_json() if isinstance(self.split, SplitPolicy) else None,
            "max_cube_size": self.max_cube_size,
            "proof_mode": self.proof_mode.value
            if isinstance(self.proof_mode, ProofMode)
            else self.proof_mode,
            "stream_heap_mib": self.stream_heap_mib,
            "quarantine_quota_bytes": self.quarantine_quota_bytes,
            "tool_retries": self.tool_retries,
            "machine_failure_limit": self.machine_failure_limit,
            "anomaly_limit": self.anomaly_limit,
            "term_grace_ms": self.term_grace_ms,
            "stop_grace_ms": self.stop_grace_ms,
        }

    @functools.cached_property
    def sha256(self) -> str:
        """``policy_sha256 = SHA256(J(policy))``."""
        return json_sha256(self.to_json())

    def leaf_time_ms_for_depth(self, depth: int) -> int:
        """Exact-depth lookup, then ``default`` (specification §4.3)."""
        if type(depth) is not int or depth < 0:
            raise ValueError(f"{depth!r} is not a cube depth")
        return self.leaf_time_ms.get(str(depth), self.leaf_time_ms["default"])

    def with_proof_mode(self, mode: ProofMode | str) -> Policy:
        """The same policy with another proof mode (a new validated value)."""
        return replace(self, proof_mode=ProofMode(mode))


def default_policy(proof_mode: ProofMode | str) -> Policy:
    """The specification §4.3 defaults with the given proof mode (there is no default mode)."""
    try:
        mode = ProofMode(proof_mode)
    except ValueError:
        raise ContractError("schema", f"{proof_mode!r} is not a proof mode") from None
    return Policy(
        leaf_time_ms=MappingProxyType({"12": 900000, "default": 300000}),
        proof_cap_bytes=4294967296,
        solver_memory_bytes=1073741824,
        checker_max_heap_mib=8192,
        checker_stack_mib=256,
        checker_max_stack_mib=2048,
        checker_slack_mib=256,
        checker_time_base_ms=600000,
        checker_time_per_100mb_ms=60000,
        heap_fit=HeapFit(),
        split=SplitPolicy(),
        max_cube_size=60,
        proof_mode=mode,
        stream_heap_mib=1024,
        quarantine_quota_bytes=21474836480,
        tool_retries=3,
        machine_failure_limit=5,
        anomaly_limit=3,
        term_grace_ms=10000,
        stop_grace_ms=30000,
    )
