"""``status.json`` as a document: strict reader, canonical bytes and the text rendering
(specification §12.3).

The reader accepts exactly the documents of the schema ``status.schema.json`` and the
requirements ``status.order``, ``utc.calendar`` and ``status.coverage``; it rejects an unknown
top-level field or format and ignores unknown names inside ``counters`` and ``info`` (readers of an
older version must survive a newer writer's diagnostics). A status is a derived monitor interface,
not evidence: nothing in it may be used to decide closure, only to watch a run.

:func:`render_status` is ``status.txt``: the same snapshot as text, with a fixed layout, bounded in
size by the bounded lists of the document (long lists are cut with a count of what is left out).
"""

from __future__ import annotations

import itertools
import re
from collections.abc import Sequence
from typing import Any

from cubeproof.base.canonical_json import document_bytes
from cubeproof.base.errors import ContractError
from cubeproof.contracts import fields as f
from cubeproof.contracts.identity import node_id
from cubeproof.contracts.primitives import is_hash, is_id128, is_name, utc_problem
from cubeproof.contracts.values import Node, Ref
from cubeproof.coordinator.status_coverage import fraction_text, mean_text
from cubeproof.evidence.schema import ResourceSnapshot

__all__ = [
    "LIFECYCLES",
    "MODEL_LIMIT",
    "STATUS_FIELDS",
    "STATUS_FORMAT",
    "render_status",
    "status_bytes",
    "validate_status",
]

STATUS_FORMAT = "cubeproof-status-1"
#: ``models`` and ``anomalies`` hold at most this many Refs (full totals are in ``counters``).
MODEL_LIMIT = 100
LIFECYCLES = ("running", "draining", "stopped")
STATUS_FIELDS = (
    "format",
    "campaign",
    "journal",
    "head",
    "policy_sha256",
    "worker",
    "seq",
    "utc",
    "lifecycle",
    "resources",
    "reservations",
    "node_counts",
    "active",
    "oldest_elapsed_ms",
    "counters",
    "export",
    "models",
    "anomalies",
    "coverage",
    "eta_ms",
    "info",
)
_COUNTER_NAME = re.compile(r"[ -~]+")
_DECIMAL = re.compile(r"0|[1-9][0-9]*")


def _hash(value: Any, at: str) -> str:
    return f.matching(value, at, is_hash, "Hash")


def _utc(value: Any, at: str) -> str:
    return f.matching(value, at, lambda text: utc_problem(text) != "schema", "UTC")


def _reservation(value: Any, at: str) -> None:
    f.obj(value, at, ("task_id", "stage", "cpu_milli", "memory_bytes", "disk"))
    f.matching(value["task_id"], f.member(at, "task_id"), is_id128, "Id128")
    f.string(value["stage"], f.member(at, "stage"))
    f.nonnegative(value["cpu_milli"], f.member(at, "cpu_milli"))
    f.nonnegative(value["memory_bytes"], f.member(at, "memory_bytes"))
    f.items(value["disk"], f.member(at, "disk"), _disk)


def _disk(value: Any, at: str) -> None:
    f.obj(value, at, ("id", "bytes"))
    f.string(value["id"], f.member(at, "id"))
    f.nonnegative(value["bytes"], f.member(at, "bytes"))


def _count(value: Any, at: str) -> None:
    f.obj(value, at, ("state", "depth", "count"))
    f.string(value["state"], f.member(at, "state"))
    f.nonnegative(value["depth"], f.member(at, "depth"))
    f.nonnegative(value["count"], f.member(at, "count"))


def _active(value: Any, at: str) -> None:
    f.obj(value, at, ("task_id", "node_id", "stage", "elapsed_ms"))
    f.matching(value["task_id"], f.member(at, "task_id"), is_id128, "Id128")
    f.nullable(value["node_id"], f.member(at, "node_id"), _hash)
    f.string(value["stage"], f.member(at, "stage"))
    f.nonnegative(value["elapsed_ms"], f.member(at, "elapsed_ms"))


def _export(value: Any, at: str) -> None:
    f.obj(value, at, ("head", "seq", "utc", "lag_ms"))
    _hash(value["head"], f.member(at, "head"))
    f.nonnegative(value["seq"], f.member(at, "seq"))
    _utc(value["utc"], f.member(at, "utc"))
    f.nonnegative(value["lag_ms"], f.member(at, "lag_ms"))


def _refs(value: Any, at: str) -> list[Ref]:
    entries = f.array(value, at)
    if len(entries) > MODEL_LIMIT:
        f.fail(at, f"more than {MODEL_LIMIT} items")
    return [Ref.from_json(entry, f.item(at, i)) for i, entry in enumerate(entries)]


def _coverage(value: Any, at: str) -> None:
    f.obj(value, at, ("node", "closed_numerator", "denominator_power_two"))
    Node.from_json(value["node"], f.member(at, "node"))
    f.matching(
        value["closed_numerator"],
        f.member(at, "closed_numerator"),
        lambda text: _DECIMAL.fullmatch(text) is not None,
        "canonical decimal",
    )
    f.nonnegative(value["denominator_power_two"], f.member(at, "denominator_power_two"))


def _counters(value: Any, at: str) -> None:
    counters = f.open_object(value, at)
    f.property_names(counters, at, lambda name: _COUNTER_NAME.fullmatch(name) is not None)
    for name, number in counters.items():
        f.nonnegative(number, f.member(at, name))


def _increasing(keys: Sequence[Any]) -> bool:
    return all(a < b for a, b in itertools.pairwise(keys))


def validate_status(value: Any) -> dict[str, Any]:
    """The status document ``value`` if it is valid, else a :class:`ContractError`.

    Rules, in the order of the reference reader: the schema (rule ``schema``), then ``status.order``
    (every list strictly increasing by its key), ``utc.calendar`` and ``status.coverage`` (reduced
    fraction, at most 1).
    """
    doc = f.obj(value, "$", STATUS_FIELDS)
    f.const(doc["format"], "$.format", STATUS_FORMAT)
    for name in ("campaign", "journal", "head", "policy_sha256"):
        _hash(doc[name], f.member("$", name))
    f.matching(doc["worker"], "$.worker", is_name, "Name")
    f.nonnegative(doc["seq"], "$.seq")
    _utc(doc["utc"], "$.utc")
    f.choice(doc["lifecycle"], "$.lifecycle", LIFECYCLES)
    ResourceSnapshot.from_json(doc["resources"], "$.resources")
    f.items(doc["reservations"], "$.reservations", _reservation)
    f.items(doc["node_counts"], "$.node_counts", _count)
    f.items(doc["active"], "$.active", _active)
    f.nonnegative(doc["oldest_elapsed_ms"], "$.oldest_elapsed_ms")
    _counters(doc["counters"], "$.counters")
    f.nullable(doc["export"], "$.export", _export)
    models = _refs(doc["models"], "$.models")
    anomalies = _refs(doc["anomalies"], "$.anomalies")
    f.items(doc["coverage"], "$.coverage", _coverage)
    f.nullable(doc["eta_ms"], "$.eta_ms", f.nonnegative)
    f.open_object(doc["info"], "$.info")

    orders: list[list[Any]] = [
        [r["task_id"] for r in doc["reservations"]],
        [(n["state"], n["depth"]) for n in doc["node_counts"]],
        [a["task_id"] for a in doc["active"]],
        [ref.sort_key for ref in models],
        [ref.sort_key for ref in anomalies],
        [
            (c["node"]["formula_sha256"], node_id(c["node"]["formula_sha256"], c["node"]["cube"]))
            for c in doc["coverage"]
        ],
    ]
    if not all(_increasing(keys) for keys in orders):
        raise ContractError("status.order", "a list is not strictly increasing by its key")
    for at, text in (("$.utc", doc["utc"]), ("$.export.utc", (doc["export"] or {}).get("utc"))):
        if text is not None and utc_problem(text) is not None:
            raise ContractError("utc.calendar", f"{text!r} is not a valid instant", location=at)
    for entry in doc["coverage"]:
        problem = _coverage_problem(entry["closed_numerator"], entry["denominator_power_two"])
        if problem is not None:
            raise ContractError("status.coverage", problem)
    result: dict[str, Any] = doc
    return result


def _coverage_problem(text: str, power: int) -> str | None:
    """Why ``text / 2**power`` is not a reduced fraction of at most 1 (None if it is).

    A hostile document must not make the check expensive: ``2**power`` is never computed (power may
    be as large as an Int64) and a numerator with more digits than the interpreter converts is
    refused, no measure of a real run has one."""
    try:
        numerator = int(text)
    except ValueError:
        return f"a numerator of {len(text)} digits"
    if not (numerator in (0, 1) if power == 0 else numerator % 2 == 1):
        return f"{numerator}/2^{power} is not reduced"
    bits = numerator.bit_length()  # numerator <= 2**power  <=>  bits <= power, or a power of two
    if bits > power + 1 or (bits == power + 1 and numerator & (numerator - 1)):
        return f"{numerator}/2^{power} is above 1"
    return None


def status_bytes(doc: dict[str, Any]) -> bytes:
    """``status.json``: the validated document as canonical J plus one LF."""
    validate_status(doc)
    return document_bytes(doc)


# -- text -----------------------------------------------------------------------------------------

_UNITS = ("B", "KiB", "MiB", "GiB", "TiB", "PiB")


def size_text(amount: int) -> str:
    value, unit = amount, 0
    while value >= 1024 * 10 and unit < len(_UNITS) - 1:
        value //= 1024
        unit += 1
    if unit == 0:
        return f"{value} B"
    return f"{value} {_UNITS[unit]}"


def duration_text(ms: int) -> str:
    """``850 ms``, ``4.2 s``, ``3m05s``, ``2h07m``, ``5d03h`` (rounded down)."""
    if ms < 1000:
        return f"{ms} ms"
    seconds = ms // 1000
    if seconds < 60:
        return f"{ms / 1000:.1f} s"
    minutes, second = divmod(seconds, 60)
    if minutes < 60:
        return f"{minutes}m{second:02d}s"
    hours, minute = divmod(minutes, 60)
    if hours < 48:
        return f"{hours}h{minute:02d}m"
    days, hour = divmod(hours, 24)
    return f"{days}d{hour:02d}h"


def _printable(text: str) -> str:
    """``text`` with every control character other than LF replaced (a status read from a file
    may carry strings that must not reach a terminal as escape sequences)."""
    return "".join(c if c == "\n" or c.isprintable() else "?" for c in text)


def _short(text: str) -> str:
    return text[:12]


def _limited(lines: list[str], items: Sequence[str], limit: int, what: str) -> None:
    lines.extend(f"  {item}" for item in items[:limit])
    if len(items) > limit:
        lines.append(f"  ... {len(items) - limit} more {what}")


def _nodes_section(doc: dict[str, Any]) -> list[str]:
    totals: dict[str, int] = {}
    depths: dict[str, list[str]] = {}
    for entry in doc["node_counts"]:
        state = entry["state"]
        totals[state] = totals.get(state, 0) + entry["count"]
        depths.setdefault(state, []).append(f"d{entry['depth']}:{entry['count']}")
    lines = ["nodes:"]
    for state, total in totals.items():
        shown = " ".join(depths[state][:10])
        extra = f" (+{len(depths[state]) - 10} depths)" if len(depths[state]) > 10 else ""
        lines.append(f"  {state}: {total}  {shown}{extra}")
    if not totals:
        lines.append("  none")
    return lines


def _coverage_section(doc: dict[str, Any]) -> list[str]:
    entries = doc["coverage"]
    lines = ["coverage:"]
    if not entries:
        return [*lines, "  no roots"]
    closed = sum(
        1 for e in entries if e["closed_numerator"] == "1" and e["denominator_power_two"] == 0
    )
    mean = mean_text([(int(e["closed_numerator"]), e["denominator_power_two"]) for e in entries])
    lines.append(f"  {closed} of {len(entries)} roots closed, mean closed fraction {mean}")
    rows = [
        f"{_short(e['node']['formula_sha256'])} depth {len(e['node']['cube'])}: "
        f"{fraction_text(int(e['closed_numerator']), e['denominator_power_two'], 4)}"
        for e in entries
    ]
    _limited(lines, rows, 10, "roots")
    return lines


def render_status(doc: dict[str, Any]) -> str:
    """``status.txt``: the snapshot in a fixed layout (the document must be valid)."""
    resources = doc["resources"]
    lines = [
        f"cubeproof status  {doc['utc']}  worker {doc['worker']}  {doc['lifecycle']}",
        f"campaign {_short(doc['campaign'])}  journal {_short(doc['journal'])}  "
        f"seq {doc['seq']}  head {_short(doc['head'])}  policy {_short(doc['policy_sha256'])}",
        f"resources: {resources['cpu_milli']} milli-CPU, memory budget "
        f"{size_text(resources['memory_budget_bytes'])}, coordinator rss "
        f"{size_text(resources['coordinator_rss_bytes'])}",
    ]
    for fs in resources["filesystems"]:
        lines.append(
            f"  disk {fs['id']}: budget {size_text(fs['budget_bytes'])}, "
            f"free {size_text(fs['free_bytes'])}"
        )
    reserved = doc["reservations"]
    cpu = sum(r["cpu_milli"] for r in reserved)
    memory = sum(r["memory_bytes"] for r in reserved)
    disk = sum(d["bytes"] for r in reserved for d in r["disk"])
    lines.append(
        f"reservations: {len(reserved)} tasks, {cpu} milli-CPU, {size_text(memory)} memory, "
        f"{size_text(disk)} disk"
    )
    lines += _nodes_section(doc)
    active = doc["active"]
    lines.append(
        f"active: {len(active)} tasks, oldest {duration_text(doc['oldest_elapsed_ms'])}"
        if active
        else "active: none"
    )
    _limited(
        lines,
        [
            f"{_short(a['task_id'])} {a['stage']} node "
            f"{_short(a['node_id']) if a['node_id'] else '-'} {duration_text(a['elapsed_ms'])}"
            for a in active
        ],
        10,
        "tasks",
    )
    lines += _coverage_section(doc)
    export = doc["export"]
    if export is None:
        lines.append("export: none yet")
    else:
        lines.append(
            f"export: seq {export['seq']} head {_short(export['head'])} at {export['utc']}, "
            f"lag {duration_text(export['lag_ms'])} (a backup: newer records are not in it)"
        )
    info = doc["info"]
    detail = info.get("export")
    if isinstance(detail, dict):
        for key in sorted(detail):
            lines.append(f"  export {key}: {detail[key]}")
    counters = doc["counters"]
    models, anomalies = doc["models"], doc["anomalies"]
    lines.append(
        f"models: {counters.get('models', len(models))} (listed {len(models)}), "
        f"anomalies: {counters.get('anomalies', len(anomalies))} (listed {len(anomalies)})"
    )
    lines.append(
        "eta: not available (frontier or rates not stable)"
        if doc["eta_ms"] is None
        else f"eta: about {duration_text(doc['eta_ms'])} (an estimate, not a promise)"
    )
    stalls = info.get("stalls")
    if isinstance(stalls, list) and stalls:
        lines.append("stalls:")
        _limited(lines, [str(item) for item in stalls], 10, "stall reasons")
    notices = info.get("truncated")
    if isinstance(notices, dict) and notices:
        lines.append(
            "truncated: " + ", ".join(f"{k}: {notices[k]} not listed" for k in sorted(notices))
        )
    lines.append("counters: " + " ".join(f"{k}={counters[k]}" for k in sorted(counters)))
    return _printable("\n".join(lines)) + "\n"
