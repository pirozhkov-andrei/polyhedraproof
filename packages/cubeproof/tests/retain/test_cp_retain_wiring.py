"""Retain wiring pieces without processes: the publication reservation and its admission, the
run's stop on a blocked retained publication, and the startup scan for referencing records.

- :func:`cubeproof.coordinator.resources.publish_need` is the disk of an attempt from the
  start of its publication until its cleanup (specification §7.2 steps 1 and 5, §8.3): the CNF and
  logs and the source proof on the work group, the copy on the results group (twice on one group).
- :func:`cubeproof.coordinator.run.publication_admission` grants it, lets it wait while other
  reservations can still free the refusing dimension, and refuses it (retain-full) otherwise.
- :meth:`cubeproof.leaf.retain.RetainBlocked.error` is the error that ends the run, with the
  specification §12.2 exit code of the block.
- :func:`cubeproof.leaf.retain.may_reference` selects the journal lines whose records can
  carry or require a reference (canonical JSON); a false positive costs a parse, a false
  negative would hide a record from the startup binding check.
"""

from __future__ import annotations

import json

import pytest

from cubeproof.base.canonical_json import document_bytes
from cubeproof.base.errors import ConfigurationError, IntegrityError, ResourceError, ToolError
from cubeproof.contracts.io import Failure
from cubeproof.coordinator.config import exit_code_of
from cubeproof.coordinator.ledger import Need, ResourceBook
from cubeproof.coordinator.resources import LOG_ALLOWANCE, publish_need, sealed_need
from cubeproof.coordinator.run import publication_admission
from cubeproof.leaf.retain import RetainBlocked, may_reference

T1, T2 = "11" * 16, "22" * 16


# -- publish_need ----------------------------------------------------------------------------


def test_the_publication_need_on_one_group_is_double_occupancy() -> None:
    need = publish_need(100, 7, source_group="g", target_group="g")
    assert need.amounts() == {"disk:g": 2 * 100 + 7 + LOG_ALLOWANCE}
    assert need.cpu_milli == 0 and need.memory_bytes == 0


def test_the_publication_need_across_groups_reserves_the_copy_on_the_target() -> None:
    need = publish_need(100, 7, source_group="work", target_group="results")
    assert need.amounts() == {"disk:work": 100 + 7 + LOG_ALLOWANCE, "disk:results": 100}


def test_the_publication_need_extends_the_sealed_reservation() -> None:
    """The sealed proof's own disk is part of it: restaging asks only for the copy."""
    sealed = sealed_need(100, 7, "g")
    need = publish_need(100, 7, source_group="g", target_group="g")
    assert need.amounts()["disk:g"] - sealed.amounts()["disk:g"] == 100


# -- publication_admission -------------------------------------------------------------------


def book_with(total: int, **held: int) -> ResourceBook:
    book = ResourceBook({"cpu": 4000, "memory": 1 << 30, "disk:g": total})
    for task, amount in held.items():
        book.reserve({"a": T1, "b": T2}[task], "sealed", Need(0, 0, (("g", amount),)))
    return book


def test_a_publication_that_fits_is_granted_and_restaged() -> None:
    book = book_with(1000, a=300)
    need = Need(0, 0, (("g", 400),))
    assert publication_admission(book, T1, need, None) == ("grant", "")
    held = book.get(T1)
    assert held is not None and held.stage == "publish" and held.need == need
    book.check()


def test_a_publication_waits_while_other_work_can_free_the_disk() -> None:
    book = book_with(1000, a=300, b=600)
    verdict, why = publication_admission(book, T1, Need(0, 0, (("g", 500),)), None)
    assert verdict == "wait" and "disk:g" in why
    held = book.get(T1)
    assert held is not None and held.stage == "sealed"  # nothing changed
    book.release(T2)
    assert publication_admission(book, T1, Need(0, 0, (("g", 500),)), None)[0] == "grant"


def test_a_publication_that_nothing_can_free_room_for_is_refused() -> None:
    book = book_with(450, a=300)
    verdict, why = publication_admission(book, T1, Need(0, 0, (("g", 500),)), None)
    assert verdict == "refuse" and "disk:g" in why
    held = book.get(T1)
    assert held is not None and held.need == Need(0, 0, (("g", 300),))


def test_a_publication_beyond_the_idle_capacity_is_refused_even_with_other_work() -> None:
    book = book_with(450, a=300, b=100)
    verdict, why = publication_admission(book, T1, Need(0, 0, (("g", 500),)), None)
    assert verdict == "refuse" and "exceeds the capacity" in why


def test_a_publication_on_a_group_without_a_ledger_is_refused() -> None:
    book = book_with(1000, a=300)
    need = Need(0, 0, (("g", 300), ("results", 10)))
    verdict, why = publication_admission(book, T1, need, None)
    assert verdict == "refuse" and "disk:results" in why


# -- RetainBlocked.error ---------------------------------------------------------------------


@pytest.mark.parametrize(
    ("kind", "error_type", "code"),
    [
        ("resource", ResourceError, 1),
        ("configuration", ConfigurationError, 3),
        ("integrity", IntegrityError, 4),
        ("tool", ToolError, 5),
        ("reject", ToolError, 5),
        ("input", ToolError, 5),
    ],
)
def test_a_blocked_publication_ends_the_run_with_its_exit_code(
    kind: str, error_type: type, code: int
) -> None:
    blocked = RetainBlocked.of(Failure(kind, "io.no_space", "x" * 500, False))
    error = blocked.error()
    assert type(error) is error_type
    assert error.rule == "retain.blocked"
    assert exit_code_of(error) == code == blocked.exit_code
    assert "io.no_space" in error.detail and len(error.detail) <= 300


def test_retain_full_is_a_resource_block_of_exit_one() -> None:
    error = RetainBlocked.full("disk:results: need 25, available 0").error()
    assert isinstance(error, ResourceError) and exit_code_of(error) == 1
    assert "retain.full" in error.detail and "disk:results" in error.detail


# -- may_reference ---------------------------------------------------------------------------


def line(**fields: object) -> bytes:
    value: dict[str, object] = {
        "type": "attempt",
        "proof_mode": "transient",
        "outcome": "VERIFIED_UNSAT",
        "retained": None,
        "quarantined": None,
        "diagnostics": {},
    }
    value.update(fields)
    return document_bytes(value).rstrip(b"\n")


ARTIFACT = {"path": "quarantine/x.lrat", "sha256": "0" * 64, "bytes": 3}


@pytest.mark.parametrize(
    ("fields", "expected"),
    [
        ({}, False),
        ({"proof_mode": "retain"}, True),
        ({"proof_mode": "retain", "outcome": "EXHAUSTED"}, True),
        ({"proof_mode": "stream"}, False),
        ({"outcome": "CHECK_REJECTED", "quarantined": ARTIFACT}, True),
        ({"outcome": "CHECK_REJECTED"}, False),
        ({"diagnostics": {"note": '"proof_mode":"retain"'}}, False),  # escaped in a string
        ({"diagnostics": {"proof_mode": "retain"}}, True),  # a harmless false positive
        ({"type": "split"}, False),
    ],
)
def test_lines_that_can_reference_an_artifact_are_selected(
    fields: dict[str, object], expected: bool
) -> None:
    assert may_reference(line(**fields)) is expected


def test_the_selection_never_misses_a_line_with_a_reference() -> None:
    """Exhaustive over the fields that decide it: retained needs retain mode (specification §4.8),
    quarantined is nonnull exactly when it carries an artifact."""
    for mode in ("transient", "retain", "stream"):
        for retained in (None, dict(ARTIFACT, path="proofs/x.lrat")):
            for quarantined in (None, ARTIFACT):
                raw = line(proof_mode=mode, retained=retained, quarantined=quarantined)
                needs = mode == "retain" or retained is not None or quarantined is not None
                if needs:
                    assert may_reference(raw), json.loads(raw)
