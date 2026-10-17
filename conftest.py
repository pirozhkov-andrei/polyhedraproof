"""Opt-in test tiers of the test suites.

Tests marked ``slow`` (more than about ten seconds) or ``image`` (needs the pinned Linux
tools of the test image) are skipped unless their tier is enabled with ``--run-slow`` or
``--run-image``. A plain ``pytest`` therefore never starts long work by accident; the make
targets enable the tiers they promise.

``make test-fast`` runs the package suites in parallel workers (pytest-xdist). Tests whose
assertions depend on wall-clock time are marked ``serial`` here, by node-id prefix, and run in a
second pass without workers, so that their limits keep their meaning.
"""

from __future__ import annotations

from collections.abc import Collection
from pathlib import Path

import pytest

OPT_IN = {"slow": "--run-slow", "image": "--run-image"}
# Node-id prefixes of tests with wall-clock assertions (latency bounds, kill windows, elapsed
# limits); they run in the serial pass of `make test-fast`.
SERIAL = (
    "packages/cubeproof/tests/unit_model/test_cp_um_helper.py::"
    "test_large_propagation_never_monopolizes_the_loop",
    "packages/cubeproof/tests/lifecycle/test_cp_life_crash.py::",
    "packages/cubeproof/tests/stream/test_cp_stream_run.py::",
)


def opt_in_skip(
    markers: Collection[str], enabled: Collection[str], relative_path: str
) -> str | None:
    """Why a test with these markers is skipped, or None when it runs."""
    missing = sorted(m for m in OPT_IN if m in markers and m not in enabled)
    if not missing:
        return None
    return "opt-in tier not enabled: " + ", ".join(f"{m} ({OPT_IN[m]})" for m in missing)


def pytest_addoption(parser: pytest.Parser) -> None:
    group = parser.getgroup("opt-in tiers")
    for marker, option in OPT_IN.items():
        group.addoption(
            option, action="store_true", default=False, help=f"run tests marked {marker}"
        )


def is_serial(nodeid: str) -> bool:
    return nodeid.startswith(SERIAL)


@pytest.hookimpl(tryfirst=True)  # before `-m` deselects by marker
def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    enabled = {marker for marker, option in OPT_IN.items() if config.getoption(option)}
    root = Path(str(config.rootpath)).resolve()
    for item in items:
        path = Path(str(item.path)).resolve()
        try:
            relative = path.relative_to(root).as_posix()
        except ValueError:
            relative = path.as_posix()
        if is_serial(item.nodeid):
            item.add_marker(pytest.mark.serial)
        reason = opt_in_skip({m.name for m in item.iter_markers()}, enabled, relative)
        if reason is not None:
            item.add_marker(pytest.mark.skip(reason=reason))
