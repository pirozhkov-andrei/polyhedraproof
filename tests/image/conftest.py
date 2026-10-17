"""The ``pinned`` fixture of the image tests."""

from __future__ import annotations

import pytest

from image.pinned import Pinned, ToolsUnavailable, locate


@pytest.fixture(scope="session")
def pinned() -> Pinned:
    """The verified pinned tools.

    Absent or unrecorded tools fail the test instead of skipping it: an image run that
    silently checked nothing is worse than a red one.
    """
    try:
        return locate()
    except ToolsUnavailable as error:
        pytest.fail(str(error), pytrace=False)
