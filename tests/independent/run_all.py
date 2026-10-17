"""Run the independent certifier tests with the standard library only.

Usage: python3 tests/independent/run_all.py [-v] [pattern]
The tests are also collected by pytest (plain unittest.TestCase classes).
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent


def main(argv: list[str]) -> int:
    verbosity = 2 if "-v" in argv else 1
    patterns = [a for a in argv if not a.startswith("-")]
    sys.path.insert(0, str(HERE))
    loader = unittest.TestLoader()
    suite = loader.discover(str(HERE), pattern=patterns[0] if patterns else "test_*.py")
    result = unittest.TextTestRunner(verbosity=verbosity).run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
