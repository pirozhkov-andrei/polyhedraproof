"""Fake tools, a test-only LRAT validator, model fixtures and I/O fault adapters.

``toolkit``        build fake executables from scripts (engine: ``fake_tool``)
``presets``        fakes of the pinned solver and checker, with their real outputs, and relays
``lrat_check``     tiny independent LRAT validator for test proofs only
``cnf_model``      tiny DIMACS/model helpers and the specification §4.8 model error codes
``fault_ops``      read/write/fsync/rename fault injection
``fixture_files``  the fixtures in ``data/`` and their manifest

Everything here is test support. No production result, claim or theorem may rest on a fake
tool or on the test validator; only the pinned cake_lpr authorises VERIFIED_UNSAT.
Importable as ``fakes`` once ``tests`` is on ``sys.path``: pytest puts it there for the
test package ``tests/image``, and every other module that uses ``fakes`` inserts it itself.
"""
