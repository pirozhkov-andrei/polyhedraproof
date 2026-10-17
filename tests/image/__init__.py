"""Tests of the development/test image: its manifest, its provenance and its pinned tools.

``pinned``  locate the pinned CaDiCaL and cake_lpr and check them against the build record

Tests marked ``image`` run the real binaries; they run only with ``--run-image`` and need
``POLYHEDRAPROOF_TEST_TOOLS`` (the image sets it). The unmarked tests check the manifest,
the Dockerfile and the provenance script anywhere. Importable as ``image`` from tests under
``tests/`` (specification §14).
"""
