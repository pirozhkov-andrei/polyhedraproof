"""The main certifier (specification §10): explicit evidence in, a certificate or a typed error out.

- :mod:`.run`: :func:`certify` (campaign file and journal files) and the result values;
- :mod:`.inputs`: journal validation with the certifier's rules, evidence extraction, copies,
  forks and workers (specification §10.1);
- :mod:`.admission`: admission, success fields, regenerated CNF hashes and models (specification
  §10.1, §10.4);
- :mod:`.closure`: the evidence graph, closure, canonical selection, open frontier (specification
  §10.2, §10.3);
- :mod:`.document`: the certificate document, summaries, Merkle roots, verdict (specification §4.9,
  §10.5).

Pure: no process, thread, tool, coordinator or cache code is reachable from here
(architecture rule PURE); files are read only as explicit inputs.
"""

from __future__ import annotations

from cubeproof.evidence.certify.admission import AttemptRules, admission_reason, success_problem
from cubeproof.evidence.certify.closure import EvidenceGraph, Leaf
from cubeproof.evidence.certify.document import CERTIFICATE_FORMAT, build_certificate
from cubeproof.evidence.certify.run import (
    CertifyLimits,
    CertifyResult,
    JournalInput,
    certify,
    certify_campaign,
    exit_code,
)

__all__ = [
    "CERTIFICATE_FORMAT",
    "AttemptRules",
    "CertifyLimits",
    "CertifyResult",
    "EvidenceGraph",
    "JournalInput",
    "Leaf",
    "admission_reason",
    "build_certificate",
    "certify",
    "certify_campaign",
    "exit_code",
    "success_problem",
]
