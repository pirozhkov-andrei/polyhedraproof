"""``certify --evidence MANIFEST``: certify a portable evidence directory (specification §4.9,
§12.1).

The manifest names the campaign, the bundles, the journal snapshots and a certificate. Only the
first three are inputs: the certifier runs on the verified files and the certificate it derives
is compared **byte for byte** with the packaged one. A packaged certificate that differs is an
integrity error (``evidence.certificate``, exit 4): the directory claims something its own
evidence does not support. The certificate file is never trusted as an input.
"""

from __future__ import annotations

from pathlib import Path

from cubeproof.base.errors import IntegrityError
from cubeproof.base.settings import DEFAULT_LIMITS, ReaderLimits
from cubeproof.commands.campaign import publish_file
from cubeproof.commands.evidence import load_evidence
from cubeproof.evidence.certify.run import CertifyLimits, CertifyResult, certify

__all__ = ["certify_evidence"]


def certify_evidence(
    manifest: Path, output: Path | None = None, *, limits: ReaderLimits = DEFAULT_LIMITS
) -> CertifyResult:
    """Certify the evidence directory of ``manifest``; publish the certificate to ``output``."""
    evidence = load_evidence(Path(manifest), limits=limits)
    result = certify(evidence.campaign, evidence.journals, limits=CertifyLimits(reader=limits))
    if result.document != evidence.certificate.read_bytes():
        raise IntegrityError(
            "evidence.certificate",
            f"{evidence.manifest_path}: the packaged certificate is not the certificate of its "
            "campaign and journals",
        )
    if output is not None:
        publish_file(Path(output).resolve(), result.document)
    return result
