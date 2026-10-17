"""Fresh identifiers from OS randomness (specification §4.1 Id128; writer obligation
writer.id128)."""

from __future__ import annotations

import secrets


def new_id128() -> str:
    """32 lowercase hexadecimal characters from the operating system's random source."""
    return secrets.token_hex(16)
