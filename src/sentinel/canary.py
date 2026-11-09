"""Canary credentials: fake keys planted in the sandbox that raise an alarm when they move.

Standard library only: the proxy container imports this module as-is.
"""

from __future__ import annotations

import base64
import secrets
import string
from collections.abc import Iterable
from urllib.parse import quote

_BASE32 = string.ascii_uppercase + "234567"
_ALNUM = string.ascii_letters + string.digits


def _random(alphabet: str, length: int) -> str:
    return "".join(secrets.choice(alphabet) for _ in range(length))


def make_canaries() -> dict[str, str]:
    """Fresh canaries per run, shaped like the real thing so scanners and attackers both bite."""
    return {
        "AWS_ACCESS_KEY_ID": "AKIA" + _random(_BASE32, 16),
        "AWS_SECRET_ACCESS_KEY": _random(_ALNUM + "/+", 40),
        "GITHUB_TOKEN": "ghp_" + _random(_ALNUM, 36),
    }


def _base64_forms(secret: bytes) -> set[bytes]:
    """Base64 of the secret at each of the three byte alignments it can have inside a blob."""
    forms = set()
    for shift, skip in ((0, 0), (1, 2), (2, 3)):
        encoded = base64.b64encode(b"\0" * shift + secret)
        stable = (shift + len(secret)) // 3 * 4
        forms.add(encoded[skip:stable])
    return forms


def encodings(secret: str) -> set[bytes]:
    raw = secret.encode()
    return {
        raw,
        raw.lower(),  # DNS labels are case-insensitive
        raw.hex().encode(),
        raw.hex().upper().encode(),
        quote(secret, safe="").encode(),
        *_base64_forms(raw),
    }


def find_canaries(data: bytes, canaries: Iterable[str]) -> list[str]:
    """Return the canaries present in data, in plain or common encoded form."""
    return [c for c in canaries if any(form in data for form in encodings(c))]
