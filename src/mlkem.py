"""Thin, explicit wrapper over the official liboqs-python ML-KEM API."""

from __future__ import annotations

import logging
from functools import lru_cache

ALGORITHM = "ML-KEM-768"
PUBLIC_KEY_BYTES = 1184
SECRET_KEY_BYTES = 2400
CIPHERTEXT_BYTES = 1088
SHARED_SECRET_BYTES = 32


@lru_cache(maxsize=1)
def require_oqs():
    """Import OQS and fail clearly unless standardized ML-KEM-768 is enabled."""
    # liboqs-python attaches an INFO-level StreamHandler to stdout on import,
    # which would corrupt our JSON CLI output. Disable that logger first.
    logging.getLogger("oqs.oqs").disabled = True
    try:
        import oqs  # type: ignore[import-not-found]
    except Exception as exc:
        raise RuntimeError(
            "Could not import/load liboqs-python or its native liboqs library. "
            "Install requirements.txt and ensure a C compiler, CMake, Git, and "
            "network access are available for native liboqs setup. "
            f"Underlying error: {type(exc).__name__}: {exc}"
        ) from exc

    try:
        enabled = oqs.get_enabled_kem_mechanisms()
    except Exception as exc:  # native loader/build failures need actionable context
        raise RuntimeError(f"Could not query enabled liboqs KEMs: {exc}") from exc

    if ALGORITHM not in enabled:
        raise RuntimeError(
            f"Required standardized mechanism {ALGORITHM!r} is not enabled. "
            f"Do not silently substitute legacy Kyber. Enabled mechanisms: {enabled}"
        )
    return oqs


def check_details() -> dict[str, object]:
    """Return non-secret OQS environment details for preflight logging."""
    oqs = require_oqs()
    with oqs.KeyEncapsulation(ALGORITHM) as kem:
        details = dict(kem.details)
    return {
        "algorithm": ALGORITHM,
        "oqs_python_version": getattr(oqs, "oqs_python_version", lambda: "unknown")(),
        "liboqs_version": getattr(oqs, "oqs_version", lambda: "unknown")(),
        "details": details,
    }
