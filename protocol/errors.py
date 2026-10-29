"""QFF 2026 PS-P1 - typed protocol failures (design v2 section 4)."""
from __future__ import annotations


class ChannelError(Exception):
    """Base class for all typed channel failures."""

    category = "ChannelError"


class PolicyViolation(ChannelError):
    """Local policy rejected version/suite before any crypto (T9)."""

    category = "PolicyViolation"


class UntrustedIdentity(ChannelError):
    """Identity not pinned in the trust store, or role mismatch (T6, T7a)."""

    category = "UntrustedIdentity"


class AuthenticationFailure(ChannelError):
    """Signature or key-confirmation (Finished) verification failed (T3, T7b, T8b)."""

    category = "AuthenticationFailure"


class TranscriptBindingError(ChannelError):
    """Malformed/ambiguous transcript bytes or KEM input rejected (T2-owned fields)."""

    category = "TranscriptBindingError"


class HandshakeReplayDetected(ChannelError):
    """Server (id_C, nonce_C) freshness cache hit (T8c; hygiene, not the anchor)."""

    category = "HandshakeReplayDetected"


class RecordReplayDetected(ChannelError):
    """Record seq is stale or duplicate under the receiver window (T8a)."""

    category = "RecordReplayDetected"


class RecordAuthenticationError(ChannelError):
    """AES-256-GCM authentication failed on a record (T4, T5); plaintext withheld."""

    category = "RecordAuthenticationError"


class SessionExhausted(ChannelError):
    """Record-count or sequence cap reached; renegotiate via a new handshake."""

    category = "SessionExhausted"

