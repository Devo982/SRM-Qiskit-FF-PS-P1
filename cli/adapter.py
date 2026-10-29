"""Reference façade for the UX layer (docs/INTEGRATION_CONTRACT.md section 4).

The UX layer NEVER touches private keys, shared secrets, or traffic keys: this
façade loads key material internally from identities/ and exposes only
open / send / recv / close plus typed failure categories (invariants I1-I5).
"""
from __future__ import annotations

import json
from pathlib import Path

from protocol.channels import ClientChannel, ServerChannel
from protocol.errors import ChannelError
from protocol.suites import (
    DEFAULT_ALLOWED,
    load_identity_private_keys,
    load_trust_store,
)


class SecureChannelFacade:
    """One façade instance per endpoint role. UX-visible surface only."""

    def __init__(
        self,
        role: str,
        identity: str,
        suite_id: str,
        *,
        trust_store_path: str | Path = "trust_store.json",
        identities_dir: str | Path = "identities",
        allowed_suites: frozenset[str] | set[str] = DEFAULT_ALLOWED,
    ) -> None:
        if role not in ("client", "server"):
            raise ValueError("role must be 'client' or 'server'")
        self.role = role
        self.identity = identity
        self.suite_id = suite_id
        self._trust = load_trust_store(Path(trust_store_path))
        if identity not in self._trust.get("identities", {}):
            raise ChannelError(f"identity '{identity}' is not pinned in the trust store")
        name = identity.split(":", 1)[1]
        idir = Path(identities_dir)
        # per-suite signing key stays encapsulated inside the façade
        from protocol.suites import SUITES
        self._sign_sk = load_identity_private_keys(idir / f"{name}.json", SUITES[suite_id])
        self._allowed = frozenset(allowed_suites)
        self._channel = None

    def open(self, endpoint) -> "SecureChannelFacade":
        """Perform the handshake over the given wire endpoint."""
        common = dict(
            suite_id=self.suite_id,
            trust_store=self._trust,
            identity=self.identity,
            sign_sk=self._sign_sk,
            endpoint=endpoint,
            allowed_suites=self._allowed,
        )
        if self.role == "client":
            self._channel = ClientChannel(**common)
            self._channel.start()
        else:
            self._channel = ServerChannel(**common)
        return self

    def accept_frame(self, frame: bytes) -> None:
        """Feed one wire frame into the channel (wire adapters call this)."""
        self._require_channel().on_frame(frame)

    def send(self, data: bytes) -> None:
        self._require_channel().send(data)

    def recv(self) -> bytes | None:
        return self._require_channel().recv()

    def close(self) -> None:
        self._require_channel().close()

    # metadata-only introspection (invariant I4)
    @property
    def state(self) -> str | None:
        return self._channel.state if self._channel else None

    @property
    def failure_category(self) -> str | None:
        return self._channel.failure_category if self._channel else None

    @property
    def established(self) -> bool:
        return self._channel.established if self._channel else False

    def _require_channel(self):
        if self._channel is None:
            raise ChannelError("open() must be called first")
        return self._channel

