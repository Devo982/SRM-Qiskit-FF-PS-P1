# Integration Contract - UX / Developer-Experience Layer <=> PS-P1 Secure Channel

> Status: **FINAL v1.0** - security invariants (§2) and the implemented UX-facing
> API surface (§4) are the integration contract for this repository.
> Owner: protocol lead (this repo). Consumer: UX/demo team.

## 1. Purpose

This document is the ONLY boundary between the user-facing layer and the
quantum-safe channel implementation. The UX layer drives demos and the developer
experience; it must never need - and must never be able - to touch cryptographic
secrets. Everything the UX layer may do is expressible through the façade in §4.

## 2. Security invariants (non-negotiable)

- **I1** The UX layer never imports crypto modules and never observes private keys,
  shared secrets, traffic keys, or nonces - in memory, files, logs, or UI.
- **I2** All private key material lives under `identities/` (git-ignored) and is
  created only by `scripts/provision_identities.py`. `trust_store.json` (public
  verification keys only) is the single committed trust anchor.
- **I3** The UX layer interacts exclusively through the channel façade (§4):
  open / send / recv / close plus typed error names. No other import path is
  supported or stable.
- **I4** Logs and UI may display metadata only: state transitions, byte counts,
  suite id, failure category. Never key bytes; never plaintext of failed records.
- **I5** No API path bypasses trust-store lookup, signature verification, or the
  record replay window. There is no "insecure mode".

## 3. Suites (selected by local configuration; never negotiated on the wire)

| Suite id | KEM | Signature | KDF | AEAD |
|---|---|---|---|---|
| `QFF26-PQC-1` | ML-KEM-768 (FIPS 203) | ML-DSA-65 (FIPS 204) | HKDF-SHA256 | AES-256-GCM |
| `QFF26-CLASSICAL-1` | X25519 | Ed25519 | HKDF-SHA256 | AES-256-GCM |

## 4. API surface (implemented)

- `ClientChannel`, `ServerChannel`: one state machine per role,
  `INIT → ... → ESTABLISHED → CLOSED | FAILED(reason)`.
- Typed failures surfaced to UX: `PolicyViolation`, `UntrustedIdentity`,
  `AuthenticationFailure`, `TranscriptBindingError`, `HandshakeReplayDetected`,
  `RecordReplayDetected`, `RecordAuthenticationError`, `SessionExhausted`.
- Implemented façade: [`cli/adapter.py`](../cli/adapter.py) (`SecureChannelFacade`) exposes `open`, `send`, `recv`, `close`, and metadata-only `state`, `failure_category`, and `established` properties.
- Runnable end-to-end example: [`cli/demo.py`](../cli/demo.py), invoked with `python -m cli.demo --suite QFF26-PQC-1`.

## 5. Test ownership

T1-T9 live in `tests/` and run via a single command; results append to
`results/security_tests.csv`. The UX layer consumes the CSV summary; it is never a
participant in the tests.

## 6. Change process

Any change to invariants I1-I5 or to the wire format requires a new signed revision
of this document and protocol-lead approval.
