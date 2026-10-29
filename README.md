# QFF 2026 PS-P1 — Quantum-Safe Secure Communication Channel (Phase 2)

Track 5 · Qiskit Fall Fest 2026 · **PS-P1: Quantum-Safe Secure Communication Channel**

A hybrid-ready authenticated secure channel with **two complete protocol suites behind ONE
state machine**, automated wire-level attack testing (T1–T9), and byte-exact official
payload verification:

| Suite | KEM | Signature | KDF | AEAD |
|---|---|---|---|---|
| `QFF26-PQC-1` | **ML-KEM-768** (FIPS 203) | **ML-DSA-65** (FIPS 204) | HKDF-SHA256 (RFC 5869) | AES-256-GCM |
| `QFF26-CLASSICAL-1` | X25519 | Ed25519 | HKDF-SHA256 | AES-256-GCM |

Suite selection is **local policy on both endpoints and is never negotiated on the wire** —
there is no downgrade path. Directional keys (`QFF26 c2s` / `QFF26 s2c` labels preserved and
strengthened with transcript-hash binding), directional 12 B nonce bases, and an exporter
secret are derived from a fixed, acyclic schedule: `ss → sig_S → TH2 → PRK → fk → fin_S →
sig_C → TH3 → fin_C → TH4 → traffic keys`.

## Security properties (full analysis in the technical report)

- **Mutual authentication** against a pinned trust store (`trust_store.json`). Verification
  keys never travel on the wire; an unknown identity fails at lookup **before any signature
  math** (T6). Roles are enforced by trust-store labels and transcript tag positions (T7a).
- **Canonical TLV transcript** — signatures cover identities, roles, version, suite ids,
  both nonces, and all exchanged key material; no signature covers itself (T2, T3, T7b).
- **Replay defenses at both layers**: handshake freshness via client nonce inside `sig_S`
  plus an `(id_C, nonce_C)` server cache as hygiene (T8b/T8c); record layer via a
  per-direction sliding window + watermark checked **before decryption** — GCM alone is
  explicitly documented as NOT a replay defense (T8a).
- **AES-256-GCM record layer**: 16 B header (always AAD), 32 B total per-record overhead,
  nonce = nonce_base ⊕ seq (injective; reuse structurally excluded), authenticated close
  records, session caps → `SessionExhausted`.
- Fixed verification order `policy → trust lookup → signature → Finished`; every failure is
  a typed error (`PolicyViolation`, `UntrustedIdentity`, `AuthenticationFailure`,
  `TranscriptBindingError`, `HandshakeReplayDetected`, `RecordReplayDetected`,
  `RecordAuthenticationError`, `SessionExhausted`); no code path falls back to a weaker
  suite; ephemeral secrets are zeroized on terminal states (best effort — prototype note).

## Repository layout

```
common/env_check.py          kit environment contract -> READY + platform_A_info.json
protocol/                    TLV wire format, suites, key schedule, record layer,
                             Client/Server state machines, in-memory wire
cli/                         UX façade (docs/INTEGRATION_CONTRACT.md) + demo
tests/harness.py             wire-level fault injectors (flip/duplicate/substitute/splice)
tests/run_security_tests.py  T1–T9 battery -> results/security_tests.csv
tests/test_regressions.py    RFC 5869 vectors + replay-window regression tests
bench/                       handshake + payload benchmarks -> results/tables/*.csv
scripts/provision_identities.py   generates identities/ (git-ignored) + trust_store.json
docs/INTEGRATION_CONTRACT.md security invariants for the UX layer
data/payloads/               official payloads (regenerated locally; *.bin not committed)
Phase One/                   archived Phase 1 submission (untouched)
```

## Quickstart (judge reproduction path)

Requirements: Python **3.10–3.13** (validated on 3.13.17), pip/uv. `cryptography==50.0.2`
is the kit pin and must not change.

```bash
git clone https://github.com/Devo982/SRM-Qiskit-FF-PS-P1.git
cd SRM-Qiskit-FF-PS-P1
python3 -m venv .venv && source .venv/bin/activate      # or: uv venv .venv
pip install -r requirements.txt

python common/env_check.py                # -> READY - environment is correct.
python scripts/provision_identities.py    # identities/ + trust_store.json (one command)
python -m tests.run_security_tests        # T1-T9, single command
python -m tests.test_regressions          # RFC 5869 vectors + replay-window regression
python -m cli.demo --suite QFF26-PQC-1    # end-to-end demo (metadata-only output)
python bench/bench_handshake.py --runs 15 # median / IQR / p95 per suite
python bench/bench_payload.py             # 1KB / 100KB / 10MB throughput
```

Expected: `ALL TESTS PASSED: 50/50 checks` (25 checks × 2 suites) and
`results/security_tests.csv` written. The test battery asserts via **public confirmation
status only** (states, failure categories, sizes) — key bytes are never printed.

> **Intel macOS note.** `cryptography==50.0.2` publishes no macOS x86_64 wheel, so on Intel
> Macs pip builds it from sdist against a local static OpenSSL (see
> `scripts/QFF2026_intel_mac_env_setup.sh`; `source ~/.qff26-openssl-env.sh` first). Every
> other platform (Linux, Windows, Apple Silicon) installs the prebuilt wheel directly.
> `platform_A_info.json` records the honest install origin of this machine.

## T1–T9 (all faults injected on the wire between two real endpoints)

| ID | Scenario | Expected |
|----|----------|----------|
| T1 | honest handshake; 3 official payloads (1KB/100KB/10MB) both directions; byte + SHA-256 vs committed `payload_sha256.txt`; authenticated close | success, ESTABLISHED, 6/6 verified |
| T2 | parametrized bit-flips: kem_pk_C, kem_ct, nonce_C, nonce_S, id_C, id_S, version, suite_id | abort at the step that owns the field; keys never established |
| T3 | bit-flip sig_S / sig_C | `AuthenticationFailure` |
| T4 | bit-flip record ciphertext | `RecordAuthenticationError`, plaintext withheld |
| T5 | bit-flip GCM tag / header (AAD, direction) | typed rejection before/with decryption failure |
| T6 | attacker identity + own valid key | `UntrustedIdentity` at lookup, before signature math |
| T7 | (a) role swap with genuine key, (b) genuine old sig_S spliced into a fresh session | transcript/identity binding rejects both |
| T8 | (a) app-record replay, (b) full old-session replay, (c) M1 replay with cache | `RecordReplayDetected` / `AuthenticationFailure` / `HandshakeReplayDetected` |
| T9 | (a) unknown suite_id, (b) echoed suite substituted to the other valid suite | `PolicyViolation` before any crypto; no fallback |

## Prototype status and assumptions

This is a competition prototype, not a production library. Stated assumptions: trust-store
distribution/integrity is out-of-band; the OS CSPRNG is trusted; no side-channel
hardening; DoS resistance out of scope; single trust domain; identity-key compromise breaks
future impersonation resistance, not past session confidentiality (fresh KEM keypair per
session; best-effort zeroization — Python cannot guarantee memory hygiene); single
in-process wire for tests/benchmarks (the same frames a socket transport would carry);
auto-renegotiation after `SessionExhausted` is documented but not automated.

