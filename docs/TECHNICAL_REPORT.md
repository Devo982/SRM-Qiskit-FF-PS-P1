# QFF 2026 PS-P1 — Technical Report

**Task:** PS-P1 — Quantum-Safe Secure Communication Channel (Phase 2)
**Repo:** `Devo982/SRM-Qiskit-FF-PS-P1` · **Track:** 5 — Post-Quantum Cryptography
**Platform of record:** Intel Mac (x86_64 native), macOS 15.8.2, CPython 3.13.17,
`cryptography==50.0.2` (kit pin; sdist build against static OpenSSL 3.5.9 — see
`platform_A_info.json` for the honest install origin).

---

## 1. Executive summary

This document specifies and evaluates the quantum-safe secure channel built for
PS-P1 Phase 2. The system is a single handshake-and-record state machine
instantiated by two cipher suites: `QFF26-PQC-1` (ML-KEM-768 + ML-DSA-65) and
`QFF26-CLASSICAL-1` (X25519 + Ed25519 as a classical baseline). Both suites share
one wire format, one HKDF-SHA256 key schedule with client-to-server and
server-to-client chains derived independently, and one AES-256-GCM record layer.
Suite selection is a local policy decision on each endpoint; it is never
negotiated on the wire.

Security is evaluated by a 25-check fault-injection battery (T1–T9), executed
twice — once per suite — for 50/50 passing checks. Every fault is injected on the
bytes between two real endpoints, so every mutation travels the real parse,
policy, trust-store, signature, and key-confirmation path. The battery asserts
via public confirmation status only (states, failure categories, payload sizes);
key material never appears in logs or assertions.

On the platform of record the full handshake completes in 3.68 ms median for the
PQC suite (15 runs) and 0.73 ms median for the classical baseline, and bulk
throughput converges to ~470–485 MB/s for both suites at the 10 MB payload,
showing that post-handshake cost is dominated by the AES-256-GCM record layer,
not by the KEM. This is a competition prototype: Section 7 states the assumptions
and limitations explicitly.

## 2. Deliverable-to-requirement map

| PS-P1 requirement | Realization in this repo |
|---|---|
| Authenticated key exchange with PQ KEM + PQ signatures | Suite `QFF26-PQC-1`, `protocol/channels.py` |
| Classical baseline for comparison | Suite `QFF26-CLASSICAL-1` |
| HKDF-SHA256, direction-separated, explicit | `protocol/keyschedule.py` (RFC 5869 implemented step-by-step) |
| AES-256-GCM record layer with replay defense | `protocol/records.py` |
| T1–T9 automated security tests → CSV | `tests/run_security_tests.py` → `results/security_tests.csv` |
| 3 official payloads (1 KB / 100 KB / 10 MB) with SHA-256 | `data/payloads/payload_sha256.txt` (manifest committed; `*.bin` regenerated locally) |
| Benchmarks, ≥10 handshakes, median/IQR/p95 | `bench/bench_handshake.py`, `bench/bench_payload.py` → `results/tables/*.csv` |
| UX layer with zero key contact | `cli/adapter.py` + invariants I1–I5 in `docs/INTEGRATION_CONTRACT.md` |
| Reproducible judge path | `README.md` quickstart (clean clone → 4 commands → 50/50) |

## 3. Protocol design (v2)

### 3.1 Design principles

**P1 — One state machine, two suites.** Client: `INIT → M1_SENT → M3_SENT →
ESTABLISHED → CLOSED | FAILED`; Server: `INIT → M2_SENT → ESTABLISHED →
CLOSED | FAILED`. The suite parameterizes cryptography only; every state
transition, check, and failure path is identical for both suites, so the fault
matrix exercises the same logic twice.

**P2 — Suites are local policy, never negotiated.** Each endpoint is configured
with a suite id and an allow-list. A suite id received on the wire that is not
known, or not in the local allow-list, raises `PolicyViolation` *before any
cryptographic operation runs* (T9a). A server echo that differs from the
client's locally-chosen suite is rejected by the client (T9b); there is no
downgrade or fallback path anywhere in the code.

**P3 — Direction-separated key chains.** `c2s_key` and `s2c_key` are independent
HKDF-Expand outputs with distinct labels; likewise the two 12-byte nonce bases.
A key (or nonce) used in one direction is never reused in the other.

**P4 — UX layer has zero key contact.** The CLI façade passes identity names,
payload bytes, and public confirmation status only (invariants I1–I5 in
`docs/INTEGRATION_CONTRACT.md`): no key bytes cross the façade, private material
lives only in git-ignored `identities/`, all protocol access goes through the
façade, logs carry metadata only, and there is no insecure mode.

**P5 — Typed failures, fail closed.** Every rejection is one of eight typed
errors (Section 4.3). `on_frame()` converts any unexpected exception into a
generic `ChannelError` failure and wipes session secrets: the pump never crashes
and never fails open.

**P6 — Faults are injected on the wire.** `protocol/wire.py` carries serialized
frames between two real endpoints; fault hooks mutate, duplicate, substitute, or
splice frames at a per-direction frame index before delivery. No test reaches
into channel internals to simulate an attack.

### 3.2 Suite registry

| Suite id | KEM | pk / ct (B) | Signature | sig (B) | Handshake nonce |
|---|---|---|---|---|---|
| `QFF26-PQC-1` | ML-KEM-768 | 1184 / 1088 | ML-DSA-65 | 3309 | 32 B |
| `QFF26-CLASSICAL-1` | X25519 (KEM-shaped) | 32 / 32 | Ed25519 | 64 | 32 B |

Both suites share: HKDF-SHA256 key schedule, AES-256-GCM record layer, 32-byte
handshake nonces, and identical transcript/signing conventions.

*X25519 as a KEM.* To reuse one state machine, the classical suite models
Diffie–Hellman in the KEM's shape: the responder generates a fresh ephemeral
X25519 keypair, derives `ss = ECDH(eph_sk_S, kem_pk_C)`, and sends its ephemeral
public key as the "ciphertext" (32 B). The initiator decapsulates with
`ss = ECDH(kem_sk_C, eph_pk_S)`. Both sides contribute fresh ephemerals, so the
classical path has forward secrecy equal to ephemeral–ephemeral ECDH. In the PQC
suite the initiator generates a fresh ML-KEM-768 keypair per session; the
identity key only ever signs transcripts.

*Signature context domain separation.* `cryptography` 50.x ML-DSA/Ed25519 APIs
expose no context parameter, so signatures are computed over
`len(ctx) u16 BE || ctx || message` with `ctx ∈ {QFF26-P1-srv, QFF26-P1-cli}` —
a server signature can never be replayed as a client signature or vice versa
(the role-swap check in T7a is additionally enforced by the trust store).

### 3.3 Wire format

A handshake frame is an ordered sequence of TLV records `(tag:1B)(len:4B BE)(value)`.
Parsing is strict: exact expected tags in fixed order, no missing fields, no
duplicates, no trailing bytes; violations raise `TranscriptBindingError`.

| Tag | Field | Tag | Field |
|---|---|---|---|
| 0x01 | proto_version (= 0x02) | 0x07 | kem_ct |
| 0x02 | suite_id | 0x08 | nonce_S |
| 0x03 | id_C | 0x09 | sig_S |
| 0x04 | kem_pk_C | 0x0A | sig_C |
| 0x05 | nonce_C | 0x0B | fin_S |
| 0x06 | id_S | 0x0C | fin_C |

Message schemas (fixed order):

- **M1** (client → server): `proto_version, suite_id, id_C, kem_pk_C, nonce_C`
- **M2** (server → client): `proto_version, suite_id, id_S, kem_ct, nonce_S, sig_S, fin_S`
- **M3** (client → server): `sig_C, fin_C`

Handshake wire cost, computed from the constants above (identity strings
`client:alice` / `server:bob`, 5 B TLV overhead per field):

| Suite | M1 | M2 | M3 | Total |
|---|---|---|---|---|
| `QFF26-PQC-1` | 1265 B | 4518 B | 3351 B | 9134 B |
| `QFF26-CLASSICAL-1` | 119 B | 223 B | 106 B | 448 B |

The ~20× wire-cost ratio is the expected price of post-quantum parameters at
NIST level 1–2 (ML-KEM-768 ct 1088 B, ML-DSA-65 sig 3309 B).

### 3.4 Handshake flow and transcript binding

```
Client                                         Server
  ---- M1: ver,suite,id_C,kem_pk_C,nonce_C ---->
  (fresh KEM keypair per session)
                                               policy: version + suite (allow-list)
                                               trust lookup (id_C, role=client)
                                               freshness cache (id_C, nonce_C)   [T8c]
                                               encapsulate -> ss, kem_ct
  <---- M2: ver,suite,id_S,kem_ct,nonce_S,
           sig_S,fin_S --------------------
                                               sig_S = Sign_S(CTX_SERVER, T2)
                                               T2 = M1(as received) || M2-core
  strict parse; policy on version+echoed suite
  trust lookup (id_S, role=server)
  length checks vs suite parameters
  ss = decapsulate(kem_sk_C, kem_ct)
  T2 = M1(as sent) || M2-core(rebuilt)
  verify sig_S over T2                         fin_S = HMAC(fk, FIN_S_LABEL || TH2)
  T3 = T2 || TLV(09,sig_S); TH2 = H(TH2_LABEL || T3)
  PRK = HKDF-Extract(salt=TH2, ikm=ss)
  verify fin_S (constant time)
  sig_C = Sign_C(CTX_CLIENT, T3)
  TH3 = H(TH3_LABEL || T3 || TLV(0A,sig_C))
  fin_C = HMAC(fk, FIN_C_LABEL || TH3)
  ---- M3: sig_C,fin_C ------------------------>
                                               trust lookup AGAIN (role=client)
                                               verify sig_C over T3
                                               verify fin_C
                                               TH4 = H(TH4_LABEL || T3 || TLV(0A,sig_C) || TLV(0C,fin_C))
                                               traffic keys = Expand(PRK, label || TH4)
  ESTABLISHED                                  ESTABLISHED
```

Key properties:

1. **Transcript-bound signatures.** The server signs `T2 = M1-exactly-as-received
   || M2-core`; the client rebuilds the same `T2` from `M1-exactly-as-sent` and the
   received M2 core before verifying. Any single-bit change anywhere in M1 or the
   M2 core breaks the signature or the shared secret (T2 battery, T7b splice).
2. **Key confirmation both ways.** `fin_S` binds `TH2` (through the client's M1 and
   the server's M2), `fin_C` binds `TH3` (which additionally covers `sig_C`). Both
   are verified with `hmac.compare_digest` before `ESTABLISHED` is entered.
3. **Verification order is fixed** on every authenticated input:
   `policy → trust-store lookup → signature → Finished`. The trust store is the
   only source of verification keys — there is no code path that consumes a
   verification key from the wire, so an attacker cannot substitute one (T6).
4. **The server re-checks the trust store at M3**, so a client identity revoked
   mid-handshake cannot complete (design v2 §4).
5. **Freshness cache, honestly scoped.** The server keeps an LRU cache
   (TTL 300 s, 4096 entries) of `(id_C, nonce_C)` pairs and raises
   `HandshakeReplayDetected` on an M1 replay (T8c). This is DoS hygiene and early
   rejection; it is *not* the correctness anchor — full handshake replay (T8b)
   is rejected by transcript binding at M3 regardless of cache state.

### 3.5 Key schedule

HKDF-SHA256 (RFC 5869) is implemented explicitly so every derivation step is
auditable against this document. The derivation order is fixed and acyclic:

```
ss -> sig_S -> TH2 -> PRK -> fk -> fin_S -> sig_C -> TH3 -> fin_C -> TH4
     -> c2s_key / s2c_key / nb_c2s / nb_s2c / exporter
```

| Value | Derivation |
|---|---|
| `TH2` | `SHA-256("QFF26-P1-TH2" ‖ T3)` |
| `PRK` | `HKDF-Extract(salt = TH2, IKM = ss)` |
| `fk` | `HKDF-Expand(PRK, "QFF26-P1 fin", 32)` |
| `fin_S` | `HMAC-SHA256(fk, "QFF26-P1 fin-S" ‖ TH2)` |
| `fin_C` | `HMAC-SHA256(fk, "QFF26-P1 fin-C" ‖ TH3)` |
| `c2s_key` | `HKDF-Expand(PRK, "QFF26-P1 c2s" ‖ TH4, 32)` |
| `s2c_key` | `HKDF-Expand(PRK, "QFF26-P1 s2c" ‖ TH4, 32)` |
| `nb_c2s` / `nb_s2c` | `HKDF-Expand(PRK, "QFF26-P1 nb c2s"/"QFF26-P1 nb s2c" ‖ TH4, 12)` |
| `exporter` | `HKDF-Expand(PRK, "QFF26-P1 export" ‖ TH4, 32)` |

The kit quickstart labels (`QFF26 c2s` / `QFF26 s2c`) are preserved and
strengthened with `TH4` transcript binding: the traffic keys do not exist until
both Finished values have been committed to the transcript. Transient secrets
(`ss`, `PRK`, `fk`, KEM private key) are wiped from the channel object on
`ESTABLISHED` and on every terminal state (best-effort; see Section 7).

### 3.6 Record layer

Header (16 B, always used as AAD):

```
version u16 (0x0001) | type u8 (0x01 app-data, 0x02 close)
| dir u8 (0x01 c2s, 0x02 s2c) | seq u64 BE | ct_len u32 BE
```

- `nonce (12 B) = nb_dir XOR (seq as u64 BE, left-padded to 12 B)` — injective in
  `seq`; with a per-direction base, nonce reuse is structurally excluded.
- Per-record wire overhead: **32 B** (16 B header + 16 B GCM tag). One record per
  payload; no chunking in scope (Section 7).
- Receiver pipeline order is fixed: length/`ct_len` consistency → record version
  → direction byte (`TranscriptBindingError` on mismatch) → **sliding replay
  window (before any decryption)** → AES-256-GCM open (`InvalidTag` →
  `RecordAuthenticationError`).
- **Replay window:** per-direction watermark + 64-bit bitmap. `seq < watermark`
  or a duplicate inside the window → `RecordReplayDetected` *before* GCM runs;
  a forward gap ≥ 64 advances the watermark (older sequence numbers become
  undeliverable). GCM authenticates integrity, not freshness — the window is the
  replay defense, and T8a verifies it (first copy delivered, byte-identical
  second copy rejected).
- **Session caps:** sender-side cap `max_records` (default 2^40, configurable) and
  hard sequence cap 2^63; exceeding raises `SessionExhausted`. Renegotiation is a
  fresh handshake (documented, not automated — Section 7).
- **Authenticated close:** `close()` emits a type-0x02 record under the send key;
  a forged close fails GCM authentication and never tears down the peer (T1c).

## 4. Security model

### 4.1 Trust model

Identities are pinned in `trust_store.json` (committed, public keys only): each
entry carries a role (`client` / `server`) and one verification key per suite.
Private keys live only in git-ignored `identities/*.json` (ML-DSA-65 stored as
its 32-byte seed, restored via `from_seed_bytes`; Ed25519 as raw 32 bytes).
Trust-store distribution and integrity are out-of-band (Section 7).

### 4.2 Attacker capabilities considered

The battery models an active attacker with full control of the wire: bit flips
in any handshake field or record byte, substitution of whole fields (rogue
identity, rogue suite id), replay of records, of full old sessions, and of M1,
splicing of a genuine old signature into a fresh session, role swap with genuine
keys, and a rogue endpoint with its own (valid) keypair.

### 4.3 Failure taxonomy (typed, fail closed)

| Category | Meaning | Fired by (observed) |
|---|---|---|
| `PolicyViolation` | version/suite rejected before any crypto | T2 (proto_version, suite_id), T9a, T9b |
| `UntrustedIdentity` | identity not pinned, or role mismatch | T2 (id_C, id_S), T6, T7a |
| `AuthenticationFailure` | signature or Finished verification failed | T2 (kem_pk_C, nonce_C, kem_ct, nonce_S), T3, T7b, T8b |
| `TranscriptBindingError` | strict-parse violation, KEM input reject, record direction mismatch | T5 (header_direction) |
| `HandshakeReplayDetected` | (id_C, nonce_C) freshness cache hit | T8c |
| `RecordReplayDetected` | stale/duplicate seq, rejected before decrypt | T8a |
| `RecordAuthenticationError` | GCM InvalidTag or header/length inconsistency | T4, T5 (gcm_tag, header_version) |
| `SessionExhausted` | record/sequence cap reached | documented; not fault-injected |

## 5. T1–T9 wire-level security battery

### 5.1 Methodology

`protocol/wire.py` delivers frames between two real `ClientChannel` /
`ServerChannel` instances. Fault hooks are registered per direction and frame
index (c2s #0 = M1, #1 = M3, #2+ = app records; s2c #0 = M2, #1+ = app records)
and can flip a byte, duplicate, substitute, or splice frames. Assertions use
public confirmation status only: channel state, `failure_category`, delivery
flags, and payload equality — never key bytes. The matrix is 25 checks per
suite × 2 suites = 50 checks, and results are written to
`results/security_tests.csv`.

### 5.2 Results (both suites pass identically — 50/50)

| ID | Scenario (all injected on the wire) | Expected | Observed | PQC-1 | CLASSICAL-1 |
|---|---|---|---|---|---|
| T1a | honest handshake | both ESTABLISHED | both ESTABLISHED | PASS | PASS |
| T1b | 3 official payloads × both directions, byte + SHA-256 vs `payload_sha256.txt` | 6/6 verified | 6/6 verified | PASS | PASS |
| T1c | authenticated close | peer CLOSED | server CLOSED | PASS | PASS |
| T2 | bit-flip kem_pk_C / nonce_C | client aborts, keys never established | `AuthenticationFailure`, established=False | PASS | PASS |
| T2 | bit-flip id_C / id_S | abort at trust lookup | `UntrustedIdentity` | PASS | PASS |
| T2 | bit-flip proto_version / suite_id | policy reject before crypto | `PolicyViolation` | PASS | PASS |
| T2 | bit-flip kem_ct / nonce_S | client aborts, keys never established | `AuthenticationFailure`, established=False | PASS | PASS |
| T3 | bit-flip sig_S / sig_C | verifier aborts | `AuthenticationFailure` | PASS | PASS |
| T4 | bit-flip record ciphertext | reject, plaintext withheld | `RecordAuthenticationError`, withheld | PASS | PASS |
| T5 | bit-flip GCM tag / header version / header direction | typed rejection, plaintext withheld | `RecordAuthenticationError` / `RecordAuthenticationError` / `TranscriptBindingError` | PASS | PASS |
| T6 | attacker identity + own valid key | reject at lookup, before signature math | `UntrustedIdentity` | PASS | PASS |
| T7a | role swap (server identity initiates as client) | reject at lookup | `UntrustedIdentity` | PASS | PASS |
| T7b | genuine old sig_S spliced into fresh session | transcript binding rejects | `AuthenticationFailure` | PASS | PASS |
| T8a | byte-identical app-record replay | first copy delivered; replay rejected before decrypt | `RecordReplayDetected`, first copy intact | PASS | PASS |
| T8b | full old-session replay | fails at M3 verification | `AuthenticationFailure` | PASS | PASS |
| T8c | M1 replay against freshness cache | early rejection | `HandshakeReplayDetected` | PASS | PASS |
| T9a | unknown suite_id | `PolicyViolation` before any crypto | `PolicyViolation` | PASS | PASS |
| T9b | M2 echoes a *different valid* suite | client local policy rejects, no fallback | `PolicyViolation`, established=False | PASS | PASS |

### 5.3 Where the guarantees bite

- **Bit-flips abort at the owning step.** Flips in bytes covered by a signature
  but not by the KEM surface as signature/Finished failures at the peer
  (`kem_pk_C`, `nonce_C`, `kem_ct`, `nonce_S` → client
  `AuthenticationFailure`); identity bytes are rejected by the trust store
  *before* signature math; policy bytes (version, suite) are rejected before any
  crypto at all. In every case traffic keys are never established.
- **Splicing fails on transcript binding (T7b).** A genuine `sig_S` from an old
  session signs a different `T2` (different M1 bytes, different nonces), so
  verification fails; the same transcript hash binds `fin_S`/`fin_C`.
- **Replay is a freshness property (T8).** A byte-identical record *does*
  authenticate under GCM — the sliding window rejects it before decryption, and
  the first copy is delivered exactly once. Full-session replay fails at M3
  because the server's fresh ephemeral KEM output makes the old transcript
  inconsistent.

## 6. Benchmarks

### 6.1 Methodology

- **Handshake latency** (`bench/bench_handshake.py --runs 15`): 15 full handshakes
  per suite on the in-process wire; every run uses fresh channels *and a fresh
  KEM keypair* (protocol-accurate); ephemeral signing keys and a matching
  ephemeral trust store are generated per invocation. Reported: median, IQR
  (Q75−Q25), p95 (linear-interpolated), min, max. No warm-up run is discarded —
  the tail therefore includes one-time library initialization (Section 6.4).
- **Payload throughput** (`bench/bench_payload.py`, repeats = 5): after a real
  handshake, each official payload (1 KB / 100 KB / 10 MB) is transferred 5 times
  per direction; each transfer is timed end-to-end (send → deliver → recv) and
  byte-compared. Reported: median MB/s per direction.

Both measure crypto + serialization cost on one machine; the in-process wire
carries exactly the frames a socket transport would carry, excluding socket and
OS scheduling effects.

### 6.2 Handshake latency (15 runs per suite)

| Suite | median | IQR | p95 | min | max |
|---|---|---|---|---|---|
| `QFF26-PQC-1` | 3.68 ms | 3.49 ms | 34.63 ms | 1.85 ms | 66.09 ms |
| `QFF26-CLASSICAL-1` | 0.73 ms | 0.01 ms | 1.23 ms | 0.72 ms | 2.25 ms |

Raw data: `results/tables/bench_handshake.csv`.

### 6.3 Payload throughput (median of 5, MB/s)

| Suite | Payload | Bytes | c2s | s2c |
|---|---|---|---|---|
| `QFF26-PQC-1` | 1 KB | 1024 | 32.1 | 40.2 |
| `QFF26-PQC-1` | 100 KB | 102400 | 649.0 | 659.0 |
| `QFF26-PQC-1` | 10 MB | 10485760 | 469.5 | 476.6 |
| `QFF26-CLASSICAL-1` | 1 KB | 1024 | 41.1 | 45.1 |
| `QFF26-CLASSICAL-1` | 100 KB | 102400 | 570.2 | 663.6 |
| `QFF26-CLASSICAL-1` | 10 MB | 10485760 | 484.7 | 482.2 |

Raw data: `results/tables/bench_payload.csv`.

### 6.4 Reading the numbers

**The handshake gap is ~5× at the median and entirely attributable to PQ
primitives.** ML-KEM-768 keypair generation + encapsulation/decapsulation and an
ML-DSA-65 sign + verify per side cost ~3 ms combined on this platform, versus
~0.7 ms for X25519 + Ed25519. At 9134 B vs 448 B of wire (Section 3.3), the PQC
handshake is also ~20× heavier on the network — both numbers are the expected
NIST level-1–2 overhead and are comfortably practical for a session-based
channel.

**The p95/max tail is cold-start, not steady state.** With n = 15 and no warm-up
discard, the linear-interpolated p95 lands essentially at the second-largest
sample. The PQC suite's max (66 ms) is dominated by the first run's one-time
costs (lazy module initialization, first ML-KEM/ML-DSA operations through the
native bindings). The honest robust numbers are the median and IQR; p95 is
reported for kit compliance and interpreted here rather than hidden.

**Bulk throughput is suite-independent — the record layer is the bottleneck.**
At 100 KB and 10 MB both suites sit within a few percent of each other
(~470–664 MB/s), because post-handshake cost is AES-256-GCM through the
`cryptography` OpenSSL backend plus Python-level per-call overhead; the KEM
choice is irrelevant once keys are established. This is the intended takeaway
for PS-P1: quantum safety costs at connection setup, not in the data path.

**Small payloads expose per-record fixed cost; the 10 MB dip is memory
hierarchy.** At 1 KB, throughput drops to 32–45 MB/s (≈ 30–45k records/s) since
the 32 B per-record overhead and fixed Python/AESGCM call cost dominate. The
mild dip from 100 KB (570–664 MB/s) to 10 MB (470–485 MB/s) is consistent with
the payload buffer exceeding CPU caches — memory bandwidth and buffer copies,
not crypto, explain the difference. No chunking exists in scope (one record per
payload), which is why per-record costs matter for small messages.

## 7. Prototype status and assumptions

This is a competition prototype built in a 24-hour sprint, not a production
library. It has no formal security proof; the construction follows standard
authenticated-key-exchange patterns (SIGMA/TLS 1.3-style transcript-bound
signatures plus Finished key confirmation), and the implementation has not been
independently audited. Explicit assumptions and limitations:

1. **Trust store distribution and integrity are out of band.** The committed
   `trust_store.json` pins demo identities; a real deployment needs a PKI or
   pre-distribution story, revocation, and rotation (none implemented).
2. **The OS CSPRNG is trusted** (`os.urandom`, `cryptography` key generation).
3. **No side-channel hardening** beyond constant-time `hmac.compare_digest` and
   the library's native primitives. Python-level timing variance is possible.
4. **DoS resistance is out of scope.** The server does cheap unauthenticated
   work (fresh encapsulation) per M1 by design; the freshness cache (TTL 300 s,
   LRU 4096) is hygiene and early replay rejection, not a correctness anchor.
5. **Single trust domain.** No namespacing, delegation, or multi-tenant policy.
6. **Identity-key compromise** breaks future impersonation resistance but not
   past session confidentiality: every session uses a fresh KEM keypair, and
   traffic keys are erased from the channel object on terminal states.
7. **Zeroization is best-effort.** `bytearray` buffers are wiped, but Python's
   memory model cannot guarantee that key bytes never persist elsewhere.
8. **One record per payload; no chunking/fragmentation.** A single record is
   bounded by the u32 `ct_len` field and available memory; `SessionExhausted`
   ends the session at the configurable cap (default 2^40 records, hard cap
   2^63).
9. **In-process wire for tests and benchmarks.** Frames are identical to what a
   socket transport would carry; sockets, TLS-over-TLS comparisons, congestion,
   and OS effects are out of scope. Numbers are single-machine (Intel Mac) and
   not representative of network deployments.
10. **Auto-renegotiation after `SessionExhausted` is documented, not automated**;
    re-establishing is a fresh handshake by construction.
11. **X25519 is modeled as a KEM** (ephemeral–ephemeral ECDH) to keep one state
    machine across suites; the classical suite is a comparison baseline, not a
    recommended migration target for production post-quantum deployments.
12. **ML-DSA-65 identity files store the 32-byte seed** (restored via
    `from_seed_bytes` in `cryptography` 50.x). The seed is equivalent to the
    full private key and is protected accordingly (git-ignored `identities/`,
    never printed, never logged).
13. **Logs and test output carry metadata only** (states, categories, sizes);
    key bytes never appear on stdout, in CSVs, or in assertions.

## 8. Reproduction guide

Clean clone on any platform with Python 3.10–3.13 (validated on 3.13.17):

```bash
git clone https://github.com/Devo982/SRM-Qiskit-FF-PS-P1.git
cd SRM-Qiskit-FF-PS-P1
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

python common/env_check.py              # -> READY - environment is correct.
python scripts/provision_identities.py  # identities/ (git-ignored) + trust_store.json
python -m tests.run_security_tests      # -> ALL TESTS PASSED: 50/50 checks
python -m cli.demo --suite QFF26-PQC-1  # metadata-only end-to-end demo
python bench/bench_handshake.py --runs 15
python bench/bench_payload.py
```

Expected artifacts after reproduction: `results/security_tests.csv`,
`results/tables/bench_handshake.csv`, `results/tables/bench_payload.csv`,
`data/payloads/payload_*.bin` + `payload_sha256.txt` (regenerated; the `.bin`
files are git-ignored), and `platform_A_info.json`.

> **Intel macOS note.** `cryptography==50.0.2` publishes no macOS x86_64 wheel;
> on Intel Macs pip builds it from sdist against a local static OpenSSL —
> `scripts/QFF2026_intel_mac_env_setup.sh` builds OpenSSL 3.5.9 (no-shared) into
> `~/.local/openssl-3.5.9` and `~/.qff26-openssl-env.sh` exports
> `OPENSSL_DIR`/`OPENSSL_LIB_DIR`/`OPENSSL_INCLUDE_DIR`/`OPENSSL_STATIC=1`.
> Every other platform installs the prebuilt wheel directly.

## 9. Artifact integrity

**Committed:** all source (`protocol/`, `tests/`, `cli/`, `bench/`, `scripts/`,
`common/`), `docs/INTEGRATION_CONTRACT.md`, this report, `README.md`,
`requirements.txt` (kit pin `cryptography==50.0.2`), `trust_store.json` (public
keys only), `data/payloads/payload_sha256.txt`, `results/security_tests.csv`,
`results/tables/*.csv`, `platform_A_info.json`.

**Never committed:** `identities/*.json` (private keys/seeds — enforced by
`.gitignore` + `git check-ignore` at provisioning time), `data/payloads/*.bin`
(regenerable from the deterministic generator, verified against the committed
SHA-256 manifest), virtualenvs and caches.
