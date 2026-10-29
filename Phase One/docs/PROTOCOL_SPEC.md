# Protocol Specification — Baseline PS-P1

## 1. Goal and non-goals

Implement and benchmark a hybrid key-establishment prototype combining ephemeral ECDH P-256 and NIST ML-KEM-768. Derive a 32-byte session key from both shared secrets with HKDF-SHA-256. Compare against ECDH-only and ML-KEM-only baselines.

This does not implement TLS, KEMTLS, Muckle#, QKD, certificates, peer authentication, or a formally analyzed authenticated key-exchange protocol. It is an engineering/measurement prototype only.

## 2. Roles and exchange

**Responder → Initiator (message 1):**
- responder's ephemeral P-256 public point (65-byte uncompressed X9.62 encoding);
- responder's fresh ML-KEM-768 encapsulation public key (1184 bytes).

**Initiator → Responder (message 2):**
- initiator's ephemeral P-256 public point (65 bytes);
- ML-KEM-768 ciphertext (1088 bytes), created by encapsulating to the responder public key.

Each side computes the ECDH secret. The initiator gets the ML-KEM secret from encapsulation; responder gets it from decapsulation. Both derive a key with the same ordered inputs and transcript.

## 3. Baseline payload expectations

No framing, certificate, MAC, or TLS record overhead included.

| Suite | Responder → Initiator | Initiator → Responder | Total |
|---|---:|---:|---:|
| ECDH-only | 65 | 65 | 130 bytes |
| ML-KEM-only | 1184 | 1088 | 2272 bytes |
| Hybrid | 65 + 1184 = 1249 | 65 + 1088 = 1153 | 2402 bytes |

The payload calculation must use actual serialized byte lengths and compare them against these values. Report ML-KEM ciphertext size (1088 bytes) as a separate metric.

## 4. Transcript

Construct a canonical transcript with deterministic length-prefix encoding. Include a protocol identifier/version, selected suite/mode, responder's P-256 public point if present, responder's ML-KEM public key if present, initiator's P-256 public point if present, and ML-KEM ciphertext if present. Encode field name length, field name, field value length, and field value; do not concatenate unframed variable-length values.

Calculate `transcript_hash = SHA-256(transcript)` and use it as the HKDF salt. Use a fixed versioned `info` label such as `PS-P1/hybrid-ECDH-P256-ML-KEM-768/v1`; distinct suites must use distinct labels.

## 5. IKM construction and key derivation

Use a deterministic ordered encoding of all participating secrets and their labels/lengths. For hybrid mode, the ECDH secret and ML-KEM secret must both be required and included. The output is 32 bytes from HKDF-SHA-256. Both endpoints should independently derive the result and compare in a test harness; secret values are never printed or serialized to outputs.

Do not use ad-hoc XOR as the combiner. Do not use an individual component's secret as the final key in hybrid mode.

## 6. Key lifecycle

- Generate a fresh ephemeral P-256 keypair per handshake.
- Generate a fresh ML-KEM-768 keypair per handshake for the baseline benchmark.
- Avoid caching a static ML-KEM key in the main benchmark. A separate key-reuse/rotation study is an optional extension and must not be mixed into the baseline numbers.
- Use the platform cryptographic random source via the libraries; do not inject deterministic seeds during ordinary benchmarks.

## 7. Error handling

- Reject malformed P-256 encodings and invalid points.
- Reject unsupported algorithm names or absent ML-KEM support.
- Respect ML-KEM's implicit-rejection semantics: arbitrary malformed ciphertext input is not guaranteed to throw. Test that mutated ciphertext does not yield the same session key as the unmodified transcript/session; use explicit key confirmation if demonstrating protocol-level detection.
- Never expose private keys or shared secrets in exception text, logs, traces, CSV, or report assets.

## 8. Security boundary

Messages are unauthenticated in this baseline. An active attacker may replace public keys and establish different keys with each endpoint. A key-confirmation MAC only confirms possession of the same derived key; it does not authenticate identity in the absence of a trusted key/certificate/signature system. Any optional confirmation exchange must be separately specified and must add its real wire bytes and timing to the measurement.

Do not claim this implementation is production-ready or equivalent to the authenticated protocol discussed in the supplied Battarbee et al. paper.
