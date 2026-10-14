# Autonomous Work Ledger — PS-P1

The agent must check off a task only when the relevant verification evidence exists. Store command outputs in `results/logs/` (create as needed), and append summaries to `results/verification_log.md`.

Status legend: `TODO` → `IN PROGRESS` → `PASS`; use `BLOCKED` for unresolved dependency/host limitations and `FAIL` for a test that currently fails.

## Phase 0 — Inspect and preflight
- [x] Read all mandatory files listed in `AGENTS.md`.
- [x] Record Python, OS, CPU, package manager, Git status, Docker availability, compiler, CMake, and network/dependency availability.
- [x] Install the declared Python dependencies in an isolated environment.
- [x] Verify that `import oqs` succeeds and that `ML-KEM-768` is listed as enabled.
- [x] Save dependency versions to `environment.md` and record preflight output.

**Gate 0:** Do not proceed to an accepted benchmark unless standardized ML-KEM-768 is available. If blocked, diagnose/install rather than substitute legacy Kyber or a mock.

## Phase 1 — ECDH P-256
- [x] Implement fresh key generation, 65-byte uncompressed point serialization, peer-key validation, and exchange.
- [x] Test matching 32-byte secrets and malformed-point rejection.
- [x] Measure key generation and exchange independently in a pilot.

**Gate 1:** ECDH tests pass, all expected lengths are asserted, and failures are recorded.

## Phase 2 — ML-KEM-768
- [x] Implement keypair, encapsulation, and decapsulation using `liboqs-python`.
- [x] Verify exact standardized mechanism identifier and expected lengths (1184-byte public key, 2400-byte secret key, 1088-byte ciphertext, 32-byte shared secret).
- [x] Test that encapsulated and decapsulated secrets agree.
- [x] Record OQS/liboqs versions and enabled mechanism list without printing keys/secrets.

**Gate 2:** ML-KEM integration tests actually execute and pass; no skip counts as a pass.

## Phase 3 — Transcript and KDF
- [x] Implement deterministic length-prefixed transcript serialization.
- [x] Bind protocol version, mode/suite, both public keys, and ML-KEM ciphertext where applicable.
- [x] Implement HKDF-SHA-256 session-key derivation with explicit labels and transcript hash.
- [x] Test same transcript/same secrets → same key; changed transcript or input secret → different key.

**Gate 3:** Tests prove both endpoints derive the same 32-byte key and that transcript changes affect derivation.

## Phase 4 — Complete handshake integration
- [x] Implement ECDH-only, ML-KEM-only, and hybrid modes for comparisons.
- [x] Use fresh ephemeral P-256 keys and fresh ML-KEM keypairs for each baseline handshake.
- [x] Verify key agreement; keep secret material out of outputs and logs.
- [x] Test expected raw payload byte counts (130, 2272, 2402), excluding framing/authentication.
- [x] Test malformed public keys and ensure ciphertext mutation is not incorrectly assumed to always throw.

**Gate 4:** Full correctness suite passes for all three modes with ML-KEM executed, and payload arithmetic matches actual serialized values.

## Phase 5 — Benchmark instrumentation
- [x] Record per-operation nanosecond timings with `perf_counter_ns`.
- [x] Record raw one-row-per-handshake observations with run/batch/platform/suite/environment metadata.
- [x] Calculate median, p95, p99, success rate, and throughput.
- [x] Implement RSS sampling separately from the latency measurement run; record baseline RSS, sampled peak RSS, and delta.
- [x] Add an output-schema test and run a small pilot before large runs.

**Gate 5:** Pilot produces valid CSV and summaries; no sample is dropped silently; memory overhead method is documented.

## Phase 6 — Platform A
- [x] Record effective environment metadata and run `--platform A` using the final source revision.
- [x] Run 100 warmups, 1000 measured samples per suite per batch, and 5 batches for final results.
- [x] Save raw CSV and logs; create a content hash/working revision marker.
- [x] Check that all modes completed and no errors were omitted.

**Gate 6:** Complete raw data, summary metrics, and platform metadata exist; output is reproducible.

## Phase 7 — Platform B
- [ ] Build the same container image used for A. **BLOCKED** — Docker daemon unavailable on host (client only; no root to start it). Mitigation: ran Platform B in the same virtualenv/source under an enforced cgroup v2 scope instead; deviation recorded in `report.md` and `results/verification_log.md`.
- [x] Run using enforced `--cpus=1 --memory=512m` limits or another documented constrained setting. *(Docker unavailable; used equivalent enforced cgroup v2 user scope: `CPUQuota=100%`, `MemoryMax=512M`.)*
- [x] Confirm that cgroup CPU and memory limits were detected; capture Docker command and image digest. *(cgroup v2 limits detected and recorded; no Docker image digest — daemon unavailable, documented deviation.)*
- [x] Run the same benchmark workload/number of batches.
- [x] Mark unverified if any required limit is not observed; don't use unverified data for comparative claims.

**Gate 7:** Platform B is verified as resource constrained, and all suites ran with same source/dependency versions.

## Phase 8 — Analysis and report
- [x] Re-run full tests on final code before using data.
- [x] Generate comparison tables and plots from raw data through scripts; no manual invented rows.
- [x] Compare ECDH-only, ML-KEM-only, and hybrid median/p95/p99, raw payload, peak RSS, and throughput.
- [x] State whether difference is statistically and practically meaningful; include spread/limitations.
- [x] Distinguish operation time from full simulated handshake time and network round-trip time.
- [x] Clearly state that container constraints are not real embedded hardware and the protocol lacks identity authentication.
- [x] Resolve or document the QFF-wide quantum Processor A/B vs PS-P1 CPU A/B scope ambiguity.
- [x] Complete `report.md` and `environment.md` with citations and verified values only.

**Gate 8:** Report conclusions map to data fields/raw rows, all plots are regenerated by code, and no placeholders are labeled final.

## Phase 9 — Final audit
- [x] Search code and result files for accidental secrets/private key material.
- [x] Search report for unsupported claims, stale placeholders, unverified Platform B claims, and skipped tests reported as passed.
- [x] Check package setup instructions from a clean environment or container.
- [x] Ensure `results/verification_log.md`, raw CSV, summaries, plots, and report are included.
- [x] Write a final acceptance summary in `results/FINAL_ACCEPTANCE.md`.

**Gate 9:** Release only with truthful pass/fail/blocked statuses and exact evidence references.
