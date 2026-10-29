# Stepwise Implementation Plan and Verification Gates

This plan is intentionally gate-driven. The agent must gather evidence for every stage and may not skip ahead on a failed gate.

## Stage 0 — Environment discovery

1. Inspect repository state and files before changing anything.
2. Record Python/OS, CPU, memory, compiler, CMake, Git, Docker, `cryptography`, `psutil`, and OQS/library versions.
3. Install dependencies in an isolated environment.
4. Verify that `ML-KEM-768` is an enabled KEM mechanism. Confirm the exact name as returned by the installed library.

**Gate:** preflight command exit code 0; OQS loaded; ML-KEM-768 appears in enabled mechanisms; output saved. Otherwise BLOCKED.

## Stage 1 — ECDH

Implement `src/ecdh.py`. Validate encoding lengths, parse peer keys, and calculate both parties' secrets. Test malformed data and agreement. Benchmark key generation and exchange separately in a pilot.

**Gate:** ECDH tests pass with key length and serialized point lengths asserted.

## Stage 2 — ML-KEM

Implement `src/mlkem.py` using official `liboqs-python` APIs. Instantiate `oqs.KeyEncapsulation("ML-KEM-768")`, generate a key pair, encapsulate to the public key, and decapsulate on the key owner. Verify both secrets match and check documented lengths.

**Gate:** tests are executed against the actual native library and pass. Skips are not accepted at final stage.

## Stage 3 — Transcript and HKDF

Build a deterministic, length-prefixed transcript. Include suite, role-labelled public keys, ciphertext, and version. Encode secret inputs in a stable order and derive a 32-byte key using HKDF-SHA-256, transcript hash as salt, and a domain-specific `info` string. Verify agreement and transcript sensitivity.

**Gate:** endpoint outputs match and transcript mutations result in different derived keys under tests.

## Stage 4 — Handshake modes

Implement three benchmark suites: `ecdh`, `mlkem`, and `hybrid`. Use fresh keys for each handshake. Record component timers and payload bytes. Do not include real network latency unless using actual sockets; report synthetic latency separately if it is later added.

**Gate:** three modes pass integration tests; payload sizes are 130/2272/2402 bytes for the chosen raw message model.

## Stage 5 — Measurement

Use `perf_counter_ns` and preserve per-observation rows. Run warmups separately. Use five independent batches with at least 1000 observations per suite per platform for final results. Calculate median, p95, p99, throughput, success rate, and memory fields. Use a separate memory-probe pass so an RSS polling thread does not perturb the latency sample.

**Gate:** short pilot output schemas validate and a full benchmark can complete. No raw sample should contain cryptographic secrets.

## Stage 6 — Platform A / B

Platform A uses a documented baseline. Platform B should reuse the same container image and code but run with enforced CPU/memory limits. Detect and record limits from cgroups/environment. If the constraints cannot be verified, report Platform B as unverified and do not compare it as if it were constrained.

**Gate:** both runs record consistent code/library versions and verified environment metadata. Platform B has an observed CPU quota and memory limit within configuration.

## Stage 7 — Reporting and audit

Build results from CSV using a reproducible script. Keep raw and processed files separate. Verify final tests after all code changes. Document limitations and any results that are missing. Search for leaked secrets and for stale placeholder values.

**Gate:** report matches raw data; logs and commands exist; all blockers disclosed.

## Required response from agent

At finish, provide a short evidence-based phase table with statuses `PASS`, `FAIL`, or `BLOCKED`; list the exact commands and artifacts; quote measured values only when outputs exist; state whether Platform B is verified; and list any remaining limitations.
