# Benchmarking Protocol and Acceptance Criteria

## 1. Benchmark configurations

- `ecdh`: fresh responder and initiator ephemeral P-256 keys; exchange shared secret; derive a session key with suite-specific HKDF.
- `mlkem`: fresh ML-KEM-768 responder keypair; initiator encapsulation; responder decapsulation; derive a session key with suite-specific HKDF.
- `hybrid`: do both; require both secrets for the final key.

Keep protocol operations comparable and explicitly list which operations are included in each end-to-end timing. The proposed implementation times cryptographic key generation, exchange/encapsulation/decapsulation, and KDF; no socket or network transfer is included.

## 2. Sample plan

For every platform and suite:
- 100 warm-up handshakes, excluded from measured observations;
- 1000 measured handshakes per batch;
- 5 independent batches;
- preserve one CSV row per measured handshake;
- record all failures and include them in success-rate calculation;
- do not delete outliers unless a documented, pre-defined data-quality rule justifies it.

A short pilot (`20` iterations, one batch) is for debugging only, not final conclusions.

## 3. Measurements

Required:
- total handshake wall time in ns/ms;
- per-component timings for P-256 key generation, ECDH exchange, ML-KEM key generation, encapsulation, decapsulation, and HKDF at each endpoint;
- raw message bytes by direction, ML-KEM ciphertext bytes, and total raw payload bytes;
- baseline RSS, sampled peak RSS, and sampled peak increase in a separate memory probe;
- attempted and successful handshakes;
- throughput at stated concurrency (initially one worker; optional controlled concurrent runs);
- environment and run metadata including platform config verification.

Summary statistics: n, failures, success rate, median, p95, p99, mean, standard deviation, and throughput. Keep units explicit. p95/p99 should use a documented quantile definition and be derived from raw samples.

## 4. Memory measurement

`tracemalloc` only accounts for Python-tracked allocations; it does not capture all native `liboqs`/OpenSSL allocations. Use process RSS via `psutil` for the main memory metric. Sample RSS during an independent memory-probe workload, after a documented warm-up; report baseline/peak/delta and polling interval. Sampling can miss short-lived peaks, so label it sampled peak RSS rather than exact maximum allocation. Also run a cold-start probe when practical to characterize library initialization.

## 5. Platform verification

Platform labels alone don't enforce limits. For Platform B, require observed CPU quota and memory cap (e.g. cgroup v2 `cpu.max` and `memory.max`, or equivalent). Record both the requested Docker arguments and the observed limits. Mark the run `platform_verified=false` and exclude it from A-vs-B conclusions if the limits cannot be verified.

The illustrative B configuration is 1 CPU and 512 MiB. It can be adjusted if the host cannot support it, but must be declared before benchmarking and held constant through all B suites.

## 6. Interpretation

- Distinguish raw ciphertext size from all handshake bytes.
- Distinguish local compute latency from network RTT and TLS handshake time.
- Don't claim energy consumption or embedded/ARM results from a CPU-limited x86 container.
- Treat single-worker latency and multi-worker throughput separately.
- Don't call a suite more secure because it benchmarks faster or slower.
- Report both effect sizes and variability; do not over-interpret tiny differences.
- A hybrid session key should depend on both input secrets and the transcript; performance data does not prove this security property.
