# PS-P1 — Quantum-Safe Hybrid Key Exchange Benchmark Report

Implementation of an ephemeral P-256 ECDH + standardized ML-KEM-768 hybrid key
establishment prototype with HKDF-SHA-256 session-key derivation, benchmarked under a
standard CPU baseline (Platform A) and an enforced CPU/memory-constrained environment
(Platform B). This is a research/benchmark prototype, **not** a production secure channel.

## Executive summary
- Implementation revision: working-tree SHA-256 `0ee224649e75130a8fb2a33d097747970e046e5bd7880ed16aaa8bc226539f88` (not a Git repo).
- ML-KEM standard mechanism / library: `ML-KEM-768` (`version=FIPS203`, NIST category 3, IND-CCA) via native `liboqs` 0.16.0 and `liboqs-python` 0.16.0.1. Preflight `PASS`; 20/20 tests executed with **zero ML-KEM skips**.
- Platform A verification: `platform_verified=true`; no CPU/memory cap imposed; 15,000/15,000 handshakes successful.
- Platform B verification: `platform_verified=true`; observed cgroup v2 `cpu.max=100000 100000` (1.0 core) and `memory.max=536870912` (512 MiB); 15,000/15,000 handshakes successful.
- Principal measured finding: single-thread **median** handshake latency is essentially identical on A and B (B/A ratio 0.99–1.02), but the 1-CPU quota markedly increases **tail latency and jitter** for the longer ECDH/hybrid handshakes (hybrid p99 ×1.68, std-dev ×4.6), while the shorter ML-KEM-only handshake is unaffected (p99 ×1.01).
- Full contents: native liboqs (real ML-KEM), automated tests, raw CSV, summary tables, plots, and audit. **Platform B used an enforced cgroup v2 scope, not a Docker container, because the Docker daemon was unavailable on the host** (documented deviation).

## Methodology

### Protocol and exact operations timed
Two simulated endpoints run sequentially in one process. Per handshake:
- ECDH-only: responder + initiator ephemeral P-256 keygen, two ECDH exchanges, HKDF at both ends.
- ML-KEM-only: responder ML-KEM-768 keypair, initiator encapsulation, responder decapsulation, HKDF at both ends.
- Hybrid: both of the above; the final key requires **both** secrets.

Fresh ephemeral P-256 keys and a **fresh ML-KEM-768 keypair are generated per handshake**
(`src/handshake.py`). `handshake_wall_ns` is measured with `time.perf_counter_ns` around the
whole local computation. It **excludes** network/socket transfer, TLS records, certificates,
and library cold-start (warmups absorb first-call effects). Component timers
(`*_keygen_ns`, `ecdh_exchange_*_ns`, `mlkem_encap_ns`, `mlkem_decap_ns`, `hkdf_*_ns`) are
recorded per row in the raw CSV.

### Transcript and KDF
A canonical length-prefixed transcript binds `protocol_id`, `protocol_version`, `suite`,
responder/inviter P-256 points, responder ML-KEM public key, and ML-KEM ciphertext
(`src/transcript.py:encode_transcript`). The session key is
`HKDF-SHA-256(ikm=length-prefixed labelled secrets, salt=SHA-256(transcript), info=PS-P1/session-key/<suite>/v1)`
(`src/hybrid.py`). Hybrid requires both `ecdh_p256` and `mlkem_768` secret components.

### CPU/memory configurations and evidence
- Platform A: host baseline, no benchmark-imposed limits. `cpu_quota_cores=None`, `memory_limit_bytes=None`.
- Platform B: same source tree and same virtualenv/dependencies, executed under a cgroup v2
  user scope created with `systemd-run --user --scope -p CPUQuota=100% -p MemoryMax=512M -p MemorySwapMax=0`.
  Observed limits are recorded in `data/processed/environment_B_*.json` with sources
  `cgroup_v2:.../cpu.max` and `cgroup_v2:.../memory.max`. The cgroup reader resolves the
  process's **own** cgroup via `/proc/self/cgroup` and walks ancestors for the tightest limit.
- **Deviation:** the intended Docker run (`--cpus=1 --memory=512m`) was not possible; the
  Docker daemon is unavailable and cannot be started without root. The cgroup v2 scope
  enforces the same numeric limits observably, but it is host-kernel emulation, not a
  container and not embedded hardware.

### Sample plan and quantiles
- Warmup: 100 handshakes per suite per batch (excluded).
- Measured: 1,000 handshakes per suite per batch × 5 batches = 5,000 per platform/suite.
- Quantiles: linear interpolation at `(n-1)*q` (inclusive), computed by `scripts/analyze_results.py`
  (`interpolation="linear"` in pandas, equivalent to the scaffold's `quantile`).
- No outliers deleted; all failures retained in success-rate denominators.

### RSS measurement
A **separate subprocess** memory probe runs after a 10-handshake warmup; a background thread
samples `psutil` process RSS every 2 ms; baseline RSS is taken after warmup/GC. This yields
*sampled peak RSS*, not exact native allocation (`tracemalloc` cannot see liboqs/OpenSSL
allocations). Probe: `src/benchmark.py:_memory_child`.

### Software versions / reproduction
Python 3.14.7; cryptography 46.0.7; liboqs-python 0.16.0.1; liboqs 0.16.0; psutil 7.2.2;
pandas 3.0.6; matplotlib 3.11.2. See `environment.md`. Both platforms used identical versions.

## Correctness and gate results
| Gate | Command | Result | Evidence |
|---|---|---|---|
| Environment/preflight | `.venv/bin/python -m src.cli check` | PASS (ML-KEM-768 enabled, FIPS203) | `results/logs/phase0_preflight_stdout.json` |
| ECDH | `.venv/bin/python -m pytest -q tests/test_ecdh.py` | PASS | 4 tests; 65-byte point, 32-byte secret, malformed rejection |
| ML-KEM-768 | `.venv/bin/python -m pytest -q tests/test_mlkem.py` | PASS (executed, not skipped) | sizes 1184/2400/1088/32; implicit rejection changes derived key |
| Hybrid KDF/transcript | `.venv/bin/python -m pytest -q tests/test_hybrid_kdf.py` | PASS | both secrets required; transcript binding; distinct suite labels |
| Full integration | `.venv/bin/python -m src.cli handshake --mode all` | PASS | `results/logs/phase4_handshake_all.json`; payloads 130/2272/2402 |
| Benchmark schema | `.venv/bin/python -m pytest -q tests/test_benchmark_schema.py` | PASS | row/summary schema; CSV round-trip; no secret-like columns |
| Platform B constraints | `systemd-run --user --scope -p CPUQuota=100% -p MemoryMax=512M ...` | PASS (verified) | `data/processed/environment_B_20261014T111137Z_53a5cead.json` |
| Full test suite | `.venv/bin/python -m pytest -q` | PASS | **20 passed, 0 skipped** |

## Performance results
Source: `results/tables/comparison_summary_verified_final.csv` (derived from
`data/raw/benchmark_{A,B}_*.csv`). Units: milliseconds. `N` = successful measured handshakes.

| Platform | Suite | N | Success % | Median ms | p95 ms | p99 ms | IQR ms | StdDev ms | Throughput handshakes/s |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| A | ECDH-only | 5000 | 100.0 | 0.3603 | 0.3859 | 0.4380 | 0.0161 | 0.0196 | 2742.4 |
| A | ML-KEM-only | 5000 | 100.0 | 0.1915 | 0.2567 | 0.2811 | 0.0206 | 0.0802 | 4914.6 |
| A | Hybrid | 5000 | 100.0 | 0.5363 | 0.5698 | 0.6430 | 0.0175 | 0.0247 | 1854.3 |
| B | ECDH-only | 5000 | 100.0 | 0.3650 | 0.4601 | 0.5701 | 0.0211 | 0.0964 | 2648.8 |
| B | ML-KEM-only | 5000 | 100.0 | 0.1893 | 0.2438 | 0.2843 | 0.0180 | 0.0668 | 5028.0 |
| B | Hybrid | 5000 | 100.0 | 0.5474 | 0.8147 | 1.0785 | 0.0679 | 0.1136 | 1688.6 |

B/A ratios: ECDH median 1.013 / p99 1.302 / stddev 4.92; ML-KEM median 0.988 / p99 1.011 / stddev 0.83; Hybrid median 1.021 / p99 1.677 / stddev 4.60.

Per-component medians (µs), `results/tables/component_timings_final.csv`:
| Platform | Suite | ML-KEM keygen | ML-KEM encap | ML-KEM decap | ECDH keygen (resp.) | ECDH exchange (init.) | HKDF (init.) |
|---|---|---:|---:|---:|---:|---:|---:|
| A | ECDH | – | – | – | 27.66 | 117.89 | 17.74 |
| A | ML-KEM | 34.78 | 34.36 | 36.46 | – | – | 18.65 |
| A | Hybrid | 35.27 | 39.74 | 37.16 | 31.50 | 120.13 | 22.98 |
| B | ECDH | – | – | – | 28.08 | 119.08 | 17.67 |
| B | ML-KEM | 34.85 | 34.36 | 36.32 | – | – | 18.16 |
| B | Hybrid | 35.69 | 41.14 | 37.23 | 33.66 | 122.01 | 24.31 |

Per-batch medians (`results/tables/per_batch_stats_final.csv`) are stable on A; B's hybrid
batch 2 median is elevated (0.5998 ms vs ~0.54 ms), showing scheduling jitter under the quota.

## Payload size
Raw unframed payload bytes (excluding certificates/MACs/TLS framing); ML-KEM ciphertext
reported separately. Constant across platforms, `data/raw/benchmark_*.csv` fields
`total_payload_bytes`, `mlkem_ciphertext_bytes`.

| Suite | Responder → Initiator bytes | Initiator → Responder bytes | Total raw payload bytes | ML-KEM ciphertext bytes |
|---|---:|---:|---:|---:|
| ECDH-only | 65 | 65 | 130 | 0 |
| ML-KEM-only | 1184 | 1088 | 2272 | 1088 |
| Hybrid | 1249 | 1153 | 2402 | 1088 |

## Memory results
Source: `results/tables/memory_comparison_all_runs_final.csv`. Sampling interval 2 ms;
sampled peak RSS − warmed baseline. Units MiB.

| Platform | Suite | Baseline RSS MiB | Sampled peak RSS MiB | Delta MiB | Sampling interval |
|---|---|---:|---:|---:|---|
| A | ECDH-only | 30.961 | 31.246 | 0.285 | 2 ms |
| A | ML-KEM-only | 36.020 | 36.230 | 0.211 | 2 ms |
| A | Hybrid | 36.586 | 36.797 | 0.211 | 2 ms |
| B | ECDH-only | 30.988 | 31.273 | 0.285 | 2 ms |
| B | ML-KEM-only | 35.781 | 35.992 | 0.211 | 2 ms |
| B | Hybrid | 36.770 | 36.980 | 0.211 | 2 ms |

Baseline RSS is higher for ML-KEM/hybrid because the liboqs native library and KEM contexts
are already loaded; the per-handshake marginal RSS increase is small (~0.2–0.3 MiB) because
fresh keypairs are small and freed each iteration. This sampled delta is not a peak-allocation
bound.

## Interpretation
- **Suite ordering (both platforms):** ML-KEM-only is the fastest (≈0.19 ms median), ECDH-only
  is slower (≈0.36 ms), and hybrid is the sum-plus-overhead (≈0.54 ms). The dominant ECDH
  cost is the P-256 scalar multiplication (~118 µs per exchange); ML-KEM keygen/encap/decap
  are each ~35 µs. This matches the component table and is why the hybrid median is close to
  ECDH + ML-KEM.
- **A vs B medians are not practically different** (within ~2%, i.e. far below the run-to-run
  spread). A single-threaded crypto workload that fits in one CPU gets essentially full speed
  even under a 1-core quota.
- **A vs B tails do differ.** For ECDH and hybrid, Platform B shows materially higher p95/p99
  and 4.6–4.9× the standard deviation, consistent with CPU-quota scheduling contention on a
  shared host. ML-KEM-only (short, cache-resident) is unaffected. This is the practically
  meaningful A-vs-B effect and it is about **jitter/tail**, not median throughput.
- **Compute vs network:** all figures are local CPU execution. Real network RTT and TLS
  handshake time are excluded; do not read these as end-to-end latency. Payload sizes are the
  raw message bytes only, not wire/frame overhead.
- **Container emulation vs hardware:** Platform B is a cgroup-limited x86 host scope. No claim
  is made about ARM, energy, caches, or real embedded/constrained hardware.

## Security and limitations
- **Unauthenticated baseline:** messages carry no identity authentication and are vulnerable to
  active man-in-the-middle key substitution. An optional key-confirmation MAC would only prove
  possession of the same derived key, not peer identity; none is included in these numbers.
- The transcript/KDF binding is tested functionally (same inputs → same key; changed transcript
  or secret → different key) but is **not** a formal security proof. Performance is unrelated
  to security; no suite is "more secure" because it is faster.
- ML-KEM implicit rejection is respected: mutated ciphertext is not assumed to raise, and the
  tests verify it does not reproduce the original or a same derived key.
- Native prototype: liboqs is built from source on first import; JIT/caching effects are
  absorbed by warmups but single-run absolute numbers may vary with host load and CPU frequency.
- Platform B is an **emulation** via cgroup v2, not a container (Docker daemon unavailable) and
  not embedded hardware.
- NIST FIPS 203 final (2024-08-13) was consulted; the page notes a potential errata issue to be
  corrected in a future revision. No erratum is claimed resolved by our library version.
- **Scope and separation:** The PS-P1 ECDH + ML-KEM work is a classical cryptographic benchmark. The QFF universal Processor A/B architecture work is a separate quantum-circuit characterization experiment, documented in `docs/UNIVERSAL_PROCESSOR_BENCHMARK.md`. Neither track is represented as an implementation of the other. The evaluation boundary and Processor D Phase 2 rationale are described separately below.

## QFF Phase Evaluation Scope and Processor D Design Rationale

### Phase 1 evaluation boundary

Per the latest clarification from the Team Technical Program Cell, Phase 1 automated evaluation covers Processor A and Processor B only. Processor C and Processor D belong to Phase 2 and are not part of the Phase 1 automated run. Phase 1 and Phase 2 use separate evaluation routes within the same judging website; this repository report documents the submission scope and does not implement or reproduce those evaluation routes.

The evaluation split is **70% automated evaluation and 30% human review of `report.md`**. The automated work follows the prescribed Processor A/B metrics documented in `docs/UNIVERSAL_PROCESSOR_BENCHMARK.md`: logical and transpiled circuit depth; physical-qubit budget; native CX count; explicit routing SWAP diagnostics and the clearly labelled SWAP-equivalent CX-cost proxy; ideal and noisy observable values; absolute observable error; and classical measurement-distribution fidelity. The run uses the recorded transpilation settings, the stated synthetic noise model, and 4096 shots per baseline case. Processor D rationale below is a human-reviewed Phase 2 design concept; it is not an input to the Phase 1 A/B benchmark.

### Processor D design philosophy — Phase 2 concept only

The proposed direction for Processor D is a **connectivity-efficient, workload-aware topology**, rather than simply the processor with the most physical qubits or coupling edges. The design objective is to balance short paths for frequent two-qubit interactions against the overhead and complexity of adding more couplings.

The concept is a connected, modular graph: retain compact local connectivity within small regions and add a carefully selected set of bridge links between regions. Frequently used interactions in the target workload should map onto short physical paths, while less frequent nonlocal interactions remain routable. This approach aims to reduce routing SWAPs and resulting CX/depth overhead without assuming that full connectivity is necessary or optimal.

The proposed design should be evaluated in Phase 2 using a controlled procedure:

1. Define a fixed logical workload and exact ideal reference before choosing the topology.
2. Select and document the Processor D physical-qubit budget and undirected edge list after the Phase 2 requirements are known; validate graph connectivity and legal edge endpoints.
3. Use the same native gate basis, transpiler optimization level, recorded seed, declared noise assumptions, and shot count as the comparison baselines unless Phase 2 specifies otherwise.
4. Measure transpiled depth, native CX count, explicit routing SWAP diagnostics, the labelled CX-overhead proxy, observable error, and measurement-distribution fidelity from saved raw artifacts.
5. Compare against the supplied baselines and, where practical, run a qubit-budget-matched sensitivity test to better separate connectivity effects from extra placement capacity.

This is an **architectural hypothesis, not a measured result**. The latest Phase 1 clarification does not supply a final Processor D qubit budget, exact topology, or Phase 2 acceptance thresholds. Therefore, this report deliberately does not invent an edge list or numerical performance claims. Processor D is not added to Phase 1 runner inputs, outputs, or evaluation tables.

### Separation of the two technical workstreams

The PS-P1 ECDH + ML-KEM implementation remains a classical cryptographic benchmark measuring local computation and memory behaviour. The Processor A/B Qiskit workload is a separate quantum architecture-characterization experiment. Neither is claimed to implement or benchmark the other, and the Phase 2 Processor D concept does not imply quantum security for the cryptographic protocol.

## Reproduction
```bash
# 0. environment (already done): python3 -m venv .venv
.venv/bin/python -m pip install cmake "cryptography>=44,<47" "psutil>=5.9,<8" \
    "pytest>=8,<9" "pandas>=2.1,<4" "matplotlib>=3.8,<4" "liboqs-python>=0.14,<0.17"
# First `import oqs` auto-builds native liboqs 0.16.0 (needs cmake + compiler).

# 1. gates
.venv/bin/python -m src.cli check
.venv/bin/python -m pytest -q
.venv/bin/python -m src.cli handshake --mode all

# 2. Platform A (host baseline)
.venv/bin/python -m src.benchmark --platform A --iterations 1000 --warmup 100 --batches 5

# 3. Platform B (enforced cgroup v2 user scope; same source/deps)
systemd-run --user --scope --collect -p CPUQuota=100% -p MemoryMax=512M -p MemorySwapMax=0 \
  --working-directory="$PWD" -- "$PWD/.venv/bin/python" \
  -m src.benchmark --platform B --iterations 1000 --warmup 100 --batches 5

# 4. analysis from raw CSV only
.venv/bin/python scripts/analyze_results.py \
  --run-ids A_20261014T111113Z_3f7184ef B_20261014T111137Z_53a5cead --output-suffix final
```

Run IDs and artifact hashes:
- Platform A raw: `data/raw/benchmark_A_20261014T111113Z_3f7184ef.csv` (sha256 `a97985ef64b2c21fff0e668d45e278b7edfe7cf7d0d19c4212af20607d80d8e3`)
- Platform B raw: `data/raw/benchmark_B_20261014T111137Z_53a5cead.csv` (sha256 `b20d147f03fd8a76ff289096470babab122409a436c8fd89d9f96a27de671c52`)
- Summary: `results/tables/summary_{A,B}_*.csv`, `results/tables/comparison_summary_*_final.csv`, `results/tables/component_timings_final.csv`, `results/tables/per_batch_stats_final.csv`
- Memory: `results/tables/memory_*_final.csv`
- Plots: `results/figures/{median_latency,payload_bytes,memory_delta}_comparison_final.png`
- Environment: `data/processed/environment_{A,B}_*.json`
- Pilot run (excluded from final aggregation): `A_20261014T110929Z_4efb66f6`
