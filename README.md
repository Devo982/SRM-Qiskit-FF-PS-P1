# PS-P1 — Quantum-Safe Hybrid Key Exchange

A reproducible Python prototype that combines **ephemeral ECDH on NIST P-256** with the
**standardized ML-KEM-768** key-encapsulation mechanism (NIST FIPS 203) and derives a
32-byte session key with **HKDF-SHA-256**. It ships a correctness test suite, three
benchmark suites (ECDH-only, ML-KEM-only, hybrid), a latency/memory benchmark runner, and
analysis scripts that turn raw CSV measurements into comparison tables and plots.

This document is the end-to-end guide: the design philosophy, the inputs, every command,
and every output location.

> **Security boundary.** This is a research / benchmark prototype, **not** a production
> secure channel. The baseline messages are **unauthenticated** and vulnerable to an active
> man-in-the-middle. It does not claim formal security, identity authentication, or
> real-hardware constrained-device performance. Do not use it to protect real secrets.

**Related documents:** [`report.md`](report.md) (final write-up), [`environment.md`](environment.md)
(pinned environment manifest), [`results/FINAL_ACCEPTANCE.md`](results/FINAL_ACCEPTANCE.md)
(gate verdict), [`results/verification_log.md`](results/verification_log.md) (timestamped
evidence), [`docs/`](docs/) (protocol spec, implementation plan, benchmark protocol).

**Separate experiment:** [Universal Processor A/B Architecture Benchmark](docs/UNIVERSAL_PROCESSOR_BENCHMARK.md) documents the independent Qiskit topology, routing, and noisy-simulation study.

---

## 1. Philosophy of the code

The codebase is built around a small number of non-negotiable rules. They are the reason the
structure looks the way it does.

1. **Real standardized cryptography only.** ML-KEM is the FIPS 203 `ML-KEM-768` from native
   `liboqs` via `liboqs-python`. Legacy `Kyber768` is never substituted, and no cryptographic
   operation is mocked in acceptance tests. If the native dependency is missing, the run
   **fails loudly** instead of degrading silently.
2. **Evidence over claims.** Every stage records a timestamp, the exact command, the exit
   code, and the observed result. A skipped ML-KEM test is treated as a blocked gate, not a
   pass. No elapsed time, memory figure, or platform limit is ever invented.
3. **Reproducibility by construction.** Dependencies are pinned in `requirements.txt`; every
   benchmark run gets a unique `run_id`; the full environment is written next to the results;
   raw samples are retained so tables can be regenerated without re-running the benchmark.
4. **Honest platform verification.** Platform B counts only when its CPU quota and memory cap
   are **observably detected from the process's own cgroup**. An unverified run is marked as
   such and excluded from comparisons — a label alone is not a platform.
5. **Cold start is separated from steady state.** Warmups are discarded, and measured
   handshakes are reported separately from the one-off native-library build/setup cost.
6. **Secret hygiene.** Raw samples, summaries, manifests, and logs contain only metadata,
   payload sizes, timings, memory figures, and booleans — **never** private keys or shared
   session secrets.
7. **Small, single-purpose modules.** Each `src/` module owns exactly one concern, so a
   reviewer can audit the crypto, the transcript, the KDF, the benchmark, and the platform
   detection independently.

---

## 2. What the application does

| Capability | Details |
|---|---|
| ECDH P-256 | Fresh ephemeral keypair per handshake; 65-byte uncompressed X9.62 points; 32-byte raw secret; malformed-point rejection (`src/ecdh.py`) |
| ML-KEM-768 | Native `liboqs` (FIPS 203, not Kyber, not a mock); keypair / encapsulate / decapsulate; sizes 1184 / 2400 / 1088 / 32 bytes; respects implicit rejection (`src/mlkem.py`) |
| Hybrid KDF | `HKDF-SHA-256`, 32-byte output, `salt = SHA-256(transcript)`, per-suite domain-separated `info`; hybrid requires **both** secrets (`src/hybrid.py`) |
| Transcript binding | Canonical length-prefixed encoding of protocol id/version, suite, both P-256 points, the ML-KEM public key, and the ciphertext (`src/transcript.py`) |
| Three suites | `ecdh`, `mlkem`, `hybrid` full local handshakes with per-component timers (`src/handshake.py`) |
| Benchmarking | One CSV row per measured handshake; median / p95 / p99 / mean / stddev / IQR / throughput; warmups separated; all failures retained (`src/benchmark.py`) |
| Memory probing | Baseline / sampled-peak / delta RSS measured in a **separate subprocess** so RSS polling does not perturb latency (`src/benchmark.py`) |
| Platform verification | Reads the process's own cgroup v2/v1 limits to verify Platform B constraints are actually enforced (`src/platforms.py`) |
| Analysis | Generates comparison tables, per-batch stats, component timings, and PNG plots from raw CSV only (`scripts/analyze_results.py`) |
| Correctness suite | Unit + integration + schema tests; ML-KEM tests run against the native library and never skip in acceptance (`tests/`) |

**The application does not do:** TLS / KEMTLS / QKD, certificates or peer authentication,
network transport or RTT measurement, Qiskit / quantum-circuit metrics, energy/ARM/cache
claims, or formal security proofs.

---

## 3. Protocol at a glance

**Message 1 — Responder → Initiator (1249 bytes):** responder's ephemeral P-256 public point
(65 B) + responder's fresh ML-KEM-768 public key (1184 B).

**Message 2 — Initiator → Responder (1153 bytes):** initiator's ephemeral P-256 public point
(65 B) + ML-KEM-768 ciphertext encapsulated to the responder key (1088 B).

| Suite | Responder → Initiator | Initiator → Responder | Total raw payload |
|---|---:|---:|---:|
| ECDH-only | 65 | 65 | **130 B** |
| ML-KEM-only | 1184 | 1088 | **2272 B** |
| Hybrid | 1249 | 1153 | **2402 B** |

The ML-KEM ciphertext is reported separately: **1088 B**.

**Transcript** (deterministic length-prefix `u16(name_len) || name || u32(value_len) || value`)
binds, in order: `protocol_id`, `protocol_version`, `suite`, `responder_ecdh_public`,
`responder_mlkem_public`, `initiator_ecdh_public`, `mlkem_ciphertext`.

**Key derivation:**
`session_key = HKDF-SHA-256(ikm, salt=SHA-256(transcript), info="PS-P1/session-key/<suite>/v1", len=32)`,
where `ikm` is a length-prefixed, labelled concatenation of the participating secrets
(`ecdh_p256`, and/or `mlkem_768`). No XOR combiner; no single component's secret is used
alone in hybrid mode. Fresh keys are generated for every handshake.

---

## 4. Requirements and installation

- Python 3.11–3.14 (developed and validated on **3.14.7**)
- A C compiler, `make`, and CMake (for the native `liboqs` build)
- Network access on first install

```bash
python3 -m venv .venv
source .venv/bin/activate              # Windows: .venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
# The first `import oqs` auto-builds native liboqs (0.16.0) into ~/_oqs.
python -m src.cli check                # must report ML-KEM-768 enabled
```

`requirements.txt`:

```
cryptography>=44,<47
liboqs-python>=0.14,<0.17
psutil>=5.9,<8
pytest>=8,<9
pandas>=2.1,<4
matplotlib>=3.8,<4
cmake>=3.15,<5
```

If native OQS cannot be built, the preflight fails explicitly — the project will **not**
silently substitute legacy `Kyber768` or a mock.

---

## 5. Inputs

The application needs no configuration file to run. Its inputs are:

| Input | Where | Notes |
|---|---|---|
| CLI arguments | command line | Select the action, suite(s), platform, and benchmark sizes (see §7). |
| Platform parameters | `platforms/platform_A.json`, `platforms/platform_B.json` | Audit-facing descriptions of the A/B definitions and the required Platform B limits (1.0 core, 512 MiB). |
| Enforced cgroup limits | runtime (Docker / `systemd-run` / cgroup) | Platform B input: the constraint is real only if the process's own `cpu.max` / `memory.max` are set. |
| Python dependencies | `requirements.txt` | Pinned ranges; `cmake` is included so the native build can run. |
| Cryptographic parameters | fixed in `src/` | curve `secp256r1` (P-256); KEM `ML-KEM-768`; KDF `HKDF-SHA-256`, 32-byte key; `info = PS-P1/session-key/<suite>/v1`; transcript field order as in §3. |
| Benchmark plan | CLI | `batches × iterations` measured handshakes per suite, plus `warmup` and the memory-probe parameters. |

There are no secret inputs to supply and no persistent state: every handshake generates fresh
keys internally.

---

## 6. Exact acceptance commands and outcomes

These are the commands run for final acceptance on the validated host, and the observed
outcomes. Exit code `0` and the stated result are both required.

| # | Command | Exit | Observed outcome |
|---|---|:--:|---|
| 1 | `python -m src.cli check` | `0` | `PASS` — P-256 agreement verified; **ML-KEM-768 enabled** (FIPS 203) |
| 2 | `python -m pytest -q` | `0` | **20 passed, 0 skipped** |
| 3 | `python -m src.cli handshake --mode all` | `0` | `PASS` — payloads `130 / 2272 / 2402` bytes |
| 4 | `python -m src.benchmark --platform A --iterations 1000 --warmup 100 --batches 5` | `0` | **15000 / 15000** successful handshakes; `platform_verified=true` |
| 5 | Platform B, same workload inside enforced limits (see §9) | `0` | **15000 / 15000** successful handshakes; `platform_verified=true` |

The Platform B command used on the validated host (Docker was unavailable, so a delegated
cgroup v2 user scope enforced the limits):

```bash
systemd-run --user --scope --collect \
  -p CPUQuota=100% -p MemoryMax=512M -p MemorySwapMax=0 \
  --working-directory="$PWD" -- "$PWD/.venv/bin/python" \
  -m src.benchmark --platform B --iterations 1000 --warmup 100 --batches 5
```

Gate logs for the correctness commands are written to `results/logs/acceptance_*.log`.

---

## 7. Command reference — all possible executions

Every execution path is listed here. Run all commands from the repository root with the
virtual environment active.

### 7.1 Correctness and preflight

```bash
python -m src.cli check                     # preflight: P-256 + standardized ML-KEM-768
python -m src.cli handshake --mode ecdh      # one ECDH-only handshake
python -m src.cli handshake --mode mlkem     # one ML-KEM-only handshake
python -m src.cli handshake --mode hybrid    # one hybrid handshake
python -m src.cli handshake --mode all       # all three suites (default)
```

### 7.2 Test suite

```bash
python -m pytest -q                          # all tests (20; 0 skips when native ML-KEM is present)
python -m pytest -q tests/test_ecdh.py
python -m pytest -q tests/test_mlkem.py
python -m pytest -q tests/test_hybrid_kdf.py
python -m pytest -q tests/test_handshake.py
python -m pytest -q tests/test_metrics.py
python -m pytest -q tests/test_benchmark_schema.py
```

### 7.3 Benchmarks

```bash
# Pilot (debug only — not for final statistics)
python -m src.benchmark --platform A --iterations 20 --warmup 5 --batches 1 --memory-reps 10

# Final workloads
python -m src.benchmark --platform A --iterations 1000 --warmup 100 --batches 5
python -m src.benchmark --platform B --iterations 1000 --warmup 100 --batches 5   # inside enforced limits
```

`src.benchmark` options:

| Option | Default | Meaning |
|---|---|---|
| `--platform {A,B}` | required | Run identifier and verification policy. |
| `--iterations N` | `1000` | Measured handshakes per suite per batch. |
| `--warmup N` | `100` | Discarded handshakes per batch before measuring. |
| `--batches N` | `5` | Number of repeated measurement batches. |
| `--memory-reps N` | `100` | RSS samples in the separate memory probe. |
| `--memory-interval S` | `0.002` | Seconds between RSS samples. |
| `--allow-unverified-platform` | off | Pilot only — allows an unenforced Platform B run and marks its data unverified. |

### 7.4 Analysis (raw CSV → tables + plots)

```bash
# Aggregate every raw run
python scripts/analyze_results.py

# Restrict to specific runs and tag the output set
python scripts/analyze_results.py \
  --run-ids A_20261014T111113Z_3f7184ef B_20261014T111137Z_53a5cead --output-suffix final
```

`scripts/analyze_results.py` options:

| Option | Default | Meaning |
|---|---|---|
| `--run-ids ID [ID ...]` | all runs | Only aggregate files whose name contains one of these run IDs (keeps pilots out of the final comparison). |
| `--output-suffix SUFFIX` | `""` | Appended to output filenames, e.g. `comparison_summary_verified_final.csv`. |

### 7.5 Gate / helper scripts, Make targets, Docker, notebook

```bash
bash scripts/quality_gate.sh          # preflight + pytest + handshake smoke, logged to results/logs/
python scripts/verify_checksums.py    # verify the original kit files (will mismatch edited sources)

make preflight                         # python -m src.cli check
make test                              # python -m pytest -q
make handshake                         # python -m src.cli handshake --mode all
make pilot                             # short A benchmark
make benchmark-a                       # full Platform A run
make benchmark-b                       # full Platform B run (run inside enforced limits)

# Docker path (one image, both platforms)
docker build -t ps-p1 .
docker run --rm -v "$PWD:/app" -w /app ps-p1 python -m src.benchmark --platform A --iterations 1000 --warmup 100 --batches 5
docker run --rm --cpus=1 --memory=512m -v "$PWD:/app" -w /app ps-p1 python -m src.benchmark --platform B --iterations 1000 --warmup 100 --batches 5

# Reproducible notebook control surface
jupyter nbconvert --to notebook --execute --inplace main.ipynb
```

---

## 8. Outputs and where they live

All results are written under the repository root. `run_id` has the form
`<platform>_<UTC timestamp>_<8 hex>` (e.g. `A_20261014T111113Z_3f7184ef`), so files from
different runs never collide. `suffix` is `_<output-suffix>` from the analysis command, or
empty.

| Output | Path | Produced by | Contents |
|---|---|---|---|
| Raw samples | `data/raw/benchmark_<run_id>.csv` | benchmark | One row per measured handshake (timings, sizes, success/key-match booleans, per-component `*_ns` timers). |
| Environment manifest | `data/processed/environment_<run_id>.json` | benchmark | CPU/OS/Python/library versions and detected cgroup limits for that run. |
| Per-suite summary | `results/tables/summary_<run_id>.csv` | benchmark | Median / p95 / p99 / mean / stddev / throughput per suite. |
| Memory summary | `results/tables/memory_<run_id>.csv` | benchmark | Baseline / sampled-peak / delta RSS per suite. |
| Acceptance manifest | `results/tables/run_manifest_<run_id>.json` | benchmark | Status, `platform_verified`, paths, summaries, caveats for the run. |
| Comparison (all runs) | `results/tables/comparison_summary_all_runs<suffix>.csv` | analysis | Cross-run summary incl. unverified rows. |
| Comparison (verified) | `results/tables/comparison_summary_verified<suffix>.csv` | analysis | Primary comparison — unverified Platform B runs excluded. |
| Per-batch stats | `results/tables/per_batch_stats<suffix>.csv` | analysis | Per-batch medians and p95. |
| Component timings | `results/tables/component_timings<suffix>.csv` | analysis | Per-component medians (µs). |
| Memory comparison | `results/tables/memory_comparison_all_runs<suffix>.csv` | analysis | Cross-run memory-probe comparison. |
| Latency plot | `results/figures/median_latency_comparison<suffix>.png` | analysis | Median latency by suite and platform. |
| Payload plot | `results/figures/payload_bytes_comparison<suffix>.png` | analysis | Raw payload bytes by suite and platform. |
| Memory plot | `results/figures/memory_delta_comparison<suffix>.png` | analysis | Sampled-peak RSS increase by suite. |
| Gate logs | `results/logs/acceptance_*.log`, `results/logs/<phase>_*` | gates / scripts | Captured stdout/stderr + exit codes. |
| Phase evidence | `results/verification_log.md` | manual/scripted | Timestamped command → exit code → observed result per phase. |
| Gate verdict | `results/FINAL_ACCEPTANCE.md` | manual | Gate table and final verdict. |
| Report / manifest | `report.md`, `environment.md` | manual | Final write-up and pinned environment. |

Key raw-CSV columns: `run_id, timestamp_utc, platform_id, platform_verified, suite, batch,
sample_index, success, key_match, handshake_wall_ns, measurement_elapsed_ns, error_type,
environment_json`, plus per-component `*_ns` timers, `total_payload_bytes`,
`mlkem_ciphertext_bytes`, and directional byte counts. Quantiles use linear interpolation at
`(n-1)*q` (inclusive); no outliers are deleted.

---

## 9. Platform A / Platform B methodology

- **Platform A** — host baseline, no benchmark-imposed CPU/memory cap. Actual CPU, OS,
  Python, and library versions are recorded in the environment JSON.
- **Platform B** — the same source tree, same virtualenv, and same dependency versions, run
  under an **enforced 1-CPU / 512 MiB** limit. The limits count only when the CPU quota and
  memory cap are **observably detected from the process's own cgroup**; otherwise the run is
  marked `platform_verified=false` and excluded from comparisons.

Reference commands (Docker, when available):

```bash
docker build -t ps-p1 .
docker run --rm --cpus=1 --memory=512m -v "$PWD:/app" -w /app ps-p1 \
  python -m src.benchmark --platform B --iterations 1000 --warmup 100 --batches 5
```

Alternative used on the validated host (Docker daemon unavailable):

```bash
systemd-run --user --scope --collect -p CPUQuota=100% -p MemoryMax=512M -p MemorySwapMax=0 \
  --working-directory="$PWD" -- "$PWD/.venv/bin/python" \
  -m src.benchmark --platform B --iterations 1000 --warmup 100 --batches 5
```

A CPU/memory-limited container or cgroup **emulates** resource constraints. It is not ARM
hardware, an IoT OS, an energy measurement, or a real microcontroller.

---

## 10. Reproducibility

1. Create the virtual environment and install `requirements.txt` (§4).
2. Run the correctness gates in §7.1–7.2 (`check`, `pytest`, `handshake --mode all`).
3. Run Platform A and Platform B with the exact commands in §7.3 (Platform B inside enforced limits).
4. Regenerate all tables and plots:
   `python scripts/analyze_results.py --run-ids <A_run> <B_run> --output-suffix final`.
5. Confirm the raw artifact hashes if comparing against the recorded run:
   - `data/raw/benchmark_A_20261014T111113Z_3f7184ef.csv`
     sha256 `a97985ef64b2c21fff0e668d45e278b7edfe7cf7d0d19c4212af20607d80d8e3`
   - `data/raw/benchmark_B_20261014T111137Z_53a5cead.csv`
     sha256 `b20d147f03fd8a76ff289096470babab122409a436c8fd89d9f96a27de671c52`

The revision marker for the recorded runs (combined SHA-256 over `src/`, `tests/`, `scripts/`)
is `0ee224649e75130a8fb2a33d097747970e046e5bd7880ed16aaa8bc226539f88`. The pilot run
`A_20261014T110929Z_4efb66f6` is retained but excluded from the final aggregation via
`--run-ids` filtering.

---

## 11. Cryptographic sizes reference

| Item | Bytes |
|---|---:|
| P-256 uncompressed public point | 65 |
| P-256 ECDH secret | 32 |
| ML-KEM-768 public key | 1,184 |
| ML-KEM-768 secret key | 2,400 |
| ML-KEM-768 ciphertext | 1,088 |
| ML-KEM shared secret | 32 |
| Derived session key | 32 |

Raw payloads (before framing, certificates, or key-confirmation MACs): ECDH-only 130 B;
ML-KEM-only 2,272 B; hybrid 2,402 B. The total hybrid payload is not the same thing as the
ML-KEM ciphertext size.

---

## 12. Limitations

- **Unauthenticated** baseline: man-in-the-middle vulnerable; no identity authentication or key confirmation.
- Platform B is **CPU/memory-limited x86 emulation**, not embedded ARM hardware; no energy or cache claims.
- Timings are **local CPU compute only**; no socket/network RTT or TLS framing overhead.
- Built on native `liboqs` and `cryptography`; first-import build and host load/frequency cause run-to-run variation. Tail differences are consistent with 1-core quota contention but not proven causal.
- NIST FIPS 203 final (2024-08-13) was consulted; the page notes a potential errata to be corrected in a future revision. No erratum is claimed resolved by the installed library.
- QFF "quantum Processor A/B" versus PS-P1 "CPU Platform A/B" scope mismatch: this project implements the PS-P1 CPU interpretation only and does not fabricate quantum metrics.

---

## 13. Background and references

- NIST FIPS 203, *Module-Lattice-Based Key-Encapsulation Mechanism Standard* — https://csrc.nist.gov/pubs/fips/203/final
- Open Quantum Safe `liboqs-python` — https://github.com/open-quantum-safe/liboqs-python
- pyca `cryptography` EC/ECDH — https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ec/
- Battarbee et al., *Quantum-Safe Hybrid Key Exchanges with KEM-Based Authentication* (arXiv:2411.04030) — background only; this prototype does not implement that broader authenticated/QKD design.

Supplied challenge and reference materials remain unmodified under `reference_materials/`.
The mock-free, evidence-driven prototype is implemented under `src/` and `tests/`.
