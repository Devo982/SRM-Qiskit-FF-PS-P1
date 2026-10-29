# PS-P1 — Quantum-Safe Hybrid Key Exchange (Implementation)

A reproducible Python prototype that combines **ephemeral NIST P-256 ECDH** with the
**standardized ML-KEM-768** key-encapsulation mechanism (NIST FIPS 203) and derives a
32-byte session key with **HKDF-SHA-256**. It ships correctness tests, three benchmark
suites (ECDH-only, ML-KEM-only, hybrid), a benchmark runner, a memory probe, and
scripts that turn raw CSV measurements into tables and plots.

> This file documents the *implemented project and its results*. The original challenge
> starter guide is preserved in [`README.md`](README.md). The formal write-up is in
> [`report.md`](report.md), the environment manifest in [`environment.md`](environment.md),
> and the audit in [`results/FINAL_ACCEPTANCE.md`](results/FINAL_ACCEPTANCE.md).

> **Security boundary:** this is a research/benchmark prototype, **not** a production
> secure channel. The baseline messages are **unauthenticated** and vulnerable to an
> active man-in-the-middle. Do not use it to protect real secrets. Key confirmation
> (not implemented) would only prove possession of the same key, not peer identity.

---

## 1. What this is capable of

| Capability | Details |
|---|---|
| ECDH P-256 | Fresh ephemeral keypair per handshake; 65-byte uncompressed X9.62 points; 32-byte raw secret; malformed-point rejection (`src/ecdh.py`) |
| ML-KEM-768 | Real native `liboqs` (not Kyber, not a mock); keypair / encapsulate / decapsulate; sizes 1184 / 2400 / 1088 / 32 bytes; respects implicit rejection (`src/mlkem.py`) |
| Hybrid KDF | `HKDF-SHA-256`, 32-byte output, `salt = SHA-256(transcript)`, domain-separated `info` per suite; hybrid requires **both** secrets (`src/hybrid.py`) |
| Transcript binding | Canonical length-prefixed encoding of protocol id/version, suite, both P-256 points, ML-KEM public key, and ciphertext (`src/transcript.py`) |
| Three suites | `ecdh`, `mlkem`, `hybrid` full local handshakes with per-component timers (`src/handshake.py`) |
| Benchmarking | One CSV row per measured handshake; median/p95/p99/mean/stddev/IQR/throughput; warmups separated; all failures retained (`src/benchmark.py`) |
| Memory probing | Baseline/sampled-peak/delta RSS measured in a **separate subprocess** so RSS polling does not perturb latency (`src/benchmark.py`) |
| Platform verification | Reads the process's own cgroup v2/v1 limits to verify Platform B constraints are actually enforced (`src/platforms.py`) |
| Analysis | Script generates comparison tables, per-batch stats, component timings, and PNG plots from raw CSV only (`scripts/analyze_results.py`) |
| Correctness suite | Unit + integration + schema tests; ML-KEM tests run against the native library and are never allowed to skip in acceptance (`tests/`) |

### What it explicitly does **not** do
- No TLS, KEMTLS, Muckle#, QKD, certificates, or peer/signature authentication.
- No network transport, sockets, or real RTT measurement (compute-only timing).
- No Qiskit / quantum-circuit metrics (the PS-P1 statement is classical CPU benchmarking).
- No energy, ARM, cache, or real embedded-hardware claims (Platform B is emulation).
- No formal security claim or proof.

---

## 2. Protocol summary

**Message 1 — Responder → Initiator (1249 bytes):** responder's ephemeral P-256 public
point (65 B) + responder's fresh ML-KEM-768 public key (1184 B).

**Message 2 — Initiator → Responder (1153 bytes):** initiator's ephemeral P-256 public
point (65 B) + ML-KEM-768 ciphertext encapsulated to the responder key (1088 B).

Both endpoints derive the same key. Expected **raw unframed payloads**:

| Suite | Responder → Initiator | Initiator → Responder | Total |
|---|---:|---:|---:|
| ECDH-only | 65 | 65 | **130 B** |
| ML-KEM-only | 1184 | 1088 | **2272 B** |
| Hybrid | 1249 | 1153 | **2402 B** |

ML-KEM ciphertext size is reported separately: **1088 B**.

**Transcript** (deterministic length-prefix: `u16(name_len) || name || u32(value_len) || value`)
binds, in order: `protocol_id`, `protocol_version`, `suite`, `responder_ecdh_public`,
`responder_mlkem_public`, `initiator_ecdh_public`, `mlkem_ciphertext`.

**Key derivation:**
`session_key = HKDF-SHA-256(ikm, salt=SHA-256(transcript), info="PS-P1/session-key/<suite>/v1", len=32)`
where `ikm` is a length-prefixed, labelled concatenation of the participating secrets
(`ecdh_p256`, and/or `mlkem_768`). No XOR combiner; no single component's secret is used
alone in hybrid mode. Fresh keys are generated every handshake.

---

## 3. Requirements and installation

- Python 3.11–3.14 (developed and validated on **3.14.7**)
- A C compiler, `make`, and CMake (for the native `liboqs` build)
- Network access on first install

```bash
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
# First `import oqs` auto-builds native liboqs (0.16.0) into ~/_oqs.
python -m src.cli check            # must print ML-KEM-768 enabled
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

## 4. Quickstart / command reference

```bash
# Environment + standardized ML-KEM availability (exit 0 required)
python -m src.cli check

# One local handshake per suite (or --mode ecdh|mlkem|hybrid)
python -m src.cli handshake --mode all

# Automated tests (ML-KEM tests execute against native liboqs; 0 skips)
python -m pytest -q

# Short pilot (debug only; not for final statistics)
python -m src.benchmark --platform A --iterations 20 --warmup 5 --batches 1 --memory-reps 10

# Final workloads
python -m src.benchmark --platform A --iterations 1000 --warmup 100 --batches 5
python -m src.benchmark --platform B --iterations 1000 --warmup 100 --batches 5  # inside enforced limits

# Turn raw CSV into tables + plots (select the final runs)
python scripts/analyze_results.py \
  --run-ids A_20261014T111113Z_3f7184ef B_20261014T111137Z_53a5cead --output-suffix final

# Optional helpers
bash scripts/quality_gate.sh          # preflight + pytest + handshake smoke
python scripts/verify_checksums.py    # verify the original kit files (will mismatch edited sources)
```

`src.benchmark` options: `--platform {A,B}` (required), `--iterations` (default 1000),
`--warmup` (100), `--batches` (5), `--memory-reps` (100), `--memory-interval` (0.002 s),
`--allow-unverified-platform` (pilot only; marks data unverified).

---

## 5. Module map

| File | Responsibility |
|---|---|
| `src/ecdh.py` | P-256 keygen, serialization, parsing/validation, exchange |
| `src/mlkem.py` | `require_oqs()`, ML-KEM-768 keypair/encap/decap, size constants, preflight details |
| `src/transcript.py` | Canonical length-prefixed transcript builder |
| `src/hybrid.py` | HKDF-SHA-256 session-key derivation and IKM encoding |
| `src/handshake.py` | Full local handshakes for the three suites with component timers |
| `src/benchmark.py` | Warmups, batches, raw CSV writer, summaries, separate memory probe, CLI |
| `src/platforms.py` | Environment metadata + own-cgroup CPU/memory limit detection/verification |
| `src/cli.py` | `check` and `handshake` subcommands |
| `scripts/analyze_results.py` | Raw CSV → comparison/component/per-batch tables + plots |
| `tests/` | ECDH, ML-KEM, hybrid KDF/transcript, handshake, metrics, benchmark-schema tests |

---

## 6. Platform A / Platform B methodology

- **Platform A** — host baseline, no benchmark-imposed CPU/memory cap. Actual CPU, OS,
  Python, and library versions are recorded in the environment JSON.
- **Platform B** — same source tree, same virtualenv, and same dependency versions, run
  under an **enforced 1-CPU / 512 MiB** limit. Constraints count only when the CPU quota
  and memory cap are **observably detected** from the process's own cgroup; otherwise the
  run is marked `platform_verified=false` and excluded from comparisons.

Reference commands (Docker, when available):

```bash
docker build -t ps-p1 .
docker run --rm -v "$PWD:/app" -w /app ps-p1 \
  python -m src.benchmark --platform A --iterations 1000 --warmup 100 --batches 5
docker run --rm --cpus=1 --memory=512m -v "$PWD:/app" -w /app ps-p1 \
  python -m src.benchmark --platform B --iterations 1000 --warmup 100 --batches 5
```

Alternative when Docker is unavailable (used for the results below):

```bash
systemd-run --user --scope --collect -p CPUQuota=100% -p MemoryMax=512M -p MemorySwapMax=0 \
  --working-directory="$PWD" -- "$PWD/.venv/bin/python" \
  -m src.benchmark --platform B --iterations 1000 --warmup 100 --batches 5
```

**A CPU/memory-limited container or cgroup is an emulation of resource constraints.** It is
not ARM hardware, an IoT OS, an energy measurement, or a real microcontroller.

---

## 7. Measured results (verified runs on this host)

Host: AMD Ryzen 7 4800H (8 physical / 16 logical), ~15.04 GiB RAM, kernel 7.2.5-3-omarchy,
Python 3.14.7, cryptography 46.0.7, liboqs 0.16.0, liboqs-python 0.16.0.1.
Revision marker (combined SHA-256 of `src/`, `tests/`, `scripts/`):
`0ee224649e75130a8fb2a33d097747970e046e5bd7880ed16aaa8bc226539f88`.

- Platform A run `A_20261014T111113Z_3f7184ef`: `platform_verified=true`, 15,000/15,000 successful.
- Platform B run `B_20261014T111137Z_53a5cead`: `platform_verified=true`, observed
  `cpu.max=100000 100000` (1.0 core) and `memory.max=536870912` (512 MiB), 15,000/15,000 successful.

**Latency** (ms; n = 5000 successful handshakes per suite; local compute, no network):

| Platform | Suite | Median | p95 | p99 | StdDev | Throughput (hs/s) |
|---|---|---:|---:|---:|---:|---:|
| A | ECDH-only | 0.3603 | 0.3859 | 0.4380 | 0.0196 | 2742.4 |
| A | ML-KEM-only | 0.1915 | 0.2567 | 0.2811 | 0.0802 | 4914.6 |
| A | Hybrid | 0.5363 | 0.5698 | 0.6430 | 0.0247 | 1854.3 |
| B | ECDH-only | 0.3650 | 0.4601 | 0.5701 | 0.0964 | 2648.8 |
| B | ML-KEM-only | 0.1893 | 0.2438 | 0.2843 | 0.0668 | 5028.0 |
| B | Hybrid | 0.5474 | 0.8147 | 1.0785 | 0.1136 | 1688.6 |

**Interpretation:** ML-KEM-only is fastest; ECDH-only is slower (P-256 scalar mult ≈118 µs
dominates); hybrid ≈ sum + overhead. Median A-vs-B differences are within ~2% (not
practically meaningful), but the 1-CPU quota raises **tail latency and jitter** for the
longer ECDH/hybrid handshakes (hybrid p99 ×1.68, stddev ×4.6), while the short ML-KEM-only
handshake is unaffected. That is the meaningful A/B effect: tail/jitter, not median throughput.

**Memory** (separate subprocess probe, 2 ms sampling; sampled peak − warmed baseline):
≈0.21–0.29 MiB per suite on both platforms.

**Payload/persistence:** payloads are constant (130 / 2272 / 2402 B; ciphertext 1088 B).
Benchmark outputs contain only metadata, sizes, timings, booleans, and memory figures —
**never** private keys or raw shared/session secrets.

---

## 8. Output layout and formats

```
data/raw/benchmark_<platform>_<UTC>_<id>.csv     one row per measured handshake
data/processed/environment_<run_id>.json         verified platform + library metadata
results/tables/summary_<run_id>.csv              per-suite statistics
results/tables/memory_<run_id>.csv               RSS memory-probe summary
results/tables/run_manifest_<run_id>.json        acceptance manifest for the run
results/tables/comparison_summary_*_final.csv    cross-run comparison (verified)
results/tables/component_timings_final.csv       per-component medians (µs)
results/tables/per_batch_stats_final.csv         per-batch medians/spread
results/tables/memory_comparison_all_runs_final.csv
results/figures/*_final.png                      latency, payload, memory plots
results/logs/                                    preflight/handshake/benchmark logs
results/verification_log.md                      timestamped per-phase evidence
results/FINAL_ACCEPTANCE.md                      gate table + verdict
report.md, environment.md                        final report + manifest
```

Key raw-CSV columns: `run_id, timestamp_utc, platform_id, platform_verified, suite, batch,
sample_index, success, key_match, handshake_wall_ns, measurement_elapsed_ns, error_type,
environment_json` plus per-component `*_ns` timers, `total_payload_bytes`,
`mlkem_ciphertext_bytes`, and directional byte counts.

Quantile convention: linear interpolation at `(n-1)*q` (inclusive). No outliers deleted.

---

## 9. Testing

```bash
python -m pytest -q          # 20 tests; 0 skipped when native ML-KEM is present
```

Coverage includes: ECDH agreement/lengths/malformed inputs; ML-KEM sizes, agreement, and
implicit rejection (mutated ciphertext must not reproduce the original or same derived key);
transcript field binding and distinct suite labels; hybrid "both secrets required"; handshake
payload arithmetic (130/2272/2402); quantile convention; and benchmark output schema
(including a guard that no secret-like column is emitted).

A skipped ML-KEM test is **not** an acceptance pass.

---

## 10. Reproducibility

1. Create the venv and install `requirements.txt` (Section 3).
2. Run the gates in Section 4 (`check`, `pytest`, `handshake --mode all`).
3. Run Platform A and Platform B with the exact commands and run IDs listed in Section 7.
4. Regenerate all tables/plots with `scripts/analyze_results.py --run-ids <A> <B> --output-suffix final`.
5. Confirm artifact hashes:
   - `data/raw/benchmark_A_20261014T111113Z_3f7184ef.csv` sha256 `a97985ef64b2c21fff0e668d45e278b7edfe7cf7d0d19c4212af20607d80d8e3`
   - `data/raw/benchmark_B_20261014T111137Z_53a5cead.csv` sha256 `b20d147f03fd8a76ff289096470babab122409a436c8fd89d9f96a27de671c52`

The pilot run `A_20261014T110929Z_4efb66f6` is retained but excluded from the final
aggregation via `--run-ids` filtering.

---

## 11. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `ModuleNotFoundError: No module named 'oqs'` | Install `requirements.txt`; ensure `cmake`, a C compiler, `make`, and network are available; re-run `import oqs` to trigger the native build |
| Preflight fails "ML-KEM-768 is not enabled" | The native build lacks ML-KEM; rebuild `liboqs` from a version ≥ 0.11 (validated: 0.16.0). Do **not** substitute `Kyber768` |
| A stray `liboqs-python faulthandler is disabled` line | Already suppressed in `src/mlkem.py`/`src/platforms.py`; if seen, oqs was imported directly elsewhere |
| Platform B reports `platform_verified=false` | The 1-CPU/512-MiB cgroup limits were not observed on the process's own cgroup; run inside Docker or a delegated cgroup v2 scope (Section 6). Unverified runs are excluded from comparisons |
| Docker daemon unavailable | Build the image on a Docker-capable host, or use the enforced `systemd-run --user --scope` route (used here) |
| `analyze_results.py` includes old runs | Pass `--run-ids <ids>` to restrict aggregation to the final runs |

---

## 12. Limitations

- **Unauthenticated** baseline: MITM-vulnerable; no identity authentication or key confirmation.
- Platform B is **CPU/memory-limited x86 emulation**, not embedded ARM hardware; no energy/cache claims.
- Timings are **local CPU compute only**; no socket/network RTT or TLS framing overhead.
- Implemented with native `liboqs` and `cryptography`; first-import build and host load/frequency
  cause run-to-run variation. Tail differences are consistent with 1-core quota contention but
  not proven causal.
- NIST FIPS 203 final (2024-08-13) was consulted; the page notes a potential errata issue to be
  corrected in a future revision. No erratum is claimed resolved by the installed library.
- QFF quantum Processor A/B versus PS-P1 CPU A/B scope mismatch: this project implements the
  PS-P1 CPU interpretation only and does not fabricate quantum metrics.

---

## 13. References and attribution

- NIST FIPS 203, *Module-Lattice-Based Key-Encapsulation Mechanism Standard*: https://csrc.nist.gov/pubs/fips/203/final
- Open Quantum Safe `liboqs-python`: https://github.com/open-quantum-safe/liboqs-python
- pyca `cryptography` EC/ECDH: https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ec/
- Background (not implemented here): Battarbee et al., *Quantum-Safe Hybrid Key Exchanges with
  KEM-Based Authentication* (arXiv:2411.04030).

Supplied challenge/reference materials remain unmodified under `reference_materials/`.
