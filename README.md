# PS-P1 — Quantum-Safe Hybrid Key Exchange

A reproducible Python prototype that combines **ephemeral ECDH on NIST P-256** with the
**standardized ML-KEM-768** key-encapsulation mechanism (NIST FIPS 203) and derives a 32-byte
session key with **HKDF-SHA-256**. It ships a correctness test suite, three benchmark suites
(ECDH-only, ML-KEM-only, hybrid), a latency/memory benchmark runner, and analysis scripts that
turn raw CSV measurements into comparison tables and plots.

The repository also contains a second, independent Qiskit experiment — the **Universal
Processor A/B Architecture Benchmark** — that compiles and simulates one fixed logical workload
on two synthetic quantum processors. The two tracks are separate: neither implements the other.

> **Security boundary.** This is a research / benchmark prototype, **not** a production
> secure channel. The baseline messages are **unauthenticated** and vulnerable to an active
> man-in-the-middle. It does not claim formal security, identity authentication, or
> real-hardware constrained-device performance. HMAC key confirmation (not implemented) would
> only prove possession of the same derived key, not peer identity. Do not use it to protect
> real secrets.

---

## Submission metadata

| Field | Value |
|---|---|
| Event | Qiskit Fall Fest 2026 — Phase 1, SRM University-AP |
| Selected problem statement | **PS-P1 — Quantum-Safe Hybrid Key Exchange** (Track 5: Post-Quantum Cryptography) |
| Repository | https://github.com/Devo982/SRM-Qiskit-FF-PS-P1 |
| Primary deliverable | PS-P1 hybrid P-256 ECDH + ML-KEM-768 key establishment with Platform A/B benchmarking |
| Secondary deliverable | Universal Processor A/B Qiskit architecture benchmark (QFF-wide framework) |
| Reference material | Supplied challenge documents, unmodified, under `reference_materials/` |

**Related documents:** [`report.md`](report.md) (formal write-up), [`environment.md`](environment.md)
(pinned environment manifest), [`results/FINAL_ACCEPTANCE.md`](results/FINAL_ACCEPTANCE.md)
(gate verdict), [`results/verification_log.md`](results/verification_log.md) (timestamped
evidence), [`docs/`](docs/) (protocol spec, implementation plan, benchmark protocol),
[`docs/UNIVERSAL_PROCESSOR_BENCHMARK.md`](docs/UNIVERSAL_PROCESSOR_BENCHMARK.md) (Processor
A/B study), [`main.ipynb`](main.ipynb) (reproducible notebook).

---

## 1. What this repository delivers

Two independent experiments live in one tree.

| Track | Question | Entry point | Primary evidence |
|---|---|---|---|
| **1. PS-P1 hybrid KEM** (selected problem statement) | What is the latency, payload size, and memory cost of ECDH P-256, ML-KEM-768, and their hybrid, under a standard CPU baseline (Platform A) versus an enforced 1-CPU / 512 MiB environment (Platform B)? | `src/` + `scripts/analyze_results.py` | `report.md`, `results/tables/*_final.csv`, `results/figures/*_final.png` |
| **2. Universal Processor A/B** (QFF-wide architecture framework) | For one fixed logical workload, how do the specified Processor A (5q) and Processor B (9q) connectivity maps affect compiled circuit cost and noisy-simulation metrics? | `scripts/run_quantum_benchmark.py` + `main.ipynb` | `docs/UNIVERSAL_PROCESSOR_BENCHMARK.md`, `results/tables/processor_A_vs_B.csv`, `results/figures/*quantum*` |

Scope separation is deliberate and documented: the PS-P1 KEM benchmark is a *classical CPU*
study; the Processor A/B study is a *quantum-circuit* architecture study. No PS-P1 number is a
quantum result and no Processor A/B number is a cryptographic result.

**This project does not implement:** TLS / KEMTLS / Muckle# / QKD, certificates, peer identity
authentication, network transport or RTT measurement, energy/ARM/cache claims, formal security
proofs, or real quantum hardware execution. The Processor A/B metrics come from Qiskit
transpilation and a synthetic noise model run in `qiskit-aer`.

---

## 2. Repository layout

```
.
├── README.md                     # this file
├── main.ipynb                    # end-to-end Processor A/B notebook
├── requirements.txt              # PS-P1 crypto-track deps (pip path)
├── pyproject.toml / uv.lock      # locked full env incl. Qiskit (uv path)
├── report.md                     # PS-P1 formal write-up
├── environment.md                # pinned PS-P1 benchmark environment
├── PROJECT_README.md             # earlier PS-P1 project README (superseded by this file)
├── PS-P1_BENCHMARK_REPORT.md     # secondary PS-P1 result record (see §6)
├── data/
│   ├── raw/                      # benchmark_<run_id>.csv, quantum_metrics.csv, ...
│   └── processed/                # environment_<run_id>.json, quantum_summary.csv, ...
├── processors/
│   ├── processor_A.json          # Processor A: 5 qubits, linear chain
│   └── processor_B.json          # Processor B: 9 qubits, 3x3 grid
├── src/
│   ├── ecdh.py mlkem.py transcript.py hybrid.py handshake.py     # PS-P1 crypto
│   ├── benchmark.py platforms.py cli.py                          # PS-P1 benchmarking
│   └── problem.py processors.py routing.py simulation.py metrics.py visualization.py  # Processor A/B
├── scripts/
│   ├── analyze_results.py                                        # PS-P1 CSV -> tables + plots
│   ├── run_quantum_benchmark.py analyze_quantum_results.py       # Processor A/B pipeline
│   ├── validate_processors.py plot_processors.py
│   └── quality_gate.sh verify_checksums.py
├── tests/                        # 64 tests (crypto + quantum)
├── results/
│   ├── tables/                   # generated CSV/JSON comparison tables
│   ├── figures/                  # generated PNG plots
│   ├── logs/                     # captured gate/benchmark logs
│   ├── verification_log.md       # timestamped per-phase evidence
│   └── FINAL_ACCEPTANCE.md       # gate table + verdict
└── reference_materials/          # supplied challenge documents (unmodified)
```

> **Artifact note.** `.gitignore` excludes `data/raw/*`, `data/processed/*`,
> `results/tables/*`, `results/figures/*`, and `results/logs/*`. A fresh clone therefore
> contains the code, configs, reports, and notebooks, but **not** the generated raw data,
> summary tables, or plots. Every artifact is reproducible from the committed code — see §6
> and §7.

---

## 3. Installation and environment

The full environment (both tracks, including Qiskit) is locked with `uv`. The PS-P1 crypto
track can also be installed with plain `pip` from `requirements.txt`.

### 3.1 Locked environment (both tracks) — recommended

```bash
uv sync --locked            # Python 3.13; installs pyproject.toml + uv.lock + dev group
```

`pyproject.toml` pins the full dependency set:

```
cryptography>=44,<47        matplotlib>=3.8,<4         qiskit>=2.5,<3
liboqs-python>=0.14,<0.17   networkx>=3,<4             qiskit-aer>=0.17,<0.18
psutil>=5.9,<8              numpy>=1.26,<3             pandas>=2.1,<4
pytest>=8,<9               cmake>=3.15,<5
```

### 3.2 PS-P1 crypto track only — pip

- Python 3.11–3.13 (the recorded PS-P1 benchmark host used **3.14.7**; the locked environment
  in this repository is **3.13**)
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

`requirements.txt` (crypto track):

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
silently substitute legacy `Kyber768` or a mock. `qiskit`, `qiskit-aer`, and `networkx` (used
only by Track 2) are **not** in `requirements.txt`; install them via `uv sync --locked` or add
them to the pip command.

---

## 4. Track 1 — PS-P1 hybrid key exchange (primary)

### 4.1 Protocol at a glance

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
(`ecdh_p256`, and/or `mlkem_768`). No XOR combiner; no single component's secret is used alone
in hybrid mode. Fresh keys are generated for every handshake.

### 4.2 Capabilities

| Capability | Details |
|---|---|
| ECDH P-256 | Fresh ephemeral keypair per handshake; 65-byte uncompressed X9.62 points; 32-byte raw secret; malformed-point rejection (`src/ecdh.py`) |
| ML-KEM-768 | Native `liboqs` (FIPS 203, not Kyber, not a mock); keypair / encapsulate / decapsulate; sizes 1184 / 2400 / 1088 / 32 bytes; respects implicit rejection (`src/mlkem.py`) |
| Hybrid KDF | `HKDF-SHA-256`, 32-byte output, `salt = SHA-256(transcript)`, per-suite domain-separated `info`; hybrid requires **both** secrets (`src/hybrid.py`) |
| Transcript binding | Canonical length-prefixed encoding of protocol id/version, suite, both P-256 points, ML-KEM public key, and ciphertext (`src/transcript.py`) |
| Three suites | `ecdh`, `mlkem`, `hybrid` full local handshakes with per-component timers (`src/handshake.py`) |
| Benchmarking | One CSV row per measured handshake; median / p95 / p99 / mean / stddev / IQR / throughput; warmups separated; all failures retained (`src/benchmark.py`) |
| Memory probing | Baseline / sampled-peak / delta RSS measured in a **separate subprocess** so RSS polling does not perturb latency (`src/benchmark.py`) |
| Platform verification | Reads the process's own cgroup v2/v1 limits to verify Platform B constraints are actually enforced (`src/platforms.py`) |
| Analysis | Generates comparison tables, per-batch stats, component timings, and PNG plots from raw CSV only (`scripts/analyze_results.py`) |

### 4.3 Commands

```bash
# Preflight: P-256 + standardized ML-KEM-768 (exit 0 required)
python -m src.cli check

# One local handshake per suite (or --mode ecdh|mlkem|hybrid)
python -m src.cli handshake --mode all

# Automated tests (ML-KEM tests execute against native liboqs; 0 skips)
python -m pytest -q

# Short pilot (debug only; not for final statistics)
python -m src.benchmark --platform A --iterations 20 --warmup 5 --batches 1 --memory-reps 10

# Final workloads
python -m src.benchmark --platform A --iterations 1000 --warmup 100 --batches 5
python -m src.benchmark --platform B --iterations 1000 --warmup 100 --batches 5   # inside enforced limits

# Rebuild tables + plots from raw CSV (select the final runs)
python scripts/analyze_results.py \
  --run-ids A_20261014T111113Z_3f7184ef B_20261014T111137Z_53a5cead --output-suffix final
```

`src.benchmark` options: `--platform {A,B}` (required), `--iterations` (default 1000),
`--warmup` (100), `--batches` (5), `--memory-reps` (100), `--memory-interval` (0.002 s),
`--allow-unverified-platform` (pilot only; marks data unverified).

Helper targets exist in the `Makefile` (`make preflight`, `make test`, `make handshake`,
`make pilot`, `make benchmark-a`, `make benchmark-b`).

### 4.4 Platform A / Platform B methodology

- **Platform A** — host baseline, no benchmark-imposed CPU/memory cap. Actual CPU, OS, Python,
  and library versions are recorded in the environment JSON.
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

Alternative used on the recorded host (Docker daemon unavailable):

```bash
systemd-run --user --scope --collect -p CPUQuota=100% -p MemoryMax=512M -p MemorySwapMax=0 \
  --working-directory="$PWD" -- "$PWD/.venv/bin/python" \
  -m src.benchmark --platform B --iterations 1000 --warmup 100 --batches 5
```

A CPU/memory-limited container or cgroup **emulates** resource constraints. It is not ARM
hardware, an IoT OS, an energy measurement, or a real microcontroller.

### 4.5 Measured results (recorded runs)

Host: AMD Ryzen 7 4800H (8 physical / 16 logical), ~15.04 GiB RAM, kernel `7.2.5-3-omarchy`,
Python 3.14.7, cryptography 46.0.7, liboqs 0.16.0, liboqs-python 0.16.0.1.

- Platform A run `A_20261014T111113Z_3f7184ef`: `platform_verified=true`, 15,000/15,000 successful.
- Platform B run `B_20261014T111137Z_53a5cead`: `platform_verified=true`, observed
  `cpu.max=100000 100000` (1.0 core) and `memory.max=536870912` (512 MiB), 15,000/15,000 successful.

**Latency** (ms; n = 5,000 successful handshakes per suite; local compute, no network):

| Platform | Suite | Median | p95 | p99 | StdDev | Throughput (hs/s) |
|---|---|---:|---:|---:|---:|---:|
| A | ECDH-only | 0.3603 | 0.3859 | 0.4380 | 0.0196 | 2742.4 |
| A | ML-KEM-only | 0.1915 | 0.2567 | 0.2811 | 0.0802 | 4914.6 |
| A | Hybrid | 0.5363 | 0.5698 | 0.6430 | 0.0247 | 1854.3 |
| B | ECDH-only | 0.3650 | 0.4601 | 0.5701 | 0.0964 | 2648.8 |
| B | ML-KEM-only | 0.1893 | 0.2438 | 0.2843 | 0.0668 | 5028.0 |
| B | Hybrid | 0.5474 | 0.8147 | 1.0785 | 0.1136 | 1688.6 |

B/A ratios: ECDH median 1.013 / p99 1.302 / stddev 4.92; ML-KEM median 0.988 / p99 1.011 /
stddev 0.83; Hybrid median 1.021 / p99 1.677 / stddev 4.60.

**Per-component medians (µs)** (`results/tables/component_timings_final.csv`):

| Platform | Suite | ML-KEM keygen | ML-KEM encap | ML-KEM decap | ECDH keygen (resp.) | ECDH exchange (init.) | HKDF (init.) |
|---|---|---:|---:|---:|---:|---:|---:|
| A | ECDH | – | – | – | 27.66 | 117.89 | 17.74 |
| A | ML-KEM | 34.78 | 34.36 | 36.46 | – | – | 18.65 |
| A | Hybrid | 35.27 | 39.74 | 37.16 | 31.50 | 120.13 | 22.98 |
| B | ECDH | – | – | – | 28.08 | 119.08 | 17.67 |
| B | ML-KEM | 34.85 | 34.36 | 36.32 | – | – | 18.16 |
| B | Hybrid | 35.69 | 41.14 | 37.23 | 33.66 | 122.01 | 24.31 |

**Sampled memory** (separate subprocess probe, 2 ms sampling; sampled peak RSS − warmed
baseline): ≈0.285 MiB (ECDH) and ≈0.211 MiB (ML-KEM, hybrid) per suite on both platforms.
Baseline RSS is higher for ML-KEM/hybrid because the native library and KEM contexts are already
loaded. This sampled delta is not a peak-allocation bound.

### 4.6 Interpretation

- **Suite ordering (both platforms):** ML-KEM-only is fastest (≈0.19 ms median), ECDH-only is
  slower (≈0.36 ms; P-256 scalar multiplication ≈118 µs per exchange dominates), and hybrid is
  the sum-plus-overhead (≈0.54 ms). This matches the component table.
- **A vs B medians are not practically different** (within ~2%, far below the run-to-run
  spread). A single-threaded crypto workload that fits in one CPU gets essentially full speed
  even under a 1-core quota.
- **A vs B tails differ.** For ECDH and hybrid, Platform B shows materially higher p95/p99 and
  4.6–4.9× the standard deviation, consistent with CPU-quota scheduling contention on a shared
  host. ML-KEM-only (short, cache-resident) is unaffected. This is the practically meaningful
  A-vs-B effect: **jitter/tail**, not median throughput.
- **Compute vs network.** All figures are local CPU execution; real network RTT and TLS handshake
  time are excluded. Payload sizes are raw message bytes, not wire/frame overhead.
- **Container emulation vs hardware.** Platform B is a cgroup-limited x86 host scope; no ARM,
  energy, cache, or embedded-hardware claim is made.

---

## 5. Track 2 — Universal Processor A/B architecture benchmark (secondary)

This is the repository's separate Qiskit experiment. It compares how one fixed five-logical-qubit
workload compiles and behaves under noisy simulation on two synthetic processor configurations.
Full detail is in [`docs/UNIVERSAL_PROCESSOR_BENCHMARK.md`](docs/UNIVERSAL_PROCESSOR_BENCHMARK.md).

| Property | Processor A | Processor B |
|---|---|---|
| Physical qubits | 5 | 9 |
| Coupling topology | Linear chain | 3 × 3 grid |
| Undirected coupling edges | (0,1),(1,2),(2,3),(3,4) | 12 edges of a 3×3 grid |
| Basis gates | `rz`, `sx`, `x`, `cx` | `rz`, `sx`, `x`, `cx` |
| 1q / CX / readout error | 0.001 / 0.005 / 0.01 | 0.001 / 0.005 / 0.01 |
| Transpiler opt level / seed | 1 / 42 | 1 / 42 |
| Shots per case | 4096 | 4096 |

The workload is the same weighted-ZZ five-qubit stress circuit for both processors
(`theta = 0.37`, `beta = 0.23`, `reps = 1, 2, 3`). Reported metrics: logical depth, transpiled
depth, native CX count, diagnostic SWAP count, a clearly-labelled SWAP-equivalent CX proxy,
noisy observable estimate, absolute observable error, and classical measurement-distribution
fidelity. Source of truth: `processors/processor_A.json`, `processors/processor_B.json`.

Recorded comparison (from `docs/UNIVERSAL_PROCESSOR_BENCHMARK.md` §5; A/B):

| Reps | Logical depth | Transpiled depth | Native CX | Diagnostic SWAP | Distribution fidelity | Abs. observable error |
|---:|---:|---:|---:|---:|---:|---:|
| 1 | 8 | 34 / 30 | 27 / 17 | 5 / 1 | 0.997488 / 0.998163 | 0.184296 / 0.130585 |
| 2 | 16 | 78 / 57 | 62 / 37 | 12 / 3 | 0.943295 / 0.966655 | 1.218163 / 0.909716 |
| 3 | 24 | 116 / 84 | 93 / 57 | 19 / 5 | 0.967119 / 0.979299 | 0.977815 / 0.769416 |

In these recorded runs Processor B has lower transpiled depth and fewer native CX gates for all
three repetition counts, with higher measured distribution fidelity and lower absolute
observable error. This is consistent with the grid's greater routing flexibility, but it does
**not** isolate topology as the sole cause: Processor B also has nine physical qubits versus
five. See §6 for the artifact-availability caveat.

### 5.1 Commands

```bash
uv sync --locked
uv run --locked python scripts/run_quantum_benchmark.py       # all six A/B x reps cases
uv run --locked python scripts/analyze_quantum_results.py     # tables + figures from raw CSV
uv run --locked python scripts/validate_processors.py         # assert processor configs
uv run --locked python scripts/plot_processors.py             # standalone topology PNGs

# End-to-end notebook
uv run --locked python -m ipykernel install --sys-prefix --name python3 \
  --display-name "Python (SRM-Qiskit-FF-PS-P1)"
uv run --locked python -m nbconvert --execute --to notebook --inplace main.ipynb \
  --ExecutePreprocessor.timeout=1200

uv run --locked python -W error -m pytest -q
```

---

## 6. Evidence and artifact availability

`report.md`, this README, and `docs/UNIVERSAL_PROCESSOR_BENCHMARK.md` reference generated
artifacts. Because `.gitignore` excludes `data/raw/*`, `data/processed/*`, `results/tables/*`,
`results/figures/*`, and `results/logs/*`, a fresh clone does **not** contain them. They are all
reproducible from committed code (see §7).

| Artifact | Path | Produced by | In a fresh clone? |
|---|---|---|---|
| PS-P1 raw samples | `data/raw/benchmark_<run_id>.csv` | `src.benchmark` | No — regenerate |
| PS-P1 environment manifest | `data/processed/environment_<run_id>.json` | `src.benchmark` | No — regenerate |
| PS-P1 per-suite summary | `results/tables/summary_<run_id>.csv` | `src.benchmark` | No — regenerate |
| PS-P1 memory summary | `results/tables/memory_<run_id>.csv` | `src.benchmark` | No — regenerate |
| PS-P1 run manifest | `results/tables/run_manifest_<run_id>.json` | `src.benchmark` | No — regenerate |
| PS-P1 comparison tables | `results/tables/comparison_summary_*_final.csv`, `component_timings_final.csv`, `per_batch_stats_final.csv`, `memory_comparison_all_runs_final.csv` | `scripts/analyze_results.py` | No — regenerate |
| PS-P1 plots | `results/figures/{median_latency,payload_bytes,memory_delta}_comparison_final.png` | `scripts/analyze_results.py` | No — regenerate |
| Gate/benchmark logs | `results/logs/*` | gates / scripts | No — regenerate |
| Processor topology PNGs | `results/figures/processor_A_topology.png`, `processor_B_topology.png` | `scripts/plot_processors.py` | Present in working tree |
| Quantum raw metrics | `data/raw/quantum_metrics.csv` | `scripts/run_quantum_benchmark.py` | No — regenerate |
| Quantum counts / circuits | `data/raw/quantum_counts.json`, `data/raw/quantum_circuits/` | `scripts/run_quantum_benchmark.py` | No — regenerate |
| Quantum run manifest | `results/logs/quantum_run_manifest.json` | `scripts/run_quantum_benchmark.py` | No — regenerate |
| Quantum summary | `data/processed/quantum_summary.csv` | `scripts/analyze_quantum_results.py` | No — regenerate |
| Processor A/B comparison | `results/tables/processor_A_vs_B.csv` | `scripts/analyze_quantum_results.py` | No — regenerate |
| Quantum figures | `results/figures/coupling_maps.png`, `depth_cx_swap_comparison.png`, `noisy_fidelity_by_reps.png` | `scripts/analyze_quantum_results.py` | Working tree: only `coupling_maps.png` present; all git-ignored |

Two audit documents **are** committed: `results/FINAL_ACCEPTANCE.md` and
`results/verification_log.md`. `PS-P1_BENCHMARK_REPORT.md` is also committed but is a secondary
record from a different host (Windows/WSL, Oct-16 runs) whose raw artifacts are not present; the
Oct-14 Linux runs documented in §4.5 are the primary reference because their raw data and
hashes exist in the working tree.

---

## 7. Reproducibility

### 7.1 PS-P1 track

1. Create the environment and install dependencies (§3).
2. Run the correctness gates: `python -m src.cli check`, `python -m pytest -q`,
   `python -m src.cli handshake --mode all`.
3. Run Platform A and Platform B with the exact commands in §4.3 (Platform B inside enforced
   limits).
4. Regenerate all tables and plots:
   `python scripts/analyze_results.py --run-ids <A_run> <B_run> --output-suffix final`.
5. Confirm artifact hashes if comparing against the recorded run:
   - `data/raw/benchmark_A_20261014T111113Z_3f7184ef.csv`
     sha256 `a97985ef64b2c21fff0e668d45e278b7edfe7cf7d0d19c4212af20607d80d8e3`
   - `data/raw/benchmark_B_20261014T111137Z_53a5cead.csv`
     sha256 `b20d147f03fd8a76ff289096470babab122409a436c8fd89d9f96a27de671c52`

The revision marker for the recorded runs (combined SHA-256 over `src/`, `tests/`, `scripts/`)
is `0ee224649e75130a8fb2a33d097747970e046e5bd7880ed16aaa8bc226539f88`. The pilot run
`A_20261014T110929Z_4efb66f6` is retained but excluded from the final aggregation via
`--run-ids` filtering. Raw CSV columns include `run_id, timestamp_utc, platform_id,
platform_verified, suite, batch, sample_index, success, key_match, handshake_wall_ns,
measurement_elapsed_ns, error_type, environment_json`, per-component `*_ns` timers,
`total_payload_bytes`, `mlkem_ciphertext_bytes`, and directional byte counts. Quantiles use
linear interpolation at `(n-1)*q` (inclusive); no outliers are deleted.

### 7.2 Processor A/B track

1. `uv sync --locked`.
2. `uv run --locked python scripts/run_quantum_benchmark.py` — runs all six Processor A/B ×
   reps 1–3 cases; confirm `PASS` in `results/logs/quantum_run_manifest.json`.
3. `uv run --locked python scripts/analyze_quantum_results.py` — rebuilds the summary, the A/B
   comparison table, and the figures.
4. Execute `main.ipynb` end-to-end (§5.1).

Fixed settings: transpiler optimization level 1, transpiler seed 42, simulator seed 42, 4096
shots per case. Finite-shot sampling means noisy metrics vary with the seed.

---

## 8. Testing

```bash
python -m pytest -q          # 64 tests; ML-KEM tests execute against native liboqs (no skips)
```

Current status on the locked environment: **64 passed** (~2.8 s). Coverage includes:

- **PS-P1:** ECDH agreement/lengths/malformed inputs; ML-KEM sizes, agreement, and implicit
  rejection (mutated ciphertext must not reproduce the original or the same derived key);
  transcript field binding and distinct suite labels; hybrid "both secrets required"; handshake
  payload arithmetic (130/2272/2402); quantile convention; benchmark output schema including a
  guard that no secret-like column is emitted.
- **Processor A/B:** workload/observable construction; processor config validation;
  transpilation basis compliance and routing diagnostics; noisy-simulation determinism; metrics
  validation; visualization acceptance/rejection; the end-to-end runner writing reproducible
  artifacts.

A skipped ML-KEM test is **not** an acceptance pass.

---

## 9. QFF Phase 1 checklist and rubric mapping

| Phase 1 checklist item | Where |
|---|---|
| Exactly one problem statement selected and documented | PS-P1, "Submission metadata" above |
| Core solution implemented and verified against a reference | §4; exact ideal reference for Processor A/B in `src/problem.py` |
| Coupling maps for Processor A (5q) and Processor B (9q) defined, justified, transpiled | `processors/*.json`, §5 |
| Quantitative A/B comparison table (depth, CX, SWAP, accuracy) | §5, `results/tables/processor_A_vs_B.csv` |
| Required repository structure incl. `main.ipynb`, `requirements.txt`, `processors/`, `results/` | §2 |
| Public GitHub repository submitted | https://github.com/Devo982/SRM-Qiskit-FF-PS-P1 |

| Rubric criterion | Weight | Where addressed |
|---|---:|---|
| Scientific & algorithmic correctness | 30 | Tests (§8); PS-P1 `check`/handshake; Processor A/B exact ideal reference |
| Processor A vs B architectural analysis & creativity | 35 | §5; `docs/UNIVERSAL_PROCESSOR_BENCHMARK.md` |
| Reproducibility & code quality | 20 | §3, §7; pinned `uv.lock`/`requirements.txt`; `main.ipynb` |
| Documentation & visualizations | 15 | This README, `report.md`, coupling-map and comparison plots (§6) |

---

## 10. Limitations

- **Unauthenticated** baseline: man-in-the-middle vulnerable; no identity authentication or key
  confirmation.
- Platform B is **CPU/memory-limited x86 emulation**, not embedded ARM hardware; no energy or
  cache claims.
- Timings are **local CPU compute only**; no socket/network RTT or TLS framing overhead.
- Built on native `liboqs` and `cryptography`; first-import build and host load/frequency cause
  run-to-run variation. Tail differences are consistent with 1-core quota contention but not
  proven causal.
- The recorded PS-P1 runs used Python 3.14.7; the locked repository environment is Python 3.13.
- Processor A/B results are from Qiskit transpilation and a **synthetic** noise model with
  finite shots — not real quantum hardware. Processor A and B have unequal physical-qubit
  budgets (5 vs 9), so connectivity is not isolated; only three repetition counts and one
  workload are reported.
- NIST FIPS 203 final (2024-08-13) was consulted; the page notes a potential errata to be
  corrected in a future revision. No erratum is claimed resolved by the installed library.
- QFF "quantum Processor A/B" versus PS-P1 "CPU Platform A/B" scope mismatch: this repository
  implements the PS-P1 CPU interpretation as its primary track and the QFF quantum Processor A/B
  study as a clearly separated second track, without conflating the two.

---

## 11. Background and references

- NIST FIPS 203, *Module-Lattice-Based Key-Encapsulation Mechanism Standard* — https://csrc.nist.gov/pubs/fips/203/final
- Open Quantum Safe `liboqs-python` — https://github.com/open-quantum-safe/liboqs-python
- pyca `cryptography` EC/ECDH — https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ec/
- Qiskit / Qiskit Aer — https://docs.quantum.ibm.com/
- Battarbee et al., *Quantum-Safe Hybrid Key Exchanges with KEM-Based Authentication* (arXiv:2411.04030) — background only; this prototype does not implement that broader authenticated/QKD design.

Supplied challenge and reference materials remain unmodified under `reference_materials/`. The
mock-free, evidence-driven PS-P1 prototype is implemented under `src/` and `tests/`; the
Processor A/B benchmark is implemented under `src/`, `processors/`, and `scripts/`.

> This README supersedes the earlier [`PROJECT_README.md`](PROJECT_README.md) and
> [`PS-P1_BENCHMARK_REPORT.md`](PS-P1_BENCHMARK_REPORT.md), which are retained for history.
