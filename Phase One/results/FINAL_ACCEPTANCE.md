# PS-P1 Final Acceptance Summary

Date (UTC): 2026-10-14
Revision marker (combined SHA-256 of `src/`, `tests/`, `scripts/` Python files):
`0ee224649e75130a8fb2a33d097747970e046e5bd7880ed16aaa8bc226539f88` (working tree is not a Git repo).

## Stage gate table

| Gate | Requirement | Status | Evidence |
|---|---|---|---|
| 0 | Native standardized ML-KEM-768 available | **PASS** | `results/logs/phase0_preflight_stdout.json` (`preflight=PASS`, `mlkem_768_enabled=true`, FIPS203) |
| 1 | ECDH P-256 correctness/lengths/malformed rejection | **PASS** | `tests/test_ecdh.py` (executed) |
| 2 | ML-KEM-768 executed (not skipped), correct lengths | **PASS** | `tests/test_mlkem.py` executed; 0 skips; `pytest -q` = 20 passed |
| 3 | Transcript binding + HKDF agreement/sensitivity | **PASS** | `tests/test_hybrid_kdf.py` |
| 4 | Three modes integrate; payloads 130/2272/2402 | **PASS** | `.venv/bin/python -m src.cli handshake --mode all` → PASS |
| 5 | Benchmark schema + pilot | **PASS** | `tests/test_benchmark_schema.py`; pilot run `A_20261014T110929Z_4efb66f6` |
| 6 | Platform A full workload | **PASS** | run `A_20261014T111113Z_3f7184ef`; 15000/15000 successful |
| 7 | Platform B verified constraint + full workload | **PASS*** | run `B_20261014T111137Z_53a5cead`; `platform_verified=true`; cpu=1.0, mem=512 MiB observed; *cgroup v2 scope used because Docker daemon unavailable |
| 8 | Tables/plots from raw CSV; report/environment complete | **PASS** | `results/tables/*_final.csv`, `results/figures/*_final.png`, `report.md`, `environment.md` |
| 9 | Final audit, tests re-run, no secrets/placeholders | **PASS** | `pytest -q` 20 passed; secret scan clean; no TBD in `report.md`/`environment.md` |

`*` Platform B deviation: the host Docker daemon is unavailable and cannot be started without
root, so the container image could not be built/run. Platform B was executed with the **same
source tree, virtualenv, and dependency versions** under an enforced cgroup v2 user scope
(`CPUQuota=100%`, `MemoryMax=512M`, `MemorySwapMax=0`); the limits were observed in the
process's own cgroup and recorded. This is resource emulation, not a container and not real
embedded hardware.

## Exact commands and outcomes
```bash
.venv/bin/python -m src.cli check                 # exit 0, preflight PASS, ML-KEM-768 enabled
.venv/bin/python -m pytest -q                     # exit 0, 20 passed, 0 skipped
.venv/bin/python -m src.cli handshake --mode all  # exit 0, PASS; payloads 130/2272/2402
.venv/bin/python -m src.benchmark --platform A --iterations 1000 --warmup 100 --batches 5   # exit 0, PASS
systemd-run --user --scope --collect -p CPUQuota=100% -p MemoryMax=512M -p MemorySwapMax=0 \
  --working-directory="$PWD" -- "$PWD/.venv/bin/python" \
  -m src.benchmark --platform B --iterations 1000 --warmup 100 --batches 5                  # exit 0, PASS, verified
.venv/bin/python scripts/analyze_results.py \
  --run-ids A_20261014T111113Z_3f7184ef B_20261014T111137Z_53a5cead --output-suffix final   # exit 0
```

## Measured results (from raw CSV)
Medians (ms) / throughput (handshakes/s), n=5000 per suite:
- Platform A: ECDH 0.3603 / 2742.4; ML-KEM 0.1915 / 4914.6; Hybrid 0.5363 / 1854.3
- Platform B: ECDH 0.3650 / 2648.8; ML-KEM 0.1893 / 5028.0; Hybrid 0.5474 / 1688.6

Tail latency: hybrid p99 A 0.6430 ms vs B 1.0785 ms (×1.68); ECDH p99 ×1.30; ML-KEM p99 ×1.01.
Median B/A within 2%. Payloads constant: ECDH 130 B; ML-KEM 2272 B (ciphertext 1088 B); hybrid 2402 B.
Sampled peak RSS delta ≈ 0.21–0.29 MiB after warmup for all suites.

## Artifacts
- Raw: `data/raw/benchmark_A_20261014T111113Z_3f7184ef.csv`, `data/raw/benchmark_B_20261014T111137Z_53a5cead.csv`
- Tables: `results/tables/comparison_summary_verified_final.csv`, `component_timings_final.csv`, `per_batch_stats_final.csv`, `memory_comparison_all_runs_final.csv`, `summary_{A,B}_*.csv`
- Plots: `results/figures/median_latency_comparison_final.png`, `payload_bytes_comparison_final.png`, `memory_delta_comparison_final.png`
- Environment: `data/processed/environment_{A,B}_*.json`; `environment.md`
- Report/log: `report.md`; `results/verification_log.md`
- Logs: `results/logs/phase*.{txt,json}`

## Limitations and unresolved blockers
- Docker daemon unavailable → no container image for Platform B (mitigated with enforced cgroup v2 scope; deviation disclosed).
- Baseline protocol is **unauthenticated** and vulnerable to active man-in-the-middle attacks; key confirmation would not establish identity.
- Platform B is CPU/memory-limited x86 emulation, not ARM/embedded hardware; no energy, cache, or microcontroller claims.
- liboqs auto-builds on first import; absolute single-run numbers vary with host load/frequency; tail differences observed are consistent with 1-core quota contention but not proven causal.
- NIST FIPS 203 page notes a potential errata issue to be corrected in a future revision; no erratum claimed resolved.
- QFF-wide quantum Processor A/B vs PS-P1 CPU A/B scope mismatch: this kit implements the PS-P1 CPU interpretation only.

## Verdict
**ACCEPTED** for the PS-P1-scoped deliverable: implementation complete, all correctness gates
pass with native standardized ML-KEM-768, Platform A and enforced Platform B runs completed with
raw data and generated analysis, and limitations truthfully disclosed. The only BLOCKED item is
the Docker container image (host daemon unavailable), with a documented enforced-cgroup substitute.
