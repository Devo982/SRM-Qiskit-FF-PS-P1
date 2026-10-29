# Verification Log

Append only evidence-backed entries. The ZIP-preparation checks performed in the packaging environment are not the same as a successful native ML-KEM acceptance run.

## Package creation
- Date (UTC): 2026-10-14
- Scope: created scaffold, protocol docs, agent instructions, sample code, tests, and reference materials.
- ML-KEM runtime status in package-creation environment: `BLOCKED` — `oqs` is not installed in the creation environment; native ML-KEM tests cannot be claimed as passed here.
- Required next action: install requirements in an environment with compiler/CMake/Git/network, run `python -m src.cli check`, and verify all ML-KEM tests execute (not skip).
- Package code check (2026-10-14): `python -m compileall -q src tests scripts` — `PASS` (exit 0).
- Package tests (2026-10-14): `python -m pytest -q` — `10 passed, 4 skipped`; all four skips are ML-KEM-dependent tests because `oqs` is unavailable in the packaging environment. This is partial scaffold verification, not final acceptance.
- ECDH smoke test (2026-10-14): `python -m src.cli handshake --mode ecdh` — `PASS`; parties agreed on the derived key and raw payload was 130 bytes. This one local smoke-test timing is not a benchmark result and must not be used in the report.
- Still BLOCKED here: native ML-KEM-768 preflight, ML-KEM/hybrid integration tests, and all Platform A/B benchmark runs pending native `liboqs` installation.
- Preflight command (2026-10-14): `python -m src.cli check` — `BLOCKED` / exit 1, with explicit diagnostic `ModuleNotFoundError: No module named 'oqs'`. ECDH preflight portion reported PASS. Output preserved under `results/logs/package_preflight_stdout.json` and `results/logs/package_preflight_stderr.txt`. Native OQS must be installed before acceptance.

---

# Native execution and benchmark evidence (2026-10-14)

Environment: AMD Ryzen 7 4800H (8P/16L), 15.04 GiB RAM, kernel 7.2.5-3-omarchy, Python 3.14.7.
Working tree is not a Git repository; revision marker = combined SHA-256 of `src/`, `tests/`,
`scripts/` Python files = `0ee224649e75130a8fb2a33d097747970e046e5bd7880ed16aaa8bc226539f88`.

## Phase 0 — Preflight / native ML-KEM
- Timestamp (UTC): 2026-10-14T11:09Z
- Command: `python3 -m venv .venv` then `.venv/bin/python -m pip install cmake "cryptography>=44,<47" "psutil>=5.9,<8" "pytest>=8,<9" "pandas>=2.1,<4" "matplotlib>=3.8,<4" "liboqs-python>=0.14,<0.17"`
- Exit code: 0
- Observed: `import oqs` present; `.venv/bin/python -m src.cli check` → exit 0, JSON
  `{"preflight":"PASS","mlkem_768_enabled":true}`, algorithm `ML-KEM-768`
  (`version=FIPS203`, `claimed_nist_level=3`, `is_ind_cca=true`); `liboqs 0.16.0`,
  `liboqs-python 0.16.0.1`, `cryptography 46.0.7`. Native liboqs auto-built on first import
  (prefix `/home/devo982/_oqs`) using pip-provided cmake 4.4.4.
- Evidence: `results/logs/phase0_preflight_stdout.json`, `results/logs/phase0_preflight_stderr.txt` (empty), `environment.md`
- Status: PASS
- Notes/fixes: `src/mlkem.py` and `src/platforms.py` now suppress the liboqs-python stdout
  INFO line so CLI JSON stays machine-parseable. Docker daemon unavailable (client 29.7.2 only,
  `systemctl is-active docker` inactive, no passwordless sudo); Platform B will use an enforced
  cgroup v2 user scope instead of a container (documented deviation).

## Phase 1–4 — ECDH / ML-KEM / transcript+KDF / integration
- Timestamp (UTC): 2026-10-14T11:09Z
- Commands:
  - `.venv/bin/python -m pytest -q` → exit 0, **20 passed, 0 skipped**
  - `.venv/bin/python -m src.cli handshake --mode all` → exit 0, `status=PASS`
- Observed: ML-KEM tests execute against native liboqs (no skips). Handshake payloads
  `ecdh=130`, `mlkem=2272`, `hybrid=2402` bytes; both endpoints' derived keys match; sizes
  65/32/1184/2400/1088/32 verified; mutated ML-KEM ciphertext does not reproduce the original
  or a same derived key (implicit rejection respected); transcript binds every field;
  distinct suites use distinct info labels.
- Evidence: `results/logs/phase4_handshake_all.json`; tests `tests/test_{ecdh,mlkem,hybrid_kdf,handshake,metrics,benchmark_schema}.py`
- Status: PASS (Gates 1–4)
- Notes/fixes: added `tests/test_benchmark_schema.py` (Phase 5 schema gate) and added
  transcript-binding / implicit-rejection-at-KDF tests.

## Phase 5 — Benchmark instrumentation and pilot
- Timestamp (UTC): 2026-10-14T11:09Z
- Command: `.venv/bin/python -m src.benchmark --platform A --iterations 20 --warmup 5 --batches 1 --memory-reps 10`
- Exit code: 0 → `status=PASS`, run ID `A_20261014T110929Z_4efb66f6`
- Observed: 60/60 rows, valid CSV schema; separate-subprocess RSS probe produced baseline/peak/delta.
- Evidence: `results/logs/phase5_pilot_stdout.txt`, `data/raw/benchmark_A_20261014T110929Z_4efb66f6.csv`
- Status: PASS (Gate 5). Pilot is excluded from final aggregation via run-id filtering.

## Phase 6 — Platform A (final)
- Timestamp (UTC): 2026-10-14T11:11Z
- Command: `.venv/bin/python -m src.benchmark --platform A --iterations 1000 --warmup 100 --batches 5`
- Exit code: 0 → `status=PASS`; run ID `A_20261014T111113Z_3f7184ef`
- Observed: 15,000/15,000 successful (100% per suite); medians ECDH 0.3603 ms, ML-KEM 0.1915 ms, hybrid 0.5363 ms.
- Evidence: `results/logs/phase6_platformA_stdout.txt`, `data/raw/benchmark_A_20261014T111113Z_3f7184ef.csv`
  (sha256 `a97985ef64b2c21fff0e668d45e278b7edfe7cf7d0d19c4212af20607d80d8e3`),
  `data/processed/environment_A_20261014T111113Z_3f7184ef.json` (`platform_verified=true`, no caps)
- Status: PASS (Gate 6)

## Phase 7 — Platform B (final, enforced cgroup v2)
- Timestamp (UTC): 2026-10-14T11:11Z
- Command: `systemd-run --user --scope --collect -p CPUQuota=100% -p MemoryMax=512M -p MemorySwapMax=0 --working-directory="$PWD" -- "$PWD/.venv/bin/python" -m src.benchmark --platform B --iterations 1000 --warmup 100 --batches 5`
- Exit code: 0 → `status=PASS`; run ID `B_20261014T111137Z_53a5cead`
- Observed: `platform_verified=true`; observed `cpu.max=100000 100000` (1.0 core) and
  `memory.max=536870912` (512 MiB) in the scope's own cgroup; 15,000/15,000 successful;
  medians ECDH 0.3650 ms, ML-KEM 0.1893 ms, hybrid 0.5474 ms. Same Python/cryptography/liboqs
  versions as Platform A.
- Evidence: `results/logs/phase7_platformB_stdout.txt` (+ `.stderr` with `Running as unit: ...scope`),
  `data/raw/benchmark_B_20261014T111137Z_53a5cead.csv` (sha256 `b20d147f03fd8a76ff289096470babab122409a436c8fd89d9f96a27de671c52`),
  `data/processed/environment_B_20261014T111137Z_53a5cead.json`
- Status: PASS (Gate 7) with documented deviation: cgroup v2 user scope used instead of Docker
  because the Docker daemon was unavailable; limits are enforced and observable, but this is not
  a container and not embedded hardware.

## Phase 8 — Analysis and report
- Timestamp (UTC): 2026-10-14T11:42Z
- Command: `.venv/bin/python scripts/analyze_results.py --run-ids A_20261014T111113Z_3f7184ef B_20261014T111137Z_53a5cead --output-suffix final`
- Exit code: 0
- Observed: comparison/verified summaries, component-timing table, per-batch table, and three
  plots generated solely from raw CSV. Final report and environment manifest written from these values.
- Evidence: `results/tables/*_final.csv`, `results/figures/*_final.png`, `report.md`, `environment.md`
- Status: PASS (Gate 8)

## Phase 9 — Final audit
- Timestamp (UTC): 2026-10-14T11:45Z
- Checks: full `pytest` re-run after all edits (20 passed, 0 skipped); secret-pattern scan over
  code and result CSV/JSON/PNG (no private keys or shared/session secrets present); report
  cross-checked against raw CSV fields; Docker-unavailability and cgroup-emulation deviations
  disclosed; no placeholder values remain.
- Evidence: `results/FINAL_ACCEPTANCE.md`
- Status: PASS (Gate 9)

