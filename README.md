# QFF 2026 Track 5 — SRM-Qiskit-FF-PS-P1 | PS-P1 Quantum-Safe Secure Communication Channel

**Challenge:** Qiskit Fall Fest 2026 · Track 5 · **Problem Statement PS-P1**

**Technical report:** [docs/TECHNICAL_REPORT.md](docs/TECHNICAL_REPORT.md)

**Integration contract:** [docs/INTEGRATION_CONTRACT.md](docs/INTEGRATION_CONTRACT.md)

## Team members and submission contact

| Role | Name | Contact |
|---|---|---|
| Primary repository contact | Vasisht Hire | This repository: [Devo982/SRM-Qiskit-FF-PS-P1](https://github.com/Devo982/SRM-Qiskit-FF-PS-P1) |

The supplied repository snapshot did not identify the complete registered team roster. Add the actual names and contacts of all other registered members here before the final submission; no teammate names have been inferred or invented for this README.

## Quick start (Windows, macOS, and Linux)

**Requirements:** Python 3.11–3.13 (Python 3.13 recommended), Git, and an internet connection for installing dependencies. `cryptography==50.0.2` is the organizer’s fixed pin and must not be changed. The recorded benchmark data comes from Platform A, an Intel Mac running macOS; the instructions below are intended for other supported machines too. A platform is not considered tested until the commands below have been run successfully on it. If you already have a clone, use that checkout and skip the `git clone` command.

The commands use the virtual environment’s Python directly, so activation is not required.

### Windows (PowerShell)

```powershell
git clone https://github.com/Devo982/SRM-Qiskit-FF-PS-P1.git
Set-Location SRM-Qiskit-FF-PS-P1
py -3.13 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe scripts/run_security_suite.py
.\.venv\Scripts\python.exe -m tests.test_regressions
.\.venv\Scripts\python.exe -m cli.demo --suite QFF26-PQC-1
```

If Python 3.13 is not installed, use an installed supported version by changing `-3.13` to `-3.12` or `-3.11`.

### macOS and Linux (Bash/Zsh)

```bash
git clone https://github.com/Devo982/SRM-Qiskit-FF-PS-P1.git
cd SRM-Qiskit-FF-PS-P1
python3.13 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python scripts/run_security_suite.py
.venv/bin/python -m tests.test_regressions
.venv/bin/python -m cli.demo --suite QFF26-PQC-1
```

If `python3.13` is not installed, use `python3.12` or `python3.11` for the virtual-environment creation command. Check the selected interpreter before installing: `python3.13 --version` (or the versioned command you chose). Do not use an unsupported system Python such as an older `/usr/bin/python3`. The optional `./scripts/bootstrap_env.sh` helper is Bash-only and can prepare a `.venv` on macOS/Linux; the explicit commands above are preferred when selecting a particular Python version.

### What the security launcher does

`scripts/run_security_suite.py` is the security-only one-command entry point. It checks that Alice/Bob test identity key pairs and `trust_store.json` are consistent, repairs missing or inconsistent local test identities when needed, and then runs T1–T9. A separate provisioning command is not required. The stable pass criterion is **`ALL TESTS PASSED: 52/52 detailed checks`**; elapsed time varies by machine.

The identities are local test material. Provisioning may regenerate `trust_store.json`; do not commit that generated local change. `common/env_check.py` writes `platform_A_info.json` by default; if you run it on a different machine for troubleshooting, do not commit that file as though it were Platform A metadata. The security suite also refreshes test-result CSVs, so check `git status --short` after running commands and do not commit generated results unless you intentionally regenerated and reviewed the evidence.

### One-command reproducibility run (recommended for organizers and teammates)

After installing dependencies, run this single command to validate the environment, run T1–T9, benchmark both suites, validate the three official payloads, and generate figures. Use `LOCAL` for an additional teammate/organizer laptop that is not the designated Platform A machine. Use `A` only on the designated Platform A machine whose results are being submitted. Do not label an ordinary teammate laptop as Platform B: the problem statement defines Platform B as a constrained profile (1 CPU core, single-threaded libraries and 128 MB memory budget).

Windows PowerShell:

```powershell
.\.venv\Scripts\python.exe scripts/run_reproducible_benchmarks.py --platform-label LOCAL
```

macOS/Linux:

```bash
.venv/bin/python scripts/run_reproducible_benchmarks.py --platform-label LOCAL
```

Each invocation creates a fresh timestamped directory under `results/runs/` and a matching ZIP bundle. The bundle contains the machine/environment JSON, `pip freeze` output, exact command logs, a manifest with the Git revision and SHA-256 hashes of bundle artifacts, the security-test CSV snapshots, both benchmark CSV sets, successful raw handshake timings, and platform-labelled plots. The run directory is ignored by Git so a teammate's measurements do not accidentally replace the committed Platform A evidence. Existing `results/tables/*.csv`, `results/figures/*.png`, and root `platform_A_info.json` are not benchmark output targets.

Default benchmark settings are 100 handshake trials per suite and 15 complete bidirectional rounds per payload and suite. They can be changed with `--handshake-runs` and `--payload-repeats`. The elapsed timing values are machine-dependent; reproducibility here means the same process, test criteria, payload checks, metadata, and output structure—not identical timing values across different machines. Measurements remain local/in-process, not real-network measurements. The self-repairing test launcher may regenerate local `trust_store.json`; keep that generated local test trust store uncommitted.

## Summary

PS-P1 Phase 2 implements a mutual-authentication secure channel with two suites behind one channel state machine. The post-quantum suite uses ML-KEM-768 (FIPS 203), ML-DSA-65 (FIPS 204), HKDF-SHA256 and AES-256-GCM. The classical comparison baseline uses X25519 and Ed25519 with the same HKDF-SHA256 key schedule and AES-256-GCM record layer. Suite selection is local policy on both endpoints; suite negotiation is not performed on the wire.

The T1–T9 fault-injection battery has 52 detailed checks across the two suites. In Platform A run `20261029T211325Z`, the PQC handshake median is 2.883 ms (IQR 1.236 ms; p95 5.186 ms) and total measured handshake traffic is 9,134 B; the classical baseline median is 0.738 ms (IQR 0.048 ms; p95 0.885 ms) and total handshake traffic is 448 B. Both suites use 32 B transmitted record overhead. Measurements are local/in-process, not network results. These figures describe Platform A only and are not performance promises for another laptop. The Platform A metadata records `on_battery=false` for this run. The reported numeric results are drawn from the committed Platform A CSVs. The all-in-one runner creates fresh figures from each run's own CSVs in its separate bundle; it does not replace the committed Platform A figures.

## Test and smoke-check commands

Run these from the repository root, using the virtual-environment interpreter shown for your operating system in Quick start.

| Purpose | Command | Expected evidence |
|---|---|---|
| Full T1–T9 security suite with automatic test-identity repair | `python scripts/run_security_suite.py` | `ALL TESTS PASSED: 52/52 detailed checks`; writes `results/security_tests.csv` and `results/security_tests_detailed.csv` |
| Environment and primitive smoke checks for the designated Platform A machine | `python common/env_check.py` | `READY - environment is correct.` and `platform_A_info.json` |
| Regression vectors and replay-window rules | `python -m tests.test_regressions` | RFC 5869 vector/oracle and replay-window assertions pass |
| End-to-end PQC demo | `python -m cli.demo --suite QFF26-PQC-1` | metadata-only handshake, bidirectional transfer and authenticated-close output |

The command examples in this table use `python` as shorthand for the selected virtual-environment interpreter. On Windows use the virtual-environment interpreter at `.\.venv\Scripts\python.exe` from the repository root; on macOS/Linux use `.venv/bin/python`. You normally do **not** need to run `python scripts/provision_identities.py` separately because the security launcher repairs missing or inconsistent local test identities automatically.
For an additional laptop, do not run the environment checker with its default Platform A output path; use the all-in-one runner with `--platform-label LOCAL`, which stores metadata inside the per-run bundle. The direct benchmark scripts also default to `LOCAL` and write to the ignored `results/runs/manual/` scratch directory, not the committed Platform A tables.

## Verification

The runner prints `ALL TESTS PASSED: 52/52 detailed checks in <elapsed>s` when successful. The elapsed time varies by machine; the stable pass criterion is `ALL TESTS PASSED: 52/52 detailed checks`.

## Reproduce principal results

Use the one-command runner above for the authoritative reproduction workflow. Every run records a unique run ID and machine metadata, preserves the raw successful handshake timings, includes T1–T9 result snapshots and dependency versions, checks that all three official payloads pass SHA-256 validation, and generates figures from that run's own tables. The resulting `summary.md`, `manifest.json`, logs, CSVs, figures and matching ZIP bundle are placed under `results/runs/`.

For component-level diagnosis, each script accepts custom output destinations so a Platform B/D experiment or an extra laptop run does not overwrite Platform A evidence:

| Component | Output / key evidence |
|---|---|
| Environment + primitive self-test | `environment.json`: OS, CPU/RAM, Python, crypto-library metadata and verified primitives |
| Mandatory T1–T9 security suite | `security/`: security-test CSV snapshots; `logs/security_suite.log` |
| Handshake benchmark | `handshake_results.csv`, `bench_handshake.csv`, `handshake_raw_samples.csv`: median, IQR, p95, actual serialized M1/M2/M3 byte counts and trial-level timings |
| Official payload benchmark | `payload_results.csv`, `bench_payload.csv`: encryption/decryption medians, record overhead, throughput and SHA-256 match for the 1 KB, 100 KB and 10 MB payloads |
| Figures | Three PNG figures rendered from the run's own CSVs with the run's platform label |

Run component commands from the repository root with the selected virtual-environment interpreter. `--output-dir`, `--tables-dir` and `--output-dir` for figures accept paths relative to the repository root. Use a fresh output directory and unique run ID for every standalone run. See `python bench/bench_handshake.py --help`, `python bench/bench_payload.py --help` and `python scripts/make_figures.py --help` for options.

## Platforms used

| Platform | CPU | Cores | RAM | OS |
|---|---|---|---|---|
| A (results platform) | Intel(R) Core(TM) i5-8257U CPU @ 1.40GHz | 4 physical / 8 logical | 8.0 GB | macOS 15.8.2, x86_64 |
| B (optional constrained profile) | Host CPU model recorded in run metadata | 1 effective CPU core | 128 MB budget | Not run; apply the official profile before claiming B |
| D | Not used | Not used | Not used | Not used |

Run metadata in `platform_A_info.json` was generated at `2026-10-29T21:13:19+00:00` and records `on_battery=false`, so the Platform A environment check observed AC power for this benchmark run. Measurements remain local/in-process; AC power does not make them network measurements or a cross-device performance guarantee.

**Cross-platform handoff:** a second laptop run uses `--platform-label LOCAL` and records that machine’s actual OS/version, CPU, core count, RAM and Python version in its own bundle. A passing security suite is a portability smoke test, not a second performance benchmark. Platform B specifically means the constrained profile in the problem statement, not a teammate's unconstrained laptop; do not claim Platform B results unless its profile has actually been applied. Do not overwrite Platform A’s measurements.

## Libraries and versions

| Library | Compatible requirement | Version in the current Python 3.13.17 environment |
|---|---|---|
| `cryptography` | `==50.0.2` (exact organizer pin) | `50.0.2` |
| `psutil` | `>=5.9` | `7.2.2` |
| `numpy` | `>=1.24` | `2.5.4` |
| `pandas` | `>=2.0` | `3.1.0` |
| `matplotlib` | `>=3.7` | `3.11.2` |

The analysis-package minimums are intentionally not exact pins: PyPI declares NumPy 2.5.4 as Python >=3.12, and pandas 3.1.0 plus matplotlib 3.11.2 as Python >=3.11. The lower bounds above let pip select compatible releases across the declared Python 3.11–3.13 range while preserving `cryptography==50.0.2`. The recorded Platform A environment used the versions shown in the last column; only Python 3.13.17 was exercised for this submission.

## Results

All current committed result files are linked below. Benchmark CSVs are the source of truth for report numbers; do not hand-edit their values.

- [Organizer security summary](results/security_tests.csv)
- [Detailed T1–T9 checks](results/security_tests_detailed.csv)
- [Official handshake results](results/tables/handshake_results.csv)
- [Handshake detail and M1/M2/M3 sizes](results/tables/bench_handshake.csv)
- [Payload encrypt/decrypt results and record overhead](results/tables/payload_results.csv)
- [End-to-end payload throughput](results/tables/bench_payload.csv)
- [Per-trial handshake samples (100 successful timings per suite)](results/tables/handshake_raw_samples.csv)
- [Handshake latency figure](results/figures/handshake_latency.png)
- [Handshake message sizes figure](results/figures/handshake_message_bytes.png)
- [10 MB payload timing figure](results/figures/payload_10mb_timing.png)
- [Official payload SHA-256 manifest](data/payloads/payload_sha256.txt)
- [Platform A environment metadata](platform_A_info.json)

## Baseline used

`QFF26-CLASSICAL-1` is the classical comparison baseline: X25519 key exchange and Ed25519 signatures. It uses the **same HKDF-SHA256 key schedule and AES-256-GCM record layer** as `QFF26-PQC-1`. It is a performance/security comparison baseline, not a recommendation to deploy a classical-only suite against a quantum-capable adversary.

## Known limitations

- This is a competition prototype, not a production secure-channel implementation or production security certification.
- Security tests and performance measurements use a local in-process wire; no two-machine network latency, packet loss, congestion or deployment measurements have been collected.
- Automatic renegotiation after `SessionExhausted` is not implemented; creating a fresh session requires a new handshake.
- Python key zeroization is best-effort; Python's object/memory model cannot guarantee complete erasure.
- Trust-store distribution, integrity, rotation and revocation are out-of-band and not solved by this prototype.
- It is a single trust domain; denial-of-service resistance and side-channel hardening are out of scope.
- Payloads are sent as one record; chunking/fragmentation is not implemented.

## T1–T9 (all faults injected on the wire between two real endpoints)

| ID | Scenario | Expected |
|----|----------|----------|
| T1 | honest handshake; 3 official payloads (1KB/100KB/10MB) both directions; byte + SHA-256 vs committed `payload_sha256.txt`; authenticated close | success, ESTABLISHED, 6/6 verified |
| T2 | parametrized bit-flips: kem_pk_C, kem_ct, nonce_C, nonce_S, id_C, id_S, version, suite_id | abort at the step that owns the field; keys never established |
| T3 | bit-flip sig_S / sig_C | `AuthenticationFailure` |
| T4 | bit-flip record ciphertext | `RecordAuthenticationError` wrapping `InvalidTag`; plaintext withheld |
| T5 | GCM tag / authenticated header-AAD tampering, plus version/direction checks | GCM tampering wraps `InvalidTag`; malformed version/direction rejected before AEAD |
| T6 | attacker identity + own valid key | `UntrustedIdentity` at lookup, before signature math |
| T7 | (a) role swap with genuine key, (b) genuine old sig_S spliced into a fresh session | transcript/identity binding rejects both |
| T8 | (a) app-record replay, (b) full old-session replay, (c) M1 replay with cache | `RecordReplayDetected` / `AuthenticationFailure` / `HandshakeReplayDetected` |
| T9 | (a) unknown suite_id, (b) echoed suite substituted to the other valid suite | `PolicyViolation` before any crypto; no fallback |

## Platform-specific troubleshooting

`cryptography==50.0.2` is the organizer's fixed pin. First try the normal `pip install -r requirements.txt` instructions above on your own OS and architecture. **Only on Intel macOS (x86_64)**, if pip cannot install a compatible wheel for the pinned `cryptography` version, consult the [Intel Mac environment helper](scripts/QFF2026_intel_mac_env_setup.sh); it prepares the static OpenSSL environment documented in that script. This helper is not a general Windows/Linux/Apple-Silicon setup path. Stock macOS `/usr/bin/python3` may be older than the required Python 3.11 minimum, so use an explicitly supported interpreter.

## Repository layout

```text
common/env_check.py              environment contract -> READY + platform_A_info.json
protocol/                         TLV, suites, key schedule, record layer, state machines
cli/adapter.py                    UX façade / integration boundary
cli/demo.py                       metadata-only end-to-end demo
tests/run_security_tests.py       T1–T9 security checks -> results/security_tests*.csv
tests/test_regressions.py         RFC 5869 and replay-window regressions
bench/bench_handshake.py          handshake timing, sizes and raw samples
bench/bench_payload.py             record timing and end-to-end throughput
scripts/make_figures.py            CSV-only figures; accepts per-run input/output paths
scripts/run_reproducible_benchmarks.py  one-command validation + isolated benchmark bundle
scripts/provision_identities.py   local identities (git-ignored) + public trust store
scripts/bootstrap_env.sh          optional Bash setup helper
scripts/QFF2026_intel_mac_env_setup.sh  Intel-Mac OpenSSL setup helper
docs/TECHNICAL_REPORT.md           full methodology, evidence and interpretation
docs/INTEGRATION_CONTRACT.md       finalized UX/protocol integration contract
results/                           committed CSV evidence and figures
data/payloads/payload_sha256.txt   official payload manifest (payload binaries generated locally)
Phase One/                        archived Phase 1 submission (large uploaded papers ZIP removed)
```
