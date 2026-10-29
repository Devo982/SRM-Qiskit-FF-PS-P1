# Phase Invaders — PS-P1: Quantum-Safe Secure Communication Channel

**Challenge:** Qiskit Fall Fest 2026 · Track 5 · **Problem Statement PS-P1**

**Technical report:** [docs/TECHNICAL_REPORT.md](docs/TECHNICAL_REPORT.md)

**Integration contract:** [docs/INTEGRATION_CONTRACT.md](docs/INTEGRATION_CONTRACT.md)

## Team members and submission contact

| Role | Name | Contact |
|---|---|---|
| Primary repository contact | Vasisht Hire | This repository: [Devo982/SRM-Qiskit-FF-PS-P1](https://github.com/Devo982/SRM-Qiskit-FF-PS-P1) |

The supplied repository snapshot did not identify the complete registered team roster. Add the actual names and contacts of all other registered members here before the final submission; no teammate names have been inferred or invented for this README.

## Summary

PS-P1 Phase 2 implements a mutual-authentication secure channel with two suites behind one channel state machine. The post-quantum suite uses ML-KEM-768 (FIPS 203), ML-DSA-65 (FIPS 204), HKDF-SHA256 and AES-256-GCM. The classical comparison baseline uses X25519 and Ed25519 with the same HKDF-SHA256 key schedule and AES-256-GCM record layer. Suite selection is local policy on both endpoints; suite negotiation is not performed on the wire.

The T1–T9 fault-injection battery has 52 detailed checks across the two suites. In Platform A run `20261029T211325Z`, the PQC handshake median is 2.883 ms (IQR 1.236 ms; p95 5.186 ms) and total measured handshake traffic is 9,134 B; the classical baseline median is 0.738 ms (IQR 0.048 ms; p95 0.885 ms) and total handshake traffic is 448 B. Both suites use 32 B transmitted record overhead. Measurements are local/in-process, not network results. The Platform A metadata records `on_battery=false` for this run. All numeric results in the report are drawn from the CSVs under `results/`; rerun `python scripts/make_figures.py` after any new benchmark run.

## Setup

Requirements: Python 3.11–3.13 (3.13 recommended) and pip. Python 3.13.17 is the version exercised for the recorded Platform A run; Python 3.11 and 3.12 are supported targets but were not separately tested for this submission. `cryptography==50.0.2` is the organizer's exact pin and must not be changed.

```bash
# 1. Clone the repository and enter it
git clone https://github.com/Devo982/SRM-Qiskit-FF-PS-P1.git
cd SRM-Qiskit-FF-PS-P1

# 2. Create a virtual environment
python -m venv .venv

# 3. Activate it using the command for your shell/platform:
# Windows PowerShell or cmd:
.venv\Scripts\activate
# macOS / Linux (run this instead of the Windows line):
source .venv/bin/activate

# 4. Install the dependencies
python -m pip install -r requirements.txt
```

Optional Unix/macOS helper: `./scripts/bootstrap_env.sh` probes supported interpreters and creates `.venv`; it is a Bash script, so use the portable `venv` commands above on Windows. On Intel macOS, read the **Intel-Mac note** below before installing `cryptography`.

## Reproduce principal results

Run the following commands in order after setup, identity provisioning and tests below. Expected runtimes are planning estimates on Platform A; exact wall-clock benchmark duration is not recorded in the CSVs and varies with system load.

| Output table / artifact | Command | Platform A expected runtime |
|---|---|---|
| `results/tables/handshake_results.csv` — official handshake summary | `python bench/bench_handshake.py --runs 100` | About 5–15 s for both suites (estimate) |
| `results/tables/bench_handshake.csv` — handshake detail including M1/M2/M3 bytes | `python bench/bench_handshake.py --runs 100` | Same run as above |
| `results/tables/payload_results.csv` — encrypt/decrypt timings and serialized overhead | `python bench/bench_payload.py --repeats 15` | About 10–30 s for both suites and all payload sizes (estimate) |
| `results/tables/bench_payload.csv` — end-to-end throughput | `python bench/bench_payload.py --repeats 15` | Same run as above |
| `results/figures/*.png` — plots generated only from `results/tables/*.csv` | `python scripts/make_figures.py` | Usually under 5 s (estimate) |

Each benchmark command writes its associated pair of tables. The handshake script also writes `results/tables/handshake_raw_samples.csv` (successful per-trial times, columns `suite,trial,ms`) so median/IQR figures can be reproduced from individual measurements. The current run includes 100 raw handshake timings for each suite in `results/tables/handshake_raw_samples.csv`; the latency figure uses empirical Q1–Q3 from those samples. The aggregate CSV's median/IQR/p95 remain the official rounded summary.

## Platforms used

| Platform | CPU | Cores | RAM | OS |
|---|---|---|---|---|
| A (results platform) | Intel(R) Core(TM) i5-8257U CPU @ 1.40GHz | 4 physical / 8 logical | 8.0 GB | macOS 15.8.2, x86_64 |
| B | Not used | Not used | Not used | Not used |
| D | Not used | Not used | Not used | Not used |

Run metadata in `platform_A_info.json` was generated at `2026-10-29T21:13:19+00:00` and records `on_battery=false`, so the Platform A environment check observed AC power for this benchmark run. Measurements remain local/in-process; AC power does not make them network measurements or a cross-device performance guarantee.

## Libraries and versions

| Library | Compatible requirement | Version in the current Python 3.13.17 environment |
|---|---|---|
| `cryptography` | `==50.0.2` (exact organizer pin) | `50.0.2` |
| `psutil` | `>=5.9` | `7.2.2` |
| `numpy` | `>=1.24` | `2.5.4` |
| `pandas` | `>=2.0` | `3.1.0` |
| `matplotlib` | `>=3.7` | `3.11.2` |

The analysis-package minimums are intentionally not exact pins: PyPI declares NumPy 2.5.4 as Python >=3.12, and pandas 3.1.0 plus matplotlib 3.11.2 as Python >=3.11. The lower bounds above let pip select compatible releases across the declared Python 3.11–3.13 range while preserving `cryptography==50.0.2`. The recorded Platform A environment used the versions shown in the last column; only Python 3.13.17 was exercised for this submission.

## Tests

| Purpose | Command | Expected output / evidence |
|---|---|---|
| Environment and primitive smoke tests | `python common/env_check.py` | `READY - environment is correct.` and `platform_A_info.json` |
| Provision endpoint identities and trust store | `python scripts/provision_identities.py` | local `identities/` files (git-ignored) and updated `trust_store.json` |
| T1–T9 wire-level security battery | `python -m tests.run_security_tests` | all 52 detailed checks pass; writes `results/security_tests.csv` and `results/security_tests_detailed.csv` |
| Regression vectors and replay-window rules | `python -m tests.test_regressions` | RFC 5869 vector/oracle and replay-window assertions pass |
| End-to-end PQC demo | `python -m cli.demo --suite QFF26-PQC-1` | metadata-only handshake, bidirectional transfer and authenticated-close output |

## Verification

On the recorded local run, the runner printed **`ALL TESTS PASSED: 52/52 detailed checks in 0.55s`**. The duration is measured at runtime and will vary; the stable pass criterion is `ALL TESTS PASSED: 52/52 detailed checks`.

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

## Intel-Mac note

`cryptography==50.0.2` is the organizer's fixed pin. On Intel macOS (x86_64), consult [the Intel Mac environment helper](scripts/QFF2026_intel_mac_env_setup.sh) before installing if pip cannot use a compatible wheel; the helper prepares the static OpenSSL environment documented in the script. The installed origin is recorded honestly in `platform_A_info.json`. Stock macOS `/usr/bin/python3` can be Python 3.9, which is below this repo's Python 3.11 minimum; use a supported interpreter and activate `.venv` before running commands.

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
scripts/make_figures.py            CSV-only reproducible figures
scripts/provision_identities.py   local identities (git-ignored) + public trust store
scripts/bootstrap_env.sh          optional Bash setup helper
scripts/QFF2026_intel_mac_env_setup.sh  Intel-Mac OpenSSL setup helper
docs/TECHNICAL_REPORT.md           full methodology, evidence and interpretation
docs/INTEGRATION_CONTRACT.md       finalized UX/protocol integration contract
results/                           committed CSV evidence and figures
data/payloads/payload_sha256.txt   official payload manifest (payload binaries generated locally)
Phase One/                        archived Phase 1 submission (large uploaded papers ZIP removed)
```
