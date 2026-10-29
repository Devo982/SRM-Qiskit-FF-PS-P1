# QFF 2026 Track 5 — SRM-Qiskit-FF-PS-P1

**Problem statement:** PS-P1 — Quantum-Safe Secure Communication Channel
**Challenge:** Qiskit Fall Fest 2026 · Track 5

- **Technical report:** [docs/TECHNICAL_REPORT.md](docs/TECHNICAL_REPORT.md)
- **Integration contract:** [docs/INTEGRATION_CONTRACT.md](docs/INTEGRATION_CONTRACT.md)

## Quick start

**Supported runtime:** Python 3.13 is the only supported version. Install Python 3.13 once before starting; Python 3.15 is not supported by this repository. The organizer dependency pin `cryptography==50.0.2` must remain unchanged. The setup below uses Python's built-in `venv` and `pip`; `uv` is not required.

### Fresh clone → install dependencies → run all checks and benchmarks

These are the complete commands, not just the final benchmark invocation. They clone the repo, create a clean virtual environment, install requirements, then run the environment check, T1–T9, both handshake suites, all three official payload cases, and figure generation. If any command fails, stop at that step and resolve the error before continuing.

**Windows (PowerShell)**

Run in PowerShell where Python 3.13 is installed through the Python Launcher:

```powershell
git clone https://github.com/Devo982/SRM-Qiskit-FF-PS-P1.git
if ($LASTEXITCODE -ne 0) { throw "git clone failed" }
Set-Location SRM-Qiskit-FF-PS-P1
py -3.13 --version
if ($LASTEXITCODE -ne 0) { throw "Install Python 3.13 first; see the Python installation section below." }
if (Test-Path .venv) { Remove-Item -Recurse -Force .venv }
py -3.13 -m venv .venv
if ($LASTEXITCODE -ne 0) { throw "Creating the virtual environment failed" }
.\.venv\Scripts\python.exe -m pip install --upgrade pip
if ($LASTEXITCODE -ne 0) { throw "Upgrading pip failed" }
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
if ($LASTEXITCODE -ne 0) { throw "Installing requirements failed" }
.\.venv\Scripts\python.exe -c "import cryptography; print('cryptography', cryptography.__version__)"
if ($LASTEXITCODE -ne 0) { throw "cryptography import check failed" }
.\.venv\Scripts\python.exe scripts/run_reproducible_benchmarks.py --platform-label LOCAL
if ($LASTEXITCODE -ne 0) { throw "Reproducible benchmark run failed; inspect the run logs" }
```

**macOS / Linux (Bash or Zsh)**

Run from the directory where you want the repository cloned, with `python3.13` installed:

```bash
git clone https://github.com/Devo982/SRM-Qiskit-FF-PS-P1.git &&
cd SRM-Qiskit-FF-PS-P1 &&
python3.13 --version &&
( [ ! -d .venv ] || rm -rf .venv ) &&
python3.13 -m venv .venv &&
.venv/bin/python3.13 -m pip install --upgrade pip &&
.venv/bin/python3.13 -m pip install -r requirements.txt &&
.venv/bin/python3.13 -c "import cryptography; print('cryptography', cryptography.__version__)" &&
.venv/bin/python3.13 scripts/run_reproducible_benchmarks.py --platform-label LOCAL
```

The `&&` chain stops if any step fails. **Already cloned the repository?** Start at your existing repository root and skip only `git clone` plus `Set-Location` / `cd`. Run the remaining commands from `py -3.13 --version` or `python3.13 --version` onward. These commands intentionally recreate `.venv`, so an old Python 3.15 environment is not reused; they do not remove source files or benchmark results.

**Expected success:** the runner ends with `Manifest status: passed` and prints the evidence directory and ZIP path under `results/runs/`. Use `LOCAL` on a teammate/organizer laptop. Use `A` only on the designated Platform A machine. `LOCAL` is not the official constrained Platform B profile.

### Run benchmarks again (environment already installed)

For later runs in an existing checkout with dependencies installed, use just this command from the repository root:

**Windows (PowerShell)**

```powershell
.\.venv\Scripts\python.exe scripts/run_reproducible_benchmarks.py --platform-label LOCAL
```

**macOS / Linux**

```bash
.venv/bin/python3.13 scripts/run_reproducible_benchmarks.py --platform-label LOCAL
```

### Install or locate Python 3.13

Use an explicitly versioned interpreter; do not assume `python`, `python3`, or `py` chooses a supported version.

**Windows (PowerShell)**

```powershell
py -0p
py -3.13 --version
```

If Python 3.13 is missing, install a Python 3.13.x release from [Python's Windows downloads](https://www.python.org/downloads/windows/), enable the Python Launcher, open a new PowerShell window, and repeat `py -3.13 --version`. Python 3.12 or 3.11 may also be used with the matching launcher command.

**macOS (Intel or Apple Silicon)**

```bash
python3.13 --version
```

If missing, install a Python 3.13.x release from [Python's macOS downloads](https://www.python.org/downloads/macos/) and open a new Terminal window. Use the versioned `python3.13` command for setup.

**Linux**

```bash
command -v python3.13
python3.13 --version
```

If missing, install Python 3.13 and its `venv` support through your distribution's supported package source. Package names vary by distribution; see the [official Python Unix/Linux documentation](https://docs.python.org/3/using/unix.html). Do not replace the operating system's system Python.

## What the one-command run produces

Each run creates a unique directory and matching ZIP in `results/runs/`. The bundle includes:

- OS, CPU, memory, Python and dependency metadata;
- exact command logs and the Git revision recorded for the run;
- T1–T9 result snapshots;
- PQC and classical handshake summary CSVs and raw successful-trial timings;
- results for the official 1 KB, 100 KB and 10 MB payloads, including SHA-256 validation;
- figures rendered from that run's own CSVs;
- a manifest and SHA-256 hashes for bundle artifacts.

Default benchmark settings are 100 handshake trials per suite and 15 bidirectional rounds per payload and suite. The runner supports `--handshake-runs` and `--payload-repeats` when longer or shorter trials are needed. Timings are machine-dependent; reproducibility means the same procedure, checks, input payloads and evidence structure—not identical timing numbers across machines. The measurements in this project are **local/in-process, not real-network measurements**.

The runner writes its benchmark artifacts inside each run bundle. It does not use the committed `results/tables/*.csv`, `results/figures/*.png`, or root `platform_A_info.json` as output targets. Run bundles are ignored by Git so local measurements do not accidentally replace the submitted Platform A evidence.

## Security-only and diagnostic commands

The full benchmark command above is the recommended path. For diagnosis, these individual commands are also available from the repository root.

| Purpose | Windows (PowerShell) | macOS / Linux |
|---|---|---|
| Run T1–T9 only | `.\.venv\Scripts\python.exe scripts/run_security_suite.py` | `.venv/bin/python scripts/run_security_suite.py` |
| Regression vectors and replay-window checks | `.\.venv\Scripts\python.exe -m tests.test_regressions` | `.venv/bin/python -m tests.test_regressions` |
| PQC end-to-end demo | `.\.venv\Scripts\python.exe -m cli.demo --suite QFF26-PQC-1` | `.venv/bin/python -m cli.demo --suite QFF26-PQC-1` |

The security launcher verifies Alice/Bob test identity key pairs and the local trust store, repairs missing or inconsistent local test identities when needed, and then runs T1–T9. Separate provisioning is not normally needed. The expected success line is `ALL TESTS PASSED: 52/52 detailed checks`; elapsed time varies by machine.

Provisioning can regenerate local `trust_store.json`; do not commit that local test file. The test suite refreshes result CSVs, so inspect `git status --short` after diagnostic commands and do not commit generated changes unless the evidence was intentionally regenerated and reviewed. `common/env_check.py` writes `platform_A_info.json` by default; do not label metadata collected on a different laptop as Platform A.

## Protocol and security summary

PS-P1 implements a **mutually authenticated** secure channel behind a shared channel state machine:

- **Post-quantum suite `QFF26-PQC-1`:** ML-KEM-768 (FIPS 203), ML-DSA-65 (FIPS 204), HKDF-SHA256 and AES-256-GCM.
- **Classical comparison `QFF26-CLASSICAL-1`:** X25519 and Ed25519 using the same HKDF-SHA256 key schedule and AES-256-GCM record layer.
- **Identity model:** Alice/Bob verification keys are authenticated by the local trust store; a peer-provided, untrusted public key is not accepted as a trust anchor.
- **Transcript protection:** signatures bind the endpoint identities, roles/session context, selected algorithms and exchanged handshake material. Each direction derives a separate traffic key.
- **Replay/tampering behavior:** record replay and handshake replay are tested; modified handshake data, invalid signatures, modified ciphertext/tags, identity swaps and algorithm downgrade attempts must be rejected before untrusted plaintext is released.
- **Suite selection:** suite policy is local to both endpoints; the protocol does not negotiate suites on the wire.

This is a competition prototype, **not a production secure-channel implementation or production security certification**.

### Mandatory T1–T9 tests

| ID | Scenario | Expected behavior |
|---|---|---|
| T1 | Honest handshake and the 1 KB, 100 KB and 10 MB official payloads in both directions | Both endpoints establish; all six payload transfers match byte-for-byte and by SHA-256; authenticated close succeeds |
| T2 | Bit flips in exchanged key material, nonces, identities, version or suite identifier | Handshake aborts at the owning validation step; no traffic keys are established |
| T3 | Signature tampering | Rejected with authentication failure |
| T4 | Application-record ciphertext tampering | Rejected; plaintext withheld |
| T5 | GCM tag and authenticated-header tampering | Invalid tag or structural/transcript rejection; plaintext withheld |
| T6 | Attacker's own valid key and signature but untrusted identity | Rejected at trust-store lookup |
| T7 | Identity/role swap or signature reused from another session | Rejected through identity and transcript binding |
| T8 | Record replay, old-session replay and repeated first-handshake message | Rejected by replay detection, handshake authentication or freshness cache |
| T9 | Unknown suite identifier or valid-suite substitution | Rejected by policy; no silent fallback |

The detailed test output documents the exact observed failure for each case. Replay-cache persistence across process restarts and deployment-wide trust-store operations are outside the guarantees of this prototype.

## Reference Platform A results

The committed Platform A results are from run `20261029T211325Z`. They are local/in-process observations, not network latency or guarantees for other machines.

| Metric | PQC: ML-KEM-768 + ML-DSA-65 | Classical: X25519 + Ed25519 |
|---|---:|---:|
| Handshake median | 2.883 ms | 0.738 ms |
| Handshake IQR | 1.236 ms | 0.048 ms |
| Handshake p95 | 5.186 ms | 0.885 ms |
| Total serialized handshake bytes | 9,134 B | 448 B |
| Successful handshakes | 100/100 | 100/100 |
| Transmitted record overhead | 32 B | 32 B |

The official payload benchmark includes encrypt/decrypt timing, wire-record size, overhead and SHA-256 results for each of the three payloads. See the CSVs linked below for the underlying values; the CSVs are the source of truth and should not be hand-edited.

## Result files

- [Technical report](docs/TECHNICAL_REPORT.md)
- [Integration contract](docs/INTEGRATION_CONTRACT.md)
- [Organizer security summary](results/security_tests.csv)
- [Detailed T1–T9 checks](results/security_tests_detailed.csv)
- [Handshake summary results](results/tables/handshake_results.csv)
- [Handshake message sizes and benchmark details](results/tables/bench_handshake.csv)
- [Raw successful handshake timings](results/tables/handshake_raw_samples.csv)
- [Payload encryption/decryption results](results/tables/payload_results.csv)
- [Payload throughput](results/tables/bench_payload.csv)
- [Handshake latency figure](results/figures/handshake_latency.png)
- [Handshake message sizes figure](results/figures/handshake_message_bytes.png)
- [10 MB payload timing figure](results/figures/payload_10mb_timing.png)
- [Official payload SHA-256 manifest](data/payloads/payload_sha256.txt)
- [Platform A environment metadata](platform_A_info.json)

## Platforms recorded

| Label | Description | Status |
|---|---|---|
| A | Intel Core i5-8257U, 4 physical / 8 logical cores, 8 GB RAM, macOS 15.8.2, x86_64 | Reference results recorded; environment metadata observed `on_battery=false` |
| B | Official constrained profile: 1 effective CPU core, single-threaded libraries, 128 MB memory budget | Not run; do not claim B results until the official profile has been applied and measured |
| D | A justified deployment constraint, such as real-link latency/loss or a slower second device | Not used |
| LOCAL | Additional teammate/organizer machine, using its actual environment metadata | Use the one-command runner to create a separate portability/evidence bundle |

An ordinary teammate laptop should be labelled `LOCAL`, not Platform B. Platform A figures remain separate and should not be overwritten by runs on other computers.

## Dependencies

`requirements.txt` is authoritative for installation. The key cryptographic dependency is the exact organizer pin `cryptography==50.0.2`. Current compatible bounds for the analysis/benchmark libraries are:

| Package | Requirement |
|---|---|
| `cryptography` | `==50.0.2` |
| `psutil` | `>=5.9` |
| `numpy` | `>=1.24` |
| `pandas` | `>=2.0` |
| `matplotlib` | `>=3.7` |

The recorded Platform A environment used Python 3.13.17, cryptography 50.0.2, psutil 7.2.2, NumPy 2.5.4, pandas 3.1.0 and matplotlib 3.11.2. Python 3.13.17 is the interpreter version exercised for the committed Platform A results; declared compatibility with Python 3.11–3.12 should not be confused with identical performance measurements.

## Known limitations

- This is a competition prototype, not a production security certification.
- The handshake and payload timings use a local in-process wire; no two-machine network latency, packet loss, congestion or deployment benchmark has been collected.
- Automatic renegotiation after `SessionExhausted` is not implemented; a fresh session needs a new handshake.
- Python key zeroization is best-effort; Python's object and memory model cannot guarantee complete erasure.
- Trust-store distribution, integrity, rotation and revocation are out-of-band and not solved here.
- The prototype assumes a single trust domain; denial-of-service resistance and side-channel hardening are out of scope.
- Each payload is sent as one record; chunking and fragmentation are not implemented.

## Troubleshooting

- **`Python 3.15 not supported`:** the `.venv` was created with an unsupported interpreter. Follow setup steps 2–3 to install/find Python 3.13 and recreate `.venv`. Reinstalling packages into the old Python 3.15 environment will not fix the version guard. Do not remove the guard without validating the dependency stack and complete workflow on another version.
- **`No matching distribution` or `cryptography==50.0.2` will not install:** verify that the virtual environment is using Python 3.11–3.13 and that `requirements.txt` retains the organizer pin. On Intel macOS (x86_64) only, if a compatible wheel cannot be installed, see the [Intel Mac environment helper](scripts/QFF2026_intel_mac_env_setup.sh); it is not a general Windows, Linux or Apple Silicon setup path.
- **Wrong Python still runs:** check `.venv/bin/python --version` on macOS/Linux or `.\.venv\Scripts\python.exe --version` in PowerShell, from the repository root. Always use the interpreter inside `.venv`.
- **`uv` not found:** it is optional. Use the `venv` and `pip` setup commands above.
- **Local files changed after tests:** inspect `git status --short`. Keep generated run bundles, regenerated `trust_store.json`, local machine metadata and unreviewed result CSV changes out of the source commit.

## Repository layout

```text
common/env_check.py                 environment contract and primitive self-test
protocol/                           TLV, suites, key schedule, record layer, state machines
cli/adapter.py                      UX facade / integration boundary
cli/demo.py                         metadata-only end-to-end demo
tests/run_security_tests.py         T1–T9 fault-injection tests
tests/test_regressions.py           HKDF vectors and replay-window regressions
bench/bench_handshake.py            handshake latency, serialized sizes, raw samples
bench/bench_payload.py              payload encryption/decryption timing and throughput
scripts/run_security_suite.py       identity repair + T1–T9 test launcher
scripts/run_reproducible_benchmarks.py  one-command validation and isolated evidence bundle
scripts/make_figures.py             figures from CSV inputs
scripts/provision_identities.py     local test identities and public trust store
docs/TECHNICAL_REPORT.md            methodology, evidence and analysis
docs/INTEGRATION_CONTRACT.md        UX/protocol integration contract
results/                            committed CSV evidence and figures
data/payloads/payload_sha256.txt    official payload SHA-256 manifest
Phase One/                          archived Phase 1 submission material
```

## Team members and submission contact

| Role | Name | Contact |
|---|---|---|
| Primary repository contact | Vasisht Hire | [Devo982/SRM-Qiskit-FF-PS-P1](https://github.com/Devo982/SRM-Qiskit-FF-PS-P1) |

The supplied repository snapshot did not identify the complete registered team roster. Add the actual names and contacts of all other registered members before final submission; no teammate names have been inferred or invented.
