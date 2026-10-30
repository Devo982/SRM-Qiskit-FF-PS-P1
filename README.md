# QFF 2026 Track 5 — SRM-Qiskit-FF-PS-P1

**Problem statement:** PS-P1 — Quantum-Safe Secure Communication Channel
**Challenge:** Qiskit Fall Fest 2026 · Track 5

- **Technical report:** [docs/TECHNICAL_REPORT.md](docs/TECHNICAL_REPORT.md)
- **Integration contract:** [docs/INTEGRATION_CONTRACT.md](docs/INTEGRATION_CONTRACT.md)
- **Security tests:** [SECURITY_TESTS.md](SECURITY_TESTS.md)

## Quick start

**Supported runtime:** Python 3.13 is the only supported version. Install Python 3.13 once before starting; Python 3.15 is not supported by this repository. The organizer dependency pin `cryptography==50.0.2` must remain unchanged. The setup below uses Python's built-in `venv` and `pip`; `uv` is not required.

### Fresh clone → install dependencies → run all checks and benchmarks

These are the complete commands, not just the final benchmark invocation. They clone the repository, create a clean virtual environment, install requirements, then run the environment check, T1–T9 security battery, TCP transport unit tests, both handshake suites, all three official payload cases, and figure generation. If any command fails, stop at that step and resolve the error before continuing.

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
.\.venv\Scripts\python.exe -m pip install -r requirements-lock.txt
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
.venv/bin/python3.13 -m pip install -r requirements-lock.txt &&
.venv/bin/python3.13 -c "import cryptography; print('cryptography', cryptography.__version__)" &&
.venv/bin/python3.13 scripts/run_reproducible_benchmarks.py --platform-label LOCAL
```

The `&&` chain stops if any step fails. **Already cloned the repository?** Start at your existing repository root and skip only `git clone` plus `Set-Location` / `cd`. Run the remaining commands from `py -3.13 --version` or `python3.13 --version` onward. These commands intentionally recreate `.venv`, so an old Python 3.15 environment is not reused; they do not remove source files or benchmark results.

**Expected success:** the runner ends with `Manifest status: passed` and prints the evidence directory and ZIP path under `results/runs/`. Use `LOCAL` on a teammate/organizer laptop. Use `A` only on the designated Platform A machine. `LOCAL` is not the official constrained Platform B profile.

### Run benchmarks again (environment already installed)

For later runs in an existing checkout with dependencies installed, use just this command from the repository root.

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

If Python 3.13 is missing, install a Python 3.13.x release from [Python Windows downloads](https://www.python.org/downloads/windows/), enable the Python Launcher, open a new PowerShell window, and repeat `py -3.13 --version`. Use Python 3.13 only; Python 3.11 and 3.12 are not supported by this pinned environment.

**macOS (Intel or Apple Silicon)**

```bash
python3.13 --version
```

If missing, install a Python 3.13.x release from [Python macOS downloads](https://www.python.org/downloads/macos/) and open a new Terminal window. Use the versioned `python3.13` command for setup.

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

Default benchmark settings are 100 handshake trials per suite and 15 bidirectional rounds per payload and suite. The runner supports `--handshake-runs` and `--payload-repeats` when longer or shorter trials are needed.

Timings are machine-dependent; reproducibility means the same procedure, checks, input payloads and evidence structure—not identical timing numbers across machines. The measurements in this project are **local/in-process, not real-network measurements**.

The one-command validation workflow runs the mandatory T1–T9 security battery and, after it passes, the 12 TCP transport unit tests. The command logs record both validation stages. The benchmark measurements themselves continue to use the existing in-process transport.

The runner writes its benchmark artifacts inside each run bundle. It does not use the committed `results/tables/*.csv`, `results/figures/*.png`, or root `platform_A_info.json` as output targets. Run bundles are ignored by Git so local measurements do not accidentally replace the submitted Platform A evidence.

## Security-only and diagnostic commands

The full benchmark command above is the recommended path. For diagnosis, these individual commands are also available from the repository root.

| Purpose | Windows (PowerShell) | macOS / Linux |
|---|---|---|
| Run T1–T9 + TCP transport tests | `.\.venv\Scripts\python.exe scripts/run_security_suite.py` | `.venv/bin/python scripts/run_security_suite.py` |
| Run TCP transport tests only | `.\.venv\Scripts\python.exe -m unittest -v tests.test_tcp_transport` | `.venv/bin/python -m unittest -v tests.test_tcp_transport` |
| Regression vectors and replay-window checks | `.\.venv\Scripts\python.exe -m tests.test_regressions` | `.venv/bin/python -m tests.test_regressions` |
| PQC in-process end-to-end demo | `.\.venv\Scripts\python.exe -m cli.demo --suite QFF26-PQC-1` | `.venv/bin/python -m cli.demo --suite QFF26-PQC-1` |

The security launcher verifies Alice/Bob test identity key pairs and the matching local test trust store at `identities/trust_store.test.json`. If local test identities or that store are missing or inconsistent, it repairs the local test material and then runs T1–T9. It does not modify the committed root `trust_store.json`.

The CLI demo also explicitly uses the generated local test trust store.

Expected validation output:

```text
ALL TESTS PASSED: 54/54 detailed checks

Ran 12 tests
OK
```

These are separate validation groups: 54 security checks and 12 TCP transport unit tests. They must not be represented as a combined 66-check security score.

The committed root `trust_store.json` is a public-only reference trust-store artifact. The automatically provisioned local tests and CLI demo use `identities/trust_store.test.json`, generated to match the local private Alice/Bob test identities in the same git-ignored directory. This generated test fixture is not an independently authenticated production trust bootstrap.

For a clean clone, run `python scripts/provision_identities.py` before directly invoking `python -m tests.run_security_tests` or `python -m cli.demo`; the security launcher provisions missing local test material automatically.

The test suite refreshes result CSVs, so inspect `git status --short` after diagnostic commands and do not commit generated changes unless the evidence was intentionally regenerated and reviewed. `common/env_check.py` writes `platform_A_info.json` by default; do not label metadata collected on a different laptop as Platform A.

## Separate-process TCP loopback demonstration

The optional TCP demonstration runs Alice and Bob as **separate Python processes** using the existing secure-channel façade.

Unlike the in-process demonstration, this runs one endpoint as a TCP server and the other as a TCP client. It reuses the existing cryptographic protocol and channel state machine. The transport layer is responsible only for delivering complete serialized protocol frames.

### Run the PQC suite

Open two terminal windows from the repository root.

**Terminal 1 — Bob/server**

macOS / Linux:

```bash
.venv/bin/python -m cli.tcp_demo --role server --suite QFF26-PQC-1
```

Windows (PowerShell):

```powershell
.\.venv\Scripts\python.exe -m cli.tcp_demo --role server --suite QFF26-PQC-1
```

Leave the server running.

**Terminal 2 — Alice/client**

macOS / Linux:

```bash
.venv/bin/python -m cli.tcp_demo --role client --suite QFF26-PQC-1
```

Windows (PowerShell):

```powershell
.\.venv\Scripts\python.exe -m cli.tcp_demo --role client --suite QFF26-PQC-1
```

The expected successful output includes:

```text
[client] mutual handshake complete; state=ESTABLISHED
[client] c2s application record sent
[client] s2c application record: bytes=55, match=True
[client] authenticated close record sent; state=CLOSED
```

The server should independently report:

```text
[server] TCP connection accepted
[server] mutual handshake complete; state=ESTABLISHED
[server] c2s application record: bytes=48, match=True
[server] s2c reply sent: bytes=55
[server] authenticated close received; state=CLOSED
```

### Run the classical suite

Repeat the same two-terminal procedure, replacing `QFF26-PQC-1` with `QFF26-CLASSICAL-1` in both commands.

The local test identities and matching `identities/trust_store.test.json` must exist before starting either endpoint. Run `scripts/run_security_suite.py` first on a fresh checkout to provision and validate the required local test material.

### TCP framing design

The TCP adapter is implemented in `protocol/tcp_wire.py`.

Each serialized protocol frame is transmitted using this transport envelope:

```text
4-byte unsigned big-endian frame length || serialized protocol frame
```

The length prefix allows the receiving endpoint to reconstruct individual frames from TCP's continuous byte stream. The receiver reads the exact header and body, handling TCP fragmentation and multiple frames arriving in the same stream read.

The default maximum frame size is 16 MiB.

The four-byte length prefix is a **transport envelope**, not part of the cryptographic protocol TLV format, handshake transcript, or signature input. The original protocol channel state machine and `InMemoryWire` remain unchanged.

The demonstration uses `127.0.0.1:8765` by default and a 30-second connection timeout. It performs a local loopback connection on one machine.

**Scope:** this is a functional separate-process TCP demonstration, not a two-device network experiment or network performance benchmark. It does not measure network RTT, packet loss, congestion, or deployment performance. The application payloads in this demo are small fixed messages; the official 1 KB, 100 KB and 10 MB payload benchmarks remain in-process measurements.

## Protocol and security summary

PS-P1 implements a **mutually authenticated** secure channel behind a shared channel state machine:

- **Post-quantum suite `QFF26-PQC-1`:** ML-KEM-768 (FIPS 203), ML-DSA-65 (FIPS 204), HKDF-SHA256 and AES-256-GCM.
- **Classical comparison `QFF26-CLASSICAL-1`:** X25519 and Ed25519 using the same HKDF-SHA256 key schedule and AES-256-GCM record layer.
- **Identity model:** Alice/Bob verification keys are authenticated by the local trust store; a peer-provided, untrusted public key is not accepted as a trust anchor.
- **Transcript protection:** signatures bind the endpoint identities, roles/session context, selected algorithms and exchanged handshake material. Each direction derives a separate traffic key.
- **Replay/tampering behavior:** record replay and handshake replay are tested; modified handshake data, invalid signatures, modified ciphertext/tags, identity swaps and algorithm downgrade attempts must be rejected before untrusted plaintext is released.
- **Suite selection:** suite policy is local to both endpoints; the protocol does not negotiate suites on the wire.
- **Transport:** the optional TCP endpoint transports the existing serialized protocol frames without changing the cryptographic protocol or channel state machine.

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
| T9 | Unknown suite identifier, suite-echo substitution, or valid alternate suite conflicting with server local policy | Rejected by policy; no silent fallback |

The detailed test output documents the exact observed failure for each case. Replay-cache persistence across process restarts and deployment-wide trust-store operations are outside the guarantees of this prototype.

### TCP transport unit tests

The additional transport tests are in `tests/test_tcp_transport.py`.

They verify:

- Four-byte big-endian frame-length encoding.
- Reconstruction of frames when TCP data arrives in fragmented reads.
- Receiving multiple frames from a continuous byte stream.
- Clean EOF handling.
- Rejection of incomplete headers and frame bodies.
- Rejection of zero-length and oversized frames.
- Validation of configured maximum frame size.
- A real local socket-pair round trip.

These are transport tests. They do not replace or increase the 54 detailed T1–T9 security checks.

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

The TCP loopback demonstration is not included in these benchmark figures.

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

**The TCP loopback demonstration does not qualify as Platform D evidence.** It runs both endpoints on the same machine through `127.0.0.1`. Platform D should only be marked as used after a justified deployment constraint has actually been applied and measured, with reproducible evidence.

## Dependencies

`requirements.txt` defines the direct project dependencies and preserves the organizer's exact cryptographic pin. `requirements-lock.txt` is generated from it with `uv`, pins resolved dependency versions and includes hashes. The README setup commands install from `requirements-lock.txt` for reproducible dependency resolution; do not treat the two files as interchangeable.

| Package | Direct requirement |
|---|---|
| `cryptography` | `==50.0.2` |
| `psutil` | `==7.2.2` |
| `numpy` | `==2.5.4` |
| `pandas` | `==3.1.0` |
| `matplotlib` | `==3.11.2` |

The recorded Platform A environment used Python 3.13.17, cryptography 50.0.2, psutil 7.2.2, NumPy 2.5.4, pandas 3.1.0 and matplotlib 3.11.2. Python 3.13.17 is the interpreter version exercised for the committed Platform A results; Python 3.13 is the only supported runtime for this submission.

## Known limitations

- This is a competition prototype, not a production security certification.
- The handshake and payload timings use a local in-process wire; no two-machine network latency, packet loss, congestion or deployment benchmark has been collected.
- The TCP demonstration is a same-machine loopback functional test, not a two-device network deployment.
- Automatic renegotiation after `SessionExhausted` is not implemented; a fresh session needs a new handshake.
- Python key zeroization is best-effort; Python's object and memory model cannot guarantee complete erasure.
- Trust-store distribution, integrity, rotation and revocation are out-of-band and not solved here.
- The prototype assumes a single trust domain; denial-of-service resistance and side-channel hardening are out of scope.
- Each application payload is sent as one protocol record; application-level chunking is not implemented. The TCP transport does handle fragmentation and coalescing of bytes in the underlying TCP stream when reconstructing length-prefixed frames.
- The TCP demonstration currently uses a fixed local host and port by default; it is not a production server or deployment configuration.

## Troubleshooting

- **`Python 3.15 not supported`:** the `.venv` was created with an unsupported interpreter. Follow setup steps above to install/find Python 3.13 and recreate `.venv`. Reinstalling packages into the old Python 3.15 environment will not fix the version guard. Do not remove the guard without validating the dependency stack and complete workflow on another version.
- **`No matching distribution` or `cryptography==50.0.2` will not install:** verify that the virtual environment uses Python 3.13 and that `requirements.txt` retains the organizer pin. On Intel macOS (x86_64) only, if a compatible wheel cannot be installed, see the [Intel Mac environment helper](scripts/QFF2026_intel_mac_env_setup.sh); it is not a general Windows, Linux or Apple Silicon setup path.
- **Wrong Python still runs:** check `.venv/bin/python --version` on macOS/Linux or `.\.venv\Scripts\python.exe --version` in PowerShell, from the repository root. Always use the interpreter inside `.venv`.
- **`uv` not found:** it is optional. Use the `venv` and `pip` setup commands above.
- **TCP server connection refused:** start the server command before running the client; verify both processes use the same host and port.
- **TCP address already in use:** check whether an earlier TCP demo server is still running. Stop that process before starting another server on the same port.
- **TCP test identity material missing:** run `scripts/run_security_suite.py` to provision and validate local Alice/Bob identities and `identities/trust_store.test.json`.
- **Local files changed after tests:** inspect `git status --short`. Keep generated run bundles, the git-ignored `identities/` directory (private test keys and `trust_store.test.json`), local machine metadata and unreviewed result CSV changes out of the source commit. Local test provisioning does not rewrite the committed root `trust_store.json`.

## Repository layout

```text
common/env_check.py                    environment contract and primitive self-test
protocol/                               TLV, suites, key schedule, record layer, state machines
protocol/tcp_wire.py                    synchronous TCP frame transport
cli/adapter.py                           UX facade / integration boundary
cli/demo.py                              metadata-only in-process end-to-end demo
cli/tcp_demo.py                          separate-process TCP loopback demonstration
tests/run_security_tests.py              T1–T9 fault-injection tests
tests/test_tcp_transport.py              TCP framing and socket transport unit tests
tests/test_regressions.py                 HKDF vectors and replay-window regressions
bench/bench_handshake.py                 handshake latency, serialized sizes, raw samples
bench/bench_payload.py                   payload encryption/decryption timing and throughput
scripts/run_security_suite.py             identity repair + T1–T9 + TCP transport test launcher
scripts/run_reproducible_benchmarks.py    one-command validation and isolated evidence bundle
scripts/make_figures.py                   figures from CSV inputs
scripts/provision_identities.py           local test identities + identities/trust_store.test.json
docs/TECHNICAL_REPORT.md                  methodology, evidence and analysis
docs/INTEGRATION_CONTRACT.md               UX/protocol integration contract
results/                                  committed CSV evidence and figures
data/payloads/payload_sha256.txt           official payload SHA-256 manifest
Phase One/                                archived Phase 1 submission material
```

## Team members and submission contact

| Role | Name | Contact |
|---|---|---|
| Primary repository contact | Vasisht Hire | [Devo982/SRM-Qiskit-FF-PS-P1](https://github.com/Devo982/SRM-Qiskit-FF-PS-P1.git) |

Registered team members: Devansh Joshi and Vasisht Hire. Add any organizer-required contact details before final submission.
