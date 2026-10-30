# Platform D — Two-device real-link experiment

## What this experiment establishes

Platform D is a deployment-constraint experiment, not another localhost test. It runs Alice and Bob on two physical devices connected over a real private Wi-Fi/LAN link. It records each endpoint's hardware/software metadata, ICMP RTT and loss in both directions, TCP connection setup time, secure-channel handshake elapsed time, application round-trip time, and round-trip application goodput.

The experiment runs both `QFF26-PQC-1` and `QFF26-CLASSICAL-1` with matching session counts, payload sizes and rounds. TCP and ICMP measurements are reported separately. ICMP packet loss must not be described as TCP packet loss.

## Safety and identity handling

- Use a private, trusted LAN only. Do not port-forward TCP 8766 to the public Internet or run this test on an untrusted public Wi-Fi network.
- Provision test identities on the primary machine using `scripts/run_security_suite.py`.
- The Alice/client device needs `identities/alice.json` and the matching public `identities/trust_store.test.json`.
- The Bob/server device needs `identities/bob.json` and the same `identities/trust_store.test.json`.
- Transfer `bob.json` to Bob using encrypted USB or authenticated encrypted file transfer. Transfer the public test trust store to Bob as well. Do not copy Alice's private identity to Bob. Never commit anything under `identities/`.
- Do not run `scripts/provision_identities.py` independently on Bob after copying the files; that would create a different trust store. The test trust store must match Alice's and Bob's private identities.

## Prerequisites

Both devices must have:

- the same project commit/branch;
- Python 3.13 and the locked project dependencies;
- the role-specific private identity and matching `identities/trust_store.test.json`;
- network reachability between the two LAN IP addresses.

The second device can be another laptop or a small computer. Record its actual hardware; do not label an ordinary second laptop as the official Platform B profile.

## 1. Create matching test material on Alice's device

On Alice's device, from the repository root:

```bash
.venv/bin/python scripts/run_security_suite.py
```

This provisions or verifies the local test keys and the matching `identities/trust_store.test.json`.

Securely transfer only these two files to Bob's device:

```text
identities/bob.json
identities/trust_store.test.json
```

On Bob's device, place them in its repository's `identities/` directory. Do not run provisioning on Bob after this transfer.

## 2. Validate both endpoint environments

Create the evidence directory on each device:

```bash
mkdir -p results/platform_d
```

On Alice's device:

```bash
.venv/bin/python common/env_check.py --platform-label D --output results/platform_d/environment_alice.json
```

On Bob's device (adjust the interpreter path if its virtual environment differs):

```bash
.venv/bin/python common/env_check.py --platform-label D --output results/platform_d/environment_bob.json
```

Retain the JSON files. The `D` label records the machine's actual environment; it does not by itself prove the network experiment succeeded.

## 3. Measure the real link in both directions

Choose a shared run ID, for example `D_20261030_WIFI01`. Use exactly the same run ID throughout this experiment.

Find the LAN IP address of each device. On macOS Wi-Fi, `ipconfig getifaddr en0` often reports it; on Windows use `ipconfig`; on Linux use `hostname -I` or `ip addr`.

From Alice, probe Bob:

```bash
.venv/bin/python scripts/platform_d_probe.py --peer <BOB_LAN_IP> --direction alice_to_bob --run-id D_20261030_WIFI01
```

From Bob, probe Alice:

```bash
.venv/bin/python scripts/platform_d_probe.py --peer <ALICE_LAN_IP> --direction bob_to_alice --run-id D_20261030_WIFI01
```

Each probe sends 30 ICMP echo requests and writes both parsed JSON metrics and raw ping output under `results/platform_d/`. If ICMP is blocked, the probe will report that it could not parse a packet summary; do not report this as 0% loss. TCP may still be reachable even if ICMP is filtered.

## 4. Run the PQC experiment

Use the same configuration on both devices: 5 sessions, 2 rounds per payload size, and 1 KB / 100 KB / 10 MB payloads. Each client sample times a request and an encrypted echo response; round-trip goodput is calculated from the plaintext bytes transferred in both directions divided by the measured round-trip time.

On Bob (server), start this first:

```bash
.venv/bin/python -m cli.platform_d --role server --suite QFF26-PQC-1 --run-id D_20261030_WIFI01 --bind-host 0.0.0.0 --port 8766 --sessions 5 --rounds 2 --payload-sizes 1024,102400,10485760
```

On Alice (client), while Bob is listening:

```bash
.venv/bin/python -m cli.platform_d --role client --suite QFF26-PQC-1 --run-id D_20261030_WIFI01 --host <BOB_LAN_IP> --port 8766 --sessions 5 --rounds 2 --payload-sizes 1024,102400,10485760
```

The server must accept 5 connections. The client should report 5/5 successful sessions, handshake statistics, and RTT/goodput statistics for all three payload sizes. The server should report 5/5 and all application records verified.

## 5. Run the classical comparison

Repeat the same process, changing only the suite to `QFF26-CLASSICAL-1` on both devices. Keep the run ID, sessions, rounds, payload sizes, network path and device roles identical.

## 6. Evidence files

The transport experiment writes one JSON file per endpoint and suite:

```text
results/platform_d/D_20261030_WIFI01_QFF26-PQC-1_client.json
results/platform_d/D_20261030_WIFI01_QFF26-PQC-1_server.json
results/platform_d/D_20261030_WIFI01_QFF26-CLASSICAL-1_client.json
results/platform_d/D_20261030_WIFI01_QFF26-CLASSICAL-1_server.json
```

The network probes and environment checks produce additional JSON and raw `.txt` files. Copy Bob's output files back to Alice's results directory after both suites finish. Do not transfer or commit private identity files.

Review the following before claiming a successful Platform D run:

1. Both environment checks pass and identify the actual devices/software.
2. Both directional ping probes contain parsed packet counts and measured RTT/loss, or ICMP filtering is explicitly documented.
3. Both suites complete all 5 handshakes on the two devices.
4. Every payload echo matches; no session, framing or authentication errors occur.
5. Client and server JSON agree on run ID, suite and configuration.
6. The report distinguishes ICMP loss from TCP application failures and does not compare TCP handshake elapsed time directly with the previous in-process benchmark as if they were the same measurement.

Platform D should only be changed from `Not used` after real two-device results have been reviewed. Do not invent a latency/loss constraint if the measured network is unconstrained; report the actual RTT and loss.
