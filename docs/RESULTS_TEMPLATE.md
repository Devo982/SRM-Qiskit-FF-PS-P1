# Results Report Template

> Replace all placeholders from generated results only. Do not hand-in this file as a final report while placeholders remain.

## Executive summary
- Implementation revision:
- ML-KEM standard mechanism / liboqs version:
- Platform A verification:
- Platform B verification:
- Principal measured finding:

## Methodology
- Protocol flow and exact operations included in handshake time:
- CPU/memory configurations and evidence of applied limits:
- Warmups, iterations, batches, quantile convention:
- RSS measurement method and limitations:
- Software versions and reproduction commands:

## Correctness and gate results
| Gate | Command | Result | Evidence |
|---|---|---|---|
| ECDH | | | |
| ML-KEM-768 | | | |
| Hybrid KDF/transcript | | | |
| Full integration | | | |
| Platform B constraints | | | |

## Performance results
| Platform | Suite | N | Success % | Median ms | p95 ms | p99 ms | Throughput handshakes/s |
|---|---|---:|---:|---:|---:|---:|---:|

## Payload size
| Suite | Responder → Initiator bytes | Initiator → Responder bytes | Total raw payload bytes | ML-KEM ciphertext bytes |
|---|---:|---:|---:|---:|

## Memory results
| Platform | Suite | Baseline RSS MiB | Sampled peak RSS MiB | Delta MiB | Sampling interval |
|---|---|---:|---:|---:|---|

## Interpretation
Discuss overhead and variance using generated data. Clearly separate single-worker latency from throughput, compute from network latency, and container-limited emulation from real constrained devices.

## Security and limitations
State that the baseline is unauthenticated and vulnerable to man-in-the-middle attacks; key confirmation alone does not authenticate identity. Mention native-library prototype limitations, platform-emulation limitations, NIST errata status consulted, and any unverified/blocked stage.

## Reproduction
Commands and immutable metadata required to reproduce all numbers and figures.
