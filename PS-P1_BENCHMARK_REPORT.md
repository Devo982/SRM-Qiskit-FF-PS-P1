\# PS-P1: Hybrid Key Exchange Benchmark Report



\## 1. Executive Summary



This experiment benchmarks three key-exchange modes:



\- ECDH using P-256

\- ML-KEM-768

\- Hybrid ECDH + ML-KEM-768



Two environments were evaluated:



\- Platform A: Windows baseline environment.

\- Platform B: Linux container constrained to 1 CPU and 512 MiB memory.



Both full runs passed. Each suite completed 5,000 measured handshakes per platform, resulting in 15,000 successful measured handshakes per platform and zero failures.



These are local implementation benchmarks. They do not measure a complete network handshake or establish production-grade cryptographic security.



\## 2. Methodology



| Parameter | Value |

|---|---|

| Measured iterations per batch | 1,000 |

| Batches per suite | 5 |

| Measured handshakes per suite | 5,000 |

| Warm-up handshakes per suite | 100 |

| Suites | ECDH, ML-KEM-768, hybrid |

| Memory sampling | Separate subprocess, periodic RSS sampling |

| Memory sampling interval | 2 ms |

| Memory probe repetitions | 100 |

| Memory probe warm-up | 10 |



The benchmark records median, P95 and P99 latency, mean latency, latency standard deviation, throughput, payload size and sampled process memory.



Timing excludes network transport and library cold-start unless separately measured. Sampled RSS increases are not exact memory allocation sizes.



\## 3. Platform A: Windows Baseline



Run ID: `A\_20261016T085819Z\_e1ac3c92`



Platform verification: PASS



Environment:

\- OS: Windows 11

\- Architecture: AMD64

\- Python: 3.13.16

\- Physical CPUs reported: 4

\- Logical CPUs reported: 8

\- Total system memory reported: approximately 17.01 GB

\- liboqs: 0.16.0

\- liboqs-python: 0.16.0.1

\- Native library: locally installed Windows Release build



\### Results



| Suite | Successful | Median (ms) | P95 (ms) | P99 (ms) | Throughput (/s) | Payload (bytes) |

|---|---:|---:|---:|---:|---:|---:|

| ECDH | 5000/5000 | 0.2965 | 0.401205 | 0.615006 | 3062.77 | 130 |

| ML-KEM-768 | 5000/5000 | 0.2289 | 0.276000 | 0.349410 | 4050.00 | 2272 |

| Hybrid | 5000/5000 | 0.4956 | 0.563205 | 0.681606 | 1908.16 | 2402 |



\### Sampled Memory



| Suite | Baseline RSS (bytes) | Sampled Peak Delta (bytes) |

|---|---:|---:|

| ECDH | 29487104 | 114688 |

| ML-KEM-768 | 36052992 | 45056 |

| Hybrid | 37433344 | 45056 |



\### Evidence Files



\- `data/raw/benchmark\_A\_20261016T085819Z\_e1ac3c92.csv`

\- `results/tables/summary\_A\_20261016T085819Z\_e1ac3c92.csv`

\- `results/tables/memory\_A\_20261016T085819Z\_e1ac3c92.csv`

\- `results/tables/run\_manifest\_A\_20261016T085819Z\_e1ac3c92.json`



\## 4. Platform B: Constrained Linux Emulation



Run ID: `B\_20261016T094830Z\_70cc04e8`



Platform verification: PASS



Enforced resource limits:

\- CPU quota: 1 CPU

\- Memory limit: 536870912 bytes (512 MiB)

\- Swap: included in the 512 MiB cap

\- Limit detection: Linux cgroup v2



Environment:

\- OS: Linux under WSL 2

\- Architecture: x86\_64

\- Python: 3.13.16

\- GCC: 12.2.0

\- liboqs: 0.16.0

\- liboqs-python: 0.16.0.1



The container is a constrained emulation running on the same physical machine, not a separate embedded device.



\### Results



| Suite | Successful | Median (ms) | P95 (ms) | P99 (ms) | Throughput (/s) | Payload (bytes) |

|---|---:|---:|---:|---:|---:|---:|

| ECDH | 5000/5000 | 0.256715 | 0.407258 | 0.640746 | 3353.80 | 130 |

| ML-KEM-768 | 5000/5000 | 0.128007 | 0.171715 | 0.255169 | 6806.55 | 2272 |

| Hybrid | 5000/5000 | 0.384720 | 0.480545 | 0.734869 | 2363.70 | 2402 |



\### Sampled Memory



| Suite | Baseline RSS (bytes) | Sampled Peak Delta (bytes) |

|---|---:|---:|

| ECDH | 30150656 | 176128 |

| ML-KEM-768 | 34267136 | 212992 |

| Hybrid | 35618816 | 81920 |



\### Evidence Files



\- `data/raw/benchmark\_B\_20261016T094830Z\_70cc04e8.csv`

\- `results/tables/summary\_B\_20261016T094830Z\_70cc04e8.csv`

\- `results/tables/memory\_B\_20261016T094830Z\_70cc04e8.csv`

\- `results/tables/run\_manifest\_B\_20261016T094830Z\_70cc04e8.json`



\## 5. Payload Comparison



| Mode | Responder-to-Initiator | Initiator-to-Responder | Total |

|---|---:|---:|---:|

| ECDH | 65 bytes | 65 bytes | 130 bytes |

| ML-KEM-768 | 1184 bytes | 1088 bytes | 2272 bytes |

| Hybrid | 1249 bytes | 1153 bytes | 2402 bytes |



ML-KEM-768 public key and ciphertext lengths were consistent with the implementation's expected standardized sizes: 1184 and 1088 bytes respectively.



The hybrid mode combines the classical and post-quantum contributions, increasing payload size relative to either standalone mode.



\## 6. Interpretation



1\. All 30,000 measured handshakes across both environments succeeded.

2\. In these runs, hybrid had the highest median latency among the three modes.

3\. Hybrid had the largest protocol payload at 2402 bytes.

4\. ML-KEM-768 had lower measured median latency than ECDH in both recorded runs.

5\. Platform B produced lower median latency measurements for all three suites than Platform A in these runs. This observation must not be interpreted as evidence that constrained hardware is inherently faster.



Platform A and Platform B use different operating systems, Python builds and native-library build environments. Platform A uses an MSVC-built Windows DLL, whereas Platform B builds and loads the Linux

