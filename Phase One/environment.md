# Environment Manifest

Values below were captured from actual commands on the benchmark host; none are guessed.
The execution environment is not a Git repository, so the working-tree identifier is a
SHA-256 over all `src/*.py`, `tests/*.py`, and `scripts/*.py` files.

- Date/time (UTC): 2026-10-14 (preflight 11:09Z; Platform A run 11:11Z; Platform B run 11:11Z)
- Working-tree identifier (combined SHA-256 of `src/`, `tests/`, `scripts/` Python files): `0ee224649e75130a8fb2a33d097747970e046e5bd7880ed16aaa8bc226539f88`
- Git commit: N/A (not a Git repository)
- OS/kernel: `Linux-7.2.5-3-omarchy-x86_64-with-glibc2.44`; kernel `7.2.5-3-omarchy`
- CPU model/architecture: AMD Ryzen 7 4800H with Radeon Graphics; x86_64; 8 physical / 16 logical CPUs
- Total host memory: 16,143,822,848 bytes (~15.04 GiB)
- Python version: 3.14.7 (CPython, GCC 16.1.1)
- `cryptography`: 46.0.7
- `liboqs-python`: 0.16.0.1
- Native `liboqs`: 0.16.0 (auto-built on first `import oqs`; installed prefix `/home/devo982/_oqs`)
- Enabled ML-KEM mechanism name: `ML-KEM-768` (details: `version=FIPS203`, `claimed_nist_level=3`, `is_ind_cca=true`, `length_public_key=1184`, `length_secret_key=2400`, `length_ciphertext=1088`, `length_shared_secret=32`)
- `psutil`: 7.2.2
- `pytest`: 8.4.2; `pandas`: 3.0.6; `matplotlib`: 3.11.2; `cmake` (pip): 4.4.4
- Docker engine/image ID: Docker **client** 29.7.2 present, but the **daemon is unavailable** (`docker info` fails, `systemctl is-active docker` = inactive, no passwordless sudo). No image could be built or run.
- Platform A effective CPU/memory limits: none imposed by the benchmark command; `cpu_quota_cores=None`, `memory_limit_bytes=None` (host baseline). Same source tree, same virtualenv, same dependency versions as Platform B.
- Platform B requested limits: 1 CPU quota, 512 MiB memory (`CPUQuota=100%`, `MemoryMax=512M`, `MemorySwapMax=0`)
- Platform B enforcement mechanism: `systemd-run --user --scope` (cgroup v2 user delegation), because Docker could not be used
- Platform B observed CPU quota: `1.0` core — source `cgroup_v2:/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/app.slice/<scope>/cpu.max` (`cpu.max = 100000 100000`)
- Platform B observed memory limit: `536870912` bytes (512 MiB) — source `cgroup_v2:/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/app.slice/<scope>/memory.max`
- Platform B verification flag recorded in results: `platform_verified=true` (both CPU quota and memory cap observed within required bounds)
- NIST FIPS 203 publication/errata status consulted: FIPS 203 final, published 2024-08-13 (https://csrc.nist.gov/pubs/fips/203/final). The page states NIST "identified an issue that will be corrected in a future update/revision," with details in the errata spreadsheet under "Documentation." No erratum is claimed resolved by the installed library version.

All placeholders above were replaced with measured values on 2026-10-14. This file is complete.
