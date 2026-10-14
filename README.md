# PS-P1 — Quantum-Safe Hybrid Key Exchange (Agent-Ready Kit)

> **Implementation overview:** see [`PROJECT_README.md`](PROJECT_README.md) for what the completed project is capable of, its architecture, commands, measured results, and limitations. This file documents the original starter kit.

This repository is a starter implementation and execution plan for PS-P1: combine ephemeral ECDH on NIST P-256 with standardized ML-KEM-768, derive a hybrid session key with HKDF-SHA-256, and benchmark correctness, latency, payload size, and memory under a standard CPU environment (Platform A) and a resource-constrained CPU environment (Platform B).

> **Important:** This is a research/benchmark prototype, not a production secure-channel implementation. The baseline messages are unauthenticated and vulnerable to an active man-in-the-middle. Do not use it to protect real secrets. The agent must not claim formal protocol security or real-hardware constrained-device performance without evidence.

## 1. How to use this with a coding agent

Open this directory as the project root in Claude Code, Gemini CLI, Codex, or another repository-aware agent. Start by telling the agent:

> Read `AGENTS.md`, `TASKS.md`, `docs/PROTOCOL_SPEC.md`, `docs/IMPLEMENTATION_PLAN.md`, and `docs/BENCHMARK_PROTOCOL.md` first. Execute the stages in order, make real code changes, and run each stage's verification gate before moving forward. Record evidence in `TASKS.md` and `results/verification_log.md`. Stop and diagnose on failures; do not skip, fake, or relabel a failed test. Do not ask me to approve routine implementation choices. Do not invent benchmark results. Finish with a reproducible report and a concise summary of what passed, what failed, and what remains blocked.

The same instructions are copied into `CLAUDE.md` and `GEMINI.md` for convenience.

## 2. Environment setup

Python 3.11 or 3.12 is recommended. ML-KEM is provided via the `liboqs-python` binding and native `liboqs` library; the native library may be built on first import. This requires a C compiler, CMake, Git, and network access for first-time installation. See the official instructions:

- `https://github.com/open-quantum-safe/liboqs-python`
- `https://csrc.nist.gov/pubs/fips/203/final`
- `https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ec/`

Create a virtual environment and install dependencies:

```bash
python -m venv .venv
# Linux/macOS/WSL
source .venv/bin/activate
# Windows PowerShell instead: .venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

If native OQS installation fails, the agent must record the exact error and environment rather than silently replace standardized ML-KEM with obsolete Kyber or a mock.

## 3. Verification commands

```bash
# Static environment and algorithm checks; must show ML-KEM-768 enabled
python -m src.cli check

# Fast local correctness run; use `--mode all` to test all three suites
python -m src.cli handshake --mode all

# Unit/integration tests
python -m pytest -q

# Short pilot benchmark (not enough for final reported statistics)
python -m src.benchmark --platform A --iterations 20 --warmup 5 --batches 1 --memory-reps 10
```

A passing result from `pytest` with ML-KEM tests skipped is **not** a full acceptance pass. For final acceptance, `python -m src.cli check` must detect `ML-KEM-768`, and ML-KEM and hybrid integration tests must actually execute.

## 4. Platform A / Platform B methodology

- **Platform A:** the documented host or baseline CPU environment. Record the actual processor, operating system, Python version, logical CPU count, RAM, and any container limits.
- **Platform B:** execute the same source tree and same container image under an enforced CPU quota and memory cap. The illustrative configuration is **1 CPU quota and 512 MiB RAM**. These are experiment parameters, not hardware facts supplied by the challenge.

Build one image, then use it for both runs:

```bash
docker build -t ps-p1 .

# Platform A: no extra CPU/memory cap imposed by this command
docker run --rm -v "$PWD:/app" -w /app ps-p1 \
  python -m src.benchmark --platform A --iterations 1000 --warmup 100 --batches 5

# Platform B: constrained execution of the exact same image and project
docker run --rm --cpus=1 --memory=512m -v "$PWD:/app" -w /app ps-p1 \
  python -m src.benchmark --platform B --iterations 1000 --warmup 100 --batches 5
```

Run from Linux/macOS/WSL with Docker. Windows PowerShell path/volume syntax may differ. The B run checks whether CPU/memory cgroup limits are actually observable. Use `--allow-unverified-platform` only for a pilot; never treat that run as valid Platform B evidence.

A CPU/memory-limited container is an emulation of resource constraints. It does **not** model ARM-specific behavior, energy usage, cache differences, an IoT operating system, or physical embedded hardware.

## 5. Expected cryptographic encodings

| Item | Expected bytes |
|---|---:|
| P-256 uncompressed public point | 65 |
| P-256 ECDH secret | 32 |
| ML-KEM-768 public key | 1,184 |
| ML-KEM-768 secret key | 2,400 |
| ML-KEM-768 ciphertext | 1,088 |
| ML-KEM shared secret | 32 |
| Derived session key | 32 |

Raw payload expectations for the baseline messages (before framing, certificates, or key-confirmation MACs): ECDH-only 130 bytes; ML-KEM-only 2,272 bytes; hybrid 2,402 bytes. The total hybrid payload is not the same thing as the ML-KEM ciphertext size.

## 6. Deliverables

The agent should fill these in rather than merely describe them:

- implementation under `src/`;
- automated tests under `tests/`;
- raw benchmark samples in `data/raw/`;
- summarized results under `results/tables/` and plots under `results/figures/`;
- evidence and unresolved blockers in `results/verification_log.md`;
- final analysis in `report.md`;
- pinned/frozen environment info in `environment.md`;
- updated checkboxes and command outputs in `TASKS.md`.

Do not commit secret keys, raw shared secrets, private key material, or logs containing them. Benchmark outputs must contain only metadata, public payload sizes, timing, memory figures, and boolean test outcomes.

## 7. Source and background materials

`reference_materials/` contains the supplied QFF Phase 1 Master Guide, a research-note extract, and the user's uploaded-paper archive. Consult these materials when needed. The uploaded notes identify Battarbee et al., *Quantum-Safe Hybrid Key Exchanges with KEM-Based Authentication*, as central background. That work covers a broader authenticated hybrid design, including KEM-based authentication and QKD; do not silently claim this simpler ECDH + ML-KEM benchmark implements that protocol.

The supplied master guide's universal challenge framework also emphasizes Qiskit Processor A/B quantum architecture metrics. PS-P1's specific task asks for standard-vs-constrained CPU benchmarking. This kit follows the PS-P1-specific CPU requirements and records the apparent scope mismatch in `docs/RESEARCH_CONTEXT.md`; the team should confirm interpretation with organizers when possible.
