# SRM-Qiskit-FF-PS-P1

Qiskit Fall Fest 2026 — Track 5, Problem Statement **PS-P1: Quantum-Safe
Secure Communication Channel** (Phase 2). This repository addresses exactly
one problem statement: PS-P1.

## Repository layout

- Phase 1 deliverable (hybrid key exchange + quantum processor study):
  preserved unchanged under `Phase One/` (see `Phase One/README.md`,
  `Phase One/PS-P1_BENCHMARK_REPORT.md`). Phase-1 tooling runs from inside
  that folder, e.g. `make -C "Phase One" <target>`.
- Phase 2 work (PS-P1 v2) lives at this root: `src/`, `tests/`, `scripts/`,
  `results/`, `docs/`, and the vendored kit folders `P1_secure_channel/`
  and `common/`.

## Status

Phase 2 implementation in progress. Setup, test, and benchmark commands
will follow the Challenge Kit README template as components land:
secure channel (ML-KEM-768, ML-DSA-65, HKDF-SHA256, AES-256-GCM),
classical baseline (X25519 + Ed25519), automated security tests T1-T9,
official payload verification, and benchmark reports.
