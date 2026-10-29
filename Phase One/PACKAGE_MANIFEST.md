# Package Manifest

This archive contains an agent-ready starter repository for PS-P1. It includes:

- `AGENTS.md`, `CLAUDE.md`, `GEMINI.md`, and `AGENT_START_PROMPT.md` for autonomous stage-by-stage execution.
- A task ledger and implementation/protocol/benchmark/research documentation, plus `main.ipynb` and `report.md` submission templates.
- Starter code for P-256 ECDH, ML-KEM-768 integration, transcript binding, HKDF, handshake modes, metrics, CPU/memory constraint verification, and benchmark orchestration.
- Pytest tests, a shell quality-gate runner, CI workflow, Dockerfile, and result aggregation/plotting script.
- Platform A/B JSON configurations, report/environment templates, and verification log.
- Supplied QFF master guide, supplied research notes, and the uploaded research-paper archive under `reference_materials/`.

## Known packaging-environment limitation

The packaging environment has `cryptography` and `psutil` available but does not have `oqs`/native `liboqs` installed. Therefore 10 Python tests passed, 4 ML-KEM-dependent tests were skipped, and the ECDH-only smoke test passed. This archive does **not** claim full ML-KEM or benchmark acceptance. The agent must install and verify the native dependency; the instructions treat skipped ML-KEM tests as a blocked gate, not a pass.
