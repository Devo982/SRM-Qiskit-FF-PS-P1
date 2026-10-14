# Research and Scope Context

## User-supplied material

The directory `reference_materials/` includes the provided QFF Phase 1 Master Guide PDF, extracted notes summarizing the uploaded papers, and the original user-supplied papers archive. The agent should inspect primary papers if it uses a claim from them and cite the precise paper/section/page in the final report.

The supplied notes identify Battarbee et al., *Quantum-Safe Hybrid Key Exchanges with KEM-Based Authentication* (arXiv:2411.04030), as most aligned with the notebook's broader research topic. Its design covers a wider authenticated hybrid setting with KEM-based authentication and QKD assumptions. It should be used as background, not conflated with the specific PS-P1 ECDH P-256 + ML-KEM-768 microbenchmark. Avoid claiming to implement Muckle# unless it is independently implemented and verified to its actual specification.

Other supplied notes include TLS/PQC performance benchmarking, QKD/KEM integration into TLS, QKD/IPsec, DNSSEC PQ signatures, zero-knowledge authenticated channels, and a hybrid smart-contract scheme. These are related background, not all required PS-P1 components.

## Specification mismatch to flag

The QFF Phase 1 Master Guide's universal framework and exact repository layout emphasize quantum Processor A/B coupling graphs, Qiskit transpilation, circuit depth, CX count, SWAP overhead, and noisy execution fidelity. The PS-P1 problem statement provided to the team specifically asks for classical P-256 ECDH + ML-KEM-768 and latency, ciphertext size, memory overhead under simulated standard/constrained CPU environments.

This kit implements the PS-P1-specific description, not Qiskit metrics. The agent should record this mismatch in the final limitations and seek organizer clarification when feasible. It must not fabricate quantum circuit depth or processor coupling metrics for a classical cryptographic benchmark.

## External technical references

- NIST FIPS 203, ML-KEM standard: https://csrc.nist.gov/pubs/fips/203/final
- Official `liboqs-python` wrapper and install guidance: https://github.com/open-quantum-safe/liboqs-python
- `cryptography` EC/ECDH API: https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ec/

NIST's FIPS 203 page notes a planning notice about an identified issue that may be corrected in a future revision. Record the publication/errata status consulted and the exact installed library versions. Do not state that a library version alone resolves an erratum unless official evidence supports it.
