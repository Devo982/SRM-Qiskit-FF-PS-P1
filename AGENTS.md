# Autonomous Agent Contract — PS-P1

## Mission
Implement and validate a reproducible Python prototype of hybrid P-256 ECDH + standardized ML-KEM-768 key establishment; measure latency, ciphertext/payload size, and memory under Platform A and a verified resource-constrained Platform B; produce reproducible results and a limitations-aware report.

## Mandatory first reads
1. `README.md`
2. `TASKS.md`
3. `docs/PROTOCOL_SPEC.md`
4. `docs/IMPLEMENTATION_PLAN.md`
5. `docs/BENCHMARK_PROTOCOL.md`
6. `docs/RESEARCH_CONTEXT.md`

## Operating rules
- Work through phases in `TASKS.md` in order. Each phase has a gate. Do not begin the next phase until all required gate checks pass or the blocker is explicitly documented.
- Take action autonomously on routine implementation details. Do not ask the user questions for decisions that can be made using the supplied specification. If an external ambiguity materially affects acceptance (especially QFF-wide quantum Processor A/B rules versus PS-P1 CPU Platform A/B rules), continue with the PS-P1-specific scope and document the question instead of blocking all work.
- Never state a command passed unless you ran it and captured its exit code/output. Never fabricate elapsed times, memory numbers, enabled mechanisms, or platform limits.
- Never count a skipped ML-KEM test as passing. A full pass requires actual ML-KEM-768 execution using `liboqs-python` backed by `liboqs`.
- Do not substitute legacy `Kyber768` for FIPS 203 `ML-KEM-768`. Do not replace cryptographic operations with mocks in acceptance tests. Mocks are allowed only in narrowly scoped tests explicitly marked unit-only.
- Before a benchmark, verify key agreement for that exact code revision. If implementation changes after the benchmark, rerun correctness tests and invalidate stale result files.
- Platform B is valid only when CPU and memory constraints are observably enforced. A JSON label alone does not emulate a platform. If detection is unavailable, mark the run unverified and don't use it as comparative evidence.
- Keep the same source revision, container image, Python version, and dependencies across A and B. Record deviations.
- Separate cold-start/setup time from steady-state operation timing. Report exactly what is included in each metric.
- Do not tune the protocol based on test-only deterministic secrets. Use normal system cryptographic randomness in performance runs.
- Do not claim production security, formal security, identity authentication, or man-in-the-middle resistance. This baseline is unauthenticated. HMAC key confirmation proves possession of the derived key but is not peer identity authentication.
- Protect secret values. Never print, persist, commit, or add shared secrets/private keys to CSV, JSON, screenshots, or logs.
- Inspect the repository before changing it. Avoid destructive cleanup and never delete supplied reference material.
- Prefer small, testable commits/steps, but don't require Git or commit changes unless the environment is already a repository and committing is safe.

## Required workflow
1. Establish environment and repository status.
2. Run preflight; verify native OQS, algorithm availability, and library versions.
3. Implement/verify ECDH alone.
4. Implement/verify ML-KEM alone.
5. Implement/verify transcript encoding and hybrid HKDF.
6. Integrate complete handshakes and make tests pass.
7. Validate message sizes, failure handling, and fresh-key lifecycle.
8. Implement benchmark and memory probe; test output schema using pilot runs.
9. Run Platform A baseline.
10. Run Platform B only with enforced, verified limits.
11. Re-run correctness suite on final revision.
12. Generate summaries/plots and write the report based only on raw measured data.
13. Audit repository for secret leakage, fabricated data, empty result claims, and undocumented failures.

## Gate evidence
After every phase, append to `results/verification_log.md`:
- timestamp (UTC);
- git commit or working-tree identifier if available;
- command executed;
- exit code;
- observed result (summary plus saved log path if lengthy);
- pass/fail/blocked;
- unresolved issue and next action.

Update `TASKS.md` only after evidence supports the status. Use `BLOCKED`, not `DONE`, when a dependency or platform is unavailable. Don't leave placeholder `TBD` results in a report labeled final.

## Required acceptance commands
At minimum, execute and record:
```bash
python -m src.cli check
python -m pytest -q
python -m src.cli handshake --mode all
python -m src.benchmark --platform A --iterations 1000 --warmup 100 --batches 5
python -m src.benchmark --platform B --iterations 1000 --warmup 100 --batches 5
```
The last command must run inside an environment that enforces the configured Platform B resource limits. If the native OQS dependency is not available, do not claim acceptance.

## Final response format
Summarize: implementation completed; stage gate table; exact tests and outcomes; Platform A/B verification state; artifact paths; measured results with units; limitations; blocked items. Do not give a generic “done” without evidence.
