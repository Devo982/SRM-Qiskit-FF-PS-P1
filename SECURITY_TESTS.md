# PS-P1 Security Test Suite

## Purpose

The mandatory security suite validates the PQC and classical communication
channels using wire-level fault injection.

## Run

From the repository root, run:

    .venv/bin/python scripts/run_security_suite.py

Expected result: 54/54 detailed checks pass across both suites.

## Mandatory tests

| Test | Validation |
|---|---|
| T1 | Honest handshake, official payloads, authenticated close |
| T2 | Handshake message tampering |
| T3 | Invalid client/server signatures |
| T4 | Ciphertext tampering |
| T5 | GCM tag and authenticated-header tampering |
| T6 | Untrusted identity rejection |
| T7 | Identity swap and transcript/signature binding |
| T8 | Record and handshake replay protection |
| T9 | Unknown suite, suite-echo substitution, server suite-policy mismatch |

The suite must verify expected failures and ensure plaintext is not released
when authentication fails.

## Evidence

Review results/security_tests.csv and results/security_tests_detailed.csv.
The expected total is 27 checks per suite, 54 overall.

Review changes to trust_store.json separately. Local test provisioning may
regenerate it when the local test identities differ from the committed
public verification keys. Do not commit generated trust-anchor changes
without reviewing them.

This is a prototype validation suite, not a claim of production security.
